/* Copyright (c) 2008-2015, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/module.h>
#include <linux/fb.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/list.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/dma-buf.h>
#include <linux/pm_runtime.h>
#include <linux/rbtree.h>
#include <linux/major.h>
#include <linux/io.h>
#include <linux/mman.h>
#include <linux/sort.h>
#include <linux/security.h>
#include <linux/compat.h>

#include "kgsl.h"
#include "kgsl_debugfs.h"
#include "kgsl_cffdump.h"
#include "kgsl_log.h"
#include "kgsl_sharedmem.h"
#include "kgsl_cmdbatch.h"
#include "kgsl_device.h"
#include "kgsl_trace.h"
#include "kgsl_sync.h"
#include "kgsl_compat.h"
#include "kgsl_htc.h"

#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "kgsl."

#ifndef arch_mmap_check
#define arch_mmap_check(addr, len, flags)	(0)
#endif

#ifndef pgprot_writebackcache
#define pgprot_writebackcache(_prot)	(_prot)
#endif

#ifndef pgprot_writethroughcache
#define pgprot_writethroughcache(_prot)	(_prot)
#endif

#ifdef CONFIG_ARM_LPAE
#define KGSL_DMA_BIT_MASK	DMA_BIT_MASK(64)
#else
#define KGSL_DMA_BIT_MASK	DMA_BIT_MASK(32)
#endif

static char *ksgl_mmu_type;
module_param_named(mmutype, ksgl_mmu_type, charp, 0);
MODULE_PARM_DESC(ksgl_mmu_type,
"Type of MMU to be used for graphics. Valid values are 'iommu' or 'nommu'");

struct kgsl_dma_buf_meta {
	struct dma_buf_attachment *attach;
	struct dma_buf *dmabuf;
	struct sg_table *table;
};

static void kgsl_mem_entry_detach_process(struct kgsl_mem_entry *entry);

static const struct file_operations kgsl_fops;

static int __kgsl_check_collision(struct kgsl_process_private *private,
			struct kgsl_mem_entry *entry,
			uint64_t *gpuaddr, uint64_t len,
			int flag_top_down);


#define MEMFREE_ENTRIES 512

static DEFINE_SPINLOCK(memfree_lock);

struct memfree_entry {
	uint64_t gpuaddr;
	uint64_t size;
	pid_t pid;
	uint64_t flags;
};

static struct {
	struct memfree_entry *list;
	int head;
	int tail;
} memfree;

static int kgsl_memfree_init(void)
{
	memfree.list = kzalloc(MEMFREE_ENTRIES * sizeof(struct memfree_entry),
		GFP_KERNEL);

	return (memfree.list) ? 0 : -ENOMEM;
}

static void kgsl_memfree_exit(void)
{
	kfree(memfree.list);
	memset(&memfree, 0, sizeof(memfree));
}

int kgsl_memfree_find_entry(pid_t pid, uint64_t *gpuaddr,
	uint64_t *size, uint64_t *flags)
{
	int ptr;

	if (memfree.list == NULL)
		return 0;

	spin_lock(&memfree_lock);

	ptr = memfree.head - 1;
	if (ptr < 0)
		ptr = MEMFREE_ENTRIES - 1;

	
	while (ptr != memfree.tail) {
		struct memfree_entry *entry = &memfree.list[ptr];

		if ((entry->pid == pid) &&
			(*gpuaddr >= entry->gpuaddr &&
			 *gpuaddr < (entry->gpuaddr + entry->size))) {
			*gpuaddr = entry->gpuaddr;
			*flags = entry->flags;
			*size = entry->size;

			spin_unlock(&memfree_lock);
			return 1;
		}

		ptr = ptr - 1;

		if (ptr < 0)
			ptr = MEMFREE_ENTRIES - 1;
	}

	spin_unlock(&memfree_lock);
	return 0;
}

static void kgsl_memfree_add(pid_t pid, uint64_t gpuaddr,
		uint64_t size, uint64_t flags)

{
	struct memfree_entry *entry;

	if (memfree.list == NULL)
		return;

	spin_lock(&memfree_lock);

	entry = &memfree.list[memfree.head];

	entry->pid = pid;
	entry->gpuaddr = gpuaddr;
	entry->size = size;
	entry->flags = flags;

	memfree.head = (memfree.head + 1) % MEMFREE_ENTRIES;

	if (memfree.head == memfree.tail)
		memfree.tail = (memfree.tail + 1) % MEMFREE_ENTRIES;

	spin_unlock(&memfree_lock);
}

int kgsl_readtimestamp(struct kgsl_device *device, void *priv,
		enum kgsl_timestamp_type type, unsigned int *timestamp)
{
	return device->ftbl->readtimestamp(device, priv, type, timestamp);
}
EXPORT_SYMBOL(kgsl_readtimestamp);


struct kgsl_mem_entry * __must_check
kgsl_get_mem_entry(struct kgsl_device *device,
	phys_addr_t ptbase, uint64_t gpuaddr, uint64_t size)
{
	struct kgsl_process_private *priv;
	struct kgsl_mem_entry *entry;

	mutex_lock(&kgsl_driver.process_mutex);

	list_for_each_entry(priv, &kgsl_driver.process_list, list) {
		if (!kgsl_mmu_pt_equal(&device->mmu, priv->pagetable, ptbase))
			continue;
		entry = kgsl_sharedmem_find_region(priv, gpuaddr, size);

		if (entry) {
			mutex_unlock(&kgsl_driver.process_mutex);
			return entry;
		}
	}
	mutex_unlock(&kgsl_driver.process_mutex);

	return NULL;
}
EXPORT_SYMBOL(kgsl_get_mem_entry);

static inline struct kgsl_mem_entry *
kgsl_mem_entry_create(void)
{
	struct kgsl_mem_entry *entry = kzalloc(sizeof(*entry), GFP_KERNEL);

	if (entry)
		kref_init(&entry->refcount);

	return entry;
}
#ifdef CONFIG_DMA_SHARED_BUFFER
static void kgsl_destroy_ion(struct kgsl_dma_buf_meta *meta)
{
	if (meta != NULL) {
		dma_buf_unmap_attachment(meta->attach, meta->table,
			DMA_FROM_DEVICE);
		dma_buf_detach(meta->dmabuf, meta->attach);
		dma_buf_put(meta->dmabuf);
		kfree(meta);
	}
}
#else
static void kgsl_destroy_ion(struct kgsl_dma_buf_meta *meta)
{

}
#endif

void
kgsl_mem_entry_destroy(struct kref *kref)
{
	struct kgsl_mem_entry *entry = container_of(kref,
						    struct kgsl_mem_entry,
						    refcount);
	unsigned int memtype;

	if (entry == NULL)
		return;

	
	memtype = kgsl_memdesc_usermem_type(&entry->memdesc);

	
	kgsl_mem_entry_detach_process(entry);

	if (memtype != KGSL_MEM_ENTRY_KERNEL)
		kgsl_driver.stats.mapped -= entry->memdesc.size;

	if (memtype == KGSL_MEM_ENTRY_ION)
		entry->memdesc.sgt = NULL;

	if ((memtype == KGSL_MEM_ENTRY_USER)
		&& !(entry->memdesc.flags & KGSL_MEMFLAGS_GPUREADONLY)) {
		int i = 0, j;
		struct scatterlist *sg;
		struct page *page;
		for_each_sg(entry->memdesc.sgt->sgl, sg,
			    entry->memdesc.sgt->nents, i) {
			page = sg_page(sg);
			for (j = 0; j < (sg->length >> PAGE_SHIFT); j++)
				set_page_dirty(nth_page(page, j));
		}
	}

	kgsl_sharedmem_free(&entry->memdesc);

	switch (memtype) {
	case KGSL_MEM_ENTRY_ION:
		kgsl_destroy_ion(entry->priv_data);
		break;
	default:
		break;
	}

	kfree(entry);
}
EXPORT_SYMBOL(kgsl_mem_entry_destroy);

static int
kgsl_mem_entry_track_gpuaddr(struct kgsl_process_private *process,
				struct kgsl_mem_entry *entry)
{
	int ret = 0;
	struct rb_node **node;
	struct rb_node *parent = NULL;
	struct kgsl_pagetable *pagetable = process->pagetable;

	assert_spin_locked(&process->mem_lock);

	if (kgsl_memdesc_use_cpu_map(&entry->memdesc)) {
		if (!entry->memdesc.gpuaddr)
			goto done;
	} else if (entry->memdesc.gpuaddr) {
		WARN_ONCE(1, "gpuaddr assigned w/o holding memory lock\n");
		ret = -EINVAL;
		goto done;
	}
	if (kgsl_memdesc_is_secured(&entry->memdesc))
		pagetable = pagetable->mmu->securepagetable;

	ret = kgsl_mmu_get_gpuaddr(pagetable, &entry->memdesc);
	if (ret)
		goto done;

	node = &process->mem_rb.rb_node;

	while (*node) {
		struct kgsl_mem_entry *cur;

		parent = *node;
		cur = rb_entry(parent, struct kgsl_mem_entry, node);

		if (entry->memdesc.gpuaddr < cur->memdesc.gpuaddr)
			node = &parent->rb_left;
		else
			node = &parent->rb_right;
	}

	rb_link_node(&entry->node, parent, node);
	rb_insert_color(&entry->node, &process->mem_rb);

done:
	return ret;
}

static void
kgsl_mem_entry_untrack_gpuaddr(struct kgsl_process_private *process,
				struct kgsl_mem_entry *entry)
{
	assert_spin_locked(&process->mem_lock);
	if (entry->memdesc.gpuaddr) {
		kgsl_mmu_put_gpuaddr(entry->memdesc.pagetable,
					&entry->memdesc);
		rb_erase(&entry->node, &entry->priv->mem_rb);
	}
}

int
kgsl_mem_entry_attach_process(struct kgsl_mem_entry *entry,
				   struct kgsl_device_private *dev_priv)
{
	int id;
	int ret;
	struct kgsl_process_private *process = dev_priv->process_priv;
	struct kgsl_pagetable *pagetable = NULL;

	ret = kgsl_process_private_get(process);
	if (!ret)
		return -EBADF;
	idr_preload(GFP_KERNEL);
	spin_lock(&process->mem_lock);
	id = idr_alloc(&process->mem_idr, entry, 1, 0, GFP_NOWAIT);
	spin_unlock(&process->mem_lock);
	idr_preload_end();

	if (id < 0) {
		ret = id;
		goto err_put_proc_priv;
	}

	entry->id = id;
	entry->priv = process;
	entry->memdesc.private = process;

	spin_lock(&process->mem_lock);
	ret = kgsl_mem_entry_track_gpuaddr(process, entry);
	if (ret)
		idr_remove(&process->mem_idr, entry->id);
	spin_unlock(&process->mem_lock);
	if (ret)
		goto err_put_proc_priv;
	
	if (entry->memdesc.gpuaddr) {
		
		if (kgsl_memdesc_is_secured(&entry->memdesc))
			pagetable = process->pagetable->mmu->securepagetable;
		else
			pagetable = process->pagetable;

		entry->memdesc.pagetable = pagetable;
		ret = kgsl_mmu_map(pagetable, &entry->memdesc);
		if (ret)
			kgsl_mem_entry_detach_process(entry);
	}
	return ret;

err_put_proc_priv:
	kgsl_process_private_put(process);
	return ret;
}


static void kgsl_mem_entry_detach_process(struct kgsl_mem_entry *entry)
{
	unsigned int type;
	if (entry == NULL)
		return;

	
	kgsl_mmu_unmap(entry->memdesc.pagetable, &entry->memdesc);

	spin_lock(&entry->priv->mem_lock);

	kgsl_mem_entry_untrack_gpuaddr(entry->priv, entry);
	if (entry->id != 0)
		idr_remove(&entry->priv->mem_idr, entry->id);
	entry->id = 0;

	type = kgsl_memdesc_usermem_type(&entry->memdesc);
	entry->priv->stats[type].cur -= entry->memdesc.size;
	spin_unlock(&entry->priv->mem_lock);
	kgsl_process_private_put(entry->priv);

	entry->priv = NULL;
}

void kgsl_context_dump(struct kgsl_context *context)
{
	struct kgsl_device *device;

	if (_kgsl_context_get(context) == 0)
		return;

	device = context->device;

	if (kgsl_context_detached(context)) {
		dev_err(device->dev, "  context[%d]: context detached\n",
			context->id);
	} else if (device->ftbl->drawctxt_dump != NULL)
		device->ftbl->drawctxt_dump(device, context);

	kgsl_context_put(context);
}
EXPORT_SYMBOL(kgsl_context_dump);

int _kgsl_get_context_id(struct kgsl_device *device,
		struct kgsl_context *context)
{
	int id;

	idr_preload(GFP_KERNEL);
	write_lock(&device->context_lock);
	id = idr_alloc(&device->context_idr, context, 1,
		KGSL_MEMSTORE_MAX, GFP_NOWAIT);
	write_unlock(&device->context_lock);
	idr_preload_end();

	if (id > 0)
		context->id = id;

	return id;
}

int kgsl_context_init(struct kgsl_device_private *dev_priv,
			struct kgsl_context *context)
{
	struct kgsl_device *device = dev_priv->device;
	char name[64];
	int ret = 0, id;

	id = _kgsl_get_context_id(device, context);
	if (id == -ENOSPC) {

		flush_workqueue(device->events_wq);
		id = _kgsl_get_context_id(device, context);
	}

	if (id < 0) {
		if (id == -ENOSPC)
			KGSL_DRV_INFO(device,
				"cannot have more than %zu contexts due to memstore limitation\n",
				KGSL_MEMSTORE_MAX);

		return id;
	}

	kref_init(&context->refcount);
	if (!kgsl_process_private_get(dev_priv->process_priv)) {
		ret = -EBADF;
		goto out;
	}
	context->device = dev_priv->device;
	context->dev_priv = dev_priv;
	context->proc_priv = dev_priv->process_priv;
	context->tid = task_pid_nr(current);

	ret = kgsl_sync_timeline_create(context);
	if (ret)
		goto out;

	snprintf(name, sizeof(name), "context-%d", id);
	kgsl_add_event_group(&context->events, context, name,
		kgsl_readtimestamp, context);

out:
	if (ret) {
		write_lock(&device->context_lock);
		idr_remove(&dev_priv->device->context_idr, id);
		kgsl_dump_contextpid_locked(&dev_priv->device->context_idr);
		write_unlock(&device->context_lock);
	}

	return ret;
}
EXPORT_SYMBOL(kgsl_context_init);

static void kgsl_context_detach(struct kgsl_context *context)
{
	struct kgsl_device *device;

	if (context == NULL)
		return;

	if (test_and_set_bit(KGSL_CONTEXT_PRIV_DETACHED, &context->priv))
		return;

	device = context->device;

	trace_kgsl_context_detach(device, context);

	context->device->ftbl->drawctxt_detach(context);

	kgsl_cancel_events(device, &context->events);

	
	kgsl_del_event_group(&context->events);

	kgsl_context_put(context);
}

void
kgsl_context_destroy(struct kref *kref)
{
	struct kgsl_context *context = container_of(kref, struct kgsl_context,
						    refcount);
	struct kgsl_device *device = context->device;

	trace_kgsl_context_destroy(device, context);

	BUG_ON(!kgsl_context_detached(context));

	write_lock(&device->context_lock);
	if (context->id != KGSL_CONTEXT_INVALID) {

		
		kgsl_sharedmem_writel(device, &device->memstore,
			KGSL_MEMSTORE_OFFSET(context->id, soptimestamp), 0);
		kgsl_sharedmem_writel(device, &device->memstore,
			KGSL_MEMSTORE_OFFSET(context->id, eoptimestamp), 0);

		
		if (context->id == device->pwrctrl.constraint.owner_id) {
			trace_kgsl_constraint(device,
				device->pwrctrl.constraint.type,
				device->pwrctrl.active_pwrlevel,
				0);
			device->pwrctrl.constraint.type = KGSL_CONSTRAINT_NONE;
		}

		idr_remove(&device->context_idr, context->id);
		context->id = KGSL_CONTEXT_INVALID;
	}
	write_unlock(&device->context_lock);
	kgsl_sync_timeline_destroy(context);
	kgsl_process_private_put(context->proc_priv);

	device->ftbl->drawctxt_destroy(context);
}

struct kgsl_device *kgsl_get_device(int dev_idx)
{
	int i;
	struct kgsl_device *ret = NULL;

	mutex_lock(&kgsl_driver.devlock);

	for (i = 0; i < KGSL_DEVICE_MAX; i++) {
		if (kgsl_driver.devp[i] && kgsl_driver.devp[i]->id == dev_idx) {
			ret = kgsl_driver.devp[i];
			break;
		}
	}

	mutex_unlock(&kgsl_driver.devlock);
	return ret;
}
EXPORT_SYMBOL(kgsl_get_device);

static struct kgsl_device *kgsl_get_minor(int minor)
{
	struct kgsl_device *ret = NULL;

	if (minor < 0 || minor >= KGSL_DEVICE_MAX)
		return NULL;

	mutex_lock(&kgsl_driver.devlock);
	ret = kgsl_driver.devp[minor];
	mutex_unlock(&kgsl_driver.devlock);

	return ret;
}

int kgsl_check_timestamp(struct kgsl_device *device,
	struct kgsl_context *context, unsigned int timestamp)
{
	unsigned int ts_processed;

	kgsl_readtimestamp(device, context, KGSL_TIMESTAMP_RETIRED,
		&ts_processed);

	return (timestamp_cmp(ts_processed, timestamp) >= 0);
}
EXPORT_SYMBOL(kgsl_check_timestamp);

static int kgsl_suspend_device(struct kgsl_device *device, pm_message_t state)
{
	int status = -EINVAL;

	if (!device)
		return -EINVAL;

	KGSL_PWR_WARN(device, "suspend start\n");

	mutex_lock(&device->mutex);
	status = kgsl_pwrctrl_change_state(device, KGSL_STATE_SUSPEND);
	mutex_unlock(&device->mutex);

	KGSL_PWR_WARN(device, "suspend end\n");
	return status;
}

static int kgsl_resume_device(struct kgsl_device *device)
{
	if (!device)
		return -EINVAL;

	KGSL_PWR_WARN(device, "resume start\n");
	mutex_lock(&device->mutex);
	if (device->state == KGSL_STATE_SUSPEND) {
		kgsl_pwrctrl_change_state(device, KGSL_STATE_SLUMBER);
	} else if (device->state != KGSL_STATE_INIT) {
		if (device->state == KGSL_STATE_ACTIVE)
			device->ftbl->idle(device);
		kgsl_pwrctrl_change_state(device, KGSL_STATE_SLUMBER);
		KGSL_PWR_ERR(device,
			"resume invoked without a suspend\n");
	}

	mutex_unlock(&device->mutex);
	KGSL_PWR_WARN(device, "resume end\n");
	return 0;
}

static int kgsl_suspend(struct device *dev)
{

	pm_message_t arg = {0};
	struct kgsl_device *device = dev_get_drvdata(dev);
	return kgsl_suspend_device(device, arg);
}

static int kgsl_resume(struct device *dev)
{
	struct kgsl_device *device = dev_get_drvdata(dev);
	return kgsl_resume_device(device);
}

static int kgsl_runtime_suspend(struct device *dev)
{
	return 0;
}

static int kgsl_runtime_resume(struct device *dev)
{
	return 0;
}

const struct dev_pm_ops kgsl_pm_ops = {
	.suspend = kgsl_suspend,
	.resume = kgsl_resume,
	.runtime_suspend = kgsl_runtime_suspend,
	.runtime_resume = kgsl_runtime_resume,
};
EXPORT_SYMBOL(kgsl_pm_ops);

int kgsl_suspend_driver(struct platform_device *pdev,
					pm_message_t state)
{
	struct kgsl_device *device = dev_get_drvdata(&pdev->dev);
	return kgsl_suspend_device(device, state);
}
EXPORT_SYMBOL(kgsl_suspend_driver);

int kgsl_resume_driver(struct platform_device *pdev)
{
	struct kgsl_device *device = dev_get_drvdata(&pdev->dev);
	return kgsl_resume_device(device);
}
EXPORT_SYMBOL(kgsl_resume_driver);

static void kgsl_destroy_process_private(struct kref *kref)
{
	struct kgsl_process_private *private = container_of(kref,
			struct kgsl_process_private, refcount);

	idr_destroy(&private->mem_idr);
	idr_destroy(&private->syncsource_idr);

	
	if (kgsl_mmu_enabled() &&
		 private->pagetable->name != KGSL_MMU_GLOBAL_PT)
		kgsl_mmu_putpagetable(private->pagetable);

	kfree(private);
	return;
}

void
kgsl_process_private_put(struct kgsl_process_private *private)
{
	if (private)
		kref_put(&private->refcount, kgsl_destroy_process_private);
}

struct kgsl_process_private *kgsl_process_private_find(pid_t pid)
{
	struct kgsl_process_private *p, *private = NULL;

	mutex_lock(&kgsl_driver.process_mutex);
	list_for_each_entry(p, &kgsl_driver.process_list, list) {
		if (p->pid == pid) {
			if (kgsl_process_private_get(p))
				private = p;
			break;
		}
	}
	mutex_unlock(&kgsl_driver.process_mutex);
	return private;
}

static struct kgsl_process_private *kgsl_process_private_new(
		struct kgsl_device *device)
{
	struct kgsl_process_private *private;
	pid_t tgid = task_tgid_nr(current);

	
	list_for_each_entry(private, &kgsl_driver.process_list, list) {
		if (private->pid == tgid) {
			if (!kgsl_process_private_get(private))
				private = ERR_PTR(-EINVAL);
			return private;
		}
	}

	
	private = kzalloc(sizeof(struct kgsl_process_private), GFP_KERNEL);
	if (private == NULL)
		return ERR_PTR(-ENOMEM);

	kref_init(&private->refcount);

	private->pid = tgid;
	get_task_comm(private->comm, current->group_leader);
	private->mem_rb = RB_ROOT;

	spin_lock_init(&private->mem_lock);
	spin_lock_init(&private->syncsource_lock);

	idr_init(&private->mem_idr);
	idr_init(&private->syncsource_idr);

	
	if (kgsl_mmu_enabled()) {
		private->pagetable = kgsl_mmu_getpagetable(&device->mmu, tgid);
		if (private->pagetable == NULL) {
			idr_destroy(&private->mem_idr);
			idr_destroy(&private->syncsource_idr);

			kfree(private);
			private = ERR_PTR(-ENOMEM);
		}
	}

	return private;
}

static void process_release_memory(struct kgsl_process_private *private)
{
	struct kgsl_mem_entry *entry;
	int next = 0;

	while (1) {
		spin_lock(&private->mem_lock);
		entry = idr_get_next(&private->mem_idr, &next);
		if (entry == NULL) {
			spin_unlock(&private->mem_lock);
			break;
		}
		if (!entry->pending_free) {
			entry->pending_free = 1;
			spin_unlock(&private->mem_lock);
			kgsl_mem_entry_put(entry);
		} else {
			spin_unlock(&private->mem_lock);
		}
		next = next + 1;
	}
}

static void process_release_sync_sources(struct kgsl_process_private *private)
{
	struct kgsl_syncsource *syncsource;
	int next = 0;

	while (1) {
		spin_lock(&private->syncsource_lock);
		syncsource = idr_get_next(&private->syncsource_idr, &next);
		spin_unlock(&private->syncsource_lock);

		if (syncsource == NULL)
			break;

		kgsl_syncsource_put(syncsource);
		next = next + 1;
	}
}

static void kgsl_process_private_close(struct kgsl_device_private *dev_priv,
		struct kgsl_process_private *private)
{
	mutex_lock(&kgsl_driver.process_mutex);

	if (--private->fd_count > 0) {
		mutex_unlock(&kgsl_driver.process_mutex);
		kgsl_process_private_put(private);
		return;
	}


	kgsl_process_uninit_sysfs(private);
	debugfs_remove_recursive(private->debug_root);

	process_release_sync_sources(private);

	
	if (kgsl_mmu_enabled() &&
		private->pagetable->name != KGSL_MMU_GLOBAL_PT)
		kgsl_mmu_detach_pagetable(private->pagetable);

	
	list_del(&private->list);

	mutex_unlock(&kgsl_driver.process_mutex);

	process_release_memory(private);

	kgsl_process_private_put(private);
}


static struct kgsl_process_private *kgsl_process_private_open(
		struct kgsl_device *device)
{
	struct kgsl_process_private *private;

	mutex_lock(&kgsl_driver.process_mutex);
	private = kgsl_process_private_new(device);

	if (IS_ERR(private))
		goto done;


	if (private->fd_count++ == 0) {
		kgsl_process_init_sysfs(device, private);
		kgsl_process_init_debugfs(private);

		list_add(&private->list, &kgsl_driver.process_list);
	}

done:
	mutex_unlock(&kgsl_driver.process_mutex);
	return private;
}

static int kgsl_close_device(struct kgsl_device *device)
{
	int result = 0;

	mutex_lock(&device->mutex);
	device->open_count--;
	if (device->open_count == 0) {

		
		kgsl_active_count_wait(device, 0);

		
		BUG_ON(atomic_read(&device->active_cnt) > 0);

		result = kgsl_pwrctrl_change_state(device, KGSL_STATE_INIT);
	}
	mutex_unlock(&device->mutex);
	return result;

}

static void device_release_contexts(struct kgsl_device_private *dev_priv)
{
	struct kgsl_device *device = dev_priv->device;
	struct kgsl_context *context;
	int next = 0;

	while (1) {
		read_lock(&device->context_lock);
		context = idr_get_next(&device->context_idr, &next);
		read_unlock(&device->context_lock);

		if (context == NULL)
			break;

		if (context->dev_priv == dev_priv) {

			if (_kgsl_context_get(context)) {
				kgsl_context_detach(context);
				kgsl_context_put(context);
			}
		}

		next = next + 1;
	}
}

static int kgsl_release(struct inode *inodep, struct file *filep)
{
	struct kgsl_device_private *dev_priv = filep->private_data;
	struct kgsl_device *device = dev_priv->device;
	int result;

	filep->private_data = NULL;

	
	device_release_contexts(dev_priv);

	
	kgsl_process_private_close(dev_priv, dev_priv->process_priv);

	kfree(dev_priv);

	result = kgsl_close_device(device);
	pm_runtime_put(&device->pdev->dev);

	return result;
}

static int kgsl_open_device(struct kgsl_device *device)
{
	int result = 0;

	mutex_lock(&device->mutex);
	if (device->open_count == 0) {
		atomic_inc(&device->active_cnt);
		kgsl_sharedmem_set(device, &device->memstore, 0, 0,
				device->memstore.size);

		result = device->ftbl->init(device);
		if (result)
			goto err;

		result = device->ftbl->start(device, 0);
		if (result)
			goto err;
		complete_all(&device->hwaccess_gate);
		kgsl_pwrctrl_change_state(device, KGSL_STATE_ACTIVE);
		kgsl_active_count_put(device);
	}
	device->open_count++;
err:
	if (result) {
		kgsl_pwrctrl_change_state(device, KGSL_STATE_INIT);
		atomic_dec(&device->active_cnt);
	}

	mutex_unlock(&device->mutex);
	return result;
}

static int kgsl_open(struct inode *inodep, struct file *filep)
{
	int result;
	struct kgsl_device_private *dev_priv;
	struct kgsl_device *device;
	unsigned int minor = iminor(inodep);

	device = kgsl_get_minor(minor);
	BUG_ON(device == NULL);

	result = pm_runtime_get_sync(&device->pdev->dev);
	if (result < 0) {
		KGSL_DRV_ERR(device,
			"Runtime PM: Unable to wake up the device, rc = %d\n",
			result);
		return result;
	}
	result = 0;

	dev_priv = kzalloc(sizeof(struct kgsl_device_private), GFP_KERNEL);
	if (dev_priv == NULL) {
		result = -ENOMEM;
		goto err;
	}

	dev_priv->device = device;
	filep->private_data = dev_priv;

	result = kgsl_open_device(device);
	if (result)
		goto err;

	dev_priv->process_priv = kgsl_process_private_open(device);
	if (IS_ERR(dev_priv->process_priv)) {
		result = PTR_ERR(dev_priv->process_priv);
		kgsl_close_device(device);
		goto err;
	}

err:
	if (result) {
		filep->private_data = NULL;
		kfree(dev_priv);
		pm_runtime_put(&device->pdev->dev);
	}
	return result;
}

struct kgsl_mem_entry * __must_check
kgsl_sharedmem_find_region(struct kgsl_process_private *private,
	uint64_t gpuaddr, uint64_t size)
{
	struct rb_node *node;

	if (!private)
		return NULL;

	if (!kgsl_mmu_gpuaddr_in_range(private->pagetable, gpuaddr))
		return NULL;

	spin_lock(&private->mem_lock);
	node = private->mem_rb.rb_node;
	while (node != NULL) {
		struct kgsl_mem_entry *entry;

		entry = rb_entry(node, struct kgsl_mem_entry, node);

		if (kgsl_gpuaddr_in_memdesc(&entry->memdesc, gpuaddr, size)) {
			if (!kgsl_mem_entry_get(entry))
				break;
			spin_unlock(&private->mem_lock);
			return entry;
		}
		if (gpuaddr < entry->memdesc.gpuaddr)
			node = node->rb_left;
		else if (gpuaddr >=
			(entry->memdesc.gpuaddr + entry->memdesc.size))
			node = node->rb_right;
		else {
			spin_unlock(&private->mem_lock);
			return NULL;
		}
	}
	spin_unlock(&private->mem_lock);

	return NULL;
}
EXPORT_SYMBOL(kgsl_sharedmem_find_region);

static inline struct kgsl_mem_entry * __must_check
kgsl_sharedmem_find(struct kgsl_process_private *private, uint64_t gpuaddr)
{
	return kgsl_sharedmem_find_region(private, gpuaddr, 1);
}

static int
kgsl_sharedmem_region_empty(struct kgsl_process_private *private,
	uint64_t gpuaddr, uint64_t size,
	struct kgsl_mem_entry **collision_entry)
{
	int result = 1;
	uint64_t gpuaddr_end = gpuaddr + size;

	struct rb_node *node;

	assert_spin_locked(&private->mem_lock);

	if (!kgsl_mmu_gpuaddr_in_range(private->pagetable, gpuaddr))
		return 0;

	
	if (gpuaddr_end < gpuaddr)
		return 0;

	node = private->mem_rb.rb_node;
	while (node != NULL) {
		struct kgsl_mem_entry *entry;
		uint64_t memdesc_start, memdesc_end;

		entry = rb_entry(node, struct kgsl_mem_entry, node);

		memdesc_start = entry->memdesc.gpuaddr;
		memdesc_end = memdesc_start
				+ kgsl_memdesc_mmapsize(&entry->memdesc);

		if (gpuaddr_end <= memdesc_start)
			node = node->rb_left;
		else if (memdesc_end <= gpuaddr)
			node = node->rb_right;
		else {
			if (collision_entry)
				*collision_entry = entry;
			result = 0;
			break;
		}
	}
	return result;
}

struct kgsl_mem_entry * __must_check
kgsl_sharedmem_find_id(struct kgsl_process_private *process, unsigned int id)
{
	int result = 0;
	struct kgsl_mem_entry *entry;

	spin_lock(&process->mem_lock);
	entry = idr_find(&process->mem_idr, id);
	if (entry)
		result = kgsl_mem_entry_get(entry);
	spin_unlock(&process->mem_lock);

	if (!result)
		return NULL;
	return entry;
}

static inline void kgsl_mem_entry_unset_pend(struct kgsl_mem_entry *entry)
{
	if (entry == NULL)
		return;
	spin_lock(&entry->priv->mem_lock);
	entry->pending_free = 0;
	spin_unlock(&entry->priv->mem_lock);
}

static inline bool kgsl_mem_entry_set_pend(struct kgsl_mem_entry *entry)
{
	bool ret = false;

	if (entry == NULL)
		return false;

	spin_lock(&entry->priv->mem_lock);
	if (!entry->pending_free) {
		entry->pending_free = 1;
		ret = true;
	}
	spin_unlock(&entry->priv->mem_lock);
	return ret;
}

long kgsl_ioctl_device_getproperty(struct kgsl_device_private *dev_priv,
					  unsigned int cmd, void *data)
{
	int result = 0;
	struct kgsl_device_getproperty *param = data;

	switch (param->type) {
	case KGSL_PROP_VERSION:
	{
		struct kgsl_version version;
		if (param->sizebytes != sizeof(version)) {
			result = -EINVAL;
			break;
		}

		version.drv_major = KGSL_VERSION_MAJOR;
		version.drv_minor = KGSL_VERSION_MINOR;
		version.dev_major = dev_priv->device->ver_major;
		version.dev_minor = dev_priv->device->ver_minor;

		if (copy_to_user(param->value, &version, sizeof(version)))
			result = -EFAULT;

		break;
	}
	case KGSL_PROP_GPU_RESET_STAT:
	{
		
		uint32_t id;
		struct kgsl_context *context;

		if (param->sizebytes != sizeof(unsigned int)) {
			result = -EINVAL;
			break;
		}
		
		if (copy_from_user(&id, param->value,
			sizeof(unsigned int))) {
			result = -EFAULT;
			break;
		}
		context = kgsl_context_get_owner(dev_priv, id);
		if (!context) {
			result = -EINVAL;
			break;
		}
		if (copy_to_user(param->value, &(context->reset_status),
			sizeof(unsigned int)))
			result = -EFAULT;
		else {
			
			context->reset_status = KGSL_CTX_STAT_NO_ERROR;
		}

		kgsl_context_put(context);
		break;
	}
	default:
		if (is_compat_task())
			result = dev_priv->device->ftbl->getproperty_compat(
					dev_priv->device, param->type,
					param->value, param->sizebytes);
		else
			result = dev_priv->device->ftbl->getproperty(
					dev_priv->device, param->type,
					param->value, param->sizebytes);
	}


	return result;
}

long kgsl_ioctl_device_setproperty(struct kgsl_device_private *dev_priv,
					  unsigned int cmd, void *data)
{
	int result = 0;
	
	struct kgsl_device_getproperty *param = data;

	
	if (is_compat_task())
		result = dev_priv->device->ftbl->setproperty_compat(
			dev_priv, param->type, param->value,
			param->sizebytes);
	else if (dev_priv->device->ftbl->setproperty)
		result = dev_priv->device->ftbl->setproperty(
			dev_priv, param->type, param->value,
			param->sizebytes);

	return result;
}

long kgsl_ioctl_device_waittimestamp_ctxtid(
		struct kgsl_device_private *dev_priv, unsigned int cmd,
		void *data)
{
	struct kgsl_device_waittimestamp_ctxtid *param = data;
	struct kgsl_device *device = dev_priv->device;
	long result = -EINVAL;
	unsigned int temp_cur_ts = 0;
	struct kgsl_context *context;

	context = kgsl_context_get_owner(dev_priv, param->context_id);
	if (context == NULL)
		return result;

	kgsl_readtimestamp(device, context, KGSL_TIMESTAMP_RETIRED,
		&temp_cur_ts);

	trace_kgsl_waittimestamp_entry(device, context->id, temp_cur_ts,
		param->timestamp, param->timeout);

	result = device->ftbl->waittimestamp(device, context, param->timestamp,
		param->timeout);

	kgsl_readtimestamp(device, context, KGSL_TIMESTAMP_RETIRED,
		&temp_cur_ts);
	trace_kgsl_waittimestamp_exit(device, temp_cur_ts, result);

	kgsl_context_put(context);

	return result;
}

long kgsl_ioctl_rb_issueibcmds(struct kgsl_device_private *dev_priv,
				      unsigned int cmd, void *data)
{
	struct kgsl_ringbuffer_issueibcmds *param = data;
	struct kgsl_device *device = dev_priv->device;
	struct kgsl_context *context;
	struct kgsl_cmdbatch *cmdbatch = NULL;
	long result = -EINVAL;

	
	if ((param->flags & (KGSL_CMDBATCH_SYNC | KGSL_CMDBATCH_MARKER)))
		return -EINVAL;

	
	context = kgsl_context_get_owner(dev_priv, param->drawctxt_id);
	if (context == NULL)
		return -EINVAL;

	
	cmdbatch = kgsl_cmdbatch_create(device, context, param->flags);
	if (IS_ERR(cmdbatch)) {
		result = PTR_ERR(cmdbatch);
		goto done;
	}

	if (param->flags & KGSL_CMDBATCH_SUBMIT_IB_LIST) {
		
		if (param->numibs == 0 || param->numibs > KGSL_MAX_NUMIBS) {
			result = -EINVAL;
			goto done;
		}
		result = kgsl_cmdbatch_add_ibdesc_list(device, cmdbatch,
			(void __user *) param->ibdesc_addr,
			param->numibs);
	} else {
		struct kgsl_ibdesc ibdesc;
		

		ibdesc.gpuaddr = param->ibdesc_addr;
		ibdesc.sizedwords = param->numibs;
		ibdesc.ctrl = 0;

		result = kgsl_cmdbatch_add_ibdesc(device, cmdbatch, &ibdesc);
	}

	if (result)
		goto done;

	result = dev_priv->device->ftbl->issueibcmds(dev_priv, context,
		cmdbatch, &param->timestamp);

done:
	if (result && result != -EPROTO)
		kgsl_cmdbatch_destroy(cmdbatch);

	kgsl_context_put(context);
	return result;
}

long kgsl_ioctl_submit_commands(struct kgsl_device_private *dev_priv,
				      unsigned int cmd, void *data)
{
	struct kgsl_submit_commands *param = data;
	struct kgsl_device *device = dev_priv->device;
	struct kgsl_context *context;
	struct kgsl_cmdbatch *cmdbatch = NULL;
	long result = -EINVAL;


	if ((param->flags & KGSL_CMDBATCH_SYNC) && param->numcmds)
		KGSL_DEV_ERR_ONCE(device,
			"Commands specified with the SYNC flag.  They will be ignored\n");
	else if (param->numcmds > KGSL_MAX_NUMIBS)
		return -EINVAL;
	else if (!(param->flags & KGSL_CMDBATCH_SYNC) && param->numcmds == 0)
		param->flags |= KGSL_CMDBATCH_MARKER;

	
	if (param->numsyncs > KGSL_MAX_NUMIBS)
		return -EINVAL;

	context = kgsl_context_get_owner(dev_priv, param->context_id);
	if (context == NULL)
		return -EINVAL;

	
	cmdbatch = kgsl_cmdbatch_create(device, context, param->flags);
	if (IS_ERR(cmdbatch)) {
		result = PTR_ERR(cmdbatch);
		goto done;
	}

	result = kgsl_cmdbatch_add_ibdesc_list(device, cmdbatch,
		param->cmdlist, param->numcmds);
	if (result)
		goto done;

	result = kgsl_cmdbatch_add_syncpoints(device, cmdbatch,
		param->synclist, param->numsyncs);
	if (result)
		goto done;

	
	if (cmdbatch->profiling_buf_entry == NULL)
		cmdbatch->flags &= ~KGSL_CMDBATCH_PROFILING;

	result = dev_priv->device->ftbl->issueibcmds(dev_priv, context,
		cmdbatch, &param->timestamp);

done:
	if (result && result != -EPROTO)
		kgsl_cmdbatch_destroy(cmdbatch);

	kgsl_context_put(context);
	return result;
}

long kgsl_ioctl_gpu_command(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data)
{
	struct kgsl_gpu_command *param = data;
	struct kgsl_device *device = dev_priv->device;
	struct kgsl_context *context;
	struct kgsl_cmdbatch *cmdbatch = NULL;

	long result = -EINVAL;

	if ((param->flags & KGSL_CMDBATCH_SYNC) && param->numcmds)
		KGSL_DEV_ERR_ONCE(device,
			"Commands specified with the SYNC flag.  They will be ignored\n");
	else if (!(param->flags & KGSL_CMDBATCH_SYNC) && param->numcmds == 0)
		param->flags |= KGSL_CMDBATCH_MARKER;

	
	if (param->numcmds > KGSL_MAX_NUMIBS ||
		param->numobjs > KGSL_MAX_NUMIBS ||
		param->numsyncs > KGSL_MAX_NUMIBS)
		return -EINVAL;

	context = kgsl_context_get_owner(dev_priv, param->context_id);
	if (context == NULL)
		return -EINVAL;

	cmdbatch = kgsl_cmdbatch_create(device, context, param->flags);
	if (IS_ERR(cmdbatch)) {
		result = PTR_ERR(cmdbatch);
		goto done;
	}

	result = kgsl_cmdbatch_add_cmdlist(device, cmdbatch,
		(void __user *) (uintptr_t) param->cmdlist,
		param->cmdsize, param->numcmds);
	if (result)
		goto done;

	result = kgsl_cmdbatch_add_memlist(device, cmdbatch,
		(void __user *) (uintptr_t) param->objlist,
		param->objsize, param->numobjs);
	if (result)
		goto done;

	result = kgsl_cmdbatch_add_synclist(device, cmdbatch,
		(void __user *) (uintptr_t) param->synclist,
		param->syncsize, param->numsyncs);
	if (result)
		goto done;

	
	if (cmdbatch->profiling_buf_entry == NULL)
		cmdbatch->flags &= ~KGSL_CMDBATCH_PROFILING;

	result = dev_priv->device->ftbl->issueibcmds(dev_priv, context,
		cmdbatch, &param->timestamp);

done:
	if (result && result != -EPROTO)
		kgsl_cmdbatch_destroy(cmdbatch);

	kgsl_context_put(context);
	return result;
}

long kgsl_ioctl_cmdstream_readtimestamp_ctxtid(struct kgsl_device_private
						*dev_priv, unsigned int cmd,
						void *data)
{
	struct kgsl_cmdstream_readtimestamp_ctxtid *param = data;
	struct kgsl_device *device = dev_priv->device;
	struct kgsl_context *context;
	long result = -EINVAL;

	mutex_lock(&device->mutex);
	context = kgsl_context_get_owner(dev_priv, param->context_id);

	if (context) {
		result = kgsl_readtimestamp(device, context,
			param->type, &param->timestamp);

		trace_kgsl_readtimestamp(device, context->id,
			param->type, param->timestamp);
	}

	kgsl_context_put(context);
	mutex_unlock(&device->mutex);
	return result;
}

long kgsl_ioctl_drawctxt_create(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data)
{
	int result = 0;
	struct kgsl_drawctxt_create *param = data;
	struct kgsl_context *context = NULL;
	struct kgsl_device *device = dev_priv->device;

	context = device->ftbl->drawctxt_create(dev_priv, &param->flags);
	if (IS_ERR(context)) {
		result = PTR_ERR(context);
		goto done;
	}
	trace_kgsl_context_create(dev_priv->device, context, param->flags);
	param->drawctxt_id = context->id;
done:
	return result;
}

long kgsl_ioctl_drawctxt_destroy(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data)
{
	struct kgsl_drawctxt_destroy *param = data;
	struct kgsl_context *context;

	context = kgsl_context_get_owner(dev_priv, param->drawctxt_id);
	if (context == NULL)
		return -EINVAL;

	kgsl_context_detach(context);
	kgsl_context_put(context);

	return 0;
}

static long gpumem_free_entry(struct kgsl_mem_entry *entry)
{
	if (!kgsl_mem_entry_set_pend(entry))
		return -EBUSY;

	trace_kgsl_mem_free(entry);

	kgsl_memfree_add(entry->priv->pid, entry->memdesc.gpuaddr,
		entry->memdesc.size, entry->memdesc.flags);

	kgsl_mem_entry_put(entry);

	return 0;
}

static void gpumem_free_func(struct kgsl_device *device,
		struct kgsl_event_group *group, void *priv, int ret)
{
	struct kgsl_context *context = group->context;
	struct kgsl_mem_entry *entry = priv;
	unsigned int timestamp;

	kgsl_readtimestamp(device, context, KGSL_TIMESTAMP_RETIRED, &timestamp);

	
	trace_kgsl_mem_timestamp_free(device, entry, KGSL_CONTEXT_ID(context),
		timestamp, 0);
	kgsl_mem_entry_put(entry);
}

static long gpumem_free_entry_on_timestamp(struct kgsl_device *device,
		struct kgsl_mem_entry *entry,
		struct kgsl_context *context, unsigned int timestamp)
{
	int ret;
	unsigned int temp;

	if (!kgsl_mem_entry_set_pend(entry))
		return -EBUSY;

	kgsl_readtimestamp(device, context, KGSL_TIMESTAMP_RETIRED, &temp);
	trace_kgsl_mem_timestamp_queue(device, entry, context->id, temp,
		timestamp);
	ret = kgsl_add_event(device, &context->events,
		timestamp, gpumem_free_func, entry);

	if (ret)
		kgsl_mem_entry_unset_pend(entry);

	return ret;
}

long kgsl_ioctl_sharedmem_free(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data)
{
	struct kgsl_sharedmem_free *param = data;
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_mem_entry *entry;
	long ret;

	entry = kgsl_sharedmem_find(private, (uint64_t) param->gpuaddr);
	if (entry == NULL) {
		KGSL_MEM_INFO(dev_priv->device,
			"Invalid GPU address 0x%016llx\n",
			(uint64_t) param->gpuaddr);
		return -EINVAL;
	}

	ret = gpumem_free_entry(entry);
	kgsl_mem_entry_put(entry);

	return ret;
}

long kgsl_ioctl_gpumem_free_id(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data)
{
	struct kgsl_gpumem_free_id *param = data;
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_mem_entry *entry;
	long ret;

	entry = kgsl_sharedmem_find_id(private, param->id);
	if (entry == NULL) {
		KGSL_MEM_INFO(dev_priv->device,
			"Invalid GPU memory object ID %d\n", param->id);
		return -EINVAL;
	}

	ret = gpumem_free_entry(entry);
	kgsl_mem_entry_put(entry);

	return ret;
}

static long gpuobj_free_on_timestamp(struct kgsl_device_private *dev_priv,
		struct kgsl_mem_entry *entry, struct kgsl_gpuobj_free *param)
{
	struct kgsl_gpu_event_timestamp event;
	struct kgsl_context *context;
	long ret;

	memset(&event, 0, sizeof(event));

	ret = _copy_from_user(&event, (void __user *) (uintptr_t) param->priv,
		sizeof(event), param->len);
	if (ret)
		return ret;

	if (event.context_id == 0)
		return -EINVAL;

	context = kgsl_context_get_owner(dev_priv, event.context_id);
	if (context == NULL)
		return -EINVAL;

	ret = gpumem_free_entry_on_timestamp(dev_priv->device, entry, context,
		event.timestamp);

	kgsl_context_put(context);
	return ret;
}

static void gpuobj_free_fence_func(void *priv)
{
	struct kgsl_mem_entry *entry = priv;
	kgsl_mem_entry_put(entry);
}

static long gpuobj_free_on_fence(struct kgsl_device_private *dev_priv,
		struct kgsl_mem_entry *entry, struct kgsl_gpuobj_free *param)
{
	struct kgsl_sync_fence_waiter *handle;
	struct kgsl_gpu_event_fence event;
	long ret;

	memset(&event, 0, sizeof(event));

	ret = _copy_from_user(&event, (void __user *) (uintptr_t) param->priv,
		sizeof(event), param->len);
	if (ret)
		return ret;

	if (event.fd < 0)
		return -EINVAL;

	handle = kgsl_sync_fence_async_wait(event.fd,
		gpuobj_free_fence_func, entry);

	
	if (handle == NULL)
		return gpumem_free_entry(entry);

	return IS_ERR(handle) ? PTR_ERR(handle) : 0;
}

long kgsl_ioctl_gpuobj_free(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data)
{
	struct kgsl_gpuobj_free *param = data;
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_mem_entry *entry;
	long ret;

	entry = kgsl_sharedmem_find_id(private, param->id);
	if (entry == NULL) {
		KGSL_MEM_ERR(dev_priv->device,
			"Invalid GPU memory object ID %d\n", param->id);
		return -EINVAL;
	}

	
	if (!(param->flags & KGSL_GPUOBJ_FREE_ON_EVENT))
		ret = gpumem_free_entry(entry);
	else if (param->type == KGSL_GPU_EVENT_TIMESTAMP)
		ret = gpuobj_free_on_timestamp(dev_priv, entry, param);
	else if (param->type == KGSL_GPU_EVENT_FENCE)
		ret = gpuobj_free_on_fence(dev_priv, entry, param);
	else
		ret = -EINVAL;

	kgsl_mem_entry_put(entry);
	return ret;
}

long kgsl_ioctl_cmdstream_freememontimestamp_ctxtid(
		struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data)
{
	struct kgsl_cmdstream_freememontimestamp_ctxtid *param = data;
	struct kgsl_context *context = NULL;
	struct kgsl_mem_entry *entry;
	long ret = -EINVAL;

	if (param->type != KGSL_TIMESTAMP_RETIRED)
		return -EINVAL;

	context = kgsl_context_get_owner(dev_priv, param->context_id);
	if (context == NULL)
		return -EINVAL;

	entry = kgsl_sharedmem_find(dev_priv->process_priv,
		(uint64_t) param->gpuaddr);
	if (entry == NULL) {
		KGSL_MEM_ERR(dev_priv->device,
			"Invalid GPU address 0x%016llx\n",
			(uint64_t) param->gpuaddr);
		goto out;
	}

	ret = gpumem_free_entry_on_timestamp(dev_priv->device, entry,
		context, param->timestamp);

	kgsl_mem_entry_put(entry);
out:
	kgsl_context_put(context);

	return ret;
}

static inline int _check_region(unsigned long start, unsigned long size,
				uint64_t len)
{
	uint64_t end = ((uint64_t) start) + size;
	return (end > len);
}

static int check_vma(struct vm_area_struct *vma, struct file *vmfile,
		struct kgsl_memdesc *memdesc)
{
	if (vma == NULL || vma->vm_file != vmfile)
		return -EINVAL;

	
	if (memdesc->size == 0)
		memdesc->size = vma->vm_end - vma->vm_start;
	
	if (vma->vm_start != memdesc->useraddr ||
		(memdesc->useraddr + memdesc->size) != vma->vm_end)
		return -EINVAL;
	return 0;
}

static int memdesc_sg_virt(struct kgsl_memdesc *memdesc, struct file *vmfile)
{
	int ret = 0;
	long npages = 0, i;
	size_t sglen = (size_t) (memdesc->size / PAGE_SIZE);
	struct page **pages = NULL;
	int write = (memdesc->flags & KGSL_MEMFLAGS_GPUREADONLY) != 0;

	if (sglen == 0 || sglen >= LONG_MAX)
		return -EINVAL;

	pages = kgsl_malloc(sglen * sizeof(struct page *));
	if (pages == NULL)
		return -ENOMEM;

	memdesc->sgt = kmalloc(sizeof(struct sg_table), GFP_KERNEL);
	if (memdesc->sgt == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	down_read(&current->mm->mmap_sem);
	
	if (vmfile != NULL)
		ret = check_vma(find_vma(current->mm, memdesc->useraddr),
				vmfile, memdesc);

	if (ret == 0) {
		npages = get_user_pages(current, current->mm, memdesc->useraddr,
					sglen, write, 0, pages, NULL);
		ret = (npages < 0) ? (int)npages : 0;
	}
	up_read(&current->mm->mmap_sem);

	if (ret)
		goto out;

	if ((unsigned long) npages != sglen) {
		ret = -EINVAL;
		goto out;
	}

	ret = sg_alloc_table_from_pages(memdesc->sgt, pages, npages,
					0, memdesc->size, GFP_KERNEL);
out:
	if (ret) {
		for (i = 0; i < npages; i++)
			put_page(pages[i]);

		kfree(memdesc->sgt);
		memdesc->sgt = NULL;
	}
	kgsl_free(pages);
	return ret;
}

static int kgsl_setup_anon_useraddr(struct kgsl_pagetable *pagetable,
	struct kgsl_mem_entry *entry, unsigned long hostptr,
	size_t offset, size_t size)
{
	

	if (size == 0 || offset != 0 ||
		!IS_ALIGNED(size, PAGE_SIZE))
		return -EINVAL;

	entry->memdesc.pagetable = pagetable;
	entry->memdesc.size = (uint64_t) size;
	entry->memdesc.mmapsize = (uint64_t) size;
	entry->memdesc.useraddr = hostptr;
	if (kgsl_memdesc_use_cpu_map(&entry->memdesc))
		entry->memdesc.gpuaddr = (uint64_t)  entry->memdesc.useraddr;
	entry->memdesc.flags |= KGSL_MEMFLAGS_USERMEM_ADDR;

	return memdesc_sg_virt(&entry->memdesc, NULL);
}

static int match_file(const void *p, struct file *file, unsigned int fd)
{
	return (p == file) ? (fd + 1) : 0;
}

static void _setup_cache_mode(struct kgsl_mem_entry *entry,
		struct vm_area_struct *vma)
{
	unsigned int mode;
	pgprot_t pgprot = vma->vm_page_prot;

	if (pgprot == pgprot_noncached(pgprot))
		mode = KGSL_CACHEMODE_UNCACHED;
	else if (pgprot == pgprot_writecombine(pgprot))
		mode = KGSL_CACHEMODE_WRITECOMBINE;
	else
		mode = KGSL_CACHEMODE_WRITEBACK;

	entry->memdesc.flags |= (mode << KGSL_CACHEMODE_SHIFT);
}

#ifdef CONFIG_DMA_SHARED_BUFFER
static int kgsl_setup_dma_buf(struct kgsl_device *device,
				struct kgsl_pagetable *pagetable,
				struct kgsl_mem_entry *entry,
				struct dma_buf *dmabuf);

static int kgsl_setup_dmabuf_useraddr(struct kgsl_device *device,
		struct kgsl_pagetable *pagetable,
		struct kgsl_mem_entry *entry, unsigned long hostptr)
{
	struct vm_area_struct *vma;
	struct dma_buf *dmabuf = NULL;
	int ret;

	down_read(&current->mm->mmap_sem);
	vma = find_vma(current->mm, hostptr);

	if (vma && vma->vm_file) {
		int fd;

		if (vma->vm_file->f_op == &kgsl_fops) {
			up_read(&current->mm->mmap_sem);
			return -EFAULT;
		}

		
		fd = iterate_fd(current->files, 0, match_file, vma->vm_file);
		if (fd != 0)
			dmabuf = dma_buf_get(fd - 1);
	}
	up_read(&current->mm->mmap_sem);

	if (dmabuf == NULL)
		return -ENODEV;

	ret = kgsl_setup_dma_buf(device, pagetable, entry, dmabuf);
	if (ret) {
		dma_buf_put(dmabuf);
		return ret;
	}

	
	entry->memdesc.useraddr = hostptr;
	_setup_cache_mode(entry, vma);

	return 0;
}
#else
static int kgsl_setup_dmabuf_useraddr(struct kgsl_device *device,
		struct kgsl_pagetable *pagetable,
		struct kgsl_mem_entry *entry, unsigned long hostptr)
{
	return -ENODEV;
}
#endif

static int kgsl_setup_useraddr(struct kgsl_device *device,
		struct kgsl_pagetable *pagetable,
		struct kgsl_mem_entry *entry,
		unsigned long hostptr, size_t offset, size_t size)
{
	int ret;

	if (hostptr == 0 || !IS_ALIGNED(hostptr, PAGE_SIZE))
		return -EINVAL;

	
	ret = kgsl_setup_dmabuf_useraddr(device, pagetable, entry, hostptr);
	if (ret != -ENODEV)
		return ret;

	
	return kgsl_setup_anon_useraddr(pagetable, entry,
		hostptr, offset, size);
}

static long _gpuobj_map_useraddr(struct kgsl_device *device,
		struct kgsl_pagetable *pagetable,
		struct kgsl_mem_entry *entry,
		struct kgsl_gpuobj_import *param)
{
	struct kgsl_gpuobj_import_useraddr useraddr;
	int ret;

	param->flags &= KGSL_MEMFLAGS_GPUREADONLY
		| KGSL_CACHEMODE_MASK
		| KGSL_MEMTYPE_MASK;

	
	if (param->flags & KGSL_MEMFLAGS_SECURE)
		return -ENOTSUPP;

	ret = _copy_from_user(&useraddr,
		(void __user *) (uintptr_t) param->priv, sizeof(useraddr),
		param->priv_len);
	if (ret)
		return ret;

	
	if (useraddr.virtaddr > ULONG_MAX)
		return -EINVAL;

	return kgsl_setup_useraddr(device, pagetable, entry,
		(unsigned long) useraddr.virtaddr, 0, 0);
}

#ifdef CONFIG_DMA_SHARED_BUFFER
static long _gpuobj_map_dma_buf(struct kgsl_device *device,
		struct kgsl_pagetable *pagetable,
		struct kgsl_mem_entry *entry,
		struct kgsl_gpuobj_import *param,
		int *fd)
{
	struct kgsl_gpuobj_import_dma_buf buf;
	struct dma_buf *dmabuf;
	int ret;

	if (entry->memdesc.flags & KGSL_MEMFLAGS_SECURE) {
		if (!kgsl_mmu_is_secured(&device->mmu)) {
			dev_WARN_ONCE(device->dev, 1,
				"Secure buffer not supported");
			return -ENOTSUPP;
		}

		entry->memdesc.priv |= KGSL_MEMDESC_SECURE;
	}

	ret = _copy_from_user(&buf, (void __user *) (uintptr_t) param->priv,
			sizeof(buf), param->priv_len);
	if (ret)
		return ret;

	if (buf.fd == 0)
		return -EINVAL;

	*fd = buf.fd;
	dmabuf = dma_buf_get(buf.fd);

	if (IS_ERR_OR_NULL(dmabuf))
		return (dmabuf == NULL) ? -EINVAL : PTR_ERR(dmabuf);

	ret = kgsl_setup_dma_buf(device, pagetable, entry, dmabuf);
	if (ret)
		dma_buf_put(dmabuf);

	return ret;
}
#else
static long _gpuobj_map_dma_buf(struct kgsl_device *device,
		struct kgsl_pagetable *pagetable,
		struct kgsl_mem_entry *entry,
		struct kgsl_gpuobj_import *param,
		int *fd)
{
	return -EINVAL;
}
#endif

long kgsl_ioctl_gpuobj_import(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data)
{
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_gpuobj_import *param = data;
	struct kgsl_mem_entry *entry;
	int ret, fd = -1;

	entry = kgsl_mem_entry_create();
	if (entry == NULL)
		return -ENOMEM;

	param->flags &= KGSL_MEMFLAGS_GPUREADONLY
			| KGSL_MEMTYPE_MASK
			| KGSL_MEMALIGN_MASK
			| KGSL_MEMFLAGS_USE_CPU_MAP
			| KGSL_MEMFLAGS_SECURE;

	entry->memdesc.flags = param->flags;

	if (param->type == KGSL_USER_MEM_TYPE_ADDR)
		ret = _gpuobj_map_useraddr(dev_priv->device, private->pagetable,
			entry, param);
	else if (param->type == KGSL_USER_MEM_TYPE_DMABUF)
		ret = _gpuobj_map_dma_buf(dev_priv->device, private->pagetable,
			entry, param, &fd);
	else
		ret = -ENOTSUPP;

	if (ret)
		goto out;

	if (entry->memdesc.size >= SZ_1M)
		kgsl_memdesc_set_align(&entry->memdesc, ilog2(SZ_1M));
	else if (entry->memdesc.size >= SZ_64K)
		kgsl_memdesc_set_align(&entry->memdesc, ilog2(SZ_64K));

	param->flags = entry->memdesc.flags;

	ret = kgsl_mem_entry_attach_process(entry, dev_priv);
	if (ret)
		goto unmap;

	param->id = entry->id;

	KGSL_STATS_ADD(entry->memdesc.size, kgsl_driver.stats.mapped,
		kgsl_driver.stats.mapped_max);

	kgsl_process_add_stats(private,
		kgsl_memdesc_usermem_type(&entry->memdesc),
		entry->memdesc.size);

	trace_kgsl_mem_map(entry, fd);

	return 0;

unmap:
	if (param->type == KGSL_USER_MEM_TYPE_DMABUF)
		kgsl_destroy_ion(entry->priv_data);

	kgsl_sharedmem_free(&entry->memdesc);

out:
	kfree(entry);
	return ret;
}

static long _map_usermem_addr(struct kgsl_device *device,
		struct kgsl_pagetable *pagetable, struct kgsl_mem_entry *entry,
		unsigned long hostptr, size_t offset, size_t size)
{
	if (!kgsl_mmu_enabled()) {
		KGSL_DRV_ERR(device,
			"Cannot map paged memory with the MMU disabled\n");
		return -EINVAL;
	}

	
	if (entry->memdesc.flags & KGSL_MEMFLAGS_SECURE)
		return -EINVAL;

	return kgsl_setup_useraddr(device, pagetable, entry, hostptr,
		offset, size);
}

#ifdef CONFIG_DMA_SHARED_BUFFER
static int _map_usermem_dma_buf(struct kgsl_device *device,
		struct kgsl_pagetable *pagetable,
		struct kgsl_mem_entry *entry,
		unsigned int fd)
{
	int ret;
	struct dma_buf *dmabuf;


	if (entry->memdesc.flags & KGSL_MEMFLAGS_SECURE) {
		if (!kgsl_mmu_is_secured(&device->mmu)) {
			dev_WARN_ONCE(device->dev, 1,
				"Secure buffer not supported");
			return -EINVAL;
		}

		entry->memdesc.priv |= KGSL_MEMDESC_SECURE;
	}

	dmabuf = dma_buf_get(fd);
	if (IS_ERR_OR_NULL(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		return ret ? ret : -EINVAL;
	}
	ret = kgsl_setup_dma_buf(device, pagetable, entry, dmabuf);
	if (ret)
		dma_buf_put(dmabuf);
	return ret;
}
#else
static int _map_usermem_dma_buf(struct kgsl_device *device,
		struct kgsl_pagetable *pagetable,
		struct kgsl_mem_entry *entry,
		unsigned int fd)
{
	return -EINVAL;
}
#endif

#ifdef CONFIG_DMA_SHARED_BUFFER
static int kgsl_setup_dma_buf(struct kgsl_device *device,
				struct kgsl_pagetable *pagetable,
				struct kgsl_mem_entry *entry,
				struct dma_buf *dmabuf)
{
	int ret = 0;
	struct scatterlist *s;
	struct sg_table *sg_table;
	struct dma_buf_attachment *attach = NULL;
	struct kgsl_dma_buf_meta *meta;

	meta = kzalloc(sizeof(*meta), GFP_KERNEL);
	if (!meta)
		return -ENOMEM;

	attach = dma_buf_attach(dmabuf, device->dev);
	if (IS_ERR_OR_NULL(attach)) {
		ret = attach ? PTR_ERR(attach) : -EINVAL;
		goto out;
	}

	meta->dmabuf = dmabuf;
	meta->attach = attach;

	entry->priv_data = meta;
	entry->memdesc.pagetable = pagetable;
	entry->memdesc.size = 0;
	entry->memdesc.mmapsize = 0;
	
	entry->memdesc.flags &= ~KGSL_MEMFLAGS_USE_CPU_MAP;
	entry->memdesc.flags |= KGSL_MEMFLAGS_USERMEM_ION;

	sg_table = dma_buf_map_attachment(attach, DMA_TO_DEVICE);

	if (IS_ERR_OR_NULL(sg_table)) {
		ret = PTR_ERR(sg_table);
		goto out;
	}

	meta->table = sg_table;
	entry->priv_data = meta;
	entry->memdesc.sgt = sg_table;

	
	for (s = entry->memdesc.sgt->sgl; s != NULL; s = sg_next(s)) {
		int priv = (entry->memdesc.priv & KGSL_MEMDESC_SECURE) ? 1 : 0;


		if (PagePrivate(sg_page(s)) != priv) {
			ret = -EPERM;
			goto out;
		}

		entry->memdesc.size += (uint64_t) s->length;
	}

	entry->memdesc.size = PAGE_ALIGN(entry->memdesc.size);
	entry->memdesc.mmapsize = PAGE_ALIGN(entry->memdesc.size);

out:
	if (ret) {
		if (!IS_ERR_OR_NULL(attach))
			dma_buf_detach(dmabuf, attach);


		kfree(meta);
	}

	return ret;
}
#endif

long kgsl_ioctl_map_user_mem(struct kgsl_device_private *dev_priv,
				     unsigned int cmd, void *data)
{
	int result = -EINVAL;
	struct kgsl_map_user_mem *param = data;
	struct kgsl_mem_entry *entry = NULL;
	struct kgsl_process_private *private = dev_priv->process_priv;
	unsigned int memtype;


	if (param->flags & KGSL_MEMFLAGS_SECURE) {
		
		if (!kgsl_mmu_is_secured(&dev_priv->device->mmu)) {
			dev_WARN_ONCE(dev_priv->device->dev, 1,
				"Secure buffer not supported");
			return -EOPNOTSUPP;
		}

		
		if (param->flags & KGSL_MEMFLAGS_USE_CPU_MAP)
			return -EINVAL;
	}

	entry = kgsl_mem_entry_create();

	if (entry == NULL)
		return -ENOMEM;

	memtype = param->memtype + 1;

	param->flags &= KGSL_MEMFLAGS_GPUREADONLY
			| KGSL_MEMTYPE_MASK
			| KGSL_MEMALIGN_MASK
			| KGSL_MEMFLAGS_USE_CPU_MAP
			| KGSL_MEMFLAGS_SECURE;

	entry->memdesc.flags = param->flags;

	if (!kgsl_mmu_use_cpu_map(&dev_priv->device->mmu))
		entry->memdesc.flags &= ~KGSL_MEMFLAGS_USE_CPU_MAP;

	if (kgsl_mmu_get_mmutype() == KGSL_MMU_TYPE_IOMMU)
		entry->memdesc.priv |= KGSL_MEMDESC_GUARD_PAGE;

	if (param->flags & KGSL_MEMFLAGS_SECURE)
		entry->memdesc.priv |= KGSL_MEMDESC_SECURE;

	switch (memtype) {
	case KGSL_MEM_ENTRY_USER:
		result = _map_usermem_addr(dev_priv->device, private->pagetable,
			entry, param->hostptr, param->offset, param->len);
		break;
	case KGSL_MEM_ENTRY_ION:
		if (param->offset != 0)
			result = -EINVAL;
		else
			result = _map_usermem_dma_buf(dev_priv->device,
				private->pagetable, entry, param->fd);
		break;
	default:
		KGSL_CORE_ERR("Invalid memory type: %x\n", memtype);
		result = -EOPNOTSUPP;
		break;
	}

	if (result)
		goto error;

	if ((param->flags & KGSL_MEMFLAGS_SECURE) &&
		!IS_ALIGNED(entry->memdesc.size, SZ_1M)) {
			KGSL_DRV_ERR(dev_priv->device,
				"Secure buffer size %lld must be 1MB aligned",
				entry->memdesc.size);
		result = -EINVAL;
		goto error_attach;
	}

	if (entry->memdesc.size >= SZ_2M)
		kgsl_memdesc_set_align(&entry->memdesc, ilog2(SZ_2M));
	else if (entry->memdesc.size >= SZ_1M)
		kgsl_memdesc_set_align(&entry->memdesc, ilog2(SZ_1M));
	else if (entry->memdesc.size >= SZ_64K)
		kgsl_memdesc_set_align(&entry->memdesc, ilog2(SZ_64));

	
	param->flags = (unsigned int) entry->memdesc.flags;

	result = kgsl_mem_entry_attach_process(entry, dev_priv);
	if (result)
		goto error_attach;

	
	param->gpuaddr = (unsigned long)
		entry->memdesc.gpuaddr + (param->offset & PAGE_MASK);

	KGSL_STATS_ADD(param->len, kgsl_driver.stats.mapped,
		kgsl_driver.stats.mapped_max);

	kgsl_process_add_stats(private,
			kgsl_memdesc_usermem_type(&entry->memdesc), param->len);

	trace_kgsl_mem_map(entry, param->fd);

	return result;

error_attach:
	switch (memtype) {
	case KGSL_MEM_ENTRY_ION:
		kgsl_destroy_ion(entry->priv_data);
		entry->memdesc.sgt = NULL;
		break;
	default:
		break;
	}
	kgsl_sharedmem_free(&entry->memdesc);
error:
	
	param->gpuaddr = 0;

	kfree(entry);
	return result;
}

static int _kgsl_gpumem_sync_cache(struct kgsl_mem_entry *entry,
		uint64_t offset, uint64_t length, unsigned int op)
{
	int ret = 0;
	int cacheop;
	int mode;


	if ((op & KGSL_GPUMEM_CACHE_FLUSH) == KGSL_GPUMEM_CACHE_FLUSH)
		cacheop = KGSL_CACHE_OP_FLUSH;
	else if (op & KGSL_GPUMEM_CACHE_CLEAN)
		cacheop = KGSL_CACHE_OP_CLEAN;
	else if (op & KGSL_GPUMEM_CACHE_INV)
		cacheop = KGSL_CACHE_OP_INV;
	else {
		ret = -EINVAL;
		goto done;
	}

	if (!(op & KGSL_GPUMEM_CACHE_RANGE)) {
		offset = 0;
		length = entry->memdesc.size;
	}

	mode = kgsl_memdesc_get_cachemode(&entry->memdesc);
	if (mode != KGSL_CACHEMODE_UNCACHED
		&& mode != KGSL_CACHEMODE_WRITECOMBINE) {
		trace_kgsl_mem_sync_cache(entry, offset, length, op);
		ret = kgsl_cache_range_op(&entry->memdesc, offset,
					length, cacheop);
	}

done:
	return ret;
}


long kgsl_ioctl_gpumem_sync_cache(struct kgsl_device_private *dev_priv,
	unsigned int cmd, void *data)
{
	struct kgsl_gpumem_sync_cache *param = data;
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_mem_entry *entry = NULL;
	long ret;

	if (param->id != 0) {
		entry = kgsl_sharedmem_find_id(private, param->id);
		if (entry == NULL) {
			KGSL_MEM_INFO(dev_priv->device, "can't find id %d\n",
					param->id);
			return -EINVAL;
		}
	} else if (param->gpuaddr != 0) {
		entry = kgsl_sharedmem_find(private, (uint64_t) param->gpuaddr);
		if (entry == NULL) {
			KGSL_MEM_INFO(dev_priv->device,
					"can't find gpuaddr 0x%08lX\n",
					param->gpuaddr);
			return -EINVAL;
		}
	} else {
		return -EINVAL;
	}

	ret = _kgsl_gpumem_sync_cache(entry, (uint64_t) param->offset,
					(uint64_t) param->length, param->op);
	kgsl_mem_entry_put(entry);
	return ret;
}

static int mem_id_cmp(const void *_a, const void *_b)
{
	const unsigned int *a = _a, *b = _b;
	if (*a == *b)
		return 0;
	return (*a > *b) ? 1 : -1;
}

#ifdef CONFIG_ARM64
static inline bool check_full_flush(size_t size, int op)
{
	return false;
}
#else
static inline bool check_full_flush(size_t size, int op)
{
	
	return (kgsl_driver.full_cache_threshold != 0) &&
		(size >= kgsl_driver.full_cache_threshold) &&
		(op == KGSL_GPUMEM_CACHE_FLUSH);
}
#endif

long kgsl_ioctl_gpumem_sync_cache_bulk(struct kgsl_device_private *dev_priv,
	unsigned int cmd, void *data)
{
	int i;
	struct kgsl_gpumem_sync_cache_bulk *param = data;
	struct kgsl_process_private *private = dev_priv->process_priv;
	unsigned int id, last_id = 0, *id_list = NULL, actual_count = 0;
	struct kgsl_mem_entry **entries = NULL;
	long ret = 0;
	uint64_t op_size = 0;
	bool full_flush = false;

	if (param->id_list == NULL || param->count == 0
			|| param->count > (PAGE_SIZE / sizeof(unsigned int)))
		return -EINVAL;

	id_list = kzalloc(param->count * sizeof(unsigned int), GFP_KERNEL);
	if (id_list == NULL)
		return -ENOMEM;

	entries = kzalloc(param->count * sizeof(*entries), GFP_KERNEL);
	if (entries == NULL) {
		ret = -ENOMEM;
		goto end;
	}

	if (copy_from_user(id_list, param->id_list,
				param->count * sizeof(unsigned int))) {
		ret = -EFAULT;
		goto end;
	}
	
	sort(id_list, param->count, sizeof(*id_list), mem_id_cmp, NULL);

	for (i = 0; i < param->count; i++) {
		unsigned int cachemode;
		struct kgsl_mem_entry *entry = NULL;

		id = id_list[i];
		
		if (id == last_id)
			continue;

		entry = kgsl_sharedmem_find_id(private, id);
		if (entry == NULL)
			continue;

		
		cachemode = kgsl_memdesc_get_cachemode(&entry->memdesc);
		if (cachemode != KGSL_CACHEMODE_WRITETHROUGH &&
		    cachemode != KGSL_CACHEMODE_WRITEBACK) {
			kgsl_mem_entry_put(entry);
			continue;
		}

		op_size += entry->memdesc.size;
		entries[actual_count++] = entry;

		full_flush  = check_full_flush(op_size, param->op);
		if (full_flush)
			break;

		last_id = id;
	}
	if (full_flush) {
		trace_kgsl_mem_sync_full_cache(actual_count, op_size);
		flush_cache_all();
	}

	param->op &= ~KGSL_GPUMEM_CACHE_RANGE;

	for (i = 0; i < actual_count; i++) {
		if (!full_flush)
			_kgsl_gpumem_sync_cache(entries[i], 0,
						entries[i]->memdesc.size,
						param->op);
		kgsl_mem_entry_put(entries[i]);
	}
end:
	kfree(entries);
	kfree(id_list);
	return ret;
}


long kgsl_ioctl_sharedmem_flush_cache(struct kgsl_device_private *dev_priv,
				 unsigned int cmd, void *data)
{
	struct kgsl_sharedmem_free *param = data;
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_mem_entry *entry = NULL;
	long ret;

	entry = kgsl_sharedmem_find(private, (uint64_t) param->gpuaddr);
	if (entry == NULL) {
		KGSL_MEM_INFO(dev_priv->device,
				"can't find gpuaddr 0x%08lX\n",
				param->gpuaddr);
		return -EINVAL;
	}

	ret = _kgsl_gpumem_sync_cache(entry, 0, entry->memdesc.size,
					KGSL_GPUMEM_CACHE_FLUSH);
	kgsl_mem_entry_put(entry);
	return ret;
}

long kgsl_ioctl_gpuobj_sync(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data)
{
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_gpuobj_sync *param = data;
	struct kgsl_gpuobj_sync_obj *objs;
	struct kgsl_mem_entry **entries;
	long ret = 0;
	bool full_flush = false;
	uint64_t size = 0;
	int i, count = 0;
	void __user *ptr;

	if (param->count == 0 || param->count > 128)
		return -EINVAL;

	objs = kzalloc(param->count * sizeof(*objs), GFP_KERNEL);
	if (objs == NULL)
		return -ENOMEM;

	entries = kzalloc(param->count * sizeof(*entries), GFP_KERNEL);
	if (entries == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ptr = (void __user *) (uintptr_t) param->objs;

	for (i = 0; i < param->count; i++) {
		ret = _copy_from_user(&objs[i], ptr, sizeof(*objs),
			param->obj_len);
		if (ret)
			goto out;

		entries[i] = kgsl_sharedmem_find_id(private, objs[i].id);

		
		if (entries[i] == NULL)
			continue;

		count++;

		if (!(objs[i].op & KGSL_GPUMEM_CACHE_RANGE))
			size += entries[i]->memdesc.size;
		else if (objs[i].offset < entries[i]->memdesc.size)
			size += (entries[i]->memdesc.size - objs[i].offset);

		full_flush = check_full_flush(size, objs[i].op);
		if (full_flush)
			break;

		ptr += sizeof(*objs);
	}

	if (full_flush) {
		trace_kgsl_mem_sync_full_cache(count, size);
		flush_cache_all();
	} else {
		for (i = 0; !ret && i < param->count; i++)
			if (entries[i])
				ret = _kgsl_gpumem_sync_cache(entries[i],
						objs[i].offset, objs[i].length,
						objs[i].op);
	}

	for (i = 0; i < param->count; i++)
		if (entries[i])
			kgsl_mem_entry_put(entries[i]);

out:
	kfree(entries);
	kfree(objs);

	return ret;
}

#ifdef CONFIG_ARM64
uint64_t kgsl_filter_cachemode(uint64_t flags)
{
	if ((flags & KGSL_CACHEMODE_MASK) >> KGSL_CACHEMODE_SHIFT ==
					KGSL_CACHEMODE_WRITETHROUGH) {
		flags &= ~KGSL_CACHEMODE_MASK;
		flags |= (KGSL_CACHEMODE_WRITEBACK << KGSL_CACHEMODE_SHIFT) &
							KGSL_CACHEMODE_MASK;
	}
	return flags;
}
#else
uint64_t kgsl_filter_cachemode(uint64_t flags)
{
	return flags;
}
#endif

#define KGSL_MAX_ALIGN (32 * SZ_1M)

static struct kgsl_mem_entry *gpumem_alloc_entry(
		struct kgsl_device_private *dev_priv,
		uint64_t size, uint64_t mmapsize, uint64_t flags)
{
	int ret;
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_mem_entry *entry;
	unsigned int align;
	struct kgsl_memdesc *memdesc = NULL;

	flags &= KGSL_MEMFLAGS_GPUREADONLY
		| KGSL_CACHEMODE_MASK
		| KGSL_MEMTYPE_MASK
		| KGSL_MEMALIGN_MASK
		| KGSL_MEMFLAGS_USE_CPU_MAP
		| KGSL_MEMFLAGS_SECURE;

	
	if (!kgsl_mmu_use_cpu_map(&dev_priv->device->mmu))
		flags &= ~KGSL_MEMFLAGS_USE_CPU_MAP;

	
	if (!kgsl_mmu_is_secured(&dev_priv->device->mmu) &&
			(flags & KGSL_MEMFLAGS_SECURE)) {
		dev_WARN_ONCE(dev_priv->device->dev, 1,
				"Secure memory not supported");
		return ERR_PTR(-EOPNOTSUPP);
	}

	
	if ((flags & KGSL_MEMFLAGS_SECURE) &&
		(flags & KGSL_MEMFLAGS_USE_CPU_MAP))
		flags &= ~KGSL_MEMFLAGS_USE_CPU_MAP;

	
	align = MEMFLAGS(flags, KGSL_MEMALIGN_MASK, KGSL_MEMALIGN_SHIFT);
	if (align >= ilog2(KGSL_MAX_ALIGN)) {
		KGSL_CORE_ERR("Alignment too large; restricting to %dK\n",
			KGSL_MAX_ALIGN >> 10);

		flags &= ~KGSL_MEMALIGN_MASK;
		flags |= (ilog2(KGSL_MAX_ALIGN) << KGSL_MEMALIGN_SHIFT) &
			KGSL_MEMALIGN_MASK;
	}

	if (mmapsize < size)
		mmapsize = size;

	
	if (size > UINT_MAX)
		return ERR_PTR(-EINVAL);

	
	if (mmapsize > UINT_MAX)
		return ERR_PTR(-EINVAL);

	flags = kgsl_filter_cachemode(flags);

	entry = kgsl_mem_entry_create();
	memdesc = &entry->memdesc;
	if (entry == NULL)
		return ERR_PTR(-ENOMEM);

	if (kgsl_mmu_get_mmutype() == KGSL_MMU_TYPE_IOMMU)
		entry->memdesc.priv |= KGSL_MEMDESC_GUARD_PAGE;

	if (flags & KGSL_MEMFLAGS_SECURE)
		entry->memdesc.priv |= KGSL_MEMDESC_SECURE;

	memdesc->private = private;
	ret = kgsl_allocate_user(dev_priv->device, &entry->memdesc,
				private->pagetable, size, mmapsize, flags);
	if (ret != 0)
		goto err;

	ret = kgsl_mem_entry_attach_process(entry, dev_priv);
	if (ret != 0) {
		kgsl_sharedmem_free(&entry->memdesc);
		goto err;
	}

	kgsl_process_add_stats(private,
			kgsl_memdesc_usermem_type(&entry->memdesc),
			entry->memdesc.size);
	trace_kgsl_mem_alloc(entry);

	return entry;
err:
	kfree(entry);
	return ERR_PTR(ret);
}

long kgsl_ioctl_gpuobj_alloc(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data)
{
	struct kgsl_gpuobj_alloc *param = data;
	struct kgsl_mem_entry *entry;

	
	param->flags |= KGSL_MEMFLAGS_USE_CPU_MAP;

	entry = gpumem_alloc_entry(dev_priv, param->size,
		param->va_len, param->flags);

	if (IS_ERR(entry))
		return PTR_ERR(entry);

	param->size = entry->memdesc.size;
	param->flags = entry->memdesc.flags;
	param->mmapsize = kgsl_memdesc_mmapsize(&entry->memdesc);
	param->id = entry->id;

	return 0;
}

long kgsl_ioctl_gpumem_alloc(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data)
{
	struct kgsl_gpumem_alloc *param = data;
	struct kgsl_mem_entry *entry;
	uint64_t flags = param->flags;

	
	flags &= ~KGSL_MEMFLAGS_USE_CPU_MAP;

	entry = gpumem_alloc_entry(dev_priv, (uint64_t) param->size,
		(uint64_t) param->size, flags);

	if (IS_ERR(entry))
		return PTR_ERR(entry);

	param->gpuaddr = (unsigned long) entry->memdesc.gpuaddr;
	param->size = (size_t) entry->memdesc.size;
	param->flags = (unsigned int) entry->memdesc.flags;

	return 0;
}

long kgsl_ioctl_gpumem_alloc_id(struct kgsl_device_private *dev_priv,
			unsigned int cmd, void *data)
{
	struct kgsl_gpumem_alloc_id *param = data;
	struct kgsl_mem_entry *entry;
	uint64_t flags = param->flags;

	entry = gpumem_alloc_entry(dev_priv, (uint64_t) param->size,
		(uint64_t) param->mmapsize, flags);

	if (IS_ERR(entry))
		return PTR_ERR(entry);

	param->id = entry->id;
	param->flags = (unsigned int) entry->memdesc.flags;
	param->size = (size_t) entry->memdesc.size;
	param->mmapsize = (size_t)
		kgsl_memdesc_mmapsize(&entry->memdesc);
	param->gpuaddr = (unsigned long) entry->memdesc.gpuaddr;

	return 0;
}

long kgsl_ioctl_gpumem_get_info(struct kgsl_device_private *dev_priv,
			unsigned int cmd, void *data)
{
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_gpumem_get_info *param = data;
	struct kgsl_mem_entry *entry = NULL;
	int result = 0;

	if (param->id != 0) {
		entry = kgsl_sharedmem_find_id(private, param->id);
		if (entry == NULL)
			return -EINVAL;
	} else if (param->gpuaddr != 0) {
		entry = kgsl_sharedmem_find(private, (uint64_t) param->gpuaddr);
		if (entry == NULL)
			return -EINVAL;
	} else
		return -EINVAL;

	if (entry->memdesc.gpuaddr > ULONG_MAX)
		result = -ERANGE;

	param->gpuaddr = (unsigned long) entry->memdesc.gpuaddr;
	param->id = entry->id;
	param->flags = (unsigned int) entry->memdesc.flags;
	param->size = (size_t) entry->memdesc.size;
	param->mmapsize = (size_t) kgsl_memdesc_mmapsize(&entry->memdesc);
	param->useraddr = entry->memdesc.useraddr;

	kgsl_mem_entry_put(entry);
	return result;
}

long kgsl_ioctl_gpuobj_info(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data)
{
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_gpuobj_info *param = data;
	struct kgsl_mem_entry *entry;

	if (param->id == 0)
		return -EINVAL;

	entry = kgsl_sharedmem_find_id(private, param->id);
	if (entry == NULL)
		return -EINVAL;

	param->id = entry->id;
	param->gpuaddr = entry->memdesc.gpuaddr;
	param->flags = entry->memdesc.flags;
	param->size = entry->memdesc.size;
	param->va_len = kgsl_memdesc_mmapsize(&entry->memdesc);
	param->va_addr = (uint64_t) entry->memdesc.useraddr;

	kgsl_mem_entry_put(entry);
	return 0;
}

long kgsl_ioctl_cff_syncmem(struct kgsl_device_private *dev_priv,
					unsigned int cmd, void *data)
{
	struct kgsl_cff_syncmem *param = data;
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_mem_entry *entry = NULL;
	uint64_t offset;

	entry = kgsl_sharedmem_find_region(private, (uint64_t) param->gpuaddr,
		(uint64_t) param->len);
	if (entry == NULL)
		return -EINVAL;


	offset = ((uint64_t) param->gpuaddr) - entry->memdesc.gpuaddr;

	kgsl_cffdump_syncmem(dev_priv->device, entry, offset,
		(uint64_t) param->len, true);

	kgsl_mem_entry_put(entry);
	return 0;
}

long kgsl_ioctl_cff_sync_gpuobj(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data)
{
	struct kgsl_cff_sync_gpuobj *param = data;
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_mem_entry *entry = NULL;

	entry = kgsl_sharedmem_find_id(private, param->id);
	if (entry == NULL)
		return -EINVAL;

	kgsl_cffdump_syncmem(dev_priv->device, entry, param->offset,
		param->length, true);

	kgsl_mem_entry_put(entry);
	return 0;
}

long kgsl_ioctl_cff_user_event(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data)
{
	int result = 0;
	struct kgsl_cff_user_event *param = data;

	kgsl_cffdump_user_event(dev_priv->device, param->cff_opcode,
			param->op1, param->op2,
			param->op3, param->op4, param->op5);

	return result;
}


long kgsl_ioctl_timestamp_event(struct kgsl_device_private *dev_priv,
		unsigned int cmd, void *data)
{
	struct kgsl_timestamp_event *param = data;
	int ret;

	switch (param->type) {
	case KGSL_TIMESTAMP_EVENT_FENCE:
		ret = kgsl_add_fence_event(dev_priv->device,
			param->context_id, param->timestamp, param->priv,
			param->len, dev_priv);
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static int
kgsl_mmap_memstore(struct kgsl_device *device, struct vm_area_struct *vma)
{
	struct kgsl_memdesc *memdesc = &device->memstore;
	int result;
	unsigned int vma_size = vma->vm_end - vma->vm_start;

	

	if (vma->vm_flags & VM_WRITE)
		return -EPERM;

	if (memdesc->size  !=  vma_size) {
		KGSL_MEM_ERR(device, "memstore bad size: %d should be %llu\n",
			     vma_size, memdesc->size);
		return -EINVAL;
	}

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	result = remap_pfn_range(vma, vma->vm_start,
				device->memstore.physaddr >> PAGE_SHIFT,
				 vma_size, vma->vm_page_prot);
	if (result != 0)
		KGSL_MEM_ERR(device, "remap_pfn_range failed: %d\n",
			     result);

	return result;
}


static void kgsl_gpumem_vm_open(struct vm_area_struct *vma)
{
	struct kgsl_mem_entry *entry = vma->vm_private_data;
	if (!kgsl_mem_entry_get(entry))
		vma->vm_private_data = NULL;
}

static int
kgsl_gpumem_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct kgsl_mem_entry *entry = vma->vm_private_data;

	if (!entry)
		return VM_FAULT_SIGBUS;
	if (!entry->memdesc.ops || !entry->memdesc.ops->vmfault)
		return VM_FAULT_SIGBUS;

	return entry->memdesc.ops->vmfault(&entry->memdesc, vma, vmf);
}

static void
kgsl_gpumem_vm_close(struct vm_area_struct *vma)
{
	struct kgsl_mem_entry *entry  = vma->vm_private_data;

	if (!entry)
		return;

	entry->memdesc.useraddr = 0;
	kgsl_mem_entry_put(entry);
}

static struct vm_operations_struct kgsl_gpumem_vm_ops = {
	.open  = kgsl_gpumem_vm_open,
	.fault = kgsl_gpumem_vm_fault,
	.close = kgsl_gpumem_vm_close,
};

static int
get_mmap_entry(struct kgsl_process_private *private,
		struct kgsl_mem_entry **out_entry, unsigned long pgoff,
		unsigned long len)
{
	int ret = 0;
	struct kgsl_mem_entry *entry;

	entry = kgsl_sharedmem_find_id(private, pgoff);
	if (entry == NULL)
		entry = kgsl_sharedmem_find(private, pgoff << PAGE_SHIFT);

	if (!entry)
		return -EINVAL;

	if (!entry->memdesc.ops ||
		!entry->memdesc.ops->vmflags ||
		!entry->memdesc.ops->vmfault) {
		ret = -EINVAL;
		goto err_put;
	}

	if (entry->memdesc.useraddr != 0) {
		ret = -EBUSY;
		goto err_put;
	}

	if (kgsl_memdesc_use_cpu_map(&entry->memdesc)) {
		if (len != kgsl_memdesc_mmapsize(&entry->memdesc)) {
			ret = -ERANGE;
			goto err_put;
		}
	} else if (len != kgsl_memdesc_mmapsize(&entry->memdesc) &&
		len != entry->memdesc.size) {
		ret = -ERANGE;
		goto err_put;
	}

	*out_entry = entry;
	return 0;
err_put:
	kgsl_mem_entry_put(entry);
	return ret;
}

static inline bool
mmap_range_valid(uint64_t addr, uint64_t len)
{
	return ((ULONG_MAX - addr) > len) && ((addr + len) <=
		KGSL_SVM_UPPER_BOUND) && (addr >= KGSL_SVM_LOWER_BOUND);
}

static int __kgsl_check_collision(struct kgsl_process_private *private,
			struct kgsl_mem_entry *entry,
			uint64_t *gpuaddr, uint64_t len,
			int flag_top_down)
{
	int ret = 0;
	uint64_t addr = *gpuaddr;
	struct kgsl_mem_entry *collision_entry = entry;
	struct rb_node *node, *node_first, *node_last;

	if (len > (KGSL_SVM_UPPER_BOUND - KGSL_SVM_LOWER_BOUND))
		return -ENOENT;

	if (!collision_entry)
		return -ENOENT;

	node = &(collision_entry->node);
	node_first = rb_first(&private->mem_rb);
	node_last = rb_last(&private->mem_rb);

	while (1) {
		if (flag_top_down) {
			addr = collision_entry->memdesc.gpuaddr - len;
			
			if (addr > collision_entry->memdesc.gpuaddr || !addr) {
				*gpuaddr = KGSL_SVM_UPPER_BOUND;
				ret = -EAGAIN;
				break;
			}
			if (node == node_first) {
				collision_entry = NULL;
			} else {
				node = rb_prev(&collision_entry->node);
				collision_entry = container_of(node,
					struct kgsl_mem_entry, node);
			}
		} else {
			addr = collision_entry->memdesc.gpuaddr +
				kgsl_memdesc_mmapsize(
					&collision_entry->memdesc);
			
			if (addr < collision_entry->memdesc.gpuaddr ||
				!mmap_range_valid(addr, len)) {
				*gpuaddr = KGSL_SVM_UPPER_BOUND;
				ret = -EAGAIN;
				break;
			}
			if (node == node_last) {
				collision_entry = NULL;
			} else {
				node = rb_next(&collision_entry->node);
				collision_entry = container_of(node,
					struct kgsl_mem_entry, node);
			}
		}

		if (!collision_entry ||
			!kgsl_addr_range_overlap(addr, len,
			collision_entry->memdesc.gpuaddr,
			kgsl_memdesc_mmapsize(&collision_entry->memdesc))) {
			
			*gpuaddr = addr;
			break;
		}
	}

	return ret;
}

static int kgsl_check_gpu_addr_collision(
				struct kgsl_process_private *private,
				struct kgsl_mem_entry *entry,
				unsigned long addr, unsigned long len,
				uint64_t *gpumap_free_addr,
				bool flag_top_down,
				unsigned int align)
{
	uint64_t gpuaddr = addr;

	int ret = -EAGAIN;
	struct kgsl_mem_entry *collision_entry = NULL;
	spin_lock(&private->mem_lock);
	if (kgsl_sharedmem_region_empty(private, (uint64_t) addr,
		(uint64_t) len, &collision_entry)) {

		entry->memdesc.gpuaddr = (uint64_t) addr;
		
		ret = kgsl_mem_entry_track_gpuaddr(private, entry);
		spin_unlock(&private->mem_lock);
		BUG_ON(ret);
		
		ret = kgsl_mmu_map(private->pagetable,
					&entry->memdesc);
		if (ret) {
			spin_lock(&private->mem_lock);
			kgsl_mem_entry_untrack_gpuaddr(private, entry);
			spin_unlock(&private->mem_lock);
		}
	} else {
		trace_kgsl_mem_unmapped_area_collision(entry, addr, len,
							ret);
		if (!gpumap_free_addr) {
			spin_unlock(&private->mem_lock);
			return ret;
		}
		len += (1U << align);

		ret = __kgsl_check_collision(private, collision_entry, &gpuaddr,
						(uint64_t) len, flag_top_down);
		if (!ret || -EAGAIN == ret) {
			*gpumap_free_addr = gpuaddr;
			ret = -EAGAIN;
		}

		spin_unlock(&private->mem_lock);
	}
	return ret;
}

static unsigned long
kgsl_get_unmapped_area(struct file *file, unsigned long addr,
			unsigned long len, unsigned long pgoff,
			unsigned long flags)
{
	unsigned long ret = 0, orig_len = len;
	unsigned long vma_offset = pgoff << PAGE_SHIFT;
	struct kgsl_device_private *dev_priv = file->private_data;
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_device *device = dev_priv->device;
	struct kgsl_mem_entry *entry = NULL;
	unsigned int align;
	unsigned int retry = 0;
	struct vm_area_struct *vma;
	int ret_val;
	uint64_t gpumap_free_addr = 0;
	bool flag_top_down = true;
	struct vm_unmapped_area_info info;

	if (vma_offset == (unsigned long) device->memstore.gpuaddr)
		return get_unmapped_area(NULL, addr, len, pgoff, flags);

	ret = get_mmap_entry(private, &entry, pgoff, len);
	if (ret)
		return ret;

	ret = arch_mmap_check(addr, len, flags);
	if (ret)
		goto put;

	
	if (kgsl_memdesc_is_secured(&entry->memdesc)) {
		ret = -EPERM;
		goto put;
	}

	if (!kgsl_memdesc_use_cpu_map(&entry->memdesc)) {
		ret = get_unmapped_area(NULL, addr, len, pgoff, flags);
		goto put;
	}
	if (entry->memdesc.gpuaddr != 0) {
		KGSL_MEM_INFO(device,
				"pgoff %lX already mapped to gpuaddr 0x%016llX\n",
				pgoff, entry->memdesc.gpuaddr);
		ret = -EBUSY;
		goto put;
	}
	
	if (flags & MAP_FIXED) {
		if (!mmap_range_valid(addr, len)) {
			ret = -EFAULT;
			goto put;
		}
		ret = get_unmapped_area(NULL, addr, len, pgoff, flags);
		if (!ret || IS_ERR_VALUE(ret))
			goto put;
		ret_val = kgsl_check_gpu_addr_collision(private, entry,
					addr, len, 0, 0, 0);
		if (ret_val)
			ret = ret_val;
		goto put;
	}

	align = kgsl_memdesc_get_align(&entry->memdesc);
	if (align >= ilog2(SZ_2M))
		align = ilog2(SZ_2M);
	else if (align >= ilog2(SZ_1M))
		align = ilog2(SZ_1M);
	else if (align >= ilog2(SZ_64K))
		align = ilog2(SZ_64K);
	else if (align <= PAGE_SHIFT)
		align = 0;

	if (align)
		len += 1 << align;

	if (mmap_range_valid(addr, len)) {
		vma = find_vma(current->mm, addr);
		if (!vma || ((addr + len) <= vma->vm_start)) {

			if (align)
				ret = ALIGN(addr, (1 << align));

			ret_val = kgsl_check_gpu_addr_collision(private,
				entry, ret, orig_len, NULL, 0, 0);

			if (!ret_val) {
				
				goto put;
			} else if (((ret_val < 0) && (ret_val != -EAGAIN))) {
				ret = ret_val;
				goto put;
			}
		}
	}

	if (mmap_min_addr >= KGSL_SVM_UPPER_BOUND)
		return -ERANGE;

	addr = current->mm->mmap_base;
	info.length = orig_len;
	info.align_mask = ((1 << align) - 1);
	info.align_offset = 0;
	while (1) {
		if (retry) {
			if (flag_top_down) {
				flag_top_down = false;
				addr = max_t(unsigned long,
					KGSL_SVM_LOWER_BOUND, mmap_min_addr);
				gpumap_free_addr = 0;
				ret = 0;
				retry = 0;
				continue;
			}
			if (align) {
				align = 0;
				flag_top_down = true;
				addr = current->mm->mmap_base;
				gpumap_free_addr = 0;
				len = orig_len;
				ret = 0;
				retry = 0;
				info.align_mask = 0;
				continue;
			}
			break;
		}

		if (gpumap_free_addr) {
			
			if (gpumap_free_addr > ULONG_MAX) {
				ret = (unsigned long) -EOVERFLOW;
				break;
			}

			addr = (unsigned long) gpumap_free_addr;
		}

		if (flag_top_down) {
			info.flags = VM_UNMAPPED_AREA_TOPDOWN;
			info.low_limit = max_t(unsigned long,
					KGSL_SVM_LOWER_BOUND, mmap_min_addr);
			info.high_limit = (addr > KGSL_SVM_UPPER_BOUND) ?
						KGSL_SVM_UPPER_BOUND : addr;
		} else {
			info.flags = 0;
			info.low_limit = addr;
			info.high_limit = KGSL_SVM_UPPER_BOUND;
		}
		ret = vm_unmapped_area(&info);

		if (ret == (unsigned long)-ENOMEM) {
			retry = 1;
			continue;
		} else if (!ret || (~PAGE_MASK & ret)) {
			ret = -EBUSY;
			retry = 1;
			continue;
		} else if (IS_ERR_VALUE(ret)) {
			break;
		} else {
			unsigned long temp = ret;
			ret = security_mmap_addr(ret);
			if (ret) {
				retry = 1;
				continue;
			}
			ret = temp;
		}

		
		ret_val = kgsl_check_gpu_addr_collision(private, entry,
				ret, orig_len, &gpumap_free_addr,
				flag_top_down, align);
		if (!ret_val) {
			
			break;
		} else if ((ret_val < 0) && (ret_val != -EAGAIN)) {
			ret = ret_val;
			break;
		}

		if (!mmap_range_valid(gpumap_free_addr, len)) {
			retry = 1;
			ret = -EBUSY;
			continue;
		}
	}

put:
	if (IS_ERR_VALUE(ret))
		KGSL_MEM_ERR_RATELIMITED(device,
				"pid %d pgoff %lx len %ld failed error %ld\n",
				private->pid, pgoff, len, ret);
	kgsl_mem_entry_put(entry);
	return ret;
}

static int kgsl_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned int ret, cache;
	unsigned long vma_offset = vma->vm_pgoff << PAGE_SHIFT;
	struct kgsl_device_private *dev_priv = file->private_data;
	struct kgsl_process_private *private = dev_priv->process_priv;
	struct kgsl_mem_entry *entry = NULL;
	struct kgsl_device *device = dev_priv->device;

	

	if (vma_offset == (unsigned long) device->memstore.gpuaddr)
		return kgsl_mmap_memstore(device, vma);

	ret = get_mmap_entry(private, &entry, vma->vm_pgoff,
				vma->vm_end - vma->vm_start);
	if (ret)
		return ret;

	vma->vm_flags |= entry->memdesc.ops->vmflags;

	vma->vm_private_data = entry;

	

	cache = kgsl_memdesc_get_cachemode(&entry->memdesc);

	switch (cache) {
	case KGSL_CACHEMODE_UNCACHED:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		break;
	case KGSL_CACHEMODE_WRITETHROUGH:
		vma->vm_page_prot = pgprot_writethroughcache(vma->vm_page_prot);
		if (vma->vm_page_prot ==
			pgprot_writebackcache(vma->vm_page_prot))
			WARN_ONCE(1, "WRITETHROUGH is deprecated for arm64");
		break;
	case KGSL_CACHEMODE_WRITEBACK:
		vma->vm_page_prot = pgprot_writebackcache(vma->vm_page_prot);
		break;
	case KGSL_CACHEMODE_WRITECOMBINE:
	default:
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
		break;
	}

	vma->vm_ops = &kgsl_gpumem_vm_ops;

	if (cache == KGSL_CACHEMODE_WRITEBACK
		|| cache == KGSL_CACHEMODE_WRITETHROUGH) {
		struct scatterlist *s;
		int i;
		unsigned long addr = vma->vm_start;

		for_each_sg(entry->memdesc.sgt->sgl, s,
				entry->memdesc.sgt->nents, i) {
			int j;
			for (j = 0; j < (s->length >> PAGE_SHIFT); j++) {
				struct page *page = sg_page(s);
				page = nth_page(page, j);
				vm_insert_page(vma, addr, page);
				addr += PAGE_SIZE;
			}
		}
	}

	vma->vm_file = file;

	entry->memdesc.useraddr = vma->vm_start;

	trace_kgsl_mem_mmap(entry);
	return 0;
}

static irqreturn_t kgsl_irq_handler(int irq, void *data)
{
	struct kgsl_device *device = data;

	return device->ftbl->irq_handler(device);

}

#define KGSL_READ_MESSAGE "OH HAI GPU"

static ssize_t kgsl_read(struct file *filep, char __user *buf, size_t count,
		loff_t *pos)
{
	int ret;

	if (*pos >= strlen(KGSL_READ_MESSAGE) + 1)
		return 0;

	ret = snprintf(buf, count, "%s\n", KGSL_READ_MESSAGE);
	*pos += ret;

	return ret;
}

static const struct file_operations kgsl_fops = {
	.owner = THIS_MODULE,
	.release = kgsl_release,
	.open = kgsl_open,
	.mmap = kgsl_mmap,
	.read = kgsl_read,
	.get_unmapped_area = kgsl_get_unmapped_area,
	.unlocked_ioctl = kgsl_ioctl,
	.compat_ioctl = kgsl_compat_ioctl,
};

struct kgsl_driver kgsl_driver  = {
	.process_mutex = __MUTEX_INITIALIZER(kgsl_driver.process_mutex),
	.ptlock = __SPIN_LOCK_UNLOCKED(kgsl_driver.ptlock),
	.devlock = __MUTEX_INITIALIZER(kgsl_driver.devlock),
	.full_cache_threshold = SZ_16M,
};
EXPORT_SYMBOL(kgsl_driver);

static void _unregister_device(struct kgsl_device *device)
{
	int minor;

	mutex_lock(&kgsl_driver.devlock);
	for (minor = 0; minor < KGSL_DEVICE_MAX; minor++) {
		if (device == kgsl_driver.devp[minor])
			break;
	}
	if (minor != KGSL_DEVICE_MAX) {
		device_destroy(kgsl_driver.class,
				MKDEV(MAJOR(kgsl_driver.major), minor));
		kgsl_driver.devp[minor] = NULL;
	}
	mutex_unlock(&kgsl_driver.devlock);
}

static int _register_device(struct kgsl_device *device)
{
	int minor, ret;
	dev_t dev;

	

	mutex_lock(&kgsl_driver.devlock);
	for (minor = 0; minor < KGSL_DEVICE_MAX; minor++) {
		if (kgsl_driver.devp[minor] == NULL) {
			kgsl_driver.devp[minor] = device;
			break;
		}
	}
	mutex_unlock(&kgsl_driver.devlock);

	if (minor == KGSL_DEVICE_MAX) {
		KGSL_CORE_ERR("minor devices exhausted\n");
		return -ENODEV;
	}

	
	dev = MKDEV(MAJOR(kgsl_driver.major), minor);
	device->dev = device_create(kgsl_driver.class,
				    &device->pdev->dev,
				    dev, device,
				    device->name);

	if (IS_ERR(device->dev)) {
		mutex_lock(&kgsl_driver.devlock);
		kgsl_driver.devp[minor] = NULL;
		mutex_unlock(&kgsl_driver.devlock);
		ret = PTR_ERR(device->dev);
		KGSL_CORE_ERR("device_create(%s): %d\n", device->name, ret);
		return ret;
	}

	dev_set_drvdata(&device->pdev->dev, device);
	return 0;
}

int kgsl_device_platform_probe(struct kgsl_device *device)
{
	int status = -EINVAL;
	struct resource *res;

	status = _register_device(device);
	if (status)
		return status;

	
	kgsl_device_debugfs_init(device);

	status = kgsl_pwrctrl_init(device);
	if (status)
		goto error;

	
	res = platform_get_resource_byname(device->pdev, IORESOURCE_MEM,
					   device->iomemname);
	if (res == NULL) {
		KGSL_DRV_ERR(device, "platform_get_resource_byname failed\n");
		status = -EINVAL;
		goto error_pwrctrl_close;
	}
	if (res->start == 0 || resource_size(res) == 0) {
		KGSL_DRV_ERR(device, "dev %d invalid register region\n",
			device->id);
		status = -EINVAL;
		goto error_pwrctrl_close;
	}

	device->reg_phys = res->start;
	device->reg_len = resource_size(res);

	if (device->shadermemname != NULL) {
		res = platform_get_resource_byname(device->pdev, IORESOURCE_MEM,
						device->shadermemname);

		if (res == NULL) {
			KGSL_DRV_WARN(device,
			"Shader memory: platform_get_resource_byname failed\n");
		}

		else {
			device->shader_mem_phys = res->start;
			device->shader_mem_len = resource_size(res);
		}

		if (!devm_request_mem_region(device->dev,
					device->shader_mem_phys,
					device->shader_mem_len,
						device->name)) {
			KGSL_DRV_WARN(device, "request_mem_region_failed\n");
		}
	}

	if (!devm_request_mem_region(device->dev, device->reg_phys,
				device->reg_len, device->name)) {
		KGSL_DRV_ERR(device, "request_mem_region failed\n");
		status = -ENODEV;
		goto error_pwrctrl_close;
	}

	device->reg_virt = devm_ioremap(device->dev, device->reg_phys,
					device->reg_len);

	if (device->reg_virt == NULL) {
		KGSL_DRV_ERR(device, "ioremap failed\n");
		status = -ENODEV;
		goto error_pwrctrl_close;
	}
	
	device->pwrctrl.interrupt_num =
		platform_get_irq_byname(device->pdev, device->pwrctrl.irq_name);

	if (device->pwrctrl.interrupt_num <= 0) {
		KGSL_DRV_ERR(device, "platform_get_irq_byname failed: %d\n",
					 device->pwrctrl.interrupt_num);
		status = -EINVAL;
		goto error_pwrctrl_close;
	}

	status = devm_request_irq(device->dev, device->pwrctrl.interrupt_num,
				  kgsl_irq_handler, IRQF_TRIGGER_HIGH,
				  device->name, device);
	if (status) {
		KGSL_DRV_ERR(device, "request_irq(%d) failed: %d\n",
			      device->pwrctrl.interrupt_num, status);
		goto error_pwrctrl_close;
	}
	disable_irq(device->pwrctrl.interrupt_num);

	KGSL_DRV_INFO(device,
		"dev_id %d regs phys 0x%08lx size 0x%08x virt %p\n",
		device->id, device->reg_phys, device->reg_len,
		device->reg_virt);

	rwlock_init(&device->context_lock);

	setup_timer(&device->idle_timer, kgsl_timer, (unsigned long) device);

	
	device->work_queue = create_singlethread_workqueue(device->name);
	if (device->work_queue == NULL) {
		status = -ENODEV;
		KGSL_DRV_ERR(device,
			"create_singelthreaded_workqueue(%s) failed\n",
			device->name);
		goto error_pwrctrl_close;
	}

	status = kgsl_mmu_init(device);
	if (status != 0) {
		KGSL_DRV_ERR(device, "kgsl_mmu_init failed %d\n", status);
		goto error_dest_work_q;
	}

	
	status = dma_set_coherent_mask(&device->pdev->dev, KGSL_DMA_BIT_MASK);
	if (status)
		goto error_close_mmu;

	status = kgsl_allocate_global(device, &device->memstore,
		KGSL_MEMSTORE_SIZE, 0, 0);

	if (status != 0) {
		KGSL_DRV_ERR(device, "kgsl_allocate_global failed %d\n",
				status);
		goto error_close_mmu;
	}

#ifdef CONFIG_SMP

	device->pwrctrl.pm_qos_req_dma.type = PM_QOS_REQ_AFFINE_IRQ;
	device->pwrctrl.pm_qos_req_dma.irq = device->pwrctrl.interrupt_num;

#endif
	pm_qos_add_request(&device->pwrctrl.pm_qos_req_dma,
				PM_QOS_CPU_DMA_LATENCY,
				PM_QOS_DEFAULT_VALUE);


	device->events_wq = create_workqueue("kgsl-events");

	
	kgsl_device_snapshot_init(device);

	
	kgsl_pwrctrl_init_sysfs(device);

	
	kgsl_device_htc_init(device);

	dev_info(device->dev, "Initialized %s: mmu=%s\n", device->name,
		kgsl_mmu_enabled() ? "on" : "off");

	return 0;

error_close_mmu:
	kgsl_mmu_close(device);
error_dest_work_q:
	destroy_workqueue(device->work_queue);
	device->work_queue = NULL;
error_pwrctrl_close:
	kgsl_pwrctrl_close(device);
error:
	_unregister_device(device);
	return status;
}
EXPORT_SYMBOL(kgsl_device_platform_probe);

void kgsl_device_platform_remove(struct kgsl_device *device)
{
	destroy_workqueue(device->events_wq);

	kgsl_device_snapshot_close(device);

	kgsl_pwrctrl_uninit_sysfs(device);

	pm_qos_remove_request(&device->pwrctrl.pm_qos_req_dma);

	idr_destroy(&device->context_idr);

	kgsl_free_global(&device->memstore);

	kgsl_mmu_close(device);

	if (device->work_queue) {
		destroy_workqueue(device->work_queue);
		device->work_queue = NULL;
	}
	kgsl_pwrctrl_close(device);

	_unregister_device(device);
}
EXPORT_SYMBOL(kgsl_device_platform_remove);

static void kgsl_core_exit(void)
{
	kgsl_events_exit();
	kgsl_cffdump_destroy();
	kgsl_core_debugfs_close();

	if (kgsl_driver.virtdev.class) {
		kgsl_sharedmem_uninit_sysfs();
		device_unregister(&kgsl_driver.virtdev);
	}

	if (kgsl_driver.class) {
		class_destroy(kgsl_driver.class);
		kgsl_driver.class = NULL;
	}

	kgsl_cmdbatch_exit();

	kgsl_memfree_exit();
	unregister_chrdev_region(kgsl_driver.major, KGSL_DEVICE_MAX);
}

static int __init kgsl_core_init(void)
{
	int result = 0;
	
	result = alloc_chrdev_region(&kgsl_driver.major, 0, KGSL_DEVICE_MAX,
		"kgsl");

	if (result < 0) {

		KGSL_CORE_ERR("alloc_chrdev_region failed err = %d\n", result);
		goto err;
	}

	cdev_init(&kgsl_driver.cdev, &kgsl_fops);
	kgsl_driver.cdev.owner = THIS_MODULE;
	kgsl_driver.cdev.ops = &kgsl_fops;
	result = cdev_add(&kgsl_driver.cdev, MKDEV(MAJOR(kgsl_driver.major), 0),
		       KGSL_DEVICE_MAX);

	if (result) {
		KGSL_CORE_ERR("kgsl: cdev_add() failed, dev_num= %d,"
			     " result= %d\n", kgsl_driver.major, result);
		goto err;
	}

	kgsl_driver.class = class_create(THIS_MODULE, "kgsl");

	if (IS_ERR(kgsl_driver.class)) {
		result = PTR_ERR(kgsl_driver.class);
		KGSL_CORE_ERR("failed to create class for kgsl");
		goto err;
	}

	kgsl_driver.virtdev.class = kgsl_driver.class;
	dev_set_name(&kgsl_driver.virtdev, "kgsl");
	result = device_register(&kgsl_driver.virtdev);
	if (result) {
		KGSL_CORE_ERR("driver_register failed\n");
		goto err;
	}

	

	kgsl_driver.ptkobj =
	  kobject_create_and_add("pagetables",
				 &kgsl_driver.virtdev.kobj);

	kgsl_driver.prockobj =
		kobject_create_and_add("proc",
				       &kgsl_driver.virtdev.kobj);

	kgsl_core_debugfs_init();

	kgsl_sharedmem_init_sysfs();
	kgsl_cffdump_init();

	INIT_LIST_HEAD(&kgsl_driver.process_list);

	INIT_LIST_HEAD(&kgsl_driver.pagetable_list);

	kgsl_mmu_set_mmutype(ksgl_mmu_type);

	kgsl_events_init();

	result = kgsl_cmdbatch_init();
	if (result)
		goto err;

	kgsl_memfree_init();

	kgsl_driver_htc_init(&kgsl_driver.priv);

	return 0;

err:
	kgsl_core_exit();
	return result;
}

module_init(kgsl_core_init);
module_exit(kgsl_core_exit);

MODULE_AUTHOR("Qualcomm Innovation Center, Inc.");
MODULE_DESCRIPTION("MSM GPU driver");
MODULE_LICENSE("GPL");
