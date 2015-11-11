/* drivers/soc/qcom/smd.c
 *
 * Copyright (C) 2007 Google, Inc.
 * Copyright (c) 2008-2015, The Linux Foundation. All rights reserved.
 * Author: Brian Swetland <swetland@google.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/platform_device.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/termios.h>
#include <linux/ctype.h>
#include <linux/remote_spinlock.h>
#include <linux/uaccess.h>
#include <linux/kfifo.h>
#include <linux/pm.h>
#include <linux/notifier.h>
#include <linux/suspend.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/ipc_logging.h>

#include <soc/qcom/ramdump.h>
#include <soc/qcom/smd.h>
#include <soc/qcom/smem.h>
#include <soc/qcom/subsystem_notif.h>
#include <soc/qcom/subsystem_restart.h>

#include "smd_private.h"
#include "smem_private.h"

#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#include <linux/debugfs.h>
void smsm_dbg_log_event(const char * event, ...);

#define DBG_MSG_LEN   100UL

#define DBG_MAX_MSG   256UL
#define DBG_SMD_MAX_MSG   (DBG_MAX_MSG * 2)

#define TIME_BUF_LEN  20

static int smsm_htc_debug_enable = 1;
static int smsm_htc_debug_dump = 1;
static int smsm_htc_debug_dump_lines = DBG_MAX_MSG;
static int smsm_htc_debug_print = 0;
module_param_named(smsm_htc_debug_enable, smsm_htc_debug_enable,
		   int, S_IRUGO | S_IWUSR | S_IWGRP);
module_param_named(smsm_htc_debug_dump, smsm_htc_debug_dump,
		   int, S_IRUGO | S_IWUSR | S_IWGRP);
module_param_named(smsm_htc_debug_dump_lines, smsm_htc_debug_dump_lines,
		   int, S_IRUGO | S_IWUSR | S_IWGRP);
module_param_named(smsm_htc_debug_print, smsm_htc_debug_print,
		   int, S_IRUGO | S_IWUSR | S_IWGRP);

static struct {
	char     (buf[DBG_MAX_MSG])[DBG_MSG_LEN];   
	unsigned idx;   
	rwlock_t lck;   
} dbg_smsm = {
	.idx = 0,
	.lck = __RW_LOCK_UNLOCKED(lck)
};

void smd_dbg_log_event(const char * event, ...);

static int smd_htc_debug_enable = 1;
static int smd_htc_debug_dump = 1;
static int smd_htc_debug_dump_lines = DBG_SMD_MAX_MSG;
static int smd_htc_debug_print = 0;
module_param_named(smd_htc_debug_enable, smd_htc_debug_enable,
		   int, S_IRUGO | S_IWUSR | S_IWGRP);
module_param_named(smd_htc_debug_dump, smd_htc_debug_dump,
		   int, S_IRUGO | S_IWUSR | S_IWGRP);
module_param_named(smd_htc_debug_dump_lines, smd_htc_debug_dump_lines,
		   int, S_IRUGO | S_IWUSR | S_IWGRP);
module_param_named(smd_htc_debug_print, smd_htc_debug_print,
		   int, S_IRUGO | S_IWUSR | S_IWGRP);

static struct {
	char     (buf[DBG_SMD_MAX_MSG])[DBG_MSG_LEN];   
	unsigned idx;   
	rwlock_t lck;   
} dbg_smd = {
	.idx = 0,
	.lck = __RW_LOCK_UNLOCKED(lck)
};
#endif

#define SMSM_SNAPSHOT_CNT 64
#define SMSM_SNAPSHOT_SIZE ((SMSM_NUM_ENTRIES + 1) * 4 + sizeof(uint64_t))
#define RSPIN_INIT_WAIT_MS 1000
#define SMD_FIFO_FULL_RESERVE 4
#define SMD_FIFO_ADDR_ALIGN_BYTES 3

uint32_t SMSM_NUM_ENTRIES = 8;
uint32_t SMSM_NUM_HOSTS = 3;

#define LEGACY_MODEM_SMSM_MASK (SMSM_RESET | SMSM_INIT | SMSM_SMDINIT)

struct smsm_shared_info {
	uint32_t *state;
	uint32_t *intr_mask;
	uint32_t *intr_mux;
};

static struct smsm_shared_info smsm_info;
static struct kfifo smsm_snapshot_fifo;
static struct wakeup_source smsm_snapshot_ws;
static int smsm_snapshot_count;
static DEFINE_SPINLOCK(smsm_snapshot_count_lock);

struct smsm_size_info_type {
	uint32_t num_hosts;
	uint32_t num_entries;
	uint32_t reserved0;
	uint32_t reserved1;
};

struct smsm_state_cb_info {
	struct list_head cb_list;
	uint32_t mask;
	void *data;
	void (*notify)(void *data, uint32_t old_state, uint32_t new_state);
};

struct smsm_state_info {
	struct list_head callbacks;
	uint32_t last_value;
	uint32_t intr_mask_set;
	uint32_t intr_mask_clear;
};

static irqreturn_t smsm_irq_handler(int irq, void *data);

static struct interrupt_config private_intr_config[NUM_SMD_SUBSYSTEMS] = {
	[SMD_MODEM] = {
		.smd.irq_handler = smd_modem_irq_handler,
		.smsm.irq_handler = smsm_modem_irq_handler,
	},
	[SMD_Q6] = {
		.smd.irq_handler = smd_dsp_irq_handler,
		.smsm.irq_handler = smsm_dsp_irq_handler,
	},
	[SMD_DSPS] = {
		.smd.irq_handler = smd_dsps_irq_handler,
		.smsm.irq_handler = smsm_dsps_irq_handler,
	},
	[SMD_WCNSS] = {
		.smd.irq_handler = smd_wcnss_irq_handler,
		.smsm.irq_handler = smsm_wcnss_irq_handler,
	},
	[SMD_MODEM_Q6_FW] = {
		.smd.irq_handler = smd_modemfw_irq_handler,
		.smsm.irq_handler = NULL, 
	},
	[SMD_RPM] = {
		.smd.irq_handler = smd_rpm_irq_handler,
		.smsm.irq_handler = NULL, 
	},
};

union fifo_mem {
	uint64_t u64;
	uint8_t u8;
};

struct interrupt_stat interrupt_stats[NUM_SMD_SUBSYSTEMS];

#define SMSM_STATE_ADDR(entry)           (smsm_info.state + entry)
#define SMSM_INTR_MASK_ADDR(entry, host) (smsm_info.intr_mask + \
					  entry * SMSM_NUM_HOSTS + host)
#define SMSM_INTR_MUX_ADDR(entry)        (smsm_info.intr_mux + entry)

int msm_smd_debug_mask = MSM_SMD_POWER_INFO | MSM_SMD_INFO |
							MSM_SMSM_POWER_INFO;
module_param_named(debug_mask, msm_smd_debug_mask,
		   int, S_IRUGO | S_IWUSR | S_IWGRP);
void *smd_log_ctx;
void *smsm_log_ctx;
#define NUM_LOG_PAGES 4

#define IPC_LOG_SMD(level, x...) do { \
	if (smd_log_ctx) \
		ipc_log_string(smd_log_ctx, x); \
	else \
		printk(level x); \
	} while (0)

#define IPC_LOG_SMSM(level, x...) do { \
	if (smsm_log_ctx) \
		ipc_log_string(smsm_log_ctx, x); \
	else \
		printk(level x); \
	} while (0)

#if defined(CONFIG_MSM_SMD_DEBUG)
#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#define SMD_DBG(x...) do {				\
		if (msm_smd_debug_mask & MSM_SMD_DEBUG) \
			IPC_LOG_SMD(KERN_DEBUG, x);	\
		if (smd_htc_debug_enable) \
			smd_dbg_log_event(x); \
	} while (0)
#else
#define SMD_DBG(x...) do {				\
		if (msm_smd_debug_mask & MSM_SMD_DEBUG) \
			IPC_LOG_SMD(KERN_DEBUG, x);	\
	} while (0)
#endif

#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#define SMSM_DBG(x...) do {					\
		if (msm_smd_debug_mask & MSM_SMSM_DEBUG)	\
			IPC_LOG_SMSM(KERN_DEBUG, x);		\
		if (smsm_htc_debug_enable) \
			smsm_dbg_log_event(x); \
	} while (0)
#else
#define SMSM_DBG(x...) do {					\
		if (msm_smd_debug_mask & MSM_SMSM_DEBUG)	\
			IPC_LOG_SMSM(KERN_DEBUG, x);		\
	} while (0)
#endif


#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#define SMD_INFO(x...) do {				\
		if (msm_smd_debug_mask & MSM_SMD_INFO)	\
			IPC_LOG_SMD(KERN_INFO, x);	\
		if (smd_htc_debug_enable) \
			smd_dbg_log_event(x); \
	} while (0)
#else
#define SMD_INFO(x...) do {				\
		if (msm_smd_debug_mask & MSM_SMD_INFO)	\
			IPC_LOG_SMD(KERN_INFO, x);	\
	} while (0)
#endif

#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#define SMSM_INFO(x...) do {				\
		if (msm_smd_debug_mask & MSM_SMSM_INFO) \
			IPC_LOG_SMSM(KERN_INFO, x);	\
		if (smsm_htc_debug_enable) \
			smsm_dbg_log_event(x); \
	} while (0)
#else
#define SMSM_INFO(x...) do {				\
		if (msm_smd_debug_mask & MSM_SMSM_INFO) \
			IPC_LOG_SMSM(KERN_INFO, x);	\
	} while (0)
#endif


#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#define SMD_POWER_INFO(x...) do {				\
		if (msm_smd_debug_mask & MSM_SMD_POWER_INFO)	\
			IPC_LOG_SMD(KERN_INFO, x);		\
		if (smd_htc_debug_enable) \
			smd_dbg_log_event(x); \
	} while (0)
#else
#define SMD_POWER_INFO(x...) do {				\
		if (msm_smd_debug_mask & MSM_SMD_POWER_INFO)	\
			IPC_LOG_SMD(KERN_INFO, x);		\
	} while (0)
#endif

#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#define SMSM_POWER_INFO(x...) do {				\
		if (msm_smd_debug_mask & MSM_SMSM_POWER_INFO)	\
			IPC_LOG_SMSM(KERN_INFO, x);		\
		if (smsm_htc_debug_enable) \
			smsm_dbg_log_event(x); \
	} while (0)
#else
#define SMSM_POWER_INFO(x...) do {				\
		if (msm_smd_debug_mask & MSM_SMSM_POWER_INFO)	\
			IPC_LOG_SMSM(KERN_INFO, x);		\
	} while (0)
#endif

#else

#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#define SMD_DBG(x...) do {					\
		if (smd_htc_debug_enable) \
			smd_dbg_log_event(x); \
	} while (0)
#else
#define SMD_DBG(x...) do { } while (0)
#endif

#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#define SMSM_DBG(x...) do {					\
		if (smsm_htc_debug_enable) \
			smsm_dbg_log_event(x); \
	} while (0)
#else
#define SMSM_DBG(x...) do { } while (0)
#endif

#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#define SMD_INFO(x...) do {				\
		if (smd_htc_debug_enable) \
			smsm_dbg_log_event(x); \
	} while (0)
#else
#define SMD_INFO(x...) do { } while (0)
#endif

#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#define SMSM_INFO(x...) do {				\
		if (smsm_htc_debug_enable) \
			smsm_dbg_log_event(x); \
	} while (0)
#else
#define SMSM_INFO(x...) do { } while (0)
#endif

#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#define SMD_POWER_INFO(x...) do {				\
		if (smd_htc_debug_enable) \
			smsm_dbg_log_event(x); \
	} while (0)
#else
#define SMD_POWER_INFO(x...) do { } while (0)
#endif

#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#define SMSM_POWER_INFO(x...) do {				\
		if (smsm_htc_debug_enable) \
			smsm_dbg_log_event(x); \
	} while (0)
#else
#define SMSM_POWER_INFO(x...) do { } while (0)
#endif

#endif

static void smd_fake_irq_handler(unsigned long arg);
static void smsm_cb_snapshot(uint32_t use_wakeup_source);

static struct workqueue_struct *smsm_cb_wq;
static void notify_smsm_cb_clients_worker(struct work_struct *work);
static DECLARE_WORK(smsm_cb_work, notify_smsm_cb_clients_worker);
static DEFINE_MUTEX(smsm_lock);
static struct smsm_state_info *smsm_states;

static int smd_stream_write_avail(struct smd_channel *ch);
static int smd_stream_read_avail(struct smd_channel *ch);

static bool pid_is_on_edge(uint32_t edge_num, unsigned pid);

static inline void smd_write_intr(unsigned int val, void __iomem *addr)
{
	wmb();
	__raw_writel(val, addr);
}

static void *smd_memcpy_to_fifo(void *dest, const void *src, size_t num_bytes)
{
	union fifo_mem *temp_dst = (union fifo_mem *)dest;
	union fifo_mem *temp_src = (union fifo_mem *)src;
	uintptr_t mask = sizeof(union fifo_mem) - 1;

	
	while ((uintptr_t)temp_dst & mask && num_bytes) {
		__raw_writeb_no_log(temp_src->u8, temp_dst);
		temp_src = (union fifo_mem *)((uintptr_t)temp_src + 1);
		temp_dst = (union fifo_mem *)((uintptr_t)temp_dst + 1);
		num_bytes--;
	}

	
	while (num_bytes >= sizeof(union fifo_mem)) {
		__raw_writeq_no_log(temp_src->u64, temp_dst);
		temp_dst++;
		temp_src++;
		num_bytes -= sizeof(union fifo_mem);
	}

	
	while (num_bytes--) {
		__raw_writeb_no_log(temp_src->u8, temp_dst);
		temp_src = (union fifo_mem *)((uintptr_t)temp_src + 1);
		temp_dst = (union fifo_mem *)((uintptr_t)temp_dst + 1);
	}

	return dest;
}

static void *smd_memcpy_from_fifo(void *dest, const void *src, size_t num_bytes)
{
	union fifo_mem *temp_dst = (union fifo_mem *)dest;
	union fifo_mem *temp_src = (union fifo_mem *)src;
	uintptr_t mask = sizeof(union fifo_mem) - 1;

	
	while ((uintptr_t)temp_src & mask && num_bytes) {
		temp_dst->u8 = __raw_readb_no_log(temp_src);
		temp_src = (union fifo_mem *)((uintptr_t)temp_src + 1);
		temp_dst = (union fifo_mem *)((uintptr_t)temp_dst + 1);
		num_bytes--;
	}

	
	while (num_bytes >= sizeof(union fifo_mem)) {
		temp_dst->u64 = __raw_readq_no_log(temp_src);
		temp_dst++;
		temp_src++;
		num_bytes -= sizeof(union fifo_mem);
	}

	
	while (num_bytes--) {
		temp_dst->u8 = __raw_readb_no_log(temp_src);
		temp_src = (union fifo_mem *)((uintptr_t)temp_src + 1);
		temp_dst = (union fifo_mem *)((uintptr_t)temp_dst + 1);
	}

	return dest;
}

static void *smd_memcpy32_to_fifo(void *dest, const void *src, size_t num_bytes)
{
	uint32_t *dest_local = (uint32_t *)dest;
	uint32_t *src_local = (uint32_t *)src;

	BUG_ON(num_bytes & SMD_FIFO_ADDR_ALIGN_BYTES);
	BUG_ON(!dest_local ||
			((uintptr_t)dest_local & SMD_FIFO_ADDR_ALIGN_BYTES));
	BUG_ON(!src_local ||
			((uintptr_t)src_local & SMD_FIFO_ADDR_ALIGN_BYTES));
	num_bytes /= sizeof(uint32_t);

	while (num_bytes--)
		__raw_writel_no_log(*src_local++, dest_local++);

	return dest;
}

static void *smd_memcpy32_from_fifo(void *dest, const void *src,
						size_t num_bytes)
{

	uint32_t *dest_local = (uint32_t *)dest;
	uint32_t *src_local = (uint32_t *)src;

	BUG_ON(num_bytes & SMD_FIFO_ADDR_ALIGN_BYTES);
	BUG_ON(!dest_local ||
			((uintptr_t)dest_local & SMD_FIFO_ADDR_ALIGN_BYTES));
	BUG_ON(!src_local ||
			((uintptr_t)src_local & SMD_FIFO_ADDR_ALIGN_BYTES));
	num_bytes /= sizeof(uint32_t);

	while (num_bytes--)
		*dest_local++ = __raw_readl_no_log(src_local++);

	return dest;
}

static inline void log_notify(uint32_t subsystem, smd_channel_t *ch)
{
	const char *subsys = smd_edge_to_subsystem(subsystem);

	(void) subsys;

	if (!ch)
		SMD_POWER_INFO("Apps->%s\n", subsys);
	else
		SMD_POWER_INFO(
			"Apps->%s ch%d '%s': tx%d/rx%d %dr/%dw : %dr/%dw\n",
			subsys, ch->n, ch->name,
			ch->fifo_size -
				(smd_stream_write_avail(ch) + 1),
			smd_stream_read_avail(ch),
			ch->half_ch->get_tail(ch->send),
			ch->half_ch->get_head(ch->send),
			ch->half_ch->get_tail(ch->recv),
			ch->half_ch->get_head(ch->recv)
			);
}

static inline void notify_modem_smd(smd_channel_t *ch)
{
	static const struct interrupt_config_item *intr
	   = &private_intr_config[SMD_MODEM].smd;

	log_notify(SMD_APPS_MODEM, ch);
	if (intr->out_base) {
		++interrupt_stats[SMD_MODEM].smd_out_count;
		smd_write_intr(intr->out_bit_pos,
		intr->out_base + intr->out_offset);
	}
}

static inline void notify_dsp_smd(smd_channel_t *ch)
{
	static const struct interrupt_config_item *intr
		= &private_intr_config[SMD_Q6].smd;

	log_notify(SMD_APPS_QDSP, ch);
	if (intr->out_base) {
		++interrupt_stats[SMD_Q6].smd_out_count;
		smd_write_intr(intr->out_bit_pos,
		intr->out_base + intr->out_offset);
	}
}

static inline void notify_dsps_smd(smd_channel_t *ch)
{
	static const struct interrupt_config_item *intr
		= &private_intr_config[SMD_DSPS].smd;

	log_notify(SMD_APPS_DSPS, ch);
	if (intr->out_base) {
		++interrupt_stats[SMD_DSPS].smd_out_count;
		smd_write_intr(intr->out_bit_pos,
		intr->out_base + intr->out_offset);
	}
}

static inline void notify_wcnss_smd(struct smd_channel *ch)
{
	static const struct interrupt_config_item *intr
		= &private_intr_config[SMD_WCNSS].smd;

	log_notify(SMD_APPS_WCNSS, ch);
	if (intr->out_base) {
		++interrupt_stats[SMD_WCNSS].smd_out_count;
		smd_write_intr(intr->out_bit_pos,
		intr->out_base + intr->out_offset);
	}
}

static inline void notify_modemfw_smd(smd_channel_t *ch)
{
	static const struct interrupt_config_item *intr
		= &private_intr_config[SMD_MODEM_Q6_FW].smd;

	log_notify(SMD_APPS_Q6FW, ch);
	if (intr->out_base) {
		++interrupt_stats[SMD_MODEM_Q6_FW].smd_out_count;
		smd_write_intr(intr->out_bit_pos,
		intr->out_base + intr->out_offset);
	}
}

static inline void notify_rpm_smd(smd_channel_t *ch)
{
	static const struct interrupt_config_item *intr
		= &private_intr_config[SMD_RPM].smd;

	if (intr->out_base) {
		log_notify(SMD_APPS_RPM, ch);
		++interrupt_stats[SMD_RPM].smd_out_count;
		smd_write_intr(intr->out_bit_pos,
		intr->out_base + intr->out_offset);
	}
}

static inline void notify_modem_smsm(void)
{
	static const struct interrupt_config_item *intr
		= &private_intr_config[SMD_MODEM].smsm;

	SMSM_POWER_INFO("SMSM Apps->%s", "MODEM");

	if (intr->out_base) {
		++interrupt_stats[SMD_MODEM].smsm_out_count;
		smd_write_intr(intr->out_bit_pos,
		intr->out_base + intr->out_offset);
	}
}

static inline void notify_dsp_smsm(void)
{
	static const struct interrupt_config_item *intr
		= &private_intr_config[SMD_Q6].smsm;

	SMSM_POWER_INFO("SMSM Apps->%s", "ADSP");

	if (intr->out_base) {
		++interrupt_stats[SMD_Q6].smsm_out_count;
		smd_write_intr(intr->out_bit_pos,
		intr->out_base + intr->out_offset);
	}
}

static inline void notify_dsps_smsm(void)
{
	static const struct interrupt_config_item *intr
		= &private_intr_config[SMD_DSPS].smsm;

	SMSM_POWER_INFO("SMSM Apps->%s", "DSPS");

	if (intr->out_base) {
		++interrupt_stats[SMD_DSPS].smsm_out_count;
		smd_write_intr(intr->out_bit_pos,
		intr->out_base + intr->out_offset);
	}
}

static inline void notify_wcnss_smsm(void)
{
	static const struct interrupt_config_item *intr
		= &private_intr_config[SMD_WCNSS].smsm;

	SMSM_POWER_INFO("SMSM Apps->%s", "WCNSS");

	if (intr->out_base) {
		++interrupt_stats[SMD_WCNSS].smsm_out_count;
		smd_write_intr(intr->out_bit_pos,
		intr->out_base + intr->out_offset);
	}
}

static void notify_other_smsm(uint32_t smsm_entry, uint32_t notify_mask)
{
	if (smsm_info.intr_mask &&
	    (__raw_readl(SMSM_INTR_MASK_ADDR(smsm_entry, SMSM_MODEM))
				& notify_mask))
		notify_modem_smsm();

	if (smsm_info.intr_mask &&
	    (__raw_readl(SMSM_INTR_MASK_ADDR(smsm_entry, SMSM_Q6))
				& notify_mask))
		notify_dsp_smsm();

	if (smsm_info.intr_mask &&
	    (__raw_readl(SMSM_INTR_MASK_ADDR(smsm_entry, SMSM_WCNSS))
				& notify_mask)) {
		notify_wcnss_smsm();
	}

	if (smsm_info.intr_mask &&
	    (__raw_readl(SMSM_INTR_MASK_ADDR(smsm_entry, SMSM_DSPS))
				& notify_mask)) {
		notify_dsps_smsm();
	}

	if (smsm_info.intr_mask &&
	    (__raw_readl(SMSM_INTR_MASK_ADDR(smsm_entry, SMSM_APPS))
				& notify_mask)) {
		smsm_cb_snapshot(1);
	}
}

static int smsm_pm_notifier(struct notifier_block *nb,
				unsigned long event, void *unused)
{
	switch (event) {
	case PM_SUSPEND_PREPARE:
		smsm_change_state(SMSM_APPS_STATE, SMSM_PROC_AWAKE, 0);
		break;

	case PM_POST_SUSPEND:
		smsm_change_state(SMSM_APPS_STATE, 0, SMSM_PROC_AWAKE);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block smsm_pm_nb = {
	.notifier_call = smsm_pm_notifier,
	.priority = 0,
};

static DEFINE_SPINLOCK(smd_lock);
DEFINE_SPINLOCK(smem_lock);

static DEFINE_MUTEX(smd_creation_mutex);

struct smd_shared {
	struct smd_half_channel ch0;
	struct smd_half_channel ch1;
};

struct smd_shared_word_access {
	struct smd_half_channel_word_access ch0;
	struct smd_half_channel_word_access ch1;
};

static struct edge_to_pid edge_to_pids[] = {
	[SMD_APPS_MODEM] = {SMD_APPS, SMD_MODEM, "modem"},
	[SMD_APPS_QDSP] = {SMD_APPS, SMD_Q6, "adsp"},
	[SMD_MODEM_QDSP] = {SMD_MODEM, SMD_Q6},
	[SMD_APPS_DSPS] = {SMD_APPS, SMD_DSPS, "dsps"},
	[SMD_MODEM_DSPS] = {SMD_MODEM, SMD_DSPS},
	[SMD_QDSP_DSPS] = {SMD_Q6, SMD_DSPS},
	[SMD_APPS_WCNSS] = {SMD_APPS, SMD_WCNSS, "wcnss"},
	[SMD_MODEM_WCNSS] = {SMD_MODEM, SMD_WCNSS},
	[SMD_QDSP_WCNSS] = {SMD_Q6, SMD_WCNSS},
	[SMD_DSPS_WCNSS] = {SMD_DSPS, SMD_WCNSS},
	[SMD_APPS_Q6FW] = {SMD_APPS, SMD_MODEM_Q6_FW},
	[SMD_MODEM_Q6FW] = {SMD_MODEM, SMD_MODEM_Q6_FW},
	[SMD_QDSP_Q6FW] = {SMD_Q6, SMD_MODEM_Q6_FW},
	[SMD_DSPS_Q6FW] = {SMD_DSPS, SMD_MODEM_Q6_FW},
	[SMD_WCNSS_Q6FW] = {SMD_WCNSS, SMD_MODEM_Q6_FW},
	[SMD_APPS_RPM] = {SMD_APPS, SMD_RPM},
	[SMD_MODEM_RPM] = {SMD_MODEM, SMD_RPM},
	[SMD_QDSP_RPM] = {SMD_Q6, SMD_RPM},
	[SMD_WCNSS_RPM] = {SMD_WCNSS, SMD_RPM},
	[SMD_TZ_RPM] = {SMD_TZ, SMD_RPM},
};

struct restart_notifier_block {
	unsigned processor;
	char *name;
	struct notifier_block nb;
};

static struct platform_device loopback_tty_pdev = {.name = "LOOPBACK_TTY"};

static LIST_HEAD(smd_ch_closed_list);
static LIST_HEAD(smd_ch_closing_list);
static LIST_HEAD(smd_ch_to_close_list);

struct remote_proc_info {
	unsigned remote_pid;
	unsigned free_space;
	struct work_struct probe_work;
	struct list_head ch_list;
	
	unsigned char ch_allocated[SMEM_NUM_SMD_STREAM_CHANNELS * 2];
	bool skip_pil;
};

static struct remote_proc_info remote_info[NUM_SMD_SUBSYSTEMS];

static void finalize_channel_close_fn(struct work_struct *work);
static DECLARE_WORK(finalize_channel_close_work, finalize_channel_close_fn);
static struct workqueue_struct *channel_close_wq;

#define PRI_ALLOC_TBL 1
#define SEC_ALLOC_TBL 2
static int smd_alloc_channel(struct smd_alloc_elm *alloc_elm, int table_id,
				struct remote_proc_info *r_info);

static bool smd_edge_inited(int edge)
{
	return edge_to_pids[edge].initialized;
}

static DEFINE_MUTEX(smd_probe_lock);

static void scan_alloc_table(struct smd_alloc_elm *shared,
				char *smd_ch_allocated,
				int table_id,
				unsigned num_entries,
				struct remote_proc_info *r_info)
{
	unsigned n;
	uint32_t type;

	for (n = 0; n < num_entries; n++) {
		if (smd_ch_allocated[n])
			continue;

		type = SMD_CHANNEL_TYPE(shared[n].type);
		if (!pid_is_on_edge(type, SMD_APPS) ||
				!pid_is_on_edge(type, r_info->remote_pid))
			continue;
		if (!shared[n].ref_count)
			continue;
		if (!shared[n].name[0])
			continue;

		if (!smd_edge_inited(type)) {
			SMD_INFO(
				"Probe skipping proc %d, tbl %d, ch %d, edge not inited\n",
				r_info->remote_pid, table_id, n);
			continue;
		}

		if (!smd_alloc_channel(&shared[n], table_id, r_info))
			smd_ch_allocated[n] = 1;
		else
			SMD_INFO(
				"Probe skipping proc %d, tbl %d, ch %d, not allocated\n",
				r_info->remote_pid, table_id, n);
	}
}

static void smd_channel_probe_now(struct remote_proc_info *r_info)
{
	struct smd_alloc_elm *shared;
	unsigned tbl_size;

	shared = smem_get_entry(ID_CH_ALLOC_TBL, &tbl_size,
							r_info->remote_pid, 0);

	if (!shared) {
		pr_err("%s: allocation table not initialized\n", __func__);
		return;
	}

	mutex_lock(&smd_probe_lock);

	scan_alloc_table(shared, r_info->ch_allocated, PRI_ALLOC_TBL,
						tbl_size / sizeof(*shared),
						r_info);

	shared = smem_get_entry(SMEM_CHANNEL_ALLOC_TBL_2, &tbl_size,
							r_info->remote_pid, 0);
	if (shared)
		scan_alloc_table(shared,
			&(r_info->ch_allocated[SMEM_NUM_SMD_STREAM_CHANNELS]),
			SEC_ALLOC_TBL,
			tbl_size / sizeof(*shared),
			r_info);

	mutex_unlock(&smd_probe_lock);
}

static void smd_channel_probe_worker(struct work_struct *work)
{
	struct remote_proc_info *r_info;

	r_info = container_of(work, struct remote_proc_info, probe_work);

	smd_channel_probe_now(r_info);
}

static int get_remote_ch(void *shared2,
		uint32_t type, uint32_t pid,
		void **remote_ch,
		int is_word_access_ch
		)
{
	if (!remote_ch || !shared2 || !pid_is_on_edge(type, pid) ||
				!pid_is_on_edge(type, SMD_APPS))
		return -EINVAL;

	if (is_word_access_ch)
		*remote_ch =
			&((struct smd_shared_word_access *)(shared2))->ch1;
	else
		*remote_ch = &((struct smd_shared *)(shared2))->ch1;

	return 0;
}

int smd_remote_ss_to_edge(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(edge_to_pids); ++i) {
		if (edge_to_pids[i].subsys_name[0] != 0x0) {
			if (!strncmp(edge_to_pids[i].subsys_name, name,
								strlen(name)))
				return i;
		}
	}

	return -EINVAL;
}
EXPORT_SYMBOL(smd_remote_ss_to_edge);

const char *smd_edge_to_pil_str(uint32_t type)
{
	const char *pil_str = NULL;

	if (type < ARRAY_SIZE(edge_to_pids)) {
		if (!edge_to_pids[type].initialized)
			return ERR_PTR(-EPROBE_DEFER);
		if (!remote_info[smd_edge_to_remote_pid(type)].skip_pil) {
			pil_str = edge_to_pids[type].subsys_name;
			if (pil_str[0] == 0x0)
				pil_str = NULL;
		}
	}
	return pil_str;
}
EXPORT_SYMBOL(smd_edge_to_pil_str);

const char *smd_edge_to_subsystem(uint32_t type)
{
	const char *subsys = NULL;

	if (type < ARRAY_SIZE(edge_to_pids)) {
		subsys = edge_to_pids[type].subsys_name;
		if (subsys[0] == 0x0)
			subsys = NULL;
		if (!edge_to_pids[type].initialized)
			subsys = ERR_PTR(-EPROBE_DEFER);
	}
	return subsys;
}
EXPORT_SYMBOL(smd_edge_to_subsystem);

const char *smd_pid_to_subsystem(uint32_t pid)
{
	const char *subsys = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(edge_to_pids); ++i) {
		if (pid == edge_to_pids[i].remote_pid) {
			if (!edge_to_pids[i].initialized) {
				subsys = ERR_PTR(-EPROBE_DEFER);
				break;
			}
			if (edge_to_pids[i].subsys_name[0] != 0x0) {
				subsys = edge_to_pids[i].subsys_name;
				break;
			} else if (pid == SMD_RPM) {
				subsys = "rpm";
				break;
			}
		}
	}

	return subsys;
}
EXPORT_SYMBOL(smd_pid_to_subsystem);

static void smd_reset_edge(void *void_ch, unsigned new_state,
				int is_word_access_ch)
{
	if (is_word_access_ch) {
		struct smd_half_channel_word_access *ch =
			(struct smd_half_channel_word_access *)(void_ch);
		if (ch->state != SMD_SS_CLOSED) {
			ch->state = new_state;
			ch->fDSR = 0;
			ch->fCTS = 0;
			ch->fCD = 0;
			ch->fSTATE = 1;
		}
	} else {
		struct smd_half_channel *ch =
			(struct smd_half_channel *)(void_ch);
		if (ch->state != SMD_SS_CLOSED) {
			ch->state = new_state;
			ch->fDSR = 0;
			ch->fCTS = 0;
			ch->fCD = 0;
			ch->fSTATE = 1;
		}
	}
}

static void smd_channel_reset_state(struct smd_alloc_elm *shared, int table_id,
		unsigned new_state, unsigned pid, unsigned num_entries)
{
	unsigned n;
	void *shared2;
	uint32_t type;
	void *remote_ch;
	int is_word_access;
	unsigned base_id;

	switch (table_id) {
	case PRI_ALLOC_TBL:
		base_id = SMEM_SMD_BASE_ID;
		break;
	case SEC_ALLOC_TBL:
		base_id = SMEM_SMD_BASE_ID_2;
		break;
	default:
		SMD_INFO("%s: invalid table_id:%d\n", __func__, table_id);
		return;
	}

	for (n = 0; n < num_entries; n++) {
		if (!shared[n].ref_count)
			continue;
		if (!shared[n].name[0])
			continue;

		type = SMD_CHANNEL_TYPE(shared[n].type);
		is_word_access = is_word_access_ch(type);
		if (is_word_access)
			shared2 = smem_find(base_id + n,
				sizeof(struct smd_shared_word_access), pid,
				0);
		else
			shared2 = smem_find(base_id + n,
				sizeof(struct smd_shared), pid, 0);
		if (!shared2)
			continue;

		if (!get_remote_ch(shared2, type, pid,
					&remote_ch, is_word_access))
			smd_reset_edge(remote_ch, new_state, is_word_access);
	}
}

static bool pid_is_on_edge(uint32_t edge_num, unsigned pid)
{
	struct edge_to_pid edge;

	if (edge_num >= ARRAY_SIZE(edge_to_pids))
		return 0;

	edge = edge_to_pids[edge_num];
	return (edge.local_pid == pid || edge.remote_pid == pid);
}

void smd_channel_reset(uint32_t restart_pid)
{
	struct smd_alloc_elm *shared_pri;
	struct smd_alloc_elm *shared_sec;
	unsigned long flags;
	unsigned pri_size;
	unsigned sec_size;

	SMD_POWER_INFO("%s: starting reset\n", __func__);

	shared_pri = smem_get_entry(ID_CH_ALLOC_TBL, &pri_size,	restart_pid, 0);
	if (!shared_pri) {
		pr_err("%s: allocation table not initialized\n", __func__);
		return;
	}
	shared_sec = smem_get_entry(SMEM_CHANNEL_ALLOC_TBL_2, &sec_size,
								restart_pid, 0);

	
	if (smsm_info.state) {
		writel_relaxed(0, SMSM_STATE_ADDR(restart_pid));

		
		if (restart_pid == SMSM_MODEM) {
			smsm_change_state(SMSM_APPS_STATE,
				SMSM_INIT | SMSM_SMD_LOOPBACK | SMSM_RESET,
				0);
		}

		
		smsm_irq_handler(0, 0);
		notify_modem_smsm();
		notify_dsp_smsm();
		notify_dsps_smsm();
		notify_wcnss_smsm();
	}

	
	mutex_lock(&smd_probe_lock);
	spin_lock_irqsave(&smd_lock, flags);
	smd_channel_reset_state(shared_pri, PRI_ALLOC_TBL, SMD_SS_CLOSING,
				restart_pid, pri_size / sizeof(*shared_pri));
	if (shared_sec)
		smd_channel_reset_state(shared_sec, SEC_ALLOC_TBL,
						SMD_SS_CLOSING, restart_pid,
						sec_size / sizeof(*shared_sec));
	spin_unlock_irqrestore(&smd_lock, flags);
	mutex_unlock(&smd_probe_lock);

	mb();
	smd_fake_irq_handler(0);

	
	mutex_lock(&smd_probe_lock);
	spin_lock_irqsave(&smd_lock, flags);
	smd_channel_reset_state(shared_pri, PRI_ALLOC_TBL, SMD_SS_CLOSED,
				restart_pid, pri_size / sizeof(*shared_pri));
	if (shared_sec)
		smd_channel_reset_state(shared_sec, SEC_ALLOC_TBL,
						SMD_SS_CLOSED, restart_pid,
						sec_size / sizeof(*shared_sec));
	spin_unlock_irqrestore(&smd_lock, flags);
	mutex_unlock(&smd_probe_lock);

	mb();
	smd_fake_irq_handler(0);

	SMD_POWER_INFO("%s: finished reset\n", __func__);
}

static int smd_stream_read_avail(struct smd_channel *ch)
{
	unsigned head = ch->half_ch->get_head(ch->recv);
	unsigned tail = ch->half_ch->get_tail(ch->recv);
	unsigned fifo_size = ch->fifo_size;
	unsigned bytes_avail = head - tail;

	if (head < tail)
		bytes_avail += fifo_size;

	BUG_ON(bytes_avail >= fifo_size);
	return bytes_avail;
}

static int smd_stream_write_avail(struct smd_channel *ch)
{
	unsigned head = ch->half_ch->get_head(ch->send);
	unsigned tail = ch->half_ch->get_tail(ch->send);
	unsigned fifo_size = ch->fifo_size;
	unsigned bytes_avail = tail - head;

	if (tail <= head)
		bytes_avail += fifo_size;
	if (bytes_avail < SMD_FIFO_FULL_RESERVE)
		bytes_avail = 0;
	else
		bytes_avail -= SMD_FIFO_FULL_RESERVE;

	BUG_ON(bytes_avail >= fifo_size);
	return bytes_avail;
}

static int smd_packet_read_avail(struct smd_channel *ch)
{
	if (ch->current_packet) {
		int n = smd_stream_read_avail(ch);
		if (n > ch->current_packet)
			n = ch->current_packet;
		return n;
	} else {
		return 0;
	}
}

static int smd_packet_write_avail(struct smd_channel *ch)
{
	int n = smd_stream_write_avail(ch);
	return n > SMD_HEADER_SIZE ? n - SMD_HEADER_SIZE : 0;
}

static int ch_is_open(struct smd_channel *ch)
{
	return (ch->half_ch->get_state(ch->recv) == SMD_SS_OPENED ||
		ch->half_ch->get_state(ch->recv) == SMD_SS_FLUSHING)
		&& (ch->half_ch->get_state(ch->send) == SMD_SS_OPENED);
}

static unsigned ch_read_buffer(struct smd_channel *ch, void **ptr)
{
	unsigned head = ch->half_ch->get_head(ch->recv);
	unsigned tail = ch->half_ch->get_tail(ch->recv);
	unsigned fifo_size = ch->fifo_size;

	BUG_ON(fifo_size >= SZ_1M);
	BUG_ON(head >= fifo_size);
	BUG_ON(tail >= fifo_size);
	BUG_ON(OVERFLOW_ADD_UNSIGNED(uintptr_t, (uintptr_t)ch->recv_data,
								tail));
	*ptr = (void *) (ch->recv_data + tail);
	if (tail <= head)
		return head - tail;
	else
		return fifo_size - tail;
}

static int read_intr_blocked(struct smd_channel *ch)
{
	return ch->half_ch->get_fBLOCKREADINTR(ch->recv);
}

static void ch_read_done(struct smd_channel *ch, unsigned count)
{
	unsigned tail = ch->half_ch->get_tail(ch->recv);
	unsigned fifo_size = ch->fifo_size;

	BUG_ON(count > smd_stream_read_avail(ch));

	tail += count;
	if (tail >= fifo_size)
		tail -= fifo_size;
	ch->half_ch->set_tail(ch->recv, tail);
	wmb();
	ch->half_ch->set_fTAIL(ch->send,  1);
}

static int ch_read(struct smd_channel *ch, void *_data, int len)
{
	void *ptr;
	unsigned n;
	unsigned char *data = _data;
	int orig_len = len;

	while (len > 0) {
		n = ch_read_buffer(ch, &ptr);
		if (n == 0)
			break;

		if (n > len)
			n = len;
		if (_data)
			ch->read_from_fifo(data, ptr, n);

		data += n;
		len -= n;
		ch_read_done(ch, n);
	}

	return orig_len - len;
}

static void update_stream_state(struct smd_channel *ch)
{
	
}

static void update_packet_state(struct smd_channel *ch)
{
	unsigned hdr[5];
	int r;
	const char *peripheral = NULL;

	
	while (ch->current_packet == 0) {
		

		
		if (smd_stream_read_avail(ch) < SMD_HEADER_SIZE)
			return;

		r = ch_read(ch, hdr, SMD_HEADER_SIZE);
		BUG_ON(r != SMD_HEADER_SIZE);

		ch->current_packet = hdr[0];
		if (ch->current_packet > (uint32_t)INT_MAX) {
			pr_err("%s: Invalid packet size of %d bytes detected. Edge: %d, Channel : %s, RPTR: %d, WPTR: %d",
				__func__, ch->current_packet, ch->type,
				ch->name, ch->half_ch->get_tail(ch->recv),
				ch->half_ch->get_head(ch->recv));
			peripheral = smd_edge_to_pil_str(ch->type);
			if (peripheral) {
				if (subsystem_restart(peripheral) < 0)
					BUG();
			} else {
				BUG();
			}
		}
	}
}

/**
 * ch_write_buffer() - Provide a pointer and length for the next segment of
 * free space in the FIFO.
 * @ch: channel
 * @ptr: Address to pointer for the next segment write
 * @returns: Maximum size that can be written until the FIFO is either full
 *           or the end of the FIFO has been reached.
 *
 * The returned pointer and length are passed to memcpy, so the next segment is
 * defined as either the space available between the read index (tail) and the
 * write index (head) or the space available to the end of the FIFO.
 */
static unsigned ch_write_buffer(struct smd_channel *ch, void **ptr)
{
	unsigned head = ch->half_ch->get_head(ch->send);
	unsigned tail = ch->half_ch->get_tail(ch->send);
	unsigned fifo_size = ch->fifo_size;

	BUG_ON(fifo_size >= SZ_1M);
	BUG_ON(head >= fifo_size);
	BUG_ON(tail >= fifo_size);
	BUG_ON(OVERFLOW_ADD_UNSIGNED(uintptr_t, (uintptr_t)ch->send_data,
								head));

	*ptr = (void *) (ch->send_data + head);
	if (head < tail) {
		return tail - head - SMD_FIFO_FULL_RESERVE;
	} else {
		if (tail < SMD_FIFO_FULL_RESERVE)
			return fifo_size + tail - head
					- SMD_FIFO_FULL_RESERVE;
		else
			return fifo_size - head;
	}
}

static void ch_write_done(struct smd_channel *ch, unsigned count)
{
	unsigned head = ch->half_ch->get_head(ch->send);
	unsigned fifo_size = ch->fifo_size;

	BUG_ON(count > smd_stream_write_avail(ch));
	head += count;
	if (head >= fifo_size)
		head -= fifo_size;
	ch->half_ch->set_head(ch->send, head);
	wmb();
	ch->half_ch->set_fHEAD(ch->send, 1);
}

static void ch_set_state(struct smd_channel *ch, unsigned n)
{
	if (n == SMD_SS_OPENED) {
		ch->half_ch->set_fDSR(ch->send, 1);
		ch->half_ch->set_fCTS(ch->send, 1);
		ch->half_ch->set_fCD(ch->send, 1);
	} else {
		ch->half_ch->set_fDSR(ch->send, 0);
		ch->half_ch->set_fCTS(ch->send, 0);
		ch->half_ch->set_fCD(ch->send, 0);
	}
	ch->half_ch->set_state(ch->send, n);
	ch->half_ch->set_fSTATE(ch->send, 1);
	ch->notify_other_cpu(ch);
}

static void do_smd_probe(unsigned remote_pid)
{
	unsigned free_space;

	free_space = smem_get_free_space(remote_pid);
	if (free_space != remote_info[remote_pid].free_space) {
		remote_info[remote_pid].free_space = free_space;
		schedule_work(&remote_info[remote_pid].probe_work);
	}
}

static void smd_state_change(struct smd_channel *ch,
			     unsigned last, unsigned next)
{
	ch->last_state = next;

	SMD_INFO("SMD: ch %d %d -> %d\n", ch->n, last, next);

	switch (next) {
	case SMD_SS_OPENING:
		if (ch->half_ch->get_state(ch->send) == SMD_SS_CLOSING ||
		    ch->half_ch->get_state(ch->send) == SMD_SS_CLOSED) {
			ch->half_ch->set_tail(ch->recv, 0);
			ch->half_ch->set_head(ch->send, 0);
			ch->half_ch->set_fBLOCKREADINTR(ch->send, 0);
			ch->current_packet = 0;
			ch_set_state(ch, SMD_SS_OPENING);
		}
		break;
	case SMD_SS_OPENED:
		if (ch->half_ch->get_state(ch->send) == SMD_SS_OPENING) {
			ch_set_state(ch, SMD_SS_OPENED);
			ch->notify(ch->priv, SMD_EVENT_OPEN);
		}
		break;
	case SMD_SS_FLUSHING:
	case SMD_SS_RESET:
		
		break;
	case SMD_SS_CLOSED:
		if (ch->half_ch->get_state(ch->send) == SMD_SS_OPENED) {
			ch_set_state(ch, SMD_SS_CLOSING);
			ch->pending_pkt_sz = 0;
			ch->notify(ch->priv, SMD_EVENT_CLOSE);
		}
		break;
	case SMD_SS_CLOSING:
		if (ch->half_ch->get_state(ch->send) == SMD_SS_CLOSED) {
			list_move(&ch->ch_list,
					&smd_ch_to_close_list);
			queue_work(channel_close_wq,
						&finalize_channel_close_work);
		}
		break;
	}
}

static void handle_smd_irq_closing_list(void)
{
	unsigned long flags;
	struct smd_channel *ch;
	struct smd_channel *index;
	unsigned tmp;

	spin_lock_irqsave(&smd_lock, flags);
	list_for_each_entry_safe(ch, index, &smd_ch_closing_list, ch_list) {
		if (ch->half_ch->get_fSTATE(ch->recv))
			ch->half_ch->set_fSTATE(ch->recv, 0);
		tmp = ch->half_ch->get_state(ch->recv);
		if (tmp != ch->last_state)
			smd_state_change(ch, ch->last_state, tmp);
	}
	spin_unlock_irqrestore(&smd_lock, flags);
}

static void handle_smd_irq(struct remote_proc_info *r_info,
		void (*notify)(smd_channel_t *ch))
{
	unsigned long flags;
	struct smd_channel *ch;
	unsigned ch_flags;
	unsigned tmp;
	unsigned char state_change;
	struct list_head *list;

	list = &r_info->ch_list;

	spin_lock_irqsave(&smd_lock, flags);
	list_for_each_entry(ch, list, ch_list) {
		state_change = 0;
		ch_flags = 0;
		if (ch_is_open(ch)) {
			if (ch->half_ch->get_fHEAD(ch->recv)) {
				ch->half_ch->set_fHEAD(ch->recv, 0);
				ch_flags |= 1;
			}
			if (ch->half_ch->get_fTAIL(ch->recv)) {
				ch->half_ch->set_fTAIL(ch->recv, 0);
				ch_flags |= 2;
			}
			if (ch->half_ch->get_fSTATE(ch->recv)) {
				ch->half_ch->set_fSTATE(ch->recv, 0);
				ch_flags |= 4;
			}
		}
		tmp = ch->half_ch->get_state(ch->recv);
		if (tmp != ch->last_state) {
			SMD_POWER_INFO("SMD ch%d '%s' State change %d->%d\n",
					ch->n, ch->name, ch->last_state, tmp);
			smd_state_change(ch, ch->last_state, tmp);
			state_change = 1;
		}
		if (ch_flags & 0x3) {
			ch->update_state(ch);
			SMD_POWER_INFO(
				"SMD ch%d '%s' Data event 0x%x tx%d/rx%d %dr/%dw : %dr/%dw\n",
				ch->n, ch->name,
				ch_flags,
				ch->fifo_size -
					(smd_stream_write_avail(ch) + 1),
				smd_stream_read_avail(ch),
				ch->half_ch->get_tail(ch->send),
				ch->half_ch->get_head(ch->send),
				ch->half_ch->get_tail(ch->recv),
				ch->half_ch->get_head(ch->recv)
				);
			ch->notify(ch->priv, SMD_EVENT_DATA);
		}
		if (ch_flags & 0x4 && !state_change) {
			SMD_POWER_INFO("SMD ch%d '%s' State update\n",
					ch->n, ch->name);
			ch->notify(ch->priv, SMD_EVENT_STATUS);
		}
	}
	spin_unlock_irqrestore(&smd_lock, flags);
	do_smd_probe(r_info->remote_pid);
}

static inline void log_irq(uint32_t subsystem)
{
	const char *subsys = smd_edge_to_subsystem(subsystem);

	(void) subsys;

	SMD_POWER_INFO("SMD Int %s->Apps\n", subsys);
}

irqreturn_t smd_modem_irq_handler(int irq, void *data)
{
	if (unlikely(!edge_to_pids[SMD_APPS_MODEM].initialized))
		return IRQ_HANDLED;
	log_irq(SMD_APPS_MODEM);
	++interrupt_stats[SMD_MODEM].smd_in_count;
	handle_smd_irq(&remote_info[SMD_MODEM], notify_modem_smd);
	handle_smd_irq_closing_list();
	return IRQ_HANDLED;
}

irqreturn_t smd_dsp_irq_handler(int irq, void *data)
{
	if (unlikely(!edge_to_pids[SMD_APPS_QDSP].initialized))
		return IRQ_HANDLED;
	log_irq(SMD_APPS_QDSP);
	++interrupt_stats[SMD_Q6].smd_in_count;
	handle_smd_irq(&remote_info[SMD_Q6], notify_dsp_smd);
	handle_smd_irq_closing_list();
	return IRQ_HANDLED;
}

irqreturn_t smd_dsps_irq_handler(int irq, void *data)
{
	if (unlikely(!edge_to_pids[SMD_APPS_DSPS].initialized))
		return IRQ_HANDLED;
	log_irq(SMD_APPS_DSPS);
	++interrupt_stats[SMD_DSPS].smd_in_count;
	handle_smd_irq(&remote_info[SMD_DSPS], notify_dsps_smd);
	handle_smd_irq_closing_list();
	return IRQ_HANDLED;
}

irqreturn_t smd_wcnss_irq_handler(int irq, void *data)
{
	if (unlikely(!edge_to_pids[SMD_APPS_WCNSS].initialized))
		return IRQ_HANDLED;
	log_irq(SMD_APPS_WCNSS);
	++interrupt_stats[SMD_WCNSS].smd_in_count;
	handle_smd_irq(&remote_info[SMD_WCNSS], notify_wcnss_smd);
	handle_smd_irq_closing_list();
	return IRQ_HANDLED;
}

irqreturn_t smd_modemfw_irq_handler(int irq, void *data)
{
	if (unlikely(!edge_to_pids[SMD_APPS_Q6FW].initialized))
		return IRQ_HANDLED;
	log_irq(SMD_APPS_Q6FW);
	++interrupt_stats[SMD_MODEM_Q6_FW].smd_in_count;
	handle_smd_irq(&remote_info[SMD_MODEM_Q6_FW], notify_modemfw_smd);
	handle_smd_irq_closing_list();
	return IRQ_HANDLED;
}

irqreturn_t smd_rpm_irq_handler(int irq, void *data)
{
	if (unlikely(!edge_to_pids[SMD_APPS_RPM].initialized))
		return IRQ_HANDLED;
	log_irq(SMD_APPS_RPM);
	++interrupt_stats[SMD_RPM].smd_in_count;
	handle_smd_irq(&remote_info[SMD_RPM], notify_rpm_smd);
	handle_smd_irq_closing_list();
	return IRQ_HANDLED;
}

static void smd_fake_irq_handler(unsigned long arg)
{
	handle_smd_irq(&remote_info[SMD_MODEM], notify_modem_smd);
	handle_smd_irq(&remote_info[SMD_Q6], notify_dsp_smd);
	handle_smd_irq(&remote_info[SMD_DSPS], notify_dsps_smd);
	handle_smd_irq(&remote_info[SMD_WCNSS], notify_wcnss_smd);
	handle_smd_irq(&remote_info[SMD_MODEM_Q6_FW], notify_modemfw_smd);
	handle_smd_irq(&remote_info[SMD_RPM], notify_rpm_smd);
	handle_smd_irq_closing_list();
}

static int smd_is_packet(struct smd_alloc_elm *alloc_elm)
{
	if (SMD_XFER_TYPE(alloc_elm->type) == 1)
		return 0;
	else if (SMD_XFER_TYPE(alloc_elm->type) == 2)
		return 1;

	panic("Unsupported SMD xfer type: %d name:%s edge:%d\n",
					SMD_XFER_TYPE(alloc_elm->type),
					alloc_elm->name,
					SMD_CHANNEL_TYPE(alloc_elm->type));
}

static int smd_stream_write(smd_channel_t *ch, const void *_data, int len,
				bool intr_ntfy)
{
	void *ptr;
	const unsigned char *buf = _data;
	unsigned xfer;
	int orig_len = len;

	SMD_DBG("smd_stream_write() %d -> ch%d\n", len, ch->n);
	if (len < 0)
		return -EINVAL;
	else if (len == 0)
		return 0;

	while ((xfer = ch_write_buffer(ch, &ptr)) != 0) {
		if (!ch_is_open(ch)) {
			len = orig_len;
			break;
		}
		if (xfer > len)
			xfer = len;

		ch->write_to_fifo(ptr, buf, xfer);
		ch_write_done(ch, xfer);
		len -= xfer;
		buf += xfer;
		if (len == 0)
			break;
	}

	if (orig_len - len && intr_ntfy)
		ch->notify_other_cpu(ch);

	return orig_len - len;
}

static int smd_packet_write(smd_channel_t *ch, const void *_data, int len,
				bool intr_ntfy)
{
	int ret;
	unsigned hdr[5];

	SMD_DBG("smd_packet_write() %d -> ch%d\n", len, ch->n);
	if (len < 0)
		return -EINVAL;
	else if (len == 0)
		return 0;

	if (smd_stream_write_avail(ch) < (len + SMD_HEADER_SIZE))
		return -ENOMEM;

	hdr[0] = len;
	hdr[1] = hdr[2] = hdr[3] = hdr[4] = 0;


	ret = smd_stream_write(ch, hdr, sizeof(hdr), false);
	if (ret < 0 || ret != sizeof(hdr)) {
		SMD_DBG("%s failed to write pkt header: %d returned\n",
								__func__, ret);
		return -EFAULT;
	}


	ret = smd_stream_write(ch, _data, len, true);
	if (ret < 0 || ret != len) {
		SMD_DBG("%s failed to write pkt data: %d returned\n",
								__func__, ret);
		return ret;
	}

	return len;
}

static int smd_stream_read(smd_channel_t *ch, void *data, int len)
{
	int r;

	if (len < 0)
		return -EINVAL;

	r = ch_read(ch, data, len);
	if (r > 0)
		if (!read_intr_blocked(ch))
			ch->notify_other_cpu(ch);

	return r;
}

static int smd_packet_read(smd_channel_t *ch, void *data, int len)
{
	unsigned long flags;
	int r;

	if (len < 0)
		return -EINVAL;

	if (ch->current_packet > (uint32_t)INT_MAX) {
		pr_err("%s: Invalid packet size for Edge %d and Channel %s",
			__func__, ch->type, ch->name);
		return -EFAULT;
	}

	if (len > ch->current_packet)
		len = ch->current_packet;

	r = ch_read(ch, data, len);
	if (r > 0)
		if (!read_intr_blocked(ch))
			ch->notify_other_cpu(ch);

	spin_lock_irqsave(&smd_lock, flags);
	ch->current_packet -= r;
	update_packet_state(ch);
	spin_unlock_irqrestore(&smd_lock, flags);

	return r;
}

static int smd_packet_read_from_cb(smd_channel_t *ch, void *data, int len)
{
	int r;

	if (len < 0)
		return -EINVAL;

	if (ch->current_packet > (uint32_t)INT_MAX) {
		pr_err("%s: Invalid packet size for Edge %d and Channel %s",
			__func__, ch->type, ch->name);
		return -EFAULT;
	}

	if (len > ch->current_packet)
		len = ch->current_packet;

	r = ch_read(ch, data, len);
	if (r > 0)
		if (!read_intr_blocked(ch))
			ch->notify_other_cpu(ch);

	ch->current_packet -= r;
	update_packet_state(ch);

	return r;
}

static int smd_alloc(struct smd_channel *ch, int table_id,
						struct remote_proc_info *r_info)
{
	void *buffer;
	unsigned buffer_sz;
	unsigned base_id;
	unsigned fifo_id;

	switch (table_id) {
	case PRI_ALLOC_TBL:
		base_id = SMEM_SMD_BASE_ID;
		fifo_id = SMEM_SMD_FIFO_BASE_ID;
		break;
	case SEC_ALLOC_TBL:
		base_id = SMEM_SMD_BASE_ID_2;
		fifo_id = SMEM_SMD_FIFO_BASE_ID_2;
		break;
	default:
		SMD_INFO("Invalid table_id:%d passed to smd_alloc\n", table_id);
		return -EINVAL;
	}

	if (is_word_access_ch(ch->type)) {
		struct smd_shared_word_access *shared2;
		shared2 = smem_find(base_id + ch->n, sizeof(*shared2),
							r_info->remote_pid, 0);
		if (!shared2) {
			SMD_INFO("smem_find failed ch=%d\n", ch->n);
			return -EINVAL;
		}
		ch->send = &shared2->ch0;
		ch->recv = &shared2->ch1;
	} else {
		struct smd_shared *shared2;
		shared2 = smem_find(base_id + ch->n, sizeof(*shared2),
							r_info->remote_pid, 0);
		if (!shared2) {
			SMD_INFO("smem_find failed ch=%d\n", ch->n);
			return -EINVAL;
		}
		ch->send = &shared2->ch0;
		ch->recv = &shared2->ch1;
	}
	ch->half_ch = get_half_ch_funcs(ch->type);

	buffer = smem_get_entry(fifo_id + ch->n, &buffer_sz,
							r_info->remote_pid, 0);
	if (!buffer) {
		SMD_INFO("smem_get_entry failed\n");
		return -EINVAL;
	}

	
	if ((buffer_sz & (SZ_32 - 1)) != 0) {
		SMD_INFO("Buffer size: %u not multiple of 32\n", buffer_sz);
		return -EINVAL;
	}
	buffer_sz /= 2;
	ch->send_data = buffer;
	ch->recv_data = buffer + buffer_sz;
	ch->fifo_size = buffer_sz;

	return 0;
}

static int smd_alloc_channel(struct smd_alloc_elm *alloc_elm, int table_id,
				struct remote_proc_info *r_info)
{
	struct smd_channel *ch;

	ch = kzalloc(sizeof(struct smd_channel), GFP_KERNEL);
	if (ch == 0) {
		pr_err("smd_alloc_channel() out of memory\n");
		return -ENOMEM;
	}
	ch->n = alloc_elm->cid;
	ch->type = SMD_CHANNEL_TYPE(alloc_elm->type);

	if (smd_alloc(ch, table_id, r_info)) {
		kfree(ch);
		return -ENODEV;
	}

	
	if (ch->type == SMD_APPS_MODEM)
		ch->notify_other_cpu = notify_modem_smd;
	else if (ch->type == SMD_APPS_QDSP)
		ch->notify_other_cpu = notify_dsp_smd;
	else if (ch->type == SMD_APPS_DSPS)
		ch->notify_other_cpu = notify_dsps_smd;
	else if (ch->type == SMD_APPS_WCNSS)
		ch->notify_other_cpu = notify_wcnss_smd;
	else if (ch->type == SMD_APPS_Q6FW)
		ch->notify_other_cpu = notify_modemfw_smd;
	else if (ch->type == SMD_APPS_RPM)
		ch->notify_other_cpu = notify_rpm_smd;

	if (smd_is_packet(alloc_elm)) {
		ch->read = smd_packet_read;
		ch->write = smd_packet_write;
		ch->read_avail = smd_packet_read_avail;
		ch->write_avail = smd_packet_write_avail;
		ch->update_state = update_packet_state;
		ch->read_from_cb = smd_packet_read_from_cb;
		ch->is_pkt_ch = 1;
	} else {
		ch->read = smd_stream_read;
		ch->write = smd_stream_write;
		ch->read_avail = smd_stream_read_avail;
		ch->write_avail = smd_stream_write_avail;
		ch->update_state = update_stream_state;
		ch->read_from_cb = smd_stream_read;
	}

	if (is_word_access_ch(ch->type)) {
		ch->read_from_fifo = smd_memcpy32_from_fifo;
		ch->write_to_fifo = smd_memcpy32_to_fifo;
	} else {
		ch->read_from_fifo = smd_memcpy_from_fifo;
		ch->write_to_fifo = smd_memcpy_to_fifo;
	}

	smd_memcpy_from_fifo(ch->name, alloc_elm->name, SMD_MAX_CH_NAME_LEN);
	ch->name[SMD_MAX_CH_NAME_LEN-1] = 0;

	ch->pdev.name = ch->name;
	ch->pdev.id = ch->type;

	SMD_INFO("smd_alloc_channel() '%s' cid=%d\n",
		 ch->name, ch->n);

	mutex_lock(&smd_creation_mutex);
	list_add(&ch->ch_list, &smd_ch_closed_list);
	mutex_unlock(&smd_creation_mutex);

	platform_device_register(&ch->pdev);
	if (!strncmp(ch->name, "LOOPBACK", 8) && ch->type == SMD_APPS_MODEM) {
		loopback_tty_pdev.id = ch->type;
		platform_device_register(&loopback_tty_pdev);
	}
	return 0;
}

static void do_nothing_notify(void *priv, unsigned flags)
{
}

static void finalize_channel_close_fn(struct work_struct *work)
{
	unsigned long flags;
	struct smd_channel *ch;
	struct smd_channel *index;

	mutex_lock(&smd_creation_mutex);
	spin_lock_irqsave(&smd_lock, flags);
	list_for_each_entry_safe(ch, index,  &smd_ch_to_close_list, ch_list) {
		list_del(&ch->ch_list);
		list_add(&ch->ch_list, &smd_ch_closed_list);
		ch->notify(ch->priv, SMD_EVENT_REOPEN_READY);
		ch->notify = do_nothing_notify;
	}
	spin_unlock_irqrestore(&smd_lock, flags);
	mutex_unlock(&smd_creation_mutex);
}

struct smd_channel *smd_get_channel(const char *name, uint32_t type)
{
	struct smd_channel *ch;

	mutex_lock(&smd_creation_mutex);
	list_for_each_entry(ch, &smd_ch_closed_list, ch_list) {
		if (!strcmp(name, ch->name) &&
			(type == ch->type)) {
			list_del(&ch->ch_list);
			mutex_unlock(&smd_creation_mutex);
			return ch;
		}
	}
	mutex_unlock(&smd_creation_mutex);

	return NULL;
}

int smd_named_open_on_edge(const char *name, uint32_t edge,
			   smd_channel_t **_ch,
			   void *priv, void (*notify)(void *, unsigned))
{
	struct smd_channel *ch;
	unsigned long flags;

	if (edge >= SMD_NUM_TYPE) {
		pr_err("%s: edge:%d is invalid\n", __func__, edge);
		return -EINVAL;
	}

	if (!smd_edge_inited(edge)) {
		SMD_INFO("smd_open() before smd_init()\n");
		return -EPROBE_DEFER;
	}

	SMD_DBG("smd_open('%s', %p, %p)\n", name, priv, notify);

	ch = smd_get_channel(name, edge);
	if (!ch) {
		spin_lock_irqsave(&smd_lock, flags);
		
		list_for_each_entry(ch,
			&remote_info[edge_to_pids[edge].remote_pid].ch_list,
			ch_list) {
			if (!strcmp(name, ch->name)) {
				
				spin_unlock_irqrestore(&smd_lock, flags);
				SMD_DBG("smd_open: channel '%s' already open\n",
					ch->name);
				return -EBUSY;
			}
		}

		
		list_for_each_entry(ch, &smd_ch_closing_list, ch_list) {
			if (!strncmp(name, ch->name, 20) &&
				(edge == ch->type)) {
				
				spin_unlock_irqrestore(&smd_lock, flags);
				return -EAGAIN;
			}
		}

		
		list_for_each_entry(ch, &smd_ch_to_close_list, ch_list) {
			if (!strncmp(name, ch->name, 20) &&
				(edge == ch->type)) {
				
				spin_unlock_irqrestore(&smd_lock, flags);
				return -EAGAIN;
			}
		}
		spin_unlock_irqrestore(&smd_lock, flags);

		
		ch = smd_get_channel(name, edge);
		if (!ch)
			return -ENODEV;
	}

	if (ch->half_ch->get_fSTATE(ch->send)) {
		
		SMD_INFO("%s: ch %d valid, waiting for remote to ack state\n",
				__func__, ch->n);
		msleep(250);
		if (ch->half_ch->get_fSTATE(ch->send))
			SMD_INFO("%s: ch %d - no remote ack, continuing\n",
					__func__, ch->n);
	}

	if (notify == 0)
		notify = do_nothing_notify;

	ch->notify = notify;
	ch->current_packet = 0;
	ch->last_state = SMD_SS_CLOSED;
	ch->priv = priv;

	*_ch = ch;

	SMD_DBG("smd_open: opening '%s'\n", ch->name);

	spin_lock_irqsave(&smd_lock, flags);
	list_add(&ch->ch_list,
		       &remote_info[edge_to_pids[ch->type].remote_pid].ch_list);

	SMD_DBG("%s: opening ch %d\n", __func__, ch->n);

	smd_state_change(ch, ch->last_state, SMD_SS_OPENING);

	spin_unlock_irqrestore(&smd_lock, flags);

	return 0;
}
EXPORT_SYMBOL(smd_named_open_on_edge);

int smd_close(smd_channel_t *ch)
{
	unsigned long flags;
	bool was_opened;

	if (ch == 0)
		return -EINVAL;

	SMD_INFO("smd_close(%s)\n", ch->name);

	spin_lock_irqsave(&smd_lock, flags);
	list_del(&ch->ch_list);

	was_opened = ch->half_ch->get_state(ch->recv) == SMD_SS_OPENED;
	ch_set_state(ch, SMD_SS_CLOSED);

	if (was_opened) {
		list_add(&ch->ch_list, &smd_ch_closing_list);
		spin_unlock_irqrestore(&smd_lock, flags);
	} else {
		spin_unlock_irqrestore(&smd_lock, flags);
		ch->notify = do_nothing_notify;
		mutex_lock(&smd_creation_mutex);
		list_add(&ch->ch_list, &smd_ch_closed_list);
		mutex_unlock(&smd_creation_mutex);
	}

	return 0;
}
EXPORT_SYMBOL(smd_close);

int smd_write_start(smd_channel_t *ch, int len)
{
	int ret;
	unsigned hdr[5];

	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}
	if (!ch->is_pkt_ch) {
		pr_err("%s: non-packet channel specified\n", __func__);
		return -EACCES;
	}
	if (len < 1) {
		pr_err("%s: invalid length: %d\n", __func__, len);
		return -EINVAL;
	}

	if (ch->pending_pkt_sz) {
		pr_err("%s: packet of size: %d in progress\n", __func__,
			ch->pending_pkt_sz);
		return -EBUSY;
	}
	ch->pending_pkt_sz = len;

	if (smd_stream_write_avail(ch) < (SMD_HEADER_SIZE)) {
		ch->pending_pkt_sz = 0;
		SMD_DBG("%s: no space to write packet header\n", __func__);
		return -EAGAIN;
	}

	hdr[0] = len;
	hdr[1] = hdr[2] = hdr[3] = hdr[4] = 0;


	ret = smd_stream_write(ch, hdr, sizeof(hdr), true);
	if (ret < 0 || ret != sizeof(hdr)) {
		ch->pending_pkt_sz = 0;
		pr_err("%s: packet header failed to write\n", __func__);
		return -EPERM;
	}
	return 0;
}
EXPORT_SYMBOL(smd_write_start);

int smd_write_segment(smd_channel_t *ch, const void *data, int len)
{
	int bytes_written;

	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}
	if (len < 1) {
		pr_err("%s: invalid length: %d\n", __func__, len);
		return -EINVAL;
	}

	if (!ch->pending_pkt_sz) {
		pr_err("%s: no transaction in progress\n", __func__);
		return -ENOEXEC;
	}
	if (ch->pending_pkt_sz - len < 0) {
		pr_err("%s: segment of size: %d will make packet go over length\n",
								__func__, len);
		return -EINVAL;
	}

	bytes_written = smd_stream_write(ch, data, len, true);

	ch->pending_pkt_sz -= bytes_written;

	return bytes_written;
}
EXPORT_SYMBOL(smd_write_segment);

int smd_write_end(smd_channel_t *ch)
{

	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}
	if (ch->pending_pkt_sz) {
		pr_err("%s: current packet not completely written\n", __func__);
		return -E2BIG;
	}

	return 0;
}
EXPORT_SYMBOL(smd_write_end);

int smd_write_segment_avail(smd_channel_t *ch)
{
	int n;

	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}
	if (!ch->is_pkt_ch) {
		pr_err("%s: non-packet channel specified\n", __func__);
		return -ENODEV;
	}

	n = smd_stream_write_avail(ch);

	/* pkt hdr already written, no need to reserve space for it */
	if (ch->pending_pkt_sz)
		return n;

	return n > SMD_HEADER_SIZE ? n - SMD_HEADER_SIZE : 0;
}
EXPORT_SYMBOL(smd_write_segment_avail);

int smd_read(smd_channel_t *ch, void *data, int len)
{
	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}

	return ch->read(ch, data, len);
}
EXPORT_SYMBOL(smd_read);

int smd_read_from_cb(smd_channel_t *ch, void *data, int len)
{
	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}

	return ch->read_from_cb(ch, data, len);
}
EXPORT_SYMBOL(smd_read_from_cb);

int smd_write(smd_channel_t *ch, const void *data, int len)
{
	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}

	return ch->pending_pkt_sz ? -EBUSY : ch->write(ch, data, len, true);
}
EXPORT_SYMBOL(smd_write);

int smd_read_avail(smd_channel_t *ch)
{
	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}

	if (ch->current_packet > (uint32_t)INT_MAX) {
		pr_err("%s: Invalid packet size for Edge %d and Channel %s",
			__func__, ch->type, ch->name);
		return -EFAULT;
	}
	return ch->read_avail(ch);
}
EXPORT_SYMBOL(smd_read_avail);

int smd_write_avail(smd_channel_t *ch)
{
	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}

	return ch->write_avail(ch);
}
EXPORT_SYMBOL(smd_write_avail);

void smd_enable_read_intr(smd_channel_t *ch)
{
	if (ch)
		ch->half_ch->set_fBLOCKREADINTR(ch->send, 0);
}
EXPORT_SYMBOL(smd_enable_read_intr);

void smd_disable_read_intr(smd_channel_t *ch)
{
	if (ch)
		ch->half_ch->set_fBLOCKREADINTR(ch->send, 1);
}
EXPORT_SYMBOL(smd_disable_read_intr);

int smd_interrupt_id(smd_channel_t *ch)
{
    struct interrupt_config_item *int_cfg;

    if (!ch)
        return -1;

    if (ch->type >= ARRAY_SIZE(edge_to_pids))
        return -1;

    int_cfg = &private_intr_config[edge_to_pids[ch->type].remote_pid].smd;

    return int_cfg->irq_id;
}
EXPORT_SYMBOL(smd_interrupt_id);

int smd_mask_receive_interrupt(smd_channel_t *ch, bool mask,
		const struct cpumask *cpumask)
{
	struct irq_chip *irq_chip;
	struct irq_data *irq_data;
	struct interrupt_config_item *int_cfg;

	if (!ch)
		return -EINVAL;

	if (ch->type >= ARRAY_SIZE(edge_to_pids))
		return -ENODEV;

	int_cfg = &private_intr_config[edge_to_pids[ch->type].remote_pid].smd;

	if (int_cfg->irq_id < 0)
		return -ENODEV;

	irq_chip = irq_get_chip(int_cfg->irq_id);
	if (!irq_chip)
		return -ENODEV;

	irq_data = irq_get_irq_data(int_cfg->irq_id);
	if (!irq_data)
		return -ENODEV;

	if (mask) {
		SMD_POWER_INFO("SMD Masking interrupts from %s\n",
				edge_to_pids[ch->type].subsys_name);
		irq_chip->irq_mask(irq_data);
		if (cpumask)
			irq_set_affinity(int_cfg->irq_id, cpumask);
	} else {
		SMD_POWER_INFO("SMD Unmasking interrupts from %s\n",
				edge_to_pids[ch->type].subsys_name);
		irq_chip->irq_unmask(irq_data);
	}

	return 0;
}
EXPORT_SYMBOL(smd_mask_receive_interrupt);

int smd_cur_packet_size(smd_channel_t *ch)
{
	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}

	if (ch->current_packet > (uint32_t)INT_MAX) {
		pr_err("%s: Invalid packet size for Edge %d and Channel %s",
			__func__, ch->type, ch->name);
		return -EFAULT;
	}
	return ch->current_packet;
}
EXPORT_SYMBOL(smd_cur_packet_size);

int smd_tiocmget(smd_channel_t *ch)
{
	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}

	return  (ch->half_ch->get_fDSR(ch->recv) ? TIOCM_DSR : 0) |
		(ch->half_ch->get_fCTS(ch->recv) ? TIOCM_CTS : 0) |
		(ch->half_ch->get_fCD(ch->recv) ? TIOCM_CD : 0) |
		(ch->half_ch->get_fRI(ch->recv) ? TIOCM_RI : 0) |
		(ch->half_ch->get_fCTS(ch->send) ? TIOCM_RTS : 0) |
		(ch->half_ch->get_fDSR(ch->send) ? TIOCM_DTR : 0);
}
EXPORT_SYMBOL(smd_tiocmget);

int
smd_tiocmset_from_cb(smd_channel_t *ch, unsigned int set, unsigned int clear)
{
	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}

	if (set & TIOCM_DTR)
		ch->half_ch->set_fDSR(ch->send, 1);

	if (set & TIOCM_RTS)
		ch->half_ch->set_fCTS(ch->send, 1);

	if (clear & TIOCM_DTR)
		ch->half_ch->set_fDSR(ch->send, 0);

	if (clear & TIOCM_RTS)
		ch->half_ch->set_fCTS(ch->send, 0);

	ch->half_ch->set_fSTATE(ch->send, 1);
	barrier();
	ch->notify_other_cpu(ch);

	return 0;
}
EXPORT_SYMBOL(smd_tiocmset_from_cb);

int smd_tiocmset(smd_channel_t *ch, unsigned int set, unsigned int clear)
{
	unsigned long flags;

	if (!ch) {
		pr_err("%s: Invalid channel specified\n", __func__);
		return -ENODEV;
	}

	spin_lock_irqsave(&smd_lock, flags);
	smd_tiocmset_from_cb(ch, set, clear);
	spin_unlock_irqrestore(&smd_lock, flags);

	return 0;
}
EXPORT_SYMBOL(smd_tiocmset);

int smd_is_pkt_avail(smd_channel_t *ch)
{
	unsigned long flags;

	if (!ch || !ch->is_pkt_ch)
		return -EINVAL;

	if (ch->current_packet)
		return 1;

	spin_lock_irqsave(&smd_lock, flags);
	update_packet_state(ch);
	spin_unlock_irqrestore(&smd_lock, flags);

	return ch->current_packet ? 1 : 0;
}
EXPORT_SYMBOL(smd_is_pkt_avail);

static int smsm_cb_init(void)
{
	struct smsm_state_info *state_info;
	int n;
	int ret = 0;

	smsm_states = kmalloc(sizeof(struct smsm_state_info)*SMSM_NUM_ENTRIES,
		   GFP_KERNEL);

	if (!smsm_states) {
		pr_err("%s: SMSM init failed\n", __func__);
		return -ENOMEM;
	}

	smsm_cb_wq = create_singlethread_workqueue("smsm_cb_wq");
	if (!smsm_cb_wq) {
		pr_err("%s: smsm_cb_wq creation failed\n", __func__);
		kfree(smsm_states);
		return -EFAULT;
	}

	mutex_lock(&smsm_lock);
	for (n = 0; n < SMSM_NUM_ENTRIES; n++) {
		state_info = &smsm_states[n];
		state_info->last_value = __raw_readl(SMSM_STATE_ADDR(n));
		state_info->intr_mask_set = 0x0;
		state_info->intr_mask_clear = 0x0;
		INIT_LIST_HEAD(&state_info->callbacks);
	}
	mutex_unlock(&smsm_lock);

	return ret;
}

static int smsm_init(void)
{
	int i;
	struct smsm_size_info_type *smsm_size_info;
	unsigned long flags;
	unsigned long j_start;
	static int first = 1;
	remote_spinlock_t *remote_spinlock;

	if (!first)
		return 0;
	first = 0;

	
	remote_spinlock = smem_get_remote_spinlock();
	j_start = jiffies;
	while (!remote_spin_trylock_irqsave(remote_spinlock, flags)) {
		if (jiffies_to_msecs(jiffies - j_start) > RSPIN_INIT_WAIT_MS) {
			panic("%s: Remote processor %d will not release spinlock\n",
				__func__, remote_spin_owner(remote_spinlock));
		}
	}
	remote_spin_unlock_irqrestore(remote_spinlock, flags);

	smsm_size_info = smem_find(SMEM_SMSM_SIZE_INFO,
				sizeof(struct smsm_size_info_type), 0,
				SMEM_ANY_HOST_FLAG);
	if (smsm_size_info) {
		SMSM_NUM_ENTRIES = smsm_size_info->num_entries;
		SMSM_NUM_HOSTS = smsm_size_info->num_hosts;
	}

	i = kfifo_alloc(&smsm_snapshot_fifo,
			sizeof(uint32_t) * SMSM_NUM_ENTRIES * SMSM_SNAPSHOT_CNT,
			GFP_KERNEL);
	if (i) {
		pr_err("%s: SMSM state fifo alloc failed %d\n", __func__, i);
		return i;
	}
	wakeup_source_init(&smsm_snapshot_ws, "smsm_snapshot");

	if (!smsm_info.state) {
		smsm_info.state = smem_alloc(ID_SHARED_STATE,
						SMSM_NUM_ENTRIES *
						sizeof(uint32_t), 0,
						SMEM_ANY_HOST_FLAG);

		if (smsm_info.state)
			__raw_writel(0, SMSM_STATE_ADDR(SMSM_APPS_STATE));
	}

	if (!smsm_info.intr_mask) {
		smsm_info.intr_mask = smem_alloc(SMEM_SMSM_CPU_INTR_MASK,
						SMSM_NUM_ENTRIES *
						SMSM_NUM_HOSTS *
						sizeof(uint32_t), 0,
						SMEM_ANY_HOST_FLAG);

		if (smsm_info.intr_mask) {
			for (i = 0; i < SMSM_NUM_ENTRIES; i++)
				__raw_writel(0x0,
					SMSM_INTR_MASK_ADDR(i, SMSM_APPS));

			
			__raw_writel(LEGACY_MODEM_SMSM_MASK,
				SMSM_INTR_MASK_ADDR(SMSM_MODEM_STATE,
					SMSM_APPS));
		}
	}

	i = smsm_cb_init();
	if (i)
		return i;

	wmb();

	smsm_pm_notifier(&smsm_pm_nb, PM_POST_SUSPEND, NULL);
	i = register_pm_notifier(&smsm_pm_nb);
	if (i)
		pr_err("%s: power state notif error %d\n", __func__, i);

	return 0;
}

static void smsm_cb_snapshot(uint32_t use_wakeup_source)
{
	int n;
	uint32_t new_state;
	unsigned long flags;
	int ret;
	uint64_t timestamp;

	timestamp = sched_clock();
	ret = kfifo_avail(&smsm_snapshot_fifo);
	if (ret < SMSM_SNAPSHOT_SIZE) {
		pr_err("%s: SMSM snapshot full %d\n", __func__, ret);
		return;
	}

	if (use_wakeup_source) {
		spin_lock_irqsave(&smsm_snapshot_count_lock, flags);
		if (smsm_snapshot_count == 0) {
			SMSM_POWER_INFO("SMSM snapshot wake lock\n");
			__pm_stay_awake(&smsm_snapshot_ws);
		}
		++smsm_snapshot_count;
		spin_unlock_irqrestore(&smsm_snapshot_count_lock, flags);
	}

	
	for (n = 0; n < SMSM_NUM_ENTRIES; n++) {
		new_state = __raw_readl(SMSM_STATE_ADDR(n));

		ret = kfifo_in(&smsm_snapshot_fifo,
				&new_state, sizeof(new_state));
		if (ret != sizeof(new_state)) {
			pr_err("%s: SMSM snapshot failure %d\n", __func__, ret);
			goto restore_snapshot_count;
		}
	}

	ret = kfifo_in(&smsm_snapshot_fifo, &timestamp, sizeof(timestamp));
	if (ret != sizeof(timestamp)) {
		pr_err("%s: SMSM snapshot failure %d\n", __func__, ret);
		goto restore_snapshot_count;
	}

	
	ret = kfifo_in(&smsm_snapshot_fifo,
			&use_wakeup_source, sizeof(use_wakeup_source));
	if (ret != sizeof(use_wakeup_source)) {
		pr_err("%s: SMSM snapshot failure %d\n", __func__, ret);
		goto restore_snapshot_count;
	}

	queue_work(smsm_cb_wq, &smsm_cb_work);
	return;

restore_snapshot_count:
	if (use_wakeup_source) {
		spin_lock_irqsave(&smsm_snapshot_count_lock, flags);
		if (smsm_snapshot_count) {
			--smsm_snapshot_count;
			if (smsm_snapshot_count == 0) {
				SMSM_POWER_INFO("SMSM snapshot wake unlock\n");
				__pm_relax(&smsm_snapshot_ws);
			}
		} else {
			pr_err("%s: invalid snapshot count\n", __func__);
		}
		spin_unlock_irqrestore(&smsm_snapshot_count_lock, flags);
	}
}

static irqreturn_t smsm_irq_handler(int irq, void *data)
{
	unsigned long flags;

	spin_lock_irqsave(&smem_lock, flags);
	if (!smsm_info.state) {
		SMSM_INFO("<SM NO STATE>\n");
	} else {
		unsigned old_apps, apps;
		unsigned modm = __raw_readl(SMSM_STATE_ADDR(SMSM_MODEM_STATE));

		old_apps = apps = __raw_readl(SMSM_STATE_ADDR(SMSM_APPS_STATE));

		SMSM_DBG("<SM %08x %08x>\n", apps, modm);
		if (modm & SMSM_RESET) {
			pr_err("SMSM: Modem SMSM state changed to SMSM_RESET.\n");
		} else if (modm & SMSM_INIT) {
			if (!(apps & SMSM_INIT))
				apps |= SMSM_INIT;
			if (modm & SMSM_SMDINIT)
				apps |= SMSM_SMDINIT;
		}

		if (old_apps != apps) {
			SMSM_DBG("<SM %08x NOTIFY>\n", apps);
			__raw_writel(apps, SMSM_STATE_ADDR(SMSM_APPS_STATE));
			notify_other_smsm(SMSM_APPS_STATE, (old_apps ^ apps));
		}

		smsm_cb_snapshot(1);
	}
	spin_unlock_irqrestore(&smem_lock, flags);
	return IRQ_HANDLED;
}

irqreturn_t smsm_modem_irq_handler(int irq, void *data)
{
	SMSM_POWER_INFO("SMSM Int Modem->Apps\n");
	++interrupt_stats[SMD_MODEM].smsm_in_count;
	return smsm_irq_handler(irq, data);
}

irqreturn_t smsm_dsp_irq_handler(int irq, void *data)
{
	SMSM_POWER_INFO("SMSM Int LPASS->Apps\n");
	++interrupt_stats[SMD_Q6].smsm_in_count;
	return smsm_irq_handler(irq, data);
}

irqreturn_t smsm_dsps_irq_handler(int irq, void *data)
{
	SMSM_POWER_INFO("SMSM Int DSPS->Apps\n");
	++interrupt_stats[SMD_DSPS].smsm_in_count;
	return smsm_irq_handler(irq, data);
}

irqreturn_t smsm_wcnss_irq_handler(int irq, void *data)
{
	SMSM_POWER_INFO("SMSM Int WCNSS->Apps\n");
	++interrupt_stats[SMD_WCNSS].smsm_in_count;
	return smsm_irq_handler(irq, data);
}

int smsm_change_intr_mask(uint32_t smsm_entry,
			  uint32_t clear_mask, uint32_t set_mask)
{
	uint32_t  old_mask, new_mask;
	unsigned long flags;

	if (smsm_entry >= SMSM_NUM_ENTRIES) {
		pr_err("smsm_change_state: Invalid entry %d\n",
		       smsm_entry);
		return -EINVAL;
	}

	if (!smsm_info.intr_mask) {
		pr_err("smsm_change_intr_mask <SM NO STATE>\n");
		return -EIO;
	}

	spin_lock_irqsave(&smem_lock, flags);
	smsm_states[smsm_entry].intr_mask_clear = clear_mask;
	smsm_states[smsm_entry].intr_mask_set = set_mask;

	old_mask = __raw_readl(SMSM_INTR_MASK_ADDR(smsm_entry, SMSM_APPS));
	new_mask = (old_mask & ~clear_mask) | set_mask;
	__raw_writel(new_mask, SMSM_INTR_MASK_ADDR(smsm_entry, SMSM_APPS));

	wmb();
	spin_unlock_irqrestore(&smem_lock, flags);

	return 0;
}
EXPORT_SYMBOL(smsm_change_intr_mask);

int smsm_get_intr_mask(uint32_t smsm_entry, uint32_t *intr_mask)
{
	if (smsm_entry >= SMSM_NUM_ENTRIES) {
		pr_err("smsm_change_state: Invalid entry %d\n",
		       smsm_entry);
		return -EINVAL;
	}

	if (!smsm_info.intr_mask) {
		pr_err("smsm_change_intr_mask <SM NO STATE>\n");
		return -EIO;
	}

	*intr_mask = __raw_readl(SMSM_INTR_MASK_ADDR(smsm_entry, SMSM_APPS));
	return 0;
}
EXPORT_SYMBOL(smsm_get_intr_mask);

int smsm_change_state(uint32_t smsm_entry,
		      uint32_t clear_mask, uint32_t set_mask)
{
	unsigned long flags;
	uint32_t  old_state, new_state;

	if (smsm_entry >= SMSM_NUM_ENTRIES) {
		pr_err("smsm_change_state: Invalid entry %d",
		       smsm_entry);
		return -EINVAL;
	}

	if (!smsm_info.state) {
		pr_err("smsm_change_state <SM NO STATE>\n");
		return -EIO;
	}
	spin_lock_irqsave(&smem_lock, flags);

	old_state = __raw_readl(SMSM_STATE_ADDR(smsm_entry));
	new_state = (old_state & ~clear_mask) | set_mask;
	__raw_writel(new_state, SMSM_STATE_ADDR(smsm_entry));
	SMSM_POWER_INFO("%s %d:%08x->%08x", __func__, smsm_entry,
			old_state, new_state);
	notify_other_smsm(SMSM_APPS_STATE, (old_state ^ new_state));

	spin_unlock_irqrestore(&smem_lock, flags);

	return 0;
}
EXPORT_SYMBOL(smsm_change_state);

uint32_t smsm_get_state(uint32_t smsm_entry)
{
	uint32_t rv = 0;

	
	if (smsm_entry >= SMSM_NUM_ENTRIES) {
		pr_err("smsm_change_state: Invalid entry %d",
		       smsm_entry);
		return 0;
	}

	if (!smsm_info.state)
		pr_err("smsm_get_state <SM NO STATE>\n");
	else
		rv = __raw_readl(SMSM_STATE_ADDR(smsm_entry));

	return rv;
}
EXPORT_SYMBOL(smsm_get_state);

void notify_smsm_cb_clients_worker(struct work_struct *work)
{
	struct smsm_state_cb_info *cb_info;
	struct smsm_state_info *state_info;
	int n;
	uint32_t new_state;
	uint32_t state_changes;
	uint32_t use_wakeup_source;
	int ret;
	unsigned long flags;
	uint64_t t_snapshot;
	uint64_t t_start;
	unsigned long nanosec_rem;

	while (kfifo_len(&smsm_snapshot_fifo) >= SMSM_SNAPSHOT_SIZE) {
		t_start = sched_clock();
		mutex_lock(&smsm_lock);
		for (n = 0; n < SMSM_NUM_ENTRIES; n++) {
			state_info = &smsm_states[n];

			ret = kfifo_out(&smsm_snapshot_fifo, &new_state,
					sizeof(new_state));
			if (ret != sizeof(new_state)) {
				pr_err("%s: snapshot underflow %d\n",
					__func__, ret);
				mutex_unlock(&smsm_lock);
				return;
			}

			state_changes = state_info->last_value ^ new_state;
			if (state_changes) {
				SMSM_POWER_INFO("SMSM Change %d: %08x->%08x\n",
						n, state_info->last_value,
						new_state);
				list_for_each_entry(cb_info,
					&state_info->callbacks, cb_list) {

					if (cb_info->mask & state_changes)
						cb_info->notify(cb_info->data,
							state_info->last_value,
							new_state);
				}
				state_info->last_value = new_state;
			}
		}

		ret = kfifo_out(&smsm_snapshot_fifo, &t_snapshot,
				sizeof(t_snapshot));
		if (ret != sizeof(t_snapshot)) {
			pr_err("%s: snapshot underflow %d\n",
				__func__, ret);
			mutex_unlock(&smsm_lock);
			return;
		}

		
		ret = kfifo_out(&smsm_snapshot_fifo, &use_wakeup_source,
				sizeof(use_wakeup_source));
		if (ret != sizeof(use_wakeup_source)) {
			pr_err("%s: snapshot underflow %d\n",
				__func__, ret);
			mutex_unlock(&smsm_lock);
			return;
		}
		mutex_unlock(&smsm_lock);

		if (use_wakeup_source) {
			spin_lock_irqsave(&smsm_snapshot_count_lock, flags);
			if (smsm_snapshot_count) {
				--smsm_snapshot_count;
				if (smsm_snapshot_count == 0) {
					SMSM_POWER_INFO(
						"SMSM snapshot wake unlock\n");
					__pm_relax(&smsm_snapshot_ws);
				}
			} else {
				pr_err("%s: invalid snapshot count\n",
						__func__);
			}
			spin_unlock_irqrestore(&smsm_snapshot_count_lock,
					flags);
		}

		t_start = t_start - t_snapshot;
		nanosec_rem = do_div(t_start, 1000000000U);
		SMSM_POWER_INFO(
			"SMSM snapshot queue response time %6u.%09lu s\n",
			(unsigned)t_start, nanosec_rem);
	}
}


int smsm_state_cb_register(uint32_t smsm_entry, uint32_t mask,
		void (*notify)(void *, uint32_t, uint32_t), void *data)
{
	struct smsm_state_info *state;
	struct smsm_state_cb_info *cb_info;
	struct smsm_state_cb_info *cb_found = 0;
	uint32_t new_mask = 0;
	int ret = 0;

	if (smsm_entry >= SMSM_NUM_ENTRIES)
		return -EINVAL;

	mutex_lock(&smsm_lock);

	if (!smsm_states) {
		
		ret = -ENODEV;
		goto cleanup;
	}

	state = &smsm_states[smsm_entry];
	list_for_each_entry(cb_info,
			&state->callbacks, cb_list) {
		if (!ret && (cb_info->notify == notify) &&
				(cb_info->data == data)) {
			cb_info->mask |= mask;
			cb_found = cb_info;
			ret = 1;
		}
		new_mask |= cb_info->mask;
	}

	if (!cb_found) {
		cb_info = kmalloc(sizeof(struct smsm_state_cb_info),
			GFP_ATOMIC);
		if (!cb_info) {
			ret = -ENOMEM;
			goto cleanup;
		}

		cb_info->mask = mask;
		cb_info->notify = notify;
		cb_info->data = data;
		INIT_LIST_HEAD(&cb_info->cb_list);
		list_add_tail(&cb_info->cb_list,
			&state->callbacks);
		new_mask |= mask;
	}

	
	if (smsm_entry == SMSM_MODEM_STATE)
		new_mask |= LEGACY_MODEM_SMSM_MASK;

	if (smsm_info.intr_mask) {
		unsigned long flags;

		spin_lock_irqsave(&smem_lock, flags);
		new_mask = (new_mask & ~state->intr_mask_clear)
				| state->intr_mask_set;
		__raw_writel(new_mask,
				SMSM_INTR_MASK_ADDR(smsm_entry, SMSM_APPS));
		wmb();
		spin_unlock_irqrestore(&smem_lock, flags);
	}

cleanup:
	mutex_unlock(&smsm_lock);
	return ret;
}
EXPORT_SYMBOL(smsm_state_cb_register);


int smsm_state_cb_deregister(uint32_t smsm_entry, uint32_t mask,
		void (*notify)(void *, uint32_t, uint32_t), void *data)
{
	struct smsm_state_cb_info *cb_info;
	struct smsm_state_cb_info *cb_tmp;
	struct smsm_state_info *state;
	uint32_t new_mask = 0;
	int ret = 0;

	if (smsm_entry >= SMSM_NUM_ENTRIES)
		return -EINVAL;

	mutex_lock(&smsm_lock);

	if (!smsm_states) {
		
		mutex_unlock(&smsm_lock);
		return -ENODEV;
	}

	state = &smsm_states[smsm_entry];
	list_for_each_entry_safe(cb_info, cb_tmp,
		&state->callbacks, cb_list) {
		if (!ret && (cb_info->notify == notify) &&
			(cb_info->data == data)) {
			cb_info->mask &= ~mask;
			ret = 1;
			if (!cb_info->mask) {
				
				list_del(&cb_info->cb_list);
				kfree(cb_info);
				ret = 2;
				continue;
			}
		}
		new_mask |= cb_info->mask;
	}

	
	if (smsm_entry == SMSM_MODEM_STATE)
		new_mask |= LEGACY_MODEM_SMSM_MASK;

	if (smsm_info.intr_mask) {
		unsigned long flags;

		spin_lock_irqsave(&smem_lock, flags);
		new_mask = (new_mask & ~state->intr_mask_clear)
				| state->intr_mask_set;
		__raw_writel(new_mask,
				SMSM_INTR_MASK_ADDR(smsm_entry, SMSM_APPS));
		wmb();
		spin_unlock_irqrestore(&smem_lock, flags);
	}

	mutex_unlock(&smsm_lock);
	return ret;
}
EXPORT_SYMBOL(smsm_state_cb_deregister);

static int restart_notifier_cb(struct notifier_block *this,
				  unsigned long code,
				  void *data);

static struct restart_notifier_block restart_notifiers[] = {
	{SMD_MODEM, "modem", .nb.notifier_call = restart_notifier_cb},
	{SMD_Q6, "lpass", .nb.notifier_call = restart_notifier_cb},
	{SMD_WCNSS, "wcnss", .nb.notifier_call = restart_notifier_cb},
	{SMD_DSPS, "dsps", .nb.notifier_call = restart_notifier_cb},
	{SMD_MODEM, "gss", .nb.notifier_call = restart_notifier_cb},
	{SMD_Q6, "adsp", .nb.notifier_call = restart_notifier_cb},
	{SMD_DSPS, "slpi", .nb.notifier_call = restart_notifier_cb},
};

static int restart_notifier_cb(struct notifier_block *this,
				  unsigned long code,
				  void *data)
{
	remote_spinlock_t *remote_spinlock;

	if (code == SUBSYS_AFTER_SHUTDOWN) {
		struct restart_notifier_block *notifier;

		notifier = container_of(this,
				struct restart_notifier_block, nb);
		SMD_INFO("%s: ssrestart for processor %d ('%s')\n",
				__func__, notifier->processor,
				notifier->name);

		remote_spinlock = smem_get_remote_spinlock();
		remote_spin_release(remote_spinlock, notifier->processor);
		remote_spin_release_all(notifier->processor);

		smd_channel_reset(notifier->processor);
	}

	return NOTIFY_DONE;
}

void smd_post_init(unsigned remote_pid)
{
	smd_channel_probe_now(&remote_info[remote_pid]);
}

int smsm_post_init(void)
{
	int ret;

	ret = smsm_init();
	if (ret) {
		pr_err("smsm_init() failed ret = %d\n", ret);
		return ret;
	}
	smsm_irq_handler(0, 0);

	return ret;
}

struct interrupt_config *smd_get_intr_config(uint32_t edge)
{
	if (edge >= ARRAY_SIZE(edge_to_pids))
		return NULL;
	return &private_intr_config[edge_to_pids[edge].remote_pid];
}

int smd_edge_to_remote_pid(uint32_t edge)
{
	if (edge >= ARRAY_SIZE(edge_to_pids))
		return -EINVAL;
	return edge_to_pids[edge].remote_pid;
}

int smd_edge_to_local_pid(uint32_t edge)
{
	if (edge >= ARRAY_SIZE(edge_to_pids))
		return -EINVAL;
	return edge_to_pids[edge].local_pid;
}

void smd_proc_set_skip_pil(unsigned pid, bool skip_pil)
{
	if (pid >= NUM_SMD_SUBSYSTEMS) {
		pr_err("%s: invalid pid:%d\n", __func__, pid);
		return;
	}
	remote_info[pid].skip_pil = skip_pil;
}

void smd_set_edge_subsys_name(uint32_t edge, const char *subsys_name)
{
	if (edge < ARRAY_SIZE(edge_to_pids))
		if (subsys_name)
			strlcpy(edge_to_pids[edge].subsys_name,
				subsys_name, SMD_MAX_CH_NAME_LEN);
		else
			strlcpy(edge_to_pids[edge].subsys_name,
				"", SMD_MAX_CH_NAME_LEN);
	else
		pr_err("%s: Invalid edge type[%d]\n", __func__, edge);
}

void smd_reset_all_edge_subsys_name(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(edge_to_pids); i++)
		strlcpy(edge_to_pids[i].subsys_name,
			"", sizeof(""));
}

void smd_set_edge_initialized(uint32_t edge)
{
	if (edge < ARRAY_SIZE(edge_to_pids))
		edge_to_pids[edge].initialized = true;
	else
		pr_err("%s: Invalid edge type[%d]\n", __func__, edge);
}

void smd_cfg_smd_intr(uint32_t proc, uint32_t mask, void *ptr)
{
	private_intr_config[proc].smd.out_bit_pos = mask;
	private_intr_config[proc].smd.out_base = ptr;
	private_intr_config[proc].smd.out_offset = 0;
}

void smd_cfg_smsm_intr(uint32_t proc, uint32_t mask, void *ptr)
{
	private_intr_config[proc].smsm.out_bit_pos = mask;
	private_intr_config[proc].smsm.out_base = ptr;
	private_intr_config[proc].smsm.out_offset = 0;
}

static __init int modem_restart_late_init(void)
{
	int i;
	void *handle;
	struct restart_notifier_block *nb;

	for (i = 0; i < ARRAY_SIZE(restart_notifiers); i++) {
		nb = &restart_notifiers[i];
		handle = subsys_notif_register_notifier(nb->name, &nb->nb);
		SMD_DBG("%s: registering notif for '%s', handle=%p\n",
				__func__, nb->name, handle);
	}

	return 0;
}
late_initcall(modem_restart_late_init);

#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG

static char smsm_klog[PAGE_SIZE];
static void smd_dbg_inc(unsigned *idx)
{
	*idx = (*idx + 1) & (DBG_MAX_MSG-1);
}

static char *smd_get_timestamp(char *tbuf)
{
	unsigned long long t;
	unsigned long nanosec_rem;

	t = cpu_clock(smp_processor_id());
	nanosec_rem = do_div(t, 1000000000)/1000;
	scnprintf(tbuf, TIME_BUF_LEN, "[%5lu.%06lu] ", (unsigned long)t,
		nanosec_rem);
	return tbuf;
}

void smsm_events_print(void)
{
	unsigned long	flags;
	unsigned	i;
	unsigned lines = 0;

	pr_info("### Show SMSM Log Start ###\n");

	read_lock_irqsave(&dbg_smsm.lck, flags);

	i = dbg_smsm.idx;

	for (smd_dbg_inc(&i); i != dbg_smsm.idx; smd_dbg_inc(&i)) {
		if (!strnlen(dbg_smsm.buf[i], DBG_MSG_LEN))
			continue;
		pr_info("%s", dbg_smsm.buf[i]);
		lines++;
		if ( lines > smsm_htc_debug_dump_lines )
			break;
	}

	read_unlock_irqrestore(&dbg_smsm.lck, flags);

	pr_info("### Show SMSM Log End ###\n");
}

void msm_smsm_dumplog(void)
{
	int ret = 0;

	if ( !smsm_htc_debug_enable ) {
		pr_info("%s: smsm_htc_debug_enable=[%d]\n", __func__, smsm_htc_debug_enable);
		return;
	}

	if ( !smsm_htc_debug_dump ) {
		pr_info("%s: smsm_htc_debug_dump=[%d]\n", __func__, smsm_htc_debug_dump);
		return;
	}

	if ( !smsm_log_ctx ) {
		pr_info("%s: smsm_log_ctx = NULL\n", __func__);
		smsm_events_print();
		return;
	}

	if ( !(msm_smd_debug_mask & MSM_SMSM_DEBUG
		&& msm_smd_debug_mask & MSM_SMSM_INFO
		&& msm_smd_debug_mask & MSM_SMSM_POWER_INFO) ) {
		pr_info("%s: msm_smd_debug_mask=[%d]\n", __func__, msm_smd_debug_mask);
		smsm_events_print();
		return;
	}

	pr_info("### Show SMSM Log Start ###[IPC log]\n");

	do {

		memset(smsm_klog, 0x0, PAGE_SIZE);
		ret = ipc_log_extract( smsm_log_ctx, smsm_klog, PAGE_SIZE);
		if ( ret >= 0 ) {
			pr_info("%s\n", smsm_klog);
		}

	} while ( ret > 0 );

	pr_info("### Show SMSM Log End ###[IPC log]\n");

}
EXPORT_SYMBOL(msm_smsm_dumplog);

void smsm_dbg_log_event(const char * event, ...)
{
	unsigned long flags;
	char tbuf[TIME_BUF_LEN];
	char dbg_buff[DBG_MSG_LEN];
	va_list arg_list;
	int data_size;

	if ( !smsm_htc_debug_enable ) {
		return;
	}

	va_start(arg_list, event);
	data_size = vsnprintf(dbg_buff,
			      DBG_MSG_LEN, event, arg_list);
	va_end(arg_list);

	write_lock_irqsave(&dbg_smsm.lck, flags);

	scnprintf(dbg_smsm.buf[dbg_smsm.idx], DBG_MSG_LEN,
		"%s %s", smd_get_timestamp(tbuf), dbg_buff);

	smd_dbg_inc(&dbg_smsm.idx);

	if ( smsm_htc_debug_print )
		pr_info("%s", dbg_buff);
	write_unlock_irqrestore(&dbg_smsm.lck, flags);

	return;

}
EXPORT_SYMBOL(smsm_dbg_log_event);

static int smsm_events_show(struct seq_file *s, void *unused)
{
	unsigned long	flags;
	unsigned	i;

	read_lock_irqsave(&dbg_smsm.lck, flags);

	i = dbg_smsm.idx;
	for (smd_dbg_inc(&i); i != dbg_smsm.idx; smd_dbg_inc(&i)) {
		if (!strnlen(dbg_smsm.buf[i], DBG_MSG_LEN))
			continue;
		seq_printf(s, "%s", dbg_smsm.buf[i]);
	}

	read_unlock_irqrestore(&dbg_smsm.lck, flags);

	return 0;
}

static int smsm_events_open(struct inode *inode, struct file *f)
{
	return single_open(f, smsm_events_show, inode->i_private);
}

const struct file_operations smsm_dbg_fops = {
	.open = smsm_events_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static char smd_klog[PAGE_SIZE];

void smd_events_print(void)
{
	unsigned long	flags;
	unsigned	i;
	unsigned lines = 0;

	pr_info("### Show SMD Log Start ###\n");

	read_lock_irqsave(&dbg_smd.lck, flags);

	i = dbg_smd.idx;

	for (smd_dbg_inc(&i); i != dbg_smd.idx; smd_dbg_inc(&i)) {
		if (!strnlen(dbg_smd.buf[i], DBG_MSG_LEN))
			continue;
		pr_info("%s", dbg_smd.buf[i]);
		lines++;
		if ( lines > smd_htc_debug_dump_lines )
			break;
	}

	read_unlock_irqrestore(&dbg_smd.lck, flags);

	pr_info("### Show SMD Log End ###\n");
}

void msm_smd_dumplog(void)
{
	int ret = 0;

	if ( !smd_htc_debug_enable ) {
		pr_info("%s: smd_htc_debug_enable=[%d]\n", __func__, smd_htc_debug_enable);
		return;
	}

	if ( !smd_htc_debug_dump ) {
		pr_info("%s: smd_htc_debug_dump=[%d]\n", __func__, smd_htc_debug_dump);
		return;
	}

	if ( !smd_log_ctx ) {
		pr_info("%s: smd_log_ctx = NULL\n", __func__);
		smd_events_print();
		return;
	}

	if ( !(msm_smd_debug_mask & MSM_SMD_DEBUG
		&& msm_smd_debug_mask & MSM_SMD_INFO
		&& msm_smd_debug_mask & MSM_SMD_POWER_INFO) ) {
		pr_info("%s: msm_smd_debug_mask=[%d]\n", __func__, msm_smd_debug_mask);
		smd_events_print();
		return;
	}

	pr_info("### Show SMD Log Start ###[IPC log]\n");

	do {

		memset(smd_klog, 0x0, PAGE_SIZE);
		ret = ipc_log_extract( smd_log_ctx, smd_klog, PAGE_SIZE);
		if ( ret >= 0 ) {
			pr_info("%s\n", smd_klog);
		}

	} while ( ret > 0 );

	pr_info("### Show SMD Log End ###[IPC log]\n");

}
EXPORT_SYMBOL(msm_smd_dumplog);

void smd_dbg_log_event(const char * event, ...)
{
	unsigned long flags;
	char tbuf[TIME_BUF_LEN];
	char dbg_buff[DBG_MSG_LEN];
	va_list arg_list;
	int data_size;

	if ( !smd_htc_debug_enable ) {
		return;
	}

	va_start(arg_list, event);
	data_size = vsnprintf(dbg_buff,
			      DBG_MSG_LEN, event, arg_list);
	va_end(arg_list);

	write_lock_irqsave(&dbg_smd.lck, flags);

	scnprintf(dbg_smd.buf[dbg_smd.idx], DBG_MSG_LEN,
		"%s %s", smd_get_timestamp(tbuf), dbg_buff);

	smd_dbg_inc(&dbg_smd.idx);

	if ( smd_htc_debug_print )
		pr_info("%s", dbg_buff);
	write_unlock_irqrestore(&dbg_smd.lck, flags);

	return;

}
EXPORT_SYMBOL(smd_dbg_log_event);

static int smd_events_show(struct seq_file *s, void *unused)
{
	unsigned long	flags;
	unsigned	i;

	read_lock_irqsave(&dbg_smd.lck, flags);

	i = dbg_smd.idx;
	for (smd_dbg_inc(&i); i != dbg_smd.idx; smd_dbg_inc(&i)) {
		if (!strnlen(dbg_smd.buf[i], DBG_MSG_LEN))
			continue;
		seq_printf(s, "%s", dbg_smd.buf[i]);
	}

	read_unlock_irqrestore(&dbg_smd.lck, flags);

	return 0;
}

static int smd_events_open(struct inode *inode, struct file *f)
{
	return single_open(f, smd_events_show, inode->i_private);
}

const struct file_operations smd_dbg_fops = {
	.open = smd_events_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif

int __init msm_smd_init(void)
{
	static bool registered;
	int rc;
	int i;

	if (registered)
		return 0;

	smd_log_ctx = ipc_log_context_create(NUM_LOG_PAGES, "smd", 0);
	if (!smd_log_ctx) {
		pr_err("%s: unable to create SMD logging context\n", __func__);
		msm_smd_debug_mask = 0;
	}

	smsm_log_ctx = ipc_log_context_create(NUM_LOG_PAGES, "smsm", 0);
	if (!smsm_log_ctx) {
		pr_err("%s: unable to create SMSM logging context\n", __func__);
		msm_smd_debug_mask = 0;
	}

	registered = true;

	for (i = 0; i < NUM_SMD_SUBSYSTEMS; ++i) {
		remote_info[i].remote_pid = i;
		remote_info[i].free_space = UINT_MAX;
		INIT_WORK(&remote_info[i].probe_work, smd_channel_probe_worker);
		INIT_LIST_HEAD(&remote_info[i].ch_list);
	}

	channel_close_wq = create_singlethread_workqueue("smd_channel_close");
	if (IS_ERR(channel_close_wq)) {
		pr_err("%s: create_singlethread_workqueue ENOMEM\n", __func__);
		return -ENOMEM;
	}

	rc = msm_smd_driver_register();
	if (rc) {
		pr_err("%s: msm_smd_driver register failed %d\n",
			__func__, rc);
		return rc;
	}

#ifdef CONFIG_HTC_DEBUG_RIL_PCN0005_HTC_DUMP_SMSM_LOG
#ifdef CONFIG_DEBUG_FS
	do {
		struct dentry *dent;

		dent = debugfs_create_dir("smsm", 0);
		if (!IS_ERR(dent)) {
			debugfs_create_file("dumplog", S_IRUGO, dent, NULL, &smsm_dbg_fops);
		}
	} while(0);
	do {
		struct dentry *dent;

		dent = debugfs_create_dir("smd", 0);
		if (!IS_ERR(dent)) {
			debugfs_create_file("dumplog", S_IRUGO, dent, NULL, &smd_dbg_fops);
		}
	} while(0);
#endif
#endif

	return 0;
}

arch_initcall(msm_smd_init);

MODULE_DESCRIPTION("MSM Shared Memory Core");
MODULE_AUTHOR("Brian Swetland <swetland@google.com>");
MODULE_LICENSE("GPL");
