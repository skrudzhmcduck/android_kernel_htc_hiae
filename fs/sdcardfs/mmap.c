/*
 * fs/sdcardfs/mmap.c
 *
 * Copyright (c) 2013 Samsung Electronics Co. Ltd
 *   Authors: Daeho Jeong, Woojoong Lee, Seunghwan Hyun,
 *               Sunghwan Yun, Sungjong Seo
 *
 * This program has been developed as a stackable file system based on
 * the WrapFS which written by
 *
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009     Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This file is dual licensed.  It may be redistributed and/or modified
 * under the terms of the Apache 2.0 License OR version 2 of the GNU
 * General Public License.
 */

#include "sdcardfs.h"

static int sdcardfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int err;
	struct file *file, *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
	struct vm_area_struct lower_vma;

	memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
	file = lower_vma.vm_file;
	lower_vm_ops = SDCARDFS_F(file)->lower_vm_ops;
	BUG_ON(!lower_vm_ops);

	lower_file = sdcardfs_lower_file(file);
	lower_vma.vm_file = lower_file;
	err = lower_vm_ops->fault(&lower_vma, vmf);
	return err;
}

static ssize_t sdcardfs_direct_IO(int rw, struct kiocb *iocb,
			      const struct iovec *iov, loff_t offset,
			      unsigned long nr_segs)
{
	printk(KERN_INFO "%s, operation is not supported\n", __func__);
	return 0;
}

const struct address_space_operations sdcardfs_aops = {
	
	.direct_IO	= sdcardfs_direct_IO,
};

const struct vm_operations_struct sdcardfs_vm_ops = {
	.fault		= sdcardfs_fault,
};
