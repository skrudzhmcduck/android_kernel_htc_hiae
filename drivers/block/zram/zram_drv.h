/*
 * Compressed RAM block device
 *
 * Copyright (C) 2008, 2009, 2010  Nitin Gupta
 *               2012, 2013 Minchan Kim
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the licence that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 *
 */

#ifndef _ZRAM_DRV_H_
#define _ZRAM_DRV_H_

#include <linux/spinlock.h>
#include <linux/zsmalloc.h>

#include "zcomp.h"

static const unsigned max_num_devices = 32;


static const size_t max_zpage_size = PAGE_SIZE / 10 * 9;



#define SECTOR_SHIFT		9
#define SECTORS_PER_PAGE_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define SECTORS_PER_PAGE	(1 << SECTORS_PER_PAGE_SHIFT)
#define ZRAM_LOGICAL_BLOCK_SHIFT 12
#define ZRAM_LOGICAL_BLOCK_SIZE	(1 << ZRAM_LOGICAL_BLOCK_SHIFT)
#define ZRAM_SECTOR_PER_LOGICAL_BLOCK	\
	(1 << (ZRAM_LOGICAL_BLOCK_SHIFT - SECTOR_SHIFT))


#define ZRAM_FLAG_SHIFT 24

enum zram_pageflags {
	
	ZRAM_ZERO = ZRAM_FLAG_SHIFT,
	ZRAM_ACCESS,	

	__NR_ZRAM_PAGEFLAGS,
};


struct zram_table_entry {
	unsigned long handle;
	unsigned long value;
};

struct zram_stats {
	atomic64_t compr_data_size;	
	atomic64_t num_reads;	
	atomic64_t num_writes;	
	atomic64_t num_migrated;	
	atomic64_t failed_reads;	
	atomic64_t failed_writes;	
	atomic64_t invalid_io;	
	atomic64_t notify_free;	
	atomic64_t zero_pages;		
	atomic64_t pages_stored;	
	atomic_long_t max_used_pages;	
};

struct zram_meta {
	struct zram_table_entry *table;
	struct zs_pool *mem_pool;
};

struct zram {
	struct zram_meta *meta;
	struct zcomp *comp;
	struct gendisk *disk;
	
	struct rw_semaphore init_lock;
	unsigned long limit_pages;
	int max_comp_streams;

	struct zram_stats stats;
	atomic_t refcount; 
	
	wait_queue_head_t io_done;
	u64 disksize;	
	char compressor[10];
};
#endif
