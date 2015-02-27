/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef _LWKMEM_H_
#define _LWKMEM_H_

/*#undef LWKMEM_DEBUG_ENABLED*/
#define LWKMEM_DEBUG_ENABLED

#ifdef LWKMEM_DEBUG_ENABLED

extern int lwkmem_debug;
#define LWKMEM_DEBUG         (lwkmem_debug > 0)
#define LWKMEM_DEBUG_VERBOSE (lwkmem_debug > 1)
#define LWKMEM_DEBUG_EXTREME (lwkmem_debug > 2)

#else

#define LWKMEM_DEBUG         0
#define LWKMEM_DEBUG_VERBOSE 0
#define LWKMEM_DEBUG_EXTREME 0
#define memblock_dump_free()
#define dump_block_lists(...)
#endif

#define MAX_NIDS (1 << CONFIG_NODES_SHIFT)

/*
 * A list of this structure holds the chunks of memory we designated during
 * boot for the LWK. On most systems this list will contain less than a
 * dozen, multi-gigabyte chunks of physical memory.
 */
struct mos_lwk_mem_granule {
	struct list_head list;
	void *base;
	resource_size_t length;
	pid_t owner;	/* -1 if free */
	int nid; /* NUMA id */
};

/*
 * Each LWK process has a list of this structure to indicate which of the
 * LWK designated memory has been reserved for this process. It is just a list
 * of pointers back to entries in the mos_lwk_mem_granule list.
 */
struct lwk_process_granule {
	struct list_head list;
	struct mos_lwk_mem_granule *granule;
	resource_size_t offset; /* watermark within granule */
};

/*
 * For each TLB size there is a list of physical memory blocks that have been
 * assigned to this process.
 */
struct blk_list {
	struct list_head list;
	struct mos_lwk_mem_granule *phys;
	int64_t offset;		/* start of this block, in bytes, within phys */
	uint64_t num_blks;	/* Num blocks represented by this entry */
	unsigned long vma_addr; /* User-space virtual address */
	int free;
};

struct allocate_options_t {
	struct mos_process_t *mosp;
	int type_order[lwkmem_type_last];
	int nid_order[lwkmem_type_last][MAX_NIDS];
	int nid_order_len[lwkmem_type_last];
	int64_t max_page_size;

	int64_t (*blocks_wanted)(int64_t len, int64_t *wanted,
			      struct allocate_options_t *opts);

	struct blk_list *(*find_available)(enum lwkmem_kind_t knd,
					   struct allocate_options_t *opts);

	struct blk_list *(*divide_block)(enum lwkmem_kind_t knd,
					 struct allocate_options_t *opts);
};

enum allocate_site_t { lwkmem_mmap, lwkmem_brk, lwkmem_mremap };

struct allocate_options_t *allocate_options_factory(enum allocate_site_t,
			    unsigned long addr, unsigned long flags,
			    struct mos_process_t *);

extern long allocate_blocks(unsigned long addr, int64_t len,
			    unsigned long prot, unsigned long mmap_flags,
			    unsigned long pgoff, struct allocate_options_t *);

extern unsigned long allocate_blocks_fixed(unsigned long addr,
			   unsigned long len, unsigned long prot,
			   unsigned long mmap_flags, enum allocate_site_t site);

extern unsigned long next_lwkmem_address(unsigned long len,
					 struct mos_process_t *mosp);

extern long deallocate_blocks(unsigned long addr, unsigned long len,
			      struct mos_process_t *mosp);

#endif /* _LWKMEM_H_ */
