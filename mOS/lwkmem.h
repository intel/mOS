/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016 - 2017, Intel Corporation.
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

#define MAX_NIDS (1 << CONFIG_NODES_SHIFT)

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
static char *kind_str[kind_last] __attribute__ ((unused)) = {"4k", "2m", "1g"};
#else
static char *kind_str[kind_last] __attribute__ ((unused)) = {"4k", "4m", "1g"};
#endif

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
	unsigned int stride;    /* Virtual address stride (in blocks) */
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

	long (*allocate_blocks)(unsigned long addr, int64_t len,
			unsigned long prot, unsigned long mmap_flags,
			unsigned long pgoff, struct allocate_options_t *);

};


struct allocate_options_t *allocate_options_factory(enum allocate_site_t,
			unsigned long addr, unsigned long flags,
			struct mos_process_t *);

extern unsigned long allocate_blocks_fixed(unsigned long addr,
			unsigned long len, unsigned long prot,
			unsigned long mmap_flags, enum allocate_site_t site);

extern unsigned long next_lwkmem_address(unsigned long len,
			struct mos_process_t *mosp);

extern long deallocate_blocks(unsigned long addr, unsigned long len,
			struct mos_process_t *mosp,
			struct mm_struct *mm);

extern unsigned long block_size_virt(struct blk_list *b, enum lwkmem_kind_t k);

extern void lwkpage_add_rmap(struct page *page, struct vm_area_struct *vma,
		unsigned long address);
extern void lwkpage_remove_rmap(struct page *page);

extern int build_pagetbl(enum lwkmem_kind_t knd, struct vm_area_struct *vma,
			 unsigned long phys_addr, unsigned long vstart,
			 unsigned long vend, unsigned int stride);
extern int unmap_pagetbl(enum lwkmem_kind_t k, unsigned long vstart,
			 unsigned long vend, unsigned int stride,
			 struct mm_struct *mm, bool lwkxpmem);
extern int unmap_lwkxpmem_range(struct vm_area_struct *vma, unsigned long start,
				unsigned long end);
extern void init_xpmem_stats(struct mos_process_t *mosp);
extern void show_xpmem_stats(struct mos_process_t *mosp);
#endif /* _LWKMEM_H_ */
