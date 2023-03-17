/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016-2020, Intel Corporation.
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

#ifndef _LINUX_MOSLWKMEM_H
#define _LINUX_MOSLWKMEM_H

#include <linux/list.h>
#include <linux/mm.h>

#ifdef CONFIG_MOS_LWKMEM

/*
 * Flags used in private member field of a struct page in LWK pages.
 *
 *       <---------------------- 64 bit --------------->
 *       +-+--------------+-----+----------------------+
 *       |D|  LWK mm id   |order|       _LWKPG         |
 *       +-+--------------+-----+----------------------+
 * Bits   1       26         5            32
 * resvd
 *
 *   D -> _LWKPG_DIRTY bit 63
 *
 * Assumptions:
 *   - Max 2^26 LWK active processes at any point using LWK memory
 *   - Max 2^5 orders when LWK buddy allocator is in use.
 */

#define _LWKPG_POS		0
#define _LWKPG_ORDER_POS	32
#define _LWKPG_MMID_POS		37
#define _LWKPG_DBIT_POS		63

#define _LWKPG_WD		32
#define _LWKPG_ORDER_WD		5
#define _LWKPG_MMID_WD		26
#define _LWKPG_DBIT_WD		1

#define _LWKPG_MASK		(~(~0UL << _LWKPG_WD) << _LWKPG_POS)
#define _LWKPG_ORDER_MASK	(~(~0UL << _LWKPG_ORDER_WD) << _LWKPG_ORDER_POS)
#define _LWKPG_MMID_MASK	(~(~0UL << _LWKPG_MMID_WD) << _LWKPG_MMID_POS)
#define _LWKPG_DBIT_MASK	(~(~0UL << _LWKPG_DBIT_WD) << _LWKPG_DBIT_POS)

#define _LWKPG			_AC(0x4c574b4d, UL)
#define _LWKPG_DIRTY		(1UL << _LWKPG_DBIT_POS)

/* LWKMEM memory policy end of list marker used by yod */
#define LWKMEM_MEMPOL_EOL	((u8) 0xff)
/* LWKMEM prints */
#define LWKMEM_ERROR(format, ...) \
		mos_ras(MOS_LWKMEM_PROCESS_ERROR, \
			"%s: " format, __func__, ##__VA_ARGS__)
#define LWKMEM_ERROR_ON(cond, format, ...) \
		do { if (cond) LWKMEM_ERROR(format, ##__VA_ARGS__); } while (0)
#define LWKMEM_WARN(format, ...) \
		mos_ras(MOS_LWKMEM_PROCESS_WARNING,\
			"%s: " format, __func__, ##__VA_ARGS__)
#define LWKMEM_WARN_ON(cond, format, ...) \
		do { if (cond) LWKMEM_WARN(format, ##__VA_ARGS__); } while (0)

/* LWKMEM VMA and struct page tests */
#define is_lwkpg(page)		((((page)->private) & _LWKPG_MASK) == _LWKPG)
#define is_lwkpg_dirty(page)	(((page)->private) & _LWKPG_DIRTY)
#define set_lwkpg_dirty(page)	((page)->private |= _LWKPG_DIRTY)
#define clear_lwkpg_dirty(page) ((page)->private &= ~_LWKPG_DIRTY)
#define is_lwkvma(vma)		((vma)->vm_flags & VM_LWK)
#define is_lwkxpmem(vma) 	((vma)->vm_flags & VM_LWK_XPMEM)
#define is_lwkmem_enabled(t)	(is_lwk_process(t) && \
				 (t)->mos_process->lwk_mm && \
				 (t)->mos_process->lwk_mm->active && \
				 (t)->mos_process->yod_mm != (t)->mm)
#define is_lwkvmr_disabled(vmr)	curr_lwk_mm()->policy[vmr].disabled
extern bool is_lwkmem_nofault(unsigned long vm_flags);

/* Macros to work with LWK page types: ex: 4k, 2m, 1g */
#define for_each_lwkpage_type_from(t, p) \
		for (t = (p); t < LWK_MAX_NUMPGTYPES; t++)
#define for_each_lwkpage_type_to(t, p) \
		for (t = LWK_PG_4K; t <= p; t++)
#define for_each_lwkpage_type(t) for_each_lwkpage_type_from(t, LWK_PG_4K)
#define for_each_lwkpage_type_reverse_from(t, p)\
		for (t = (p); (int)t >= LWK_PG_4K; t--)
#define for_each_lwkpage_type_reverse_to(t, p)\
		for (t = LWK_MAX_NUMPGTYPES-1; (int)t >= (p); t--)
#define for_each_lwkpage_type_reverse(t)\
		for_each_lwkpage_type_reverse_from(t, LWK_MAX_NUMPGTYPES-1)
#define valid_lwkpage_type(t) \
		(((int)(t) >= LWK_PG_4K) && ((int)(t) < LWK_MAX_NUMPGTYPES))

/* Macro to validate lwk_pma_alloc_flags type */
#define valid_pma_alloc_flags(f) (((int)(f) >= PMA_ALLOC_NORMAL) && \
				  ((int)(f) <= PMA_ALLOC_RANDOM))
/* Macro to validate lwk_mempolicy_type */
#define valid_mempol_type(t) (((int)(t) >= LWK_MEMPOL_NORMAL) && \
				  ((int)(t) < LWK_MAX_MEMPOL_TYPES))
/* Forward declrations */
struct lwk_mm;

/*
 * Types of physical memory allocator(pma)
 */
enum lwk_pma_type {
	LWK_BUDDY_ALLOCATOR = 0,
	LWK_PMA_MAX
};

enum lwk_pma_alloc_flags {
	PMA_ALLOC_NORMAL = 0,
	PMA_ALLOC_CONTIG,
	PMA_ALLOC_RANDOM
};

enum lwk_page_type {
	LWK_PG_4K = 0,
	LWK_PG_2M,
	LWK_PG_1G,
	LWK_MAX_NUMPGTYPES
};

/*
 * Process virtual memory regions supported by LWK memory management
 *   @LWK_VMR_DBSS,           data/bss region.
 *   @LWK_VMR_HEAP,           heap.
 *   @LWK_VMR_ANON_PRIVATE,   privated anonymous mmaped region.
 *   @LWK_VMR_TSTACK,         mmaped regions reserved for thread stack.
 *   @LWK_VMR_STACK,          process stack.
 *   @LWK_VMR_NUMTYPES        number of virtual memory area types supported.
 *
 * NOTE: Yod uses these enum values for specifying mempolicy info for each VMR.
 *       So any change to enum should adjust yod to keep it in sync.
 */
enum lwk_vmr_type {
	LWK_VMR_DBSS = 0,
	LWK_VMR_HEAP,
	LWK_VMR_ANON_PRIVATE,
	LWK_VMR_TSTACK,
	LWK_VMR_STACK,
	LWK_MAX_NUMVMRTYPES
};

/*
 * NOTE: Yod uses these enum values for specifying mempolicy info for each VMR.
 *       So any change to enum should adjust yod to keep it in sync.
 */
enum lwk_pagefault_level {
	LWK_PF_NOFAULT = 0,
	LWK_PF_ONEFAULT,
	LWK_PF_LEVELS
};

/*
 * NOTE: Yod uses these enum values for specifying mempolicy info for each VMR.
 *       So any change to enum should adjust yod to keep it in sync.
 */
enum lwk_mempolicy_type {
	LWK_MEMPOL_NORMAL = 0,
	LWK_MEMPOL_RANDOM,
	LWK_MEMPOL_INTERLEAVE,
	LWK_MEMPOL_INTERLEAVE_RANDOM,
	LWK_MAX_MEMPOL_TYPES
};

/*
 * Memory information structure to communicate the usage statistics between
 * PMA and LWK mm core.
 *   @total, total process reserved memory in 4k pages.
 *   @free,  free memory available for allocation in 4k pages.
 */
struct lwk_pma_meminfo {
	unsigned long total_pages;
	unsigned long free_pages;
};

/*
 * LWK memory policy,
 *
 *   Memory policy is defined during the process start up and is defined per
 *   virtual memory region(VMR)s like - data/bss, heap, mmap, thread stacks,
 *   process stack. For every such region based on a threshold value @threshold
 *   a set of NUMA nodes are preferred/selected for allocating physical memory.
 *
 *   For those allocations of size >= threshold,
 *     @above_threshold NUMA nodes are used
 *
 *   For those allocations of size < threshold,
 *     @below_threshold NUMA nodes are used
 *
 *   Each of @above_threshold/@below_threshold is an array of list of NUMA
 *     nodes in the order of their preferences, i.e. index 0 being highest
 *     preferred, 1 the next best, so on. Within a list all sets of NUMA
 *     nodes are equally preferred i.e. at the same priority.
 *
 *   Ex:
 *                                Indices within each list
 *
 *                            [0]   [1]   [2]   [3]   [4]   [5]
 *                          +-----+-----+-----+-----+-----+-----+
 *     *_threshold[0].nodes |  4  |  5  |  6  |  7  |  8  |  9  |
 *                          +-----+-----+-----+-----+-----+-----+
 *     *_threshold[1].nodes |  0  |  1  |  2  |  3  |
 *                          +-----+-----+-----+-----+
 *
 *     NIDs 4,5,6,7,8,9 are preferred first, then NIDs 0,1,2,3 so on.
 *
 *   The number of elements in each list is stored in *_threshold[n].num_nodes
 *   The total number of lists within a set is fixed for a process and is set
 *   when the user stores memory policy information to kernel through yod.
 *
 *   @nodelist_ratio is used to interleave between memory types using the value
 *              provided as a ratio of allocations between the node lists
 *
 *   @pagefault_level indicates the level of ondemand paging for this region
 *
 *   @disabled indicates if the LWKMEM allocation is disabled for the region
 *             useful for debugging.
 */
struct lwk_mempolicy_nodelists {
	unsigned long num_nodes;
	u8 *nodes;
};

struct lwk_mempolicy {
	struct lwk_mempolicy_nodelists *above_threshold;
	struct lwk_mempolicy_nodelists *below_threshold;
	unsigned long threshold;
	enum lwk_page_type max_page;
	int nodelist_ratio;
	enum lwk_pagefault_level pagefault_level;
	enum lwk_mempolicy_type type;
	bool disabled;
};

/*
 * Private data of a LWK VMA.
 *
 *   @vma_sem, used to serialize one-fault allocation of VMA pages
 *             from multiple threads.
 *
 *   @lwk_vm_start, @lwk_vm_end,
 *             Markers used to track the range [start, end) within the
 *             LWK VMA that has been populated with physical memory
 *             backings. These are used in cases where the VMR of the
 *             VMA is configured to either LWK_PF_NOFAULT or LWK_PF_ONEFAULT.
 *
 *   @xpmem_private_data, @subregions_lock, @subregions
 *             Manage XPEM virtual address attachments
 *
 */
struct lwk_vma_private {
	struct rw_semaphore vma_sem;
	unsigned long lwk_vm_start;
	unsigned long lwk_vm_end;
	struct lwk_mm *lwk_mm;
	void *xpmem_private_data;
	struct mutex subregions_lock;
	struct list_head subregions;
};

enum attachment_align_stats_t {
	ALIGN_ELIGIBLE = 0,
	ALIGN_NOT_ELIGIBLE,
	ALIGN_SUCCESS,
	ALIGN_SUCCESS_HP,
	ALIGN_FAIL_MAPFIXED,
	ALIGN_FAIL_LINUXVMA,
	ALIGN_FAIL_SRCPGSZ,
	ALIGN_FAIL_NOVM,
	ALIGN_FAIL_ERROR,
	ALIGN_STAT_END
};

struct lwk_vm_stats {
	/* TBD counters */
	/* XPMEM counters */
	unsigned long src_pgmap[LWK_MAX_NUMPGTYPES][LWK_MAX_NUMPGTYPES];
	unsigned long dst_pgmap[LWK_MAX_NUMPGTYPES][LWK_MAX_NUMPGTYPES];
	unsigned long attachment_align_stats[ALIGN_STAT_END];
};


/*
 * LWK physical memory operations,
 *   A physical memory allocator need to implement following operations
 *   that are called by the LWK memory manager. LWK memory manager is
 *   connected to a physical memory allocator implementation during the
 *   LWK process startup as specified by the yod option. It does so by
 *   storing the pointer to physical memory allocator instance.
 *
 *   Subsequently the LWK memory manager calls physical memory allocator
 *   by passing in the pointer to physical memory allocator instance @pma.
 *
 *   Operations deal in terms of physical page frame number(pfn). The
 *   choice of how physical memory is represented internally is left to a
 *   specific implementation.
 */
struct lwk_pm_operations {
	/*
	 * Allocate pages of specified order from a NUMA node. These are
	 * meant to be called upon a page fault handler or gup where
	 * page table structures are created and filled with pfn supplied
	 * from this function.
	 *
	 * Arguments,
	 *   @pma, pointer to physical memory allocator context.
	 *   @nid, NUMA node id from where page needs to be allocated.
	 *   @n_needed, number of physical pages of @pgtype to be allocated.
	 *   @pgtype, type of pages to allocate, ex: LWK_PG_4K for 4k pages.
	 *   @flags, flags that define desired allocation behavior.
	 *   @list, list of struct pages linked with 'lru' field of the
	 *          structure. Each page is of type @pgtype. If @flags
	 *          is set to PMA_ALLOC_CONTIG then @list will have only
	 *          the first page of contiguous region allocated.
	 *   @n_allocated, used to return the number of pages of @pgtype that
	 *                 were allocated upon successful return,
	 *
	 * Returns, 0 on success,
	 *              i.e. atleast 1 page of @pgtype was allocated, @list and
	 *              @n_allocated indicates actual allocation result which
	 *              can be less than or equal to @n_needed.
	 *          -ve error code on failure.
	 */
	int (*alloc_pages)(void *pma, int nid, unsigned long n_needed,
			   enum lwk_page_type pgtype,
			   enum lwk_pma_alloc_flags flags,
			   struct list_head *list, unsigned long *n_allocated);
	/*
	 * Frees pages to physical memory allocator pool. Meant to be called
	 * from unmap flow. The reference counting of pages is implementation
	 * specific. If the pages are reference counted then this function
	 * needs to be called when the reference count reaches 0.
	 *
	 * Arguments,
	 *   @pma, pointer to physical memory allocator context.
	 *   @pgtype, type of pages to free, ex: LWK_PG_4K for 4k pages.
	 *   @spfn, @n, if the pages being freed are contiguous physical memory
	 *              then these provide the contiguous pfn range which is,
	 *              @n pages of @pgtype from @spfn. If pages to be freed
	 *              are not contiguous physical memory then these fields
	 *              are ignored.
	 *   @list, When set to NULL indicates that the physical memory being
	 *          being freed is contiguous. For non-contiguous physical
	 *          memory the list will have list of struct pages linked with
	 *          'lru' field of struct page to be freed.
	 *
	 * Returns, 0 on success.
	 *          -ve error code on failure.
	 */
	int (*free_pages)(void *pma, enum lwk_page_type pgtype,
			  unsigned long spfn, unsigned long n,
			  struct list_head *list);

	/*
	 * Called when a page previously allocated is being split by the
	 * LWK mm core. This is used as a notification to PMA so that
	 * it can update its node statistics.
	 *
	 * Arguments,
	 *   @pma, pointer to physical memory allocator context.
	 *   @pgtype, type of page being split.
	 *   @pfn, page frame number of the page being split.
	 *
	 * Returns, 0 on success.
	 *          -ve error code on failure.
	 */
	int (*split_page)(void *pma, enum lwk_page_type pgtype,
			  unsigned long pfn);
	/*
	 * Report/debug output.
	 *
	 * Arguments,
	 *   @pma, pointer to physical memory allocator context.
	 *   @verbose, verbosity level.
	 *
	 * Returns, none.
	 */
	void (*report)(void *pma, int verbose);

	/*
	 * Read memory usage information.
	 *
	 * Arguments,
	 *   @pma, pointer to physical memory allocator context.
	 *   @nid, NUMA node id, or NUMA_NO_NODE to read sum for all nids.
	 *   @info, structure that holds memory information once the
	 *          call is returned.
	 *
	 */
	void (*meminfo)(void *pma, int nid, struct lwk_pma_meminfo *info);

	/*
	 * Setup the physical memory allocator initial state.
	 *
	 * Arguments,
	 *   @pma,           pointer to physical memory allocator context.
	 *   @list_physmem,  pointer to array of lists of physical memory
	 *                   reserved for this context. Element at a given
	 *                   index contains the head of list for that NID
	 *                   Array should have MAX_NUMNODES elements.
	 *   @cache_limits,  PMA cache sizes to set if supported by PMA.
	 *   @lwk_mm_id,     MMID of the LWK MM that is attached to PMA.
	 *   @enable_report, if true capture and report debug counters in PMA.
	 *
	 * Returns,
	 *   0 on success.
	 *   -ve error code on failure.
	 */
	int (*setup)(void *pma, struct list_head (*list_phymem)[MAX_NUMNODES],
		     unsigned long (*cache_limits)[LWK_MAX_NUMPGTYPES],
		     unsigned long lwk_mm_id, bool enable_report);
};

struct lwk_pm_factory_operations {
	/*
	 * Allocates a context of physical memory allocator.
	 *
	 * Arguments, none
	 *
	 * Returns,
	 *   on success an opaque pointer that need to passed to
	 *   subsequent calls to physical memory allocator operations.
	 *   NULL on failure.
	 */
	void * (*alloc_pma)(void);

	/*
	 * Frees a physical memory allocator context.
	 *
	 * Arguments, @pma, pointer to physical memory allocator context.
	 *
	 * Returns, none
	 */
	void (*free_pma)(void *pma);

};

/*
 * LWK virtual memory operations,
 *   An LWK memory manager need to implement following virtual memory
 *   operations that are necessary to make this work with Linux memory
 *   management. These operations are invoked from various places in
 *   Linux mm such as syscalls, page table walk, unmap, page faults,
 *   gup, process exit. The APIs may need adjustments when we rebase
 *   onto a new Linux kernel version due to Linux dependencies.
 *
 *   Guidelines for changes,
 *
 *   Keep the APIs to base functionality that is re-usable from
 *   multiple points in the glue code interfacing with Linux and
 *   avoid duplication of Linux functionality when possible.
 */
struct lwk_vm_operations {
	/*
	 * Return virtual address to be assigned to a new mapping. This
	 * function is called from Linux for generating virtual addresses
	 * for LWK VMAs. For LWK VMAs we try to align the start address of
	 * VMA on huge page boundary based on @len
	 *
	 * Arguments,
	 *   @file,  should be NULL to LWK VMAs.
	 *   @addr,  starting address hint from application.
	 *   @len,   size of unmapped region required
	 *   @pgoff, ignored for LWK VMAs
	 *   @flags, mmap flags
	 *
	 * Returns, virtual address allocated on success.
	 *   -ve error code on failure.
	 */
	unsigned long (*get_unmapped_area)(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags);
	/*
	 * Unmap virtual address range [start, end) in a VMA. Meant to be
	 * called from Linux when it unmaps a single VMA and finds that it
	 * is LWK VMA.
	 *
	 * Arguments,
	 *   @tlb, pointer to mmu_gather passed from Linux that has mm.
	 *   @vma, pointer to virtual memory area being unmapped.
	 *   @start, @end, range to be unmapped [start, end).
	 *
	 * Returns, none.
	 */
	void (*unmap_page_range)(struct vm_area_struct *vma,
				 unsigned long start, unsigned long end);

	/*
	 * Move page table mappings of on an existing virtual memory range to
	 * new virtual memory range that doesn't have page table mappings yet.
	 *
	 * Arguments,
	 *   @old_vma,  vma of the old map.
	 *   @old_addr, start address of the range that needs to be re-mapped.
	 *   @new_vma,  vma of the new map.
	 *   @new_addr, start address of the re-mapped range.
	 *   @len,      length of range that needs to be re-mapped.
	 *
	 * Returns, numer of bytes re-mapped
	 */
	unsigned long (*move_page_tables)(struct vm_area_struct *old_vma,
					  unsigned long old_addr,
					  struct vm_area_struct *new_vma,
					  unsigned long new_addr,
					  unsigned long len);
	/*
	 * Change memory protection bits for virtual address range.
	 *
	 * Arguments,
	 *   @vma, virtual memory area that needs mprotect change.
	 *   @start, @end, defines virtual address range [start, end)
	 *                 within @vma for the change.
	 *   @newprot, new memory protection value.
	 *
	 * Returns, number of page table entries modified.
	 */
	unsigned long (*change_protection)(struct vm_area_struct *vma,
					   unsigned long start,
					   unsigned long end, pgprot_t newprot);
	/*
	 * GUP functions
	 */
	/*
	 * Walks page table returning struct page if found one.
	 *
	 * Arguments,
	 *   @vma, virtual memory area for which the function is invoked.
	 *   @address, virtual address used to follow page table entries.
	 *   @flags, Linux gup flags that determines actions to be
	 *           performed while walking the process page table.
	 *   @page_mask, Mask returned based on page size found.
	 *               i.e. mask = (page size in number of 4k pages) - 1
	 *
	 * Returns, pointer to struct page corresponding to @address on success,
	 *          NULL if no physical page is mapped yet.
	 *          -ve error code on errors.
	 */
	struct page *(*follow_page)(struct vm_area_struct *vma,
				    unsigned long address, unsigned int flags,
				    unsigned int *page_mask);
	/*
	 * Walks pages table without locking mm by the caller and collects
	 * pages. Meant to be called from get_user_pages_fast() if supported.
	 *
	 * Arguments,
	 *   @addr, @end, define range [addr, addr+end) for which pages
	 *                are to be pinned.
	 *   @flags, Linux gup flags.
	 *   @pages, array of struct pages of pages pinned. The function
	 *           need to fill in an entry in the array for every page
	 *           pinned by the function.
	 *   @nr, number of pages pinned by the function.
	 *
	 * Return, none.
	 */
	void (*gup_pgd_range)(unsigned long addr, unsigned long end,
			      unsigned int flags, struct page **pages,
			      int *nr);
	/*
	 * Page fault handler for LWKMEM. Called from the Linux generic
	 * handler for the page faults i.e. handle_mm_fault().
	 *
	 * Arguments,
	 *   @vma, vma covering the page fault.
	 *   @address, faulting address.
	 *   @flags,   FAULT_* flags from Linux page fault handler.
	 *
	 * Returns, the bit mask as defined by Linux enum vm_fault_reason.
	 */
	vm_fault_t (*page_fault)(struct vm_area_struct *vma,
				 unsigned long address, unsigned long flags);
	/*
	 * Allocate physical memory for virtual address range [start, end)
	 * within the specified VMA. It ensures that the memory policy
	 * predefined at the process startup is applied based on the
	 * lwk_vma_type to which this vma belongs. The mapping of vmas to
	 * lwk_vma_type is implementation specific.
	 *
	 * Arguments,
	 *   @vma, virtual memory area for which pages need to be
	 *         allocated.
	 *   @start, @end, define virtual address range [start, end)
	 *                 within the @vma
	 * Returns, 0 on success.
	 *   -ve error code on failure.
	 */
	int (*alloc_pages_vma)(struct vm_area_struct *vma, unsigned long start,
			       unsigned long end);
	/*
	 * Called by Linux MM when a LWK VMA's start/end are being adjusted.
	 * This allows us to split the large pages based on new start/end.
	 *
	 * Arguments,
	 *   @vma, LWK VMA that is being adjusted
	 *   @start, @end new [start, end) for the VMA.
	 *   @adjust_next,
	 *
	 * Return, none.
	 */
	void (*vma_adjust)(struct vm_area_struct *vma, unsigned long start,
			   unsigned long end);

	/*
	 * Called from Linux when a VMA is expanded to see if we need
	 * to populate the expanded region with physical memory. This
	 * function needs to be called while holding writer lock of
	 * mmap_sem to serialize against page fault handler.
	 *
	 * Arguments,
	 *   @vma, LWK vma to check for.
	 *
	 *   Returns,
	 *     true  if @vma is in VM region which is either set to onefault
	 *           or set to nofault and is already populated once.
	 *     false when @vma is in VM region which is set to onefault and
	 *           not populated yet.
	 */
	bool (*populated)(struct vm_area_struct *vma);

	/*
	 * Called from Linux MM during fork to copy pages covered by LWK VMAs
	 * from parent LWK process to child Linux process.
	 *
	 * Arguments,
	 *   @oldvma, VMA of parent process, pages of which needs to be copied.
	 *   @newvma, VMA of child process which needs to be populated.
	 *
	 * Returns, 0 on success.
	 *   -ve error code on failure.
	 */
	int (*fork)(struct vm_area_struct *oldvma,
		    struct vm_area_struct *newvma);

	/*
	 * Used to clear the heap area upon heap expansion if the pages were
	 * pre-allocated in the expanded heap area. In LWK heap pages could be
	 * pre-allocated because the pages are not released whenever heap is
	 * shrunk.
	 *
	 * Arguments,
	 *   @vma, VMA corresponding to heap area.
	 *   @oldbrk, old brk line which is being expanded.
	 *   @newbrk, brk line after expansion i.e. latest end of heap.
	 *
	 * Return, none.
	 */
	void (*clear_heap)(struct vm_area_struct *vma, unsigned long oldbrk,
			   unsigned long newbrk);

	/*
	 * Map and initialize a RW ELF segment. This is used to load
	 * .data/.bss regions to LWK memory from Linux ELF loader code.
	 *
	 * Arguments,
	 *   @map_start,  determines the range in the process virtual address
	 *   @map_size,   space [@map_start, @map_start + @map_size) that holds
	 *                the ELF segment being loaded.
	 *   @filep,	  file pointer from where the data has to be read.
	 *   @offset,     offset within the file from where the data has to
	 *                be read.
	 *   @addr,       virtual address in the map where file data starts.
	 *   @size,	  size of bytes to be read from the file.
	 *   @total_size, total size of the entire ELF image being loaded.
	 *
	 * Returns,
	 *   start address of map on success.
	 *   -ve error code on failure.
	 */
	unsigned long (*elf_map)(unsigned long map_start,
				 unsigned long map_size,
				 struct file *filep, unsigned long offset,
				 unsigned long addr, unsigned long size,
				 unsigned long total_size);
};

/*
 * LWK memory manager,
 *
 *   The structre represents LWK memory manager allocated per LWK
 *   process. Following description summarizes the life cycle of a
 *   LWK memory manager instance.
 *
 *   Pre-condition,
 *
 *   Below pre-conditions are met in a subsys_initcall() that is
 *   called by the Linux kernel early during kernel boot up.
 *
 *     - Register LWK per process callbacks for LWK memory management.
 *         mos_register_process_callbacks()
 *     - Register callback for LWK memory management yod option.
 *         mos_register_option_callback() for each option.
 *
 *     - All physical memory allocator implementations register themselves
 *       by calling register_lwk_pma() function of LWK memory management
 *       core from a subsys_initcall().
 *
 *   a. creation,
 *
 *     If lwkmem requested is non-zero then allocate a structure during,
 *     lwkmem_request_store() -> lwkmem_request() -> allocate_lwk_mm() call.
 *       - Initialize @vm_ops to point to a specific implementation.
 *       - Set to defaults all other fields of the structure.
 *
 *     Store the pointer to lwk_mm structure in mOS process strucutre
 *     mos_process_t field that tracks it.
 *
 *   b. setup,
 *
 *     - Initialize @lwkmem, @list_pmem upon sysfs write from yod,
 *         lwkmem_request_store() -> lwkmem_request() call.
 *     - Initialize @policy, upon sysfs write from yod,
 *         lwkmem_policy_store() -> lwkmem_policy() call.
 *     - Initialize yod options upon sysfs write from yod,
 *         lwk_options_store(),
 *     - Upon mos_process_start() callback, allocate a physical memory
 *       allocator based on yod option or a default one if not specified
 *       and call setup() operation of physical memory allocator by
 *       supplying the list of reserved physical memory for the process.
 *
 *   c. deletion,
 *
 *     - Release physical memory allocator resources by calling free_pma().
 *     - Free physical memory allocator structure.
 *     - Release all LWK mm resources previously allocated.
 *     - Release lwk_mm structure.
 *     - Store NULL pointer in mOS process structure field that tracks it.
 */
struct lwk_mm {
	/* Status of LWK mm, set true upon successful start_lwk_mm() */
	bool active;

	/* A unique identifier to distinguish between two per process LWK mm */
	unsigned long id;

	/* Pointer to LWK memory operations */
	struct lwk_vm_operations *vm_ops;

	/* Physical memory allocator related */
	void *pma;                  /* Pointer to physical memory allocator  */
	struct lwk_pm_operations *pm_ops; /* Pointer to physical memory ops  */
	struct list_head list_pmem[MAX_NUMNODES]; /* Lists of reserved memory*/
	unsigned long pma_cache_limits[LWK_MAX_NUMPGTYPES]; /* Default sizes */
							    /* of PMA caches */
	/* Virtual memory management */
	bool policy_set;
	u64 policy_nlists;
	struct lwk_mempolicy policy[LWK_MAX_NUMVMRTYPES]; /* Memory policies.*/
	struct lwk_vm_stats vm_stats;                /* virtual memory stats */

	/* yod options */
	enum lwk_pma_type pma_type;/* Physical memory allocator type chosen  */
	unsigned long report_level;/* Enable record/reporting of debug counts*/
	long brk_clear_len;	   /* Heap length to clear when it expands   */
};

extern struct lwk_mm *curr_lwk_mm(void);
extern struct lwk_mm *vma_lwk_mm(struct vm_area_struct *vma);
extern void set_lwk_mm(struct lwk_mm *lwk_mm);
extern int allocate_lwk_mm(void);
extern int start_lwk_mm(void);
extern int exit_lwk_mm(void);
extern int free_lwk_mm(void);
extern int register_lwk_pma(enum lwk_pma_type pma_type,
			    struct lwk_pm_factory_operations *factory_ops,
			    struct lwk_pm_operations *pm_ops);
/*
 * Interface between Linux and LWK memory management VM operations.
 *
 * -: NOTE :-
 * These functions are called either from LWK process or on a LWK VMA
 * from a remote process (Linux/LWK). Caller needs to validate these
 * pre-conditions before calling lwkmem_* interface functions. The only
 * exception to this rule is lwkmem_meminfo() which can be called by either
 * LWK or Linux process.
 */
extern void lwkpage_add_rmap(struct page *page, struct vm_area_struct *vma,
			     unsigned long address);
extern void lwkpage_remove_rmap(struct page *page);
extern void vma_set_lwkvma(struct vm_area_struct *vma);
extern void vma_clear_lwkvma(struct vm_area_struct *vma);
extern void lwkmem_meminfo(struct sysinfo *si, int nid);
extern void show_xpmem_stats(struct lwk_vm_stats *vm_stats);
extern void *get_xpmem_private_data(struct vm_area_struct *vma);
extern void release_lwkxpmem_vma(struct vm_area_struct *vma);
extern void set_xpmem_private_data(struct vm_area_struct *vma, void *data);
extern int copy_lwkmem_to_lwkxpmem(struct vm_area_struct *src_vma,
				unsigned long src_start,
				struct vm_area_struct *dst_vma,
				unsigned long dst_start, unsigned long len);
extern struct vm_area_struct *create_lwkxpmem_vma(struct mm_struct *src_mm,
						unsigned long src_start,
						unsigned long dst_start,
						unsigned long len,
						unsigned long prot,
						void *xpmem_private_data,
					const struct vm_operations_struct *ops);
extern int unmap_lwkxpmem_range(struct vm_area_struct *vma, unsigned long start,
				unsigned long end);
extern void init_xpmem_stats(struct lwk_vm_stats *vm_stats);

#define lwkmem_get_unmapped_area_ops() \
		curr_lwk_mm()->vm_ops->get_unmapped_area
#define lwkmem_page_fault(vma, addr, flags)\
		vma_lwk_mm(vma)->vm_ops->page_fault(vma, addr, flags)
#define lwkmem_unmap_range(vma, start, end)\
		vma_lwk_mm(vma)->vm_ops->unmap_page_range(vma, start, end)
#define lwkmem_change_protection_range(vma, start, end, prot) \
		vma_lwk_mm(vma)->vm_ops->change_protection(vma, start, end, \
							   prot)
#define lwkmem_vma_adjust(vma, start, end) \
		vma_lwk_mm(vma)->vm_ops->vma_adjust(vma, start, end)
#define lwkmem_follow_page(vma, addr, flags, pagemask) \
		vma_lwk_mm(vma)->vm_ops->follow_page(vma, addr, flags, pagemask)
#define lwkmem_move_page_tables(old_vma, old_addr, new_vma, new_addr, len) \
		vma_lwk_mm(old_vma)->vm_ops->move_page_tables(old_vma, \
						old_addr, new_vma, new_addr,\
						len)
#define lwkmem_populated(vma) \
		vma_lwk_mm(vma)->vm_ops->populated(vma)
#define lwkmem_fork(oldvma, newvma) \
		vma_lwk_mm(oldvma)->vm_ops->fork(oldvma, newvma)
#define lwkmem_clear_heap(vma, oldbrk, newbrk) \
		vma_lwk_mm(vma)->vm_ops->clear_heap(vma, oldbrk, newbrk)
#define lwkmem_elf_map(s, len, fp, off, addr, sz, tsz) \
		curr_lwk_mm()->vm_ops->elf_map(s, len, fp, off, addr, sz, tsz)
#else
#define LWK_VMR_DBSS		0
#define LWK_VMR_HEAP		0
#define LWK_VMR_ANON_PRIVATE	0
#define LWK_VMR_TSTACK		0
#define LWK_PF_NOFAULT		0
#define LWK_PF_ONEFAULT		0
#define LWKMEM_ERROR(format, ...)
#define LWKMEM_ERROR_ON(cond, format, ...)
#define LWKMEM_WARN(format, ...)
#define LWKMEM_WARN_ON(cond, format, ...)
#define is_lwkpg(page)		0
#define is_lwkpg_dirty(page)	0
#define set_lwkpg_dirty(page)
#define clear_lwkpg_dirty(page)
#define is_lwkvma(vma)		0
#define vma_set_lwkvma(vma)
#define vma_clear_lwkvma(vma)
#define is_lwkmem_enabled(t)	0
#define is_lwkvmr_disabled(vmr) true
#define is_lwkmem_nofault(f)    0
#define for_noop		for (; 0;)
#define for_each_lwkpage_type_from(t, p)	 for_noop
#define for_each_lwkpage_type_to(t, p)		 for_noop
#define for_each_lwkpage_type(t)		 for_noop
#define for_each_lwkpage_type_reverse_from(t, p) for_noop
#define for_each_lwkpage_type_reverse_to(t, p)	 for_noop
#define for_each_lwkpage_type_reverse(t)	 for_noop
#define valid_lwkpage_type(t)	0
#define lwkmem_get_unmapped_area_ops() current->mm->get_unmapped_area
#define lwkmem_unmap_range(v, s, e)
#define lwkmem_vma_adjust(v, s, e)
#define lwkmem_populated(vma)	false
#define lwkmem_meminfo(si, nid)
#define lwkmem_clear_heap(vma, oldbrk, newbrk)
#define is_lwkxpmem(vma) 	0
#define get_xpmem_private_data(vma)	NULL
#define set_xpmem_private_data(vma, data)
#define release_lwkxpmem_vma(vma)
#define unmap_lwkxpmem_range(vma, start, end)	0
#define create_lwkxpmem_vma(mm, src, dst, len, prot, private, ops)	NULL
#define copy_lwkmem_to_lwkxpmem(src_vma, src_start, dst_vma, dst_start, len) 0

static inline
vm_fault_t lwkmem_page_fault(struct vm_area_struct *vma, unsigned long addr,
			unsigned long flags)
{
	return 0;
}

static inline
unsigned long lwkmem_change_protection_range(struct vm_area_struct *vma,
			unsigned long start, unsigned long end,
			pgprot_t newprot)
{
	return 0;
}

static inline
struct page *lwkmem_follow_page(struct vm_area_struct *vma, unsigned long addr,
			unsigned long flags, unsigned int *page_mask)
{
	return NULL;
}

static inline
unsigned long lwkmem_move_page_tables(struct vm_area_struct *old_vma,
			unsigned long old_addr, struct vm_area_struct *new_vma,
			unsigned long new_addr, unsigned long len)
{
	return 0;
}

static inline
int lwkmem_fork(struct vm_area_struct *oldvma, struct vm_area_struct *newvma)
{
	return 0;
}

static inline
unsigned long lwkmem_elf_map(unsigned long map_start,
			unsigned long map_size, struct file *filep,
			unsigned long offset, unsigned long addr,
			unsigned long size, unsigned long total_size)
{
	return -EINVAL;
}
#endif
#endif // _LINUX_MOSLWKMEM_H
