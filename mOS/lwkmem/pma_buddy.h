/*
 * Multi Operating System (mOS)
 * Copyright (c) 2020, Intel Corporation.
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

#ifndef __PMA_BUDDY_H__
#define __PMA_BUDDY_H__

/* LWK physical memory buddy allocator or in short LWK buddy allocator,
 *
 * This is a simplified version of Linux page allocator's buddy allocator
 * but differs in following aspects,
 *   - scalability (i.e. allocator is a per process allocator), so there
 *     are no shared locks between two processes.
 *   - supports pages of size 4KB, 2MB and 1GB.
 *   - larger guarantee of contig physical memory due to higher orders
 *     supported and isolation of allocation to per process.
 *   - supports large contiguous memory allocation beyond highest order
 *     page sizes.
 *
 * Free physical memory area in short free area of a NUMA node is tracked
 * in a multilevel list. The size of free memory area represented by an
 * element in the list at a level N is twice the size of elements linked
 * in the list below at level N-1.
 *
 * Order     Buddy element size
 * -----     ------------------
 * 22        16 GB  <- Max contiguous space guranteed if there is atleast
 *                     1 element at this level. This depends on the physical
 * .         .         memory reserved to the process and its alignment.
 * .         .
 * 18        1 GB
 * .         .
 * 9         2 MB
 * .         .
 * 0         4 KB   <- Base page size.
 *
 *                      +-----------+
 *   LWK_MAX_ORDEDR     | free_area | ->[_____________________________]
 *                      +-----------+
 *        .             ~       ~
 *                      +-----------+
 *        1             | free_area | ->[______]->[______]
 *                      +-----------+
 *        0             | free_area | ->[_]->[_]->[_]
 *                      +-----------+
 *
 *      Order    area[LWK_MAX_NUMORDERS]
 */

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>

/* Constant macros */
//#define DEBUG_BUDDY_PMA
//#define TEST_BUDDY_PMA
#define LWK_MAX_NUMORDERS	23
#define LWK_MAX_ORDER		(LWK_MAX_NUMORDERS - 1)
#define PMA_ACTIVE		true
#define PMA_REPORT_MAXLINESZ	300
#define PMA_REPORT_LIBSTRSZ	20

/* Macros for iterating, looking up buddy orders */
#define for_each_order_from(o)		for (; o < LWK_MAX_NUMORDERS; o++)
#define for_each_order(o)		for (o = 0; o < LWK_MAX_NUMORDERS; o++)
#define for_each_order_reverse_from(o)	for (; o >= 0; o--)
#define for_each_order_reverse(o)	for (o = LWK_MAX_ORDER; o >= 0; o--)

/* Macros to work with coversion between orders */
#define base_pages_per_unit(o)	(1UL << (o))
#define next_pfn(o, pfn)	((pfn) + base_pages_per_unit(o))
#define prev_pfn(o, pfn)	((pfn) - base_pages_per_unit(o))
#define pfn_aligned(o, pfn)	(((pfn) & (base_pages_per_unit(o) - 1)) == 0)
#define in_base_pages(n, o)	(((unsigned long)(n)) << (o))
#define in_lorder_pages(n, high, low) (((unsigned long)(n)) << ((high) - (low)))
#define in_horder_pages(n, low, high) (((unsigned long)(n)) >> ((high) - (low)))

/* Helper macros to work with contiguous ranges */
#define range_set_front(r, o)	set_bit((o), r->front_orders)
#define range_set_back(r, o)	set_bit((o), r->back_orders)
#define range_test_front(r, o)	test_bit((o), r->front_orders)
#define range_test_back(r, o)	test_bit((o), r->back_orders)
#define range_clear(r) do { bitmap_zero(r->front_orders, LWK_MAX_NUMORDERS); \
			    bitmap_zero(r->back_orders, LWK_MAX_NUMORDERS);  \
			    r->nr_pages = 0; } while (0)
/* Print formatter */
#define pr_report(id, format, ...)	pr_info("[%d:%ld] " format, \
					current->pid, id, ##__VA_ARGS__)
#define pr_test(format, ...) pr_info("[PID %d] >> [Buddy Test] " format,\
				     current->pid, ##__VA_ARGS__)

/*
 * Helper macros and an inline function to assist with snprintf chores.
 * These are used in buddy_report() for preparing print lines.
 */
#define snprintf_init(i, s) do { i = 0; s = PMA_REPORT_MAXLINESZ; } while (0)
#define snprintf_inc(i, s, r) do { i += r; s -= r; } while (0)
static inline int snprintf_error(int rc, int size)
{
	if (rc < 0)
		LWKMEM_ERROR("IO error in snprintf rc=%d", rc);
	if (rc >= size)
		LWKMEM_ERROR("Buffer overrun in snprintf rc=%d", rc);
	return rc < 0 || rc >= size;
}

/* Macro to print size in 4k pages to human readable format */
#define human_readable_format(s, p) string_get_size(pages_to_bytes(p), 1, \
						    STRING_UNITS_2, s, \
						    PMA_REPORT_LIBSTRSZ)
/*
 * Buddy PMA counters for debug and statistics.
 */
enum buddy_counter {
	BUDDY_COUNTER_ALLOC = 0,
	BUDDY_COUNTER_FREE,
	BUDDY_COUNTER_CACHE_HIT,
	BUDDY_COUNTER_CACHE_MISS,
};

/*
 * The structure that anchors list of pages at an order level
 */
struct freemem {
	/* Number of free pages at this order */
	unsigned long nr_free;
	/* List of free pages of order at this level */
	struct list_head list;
};

/*
 * Physical memory usage, debug statistics are captured in the below
 * structure. The per node structure allocates and records a pointer
 * to it only if reporting of such statistics is enabled by the user
 * through a yod option specified.
 */
struct node_numa_stats {
	/* Number of allocations of each page size */
	unsigned long nr_allocs[LWK_MAX_NUMPGTYPES];
	/* Maximum number of allocations of each page size */
	unsigned long nr_alloc_max[LWK_MAX_NUMPGTYPES];
	/* Maximum memory used in terms of base pages */
	unsigned long nr_alloc_max_mem;
	unsigned long nr_cache_hit[LWK_MAX_NUMPGTYPES];
	unsigned long nr_cache_miss[LWK_MAX_NUMPGTYPES];
};

/*
 * LWK buddy allocator tracks per process reserved free memory through per
 * NUMA node buddy lists. The following structure represents the state of the
 * allocator for a NUMA node.
 */
struct node_memory {
	spinlock_t lock;
	/* For buddy list maintenance */
	int nid;
	unsigned long nr_total;
	unsigned long nr_free;
	/* Seed for psuedo-random allocations */
	unsigned int seed;

	struct freemem mem[LWK_MAX_NUMORDERS];
	/*
	 * Cache free pages of different types for faster allocations.
	 */
	struct freemem cache[LWK_MAX_NUMPGTYPES];
	unsigned long cache_max_size[LWK_MAX_NUMPGTYPES];

	/*
	 * For reporting node usage. We want to store pointer as we do not
	 * want to pollute cache by caching structure elements when reporting
	 * is turned off.
	 */
	struct node_numa_stats *stats;
};

/*
 * LWK buddy allocator structure,
 *   the physical memory allocator context for an LWK process.
 */
struct lwk_pm_buddy_allocator {
	/* State of the allocator */
	bool active;
	/* LWK mm ID generated and passed on to PMA from LWK mm */
	unsigned long id;
	/* NUMA nodes managed by the allocator */
	unsigned long nr_nodes;
	nodemask_t nodes_mask;
	/*
	 *  Pointer to each node's buddy data is store in the array.
	 *  Index 0 corresponds to the 1st bit set in node_mask,
	 *  Index 1 corresponds to the 2nd bit set in node_mask, so on.
	 */
	struct node_memory **node_mem;
};

/*
 *  Structure that describes a contiguous range of memory in the buddy list.
 *  It is used to return the search result of contiguous range of free memory
 *  as shown below. Highest order needed is 'h'=horder and the smallest
 *  granularity needed is of order 'l'=lorder.
 *
 *  Orders
 *  ------
 *  LWK_MAX_ORDER
 *  .               order h         one or more     allocated at lower
 *  .             page length      order h pages    orders or reserved
 *  .          <--------------X----............----X-------------->
 *  h          |//////////////|____............____|//////////////|
 *  h-1        |//////|_______|                    |_______|//////|
 *  h-2        |///|__|       ^                    ^       |__|///|
 *  h-3        |/|_|  ^       |                    |       ^  |_|/|
 *  .            ^    |    front_page[h]           |       |
 *  .            | front_page[h-1]          back_page[h-1] |
 *  .         front_page[h-2]                     back_page[h-2]
 *  .            .                                 .
 *  .            .                                 .
 *  l
 *  .
 *  2
 *  1
 *  0
 */
struct buddy_contig_range {
	/*
	 * Highest and lowest order requested, i.e. h and l in the description
	 * above.
	 */
	int horder;
	int lorder;
	/*
	 * Array used to return the struct pages of front lower order pages.
	 * front_page[horder] will be used to return the starting page of
	 * horder in the found contiguous range.
	 */
	struct page *front_page[LWK_MAX_NUMORDERS];
	/*
	 * Array used to return the struct pages of back lower order pages.
	 * back_page[horder] is always  unused.
	 */
	struct page *back_page[LWK_MAX_NUMORDERS];
	/*
	 * Bitmasks with bits set corresponding to valid orders returned in
	 * front_page, back_page arrays.
	 */
	DECLARE_BITMAP(front_orders, LWK_MAX_NUMORDERS);
	DECLARE_BITMAP(back_orders, LWK_MAX_NUMORDERS);
	/* Total number of horder pages in the range */
	unsigned long nr_horder_pages;
	/* Size of the entire contiguous range in terms of lorder pages.*/
	unsigned long nr_pages;
};

#ifdef TEST_BUDDY_PMA
static void test_buddy_pma(struct lwk_pm_buddy_allocator *pma_buddy);
#else
#define test_buddy_pma(p)
#endif

#endif // __PMA_BUDDY_H__
