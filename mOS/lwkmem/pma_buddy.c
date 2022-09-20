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
#include <linux/string.h>
#include <linux/string_helpers.h>
#include <linux/mos.h>
#include <linux/random.h>
#include <trace/events/lwkmem.h>

/* Private headers */
#include "lwk_mm_private.h"
#include "pma_buddy.h"

/* Forward declarations, only if can not be avoided. */
static int alloc_lwkpage(struct freemem *mem, unsigned long id,
			 int order, struct page **page_out);
static void free_lwkpage(struct freemem *mem, unsigned long id,
			 unsigned long pfn, int order);
static void free_lwkpage_partial(struct freemem *mem, unsigned long id,
				 unsigned long pfn, int horder, int lorder,
				 unsigned long n_alloc, bool alloc_first_part);
static void buddy_report_buddylist(struct freemem *mem, unsigned long id,
				   int order);
static void buddy_report(void *pma, int verbose);

/*
 * Grouping of functions:
 *   The PMA buddy allocator source code is structured into following
 *   order and grouping for better readability. Functions implementing
 *   similar functionality are grouped together.
 *
 *   -> Helper functions to manipulate PMA buddy allocator instance,
 *      its per NUMA node memory tracking structure.
 *
 *   -> Helper functions to manage buddy lists and its pages.
 *
 *   -> Primitive functions to alloc/free pages to buddylist which is
 *      used by various functions that implement interface to LWK mm core.
 *
 *   -> Physical memory operation interface functions, the pointers
 *      to which are packed in a structure and returned to LWK mm.
 *      These are the entry points to calls from LWK mm to buddy PMA.
 *
 *   -> Buddy PMA factory operation interface functions.
 *
 *   -> Buddy PMA early initializations during kernel bootup.
 *
 *   -> Buddy PMA tests for debugging.
 */

/*
 * Helper function that asserts PMA pointer and its expected state.
 * Every PM operation interface function should use it for sanity check.
 */
static inline int check_pma(struct lwk_pm_buddy_allocator *pma_buddy,
			    bool active)
{
	if (!pma_buddy) {
		LWKMEM_ERROR("%s: Error, PMA pointer is NULL", __func__);
		return -EINVAL;
	}

	if (pma_buddy->active != active) {
		LWKMEM_ERROR("%s: Error, PMA buddy is %s setup!", __func__,
				active ? "not yet" : "already");
		return -EINVAL;
	}
	return 0;
}

/*
 * Helper function that returns pointer to node memory tracking structure
 * given a NUMA node id @nid, returns NULL when the process does not have
 * any memory reserved for the given NUMA node @nid
 */
static struct node_memory *get_node_memory(struct lwk_pm_buddy_allocator *pma,
					   int nid)
{
	struct node_memory *mem = NULL;
	int node, i = 0;

	if (pma) {
		if (!pma->node_mem)
			goto out;
		for_each_node_mask(node, pma->nodes_mask) {
			if (node == nid) {
				mem = pma->node_mem[i];
				goto out;
			}
			i++;
		}
	}
out:
	return mem;
}

/*
 * Conversion between buddy order and LWK page type.
 */
static inline enum lwk_page_type order_to_lwkpagetype(int order)
{
	enum lwk_page_type t;

	for_each_lwkpage_type(t) {
		if (lwkpage_order(t) == order)
			break;
	}
	return t;
}

/*
 * Housekeeping of statistics, debug counters for a NUMA node.
 *
 * @nm,      pointer to per NUMA node memory tracking strucure.
 * @order,   order to consider to interpret @count.
 * @counter, buddy counter type to update.
 * @count,   count of pages.
 */
static void update_node_stats(struct node_memory *nm, int order,
			      enum buddy_counter counter, unsigned long count)
{
	enum lwk_page_type t;
	unsigned long nr_alloc;
	struct node_numa_stats *st = nm->stats;

	if (count == 0)
		return;
	if (st) {
		t = order_to_lwkpagetype(order);
		if (t >= LWK_MAX_NUMPGTYPES)
			return;
	}

	switch (counter) {
	case BUDDY_COUNTER_ALLOC:
		nm->nr_free -= count << order;
		/* Record debug stats when enabled. */
		if (st) {
			st->nr_allocs[t] += count;
			if (st->nr_allocs[t] > st->nr_alloc_max[t])
				st->nr_alloc_max[t] = st->nr_allocs[t];

			nr_alloc = nm->nr_total - nm->nr_free;
			if (nr_alloc > st->nr_alloc_max_mem)
				st->nr_alloc_max_mem = nr_alloc;
		}
		break;

	case BUDDY_COUNTER_FREE:
		nm->nr_free += count << order;
		if (st)
			nm->stats->nr_allocs[t] -= count;
		break;

	case BUDDY_COUNTER_CACHE_HIT:
		if (st)
			nm->stats->nr_cache_hit[t] += count;
		break;

	case BUDDY_COUNTER_CACHE_MISS:
		if (st)
			nm->stats->nr_cache_miss[t] += count;
		break;

	default:
		LWKMEM_WARN("Invalid counter %d for nid %d order %d count %lu",
			    counter, nm->nid, order, count);
		break;
	}
}

/*
 * Helper functions to manage buddy lists and its elements.
 */

/* Embedd LWK mm id in every struct page of [spfn, epfn) */
static void set_lwk_mm_id(unsigned long spfn, unsigned long epfn,
			  unsigned long id)
{
	struct page *page;

	/* Position LWK mm id in bitmask, ensures unsigned long width */
	id = id << _LWKPG_MMID_POS;
	/* Mark all struct pages with LWK mm id */
	while (spfn < epfn) {
		page = pfn_to_page(spfn);
		page->private &= ~_LWKPG_MMID_MASK;
		page->private |= id;
		spfn++;
	}
}

static inline unsigned long page_lwk_mm_id(struct page *page)
{
	return (page->private & _LWKPG_MMID_MASK) >> _LWKPG_MMID_POS;
}

static inline void set_page_order(struct page *page, int order)
{
	unsigned long val = order;

	page->private &= ~_LWKPG_ORDER_MASK;
	page->private |= (val << _LWKPG_ORDER_POS) & _LWKPG_ORDER_MASK;
}

static inline int page_order(struct page *page)
{
	unsigned long mask = ~(~0UL << _LWKPG_ORDER_WD);
	unsigned long val = page->private;

	val &= _LWKPG_ORDER_MASK;
	val = (val >> _LWKPG_ORDER_POS) & mask;
	return val;
}

static inline unsigned long find_buddy_pfn(unsigned long pfn, int order)
{
	return pfn ^ (1UL << order);
}

static inline int assert_page(struct page *page, unsigned long id)
{
	/*
	 * Check if this page is an LWK page and owned by current LWK mm
	 * if not then print appropriate RAS message and return -EINVAL.
	 */
	if (!is_lwkpg(page)) {
		LWKMEM_ERROR("Not a LWK page!");
		dump_page(page, "Not a LWK page");
		return -EINVAL;
	}

	if (id != page_lwk_mm_id(page)) {
		LWKMEM_ERROR("Unmanaged LWK page(mmid %ld) curr mmid %ld",
			     page_lwk_mm_id(page), id);
		return -EINVAL;
	}
	return 0;
}

/*
 * Checks if @page_tested adheres to following conditions,
 *     - It has to be an LWK page
 *     - Managed by the same per process LWK memory manager as that of @page
 *     - It has to be a free page already in the LWK buddy list
 *     - Belongs to the same NUMA node as that of @page
 *     - Its order is equal to @order
 */
static inline bool test_lwkpage(struct page *page, struct page *page_tested,
				int order)
{
	if (is_lwkpg(page_tested) &&
	    page_lwk_mm_id(page_tested) == page_lwk_mm_id(page) &&
	    PageBuddy(page_tested) &&
	    page_to_nid(page_tested) == page_to_nid(page) &&
	    page_order(page_tested) == order)
		return true;
	return false;
}

static void add_page_to_buddylist(struct page *page, struct freemem *mem,
				  int order)
{
	set_page_order(page, order);
	__SetPageBuddy(page);
	list_add_tail(&page->lru, &mem[order].list);
	mem[order].nr_free++;
}

static void remove_page_from_buddylist(struct page *page, struct freemem *mem)
{
	int order = page_order(page);

	if (unlikely(!mem[order].nr_free || list_empty(&mem[order].list))) {
		LWKMEM_ERROR("%s: order %d pfn %#lx",
			     !mem[order].nr_free ? "Underflow" : "Empty list",
			     order, page_to_pfn(page));
		for_each_order_reverse(order) {
			buddy_report_buddylist(mem, page_lwk_mm_id(page),
					       order);
		}
		dump_page(page, "LWK PMA error");
		dump_stack();
		return;
	}

	list_del(&page->lru);
	__ClearPageBuddy(page);
	mem[order].nr_free--;
}

static void remove_all_from_buddylist(struct freemem *mem, int order)
{
	struct page *page, *page_next;

	list_for_each_entry_safe(page, page_next, &mem[order].list, lru)
		remove_page_from_buddylist(page, mem);
}

static void insert_to_sorted_list(struct page *page_insert,
				  struct list_head *sorted_list)
{
	struct page *page;
	unsigned long pfn = page_to_pfn(page_insert);

	list_for_each_entry_reverse(page, sorted_list, lru) {
		if (pfn > page_to_pfn(page)) {
			list_add(&page_insert->lru, &page->lru);
			return;
		}
	}
	list_add(&page_insert->lru, sorted_list);
}

static void sort_buddylist(struct freemem *mem, int order)
{
	struct list_head sorted_list, *head;
	struct page *page, *page_next;

	head = &mem[order].list;
	INIT_LIST_HEAD(&sorted_list);
	list_for_each_entry_safe(page, page_next, head, lru) {
		list_del(&page->lru);
		insert_to_sorted_list(page, &sorted_list);
	}
	/* Back to buddy list head, now should be a sorted list */
	list_replace(&sorted_list, head);
	trace_mos_buddy_list_sort(order, mem[order].nr_free);
}

#ifdef DEBUG_BUDDY_PMA
static void range_show(struct buddy_contig_range *r, unsigned long id)
{
	int order;

	pr_report(id, "Range: nr_pages          : %lu\n", r->nr_pages);
	pr_report(id, "Range: nr_horder_pages   : %lu\n", r->nr_horder_pages);
	pr_report(id, "Range: horder, lorder    : %d, %d\n",
		  r->horder, r->lorder);
	pr_report(id, "Range: front lower orders: %*pbl\n",
		LWK_MAX_NUMORDERS, r->front_orders);
	pr_report(id, "Range: back lower orders : %*pbl\n",
		LWK_MAX_NUMORDERS, r->back_orders);
	for (order = r->horder; order >= r->lorder; order--) {
		if (range_test_front(r, order))
			pr_report(id, "Range: Front order %3d: pfn %#013lx\n",
				order, page_to_pfn(r->front_page[order]));
	}

	for (order = r->horder; order >= r->lorder; order--) {
		if (range_test_back(r, order))
			pr_report(id, "Range: Back  order %3d: pfn %#013lx\n",
				order, page_to_pfn(r->back_page[order]));
	}
}
#else
#define range_show(r, id)
#endif

/*
 * For the buddy list of given order this function returns the next
 * @n_contig_pages found. The function returns pointer to first
 * struct page among the batch of @n_contig_pages. This function
 * is used to iterate over the freelist looking for required number
 * of contiguous pages.
 *
 *   @mem,            pointer to freemem array of the NUMA node
 *   @order,          order of the buddy list that needs to iterated
 *   @n_done,         pointer to counter to be maintained by the caller
 *                    that tracks the progress
 *   @ppage_pos,      pointer to a struct page pointer to be maintained
 *                    by the caller, this is used as a cursor to continue
 *                    iteration between two calls
 *   @ppage_contig,   used to return pointer to the first struct page of
 *                    @n_contig_pages found, NULL on non-zero return value
 *   @n_contig_pages, number of contiguous pages to search for
 *
 *   Returns,         0   on success,
 *                    -ve error code on failure
 */
static int next_contig_range(struct freemem *mem, unsigned long order,
			     unsigned long *n_done, struct page **ppage_pos,
			     struct page **ppage_contig,
			     unsigned long n_contig_pages)
{
	struct list_head *head;
	unsigned long pfn, pfn_adj, epfn, nr_free, n;
	struct page *page, *page_start, *page_next, *page_adj;

	/* Reset output */
	if (ppage_contig)
		*ppage_contig = NULL;
	if (!mem || order > LWK_MAX_ORDER || !n_done ||
	    !ppage_pos || !ppage_contig || !n_contig_pages)
		return -EINVAL;

	nr_free = mem[order].nr_free;
	if (!nr_free || nr_free <= *n_done)
		return -EINVAL;
	if ((nr_free - *n_done) < n_contig_pages)
		return -ENOMEM;

	n = epfn = 0;
	head = &mem[order].list;
	*ppage_contig = page_start = NULL;
	page = list_prepare_entry((*ppage_pos), head, lru);
	/*
	 * For search request of length more than 2 contiguous pages
	 * we assume that the list is already sorted at @order.
	 */
	if (n_contig_pages > 2) {
		list_for_each_entry_continue(page, head, lru) {
			*n_done += 1;
			pfn = page_to_pfn(page);
			if (n == 0 || pfn != epfn) {
				/* Reset on start or non-contiguous pfn */
				n = 1;
				page_start = page;
			} else {
				if (++n == n_contig_pages)
					break;
			}
			/* Are there enough left? */
			if ((nr_free - *n_done) < (n_contig_pages - n))
				break;
			epfn = next_pfn(order, pfn);
		}
	} else {
		list_for_each_entry_safe_continue(page, page_next, head, lru) {
			*n_done += 1;
			if (n_contig_pages == 2) {
				/*
				 * No point in probing last page in the list
				 * continue to loop to update the cursor *page.
				 */
				if (&page_next->lru == head)
					continue;

				/* Is previous page free? */
				pfn = page_to_pfn(page);
				pfn_adj = prev_pfn(order, pfn);
				if (pfn_valid(pfn_adj)) {
					page_adj = pfn_to_page(pfn_adj);
					if (test_lwkpage(page, page_adj,
							 order)) {
						page_start = page_adj;
						n = 2;
						break;
					}
				}

				/* Is next page free? */
				pfn_adj = next_pfn(order, pfn);
				page_adj = pfn_to_page(pfn_adj);
				if (pfn_valid(pfn_adj)) {
					if (test_lwkpage(page, page_adj,
							 order)) {
						page_start = page;
						n = 2;
						break;
					}
				}
			} else {
				page_start = page;
				n = 1;
				break;
			}
		}
	}
	*ppage_pos = page;
	if (n == n_contig_pages) {
		*ppage_contig = page_start;
		return 0;
	}
	return -ENOMEM;
}

/*
 * Search contiguous range of free memory starting at order @horder
 * with a minimum page granularity of @lorder, i.e., smallest page
 * in the contiguous range can be of @lorder.
 *
 *   @n_horder, number of contiguous pages required at @horder.
 *   @n_needed, size of total contiguous memory needed in terms of number
 *              of @lorder pages.
 *   @range,    search results that describes found contiguous range.
 *
 *   Return,    none
 */
static void search_contig_memory(struct freemem *mem, int horder, int lorder,
				 unsigned long n_horder, unsigned long n_needed,
				 struct buddy_contig_range *range)
{
	int order;
	bool horder_only;
	unsigned long pfn, spfn, epfn, trace_spfn = 0;
	unsigned long n_total, done = 0;
	struct page *page, *pg_adj, *pos = NULL;
	struct buddy_contig_range *range_copy = NULL;
	struct buddy_contig_range *range_curr, *range_max, *range_temp;

	trace_mos_buddy_search_contig_enter(horder, lorder, n_horder, n_needed);

	/* Make sure the output is cleared, we may not find contiguous memory*/
	range_clear(range);
	range_curr = range;
	range_max = NULL;
	horder_only = in_lorder_pages(n_horder, horder, lorder) >= n_needed;
	if (!horder_only) {
		range_copy = kmalloc(sizeof(struct buddy_contig_range),
				     GFP_KERNEL);
		if (!range_copy)
			return;
		range_max = range_copy;
		range_clear(range_max);
	}

	while (!next_contig_range(mem, horder, &done, &pos, &page, n_horder)) {
		/* Reset working range */
		range_clear(range_curr);
		range_curr->nr_pages = in_lorder_pages(n_horder, horder,
						       lorder);
		range_curr->front_page[horder] = page;
		range_set_front(range_curr, horder);

		/* If the search is for only at horder, we are done.*/
		if (horder_only || horder == 0 || horder == lorder) {
			range_max = range_curr;
			trace_spfn = page_to_pfn(page);
			break;
		}

		/* Search lower order tails of @horder range [spfn, epfn) */
		spfn = page_to_pfn(page);
		epfn = spfn + in_base_pages(n_horder, horder);
		n_total = range_curr->nr_pages;

		for (order = horder - 1; order >= lorder; order--) {
			/* Search front lower order pages */
			pfn = spfn - in_base_pages(1, order);
			if (pfn_valid(pfn)) {
				pg_adj = pfn_to_page(pfn);
				if (test_lwkpage(page, pg_adj, order)) {
					range_set_front(range_curr, order);
					range_curr->front_page[order] = pg_adj;
					n_total += in_lorder_pages(1, order,
								   lorder);
					spfn = pfn;
				}
			}

			/* Search back lower order pages */
			pfn = epfn;
			if (pfn_valid(pfn)) {
				pg_adj = pfn_to_page(pfn);
				if (test_lwkpage(page, pg_adj, order)) {
					range_set_back(range_curr, order);
					range->back_page[order] = pg_adj;
					n_total += in_lorder_pages(1, order,
								   lorder);
					epfn = epfn + in_base_pages(1, order);
				}
			}
		}
		range_curr->nr_pages = n_total;

		if (n_total >= n_needed) {
			/* We found a range sufficiently large */
			range_max = range_curr;
			trace_spfn = spfn;
			break;
		}

		/*
		 * Make this the largest range found found so far that is
		 * smaller than the size asked for. In the case if we do not
		 * find a range that is sufficiently large then we return the
		 * next best possible.
		 */
		if (n_total > range_max->nr_pages) {
			range_temp = range_max;
			range_max = range_curr;
			range_curr = range_temp;
			trace_spfn = spfn;
		}
	}

	if (range_max && range_max != range)
		*range = *range_max;

	range->horder = range->nr_pages ? horder : 0;
	range->lorder = range->nr_pages ? lorder : 0;
	range->nr_horder_pages = range->nr_pages ? n_horder : 0;

	kfree(range_copy);
	trace_mos_buddy_search_contig_exit(range->horder, range->lorder,
			range->nr_horder_pages, range->nr_pages,
			trace_spfn);
}

/*
 * Find and remove all pages in the lists beween two given orders that form
 * a contiguous memory range of needed size. Truncate the needed request and
 * allocate the next best available if the given request can not be fullfilled.
 *
 *   @mem,         pointer to freemem array of the NUMA node
 *   @horder,      maximum higher order to consider
 *   @lorder,      minimum lower order to consider
 *   @n_needed,    the number of contiguous pages of @lorder needed
 *   @n_allocated, the number of contiguous pages of @lorder allocated,
 *                 0 if the function returns NULL
 *
 *   Returns,      pointer to the first struct page of the contiguous range,
 *                 NULL if the @horder list is empty, this means for the
 *                 function to proceed there needs to be atleast 1 element
 *                 in that buddy list
 */
static struct page *remove_contig_pages_from_buddylist(struct freemem *mem,
					unsigned long id,
					int horder, int lorder,
					unsigned long n_needed,
					unsigned long *n_allocated)
{
	struct page *page, *page_first;
	struct buddy_contig_range *range, *r;
	unsigned long pfn, n_horder, n_max, n_unit, n_used, n_free;
	int h, l, pass, use_first_part;

	trace_mos_buddy_remove_contig(horder, lorder, n_needed);

	/* Reset output */
	if (n_allocated)
		*n_allocated = 0;

	if (!mem || horder > LWK_MAX_ORDER || horder < lorder ||
	    !n_needed || !n_allocated)
		return NULL;

	if (list_empty(&mem[horder].list))
		return NULL;

	page_first = NULL;

	range = kzalloc(sizeof(struct buddy_contig_range) * 2, GFP_KERNEL);
	if (!range)
		return NULL;
	/*
	 * If the request is of size more than 4 higher order pages then we
	 * need to sort the list before searching for contiguous memory. Any
	 * request smaller than that would be treated as general case below.
	 * This sorting will be necessary only for LWK_MAX_ORDER list since
	 * only at that order there could be more than 2 elements in the list
	 * to form a contiguous range. The sorting may not be as bad as one
	 * would imagine as in a reasonable configuration there will be very
	 * few elements at LWK_MAX_ORDER list.
	 */
	if (n_needed >= in_lorder_pages(4, horder, lorder) &&
	    horder == LWK_MAX_ORDER) {
		sort_buddylist(mem, horder);
		n_unit = in_lorder_pages(1, horder, lorder);
		n_horder = (n_unit + n_needed - 1) / n_unit;

		while (n_horder >= 4) {
			r = &range[0];
			search_contig_memory(mem, horder, lorder, n_horder,
					     n_needed, r);
			if (r->nr_pages) {
				/*
				 * Truncate request to the max possible we
				 * could get if we got less than requested.
				 */
				if (r->nr_pages < n_needed)
					n_needed = r->nr_pages;
				goto remove_pages;
			}
			n_horder--;
		}
	}

	/*
	 * From here onwards, for any available contiguous range there can not
	 * be more than 2 pages of @horder either because their buddies are al-
	 * -located or simply not available to the process like shown below.
	 *
	 *   @horder+1 -> |<-  pfn 1 ->|<-  pfn 2 ->|
	 *   @horder   -> |/////| Free | Free |/////|
	 *
	 * But this contiguous range could be extended either at front or
	 * back or both by the lower order pages whose buddies are allocated
	 * or unavailable. We refer to them as tail of @horder pages. At best
	 * all of these could add up to 3.x < 4 @horder pages.
	 *
	 * We follow the steps bellow,
	 *   1. Search for 2 @horder contiguous pages and consider lower order
	 *      tails during the search if @n_needed > 2 @horder pages. If
	 *      success then allocate @n_needed @lorder pages out of it and
	 *      release unused portion of the range back to buddy list.
	 *   2. If 1. fails, we clamp @n_needed to 2.x < 3 pages if need be.
	 *      Search for 1 @horder page and consider lower order tails duri-
	 *      -ng the search if @n_needed > 1 @horder page. If that is suff-
	 *      -icient to fulfill the request then allocate from that batch
	 *      releasing unused parts back to buddy lists.
	 *   3. If 2. fails and if @horder > @lorder, search @horder-1 list for
	 *      2 contig pages and lower order tails that combined can fulfill
	 *      the request.
	 *   4. If 3. fails, we truncate the request to max contig range found
	 *      in 2. and allocate that piece.
	 *
	 * Note that this function returns NULL right away at the beginning
	 * if the list at @horder is empty. We expect caller to retry by
	 * calling this function at lower orders on receiving NULL.
	 */
	h = horder;
	l = lorder;
	r = &range[0];
	for (pass = 1; pass < 5; pass++) {
		switch (pass) {
		case 1:
			/* Max is 3.x < 4 pages at this order */
			n_max = in_lorder_pages(4, h, l) - 1;
			n_needed = min(n_needed, n_max);
			n_horder = 2;
			break;
		case 2:
			/* Next max is 2.x < 3 pages at this order */
			n_max = in_lorder_pages(3, h, l) - 1;
			n_needed = min(n_needed, n_max);
			n_horder = 1;
			break;
		case 3:
			if (h > l) {
				h--;
				n_horder = 2;
				r = &range[1];
			} else {
				n_needed = r->nr_pages;
				goto remove_pages;
			}
			break;
		case 4:
			r = &range[0];
			n_needed = r->nr_pages;
			goto remove_pages;
		default:
			WARN_ON_ONCE(1);
			goto out;
		}
		search_contig_memory(mem, h, l, n_horder, n_needed, r);
		if (r->nr_pages >= n_needed)
			break;
	}

remove_pages:
	/*
	 * We found contiguous memory of required size or less. Now
	 * go ahead and remove pages in the range from buddy lists.
	 */
	*n_allocated = 0;
	if (r && r->nr_pages) {
		/* Print range only if debug is enabled */
		range_show(r, id);

		/* Updated orders from search results */
		horder = r->horder;
		lorder = r->lorder;

		/* Remove @horder pages first from buddy list. */
		n_free = r->nr_horder_pages;
		n_unit = base_pages_per_unit(horder);
		page_first = r->front_page[horder];
		pfn = page_to_pfn(page_first);

		while (n_free) {
			page = pfn_to_page(pfn);
			remove_page_from_buddylist(page, mem);
			pfn += n_unit;
			n_free--;
		}
		*n_allocated = in_lorder_pages(r->nr_horder_pages, horder,
					       lorder);
		/* Are @horder pages sufficient to fulfill the request ? */
		if (*n_allocated >= n_needed) {
			/*
			 * Free unused portion of the first page if
			 * it is partly used.
			 */
			if (*n_allocated > n_needed) {
				n_unit = in_lorder_pages(1, horder, lorder);
				n_used = n_needed % n_unit;
				pfn = page_to_pfn(page_first);
				free_lwkpage_partial(mem, id, pfn, horder,
						     lorder, n_used, true);
			}
		} else {
			if (horder == 0 || horder <= lorder)
				goto out;

			/* Remove lower order pages if any from buddy list */
			n_used = 0;
			page = NULL;
			use_first_part = true;
			for (h = horder - 1; h >= lorder; h--) {
				n_unit = in_lorder_pages(1, h, lorder);
				if (range_test_front(r, h)) {
					page = page_first = r->front_page[h];
					remove_page_from_buddylist(page, mem);
					*n_allocated += n_unit;
					if (*n_allocated >= n_needed) {
						l = h;
						n_used = n_needed % n_unit;
						use_first_part = false;
						break;
					}
				}

				if (range_test_back(r, h)) {
					page = r->back_page[h];
					remove_page_from_buddylist(page, mem);
					*n_allocated += n_unit;
					if (*n_allocated >= n_needed) {
						l = h;
						n_used = n_needed % n_unit;
						break;
					}
				}
			}
			/* Free unused portion of partly used page */
			if (n_used) {
				pfn = page_to_pfn(page);
				free_lwkpage_partial(mem, id, pfn, l, lorder,
						     n_used, use_first_part);
				/*
				 * Recompute start page if we partially
				 * freed a front page.
				 */
				if (!use_first_part) {
					n_unit = in_lorder_pages(1, l, lorder);
					pfn += in_base_pages(n_unit - n_used,
							     lorder);
					page_first = pfn_to_page(pfn);
				}
			}
		}
	}
out:
	kfree(range);
	return page_first;
}

/*
 * Helper functions to manage buddy PMA cache of pages.
 */
static void buddy_cache_refill(struct node_memory *node_mem, unsigned long id,
			       enum lwk_page_type pgtype, bool record_stats)
{
	int order = lwkpage_order(pgtype);
	struct page *page;
	struct freemem *mem = node_mem->mem;
	struct freemem *cache = &node_mem->cache[pgtype];
	unsigned long n_cache_max_size = node_mem->cache_max_size[pgtype];
	unsigned long n_free_orig = cache->nr_free;

	while (cache->nr_free < n_cache_max_size &&
	       alloc_lwkpage(mem, id, order, &page) == 0) {
		list_add_tail(&page->lru, &cache->list);
		cache->nr_free++;
	}

	if (record_stats && node_mem->stats && cache->nr_free > n_free_orig) {
		update_node_stats(node_mem, order, BUDDY_COUNTER_CACHE_MISS,
				  cache->nr_free - n_free_orig);
	}
}

static int buddy_cache_flush(struct node_memory *node_mem, unsigned long id,
			     enum lwk_page_type pgtype)
{
	int order;
	struct page *page, *page_next;
	struct freemem *cache = &node_mem->cache[pgtype];
	unsigned long n_flushed = cache->nr_free;

	if (cache->nr_free) {
		order = lwkpage_order(pgtype);

		list_for_each_entry_safe(page, page_next, &cache->list, lru) {
			list_del_init(&page->lru);
			free_lwkpage(node_mem->mem, id, page_to_pfn(page),
				     order);
		}
		cache->nr_free = 0;
	}
	return n_flushed;
}

static void buddy_cache_insert(struct list_head *list, struct page *page,
			       int horder, int lorder)
{
	unsigned long n_pages = in_lorder_pages(1, horder, lorder);
	unsigned long pfn_stride = base_pages_per_unit(lorder);
	unsigned long pfn = page_to_pfn(page);

	while (n_pages--) {
		page = pfn_to_page(pfn);
		list_add_tail(&page->lru, list);
		pfn += pfn_stride;
	}
}

/*
 * Buddy allocators core function that releases a page to buddy list. Further
 * it merges the buddy pages of the page being freed at @order and all higher
 * orders if the buddies are also free.
 *
 *   @mem,    pointer to freemem array of the NUMA node
 *   @pfn,    pfn of the page being freed
 *   @order,  order of the page being freed
 *
 *   Returns, none
 */
static void free_lwkpage(struct freemem *mem, unsigned long id,
			 unsigned long pfn, int order)
{
	struct page *page, *buddy;
	unsigned long buddy_pfn, combined_pfn;

	VM_BUG_ON_PAGE(pfn & ((1UL << order) - 1), page);
	page = pfn_to_page(pfn);
	assert_page(page, id);

	while (order < LWK_MAX_ORDER) {
		buddy_pfn = find_buddy_pfn(pfn, order);
		buddy = page + (buddy_pfn - pfn);

		if (!pfn_valid(buddy_pfn) ||
		    !pfn_in_present_section(buddy_pfn))
			break;
		if (!test_lwkpage(page, buddy, order))
			break;

		remove_page_from_buddylist(buddy, mem);
		combined_pfn = buddy_pfn & pfn;
		page = page + (combined_pfn - pfn);
		pfn = combined_pfn;
		order++;
	}
	add_page_to_buddylist(page, mem, order);
}

/*
 * Frees an higher order page partially while allocating few lower order
 * pages out of it.
 *
 *   @mem,      pointer to freemem array of the NUMA node
 *   @pfn,      pfn of the higher order page
 *   @horder,   order of higher order page beign freed partially
 *   @lorder,   order of lower order pages to be allocated
 *   @n_alloc,  number of lower order pages to be allocated
 *   @alloc_first_part,
 *              when true, lower order pages need to be allocated from the
 *              start of higher order page otherwise they need to be allocated
 *              from the end of higher order page
 *
 *   Returns,   none
 */
static void free_lwkpage_partial(struct freemem *mem, unsigned long id,
				 unsigned long pfn, int horder, int lorder,
				 unsigned long n_alloc, bool alloc_first_part)
{
	unsigned long spfn, epfn;
	struct page *page = pfn_to_page(pfn);

	VM_BUG_ON_PAGE(pfn & ((1UL << horder) - 1), page);
	VM_BUG_ON_PAGE(horder < lorder, page);
	VM_BUG_ON_PAGE(horder == 0, page);
	if (assert_page(page, id)) {
		LWKMEM_ERROR("%s: Err, pfn %ld, high %d low %d n %lu alloc %s",
				__func__, pfn, horder, lorder, n_alloc,
				alloc_first_part ? "first" : "last");
	}

	if (horder == lorder) {
		VM_BUG_ON_PAGE(n_alloc != 1, page);
		free_lwkpage(mem, id, pfn, lorder);
	}

	epfn = pfn + in_base_pages(1, horder);
	if (alloc_first_part) {
		pfn = pfn + in_base_pages(n_alloc, lorder);

		while (--horder >= lorder) {
			spfn = epfn - base_pages_per_unit(horder);
			if (spfn < pfn)
				continue;

			page = pfn_to_page(spfn);
			add_page_to_buddylist(page, mem, horder);
			if (spfn == pfn)
				break;
			epfn = spfn;
		}
	} else {
		spfn = pfn;
		pfn = epfn - n_alloc;

		while (--horder >= lorder) {
			epfn = spfn + base_pages_per_unit(horder);
			if (epfn > pfn)
				continue;

			page = pfn_to_page(spfn);
			add_page_to_buddylist(page, mem, horder);
			if (epfn == pfn)
				break;
			spfn = epfn;
		}
	}
}

/*
 * Frees pages of a NUMA node tracked by @node_mem.
 *
 *  @n_pages, number of pages of @order to be freed
 *  @pfn,     pfn of first page to be freed
 *  @order,   order of pages to be freed
 *
 *  Returns, none
 */
static void free_lwkpages_node(struct node_memory *node_mem, unsigned long id,
			       unsigned long pfn, unsigned long n_pages,
			       int order)
{
	unsigned long n = 0, flags;
	struct page *page;
	enum lwk_page_type pt = order_to_lwkpagetype(order);

	trace_mos_buddy_free_lwkpages_node(node_mem->nid, pfn, n_pages, order);
	spin_lock_irqsave(&node_mem->lock, flags);

	/* Only use cache for valid page order */
	if (pt < LWK_MAX_NUMPGTYPES) {
		struct freemem *cache = &node_mem->cache[pt];
		unsigned long n_cache_max = node_mem->cache_max_size[pt];

		/* Free pages back to cache if there is room */
		while (cache->nr_free < n_cache_max && n < n_pages) {
			page = pfn_to_page(pfn);
			list_add_tail(&page->lru, &cache->list);
			cache->nr_free++;
			pfn = next_pfn(order, pfn);
			n++;
		}
	}

	/* Free remaining pages to the buddy lists */
	while (n < n_pages) {
		free_lwkpage(node_mem->mem, id, pfn, order);
		pfn = next_pfn(order, pfn);
		n++;
	}

	update_node_stats(node_mem, order, BUDDY_COUNTER_FREE, n);
	spin_unlock_irqrestore(&node_mem->lock, flags);
}

/*
 * Frees pages in the given pfn range.
 *
 *   @pma_buddy, pointer to per process buddy allocator context
 *   @pfn,       pfn of first page in the range to be freed
 *   @n_pages,   number of pages of @order to be freed
 *   @order,     order of the pages in the range to be freed
 *
 *   Returns,    0   on success,
 *               -ve error code on failure
 */
static int free_lwkpages_range(struct lwk_pm_buddy_allocator *pma_buddy,
			       unsigned long pfn, unsigned long n_pages,
			       int order)
{
	int nid;
	struct node_memory *node_mem;
	unsigned long spfn, epfn, n;

	trace_mos_free_lwkpages_range(pfn, n_pages, order);

	if (!n_pages)
		return -EINVAL;
	epfn = pfn + in_base_pages(n_pages, order);
	while (pfn < epfn) {
		/* Find pfn range that has same NUMA node id */
		nid = page_to_nid(pfn_to_page(pfn));
		spfn = pfn;
		pfn = next_pfn(order, pfn);
		n = 1;

		while (pfn < epfn && page_to_nid(pfn_to_page(pfn)) == nid) {
			pfn = next_pfn(order, pfn);
			n++;
		}

		/* Free pages for NUMA node @nid */
		node_mem = get_node_memory(pma_buddy, nid);
		if (!node_mem) {
			LWKMEM_ERROR(
				"%s: [ %#013lx-%#013lx ) nm[%d]=NULL, R[%*pbl]",
				__func__, spfn, spfn + in_base_pages(n, order),
				nid, nodemask_pr_args(&pma_buddy->nodes_mask));
			return -EINVAL;
		}
		free_lwkpages_node(node_mem, pma_buddy->id, spfn, n, order);
	}
	return 0;
}

/*
 * Buddy allocator core function that allocates a single page.
 *
 *   @mem,      pointer to freemem array of the NUMA node
 *   @order,    order of the page that needs to be allocated
 *   @page_out, used to return the pointer to struct page of the page
 *              allocated. NULL if the allocation can not be done
 *
 *   Returns,   0       on success,
 *              -ENOMEM when there is no memory at @order or higher
 */
static int alloc_lwkpage(struct freemem *mem, unsigned long id,
			 int order, struct page **page_out)
{
	struct page *page;
	struct list_head *head_list;
	int order_curr, rc = -ENOMEM;

	order_curr = order;
	for_each_order_from(order_curr) {
		head_list = &mem[order_curr].list;
		if (list_empty(head_list))
			continue;
		rc = 0;
		page = list_first_entry(head_list, struct page, lru);
		remove_page_from_buddylist(page, mem);
		if (order_curr > order) {
			free_lwkpage_partial(mem, id, page_to_pfn(page),
					     order_curr, order, 1, true);
		}
		break;
	}

	if (page_out)
		*page_out = rc ? NULL : page;
	return rc;
}

/*
 * Allocates contiguous pages on a NUMA node.
 *
 *   @node_mem,    pointer to per NUMA node memory tracking structure
 *   @id,          LWK MMID to which the PMA is attached
 *   @n_needed,    the number of @pgtype contiguous pages needed,
 *                 needs be >= 2 for contiguous allocation request
 *   @pgtype,      the type of LWK pages needed
 *   @list,        list that is used to return the struct page of the
 *                 first page allocated in the contiguous range.
 *   @n_allocated, the number of @pgtype contiguous pages allocated,
 *                 0 on non-zero return value
 *
 *   Returns, 0       on success,
 *            -EINVAL on attempt to pass invalid argument
 *            -ENOMEM when no free memory is available at @order or higer
 */
static int alloc_lwkpages_node_contig(struct node_memory *node_mem,
				      unsigned long id,
				      unsigned long n_needed,
				      enum lwk_page_type pgtype,
				      struct list_head *list,
				      unsigned long *n_allocated)
{
	unsigned long n, pfn;
	struct page *page;
	enum lwk_page_type pt;
	struct freemem *mem;
	bool retry, cache_flushed;
	int rc, order_curr, order = lwkpage_order(pgtype);

	trace_mos_buddy_alloc_contig(order, n_needed);

	if (!node_mem || n_needed < 2 || order > LWK_MAX_ORDER ||
	    !n_allocated || !list || !list_empty(list)) {
		if (n_allocated)
			*n_allocated = 0;
		if (list)
			INIT_LIST_HEAD(list);
		return -EINVAL;
	}
	mem = node_mem->mem;

	/*
	 * Find the minimum higher order at which we can
	 * fulfill the request with single element.
	 */
	n = 0;
	order_curr = order + 1;
	for_each_order_from(order_curr) {
		n = in_lorder_pages(1, order_curr, order);
		if (n >= n_needed)
			break;
	}

	cache_flushed = false;
	if (likely(order_curr <= LWK_MAX_ORDER)) {
		/* Fast path */
		do {
			retry = false;
			rc = alloc_lwkpage(mem, id, order_curr, &page);
			if (rc == -ENOMEM && !cache_flushed) {
				/* Retry once after flushing PMA caches */
				retry = true;
				cache_flushed = true;
				for_each_lwkpage_type_reverse(pt)
					buddy_cache_flush(node_mem, id, pt);
			}
		} while (rc == -ENOMEM && retry);

		if (rc == 0) {
			/*
			 * Success! we found a free buddy element at higher
			 * order. We use it in part or full based on contig
			 * memory needed. When used in part free the unused
			 * memory back to the buddy list.
			 */
			*n_allocated = n_needed;
			if (n > n_needed) {
				pfn = page_to_pfn(page);
				free_lwkpage_partial(mem, id, pfn, order_curr,
						     order, n_needed, true);
			}
			list_add_tail(&page->lru, list);
			return 0;
		}
	}

	/* Slow path */
	page = NULL;
	*n_allocated = 0;

	/* Flush PMA caches if not already done before */
	if (!cache_flushed) {
		for_each_lwkpage_type_reverse(pt)
			buddy_cache_flush(node_mem, id, pt);
	}

	while (--order_curr >= order && !page) {
		page = remove_contig_pages_from_buddylist(mem, id, order_curr,
						order, n_needed, n_allocated);
	}

	if (page) {
		list_add_tail(&page->lru, list);
		return 0;
	}
	return -ENOMEM;
}

/*
 * Allocates pages through PMA cache
 *
 *   @node_mem,    pointer to per NUMA node memory tracking structure
 *   @id,          LWK MMID to which PMA is attached
 *   @n_needed,    number of pages of @pgtype needed
 *   @pgtype,      the type of LWK pages needed
 *   @alloc_flags, flags that determine allocation behaviors,
 *                 i.e., normal or random handled in this function
 *   @list,        list that is used to return the struct page(s) allocated
 *   @n_allocated  number of pages of @pgtype allocated
 *
 *   Returns, 0       on success, @list @n_allocated are valid
 *            -EINVAL on attempt to pass invalid argument
 *            -ENOMEM when no free memory is available at @order or higer
 */
static int alloc_lwkpages_cache(struct node_memory *node_mem, unsigned long id,
				unsigned long n_needed,
				enum lwk_page_type pgtype,
				enum lwk_pma_alloc_flags alloc_flags,
				struct list_head *list,
				unsigned long *n_allocated)
{
	bool rev, flushed;
	enum lwk_page_type pt;
	int horder, lorder, rc = 0;
	struct page *page;
	struct list_head *head, *pos;
	unsigned long n, n_elements, r_index;
	unsigned long extracted = 0;
	unsigned long n_cache = 0;
	unsigned long n_buddylists = 0;
	struct freemem *mem = node_mem->mem;
	struct freemem *cache = &node_mem->cache[pgtype];

	/*
	 * If the cache of @pgtype does not have sufficient pages then try to
	 * re-fill from caches of higher page size. If @pgtype is of highest
	 * page size then there are no further caches to re-fill from.
	 */
	if (pgtype < LWK_MAX_NUMPGTYPES - 1) {
		pt = pgtype;
		while (cache->nr_free < n_needed) {
			for_each_lwkpage_type_from(pt, pt + 1)
				if (node_mem->cache[pt].nr_free)
					break;
			/* All caches are emtpy? */
			if (pt == LWK_MAX_NUMPGTYPES)
				break;
			/*
			 * Transfer a page from higher order cache to one or
			 * more pages in the lower orders cache.
			 */
			for_each_lwkpage_type_reverse_from(pt, pt) {
				if (pt == pgtype)
					break;
				horder = lwkpage_order(pt);
				lorder = lwkpage_order(pt - 1);
				n = in_lorder_pages(1, horder, lorder);

				/* Remove first page at the front */
				head = &node_mem->cache[pt].list;
				page = list_first_entry(head, struct page, lru);
				list_del(&page->lru);

				/* Split and transfer */
				head = &node_mem->cache[pt - 1].list;
				buddy_cache_insert(head, page, horder, lorder);

				/* Update cache counters for free pages */
				node_mem->cache[pt].nr_free--;
				node_mem->cache[pt - 1].nr_free += n;
			}
		}
	}
	n = min(cache->nr_free, n_needed);
	if (cache->nr_free) {
		if (alloc_flags & PMA_ALLOC_RANDOM) {
			while (extracted < n) {
				/* Fetch a random page, one at a time */
				r_index = get_random_u32() % cache->nr_free;
				head = &cache->list;
				rev = r_index > cache->nr_free >> 1;
				n_elements = rev ?
					cache->nr_free - r_index - 1 : r_index;
				pos = rev ? head->prev : head->next;
				while (n_elements--)
					pos = rev ? pos->prev : pos->next;
				list_move_tail(pos, list);
				--cache->nr_free;
				extracted++;
			}
		} else {
			/* Fetch @n pages from the cache */
			if (n == cache->nr_free)
				list_replace_init(&cache->list, list);
			else {
				head = &cache->list;
				rev = n > cache->nr_free >> 1;

				n_elements = rev ? cache->nr_free - n : n - 1;
				pos = rev ? head->prev : head->next;
				while (n_elements--)
					pos = rev ? pos->prev : pos->next;
				list_cut_position(list, head, pos);
			}
			/* Update cache counters */
			cache->nr_free -= n;
		}
	}
	n_cache = n;

	/*
	 * If we could not get all pages from the cache then
	 * fetch remaining pages from the buddy lists directly.
	 */
	pt = pgtype;
	while (n_needed > n) {
		rc = alloc_lwkpage(mem, id, lwkpage_order(pgtype), &page);
		if (rc) {
			/*
			 * Upon no memory error, retry allocation after
			 * flushing a lower order cache one at a time.
			 */
			if (rc == -ENOMEM) {
				flushed = false;
				for_each_lwkpage_type_reverse_from(pt, pt - 1) {
					if (buddy_cache_flush(node_mem, id,
							      pt)) {
						flushed = true;
						break;
					}
				}

				/* Retry only if we flushed any pages. */
				if (flushed)
					continue;
			}
			/* Return success if we allocated a few so far */
			if (n)
				rc = 0;
			break;
		}
		list_add_tail(&page->lru, list);
		n++;
	}
	n_buddylists = n - n_cache;

	/* Try to replenish the cache of the highest page size if empty */
	if (node_mem->cache[LWK_MAX_NUMPGTYPES - 1].nr_free == 0)
		buddy_cache_refill(node_mem, id, LWK_MAX_NUMPGTYPES - 1, true);

	if (node_mem->stats) {
		lorder = lwkpage_order(pgtype);
		update_node_stats(node_mem, lorder,
				  BUDDY_COUNTER_CACHE_HIT, n_cache);
		update_node_stats(node_mem, lorder,
				  BUDDY_COUNTER_CACHE_MISS, n_buddylists);
	}
	*n_allocated = rc ? 0 : n;
	return rc;
}

/*
 * Allocates pages from a NUMA node
 *
 *   @node_mem,    pointer to per NUMA node memory tracking structure
 *   @id,          LWK MMID to which the PMA is attached
 *   @n_needed,    number of pages of @pgtype needed
 *   @pgtype,      the type of LWK pages needed
 *   @alloc_flags, flags that determine allocation behaviors,
 *                 i.e., normal, contiguous, or random
 *   @list,        list that is used to return the struct page(s) allocated
 *   @n_allocated  number of pages of @pgtype allocated
 *
 *   Returns, 0       on success, @list @n_allocated are valid
 *            -EINVAL on attempt to pass invalid argument
 *            -ENOMEM when no free memory is available at @order or higer
 */
static int alloc_lwkpages_node(struct node_memory *node_mem, unsigned long id,
			       unsigned long n_needed,
			       enum lwk_page_type pgtype,
			       enum lwk_pma_alloc_flags alloc_flags,
			       struct list_head *list,
			       unsigned long *n_allocated)
{
	int rc;
	unsigned long flags;

	spin_lock_irqsave(&node_mem->lock, flags);

	/* Reset output */
	INIT_LIST_HEAD(list);
	*n_allocated = 0;

	if (alloc_flags == PMA_ALLOC_CONTIG && n_needed > 1)
		rc = alloc_lwkpages_node_contig(node_mem, id, n_needed, pgtype,
						list, n_allocated);
	else
		rc = alloc_lwkpages_cache(node_mem, id, n_needed, pgtype,
					  alloc_flags, list, n_allocated);
	/* Update PMA alloc counters on success */
	if (rc == 0) {
		update_node_stats(node_mem, lwkpage_order(pgtype),
				  BUDDY_COUNTER_ALLOC, *n_allocated);
	}

	spin_unlock_irqrestore(&node_mem->lock, flags);
	return rc;
}

/*
 * LWK memory manager core to Buddy PMA interface functions and their helpers.
 * Expected behavior of these interface functions are documented in,
 * include/linux/moslwkmem.h
 */
static int buddy_free_pages(void *pma, enum lwk_page_type pgtype,
			    unsigned long spfn, unsigned long n,
			    struct list_head *list)
{
	struct lwk_pm_buddy_allocator *pma_buddy = pma;
	struct page *page, *page_next;
	int error, rc;

	/* Validate state */
	if (check_pma(pma_buddy, PMA_ACTIVE))
		return -EINVAL;
	/* Validate args. */
	if (!valid_lwkpage_type(pgtype))
		return -EINVAL;
	if (list && list_empty(list))
		return -EINVAL;
	if (!list && !n)
		return -EINVAL;

	if (!list) {
		/* Free contiguous pages */
		rc = free_lwkpages_range(pma_buddy, spfn, n,
					 lwkpage_order(pgtype));
	} else {
		rc = 0;
		/* Free non-contiguous pages in the list @list */
		list_for_each_entry_safe(page, page_next, list, lru) {
			list_del(&page->lru);
			error = free_lwkpages_range(pma_buddy,
					page_to_pfn(page), 1,
					lwkpage_order(pgtype));
			/* Capture first error, and try to free remaining */
			if (!rc && error)
				rc = error;
		}
	}
	return rc;
}

static int buddy_alloc_pages(void *pma, int nid, unsigned long n_needed,
			     enum lwk_page_type pgtype,
			     enum lwk_pma_alloc_flags flags,
			     struct list_head *list, unsigned long *n_allocated)
{
	int rc;
	struct lwk_pm_buddy_allocator *pma_buddy = pma;
	struct node_memory *node_mem;

	trace_mos_buddy_alloc_enter(nid, n_needed, pgtype, flags);

	/* Validate PMA state */
	if (check_pma(pma_buddy, PMA_ACTIVE))
		return -EINVAL;
	/* Validate arguments */
	if (!n_needed || !list || !valid_lwkpage_type(pgtype) || !n_allocated ||
	    !valid_pma_alloc_flags(flags))
		return -EINVAL;
	if (!node_isset(nid, pma_buddy->nodes_mask)) {
		LWKMEM_ERROR("%s: Invalid nid=%d, valid nodes[%*pbl]", __func__,
				nid, nodemask_pr_args(&pma_buddy->nodes_mask));
		return -EINVAL;
	}
	node_mem = get_node_memory(pma_buddy, nid);
	if (!node_mem) {
		LWKMEM_ERROR("%s: node_memory[%d]=NULL, Reserved [%*pbl]",
				__func__, nid,
				nodemask_pr_args(&pma_buddy->nodes_mask));
		return -EINVAL;
	}

	rc = alloc_lwkpages_node(node_mem, pma_buddy->id, n_needed,
				 pgtype, flags, list, n_allocated);
	trace_mos_buddy_alloc_exit(*n_allocated);
	return rc;
}

static int buddy_split_page(void *pma, enum lwk_page_type pgtype,
			    unsigned long pfn)
{
	int orderh, orderl;
	unsigned long flags, npages;
	struct lwk_pm_buddy_allocator *pma_buddy = pma;
	struct node_memory *node_mem;
	struct page *page = pfn_to_page(pfn);
	int nid = page_to_nid(page);

	/* Validate PMA state */
	if (check_pma(pma_buddy, PMA_ACTIVE))
		return -EINVAL;
	if (!valid_lwkpage_type(pgtype)) {
		LWKMEM_ERROR("Invalid page type: %d", pgtype);
		return -EINVAL;
	}

	if (assert_page(page, pma_buddy->id)) {
		LWKMEM_ERROR("Invalid page");
		return -EINVAL;
	}

	trace_mos_buddy_split_page(pgtype, pfn, nid);

	if (pgtype == LWK_PG_4K)
		return 0;

	node_mem = get_node_memory(pma_buddy, nid);
	if (!node_mem) {
		LWKMEM_ERROR("node_memory[%d]=NULL, Reserved [%*pbl]",
			nid, nodemask_pr_args(&pma_buddy->nodes_mask));
		return -EINVAL;
	}

	/* Nothing to do if recording of node stats is not enabled */
	if (!node_mem->stats)
		return 0;

	orderh = lwkpage_order(pgtype);
	orderl = lwkpage_order(pgtype - 1);
	npages = in_lorder_pages(1, orderh, orderl);

	/*
	 * Update stats as if it were like freeing a higher order page
	 * and allocating @npages of lower order pages.
	 */
	spin_lock_irqsave(&node_mem->lock, flags);
	update_node_stats(node_mem, orderh, BUDDY_COUNTER_FREE, 1);
	update_node_stats(node_mem, orderl, BUDDY_COUNTER_ALLOC, npages);
	spin_unlock_irqrestore(&node_mem->lock, flags);
	return 0;
}

static void buddy_report_buddylist(struct freemem *mem, unsigned long id,
				   int order)
{
	struct page *page;
	struct list_head *head_list;
	unsigned long pfn, spfn, epfn, page_len;

	if (!mem)
		return;
	head_list = &mem[order].list;
	if (list_empty(head_list))
		return;

	page = list_first_entry(head_list, struct page, lru);
	spfn = epfn = page_to_pfn(page);
	page_len = base_pages_per_unit(order);

	list_for_each_entry(page, head_list, lru) {
		pfn = page_to_pfn(page);
		if (pfn == epfn) {
			epfn += page_len;
			continue;
		}
		pr_report(id, "%9s| %5d | %#013lx | %#013lx | %13lu |\n",
			  "", order, spfn, epfn, (epfn - spfn) / page_len);
		/* Reset markers to next contiguous range */
		spfn = pfn;
		epfn = pfn + page_len;
	}
	/*
	 * We know this list is not empty, so there
	 * is atleast one range to print.
	 */
	pr_report(id, "%9s| %5d | %#013lx | %#013lx | %13lu |\n",
		  "", order, spfn, epfn, (epfn - spfn) / page_len);
}

static void buddy_report_lists_detail(struct lwk_pm_buddy_allocator *pma_buddy)
{
	int nid, order;
	struct node_memory *node_mem;
	unsigned long id = pma_buddy->id;

	/* Display buddy list if verbose is set */
	pr_report(id, "Buddy free lists:\n");
	for_each_node_mask(nid, pma_buddy->nodes_mask) {
		node_mem = get_node_memory(pma_buddy, nid);
		if (!node_mem) {
			LWKMEM_ERROR("No node mem structure for nid %3d", nid);
			continue;
		}

		pr_report(id, "Node%3d:\n", nid);
		pr_report(id, "%9s| %5s | %13s | %13s | %13s |\n", "",
			  "Order", "Start pfn", "End pfn", "Page(s)");
		for_each_order_reverse(order)
			buddy_report_buddylist(node_mem->mem, id, order);
	}
}

static void buddy_report_lists_summary(struct lwk_pm_buddy_allocator *pma_buddy)
{
	char *line;
	int i, nid, size, rc, order;
	char str[PMA_REPORT_LIBSTRSZ];
	struct node_memory *node_mem;
	unsigned long nr_free, flags;

	line = kzalloc(PMA_REPORT_MAXLINESZ, GFP_KERNEL);
	if (!line)
		goto out;

	/* Display per order buddy list usage across NUMA nodes */
	pr_report(pma_buddy->id, "Buddy list summary:\n");

	snprintf_init(i, size);
	rc = snprintf(line, size, "Order ");
	if (snprintf_error(rc, size))
		goto out;

	for_each_node_mask(nid, pma_buddy->nodes_mask) {
		snprintf_inc(i, size, rc);
		rc = snprintf(line+i, size, "%10s%3d ", "Node", nid);
		if (snprintf_error(rc, size))
			goto out;
	}
	pr_report(pma_buddy->id, "%s\n", line);

	for_each_order_reverse(order) {
		snprintf_init(i, size);
		rc = snprintf(line, size, "%5d ", order);
		if (snprintf_error(rc, size))
			goto out;

		for_each_node_mask(nid, pma_buddy->nodes_mask) {
			node_mem = get_node_memory(pma_buddy, nid);
			if (!node_mem)
				continue;
			spin_lock_irqsave(&node_mem->lock, flags);
			nr_free = in_base_pages(node_mem->mem[order].nr_free,
						order);
			spin_unlock_irqrestore(&node_mem->lock, flags);
			human_readable_format(str, nr_free);

			snprintf_inc(i, size, rc);
			rc = snprintf(line+i, size, "%13s ", str);
			if (snprintf_error(rc, size))
				goto out;
		}
		pr_report(pma_buddy->id, "%s\n", line);
	}
out:
	kfree(line);
}

static void buddy_report_pma_cache(struct lwk_pm_buddy_allocator *pma_buddy)
{
	char *line = NULL;
	bool print_header;
	int i, j, nid, size, rc;
	struct node_memory *node_mem;
	struct node_numa_stats *stats = NULL;
	unsigned long flags;

	line = kzalloc(PMA_REPORT_MAXLINESZ, GFP_KERNEL);
	if (!line)
		goto out;
	stats = kzalloc(sizeof(struct node_numa_stats), GFP_KERNEL);
	if (!stats)
		goto out;

	/* Display per node PMA cache counters */
	print_header = true;
	pr_report(pma_buddy->id, "PMA cache summary:\n");
	for_each_node_mask(nid, pma_buddy->nodes_mask) {
		node_mem = get_node_memory(pma_buddy, nid);
		if (!node_mem) {
			LWKMEM_ERROR("No node mem structure for nid %3d", nid);
			continue;
		}

		if (!node_mem->stats)
			continue;

		/* Snapshot per node statistics under lock. */
		spin_lock_irqsave(&node_mem->lock, flags);
		for_each_lwkpage_type(j) {
			stats->nr_cache_hit[j] =
				node_mem->stats->nr_cache_hit[j];
			stats->nr_cache_miss[j] =
				node_mem->stats->nr_cache_miss[j];
		}
		spin_unlock_irqrestore(&node_mem->lock, flags);

		/* Print header once at first */
		if (print_header) {
			snprintf_init(i, size);
			rc = snprintf(line, size, "Node");
			if (snprintf_error(rc, size))
				goto out;

			for_each_lwkpage_type(j) {
				snprintf_inc(i, size, rc);
				rc = snprintf(line+i, size,
					" %12s[%2s] %12s[%2s]",
					"Hit",
					lwkpage_desc(j),
					"Miss",
					lwkpage_desc(j));
				if (snprintf_error(rc, size))
					goto out;
			}
			pr_report(pma_buddy->id, "%s\n", line);
			print_header = false;
		}

		/* Print values per NUMA node */
		snprintf_init(i, size);
		rc = snprintf(line, size, "%4d", nid);
		if (snprintf_error(rc, size))
			goto out;

		for_each_lwkpage_type(j) {
			snprintf_inc(i, size, rc);
			rc = snprintf(line+i, size, " %16lu %16lu",
				      stats->nr_cache_hit[j],
				      stats->nr_cache_miss[j]);
			if (snprintf_error(rc, size))
				goto out;
		}
		pr_report(pma_buddy->id, "%s\n", line);
	}
out:
	kfree(stats);
	kfree(line);
}

static void buddy_report_memory_usage(struct lwk_pm_buddy_allocator *pma_buddy)
{
	char *line;
	bool print_header;
	int i, j, nid, size, rc;
	char str[PMA_REPORT_LIBSTRSZ];
	struct node_memory *node_mem;
	struct node_numa_stats *stats = NULL;
	unsigned long nr_total, nr_free, flags;

	line = kzalloc(PMA_REPORT_MAXLINESZ, GFP_KERNEL);
	if (!line)
		goto out;

	/* Display per node summary */
	print_header = true;
	pr_report(pma_buddy->id, "Memory usage summary:\n");
	for_each_node_mask(nid, pma_buddy->nodes_mask) {
		node_mem = get_node_memory(pma_buddy, nid);
		if (!node_mem) {
			LWKMEM_ERROR("No node mem structure for nid %3d", nid);
			continue;
		}

		if (node_mem->stats && !stats) {
			stats = kzalloc(sizeof(struct node_numa_stats),
					GFP_KERNEL);
			if (!stats)
				goto out;
		}

		/* Snapshot per node statistics under lock. */
		spin_lock_irqsave(&node_mem->lock, flags);
		nr_total = node_mem->nr_total;
		nr_free  = node_mem->nr_free;
		if (node_mem->stats) {
			stats->nr_alloc_max_mem =
				node_mem->stats->nr_alloc_max_mem;
			for_each_lwkpage_type(j) {
				stats->nr_allocs[j] =
					node_mem->stats->nr_allocs[j];
				stats->nr_alloc_max[j] =
					node_mem->stats->nr_alloc_max[j];
			}
		}
		spin_unlock_irqrestore(&node_mem->lock, flags);

		/* Print header once at first */
		if (print_header) {
			snprintf_init(i, size);
			rc = snprintf(line, size, "Node %12s %12s",
				      "Total", "Free");
			if (snprintf_error(rc, size))
				goto out;
			if (node_mem->stats) {
				snprintf_inc(i, size, rc);
				rc = snprintf(line+i, size, " %12s",
					      "AllocMax");
				if (snprintf_error(rc, size))
					goto out;

				for_each_lwkpage_type(j) {
					snprintf_inc(i, size, rc);
					rc = snprintf(line+i, size,
						" %12s[%2s] %12s[%2s]",
						"Allocs",
						lwkpage_desc(j),
						"AllocsMax",
						lwkpage_desc(j));
					if (snprintf_error(rc, size))
						goto out;
				}
			}
			pr_report(pma_buddy->id, "%s\n", line);
			print_header = false;
		}

		/* Print node total */
		human_readable_format(str, nr_total);
		snprintf_init(i, size);
		rc = snprintf(line, size, "%4d %12s", nid, str);
		if (snprintf_error(rc, size))
			goto out;

		/* Print node free */
		human_readable_format(str, nr_free);
		snprintf_inc(i, size, rc);
		rc = snprintf(line+i, size, " %12s", str);
		if (snprintf_error(rc, size))
			goto out;

		if (node_mem->stats) {
			/* Print NUMA node statistics if enabled */
			human_readable_format(str, stats->nr_alloc_max_mem);
			snprintf_inc(i, size, rc);
			rc = snprintf(line+i, size, " %12s", str);
			if (snprintf_error(rc, size))
				goto out;

			for_each_lwkpage_type(j) {
				snprintf_inc(i, size, rc);
				rc = snprintf(line+i, size, " %16lu %16lu",
					      stats->nr_allocs[j],
					      stats->nr_alloc_max[j]);
				if (snprintf_error(rc, size))
					goto out;
			}
		}
		pr_report(pma_buddy->id, "%s\n", line);
	}
out:
	kfree(stats);
	kfree(line);
}

static void buddy_report(void *pma, int verbose)
{
	int i;
	unsigned long id;
	struct lwk_pm_buddy_allocator *pma_buddy = pma;

	void (*reporter[])(struct lwk_pm_buddy_allocator *) = {
		buddy_report_memory_usage,
		buddy_report_pma_cache,
		buddy_report_lists_summary,
		buddy_report_lists_detail
	};

	if (check_pma(pma_buddy, PMA_ACTIVE))
		return;

	id = pma_buddy->id;
	pr_report(id, "LWK memory report:\n");
	if (pma_buddy->nr_nodes == 0) {
		pr_report(id, "No NUMA nodes being managed, Node list[%*pbl]\n",
			  nodemask_pr_args(&pma_buddy->nodes_mask));
		return;
	}

	verbose = min_t(int, verbose, ARRAY_SIZE(reporter));
	for (i = 0; i < verbose; i++)
		reporter[i](pma_buddy);
}

static void buddy_meminfo(void *pma, int nid, struct lwk_pma_meminfo *info)
{
	int n;
	unsigned long flags;
	struct lwk_pma_meminfo mi = {0};
	struct node_memory *node_mem;
	struct lwk_pm_buddy_allocator *pma_buddy = pma;

	if (!info)
		return;

	memset(info, 0, sizeof(struct lwk_pma_meminfo));
	if (check_pma(pma_buddy, PMA_ACTIVE))
		return;

	for_each_node_mask(n, pma_buddy->nodes_mask) {
		if (nid != NUMA_NO_NODE && n != nid)
			continue;
		node_mem = get_node_memory(pma_buddy, n);
		if (!node_mem) {
			LWKMEM_ERROR("%s: node_memory[%d]=NULL, R[%*pbl]",
				__func__, nid,
				nodemask_pr_args(&pma_buddy->nodes_mask));
			return;
		}
		spin_lock_irqsave(&node_mem->lock, flags);
		mi.total_pages += node_mem->nr_total;
		mi.free_pages += node_mem->nr_free;
		spin_unlock_irqrestore(&node_mem->lock, flags);
		if (nid != NUMA_NO_NODE)
			break;
	}
	*info = mi;
}

static int buddy_setup_node(struct lwk_pm_buddy_allocator *pma_buddy, int nid,
			    struct list_head *list_phymem,
			    unsigned long (*cache_limits)[LWK_MAX_NUMPGTYPES],
			    bool enable_report)
{
	int rc, order;
	enum lwk_page_type pt;
	struct lwkmem_granule *curr;
	unsigned long pfn, spfn, epfn;
	unsigned long nr_total, n_pages;
	struct node_memory *node_mem;
	struct node_numa_stats *stats = NULL;

	/* Reset pointer */
	pma_buddy->node_mem[pma_buddy->nr_nodes] = NULL;
	/*
	 * Allocate per NUMA node free memory tracking structure
	 * and initialize it with process reserved memory obtained
	 * on the given NUMA node id @nid.
	 */
	node_mem = kzalloc(sizeof(struct node_memory), GFP_KERNEL);
	if (!node_mem)
		return -ENOMEM;
	if (enable_report) {
		stats = kzalloc(sizeof(struct node_numa_stats), GFP_KERNEL);
		if (!stats) {
			rc = -ENOMEM;
			goto out;
		}
	}

	spin_lock_init(&node_mem->lock);
	node_mem->nid = nid;
	for_each_order(order)
		INIT_LIST_HEAD(&node_mem->mem[order].list);
	for_each_lwkpage_type(pt)
		INIT_LIST_HEAD(&node_mem->cache[pt].list);

	/* Total freed pages in terms of base page size */
	nr_total = 0;
	list_for_each_entry(curr, list_phymem, list_reserved) {
		spfn = kaddr_to_pfn(curr->base);
		epfn = spfn + bytes_to_pages(curr->length);
		trace_mos_buddy_setup(nid, spfn, epfn);

		set_lwk_mm_id(spfn, epfn, pma_buddy->id);
		while (spfn < epfn) {
			/* Find the highest order at which pfn is aligned */
			for_each_order_reverse(order) {
				if (pfn_aligned(order, spfn))
					break;
			}
			/*
			 * Now search for the highest order at which atleast
			 * a single page can be freed within the working range
			 * [spfn, epfn)
			 */
			while (order && next_pfn(order, spfn) > epfn)
				order--;
			/*
			 * Compute the number of pages we can release
			 * to the buddy list at this order from spfn
			 */
			pfn = next_pfn(order, spfn);
			pfn = round_up(pfn, base_pages_per_unit(order + 1));
			if (pfn >= epfn || order == LWK_MAX_ORDER) {
				/*
				 * We have no more higher order pages in the
				 * range [spfn, epfn). There could be lower
				 * order pages based on epfn alignment
				 */
				n_pages = base_pages_per_unit(order);
				/*
				 * This rounding will not underflow as we have
				 * already checked if there is atleast 1 page
				 * at this order that we can free within range
				 */
				n_pages = round_down(epfn, n_pages) - spfn;
				n_pages = in_horder_pages(n_pages, 0, order);
			} else
				n_pages = in_horder_pages(pfn - spfn, 0, order);

			/* Free page(s) to the buddy list at this order */
			free_lwkpages_node(node_mem, pma_buddy->id, spfn,
					   n_pages, order);

			/* Convert in terms of base page size */
			n_pages = in_base_pages(n_pages, order);
			nr_total += n_pages;
			spfn += n_pages;
		}
	}
	/*
	 * If either the given list is empty or has zero reserved memory
	 * then we return -EINVAL.
	 */
	rc = nr_total ? 0 : -EINVAL;
out:
	/* If success commit this per node structure */
	if (!rc) {
		node_mem->nr_total = nr_total;
		node_mem->nr_free = nr_total;
		node_mem->stats = stats;
		pma_buddy->node_mem[pma_buddy->nr_nodes] = node_mem;

		if (cache_limits) {
			/* Keep the caches hot */
			for_each_lwkpage_type_reverse(pt) {
				/*
				 * We intentionally delay this step to set the
				 * maximum cache sizes to ensure that the pages
				 * freed during the setup phase above bypasses
				 * the caches as by default the maximum size is
				 * set to zero during kzalloc of the structure.
				 *
				 * This ensures optimal refill as we go from the
				 * highest page size to the smallest page size.
				 */
				node_mem->cache_max_size[pt] =
						   (*cache_limits)[pt];
				buddy_cache_refill(node_mem, pma_buddy->id,
						   pt, false);
			}
		}
	} else {
		kfree(stats);
		kfree(node_mem);
	}
	return rc;
}

static int buddy_setup(void *pma, struct list_head (*list_phymem)[MAX_NUMNODES],
		       unsigned long (*cache_limits)[LWK_MAX_NUMPGTYPES],
		       unsigned long id, bool enable_report)
{
	int nid, rc = -EINVAL;
	unsigned long n = 0;
	struct list_head *head;
	struct lwk_pm_buddy_allocator *pma_buddy = pma;

	if (check_pma(pma_buddy, !PMA_ACTIVE))
		goto out;

	/* Copy LWK mm id of the memory manager this PMA is bound to */
	pma_buddy->id = id;
	nodes_clear(pma_buddy->nodes_mask);
	for (nid = 0; nid < MAX_NUMNODES; nid++) {
		head = &(*list_phymem)[nid];
		if (list_empty(head))
			continue;
		node_set(nid, pma_buddy->nodes_mask);
		n++;
	}

	if (n == 0)
		goto out;

	pma_buddy->node_mem = kcalloc(n, sizeof(struct node_memory *),
				      GFP_KERNEL);
	if (!pma_buddy->node_mem) {
		nodes_clear(pma_buddy->nodes_mask);
		rc = -ENOMEM;
		goto out;
	}

	pma_buddy->nr_nodes = 0;
	for_each_node_mask(nid, pma_buddy->nodes_mask) {
		head = &(*list_phymem)[nid];
		rc = buddy_setup_node(pma_buddy, nid, head, cache_limits,
				      enable_report);
		if (rc) {
			LWKMEM_ERROR("%s: Err on node %d, rc = %d",
					__func__, nid, rc);
			/* Clear nodes from nodemask that we did not setup */
			for (; nid < MAX_NUMNODES; nid++)
				node_clear(nid, pma_buddy->nodes_mask);
			goto out;
		}
		pma_buddy->nr_nodes++;
	}
	/* initialize random number generator support */
	wait_for_random_bytes();

	pma_buddy->active = true;
	rc = 0;
	/* Test PMA at process startup only if debug is enabled */
	test_buddy_pma(pma);
out:
	return rc;
}

static struct lwk_pm_operations pma_buddy_ops = {
	.alloc_pages = buddy_alloc_pages,
	.free_pages = buddy_free_pages,
	.split_page = buddy_split_page,
	.report = buddy_report,
	.meminfo = buddy_meminfo,
	.setup = buddy_setup
};

/*
 * Buddy PMA's Factory operations,
 *   These operations are registered with the LWK mm core during the kernel
 *   boot up. Eventually LWK mm core will use these operations to create or
 *   destroy a per process instance of the allocator.
 */
static void *alloc_pma_buddy(void)
{
	struct lwk_pm_buddy_allocator *pma_buddy;

	pma_buddy = kzalloc(sizeof(struct lwk_pm_buddy_allocator), GFP_KERNEL);
	if (!pma_buddy) {
		LWKMEM_ERROR("%s: No free memory to allocate PMA buddy",
				__func__);
		return pma_buddy;
	}
	pma_buddy->active = false;
	pma_buddy->nr_nodes = 0;
	pma_buddy->node_mem = NULL;
	nodes_clear(pma_buddy->nodes_mask);
	return pma_buddy;
}

static void free_pma_buddy(void *pma)
{
	struct lwk_pm_buddy_allocator *pma_buddy = pma;
	struct node_memory *node_mem;
	unsigned long flags;
	int i, order;

	/* De-initialize active state of the allocator */
	if (pma_buddy) {
		for (i = 0; i < pma_buddy->nr_nodes; i++) {
			node_mem = pma_buddy->node_mem[i];

			spin_lock_irqsave(&node_mem->lock, flags);
			for_each_order(order)
				remove_all_from_buddylist(node_mem->mem, order);
			kfree(node_mem->stats);
			spin_unlock_irqrestore(&node_mem->lock, flags);

			pma_buddy->node_mem[i] = NULL;
			kfree(node_mem);
		}
		/* Free node memory array itself */
		kfree(pma_buddy->node_mem);
	}
	/* Release inactive state of the allocator */
	kfree(pma_buddy);
}

static struct lwk_pm_factory_operations pma_buddy_factory_ops = {
	.alloc_pma = alloc_pma_buddy,
	.free_pma = free_pma_buddy
};

/*
 * LWK Buddy allocator early initializations. Gets invoked during kernel bootup
 * and registers the factory operations and physical memory operations with LWK
 * mm core.
 */
static int __init pma_buddy_init(void)
{
	int rc = register_lwk_pma(LWK_BUDDY_ALLOCATOR, &pma_buddy_factory_ops,
				  &pma_buddy_ops);
	if (rc)
		pr_err("Failed to register LWK PMA factory operations\n");
	return rc;
}
subsys_initcall(pma_buddy_init)

#ifdef TEST_BUDDY_PMA
/*
 * Buddy allocator testing at kernel level. Used for debugging.
 */
static void test_buddy_pma_contig(struct lwk_pm_buddy_allocator *pma_buddy,
				  int nid, unsigned long total,
				  enum lwk_page_type page_type)
{
	int rc, order;
	unsigned long requested, allocated, spfn, count;
	struct list_head list;
	struct page *page, *page_next;
	struct lwk_pm_operations *ops = &pma_buddy_ops;

	pr_test("\n");
	pr_test("Testing contiguous allocations: NID%3d type %s sz(4k) %lu\n",
		nid, lwkpage_desc(page_type), total);

	pr_test("Report before allocation:\n");
	ops->report(pma_buddy, 3);
	/*
	 * Allocate contiguous memory of @page_type, retry with smaller sizes
	 * by reducing the request by a page of @page_type when allocation
	 * fails. Note: @total is in terms of 4k pages.
	 */
	rc = -1;
	order = lwkpage_order(page_type);
	requested = in_horder_pages(total, 0, order);
	allocated = 9999999;

	INIT_LIST_HEAD(&list);
	if (requested) {
		rc = ops->alloc_pages(pma_buddy, nid, requested, page_type,
				      PMA_ALLOC_CONTIG, &list, &allocated);
		pr_test("requested %ld allocated %ld rc=%d\n",
			requested, allocated, rc);
		if (rc) {
			if (allocated != 0)
				pr_test("ERR alloc counter %lu when rc=%d\n",
					allocated, rc);
			if (!list_empty(&list))
				pr_test("ERR non-empty list and rc=%d\n", rc);
		} else {
			count = 0;
			list_for_each_entry(page, &list, lru)
				count++;
			if (count != 1)
				pr_test("ERR list size %lu (>1) when rc=0\n",
					count);
		}
	}

	/* Free allocated contiguous memory */
	if (!list_empty(&list)) {
		pr_test("Report after allocation:\n");
		ops->report(pma_buddy, 3);

		page = list_first_entry(&list, struct page, lru);
		list_del(&page->lru);
		spfn = page_to_pfn(page);
		pr_test("freeing %lu\n", allocated);
		if (allocated > requested) {
			pr_test("ERR: allocated %lu > requested %lu\n",
				allocated, requested);
			return;
		}
		rc = ops->free_pages(pma_buddy, page_type, spfn, allocated,
				     NULL);
		if (rc)
			pr_test("ERR freeing [%lu, %lu) rc=%d\n", spfn,
				spfn + in_base_pages(allocated, order), rc);

		/*
		 * In case list had more than one page which is an
		 * unexpected error delete additional pages from list.
		 */
		list_for_each_entry_safe(page, page_next, &list, lru) {
			list_del(&page->lru);
			spfn = page_to_pfn(page);
			pr_test("ERR extra in list: [%lu, %lu)\n", spfn,
				spfn + in_base_pages(1, order));
		}
		pr_test("Report after free:\n");
		ops->report(pma_buddy, 3);
	}
}

static void test_buddy_pma_normal(struct lwk_pm_buddy_allocator *pma_buddy,
				  int nid, unsigned long total,
				  enum lwk_page_type max)
{
	int rc = 0;
	enum lwk_page_type t;
	unsigned long needed, requested, allocated, order;
	struct list_head list[LWK_MAX_NUMPGTYPES];
	struct lwk_pm_operations *ops = &pma_buddy_ops;

	pr_test("\n");
	pr_test("Testing normal allocations: NID%3d type(max) %s sz(4k) %lu\n",
		nid, lwkpage_desc(max), total);
	pr_test("Report before allocation:\n");
	ops->report(pma_buddy, 3);

	/* Allocate memory at various page sizes */
	needed = total;
	for_each_lwkpage_type_reverse(t) {
		if (t > max)
			continue;
		INIT_LIST_HEAD(&list[t]);
		order = lwkpage_order(t);
		requested = in_horder_pages(needed, 0, order);
		if (requested == 0)
			continue;
		allocated = 99999;
		rc = ops->alloc_pages(pma_buddy, nid, requested, t,
				      PMA_ALLOC_NORMAL, &list[t], &allocated);
		pr_test("%2s pages: requested %ld allocated %ld rc=%d\n",
			  lwkpage_desc(t), requested, allocated, rc);
		if (rc && allocated) {
			pr_test("ERR: allocated = %lu when rc %d\n",
				allocated, rc);
		}
		needed -= in_base_pages(allocated, order);
	}
	pr_test("Total: requested %ld allocated %ld\n", total, total - needed);

	pr_test("Report after allocation:\n");
	ops->report(pma_buddy, 3);
	/* Free allocated memory */
	for_each_lwkpage_type_reverse(t) {
		if (t > max)
			continue;
		if (list_empty(&list[t]))
			continue;
		pr_test("Freeing %2s pages\n", lwkpage_desc(t));
		rc = ops->free_pages(pma_buddy, t, 0, 0, &list[t]);
		if (rc) {
			pr_test("ERR: Failed to free %2s pages\n",
				  lwkpage_desc(t));
		}
		if (!rc && !list_empty(&list[t]))
			pr_test("ERR: Not all pages released\n");
	}
	pr_test("Report after free:\n");
	ops->report(pma_buddy, 3);
	pr_test("Testing normal allocations: done\n");
}

static void test_buddy_pma_random(struct lwk_pm_buddy_allocator *pma_buddy,
				  int nid, unsigned long total,
				  enum lwk_page_type max)
{
	int rc = 0;
	enum lwk_page_type t;
	unsigned long needed, requested, allocated, order, total_requested;
	struct list_head list[LWK_MAX_NUMPGTYPES];
	struct lwk_pm_operations *ops = &pma_buddy_ops;
	unsigned long cache_max_size;
	struct node_memory *node_mem;
	struct page *page, *page_next;
	int column_count;

	pr_test("\n");
	pr_test("Testing random allocations: NID%3d type(max) %s sz(4k) %lu\n",
		nid, lwkpage_desc(max), total);
	pr_test("Report before allocation:\n");
	ops->report(pma_buddy, 3);
	node_mem = get_node_memory(pma_buddy, nid);

	/* Allocate memory at various page sizes */
	needed = total;
	total_requested = 0;
	for_each_lwkpage_type_reverse(t) {
		if (t >= max)
			continue;
		INIT_LIST_HEAD(&list[t]);
		order = lwkpage_order(t);
		cache_max_size = node_mem->cache_max_size[t];
		requested = in_horder_pages(needed, 0, order);
		requested = min(requested, cache_max_size);
		total_requested += requested;
		if (requested == 0)
			continue;
		allocated = 99999;
		rc = ops->alloc_pages(pma_buddy, nid, requested, t,
				      PMA_ALLOC_RANDOM, &list[t], &allocated);
		pr_test("%2s pages: requested %ld allocated %ld rc=%d\n",
			  lwkpage_desc(t), requested, allocated, rc);
		if (rc && allocated)
			pr_test("ERR: allocated = %lu when rc %d\n",
				allocated, rc);
		/* Dump pfn allocation sequence to inspect randomness */
		pr_test("Actual allocation sequence follows (should see randomness):");
		column_count = 0;
		list_for_each_entry_safe(page, page_next, &list[t], lru) {
			if ((column_count++ % 16) == 0)
				printk("%08lu  ", page_to_pfn(page));
			else
				printk(KERN_CONT "%08lu  ", page_to_pfn(page));
		}
		needed -= in_base_pages(allocated, order);
	}
	pr_test("Total: requested %ld allocated %ld\n", total_requested, total - needed);

	pr_test("Report after allocation:\n");
	ops->report(pma_buddy, 3);
	/* Free allocated memory */
	for_each_lwkpage_type_reverse(t) {
		if (t >= max)
			continue;
		if (list_empty(&list[t]))
			continue;
		pr_test("Freeing %2s pages\n", lwkpage_desc(t));
		rc = ops->free_pages(pma_buddy, t, 0, 0, &list[t]);
		if (rc) {
			pr_test("ERR: Failed to free %2s pages\n",
				  lwkpage_desc(t));
		}
		if (!rc && !list_empty(&list[t]))
			pr_test("ERR: Not all pages released\n");
	}
	pr_test("Report after free:\n");
	ops->report(pma_buddy, 3);
	pr_test("Testing random allocations: done\n");
}

/*
 * Debug/test buddy allocator interface operations.
 */
static void test_buddy_pma(struct lwk_pm_buddy_allocator *pma_buddy)
{
	int nid;
	enum lwk_page_type t;
	struct node_memory *nm;
	struct lwk_pma_meminfo info;
	struct lwk_pm_operations *ops = &pma_buddy_ops;
	struct list_head head;
	char str[PMA_REPORT_LIBSTRSZ];

	pr_test("Testing buddy allocator:\n");
	if (!pma_buddy) {
		pr_test(">>ERR: pma_buddy is NULL\n");
		goto out;
	}
	pr_test("State:\n");
	pr_test("\tActive: %s\n", pma_buddy->active ? "yes" : "no");
	pr_test("\tNodes: %*pbl [%3ld]\n",
		  nodemask_pr_args(&pma_buddy->nodes_mask),
		  pma_buddy->nr_nodes);
	pr_test("\tnode_mem: %p\n", pma_buddy->node_mem);

	if (!pma_buddy->active)
		goto out;
	if (!pma_buddy->node_mem || pma_buddy->nr_nodes == 0 ||
	    pma_buddy->nr_nodes != nodes_weight(pma_buddy->nodes_mask))
		goto out;
	INIT_LIST_HEAD(&head);
	for_each_node_mask(nid, pma_buddy->nodes_mask) {
		pr_test("Node%3d:\n", nid);
		nm = get_node_memory(pma_buddy, nid);
		if (!nm) {
			pr_test("ERR: Node%3d node memory is NULL\n", nid);
			continue;
		}
		ops->meminfo(pma_buddy, nid, &info);
		human_readable_format(str, info.total_pages);
		pr_test("\tTotal: %s\n", str);
		human_readable_format(str, info.free_pages);
		pr_test("\tFree : %s\n", str);
		if (info.total_pages == 0) {
			pr_test("ERR: no memory\n");
			continue;
		}
		/* Test normal allocation requests */
		for_each_lwkpage_type_reverse(t) {
			test_buddy_pma_normal(pma_buddy, nid,
					      info.total_pages, t);
		}
		/* Test contig allocation requests */
		for_each_lwkpage_type_reverse(t) {
			test_buddy_pma_contig(pma_buddy, nid,
					      info.total_pages, t);
		}
		/* Test random allocation requests */
		for_each_lwkpage_type_reverse(t) {
			test_buddy_pma_random(pma_buddy, nid,
					      info.total_pages, t);
		}
	}
out:
	pr_test("End of buddy allocator test");
}
#endif
