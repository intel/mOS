/*
 * Multi Operating System (mOS)
 * Copyright (c) 2020 Intel Corporation.
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

#include <linux/mos.h>
#include <trace/events/lwkmem.h>

/* Private headers */
#include "lwk_mm_private.h"

enum lwk_vmr_type lwk_mm_vmflags_to_vmr(unsigned long vm_flags)
{
	if ((vm_flags & VM_LWK) == 0)
		return LWK_MAX_NUMVMRTYPES;

	if (vm_flags & VM_LWK_DBSS)
		return LWK_VMR_DBSS;
	else if (vm_flags & VM_LWK_HEAP)
		return LWK_VMR_HEAP;
	else if (vm_flags & VM_LWK_ANON_PRIVATE)
		return LWK_VMR_ANON_PRIVATE;
	else if (vm_flags & VM_LWK_TSTACK)
		return LWK_VMR_TSTACK;
	else if (vm_flags & VM_LWK_STACK)
		return LWK_VMR_STACK;
	else
		return LWK_MAX_NUMVMRTYPES;
}

bool is_lwkmem_nofault(unsigned long vm_flags)
{
	struct lwk_mm *lwk_mm;
	enum lwk_vmr_type vmr;

	if ((vm_flags & VM_LWK) == 0)
		return false;
	if (!is_lwkmem_enabled(current))
		return false;

	lwk_mm = curr_lwk_mm();
	vmr = lwk_mm_vmflags_to_vmr(vm_flags);
	if (vmr == LWK_MAX_NUMVMRTYPES) {
		LWKMEM_ERROR("No valid VMR indicated by vm_flags=%lx",
			     vm_flags);
		dump_stack();
		return false;
	}

	return lwk_mm->policy[vmr].pagefault_level == LWK_PF_NOFAULT;
}

/*
 * Retrieves the pre-set memory policy for the virtual memory region that @vma
 * belongs to.
 */
static struct lwk_mempolicy *lwk_mm_get_mempolicy(struct vm_area_struct *vma)
{
	struct lwk_mm *lwk_mm = vma_lwk_mm(vma);
	enum lwk_vmr_type vmr;

	if (!vma || !is_lwkvma(vma)) {
		LWKMEM_ERROR("vma is %s", !vma ? "invalid" : "not LWK VMA");
		return NULL;
	}

	if (!lwk_mm || !lwk_mm->active) {
		LWKMEM_ERROR("lwk mm is %s", !lwk_mm ? "invalid" : "inactive");
		return NULL;
	}

	if (!lwk_mm->policy_set) {
		LWKMEM_ERROR("lwk memory policy is not yet setup!");
		return NULL;
	}

	if (!lwk_mm->policy_nlists) {
		LWKMEM_ERROR("Invalid memory policy configuration");
		return NULL;
	}

	/* Find the memory policy to be used for this LWK VMA */
	vmr = lwk_mm_vmflags_to_vmr(vma->vm_flags);
	if (vmr == LWK_MAX_NUMVMRTYPES) {
		LWKMEM_ERROR("VMA of unknown LWK region vm_flags=%lx",
			     vma->vm_flags);
		dump_stack();
		return NULL;
	}

	return &lwk_mm->policy[vmr];
}

/*
 * Finds the maximum page size that can be used for the given range
 * [@start, @end) under the max page size limit of @max_limit
 */
static enum lwk_page_type find_max_lwk_page(unsigned long start,
				unsigned long end, enum lwk_page_type max_limit)
{
	enum lwk_page_type t;
	unsigned long aligned_start;
	unsigned long aligned_end;

	for_each_lwkpage_type_reverse_from(t, max_limit) {
		aligned_start = ALIGN(start, lwkpage_size(t));
		aligned_end = ALIGN_DOWN(end, lwkpage_size(t));

		if (aligned_start < aligned_end &&
		    aligned_start >= start &&
		    aligned_end <= end)
			return t;
	}
	return LWK_PG_4K;
}

/*
 * Helper functions to dump memory policy and related node lists.
 * Used for debugging purpose.
 */
static void dump_lwk_mempolicy_list(struct lwk_mempolicy_nodelists *nodelist,
				    unsigned long nlists)
{
	int i, j, rc, size = PAGE_SIZE;
	char *line;

	if (!nodelist || !nlists)
		return;

	line = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!line)
		return;

	for (i = 0; i < nlists; i++) {
		rc = snprintf(line, size, "Nodelist[%3d] [Total : %3lu] : ",
			      i, nodelist[i].num_nodes);
		for (j = 0; j < nodelist[i].num_nodes; j++) {
			rc += snprintf(line+rc, size-rc, "%s%3d", j ? "," : "",
				       nodelist[i].nodes[j]);
		}
		pr_info("%s\n", line);
	}
	kfree(line);
}

void dump_lwk_mempolicy_vmr(struct lwk_mm *lwk_mm, enum lwk_vmr_type vmr)
{
	struct lwk_mempolicy *policy;
	unsigned long nlists;
	bool nofault;

	if (!lwk_mm) {
		LWKMEM_WARN("Invalid lwk_mm");
		return;
	}

	if (!lwk_mm->policy_set) {
		LWKMEM_WARN("No policy set for the process");
		return;
	}

	if (vmr >= LWK_MAX_NUMVMRTYPES) {
		LWKMEM_WARN("Unknown VMR type for LWK vma");
		return;
	}

	policy = &lwk_mm->policy[vmr];
	nlists = lwk_mm->policy_nlists;
	nofault = policy->pagefault_level == LWK_PF_NOFAULT;

	pr_info("Mempolicy info VMR[ %s ]\n", lwk_vmrs_name[vmr]);
	pr_info("Threshold  : %lu\n", policy->threshold);
	pr_info("Max page   : %s\n",  lwkpage_desc(policy->max_page));
	pr_info("Pagefaults : %s\n", nofault ? "nofault" : "onefault");
	pr_info("Enabled    : %s\n", policy->disabled ? "no" : "yes");
	pr_info("No.of lists: %lu\n", nlists);
	pr_info("Node lists (for above threshold):\n");
	dump_lwk_mempolicy_list(policy->above_threshold, nlists);
	pr_info("Node lists (for below threshold):\n");
	dump_lwk_mempolicy_list(policy->below_threshold, nlists);
}

void dump_lwk_mempolicy_vma(struct vm_area_struct *vma)
{
	struct lwk_mm *lwk_mm = vma_lwk_mm(vma);

	if (is_lwkvma(vma)) {
		dump_lwk_mempolicy_vmr(lwk_mm,
			lwk_mm_vmflags_to_vmr(vma->vm_flags));
	}
}

/*
 * Helper function used to map in the process page table the allocated
 * physical pages of type @t in @listp to the given virtual address range
 * [@start, @end).
 *
 * NOTE: Caller needs to ensure @vma, @t are validated
 *       to avoid repeated redundant checking.
 */
static inline int lwk_mm_map_pagetable(struct vm_area_struct *vma,
			unsigned long start, unsigned long end,
			enum lwk_page_type t, struct list_head *listp)
{
	int rc = EINVAL;
	unsigned long npages, allocated;
	struct list_head *pos;

	if (end <= start || !listp || list_empty(listp))
		return rc;

	rc = lwk_mm_map_pages(vma, start, end, t, listp);
	if (!list_empty(listp)) {
		npages = 0;
		list_for_each(pos, listp)
			npages++;
		allocated = bytes_to_pages(end - start) >> lwkpage_order(t);
		LWKMEM_ERROR("%ld/%ld %s pages, not mapped in [%lx, %lx) rc=%d",
			     npages, allocated, lwkpage_desc(t),
			     start, end, rc);
		lwk_mm_unmap_pages(vma, start, end);
		rc = !rc ? -EINVAL : rc;
	}
	return rc;
}

/*
 * NOTE: Caller needs to ensure @vma, @t, @end alignment and pointers
 *       @nodelist, @startp are validated to avoid repeated redundant
 *       checking.
 */
static int lwk_mm_map_nodelist_normal(struct vm_area_struct *vma,
			unsigned long *startp, unsigned long end,
			enum lwk_page_type t,
			struct lwk_mempolicy_nodelists *nodelist,
			enum lwk_pma_alloc_flags pma_alloc_flag)
{
	int i, rc, ret;
	unsigned long needed, allocated;
	unsigned long npages, next;
	struct list_head list, sublist;
	struct lwk_mm *lwk_mm = vma_lwk_mm(vma);
	void *pma = lwk_mm->pma;

	if (*startp >= end || !IS_ALIGNED(*startp, lwkpage_size(t))) {
		LWKMEM_WARN("Invalid: range=[%lx, %lx) maxpg=%s",
			    *startp, end, lwkpage_desc(t));
		return -EINVAL;
	}

	rc = -ENOMEM;
	allocated = 0;
	needed = bytes_to_pages(end - *startp) >> lwkpage_order(t);
	INIT_LIST_HEAD(&list);

	for (i = 0; i < nodelist->num_nodes; i++) {
		if (needed == 0)
			break;

		npages = 0;
		INIT_LIST_HEAD(&sublist);
		rc = lwk_mm->pm_ops->alloc_pages(pma, nodelist->nodes[i],
						 needed, t, pma_alloc_flag,
						 &sublist, &npages);
		if (rc && rc != -ENOMEM)
			goto cleanup;
		if (rc == 0) {
			list_splice_tail(&sublist, &list);
			allocated += npages;
			needed -= npages;
		}
	}

	if (allocated) {
		next = *startp + pages_to_bytes(allocated << lwkpage_order(t));
		rc = lwk_mm_map_pagetable(vma, *startp, next, t, &list);
		if (rc)
			goto cleanup;
		*startp = next;
		/* Return -ENOMEM on partial allocation */
		return next == end ? 0 : -ENOMEM;
	}

cleanup:
	if (!list_empty(&list)) {
		ret = lwk_mm->pm_ops->free_pages(pma, t, 0, 0, &list);
		if (ret) {
			LWKMEM_ERROR("freeing allocated pages on error, rc=%d",
				     ret);
			LWKMEM_ERROR("start=%lx end=%lx pgs=%s",
				     *startp, end, lwkpage_desc(t));
		}
	}
	return rc;
}

/*
 * Interleaving algorithm,
 *
 *   +--------------------------------------> Interleave direction
 *   |
 *   |        nodelists[0].nodes -> +----+----+----+----+----+----+----+
 *   |                              | A0 | A1 |    |  .........   | Ap |
 *   |                              +----+----+----+----+----+----+----+
 *   |
 *   |        nodelists[1].nodes -> +----+----+----+----+----+----+----+
 *   |                              | B0 | B1 |    |  .........   | Bq |
 *   |                              +----+----+----+----+----+----+----+
 *   |                  .
 *   |                  .
 *   |
 *   v        nodelists[N].nodes -> +----+----+----+----+----+----+----+
 * Fallback                         | C0 | C1 |    |  .........   | Cr |
 * direction                        +----+----+----+----+----+----+----+
 *
 * Per VMR nodelists are setup by yod or default values through,
 *   lwk_mm_set_mempolicy_info()
 *
 * nodelists[0] is the highest preferred list and nodelists[N] is the lowest
 * preferred list in the order from 0 to N.
 *
 * For a given range [@start, @end) within @vma and with contstraint of
 * maximum page size usable @tmax, and with a preferred node list @nodelist
 * below steps are followed,
 *
 *   - Interleaving starts at index,
 *       pos = (virtual page offset of @start) % nodelist->num_nodes
 *
 *   - Interleaving proceeds at given page of 't' granularity in a round
 *     robin fashion from low to high index and wraps around,
 *       i.e. for ex: from pos, pos+1, pos+2, ... pos+p, pos0, pos1, .. etc,
 *       for nodelists[0] in the above picture.
 *
 *   - In the first pass when @relax is not set, i.e. interleaving rules are not
 *     relaxed, lwk_mm_map_nodelist_interleaved() returns -ENOMEM if it can not
 *     allocate a page at an index during round robin iterations. It returns
 *     after mapping what has been allocated so far and incrementing @startp.
 *     This gives a chance to the caller to retry,
 *       i.  at the same pos with the next smaller page size till t = LWK_PG_4K
 *           and with the same preferred list of NUMA nodes.
 *       ii. at the next preferred list of NUMA nodes and starting at the max
 *           page limit 't' set to the range by lwk_mm_map_aligned_range().
 *     Notice that the index to restart still depends on @startp where
 *     it was left before indicating the start of yet to map range.
 *
 *   - In the second pass, when @relax is set, i.e interleaving rules are
 *     relaxed, if we can not get a page at an index then we try all NUMA nodes
 *     in the list in round robin and if we do not get a page from any of the
 *     NUMA nodes then lwk_mm_map_nodelist_interleaved() returns -ENOMEM.
 *     Caller then retries,
 *       i.  at the next smaller page size till t = LWK_PG_4K and with the
 *           same preferred list of NUMA nodes.
 *       ii. at the next preferred list list of NUMA nodes and starting at the
 *           max page limit 't' set to the range by lwk_mm_map_aligned_range().
 *
 *   - If interleaving fails even after relaxing rules then -ENOMEM is returned.
 *
 * NOTE: Caller needs to ensure @vma, @t, @end alignment and pointers
 *       @nodelist, @startp are validated to avoid repeated redundant
 *       checking.
 */
static int lwk_mm_map_nodelist_interleaved(struct vm_area_struct *vma,
			unsigned long *startp, unsigned long end,
			enum lwk_page_type t,
			struct lwk_mempolicy_nodelists *nodelist, int relax,
			enum lwk_pma_alloc_flags pma_alloc_flag)
{
	int i, rc, ret;
	unsigned long pgoff;
	unsigned long needed, allocated, npages;
	unsigned long next, tried;
	struct list_head list, sublist;
	struct lwk_mm *lwk_mm = vma_lwk_mm(vma);
	void *pma = lwk_mm->pma;

	if (*startp >= end || !IS_ALIGNED(*startp, lwkpage_size(t))) {
		LWKMEM_WARN("Invalid: range=[%lx, %lx) maxpg=%s",
			    *startp, end, lwkpage_desc(t));
		return -EINVAL;
	}

	rc = 0;
	tried = 0;
	needed = bytes_to_pages(end - *startp) >> lwkpage_order(t);
	allocated = needed;
	INIT_LIST_HEAD(&list);
	/*
	 * Calculate the virtual page offset of the first page and
	 * compute the first NUMA node in the nodelist to start
	 * interleaving from.
	 */
	pgoff = vma->vm_pgoff + bytes_to_pages(*startp - vma->vm_start);
	i = (pgoff >> lwkpage_order(t)) % nodelist->num_nodes;

	/*
	 * In case of -ENOMEM on a node if we are allowed to relax interleaving
	 * rules, then try until we could not find memory in any of the NUMA
	 * domains in the list, and at that stage we flag -ENOMEM. Irrespective
	 * of @relax the function return -ENOMEM on partial or no allocation.
	 */
	while (needed && (rc == 0 || (rc == -ENOMEM && relax))) {
		INIT_LIST_HEAD(&sublist);
		npages = 0;
		/* Allocate a single page */
		rc = lwk_mm->pm_ops->alloc_pages(pma, nodelist->nodes[i],
						 1, t, pma_alloc_flag,
						 &sublist, &npages);
		/* Any fatal error? terminate further processing */
		if (rc && rc != -ENOMEM)
			goto cleanup;
		/* Success! add this to the list of pages to be mapped */
		if (rc == 0) {
			if (unlikely(npages != 1))
				LWKMEM_WARN("Allocated %ld expected 1", npages);
			list_splice_tail(&sublist, &list);
			needed--;
			/* Reset tried NUMA domain counter if relax is set */
			if (relax)
				tried = 0;
		} else if (relax) {
			/* We tried all NUMA domains in the list */
			if (++tried == nodelist->num_nodes)
				break;
		}

		/* Next NUMA domain to interleave */
		i = (i + 1) % nodelist->num_nodes;
	}
	allocated -= needed;

	if (allocated) {
		next = *startp + pages_to_bytes(allocated << lwkpage_order(t));
		ret = lwk_mm_map_pagetable(vma, *startp, next, t, &list);
		/* Increment start if we successfully allcoated and mapped */
		if (ret == 0)
			*startp = next;
		/*
		 * If map succeeded then we return allocation status otherwise
		 * we return map status irrespective of allocation status. This
		 * is because in case of partial allocation we still want to
		 * map what has been allocated but return -ENOMEM to indicate
		 * that the caller did not get everything that was requested.
		 */
		rc = ret == 0 ? rc : ret;
	}

cleanup:
	if (!list_empty(&list)) {
		ret = lwk_mm->pm_ops->free_pages(pma, t, 0, 0, &list);
		if (ret) {
			rc = rc == 0 ? ret : rc;
			LWKMEM_ERROR("freeing allocated pages on error, rc=%d",
				     rc);
			LWKMEM_ERROR("start=%lx end=%lx pgs=%s",
				     *startp, end, lwkpage_desc(t));
		}
	}
	return rc;
}

/*
 * NOTE: Caller needs to ensure @vma, @tmax, and pointers @nodelist, @startp
 *       are validated to avoid repeated redundant checking.
 */
static int lwk_mm_map_try_page_sizes(struct vm_area_struct *vma,
			unsigned long *startp, unsigned long end,
			enum lwk_page_type tmax,
			struct lwk_mempolicy_nodelists *nodelist,
			enum lwk_mempolicy_type policy_type, int relax)
{
	int rc = 0;
	enum lwk_page_type t;
	enum lwk_pma_alloc_flags pma_alloc_flag;

	if (*startp >= end ||
	    !IS_ALIGNED(*startp, lwkpage_size(tmax)) ||
	    !IS_ALIGNED(end, lwkpage_size(tmax)))
		rc = -EINVAL;

	if (*startp + lwkpage_size(tmax) < *startp ||
	    (*startp + lwkpage_size(tmax) > end))
		rc = -EINVAL;

	if (rc == -EINVAL) {
		LWKMEM_WARN("Invalid: range=[%lx, %lx) maxpg=%s",
			    *startp, end, lwkpage_desc(tmax));
		return rc;
	}
	if (policy_type == LWK_MEMPOL_RANDOM ||
	    policy_type == LWK_MEMPOL_INTERLEAVE_RANDOM)
		pma_alloc_flag = PMA_ALLOC_RANDOM;
	else
		pma_alloc_flag = PMA_ALLOC_NORMAL;

	/* If there are not enough higher size pages try smaller page size. */
	for_each_lwkpage_type_reverse_from(t, tmax) {
		if (policy_type == LWK_MEMPOL_NORMAL ||
		    policy_type == LWK_MEMPOL_RANDOM)
			rc = lwk_mm_map_nodelist_normal(vma, startp, end,
							t, nodelist,
							pma_alloc_flag);
		else
			rc = lwk_mm_map_nodelist_interleaved(vma, startp, end,
							t, nodelist, relax,
							pma_alloc_flag);
		/* Return on success or other fatal errors */
		if (rc == 0 || (rc && rc != -ENOMEM))
			return rc;
	}

	/*
	 * The given request could not be completely fulfilled due to
	 * insufficient memory available in @nodelist at all pages of
	 * size <= tmax, even for a partial success we return -ENOMEM
	 * and [start, end) upon return indicates the unallocated range
	 * to the caller. So the decision to either unmap the part of
	 * the range that succeeded and to restart a fresh or to continue
	 * mapping the rest of the range from a different set of NUMA nodes
	 * rests with the caller.
	 */
	return -ENOMEM;
}

/*
 * NOTE:
 *  - Caller needs to ensure @vma, @start, @end, @tmax, @policy_nodelists
 *    are validated to avoid repeated redundant checking.
 */
static int lwk_mm_map_aligned_range(struct vm_area_struct *vma,
			unsigned long start, unsigned long end,
			enum lwk_page_type tmax,
			struct lwk_mempolicy_nodelists *nodelists,
			enum lwk_mempolicy_type policy_type)
{
	int i, rc = 0;
	int relax = 0;
	enum lwk_page_type t;
	unsigned long next;
	struct lwk_mm *lwk_mm = vma_lwk_mm(vma);
	struct lwk_mempolicy_nodelists *nodelist;

	trace_mos_mm_map_aligned_range(start, end, tmax);

	if (!IS_ALIGNED(start, lwkpage_size(tmax)) ||
	    !IS_ALIGNED(end, lwkpage_size(tmax))) {
		LWKMEM_WARN("Unaligned range");
		rc = -EINVAL;
	}

	next = start + lwkpage_size(tmax);
	if (next < start || next > end) {
		LWKMEM_WARN("Overflow");
		rc = -EINVAL;
	}

	if (rc == -EINVAL) {
		LWKMEM_WARN("Invalid: [%lx, %lx) tmax=%s",
			    start, end, lwkpage_desc(tmax));
		return rc;
	}

retry:
	/*
	 * Allocate from NUMA nodes from the preferred nodelists in the
	 * order of their perference as set by mempolicy for the VMR.
	 */
	for (i = 0; i < lwk_mm->policy_nlists && start < end; i++) {
		nodelist = nodelists + i;
		if (!nodelist) {
			LWKMEM_ERROR("Unexpected nodelist pointer");
			return -EINVAL;
		}

		if (!nodelist->num_nodes)
			continue;

		while (start < end) {
			/*
			 * Find the page size to start allocation with, this
			 * takes care of restarting the allocation at the
			 * highest aligned page size that is <= tmax type page
			 * size when not all the requested memory could be
			 * allocated in the previous iteration.
			 */
			for_each_lwkpage_type_reverse_from(t, tmax) {
				if (IS_ALIGNED(start, lwkpage_size(t)) &&
				    (start + lwkpage_size(t) <= end))
					break;
			}

			/*
			 * We have already validated that @end is @tmax aligned
			 * so this alignment of @next can not go beyond @end
			 * since the test ensures @t + 1 <= @tmax.
			 */
			if (t < tmax)
				next = ALIGN(start, lwkpage_size(t + 1));
			else
				next = end;

			/* Try all page sizes @t and below within @nodelist */
			rc = lwk_mm_map_try_page_sizes(vma, &start, next, t,
					nodelist, policy_type, relax);
			/*
			 * Not enough memory of this type? then try
			 * NUMA nodes of next perferred memory.
			 */
			if (rc == -ENOMEM)
				break;
			/* Other fatal errors */
			if (rc)
				goto out;
			/* Unexpected error, avoid looping forever */
			if (start != next) {
				rc = -EINVAL;
				LWKMEM_ERROR("start %llx != next %llx rc=0",
					start, next);
				goto out;
			}
		}
	}

	/*
	 * We tried all nodelists but could not allocate and map the given
	 * range [@start, @end). Caller is expected to unmap this range on
	 * error.
	 */
	if (start != end)
		rc = -ENOMEM;

	/* For interleave policy try relaxing rules before giving up */
	if (rc == -ENOMEM && policy_type == LWK_MEMPOL_INTERLEAVE &&
	    relax == 0) {
		LWKMEM_WARN("Trying with relaxed interleaving rules");
		relax = 1;
		goto retry;
	}
out:
	if (rc) {
		LWKMEM_WARN("rc=%d range=[%#lx, %#lx) pgs=%s",
			    rc, start, next, lwkpage_desc(tmax));
	}
	return rc;
}

/*
 * Allocates physical memory for the range [@start, @end) within @vma and
 * maps the corresponding page table entries for the range.
 *
 * Allocation strategy,
 *
 * lwk_mm_map_range(),
 *   - Pick the nodelists to be used based on the allocation size and the
 *     threshold size set by the memory policy of the virtual memory region(VMR)
 *     corresponding to the given @vma.
 *
 *   - Find the largest page size that can be allocated based on given range
 *     [@start, @end) and the limit set by the memory policy for the VMR.
 *
 *   - Break the given address range into sub-ranges of different max page sizes
 *     possible in the sub-range based on the address alignment and the max page
 *     limit found in the previous step.
 *
 *   - Allocate physical memory and map each of the aligned sub-ranges found
 *     using lwk_mm_map_aligned_range().
 *
 * lwk_mm_map_aligned_range(),
 *   - For every preferred NUMA nodes(or domains) in the order of their
 *     preference as specified by the memory policy for the VMR, allocate pages
 *     for the sub-range within max page size limit of the sub-range using,
 *     lwk_mm_map_try_page_sizes().
 *
 *   - If memory can not be allocated for the entire range in the previous step
 *     and if the memory policy type is interleaving then retry all nodelists
 *     with relaxed interleaving rules for the remaining unallocated range.
 *
 *   - If memory can not be allocated with the above two steps then return
 *     error -ENOMEM.
 *
 * lwk_mm_map_try_page_sizes(),
 *   - Try allocating pages within a given max page size from NUMA nodes within
 *     the given nodelist (normally corresponds to NUMA nodes of a memory type
 *     but not necessarily) based on the memory policy type of the VMR using
 *     either lwk_mm_map_nodelist_normal() or lwk_mm_map_nodelist_interleaved().
 *
 *   - If the request can not be fulfilled at the given page size and in all
 *     NUMA nodes in the given nodelist then re-try with smaller page sizes.
 *
 * lwk_mm_map_nodelist_normal()
 *     Allocate and map pages of a given page size from the set of NUMA nodes
 *     within the given nodelist. i.e. if pages of the given page size is not
 *     available on a NUMA node then try allocating pages of the same page
 *     size from the next NUMA node within the given nodelist. Trial starts
 *     at index 0 in the list and goes up to the last element in the list.
 *
 * lwk_mm_map_nodelist_interleaved()
 *     Allocate pages from the given nodelists in interleaving policy. Refer to
 *     the detailed documentation at function implementation above.
 */

/*
 * NOTE: Caller needs to ensure @vma, @start, @end are validated to avoid
 *       repeated redundant checking
 */
int lwk_mm_map_range(struct vm_area_struct *vma, unsigned long start,
		     unsigned long end)
{
	int rc;
	enum lwk_page_type t, tmax;
	unsigned long lstart, uend;
	unsigned long lstart_prev, uend_prev;
	struct lwk_mempolicy *mempolicy;
	struct lwk_mempolicy_nodelists *policy_nodelists;

	mempolicy = lwk_mm_get_mempolicy(vma);
	if (!mempolicy)
		return -EINVAL;

	if ((end - start) >= mempolicy->threshold)
		policy_nodelists = mempolicy->above_threshold;
	else
		policy_nodelists = mempolicy->below_threshold;

	if (!policy_nodelists) {
		LWKMEM_ERROR("Memory policy nodelists are not setup yet");
		return -EINVAL;
	}

	if (!valid_mempol_type(mempolicy->type)) {
		LWKMEM_WARN("Invalid memory policy type, setting to normal");
		mempolicy->type = LWK_MEMPOL_NORMAL;
	}

	/* Find maximum page size that can be used in the range [start, end) */
	tmax = find_max_lwk_page(start, end, mempolicy->max_page);

	/* Allocate physical memory for each subrange of [start, end)
	 * aligned at different page sizes.
	 *
	 * tmax = LWK_PG_1G
	 *
	 * Ex:   start         lstart_prev            uend_prev  end
	 *        |              |                       |        |
	 *        v              v                       v        v
	 *        +----+---------+----------s  s---------+-----+--+
	 *        | 4k |   2m    |  1g                   | 2m  |4k| <- max page
	 *        +----+---------+----------s  s---------+-----+--+   size that
	 *                                                           can be used
	 */
	lstart_prev = uend_prev = 0;
	for_each_lwkpage_type_reverse_from(t, tmax) {
		lstart = ALIGN(start, lwkpage_size(t));
		uend = ALIGN_DOWN(end, lwkpage_size(t));

		if (t == tmax) {
			lstart_prev = uend;
			uend_prev = uend;
		}

		if (lstart != lstart_prev) {
			rc = lwk_mm_map_aligned_range(vma, lstart, lstart_prev,
					t, policy_nodelists, mempolicy->type);
			if (rc)
				goto alloc_error;
			lstart_prev = lstart;
		}

		if (uend != uend_prev) {
			rc = lwk_mm_map_aligned_range(vma, uend_prev, uend,
					t, policy_nodelists, mempolicy->type);
			if (rc)
				goto alloc_error;
			uend_prev = uend;
		}

		if (lstart == start && uend == end)
			break;
	}
	return 0;

alloc_error:
	lwk_mm_unmap_pages(vma, start, end);
	LWKMEM_WARN("Allocation error rc=%d range=[%lx, %lx) len=%lx",
		    rc, start, end, end - start);
	return rc;
}
