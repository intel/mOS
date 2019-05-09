/*
 * Multi Operating System (mOS)
 * Copyright (c) 2018-2019, Intel Corporation.
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

#include <linux/list.h>
#include <linux/sizes.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/mos.h>
#include <linux/hugetlb.h>
#include <linux/memory.h>
#include <linux/ftrace.h>
#include <asm/setup.h>
#include <asm/tlbflush.h>
#include "lwkmem.h"
#include <trace/events/lwkmem.h>

#undef pr_fmt
#define pr_fmt(fmt)		"mOS-xpmem: " fmt
#define MAX_CHARS		100

#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
static int64_t kind_size[kind_last] = {SZ_4K, SZ_2M, SZ_1G};
#else
static int64_t kind_size[kind_last] = {SZ_4K, SZ_4M, SZ_1G};
#endif

#define inc_att_align_stats_cond(s, c) do {\
		if (unlikely(current->mos_process->report_xpmem_stats && (c))) \
			current->mos_process->attachment_align_stats[s]++;\
	} while (0)
#define inc_att_align_stats(stats) inc_att_align_stats_cond(stats, true)

char *attachment_align_msg[] = {
	"Eligible",
	"Not eligible",
	"Success total",
	"Success with huge page alignment",
	"Failed due to MAP_FIXED",
	"Failed due to Linux VMA",
	"Failed due to no source huge page",
	"Failed due to insufficient VM",
	"Error looking up struct page",
};

/*
 * Helpers to record and report XPMEM stats
 */
void init_xpmem_stats(struct mos_process_t *mosp)
{
	enum lwkmem_kind_t k1, k2;
	enum attachment_align_stats_t s;

	if (mosp) {
		mosp->report_xpmem_stats = false;
		for (k1 = kind_4k; k1 < kind_last; k1++) {
			for (k2 = kind_4k; k2 < kind_last; k2++) {
				mosp->src_pgmap[k1][k2] = 0;
				mosp->dst_pgmap[k1][k2] = 0;
			}
		}

		for (s = 0; s < ALIGN_STAT_END; s++)
			mosp->attachment_align_stats[s] = 0;
	}
}

static void show_xpmem_pgmap_stats(struct mos_process_t *mosp, bool src)
{
	int rc;
	enum lwkmem_kind_t k1, k2;
	unsigned long size = kind_last * MAX_CHARS;
	char *str = kzalloc(size, GFP_KERNEL);

	if (!mosp || !str)
		goto out;

	/* Print header */
	pr_info("%s map stats:\n", src ? "Source" : "Destination");
	for (k1 = kind_last - 1, rc = 0; (int) k1 >= kind_4k; k1--)
		rc += snprintf((str + rc), size - rc, " %16s", kind_str[k1]);
	pr_info("%4s%s\n", " ", str);

	/* Print table */
	memset(str, 0, size);
	for (k1 = kind_last - 1; (int) k1 >= kind_4k; k1--) {
		for (k2 = kind_last - 1, rc = 0; (int) k2 >= kind_4k; k2--) {
			rc += snprintf((str + rc), size - rc, " %16ld",
					src ? mosp->src_pgmap[k1][k2] :
					      mosp->dst_pgmap[k1][k2]);
		}
		pr_info("%3s:%s\n", kind_str[k1], str);
	}
out:
	kfree(str);
}

void show_xpmem_stats(struct mos_process_t *mosp)
{
	enum attachment_align_stats_t s;

	if (mosp && mosp->report_xpmem_stats) {

		pr_info("mOS XPMEM stats for tgid %d\n", current->tgid);
		show_xpmem_pgmap_stats(mosp, true);
		show_xpmem_pgmap_stats(mosp, false);

		pr_info("Attachment alignment stats:\n");
		for (s = 0; s < ALIGN_STAT_END; s++) {
			pr_info("%-35s: %ld\n", attachment_align_msg[s],
				mosp->attachment_align_stats[s]);
		}
	}
}

/*
 * LWKXPMEM Page table handling routines
 */
static int build_lwkxpmem_pagetbl(struct vm_area_struct *vma,
				  unsigned long vstart,
				  unsigned long pfn_start,
				  unsigned long pfn_end,
				  enum lwkmem_kind_t max_k)
{
	int rc;
	unsigned long vend;
	enum lwkmem_kind_t k = max_k;

	vend = vstart + (pfn_end - pfn_start) * PAGE_SIZE;

	while (max_k > kind_4k && !IS_ALIGNED(vstart, kind_size[max_k]))
		max_k--;

	if (unlikely(current->mos_process->report_xpmem_stats))
		current->mos_process->dst_pgmap[k][max_k]++;

	rc = build_pagetbl(max_k, vma, __pfn_to_phys(pfn_start),
			   vstart, vend, 1);

	trace_mos_build_lwkxpmem_pagetbl(vma->vm_start, vma->vm_end,
		vstart, vend, pfn_start, pfn_end, max_k, rc);
	return rc;
}

static inline void set_pages_dirty(unsigned long pfn_start,
				   unsigned long pfn_end)
{
	while (pfn_start < pfn_end) {
		set_lwkpg_dirty(pfn_to_page(pfn_start));
		pfn_start++;
	}
}

static inline void clear_pte_range(struct mm_struct *mm, pmd_t *pmd,
				   unsigned long start, unsigned long end)
{
	spinlock_t *ptl;
	pte_t *start_pte, *pte;
	unsigned long pfn;

	start_pte = pte_offset_map_lock(mm, pmd, start, &ptl);
	for (pte = start_pte; start != end; start += PAGE_SIZE, pte++) {
		if (pte_none(*pte))
			continue;
		if (pte_present(*pte)) {
			if (pte_dirty(*pte)) {
				pfn = pte_pfn(*pte);
				/*
				 * Let owner or LWKMEM know this page
				 * was dirtied by the non-owner process
				 */
				set_pages_dirty(pfn, pfn + 1);
			}
			pte_clear(mm, start, pte);
		}
	}
	flush_tlb_mm_range(mm, start, end, 0);
	pte_unmap_unlock(start_pte, ptl);
}

static inline void clear_pmd_range(struct mm_struct *mm, pud_t *pud,
				   unsigned long start, unsigned long end)
{
	pmd_t *pmd;
	spinlock_t *ptl;
	unsigned long next, pfn_start, pfn_end;

	for (pmd = pmd_offset(pud, start); start != end; start = next, pmd++) {
		next = pmd_addr_end(start, end);
		if (pmd_none(*pmd))
			continue;

		if (pmd_val(*pmd) & _PAGE_PSE) {
			ptl = pmd_lock(mm, pmd);
			/* Check against a racing thread */
			if (pmd_present(*pmd) &&
			    (pmd_val(*pmd) & _PAGE_PSE)) {
				/*
				 * There is no need to split the pmd yet
				 * because XPMEM attachments are detached
				 * completely but not partially.
				 */
				if (pmd_dirty(*pmd)) {
					pfn_start = pmd_pfn(*pmd);
					pfn_end = pfn_start +
						  PMD_PAGE_SIZE / PAGE_SIZE;
					/*
					 * Let owner or LWKMEM know these pages
					 * were dirtied by the non-owner process
					 */
					set_pages_dirty(pfn_start, pfn_end);
				}
				pmd_clear(pmd);
				flush_tlb_mm_range(mm, start, next, 0);
			}
			spin_unlock(ptl);
		} else
			clear_pte_range(mm, pmd, start, next);
	}
}

static inline void clear_pud_range(struct mm_struct *mm, p4d_t *p4d,
				   unsigned long start, unsigned long end)
{
	pud_t *pud;
	spinlock_t *ptl;
	unsigned long next, pfn_start, pfn_end;

	for (pud = pud_offset(p4d, start); start != end; start = next, pud++) {
		next = pud_addr_end(start, end);
		if (pud_none(*pud))
			continue;

		if ((pud_val(*pud) & _PAGE_PSE)) {
			ptl = pud_lock(mm, pud);
			/* Check against a racing thread */
			if (pud_present(*pud) &&
			    (pud_val(*pud) & _PAGE_PSE)) {
				/*
				 * There is no need to split the pud yet
				 * because XPMEM attachments are detached
				 * completely but not partially.
				 */
				if (pud_dirty(*pud)) {
					pfn_start = pud_pfn(*pud);
					pfn_end = pfn_start +
						  PUD_PAGE_SIZE / PAGE_SIZE;
					/*
					 * Let owner or LWKMEM know these pages
					 * were dirtied by the non-owner process
					 */
					set_pages_dirty(pfn_start, pfn_end);
				}
				pud_clear(pud);
				flush_tlb_mm_range(mm, start, next, 0);
			}
			spin_unlock(ptl);
		} else
			clear_pmd_range(mm, pud, start, next);
	}
}

static inline void clear_p4d_range(struct mm_struct *mm, pgd_t *pgd,
				   unsigned long start, unsigned long end)
{
	p4d_t *p4d;
	unsigned long next;

	for (p4d = p4d_offset(pgd, start); start != end; start = next, p4d++) {
		next = p4d_addr_end(start, end);
		if (p4d_none(*p4d))
			continue;
		clear_pud_range(mm, p4d, start, next);
	}
}

static void clear_lwkxpmem_pagetbl(struct mm_struct *mm, unsigned long start,
				   unsigned long end)
{
	pgd_t *pgd;
	unsigned long next;

	for (pgd = pgd_offset(mm, start); start != end; start = next, pgd++) {
		next = pgd_addr_end(start, end);
		if (pgd_none(*pgd))
			continue;
		clear_p4d_range(mm, pgd, start, next);
	}
	trace_mos_clear_lwkxpmem_pagetbl(start, end);
}

#ifdef MOSXPMEM_DEBUG
/*
 * VMA sub-region handling routines
 */
static void show_vma_subregions(struct list_head *head, char *msg)
{
	struct vma_subregion *sr;

	pr_info("tgid %d %s\n", current->tgid, msg);
	list_for_each_entry(sr, head, list) {
		pr_info("tgid %d 0x%lx-0x%lx\n",
			current->tgid,
			sr->start, sr->end);
	}
}
#else
#define show_vma_subregions(h, m)
#endif

static int split_vma_subregion(struct vma_subregion *orig,
			       unsigned long split_address,
			       struct vma_subregion **next)
{
	struct vma_subregion *new;

	new = kmalloc(sizeof(struct vma_subregion), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	*new = *orig;
	orig->end = split_address;
	new->start = split_address;
	list_add(&new->list, &orig->list);

	if (next)
		*next = new;
	return 0;
}

static inline bool overlaps_subregion(struct vma_subregion *sr,
			unsigned long start, unsigned long end)
{
	return !(start >= sr->end || end <= sr->start);
}

static int insert_vma_subregion(struct vm_area_struct *vma, unsigned long start,
				unsigned long end)
{
	struct vma_subregion *subregion, *sr, *sr_next;
	struct vma_xpmem_private *private = vma->vm_private_data;
	int rc = -1;

	subregion = kmalloc(sizeof(struct vma_subregion), GFP_KERNEL);
	if (!subregion)
		return -ENOMEM;
	subregion->start = start;
	subregion->end   = end;

	mutex_lock(&private->subregions_lock);

	show_vma_subregions(&private->subregions, "Before insert");
	if (unlikely(list_empty(&private->subregions))) {
		list_add(&subregion->list, &private->subregions);
		rc = 0;
	} else {
		sr = list_first_entry(&private->subregions,
				      struct vma_subregion, list);
		if (end <= sr->start) {
			list_add(&subregion->list, &private->subregions);
			rc = 0;
		} else {
			list_for_each_entry_safe(sr, sr_next,
						 &private->subregions, list) {
				if (overlaps_subregion(sr, start, end)) {
					pr_err("%s(!): P%d r %lx-%lx sr %lx-%lx\n",
					       __func__, current->tgid, start,
						end, sr->start, sr->end);
					break;
				}

				if (&sr_next->list != &private->subregions) {
					if (overlaps_subregion(sr_next, start,
							       end)) {
						pr_err("%s: P%d r %lx-%lx sr %lx-%lx\n",
							__func__, current->tgid,
							start, end, sr->start,
							sr->end);
						break;
					}
					if (sr_next->end <= start)
						continue;
				}
				list_add(&subregion->list, &sr->list);
				rc = 0;
				break;
			}
		}
	}
	show_vma_subregions(&private->subregions, "After insert");
	mutex_unlock(&private->subregions_lock);
	trace_mos_insert_vma_subregion(vma->vm_start, vma->vm_end,
		start, end, rc);
	return rc;
}

/*
 * Removes a VMA subregion in full or part based on the overlap
 * with the given range
 *
 * Possible overlaps,
 *
 * |  |  -> VMA subregion, [  ] -> Given range
 *
 * Case 1: |[      ]| Exact overlap
 * Case 2: [  |  |  ] Enclosed within the given range
 * Case 3: |  [  ]  | Part of the sub-region to be removed
 * Case 4: [  |  ]  | Left overlalp
 * Case 5: |  [  |  ] Right overlap
 *
 * Case 1 & 2 --> Delete the entire VMA subregion.
 * Case 3     --> Split the VMA subregion and append new subregion.
 * case 4 & 5 --> Adjust the current VMA subregion either start or end.
 *
 * Though in case 3 we add a new VMA subregion the iterator calling this
 * function need not reset the next pointer to newly inserted element
 * since its already processed.
 */
static int remove_vma_subregion(struct vm_area_struct *vma,
				struct vma_subregion *subregion,
				unsigned long start,
				unsigned long end)
{
	int rc = 0;
	unsigned long unmap_start = max(start, subregion->start);
	unsigned long unmap_end = min(end, subregion->end);


	/* Unmap corresponding page table entries */
	if (unmap_start > unmap_end) {
		pr_err("%s(): ERR range[%lx-%lx) vma[%lx-%lx) sub[%lx-%lx)\n",
		       __func__, start, end, vma->vm_start, vma->vm_end,
		       subregion->start, subregion->end);
		rc = -EINVAL;
		goto out;
	}

	clear_lwkxpmem_pagetbl(vma->vm_mm, unmap_start, unmap_end);

	/* Remove the VMA sub-region in part or full */
	if (subregion->start >= start && subregion->end <= end) {
		/* Case 1 or 2*/
		list_del(&subregion->list);
		kfree(subregion);
	} else if (start >= subregion->start && end <= subregion->end) {
		/* Case 3 */
		if (start == subregion->start)
			subregion->start = end;
		else if (end == subregion->end)
			subregion->end = start;
		else {
			rc = split_vma_subregion(subregion, start,
					&subregion);
			if (rc)
				goto out;
			subregion->start = end;
		}
	} else {
		/* Case 4 or 5 */
		if (start < subregion->start)
			subregion->start = end;
		if (end > subregion->end)
			subregion->end = start;
	}
out:
	return rc;
}

static int __remove_vma_subregions(struct vm_area_struct *vma,
				   unsigned long start,
				   unsigned long end)
{	int rc = 0;
	bool done;
	struct vma_subregion *sr_curr, *sr_next;
	struct vma_xpmem_private *private = vma->vm_private_data;

	show_vma_subregions(&private->subregions, "Before removal");
	list_for_each_entry_safe(sr_curr, sr_next, &private->subregions, list) {
		if (!overlaps_subregion(sr_curr, start, end))
			continue;
		/* Does one vma sub-region enclose the whole range? */
		done = start >= sr_curr->start && end <= sr_curr->end;

		rc = remove_vma_subregion(vma, sr_curr, start, end);
		if (rc || done)
			break;
	}
	show_vma_subregions(&private->subregions, "After removal");
	trace_mos_remove_vma_subregions(vma->vm_start, vma->vm_end,
		start, end, rc);
	return rc;
}

static int remove_vma_subregions(struct vm_area_struct *vma,
				 unsigned long start,
				 unsigned long end)
{
	int rc = -1;
	struct vma_xpmem_private *private;

	start = max(start, vma->vm_start);
	end = min(end, vma->vm_end);
	private = vma->vm_private_data;

	mutex_lock(&private->subregions_lock);
	rc = __remove_vma_subregions(vma, start, end);
	mutex_unlock(&private->subregions_lock);
	return rc;
}

static void release_all_vma_subregions(struct vm_area_struct *vma)
{
	struct vma_xpmem_private *private;
	struct vma_subregion *sr_curr, *sr_next;

	private = vma->vm_private_data;
	mutex_lock(&private->subregions_lock);
	if (__remove_vma_subregions(vma, vma->vm_start, vma->vm_end)) {
		pr_err("%s(): ERR VMA[0x%lx-0x%lx)\n",
		       __func__, vma->vm_start, vma->vm_end);
		goto out;
	}
	/* Delete all entries. */
	list_for_each_entry_safe(sr_curr, sr_next, &private->subregions, list)
		kfree(sr_curr);
out:
	mutex_unlock(&private->subregions_lock);
}

/*
 * VMA copy handling routines
 */
static int find_page_pfns(struct mm_struct *mm, unsigned long vaddr,
			  unsigned long *pfn_start, unsigned long *pfn_end,
			  enum lwkmem_kind_t *page_type)
{
	unsigned long vaddr_page_start, pfn_offset, page_size;
	enum lwkmem_kind_t k;
	struct page *page;
	unsigned int size;

	page = lwkmem_user_to_page(mm, vaddr, &size);
	if (!page) {
		pr_err("%s(): PID %d No valid struct page found for 0x%lx\n",
			__func__, current->pid, vaddr);
		return -EINVAL;
	}
	page_size = size;
	vaddr_page_start = vaddr & ~(page_size - 1);
	pfn_offset = (vaddr - vaddr_page_start) / PAGE_SIZE;
	*pfn_start = page_to_pfn(page);
	*pfn_end = *pfn_start - pfn_offset + size / PAGE_SIZE;

	*page_type = kind_4k;
	for (k = kind_4k; k < kind_last; k++) {
		if (kind_size[k] == size) {
			*page_type = k;
			break;
		}
	}
	return 0;
}

/*
 * This function copies an LWK VMA fully or partially to a non-owner virtual
 * memory. The page table mapping in the non-owner may not be identical to
 * owner process. The number and types of TLBs used depends on multiple factors
 * such as, the start of mapped memory @dst_start, length of mapping @len, and
 * start of mapping in the owner process @src_start
 *
 * Ex:
 *      Owner virtual memory       Non-owner virtual memory
 *            |        |                 |        |
 *            +--------+ ^               |        |
 *            |        | |               +--------+       ^
 * src_start->|........| | src_vma       |        |       |
 *            |........| |               +--------+^      |
 *            +--------+ v   dst_start ->|........|| len  | dst_vma
 *            |        |                 |........||      |
 *            |        |                 +--------+v      |
 *            |        |                 |        |       |
 *            |        |                 +--------+       v
 *            |        |                 |        |
 *
 * As shown in the example above the copy can potentially be in the middle of
 * the source VMA. Also it could be such that src_start is in the middle of a
 * page. To begin with src_start is rounded down to start of a 4k page. If
 * the src_start or src_end is within a large page (i.e. 2m or 1g page) then
 * the rest of the page can be mapped using a lower TLB size in the non-owner
 * process. Further the size of TLB to be used in the non-owner process for
 * this part of huge page is determined by the alignment of dst_start.
 *
 * Building of page table in the non-owner is done for one page in the owner
 * process at a time since the owner pages could potentially be interleaved
 * and have non-contiguous pfn's mapped in the original mapping.
 *
 * The destination process VMA will have sub-regions. A sub-region @dst_start to
 * @dst_start + @len is created and inserted to the list of sub-regions in the
 * destination VMA upon successful copy of source VMA. A sub-region represents
 * the part of the VMA which is mapped using either Linux physical memory or LWK
 * physical memory. This structure will be useful in unmapping the VMA.
 *
 * Caller needs to ensure that the src_start, dst_start and len
 * are PAGE_SIZE aligned.
 */
static int copy_one_lwkvma(struct vm_area_struct *src_vma,
			   unsigned long src_start,
			   struct vm_area_struct *dst_vma,
			   unsigned long dst_start, unsigned long len)
{
	int rc = -1;
	enum lwkmem_kind_t max_k, src_k;
	unsigned long pfn_start, pfn_end, scale, map_len;

	while (len > 0) {
		rc = find_page_pfns(src_vma->vm_mm, src_start,
				    &pfn_start, &pfn_end, &max_k);
		if (rc)
			goto out;

		pfn_end = min(pfn_end, pfn_start + len / PAGE_SIZE);
		map_len = (pfn_end - pfn_start) * PAGE_SIZE;
		scale = kind_size[max_k] / PAGE_SIZE;

		/*
		 * The source address start or end could fall in the middle
		 * of a large page.
		 *
		 * We gradually reduce the max page size and see if the given
		 * page size can be used within the boundary of specified
		 * range [pfn_start-pfn_end).
		 */
		src_k = max_k;
		while (max_k > kind_4k &&
		       ((pfn_start % scale) || (pfn_end % scale))) {
			/* Get the next lower page size */
			max_k--;
			scale = kind_size[max_k] / PAGE_SIZE;
		}

		if (unlikely(current->mos_process->report_xpmem_stats))
			current->mos_process->src_pgmap[src_k][max_k]++;

		rc = build_lwkxpmem_pagetbl(dst_vma, dst_start,
				pfn_start, pfn_end, max_k);
		if (rc) {
			pr_err("%s(): Map failed pfn[%ld-%ld) ps %lld to %lx\n",
			       __func__, pfn_start, pfn_end,
			       kind_size[max_k], dst_start);
			goto out;
		}
		src_start += map_len;
		dst_start += map_len;
		len -= map_len;
	}
out:
	return rc;
}

/*
 * Copies page table of LWKMEM VMA to LWKXPMEM VMA and insert necessary
 * VMA subregion.
 */
int copy_lwkmem_to_lwkxpmem(struct vm_area_struct *src_vma,
			    unsigned long src_start,
			    struct vm_area_struct *dst_vma,
			    unsigned long dst_start, unsigned long len)
{
	int rc = -EINVAL;

	if (!src_vma || !dst_vma) {
		pr_err("%s(): ERR Invalid VMA, src = %p dst = %p\n",
			__func__, src_vma, dst_vma);
		goto out;
	}

	if (offset_in_page(src_start) || offset_in_page(dst_start) ||
	    offset_in_page(len)) {
		pr_err("%s(): ERR Un-aligned copy src %lx dst %lx len %ld\n",
			__func__, src_start, dst_start, len);
		goto out;
	}

	if (!is_lwkmem(src_vma)) {
		pr_err("%s(): ERR src VMA[%lx-%lx) start %lx is not LWKMEM\n",
			__func__, src_vma->vm_start, src_vma->vm_end,
			src_start);
		goto out;
	}

	if (!is_lwkxpmem(dst_vma)) {
		pr_err("%s(): ERR dst VMA[%lx-%lx) start %lx is not LWKXPMEM\n",
		       __func__, dst_vma->vm_start, dst_vma->vm_end, dst_start);
		goto out;
	}

	if (src_vma->vm_start > src_start ||
	    src_vma->vm_end < src_start + len) {
		pr_err("%s(): ERR PID %d src req[%lx-0x%lx) VMA[%lx-%lx)\n",
		       __func__, current->pid, src_start, src_start + len,
		       src_vma->vm_start, src_vma->vm_end);
		goto out;
	}

	if (dst_vma->vm_start > dst_start ||
	    dst_vma->vm_end < dst_start + len) {
		pr_err("%s(): ERR PID %d dst req[%lx-%lx) VMA[%lx-%lx)\n",
		       __func__, current->pid, dst_start, dst_start + len,
		       dst_vma->vm_start, dst_vma->vm_end);
		goto out;
	}

	/* Nothing to do for zero len copy */
	if (!len) {
		rc = 0;
		goto out;
	}

	/* Add a new sub-region in the destination VMA */
	rc = insert_vma_subregion(dst_vma, dst_start, dst_start + len);
	if (rc)
		goto out;

	/* Build destination page table */
	rc = copy_one_lwkvma(src_vma, src_start, dst_vma, dst_start, len);
out:
	trace_mos_copy_lwkmem_to_lwkxpmem(src_vma->vm_start, src_vma->vm_end,
		src_start, dst_vma->vm_start, dst_vma->vm_end, dst_start, len,
		rc);
	return rc;
}
EXPORT_SYMBOL(copy_lwkmem_to_lwkxpmem);

int unmap_lwkxpmem_range(struct vm_area_struct *vma, unsigned long start,
			 unsigned long end)
{
	int rc = -EINVAL;

	if (start > end || !is_lwkxpmem(vma) || !vma->vm_private_data)
		goto out;
	rc = remove_vma_subregions(vma, start, end);
out:
	trace_mos_unmap_lwkxpmem_range(vma->vm_start, vma->vm_end, start, end,
		rc);
	return rc;
}

static int get_aligned_start(unsigned long src_start, unsigned long *dst_start,
			     unsigned long len, unsigned long page_size)
{
	enum lwkmem_kind_t k;
	unsigned long offset;
	unsigned long dst_start_aligned;
	struct vm_unmapped_area_info info;

	len = round_up(len, PAGE_SIZE);

	/* Based on @len choose the page size which is <= @len */
	for (k = kind_last - 1; k > kind_4k; k--) {
		if (kind_size[k] > page_size)
			continue;
		if (kind_size[k] <= len)
			break;
	}

	inc_att_align_stats_cond(ALIGN_SUCCESS_HP, k > kind_4k);

	offset = src_start - ALIGN_DOWN(src_start, kind_size[k]);
	info.flags = 0;
	info.length = len + offset;
	info.low_limit = current->mm->mmap_legacy_base;
	info.high_limit = TASK_SIZE;
	info.align_mask = kind_size[k] - 1;
	info.align_offset = 0;
	dst_start_aligned = unmapped_area(&info);

	if (offset_in_page(dst_start_aligned))
		return -1;

	*dst_start = dst_start_aligned + offset;
	return 0;
}

/*
 * This function creates a VMA in the non-owner(caller) process that
 * represents the XPMEM attached shared virtual memory. The kernel
 * function is exported and called from the XPMEM device driver upon
 * xpmem_attach().
 *
 * In mOS the VMA created will be MAP_SHARED mapping with custom VMA
 * attributes such as VM_LWK_XPMEM to mark them as mOS XPMEM
 * implementation. This bit is used by mOS memory management to
 * identify a VMA as mOS XPMEM VMA.
 *
 * @src_start is used to arrive at an optimum alignment of the VMA
 * corresponding to this attachment in the non-owner which can
 * improve the large page usage in the non-owner when source page
 * table is remapped.
 */
struct vm_area_struct *create_lwkxpmem_vma(struct mm_struct *src_mm,
					unsigned long src_start,
					unsigned long dst_start,
					unsigned long len,
					unsigned long prot,
					void *vm_private_data,
					const struct vm_operations_struct *ops)
{
	unsigned long populate, vaddr = 0;
	unsigned long flags, vm_flags;
	struct vm_area_struct *vma = NULL;
	struct vma_xpmem_private *private;
	bool align_dst_vma = false;
	struct page *page = NULL;
	unsigned int size = 0;

	/* Allocate and initialize VMA private data */
	private = kmalloc(sizeof(struct vma_xpmem_private), GFP_KERNEL);
	if (!private)
		return NULL;

	private->private_data = vm_private_data;
	mutex_init(&private->subregions_lock);
	INIT_LIST_HEAD(&private->subregions);

	flags = MAP_SHARED;
	if (dst_start != 0) {
		flags |= MAP_FIXED;
		inc_att_align_stats(ALIGN_FAIL_MAPFIXED);
	}

	inc_att_align_stats_cond(ALIGN_ELIGIBLE,
		len >= kind_size[kind_4k + 1]);
	inc_att_align_stats_cond(ALIGN_NOT_ELIGIBLE,
		len < kind_size[kind_4k + 1]);
	/*
	 * Do not try to align the destination vma start if the requested length
	 * is smaller than the smallest huge page or if the request had asked us
	 * to map the destination vma at a fixed start address.
	 */
	if (!(flags & MAP_FIXED) && (len >= kind_size[kind_4k + 1])) {
		/* We check if there is already a VMA populated  */
		/* and if it is LWKMEM                           */
		down_read(&src_mm->mmap_sem);

		align_dst_vma = true;
		vma = find_vma(src_mm, src_start);
		if (vma && src_start >= vma->vm_start) {
			if (!is_lwkmem(vma)) {
				align_dst_vma = false;
				inc_att_align_stats(ALIGN_FAIL_LINUXVMA);
			} else {
				page = lwkmem_user_to_page(src_mm, src_start,
							   &size);
				if (!page) {
					pr_err("%s(): %d no struct page %lx\n",
						__func__, current->pid,
						src_start);
					align_dst_vma = false;
					inc_att_align_stats(ALIGN_FAIL_ERROR);
				}
			}
		}

		up_read(&src_mm->mmap_sem);

		/* If there is no VMA backing yet either Linux or LWKMEM.
		 * Assume that the largest page size will cover this address
		 * in the future.
		 */
		if (align_dst_vma && !page)
			size = kind_size[kind_last - 1];

		/* Let Linux choose the best fit for base pages */
		if (align_dst_vma && size == PAGE_SIZE) {
			align_dst_vma = false;
			inc_att_align_stats_cond(ALIGN_FAIL_SRCPGSZ,
				page && size == PAGE_SIZE);
		}
	}

	/* Allocate and initialize LWKXPMEM VMA */
	down_write(&current->mm->mmap_sem);

	if (align_dst_vma &&
	    !get_aligned_start(src_start, &dst_start, len, size))
		flags |= MAP_FIXED;

	vma = NULL;
	vm_flags = VM_DONTCOPY | VM_DONTDUMP | VM_DONTEXPAND |
		   VM_IO | VM_PFNMAP | VM_NORESERVE | VM_LWK_XPMEM;
retry:
	vaddr = do_mmap(NULL, dst_start, len, prot, flags, vm_flags, 0,
			&populate, NULL);
	if (IS_ERR((void *) vaddr) ||
	    ((flags & MAP_FIXED) && (vaddr != dst_start))) {
		/*
		 * If there isn't sufficient virtual memory to fit
		 * the new map at an aligned start then we retry
		 * without any alignment constraints.
		 */
		if (align_dst_vma) {
			flags &= ~MAP_FIXED;
			dst_start = 0;
			align_dst_vma = false;
			inc_att_align_stats(ALIGN_FAIL_NOVM);
			goto retry;
		}
		pr_err("%s(ERR): pid %d src %lx dst %lx len %ld rc %lx\n",
		       __func__, current->tgid, src_start, dst_start, len,
		       vaddr);
		goto out;
	}

	vma = find_vma(current->mm, vaddr);
	if (vma && is_lwkxpmem(vma) && vma->vm_start == vaddr) {
		vma->vm_private_data = private;
		vma->vm_ops = ops;
		inc_att_align_stats_cond(ALIGN_SUCCESS, align_dst_vma);
	} else {
		pr_err("%s(): Failed to look up VMA created\n", __func__);
		vma = NULL;
	}
out:
	up_write(&current->mm->mmap_sem);
	if (!vma)
		kfree(private);
	trace_mos_create_lwkxpmem_vma(src_start, dst_start, len, prot,
		vm_private_data, ops, vaddr);
	return vma;
}
EXPORT_SYMBOL(create_lwkxpmem_vma);

void release_lwkxpmem_vma(struct vm_area_struct *vma)
{
	struct vma_xpmem_private *private;
	bool lwkxpmem = is_lwkxpmem(vma);

	if (lwkxpmem) {
		/*
		 * Remove all LWK XPMEM attributes of the VMA and let
		 * the XPMEM driver and the Linux cleanup the rest.
		 */
		private = vma->vm_private_data;
		if (private) {
			release_all_vma_subregions(vma);
			vma->vm_private_data = private->private_data;
			kfree(private);
		}
		vma->vm_flags &= ~VM_LWK_XPMEM;
	}
	trace_mos_release_lwkxpmem_vma(vma->vm_start, vma->vm_end, lwkxpmem);
}
EXPORT_SYMBOL(release_lwkxpmem_vma);

void *get_xpmem_private_data(struct vm_area_struct *vma)
{
	struct vma_xpmem_private *private;

	if (!vma)
		return NULL;

	if (is_lwkxpmem(vma) && vma->vm_private_data) {
		private = vma->vm_private_data;
		return private->private_data;
	}
	return vma->vm_private_data;
}
EXPORT_SYMBOL(get_xpmem_private_data);

void set_xpmem_private_data(struct vm_area_struct *vma, void *data)
{
	struct vma_xpmem_private *private;

	if (vma) {
		if (is_lwkxpmem(vma)) {
			private = vma->vm_private_data;
			private->private_data = data;
		} else
			vma->vm_private_data = data;
	}
}
EXPORT_SYMBOL(set_xpmem_private_data);
