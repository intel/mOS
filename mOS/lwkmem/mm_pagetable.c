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
#include <asm/tlbflush.h>
#include <asm/pgalloc.h>
#include <linux/mos.h>
#include <trace/events/lwkmem.h>

/* Private headers */
#include "lwk_mm_private.h"

#define LWKPG_SPLIT_PMD_FLAGS (_PAGE_DIRTY | _PAGE_ACCESSED | _PAGE_RW)
#define LWKPG_SPLIT_PUD_FLAGS (LWKPG_SPLIT_PMD_FLAGS)

#define TRACE_PTE	0
#define TRACE_PMD	1
#define TRACE_PUD	2

/*
 * Linux does not have this function yet. We follow pmdp_estabish() logic
 * that is defined at arch/x86/include/asm/pgtable.h
 *
 * Keeping this identical to Linux pmdp_establish() prototype so that if
 * Linux adds this function later then it would conflict with us and we
 * will know about that change.
 */
static inline pud_t pudp_establish(struct vm_area_struct *vma,
				   unsigned long address,
				   pud_t *pudp, pud_t pud)
{
	pud_t old;

	if (IS_ENABLED(CONFIG_SMP))
		old = xchg(pudp, pud);
	else {
		old = *pudp;
		WRITE_ONCE(*pudp, pud);
	}
	return old;
}

/*
 * Simplified version of __split_huge_pmd_locked(), look at mm/huge_memory.c
 * comments on hardware limitations and related handling of huge PMD splits.
 * We ignore the reference counts for now as LWK memory is not ref. counted.
 */
void lwk_mm_split_pmd_locked(struct vm_area_struct *vma, pmd_t *pmd,
			     unsigned long address)
{
	int rc;
	pgtable_t ptetable;
	pmd_t old_pmd, new_pmd;
	bool dirty, young;
	pte_t *pte, entry;
	struct page *page, *tail;
	pgprot_t pgprot;
	unsigned long i, addr;
	struct mm_struct *mm = vma->vm_mm;
	struct lwk_mm *lwk_mm = vma_lwk_mm(vma);
	unsigned long start = address & PMD_MASK;
	enum lwk_page_type t = LWK_PG_4K + 1;
	unsigned long end = start + lwkpage_size(t);
	unsigned long npages = 1UL << (PMD_SHIFT - PAGE_SHIFT);

	trace_mos_mm_pgtbl_split(TRACE_PMD, vma->vm_start, vma->vm_end,
				 address);

	/* Allocate a page table which holds PTEs of the split PMD */
	ptetable = pte_alloc_one(mm);
	if (!ptetable) {
		LWKMEM_ERROR("Could not allocate a PTE table");
		return;
	}

	/*
	 * Make old PMD entry as not present and invalidate TLB entries to
	 * reflect this change in all TLBs. Subsequent access to virtual
	 * address in this PMD range would page fault and in the page fault
	 * handler it would wait for us to split the PMD here and should see
	 * the split PMD for subsequent accesses.
	 */
	old_pmd = pmdp_establish(vma, start, pmd, pmd_mkinvalid(*pmd));
	/* Invalidate TLB entries to reflect above change */
	flush_tlb_mm_range(mm, start, end, PMD_SHIFT, true);

	/* Prepare flags to set for every PTE entry when this PMD is split */
	dirty = pmd_dirty(old_pmd);
	young = pmd_young(old_pmd);

	page = pmd_page(old_pmd);
	/* No longer a compound page */
	ClearPageHead(page);
	if (pmd_dirty(old_pmd)) {
		SetPageDirty(page);
		set_lwkpg_dirty(page);
	}

	/* Populate the new PTE table */
	pgprot = READ_ONCE(vma->vm_page_prot);
	pmd_populate(mm, &new_pmd, ptetable);
	pte = pte_offset_map(&new_pmd, start);

	for (i = 0, addr = start; i < npages; i++, addr += PAGE_SIZE) {
		if (i) {
			/* No longer tail pages */
			tail = page + i;
			clear_compound_head(tail);
			tail->mapping = page->mapping;
			tail->index = linear_page_index(vma, addr);
		}
		/*
		 * LWK pages are not refcounted or shared,
		 * this is just to keep Linux happy.
		 */
		atomic_set(&page->_mapcount, 0);
		entry = mk_pte(page + i, pgprot);
		entry = pte_clear_flags(entry, LWKPG_CLR_FLAGS);
		entry = pte_mkwrite(entry);
		entry = dirty ? pte_mkdirty(entry) : pte_mkclean(entry);
		entry = young ? pte_mkyoung(entry) : pte_mkold(entry);
		set_pte_at(mm, addr, pte + i, entry);
	}
	pte_unmap(pte);

	/* Commit the new PMD table */
	smp_wmb(); /* make pte visible before pmd */
	pmd_populate(mm, pmd, ptetable);
	mm_inc_nr_ptes(mm);
	flush_tlb_mm_range(mm, start, end, PMD_SHIFT, true);

	/* If reporting is enabled then notify PMA that we split a huge page */
	if (lwk_mm->report_level) {
		rc = lwk_mm->pm_ops->split_page(lwk_mm->pma, t,
						page_to_pfn(page));
		if (rc) {
			LWKMEM_WARN("rc=%d, PMA split_page pfn=%#lx type=%s",
				    rc, page_to_pfn(page), lwkpage_desc(t));
		}
	}
}

void lwk_mm_split_pud_locked(struct vm_area_struct *vma, pud_t *pud,
			     unsigned long address)
{
	int rc;
	pmd_t *pmdtable;
	pud_t old_pud;
	bool dirty, young;
	pmd_t entry;
	struct page *page;
	pgprot_t pgprot;
	unsigned long i, j, addr, pfn_start;
	struct mm_struct *mm = vma->vm_mm;
	struct lwk_mm *lwk_mm = vma_lwk_mm(vma);
	unsigned long start = address & PUD_MASK;
	unsigned long end = start + lwkpage_size(LWK_PG_4K + 2);
	unsigned long npmds = 1UL << (PUD_SHIFT - PMD_SHIFT);
	int order = PMD_SHIFT - PAGE_SHIFT;
	unsigned long npages = 1UL << order;
	struct address_space *mapping;

	trace_mos_mm_pgtbl_split(TRACE_PUD, vma->vm_start, vma->vm_end,
				 address);

	/* Allocate a page table which holds the PMDs of the split PUD */
	pmdtable = pmd_alloc_one(mm, address);
	if (!pmdtable) {
		LWKMEM_ERROR("Could not allocate a PMD table");
		return;
	}

	/*
	 * Make old PUD entry as not present and invalidate TLB entries to
	 * reflect this change in all TLBs. Subsequent access to virtual
	 * address in this PUD range would page fault and in the page fault
	 * handler it would wait for us to split the PUD here and should see
	 * the split PUD for subsequent accesses.
	 */
	old_pud = pudp_establish(vma, start, pud, pud_mkinvalid(*pud));
	flush_tlb_mm_range(mm, start, end, PUD_SHIFT, true);

	/* Prepare flags to set for every PMD entry when this PUD is split */
	dirty = pud_dirty(old_pud);
	young = pud_young(old_pud);

	page = pud_page(old_pud);
	pfn_start = page_to_pfn(page);
	if (pud_dirty(old_pud)) {
		SetPageDirty(page);
		set_lwkpg_dirty(page);
	}

	/* Populate the new PMD table */
	pgprot = READ_ONCE(vma->vm_page_prot);
	mapping = page->mapping;

	for (i = 0, addr = start; i < npmds; i++, addr += PMD_SIZE) {
		clear_compound_head(page);
		set_compound_order(page, order);
		__SetPageHead(page);
		page->mapping = mapping;
		page->index = linear_page_index(vma, addr);
		/*
		 * Adjust tail pages to point to new head, other fields of
		 * tail pages need no change as they were previously also part
		 * of a larger compound page and were set appropriately.
		 */
		for (j = 1; j < npages; j++)
			set_compound_head(page + j, page);
		/*
		 * LWK pages are not refcounted or shared,
		 * this is just to keep Linux happy.
		 */
		atomic_set(compound_mapcount_ptr(page), 0);

		entry = mk_pmd(page, pgprot);
		entry = pmd_clear_flags(entry, LWKPG_CLR_FLAGS);
		entry = pmd_mkwrite(entry);
		entry = pmd_mkhuge(entry);
		entry = dirty ? pmd_mkdirty(entry) : pmd_mkclean(entry);
		entry = young ? pmd_mkyoung(entry) : pmd_mkold(entry);

		set_pmd_at(mm, addr, pmdtable + i, entry);
		page += npages;
	}

	/* Commit the new PUD table */
	smp_wmb(); /* make pmd visible before pud */
	pud_populate(mm, pud, pmdtable);
	mm_inc_nr_pmds(mm);
	flush_tlb_mm_range(mm, start, end, PUD_SHIFT, true);

	/* If reporting is enabled then notify PMA that we split a huge page */
	if (lwk_mm->report_level) {
		rc = lwk_mm->pm_ops->split_page(lwk_mm->pma, LWK_PG_1G,
						pfn_start);
		if (rc) {
			LWKMEM_WARN("rc=%d, PMA split_page pfn=%#lx type=%s",
				    rc, pfn_start, lwkpage_desc(LWK_PG_1G));
		}
	}
}

void lwk_mm_split_pmd(struct vm_area_struct *vma, unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	spinlock_t *ptl;

	pgd = pgd_offset(vma->vm_mm, address);
	if (!pgd_present(*pgd))
		return;

	p4d = p4d_offset(pgd, address);
	if (!p4d_present(*p4d))
		return;

	pud = pud_offset(p4d, address);
	if (!pud_present(*pud))
		return;

	pmd = pmd_offset(pud, address);
	if (lwk_huge_pmd(pmd)) {
		ptl = pmd_lock(vma->vm_mm, pmd);

		if (!pmd_present(*pmd) || pmd_none(*pmd) ||
		    !lwk_huge_pmd(pmd)) {
			spin_unlock(ptl);
			return;
		}
		lwk_mm_split_pmd_locked(vma, pmd, address);
		spin_unlock(ptl);
	}
}

void lwk_mm_split_pud(struct vm_area_struct *vma, unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	spinlock_t *ptl;

	pgd = pgd_offset(vma->vm_mm, address);
	if (!pgd_present(*pgd))
		return;

	p4d = p4d_offset(pgd, address);
	if (!p4d_present(*p4d))
		return;

	pud = pud_offset(p4d, address);

	if (!pud_present(*pud))
		return;
	if (lwk_huge_pud(pud)) {
		ptl = pud_lock(vma->vm_mm, pud);

		if (!pud_present(*pud) || pud_none(*pud)) {
			spin_unlock(ptl);
			return;
		}

		if (lwk_huge_pud(pud))
			lwk_mm_split_pud_locked(vma, pud, address);
		spin_unlock(ptl);
	}

	/*
	 * If @address is not aligned at PMD page size then
	 * further split the PMD that has @address.
	 */
	if (address & ~PMD_MASK) {
		pmd = pmd_offset(pud, address);
		ptl = pmd_lock(vma->vm_mm, pmd);

		if (!pmd_present(*pmd) || pmd_none(*pmd) ||
		    !lwk_huge_pmd(pmd)) {
			spin_unlock(ptl);
			return;
		}
		lwk_mm_split_pmd_locked(vma, pmd, address);
		spin_unlock(ptl);
	}
}

/*
 * Function to clear struct page and corresponding physical memory contents
 * before releasing it to physical memory allocator. To be used by unmap
 * functions.
 */
static void clear_user_lwkpg(struct page *page, unsigned long page_size,
			     bool pte_dirty)
{
	int i;
	struct page *pg;
	unsigned long nr_pages = 0;

	//lwkpage_remove_rmap(page);
	ClearPageDirty(page);
	ClearPageHead(page);

	nr_pages = page_size / PAGE_SIZE;
	for (i = 0; i < nr_pages; i++) {
		pg = page + i;
		if (is_lwkpg_dirty(pg) || pte_dirty) {
			memset((void *) page_to_virt(pg), 0, PAGE_SIZE);
			clear_lwkpg_dirty(pg);
		}
		pg->mapping = NULL;
		pg->index = 0;
		page_mapcount_reset(pg);
		init_page_count(pg);
	}
}

/*
 * Functions to map page table for a range of addresses within an LWK VMA
 */
int lwk_mm_map_pte(pmd_t *pmd, struct vm_area_struct *vma, unsigned long start,
		   unsigned long end, struct list_head *list)
{
	pte_t *pte, *pte_start;
	pte_t entry;
	struct page *page;
	spinlock_t *ptl;
	unsigned long addr;
	struct mm_struct *mm = vma->vm_mm;

	addr = start;
	pte_start = pte_alloc_map_lock(mm, pmd, addr, &ptl);
	if (!pte_start)
		return -ENOMEM;

	trace_mos_mm_pgtbl_map(TRACE_PTE, start, end);
	pte = pte_start;
	do {
		if (pte_none(*pte)) {
			if (unlikely(list_empty(list))) {
				pte_unmap_unlock(pte, ptl);
				LWKMEM_ERROR("page list is empty");
				return -ENOMEM;
			}
			page = list_first_entry(list, struct page, lru);
			list_del(&page->lru);
			lwkpage_add_rmap(page, vma, addr);
			entry = mk_pte(page, vma->vm_page_prot);
			entry = pte_clear_flags(entry, LWKPG_CLR_FLAGS);
			entry = pte_mkwrite(entry);
			set_pte_at(mm, addr, pte, entry);
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);
	pte_unmap_unlock(pte_start, ptl);

	return 0;
}

int lwk_mm_map_pmd(pud_t *pud, struct vm_area_struct *vma, unsigned long start,
		   unsigned long end, enum lwk_page_type t,
		   struct list_head *list)

{
	int rc = 0;
	pmd_t *pmd;
	pmd_t entry;
	struct page *page;
	spinlock_t *ptl;
	unsigned long addr, next;
	struct mm_struct *mm = vma->vm_mm;

	addr = start;
	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return -ENOMEM;

	if (lwkpage_pmd_page(t))
		ptl = pmd_lock(mm, pmd);
	do {
		next = pmd_addr_end(addr, end);
		if (lwkpage_pmd_page(t)) {
			if (pmd_none(*pmd)) {
				if (unlikely(list_empty(list))) {
					spin_unlock(ptl);
					LWKMEM_ERROR("page list is empty");
					return -ENOMEM;
				}

				trace_mos_mm_pgtbl_map(TRACE_PMD, addr, next);
				page = list_first_entry(list, struct page, lru);
				list_del(&page->lru);
				prep_compound_page(page, lwkpage_order(t));
				lwkpage_add_rmap(page, vma, addr);
				entry = mk_pmd(page, vma->vm_page_prot);
				entry = pmd_clear_flags(entry, LWKPG_CLR_FLAGS);
				entry = pmd_mkwrite(entry);
				entry = pmd_mkhuge(entry);
				set_pmd_at(vma->vm_mm, addr, pmd, entry);
			}
		} else
			rc = lwk_mm_map_pte(pmd, vma, addr, next, list);
	} while (pmd++, addr = next, !rc && addr != end);

	if (lwkpage_pmd_page(t))
		spin_unlock(ptl);
	return rc;
}

int lwk_mm_map_pud(p4d_t *p4d, struct vm_area_struct *vma, unsigned long start,
		   unsigned long end, enum lwk_page_type t,
		   struct list_head *list)
{
	int rc = 0;
	pud_t *pud;
	pud_t entry;
	struct page *page;
	spinlock_t *ptl;
	unsigned long addr, next;
	struct mm_struct *mm = vma->vm_mm;

	addr = start;
	pud = pud_alloc(mm, p4d, addr);
	if (!pud)
		return -ENOMEM;

	if (lwkpage_pud_page(t))
		ptl = pud_lock(mm, pud);
	do {
		next = pud_addr_end(addr, end);
		if (lwkpage_pud_page(t)) {
			if (pud_none(*pud)) {
				if (unlikely(list_empty(list))) {
					spin_unlock(ptl);
					LWKMEM_ERROR("page list is empty");
					return -ENOMEM;
				}

				trace_mos_mm_pgtbl_map(TRACE_PUD, addr, next);
				page = list_first_entry(list, struct page, lru);
				list_del(&page->lru);
				prep_compound_page(page, lwkpage_order(t));
				lwkpage_add_rmap(page, vma, addr);
				entry = mk_pud(page, vma->vm_page_prot);
				entry = pud_clear_flags(entry, LWKPG_CLR_FLAGS);
				entry = pud_mkwrite(entry);
				entry = pud_mkhuge(entry);
				set_pud_at(vma->vm_mm, addr, pud, entry);
			}
		} else
			rc = lwk_mm_map_pmd(pud, vma, addr, next, t, list);
	} while (pud++, addr = next, !rc && addr != end);

	if (lwkpage_pud_page(t))
		spin_unlock(ptl);
	return rc;
}

int lwk_mm_map_p4d(pgd_t *pgd, struct vm_area_struct *vma, unsigned long start,
		   unsigned long end, enum lwk_page_type t,
		   struct list_head *list)
{
	int rc;
	p4d_t *p4d;
	unsigned long addr, next;

	addr = start;
	p4d = p4d_alloc(vma->vm_mm, pgd, addr);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);
		rc = lwk_mm_map_pud(p4d, vma, addr, next, t, list);
	} while (p4d++, addr = next, !rc && addr != end);

	return rc;
}

int lwk_mm_map_pages(struct vm_area_struct *vma, unsigned long start,
		     unsigned long end, enum lwk_page_type t,
		     struct list_head *list)
{
	int rc = -EINVAL;
	pgd_t *pgd;
	unsigned long addr, next;

	if (!vma || !vma->vm_mm || start >= end || !list ||
	    list_empty(list) || !valid_lwkpage_type(t))
		goto out;

	if (!IS_ALIGNED(start, lwkpage_size(t)) ||
	    !IS_ALIGNED(end, lwkpage_size(t))) {
		LWKMEM_WARN("Unaligned range");
		goto out;
	}

	trace_mos_mm_pgtbl_map_pages(start, end, t);

	addr = start;
	pgd = pgd_offset(vma->vm_mm, start);
	do {
		next = pgd_addr_end(addr, end);
		rc = lwk_mm_map_p4d(pgd, vma, addr, next, t, list);
	} while (pgd++, addr = next, !rc && addr != end);
out:
	if (rc) {
		LWKMEM_WARN("vma=%p mm=%p [%lx, %lx) t=%d listp=%p (%s) rc=%d",
			vma, vma ? vma->vm_mm : NULL, start, end, t, list,
			list && !list_empty(list) ? "non-empty" : "empty", rc);
	}
	return rc;
}

/*
 * Functions to unmap page table for a range of addresses within an LWK VMA
 */
static void lwk_mm_unmap_pte(struct vm_area_struct *vma, pmd_t *pmd,
			     unsigned long start, unsigned long end,
			     struct list_head (*list)[LWK_MAX_NUMPGTYPES])
{
	struct mm_struct *mm = vma->vm_mm;
	pte_t *pte, *start_pte;
	unsigned long addr;
	struct page *page;
	spinlock_t *ptl;

	addr = start;
	start_pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	pte = start_pte;
	trace_mos_mm_pgtbl_unmap(TRACE_PTE, start, end);

	do {
		if (pte_none(*pte) || !pte_present(*pte))
			continue;
		page = pte_page(*pte);
		clear_user_lwkpg(page, PAGE_SIZE, pte_dirty(*pte));
		list_add_tail(&page->lru, &(*list)[LWK_PG_4K]);
		pte_clear(mm, addr, pte);
	} while (pte++, addr = addr + PAGE_SIZE, addr != end);

	flush_tlb_mm_range(mm, start, end, PAGE_SHIFT, true);
	pte_unmap_unlock(start_pte, ptl);
}

static void lwk_mm_unmap_pmd(struct vm_area_struct *vma, pud_t *pud,
			     unsigned long start, unsigned long end,
			     struct list_head (*list)[LWK_MAX_NUMPGTYPES])
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long addr, next;
	pmd_t *pmd;
	struct page *page;
	spinlock_t *ptl;

	addr = start;
	pmd = pmd_offset(pud, addr);

	do {
		next = pmd_addr_end(addr, end);
retry:
		if (pmd_none(*pmd))
			continue;
		if (lwk_huge_pmd(pmd)) {
			ptl = pmd_lock(mm, pmd);
			if (!pmd_present(*pmd) || pmd_none(*pmd) ||
			    !lwk_huge_pmd(pmd)) {
				spin_unlock(ptl);
				goto retry;
			}

			trace_mos_mm_pgtbl_unmap(TRACE_PMD, addr, next);
			page = pmd_page(*pmd);
			clear_user_lwkpg(page, PMD_SIZE, pmd_dirty(*pmd));
			list_add_tail(&page->lru, &(*list)[LWK_PG_2M]);
			pmd_clear(pmd);
			flush_tlb_mm_range(mm, addr, next, PMD_SHIFT, true);
			spin_unlock(ptl);
		} else
			lwk_mm_unmap_pte(vma, pmd, addr, next, list);
	} while (pmd++, addr = next, addr != end);
}

static void lwk_mm_unmap_pud(struct vm_area_struct *vma, p4d_t *p4d,
			     unsigned long start, unsigned long end,
			     struct list_head (*list)[LWK_MAX_NUMPGTYPES])
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long addr, next;
	pud_t *pud;
	struct page *page;
	spinlock_t *ptl;

	addr = start;
	pud = pud_offset(p4d, addr);

	do {
		next = pud_addr_end(addr, end);
retry:
		if (pud_none(*pud))
			continue;
		if (lwk_huge_pud(pud)) {
			ptl = pud_lock(mm, pud);
			if (!pud_present(*pud) || pud_none(*pud) ||
			    !lwk_huge_pud(pud)) {
				spin_unlock(ptl);
				goto retry;
			}

			trace_mos_mm_pgtbl_unmap(TRACE_PUD, addr, next);
			page = pud_page(*pud);
			clear_user_lwkpg(page, PUD_SIZE, pud_dirty(*pud));
			list_add_tail(&page->lru, &(*list)[LWK_PG_1G]);
			pud_clear(pud);
			flush_tlb_mm_range(mm, addr, next, PUD_SHIFT, true);
			spin_unlock(ptl);
		} else
			lwk_mm_unmap_pmd(vma, pud, addr, next, list);
	} while (pud++, addr = next, addr != end);
}

static void lwk_mm_unmap_p4d(struct vm_area_struct *vma, pgd_t *pgd,
			     unsigned long start, unsigned long end,
			     struct list_head (*list)[LWK_MAX_NUMPGTYPES])
{
	unsigned long addr, next;
	p4d_t *p4d;

	addr = start;
	p4d = p4d_offset(pgd, addr);

	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(p4d))
			continue;
		lwk_mm_unmap_pud(vma, p4d, addr, next, list);
	} while (p4d++, addr = next, addr != end);
}

void lwk_mm_unmap_pages(struct vm_area_struct *vma,
			unsigned long start, unsigned long end)
{
	struct lwk_vma_private *vm_private;
	struct list_head list[LWK_MAX_NUMPGTYPES];
	struct lwk_mm *lwk_mm = vma ? vma_lwk_mm(vma) : 0;
	void *pma;
	unsigned long addr, next;
	enum lwk_page_type t;
	pgd_t *pgd;
	int rc, error = 0;

	start = ALIGN_DOWN(start, PAGE_SIZE);
	end = ALIGN(end, PAGE_SIZE);

	if (!lwk_mm || !lwk_mm->pma || !vma || !vma->vm_mm || start > end) {
		LWKMEM_ERROR("Invalid lwk_mm=%p pma=%p vma=%p mm=%p [%lx, %lx)",
			     lwk_mm, lwk_mm ? lwk_mm->pma : NULL,
			     vma, vma ? vma->vm_mm : NULL, start, end);
		return;
	}

	trace_mos_mm_pgtbl_unmap_pages(vma->vm_start, vma->vm_end, start, end,
				       vma->vm_flags);

	/* Unmap page table and TLB shootdown */
	pma = lwk_mm->pma;
	start = max(start, vma->vm_start);
	end = min(end, vma->vm_end);

	if (end <= start)
		return;

	/*
	 * For LWK heap actual address space mapped can be beyond vma end
	 * as we do not unmap pages when heap shrinks for performance
	 * optimization.
	 */
	if ((vma->vm_flags & VM_LWK_HEAP) && end == vma->vm_end) {
		vm_private = vma->vm_private_data;
		if (vm_private)
			end = max(end, vm_private->lwk_vm_end);
	}

	for_each_lwkpage_type(t)
		INIT_LIST_HEAD(&list[t]);
	addr = start;
	pgd = pgd_offset(vma->vm_mm, addr);

	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		lwk_mm_unmap_p4d(vma, pgd, addr, next, &list);
	} while (pgd++, addr = next, addr != end);

	/* Release pages to physical memory allocator */
	for_each_lwkpage_type_reverse(t) {
		if (!list_empty(&list[t])) {
			rc = lwk_mm->pm_ops->free_pages(pma, t, 0, 0, &list[t]);
			if (rc) {
				LWKMEM_ERROR("free %s pgs in [%lx, %lx) rc=%d",
					     lwkpage_desc(t), start, end, rc);
				error = 1;
			}
		}
	}

	if (error) {
		dump_lwkvma(vma);
		dump_stack();
	}
}

/*
 * Support for remaping part of the page table from old virtual address range to
 * the new virtual address range. We could have re-used Linux move_page_table()
 * with minor patches but unfortunately it does not support PUD size huge pages
 * yet. So we do something similar but with the consideration that there could
 * be PUD size pages in LWK VMAs.
 */
unsigned long lwk_mm_move_entire_pmd(pmd_t *old_pmd,
				     struct vm_area_struct *old_vma,
				     unsigned long old_addr,
				     struct vm_area_struct *new_vma,
				     unsigned long *new_addrp)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pmd_t pmd_entry;
	struct mm_struct *mm = old_vma->vm_mm;
	spinlock_t *old_ptl, *new_ptl;

	pgd = pgd_offset(mm, *new_addrp);

	p4d = p4d_alloc(mm, pgd, *new_addrp);
	if (!p4d) {
		LWKMEM_ERROR("Failed to allocate p4d");
		return old_addr;
	}

	pud = pud_alloc(mm, p4d, *new_addrp);
	if (!pud) {
		LWKMEM_ERROR("Failed to allocate pud");
		return old_addr;
	}

	pmd = pmd_alloc(mm, pud, *new_addrp);
	if (!pmd) {
		LWKMEM_ERROR("Failed to allocate pmd");
		return old_addr;
	}

	old_ptl = pmd_lockptr(mm, old_pmd);
	new_ptl = pmd_lockptr(mm, pmd);

	if (old_ptl != new_ptl)
		spin_lock_nested(new_ptl, SINGLE_DEPTH_NESTING);

	trace_mos_mm_pgtbl_move(TRACE_PMD, old_addr, *new_addrp, PMD_SIZE);
	pmd_entry = pmdp_huge_get_and_clear(mm, old_addr, old_pmd);
	set_pmd_at(mm, *new_addrp, pmd, pmd_entry);
	if (old_ptl != new_ptl)
		spin_unlock(new_ptl);

	*new_addrp += PMD_SIZE;
	return old_addr + PMD_SIZE;
}

unsigned long lwk_mm_move_entire_pud(pud_t *old_pud,
				     struct vm_area_struct *old_vma,
				     unsigned long old_addr,
				     struct vm_area_struct *new_vma,
				     unsigned long *new_addrp)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pud_t pud_entry;
	struct mm_struct *mm = old_vma->vm_mm;

	pgd = pgd_offset(mm, *new_addrp);
	p4d = p4d_alloc(mm, pgd, *new_addrp);
	if (!p4d) {
		LWKMEM_ERROR("Failed to allocate p4d");
		return old_addr;
	}

	pud = pud_alloc(mm, p4d, *new_addrp);
	if (!pud) {
		LWKMEM_ERROR("Failed to allocate pud");
		return old_addr;
	}

	/*
	 * There is no need to acquire PUD level lock yet as pud level lock
	 * is global page table lock of the process and its already taken
	 * while inspecting PUD that corresponds to @old_addr. If Linux
	 * implements split page table locks for PUD level then we need to
	 * revisit this code to ensure PUD corresponding to new_addr is also
	 * locked.
	 */
	trace_mos_mm_pgtbl_move(TRACE_PUD, old_addr, *new_addrp, PUD_SIZE);
	pud_entry = pudp_huge_get_and_clear(mm, old_addr, old_pud);
	set_pud_at(mm, *new_addrp, pud, pud_entry);
	*new_addrp += PUD_SIZE;
	return old_addr + PUD_SIZE;
}

static pte_t *get_new_pte(struct mm_struct *mm, unsigned long addr,
			  spinlock_t **ptl)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte = NULL;

	*ptl = NULL;
	pgd = pgd_offset(mm, addr);
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d) {
		LWKMEM_ERROR("Failed to allocate p4d");
		goto out;
	}

	pud = pud_alloc(mm, p4d, addr);
	if (!pud) {
		LWKMEM_ERROR("Failed to allocate pud");
		goto out;
	}

	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd) {
		LWKMEM_ERROR("Failed to allocate pmd");
		goto out;
	}

	pte = pte_alloc_map(mm, pmd, addr);
	if (!pte) {
		LWKMEM_ERROR("Failed to allocate pte");
		goto out;
	}
	*ptl = pte_lockptr(mm, pmd);
out:
	return pte;
}

unsigned long lwk_mm_move_pte(pmd_t *old_pmd, struct vm_area_struct *old_vma,
			      unsigned long old_addr, unsigned long old_end,
			      struct vm_area_struct *new_vma,
			      unsigned long *new_addrp)
{
	pte_t entry;
	bool flush_tlb = false;
	pte_t *old_pte, *old_pte_start;
	pte_t *new_pte, *new_pte_start;
	spinlock_t *old_ptl, *new_ptl;
	unsigned long new_next, new_end;
	unsigned long old_start = old_addr;
	struct mm_struct *mm = old_vma->vm_mm;

	if (old_start >= old_end)
		return old_addr;

	old_pte = pte_offset_map_lock(mm, old_pmd, old_start, &old_ptl);
	if (!old_pte || !old_ptl) {
		LWKMEM_ERROR("Failed to map old PMD at %#lx pmd=%p ptl=%p",
			     old_start, old_pmd, old_ptl);
		return old_addr;
	}
	old_pte_start = old_pte;

	trace_mos_mm_pgtbl_move(TRACE_PTE, old_addr, *new_addrp,
				old_end - old_start);
	new_next = *new_addrp;
	new_end = *new_addrp + (old_end - old_start);
	new_ptl = NULL;
	new_pte = new_pte_start = NULL;

	while (old_addr < old_end) {
		if (!pte_none(*old_pte) && pte_present(*old_pte)) {
			/*
			 * At PMD boundary in the new map we need to release the
			 * previously held page table lock if any and allocate
			 * new PMD and require lock in the new PMD page and
			 * reset @new_ptl and @new_pte_start pointers. Note that
			 * the '<' condition below catches the first pass here.
			 */
			if (new_next <= *new_addrp) {
				if (new_pte_start) {
					if (new_ptl != old_ptl)
						spin_unlock(new_ptl);
					pte_unmap(new_pte_start);
				}

				new_pte = get_new_pte(mm, *new_addrp, &new_ptl);
				new_pte_start = new_pte;
				if (!new_pte)
					break;
				if (new_ptl != old_ptl) {
					spin_lock_nested(new_ptl,
						SINGLE_DEPTH_NESTING);
				}
				new_next = pmd_addr_end(*new_addrp, new_end);
			}

			entry = ptep_get_and_clear(mm, old_addr, old_pte);
			entry = move_pte(entry, new_vma->vm_page_prot,
				       old_addr, *new_addrp);
			/* Coverity: Passing null pointer new_pte to set_pte_at, which dereferences it. */
			if (new_pte) {
				set_pte_at(mm, *new_addrp, new_pte, entry);
				flush_tlb = true;
			}
		}
		old_addr += PAGE_SIZE;
		*new_addrp += PAGE_SIZE;
		old_pte++;
		/* Coverity: Comparing new_pte to null implies that new_pte might be null. */
		if (new_pte)
			new_pte++;
	}

	if (new_pte_start) {
		if (new_ptl != old_ptl)
			spin_unlock(new_ptl);
		pte_unmap(new_pte_start);
	}

	if (flush_tlb)
		flush_tlb_mm_range(mm, old_start, old_end, PAGE_SHIFT, true);
	pte_unmap_unlock(old_pte_start, old_ptl);
	return old_addr;
}

unsigned long lwk_mm_move_pmd(pud_t *pud, struct vm_area_struct *old_vma,
			      unsigned long old_addr, unsigned long old_end,
			      struct vm_area_struct *new_vma,
			      unsigned long *new_addrp)
{
	pmd_t *pmd;
	spinlock_t *ptl;
	unsigned long map_next;
	unsigned long old_next;
	struct mm_struct *mm = old_vma->vm_mm;

	pmd = pmd_offset(pud, old_addr);

	do {
		old_next = pmd_addr_end(old_addr, old_end);
retry:
		if (pmd_none(*pmd) || !pmd_present(*pmd)) {
			map_next = old_next;
			continue;
		}

		if (lwk_huge_pmd(pmd)) {
			ptl = pmd_lock(mm, pmd);

			if (pmd_none(*pmd) || !pmd_present(*pmd) ||
			    !lwk_huge_pmd(pmd)) {
				spin_unlock(ptl);
				goto retry;
			}

			/* Can it be huge pmd in both old and new map? */
			if ((old_addr & ~PMD_MASK) == 0 &&
			    (old_next & ~PMD_MASK) == 0 &&
			    (*new_addrp & ~PMD_MASK) == 0) {
				map_next = lwk_mm_move_entire_pmd(pmd, old_vma,
							old_addr, new_vma,
							new_addrp);
				flush_tlb_mm_range(mm, old_addr, old_next,
						   PMD_SHIFT, true);
				spin_unlock(ptl);
				continue;
			}
			lwk_mm_split_pmd_locked(old_vma, pmd,
						old_addr & PMD_MASK);
			spin_unlock(ptl);
		}

		/*
		 * At this point the PMD is not a huge PMD instead is a normal
		 * PMD that hold PTEs. For normal PMD we can move the entire PMD
		 * if the given range [@old_addr, @old_next) covers the entire
		 * PMD range.
		 */
		if ((old_addr & ~PMD_MASK) == 0 &&
		    (old_next & ~PMD_MASK) == 0 &&
		    (*new_addrp & ~PMD_MASK) == 0) {
			ptl = pmd_lock(mm, pmd);
			if (pmd_none(*pmd) || !pmd_present(*pmd)) {
				map_next = old_next;
				spin_unlock(ptl);
				continue;
			}
			map_next = lwk_mm_move_entire_pmd(pmd, old_vma,
					old_addr, new_vma, new_addrp);
			flush_tlb_mm_range(mm, old_addr, old_next,
					   PAGE_SHIFT, true);
			spin_unlock(ptl);
			continue;
		}
		map_next = lwk_mm_move_pte(pmd, old_vma, old_addr, old_next,
					   new_vma, new_addrp);
	} while (pmd++, old_addr = old_next,
		 old_addr != old_end && old_addr == map_next);
	return map_next;
}

unsigned long lwk_mm_move_pud(p4d_t *p4d, struct vm_area_struct *old_vma,
			      unsigned long old_addr, unsigned long old_end,
			      struct vm_area_struct *new_vma,
			      unsigned long *new_addrp)
{
	pud_t *pud;
	spinlock_t *ptl;
	unsigned long map_next;
	unsigned long old_next;
	struct mm_struct *mm = old_vma->vm_mm;

	pud = pud_offset(p4d, old_addr);
	map_next = old_addr;

	do {
		old_next = pud_addr_end(old_addr, old_end);
retry:
		if (pud_none(*pud) || !pud_present(*pud)) {
			map_next = old_next;
			continue;
		}

		if (lwk_huge_pud(pud)) {
			ptl = pud_lock(mm, pud);
			if (pud_none(*pud) || !pud_present(*pud) ||
			    !lwk_huge_pud(pud)) {
				spin_unlock(ptl);
				goto retry;
			}

			/* Can it be huge pud in both old and new map? */
			if ((old_addr & ~PUD_MASK) == 0 &&
			    (old_next & ~PUD_MASK) == 0 &&
			    (*new_addrp & ~PUD_MASK) == 0) {
				map_next = lwk_mm_move_entire_pud(pud, old_vma,
							old_addr, new_vma,
							new_addrp);
				flush_tlb_mm_range(mm, old_addr, old_next,
						   PUD_SHIFT, true);
				spin_unlock(ptl);
				continue;
			}
			lwk_mm_split_pud_locked(old_vma, pud,
						old_addr & PUD_MASK);
			spin_unlock(ptl);
		}

		/*
		 * At this point the PUD is not a huge PUD instead is a normal
		 * PUD that hold PMDs. For normal PUD we can move the entire PUD
		 * if the given range [@old_addr, @old_next) covers the entire
		 * PUD range.
		 */
		if ((old_addr & ~PUD_MASK) == 0 &&
		    (old_next & ~PUD_MASK) == 0 &&
		    (*new_addrp & ~PUD_MASK) == 0) {
			ptl = pud_lock(mm, pud);
			if (pud_none(*pud) || !pud_present(*pud)) {
				map_next = old_next;
				spin_unlock(ptl);
				continue;
			}
			map_next = lwk_mm_move_entire_pud(pud, old_vma,
					old_addr, new_vma, new_addrp);
			flush_tlb_mm_range(mm, old_addr, old_next,
					   PMD_SHIFT, true);
			spin_unlock(ptl);
			continue;
		}
		map_next = lwk_mm_move_pmd(pud, old_vma, old_addr, old_next,
					   new_vma, new_addrp);
	} while (pud++, old_addr = old_next,
		 old_addr != old_end && old_addr == map_next);
	return map_next;
}

unsigned long lwk_mm_move_p4d(pgd_t *pgd, struct vm_area_struct *old_vma,
			      unsigned long old_addr, unsigned long old_end,
			      struct vm_area_struct *new_vma,
			      unsigned long *new_addrp)
{
	p4d_t *p4d;
	unsigned long map_next;
	unsigned long old_next;

	p4d = p4d_offset(pgd, old_addr);
	map_next = old_addr;

	do {
		old_next = p4d_addr_end(old_addr, old_end);
		if (p4d_none_or_clear_bad(p4d)) {
			map_next = old_next;
			continue;
		}

		map_next = lwk_mm_move_pud(p4d, old_vma, old_addr, old_next,
					   new_vma, new_addrp);
	} while (p4d++, old_addr = old_next,
		 old_addr != old_end && old_addr == map_next);
	return map_next;
}

unsigned long lwk_mm_move_page_tables(struct vm_area_struct *old_vma,
				      unsigned long old_start,
				      struct vm_area_struct *new_vma,
				      unsigned long new_start,
				      unsigned long len)
{
	unsigned long old_addr, old_end, old_next;
	unsigned long new_addr, map_next;
	pgd_t *pgd;

	trace_mos_mm_pgtbl_move_enter(old_vma->vm_start, old_vma->vm_end,
		old_start, new_vma->vm_start, new_vma->vm_end, new_start,
		len, 0);

	if (unlikely(!old_vma || !new_vma || !len ||
	    old_start == new_start || !IS_ALIGNED(len, PAGE_SIZE))) {
		LWKMEM_WARN("-EINVAL, old %p new %p os %lx ns %lx len %lx",
			    old_vma, new_vma, old_start, new_start, len);
		return 0;
	}

	old_addr = old_start;
	new_addr = new_start;
	old_end = old_start + len;

	if (unlikely(old_start > old_end || new_start > (new_start + len))) {
		LWKMEM_WARN("Overflow, os %lx ns %lx len %lx",
			    old_start, new_start, len);
		return 0;
	}

	pgd = pgd_offset(old_vma->vm_mm, old_addr);
	map_next = old_addr;

	do {
		old_next = pgd_addr_end(old_addr, old_end);
		if (pgd_none_or_clear_bad(pgd)) {
			map_next = old_next;
			continue;
		}
		map_next = lwk_mm_move_p4d(pgd, old_vma, old_addr, old_next,
					   new_vma, &new_addr);
	} while (pgd++, old_addr = old_next,
		 old_addr != old_end && old_addr == map_next);

	trace_mos_mm_pgtbl_move_exit(old_vma->vm_start, old_vma->vm_end,
		old_start, new_vma->vm_start, new_vma->vm_end, new_start,
		len, map_next - old_start);
	/*
	 * If we are moving pagetable maps across two VMAs then this is
	 * triggered from an mremap() to new VMA, so we need to set the
	 * LWK VMA allocated range markers in the new VMA by looking up
	 * those from old VMA's LWK private data.
	 */
	if (new_vma != old_vma && map_next > old_start)
		lwk_mm_copy_mapped_range(old_vma, old_start, map_next, new_vma);

	return map_next - old_start;
}
