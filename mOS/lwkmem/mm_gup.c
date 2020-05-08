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
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/mos.h>
#include <trace/events/lwkmem.h>

/* Private headers */
#include "lwk_mm_private.h"

#define no_page_table(flags) (flags & FOLL_DUMP ? ERR_PTR(-EFAULT) : NULL)

/*
 * Remove the definition of FOLL_SPLIT_PMD when moving to kernel version 5.4
 * and beyond. This macro was defined when backporting from 5.6 to 5.3 sles sp2
 * kernel where the macro is not defined by Linux.
 */
#define FOLL_SPLIT_PMD 0x20000

static struct page *lwk_mm_follow_pte_mask(struct vm_area_struct *vma,
					   unsigned long address, pmd_t *pmd,
					   unsigned int flags)
{
	pte_t *pte;
	spinlock_t *ptl;
	struct page *page;
	struct mm_struct *mm = vma->vm_mm;

retry:
	pte = pte_offset_map_lock(mm, pmd, address, &ptl);
	if (pte_none(*pte))
		goto no_page;

	if (!pte_present(*pte)) {
		swp_entry_t entry;

		if (likely(!(flags & FOLL_MIGRATION)))
			goto no_page;
		entry = pte_to_swp_entry(*pte);
		if (!is_migration_entry(entry))
			goto no_page;
		pte_unmap_unlock(pte, ptl);
		migration_entry_wait(mm, pmd, address);
		goto retry;
	}
	page = pte_page(*pte);
	pte_unmap_unlock(pte, ptl);
	return page;
no_page:
	pte_unmap_unlock(pte, ptl);
	return no_page_table(flags);
}

static struct page *lwk_mm_follow_pmd_mask(struct vm_area_struct *vma,
					   unsigned long address, pud_t *pud,
					   unsigned int flags,
					   unsigned int *page_mask)
{
	pmd_t *pmd, pmdval;
	spinlock_t *ptl;
	unsigned long offset;
	unsigned long npages;
	struct page *page;

	pmd = pmd_offset(pud, address);
retry:
	pmdval = READ_ONCE(*pmd);
	if (pmd_none(pmdval))
		return no_page_table(flags);
	if (!pmd_present(pmdval)) {
		if (likely(!(flags & FOLL_MIGRATION)))
			return no_page_table(flags);
		if (is_pmd_migration_entry(pmdval))
			pmd_migration_entry_wait(vma->vm_mm, pmd);
		goto retry;
	}

	if (lwk_huge_pmd(&pmdval)) {
		ptl = pmd_lock(vma->vm_mm, pmd);
		if (unlikely(!pmd_present(*pmd) || !lwk_huge_pmd(pmd))) {
			spin_unlock(ptl);
			goto retry;
		}

		if (flags & FOLL_SPLIT_PMD) {
			lwk_mm_split_pmd_locked(vma, pmd, address);
			spin_unlock(ptl);
		} else {
			page = pmd_page(*pmd);
			offset = bytes_to_pages(address & (PMD_SIZE - 1));
			page = page + offset;
			if (page_mask) {
				npages = 1UL << (PMD_SHIFT - PAGE_SHIFT);
				*page_mask = npages - 1;
			}
			spin_unlock(ptl);
			return page;
		}
	}

	if (page_mask)
		*page_mask = 0;
	return lwk_mm_follow_pte_mask(vma, address, pmd, flags);
}

static struct page *lwk_mm_follow_pud_mask(struct vm_area_struct *vma,
					   unsigned long address, p4d_t *p4d,
					   unsigned int flags,
					   unsigned int *page_mask)
{
	pud_t *pud;
	pmd_t *pmd;
	struct page *page;
	unsigned long offset;
	unsigned long npages;
	spinlock_t *ptl;

	pud = pud_offset(p4d, address);
retry:
	if (pud_none(*pud))
		return no_page_table(flags);

	if (lwk_huge_pud(pud)) {
		ptl = pud_lock(vma->vm_mm, pud);
		if (!lwk_huge_pud(pud)) {
			spin_unlock(ptl);
			goto retry;
		}

		/*
		 * For now we interpret FOLL_SPLIT_PMD as instruction to split
		 * PUD size huge page too till Linux THP adds PUD page support
		 * and eventually corresponding macro FOLL_SPLIT_PUD
		 */
		if (flags & FOLL_SPLIT_PMD) {
			lwk_mm_split_pud_locked(vma, pud, address);
			pmd = pmd_offset(pud, address);
			lwk_mm_split_pmd_locked(vma, pmd, address);
			spin_unlock(ptl);
		} else {
			page = pud_page(*pud);
			offset = bytes_to_pages(address & (PUD_SIZE - 1));
			page = page + offset;

			if (page_mask) {
				npages = 1UL << (PUD_SHIFT - PAGE_SHIFT);
				*page_mask = npages - 1;
			}
			spin_unlock(ptl);
			return page;
		}
	}
	return lwk_mm_follow_pmd_mask(vma, address, pud, flags, page_mask);
}

static struct page *lwk_mm_follow_p4d_mask(struct vm_area_struct *vma,
					   unsigned long address, pgd_t *pgd,
					   unsigned int flags,
					   unsigned int *page_mask)
{
	p4d_t *p4d = p4d_offset(pgd, address);

	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
		return no_page_table(flags);
	return lwk_mm_follow_pud_mask(vma, address, p4d, flags, page_mask);
}

struct page *lwk_mm_follow_page(struct vm_area_struct *vma,
				unsigned long address, unsigned int flags,
				unsigned int *page_mask)
{
	pgd_t *pgd = pgd_offset(vma->vm_mm, address);

	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return no_page_table(flags);

	return lwk_mm_follow_p4d_mask(vma, address, pgd, flags, page_mask);
}

