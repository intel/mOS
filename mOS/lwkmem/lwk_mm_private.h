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

#ifndef __LWK_MM_PRIVATE_H__
#define __LWK_MM_PRIVATE_H__

#include <linux/list.h>
#include <linux/mm.h>

#undef pr_fmt
#define pr_fmt(fmt)		"mOS-mem: " fmt
#define kaddr_to_pfn(va)        (__pa(va) >> PAGE_SHIFT)
#define pages_to_bytes(val)	(((unsigned long)(val)) << PAGE_SHIFT)
#define bytes_to_pages(val)	(((unsigned long)(val)) >> PAGE_SHIFT)

/*****************************************************************************/
/* LWK memory(mm + pma + sysfs + yodopts + init) functionality               */
/*****************************************************************************/

/* Structures used to track physical memory designated to LWK.
 *
 * lwkmem_designated[NID]  lwkmem_granule         lwkmem_granule
 *       +--------------+  +-----------------+    +-----------------+
 *       | list         |->| list_designated |--->| list_designated |
 *       | n_resv_pages |  | list_reserved   |    | list_reserved   |
 *       | n_free_pages |  | base            |    | base            |
 *       +--------------+  | length          |    | length          |
 *                         | owner           |    | owner           |
 *                         +-----------------+    +-----------------+
 */
struct lwkmem_designated {
	struct list_head list;
	/* Free/reserved memory in terms of number of 4k pages */
	unsigned long n_resv_pages;
	unsigned long n_free_pages;
};

struct lwkmem_granule {
	struct list_head list_designated;/* In LWK designated memory list   */
	struct list_head list_reserved;  /* In process reserved memory list */
	void *base; /* Kernel virtual address of start of physical memory   */
	unsigned long length;   /* Size of physcal memory being tracked     */
	pid_t owner;            /* -1 for free, pid for reserved            */
};

extern void lwkmem_yod_options_init(void);
extern void lwkmem_yod_options_set_default(void);
extern void lwkmem_page_init(struct page *p);
extern void lwkmem_page_deinit(struct page *p);

/*****************************************************************************/
/* LWK mm auxilary functionality                                             */
/*****************************************************************************/

/*
 * Bits cleared for an LWK page table entry. Soft dirty bit mask is 0 when the
 * CONFIG_MEM_SOFT_DIRTY is not enabled, so we should be fine here, a | 0 = a
 *
 * LWK pages are RWE by default so clear _PAGE_NX
 */
#define LWKPG_CLR_FLAGS	(_PAGE_PWT | _PAGE_PCD | _PAGE_NX | \
			 _PAGE_DIRTY | _PAGE_SOFT_DIRTY | _PAGE_PSE)

/* Till Linux define this macro for PUD level we cover it here. */
#ifndef mk_pud
#define mk_pud(page, prot)	pfn_pud(page_to_pfn(page), (prot))
#endif
#define lwkpage_pud_page(k)	((k) == LWK_PG_1G)
#define lwkpage_pmd_page(k)	((k) == LWK_PG_2M)
#define lwk_huge_pmd(pmd)	((pmd_val(*pmd) & _PAGE_PSE) != 0)
#define lwk_huge_pud(pud)	((pud_val(*pud) & _PAGE_PSE) != 0)

#define lwkpage_desc(t)		lwkpage_attrs[t].desc
#define lwkpage_size(t) 	lwkpage_attrs[t].size
#define lwkpage_order(t)	lwkpage_attrs[t].order

struct lwkpage_attributes {
	char *desc;
	int order;
	unsigned long size;
};

extern struct lwkpage_attributes lwkpage_attrs[LWK_MAX_NUMPGTYPES];
extern char *lwk_pmas_name[LWK_PMA_MAX];
extern char *lwk_vmrs_name[LWK_MAX_NUMVMRTYPES];

/*  Exports from mOS/lwkmem/mm.c */
extern void dump_lwkvma(const struct vm_area_struct *vma);
extern int lwk_mm_set_mempolicy_info(const char *buff, size_t size);
extern void lwk_mm_copy_mapped_range(struct vm_area_struct *old_vma,
			unsigned long old_start, unsigned long old_end,
			struct vm_area_struct *new_vma);

/* Exports from mOS/lwkmem/mm_mempolicy.c */
extern int lwk_mm_map_range(struct vm_area_struct *vma, unsigned long start,
			unsigned long end);
extern enum lwk_vmr_type lwk_mm_vmflags_to_vmr(unsigned long vm_flags);
extern void dump_lwk_mempolicy_vmr(struct lwk_mm *lwk_mm, enum lwk_vmr_type v);
extern void dump_lwk_mempolicy(struct vm_area_struct *vma);

/* Exports from mOS/lwkmem/mm_pagetable.c */
extern int lwk_mm_map_pages(struct vm_area_struct *vma, unsigned long start,
			unsigned long end, enum lwk_page_type t,
			struct list_head *list);
extern void lwk_mm_unmap_pages(struct vm_area_struct *vma, unsigned long start,
			unsigned long end);
extern void lwk_mm_split_pud(struct vm_area_struct *vma, unsigned long address);
extern void lwk_mm_split_pmd(struct vm_area_struct *vma, unsigned long address);
extern void lwk_mm_split_pud_locked(struct vm_area_struct *vma, pud_t *pud,
			unsigned long address);
extern void lwk_mm_split_pmd_locked(struct vm_area_struct *vma, pmd_t *pmd,
			unsigned long address);
extern unsigned long lwk_mm_move_page_tables(struct vm_area_struct *old_vma,
			unsigned long old_start,
			struct vm_area_struct *new_vma,
			unsigned long new_start,
			unsigned long len);

/* Exports from mOS/lwkmem/mm_protection.c */
extern unsigned long lwk_mm_change_protection(struct vm_area_struct *vma,
			unsigned long start, unsigned long end,
			pgprot_t newprot);

/* Exports from mOS/lwkmem/mm_gup.c */
extern struct page *lwk_mm_follow_page(struct vm_area_struct *vma,
			unsigned long address, unsigned int flags,
			unsigned int *page_mask);

/* Declared by internal header mm/internal.h, so we declare manually here.  */
extern void prep_compound_page(struct page *page, unsigned int order);

#endif //__LWK_MM_PRIVATE_H__
