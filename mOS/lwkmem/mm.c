/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016-2020 Intel Corporation.
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

#include <linux/printk.h>
#include <linux/rmap.h>
#include <linux/highmem.h>
#include <linux/mos.h>
#define CREATE_TRACE_POINTS
#include <trace/events/lwkmem.h>

/* Private headers */
#include "lwk_mm_private.h"

#define MAP_TSTACK_FLAGS (MAP_STACK | MAP_NORESERVE)

/* Global LWK page attributes */
struct lwkpage_attributes lwkpage_attrs[LWK_MAX_NUMPGTYPES] = {
	[LWK_PG_4K] = { "4k", 0, SZ_4K },
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
	[LWK_PG_2M] = { "2m", 9, SZ_2M },
#else
	[LWK_PG_4M] = { "4m", 10, SZ_4M },
#endif
	[LWK_PG_1G] = { "1g", 18, SZ_1G },
};

char *lwk_pmas_name[LWK_PMA_MAX] = {
	[LWK_BUDDY_ALLOCATOR]	= "buddy",
};

char *lwk_vmrs_name[LWK_MAX_NUMVMRTYPES] = {
	[LWK_VMR_DBSS]		= "dbss",
	[LWK_VMR_HEAP]		= "heap",
	[LWK_VMR_ANON_PRIVATE]	= "anon_private",
	[LWK_VMR_TSTACK]	= "tstack",
	[LWK_VMR_STACK]		= "stack",
};

/* Global variable static to mm */
static unsigned long lwk_mm_id;

static struct {
	struct lwk_pm_factory_operations *factory_ops;
	struct lwk_pm_operations *pm_ops;
} pm_registered_ops[LWK_PMA_MAX];

/* Forward declarations */
static void lwk_mm_adjust_mapped_range(struct vm_area_struct *vma,
				       unsigned long vm_start,
				       unsigned long vm_end);

void dump_lwkvma(const struct vm_area_struct *vma)
{
	LWKMEM_WARN("vma %px start %px end %px\n"
		"next %px prev %px mm %px\n"
		"prot %lx anon_vma %px vm_ops %px\n"
		"pgoff %lx file %px private_data %px\n"
		"flags: %#lx(%pGv)",
		vma, (void *)vma->vm_start, (void *)vma->vm_end, vma->vm_next,
		vma->vm_prev, vma->vm_mm,
		(unsigned long)pgprot_val(vma->vm_page_prot),
		vma->anon_vma, vma->vm_ops, vma->vm_pgoff,
		vma->vm_file, vma->vm_private_data,
		vma->vm_flags, &vma->vm_flags);
}

/*
 * Virtual memory operations
 */
static unsigned long lwk_mm_get_unmapped_area(struct file *file,
					      unsigned long addr,
					      unsigned long len,
					      unsigned long pgoff,
					      unsigned long flags)
{
	unsigned long rval, size;
	unsigned long hint;
	struct lwk_mm *lwk_mm = curr_lwk_mm();

	if (len < PMD_SIZE || flags & (MAP_FIXED | MAP_FIXED_NOREPLACE))
		goto fallback;

	if (!lwk_mm)
		goto fallback;

	/* Do nothing if the LWK VMR is disabled */
	if ((flags & MAP_TSTACK_FLAGS) &&
	    lwk_mm->policy[LWK_VMR_TSTACK].disabled)
		goto fallback;
	else if (lwk_mm->policy[LWK_VMR_ANON_PRIVATE].disabled)
		goto fallback;

	if (len >= PUD_SIZE)
		size = PUD_SIZE;
	else
		size = PMD_SIZE;

	/*
	 * Ignore address hint and prioritize alignment if address hint
	 * unaligned.
	 */
	hint = addr && IS_ALIGNED(addr, size) ? addr : 0;
	rval = current->mm->get_unmapped_area(file, hint, len + size,
					      pgoff, flags);
	if (IS_ERR_VALUE(rval))
		goto fallback;

	return ALIGN(rval, size);

fallback:
	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}

static int lwk_mm_alloc_pages_vma(struct vm_area_struct *vma,
				  unsigned long start, unsigned long end)
{
	int rc;
	enum lwk_page_type tmax, tcurr;
	struct lwk_mm *lwk_mm = vma_lwk_mm(vma);
	struct lwk_vma_private *vma_private = vma->vm_private_data;

	/* Page align start and end */
	start = ALIGN_DOWN(start, PAGE_SIZE);

	if (vma->vm_flags & VM_LWK_HEAP) {
		tmax = lwk_mm->policy[LWK_VMR_HEAP].max_page;
		for_each_lwkpage_type_reverse_from(tcurr, tmax) {
			/* Align @end to heap page size boundary */
			end = ALIGN(end, lwkpage_size(tcurr));
			/*
			 * If heap end overflows with this page size
			 * then try next lower page size.
			 */
			if (vma->vm_next &&
			    (end + PAGE_SIZE) > vm_start_gap(vma->vm_next))
				continue;
			break;
		}
	} else
		end = ALIGN(end, PAGE_SIZE);

	if (end <= start)
		return -EINVAL;
	if (start < vma->vm_start)
		return -EINVAL;
	if (!(vma->vm_flags & VM_LWK_HEAP) && end > vma->vm_end)
		return -EINVAL;

	trace_mos_mm_alloc_pages_vma(vma->vm_start, vma->vm_end, start, end,
				     vma->vm_flags);
	rc = lwk_mm_map_range(vma, start, end);
	if (rc) {
		LWKMEM_ERROR("rc=%d failed to allocate memory for [%lx, %lx)",
			     rc, start, end);
		dump_lwkvma(vma);
	} else {
		if (start < vma_private->lwk_vm_start)
			vma_private->lwk_vm_start = start;
		if (end > vma_private->lwk_vm_end)
			vma_private->lwk_vm_end = end;
	}
	return rc;
}

static vm_fault_t lwk_mm_page_fault(struct vm_area_struct *vma,
				    unsigned long address, unsigned long flags)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	int rc = 0;
	unsigned long start, end;
	struct lwk_vma_private *vma_private = vma->vm_private_data;
	struct lwk_mm *lwk_mm = vma_lwk_mm(vma);

	down_write(&vma_private->vma_sem);

	trace_mos_mm_page_fault(vma->vm_start, vma->vm_end,
		vma_private->lwk_vm_start, vma_private->lwk_vm_end,
		address, flags);

	pgd = pgd_offset(vma->vm_mm, address);

	if (pgd_none(*pgd))
		goto allocate;
	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d))
		goto allocate;
	pud = pud_offset(p4d, address);
	if (pud_none(*pud))
		goto allocate;
	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		goto allocate;
	pte = pte_offset_map(pmd, address);
	if (pte_none(*pte))
		goto allocate;
	/* The pages are already allocated by a racing thread */
	goto out;

	trace_mos_mm_page_fault_pagetbl(address, flags,
		pud_val(*pud), pmd_val(*pmd), pte_val(*pte));
allocate:
	rc = anon_vma_prepare(vma);
	if (rc) {
		LWKMEM_ERROR("[%lx, %lx)-[%lx, %lx) %lx anon_vma_prepare rc=%d",
			vma->vm_start, vma->vm_end,
			vma_private->lwk_vm_start,
			vma_private->lwk_vm_end,
			vma->vm_flags, rc);
		goto out;
	}

	/* Is this the first fault in the VMA? */
	if (likely(vma_private->lwk_vm_start >= vma_private->lwk_vm_end)) {
		start = vma->vm_start;
		end = vma->vm_end;
		rc =  lwk_mm->vm_ops->alloc_pages_vma(vma, start, end);
		if (rc) {
			LWKMEM_ERROR("[%lx, %lx)-[%lx, %lx) %lx alloc1 rc=%d",
				vma->vm_start, vma->vm_end,
				vma_private->lwk_vm_start,
				vma_private->lwk_vm_end,
				vma->vm_flags, rc);
			goto out;
		}
		goto out;
	}

	/* Was vm_start expanded? */
	if (vma->vm_start < vma_private->lwk_vm_start) {
		start = vma->vm_start;
		end = vma_private->lwk_vm_start;
		rc = lwk_mm->vm_ops->alloc_pages_vma(vma, start, end);
		if (rc) {
			LWKMEM_ERROR("[%lx, %lx)-[%lx, %lx) %lx alloc2 rc=%d",
				vma->vm_start, vma->vm_end,
				vma_private->lwk_vm_start,
				vma_private->lwk_vm_end,
				vma->vm_flags, rc);
			goto out;
		}
	}

	/* Was vm_end expanded? */
	if (vma->vm_end > vma_private->lwk_vm_end) {
		start = vma_private->lwk_vm_end;
		end = vma->vm_end;
		rc = lwk_mm->vm_ops->alloc_pages_vma(vma, start, end);
		if (rc) {
			LWKMEM_ERROR("[%lx, %lx)-[%lx, %lx) %lx alloc3 rc=%d",
				vma->vm_start, vma->vm_end,
				vma_private->lwk_vm_start,
				vma_private->lwk_vm_end,
				vma->vm_flags, rc);
			goto out;
		}
	}
out:
	up_write(&vma_private->vma_sem);

	if (rc) {
		/* There is no OOM killer for LWK Memory. */
		force_sig(SIGKILL);
	}
	return 0;
}

static inline bool may_need_tlb_split(struct vm_area_struct *vma,
				      unsigned long addr,
				      unsigned long page_mask,
				      unsigned long page_size)
{
	if (addr & ~page_mask &&
	    (addr & page_mask) >= vma->vm_start &&
	    (addr & page_mask) + page_size <= vma->vm_end)
		return true;
	return false;
}

static void lwk_mm_vma_adjust(struct vm_area_struct *vma, unsigned long start,
			      unsigned long end)
{
	/*
	 * Do not adjust LWK heap as the real heap (physical) only grows
	 * and only the VMA shrinks and grows. This VMA adjust is triggered
	 * from general VMA adjust, mremap (copy_vma) and split VMA. Later
	 * two cases never occur for heap.
	 */
	if (vma->vm_flags & VM_LWK_HEAP)
		return;

	lwk_mm_adjust_mapped_range(vma, start, end);

	if (vma->vm_start != start) {
		if (may_need_tlb_split(vma, start, PUD_MASK, PUD_SIZE))
			lwk_mm_split_pud(vma, start);
		else if (may_need_tlb_split(vma, start, PMD_MASK, PMD_SIZE))
			lwk_mm_split_pmd(vma, start);
	}

	if (vma->vm_end != end) {
		if (may_need_tlb_split(vma, end, PUD_MASK, PUD_SIZE))
			lwk_mm_split_pud(vma, end);
		else if (may_need_tlb_split(vma, end, PMD_MASK, PMD_SIZE))
			lwk_mm_split_pmd(vma, end);
	}
}

static bool lwk_mm_vma_populated(struct vm_area_struct *vma)
{
	struct lwk_vma_private *private = vma->vm_private_data;

	return private && private->lwk_vm_end > private->lwk_vm_start;
}

static int lwk_mm_fork(struct vm_area_struct *old_vma,
		       struct vm_area_struct *new_vma)
{
	unsigned long addr, end = old_vma->vm_end;
	unsigned long min_flt, maj_flt;
	struct page *src_page, *dst_page;
	long ret;

	/*
	 * Since child of LWK process is not an LWK process, this
	 * copied VMA is not an LWK VMA.
	 */
	vma_clear_lwkvma(new_vma);

	/*
	 * Save the counters which are affected by the side effects
	 * from below inevitable actions. See notes below.
	 */
	min_flt = current->min_flt;
	maj_flt = current->maj_flt;

	for (addr = old_vma->vm_start; addr < end; addr += PAGE_SIZE) {
		/* Get the old page from parent process i.e. caller */
		ret = get_user_pages(addr, 1, 0, &src_page, NULL);

		if (ret == 0)
			continue;
		if (ret < 0) {
			LWKMEM_ERROR("Could not get src page at: %#lx rc %ld",
				     addr, ret);
			return ret;
		}

		/*
		 * Get the new page from the child process. Since we do not
		 * have a nice way of obtaining the pointer to child process
		 * task struct at the point of interception in Linux without
		 * patching main interfaces of Linux like dup_mmap() we are
		 * going to call remote version of gup with mm of child
		 * process but task struct of parent i.e. first argument set
		 * to NULL. The only side effect of this is that two counters
		 * of parent task struct i.e. maj_flt and min_flt is updated
		 * with the number of pages newly faulted in or populated
		 * in the child when below call is made. We negate this
		 * accounting at the very end in the parent process once we
		 * are done copying all the pages by saving and restoring
		 * these counters in the parent process. This works because
		 * there won't be any concurrent faults racing with us to
		 * modify these counters at this point in the parent as the
		 * caller already took write side mmap_sem before calling us.
		 */
		ret = get_user_pages_remote(new_vma->vm_mm, addr, 1,
					    FOLL_WRITE | FOLL_POPULATE,
					    &dst_page, NULL, NULL);
		if (ret <= 0) {
			LWKMEM_ERROR("Could not get dst page at: %#lx rc %ld",
				     addr, ret);
			if (ret == 0)
				ret = -ENOMEM;
			return ret;
		}

		/* Copy memory contents from parent's page to child's page */
		copy_user_highpage(dst_page, src_page, addr, old_vma);
		/* No reference counts for LWK pages yet */
		put_page(dst_page);
	}

	/* Restore counters in the parent */
	current->min_flt = min_flt;
	current->maj_flt = maj_flt;
	return 0;
}

static void lwk_mm_clear_heap(struct vm_area_struct *vma, unsigned long oldbrk,
			      unsigned long newbrk)
{
	long clear_len;
	struct lwk_vma_private *vma_private;
	struct lwk_mm *lwk_mm = vma_lwk_mm(vma);

	if (!lwk_mm || !lwk_mm->brk_clear_len || newbrk <= oldbrk)
		return;

	vma_private = vma->vm_private_data;
	if (!vma_private) {
		LWKMEM_ERROR("Invalid private pointer, old %#lx new %#lx",
			     oldbrk, newbrk);
		dump_lwkvma(vma);
		return;
	}

	if (lwk_mm_vma_populated(vma) && vma_private->lwk_vm_end > oldbrk) {
		clear_len = min(newbrk, vma_private->lwk_vm_end) - oldbrk;
		if (lwk_mm->brk_clear_len > 0)
			clear_len = min(clear_len, lwk_mm->brk_clear_len);

		if (clear_len && clear_user((void *) oldbrk, clear_len)) {
			LWKMEM_WARN(" Failed to clear heap at %#lx [%ld]",
				    oldbrk, clear_len);
		}
	}
}

unsigned long lwk_mm_elf_map(unsigned long map_start, unsigned long map_size,
			     struct file *filep, unsigned long offset,
			     unsigned long addr, unsigned long size,
			     unsigned long total_size)
{
	int rc;
	ssize_t bytes_read;
	loff_t pos = offset;
	unsigned long vm_flags = VM_LWK | VM_LWK_DBSS | VM_LWK_EXTRA;
	unsigned long rval;

	/*
	 * If @total_size is specified then it is the request for first map.
	 * We need to make sure the entire ELF image size can be fit starting
	 * @map_start before we map in the requested ELF segment.
	 */
	if (total_size) {
		rval = get_unmapped_area(NULL, addr, total_size, 0, MAP_FIXED);
		if (IS_ERR_VALUE(rval))
			return rval;
	}

	/* Map and populate ELF segment */
	rc = vm_brk_flags(map_start, map_size, vm_flags);
	if (rc)
		return rc;
	mm_populate(map_start, map_size);

	/* Load data from the file for this ELF segment's memory map */
	bytes_read = vfs_read(filep, (char __user *) addr, size, &pos);
	if (bytes_read != size) {
		LWKMEM_ERROR("Failed to read ELF segment from file");
		return -EINVAL;
	}
	return map_start;
}

static struct lwk_vm_operations lwk_vm_ops = {
	.get_unmapped_area	= lwk_mm_get_unmapped_area,
	.unmap_page_range	= lwk_mm_unmap_pages,
	.move_page_tables	= lwk_mm_move_page_tables,
	.change_protection	= lwk_mm_change_protection,
	.follow_page		= lwk_mm_follow_page,
	.page_fault		= lwk_mm_page_fault,
	.alloc_pages_vma	= lwk_mm_alloc_pages_vma,
	.vma_adjust		= lwk_mm_vma_adjust,
	.populated		= lwk_mm_vma_populated,
	.fork			= lwk_mm_fork,
	.clear_heap		= lwk_mm_clear_heap,
	.elf_map		= lwk_mm_elf_map,
};

/*
 * Helper functions for managing LWK VMA private structure.
 */
void vma_set_lwkvma(struct vm_area_struct *vma)
{
	struct lwk_vma_private *vma_private, *vma_private_orig;
	unsigned long lwk_vm_start, lwk_vm_end;
	struct lwk_mm *lwk_mm;

	if (vma && is_lwkvma(vma)) {
		vma_private = kzalloc(sizeof(struct lwk_vma_private),
				       GFP_KERNEL);
		if (!vma_private) {
			LWKMEM_ERROR("Failed to allocate VMA private struct");
			/* Not a problem as long as LWK VMAs are not merged */
			vma->vm_flags &= ~VM_LWK_FLAGS;
			dump_stack();
			return;
		}

		/*
		 * If LWK VMA is being newly created then we set the LWK VMA's
		 * markers to the new VMA's start. If the LWK VMA is being
		 * copied then we copy the LWK VMA markers from old VMA's
		 * private data and we let the vma_adjust() ops take care of the
		 * re-adjustment of these markers later in the flow. This is
		 * because we do not yet know what the actual start/end of the
		 * newly copied VMA is before the caller sets the copied VMA's
		 * start and end.
		 */
		if (vma->vm_private_data) {
			vma_private_orig = vma->vm_private_data;
			lwk_vm_start = vma_private_orig->lwk_vm_start;
			lwk_vm_end = vma_private_orig->lwk_vm_end;
			lwk_mm = vma_private_orig->lwk_mm;
		} else {
			lwk_vm_start = vma->vm_start;
			lwk_vm_end = vma->vm_start;
			if (!is_mostask()) {
				LWKMEM_ERROR("Not a mOS task pid %d",
					      current->tgid);
			}
			lwk_mm = curr_lwk_mm();
		}

		vma_private->lwk_vm_start = lwk_vm_start;
		vma_private->lwk_vm_end = lwk_vm_end;
		vma_private->lwk_mm = lwk_mm;
		init_rwsem(&vma_private->vma_sem);
		vma->vm_private_data = vma_private;

		/*
		 * Set extra flags if not already set,
		 *
		 * VM_WIPEONFORK,
		 *   Request Linux not to copy page tables corresponding to this
		 *   LWK VMA during fork, instead let the corresponding new VMA
		 *   in the child process have a fresh start without any LWK VMA
		 *   dependencies but also at the same time let us populate new
		 *   pages in child process and copy memory contents from parent
		 *   LWK process.
		 *
		 * VM_NOHUGEPAGE,
		 *   We do not want Linux THP khugepaged to scan LWK VMA.
		 *
		 * VM_DATA_DEFAULT_FLAGS,
		 *   By default LWK VMAs are read/write/executable.
		 */
		vma->vm_flags |= VM_LWK_EXTRA;
	}
	return;
}

void vma_clear_lwkvma(struct vm_area_struct *vma)
{
	if (vma && is_lwkvma(vma)) {
		kfree(vma->vm_private_data);
		vma->vm_private_data = NULL;
		vma->vm_flags &= ~VM_LWK_FLAGS | VM_DATA_DEFAULT_FLAGS;
	}
}

/*
 * Adjust the LWK VMA allocated range markers as per new start/end
 * of the VMA. This should be called when vm_start and/or vm_end of
 * @vma changes.
 */
static void lwk_mm_adjust_mapped_range(struct vm_area_struct *vma,
				       unsigned long vm_start,
				       unsigned long vm_end)
{
	struct lwk_vma_private *vma_private = vma->vm_private_data;
	unsigned long start, end;

	if (vm_start > vm_end) {
		LWKMEM_ERROR("Invalid args vm_start %lx > vm_end %lx",
			     vm_start, vm_end);
		return;
	}
	if (vma_private->lwk_vm_start > vma_private->lwk_vm_end) {
		LWKMEM_ERROR("lwk_vma_start %lx > lwk_vma_end %lx",
			vma_private->lwk_vm_start, vma_private->lwk_vm_end);
		vma_private->lwk_vm_start = vm_start;
		vma_private->lwk_vm_end = vm_end;
		return;
	}

	if (vma_private->lwk_vm_start >= vm_end ||
	    vma_private->lwk_vm_end <= vm_start) {
		start = vm_start;
		end = vm_start;
	} else  {
		start = max(vm_start, vma_private->lwk_vm_start);
		end = min(vm_end, vma_private->lwk_vm_end);

	}
	vma_private->lwk_vm_start = start;
	vma_private->lwk_vm_end = end;
}

/*
 * Copy the LWK VMA allocated range marker offsets and apply it to the @new_vma.
 * This should be called when a range of virtual memory [@old_start, @old_end)
 * in @old_vma is remapped on to @new_vma.
 */
void lwk_mm_copy_mapped_range(struct vm_area_struct *old_vma,
			      unsigned long old_start, unsigned long old_end,
			      struct vm_area_struct *new_vma)
{
	unsigned long offset_start, offset_end;
	struct lwk_vma_private *old_private = old_vma->vm_private_data;
	struct lwk_vma_private *new_private = new_vma->vm_private_data;

	/* Set default */
	new_private->lwk_vm_start = new_vma->vm_start;
	new_private->lwk_vm_end = new_vma->vm_start;

	/* Old VMA is not populated yet, we are done here! */
	if (!lwk_mm_vma_populated(old_vma))
		return;
	/*
	 * Non overlapping cases where virtual memory being remapped
	 * does not yet have physical memory backings in the range.
	 */
	if (old_private->lwk_vm_end <= old_start ||
	    old_private->lwk_vm_start >= old_end ||
	    new_vma->vm_start == new_vma->vm_end ||
	    old_start == old_end)
		return;

	/* Compute offsets of allocated range markers */
	offset_start = max(old_start, old_private->lwk_vm_start) - old_start;
	offset_end = min(old_end, old_private->lwk_vm_end) - old_start;

	/* Apply it to new VMA */
	new_private->lwk_vm_start += offset_start;
	new_private->lwk_vm_end += offset_end;
}

/*
 * Helper to do common checking of LWK mm state.
 *
 * If @mm_status is set to 'true' then the function returns error if lwk_mm
 * pointer is not yet set up in current->mos_process structure, i.e. it checks
 * for invalid state when it is expected to have a valid lwk_mm structure
 * pre-allocated for the calling LWK process.
 *
 * If @mm_staus is set to 'false' then the function returns error if lwk_mm
 * pointer is already set up in current->mos_process structure, i.e. it checks
 * for invalid state when it is expected not to have an lwk_mm pre-allocated
 * structure for the calling LWK process.
 */
static int check_lwk_mm(bool mm_status)
{
	struct mos_process_t *mosp = current->mos_process;

	if (!mosp) {
		LWKMEM_ERROR("%s: Invalid args PID %d is not an LWK process!",
				__func__, current->pid);
		goto error;
	}

	if (mm_status && !mosp->lwk_mm) {
		LWKMEM_ERROR("%s: Invalid args PID %d has no LWK mm!",
				__func__, current->pid);
		goto error;
	}

	if (!mm_status && mosp->lwk_mm) {
		LWKMEM_ERROR("%s: Invalid args PID %d already has an LWK mm!",
				__func__, current->pid);
		goto error;
	}
	return 0;
error:
	dump_stack();
	return -EINVAL;
}

static void report_lwk_vm(struct lwk_vm_stats *vm_stats) {
	show_xpmem_stats(vm_stats);
}

/*
 * Access/set helpers for LWK mm.
 */
inline struct lwk_mm *curr_lwk_mm(void)
{
	return current->mos_process ? current->mos_process->lwk_mm : NULL;
}

inline struct lwk_mm *vma_lwk_mm(struct vm_area_struct *vma)
{
	struct lwk_vma_private *vma_private = vma->vm_private_data;

	return vma_private ? vma_private->lwk_mm : NULL;
}

inline void set_lwk_mm(struct lwk_mm *lwk_mm)
{
	if (current->mos_process)
		current->mos_process->lwk_mm = lwk_mm;
}

static void report_lwk_mm(void)
{
	struct lwk_mm *lwk_mm;

	if (check_lwk_mm(true))
		return;

	lwk_mm = curr_lwk_mm();

	if (lwk_mm->report_level > 0)
		lwk_mm->pm_ops->report(lwk_mm->pma, lwk_mm->report_level);
	if (lwk_mm->report_level > 1)
		report_lwk_vm(&lwk_mm->vm_stats);
}

/*
 * Helpers to store mempolicy info for the LWK process.
 */
static int setup_policy_lists(u64 *buffer, u8 *default_buffer,
			u64 max_longs_per_list,
			struct lwk_mempolicy_nodelists **plists, u64 num_lists)
{
	int i, j;
	u8 *byte;
	u64 max_nodes_per_list;
	struct lwk_mempolicy_nodelists *lists;
	struct lwk_mm *lwk_mm = curr_lwk_mm();

	if (!buffer && !default_buffer) {
		LWKMEM_ERROR("Invalid buffer and defaults");
		return -EINVAL;
	}

	if (!plists) {
		LWKMEM_ERROR("Invalid lists, num lists %lu mpl %lu",
			     num_lists, max_longs_per_list);
		return -EINVAL;
	}

	if (*plists) {
		LWKMEM_WARN("Pre-allocated lists! Freeing...");
		/*
		 * @policy_nlists if present should be the previous setting,
		 * as the current settings are updated after all VMRs policy
		 * lists are populated.
		 */
		lists = *plists;
		for (i = 0; i < lwk_mm->policy_nlists; i++)
			kfree(lists[i].nodes);
		kfree(lists);
	}

	/* Allocate array of pointer to lists */
	*plists = kmalloc_array(num_lists,
				sizeof(struct lwk_mempolicy_nodelists),
				GFP_KERNEL);
	if (!*plists)
		return -ENOMEM;
	/*
	 * Each field in the buffer is 64 bit long and each byte within
	 * the field can describe a NUMA node number or NID. We can do
	 * the below calculation to get the maximum possible number of
	 * NUMA nodes in the buffer per list. Further a list could have
	 * been terminated by the presence of LWKMEM_MEMPOL_EOL byte in
	 * which case the actual number of nodes will be less than max.
	 */
	max_nodes_per_list = 8 * max_longs_per_list;
	/* Allocate storage for every list and fill in each list pointer */
	for (i = 0, lists = *plists; i < num_lists; i++) {
		byte = buffer ? (u8 *)buffer : default_buffer;

		/* Find the actual number of nodes for this list */
		for (j = 0; j < max_nodes_per_list; j++) {
			if (byte[j] == LWKMEM_MEMPOL_EOL)
				break;
		}

		/* Allocate memory to hold this list of nodes */
		lists[i].num_nodes = j;
		lists[i].nodes = kmalloc_array(lists[i].num_nodes, 1,
					       GFP_KERNEL);
		if (!lists[i].nodes) {
			/* Clean up on error */
			while (--i >= 0)
				kfree(lists[i].nodes);
			kfree(lists);
			*plists = NULL;
			return -ENOMEM;
		}

		/* Fill the list with actual values from yod or default */
		for (j = 0; j < lists[i].num_nodes; j++)
			lists[i].nodes[j] = byte[j];
		if (buffer)
			buffer += max_longs_per_list;
	}
	return 0;
}

static void lwk_mm_clear_mempolicy_info(void)
{
	int n;
	enum lwk_vmr_type vmr;
	struct lwk_mempolicy *policy;
	struct lwk_mm *lwk_mm = curr_lwk_mm();

	for (vmr = 0; vmr < LWK_MAX_NUMVMRTYPES; vmr++) {
		policy = &lwk_mm->policy[vmr];

		/* Free individual lists */
		if (policy->above_threshold) {
			for (n = 0; n < lwk_mm->policy_nlists; n++)
				kfree(policy->above_threshold[n].nodes);
		}
		if (policy->below_threshold) {
			for (n = 0; n < lwk_mm->policy_nlists; n++)
				kfree(policy->below_threshold[n].nodes);
		}

		kfree(policy->above_threshold);
		kfree(policy->below_threshold);
		policy->above_threshold = NULL;
		policy->below_threshold = NULL;
		policy->disabled = true;
	}
	lwk_mm->policy_nlists = 0;
	lwk_mm->policy_set = false;
}

/*
 * Interpret and store mempolicy info buffer from yod.
 */
int lwk_mm_set_mempolicy_info(const char *buff, size_t size)
{
	int node, rc = -EINVAL;
	u8 *default_buffer = NULL;
	u64 *ptr = NULL;
	u64 header_size, info_size = 0;
	u64 nvmrs, nmax;
	u64 max_lists, valid_lists, max_longs_per_list;
	enum lwk_page_type t;
	enum lwk_vmr_type vmr;
	enum lwk_pagefault_level pf_level;
	enum lwk_mempolicy_type type;
	struct lwk_mempolicy *policy;
	struct lwk_mm *lwk_mm = curr_lwk_mm();

	if (!lwk_mm) {
		LWKMEM_ERROR("Invalid lwk_mm");
		return rc;
	}

	if (buff) {
		/* Parse memory policy info header */
		if (!size || size % 8) {
			LWKMEM_ERROR("Invalid mempolicy info size %lu", size);
			return rc;
		}
		ptr = (u64 *) buff;
		header_size = ptr[0];
		info_size   = ptr[1];
		nvmrs = ptr[2];

		/* Validate the total buffer size */
		if ((header_size + info_size * nvmrs) != size) {
			LWKMEM_ERROR("size %lu header %lu info %lu vmrs %lu",
				     size, header_size, info_size, nvmrs);
			return rc;
		}

		max_lists = ptr[3];
		valid_lists = ptr[4];
		max_longs_per_list = ptr[5];
		ptr = (u64 *)((u8 *)ptr + header_size);
	} else {
		/*
		 * Compute and store default set of nodes from which
		 * memory has been reserved for this LWK process.
		 */
		for (nmax = 0, node = 0; node < MAX_NUMNODES; node++) {
			if (list_empty(&lwk_mm->list_pmem[node]))
				continue;
			nmax++;
		}

		/* Add space for list termination marker if needed */
		if (nmax % 8)
			nmax++;
		default_buffer = kmalloc_array(nmax, 8, GFP_KERNEL);
		if (!default_buffer)
			return -ENOMEM;

		for (nmax = 0, node = 0; node < MAX_NUMNODES; node++) {
			if (list_empty(&lwk_mm->list_pmem[node]))
				continue;
			default_buffer[nmax++] = node;
		}
		/* Mark end of list if we filled less than capacity */
		if (nmax % 8)
			default_buffer[nmax] = LWKMEM_MEMPOL_EOL;
		nvmrs = LWK_MAX_NUMVMRTYPES;
		max_lists = 1;
		valid_lists = 1;
		max_longs_per_list = (nmax + 7) / 8;
		ptr = NULL;
	}

	if (nvmrs > LWK_MAX_NUMVMRTYPES) {
		LWKMEM_ERROR("Invalid number of VMRs %lld supported %d max",
			     nvmrs, LWK_MAX_NUMVMRTYPES);
		return rc;
	}

	if (max_lists > MAX_NUMNODES) {
		LWKMEM_ERROR("Invalid number of lists %lld, allowed %d max",
			     max_lists, MAX_NUMNODES);
		return rc;
	}

	if (valid_lists > max_lists) {
		LWKMEM_ERROR("Invalid number of valid lists %lld > maxlist %lld",
			     valid_lists, max_lists);
		return rc;
	}

	nmax = max_longs_per_list * 8;
	if (nmax > MAX_NUMNODES) {
		LWKMEM_ERROR("Invalid NUMA nodes per list %ld, allowed %d max",
			     nmax, MAX_NUMNODES);
		return rc;
	}

	/*
	 * Read and store memory policy information for every supported
	 * Virtual Memory Regions. If not given then set a default policy.
	 */
	for (vmr = 0; vmr < LWK_MAX_NUMVMRTYPES; vmr++) {
		policy = &lwk_mm->policy[vmr];

		/* Store nodelists for allocation above threshold */
		rc = setup_policy_lists(ptr, default_buffer, max_longs_per_list,
					&policy->above_threshold, valid_lists);
		if (rc) {
			LWKMEM_ERROR("Failed to setup nodelists1 rc=%d", rc);
			goto out;
		}

		if (!ptr) {
			/* Set defaults for rest of VMRs from @vmr onwards. */
			LWKMEM_WARN("No mempolicy by yod for [%s] set default",
				    lwk_vmrs_name[vmr]);
			policy->threshold = 1;
			policy->pagefault_level = LWK_PF_NOFAULT;
			policy->type = LWK_MEMPOL_NORMAL;
			policy->disabled = false;
			if (vmr != LWK_VMR_HEAP)
				policy->max_page = LWK_MAX_NUMPGTYPES - 1;
			else
				policy->max_page = LWK_MAX_NUMPGTYPES - 2;
			continue;
		}
		ptr += max_longs_per_list * max_lists;

		/* Store nodelists for allocation below threshold */
		rc = setup_policy_lists(ptr, default_buffer, max_longs_per_list,
					&policy->below_threshold, valid_lists);
		if (rc) {
			LWKMEM_ERROR("Failed to setup nodelists2 rc=%d", rc);
			goto out;
		}
		ptr += max_longs_per_list * max_lists;

		/* Store threshold */
		policy->threshold = *ptr++;
		/* Store max page type */
		for_each_lwkpage_type_reverse(t) {
			if (lwkpage_size(t) == *ptr)
				break;
		}
		if ((int)t < 0) {
			t = LWK_MAX_NUMPGTYPES - 1;
			LWKMEM_WARN("%s: Invalid maxpg size %lu, set to %s",
				    lwk_vmrs_name[vmr], *ptr, lwkpage_desc(t));
		}
		policy->max_page = t;
		ptr++;

		/* Store page fault level, default to nofaults  */
		pf_level = LWK_PF_NOFAULT;
		policy->pagefault_level = pf_level;
		for (; (int) pf_level < LWK_PF_LEVELS; pf_level++) {
			if ((u64)pf_level == *ptr) {
				policy->pagefault_level = pf_level;
				break;
			}
		}

		if ((int) pf_level == LWK_PF_LEVELS) {
			LWKMEM_WARN("%s: Invalid pagefault lvl %ld, set nofault",
				    lwk_vmrs_name[vmr], *ptr);
		}
		ptr++;

		/* Store policy type, default to normal  */
		type = LWK_MEMPOL_NORMAL;
		policy->type = type;
		for (; (int) type < LWK_MAX_MEMPOL_TYPES; type++) {
			if ((u64) type == *ptr) {
				policy->type = type;
				break;
			}
		}
		if ((int) type == LWK_MAX_MEMPOL_TYPES) {
			LWKMEM_WARN("%s: Invalid policy type %lld, set normal",
				    lwk_vmrs_name[vmr], *ptr);
		}
		ptr++;
	}
	/* Everything looks ok, let us update this in lwk_mm structure */
	lwk_mm->policy_nlists = valid_lists;
	lwk_mm->policy_set = true;
	rc = 0;
out:
	if (rc)
		lwk_mm_clear_mempolicy_info();
	kfree(default_buffer);
	return rc;
}

/*
 * Prepares LWK memory manger to start to an active state. When this
 * function returns success we have an active LWK memory manager for
 * the calling process.
 */
int start_lwk_mm(void)
{
	int rc;
	void *pma;
	enum lwk_pma_type pma_type;
	struct lwk_mm *lwk_mm;

	rc = check_lwk_mm(true);
	if (rc)
		goto out;

	lwk_mm = curr_lwk_mm();
	/* Already active? */
	if (lwk_mm->active) {
		rc = 0;
		goto out;
	}

	/* Set default mempolicy if mempolicy is not yet setup */
	if (!lwk_mm->policy_set) {
		rc = lwk_mm_set_mempolicy_info(NULL, 0);
		if (rc) {
			LWKMEM_ERROR("set default mempolicy, rc=%d", rc);
			goto out;
		}
	}

	/* Create an instance of PMA */
	pma_type = lwk_mm->pma_type;
	pma = pm_registered_ops[pma_type].factory_ops->alloc_pma();
	if (!pma) {
		LWKMEM_ERROR("%s: Error allocating a PMA instance", __func__);
		rc = -ENOMEM;
		goto out;
	}
	lwk_mm->pma = pma;
	lwk_mm->pm_ops = pm_registered_ops[pma_type].pm_ops;

	/* Initialize the PMA instance */
	rc = lwk_mm->pm_ops->setup(lwk_mm->pma, &lwk_mm->list_pmem,
				   &lwk_mm->pma_cache_limits,
				   lwk_mm->id, lwk_mm->report_level);
	if (rc) {
		pm_registered_ops[pma_type].factory_ops->free_pma(pma);
		lwk_mm->pma = NULL;
		lwk_mm->pm_ops = NULL;
		lwk_mm->active = false;
	} else {
		/* Don't randomize address space for LWK processes! */
		current->personality |= ADDR_NO_RANDOMIZE;
		lwk_mm->active = true;
	}
out:
	return rc;
}

/*
 * Put LWK memory manager to inactive state and release PMA. Once
 * this function returns success LWK memory manager structre can
 * be released by calling free_lwk_mm()
 */
int exit_lwk_mm(void)
{
	int rc;
	void *pma;
	enum lwk_pma_type pma_type;
	struct lwk_mm *lwk_mm;

	rc = check_lwk_mm(true);
	if (rc)
		goto out;

	lwk_mm = curr_lwk_mm();
	/* Already inactive? */
	if (!lwk_mm->active) {
		rc = 0;
		goto out;
	}

	/* Print reports if enabled. */
	report_lwk_mm();
	/* Release the PMA instance */
	pma = lwk_mm->pma;
	pma_type = lwk_mm->pma_type;
	pm_registered_ops[pma_type].factory_ops->free_pma(pma);

	/* Set to inactive state */
	lwk_mm->pma = NULL;
	lwk_mm->pm_ops = NULL;
	lwk_mm->active = false;
	rc = 0;
out:
	return rc;
}

static void init_vm_stats(struct lwk_vm_stats *vm_stats)
{

	/* Currently the only vm stats are for xpmem */
	init_xpmem_stats(vm_stats);
}

/*
 * Allocates the LWK memory manager structure and initializes it
 * to the default inactive state. Upon successful return the pointer
 * current->mos_process->lwk_mm is set to point to the initialized
 * lwk_mm structure and LWKMEM yod options are set to default.
 *
 * Function assumes that the caller ensures mutual exclusion across
 * multiple LWK processes.
 */
int allocate_lwk_mm(void)
{
	struct lwk_mm *lwk_mm;
	enum lwk_vmr_type vmr;
	unsigned long mm_id_mask = ~(~0UL << _LWKPG_MMID_WD);
	int rc, n;

	rc = check_lwk_mm(false);
	if (rc)
		goto error;

	lwk_mm = kzalloc(sizeof(struct lwk_mm), GFP_KERNEL);
	if (!lwk_mm) {
		LWKMEM_ERROR("%s: Low kernel memory could not allocate LWK mm!",
				__func__);
		rc = -ENOMEM;
		goto error;
	}

	lwk_mm->vm_ops = &lwk_vm_ops;

	/* Initialize nodelist pointers */
	lwk_mm->policy_set = false;
	for (vmr = 0; vmr < LWK_MAX_NUMVMRTYPES; vmr++) {
		lwk_mm->policy[vmr].above_threshold = NULL;
		lwk_mm->policy[vmr].below_threshold = NULL;
	}

	/* Initialize the vm stats area */
	init_vm_stats(&lwk_mm->vm_stats);

	/*
	 * Get a unique ID for this instance of LWK MM. No need of atomic
	 * variable here as the caller already ensures mutual exclusion
	 * between multiple LWK processes.
	 */
	lwk_mm->id = lwk_mm_id++ & mm_id_mask;
	for (n = 0; n < MAX_NUMNODES; n++)
		INIT_LIST_HEAD(&lwk_mm->list_pmem[n]);
	set_lwk_mm(lwk_mm);
	lwkmem_yod_options_set_default();
	return 0;
error:
	return rc;
}

/*
 * Releases resources allocated by both allocate/start_lwk_mm() for
 * the calling LWK process. Upon successful return the pointer
 * current->mos_process->lwk_mm is set to NULL.
 *
 * Function assumes that the caller ensures mutual exclusion across
 * multiple LWK processes.
 */
int free_lwk_mm(void)
{
	struct lwk_mm *lwk_mm;
	int rc;

	rc = check_lwk_mm(true);
	if (rc)
		goto out;

	lwk_mm = curr_lwk_mm();
	if (lwk_mm->active) {
		LWKMEM_ERROR("%s: Can not free an active LWK mm", __func__);
		rc = -EINVAL;
		goto out;
	}

	/* Free arrays of nodelists if allocated */
	lwk_mm_clear_mempolicy_info();
	/* Clean up inactive state */
	kfree(lwk_mm);
	set_lwk_mm(NULL);
	rc = 0;
out:
	return rc;
}

/*
 * Every PMA implementation needs to register itself with LWK mm core by
 * calling this function early in the kernel boot in a subsys_initcall.
 * It registers the factory functions that are needed to allocate/free a
 * PMA instance of a PMA type. This function should not use RAS prints to
 * communicate errors as it is called very early in the kernel boot up and
 * RAS will not be available by then.
 */
int register_lwk_pma(enum lwk_pma_type pma_type,
		     struct lwk_pm_factory_operations *factory_ops,
		     struct lwk_pm_operations *pm_ops)
{
	if (pma_type < 0 || pma_type >= LWK_PMA_MAX) {
		pr_err("%s: Invalid PMA type %d (Valid 0-%d)\n",
			__func__, pma_type, LWK_PMA_MAX - 1);
		return -EINVAL;
	}

	if (!factory_ops || !pm_ops) {
		pr_err("%s: Err, %s ops is NULL\n", __func__,
		       !factory_ops ? "factory" : "pm");
		return -EINVAL;
	}

	/* Make sure all factory ops are implemented */
	if (!factory_ops->alloc_pma || !factory_ops->free_pma) {
		pr_err("%s: %s() is NULL when setting factory ops!\n", __func__,
		       !factory_ops->alloc_pma ? "alloc_pma" : "free_pma");
		return -EINVAL;
	}

	/* Make sure all pm ops are implemented */
	if (!pm_ops->alloc_pages ||
	    !pm_ops->free_pages ||
	    !pm_ops->report ||
	    !pm_ops->meminfo ||
	    !pm_ops->setup) {
		pr_err("%s: Invalid pm ops, %s() is NULL\n", __func__,
			!pm_ops->alloc_pages ? "alloc_pages" :
			!pm_ops->free_pages ? "free_pages" :
			!pm_ops->report ? "report" :
			!pm_ops->meminfo ? "meminfo" : "setup");
		return -EINVAL;
	}
	pm_registered_ops[pma_type].factory_ops = factory_ops;
	pm_registered_ops[pma_type].pm_ops = pm_ops;
	return 0;
}
