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

#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/memory.h>
#include <linux/printk.h>
#include <linux/mos.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/mempolicy.h>
#include <linux/ftrace.h>
#include <asm/tlb.h>
#include "lwkmem.h"

#define CREATE_TRACE_POINTS
#include <trace/events/lwkmem.h>

#undef pr_fmt
#define pr_fmt(fmt)	"mOS-mmap: " fmt


extern void list_vmas(struct mm_struct *mm);

static struct vm_area_struct *mos_find_vma(struct mm_struct *mm,
					   unsigned long addr)
{
	struct vm_area_struct *vma;

	vma = find_vma(mm, addr);
	if (likely(vma && addr >= vma->vm_start && addr < vma->vm_end))
		return vma;
	else
		return NULL;
}

/*
 * Unmaps and frees the physical page frames from the user page table
 * for a specified user virtual address range. The function assumes that
 * the caller holds the mm->mmap_sem lock. We need to get mm from caller
 * because during the process exit current->mm is set to NULL even before
 * exit_mmap() is called.
 *
 * Since LWK VMA avoids page faults by pre-populating the page table there
 * isn't a use case where one needs to unmap an LWK VMA partially. This
 * requirement might change for example if LWK decides to respect a user
 * madvise such MADV_DONTNEED or MADV_FREE just to free up physical memory
 * temporarily. Currently this function supports unmaping of an entire VMA
 * with exact overlap in the address range being requested.
 *
 */
void unmap_lwkmem_range(struct mmu_gather *tlb, struct vm_area_struct *vma,
			unsigned long start, unsigned long end,
			struct zap_details *details)
{
	struct mm_struct *mm = tlb->mm;
	struct mos_process_t *mosp = current->mos_process;

	if (!vma || start > end) {
		mos_ras(MOS_LWKMEM_PROCESS_WARNING,
			"%s: Invalid arguments.  pid:%d vma:%p start:%lx end:%lx.",
			__func__, current->pid, vma, start, end);
		return;
	}

	if (start == end)
		return;

	if (is_lwkxpmem(vma)) {
		if (unmap_lwkxpmem_range(vma, start, end)) {
			pr_err("%s():ERR Unmapping LWKXPMEM[%lx-%lx][%lx-%lx]",
			       __func__, vma->vm_start, vma->vm_end,
			       start, end);
		} else {
			/* Unmap Linux part of LWKXPMEM VMA if any. */
			unmap_page_range(tlb, vma, start, end, details);
		}
		goto out;
	}

	if (!mosp) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: pid %d is not an mOS process.",
			__func__, current->pid);
		return;
	}

	if (unlikely(!is_lwkmem(vma))) {
		list_vmas(mm);
		mos_ras(MOS_LWKMEM_PROCESS_WARNING,
			"%s: Memory range[0x%016lx,0x%016lx) is not in an LWK VMA. pid=%d.",
			__func__, start, end, current->pid);
		return;
	}

	/* Currently partial unmaping of LWKMEM VMA is not supported
	 * alert if we see an unsupported use case.
	 */
	if (vma->vm_start != start || vma->vm_end != end) {
		mos_ras(MOS_LWKMEM_PROCESS_WARNING,
			"%s: Partial unmapping is not supported.  VMA: [%016lx,%016lx) region: [%016lx,%016lx)",
			__func__, vma->vm_start, vma->vm_end, start, end);
		return;
	}

	/* Deallocate LWK memory blocks.  If this fails, we are going to
	 * continue regardless; we may not have cleaned up completely
	 * but we are no worse off than we were before.
	 */
	deallocate_blocks(start, end-start, mosp, mm);
out:
	trace_mos_munmap(start, end-start, 0, current->tgid);
}

asmlinkage long lwk_sys_mmap_pgoff(unsigned long addr, unsigned long len,
		unsigned long prot, unsigned long flags,
		unsigned long fd, unsigned long pgoff)
{
	struct vm_area_struct *vma;
	struct mos_process_t *mosp;
	struct allocate_options_t *opts;
	long ret;
	const unsigned long addr_in = addr, len_in = len;

	mosp = current->mos_process;
	/* Let Linux deal with this, if it is not a mOS task */

	if (!mosp || (mosp->lwkmem <= 0) ||
	    !(flags & MAP_ANONYMOUS) || (flags & MAP_SHARED)) {
		ret = -ENOSYS;
		goto out;
	}

	if (prot == PROT_NONE && mosp->lwkmem_prot_none_delegation) {
		ret = -ENOSYS;
		goto out;
	}

	/* Alignment test from arch/x86/kernel/sys_x86_64.c */
	if ((pgoff & ~PAGE_MASK) || (len == 0)) {
		ret = -EINVAL;
		goto out;
	}

	if (len > TASK_SIZE ||
	    ((flags & MAP_FIXED) && (addr > TASK_SIZE - len))) {
		ret = -ENOMEM;
		goto out;
	}

	if (down_write_killable(&current->mm->mmap_sem)) {
		ret = -EINTR;
		goto out;
	}

	if (unlikely(addr && (flags & MAP_FIXED))) {
		unsigned long a0, a1, b0, b1;
		int nlinux = 0, nlwk = 0;

		a0 = addr;
		a1 = addr + len;

		while (a0 < a1) {

			vma = find_vma_intersection(current->mm, a0, a1);

			if (!vma)
				break;

			b0 = max(vma->vm_start, a0);
			b1 = min(vma->vm_end, a1);

			/* Unmap overlapping LWK VMAs.  And also, unmap any
			 * private, anonymous, inaccessible VMAs if we are
			 * in reclamation mode.  Let Linux handle the other
			 * cases.
			 */
			if (is_lwkmem(vma) || (mosp->lwkmem_prot_none_delegation &&
			       !vma->vm_file &&
			       !(vma->vm_flags & (VM_MAYSHARE | VM_READ | VM_WRITE | VM_EXEC)))) {

				nlwk++;

				trace_mos_unmapped_region(b0, b1 - b0,
					  vma->vm_flags, current->tgid);

				if (do_munmap(current->mm, b0, b1 - b0, NULL)) {
					mos_ras(MOS_LWKMEM_PROCESS_WARNING,
						"%s: Could not unmap [%lx,%lx)",
						__func__, b0, b1);
					ret = -ENOMEM;
					goto done;
				}
			} else
				nlinux++;

			a0 = vma->vm_end;
		}

		/* If we are delgating to Linux, ensure that all overlapping
		 * VMAs were Linux VMAs.
		 */

		if (nlinux > 0) {

			if (nlwk > 0) {
				mos_ras(MOS_LWKMEM_PROCESS_WARNING,
					"%s: Mixed VMA types detected in mmap [%lx,%lx) Linux:%d LWK:%d",
					__func__, addr, addr + len, nlinux, nlwk);
				ret = -ENOMEM;
			} else {
				ret = -ENOSYS;
			}
			goto done;
		}

	} else if (unlikely(addr)) {
		vma = mos_find_vma(current->mm, addr);

		if (vma && !is_lwkmem(vma)) {
			up_write(&current->mm->mmap_sem);
			ret = -ENOSYS;
			goto done;
		}
	}

	if (mosp->lwkmem_mmap_aligned_threshold > 0) {
		if (len >= mosp->lwkmem_mmap_aligned_threshold) {
			if (!(flags & MAP_FIXED))
				addr = next_lwkmem_address(len, mosp);

			if (addr <= TASK_SIZE - len) {
				ret = allocate_blocks_fixed(addr, len, prot,
					flags | MAP_FIXED, lwkmem_mmap);
				goto done;
			}
			addr = addr_in;
		}

		opts = allocate_options_factory(lwkmem_mmap, len,
				flags, mosp);
		if (opts) {
			ret = opts->allocate_blocks(addr, len,
					prot, flags, pgoff, opts);
			kfree(opts);
		} else
			ret = -ENOMEM;
	} else {
		/* Packed virtual memory */
		len = round_up(len, PAGE_SIZE);
		addr = get_unmapped_area(NULL, addr, len, pgoff,
				flags & MAP_FIXED);
		if (offset_in_page(addr))
			ret = addr;
		else
			ret = allocate_blocks_fixed(addr, len, prot,
					flags | MAP_FIXED, lwkmem_mmap);
	}
done:
	up_write(&current->mm->mmap_sem);

	if (unlikely(ret == 0)) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: Out of LWK memory.", __func__);
		ret = -ENOMEM;
	}
out:
	trace_mos_mmap(addr_in, len_in, prot, flags, ret, current->tgid);
	return ret;

} /* end of lwk_sys_mmap_pgoff() */

#ifndef CONFIG_X86_64

/* NOTE: X86_64 defines the sys_mmap() entry point which then delegates to
 *       sys_mmap_pgoff.  The syscall migration macros will "triage" both of
 *       these entry points.   And so, if we have both a lwk_sys_mmap_pgoff()
 *       and lwk_sys_mmap(), the above code will get invoked twice to determine
 *       that delegation to Linux is required.  So we eliminate the outer
 *       wrapper.
 */

asmlinkage long lwk_sys_mmap(unsigned long addr, unsigned long len,
		unsigned long prot, unsigned long flags,
		unsigned long fd, unsigned long pgoff)
{
	return lwk_sys_mmap_pgoff(addr, len, prot, flags, fd, pgoff);
}

#endif

#ifdef __ARCH_WANT_SYS_OLD_MMAP
asmlinkage long lwk_sys_old_mmap(struct mmap_arg_struct __user *arg)
{
	pr_debug("%s(arg=%p) CPU=%d pid=%d\n", __func__, arg,
		 smp_processor_id(), current->pid);

	return -ENOSYS;
}
#endif /* __ARCH_WANT_SYS_OLD_MMAP */

asmlinkage long lwk_sys_brk(unsigned long brk)
{
	long ret;
	struct mos_process_t *mosp;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
	struct mm_struct *mm = current->mm;
	unsigned long len;
	unsigned long clear_len = 0;
	void *clear_addr = 0;
	bool first_brk = false;

	mosp = current->mos_process;

	if (!mosp) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: pid %d is not an mOS process.",
			__func__, current->pid);
		ret = -ENOSYS;
		goto out;
	}

	if (mosp->yod_mm == mm) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: yod MM error. pid=%d.",
			__func__, current->pid, __func__);
		ret = -ENOSYS;
		goto out;
	}

	if (mosp->lwkmem_brk_disable) {
		ret = -ENOSYS;
		goto out;
	}

	if (down_write_killable(&mm->mmap_sem)) {
		ret = -EINTR;
		goto out;
	}

	if (mosp->brk == 0) {
		/* First time here. Allocate initial block of LWK memory for
		 * the heap in this process. Align it so future requests can
		 * be satisfied in heap_page_size chunks.
		 */
		unsigned long heap_addr;

		heap_addr = roundup(mm->brk, mosp->heap_page_size);

		/* A couple of sanity checks */
		if ((brk != 0) || (mm->start_brk != mm->brk)) {
			mos_ras(MOS_LWKMEM_PROCESS_WARNING,
				"%s: Unexpected initial state. brk:%lx start-brk:%lx mm-brk:%lx pid:%d.",
				__func__, brk, mm->start_brk, mm->brk,
				current->pid);
		}

		ret = allocate_blocks_fixed(heap_addr, mosp->heap_page_size,
					    PROT_READ | PROT_WRITE,
					    flags, lwkmem_brk);

		if (ret != heap_addr) {
			/* Initial heap allocation failed.  Set both brk and
			 * brk_end to the intended heap address.  Any subsequent
			 * attempts to extend the heap will likely fail below.
			 */
			mos_ras(MOS_LWKMEM_PROCESS_WARNING,
				"%s: No LWK memory for heap at %lx (rc=%ld). pid:%d",
				__func__, heap_addr, ret, current->pid);
			ret = mosp->brk = mosp->brk_end = heap_addr;
		} else {
			ret = mosp->brk = heap_addr;
			mosp->brk_end = heap_addr + mosp->heap_page_size;
			mm->start_brk = mosp->brk;
			mm->brk = mosp->brk_end;
		}

		first_brk = true;

	} else if (brk == 0) {
		/* Just a query. */
		ret = mosp->brk;
	} else if (brk > mosp->brk) {

		/* Expanding the break line.  There are two cases:
		 *   1) The requested line falls within the region that
		 *      has already been allocated, demarked by brk_end.
		 *   2) The requested line spills over the end of the
		 *      allocated region (brk_end).
		 *      We allocate as many heap_page_size (default 2 MB)
		 *      pages as needed. That way, brk_end is always large
		 *      page size aligned.
		 *      We then gradually fill the page (case 1 above).
		 */

		clear_len = brk - mosp->brk;
		clear_addr = (void *)mosp->brk;

		if (brk <= mosp->brk_end) {
			len = brk - mosp->brk;
			if (mosp->brk_clear_len >= 0 &&
			    mosp->brk_clear_len < clear_len)
				clear_len = mosp->brk_clear_len;
		} else {

			len = roundup(brk, mosp->heap_page_size) -
				mosp->brk_end;

			ret = allocate_blocks_fixed(mosp->brk_end, len,
						    PROT_READ | PROT_WRITE,
						    flags, lwkmem_brk);

			if (ret != mosp->brk_end) {
				/* The proper way to signal an error to the
				 * runtime is to return the existing brk address
				 * (see man page for brk).
				 */
				mos_ras(MOS_LWKMEM_PROCESS_ERROR,
					"%s: Could not expand LWK heap to %lx (rc=%ld). pid:%d",
					__func__, mosp->brk_end, ret,
					current->pid);
				ret = mosp->brk;
				up_write(&mm->mmap_sem);
				goto out;
			}
			mosp->brk_end += len;
		}
		ret = mosp->brk = brk;
	} else {
		/* Shrinking the brk line.  We don't give memory back at this
		 * time ... just move the line back.  If it grows again, we
		 * are pre allocated.
		 */
		ret = mosp->brk = brk;
	}

	/* Release the semaphore before calling clear_user(), which may
	 * take a while.
	 */
	up_write(&mm->mmap_sem);

	if (clear_len && clear_addr) {
		/* Clear only the newly requested amount */
		if (clear_user((void *) clear_addr, clear_len))
			mos_ras(MOS_LWKMEM_PROCESS_WARNING,
				"%s: Failed to clear memory at 0x%p [%ld]",
				__func__, clear_addr, clear_len);
	}

 out:
	if (brk && ret != brk)
		mos_ras(MOS_LWKMEM_PROCESS_WARNING,
			"%s: Requested brk:%lx but returning %lx.",
			__func__, brk, ret);
	if (brk || first_brk)
		trace_mos_brk(ret, clear_len, clear_addr, current->tgid);

	return ret;
}

asmlinkage long lwk_sys_remap_file_pages(unsigned long start,
		unsigned long size, unsigned long prot, unsigned long pgoff,
		unsigned long flags)
{
	pr_debug("%s(start=0x%lx size=%ld prot=0x%lx off=0x%lx flags=0x%lx) CPU=%d pid=%d\n",
		 __func__, start, size, prot, pgoff, flags, smp_processor_id(),
		 current->pid);

	return -ENOSYS;
}

/*
 * sys_madvise() needs to be an LWK function.
 * Any Linux policy settings are not likely to be appropriate for LWK memory.
 * Also, letting Linux unmap pages after a MADV_DONTNEED can lead to page
 * faults.
 */
asmlinkage long lwk_sys_madvise(unsigned long addr, size_t len,
		int behavior)
{
	struct mos_process_t *mos_p;
	struct vm_area_struct *vma;
	long ret;

	mos_p = current->mos_process;

	if (!mos_p) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: pid %d is not an mOS process.",
			__func__, current->pid);
		ret = -ENOSYS;
		goto out;
	}

	down_read(&current->mm->mmap_sem);
	vma = mos_find_vma(current->mm, addr);
	up_read(&current->mm->mmap_sem);

	if (!vma) {
		mos_ras(MOS_LWKMEM_PROCESS_WARNING,
			"%s: No VMA found.  pid:%d addr:%lx.",
			__func__, current->pid, addr);
		ret = -ENOSYS;
		goto out;
	}

	if (is_lwkmem(vma))
		ret = 0;

	else
		/* Not LWK memory; let Linux handle it */
		ret = -ENOSYS;

 out:
	trace_mos_madvise(addr, len, behavior, ret, current->tgid);
	return ret;

}

asmlinkage long lwk_sys_mbind(unsigned long start, unsigned long len,
		unsigned long mode, const unsigned long __user *nmask,
		unsigned long maxnode, unsigned int flags)
{
	struct vm_area_struct *vma;
	struct mos_process_t *mosp = current->mos_process;
	long ret = -ENOSYS;

	if (!mosp) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: pid %d is not an mOS process.",
			__func__, current->pid);
		goto out;
	}

	vma = mos_find_vma(current->mm, start);

	if (vma && is_lwkmem(vma))
		if (mode == MPOL_PREFERRED)
			ret = 0;

 out:
	trace_mos_mbind(start, len, mode, flags, ret, current->tgid);
	return ret;
}

asmlinkage long lwk_sys_set_mempolicy(int mode,
		const unsigned long __user *nmask, unsigned long maxnode)
{
	pr_debug("%s(mode=0x%x nmask=%p maxnode=%ld) CPU=%d pid=%d\n",
		 __func__, mode, nmask, maxnode, smp_processor_id(),
		 current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_migrate_pages(pid_t pid, unsigned long maxnode,
		const unsigned long __user *old_nodes,
		const unsigned long __user *new_nodes)
{
	pr_debug("%s(pid=%d maxnode=%ld old=%p new=%p) CPU=%d pid=%d\n",
		 __func__, pid, maxnode, old_nodes, new_nodes,
		 smp_processor_id(), current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_get_mempolicy(int __user *policy,
		unsigned long __user *nmask, unsigned long maxnode,
		unsigned long addr, unsigned long flags)
{
	pr_debug("%s(policy=%p nmask=%p maxnode=%ld addr=0x%lx flags=0x%lx) CPU=%d pid=%d\n",
		__func__, policy, nmask, maxnode, addr, flags,
		smp_processor_id(), current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_move_pages(pid_t pid, unsigned long nr_pages,
		const void __user *__user *pages,
		const int __user *nodes,
		int __user *status, int flags)
{
	pr_debug("%s(pid=%d nr_pages=%ld pages=%p nodes=%p status=%p flags=0x%x) CPU=%d pid=%d\n",
		 __func__, pid, nr_pages, pages, nodes, status, flags,
		 smp_processor_id(), current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_mincore(unsigned long start, size_t len,
		unsigned char __user *vec)
{
	pr_debug("%s(start=0x%lx len=%ld vec=%p) CPU=%d pid=%d\n",
		 __func__, start, len, vec, smp_processor_id(), current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_mlock(unsigned long start, size_t len)
{
	pr_debug("%s(start=0x%lx len=%ld) CPU=%d pid=%d\n",
		 __func__, start, len, smp_processor_id(), current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_munlock(unsigned long start, size_t len)
{
	pr_debug("%s(start=0x%lx len=%ld) CPU=%d pid=%d\n",
		 __func__, start, len, smp_processor_id(), current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_mlockall(int flags)
{
	pr_debug("%s(flags=0x%x) CPU=%d pid=%d\n",
		 __func__, flags, smp_processor_id(), current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_munlockall(void)
{
	pr_debug("%s() CPU=%d pid=%d\n",
		 __func__, smp_processor_id(), current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_mprotect(unsigned long start, size_t len_in,
		unsigned long prot)
{
	struct vm_area_struct *vma;
	struct mos_process_t *mosp = current->mos_process;
	bool read_lock_held = false;
	bool write_lock_held = false;
	long ret = -ENOSYS;
	size_t len = round_up(len_in, PAGE_SIZE);

	if (!mosp) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: pid %d is not an mOS process.",
			__func__, current->pid);
		goto out;
	}

	down_read(&current->mm->mmap_sem);
	read_lock_held = true;
	vma = mos_find_vma(current->mm, start);

	if (!vma)
		goto out;

	if (is_lwkmem(vma)) {
		/* We ignore PROT_NONE and also PROT_EXEC/PROT_READ bits. */
		if ((prot == PROT_NONE) || (prot & (PROT_EXEC | PROT_READ)))
			ret = 0;

	} else {
		if (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC | VM_MAYSHARE) ||
		    vma->vm_file || !mosp->lwkmem_prot_none_delegation)
			goto out;

		/* We need to unmap and then allocate LWK memory, so escalate
		 * the MM semaphore to a write lock.
		 */
		up_read(&current->mm->mmap_sem);
		read_lock_held = false;

		if (down_write_killable(&current->mm->mmap_sem)) {
			ret = -EINTR;
			goto out;
		}

		write_lock_held = true;

		/* Get the VMA again, ensuring that it is still appropriate
		 * for LWK reclamation:
		 */

		vma = mos_find_vma(current->mm, start);

		if (is_lwkmem(vma)) {
			/* We ignore PROT_NONE and PROT_EXEC/PROT_READ bits. */
			if ((prot == PROT_NONE) ||
			    (prot & (PROT_EXEC | PROT_READ)))
				ret = 0;
			goto out;
		}

		if (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC | VM_MAYSHARE) ||
		    vma->vm_file)
			goto out;

		trace_mos_unmapped_region(start, len, vma->vm_flags, current->tgid);

		if (do_munmap(current->mm, start, len, NULL)) {
			mos_ras(MOS_LWKMEM_PROCESS_WARNING,
				"%s: Could not unmap [%lx,%lx)",
				__func__, start, start + len);
			ret = -ENOMEM;
			goto out;
		}

		ret = allocate_blocks_fixed(start, len, prot,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
			    lwkmem_mmap);

		ret = (ret == start) ? 0 : -ENOMEM;
	}

 out:

	if (read_lock_held)
		up_read(&current->mm->mmap_sem);

	if (write_lock_held)
		up_write(&current->mm->mmap_sem);

	trace_mos_mprotect(start, len_in, prot, ret, current->tgid);
	return ret;
}

asmlinkage long lwk_sys_mremap(unsigned long addr, unsigned long old_len,
		unsigned long new_len, unsigned long flags,
		unsigned long new_addr)
{
	long ret;
	struct mos_process_t *mos_p;
	struct vm_area_struct *vma;
	int alloc_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
	int prot = 0;
	int i;
	unsigned long clear_len = 0;
	void *clear_addr = 0;

	static int vm_flags[] = { VM_MAYREAD, VM_MAYWRITE, VM_MAYEXEC };
	static int prot_flags[] = { PROT_READ, PROT_WRITE, PROT_EXEC };

	mos_p = current->mos_process;

	if (!mos_p) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: pid %d is not an mOS process.",
			__func__, current->pid);
		ret = -EFAULT;
		goto trace;
	}

	if (down_write_killable(&current->mm->mmap_sem)) {
		ret = -EINTR;
		goto trace;
	}

	vma = mos_find_vma(current->mm, addr);
	if (!vma || !is_lwkmem(vma)) {
		ret = -ENOSYS;
		goto out;
	}

	if (new_len <= old_len) {
		mos_ras(MOS_LWKMEM_PROCESS_WARNING,
			"%s: Attempted to shrink region via mremap.", __func__);
		ret = addr;
		goto out;
	}

	/* We don't yet support the scenario of remapping to a new, fixed
	 * location.
	 */

	if ((flags & MREMAP_FIXED) && (addr != new_addr)) {
		mos_ras(MOS_LWKMEM_PROCESS_WARNING,
			"%s: Unsupported relocation flags:%lx old:%lx new:%lx\n",
			__func__, flags, addr, new_addr);
		ret = -EINVAL;
		goto out;
	}

	/* Copy protection flags from the VMA: */
	for (i = 0; i < ARRAY_SIZE(vm_flags); i++)
		if (pgprot_val(vma->vm_page_prot) & vm_flags[i])
			prot |= prot_flags[i];

	ret = allocate_blocks_fixed(addr + old_len, new_len - old_len, prot,
				    alloc_flags, lwkmem_mmap);

	if (ret == (addr + old_len)) {
		clear_len = new_len - old_len;
		clear_addr = (void *) ret;
		ret = addr;
	} else {
		mos_ras(MOS_LWKMEM_PROCESS_WARNING,
			"%s: Unexpected remap %lx -> %lx\n",
			__func__, addr + old_len, ret);
		ret = -EFAULT;
	}

 out:
	up_write(&current->mm->mmap_sem);

 trace:
	trace_mos_mremap(addr, old_len, new_len, flags, new_addr, ret, current->tgid);


	return ret;
}

asmlinkage long lwk_sys_msync(unsigned long start, size_t len, int flags)
{
	pr_debug("%s(start=0x%lx len=%ld flags=0x%x) CPU=%d pid=%d\n",
		 __func__, start, len, flags, smp_processor_id(), current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_process_vm_readv(pid_t pid,
		const struct iovec __user *lvec, unsigned long liovcnt,
		const struct iovec __user *rvec, unsigned long riovcnt,
		unsigned long flags)
{
	pr_debug("%s(pid=%d lvec=%p lcnt=%ld rvec=%p rcnt=%ld flags=0x%lx) CPU=%d pid=%d\n",
		 __func__, pid, lvec, liovcnt, rvec, riovcnt, flags,
		 smp_processor_id(), current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_process_vm_writev(pid_t pid,
		const struct iovec __user *lvec,
		unsigned long liovcnt, const struct iovec __user *rvec,
		unsigned long riovcnt, unsigned long flags)
{
	pr_debug("%s(pid=%d lvec=%p lcnt=%ld rvec=%p rcnt=%ld flags=0x%lx) CPU=%d pid=%d\n",
		 __func__, pid, lvec, liovcnt, rvec, riovcnt, flags,
		 smp_processor_id(), current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_readahead(int fd, loff_t offset, size_t count)
{
	pr_debug("%s(fd=%d offs=0x%llx cnt=%ld) CPU=%d pid=%d\n",
		 __func__, fd, offset, count, smp_processor_id(), current->pid);

	return -ENOSYS;
}

asmlinkage long lwk_sys_memfd_create(const char __user *uname,
		unsigned int flags)
{
	pr_debug("%s(uname=%p flags=0x%x) CPU=%d pid=%d\n",
		 __func__, uname, flags, smp_processor_id(), current->pid);

	return -ENOSYS;
}

SYSCALL_DEFINE4(mos_get_addr_info,
	unsigned long, addr,
	unsigned long *, phys_addr,
	int *, numa_domain,
	int *, page_size)
{
	return -EINVAL;
}

static int64_t kind_size[kind_last] = {SZ_4K, SZ_2M, SZ_1G};

asmlinkage long lwk_sys_mos_get_addr_info(unsigned long addr,
		unsigned long *phys_addr, int *numa_domain, int *page_size)
{
	int rc = 0;
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct page *phys_page = 0;
	int size, numa = -1;
	struct mos_process_t *mosp;
	int nid;
	enum lwkmem_kind_t knd;
	struct list_head *busyl;
	struct blk_list *bl;
	int i;
	unsigned long offset, left, right;
	unsigned long virt_end;

	vma = mos_find_vma(mm, addr);
	if (!vma) {
		pr_debug("%s() Can't find vma\n", __func__);
		rc = -EINVAL;
		goto out;
	}

	if (!is_lwkmem(vma)) {
		/* FIXME: For now. Eventually we want to return info for Linux
		 * addresses as well.
		 */
		pr_debug("%s() This probably is a Linux address\n", __func__);
		rc = -EINVAL;
		goto out;
	}

	mosp = current->mos_process;
	if (!mosp)   {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: pid %d is not an mOS process.",
			__func__, current->pid);
		return -ENOSYS;
	}

	phys_page = lwkmem_user_to_page(mm, addr, &size);

	if (phys_page == NULL)   {
		rc = -EINVAL;
		goto out;
	}

	if (size == SZ_1G)   {
		knd = kind_1g;
	} else if (size == SZ_2M)   {
		knd = kind_2m;
	} else if (size == SZ_4K)   {
		knd = kind_4k;
	} else   {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: Unknown page size %d.",
			__func__, size);
		rc = -EINVAL;
		goto out;
	}

	/* Find the block list and numa domain */
	down_read(&current->mm->mmap_sem);

	for_each_online_node(nid)   {
		busyl = &mosp->busy_list[knd][nid];
		list_for_each_entry(bl, busyl, list)   {
			virt_end = bl->vma_addr + block_size_virt(bl, knd);
			if ((addr < bl->vma_addr) || (addr >= virt_end))
				/* Virt addr not within this block. No point in
				 * iterrating over sub-block
				 */
				continue;

			/* If this is a contigous block, and addr is within it
			 * then we found it
			 */
			if (bl->stride == 1)   {
				numa = bl->phys->nid;
				goto found_it;
			}

			/* This is a strided block and addr might be within it.
			 * Check each sub-block
			 */
			for (i = 0; i < bl->num_blks; i++) {
				offset = i * bl->stride * kind_size[knd];
				left = bl->vma_addr + offset;
				right = left + kind_size[knd];

				if ((addr >= left) && (addr < right))   {
					numa = bl->phys->nid;
					goto found_it;
				}
			}
		}
	}

found_it:
	up_read(&current->mm->mmap_sem);

	if (numa < 0)   {
		pr_debug("%s() No NUMA domain for virt 0x%lx\n",
			 __func__, addr);
		rc = -EINVAL;
		goto out;
	}

	if (put_user(page_to_phys(phys_page), phys_addr) ||
	    put_user(size, page_size) ||
	    put_user(numa, numa_domain)) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: put_user() failed.", __func__);
		rc = -EACCES;
		goto out;
	}
out:
	pr_debug("%s() v_addr 0x%lx = p_addr 0x%llx, page size %d, numa domain %d\n",
		 __func__, addr, phys_page ? page_to_phys(phys_page) : 0, size, numa);
	return rc;

}
