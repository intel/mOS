/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016, Intel Corporation.
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

#include "lwkmem.h"

#undef pr_fmt
#define pr_fmt(fmt)	"mOS-mmap: " fmt


extern void list_vmas(struct mm_struct *mm);

asmlinkage long lwk_sys_munmap(unsigned long addr, size_t len)
{
	struct mm_struct *mm = current->mm;
	struct mos_process_t *mos_p;
	struct vm_area_struct *vma;

	if (LWKMEM_DEBUG)
		pr_info("%s(addr=0x%lx len=%ld) CPU=%d pid=%d nst=%d\n",
			__func__, addr, len,
			smp_processor_id(), current->pid, current->mos_nesting);

	/*
	 * If addr is in LWK memory, we need to do something here.
	 * Otherwise, let the Linux sys_munmap handle it.
	 */

	mos_p = current->mos_process;

	if (!mos_p) {
		pr_warn("(!) %s() not an mOS pid %d\n", __func__, current->pid);
		return -ENOSYS;
	}

	vma = find_vma(mm, addr);
	if (!vma) {
		pr_warn("(!)  %s() no vma for pid %d\n", __func__,
			current->pid);
		return -ENOSYS;
	}

	if (is_lwkmem(vma))
		/* Deallocate LWK memory blocks.  If this fails, we are going to
		 * continue regardless; we may not have cleaned up completely
		 * but we are no worse off than we were before.
		 */
		deallocate_blocks(addr, len, mos_p);

	return -ENOSYS;
} /* end of lwk_sys_munmap() */

asmlinkage long lwk_sys_mmap_pgoff(unsigned long addr, unsigned long len,
		unsigned long prot, unsigned long flags,
		unsigned long fd, unsigned long pgoff)
{
	struct vm_area_struct *vma;
	struct mos_process_t *mosp;
	struct allocate_options_t *opts = 0;
	long ret;
	unsigned long rc;

	if (LWKMEM_DEBUG)
		pr_info("%s(addr=0x%lx len=%ld prot=%lx flags=%lx fd=%ld off=%lX) CPU=%d pid=%d nst=%d\n",
			__func__, addr, len, prot, flags, fd, pgoff,
			smp_processor_id(), current->pid, current->mos_nesting);

	mosp = current->mos_process;
	if (!mosp) {
		if (LWKMEM_DEBUG_VERBOSE)
			pr_warn("CPU %3d %s() addr 0x%lx, len %lu, flags 0x%lx, pgoff %lu, not an mOS pid %d\n",
			       smp_processor_id(), __func__, addr, len, flags,
			       pgoff, current->pid);

		/* Let Linux deal with this, if it is not a mOS task */
		return -ENOSYS;
	}

	if (mosp->lwkmem <= 0) {
		if (LWKMEM_DEBUG_VERBOSE)
			pr_info("CPU %3d %s() addr 0x%lx, len %lu, flags 0x%lx, pgoff %lu, no lwkmem yet\n",
			       smp_processor_id(), __func__, addr, len, flags,
			       pgoff);
		return -ENOSYS;
	}

	/* Only anonymous mmap for now */
	if (!(flags & MAP_ANONYMOUS)) {
		if (LWKMEM_DEBUG_VERBOSE)
			pr_info("CPU %3d %s() addr 0x%lx, len %lu, flags 0x%lx, pgoff %lu, not anonymous\n",
			       smp_processor_id(), __func__, addr, len, flags,
			       pgoff);
		return -ENOSYS;
	}

	/* Alignment test from arch/x86/kernel/sys_x86_64.c */
	if (pgoff & ~PAGE_MASK) {
		if (LWKMEM_DEBUG_VERBOSE)
			pr_warn("CPU %3d %s() addr 0x%lx, len %lu, flags 0x%lx, pgoff %lu, offset not aligned\n",
			       smp_processor_id(), __func__, addr, len, flags,
			       pgoff);
		return -EINVAL;
	}

	if (fd != 0x00000000ffffffff) {
		/* This should not be with MAP_ANONYMOUS */
		if (LWKMEM_DEBUG_VERBOSE)
			pr_warn("CPU %3d %s() addr 0x%lx, len %lu, flags 0x%lx, pgoff %lu, fd not -1: %p\n",
			       smp_processor_id(), __func__, addr, len, flags,
			       pgoff, (void *)fd);
	} else {
		if (LWKMEM_DEBUG_VERBOSE)
			pr_info("CPU %3d %s() addr 0x%lx, len %lu, flags 0x%lx, pgoff %lu\n",
			       smp_processor_id(), __func__, addr, len, flags,
			       pgoff);
	}

	vma = find_vma(current->mm, addr);
	if ((addr != 0) && vma) {
		if (LWKMEM_DEBUG_VERBOSE) {
			pr_info("addr 0x%lx already has a vma!\n", addr);
			list_vmas(current->mm);
		}

		if (!is_lwkmem(vma)) {
			if (LWKMEM_DEBUG_VERBOSE)
				pr_info("... and it is not one of ours. Let Linux handle it\n");
			return -ENOSYS;
		}
	}

	if (mosp->lwkmem_mmap_fixed && len >= mosp->lwkmem_mmap_fixed) {
		unsigned long fixed;

		fixed = next_lwkmem_address(len, mosp);
		ret = allocate_blocks_fixed(fixed, len, prot, flags | MAP_FIXED,
					    lwkmem_mmap);
	} else {

		opts = allocate_options_factory(lwkmem_mmap, len, flags, mosp);

		ret = opts ?
			allocate_blocks(addr, len, prot, flags, pgoff, opts) :
			-ENOMEM;
	}

	kfree(opts);

	if (ret <= 0) {
		pr_warn("Out of LWK memory\n");
		return -ENOMEM;
	}

	/* For MAP_ANONYMOUS memory needs to be cleared */
	rc = clear_user((void *)ret, len);
	if (rc)
		pr_warn("Only some memory cleared: %ld/%ld\n", rc, len);

	return ret;

} /* end of lwk_sys_mmap_pgoff() */

asmlinkage long lwk_sys_mmap(unsigned long addr, unsigned long len,
		unsigned long prot, unsigned long flags,
		unsigned long fd, unsigned long pgoff)
{
	return lwk_sys_mmap_pgoff(addr, len, prot, flags, fd, pgoff);
}

#ifdef __ARCH_WANT_SYS_OLD_MMAP
asmlinkage long lwk_sys_old_mmap(struct mmap_arg_struct __user *arg)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(arg=%p) CPU=%d pid=%d nst=%d\n",
		       __func__, arg,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_old_mmap(arg);

	--current->mos_nesting;
	return ret;
}
#endif /* __ARCH_WANT_SYS_OLD_MMAP */

asmlinkage long lwk_sys_brk(unsigned long brk)
{
	long ret;
	struct mos_process_t *mosp;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
	struct mm_struct *mm = current->mm;
	unsigned long len;

	if (LWKMEM_DEBUG)
		pr_info("(pid=%4d) %s(brk=%lx) CPU=%d nst=%d\n", current->pid,
			__func__, brk, smp_processor_id(),
			current->mos_nesting);

	mosp = current->mos_process;

	if (current->mos_nesting > 0 || !mosp)
		return -ENOSYS;

	if (mosp->yod_mm == mm) {
		pr_warn("(> %4d) Yod calling %s()\n", current->pid, __func__);
		return -ENOSYS;
	}

	if (LWKMEM_DEBUG_VERBOSE)
		pr_info("(> %4d) %s(%lx) mos brk=%lx end=%lx CPU=%d\n",
			current->pid, __func__, brk, mosp->brk, mosp->brk_end,
			smp_processor_id());

	current->mos_nesting++;

	if (mosp->lwkmem_brk_disable) {
		ret = sys_brk(brk);
	} else if (mosp->brk == 0) {
		/* First time here. Allocate initial block of LWK memory for
		 * the heap in this process. Align it so future requests can
		 * be satisfied in heap_page_size chunks.
		 */
		unsigned long heap_addr;

		heap_addr = roundup(mm->brk, mosp->heap_page_size);
		if (LWKMEM_DEBUG_VERBOSE)
			pr_info("(> %4d) Using mm->brk 0x%lx as lower bound for 0x%lx\n",
				current->pid, mm->brk, heap_addr);

		if (LWKMEM_DEBUG_VERBOSE) {
			pr_info("(> %4d) Attempt to set our own brk at 0x%lx\n",
				current->pid, heap_addr);
			pr_info("(> %4d) mm->start_code 0x%lx, mm->end_code 0x%lx\n",
				current->pid, mm->start_code, mm->end_code);
			pr_info("(> %4d) mm->start_data 0x%lx, mm->end_data 0x%lx\n",
				current->pid, mm->start_data, mm->end_data);
			pr_info("(> %4d) mm->start_brk 0x%lx, mm->brk 0x%lx\n",
				current->pid, mm->start_brk, mm->brk);
			pr_info("(> %4d) mm->start_stack 0x%lx\n",
				current->pid, mm->start_stack);
			pr_info("(> %4d) mm->arg_start 0x%lx, mm->arg_end 0x%lx\n",
				current->pid, mm->arg_start, mm->arg_end);
			pr_info("(> %4d) mm->env_start 0x%lx, mm->env_end 0x%lx\n",
				current->pid, mm->env_start, mm->env_end);
		}

		/* A couple of sanity checks */
		if (brk != 0)
			pr_warn("(> %4d) Why is brk(%ld) not 0?\n",
				current->pid, brk);

		if (mm->start_brk != mm->brk)   {
			pr_warn("(> %4d) start_brk 0x%lx != brk 0x%lx Should not be\n",
				 current->pid, mm->start_brk, mm->brk);
		}

		ret = allocate_blocks_fixed(heap_addr, mosp->heap_page_size,
					    PROT_READ | PROT_WRITE,
					    flags, lwkmem_brk);

		if (ret != heap_addr) {
			pr_warn("(! %4d) Requested heap addr %ld, but allocate_blocks_fixed()\n",
				current->pid, heap_addr);
			pr_warn("(! %4d) returned %ld, falling back to Linux sys_brk()\n",
				current->pid, ret);
			ret = mosp->brk = mosp->brk_end = sys_brk(brk);
		} else {
			ret = clear_user((void *)heap_addr,
				mosp->heap_page_size);
			if (ret)
				pr_warn("(! %4d) Only %lld/%lld cleared (bootstrap)\n",
					current->pid,
					mosp->heap_page_size - ret,
					mosp->heap_page_size);

			ret = mosp->brk = heap_addr;
			mosp->brk_end = heap_addr + mosp->heap_page_size;
			mm->start_brk = mosp->brk;
			mm->brk = mosp->brk_end;
		}

		if (LWKMEM_DEBUG_VERBOSE)
			pr_info("(> %4d) The mOS brk is at %lx\n", current->pid,
				mosp->brk);

	} else if (brk == 0) {
		/* Just a query. */
		ret = mosp->brk;
		if (LWKMEM_DEBUG_VERBOSE)
			pr_info("(> %4d) Just a query, returning brk = 0x%lx\n",
				current->pid, ret);

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

		unsigned long clear_len = brk - mosp->brk;

		if (brk <= mosp->brk_end) {
			len = brk - mosp->brk;
			if (LWKMEM_DEBUG_VERBOSE)
				pr_info("(> %4d) Sufficient space old 0x%lx + %ld = brk=%lx <= brk-end=%lx\n",
					current->pid, mosp->brk, len, brk,
					mosp->brk_end);
			if (mosp->brk_clear_len >= 0 &&
			    mosp->brk_clear_len < clear_len)
				clear_len = mosp->brk_clear_len;
		} else {

			len = roundup(brk, mosp->heap_page_size) -
				mosp->brk_end;
			if (LWKMEM_DEBUG_VERBOSE)
				pr_info("(> %4d) Expanding brk by %ld bytes (brk=%lx brk_end=%lx)\n",
					current->pid, len, brk, mosp->brk_end);

			ret = allocate_blocks_fixed(mosp->brk_end, len,
						    PROT_READ | PROT_WRITE,
						    flags, lwkmem_brk);

			if (ret != mosp->brk_end) {
				pr_warn("(! %4d) allocate_blocks_fixed(len %ld) failed\n",
					current->pid, len);
				ret = -1;
				goto out;
			}
			mosp->brk_end += len;
		}

		/* Clear only the newly requested amount */
		ret = clear_len > 0 ?
			clear_user((void *)mosp->brk, clear_len) : 0;
		if (ret)
			pr_warn("(! %4d) Only %ld/%ld cleared (expand)\n",
				current->pid, clear_len - ret, len);

		ret = mosp->brk = brk;
	} else {
		/* Shrinking the brk line.  We don't give memory back at this
		 * time ... just move the line back.  If it grows again, we
		 * are pre allocated.
		 */
		if (LWKMEM_DEBUG_VERBOSE)
			pr_info("(> %4d) Shrinking heap brk=%lx. len=%ld\n",
				current->pid, brk, mosp->brk_end - brk);

		ret = mosp->brk = brk;
	}

 out:
	if (brk && ret != brk)
		pr_warn("(! %4d) ret=%lx CPU=%d\n",
			current->pid, ret, smp_processor_id());
	else if (LWKMEM_DEBUG_VERBOSE)
		pr_info("(< %4d) %s(%lx) -> %lx brk=%lx end=%lx CPU=%d\n",
			current->pid, __func__, brk, ret, mosp->brk,
			mosp->brk_end, smp_processor_id());

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_remap_file_pages(unsigned long start,
		unsigned long size, unsigned long prot, unsigned long pgoff,
		unsigned long flags)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(start=0x%lx size=%ld prot=0x%lx off=0x%lx flags=0x%lx) CPU=%d pid=%d nst=%d\n",
		       __func__, start, size, prot, pgoff, flags,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_remap_file_pages(start, size, prot, pgoff, flags);

	--current->mos_nesting;
	return ret;
}

/*
** sys_madvise() needs to be an LWK function.
** Any Linux policy settings are not likely to be appropriate for LWK memory.
** Also, letting Linux unmap pages after a MADV_DONTNEED can lead to page
** faults.
*/
asmlinkage long lwk_sys_madvise(unsigned long start, size_t len_in,
		int behavior)
{
	struct mm_struct *mm = current->mm;
	struct mos_process_t *mos_p;
	struct vm_area_struct *vma;
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(start=0x%lx len=%ld behav=0x%x) CPU=%d pid=%d nst=%d\n",
		       __func__, start, len_in, behavior,
		       smp_processor_id(), current->pid, current->mos_nesting);

	mos_p = current->mos_process;

	if (!mos_p) {
		pr_warn("(!) %s() not an mOS pid %d\n", __func__, current->pid);
		return -ENOSYS;
	}

	vma = find_vma(mm, start);
	if (!vma) {
		pr_warn("(!) %s() no vma for pid %d\n", __func__, current->pid);
		return -ENOSYS;
	}

	if (is_lwkmem(vma))
		ret = 0;
	else
		/* Not LWK memory; let Linux handle it */
		ret = -ENOSYS;

	return ret;

}

asmlinkage long lwk_sys_mbind(unsigned long start, unsigned long len,
		unsigned long mode, const unsigned long __user *nmask,
		unsigned long maxnode, unsigned flags)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(start=0x%lx len=%ld mode=0x%lx nmask=%p maxnode=%ld flags=0x%x) CPU=%d pid=%d nst=%d\n",
		       __func__, start, len, mode, nmask, maxnode, flags,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_mbind(start, len, mode, nmask, maxnode, flags);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_set_mempolicy(int mode,
		const unsigned long __user *nmask, unsigned long maxnode)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(mode=0x%x nmask=%p maxnode=%ld) CPU=%d pid=%d nst=%d\n",
		       __func__, mode, nmask, maxnode,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_set_mempolicy(mode, nmask, maxnode);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_migrate_pages(pid_t pid, unsigned long maxnode,
		const unsigned long __user *old_nodes,
		const unsigned long __user *new_nodes)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(pid=%d maxnode=%ld old=%p new=%p) CPU=%d pid=%d nst=%d\n",
		       __func__, pid, maxnode, old_nodes, new_nodes,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_migrate_pages(pid, maxnode, old_nodes, new_nodes);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_get_mempolicy(int __user *policy,
		unsigned long __user *nmask, unsigned long maxnode,
		unsigned long addr, unsigned long flags)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(policy=%p nmask=%p maxnode=%ld addr=0x%lx flags=0x%lx) CPU=%d pid=%d nst=%d\n",
		       __func__, policy, nmask, maxnode, addr, flags,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_get_mempolicy(policy, nmask, maxnode, addr, flags);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_move_pages(pid_t pid, unsigned long nr_pages,
		const void __user *__user *pages,
		const int __user *nodes,
		int __user *status, int flags)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(pid=%d nr_pages=%ld pages=%p nodes=%p status=%p flags=0x%x) CPU=%d pid=%d nst=%d\n",
		       __func__, pid, nr_pages, pages, nodes, status, flags,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_move_pages(pid, nr_pages, pages, nodes, status, flags);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_mincore(unsigned long start, size_t len,
		unsigned char __user *vec)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(start=0x%lx len=%ld vec=%p) CPU=%d pid=%d nst=%d\n",
		       __func__, start, len, vec,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_mincore(start, len, vec);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_mlock(unsigned long start, size_t len)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(start=0x%lx len=%ld) CPU=%d pid=%d nst=%d\n",
		       __func__, start, len,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_mlock(start, len);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_munlock(unsigned long start, size_t len)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(start=0x%lx len=%ld) CPU=%d pid=%d nst=%d\n",
		       __func__, start, len,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_munlock(start, len);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_mlockall(int flags)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(flags=0x%x) CPU=%d pid=%d nst=%d\n",
		       __func__, flags,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_mlockall(flags);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_munlockall(void)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s() CPU=%d pid=%d nst=%d\n",
		       __func__,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_munlockall();

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_mprotect(unsigned long start, size_t len,
		unsigned long prot)
{
	long ret;
	struct vm_area_struct *vma;

	if (LWKMEM_DEBUG) {
		pr_info("%s(start=0x%lx len=%ld prot=0x%lx) CPU=%d",
		       __func__, start, len, prot, smp_processor_id());
		pr_info("pid=%d nst=%d\n", current->pid, current->mos_nesting);
	}

	vma = find_vma(current->mm, start);
	if (vma && is_lwkmem(vma) &&
		((prot == PROT_NONE) || (prot == PROT_READ))) {
		if (LWKMEM_DEBUG)
			pr_warn("(!) LWK mprotect ignores PROT_NONE and PROT_READ).\n");

		return 0;
	}

	if (current->mos_nesting > 0)
		return -ENOSYS;


	current->mos_nesting++;

	ret = sys_mprotect(start, len, prot);

	--current->mos_nesting;
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

	static int vm_flags[] = { VM_MAYREAD, VM_MAYWRITE, VM_MAYEXEC };
	static int prot_flags[] = { PROT_READ, PROT_WRITE, PROT_EXEC };

	if (LWKMEM_DEBUG)
		pr_info("%s(addr=0x%lx oldlen=%ld newlen=%ld flags=0x%lx newaddr=0x%lx) CPU=%d pid=%d nst=%d\n",
		       __func__, addr, old_len, new_len, flags, new_addr,
		       smp_processor_id(), current->pid, current->mos_nesting);

	mos_p = current->mos_process;

	if (!mos_p) {
		pr_err("(!) %s() : not an mOS pid %d\n",
			__func__, current->pid);
		return -EFAULT;
	}

	vma = find_vma(current->mm, addr);

	if (!vma || !is_lwkmem(vma)) {
		if (LWKMEM_DEBUG_VERBOSE)
			pr_info("mremap: VMA 0x%lx is not LWK memory.\n", addr);
		return -ENOSYS;
	}

	if (new_len <= old_len) {
		pr_err("%s() : mremap shrank region.\n", __func__);
		ret = addr;
		goto out;
	}

	/* We don't yet support the scenario of remapping to a new, fixed
	 * location.
	 */

	if ((flags & MREMAP_FIXED) && (addr != new_addr)) {
		pr_info("%s() : unsupported relocation flags:%lx old:%lx new:%lx\n",
			__func__, flags, addr, new_addr);
		ret = -EINVAL;
		goto out;
	}

	/* Copy protection flags from the VMA: */

	for (i = 0; i < ARRAY_SIZE(vm_flags); i++)
		if (pgprot_val(vma->vm_page_prot) & vm_flags[i])
			prot |= prot_flags[i];

	ret = allocate_blocks_fixed(addr + old_len, new_len - old_len, prot,
				    alloc_flags, lwkmem_mremap);

	if (ret == (addr + old_len)) {
		ret = clear_user((void *)ret, new_len - old_len);
		if (ret)
			pr_warn("Only some remapped memory cleared: %ld\n",
				ret);
		ret = addr;
	} else {
		pr_info("%s() : unexpected remap %lx -> %lx\n",
			__func__, addr + old_len, ret);
		ret = -EFAULT;
	}

 out:
	if (LWKMEM_DEBUG)
		pr_info("(<) %s(addr=0x%lx oldlen=%ld newlen=%ld flags=0x%lx newaddr=0x%lx) = %lx CPU=%d pid=%d nst=%d\n",
			__func__, addr, old_len, new_len, flags, new_addr,
			ret, smp_processor_id(), current->pid,
			current->mos_nesting);
	return ret;
}

asmlinkage long lwk_sys_msync(unsigned long start, size_t len, int flags)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(start=0x%lx len=%ld flags=0x%x) CPU=%d pid=%d nst=%d\n",
		       __func__, start, len, flags,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_msync(start, len, flags);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_process_vm_readv(pid_t pid,
		const struct iovec __user *lvec, unsigned long liovcnt,
		const struct iovec __user *rvec, unsigned long riovcnt,
		unsigned long flags)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(pid=%d lvec=%p lcnt=%ld rvec=%p rcnt=%ld flags=0x%lx) CPU=%d pid=%d nst=%d\n",
		       __func__, pid, lvec, liovcnt, rvec, riovcnt, flags,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_process_vm_writev(pid_t pid,
		const struct iovec __user *lvec,
		unsigned long liovcnt, const struct iovec __user *rvec,
		unsigned long riovcnt, unsigned long flags)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(pid=%d lvec=%p lcnt=%ld rvec=%p rcnt=%ld flags=0x%lx) CPU=%d pid=%d nst=%d\n",
		       __func__, pid, lvec, liovcnt, rvec, riovcnt, flags,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_readahead(int fd, loff_t offset, size_t count)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(fd=%d offs=0x%llx cnt=%ld) CPU=%d pid=%d nst=%d\n",
		       __func__, fd, offset, count,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_readahead(fd, offset, count);

	--current->mos_nesting;
	return ret;
}

asmlinkage long lwk_sys_memfd_create(const char __user *uname,
		unsigned int flags)
{
	long ret;

	if (LWKMEM_DEBUG)
		pr_info("%s(uname=%p flags=0x%x) CPU=%d pid=%d nst=%d\n",
		       __func__, uname, flags,
		       smp_processor_id(), current->pid, current->mos_nesting);

	if (current->mos_nesting > 0)
		return -ENOSYS;

	current->mos_nesting++;

	ret = sys_memfd_create(uname, flags);

	--current->mos_nesting;
	return ret;
}
