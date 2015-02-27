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

#include <linux/printk.h>
#include <linux/mos.h>
#include <linux/ftrace.h>
#include "lwkmem.h"

#include <trace/events/lwkmem.h>

/**
 * elf_map_to_lwkmem() - maps an ELF segment to LWKMEM
 * @addr: fixed address in virtual memory where this segment needs to be mapped
 * @size: length of the region
 * @prot: protection flags corresponding to this segment
 * @type: vma flags corresponding to this segment
 *
 * The function returns,
 *      In case of success, the mapped address
 *      In case of failure, an error code
 */
unsigned long elf_map_to_lwkmem(unsigned long addr, unsigned long size,
				int prot, int type)
{
	struct mos_process_t *mosp;
	unsigned long map_addr;

	mosp = current->mos_process;

	if (!mosp) {
		mos_ras(MOS_LWKMEM_PROCESS_ERROR,
			"%s: pid %d is not an mOS process.",
			__func__, current->pid);
		map_addr = -EINVAL;
		goto out;
	}
	/*
	 * mmap() will return -EINVAL if given a zero size, but a
	 * segment with zero filesize is perfectly valid
	 */
	if (!size) {
		map_addr = addr;
		goto out;
	}

	if (down_write_killable(&current->mm->mmap_sem)) {
		map_addr = -EINTR;
		goto out;
	}

	map_addr = allocate_blocks_fixed(addr, size, prot, type,
					 lwkmem_static);

	up_write(&current->mm->mmap_sem);

 out:
	trace_mos_elf_map(addr, size, prot, type, current->tgid);

	return map_addr;
}

/**
 * elf_unmap_from_lwkmem() - unmaps a previously mapped ELF segment from LWKMEM
 * @addr: start address of the segment to be unmapped
 * @size: length of the region
 */
long elf_unmap_from_lwkmem(unsigned long addr, unsigned long size)
{
	long rc;

	if (!size)
		return addr;

	if (down_write_killable(&current->mm->mmap_sem))
		return -EINTR;

	rc = deallocate_blocks(addr, size, current->mos_process, current->mm);

	up_write(&current->mm->mmap_sem);

	return rc;
}
