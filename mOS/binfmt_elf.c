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
#include "lwkmem.h"

/**
 * elf_map_to_lwkmem() - maps an ELF segment to LWKMEM
 * @eppnt: pointer to the program header of the segment to be mapped
 * @addr: fixed address in virtual memory where this segment needs to be mapped
 * @prot: protection flags corresponding to this segment
 * @type: vma flags corresponding to this segment
 *
 * The function returns,
 *      In case of success, the mapped address
 *      In case of failure, an error code
 */
unsigned long elf_map_to_lwkmem(struct elf_phdr *eppnt, unsigned long addr,
				unsigned long size, int prot, int type)
{
	struct mos_process_t *mosp;
	unsigned long map_addr;

	mosp = current->mos_process;

	if (unlikely(LWKMEM_DEBUG_VERBOSE))
		pr_info("%s: addr 0x%lx size 0x%lx\n", __func__, addr, size);

	/*
	 * mmap() will return -EINVAL if given a zero size, but a
	 * segment with zero filesize is perfectly valid
	 */
	if (!size)
		return addr;

	map_addr = allocate_blocks_fixed(addr, size, prot, type,
					 lwkmem_mmap);

	if (unlikely(LWKMEM_DEBUG_VERBOSE))
		pr_info("%s: map_addr 0x%lx\n",  __func__, map_addr);

	return map_addr;
}

/**
 * elf_unmap_from_lwkmem() - unmaps a previously mapped ELF segment from LWKMEM
 * @eppnt: pointer to the program header of the segment to be unmapped
 * @addr: start address of the segment to be unmapped
 */
long elf_unmap_from_lwkmem(struct elf_phdr *eppnt, unsigned long addr,
			   unsigned long size)
{
	if (!size)
		return addr;

	return deallocate_blocks(addr, size, current->mos_process);
}
