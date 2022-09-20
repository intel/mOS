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
#include <linux/mos.h>
#include <trace/events/lwkmem.h>

/* Private headers */
#include "lwk_mm_private.h"

/*
 * TODO: Implement dynamic update of memory protections. Currently LWK VMA
 *       page tables are always set to RWE during page table mapping.
 */
unsigned long lwk_mm_change_protection(struct vm_area_struct *vma,
				       unsigned long start, unsigned long end,
				       pgprot_t newprot)
{
	return 0;
}

