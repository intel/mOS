/*
 * Multi Operating System (mOS)
 * Copyright (c) 2017, Intel Corporation.
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

#include <unistd.h>
#include <uapi/asm-generic/unistd.h>
#include <uapi/linux/mos.h>

/* mOS memory system calls */

long mos_get_addr_info(unsigned long addr, unsigned long *phys_addr,
			int *numa_domain, int *page_size)
{
	return syscall(510, addr, phys_addr, numa_domain, page_size);
}

/* mOS scheduler system calls */

long mos_set_clone_attr(struct mos_clone_attr *attr,
			unsigned long maxnodes,
			unsigned long *nodes,
			struct mos_clone_result *result,
			unsigned long location_key)
{
	return syscall(511, attr, maxnodes, nodes, result, location_key);
}


long mos_mwait(unsigned int sleep_level,
		unsigned long *location,
		unsigned long prev_value,
		unsigned int msec_timeout)
{
	return syscall(509, sleep_level, location, prev_value, msec_timeout);
}


/* other mOS system calls */
