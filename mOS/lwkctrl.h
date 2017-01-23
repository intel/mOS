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

#ifndef _LWK_CTRL_H_
#define _LWK_CTRL_H_

#include <asm/setup.h>
#include <linux/cpumask.h>

#define LWKCTRL_CPUS_SPECSZ		COMMAND_LINE_SIZE
#define LWKCTRL_MEM_SPECSZ		256
#define LWKCTRL_CPU_PROFILE_SPECSZ	64

/*
 * Describes the LWK partition
 * @lwkcpus, CPU mask of cpus that need to be taken out from Linux
 *           and allocated to LWK
 */
struct lwkctrl_partition {
	cpumask_var_t lwkcpus;
};

extern int lwkctrl_partition_create(struct lwkctrl_partition *p);
extern int lwkctrl_partition_destroy(struct lwkctrl_partition *p);
extern char lwkctrl_cpus_spec[LWKCTRL_CPUS_SPECSZ];
extern char lwkctrl_cpu_profile_spec[LWKCTRL_CPU_PROFILE_SPECSZ];
extern char lwkctrl_mem_spec[LWKCTRL_MEM_SPECSZ];

#endif

