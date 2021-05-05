/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016-2017 Intel Corporation.
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
#include <linux/nodemask.h>

#define LWKCTRL_CPUS_SPECSZ		COMMAND_LINE_SIZE
#define LWKCTRL_MEM_SPECSZ		256
#define LWKCTRL_CPU_PROFILE_SPECSZ	64

extern int lwkcpu_partition_create(cpumask_var_t lwkcpu_req);
extern int lwkcpu_partition_destroy(cpumask_var_t lwkcpu_req);
extern int lwkmem_partition_create(char *spec, bool precise);
extern int lwkmem_partition_destroy(void);
extern int lwkmem_partition_clear_memory(void);
extern char *lwkmem_get_spec(void);
extern int lwkmem_distribute_request(resource_size_t req, nodemask_t *mask,
		resource_size_t *node_size);
extern char lwkctrl_cpus_spec[LWKCTRL_CPUS_SPECSZ];
extern char lwkctrl_cpu_profile_spec[LWKCTRL_CPU_PROFILE_SPECSZ];
extern bool lwkmem_static_enabled;
#endif
