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

#ifndef _LWKCPU_H_
#define _LWKCPU_H_

#include <linux/cpumask.h>

#define LWKCPU_MAX_STATE	(CPUHP_AP_ACTIVE - 1)
#define LWKCPU_MIN_STATE	CPUHP_OFFLINE

#define LWKCPU_FILTER_STATES {			\
	CPUHP_AP_WORKQUEUE_ONLINE,		\
	CPUHP_AP_RCUTREE_ONLINE,		\
	}

#define LWKCPU_PROF_NOR	"normal"
#define LWKCPU_PROF_DBG	"debug"

extern int lwkcpu_up(unsigned int cpu);
extern int lwkcpu_down(unsigned int cpu);
extern int lwkcpu_up_multiple(cpumask_var_t request, cpumask_var_t booted);
extern int lwkcpu_down_multiple(cpumask_var_t request, cpumask_var_t shutdown);
extern int lwkcpu_reset(unsigned int cpu);
extern void lwkcpu_set_state(enum cpuhp_state state, bool val);
extern int lwkcpu_state_init(char *profile);
extern void lwkcpu_state_deinit(void);

#endif /* _LWKCPU_H_ */
