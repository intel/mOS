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

#define LWKCPU_MAX_STATE	CPUHP_AP_NOTIFY_ONLINE
#define LWKCPU_MIN_STATE	CPUHP_OFFLINE

#define LWKCPU_BASE_STATES {			\
	CPUHP_OFFLINE,				\
	CPUHP_CREATE_THREADS,			\
	CPUHP_SOFTIRQ_DEAD,			\
	CPUHP_IRQ_POLL_DEAD,			\
	CPUHP_BLOCK_SOFTIRQ_DEAD,		\
	CPUHP_ACPI_CPUDRV_DEAD,			\
	CPUHP_WORKQUEUE_PREP,			\
	CPUHP_HRTIMERS_PREPARE,			\
	CPUHP_X2APIC_PREPARE,			\
	CPUHP_SMPCFD_PREPARE,			\
	CPUHP_RCUTREE_PREP,			\
	CPUHP_NOTIFY_PREPARE,			\
	CPUHP_TIMERS_DEAD,			\
	CPUHP_BRINGUP_CPU,			\
	CPUHP_AP_IDLE_DEAD,			\
	CPUHP_AP_OFFLINE,			\
	CPUHP_AP_SCHED_STARTING,		\
	CPUHP_AP_RCUTREE_DYING,			\
	CPUHP_AP_SMPCFD_DYING,			\
	CPUHP_AP_ONLINE,			\
	CPUHP_TEARDOWN_CPU,			\
	CPUHP_AP_ONLINE_IDLE,			\
	CPUHP_AP_SMPBOOT_THREADS,		\
	CPUHP_AP_X86_VDSO_VMA_ONLINE,		\
	CPUHP_AP_NOTIFY_ONLINE			\
	}

#define LWKCPU_PERF_STATES {			\
	CPUHP_PERF_PREPARE,			\
	CPUHP_PERF_X86_PREPARE,			\
	CPUHP_PERF_X86_UNCORE_PREP,		\
	CPUHP_PERF_X86_AMD_UNCORE_PREP,		\
	CPUHP_PERF_X86_RAPL_PREP,		\
	CPUHP_PROFILE_PREPARE,			\
	CPUHP_AP_PERF_X86_UNCORE_STARTING,	\
	CPUHP_AP_PERF_X86_AMD_UNCORE_STARTING,	\
	CPUHP_AP_PERF_X86_STARTING,		\
	CPUHP_AP_PERF_X86_AMD_IBS_STARTING,	\
	CPUHP_AP_PERF_X86_CQM_STARTING,		\
	CPUHP_AP_PERF_X86_CSTATE_STARTING,	\
	CPUHP_AP_PERF_ONLINE,			\
	CPUHP_AP_PERF_X86_ONLINE,		\
	CPUHP_AP_PERF_X86_UNCORE_ONLINE,	\
	CPUHP_AP_PERF_X86_AMD_UNCORE_ONLINE,	\
	CPUHP_AP_PERF_X86_AMD_POWER_ONLINE,	\
	CPUHP_AP_PERF_X86_RAPL_ONLINE,		\
	CPUHP_AP_PERF_X86_CQM_ONLINE,		\
	CPUHP_AP_PERF_X86_CSTATE_ONLINE		\
	}

#define LWKCPU_PROF_NOR	"normal"
#define LWKCPU_PROF_DBG	"debug"

extern int lwkcpu_up(unsigned int cpu);
extern int lwkcpu_down(unsigned int cpu);
extern int lwkcpu_up_multiple(cpumask_var_t request, cpumask_var_t booted);
extern int lwkcpu_down_multiple(cpumask_var_t request, cpumask_var_t shutdown);
extern int lwkcpu_reset(unsigned int cpu);
extern int lwkcpu_parse_args(char *arg, cpumask_t *lwkcpus,
			     cpumask_t *syscall_cpus);
extern void lwkcpu_set_state(enum cpuhp_state state, bool val);
extern int lwkcpu_state_init(char *profile);
extern void lwkcpu_state_deinit(void);

#endif /* _LWKCPU_H_ */
