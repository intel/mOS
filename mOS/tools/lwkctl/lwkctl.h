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

#ifndef __LWKCTL_H__

#include <stdbool.h>
#include "../include/mos_cpuset.h"
#include "../include/mos_gpuset.h"
#include "lwkctl_debug.h"

#define MOS_SYSFS_ROOT "/sys/kernel/mOS/"
#define MOS_SYSFS_VERSION (MOS_SYSFS_ROOT "version")
#define MOS_SYSFS_LWKCPUS (MOS_SYSFS_ROOT "lwkcpus")
#define MOS_SYSFS_LWKCPUS_MASK (MOS_SYSFS_ROOT "lwkcpus_mask")
#define MOS_SYSFS_LWKCPUS_RES (MOS_SYSFS_ROOT "lwkcpus_reserved")
#define MOS_SYSFS_UTILITY_CPUS (MOS_SYSFS_ROOT "utility_cpus")
#define MOS_SYSFS_LWKMEM (MOS_SYSFS_ROOT "lwkmem")
#define MOS_SYSFS_LWKCONFIG (MOS_SYSFS_ROOT "lwk_config")
#define MOS_SYSFS_LWK_INTERRUPTS (MOS_SYSFS_ROOT "lwk_interrupts")
#define MOS_SYSFS_JOBID (MOS_SYSFS_ROOT "ras/jobid")
#define CPU_SYSFS "/sys/devices/system/cpu/"
#define CPUS_ONLINE (CPU_SYSFS "online")
#define CPUS_OFFLINE (CPU_SYSFS "offline")
#define CPUS_PRESENT (CPU_SYSFS "present")
#define CPUS_POSSIBLE (CPU_SYSFS "possible")
#define PROC_INTERRUPTS ("/proc/interrupts")

#define LC_MAX_NIDS	256
#define LC_CREATE	(0x1 << 0)
#define LC_DELETE	(0x1 << 1)
#define LC_SHOW		(0x1 << 2)
#define LC_RAW		(0x1 << 3)
#define LC_PRECISE	(0x1 << 4)
#define LC_FORCE        (0x1 << 5)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#endif
#define KB(N)		(N >> 10)

struct lwkctl_options {
	unsigned int flags;
	char *create;
	char *delete;
	bool show;
	long timeout_in_millis;
};

extern void lwkctl_abort(int rc, const char *format, ...);
extern int mos_sysfs_read(const char *file, char *buff, int len);
extern int mos_sysfs_write(const char *file, char *buff, int len);
extern int mos_sysfs_get_cpulist(const char *file, mos_cpuset_t *set);
extern int mos_sysfs_put_cpulist(const char *file, mos_cpuset_t *set);
extern int mos_sysfs_get_vector(size_t *vec, int *n, const char *filen);
extern int mos_sysfs_set_lwkconfig(char *arg);
extern int mos_sysfs_set_linuxcpu(int cpu, bool online);
extern int mos_sysfs_access_linuxcpu(mos_cpuset_t *cs);
extern int mos_sysfs_int_classes(void);
extern int mos_sysfs_set_lwk_interrupts(char *allowed_drivers);
extern void show(int level, const char *label, mos_cpuset_t *set);

extern bool is_irqbalance_active(void);
extern int start_irqbalance(void);
extern int stop_irqbalance(void);

#endif
