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

#ifndef _LWKSCHED_H
#define _LWKSCHED_H

#define _GNU_SOURCE
#include <stddef.h>
#include <sched.h>

#define MAX_CPUS 512
#define MAX_THREADS MAX_CPUS
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define CPUFMT "[%03d]"

enum log_level {
	LOG_FATAL = 0,
	LOG_ERR = 1,
	LOG_WARN = 2,
	LOG_INFO = 3,
	LOG_DEBUG = 4,
	LOG_GORY_DETAIL = 5,
};

extern int logging_level;

extern void log_msg(enum log_level level, const char *format, ...);
extern char *get_affinity(char *buff, size_t buffsize);
extern int parse_mos_mask(cpu_set_t *set, int setsize, const char *path);
extern char *cpuset_to_str(cpu_set_t *set, int setsize, char *buff,
			   size_t buffsize);

#endif
