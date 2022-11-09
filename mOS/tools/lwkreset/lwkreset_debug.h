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

#ifndef __LWKRESET_DEBUG_H
#define __LWKRESET_DEBUG_H

#include <unistd.h>

/*
 * Define logging (verbosity) levels and the associated logging
 * utility.
 */

#define LWKRESET_QUIET 0
#define LWKRESET_WARN  1
#define LWKRESET_DEBUG 2
#define LWKRESET_GORY  3

extern int lwkreset_verbosity;

#define LWKRESET_LOG(level, format, ...) \
	do { \
	if (lwkreset_verbosity >= level) \
		printf("[lwkreset:%d] " format "\n", getpid(), ##__VA_ARGS__); \
	} while (0);

#define LWKRESET_ERR(format, ...)					     \
	do {							     \
		fprintf(stderr, "[lwkreset:%d] ERROR: " format "\n", getpid(), ##__VA_ARGS__); \
	} while (0);

#define NOT_IMPLEMENTED(msg) \
	do { \
		fprintf(stderr, "[lwkreset:%d] (INTERNAL ERROR) %s not yet implemented.\n", getpid(), msg); \
	exit(-1); \
	} while (0);

#endif
