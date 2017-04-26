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

#ifndef __LC_DEBUG_H
#define __LC_DEBUG_H

#include <unistd.h>
#include "mos_debug.h"
/*
 * Define logging (verbosity) levels and the associated logging
 * utility.
 */

#define LC_QUIET 0
#define LC_WARN  1
#define LC_INFO  2
#define LC_DEBUG 3
#define LC_GORY  4

extern int lc_verbosity;

#define LC_LOG(level, format, ...) \
	do { \
	if (lc_verbosity >= level) \
		MOS_LOG("lwkctl", format, ##__VA_ARGS__);\
	} while (0)

#define LC_ERR(format, ...) MOS_ERR("lwkctl", format, ##__VA_ARGS__)
#define LC_NOT_IMPL(msg) MOS_NOT_IMPLEMENTED("lwkctl", msg)

#endif
