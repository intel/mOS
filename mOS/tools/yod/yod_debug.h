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

#ifndef __YOD_DEBUG_H
#define __YOD_DEBUG_H

#include <unistd.h>
#include "../include/mos_debug.h"
/*
 * Define logging (verbosity) levels and the associated logging
 * utility.
 */

#define YOD_CRIT  0
#define YOD_WARN  1
#define YOD_INFO  2
#define YOD_DEBUG 3
#define YOD_GORY  4

extern int yod_verbosity;

#define YOD_LOG(level, format, ...) \
	do { \
	if (yod_verbosity >= level) \
		MOS_LOG("yod", format, ##__VA_ARGS__);\
	} while (0);

#define YOD_ERR(format, ...) MOS_ERR("yod", format, ##__VA_ARGS__)
#define NOT_IMPLEMENTED(msg) MOS_NOT_IMPLEMENTED("yod", msg)

#endif
