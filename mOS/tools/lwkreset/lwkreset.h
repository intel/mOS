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

#ifndef __LWKRESET_H
#define __LWKRESET_H

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#endif

#define STARTS_WITH(s, prefix) (strncmp(s, prefix, strlen(prefix)) == 0)

#define ARRAY_ENT(arr, idx, fld, dflt)	\
	(idx < ARRAY_SIZE(arr) ? arr[idx].fld : dflt)


void lwkreset_abort(int rc, const char *fmt, ...) __attribute__ ((noreturn));

#endif
