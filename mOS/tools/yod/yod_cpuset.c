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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "yod.h"

mos_cpuset_t *mos_cpuset_alloc_validate()
{
	mos_cpuset_t *set;

	set = mos_cpuset_alloc();
	if (!set)
		yod_abort(-ENOMEM, "Could not allocate a yod_cpuset");

	return set;
}

char *mos_cpuset_to_list_validate(mos_cpuset_t *s)
{
	char *ret;

	ret = mos_cpuset_to_list(s);

	if (!ret)
		yod_abort(-EINVAL, "Failed to parse cpuset");
	return ret;
}
