/*
 * Multi Operating System (mOS)
 * Copyright (c) 2018 Intel Corporation.
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

#ifndef __UTILS_H__
#define __UTILS_H__


void *create_shared_mem(const char *fname, size_t size, int flags);
void *create_private_mem(void *addr, size_t size);
void *recreate_private_mem(void *addr, size_t size);

#endif
