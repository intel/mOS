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

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include "xpmem_utils.h"

void *create_shared_mem(const char *fname, size_t size, int flags)
{

	void *result;
	int fd = open(fname, O_RDWR | flags, S_IRUSR | S_IWUSR);

	if (fd < 0) {
		fprintf(stderr, "(E) Could not open %s\n", fname);
		perror("failed");
		return 0;
	}

	lseek(fd, size + 1, SEEK_SET);
	write(fd, "", 1);
	lseek(fd, 0, SEEK_SET);

	result = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	close(fd);

	return result;

}

void *create_private_mem(void *addr, size_t size)
{
	unsigned long flags = MAP_PRIVATE | MAP_ANONYMOUS;

	if (addr)
		flags |= MAP_FIXED;

	return mmap(addr, size, PROT_READ | PROT_WRITE,
		    flags, 0, 0);
}

void *recreate_private_mem(void *addr, size_t size)
{
	if (munmap(addr, size)) {
		fprintf(stderr, "(E) Failed to unmap ptr - 0x%p (size: %ld)\n",
			addr, size);
		return NULL;
	}
	return create_private_mem(addr, size);
}
