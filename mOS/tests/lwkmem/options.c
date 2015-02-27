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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *buffers[1024 * 1024];
unsigned long init_data[1024 * 1024] = { 1, 2, 3, };

const unsigned long BUFFSIZE = 4097;
const unsigned long NUMALLOCS = 1024;

int main(int argc, char **argv)
{
	unsigned long i;

	for (i = 0; i < NUMALLOCS; i++) {
		buffers[i] = malloc(BUFFSIZE);
		if (!buffers[i]) {
			printf("(E) malloc failed (i=%ld)\n", i);
			return -1;
		}
		memcpy(buffers[i], init_data, BUFFSIZE);
	}

	for (i = 0; i < 1024; i++)
		free(buffers[i]);

	return 0;
}
