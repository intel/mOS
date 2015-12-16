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

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	int i;
	int ch;

	printf("My PID is %d, parent PID is %d\n", getpid(), getppid());

	printf("Loop over getppid()? [N/y]:\n");
	ch= getchar();

	if ((ch == 'y') || (ch == 'Y'))   {
		for (i= 0; i < 10000000; i++)   {
			getppid();
		}
		printf("Called geppid() 10000000 times\n");
	}
	return 0;
}
