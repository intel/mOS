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
#include <stdlib.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <errno.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MAXDEPTH 512

struct _region_t {
	char *brk;
	unsigned long size;
	struct _region_t *next;
} heap[MAXDEPTH];

static int heap_index;

static int expand_heap(unsigned long size, long clear_len);
static int shrink_heap(void);

unsigned long PAGE_SIZES[] = {
	4 * 1024, /* 4K */
	2 * 1024 * 1024, /* 2M */
};

static int parse_options(int argc, char **argv, int *iterations, int *min_pages,
			 int *max_pages, int *clear_len);

int main(int argc, char **argv)
{

	int n_iterations = 100;
	int max_pages = 10;
	int min_pages = 1;
	int clear_len = 4096;
	int i;
	int rc = 0;
	unsigned long size;
	unsigned long num_pages;

	setlocale(LC_ALL, "");

	srand(time(0));

	rc = parse_options(argc, argv, &n_iterations, &min_pages, &max_pages, &clear_len);

	if (rc)
		goto out;

	for (i = 1; i <= n_iterations && rc == 0; i++) {

		printf("[%4d] ", i);

		if ((heap_index == 0) || (rand() % 2 == 0)) {
			size = PAGE_SIZES[rand() % ARRAY_SIZE(PAGE_SIZES)];
			num_pages = 1 + (rand() % (max_pages - min_pages + 1));

			if (expand_heap(size * num_pages, clear_len)) {
				printf("FAIL!\n");
				rc--;
			}
		} else {
			if (shrink_heap()) {
				printf("FAIL!\n");
				rc--;
			}
		}
	}

 out:
	return rc;
}

static int expand_heap(unsigned long size, long clear_len)
{
	int i = heap_index++;
	char *ch, *endp;
	int rc = 0;

	printf("Expanding %'14ld bytes ", size);

	if (i >= MAXDEPTH) {
		printf("(E) out of room!\n");
		rc = -9;
		goto out;
	}

	heap[i].brk = (char *)sbrk(size);
	if (heap[i].brk == (void *)-1) {
		perror("sbrk failed.");
		rc--;
		goto out;
	}

	heap[i].size = size;
	if (clear_len < 0 || clear_len > size)
		clear_len = size;

	for (ch = heap[i].brk, endp = heap[i].brk + clear_len; ch < endp; ch++) {
		if (*ch) {
			printf("(W) non-zero byte detected at %p -> %2.2X (offset=%lX)\n",
			       ch, *ch, ch - heap[i].brk);
			rc--;
			goto out;
		}
		*ch = rand();
	}

	printf("brk=%p depth=%3d total-size=%'14ld bytes\n",
	       heap[i].brk, heap_index, heap[i].brk - heap[0].brk + size);

 out:
	return rc;

}

static int shrink_heap(void)
{

	char *brk;
	int i = --heap_index;
	int rc = 0;

	printf("Releasing %'14ld bytes brk=%p depth=%3d\n",
	       heap[i].size, heap[i].brk, i);

	brk = (char *)sbrk(-heap[i].size);

	if (brk != (heap[i].brk + heap[i].size)) {
		printf("(W) Miscompare actual brk = %p vs %p expected\n",
		       brk, heap[i].brk);
		rc--;
	}

	return rc;
}

static void usage(void)
{
	printf("heaptest [--iterations <N>] [--min-pages <min>] [--max-pages <max>]\n");
}

static int parse_options(int argc, char **argv, int *iterations, int *min_pages,
			 int *max_pages, int *clear_len)
{
	static struct option options[] = {
		{ "iterations", required_argument, 0, 'i' },
		{ "min-pages", required_argument, 0, 'm' },
		{ "max-pages", required_argument, 0, 'M' },
		{ "clear-len", required_argument, 0, 'c' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0}
	};

	while (1) {

		int c;
		int opt_index;

		c = getopt_long(argc, argv, "i:m:M:h",
				options, &opt_index);

		if (c == -1)
			break;

		switch (c) {

		case 'h': {
			usage();
			exit(0);
			break;
		}

		case 'c': {
			*clear_len = atoi(optarg);
			break;
		}

		case 'i': {
			*iterations = atoi(optarg);
			break;
		}

		case 'm': {
			*min_pages = atoi(optarg);
			break;
		}

		case 'M': {
			*max_pages = atoi(optarg);
			break;
		}

		default: {
			usage();
			return -1;
			}
		}
	}

	if (optind != argc) {
		printf("optind=%d argc=%d\n", optind, argc);
		usage();
		return -1;
	}

	return 0;
}
