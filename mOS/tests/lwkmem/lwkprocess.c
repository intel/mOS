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
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>

#define error(fmt, ...) do { \
	printf("(E) " fmt "\n", ## __VA_ARGS__); \
	exit(1); \
	} while (0)

#define debug(fmt, ...) printf("(D) " fmt "\n", ## __VA_ARGS__)

#define MOS_SYSFS "/sys/kernel/mOS/"


/*
 * This application is a proxy for an mOS launch utility (like yod).
 * Specifically, it reserves LWK CPUs and memory.  This code
 * assumes that there are no other mOS processes running concurrently.
 */

static int mos_sysfs_read(const char *file, char *buff, size_t len)
{
	FILE *fptr;
	int rc;

	debug("(>) %s file=%s buff=%p len=%ld", __func__, file, buff, len);

	fptr = fopen(file, "r");

	if (!fptr)
		error("Could not open %s for reading. ", file);

	rc = fread(buff, 1, len, fptr);

	if (rc < 0)
		error("Could not read \"%s\" (rc = %ld)", file, len);

	if (rc < len)
		buff[rc] = 0; /* force end-of-string */

	while ((rc > 0) && (buff[rc - 1] == '\n')) {
		buff[rc - 1] = 0;
		rc--;
	}

	fclose(fptr);

	debug("(<) %s file=%s buff=\'%s\' len=%ld rc=%d", __func__, file, buff, len, rc);
	return rc;
}

static int mos_sysfs_write(const char *file, char *buff, size_t len)
{
	int fd;
	int rc = 0;

	debug("(>) %s file=%s buff=\'%s\' len=%ld", __func__, file, buff, len);

	fd = open(file, O_WRONLY);

	if (fd == -1)
		error("Could not open %s ", file);

	rc = write(fd, buff, len);

	if (rc != len)
		error("Could not write to %s (rc actual %d vs %ld expected)", file, rc, len);

	rc = close(fd);

	if (rc == -1)
		error("Close of %s failed.", file);

	debug("(<) %s file=%s buff=\'%s\' len=%ld rc=0", __func__, file, buff, len);

	return 0;
}

static void usage(void)
{
	printf("Usage: lwkprocess --lwkcpus <CPUs> [--lwkmem <mem>] [--help]\n");
}

static char *strip(char *s)
{
	char *endp;
	char *result = s;

	while (isspace(*result))
		result++;

	endp = result + strlen(result) - 1;
	while (isspace(*endp)) {
		*endp = '\0';
		endp--;
	}

	return result;
}

int main(int argc, char **argv)
{
	char *lwkcpus = 0;
	char *lwkmem = 0;
	char lwkmem_reserved[4096];
	char *p, *actual, *expected;

	static struct option options[] = {
		{ "lwkcpus", required_argument, 0, 'l' },
		{ "lwkmem", required_argument, 0, 'm' },
		{ "help", no_argument, 0, 'h' },
	};

	while (1) {

		int c;
		int opt_index;

		c = getopt_long(argc, argv, "l:u:h", options, &opt_index);

		if (c == -1)
			break;

		switch (c) {

		case 'l': {
			lwkcpus = strdup(optarg);
			break;
		}

		case 'm': {
			lwkmem = strdup(optarg);
			break;
		}

		case 'h': {
			usage();
			return 0;
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

	/* Become a LWK process by writing to the LWK CPUs request file. */
	if (mos_sysfs_write(MOS_SYSFS "lwkcpus_request", lwkcpus, strlen(lwkcpus))) {
		error("LWK CPUs request failed.\n");
		return -1;
	}

	/* Convert commas to spaces. */
	p = lwkmem;
	while (*p != '\0') {
		if (*p == ',')
			*p = ' ';
		p++;
	}

	/* Request LWK memory. */
	if (mos_sysfs_write(MOS_SYSFS "lwkmem_request", lwkmem, strlen(lwkmem))) {
		error("LWK memory request failed.\n");
		return -1;
	}

	/* Write options to trigger prcoess start. */
	if (mos_sysfs_write(MOS_SYSFS "lwk_options", "", 1)) {
		error("LWK options request failed.\n");
		return -1;
	}

	/* Now read back reserved memory ... it should be the same as
	 * what we wrote. */
	if (mos_sysfs_read(MOS_SYSFS "lwkmem_reserved", lwkmem_reserved, sizeof(lwkmem_reserved)) < 0) {
		error("failed to read lwkmem_reserved.\n");
		return -1;
	}

	actual = strip(strdup(lwkmem_reserved));
	expected = strip(strdup(lwkmem));

	debug("lwkmem          \"%s\"", expected);
	debug("lwkmem_reserved \"%s\"", actual);

	if (strcmp(actual, expected)) {
		error("lwkmem_reserved: expected \"%s\" vs \"%s\" actual", expected, actual);
		return -1;
	}

	printf("SUCCESS!\n");
	return 0;
}
