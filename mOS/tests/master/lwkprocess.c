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
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>

/*
 * This application is a proxy for an mOS launch utility (like yod).
 * Specifically, it can reserve LWK CPUs by accessing the sysfs
 * entries provided by the mOS kernel.  This code assumes that there
 * are no other mOS processes running concurrently.
 */

int debug_mode = 0;

#define error(fmt, ...) do { \
	printf("(E) " fmt "\n", ## __VA_ARGS__); \
	exit(1); \
	} while (0)

#define debug(fmt, ...) printf("(D) " fmt "\n", ## __VA_ARGS__)

#define MOS_SYSFS		"/sys/kernel/mOS/"
#define LWK_PROCESSES		MOS_SYSFS "lwkprocesses"
#define UTILITY_THREADS		MOS_SYSFS "lwk_util_threads"

#define IS_A_MASK(s) ((strncmp(s, "0x", 2) == 0) || (strncmp(s, "0X", 2) == 0))

char num_util_threads[] = "3";

/* Checks to see that a CPU list is empty, i.e. it is an
 * empty string. */
static bool is_empty_list(const char *cpus)
{
	bool is_empty = true;

	int i = 0;

	if (cpus)
		while ((cpus[i] != '\0') && is_empty)
			is_empty = isspace(cpus[i++]);

	debug("(<) %s cpus=%s rc=%d", __func__, cpus, is_empty);
	return is_empty;
}

/* Checks to see that a CPU mask is empty, i.e. it contains
 * only zeroes and commas. */

static bool is_empty_mask(const char *cpus)
{
	bool is_empty = true;
	int i = 0;

	if (cpus)
		while ((cpus[i] != '\0') && is_empty) {
			is_empty = ((cpus[i] == '0') || (cpus[i] == ','));
			i++;
		}

	debug("(<) %s cpus=%s rc=%d", __func__, cpus, is_empty);
	return is_empty;
}

struct mos_sequence_t {
	const char *request; /* file name for making requests */
	const char *reserved; /* file name for checking reservations */
	bool (*is_empty_cpulist)(const char *); /* test for emptiness */
};

static struct mos_sequence_t LWK_LIST = {
	.request = MOS_SYSFS "lwkcpus_request",
	.reserved = MOS_SYSFS "lwkcpus_reserved",
	.is_empty_cpulist = is_empty_list,
};

static struct mos_sequence_t LWK_MASK = {
	.request = MOS_SYSFS "lwkcpus_request_mask",
	.reserved = MOS_SYSFS "lwkcpus_reserved_mask",
	.is_empty_cpulist = is_empty_mask,
};

static void usage(void)
{
	printf("Usage: lwkprocess [--lwkcpus <CPUs>]\n");
	printf("         [--debug] [--help]\n");
	printf("NOTES:\n");
	printf("  1.  --lwkcpus must be specified.\n");
	printf("  2.  <CPUs> may be in either list or mask form.\n");
}

/* Reads the contents of the specified mOS sysfs file.  The contents
 * are interpreted as a string and any trailing newlines are eliminated. */

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

	/* force end-of-string */
	if (rc < len)
		buff[rc] = 0;

	/* trim trailing new-lines */
	while ((rc > 0) && (buff[rc - 1] == '\n')) {
		buff[rc - 1] = 0;
		rc--;
	}

	fclose(fptr);

	debug("(<) %s file=%s buff=\'%s\' len=%ld rc=%d", __func__, file, buff,
	      len, rc);
	return rc;
}

/** Writes to an mOS sysfs file. */

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
		error("Could not write to %s ", file);

	rc = close(fd);

	if (rc == -1)
		error("Close of %s failed.", file);

	debug("(<) %s file=%s buff=\'%s\' len=%ld rc=0",
	      __func__, file, buff, len);

	return 0;
}

static int test_sysfs_sequence(const struct mos_sequence_t const *seq,
			       char *cpus)
{
	char buffer[4096];
	int rc;
	pid_t my_pid;
	char *remainder;

	debug("(>) %s seq=%p cpus=%s", __func__, seq, cpus);

	my_pid = getpid();

	/* Read the reserved CPUs file and ensure that it is initially
	 * empty. */

	rc = mos_sysfs_read(seq->reserved, buffer, sizeof(buffer));

	if (rc < 0)
		error("Could not read %s ... aborting.",
			     seq->reserved);

	if (!seq->is_empty_cpulist(buffer))
		error("Unexpected contents in %s -> \"%s\"",
			     seq->reserved, buffer);


	/* Ensure that there are either no in-flight LWK processes
	   or only ours. */

	rc = mos_sysfs_read(LWK_PROCESSES, buffer, sizeof(buffer));

	if (rc < 0)
		error("Could not read %s ... aborting.",
			     LWK_PROCESSES);

	if ((rc > 0) && (atoi(buffer) != my_pid))
		error("Unexpected contents in %s -> \"%s\"",
			     LWK_PROCESSES, buffer);

	/* Issue the reservation request. */

	rc = mos_sysfs_write(seq->request, cpus, strlen(cpus));

	if (rc < 0)
		error("Reservation request failed. (rc=%d)", rc);

	/* Check to see that we have reserved the requestd CPUs. */

	rc = mos_sysfs_read(seq->reserved, buffer, sizeof(buffer));

	if (rc < 0)
		error("Could not read %s ... aborting.",
			     seq->reserved);

	if (rc == 0)
		error("%s is unexpectedly empty.", seq->reserved);


	/*
	 * Send the utility thread number to the process. This is a
	 * write-only file so cannot validate further. Additional validation
	 * done in scheduler unit tests.
	 */
	rc = mos_sysfs_write(UTILITY_THREADS, num_util_threads, sizeof(num_util_threads));
	if (rc < 0)
		error("Could not write %s.", UTILITY_THREADS);

	/* Our pid should be the lone entry in the lwkprocesses file. */

	rc = mos_sysfs_read(LWK_PROCESSES, buffer, sizeof(buffer));

	if (rc < 0)
		error("Could not read %s ... aborting.",
			     LWK_PROCESSES);

	if (rc == 0)
		error("%s is unexpectedly empty.", LWK_PROCESSES);

	if (my_pid != strtoul(buffer, &remainder, 10))
		error("mismatch in %s : actual %s vs. %d expected.",
			     LWK_PROCESSES, buffer, my_pid);

	if (remainder[0] != '\0')
		error("Extraneous characters in %s.\n", LWK_PROCESSES);

	debug("(<) %s seq=%p cpus=%s rc=0", __func__, seq, cpus);

	return 0;
}

int main(int argc, char **argv)
{
	char *lwkcpus = 0;
	int rc = 0;

	static struct option options[] = {
		{ "lwkcpus", required_argument, 0, 'l' },
		{ "debug", no_argument, 0, 'd' },
		{ "help", no_argument, 0, 'h' },
	};

	while (1) {

		int c;
		int opt_index;

		c = getopt_long(argc, argv, "l:dh", options, &opt_index);

		if (c == -1)
			break;

		switch (c) {

		case 'l': {
			lwkcpus = strdup(optarg);
			break;
		}

		case 'd': {
			debug_mode = 1;
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
		usage();
		return -1;
	}

	if (lwkcpus == 0) {
		error("--lwkcpus was not specified.\n");
		usage();
		return -1;
	}

	if (lwkcpus) {

		const struct mos_sequence_t *seq;

		if (IS_A_MASK(lwkcpus)) {
			seq = &LWK_MASK;
			lwkcpus += 2;
		} else {
			seq = &LWK_LIST;
		}
		rc += test_sysfs_sequence(seq, lwkcpus);
	}

	printf("rc = %d\n", rc);
	return rc;
}
