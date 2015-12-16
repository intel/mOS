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
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <getopt.h>
#include <locale.h>
#include <unistd.h>
#include <sys/wait.h>
#include "lwksched.h"

static size_t setsize;
static cpu_set_t *lwkcpus;

static void usage(void);
static int isCurrentCpuLwk(void);
static int isCpusAllowedMaskLwk(void);
static int isPolicy(int policy);

int main(int argc, char **argv)
{
	int status, rc = 0;
	pid_t pid;

	struct option options[] = {
	 { "debug", no_argument, 0, 'd' },
	 { "help", no_argument, 0, 'h' },
	};

	setlocale(LC_ALL, "");

	while (1) {

		int c;
		int opt_index;

		c = getopt_long(argc, argv, "dh", options, &opt_index);

		if (c == -1)
			break;

		switch (c) {
		case 'd':
			logging_level++;
			break;
		case 'h':
			usage();
			return 0;
		default:
			usage();
			return -1;
		}
	}

	if (optind != argc) {
		usage();
		return -1;
	}

	/* Allocate cpus masks */
	setsize = CPU_ALLOC_SIZE(MAX_CPUS);
	lwkcpus = CPU_ALLOC(MAX_CPUS);

	if (parse_mos_mask(lwkcpus, setsize, "/sys/kernel/mOS/lwkcpus_mask")) {
		log_msg(LOG_ERR, "Error parsing CPU set.");
		rc = -1;
		goto out;
	}

	pid = fork();
	if (pid > 0) {
		/* Parent */

		/* Test policy */
		if (isPolicy(SCHED_FIFO)) {
			/* Test cpus allowed mask */
			if (isCpusAllowedMaskLwk()) {
				/* Test current cpu */
				if (isCurrentCpuLwk()) {
					rc = 0;
				} else {
					log_msg(LOG_ERR,
					    "Parent current cpu is not LWK");
					rc = -1;
				}
			} else {
				log_msg(LOG_ERR,
				    "Parent allowed mask is not LWK");
				rc = -1;
			}
		} else {
			log_msg(LOG_ERR,
			    "Parent scheduling policy is not SCHED_FIFO");
			rc = -1;
		}

		wait(&status);

		if (!rc)
			rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

	} else if (pid == 0) {
		/* Child */

		/* Test policy */
		if (isPolicy(SCHED_OTHER)) {
			/* Test cpus allowed mask */
			if (!isCpusAllowedMaskLwk()) {
				/* Test current cpu */
				if (!isCurrentCpuLwk()) {
					rc = 0;
				} else {
					log_msg(LOG_ERR,
					    "Child current cpu is LWK");
					rc = -1;
				}
			} else {
				log_msg(LOG_ERR,
				    "Child allowed mask contains LWK CPUs");
				rc = -1;
			}
		} else {
			log_msg(LOG_ERR,
			    "Child scheduling policy is not SCHED_NORMAL");
			rc = -1;
		}
	} else {
		perror("fork failure");
		log_msg(LOG_ERR, "fork failure");
		rc = -1;
	}

 out:
	 /* Have only the parent report the test result */
	 if (pid > 0) {
		if (rc)
			log_msg(LOG_ERR, "Test failed.");
		else
			log_msg(LOG_INFO, "Test passed.");
	 }

	return rc;
}

static int isPolicy(int policy)
{
	int rc = 0;

	if (sched_getscheduler(0) == policy)
		rc = 1;
	return rc;
}

static int isCpusAllowedMaskLwk(void)
{
	int rc = 0;
	char buffer[4096];
	cpu_set_t *cpus_allowed_mask;

	cpus_allowed_mask = CPU_ALLOC(MAX_CPUS);
	CPU_ZERO_S(setsize, cpus_allowed_mask);

	memset(buffer, 0, sizeof(buffer));

	if (sched_getaffinity(0, setsize, cpus_allowed_mask)) {
		log_msg(LOG_FATAL, "Could not obtain affinity: %s",
			strerror(errno));
	}
	log_msg(LOG_DEBUG, "CPUs allowed %s",
	 cpuset_to_str(cpus_allowed_mask, setsize, buffer, sizeof(buffer)));

	CPU_AND_S(setsize, cpus_allowed_mask, cpus_allowed_mask, lwkcpus);
	if (CPU_COUNT_S(setsize, cpus_allowed_mask) > 0)
		rc = 1;

	return rc;
}

static int isCurrentCpuLwk(void)
{
	int cpu_now = sched_getcpu();

	if (CPU_ISSET_S(cpu_now, setsize, lwkcpus))
		return 1;
	return 0;
}

static void usage(void)
{
	printf("fork_process [--debug].. [--help]\n");
}



