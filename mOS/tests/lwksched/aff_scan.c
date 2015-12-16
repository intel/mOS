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
#include <string.h>
#include <stdlib.h>
#include <cpuid.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include "lwksched.h"

/*  Basic affinity tests - scan through all cpus in starting affinity mask.
 *    - Single threaded, does not use fork/clone.
 *    - (Optional) switch back to full mask for each cpu, check for migration
 *    off the (legal) calling cpu.
 *	  - Emulates Intel OMP scanning/affinitization.
 *	  - As of 1/2016, the mOS L-scheduler by design migrates to the lowest
 *	  numbered cpu in the mask.  This behavior is a divergence from Linux,
 *	  which may in fact also migrate off a legal cpu under some
 *	  load/scheduler conditions.
 *    - Attempts to affinitize outside starting mask - shouldn't work.
 *    - By default runs across all available cpu_set_t bits, can be limited to
 *    specific # of cpus or to number available in system.
 *
 *  Possible additions
 *    - Check syscall cpu id?  How?  Helper thread/process?  The migration
 *    tests use System Tap, don't really want that dependency here.
 *    - Add work loads?
 *    - Exercise a greater variety of system calls?
 */

#define PR_CPU_BITS (288)
#define PR_BUF_LEN (3 * PR_CPU_BITS/8 + 10)
char outbuf[PR_BUF_LEN];

/* Create a string representing the bytes in a mask array such that the mask
 * value can be read left-to-right/high-to-low bit.  If the buffer isn't long
 * enough, the low bits are chopped.
 */
static char *mask2hex_readable(cpu_set_t *mask, unsigned int nbits,
			       char *outbuf, unsigned int outlen)
{
	int i, j;

	if (nbits == 0 || outlen < 4)
		return NULL;

	for (i = (nbits - 1) / 8, j = 0; (i >= 0) && ((j + 3) < outlen);
	     i--, j += 3) {
		sprintf(&outbuf[j], "%02x ", ((unsigned char *)mask)[i]);
	}

	return outbuf;
}

/* Make a trivial migrated syscall.  On mOS, in the absence of interference
 * from other threads, the local thread should always migrate back to the
 * calling cpu before returning to user space.
 * Returns 0 for succesfull syscall, -1 if the call failed.
 */
int do_migrated_syscall(void)
{
	sigset_t sigset;

	/* Since the actual syscall used may change over time, avoid just
	 * returning the result of the call.
	 */
	if (sigpending(&sigset) != 0) {
		log_msg(LOG_DEBUG,
			"Migrated sigpending() call failed w/ errno = %d",
			errno);
		return -1;
	}

	return 0;
}

/* Set affinity to a single target cpu.  Returns new cpu id.
 */
int set_cpu(int dest_cpu)
{
	cpu_set_t dest_set;

	CPU_ZERO(&dest_set);
	CPU_SET(dest_cpu, &dest_set);

	if (sched_setaffinity(0, sizeof(cpu_set_t), &dest_set) == 0)
		log_msg(LOG_DEBUG, "set_cpu(%d) succeeded", dest_cpu);
	else
		log_msg(LOG_DEBUG, "set_cpu(%d) failed", dest_cpu);

	return sched_getcpu();
}

/*  Look for migration on sched_setaffinity() to a multi-bit mask.
 *  Single thread test: no cpus should be allocated to any other threads.
 *  - Generally, thread should migrate only when calling cpu is not in mask.
 *  - Exception: mOS migrates to the origin (first in full mask) cpu when
 *  that cpu is available (in mask and not marked as allocated).
 *  - Under loaded conditions, Linux and mOS may relocate a thread upon return
 *  from a wait condition.  This should not apply to this single threaded test
 *  on mOS, and on Linux only when other processes are sharing the cpus running
 *  the test.
 */
struct {
	int enabled;
	int check_nostart_migrate;
} affinity_tests = {0, 0};

int migration_tests(int test_cpu, int start_cpu, cpu_set_t *start_set)
{
	cpu_set_t test_set;

	CPU_ZERO(&test_set);
	CPU_OR(&test_set, &test_set, start_set);

	log_msg(LOG_DEBUG, "*** Migration_tests: test cpu: %d, start cpu: %d",
		test_cpu, start_cpu);
	log_msg(LOG_DEBUG, "Start set (%d): %s", CPU_COUNT(&test_set),
		mask2hex_readable(&test_set, PR_CPU_BITS, outbuf, PR_BUF_LEN));

	if (set_cpu(test_cpu) != test_cpu) {
		log_msg(LOG_ERR, "set_cpu(%d) failed\n", test_cpu);
		return -1;
	}

	/* Set affinity to full start set - thread should move to start cpu.
	 */
	if (sched_setaffinity(0, sizeof(cpu_set_t), &test_set) != 0) {
		log_msg(LOG_ERR, "sched_setaffinity() failed\n");
		return -1;
	}

	if (sched_getcpu() != start_cpu) {
		log_msg(LOG_DEBUG, "Migration to start_cpu failed");
		return -1;
	}

	log_msg(LOG_DEBUG, "Migration to start_cpu succeeded");

	/*  Reset to initial cpu
	 */
	if (set_cpu(test_cpu) != test_cpu) {
		log_msg(LOG_ERR, "set_cpu(%d) failed\n", test_cpu);
		return -1;
	}

	if (affinity_tests.check_nostart_migrate && test_cpu != start_cpu) {
		/*  Remove the start cpu from the test set - thread should
		 *  stay on test cpu.  This doesn't make sense if the test
		 *  and start cpus are the same.
		 */
		CPU_CLR(start_cpu, &test_set);

		if (sched_setaffinity(0, sizeof(cpu_set_t), &test_set) != 0) {
			log_msg(LOG_ERR, "sched_setaffinity() failed");
			return -1;
		}

		if (sched_getcpu() != test_cpu) {
			log_msg(LOG_DEBUG,
				"Remain on test_cpu (%d) failed - on %d",
				test_cpu, sched_getcpu());
			return -1;
		}

		log_msg(LOG_DEBUG, "Remain on test_cpu succeeded");
	}

	return sched_getcpu();
}

void usage(char *arg0)
{
	fprintf(stderr,
		"Single thread affinitizes across all cpus in starting mask and checks location.\n");
	fprintf(stderr, "Usage: %s [-m] [-e] [-f] [-F] [-a <cpu>] [-s <cpu>] [-n <ncpus>]\n", arg0);
	fprintf(stderr, "  -v - increase verbosity/log level.\n");
	fprintf(stderr,
		"  -m - check that migrated syscall returns to calling cpu.\n");
	fprintf(stderr,
		"  -e - check for escape to cpus not in start mask.\n");
	fprintf(stderr,
		"  -f - check scheduler migration to start cpu.\n");
	fprintf(stderr,
		"  -a <cpu> - add <cpu> to start set - may be repeated.\n");
	fprintf(stderr,
		"  -s <cpu> - remove <cpu> from start set - may be repeated.\n");
	fprintf(stderr,
		"  -n <ncpus> - check <ncpus> cpus:\n");
	fprintf(stderr,
		"      - defaults to all cpu_set_t bits.\n");
	fprintf(stderr,
		"      - 0 indicates all (logical) cpus in system.\n");
	fprintf(stderr,
		"  -F - check unwanted migration away from legal cpu.\n");
	fprintf(stderr, "    - NOTE: not necessarily a bug\n");
	fprintf(stderr,
		"  - Use yod or taskset to control cpu number and location.\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int start_cpu;
	int num_cpus = CPU_SETSIZE;
	cpu_set_t start_set;
	cpu_set_t escape_set;
	int dest_cpu;
	int exit_status = EXIT_SUCCESS;
	int check_syscall_migrate_return = 0;
	int check_escape = 0;

	CPU_ZERO(&escape_set);

	/* Get the starting affinity mask.  May be modified by options.
	 */
	if (sched_getaffinity(0, sizeof(cpu_set_t), &start_set) != 0) {
		log_msg(LOG_INFO, "sched_getaffinity() failed");
		exit(EXIT_FAILURE);
	}

	while ((opt = getopt(argc, argv, "mfFven:a:s:")) != -1) {
		switch (opt) {
		case 'm':
			check_syscall_migrate_return = 1;
			break;
		case 'e':
			check_escape = 1;
			break;
		case 'f':
			affinity_tests.enabled = 1;
			break;
		case 'F':
			affinity_tests.enabled = 1;
			affinity_tests.check_nostart_migrate = 1;
			break;
		case 'n':
			num_cpus = atoi(optarg);
			CPU_CLR(dest_cpu, &start_set);
			break;
		case 's':
			dest_cpu = atoi(optarg);
			CPU_CLR(dest_cpu, &start_set);
			break;
		case 'a':
			dest_cpu = atoi(optarg);
			CPU_SET(dest_cpu, &start_set);
			break;
		case 'v':
			logging_level++;
			break;
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	log_msg(LOG_INFO, "Aff_test start");

	/* Get the starting cpu.
	 */
	start_cpu = sched_getcpu();
	if (start_cpu == -1) {
		log_msg(LOG_INFO, "sched_getcpu() failed");
		exit(EXIT_FAILURE);
	}
	log_msg(LOG_INFO, "Start cpu: %d, set (%d): %s",
		start_cpu, CPU_COUNT(&start_set),
		mask2hex_readable(&start_set, PR_CPU_BITS, outbuf, PR_BUF_LEN));

	/*  If num_cpus is zero, use the number of cpus in the system.
	 */
	if (num_cpus == 0) {
		num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
		if (num_cpus == -1) {
			log_msg(LOG_ERR, "sysconf() failed");
			num_cpus = CPU_SETSIZE;
		}
	}

	for (dest_cpu = 0; dest_cpu < num_cpus; dest_cpu++) {
		if (CPU_ISSET(dest_cpu, &start_set)) {
			if (set_cpu(dest_cpu) != dest_cpu) {
				log_msg(LOG_ERR, "Failed to get to test cpu %d",
					dest_cpu);
				exit_status = EXIT_FAILURE;
			}

			/* Do a migrating syscall and check again.
			 * In the absence of interference by other threads,
			 * we should always remain on the originating
			 * cpu.
			 */
			if (check_syscall_migrate_return) {
				do_migrated_syscall();
				if (sched_getcpu() != dest_cpu) {
					log_msg(LOG_ERR,
						"Syscall migration failed to return to %d",
						dest_cpu);
					exit_status = EXIT_FAILURE;
				}
			}

			/* Check for scheduler invoked migrations when the
			 * affinity mask is expanded.  See function.
			 */
			if (affinity_tests.enabled) {
				if (migration_tests(dest_cpu, start_cpu,
						    &start_set) != dest_cpu)
					exit_status = EXIT_FAILURE;
			}
		} else if (check_escape && (set_cpu(dest_cpu) == dest_cpu)) {

			/* Looks like the thread moved to a cpu outside
			 * the legal range.
			 */
			log_msg(LOG_ERR, "Escape to cpu %d", dest_cpu);
			if (sched_getaffinity(0, sizeof(cpu_set_t), &escape_set) != 0) {
				log_msg(LOG_ERR, "sched_getaffinity() failed");
			} else {
				log_msg(LOG_DEBUG, "  Escape affinity: %s",
					mask2hex_readable(&escape_set,
						PR_CPU_BITS, outbuf,
						PR_BUF_LEN));
			}
			exit_status = EXIT_FAILURE;
		}
	}

	if (exit_status == EXIT_SUCCESS)
		log_msg(LOG_INFO, "Aff_test PASS");
	else
		log_msg(LOG_INFO, "Aff_test FAIL");

	return exit_status;
}
