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

#define HAVE_DECL_CPU_ALLOC 1
#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>
#include <time.h>
#include <locale.h>
#include <signal.h>

#include "lwkreset.h"
#include "lwkreset_debug.h"

#define MOS_SYSFS_ROOT "/sys/kernel/mOS/"
#define MOS_SYSFS_LWKPROCESSES (MOS_SYSFS_ROOT "lwkprocesses")


int lwkreset_verbosity = LWKRESET_QUIET;

struct help_text {
	const char *option;
	const char *argument;
	const char *description;
} HELP[] = {
	{"Option", "Argument", "Description",},
	{"----------------", "----------------",
		    "--------------------------------"},
	{"--verbose, -v", "<level>", "Sets verbosity of lwkreset."},
	{0, 0, " "}
};

#define HELPSTR(s) (s ? s : "")

static int get_lwk_processes(char *buff, size_t len)
{
	FILE *fptr;
	int rc;

	LWKRESET_LOG(LWKRESET_GORY, "(>) %s(file=%s buff=%p size=%ld)", __func__, MOS_SYSFS_LWKPROCESSES, buff, len);

	fptr = fopen(MOS_SYSFS_LWKPROCESSES, "r");

	if (!fptr) {
		LWKRESET_ERR("Could not open \"%s\" for reading.", MOS_SYSFS_LWKPROCESSES);
		return -1;
	}

	rc = fread(buff, 1, len, fptr);

	if (rc < 0) {
		LWKRESET_ERR("Could not read \"%s\" (rc = %ld)", MOS_SYSFS_LWKPROCESSES, len);
	} else if (rc < len) 
		buff[rc] = 0; /* force end-of-string */

	fclose(fptr);

	LWKRESET_LOG(LWKRESET_GORY, "(<) %s(file=%s buff=%p data=\"%s\" rc=%d)", __func__, MOS_SYSFS_LWKPROCESSES, buff, rc > 0 ? buff : "?", rc);
	return rc;
}

static int get_lwkpid(char **ppidstr)
{
        char *endptr;
        unsigned long int pid;
        pid = strtoul(*ppidstr, &endptr, 0);
        *ppidstr = endptr;
        if (**ppidstr == ',') 
                *ppidstr += 1;
        return pid;
}

void lwkreset_abort(int rc, const char* format, ...)
{
	char buffer[4096];
	va_list args;
	va_start(args, format);
	vsprintf(buffer, format, args);
	fprintf(stderr, "[lwkreset:%d] %s (rc=%d)\n", getpid(), buffer, rc);
	va_end(args);
        
	exit(rc);
}

static void usage(void)
{
	int i;

	printf("Usage: lwkreset [options]\n");
	printf("Options:\n");
	for (i = 0; i < sizeof(HELP) / sizeof(HELP[0]); i++) {
		printf(" %-16s  %-16s  %s\n", HELPSTR(HELP[i].option),
		       HELPSTR(HELP[i].argument), HELPSTR(HELP[i].description));
	}
}

static void show_kill_result(int level, int lwk_pid, int kill_result)
{
        if (lwkreset_verbosity >= level) {
		LWKRESET_LOG(level, "process=%d  kill result=%d", lwk_pid, kill_result);
        }
}

static void show_target(int level, int start, int argc, char **argv)
{
	if (lwkreset_verbosity >= level) {
		char target[0x4000];
		unsigned remaining = sizeof(target);
		int i;

		target[0] = 0;

		for (i = start; i < argc; i++) {
			strncat(target, argv[i], remaining);
			remaining -= strlen(argv[i]);
			strncat(target, " ", remaining);
			remaining--;
		}

		LWKRESET_LOG(level, "target: \"%s\"", target);
	}
}

static void show_lwk_processes(int level, char *buffer)
{
	if (lwkreset_verbosity >= level) {
		LWKRESET_LOG(level, "LWK Process PIDs: %s", buffer);
	}
}

static void parse_options(int argc, char **argv)
{
	static struct option options[] = {
		{"help", no_argument, 0, 'h'},
		{"verbose", required_argument, 0, 'v'},
		{0, 0, 0, 0},
	};

	while (1) {

		int c;
		int opt_index = 0;

		c = getopt_long(argc, argv, "v:h", options,
				&opt_index);

		if (c == -1)
			break;

		switch (c) {

		case 'h':{
			usage();
			exit(0);
			break;
		}

		case 'v':{
			char *optp = optarg;
			lwkreset_verbosity = strtol(optarg, &optp, 10);
			if (*optp) {
				lwkreset_abort(-EINVAL, "You must specify a verbosity level.");
			}
			break;
		}

		case '?':
		default:
			{
				/* getopt_long has already emitted an error message */
				exit(-1);
				break;
			}
		}
	}
}

int main(int argc, char **argv)
{

	char *verbose_env;
	int rc;

	verbose_env = getenv("LWKRESET_VERBOSE");
	if (verbose_env)
		lwkreset_verbosity = atoi(verbose_env);

	setlocale(LC_ALL, "");

	parse_options(argc, argv);

	show_target(LWKRESET_QUIET + 1, optind, argc, argv);

	/* Get the list of LWK PIDs from mOS */
	char buffer[4096];

	rc = get_lwk_processes(buffer, sizeof(buffer));
	if (rc < 0) {
		lwkreset_abort(rc, "Could not access list of lwk processes");
	}

	show_lwk_processes(LWKRESET_DEBUG, buffer);

	/* Walk through the list of PIDs and issue SIGKILLs.
	 * Even if we do not have the appropriate authority to kill all
	 * the target process, proceed with issuing the SIGKILLs to all
	 * processes in the list so that the ones we can control are killed.
	 */
	char *pidstr = buffer;
	int pid;
	while ((pid = get_lwkpid(&pidstr))) {
		rc = kill(pid, SIGKILL);
		show_kill_result(LWKRESET_DEBUG, pid, rc);
	};

	return 0;
}
