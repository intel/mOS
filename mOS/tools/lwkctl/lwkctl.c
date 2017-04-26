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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>

#include "lwkctl.h"

#define HELPSTR(s) (s ? s : "")

struct help_text {
	const char *option;
	const char *argument;
	const char *description;
} HELP[] = {
	{"Option",           "Argument",         "Description"},
	{"----------------", "----------------", "---------------------------"},
	{"-c, --create",     "partition spec",   "Create a new LWK partition."},
	{0,                  0,                  "Ex spec,"},
	{0,                  0,                  "s1.set1: .. :sN.setN"},
	{0,                  0,                  0},
	{0,                  0,                  "s<n> syscall cpu for set<n>"},
	{0,                  0,                  "set<n> set of LWK cpus"},
	{0,                  0,                  "       associated to s<n>"},
	{"-d, --delete",     0,                  "Deletes the LWK partition"},
	{"-s, --show",       0,                  "Show existing LWK partition."},
	{"-r, --raw",        0,                  "Modifies the format of the"},
	{0,                  0,                  "--show option output."},
	{"-v, --v",          0,                  "Specify verbosity level."},
	{"-h, --help",       0,                  "Prints help."},
};

struct lwkctl_options lc_opts;
int lc_verbosity = LC_WARN;

/*
 * Prints usage of lwkctl command
 */
static void usage(void)
{
	unsigned int i;

	printf("Usage: lwkctl [options]\n");
	printf("Options:\n\n");
	for (i = 0; i < ARRAY_SIZE(HELP); i++) {
		printf(" %-16s  %-16s  %s\n", HELPSTR(HELP[i].option),
		       HELPSTR(HELP[i].argument), HELPSTR(HELP[i].description));
	}
}

/*
 * Sets the destination string parameter to the contents of
 * source argument
 * @dst, address of pointer to destination string
 * @src, pointer to source string
 * @return, 0 on success
 *          -ve value on failure
 */
static int set_param(char **dst, char *src)
{
	int rval = -EINVAL;

	if (!src)
		goto out;

	if (!strlen(src))
		goto out;

	if (*dst)
		free(*dst);

	*dst = malloc(sizeof(char) * (strlen(src) + 1));

	if (!*dst)
		lwkctl_abort(-ENOMEM, "No free memory\n");

	strcpy(*dst, src);
	rval = 0;
out:
	return rval;
}

/*
 * Parses the command line parameter and sets the global
 * lwkctl options @lc_opts as per the user request
 *
 * @argc, number of command line arguments
 * @argv, array of pointers to command line arguments
 * @return, none
 */
static void parse_options(int argc, char **argv)
{
	static struct option options[] = {
		{"create", required_argument, 0, 'c'},
		{"delete", no_argument, 0, 'd'},
		{"show",   no_argument, 0, 's'},
		{"raw", no_argument, 0, 'r'},
		{"verbose", required_argument, 0, 'v'},
		{"help",   no_argument, 0, 'h'},
		{0, 0, 0, 0},
	};

	if (argc <= 1) {
		usage();
		exit(0);
	}

	lc_opts.flags = 0;

	while (1) {

		int c;
		int opt_index = 0;

		c = getopt_long(argc, argv, "+c:dsrv:h", options,
				&opt_index);

		if (c == -1)
			break;

		switch (c) {
		case 'c':
			if (set_param(&lc_opts.create, optarg)) {
				lwkctl_abort(-EINVAL,
					     "Invalid create parameters");
			}
			lc_opts.flags |= LC_CREATE;
			break;

		case 'd':
			lc_opts.flags |= LC_DELETE;
			break;

		case 's':
			lc_opts.flags |= LC_SHOW;
			break;

		case 'r':
			lc_opts.flags |= LC_RAW;
			break;

		case 'v':
			lc_verbosity = atoi(optarg);
			if (lc_verbosity < LC_QUIET)
				lc_verbosity = LC_QUIET;
			else if (lc_verbosity > LC_GORY)
				lc_verbosity = LC_GORY;
			break;

		case 'h':
		default:
			usage();
			exit(0);
			break;
		}
	}
	if ((lc_opts.flags & LC_RAW) && !(lc_opts.flags & LC_SHOW))
		lwkctl_abort(-EINVAL,
				"The raw option requires the show option");
}
/*
 * Parses the lwkcpu specification string and returns the
 * mask of LWKCPUs, Syscall CPUs and both.
 *
 * @str, lwkcpu specification string
 * @lwkcpus, mask of LWKCPUs found
 * @sccpus, mask of Syscall CPUs found
 * @allcpus, @lwkcpus | @sccpus
 * @return,  0 on success
 *         -ve on failure
 */
static int parse_lwkcpu_spec(char *str, mos_cpuset_t *lwkcpus,
		      mos_cpuset_t *sccpus, mos_cpuset_t *allcpus)
{
	char *to, *from;
	char *ip, *ip_itr;
	int rc = -EINVAL;
	mos_cpuset_t *cs;

	if (!str || !strlen(str))
		return rc;

	ip = strdup(str);
	cs = mos_cpuset_alloc();

	if (!ip || !cs)
		lwkctl_abort(-ENOMEM, "Insufficient memory");

	/* clear all masks */
	mos_cpuset_xor(lwkcpus, lwkcpus, lwkcpus);
	mos_cpuset_xor(sccpus, sccpus, sccpus);
	mos_cpuset_xor(allcpus, allcpus, allcpus);

	ip_itr = ip;
	while ((to = strsep(&ip_itr, ":"))) {
		from = strchr(to, '.');
		if (!from) {
			rc = -EINVAL;
			LC_ERR("Invalid lwkcpu spec\n");
			goto out;
		} else {
			*from++ = '\0';

			rc = mos_parse_cpulist(from, cs);
			if (rc) {
				LC_ERR("Failed to parse cpulist %s",
				       from);
				goto out;
			}

			if (mos_cpuset_is_empty(cs)) {
				rc = -EINVAL;
				LC_ERR("Invalid lwkcpu spec");
				goto out;
			}
			mos_cpuset_or(lwkcpus, lwkcpus, cs);

			rc = mos_parse_cpulist(to, cs);
			if (rc) {
				LC_ERR("Failed to parse cpulist %s",
				       to);
				goto out;
			}

			if (mos_cpuset_is_empty(cs)) {
				rc = -EINVAL;
				LC_ERR("Invalid lwkcpu spec");
				goto out;
			}
			mos_cpuset_or(sccpus, sccpus, cs);
		}
	}
	mos_cpuset_or(allcpus, lwkcpus, sccpus);

out:
	if (ip)
		free(ip);
	if (cs)
		mos_cpuset_free(cs);
	return rc;
}

/*
 * Terminates the program after printing error message
 * specified and return code.
 *
 * @rc, return code
 * @format, output string and format to be printed
 * @return, none
 */
void lwkctl_abort(int rc, const char *format, ...)
{
	char buffer[4096];
	va_list args;

	va_start(args, format);
	vsprintf(buffer, format, args);
	LC_ERR("%s (rc=%d)\n", buffer, rc);
	va_end(args);
	exit(rc);
}

/*
 * Deletes the specified LWK resources from an existing
 * LWK partition
 *
 * @p specification of LWK resources that to be deleted
 * @return,  0 on success
 *         -ve on failure
 */
static int __lwkctl_delete(char *p)
{
	int rc = -EINVAL;
	mos_cpuset_t *cs;

	LC_LOG(LC_DEBUG, "Deleting partition %s", p);

	cs = mos_cpuset_alloc();

	if (!cs)
		lwkctl_abort(-ENOMEM, "Insufficient memory");

	/*
	 * Do not teardown LWK partition if resources are still
	 * allocated to active LWK processes
	 */
	rc = mos_sysfs_get_cpulist(MOS_SYSFS_LWKCPUS_RES, cs);

	if (rc) {
		LC_ERR("Failed to read reserved LWKCPUs");
		goto out;
	}

	if (!mos_cpuset_is_empty(cs)) {
		LC_ERR("Can't delete LWK partition - being used");
		show(LC_WARN, "lwkcpus_reserved", cs);
		rc = -EINVAL;
		goto out;
	}

	rc = mos_sysfs_set_lwkconfig(p);

	if (rc)
		goto out;

	LC_LOG(LC_DEBUG, "Deleting partition %s.. Done", p);
out:
	return rc;
}
/*
 * Wrapper to __lwkctl_delete, this function performs prior validation
 * of input specification and onlines the CPUs to hand it over to Linux
 * which are deleted from LWK partition
 *
 * @p LWK partition specification to be delete. Currently we support
 *    only complete teardown of LWK partition, so @p is unused
 * @return,  0 on success
 *         -ve on failure
 */
static int lwkctl_delete(char *p)
{
	mos_cpuset_t *cs;
	int rc = -EINVAL;
	int cpu;

	if (p)
		LC_LOG(LC_WARN, "Supports only deleting entire partition");

	cs = mos_cpuset_alloc();
	if (!cs)
		lwkctl_abort(-ENOMEM, "Insufficient memory");

	rc = mos_sysfs_get_cpulist(MOS_SYSFS_LWKCPUS, cs);
	if (rc) {
		LC_ERR("Failed to read lwkcpus");
		goto out;
	}

	if (mos_cpuset_is_empty(cs))
		goto out;

	/* Do we have sufficient privilege to proceed? */
	rc = mos_sysfs_access_linuxcpu(cs);
	if (rc) {
		LC_ERR("Insufficient privilege");
		goto out;
	}

	rc = __lwkctl_delete("lwkcpus=");
	if (!rc) {
		char *s_cpus;

		s_cpus = mos_cpuset_to_list(cs);
		if (s_cpus)
			LC_LOG(LC_DEBUG, "Onlining Linux CPUs : %s", s_cpus);

		/* Online Linux CPUs */
		for (cpu = 0; cpu < mos_max_cpus(); cpu++) {
			if (mos_cpuset_is_set(cpu, cs)) {
				if (mos_sysfs_set_linuxcpu(cpu, true)) {
					LC_LOG(LC_WARN,
					       "Couldn't online Linux cpu%d",
					       cpu);
				}
			}
		}
	}
out:
	mos_cpuset_free(cs);
	return rc;
}

/*
 * Creates a new LWK partition as per the input specification.
 *
 * @p LWK partition specification that needs to be created
 * @return,  0 on success
 *         -ve on failure
 */
static int lwkctl_create(char *p)
{
	mos_cpuset_t *cs, *tmp_cs, *lwkcpus, *sccpus, *allcpus;
	int cpu;
	int rc = -EINVAL;
	char *s_key, *s_val, *s_dup, *s_itr;
	bool found_valid_lwkcpus;

	LC_LOG(LC_DEBUG, "Creating partition %s", p);

	if (!p || !strlen(p))
		return rc;

	cs = mos_cpuset_alloc();
	tmp_cs = mos_cpuset_alloc();
	lwkcpus = mos_cpuset_alloc();
	sccpus = mos_cpuset_alloc();
	allcpus = mos_cpuset_alloc();

	if (!cs || !tmp_cs || !lwkcpus || !sccpus || !allcpus)
		lwkctl_abort(-ENOMEM, "Insufficient memory");

	s_dup = strdup(p);

	if (!s_dup)
		lwkctl_abort(-ENOMEM, "Insufficient memory");

	s_itr = s_dup;

	/* Make sure we have a valid input spec for creating a partition */
	found_valid_lwkcpus = false;
	while ((s_key = strsep(&s_itr, " "))) {
		if (!(s_val = strchr(s_key, '='))) {
			rc = -EINVAL;
			LC_ERR("Invalid parameter to -c/--create");
			goto out;
		}
		*s_val++ = '\0';
		if (!strcmp(s_key, "lwkcpus")) {
			rc = mos_sysfs_get_cpulist(CPUS_PRESENT, cs);
			if (rc) {
				LC_ERR("Failed to read present cpus");
				goto out;
			}

			rc = parse_lwkcpu_spec(s_val, lwkcpus,
					       sccpus, allcpus);
			if (rc) {
				LC_ERR("Failed to parse lwkcpus spec");
				goto out;
			}
			if (!mos_cpuset_is_subset(allcpus, cs)) {
				LC_ERR("Invalid LWK cpu spec");
				show(LC_WARN, "lwkcpus", lwkcpus);
				show(LC_WARN, "syscall cpus", sccpus);
				show(LC_WARN, "present cpus", cs);
				rc = -EINVAL;
				goto out;
			}
			found_valid_lwkcpus = true;
		}

		if (!strcmp(s_key, "lwkmem"))
			LC_NOT_IMPL("memory partitioning");
	}

	if (!found_valid_lwkcpus) {
		rc = -EINVAL;
		LC_ERR("No valid lwkcpus spec found");
		goto out;
	}

	/* Do we have sufficient privilege to proceed? */
	rc = mos_sysfs_access_linuxcpu(lwkcpus);
	if (rc) {
		LC_ERR("Insufficient privilege");
		goto out;
	}

	/* Delete an existing partition if any. */
	rc = mos_sysfs_get_cpulist(MOS_SYSFS_LWKCPUS, cs);

	if (rc) {
		LC_ERR("Failed to read lwkcpus");
		goto out;
	}

	if (!mos_cpuset_is_empty(cs)) {
		mos_cpuset_not(tmp_cs, lwkcpus);
		mos_cpuset_and(cs, cs, tmp_cs);

		if (!mos_cpuset_is_empty(cs)) {
			/* Do we have sufficient privilege to proceed? */
			rc = mos_sysfs_access_linuxcpu(cs);
			if (rc) {
				LC_ERR("Insufficient privilege");
				goto out;
			}
		}

		rc = __lwkctl_delete("lwkcpus=");

		if (rc) {
			lwkctl_abort(-EINVAL,
				"Failed to delete the previous LWK partition");
		}

		if (!mos_cpuset_is_empty(cs)) {
			char *s_linuxcpus;

			s_linuxcpus = mos_cpuset_to_list(cs);
			if (s_linuxcpus) {
				LC_LOG(LC_DEBUG, "Onlining Linux CPUs : %s",
				       s_linuxcpus);
			}
			/*
			 * Online Linux CPUs which are not in the current
			 * request for new LWK partition.
			 */
			for (cpu = 0; cpu < mos_max_cpus(); cpu++) {
				if (mos_cpuset_is_set(cpu, cs)) {
					if (mos_sysfs_set_linuxcpu(cpu, true)) {
						LC_LOG(LC_WARN,
						 "Couldn't online Linux cpu%d",
						 cpu);
					}
				}
			}
		}
	}

	/* Create new partition */
	/* Offline all Linux CPUs that needs to be booted as LWKCPUs */
	for (cpu = 0; cpu < mos_max_cpus(); cpu++) {
		if (mos_cpuset_is_set(cpu, lwkcpus)) {
			rc = mos_sysfs_set_linuxcpu(cpu, false);
			if (rc) {
				LC_ERR("Failed to offline Linux cpu %d", cpu);
				goto out;
			}
		}
	}

	rc = mos_sysfs_set_lwkconfig(p);

	if (rc) {
		LC_ERR("Failed to create LWK partition %s", p);

		/* Handover CPUs back to Linux */
		for (cpu = 0; cpu < mos_max_cpus(); cpu++) {
			if (mos_cpuset_is_set(cpu, lwkcpus)) {
				rc = mos_sysfs_set_linuxcpu(cpu, true);
				if (rc)
					LC_ERR("Failed to online Linux cpu %d",
					       cpu);
			}
		}
		goto out;
	}
	LC_LOG(LC_DEBUG, "Creating partition %s.. Done", p);

out:
	if (cs)
		mos_cpuset_free(cs);
	if (lwkcpus)
		mos_cpuset_free(lwkcpus);
	if (sccpus)
		mos_cpuset_free(sccpus);
	if (allcpus)
		mos_cpuset_free(allcpus);
	if (s_dup)
		free(s_dup);
	return rc;
}

/*
 * Prints information related to existing LWK partition
 *
 * @return,  0 on success
 *         -ve on failure
 */
static int lwkctl_show(void)
{
	int rc, size;
	unsigned int i;
	unsigned long *lwkmem;
	mos_cpuset_t *lwkcpus, *linuxcpus, *sccpus, *temp;
	char *s_lwkcpus, *s_linuxcpus, *s_sccpus;
	char s_version[64];

	rc =  mos_sysfs_read(MOS_SYSFS_VERSION, s_version, sizeof(s_version));
	if ((rc < 0) || !rc) {
		LC_ERR("not a valid mOS kernel");
		return -EINVAL;
	}

	for (i = 0; i < strlen(s_version); i++) {
		if (s_version[i] == '\n')
			s_version[i] = '\0';
	}

	linuxcpus = mos_cpuset_alloc();
	lwkcpus = mos_cpuset_alloc();
	sccpus = mos_cpuset_alloc();
	temp = mos_cpuset_alloc();
	size = sizeof(unsigned long) * LC_MAX_NIDS;
	lwkmem = (unsigned long *) malloc(size);

	if (!linuxcpus || !lwkcpus || !sccpus || !temp || !lwkmem)
		lwkctl_abort(-ENOMEM, "Insufficient memory");

	rc = mos_sysfs_get_cpulist(CPUS_PRESENT, linuxcpus);
	if (rc) {
		LC_ERR("Failed to read Linux cpus present");
		goto out;
	}

	rc = mos_sysfs_get_cpulist(MOS_SYSFS_LWKCPUS, lwkcpus);
	if (rc) {
		LC_ERR("Failed to read LWK cpus");
		goto out;
	}

	rc = mos_sysfs_get_cpulist(MOS_SYSFS_SCCPUS, sccpus);
	if (rc) {
		LC_ERR("Failed to read SYSCALL cpus");
		goto out;
	}

	mos_cpuset_not(temp, lwkcpus);
	mos_cpuset_and(linuxcpus, linuxcpus, temp);

	s_linuxcpus = mos_cpuset_to_list(linuxcpus);
	s_lwkcpus = mos_cpuset_to_list(lwkcpus);
	s_sccpus = mos_cpuset_to_list(sccpus);

	if (!s_linuxcpus || !s_lwkcpus || !s_sccpus)
		lwkctl_abort(-ENOMEM, "Insufficient memory");

	printf("mOS version   : %s\n", s_version);
	printf("Linux   CPU(s): %s\n", s_linuxcpus);
	printf("LWK     CPU(s): %s\n", s_lwkcpus);
	printf("Syscall CPU(s): %s\n", s_sccpus);

	memset(lwkmem, 0, size);
	rc = mos_sysfs_get_vector(lwkmem, &size,
				  MOS_SYSFS_LWKMEM);
	if (rc) {
		LC_ERR("Failed to read LWK memory info");
		goto out;
	}
	printf("LWK Memory(KB):");
	for (i = 0; lwkmem[i] && (i < LC_MAX_NIDS); i++)
		printf(" %ld", KB(lwkmem[i]));
	printf("\n");

out:
	if (linuxcpus)
		mos_cpuset_free(linuxcpus);
	if (lwkcpus)
		mos_cpuset_free(lwkcpus);
	if (sccpus)
		mos_cpuset_free(sccpus);
	if (temp)
		mos_cpuset_free(temp);
	if (lwkmem)
		free(lwkmem);
	return rc;
}

/*
 * Prints the current LWK partition specification in raw format
 * as specified in /sys/kernel/mOS/lwk_config
 *
 * @return,  0 on success
 *         -ve on failure
 */
static int lwkctl_show_raw(void)
{
	int rc;
	char config_parms[2048];

	rc = mos_sysfs_read(MOS_SYSFS_LWKCONFIG, config_parms,
			sizeof(config_parms));

	if (rc <= 0) {
		LC_ERR("Failure reading LWK configuration information");
		return -EINVAL;
	}
	if (rc >= (int)sizeof(config_parms)) {
		LC_ERR("Buffer overflow reading LWK configuration information");
		return -EINVAL;
	}
	printf("%s", config_parms);

	return 0;
}

/*
 * Entry point to lwkctl command
 *
 * @argc, number of command line arguments
 * @argv, array of pointers to command line arguments
 * @return,  0 on success
 *         -ve on failure
 */
int main(int argc, char **argv)
{
	int rc = 0;

	/* Reset LWKCTL options */
	memset(&lc_opts, 0, sizeof(lc_opts));

	/* Parse arguments */
	parse_options(argc, argv);

	if (!lc_opts.flags) {
		usage();
		goto out;
	}

	while (lc_opts.flags) {
		if (lc_opts.flags & LC_DELETE) {
			rc = lwkctl_delete(lc_opts.delete);
			if (rc) {
				LC_ERR("Failed to delete");
				break;
			}
			lc_opts.flags &= ~LC_DELETE;
		}

		if (lc_opts.flags & LC_CREATE) {
			rc = lwkctl_create(lc_opts.create);
			if (rc) {
				LC_ERR("Failed to create %s",
				       lc_opts.create);
				break;
			}
			lc_opts.flags &= ~LC_CREATE;
		}

		if (lc_opts.flags & LC_SHOW) {
			if (lc_opts.flags & LC_RAW)
				rc = lwkctl_show_raw();
			else
				rc = lwkctl_show();
			if (rc)
				break;
			lc_opts.flags &= ~(LC_SHOW | LC_RAW);
		}
	}
out:
	if (lc_opts.create)
		free(lc_opts.create);
	if (lc_opts.delete)
		free(lc_opts.delete);
	return rc;
}
