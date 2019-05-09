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
#include <sys/stat.h>
#include <ctype.h>
#include <limits.h>
#include <sys/user.h>

#include "lwkctl.h"

#define HELPSTR(s)		(s ? s : "")
#define PROC_MOS_VIEW		"/proc/self/mos_view"
#define PROC_MOS_VIEW_LEN 	20
#define VM_DROP_CACHE_ALL	"3"

#define PACKAGE_ID "/sys/devices/system/cpu/cpu%d/topology/physical_package_id"
#define CORE_ID "/sys/devices/system/cpu/cpu%d/topology/core_id"
#define CPU_ONLINE "/sys/devices/system/cpu/online"
#define NODE_CPUS "/sys/devices/system/node/node%d/cpulist"
#define NODES_POSSIBLE "/sys/devices/system/node/possible"
#define PROC_BUDDYINFO "/proc/buddyinfo"
#define SYS_LWKMEM "/sys/kernel/mOS/lwkmem"
#define SYSCTL_DROP_CACHES "/proc/sys/vm/drop_caches"

/* Topology info for a CPU */
struct cpu_map {
	int core_id;
	int pkg_id;
	int node_id;
};

struct cpu_info {
	int max_cpuid;
	mos_cpuset_t *online;
	mos_cpuset_t *linux_cpus;
	struct cpu_map *cpumap;
};

struct node_info {
	unsigned long int nodes_possible;
	char *buddyinfo;
	char *lwkmeminfo;
};

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
	{0,                  0,                  "s<n> utility cpu for set<n>"},
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

static unsigned long int nodelist_to_mask(char *path, char *buffer,
					  int buff_size)
{
	char *right_s, *left_s, *tok, *endptr;
	long int val, left, right;
	unsigned long int mask = 0;
	char *str_ptr = buffer;

	if (mos_sysfs_read(path, buffer, buff_size) < 0)
		lwkctl_abort(-1, "Could not read %s", path);

	while ((tok = strsep(&str_ptr, ","))) {
		if (strlen(tok) == 0)
			break;
		right_s = tok;
		left_s = strsep(&right_s, "-");
		errno = 0;
		left = strtol(left_s, &endptr, 10);
		if (errno || (endptr == left_s))
			lwkctl_abort(-1, "Could not parse list: [%s] %s", path,
				buffer);
		errno = 0;
		if (right_s) {
			right = strtol(right_s, &endptr, 10);
			if (errno || (endptr == right_s))
				lwkctl_abort(-1,
				    "Could not parse list: [%s] %s", path,
				    buffer);
		} else
			right = left;
		if (right >= 64)
			/* mask overflow */
			lwkctl_abort(-1, "Node mask overflow: [%s] %s", path,
				buffer);
		for (val = left; val <= right; val++)
			mask |= (1 << val);
	}

	LC_LOG(LC_DEBUG, "Node list to mask. Path=%s mask=%016lx", path, mask);

	return mask;
}

static size_t lwk_memory_size(int node, struct node_info *nodeinfo)
{
	char *strptr, *endptr;
	size_t bytes, mem_GB;
	int i;

	strptr = nodeinfo->lwkmeminfo;

	for (i = 0, bytes = 0; i <= node; i++) {
		errno = 0;
		bytes = strtoul(strptr, &endptr, 10);
		if (errno || (endptr == strptr)) {
			bytes = 0;
			break;
		}
		strptr = endptr;
	}
	mem_GB = bytes / (1024 * 1024 * 1024);
	LC_LOG(LC_DEBUG, "LWK memory currently in node=%d: %lu", node, mem_GB);
	return mem_GB;
}

/*
 * Returns the available movable memory rounded down to a GB boundary for
 * the node specified.
 */
static size_t movable_memory_size(int node, struct node_info *nodeinfo)
{
	static const char *match = "Node %d, zone  Movable ";
	char *strptr, *endptr;
	char match_str[128];
	size_t pages, total_pages, mem_GB;
	int i;

	sprintf(match_str, match, node);
	strptr = strstr(nodeinfo->buddyinfo, match_str);
	if (!strptr) {
		LC_LOG(LC_DEBUG, "No movable memory found for node=%d", node);
		return 0;
	}
	/* Iterate through the entries: 2**0 thru 2**n where n >= 10 */
	strptr = strptr + strlen(match_str);
	for (i = 0, total_pages = 0; ; i++) {
		errno = 0;
		pages = strtoul(strptr, &endptr, 10);
		if (errno || (endptr == strptr)) {
			/* If we didn't reach 2**10, report an error */
			if (i <= 10)
				lwkctl_abort(-1, "Could not parse buddyinfo");
			else
				break;
		}
		pages <<= i;
		total_pages += pages;
		strptr = endptr;
	}
	mem_GB = ((PAGE_SIZE * total_pages) / (1024 * 1024 * 1024));
	LC_LOG(LC_DEBUG, "Available movable memory for node=%d: %lu",
		node, mem_GB);
	return mem_GB;
}

/*
 * Calculate the per node amount of memory available for LWK use.
 */
static size_t calc_memsize(int node, struct node_info *nodeinfo)
{
	size_t memsize_GB;

	memsize_GB = movable_memory_size(node, nodeinfo);
	memsize_GB += lwk_memory_size(node, nodeinfo);
	return memsize_GB;
}


static void initialize_nodeinfo(struct node_info *nodeinfo, char *buffer,
			int buff_size)
{
	nodeinfo->nodes_possible = nodelist_to_mask(NODES_POSSIBLE,
						buffer, buff_size);
	if (mos_sysfs_read(PROC_BUDDYINFO, buffer, buff_size) < 0)
		lwkctl_abort(-1, "Could not read %s", PROC_BUDDYINFO);
	nodeinfo->buddyinfo = strdup(buffer);
	if (mos_sysfs_read(SYS_LWKMEM, buffer, buff_size) < 0)
		lwkctl_abort(-1, "Could not read %s", SYS_LWKMEM);
	nodeinfo->lwkmeminfo = strdup(buffer);
}

static void free_nodeinfo(struct node_info *nodeinfo)
{
	free(nodeinfo->buddyinfo);
	nodeinfo->buddyinfo = NULL;
	free(nodeinfo->lwkmeminfo);
	nodeinfo->lwkmeminfo = NULL;
}

/* Replaces the partition spec string with a new partition spec string
 * containing the generated lwkmem specification.
 */
static int generate_default_mem_spec(char **partition_spec)
{
	static const int buff_size = 4096;
	char *buffer, *lwkmem_keyword, *suffix, *new_spec;
	size_t memsize_GB, orig_spec_length, new_spec_length, total_memsize_GB;
	unsigned int written, remaining_bufsize, buffer_index, node;
	unsigned long int nodes;
	struct node_info nodeinfo;

	buffer = malloc(buff_size);
	if (!buffer)
		lwkctl_abort(-1, "Could not allocate space for buffer [%s:%d]",
				__FILE__, __LINE__);

	initialize_nodeinfo(&nodeinfo, buffer, buff_size);

	total_memsize_GB = 0;
	buffer_index = 0;
	/* Iterate over the possible nodes. Build the spec string */
	for (node = 0, nodes = nodeinfo.nodes_possible; nodes;
	      nodes >>= 1, node++) {
		if (!(nodes & 1))
			continue;
		memsize_GB = calc_memsize(node, &nodeinfo);
		if (!memsize_GB) {
			LC_LOG(LC_WARN,
			    "WARNING: Node %d has no memory available for use in the LWK partition",
			    node);
			continue;
		}
		total_memsize_GB += memsize_GB;
		remaining_bufsize = buff_size - buffer_index;
		written = snprintf(buffer + buffer_index, remaining_bufsize,
					"%d:%zuG,", node, memsize_GB);
		if (written >= remaining_bufsize)
			lwkctl_abort(-1,
			 "Buffer overflow generating memory specification [%s:%d]",
			 __FILE__, __LINE__);
		buffer_index += written;
	}

	/* Trim the ',' from end of the string */
	*(buffer + buffer_index - 1) = '\0';

	/* Build a new partition spec string, adding our new memory spec */
	/* Break the current partition spec into two strings */
	orig_spec_length = strlen(*partition_spec);
	if (!(lwkmem_keyword = strstr(*partition_spec, "lwkmem=auto")))
		lwkctl_abort(-1, "No lwkmem keyword found [%s:%d]",
				__FILE__, __LINE__);
	/* Break string after the '=' */
	*(lwkmem_keyword + strlen("lwkmem=")) = '\0';

	/* Set the beginning of the suffix string */
	suffix =  lwkmem_keyword + strlen("lwkmem=auto");

	/* Calculate the new size needed to hold the partition spec */
	new_spec_length = orig_spec_length - strlen("auto") +
			  strlen(buffer) + 1;

	new_spec = (char *)malloc(new_spec_length);
	if (!new_spec)
		lwkctl_abort(-1, "Memory allocation for size %d failed [%s:%d]",
		    new_spec_length, __FILE__, __LINE__);
	written = snprintf(new_spec, new_spec_length, "%s%s%s",
			*partition_spec, buffer, suffix);
	if (written >= new_spec_length)
		lwkctl_abort(-1,
		 "Buffer overflow generating partition specification [%s:%d]",
		 __FILE__, __LINE__);

	free_nodeinfo(&nodeinfo);
	free(*partition_spec);
	free(buffer);
	*partition_spec = new_spec;
	LC_LOG(LC_DEBUG, "Partition Spec=%s", *partition_spec);

	return total_memsize_GB ? 0 : -1;
}

static void generate_cpumap(struct cpu_info *cpuinfo, char *buffer,
			    int buffer_size)
{
	char path[128], *tok, *node_info_buffer, *node_info, *right_s, *left_s;
	int left, right, cpu, num_cpus, cur_pkg, node;
	unsigned int written;
	mos_cpuset_t *node_cpus;

	node_cpus = mos_cpuset_alloc();

	/* Allocate array of CPU map objects to hold topology */
	cpuinfo->max_cpuid = mos_cpuset_biggest(cpuinfo->online);
	cpuinfo->cpumap = (struct cpu_map *)malloc((cpuinfo->max_cpuid + 1) *
					   sizeof(struct cpu_map));
	if (!cpuinfo->cpumap)
		lwkctl_abort(-1, "Could not allocate space for cpu map [%s:%d]",
			     __FILE__, __LINE__);
	memset(cpuinfo->cpumap, -1,
		(cpuinfo->max_cpuid + 1) * sizeof(struct cpu_map));

	LC_LOG(LC_DEBUG, "CPUs ONLINE: %s",
		mos_cpuset_to_list(cpuinfo->online));

	/* Populate the cpu map object */
	for (cpu = 0, num_cpus = 0;
	     cpu <= cpuinfo->max_cpuid; cpu++) {
		if (!mos_cpuset_is_set(cpu, cpuinfo->online))
			continue;
		num_cpus++;
		written = snprintf(path, sizeof(path), PACKAGE_ID, cpu);
		if (written >= sizeof(path))
			lwkctl_abort(-1,
			    "Buffer overflow in expanding %s", PACKAGE_ID);
		if (mos_sysfs_read(path, buffer, buffer_size) < 0)
			lwkctl_abort(-1, "Could not read %s", PACKAGE_ID);
		cur_pkg = atoi(buffer);
		cpuinfo->cpumap[cpu].pkg_id = cur_pkg;

		written = snprintf(path, sizeof(path), CORE_ID, cpu);
		if (written >= sizeof(path))
			lwkctl_abort(-1,
			    "Buffer overflow in expanding %s", CORE_ID);
		if (mos_sysfs_read(path, buffer, buffer_size) < 0)
			lwkctl_abort(-1, "Could not read %s", CORE_ID);
		cpuinfo->cpumap[cpu].core_id = atoi(buffer);
	}

	/* Update the CPU map with numa node id information */

	/* Read the numa domains that exist */
	if (mos_sysfs_read(NODES_POSSIBLE, buffer, buffer_size) < 0)
		lwkctl_abort(-1, "Could not read %s", NODES_POSSIBLE);

	node_info = node_info_buffer = strdup(buffer);
	if (!node_info)
		lwkctl_abort(-1, "Could not allocate string [%s:%d]",
		    __FILE__, __LINE__);

	while ((tok = strsep(&node_info, ","))) {

		if (strlen(tok) == 0)
			break;
		right_s = tok;
		left_s = strsep(&right_s, "-");
		left = atoi(left_s);
		right = right_s ? atoi(right_s) : left;
		for (node = left; node <= right; node++) {
			/* This is a valid node. Look at the CPU mask and
			 * set this node id into the cpu_map structure
			 */
			written = snprintf(path, sizeof(path), NODE_CPUS, node);

			if (written >= (int)sizeof(path))
				lwkctl_abort(-1,
				    "Buffer overflow in expanding %s",
				    NODE_CPUS);
			if (mos_sysfs_read(path, buffer, buffer_size) < 0)
				break;
			if (mos_parse_cpulist(buffer, node_cpus))
				lwkctl_abort(-1, "Could not parse %s (%s)",
					path, buffer);
			if (mos_cpuset_is_empty(node_cpus))
				continue;
			for (cpu = 0; cpu <= cpuinfo->max_cpuid; cpu++)
				if (mos_cpuset_is_set(cpu, node_cpus))
					cpuinfo->cpumap[cpu].node_id = node;
		}
	}
	mos_cpuset_free(node_cpus);
	free(node_info_buffer);
}

/*
 * Determine the numa-domains we will be processing. We use a
 * bit mask to track the valid numa-domain IDs
 */
static unsigned long int build_node_mask(struct cpu_info *cpuinfo)
{
	int cpu;
	unsigned long int node_mask;

	for (cpu = 0, node_mask = 0; cpu <= cpuinfo->max_cpuid; cpu++) {
		if (cpuinfo->cpumap[cpu].node_id >=
		    (int)(8 * sizeof(unsigned long int)))
			lwkctl_abort(-1,
			    "Mask overflow processing package ID=%d",
			    cpuinfo->cpumap[cpu].node_id);
		node_mask |= (1 << cpuinfo->cpumap[cpu].node_id);

		LC_LOG(LC_DEBUG,
		    "cpu=%d pkg=%d node=%d core=%d node_msk=%016lx", cpu,
		    cpuinfo->cpumap[cpu].pkg_id, cpuinfo->cpumap[cpu].node_id,
		    cpuinfo->cpumap[cpu].core_id, node_mask);
	}
	return node_mask;
}

static unsigned int node_cardinality(unsigned long int nodemask)
{
	int i;

	for (i = 0; nodemask; nodemask >>= 1)
		i += (nodemask & 1);
	return i;
}

static int select_linux_cpus(struct cpu_info *cpuinfo)
{
	static const int ratio_threshold = 64;
	int cpu, i, min_count, num_nodes, cpu2, num_online, num_linux_cpus,
		delta, ratio, coreid, pkgid, prev_node;
	int cpu_count_per_node[64];

	/* Generate CPU counts for each numa node. */
	memset(cpu_count_per_node, 0, sizeof(cpu_count_per_node));
	for (cpu = 0; cpu <= cpuinfo->max_cpuid; cpu++) {
		if (!mos_cpuset_is_set(cpu, cpuinfo->online))
			continue;
		if (cpuinfo->cpumap[cpu].pkg_id != 0 ||
		    cpuinfo->cpumap[cpu].core_id != 0)
			cpu_count_per_node[cpuinfo->cpumap[cpu].node_id]++;
		else {
			/* Socket/core  0/0 contains the boot CPU0. We will
			 * explicitly give this core to Linux.
			 */
			LC_LOG(LC_DEBUG, "Setting cpu=%d into Linux mask", cpu);
			mos_cpuset_set(cpu, cpuinfo->linux_cpus);
		}
	}

	/* Find the numa nodes with the minimum number of CPUs */
	for (i = 0, min_count = INT_MAX; i < 64; i++)
		if (cpu_count_per_node[i] > 0 &&
		    cpu_count_per_node[i] < min_count)
			min_count = cpu_count_per_node[i];

	/* Deal with possible imbalanced nodes so that we give each node the
	 * same number of LWK CPUs.
	 */
	for (i = 0, num_nodes = 0; i < 64; i++) {
		if (cpu_count_per_node[i] > 0) {
			++num_nodes;
			cpu_count_per_node[i] -= min_count;
		}
	}
	/* All non-zero counts represent an imbalance. Put extra CPUs into the
	 * Linux CPUs mask
	 */
	for (i = 0; i < 64; i++) {
		if (!cpu_count_per_node[i])
			continue;
		LC_LOG(LC_DEBUG,
		       "Excess CPUs found on node=%d  count=%d",
			i, cpu_count_per_node[i]);
		for (cpu = 0; cpu <= cpuinfo->max_cpuid; cpu++) {
			if (!mos_cpuset_is_set(cpu, cpuinfo->online))
				continue;
			if (cpuinfo->cpumap[cpu].node_id != i)
				continue;
			if (mos_cpuset_is_set(cpu, cpuinfo->linux_cpus))
				continue;
			/* Add all CPUs on this core to the mask */
			coreid = cpuinfo->cpumap[cpu].core_id;
			pkgid = cpuinfo->cpumap[cpu].pkg_id;
			LC_LOG(LC_DEBUG,
			    "Balance adding all cpus on coreid=%d pkgid=%d",
			    coreid, pkgid);
			for (cpu2 = cpu; cpu2 <= cpuinfo->max_cpuid; cpu2++) {
				if (!mos_cpuset_is_set(cpu2, cpuinfo->online))
					continue;
				if (coreid != cpuinfo->cpumap[cpu2].core_id ||
				    pkgid != cpuinfo->cpumap[cpu2].pkg_id)
					continue;
				LC_LOG(LC_DEBUG,
				 "Balance adding cpu=%d into Linux mask", cpu2);
				mos_cpuset_set(cpu2, cpuinfo->linux_cpus);
				cpu_count_per_node[i]--;
			}
			if (cpu_count_per_node[i] <= 0)
				break;
		}
	}
	LC_LOG(LC_DEBUG, "List of Linux/Util CPUs after balance: %s",
		mos_cpuset_to_list(cpuinfo->linux_cpus));

	/* Determine total number of Linux/Utility CPUs required. We want at
	 * least 2 Linux/Utility CPUs per node. Also enforce a maximum allowed
	 * LWKCPU:Utility ratio.
	 */
	num_online = mos_cpuset_cardinality(cpuinfo->online);
	num_linux_cpus = mos_cpuset_cardinality(cpuinfo->linux_cpus);
	delta = (2 * num_nodes) - num_linux_cpus;
	ratio = (num_online - num_linux_cpus) / num_linux_cpus;

	/* We need to add CPUs to the Linux mask. Start by taking
	 * the first core from each node until we reach our
	 * minimum required number of CPUs
	 */
	if (delta > 0)
		LC_LOG(LC_DEBUG,
		  "Num_nodes=%d Num_linux_cpus=%d Adding %d more utility CPUs to meet the 2 Utility CPUs per node requirement.",
		    num_nodes, num_linux_cpus, delta);
	if (ratio > ratio_threshold)
		LC_LOG(LC_DEBUG,
		  "Num_nodes=%d Num_linux_cpus=%d Adding more utility CPUs due to ratio threshold=%d exceeded: %d",
		   num_nodes, num_linux_cpus, ratio_threshold, ratio);
	for (cpu = 0, prev_node = -1;
	     (cpu <= cpuinfo->max_cpuid) && ((delta > 0) ||
					     (ratio > ratio_threshold));
	     cpu++) {
		if (!mos_cpuset_is_set(cpu, cpuinfo->online))
			continue;
		if (mos_cpuset_is_set(cpu, cpuinfo->linux_cpus))
			/* Already in our Linux mask. Find next */
			continue;
		if (cpuinfo->cpumap[cpu].node_id == prev_node)
			continue;
		prev_node = cpuinfo->cpumap[cpu].node_id;
		/* Add CPUs in this core to the Linux mask */
		coreid = cpuinfo->cpumap[cpu].core_id;
		pkgid = cpuinfo->cpumap[cpu].pkg_id;
		LC_LOG(LC_DEBUG, "Adding all cpus on coreid=%d pkgid=%d",
		    coreid, pkgid);
		for (cpu2 = cpu; cpu2 <= cpuinfo->max_cpuid; cpu2++) {
			if (coreid != cpuinfo->cpumap[cpu2].core_id ||
			    pkgid != cpuinfo->cpumap[cpu2].pkg_id)
				continue;
			mos_cpuset_set(cpu2, cpuinfo->linux_cpus);
			delta--;
			num_linux_cpus++;
			ratio = (num_online - num_linux_cpus) / num_linux_cpus;
			LC_LOG(LC_DEBUG, "Adding cpu=%d into Linux mask", cpu2);
		}
	}
	LC_LOG(LC_DEBUG, "Completed Linux/Util CPU list: %s",
		mos_cpuset_to_list(cpuinfo->linux_cpus));

	return ratio;
}

static void generate_cpu_string(struct cpu_info *cpuinfo, int ratio,
				char *buffer, int buffer_size)
{
	int i, j, node, syscall_target, cpu, buffer_index, num_nodes,
		num_linux_cpus, num_utils_per_node, nth_lwkcpu;
	unsigned int written, remaining_bufsize;
	unsigned long int node_mask;
	mos_cpuset_t *subgroup_cpus, *lwk_cpus;
	char *lwkcpu_str;

	subgroup_cpus = mos_cpuset_alloc();
	lwk_cpus = mos_cpuset_alloc();

	node_mask = build_node_mask(cpuinfo);
	num_nodes = node_cardinality(node_mask);
	num_linux_cpus = mos_cpuset_cardinality(cpuinfo->linux_cpus);
	num_utils_per_node = num_linux_cpus / num_nodes;

	LC_LOG(LC_DEBUG, "ratio=%d num_utils_per_node=%d",
		ratio, num_utils_per_node);

	/* Progressively process each numa node */
	for  (node = 0, buffer_index = 0; node_mask; node_mask >>= 1, node++) {
		if (!(node_mask & 1))
			continue;
		syscall_target = -1;
		mos_cpuset_xor(lwk_cpus, lwk_cpus, lwk_cpus);
		/* Populate the cpu mask with the CPUs in this node */
		for (cpu = 0; cpu <= cpuinfo->max_cpuid; cpu++) {
			if (!mos_cpuset_is_set(cpu, cpuinfo->online))
				continue;
			if (mos_cpuset_is_set(cpu, cpuinfo->linux_cpus))
				continue;
			if (cpuinfo->cpumap[cpu].node_id != node)
				continue;
			mos_cpuset_set(cpu, lwk_cpus);
		}
		LC_LOG(LC_DEBUG, "nodeid=%d LWK CPU List=%s", node,
			mos_cpuset_to_list(lwk_cpus));

		/* Create sub-groups within the this node for grouping of
		 * lwkcpus and syscall migration CPUs.
		 */
		for (i = 0, nth_lwkcpu = 1; i < num_utils_per_node; i++) {
			mos_cpuset_xor(subgroup_cpus, subgroup_cpus,
				       subgroup_cpus);
			for (j = 0; j < ratio; j++) {
				cpu = mos_cpuset_nth_cpu(nth_lwkcpu++,
							 lwk_cpus);
				if (cpu < 0)
					break;
				mos_cpuset_set(cpu, subgroup_cpus);
			}
			/* Rounding could have left CPUs orphaned on last
			 * iteration. Grab any remaining LWK CPUs in the node
			 */
			if (i == num_utils_per_node) {
				while ((cpu = mos_cpuset_nth_cpu(nth_lwkcpu++,
					lwk_cpus)) >= 0)
					mos_cpuset_set(cpu, subgroup_cpus);
			}

			/* Try to select a Utility CPU within this node.
			 * If not, just use what is available
			 */
			for (j = 1; ; j++) {
				cpu = mos_cpuset_nth_cpu(j,
							 cpuinfo->linux_cpus);
				if (cpu < 0)
					break;
				if (cpuinfo->cpumap[cpu].node_id == node) {
					mos_cpuset_clr(cpu,
						       cpuinfo->linux_cpus);
					break;
				}
			}
			if (cpu < 0) {
				/* Did not find a CPU in our node. Take the
				 * first CPU in the available mask
				 */
				cpu = mos_cpuset_nth_cpu(1,
							 cpuinfo->linux_cpus);
				if (cpu <= 0) {
					lwkctl_abort(-1,
					    "Unexpected condition configuring utility CPU [%s:%d]",
					    __FILE__, __LINE__);
				}
				mos_cpuset_clr(cpu, cpuinfo->linux_cpus);
			}
			syscall_target = cpu;

			LC_LOG(LC_DEBUG,
			    "Subgroup: syscall_target=%d LWK CPU List=%s",
			    syscall_target, mos_cpuset_to_list(subgroup_cpus));

			/* Append the CPU spec string for this sub-group. */
			lwkcpu_str = mos_cpuset_to_list(subgroup_cpus);
			remaining_bufsize = buffer_size - buffer_index;
			written = snprintf(buffer + buffer_index,
					  remaining_bufsize,
					  "%d.%s:", syscall_target, lwkcpu_str);
			if (written >= remaining_bufsize)
				lwkctl_abort(-1,
				 "Buffer overflow generating CPU specification [%s:%d]",
				 __FILE__, __LINE__);
			LC_LOG(LC_DEBUG, "Subgroup buffer=%s", buffer);
			buffer_index += written;
		}
		LC_LOG(LC_DEBUG, "Buffer=%s", buffer);
	}
	/* If we have remaining utility CPUs that have not been assigned to
	 * syscall targets, include them at the end of the string for use by
	 * utility threads. Otherwise, trim the trailing ":" from the string.
	 */
	if (!mos_cpuset_is_empty(cpuinfo->linux_cpus)) {
		remaining_bufsize = buffer_size - buffer_index;
		written = snprintf(buffer + buffer_index, remaining_bufsize,
				"%s.", mos_cpuset_to_list(cpuinfo->linux_cpus));
		if (written >= remaining_bufsize) {
			lwkctl_abort(-1,
			 "Buffer overflow generating CPU specification [%s:%d]",
			 __FILE__, __LINE__);
		}
		buffer_index += written;
	} else
		/* Replace trailing ':' with NULL */
		*(buffer + buffer_index - 1) = '\0';

	mos_cpuset_free(subgroup_cpus);
	mos_cpuset_free(lwk_cpus);
}

/*
 * Parses the lwkcpu specification string and returns the
 * mask of LWKCPUs, Utility CPUs and both.
 *
 * @str, lwkcpu specification string
 * @lwkcpus, mask of LWKCPUs found
 * @utilcpus, mask of Utility CPUs found
 * @allcpus, @lwkcpus | @utilcpus
 * @return,  0 on success
 *         -ve on failure
 */
static int parse_lwkcpu_spec(char *str, mos_cpuset_t *lwkcpus,
			mos_cpuset_t *utilcpus, mos_cpuset_t *allcpus)
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
	mos_cpuset_xor(utilcpus, utilcpus, utilcpus);
	mos_cpuset_xor(allcpus, allcpus, allcpus);
	ip_itr = ip;
	while ((to = strsep(&ip_itr, ":"))) {
		if (!(from = strchr(to, '.'))) {
			/* No syscall target defined */
			from = to;
			to = strchr(to, '\0');
		} else
			*from++ = '\0';

		rc = mos_parse_cpulist(from, cs);
		if (rc) {
			LC_ERR("Failed to parse cpulist %s",
			    from);
			goto out;
		}

		mos_cpuset_or(lwkcpus, lwkcpus, cs);

		rc = mos_parse_cpulist(to, cs);
		if (rc) {
			LC_ERR("Failed to parse cpulist %s",
				to);
			goto out;
		}

		mos_cpuset_or(utilcpus, utilcpus, cs);
	}
	mos_cpuset_or(allcpus, lwkcpus, utilcpus);

out:
	if (ip)
		free(ip);
	if (cs)
		mos_cpuset_free(cs);
	return rc;
}

/* Replaces the partition spec string with a new partition spec string
 * containing the generated lwkcpus specification. Returns a pointer to
 * a string that contains the new lwkcpus specification. The memory for the
 * returned string should be freed by the caller.
 */
static int generate_default_cpu_spec(char **partition_spec,
		mos_cpuset_t *lwkcpus, mos_cpuset_t *utilcpus,
		mos_cpuset_t *allcpus)
{
	static const int buffer_size = 4096;
	char *buffer, *lwkcpu_keyword, *new_spec, *suffix;
	int ratio, rc;
	unsigned int written;
	size_t orig_spec_length, new_spec_length;
	struct cpu_info cpuinfo;

	cpuinfo.online = mos_cpuset_alloc();
	cpuinfo.linux_cpus = mos_cpuset_alloc();

	buffer = malloc(buffer_size);
	if (!buffer)
		lwkctl_abort(-1,
		    "Could not allocate space for buffer [%s:%d]",
		    __FILE__, __LINE__);

	/* Get the mask of online CPUs */
	if (mos_sysfs_read(CPU_ONLINE, buffer, buffer_size) < 0)
		lwkctl_abort(-1, "Could not read %s", CPU_ONLINE);
	if (mos_parse_cpulist(buffer, cpuinfo.online))
		lwkctl_abort(-1, "Could not parse %s (%s)", CPU_ONLINE, buffer);

	/* Generate a CPU map with topology info */
	generate_cpumap(&cpuinfo, buffer, buffer_size);

	/* Select the Linux/Utility CPUs */
	ratio = select_linux_cpus(&cpuinfo);

	generate_cpu_string(&cpuinfo, ratio, buffer, buffer_size);

	/* Break the current partition spec into two strings */
	orig_spec_length = strlen(*partition_spec);
	if (!(lwkcpu_keyword = strstr(*partition_spec, "lwkcpus=auto")))
		lwkctl_abort(-1, "No lwkcpus keyword found [%s:%d]",
				__FILE__, __LINE__);
	/* Break string after the '=' */
	*(lwkcpu_keyword + strlen("lwkcpus=")) = '\0';

	/* Set the beginning of the suffix string */
	suffix =  lwkcpu_keyword + strlen("lwkcpus=auto");

	/* Calculate the new size needed to hold the partition spec */
	new_spec_length = orig_spec_length - strlen("auto") +
			  strlen(buffer) + 1;

	new_spec = (char *)malloc(new_spec_length);
	if (!new_spec)
		lwkctl_abort(-1, "Memory allocation for size %d failed [%s:%d]",
		    new_spec_length, __FILE__, __LINE__);

	written = snprintf(new_spec, new_spec_length, "%s%s%s",
			*partition_spec, buffer, suffix);

	LC_LOG(LC_DEBUG, "newspec rc = %d. new_spec_length=%ld",
		written, new_spec_length);

	if (written >= new_spec_length)
		lwkctl_abort(-1,
		 "Buffer overflow generating partition specification [%s:%d]",
		 __FILE__, __LINE__);

	free(*partition_spec);
	*partition_spec = new_spec;
	mos_cpuset_free(cpuinfo.online);
	mos_cpuset_free(cpuinfo.linux_cpus);

	LC_LOG(LC_DEBUG, "Buffer=%s", buffer);
	LC_LOG(LC_DEBUG, "Partition Spec=%s", *partition_spec);

	rc = parse_lwkcpu_spec(buffer, lwkcpus, utilcpus, allcpus);

	free(buffer);

	return rc;
}
/*
 * Writeback pages corresponding to dirty caches and drop clean
 * cache to ensure maximum movable pages available for dynamic
 * partitioning of memory.
 */
static void vm_drop_clean_caches(void)
{
	sync();
	if (mos_sysfs_write(SYSCTL_DROP_CACHES,
	    VM_DROP_CACHE_ALL, strlen(VM_DROP_CACHE_ALL)))
		LC_LOG(LC_WARN, "Failed to drop Linux's VM caches");
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

	rc = __lwkctl_delete("lwkcpus= lwkmem=");
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

static void auto_spec_update(char **partition_spec,
			bool auto_cpus, bool auto_mem)
{
	char *auto_s = "auto=";
	char *cpus_s = "cpu,";
	char *mem_s = "mem,";
	char *new_spec;
	size_t max_spec_size, remaining_size, written;
	int index = 0;

	max_spec_size = strlen(*partition_spec) + sizeof(" auto=cpu,mem");
	new_spec = malloc(max_spec_size);
	if (!new_spec)
		lwkctl_abort(-ENOMEM, "Insufficient memory");
	written = snprintf(new_spec, max_spec_size, "%s %s",
			*partition_spec, auto_s);
	index += written;
	remaining_size = max_spec_size - written;
	if (auto_cpus) {
		written = snprintf(new_spec + index, remaining_size, "%s",
				cpus_s);
		remaining_size -= written;
		index += written;
	}
	if (auto_mem) {
		written = snprintf(new_spec + index, remaining_size, "%s",
				mem_s);
		index += written;
	}
	*(new_spec + index - 1) = '\0';

	free(*partition_spec);
	*partition_spec = new_spec;
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
	mos_cpuset_t *cs, *tmp_cs, *lwkcpus, *utilcpus, *allcpus;
	int cpu;
	int rc = -EINVAL;
	char *s_key, *s_val, *s_dup, *s_itr, *partition_spec;
	bool found_valid_lwkcpus;
	bool auto_cpus = false;
	bool auto_mem = false;

	LC_LOG(LC_DEBUG, "Creating partition %s", p);

	if (!p || !strlen(p))
		return rc;

	partition_spec = strdup(p);
	if (!partition_spec)
		lwkctl_abort(-ENOMEM, "Insufficient memory");

	cs = mos_cpuset_alloc();
	tmp_cs = mos_cpuset_alloc();
	lwkcpus = mos_cpuset_alloc();
	utilcpus = mos_cpuset_alloc();
	allcpus = mos_cpuset_alloc();

	if (!cs || !tmp_cs || !lwkcpus || !utilcpus || !allcpus)
		lwkctl_abort(-ENOMEM, "Insufficient memory");

	s_dup = strdup(partition_spec);

	if (!s_dup)
		lwkctl_abort(-ENOMEM, "Insufficient memory");

	s_itr = s_dup;

	/* Make sure we have a valid input spec for creating a partition */
	found_valid_lwkcpus = false;
	while ((s_key = strsep(&s_itr, " "))) {
		if (strlen(s_key) == 0)
			continue;
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
			if (!strcmp(s_val, "auto")) {
				auto_cpus = true;
				rc = generate_default_cpu_spec(&partition_spec,
						lwkcpus, utilcpus, allcpus);
			} else
				rc = parse_lwkcpu_spec(s_val,
						lwkcpus, utilcpus, allcpus);
			if (rc) {
				LC_ERR("Failed to parse lwkcpus spec");
				goto out;
			}
			if (!mos_cpuset_is_subset(allcpus, cs)) {
				LC_ERR("Invalid LWK cpu spec");
				show(LC_WARN, "lwkcpus", lwkcpus);
				show(LC_WARN, "utility cpus", utilcpus);
				show(LC_WARN, "present cpus", cs);
				rc = -EINVAL;
				goto out;
			}
			found_valid_lwkcpus = true;
		}
		if (!strcmp(s_key, "lwkmem") && !strcmp(s_val, "auto")) {
			auto_mem = true;
			/* Sync and drop Linux's clean caches */
			vm_drop_clean_caches();
			rc = generate_default_mem_spec(&partition_spec);
			if (rc) {
				LC_ERR(
				    "No memory available for the LWK. Refer the Administrator's Guide for proper configuration and kernel boot parameters.");
				goto out;
			}
		}
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

	/*
	 * We only need to check if LWKCPU partition exists, because LWKMEM
	 * partition can't exist alone when the kernel is booted with dynamic
	 * LWKMEM partitioning support enabled. When booted with static LWKMEM
	 * partitioning,
	 *   - its an error to only specify 'lwkmem=' specification and in any
	 *     case such an attempt will be caught well before we get here.
	 *   - if 'lwkmem=' specification is provided along with 'lwkcpus='
	 *     specification then kernel processes only 'lwkcpus=' with a
	 *     warning that indicates 'lwkmem=' was ignored.
	 */
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

		rc = __lwkctl_delete("lwkcpus= lwkmem=");

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

	/* Did we auto-configure memory or CPUs  */
	if (auto_cpus || auto_mem)
		auto_spec_update(&partition_spec, auto_cpus, auto_mem);

	/* Sync and drop Linux's clean caches */
	vm_drop_clean_caches();

	rc = mos_sysfs_set_lwkconfig(partition_spec);

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
	LC_LOG(LC_DEBUG, "Creating partition %s.. Done", partition_spec);

out:
	if (cs)
		mos_cpuset_free(cs);
	if (lwkcpus)
		mos_cpuset_free(lwkcpus);
	if (utilcpus)
		mos_cpuset_free(utilcpus);
	if (allcpus)
		mos_cpuset_free(allcpus);
	if (s_dup)
		free(s_dup);
	if (partition_spec)
		free(partition_spec);

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
	int rc, size, i, nodes;
	unsigned long *lwkmem;
	mos_cpuset_t *lwkcpus, *linuxcpus, *utilcpus, *temp;
	char *s_lwkcpus, *s_linuxcpus, *s_utilcpus, *p_start, *p_end;
	int numlwkcpus, numlinuxcpus, numutilcpus;
	char s_version[64];
	char config_parms[2048];

	rc = mos_sysfs_read(MOS_SYSFS_VERSION, s_version, sizeof(s_version));
	if (rc <= 0) {
		LC_ERR("not a valid mOS kernel");
		return -EINVAL;
	}

	for (i = 0; i < (int)strlen(s_version); i++) {
		if (s_version[i] == '\n')
			s_version[i] = '\0';
	}

	linuxcpus = mos_cpuset_alloc();
	lwkcpus = mos_cpuset_alloc();
	utilcpus = mos_cpuset_alloc();
	temp = mos_cpuset_alloc();
	size = sizeof(unsigned long) * LC_MAX_NIDS;
	lwkmem = (unsigned long *) malloc(size);

	if (!linuxcpus || !lwkcpus || !utilcpus || !temp || !lwkmem)
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

	rc = mos_sysfs_get_cpulist(MOS_SYSFS_UTILITY_CPUS, utilcpus);
	if (rc) {
		LC_ERR("Failed to read utility cpus");
		goto out;
	}

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

	mos_cpuset_not(temp, lwkcpus);
	mos_cpuset_and(linuxcpus, linuxcpus, temp);

	s_linuxcpus = mos_cpuset_to_list(linuxcpus);
	s_lwkcpus = mos_cpuset_to_list(lwkcpus);
	s_utilcpus = mos_cpuset_to_list(utilcpus);

	numlinuxcpus = mos_cpuset_cardinality(linuxcpus);
	numlwkcpus = mos_cpuset_cardinality(lwkcpus);
	numutilcpus = mos_cpuset_cardinality(utilcpus);

	if (!s_linuxcpus || !s_lwkcpus || !s_utilcpus)
		lwkctl_abort(-ENOMEM, "Insufficient memory");

	printf("mOS version   : %s\n", s_version);
	printf("Linux   CPU(s): ");
	if (numlinuxcpus)
		printf("%s ", s_linuxcpus);
	printf("[ %d CPU(s) ]\n", numlinuxcpus);

	printf("LWK     CPU(s): ");
	if (numlwkcpus)
		printf("%s ", s_lwkcpus);
	printf("[ %d CPU(s) ]\n", numlwkcpus);

	printf("Utility CPU(s): ");
	if (numutilcpus)
		printf("%s ", s_utilcpus);
	printf("[ %d CPU(s) ]\n", numutilcpus);

	memset(lwkmem, 0, size);
	rc = mos_sysfs_get_vector(lwkmem, &size,
				  MOS_SYSFS_LWKMEM);
	if (rc) {
		LC_ERR("Failed to read LWK memory info");
		goto out;
	}
	printf("LWK Memory(KB):");
	for (i = 0, nodes = 0; i < size; i++) {
		printf(" %ld", KB(lwkmem[i]));
		if (lwkmem[i])
			nodes++;
	}
	printf(" [ %d NUMA nodes ]\n", nodes);

	p_start = strstr(config_parms, "auto=");
	if (p_start) {
		p_end = strstr(p_start, " ");
		if (p_end)
			*p_end = '\0';
		if (strstr(p_start, "cpu"))
			printf(
			    "CPU specification was automatically generated.\n");
		if (strstr(p_start, "mem"))
			printf(
			    "Memory specification was automatically generated.\n");
	}
out:
	if (linuxcpus)
		mos_cpuset_free(linuxcpus);
	if (lwkcpus)
		mos_cpuset_free(lwkcpus);
	if (utilcpus)
		mos_cpuset_free(utilcpus);
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
	char *p_start, *p_end;
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
	/* Remove the "auto" keyword if it exists */
	p_start = strstr(config_parms, "auto=");
	if (p_start) {
		p_end = strstr(p_start, " ");
		if (!p_end)
			memmove(p_start, "\n", 2);
		else
			memmove(p_start, p_end, strlen(p_end) + 1);
	}
	printf("%s", config_parms);

	return 0;
}

static bool set_mos_view(char *view)
{
	FILE *fp;
	size_t len, ret = -1;

	if (!view || !(len = strlen(view)))
		goto out;

	fp = fopen(PROC_MOS_VIEW, "w");
	if (!fp)
		goto out;
	ret = fwrite(view, 1, len, fp);
	fclose(fp);
out:
	return ret == len;
}

static bool get_mos_view(char *view)
{
	FILE *fp;
	char *c;
	size_t ret = 0;
	bool rc = false;

	if (!view)
		goto out;

	fp = fopen(PROC_MOS_VIEW, "r");
	if (!fp)
		goto out;

	ret = fread(view, 1, PROC_MOS_VIEW_LEN, fp);
	if (ret && ret <= PROC_MOS_VIEW_LEN) {
		c = strchr(view, '\n');
		if (c)
			*c = '\0';
		rc = true;
	}
	fclose(fp);
out:
	return rc;
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
	char view[PROC_MOS_VIEW_LEN] = { "all" };

	/*
	 * lwkctl needs to have full system view i.e. its mOS view
	 * need to be set to 'all'. Override the inherited mos_view
	 * from the parent and set it to 'all'
	 */
	if (set_mos_view(view) && get_mos_view(view)) {
		if (strcmp(view, "all")) {
			LC_ERR("Invalid mOS view set: %s", view);
			return -1;
		}
	} else {
		LC_ERR("Failed to set mOS view: %s", view);
		return -1;
	}

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

