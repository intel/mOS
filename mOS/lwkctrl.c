/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016-2020 Intel Corporation.
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

#include <linux/printk.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/mutex.h>
#include <linux/mos.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/cpumask.h>
#include "lwkcpu.h"
#include "lwkctrl.h"

#undef pr_fmt
#define pr_fmt(fmt)	"mOS-lwkctl: " fmt

cpumask_t __mos_lwkcpus_arg;
cpumask_t __mos_sccpus_arg;
nodemask_t __mos_lwkmem_nodes;
resource_size_t __mos_lwkmem_size[MAX_NUMNODES];
char lwkctrl_cpus_spec[LWKCTRL_CPUS_SPECSZ];
char lwkctrl_cpu_profile_spec[LWKCTRL_CPU_PROFILE_SPECSZ] = LWKCPU_PROF_NOR;
static char lwkctrl_mem_spec[LWKCTRL_MEM_SPECSZ];
/*
 * CPU masks used for parsing lwkcpus spec during early bootup
 * as dynamic allocation is not supported early.
 */
static	cpumask_t to;
static	cpumask_t from;

static int lwkcpu_parse_args(char *arg, cpumask_t *lwkcpus,
			     cpumask_t *utility_cpus);
static int lwkmem_parse_args(char *arg, nodemask_t *node_mask,
			     resource_size_t *node_size);
static void clear_lwkcpu_spec(void);
static void clear_lwkmem_spec(void);

/* Weak references to scheduler and memory management hooks, These functions
 * are overridden by mOS scheduler and memory management implementation. If
 * the prototypes change then we need to keep the function prototypes consi-
 * -stent across this module and mOS scheduler/memory management.
 */
int __weak mos_sched_init(void) { return -EINVAL; }
int __weak mos_sched_exit(void) { return -EINVAL; }
int __weak mos_sched_activate(cpumask_var_t new_lwkcpus) { return -EINVAL; }
int __weak mos_sched_deactivate(cpumask_var_t back_to_linux) { return -EINVAL; }
int __weak mos_mem_init(nodemask_t *m, resource_size_t *r, bool p)
{
	return -EINVAL;
}
int __weak mos_mem_free(void) { return -EINVAL; }
int __weak mos_mem_clear_memory(void) { return -EINVAL; }

/*
 * Partitions CPUs between Linux and LWK
 *
 * @p, specifies the resources to be taken out from Linux and allocated
 *     to LWK
 * @return, 0 on success
 *          -ve value on failure
 */
int lwkcpu_partition_create(cpumask_var_t lwkcpus_req)
{
	cpumask_var_t lwkcpus_booted;
	cpumask_var_t lwkcpus_down;
	cpumask_var_t lwkcpus_up;
	int ret = -1;

	if (!zalloc_cpumask_var(&lwkcpus_booted, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&lwkcpus_down, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&lwkcpus_up, GFP_KERNEL)) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to allocate cpumasks!", __func__);
		return -ENOMEM;
	}

	/* Initialize LWK scheduler */
	ret = mos_sched_init();
	if (ret) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to initialize LWK scheduler! ret %d",
			 __func__, ret);
		goto out;
	}

	/* Boot LWK CPUs */
	ret = lwkcpu_up_multiple(lwkcpus_req, lwkcpus_booted);
	if (ret) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed, requested [%*pbl] onlined [%*pbl]",
			__func__, cpumask_pr_args(lwkcpus_req),
			cpumask_pr_args(lwkcpus_booted));

		/* Try to rollback state. */
		if (!cpumask_empty(lwkcpus_booted) &&
		    lwkcpu_down_multiple(lwkcpus_booted, lwkcpus_down)) {
			cpumask_andnot(lwkcpus_up, lwkcpus_booted,
				       lwkcpus_down);
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: Failed to re-offline CPUs [%*pbl]",
				__func__, cpumask_pr_args(lwkcpus_up));
			/*
			 * Few CPUs are still booted, so we skip
			 * further efforts to rollback state.
			 */
			goto out;
		}

		if (mos_sched_exit()) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: LWK scheduler exit failed!", __func__);
		}
		goto out;
	}

	/* Activate LWK scheduler */
	ret = mos_sched_activate(lwkcpus_req);
	if (ret) {
		/*
		 * No point in attempting to rollback at this stage, instead
		 * send RAS failure message indicating fatal error.
		 */
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: LWK scheduler activation failed! ret %d",
			__func__, ret);
	}
out:
	free_cpumask_var(lwkcpus_booted);
	free_cpumask_var(lwkcpus_down);
	free_cpumask_var(lwkcpus_up);
	return ret;
}

/*
 * Releases the resources allocated to LWK previously
 * while creating LWKCPU partition
 *
 * @lwkcpus_req, cpumask of LWKCPUs to be released.
 * @return, 0 on success
 *          -ve value on failure
 */
int lwkcpu_partition_destroy(cpumask_var_t lwkcpus_req)
{
	cpumask_var_t lwkcpus_shutdown;
	cpumask_var_t lwkcpus_up;
	cpumask_var_t lwkcpus_down;
	int ret = -1;

	if (!zalloc_cpumask_var(&lwkcpus_shutdown, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&lwkcpus_up, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&lwkcpus_down, GFP_KERNEL)) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to allocate cpumasks.", __func__);
		return -ENOMEM;
	}

	/* Deactivate mOS scheduler on LWK CPUs */
	ret = mos_sched_deactivate(lwkcpus_req);
	if (ret) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to deactivate LWK scheduler, ret %d",
			__func__, ret);
		goto out;
	}

	/* Shutdown LWK CPUs */
	ret = lwkcpu_down_multiple(lwkcpus_req, lwkcpus_shutdown);
	if (ret) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed, requested [%*pbl] offlined [%*pbl]",
			__func__, cpumask_pr_args(lwkcpus_req),
			cpumask_pr_args(lwkcpus_shutdown));

		/* Try to rollback the LWKCPU partition state */
		if (!cpumask_empty(lwkcpus_shutdown) &&
		    lwkcpu_up_multiple(lwkcpus_shutdown, lwkcpus_up)) {
			cpumask_andnot(lwkcpus_down, lwkcpus_shutdown,
				       lwkcpus_up);
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: Failed to re-online LWKCPUs %*pbl",
				__func__, cpumask_pr_args(lwkcpus_down));
			/*
			 * At this point few CPUs are still shutdown, so we
			 * do not attempt to re-activate LWK scheduler.
			 */
			goto out;
		}

		/* Try to re-activate LWK scheduler */
		if (mos_sched_activate(lwkcpus_req)) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: Failed to activate LWK scheduler.",
				__func__);
		}
		goto out;
	}

	/* Exit mOS scheduler */
	ret = mos_sched_exit();
	if (ret) {
		/*
		 * No point in attempting to rollback at this stage, instead
		 * send RAS failure message indicating fatal error.
		 */
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: LWK scheduler exit failed, ret %d",
			__func__, ret);
	}

out:
	free_cpumask_var(lwkcpus_shutdown);
	free_cpumask_var(lwkcpus_up);
	free_cpumask_var(lwkcpus_down);
	return ret;
}

int lwkmem_partition_create(char *spec, bool precise)
{
	int rc = -EINVAL;

	if (!spec)
		goto out;

	if (spec[0] == '\0') {
		/* Noop */
		rc = 0;
		goto out;
	}

	rc = lwkmem_parse_args(spec, &__mos_lwkmem_nodes, __mos_lwkmem_size);
	if (rc) {
		mos_ras(MOS_LWKCTL_WARNING,
			"%s: Failed to parse lwkmem specification: %s.",
		       __func__, spec);
		goto out;
	}

	rc = mos_mem_init(&__mos_lwkmem_nodes, __mos_lwkmem_size, precise);
	if (rc) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to initialize mOS memory management.",
			__func__);
	}
out:
	if (rc)
		clear_lwkmem_spec();
	return rc;

}

int lwkmem_partition_destroy(void)
{
	int rc = -EINVAL;

	rc = mos_mem_free();
	if (rc)
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to exit mOS memory management.", __func__);
	else
		clear_lwkmem_spec();
	return rc;
}

int lwkmem_partition_clear_memory(void)
{
	int rc;

	rc = mos_mem_clear_memory();
	if (rc) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to clear partitioned memory rc=%d.",
			__func__, rc);
	}
	return rc;
}

/*
 * Creates a default LWK partition as specified by the boot command line.
 * This function is called from init/main.c to trigger default partition
 * creation during kernel bootup.
 */
void lwkctl_def_partition(void)
{
	int rc = -1;

	/* If lwkcpus spec is not specified then we ignore rest of the spec */
	if (cpumask_empty(mos_lwkcpus_arg))
		goto out;

	if (strlen(lwkctrl_mem_spec)) {
		/* Create default LWKMEM partition */
		pr_info("Creating default memory partition: lwkmem=%s\n",
			lwkctrl_mem_spec);
		rc = lwk_config_lwkmem(lwkctrl_mem_spec);
		pr_info("LWK creating default LWKMEM partition..%s\n",
			rc ? "Failed!" : "Done");
		if (rc) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"Failure creating default lwkmem=%s",
				lwkctrl_mem_spec);
			goto out;
		}
	}

	/* Create default LWKCPU partition */
	pr_info("Creating default CPU partition:\nlwkcpus=%s",
		lwkctrl_cpus_spec);
	pr_info(" lwkcpu_profile=%s\n",
		lwkctrl_cpu_profile_spec);
	rc = lwk_config_lwkcpus(lwkctrl_cpus_spec,
				lwkctrl_cpu_profile_spec);
	pr_info("LWK creating default partition.. %s\n",
		rc ? "Failed!" : "Done");
	/*
	 * If we created an LWK memory partition then clear partitioned
	 * LWK memory if CPU partitioning succeeded in the previous step.
	 */
	if (!rc && !nodes_empty(__mos_lwkmem_nodes))
		rc = lwkmem_partition_clear_memory();
	if (rc) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"Failed creating default lwkcpus=%s lwkcpu_profile=%s",
			lwkctrl_cpus_spec,
			lwkctrl_cpu_profile_spec);
		/* Return memory to Linux if we created an LWKMEM partition */
		if (!nodes_empty(__mos_lwkmem_nodes) &&
		    lwk_config_lwkmem(NULL) < 0)
			mos_ras(MOS_LWKCTL_FAILURE,
				"Failure returning LWK memory");
		/* Return CPUs to Linux if we created an LWKCPU partition */
		if (cpumask_weight(cpu_lwkcpus_mask) &&
		    lwk_config_lwkcpus(NULL, NULL) < 0)
			mos_ras(MOS_LWKCTL_FAILURE,
				"Failure returing LWK CPUs");
	}
out:
	if (rc) {
		/* If there wasn't a default boot partition even then
		 * we would like to clear the default settings
		 */
		lwkcpu_state_deinit();
		clear_lwkcpu_spec();
		clear_lwkmem_spec();
	}
}

/*
 * Parses the early param 'lwkcpus=<>' specified in Linux boot
 * commandline
 */
static int __init lwkcpus(char *str)
{
	int rc;
	int strsize;

	strsize = snprintf(lwkctrl_cpus_spec, LWKCTRL_CPUS_SPECSZ, "%s", str);
	if (strlen(str) > strsize)
		pr_warn("lwkcpus specification truncation occurred in %s()\n",
			__func__);

	rc = lwkcpu_parse_args(str, mos_lwkcpus_arg, mos_sccpus_arg);
	if (rc) {
		cpumask_clear(mos_lwkcpus_arg);
		cpumask_clear(mos_sccpus_arg);
		clear_lwkcpu_spec();
	}
	return 0;
}
early_param("lwkcpus", lwkcpus);

/*
 * Parses the early param 'lwkcpu_profile=<>' specified in Linux boot
 * commandline
 */
static int __init lwkcpu_profile(char *str)
{
	int strsize;

	if (!strcmp(str, LWKCPU_PROF_DBG)) {
		strsize = snprintf(lwkctrl_cpu_profile_spec,
				   LWKCTRL_CPU_PROFILE_SPECSZ, "%s", str);
		if (strlen(str) > strsize)
			pr_warn("lwkcpu_profile spec truncation in %s()\n",
				__func__);
	}
	return 0;
}
early_param("lwkcpu_profile", lwkcpu_profile);

/*
 * Parses the early param 'lwkmem=<>' specified in Linux boot
 * commandline
 */
static int __init lwkmem(char *str)
{
	int strsize;

	strsize = snprintf(lwkctrl_mem_spec, LWKCTRL_MEM_SPECSZ, "%s", str);
	if (strsize >= LWKCTRL_MEM_SPECSZ)
		pr_warn("lwkmem spec truncation occurred in %s()\n",
			__func__);
	return 0;
}
early_param("lwkmem", lwkmem);

/* Helper functions for lwkctrl */
int lwkmem_distribute_request(resource_size_t req, nodemask_t *mask,
		       resource_size_t *node_size)
{
	resource_size_t rpn, alloc;
	int nid, nodes = nodes_weight(*mask);

	if (!req || !nodes) {
		mos_ras(MOS_LWKCTL_WARNING,
			"Cannot distribute request : %s.",
			!req ? "requested size is 0" :
			       "requested nodemask is empty");
		return -1;
	}

	rpn = 0;
	while (nodes) {
		rpn = req / nodes;
		if (rpn)
			break;
		nodes--;
	}
	alloc = 0;
	while (alloc < req) {
		for_each_node_mask(nid, *mask) {
			node_size[nid] += rpn;
			alloc += rpn;
			if ((req - alloc) < rpn) {
				if (alloc != req)
					rpn = req - alloc;
				else
					break;
			}
		}
	}
	return 0;
}

static int lwkmem_parse_args(char *arg, nodemask_t *node_mask,
		      resource_size_t *node_size)
{
	char *nidstr, *memstr, *str, *str_start;
	int nid, rc;
	resource_size_t req;

	str = str_start = kstrdup(arg, GFP_KERNEL);
	if (!str) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: could not alloc temp storage for lwkmem spec: %s",
		       __func__, arg);
		return -ENOMEM;
	}

	nodes_clear(*node_mask);
	for (nid = 0; nid < MAX_NUMNODES; nid++)
		node_size[nid] = 0;

	while ((nidstr = strsep(&str, ","))) {
		memstr = strchr(nidstr, ':');
		if (!memstr) {
			nid = NUMA_NO_NODE;
			memstr = nidstr;
		} else {
			*(memstr++) = '\0';
			rc = kstrtoint(nidstr, 0, &nid);
			if (rc || nid < 0 || nid >= num_possible_nodes()) {
				mos_ras(MOS_LWKCTL_WARNING,
					"Invalid NUMA id: \"%s\".",
					nidstr);
				nid = NUMA_NO_NODE;
			}
		}

		req = memparse(memstr, 0);
		if (!req)
			continue;

		if (nid == NUMA_NO_NODE) {
			rc = lwkmem_distribute_request(req, &node_possible_map,
						node_size);
			if (rc) {
				mos_ras(MOS_LWKCTL_WARNING,
					"%s(): could not distribute %lld to nodes %*pbl.",
					__func__, req,
					nodemask_pr_args(&node_possible_map));
			} else {
				nodes_or(*node_mask, *node_mask,
					 node_possible_map);
			}
		} else {
			node_size[nid] += req;
			node_set(nid, *node_mask);
		}
	}
	kfree(str_start);
	return 0;
}

static size_t memsize_to_str(char *str, size_t strsize, resource_size_t memsize)
{
	resource_size_t mask, val, i;
	size_t retsize;
	char unit[] = { 'K', 'M', 'G', 'T', 'P', 'E'};

	for (i = 0; i < ARRAY_SIZE(unit); i++) {
		mask = 0;
		mask = ~mask << (10 * (i + 1));
		if (!(mask & memsize) || (~mask & memsize))
			break;
	}

	val = memsize;
	if (i) {
		val >>= (10 * i);
		retsize = snprintf(str, strsize, "%llu%c", val, unit[i - 1]);
	} else
		retsize = snprintf(str, strsize, "%llu", val);
	return retsize;
}

char *lwkmem_get_spec(void)
{
	int nid;
	bool truncated = false;
	size_t strsize, strsize_left;
	char *str = lwkctrl_mem_spec;

	memset(str, 0, sizeof(lwkctrl_mem_spec));
	strsize_left = ARRAY_SIZE(lwkctrl_mem_spec);

	for_each_node_mask(nid, __mos_lwkmem_nodes) {
		if (__mos_lwkmem_size[nid] == 0)
			continue;

		if (strsize_left) {
			if (str != lwkctrl_mem_spec)
				strsize = snprintf(str, strsize_left, ",%d:",
						   nid);
			else
				strsize = snprintf(str, strsize_left, "%d:",
						   nid);
			if (strsize >= strsize_left) {
				truncated = true;
				break;
			}
			strsize_left -= strsize;
			str += strsize;

			strsize = memsize_to_str(str, strsize_left,
						 __mos_lwkmem_size[nid]);
			if (strsize >= strsize_left) {
				truncated = true;
				break;
			}
			strsize_left -= strsize;
			str += strsize;
		} else {
			truncated = true;
			break;
		}
	}

	if (truncated) {
		lwkctrl_mem_spec[LWKCTRL_MEM_SPECSZ - 1] = '\0';
		mos_ras(MOS_LWKCTL_WARNING,
			"lwkmem specification truncated in %s.", __func__);
	}
	return lwkctrl_mem_spec;
}

/*
 * Parses LWK CPU partition specification provided in @arg and
 * returns the bitmask of LWK CPUs and Utility CPUs
 *
 * @arg, input string which has LWKCPU partition specification
 * @lwkcpus, bitmask of LWK CPUs after parsing @arg
 * @utility_cpus, bitmask of utility CPUs after parsing @arg
 * @return, 0 on success
 * 	    -ve on failure
 *
 *   *** This function is not thread safe and uses global masks   ***
 *   *** to, from for cpumask computation. This function          ***
 *   *** is meant to be called only from early boot up code where ***
 *   *** dynamic allocation is not possible.                      ***
 */
static int lwkcpu_parse_args(char *arg, cpumask_t *lwkcpus,
			     cpumask_t *utility_cpus)
{
	char *s_to, *s_from;
	int rc = -1;

	cpumask_clear(lwkcpus);
	cpumask_clear(utility_cpus);
	cpumask_clear(&to);
	cpumask_clear(&from);

	while ((s_to = strsep(&arg, ":"))) {
		if (!(s_from = strchr(s_to, '.'))) {
			/* No utility cpu target defined */
			s_from = s_to;
			s_to = strchr(s_to, '\0');
		} else
			*s_from++ = '\0';
		if (cpulist_parse(s_to, &to) < 0) {
			pr_err("%s: Invalid character found, Value=%s\n",
				__func__, s_to);
			goto out;
		}
		if (cpulist_parse(s_from, &from) < 0) {
			pr_err("%s: Invalid character found, Value=%s.\n",
				__func__, s_from);
			goto out;
		}
		/* Maximum of one utility CPU allowed per LWK CPU range */
		if ((cpumask_weight(&to) > 1) && !cpumask_empty(&from)) {
			pr_err("%s: More than one utility CPU was specified\n",
				__func__);
			goto out;
		}
		cpumask_or(utility_cpus, utility_cpus, &to);
		cpumask_or(lwkcpus, lwkcpus, &from);
	}

	/*
	 * a. There need to be atleast 1 LWKCPU in the spec.
	 * b. LWKCPUs can not be one of those Linux CPUs which
	 *    are not offlined yet and being used by Linux.
	 * c. A CPU can not be both LWK CPU and utility CPU.
	 */
	if (cpumask_empty(lwkcpus)) {
		pr_err("%s: No CPUs specified for LWKCPU partition!\n",
		       __func__);
		goto out;
	}
	if (cpumask_intersects(lwkcpus, cpu_online_mask)) {
		pr_err("%s: Overlap detected. LWK CPUs: %*pbl Online CPUs: %*pbl\n",
			__func__, cpumask_pr_args(lwkcpus),
			cpumask_pr_args(cpu_online_mask));
		goto out;
	}
	if (cpumask_intersects(lwkcpus, utility_cpus)) {
		pr_err("%s: Overlap detected. LWK CPUs: %*pbl Utility CPUs: %*pbl\n",
			__func__, cpumask_pr_args(lwkcpus),
			cpumask_pr_args(utility_cpus));
		goto out;
	}
	rc = 0;
out:
	return rc;
}

void clear_lwkcpu_spec(void)
{
	memset(lwkctrl_cpus_spec, 0, sizeof(lwkctrl_cpus_spec));
	memset(lwkctrl_cpu_profile_spec, 0, sizeof(lwkctrl_cpu_profile_spec));
}

void clear_lwkmem_spec(void)
{
	nodes_clear(__mos_lwkmem_nodes);
	memset(__mos_lwkmem_size, 0, sizeof(__mos_lwkmem_size));
	memset(lwkctrl_mem_spec, 0, sizeof(lwkctrl_mem_spec));
}
