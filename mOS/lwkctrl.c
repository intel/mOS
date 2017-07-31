/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016-2017 Intel Corporation.
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
#include <linux/irqnr.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
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
bool lwkmem_static_enabled;

static int lwkmem_parse_args(char *arg, nodemask_t *node_mask,
			     resource_size_t *node_size);
static void clear_lwkcpu_spec(void);
static void clear_lwkmem_spec(void);

/* Weak references to scheduler and memory management hooks, These functions
 * are overridden by mOS scheduler and memory management implementation. If
 * the prototypes change then we need to keep the function prototypes consi-
 * -stent across this module and mOS scheduler/memory management.
 */
int __weak mos_sched_init(void) { return 0; }
int __weak mos_sched_exit(void) { return 0; }
int __weak mos_sched_activate(cpumask_var_t new_lwkcpus) { return 0; }
int __weak mos_sched_deactivate(cpumask_var_t back_to_linux) { return 0; }

int __weak mos_mem_init(nodemask_t *m, resource_size_t *req) { return 0; }
int __weak mos_mem_free(void) { return 0; }

/*
 * Partitions resources (currently only cpus) between Linux and LWK
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
	int irq = 0;
	int ret = -1;

	if (!zalloc_cpumask_var(&lwkcpus_booted, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&lwkcpus_down, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&lwkcpus_up, GFP_KERNEL)) {
		pr_warn("%s: Failed to allocate cpumasks.\n", __func__);
		return -1;
	}

	/* Initialize mOS scheduler */
	ret = mos_sched_init();
	if (ret) {
		pr_err("%s: Failed to initialize mOS scheduler\n", __func__);
		goto error;
	}

	/* Boot LWK CPUs */
	ret = lwkcpu_up_multiple(lwkcpus_req, lwkcpus_booted);
	if (ret) {
		if (!cpumask_equal(lwkcpus_req, lwkcpus_booted)) {
			if (lwkcpu_down_multiple(lwkcpus_booted,
						 lwkcpus_down)) {
				cpumask_andnot(lwkcpus_up, lwkcpus_booted,
					       lwkcpus_down);
				pr_warn("%s: (!) Failed to rollback %*pbl\n",
					__func__, cpumask_pr_args(lwkcpus_up));
			}
		}
		goto error;
	}

	/* Re-affinitize interrupts away from LWK CPUs if possible */
	for_each_irq_nr(irq) {
		if (!irq_can_set_affinity(irq))
			continue;
		if (!irq_save_affinity_linux(irq, lwkcpus_req)) {
			pr_warn("%s:WARN couldn't drive away IRQ%d\n",
				__func__, irq);
		}
	}

	/* Activate mOS scheduler on LWK CPUs */
	ret = mos_sched_activate(lwkcpus_req);
	if (ret) {
		pr_err("%s: Failed to activate mOS scheduler\n", __func__);

		/* Rollback all LWK CPUs booted */
		if (lwkcpu_down_multiple(lwkcpus_booted,
					 lwkcpus_down)) {
			cpumask_andnot(lwkcpus_up, lwkcpus_booted,
				       lwkcpus_down);
			pr_warn("%s: (!) Failed to rollback %*pbl\n",
				__func__,
				cpumask_pr_args(lwkcpus_up));
		}
		if (mos_sched_exit()) {
			pr_err("%s: Failed to de-initialize mOS scheduler\n",
				__func__);
		}
		goto error;
	}

error:
	free_cpumask_var(lwkcpus_booted);
	free_cpumask_var(lwkcpus_down);
	free_cpumask_var(lwkcpus_up);
	return ret;
}

/*
 * Releases the resources allocated to LWK previously while creating
 * LWK partition
 *
 * @p, specifies the resources to be released from LWK
 * @return, 0 on success
 *          -ve value on failure
 */
int lwkcpu_partition_destroy(cpumask_var_t lwkcpus_req)
{
	cpumask_var_t lwkcpus_shutdown;
	cpumask_var_t lwkcpus_up;
	int irq;
	int ret = -1;

	if (!zalloc_cpumask_var(&lwkcpus_shutdown, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&lwkcpus_up, GFP_KERNEL)) {
		pr_warn("%s: Failed to allocate cpumasks.\n", __func__);
		return -1;
	}

	/* Deactivate mOS scheduler on LWK CPUs */
	ret = mos_sched_deactivate(lwkcpus_req);
	if (ret) {
		pr_err("%s: Failed to deactivate mOS scheduler\n", __func__);
		goto error;
	}

	/*
	 * Restore the CPU affinity of interrupts migrated
	 * away while creating partition
	 */
	for_each_irq_nr(irq) {
		if (!irq_can_set_affinity(irq))
			continue;

		if (!irq_restore_affinity_linux(irq)) {
			pr_warn("%s:WARN couldn't restore irq%d affinity\n",
				__func__, irq);
		}
	}

	/* Shutdown LWK CPUs */
	ret = lwkcpu_down_multiple(lwkcpus_req, lwkcpus_shutdown);
	if (ret) {
		if (!cpumask_equal(lwkcpus_req, lwkcpus_shutdown)) {
			cpumask_andnot(lwkcpus_up, lwkcpus_req,
				       lwkcpus_shutdown);
			pr_warn("%s: (!) Failed to shutdown %*pbl\n",
				__func__, cpumask_pr_args(lwkcpus_up));
		}
		goto error;
	}

	/* Exit mOS scheduler */
	ret = mos_sched_exit();
	if (ret) {
		pr_err("%s: Failed to exit mOS scheduler\n", __func__);
		goto error;
	}
error:
	free_cpumask_var(lwkcpus_shutdown);
	free_cpumask_var(lwkcpus_up);
	return ret;
}

int lwkmem_partition_create(char *spec)
{
	int rc = -EINVAL;

	if (lwkmem_static_enabled)
		goto error;

	rc = lwkmem_parse_args(spec, &__mos_lwkmem_nodes, __mos_lwkmem_size);
	if (rc) {
		pr_err("%s: Failed to parse LWKMEM specification: %s\n",
		       __func__, spec);
		goto error;
	}

	rc = mos_mem_init(&__mos_lwkmem_nodes, __mos_lwkmem_size);
	if (rc) {
		pr_err("%s: Failed to initialize mOS memory management\n",
			__func__);
		goto error;
	}
	return 0;
error:
	clear_lwkmem_spec();
	return rc;

}

int lwkmem_partition_destroy(void)
{
	int rc = -EINVAL;

	if (lwkmem_static_enabled)
		goto out;

	rc = mos_mem_free();
	if (rc)
		pr_err("%s: Failed to exit mOS memory management!\n", __func__);
out:
	clear_lwkmem_spec();
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

	if (!lwkmem_static_enabled && strlen(lwkctrl_mem_spec)) {
		/* Create default LWKMEM partition */
		pr_info("Creating default memory partition: lwkmem=%s\n",
			lwkctrl_mem_spec);
		rc = lwk_config_lwkmem(lwkctrl_mem_spec);
		pr_info("LWK creating default LWKMEM partition..%s\n",
			rc ? "Failed!" : "Done");
		if (rc)
			goto out;
	}

	if (!cpumask_empty(mos_lwkcpus_arg)) {
		/* Create default LWKCPU partition */
		pr_info("Creating default CPU partition:\nlwkcpus=%s",
			lwkctrl_cpus_spec);
		pr_info(" lwkcpu_profile=%s\n",
			lwkctrl_cpu_profile_spec);
		rc = lwk_config_lwkcpus(lwkctrl_cpus_spec,
					lwkctrl_cpu_profile_spec);
		pr_info("mOS: LWK creating default partition.. %s\n",
			rc ? "Failed!" : "Done");
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
		pr_warn("mOS: lwkcpus spec truncation occurred in %s.\n",
			__func__);

	rc = lwkcpu_parse_args(str, mos_lwkcpus_arg, mos_sccpus_arg);

	if (rc) {
		cpumask_clear(mos_lwkcpus_arg);
		cpumask_clear(mos_sccpus_arg);
		lwkctrl_cpus_spec[0] = '\0';
	}
	return rc;
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
		if (strlen(str) > strsize) {
			pr_warn("mOS: lwkcpu_profile spec truncation in %s.\n",
				__func__);
		}
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
		pr_warn("mOS: lwkmem specification string truncation occurred in %s.\n",
				__func__);
	return 0;
}
early_param("lwkmem", lwkmem);

static int __init enable_lwkmem_static(char *s)
{
	pr_info("set to use static partitioning of memory\n");
	lwkmem_static_enabled = true;
	return 0;
}
__setup("lwkmem_static", enable_lwkmem_static);

/* Helper functions for lwkctrl */
int lwkmem_distribute_request(resource_size_t req, nodemask_t *mask,
		       resource_size_t *node_size)
{
	resource_size_t rpn, alloc;
	int nid, nodes = nodes_weight(*mask);

	if (!req || !nodes) {
		pr_info("Can not distribute request : %s\n",
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
	if (!str)
		return -ENOMEM;

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
				pr_warn("(!) invalid NUMA id: \"%s\"\n",
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
				pr_warn("%s(): could not distribute %lld B\n",
					__func__, req);
				pr_warn("%s(): to nodes %*pbl\n",
					__func__,
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
		mask ^= mask;
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

	if (lwkmem_static_enabled)
		return str;

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
		pr_err("mOS: lwkmem spec truncated in %s()!\n", __func__);
	}
	return lwkctrl_mem_spec;
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

