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

#include <linux/printk.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/mutex.h>
#include <linux/mos.h>
#include <linux/sched.h>
#include <linux/irqnr.h>
#include <linux/interrupt.h>
#include "lwkcpu.h"
#include "lwkctrl.h"

cpumask_t __mos_lwkcpus_arg;
cpumask_t __mos_sccpus_arg;
char lwkctrl_cpus_spec[LWKCTRL_CPUS_SPECSZ];
char lwkctrl_cpu_profile_spec[LWKCTRL_CPU_PROFILE_SPECSZ] = LWKCPU_PROF_NOR;
char lwkctrl_mem_spec[LWKCTRL_MEM_SPECSZ];

/* Weak references to scheduler hooks, These functions are overridden
 * by mOS scheduler implementation. If the prototypes change then we
 * need to keep the function prototypes consistent across this module
 * and mOS scheduler.
 */
int __weak mos_sched_init(void) { return 0; }
int __weak mos_sched_exit(void) { return 0; }
int __weak mos_sched_activate(cpumask_var_t new_lwkcpus) { return 0; }
int __weak mos_sched_deactivate(cpumask_var_t back_to_linux) { return 0; }

/*
 * Partitions resources (currently only cpus) between Linux and LWK
 *
 * @p, specifies the resources to be taken out from Linux and allocated
 *     to LWK
 * @return, 0 on success
 *          -ve value on failure
 */
int lwkctrl_partition_create(struct lwkctrl_partition *p)
{
	cpumask_var_t lwkcpus_booted;
	cpumask_var_t lwkcpus_down;
	cpumask_var_t lwkcpus_up;
	int irq = 0;
	int ret = -1;

	if (!p)
		return -1;

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
	ret = lwkcpu_up_multiple(p->lwkcpus, lwkcpus_booted);

	if (ret) {
		if (!cpumask_equal(p->lwkcpus, lwkcpus_booted)) {
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
		if (!irq_save_affinity_linux(irq, p->lwkcpus)) {
			pr_warn("%s:WARN couldn't drive away IRQ%d\n",
				__func__, irq);
		}
	}

	/* Activate mOS scheduler on LWK CPUs */
	ret = mos_sched_activate(p->lwkcpus);

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
int lwkctrl_partition_destroy(struct lwkctrl_partition *p)
{
	cpumask_var_t lwkcpus_shutdown;
	cpumask_var_t lwkcpus_up;
	int irq;
	int ret = -1;

	if (!p)
		return -1;

	if (!zalloc_cpumask_var(&lwkcpus_shutdown, GFP_KERNEL) ||
	    !zalloc_cpumask_var(&lwkcpus_up, GFP_KERNEL)) {
		pr_warn("%s: Failed to allocate cpumasks.\n", __func__);
		return -1;
	}

	/* Deactivate mOS scheduler on LWK CPUs */
	ret = mos_sched_deactivate(p->lwkcpus);

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
	ret = lwkcpu_down_multiple(p->lwkcpus, lwkcpus_shutdown);

	if (ret) {
		if (!cpumask_equal(p->lwkcpus, lwkcpus_shutdown)) {
			cpumask_andnot(lwkcpus_up, p->lwkcpus,
				       lwkcpus_shutdown);
			pr_warn("%s: (!) Failed to shutdown %*pbl\n",
				__func__, cpumask_pr_args(lwkcpus_up));
		}
		goto error;
	}

	/* Exit mOS scheduler */
	ret = mos_sched_exit();

	if (ret) {
		pr_err("%s: Failed to initialize mOS scheduler\n", __func__);
		goto error;
	}

error:
	free_cpumask_var(lwkcpus_shutdown);
	free_cpumask_var(lwkcpus_up);
	return ret;
}

/*
 * Creates a default LWK partition as specified by the boot command line.
 * This function is called from init/main.c to trigger default partition
 * creation during kernel bootup.
 */
void lwkctl_def_partition(void)
{
	int rc = -1;

	if (!cpumask_empty(mos_lwkcpus_arg)) {
		pr_info("mOS: LWK creating default partition\n");
		/* Create default LWK partition */
		rc = lwk_config_lwkcpus(lwkctrl_cpus_spec,
					lwkctrl_cpu_profile_spec);
		pr_info("mOS: LWK creating default partition.. %s\n",
			rc ? "Failed!" : "Done");
	}

	if (rc) {
		/* If there wasn't a default boot partition even then
		 * we would like to clear the default settings
		 */
		lwkcpu_state_deinit();
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
	int rc = 0;
	int strsize;

	/*
	 * More work here when we support dynamic memory configuration.
	 * This mimimum level of support is to allow reading of the
	 * configuration via the mOS file lwkconfig.
	 */
	strsize = snprintf(lwkctrl_mem_spec, LWKCTRL_MEM_SPECSZ, "%s", str);
	if (strlen(str) > strsize)
		pr_warn("mOS: lwkmem specification string truncation occurred in %s.\n",
				__func__);
	return rc;
}
early_param("lwkmem", lwkmem);
