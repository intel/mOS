/*
 * Multi Operating System (mOS)
 * Copyright (c) 2016-2020, Intel Corporation.
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
#include <linux/mutex.h>
#include <linux/mos.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include "lwkcpu.h"
#include "lwkctrl.h"
#undef pr_fmt
#define pr_fmt(fmt)	"mOS: " fmt

extern int mos_sched_mark_cpu(int);

/*
 * A set of CPU hotplug states that are to be filtered while bringing
 * up an LWKCPU to ensure low OS noise on those CPUs.
 */
enum cpuhp_state filter[] = LWKCPU_FILTER_STATES;

static int linuxcpu_up(unsigned int cpu)
{
	if (cpu_islwkcpu(cpu)) {
		pr_err("%s: (!) CPU %d is in LWK partition\n", __func__, cpu);
		return -EINVAL;
	}
	return do_cpu_up(cpu, CPUHP_ONLINE);
}

/*
 * Boot an LWK cpu through a set of CPU hotplug states which are optimal
 * for an LWK use.
 *
 * @cpu,    CPU number to be booted
 * @return, 0 on success
 *          -ve value on failure
 */
int lwkcpu_up(unsigned int cpu)
{
	int rc = do_cpu_up(cpu, LWKCPU_MAX_STATE);

	if (rc)
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to online CPU %d.", __func__, cpu);
	return rc;
}

/*
 * Shutdown an LWK cpu to LWKCPU_MIN_STATE so that it can
 * be handed over to Linux for its use
 *
 * @cpu,    CPU number to be shutdown
 * @return, 0 on success
 *          -ve value on failure
 */
int lwkcpu_down(unsigned int cpu)
{
	int rc = do_cpu_down(cpu, LWKCPU_MIN_STATE);

	if (rc)
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to offline CPU %d.", __func__, cpu);
	return rc;
}

/*
 * Offline one CPU and mark it for mOS scheduler
 *
 * @cpu,    CPU number to be offlined
 * @return, 0 on success
 *          -ve value on failure
 */
int lwkcpu_offline_and_mark(int cpu)
{
	int ret;

	/* Clear target CPU from LWK CPU mask while offlining */
	cpumask_clear_cpu(cpu, per_cpu_ptr(&lwkcpus_mask, cpu));

	/* Offline CPU */
	ret = do_cpu_down(cpu, CPUHP_OFFLINE);
	if (ret) {
		mos_ras(MOS_LWKCTL_FAILURE,
				"%s: Failed to offline CPU %d.", __func__, cpu);
		return ret;
	}

	/* Mark for LWK scheduler */
	ret = mos_sched_mark_cpu(cpu);
	if (ret < 0) {
		mos_ras(MOS_LWKCTL_FAILURE,
				"%s: Failed to mark CPU %d as LWK.", __func__, cpu);
		return ret;
	}

	/* Restore LWK CPU mask */
	cpumask_set_cpu(cpu, per_cpu_ptr(&lwkcpus_mask, cpu));

	return 0;
}

/*
 * Boot multiple LWK CPUs
 *
 * @request, cpumask of cpus which needs to be booted
 * @booted,  cpumask of cpus which are booted in this call
 * @return,  0 on success
 *           -ve value on failure
 */
int lwkcpu_up_multiple(cpumask_var_t request, cpumask_var_t booted)
{
	int cpu;
	int ret;
	cpumask_var_t offlined; /* CPUs that have been offlined */
	cpumask_var_t siblings;

	if (!booted) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: booted cpumask is required", __func__);
		return -EINVAL;
	}

	if (!zalloc_cpumask_var(&offlined, GFP_KERNEL)) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to allocate offlined cpumask!", __func__);
		return -ENOMEM;
	}

	if (!zalloc_cpumask_var(&siblings, GFP_KERNEL)) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to allocate siblings cpumask!", __func__);
		ret = -ENOMEM;
		goto out_free_offlined;
	}

	/* We clear the o/p mask irrespective of the return status */
	cpumask_clear(booted);

	if (!request) {
		mos_ras(MOS_LWKCTL_FAILURE, "%s: Invalid argument.", __func__);
		ret = -EINVAL;
		goto out;
	}

	for_each_cpu(cpu, request) {
		int s_cpu;

		cpumask_clear(siblings);
		if (cpumask_test_cpu(cpu, booted)) {
			continue;
		}

		/* Offline CPU here if requested and not yet offlined */
		if (!cpumask_test_cpu(cpu, offlined)) {
			int s_cpu;

			cpumask_copy(siblings, topology_sibling_cpumask(cpu));

			ret = lwkcpu_offline_and_mark(cpu);
			if (ret) {
				/* TODO: error handling! */
				goto out;
			}

			/* This CPU has been offlined */
			cpumask_set_cpu(cpu, offlined);

			/* Offline and mark siblings as well */
			for_each_cpu(s_cpu, siblings) {
				if (cpumask_test_cpu(s_cpu, offlined) ||
					!cpumask_test_cpu(s_cpu, request))
					continue;

				ret = lwkcpu_offline_and_mark(s_cpu);
				if (ret) {
					/* TODO: error handling! */
					goto out;
				}

				/* This CPU has been offlined */
				cpumask_set_cpu(s_cpu, offlined);
			}
		}

		ret = lwkcpu_up(cpu);
		if (ret)
			goto out;

		cpumask_set_cpu(cpu, booted);

		/* Bring up siblings as well when inline offlining */
		for_each_cpu(s_cpu, siblings) {
			if (cpumask_test_cpu(s_cpu, booted) ||
				!cpumask_test_cpu(s_cpu, request))
				continue;

			ret = lwkcpu_up(s_cpu);
			if (ret)
				goto out;

			cpumask_set_cpu(s_cpu, booted);
		}
	}

	ret = 0;

out:
	free_cpumask_var(siblings);
out_free_offlined:
	free_cpumask_var(offlined);
	return ret;
}

/*
 * Shutdown multiple LWK CPUs
 *
 * @request, cpumask of cpus which needs to be shutdown
 * @booted,  cpumask of cpus which are shutdown in this call
 * @return,  0 on success
 *           -ve value on failure
 */
int lwkcpu_down_multiple(cpumask_var_t request, cpumask_var_t shutdown)
{
	int cpu;
	int ret;

	/* We clear the o/p mask irrespective of the return status */
	if (!shutdown) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: shutdown cpumask is required", __func__);
		return -EINVAL;
	}

	cpumask_clear(shutdown);

	if (!request) {
		mos_ras(MOS_LWKCTL_FAILURE, "%s: Invalid argument.", __func__);
		return -EINVAL;
	}

	for_each_cpu(cpu, request) {
		ret = lwkcpu_down(cpu);
		if (ret) {
			goto out;
		}

		/* Online CPU here if requested and not yet done */
		if (!cpumask_test_cpu(cpu, shutdown)) {
			/* Clear target CPU from LWK CPU mask while onlining */
			cpumask_clear_cpu(cpu, per_cpu_ptr(&lwkcpus_mask, cpu));
			cpumask_clear_cpu(cpu, per_cpu_ptr(&lwkcpus_mask, smp_processor_id()));

			ret = linuxcpu_up(cpu);
			if (ret) {
				goto out;
			}

			/* Restore LWK CPU mask */
			cpumask_set_cpu(cpu, per_cpu_ptr(&lwkcpus_mask, cpu));
			cpumask_set_cpu(cpu, per_cpu_ptr(&lwkcpus_mask, smp_processor_id()));
		}

		cpumask_set_cpu(cpu, shutdown);
	}

	ret = 0;

out:
	return ret;
}

/*
 * Reset an LWK cpu by bringing it down and rebooting it through CPU hotplug
 * states optimal for an LWK use
 *
 * @cpu,    CPU number to be reset
 * @return, 0 on success
 *          -ve value on failure
 */
int lwkcpu_reset(unsigned int cpu)
{
	int ret;

	ret = lwkcpu_down(cpu);
	return ret ? ret : lwkcpu_up(cpu);
}

/*
 * Mark LWK CPU hotplug states in Linux's CPU hotplug state list
 * @profile, string that specifies a profile which corresponds to
 *           certain degree of CPU hotplug state filtering.
 *
 * @return, 0 on success
 * 	    -ve on failure
 *
 */
int lwkcpu_state_init(char *profile)
{
	int s, n_states, strsize;

	if (strcmp(profile, LWKCPU_PROF_NOR) &&
	    strcmp(profile, LWKCPU_PROF_DBG)) {
		mos_ras(MOS_LWKCTL_WARNING,
			"%s: Invalid lwkcpu_profile specification: %s",
			__func__, profile);
		return -1;
	}

	for (s = LWKCPU_MIN_STATE; s <= LWKCPU_MAX_STATE; s++)
		lwkcpu_set_state(s, true);

	if (strcmp(profile, LWKCPU_PROF_DBG)) {
		n_states = sizeof(filter)/sizeof(enum cpuhp_state);

		for (s = 0; s < n_states; s++)
			lwkcpu_set_state(filter[s], false);
	}

	strsize = snprintf(lwkctrl_cpu_profile_spec,
			   LWKCTRL_CPU_PROFILE_SPECSZ, "%s", profile);
	if (strlen(profile) > strsize) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: lwkcpu_profile specification truncation occurred: \"%s\"",
			__func__, lwkctrl_cpu_profile_spec);
	} else
		pr_info("LWK CPU profile set to: %s\n",
			lwkctrl_cpu_profile_spec);
	return 0;
}

/*
 * Clear the LWK CPU hotplug state filtering setup by lwkcpu_state_init()
 */
void lwkcpu_state_deinit(void)
{
	int s;

	/* Clear LWKCPU state filtering configurations. */
	for (s = LWKCPU_MIN_STATE; s <= LWKCPU_MAX_STATE; s++)
		lwkcpu_set_state(s, false);

	/* Clear LWKCPU profile spec */
	strcpy(lwkctrl_cpu_profile_spec, "");
}
