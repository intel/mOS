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
#include <linux/mutex.h>
#include <linux/mos.h>
#include <linux/slab.h>
#include "lwkcpu.h"
#include "lwkctrl.h"
#undef pr_fmt
#define pr_fmt(fmt)	"mOS: " fmt


static	cpumask_t to;
static	cpumask_t from;
/*
 * A set of CPU hotplug states that are to be filtered while bringing
 * up an LWKCPU to ensure low OS noise on those CPUs.
 */
enum cpuhp_state filter[] = LWKCPU_FILTER_STATES;

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
	return do_cpu_up(cpu, LWKCPU_MAX_STATE);
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
	return do_cpu_down(cpu, LWKCPU_MIN_STATE);
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

	if (!request) {
		mos_ras(MOS_LWKCTL_FAILURE, "%s: Invalid argument.", __func__);
		return -1;
	}

	if (booted)
		cpumask_clear(booted);

	for_each_cpu(cpu, request) {
		ret = lwkcpu_up(cpu);
		if (ret) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: Failed to boot CPU %d.", __func__, cpu);
			return ret;
		}

		if (booted)
			cpumask_set_cpu(cpu, booted);
	}
	return 0;
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

	if (!request) {
		mos_ras(MOS_LWKCTL_FAILURE, "%s: Invalid argument.", __func__);
		return -1;
	}

	if (shutdown)
		cpumask_clear(shutdown);

	for_each_cpu(cpu, request) {
		ret = lwkcpu_down(cpu);
		if (ret) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: Failed to shutdown CPU %d.",
				__func__, cpu);
			return ret;
		}
		if (shutdown)
			cpumask_set_cpu(cpu, shutdown);
	}
	return 0;
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

	if (ret) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to shut down CPU %d.",
			__func__, cpu);
		goto error;
	}

	ret = lwkcpu_up(cpu);

	if (ret) {
		mos_ras(MOS_LWKCTL_FAILURE,
			"%s: Failed to boot CPU %d.",
			__func__, cpu);
	}

error:
	return ret;
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
 */
int lwkcpu_parse_args(char *arg, cpumask_t *lwkcpus,
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
			/* No syscall target defined */
			s_from = s_to;
			s_to = strchr(s_to, '\0');
		} else
			*(s_from++) = '\0';
		if (cpulist_parse(s_to, &to) < 0) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: Invalid character in CPU specification. Value=%s",
				__func__, s_to);
			goto out;
		}
		if (cpulist_parse(s_from, &from) < 0) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: Invalid character in CPU specification. Value=%s.",
				__func__, s_from);
			goto out;
		}
		/* Maximum of one utility CPU allowed per LWK CPU range */
		if ((cpumask_weight(&to) > 1) && !cpumask_empty(&from)) {
			mos_ras(MOS_LWKCTL_FAILURE,
				"%s: More than one utility CPU was specified.",
				__func__);
				goto out;
		}
		cpumask_or(utility_cpus, utility_cpus, &to);
		cpumask_or(lwkcpus, lwkcpus, &from);
	}
	rc = 0;
out:
	return rc;
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
		mos_ras(MOS_LWKCTL_FAILURE,
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
		mos_ras(MOS_LWKCTL_WARNING,
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
