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

/*
 *  kernel/sched/mos.c
 *
 * When executing on a CPU that has been designated to be an LWK CPU, all tasks
 * are managed by the mOS scheduler. However, the tasks within the mOS
 * scheduler must occasionally interact with the Linux scheduler. For
 * example, a Linux/mOS task may be blocked on a mutex held by a mOS/Linux task
 * and will need to be awakened when the resource is released. Also when an
 * mOS process is executing on an Linux core due to evanescence, this task must
 * obey the rules of the linux scheduler. This file contains the mOS scheduler
 * and the mos scheduler class that allow the the two schedulers to
 * interoperate.
*/

#include "sched.h"
#include "mos.h"

#include <stdarg.h>
#include <linux/ftrace.h>
#include <linux/compiler.h>
#include <linux/hrtimer.h>
#include <linux/cpumask.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/vtime.h>
#include <linux/tick.h>
#include <linux/cacheinfo.h>
#include <linux/topology.h>
#include <linux/mos.h>
#include <uapi/linux/mos.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <asm/types.h>
#include <asm/mce.h>
#include <asm/cpu_device_id.h>
#include <asm/intel-family.h>
#include <asm/mwait.h>
#include <asm/msr.h>
#include <uapi/linux/sched/types.h>


#define CREATE_TRACE_POINTS
#include <trace/events/lwksched.h>
#include <trace/events/lwkwake.h>

/*
 * Default timeslice is 100 msecs. Used when an mOS task has been enabled for
 * timeslicing.
 */
#define MOS_TIMESLICE		(100 * HZ / 1000)
#define COMMIT_MAX		INT_MAX		/* Max limit */

/* NICE values to be used for utility threads running in the Linux scheduler */
#define MOS_NICE_HIGH_PRIOR -20
#define MOS_NICE_LOW_PRIOR 19
#define MOS_NICE_DEFAULT -10

#define CMCI_THRESHOLD_MAX	32767
#define COMMIT_WARNING_THRESHOLD 1000

/* Maximum supported number of active utility thread groups */
#define UTIL_GROUP_LIMIT   4

#define PLACEMENT_SAMEDIFF     (MOS_CLONE_ATTR_SAME_L1CACHE | \
				MOS_CLONE_ATTR_SAME_L2CACHE | \
				MOS_CLONE_ATTR_SAME_L3CACHE | \
				MOS_CLONE_ATTR_DIFF_L1CACHE | \
				MOS_CLONE_ATTR_DIFF_L2CACHE | \
				MOS_CLONE_ATTR_DIFF_L3CACHE | \
				MOS_CLONE_ATTR_SAME_DOMAIN | \
				MOS_CLONE_ATTR_DIFF_DOMAIN)
#define PLACEMENT_CONFLICTS (PLACEMENT_SAMEDIFF | MOS_CLONE_ATTR_USE_NODE_SET)

enum SearchOrder {ForwardSearch = 0,
		  ReverseSearch,
};

enum CpusAllowedPerUtilThread {
	AllowMultipleCpusPerUtilThread = 0,
	AllowOnlyOneCpuPerUtilThread,
};

/* Balancer */
#define BALANCER_PULL_DEFAULT_PARM1 100 /* idle timer tick frequency X ms */
#define BALANCER_PULL_DEFAULT_PARM2  20 /* overcommit threshold X ms */
#define BALANCER_PULL_DEFAULT_PARM3   0 /* idle time (us) before first pull action */
#define BALANCER_PUSH_DEFAULT_PARM1  12 /* consider if target cpu load < (cpu load/(2**x)) */
#define BALANCER_PUSH_DEFAULT_PARM2  20 /* consider if overcommit > X ms */
#define BALANCER_PUSH_DEFAULT_PARM3  10 /* ms before allowing another push */
enum BalancerType {
	BalancerType_None = 0,
	BalancerType_Pull,
	BalancerType_Push,
};

static cpumask_var_t saved_wq_mask;

raw_spinlock_t util_grp_lock;

static struct util_group {
	struct {
		long int key;
		int refcount;
		struct mos_topology topology;
	} entry[UTIL_GROUP_LIMIT];
} util_grp;

static unsigned int shallow_sleep_mwait;
static unsigned int deep_sleep_mwait;
static bool mwait_supported;
static bool mwait_deep_sleep_tlbs_flushed;
#define MWAIT_HINT(x) (x & 0xff)

enum Idle_Control {
	Idle_Mechanism_MWAIT,	/* Use mwait in when idle */
	Idle_Mechanism_HALT,	/* Use halt when not requesting deep sleep */
	Idle_Mechanism_POLL,	/* Use polling when not requesting deep sleep */
	Idle_Boundary_NONE,	/* Idle CPUs will request to enter deep sleep */
	Idle_Boundary_COMMITTED,/* Committed CPUs will not enter deep sleep */
	Idle_Boundary_RESERVED,	/* Reserved CPUs will not enter deep sleep */
	Idle_Boundary_ONLINE,	/* Online CPUs will not enter deep sleep */
};

static void set_cpus_allowed_mos(struct task_struct *p,
				const struct cpumask *new_mask);

static inline struct task_struct *mos_task_of(struct sched_mos_entity *mos_se)
{
	return container_of(mos_se, struct task_struct, mos);
}

static inline struct rq *rq_of_mos_rq(struct mos_rq *mosrq)
{
	return container_of(mosrq, struct rq, mos);
}

static inline struct mos_rq *mos_rq_of_rq(struct rq *rq)
{
	return &rq->mos;
}

static void sched_stats_init(struct mos_sched_stats *stats)
{
	memset(stats, 0, sizeof(struct mos_sched_stats));
}

static inline bool acceptable_behavior(unsigned int b)
{
	if ((b == 0) ||
	    (b & MOS_CLONE_ATTR_EXCL) ||
	    (b & MOS_CLONE_ATTR_HCPU) ||
	    (b & MOS_CLONE_ATTR_HPRIO) ||
	    (b & MOS_CLONE_ATTR_LPRIO) ||
	    (b & MOS_CLONE_ATTR_NON_COOP))
		return true;
	return false;
}

static inline bool location_match(enum mos_match_cpu t, int i,
				struct mos_rq *q, nodemask_t *n)
{
	if ((t == mos_match_cpu_FirstAvail) ||
	    (t == mos_match_cpu_SameDomain && i == q->topology.numa_id) ||
	    (t == mos_match_cpu_SameCore && i == q->topology.core_id) ||
	    (t == mos_match_cpu_SameL1 && i == q->topology.l1c_id) ||
	    (t == mos_match_cpu_SameL2 && i == q->topology.l2c_id) ||
	    (t == mos_match_cpu_SameL3 && i == q->topology.l3c_id) ||
	    (t == mos_match_cpu_OtherDomain && i != q->topology.numa_id) ||
	    (t == mos_match_cpu_OtherCore && i != q->topology.core_id) ||
	    (t == mos_match_cpu_OtherL1 && i != q->topology.l1c_id) ||
	    (t == mos_match_cpu_OtherL2 && i != q->topology.l2c_id) ||
	    (t == mos_match_cpu_OtherL3 && i != q->topology.l3c_id) ||
	    (t == mos_match_cpu_InNMask &&
					node_isset(q->topology.numa_id, *n)))
		return true;
	return false;
}

static void sched_stats_prepare_launch(struct mos_sched_stats *stats)
{
	/* leave stats->guests unchanged */
	/* leave stats->givebacks unchanged */
	stats->pid = 0;
	stats->max_compute_level = 0;
	stats->max_util_level = 0;
	stats->max_running = 0;
	stats->guest_dispatch = 0;
	stats->timer_pop = 0;
	stats->sysc_migr = 0;
	stats->setaffinity = 0;
	stats->pushed = 0;
	stats->balance_to = 0;
	stats->balance_from = 0;
}


static void probe_mwait_capabilities(void)
{
	unsigned int eax, ebx, ecx;
	unsigned int mwait_substates, num_substates, mwait_cstate_hint;
	bool found_first = false;

	shallow_sleep_mwait = 0;
	deep_sleep_mwait = 0;

	cpuid(CPUID_MWAIT_LEAF, &eax, &ebx, &ecx, &mwait_substates);

	if (!(ecx & CPUID5_ECX_EXTENSIONS_SUPPORTED) ||
	    !(ecx & CPUID5_ECX_INTERRUPT_BREAK) ||
	    !mwait_substates) {
		pr_info(
		    "mOS: MWAIT not supported by processor. IDLE HALT enabled.");
		return;
	}
	/*
	 * Find the most shallow and the deepest CSTATE supported by the MWAIT
	 * extensions in the current processor
	 */
	for (mwait_cstate_hint = 0; mwait_cstate_hint < 7;
	      mwait_cstate_hint++) {
		num_substates =
			(mwait_substates >> ((mwait_cstate_hint + 1) * 4)) &
			MWAIT_SUBSTATE_MASK;
		if (num_substates) {
			if (!found_first) {
				found_first = true;
				mwait_supported = true;
				shallow_sleep_mwait = (mwait_cstate_hint << 4);
			}
			deep_sleep_mwait = (mwait_cstate_hint << 4) |
					   (num_substates - 1);
			if (mwait_cstate_hint > 0)
				mwait_deep_sleep_tlbs_flushed = true;
		}
	}
	if (mwait_supported) {

		pr_info(
		    "mOS-sched: IDLE MWAIT enabled. Hints min/max=%08x/%08x. CPUID_MWAIT substates=%08x\n",
		    shallow_sleep_mwait, deep_sleep_mwait, mwait_substates);
	} else
		pr_info("mOS-sched: IDLE HALT enabled. Not using MWAIT\n");
	trace_mos_mwait_cstates_configured(shallow_sleep_mwait,
					   deep_sleep_mwait, ecx,
					   mwait_substates);
}

static void init_mos_topology(struct rq *rq)
{
	struct cpu_cacheinfo *cci;
	struct cacheinfo *ci;
	int i;
	int cpu;
	struct mos_rq *mos_rq = &rq->mos;

	mos_rq->topology.core_id = -1;
	mos_rq->topology.l1c_id = -1;
	mos_rq->topology.l2c_id = -1;
	mos_rq->topology.l3c_id = -1;
	mos_rq->topology.tindex = -1;

	/* Get the numa node identifier associated with this CPU */
	mos_rq->topology.numa_id = cpu_to_node(rq->cpu);

	cpu = cpumask_first(topology_sibling_cpumask(rq->cpu));
	if (cpu < nr_cpu_ids) {
		/*
		 * Generate a unique core identifier value equal to the first
		 * CPUID in the list of CPUs associated with this core.
		 */
		mos_rq->topology.core_id = cpu;

		/* Generate a hyperthread index value for this CPU */
		for (i = 0; cpu != rq->cpu; i++)
			cpu = cpumask_next(cpu,
				topology_sibling_cpumask(rq->cpu));
		mos_rq->topology.tindex = i;
	}
	/*
	 * Get the cache boundary information. When running on KNL
	 * the L2 id will identify the tile boundary. Set the unique
	 * identifier to the first CPUID in the list of CPUs associated
	 * with the corresponding cache level.
	 */
	cci = get_cpu_cacheinfo(rq->cpu);
	if (cci) {
		for (i = 0; i < cci->num_leaves; i++) {
			ci = cci->info_list + i;
			if (ci->level == 1)
				mos_rq->topology.l1c_id =
					cpumask_first(&ci->shared_cpu_map);
			else if (ci->level == 2)
				mos_rq->topology.l2c_id =
					cpumask_first(&ci->shared_cpu_map);
			else if (ci->level == 3)
				mos_rq->topology.l3c_id =
					cpumask_first(&ci->shared_cpu_map);
		}
	}
}

static void init_mos_rq(struct rq *rq)
{
	struct mos_prio_array *array;
	int i;
	struct mos_rq *mos_rq = &rq->mos;

	array = &mos_rq->active;
	for (i = 0; i <= MOS_RQ_MAX_INDEX; i++) {
		INIT_LIST_HEAD(array->queue + i);
		__clear_bit(i, array->bitmap);
	}
	/* Delimiter for bitsearch: */
	__set_bit(MOS_RQ_MAX_INDEX+1, array->bitmap);

	raw_spin_lock_init(&mos_rq->lock);
	mos_rq->mos_nr_running = 0;
	mos_rq->rr_nr_running = 0;
	mos_rq->mos_runtime = 0;
	mos_rq->tstamp_exit_idle = 0;
	mos_rq->tstamp_overcommitted = 0;
	mos_rq->idle_pid = 0;
	mos_rq->idle = NULL;
	mos_rq->utility_commits = 0;
	mos_rq->compute_commits = 0;
	mos_rq->owner = NULL;
	mos_rq->balancer = BalancerType_None;
	mos_rq->balancer_parm1 = 0;
	mos_rq->balancer_parm2 = 0;
	mos_rq->balancer_parm3 = 0;
	atomic_set(&mos_rq->exclusive_pid, 0);
	/* Initialize mwait flags based on our processor capabilities */
	mos_rq->mwait_supported = mwait_supported;
	mos_rq->deep_sleep_mwait = deep_sleep_mwait;
	mos_rq->shallow_sleep_mwait = shallow_sleep_mwait;
	mos_rq->idle_mechanism = mwait_supported ? Idle_Mechanism_MWAIT :
						   Idle_Mechanism_HALT;
	mos_rq->idle_boundary = Idle_Boundary_RESERVED;
	if (!zalloc_cpumask_var(&mos_rq->reserved_cpus, GFP_KERNEL)) {
		mos_ras(MOS_SCHEDULER_WARNING,
			"%s: Failed to allocate CPU mask.", __func__);
	}
	sched_stats_init(&mos_rq->stats);
}

static inline int on_mos_rq(struct sched_mos_entity *mos_se)
{
	return !list_empty(&mos_se->run_list);
}

static inline void read_commits(struct mos_rq *mos_rq, int *compute_commits,
				int *util_commits)
{
	raw_spin_lock(&mos_rq->lock);
	*util_commits = mos_rq->utility_commits;
	*compute_commits = mos_rq->compute_commits;
	raw_spin_unlock(&mos_rq->lock);
}

static void uncommit_cpu(struct task_struct *p)
{
	struct mos_rq *mos_rq;
	int cpu = p->mos.cpu_home;
	int underflow = 0;
	unsigned long flags;

	if (cpu < 0)
		return;
	mos_rq = &cpu_rq(cpu)->mos;
	p->mos.cpu_home = -1;

	raw_spin_lock_irqsave(&mos_rq->lock, flags);
	if (p->mos.thread_type == mos_thread_type_normal) {
		if (mos_rq->compute_commits > 0)
			mos_rq->compute_commits--;
		else
			underflow = 1;
	}
	if (p->mos.thread_type == mos_thread_type_utility) {
		if (mos_rq->utility_commits > 0)
			mos_rq->utility_commits--;
		else
			underflow = 1;
	}
	raw_spin_unlock_irqrestore(&mos_rq->lock, flags);

	trace_mos_cpu_uncommit(p, cpu, mos_rq->compute_commits,
				mos_rq->utility_commits, underflow);
}

static void commit_cpu(struct task_struct *p, int cpu)
{
	struct mos_rq *mos_rq;
	unsigned int newval = 0;
	int overflow = 0;
	unsigned long flags;

	if (cpu < 0)
		return;
	mos_rq = &cpu_rq(cpu)->mos;
	raw_spin_lock_irqsave(&mos_rq->lock, flags);
	if (p->mos.thread_type == mos_thread_type_normal) {
		if (mos_rq->compute_commits < INT_MAX) {
			newval = ++mos_rq->compute_commits;
			if (newval > mos_rq->stats.max_compute_level)
				mos_rq->stats.max_compute_level = newval;
		} else
			overflow = 1;
	} else if (p->mos.thread_type == mos_thread_type_utility) {
		if (mos_rq->utility_commits < INT_MAX) {
			newval = ++mos_rq->utility_commits;
			if (newval > mos_rq->stats.max_util_level)
				mos_rq->stats.max_util_level = newval;
		} else
			overflow = 1;
	}
	p->mos.cpu_home = cpu;
	raw_spin_unlock_irqrestore(&mos_rq->lock, flags);
	trace_mos_cpu_commit(p, cpu, mos_rq->compute_commits,
			     mos_rq->utility_commits, overflow);
}

static int is_overcommitted(int cpu)
{
	int compute_commit;
	int util_commit;
	struct mos_rq *mos_rq = &(cpu_rq(cpu)->mos);

	read_commits(mos_rq, &compute_commit, &util_commit);

	if ((compute_commit + util_commit) > 1)
		return 1;
	return 0;
}

static inline void match_adjust(struct mos_rq *rq,
					enum mos_match_cpu *mtype, int *id,
					bool first_keyed)
{
	if (first_keyed) {
		switch (*mtype) {
		case mos_match_cpu_SameDomain:
			*id = rq->topology.numa_id;
			break;
		case mos_match_cpu_SameL3:
			*id = rq->topology.l3c_id;
			break;
		case mos_match_cpu_SameL2:
			*id = rq->topology.l2c_id;
			break;
		case mos_match_cpu_SameL1:
			*id = rq->topology.l1c_id;
			break;
		case mos_match_cpu_SameCore:
			*id = rq->topology.core_id;
			break;
		default:
			break;
		}
	}
	switch (*mtype) {
	case mos_match_cpu_OtherDomain:
		*mtype = mos_match_cpu_SameDomain;
		*id = rq->topology.numa_id;
		break;
	case mos_match_cpu_OtherL3:
		*mtype = mos_match_cpu_SameL3;
		*id = rq->topology.l3c_id;
		break;
	case mos_match_cpu_OtherL2:
		*mtype = mos_match_cpu_SameL2;
		*id = rq->topology.l2c_id;
		break;
	case mos_match_cpu_OtherL1:
		*mtype = mos_match_cpu_SameL1;
		*id = rq->topology.l1c_id;
		break;
	case mos_match_cpu_OtherCore:
		*mtype = mos_match_cpu_SameCore;
		*id = rq->topology.core_id;
		break;
	default:
		break;
	}
}

static int select_linux_utility_cpus(struct task_struct *p,
				     enum mos_match_cpu mtype,
				     int id, nodemask_t *node_mask,
				     cpumask_t *cpus,
				     bool first_keyed)
{
	int util_cpu;
	struct mos_process_t *mosp = p->mos_process;

	cpumask_clear(cpus);
	/* Are we configured to find all matching CPUs or just the
	 * the lowest committed single CPU?
	 */
	if (mosp->allowed_cpus_per_util == AllowOnlyOneCpuPerUtilThread) {
		int commit;

		/* Look for a matching CPU at the lowest commit level */
		for (commit = 0; commit < COMMIT_MAX; commit++) {
			int match = 0;
			int candidate_found = 0;
			int util_cpu;
			enum mos_match_cpu mt = first_keyed ?
					mos_match_cpu_FirstAvail : mtype;

			for_each_cpu(util_cpu, mosp->utilcpus) {
				struct mos_rq *mos_rq = &cpu_rq(util_cpu)->mos;

				if (!location_match(mt, id, mos_rq, node_mask))
					continue;
				match  = 1;
				if (mos_rq->utility_commits == commit) {
					cpumask_set_cpu(util_cpu, cpus);
					candidate_found = 1;
					break;
				}
			}
			if (!match || candidate_found)
				/* Break the commit level loop. If we didn't
				 * match the first pass, we will not match
				 * at any commit level. If we found a candidate,
				 * we were successful.
				 */
				break;
		}
	} else {
		/* Find all matching CPUs */
		bool adjusted = 0;

		for_each_cpu(util_cpu, p->mos_process->utilcpus) {
			struct mos_rq *mos_rq = &cpu_rq(util_cpu)->mos;

			if (location_match(first_keyed ?
					mos_match_cpu_FirstAvail : mtype,
					id, mos_rq, node_mask)) {
				cpumask_set_cpu(util_cpu, cpus);


				/* Adjust match conditions for the remaining
				 * CPUs to be selected within this thread.
				 */
				if (!adjusted) {
					match_adjust(mos_rq, &mtype, &id,
							first_keyed);
					adjusted = 1;
				}
			}
			if (first_keyed)
				first_keyed = 0;
		}
	}
	/*  If no cpus set, returns >= nr_cpu_ids */
	return cpumask_first(cpus);
}

/*
 * Attempt to find a CPU within the commit level limit and affinity
 * matching requested.
 */
static int _select_cpu_candidate(struct task_struct *p,
				int commit_level_limit,
				enum SearchOrder search_order,
				enum mos_match_cpu matchtype,
				int id,
				nodemask_t *nodemask,
				int range,
				enum mos_commit_cpu_scope commit_type,
				pid_t exclusive)
{
	int commitment;
	int *cpu_list = p->mos_process->lwkcpus_sequence;
	int fpath = cpumask_equal(p->cpus_ptr, p->mos_process->lwkcpus);
	int num_slots_to_search = (range < 0) ?
					p->mos_process->num_lwkcpus : range;
	int lastindex = p->mos_process->num_lwkcpus - 1;

	/*
	 * Using the lwkcpus_sequence list in the mos_process object, look for
	 * the least committed CPU starting at one end of the list and
	 * and walking sequentially through it.
	 */
	if (!range)
		goto out;
	for (commitment = 0; commitment <= commit_level_limit; commitment++) {
		int n;
		int match = 0;

		if (commitment == COMMIT_WARNING_THRESHOLD) {
			mos_ras(MOS_SCHEDULER_WARNING,
				"%s: Excessive commit level depth=%d.",
				__func__, commitment);
		}
		for (n = 0; n < num_slots_to_search; n++) {
			struct mos_rq *mos_rq;
			int cpu;
			int excl_pid;

			cpu = ((search_order == ReverseSearch) ?
			       cpu_list[lastindex - n] : cpu_list[n]);
			mos_rq = &cpu_rq(cpu)->mos;
			/* Is CPU occupied by an exclusive thread */
			excl_pid = atomic_read(&mos_rq->exclusive_pid);
			if (excl_pid && (exclusive != excl_pid))
				continue;
			if (!location_match(matchtype, id, mos_rq, nodemask))
				continue;
			match = 1;
			if (fpath ||
			    cpumask_test_cpu(cpu, p->cpus_ptr)) {
				int commits;

				if (commit_type ==
				    mos_commit_cpu_scope_OnlyUtilityCommits)
					commits = mos_rq->utility_commits;
				else if (commit_type ==
					mos_commit_cpu_scope_OnlyComputeCommits)
					commits = mos_rq->compute_commits;
				else {
					int comp_commits;
					int util_commits;

					read_commits(mos_rq, &comp_commits,
							     &util_commits);
					commits = comp_commits + util_commits;
				}
				if (commits <= commitment) {
					int prev_pid = 0;

					if (exclusive) {
						prev_pid = atomic_cmpxchg(
							&mos_rq->exclusive_pid,
							0, p->pid);
					}
					if (!prev_pid || (prev_pid ==
					    exclusive)) {
						trace_mos_cpu_select(p, cpu,
								commit_type,
								commits,
								matchtype,
								id, range,
								exclusive);
						return cpu;
					}
				}
			}
		}
		if (!match)
			goto out;
	}
out:
	/* No CPU is available at the requested commitment range and topology */
	trace_mos_cpu_select_unavail(p, -1, commit_type, commit_level_limit,
				     matchtype, id, range, exclusive);

	return -1;
}

static inline int select_cpu_candidate(struct task_struct *p,
				       int commit_level_limit)
{
	int cpu;

	/* Look for a CPU that has not be committed by
	 * any other thread
	 */
	cpu = _select_cpu_candidate(p, 0, ForwardSearch,
				mos_match_cpu_FirstAvail, 0,
				NULL, -1, mos_commit_cpu_scope_AllCommits, 0);
	if ((cpu >= 0) || (commit_level_limit == 0))
		return cpu;
	/* Unfortunately all CPUs are committed to other threads.
	 * Our next attempt will be to find a CPU that does not have
	 * another compute thread on it. We would rather share a
	 * compute thread with a utility thread than share with another
	 * compute thread
	 */
	cpu = _select_cpu_candidate(p, 0, ForwardSearch,
				mos_match_cpu_FirstAvail, 0, NULL, -1,
				mos_commit_cpu_scope_OnlyComputeCommits, 0);
	if (cpu >= 0)
		return cpu;
	/* If we reached this point, we will be overcommitting compute
	 * CPUs. Find the least committed CPU and return it.
	 */
	return _select_cpu_candidate(p, commit_level_limit, ForwardSearch,
			mos_match_cpu_FirstAvail, 0, NULL, -1,
			mos_commit_cpu_scope_AllCommits, 0);
}


static inline int select_main_thread_home(struct task_struct *p)
{
	int first_cpu;

	if (p->pid != p->tgid)
		return -1;
	first_cpu = p->mos_process->lwkcpus_sequence[0];
	if (cpu_rq(first_cpu)->mos.compute_commits)
		return -1;
	if (!cpumask_test_cpu(first_cpu, p->cpus_ptr))
		return -1;
	trace_mos_select_main_thread_home(p, first_cpu);
	return first_cpu;
}

/* Converts the Linux scheduler priorities into mOS priorities */
static inline int mos_rq_index(int priority)
{
	int qindex;

	/* Test for FIFO/RR range. External:99->1 which is internal 0->98 */
	if (likely((priority >= 0) && (priority < MAX_RT_PRIO-1)))
		/* queue index for rt range */
		qindex = priority;
	/* Test for deadline range */
	else if (priority < 0)
		/* queue index for deadline priority range */
		qindex = MOS_RQ_DL_INDEX;
	/* Test for fair range. External: (-20)->(+19) internal: 100->139 */
	else if ((priority >= MAX_RT_PRIO) && (priority < MAX_PRIO))
		qindex = MOS_RQ_FAIR_INDEX;
	/* Test for mOS idle task. */
	else if (priority == MOS_IDLE_PRIO)
		qindex = MOS_RQ_IDLE_INDEX;
	else {
		/* Unexpected priority value */
		qindex = MOS_RQ_IDLE_INDEX;
		mos_ras(MOS_SCHEDULER_WARNING, "%s: Unexpected priority = 0x%x",
			__func__, priority);
	}
	return qindex;
}

static int nice_for_util_thread(unsigned long behavior)
{
	int nice;

	if (behavior & MOS_CLONE_ATTR_HPRIO)
		nice = MOS_NICE_HIGH_PRIOR;
	else if (behavior & MOS_CLONE_ATTR_LPRIO)
		nice = MOS_NICE_LOW_PRIOR;
	else
		nice = MOS_NICE_DEFAULT;
	return nice;
}

static void move_to_linux_scheduler(struct task_struct *p,
				unsigned long behavior)
{
	p->policy = SCHED_NORMAL;
	p->static_prio = NICE_TO_PRIO(nice_for_util_thread(behavior));
	p->rt_priority = 0;
	p->prio = p->normal_prio = p->static_prio;
	p->se.load.weight =
		sched_prio_to_weight[p->static_prio - MAX_RT_PRIO];
	p->se.load.inv_weight =
		sched_prio_to_wmult[p->static_prio - MAX_RT_PRIO];
	p->sched_class = &fair_sched_class;
}

static void adjust_util_behavior(struct task_struct *p, unsigned long behavior)
{
	/*
	 * If this is a high priority thread, bump
	 * its priority above that of all other mOS
	 * threads. No other lower priority mOS threads will
	 * be allowed to run if this thread is not blocked
	 */
	if (behavior & MOS_CLONE_ATTR_HPRIO) {
		p->prio = MOS_HIGH_PRIO;
		p->normal_prio = MOS_HIGH_PRIO;
	} else if (behavior & MOS_CLONE_ATTR_LPRIO) {
		p->prio = MOS_LOW_PRIO;
		p->normal_prio = MOS_LOW_PRIO;
	}
	/*
	 * If this thread does not play well with others,
	 * forceably time-slice it so it does not starve
	 * the other threads when others are running.
	 */
	if (behavior & MOS_CLONE_ATTR_NON_COOP)
		p->policy = SCHED_RR;
}

static enum mos_match_cpu relax_match(enum mos_match_cpu current_matchtype)
{
	switch (current_matchtype) {
	case mos_match_cpu_SameL1:
		return mos_match_cpu_SameL2;
	case mos_match_cpu_SameL2:
		return mos_match_cpu_SameL3;
	case mos_match_cpu_SameL3:
		return mos_match_cpu_SameDomain;
	case mos_match_cpu_SameDomain:
		return mos_match_cpu_FirstAvail;
	case mos_match_cpu_OtherDomain:
		return mos_match_cpu_OtherL3;
	case mos_match_cpu_OtherL3:
		return mos_match_cpu_OtherL2;
	case mos_match_cpu_OtherL2:
		return mos_match_cpu_OtherL1;
	case mos_match_cpu_OtherL1:
		return mos_match_cpu_FirstAvail;
	default:
		return mos_match_cpu_FirstAvail;
	}
}

static void set_utility_cpus_allowed(struct task_struct *p,
				     int which_thread,
				     struct mos_clone_hints *hints)
{

	cpumask_var_t new_mask;
	int util_cpu, i, cpu_home;
	struct mos_topology *topology;
	struct mos_process_t *proc = p->mos_process;
	int loc_id = -1;
	bool reverse_search = true;
	int allowed_commit_level;
	int range = proc->max_cpus_for_util;
	enum mos_match_cpu matchtype = mos_match_cpu_FirstAvail;
	nodemask_t *node_mask = NULL;
	bool on_linux = 0;
	bool placement_honored = true;
	bool behavior_honored = true;
	bool key_store_pending = false;
	enum mos_commit_cpu_scope commit_type;
	pid_t exclusive_pid = 0;
	bool fwk_requested = (hints->location & MOS_CLONE_ATTR_FWK_CPU) ? 1 : 0;
	bool lwk_requested = (hints->location & MOS_CLONE_ATTR_LWK_CPU) ? 1 : 0;

	if (hints->key) {
		raw_spin_lock(&util_grp_lock);
		/* Search the list */
		for (i = 0, topology = NULL; i < UTIL_GROUP_LIMIT; i++) {
			if (util_grp.entry[i].key == hints->key) {
				util_grp.entry[i].refcount++;
				topology = &util_grp.entry[i].topology;
				p->mos.active_hints.key = hints->key;
				break;
			}
		}
		if (topology) {
			/* An entry in the group was found. Use topology */
			raw_spin_unlock(&util_grp_lock);
		} else {
			key_store_pending = true;
			/* Don't release the location_group_lock yet */
		}
	} else {
		/* Cannot use our current CPU for location matching since
		 * we may be running on a Linux utility CPU (e.g. in clone).
		 * Use the CPU designated as the LWK CPU home for this task.
		 * We should have a valid LWK CPU home. However if it is not
		 * valid, default to the first LWK CPU in the process mask.
		 */
		cpu_home = current->mos.cpu_home;
		if (likely(cpu_home >= 0))
			topology = &(cpu_rq(cpu_home)->mos.topology);
		else {
			topology =
			  &(cpu_rq(cpumask_first(proc->lwkcpus))->mos.topology);
			mos_ras(MOS_SCHEDULER_WARNING,
				"%s: Expected a valid CPU home.", __func__);
		}
	}
	/* We are placing a thread on a Utility CPU */
	if (!zalloc_cpumask_var(&new_mask, GFP_KERNEL)) {
		if (key_store_pending)
			raw_spin_unlock(&util_grp_lock);
		mos_ras(MOS_SCHEDULER_WARNING,
			"%s: CPU mask allocation failure.", __func__);
		return;
	}

	if (hints->location & MOS_CLONE_ATTR_SAME_L1CACHE) {
		matchtype = mos_match_cpu_SameL1;
		loc_id = topology ? topology->l1c_id : -1;
	} else if (hints->location & MOS_CLONE_ATTR_SAME_L2CACHE) {
		matchtype = mos_match_cpu_SameL2;
		loc_id = topology ? topology->l2c_id : -1;
	} else if (hints->location & MOS_CLONE_ATTR_SAME_L3CACHE) {
		matchtype = mos_match_cpu_SameL3;
		loc_id = topology ? topology->l3c_id : -1;
	} else if (hints->location & MOS_CLONE_ATTR_DIFF_L1CACHE) {
		matchtype = mos_match_cpu_OtherL1;
		loc_id = topology ? topology->l1c_id : -1;
	} else if (hints->location & MOS_CLONE_ATTR_DIFF_L2CACHE) {
		matchtype = mos_match_cpu_OtherL2;
		loc_id = topology ? topology->l2c_id : -1;
	} else if (hints->location & MOS_CLONE_ATTR_DIFF_L3CACHE) {
		matchtype = mos_match_cpu_OtherL3;
		loc_id = topology ? topology->l3c_id : -1;
	} else if (hints->location & MOS_CLONE_ATTR_SAME_DOMAIN) {
		matchtype = mos_match_cpu_SameDomain;
		loc_id = topology ? topology->numa_id : -1;
	} else if (hints->location & MOS_CLONE_ATTR_DIFF_DOMAIN) {
		matchtype = mos_match_cpu_OtherDomain;
		loc_id = topology ? topology->numa_id : -1;
	} else if (hints->location & MOS_CLONE_ATTR_USE_NODE_SET) {
		matchtype = mos_match_cpu_InNMask;
		node_mask = &hints->nodes;
	}
	/* If exclusive use of a CPU was requested, do not allow
	 * overcommitment
	 */
	if (hints->behavior & MOS_CLONE_ATTR_EXCL) {
		allowed_commit_level = 0;
		exclusive_pid = p->pid;
	}
	/* If specific placement has been requested relax the
	 * allowed level of overcommitment. We prioritize placement
	 * over commitment level
	 */
	else if (hints->location || proc->max_util_threads_per_cpu < 0)
		allowed_commit_level = COMMIT_MAX;
	/* Respect a threshold value for max threads per CPU */
	else
		allowed_commit_level = proc->max_util_threads_per_cpu - 1;

	/* Set the rules regarding what is considered a committed CPU
	 * when searching for the least committed CPU matching our requested
	 * location. We can look at all types of commits, compute thread
	 * commits, or utility thread commits. If we are to place a thread
	 * exclusively on a CPU, then we will override the commit type to
	 * ensure we find a completely un-committed CPU.
	 */
	commit_type = exclusive_pid ? mos_commit_cpu_scope_AllCommits :
					proc->overcommit_behavior;

	if (fwk_requested && cpumask_empty(proc->utilcpus)) {
		fwk_requested = 0;
		lwk_requested = 1;
		placement_honored = false;
	}
	/*
	 * Try to honor the location request looking at the lwkcpus
	 * and the shared utility pool. If location cannot be
	 * satisfied repeat looking for first available CPU at the
	 * requested level of overcommitment. If we still cannot satisfy
	 * the request, continue to bump up the level of allowed
	 * overcommitment until we have a match. The loop has a
	 * threshold value to prevent us from hanging the kernel due
	 * to some unexpected condition.
	 */
	for (i = 0, util_cpu = -1; i < 100; i++) {
		if (!fwk_requested) {
			/* Search for a CPU, looking for the least committed */
			util_cpu = _select_cpu_candidate(p,
					allowed_commit_level,
					reverse_search,
					key_store_pending ?
						mos_match_cpu_FirstAvail :
						matchtype,
					loc_id,
					node_mask,
					range,
					commit_type,
					exclusive_pid);
			if (util_cpu >= 0) {
				on_linux = 0;
				cpumask_set_cpu(util_cpu, new_mask);
				adjust_util_behavior(p, hints->behavior);
				break;
			}
		}

		if (!lwk_requested) {
			util_cpu = select_linux_utility_cpus(p,
						     matchtype,
						     loc_id,
						     node_mask,
						     new_mask,
						     key_store_pending);
			if ((util_cpu >= 0) && (util_cpu < nr_cpu_ids)) {
				on_linux = 1;
				/*
				 * We will be running this thread on a
				 * Linux CPU with other mos threads and
				 * Linux tasks therefore we must play by
				 * Linux rules. Give the task back to
				 * the Linux scheduler. We will no
				 * longer be in control of the
				 * scheduling of this thread.
				 */

				move_to_linux_scheduler(p,
						hints->behavior);
				break;
			}
		}
		if (unlikely(matchtype == mos_match_cpu_FirstAvail)) {
			/* The only reason we should be here is
			 * if LWK placement is explicitly requested
			 * along with not being able to satisfy the
			 * requested limit on overcommitment. If this
			 * is the case, bump up the allowed level of
			 * overcommitment and take another pass through
			 * the while loop.
			 */
			if (unlikely(!(hints->location &
				       MOS_CLONE_ATTR_LWK_CPU) ||
				     allowed_commit_level ==
				     COMMIT_MAX)) {
				/* We should not be here. FirstAvail is
				 * set and linux cpu assignment is
				 * allowed so we should always be
				 * able to find a CPU for the utility
				 * thread. Break out of this loop.
				 * Warning will be surfaced on exit.
				 */
				util_cpu = -1;
				break;
			}
			/* If the request was for an exclusive CPU, we were
			 * not able to honor it. Indicate that the behavior
			 * operation failed
			 */
			if (exclusive_pid)
				behavior_honored = false;

			/* Bump up the allowed level of overcommitment
			 * and try again
			 */
			allowed_commit_level++;
		} else {
			/*
			 * Relax the type of match we are doing. If we keep
			 * returning here, we will eventually relax the match
			 * type to FirstAvail, which will always end up with a
			 * valid CPU.
			 */
			matchtype = relax_match(matchtype);
			placement_honored = false;
		}
	}

	if (likely((util_cpu >= 0) && (util_cpu < nr_cpu_ids))) {

		int placement_result, behavior_result;

		/* Set the cpus allowed mask for the utility thread */
		set_cpus_allowed_mos(p, new_mask);

		/* Mark this mos thread as a utility thread */
		p->mos.thread_type = mos_thread_type_utility;

		/* If we are responsible for storing the location
		 * key, do it now and release the lock.
		 */
		if (key_store_pending) {
			topology = &(cpu_rq(util_cpu)->mos.topology);
			/* Find an unused slot in the key table. */
			for (i = 0; i < UTIL_GROUP_LIMIT; i++) {
				if (!util_grp.entry[i].key)
					break;
			}
			if (i < UTIL_GROUP_LIMIT) {
				if (util_grp.entry[i].refcount) {
					mos_ras(MOS_SCHEDULER_WARNING,
					 "%s: Unexpected non-zero reference count (%d).",
					  __func__, util_grp.entry[i].refcount);
				}
				util_grp.entry[i].refcount++;
				util_grp.entry[i].key =	hints->key;
				util_grp.entry[i].topology = *topology;
				p->mos.active_hints.key = hints->key;
			} else {
				placement_honored = false;
				mos_ras(MOS_SCHEDULER_WARNING,
				    "%s: No utility thread key slots available.",
				    __func__);
			}
			key_store_pending = false;
			raw_spin_unlock(&util_grp_lock);
		}
		/*
		 * If this is a moveable util thread, chain
		 * onto the list of moveable utilty threads which are
		 * executing on LWK CPUs. Add to the front of the list.
		 * Since the util threads are allocated from the end of
		 * the sequence list, later when a util thread is
		 * selected for pushing, it will push the the utility
		 * thread off of the CPU that was next in the sequence
		 * for the non-util threads, thereby preserving the
		 * desired allocation sequence of the worker threads.
		 */
		if (!on_linux &&
		    !(hints->behavior & MOS_CLONE_ATTR_EXCL) &&
		    !(hints->location) &&
		    !cpumask_empty(proc->utilcpus)) {
			/* Grab the utility list lock */
			mutex_lock(&proc->util_list_lock);

			commit_cpu(p, util_cpu);
			if (p->mos.on_moveable_list)
				mos_ras(MOS_SCHEDULER_WARNING,
				    "%s: Thread is on the moveable list.",
				    __func__);
			else {
				list_add(&p->mos.util_list, &proc->util_list);
				p->mos.on_moveable_list = true;
			}
			/* Unlock the utility list */
			mutex_unlock(&proc->util_list_lock);
		} else
			commit_cpu(p, util_cpu);

		if (placement_honored) {
			p->mos.active_hints.location = hints->location;
			placement_result = MOS_CLONE_PLACEMENT_ACCEPTED;
		} else {
			p->mos.active_hints.location = 0;
			placement_result = MOS_CLONE_PLACEMENT_REJECTED;
		}
		if (acceptable_behavior(hints->behavior) && behavior_honored) {
			p->mos.active_hints.behavior = hints->behavior;
			behavior_result = MOS_CLONE_BEHAVIOR_ACCEPTED;
		} else {
			p->mos.active_hints.behavior = 0;
			behavior_result = MOS_CLONE_BEHAVIOR_REJECTED;
		}
		if (hints->result) {
			put_user(placement_result,
				 &hints->result->placement);
			put_user(behavior_result,
				 &hints->result->behavior);
		}
		trace_mos_util_thread_assigned(util_cpu,
						cpumask_weight(new_mask),
						placement_honored);
	} else {
		if (key_store_pending)
			raw_spin_unlock(&util_grp_lock);
		mos_ras(MOS_SCHEDULER_WARNING,
			"%s: Utility CPU selection failure.", __func__);
	}
	free_cpumask_var(new_mask);
}

static void push_to_linux_scheduler(struct task_struct *p)
{
	struct sched_param param;

	param.sched_priority = 0;
	if (sched_setscheduler_nocheck(p, SCHED_NORMAL, &param))
		mos_ras(MOS_SCHEDULER_WARNING,
		    "%s: Setting scheduler policy/priority failed.", __func__);
	set_user_nice(p, nice_for_util_thread(p->mos.active_hints.behavior));
	if (set_cpus_allowed_ptr(p, p->mos_process->utilcpus))
		mos_ras(MOS_SCHEDULER_WARNING,
		    "%s: Setting allowed CPUs failed.", __func__);
}

static void push_utility_threads(struct task_struct *p)
{
	struct task_struct *util_thread;
	struct mos_process_t *proc = p->mos_process;
	int cpu;

	/* Are there any uncommitted CPUs remaining */
	cpu = _select_cpu_candidate(p, 0, ForwardSearch,
					mos_match_cpu_FirstAvail, 0, NULL,
					-1, mos_commit_cpu_scope_AllCommits, 0);
	if (cpu < 0) {
		/* There are no un-committed CPUs for the worker threads.
		 * start pushing off utility threads until we of freed up
		 * a CPU that can be used for a worker thread.
		 */

		/* Grab the utility list lock */
		mutex_lock(&proc->util_list_lock);

		/*
		 * Continue to push moveable utility threads to the share Linux
		 * CPUs until either no more utility threads are available to
		 * be pushed or until we we freed up an LWK CPU.
		 */
		while ((util_thread = list_first_entry_or_null(&proc->util_list,
							struct task_struct,
							mos.util_list))) {
			int util_cpu;
			int from_cpu;
			enum mos_match_cpu matchtype = mos_match_cpu_FirstAvail;
			int loc_id = 0;
			nodemask_t *node_mask = NULL;
			cpumask_var_t new_mask;
			bool placement_honored = true;

			if (!zalloc_cpumask_var(&new_mask, GFP_KERNEL)) {
				mos_ras(MOS_SCHEDULER_WARNING,
				"%s: CPU mask allocation failure.", __func__);
				break;
			}

			/* remove the utility thread from the list */
			list_del(&util_thread->mos.util_list);
			util_thread->mos.on_moveable_list = false;

			/*
			 * If the original request specified a domain mask,
			 * attempt to honor that request, regardless of commit
			 * level. Otherwise place on the CPU that has the
			 * lowest commit level.
			 */
			if (util_thread->mos.active_hints.location &
			    MOS_CLONE_ATTR_USE_NODE_SET) {
				matchtype = mos_match_cpu_InNMask;
				node_mask =
					&util_thread->mos.active_hints.nodes;
			}
			while (1) {

				util_cpu = select_linux_utility_cpus(
								util_thread,
								matchtype,
								loc_id,
								node_mask,
								new_mask,
								false);
				/* Did we find a CPU matching our criteria? */
				if ((util_cpu >= 0) &&
				    (util_cpu < nr_cpu_ids)) {
					/*
					 * We will now be running this thread
					 * on a Linux CPU with other mos threads
					 * and Linux tasks therefore we must
					 * play by Linux rules. Give the task
					 * back to the Linux scheduler. We will
					 * no longer be in control of the
					 * scheduling of this thread.
					 */
					push_to_linux_scheduler(util_thread);
					break;
				}
				if (matchtype == mos_match_cpu_FirstAvail) {
					/*
					 * Should never get here, indicate an
					 * error. Do not move the thread but
					 * keep it off the list of moveable
					 * utility threads
					 */
					util_cpu = util_thread->mos.cpu_home;
					mos_ras(MOS_SCHEDULER_WARNING,
						"%s: Unexpected condition searching for available CPU.",
						__func__);
					break;
				}
				/* Relax the match we are doing. If we keep
				 * returning here, we will eventually relax
				 * the match type to FirstAvail, which will
				 * always end up with a valid CPU
				 */
				matchtype = relax_match(matchtype);
				placement_honored = false;
			}
			/* Move util_thread to linux cpu */
			from_cpu = util_thread->mos.cpu_home;

			/* Update the commit counts */
			uncommit_cpu(util_thread);
			commit_cpu(util_thread, util_cpu);

			set_cpus_allowed_ptr(util_thread, new_mask);

			/* Update the count of pushed threads */
			if (from_cpu >= 0)
				cpu_rq(from_cpu)->mos.stats.pushed++;

			/* Trace the push */
			trace_mos_util_thread_pushed(from_cpu,
						     util_cpu,
						     util_thread,
						     cpumask_weight(new_mask),
						     placement_honored);
			free_cpumask_var(new_mask);
			cpu = _select_cpu_candidate(p, 0, ForwardSearch,
					mos_match_cpu_FirstAvail,
					0, NULL, -1,
					mos_commit_cpu_scope_AllCommits, 0);
			if (cpu >= 0)
				/*
				 * We have freed up an LWK CPU.
				 * Our work is done.
				 */
				break;
		}
		mutex_unlock(&proc->util_list_lock);
	}
}

static void clear_clone_hints(struct task_struct *p)
{
	memset(&current->mos.clone_hints, 0, sizeof(struct mos_clone_hints));
	memset(&p->mos.clone_hints, 0, sizeof(struct mos_clone_hints));
}

static bool balance_pull(bool start_balance_timer, bool irqs_disabled_on_entry);

static enum hrtimer_restart balance_tick(struct hrtimer *timer)
{
	struct mos_rq *mos_rq = container_of(timer, struct mos_rq, balance_timer);

	trace_mos_balancer_tick(mos_rq);

	/* Keep timer running if we are still in the idle task */
	if (current != mos_rq->idle)
		return HRTIMER_NORESTART;

	balance_pull(false, true);

	hrtimer_forward_now(timer, ms_to_ktime(mos_rq->balancer_parm1));
	return HRTIMER_RESTART;
}

/* Returns true if the balance_tick timer was enabled */
static inline bool start_balance_tick(struct mos_rq *mos_rq, uint64_t ktime)
{
	trace_mos_balancer_tick_start(mos_rq);
	hrtimer_forward_now(&mos_rq->balance_timer, ktime);
	hrtimer_start_expires(&mos_rq->balance_timer, HRTIMER_MODE_ABS_PINNED_HARD);
	mos_rq->balance_tick_started = true;
	return true;
}

static inline void stop_balance_tick(struct mos_rq *mos_rq)
{
	hrtimer_cancel(&mos_rq->balance_timer);
	mos_rq->balance_tick_started = false;
	trace_mos_balancer_tick_stop(mos_rq);
}

static bool balance_pull(bool start_balance_timer, bool irqs_disabled_on_entry)
{
	int cpu;
	bool rc = 0;
	struct rq *this_rq;
	struct mos_rq *this_mos_rq;
	struct mos_rq *max_mos_rq = NULL;
	int this_cpu = smp_processor_id();
	int pid = -1;
	unsigned long current_time;
	unsigned long max_weight = 0;
	unsigned long overcommit_threshold;

	this_rq = cpu_rq(this_cpu);
	this_mos_rq = &(this_rq->mos);
	/* Is balancing activated */
	if (this_mos_rq->balancer != BalancerType_Pull)
		/* Return, balancing is not active */
		return rc;

	/* Is there a process that has this CPU reserved? */
	if (!this_mos_rq->owner)
		/* Return. There is nothing to balance */
		return rc;

	if (start_balance_timer && this_mos_rq->balancer_parm3)
		/* Delay doing a PULL until the balance timer pops */
		goto start_timer;

	/* Search run queues to see if we can help balance the load. We can
	 * do this without locking the target queue. Once we find a likely
	 * candidate, we will then lock down both run queues involved.
	 */
	overcommit_threshold = ms_to_ktime(this_mos_rq->balancer_parm2);
	current_time = sched_clock();
	for_each_cpu(cpu, this_mos_rq->reserved_cpus) {
		unsigned long delta_idle;
		unsigned long delta_overcommit;
		unsigned long weight = 0;
		struct mos_rq *mos_rq = &cpu_rq(cpu)->mos;
		unsigned long tstamp_overcommitted =
						   mos_rq->tstamp_overcommitted;
		unsigned long tstamp_exit_idle = mos_rq->tstamp_exit_idle;
		unsigned int rr_nr_running = READ_ONCE(mos_rq->rr_nr_running);


		/* Are we not overcommitted or have not ever left the idle state
		 * or not more than 1 running lwk thread
		 */
		if (!mos_rq->tstamp_overcommitted ||
		    !mos_rq->tstamp_exit_idle || (rr_nr_running < 2))
			continue;

		/* Calculate the time since the CPU last exited idle */
		delta_idle = (current_time > tstamp_exit_idle) ?
			(current_time - tstamp_exit_idle) : 0;
		/* Calculate the time that the CPU has been overcommitted */
		delta_overcommit = (current_time > tstamp_overcommitted) ?
		(current_time - tstamp_overcommitted) : 0;

		weight = (rr_nr_running - 1) * delta_idle;
		/* Have we been over-committed beyond the threshold time? */
		if (delta_overcommit > overcommit_threshold) {
			if (weight > max_weight) {
				max_weight = weight;
				max_mos_rq = mos_rq;
			}
		}
	}
	/* Did we find a candidate? */
	if (max_mos_rq) {
		int rq_index;
		struct mos_prio_array *src_queue_array;
		struct list_head *src_queue;
		struct sched_mos_entity *mos_se;
		struct task_struct *p;
		struct rq *max_rq = rq_of_mos_rq(max_mos_rq);
		int max_cpu = cpu_of(max_rq);

		/*
		 * Pull a task from max_rq to our mos_rq
		 *
		 * We need to lock both run queues. In order to avoid a deadlock
		 * lock each run queue in a consistent order.
		 */
		if (!irqs_disabled_on_entry)
			local_irq_disable();

		if (this_rq < max_rq)
			double_rq_lock(this_rq, max_rq);
		else
			double_rq_lock(max_rq, this_rq);

		rq_index = mos_rq_index(MOS_DEFAULT_PRIO);
		src_queue_array = &max_mos_rq->active;
		src_queue = src_queue_array->queue + rq_index;

		/* Need to directly test this queue after acquiring the rq
		 * lock for two reasons:
		 * 1. Conditions may have changed since the first test when
		 *    we did not hold the rq lock
		 * 2. If non-default priorities were used, the additional
		 *    threads indicated by mos_nr_running may be attributed to
		 *    queues associated with different priorities. Unlikely but
		 *    possible.
		 */
		if (list_empty(src_queue))
			goto unlock;
		if (list_is_singular(src_queue))
			goto unlock;


		/* Choose a non-running task on the src queue that is allowed to
		 * run on our CPU.
		 */
		list_for_each_entry(mos_se, src_queue, run_list) {
			p = mos_task_of(mos_se);
			if (!task_current(max_rq, p) &&
			    cpumask_test_cpu(this_cpu, p->cpus_ptr)) {
				pid = p->pid;
				break;
			}
		}
		/* Did we find a task for balancing */
		if (pid == -1)
			goto unlock;

		trace_mos_balance(pid, max_cpu, this_cpu, max_weight, 0);
		max_mos_rq->stats.balance_from++;
		this_mos_rq->stats.balance_to++;

		/* Change the CPU commit and move thread. */
		deactivate_task(max_rq, p, 0);
		set_task_cpu(p, this_cpu);
		activate_task(this_rq, p, 0);

		/* Avoid entering idle on return and run newly acquired task */
		resched_curr(this_rq);

unlock:
		if (this_rq > max_rq)
			double_rq_unlock(this_rq, max_rq);
		else
			double_rq_unlock(max_rq, this_rq);

		if (!irqs_disabled_on_entry)
			local_irq_enable();

	}
start_timer:
	/* If balancing is allowed and no task was pulled to be dispatched,
	 * enable the balance timer
	 */
	if (start_balance_timer &&
	    !this_mos_rq->balance_tick_started && /* Is tick not running */
	    !need_resched() && /* Are we staying in idle loop */
	    (pid == -1))   /* Did we not pull a thread onto this CPU */
		rc = start_balance_tick(this_mos_rq,
			this_mos_rq->balancer_parm3 * (uint64_t)1000);
	return rc;
}

static bool balance_push(struct rq *this_rq)
{
	int cpu, this_cpu;
	bool rc = 0;
	struct mos_rq *this_mos_rq;
	struct mos_rq *min_mos_rq = NULL;
	int pid = -1;
	unsigned long this_load;
	unsigned long delta_overcommit;
	unsigned long time_since_idle;
	unsigned long cur_time;
	unsigned long min_load = -1;
	unsigned long overcommit_threshold, load_delta_threshold;
	unsigned long throttle;
	struct mos_process_t *mosp;

	this_cpu = cpu_of(this_rq);
	this_mos_rq = &(this_rq->mos);
	mosp = this_mos_rq->owner;
	if (!mosp)
		return rc;
	throttle = ms_to_ktime(mosp->balancer_parm3);

	/* Are we overcommitted */
	if (this_mos_rq->rr_nr_running <= 1)
		return rc;
	load_delta_threshold = this_mos_rq->balancer_parm1;
	overcommit_threshold = ms_to_ktime(this_mos_rq->balancer_parm2);
	cur_time = sched_clock();
	/* Have we been running overcommitted beyond threshold amount of time */
	delta_overcommit = (cur_time > this_mos_rq->tstamp_overcommitted) ?
		(cur_time - this_mos_rq->tstamp_overcommitted) : 0;
	if (delta_overcommit < overcommit_threshold)
		return rc;
	time_since_idle = (cur_time > this_mos_rq->tstamp_exit_idle) ?
	 (cur_time - this_mos_rq->tstamp_exit_idle) : 0;
	this_load = this_mos_rq->rr_nr_running * time_since_idle;

	/* We do not want multiple overcommitted CPUs deciding to push their
	 * work all to the same CPU. Obtain a process-scoped balancer lock.
	 * Process scoping this lock only works because we never have more than
	 * one mOS process thread running on any given LWK CPU. If this design
	 * ever changes, this lock design will need to be changed
	 */
	raw_spin_unlock(&this_rq->__lock);
	raw_spin_lock(&mosp->balancer_lock);

	/* Search run queues to see if we can reduce the load on this CPU. We
	 * can do this without locking the target queue. Once we find a likely
	 * candidate, we will then lock down both run queues involved.
	 */
	for_each_cpu_wrap(cpu, this_mos_rq->reserved_cpus, this_cpu) {
		unsigned long load = -1;
		struct mos_rq *mos_rq = &cpu_rq(cpu)->mos;
		unsigned long exit_idle_tstamp = mos_rq->tstamp_exit_idle;
		unsigned long delta_idle = 1;

		if (cpu == this_cpu)
			continue;
		/* Was this CPU a recent target of a push from another CPU?
		 * If so, we dont want to gang up on this CPU since it recently
		 * took on addtional work that has not yet be realized
		 */
		if (mos_rq->last_balance + throttle > cur_time)
			continue;
		/* Calculate the time since the CPU last exited idle */
		if (exit_idle_tstamp && (cur_time > exit_idle_tstamp))
			delta_idle = cur_time - exit_idle_tstamp;
		load = mos_rq->rr_nr_running * delta_idle;
		if ((load < (this_load >> load_delta_threshold)) &&
		     (load < min_load)) {
			min_load = load;
			min_mos_rq = mos_rq;
			if (!load)
				break; /* No reason to continue the search */
		}
	}
	/* Did we find a candidate? */
	if (min_mos_rq) {
		int rq_index;
		struct mos_prio_array *src_queue_array;
		struct list_head *src_queue;
		struct sched_mos_entity *mos_se;
		struct task_struct *p;
		struct rq *min_rq = rq_of_mos_rq(min_mos_rq);
		int min_cpu = cpu_of(min_rq);

		/*
		 * Push a task from our mos_rq to the min_rq
		 *
		 * We need to lock both run queues. In order to avoid a deadlock
		 * lock each run queue in a consistent order. The rq passed in
		 * to this function is already locked. We could be smarter and
		 * avoid unlock 50% of the time, however this is complicated
		 * by the Linux caller saving/restoring rq flags using
		 * rq_lock()/rq_unlock()
		 */
		if (this_rq < min_rq)

			double_rq_lock(this_rq, min_rq);
		else
			double_rq_lock(min_rq, this_rq);

		rq_index = mos_rq_index(MOS_DEFAULT_PRIO);
		src_queue_array = &this_mos_rq->active;
		src_queue = src_queue_array->queue + rq_index;

		/* Choose a non-running task on our src queue that is allowed to
		 * run on the targeted CPU.
		 */
		list_for_each_entry(mos_se, src_queue, run_list) {
			p = mos_task_of(mos_se);
			if (!task_current(this_rq, p) &&
			    cpumask_test_cpu(min_cpu, p->cpus_ptr)) {
				pid = p->pid;
				break;
			}
		}
		/* Did we find a task for balancing */
		if (pid == -1)
			goto unlock;

		min_mos_rq->last_balance = sched_clock();
		trace_mos_balance(pid, this_cpu, min_cpu, this_load, min_load);
		min_mos_rq->stats.balance_to++;
		this_mos_rq->stats.balance_from++;

		/* Change the CPU commit and move thread. */
		deactivate_task(this_rq, p, 0);
		set_task_cpu(p, min_cpu);
		activate_task(min_rq, p, 0);

		/* Poke the target CPU */
		resched_curr(min_rq);

unlock:
		/*
		 * We need to unlock both run queues. To avoid a deadlock
		 * unlock each run queue in a consistent order. The rq passed in
		 * to this function is already locked. We could be smarter and
		 * avoid the extra unlock 50% of the time, however this is
		 * complicated  by the Linux caller saving/restoring rq flags
		 * using rq_lock()/rq_unlock()
		 */

		if (this_rq > min_rq)
			double_rq_unlock(this_rq, min_rq);
		else
			double_rq_unlock(min_rq, this_rq);

	}
	/* Return with the same lock state in entry. */
	raw_spin_unlock(&mosp->balancer_lock);
	raw_spin_lock(&this_rq->__lock);
	return rc;
}

static inline void mos_idle_poll_halt_wait(struct mos_rq *mos_rq, int cpu)
{
	unsigned long ecx, eax;
	bool deep_sleep = false;

	/* Determine if we are going into deep sleep */
	if (likely(mos_rq->mwait_supported)) {
		if (mos_rq->idle_boundary == Idle_Boundary_RESERVED) {
			if (unlikely(!mos_rq->owner))
				deep_sleep = true;
		} else if (mos_rq->idle_boundary == Idle_Boundary_COMMITTED) {
			if (unlikely(!mos_rq->compute_commits &&
			    !mos_rq->utility_commits))
				deep_sleep = true;
		} else if (mos_rq->idle_boundary == Idle_Boundary_NONE)
			deep_sleep = true;
	}
	tick_nohz_idle_stop_tick();
	rcu_idle_enter();
	if (likely(mos_rq->idle_mechanism == Idle_Mechanism_MWAIT ||
							deep_sleep)) {
		ecx = 1; /* mwait break on interrupt */
		eax = MWAIT_HINT(deep_sleep ? deep_sleep_mwait :
					      shallow_sleep_mwait);
		if (deep_sleep && mwait_deep_sleep_tlbs_flushed)
			leave_mm(cpu);
		trace_mos_idle_mwait_entry(ecx, eax);
		stop_critical_timings();
		__monitor((void *)&current_thread_info()->flags, 0, 0);
		if (!need_resched())
			__mwait(eax, ecx);
		start_critical_timings();
		trace_mos_idle_mwait_exit(ecx, eax);
		local_irq_enable();
	} else if (mos_rq->idle_mechanism == Idle_Mechanism_HALT)  {
		if (current_clr_polling_and_test())
			local_irq_enable();
		else {
			trace_mos_idle_halt_entry(0);
			stop_critical_timings();
			/* Re-enable and halt */
			safe_halt();
			/* Running again */
			start_critical_timings();
			trace_mos_idle_halt_exit(0);
		}
		__current_set_polling();
	} else /* if (mos_rq->idle_mechanism == Idle_Mechanism_POLL) */ {
		trace_mos_idle_poll_entry(0);
		tick_nohz_idle_restart_tick();
		stop_critical_timings();
		local_irq_enable();
		/* Hot polling */
		while (!need_resched())
			cpu_relax();
		start_critical_timings();
		trace_mos_idle_poll_exit(0);
	}
	rcu_idle_exit();
}

/*
 * This is the mOS idle loop.
 */
static int mos_idle_main(void *data)
{
	int cpu = (int)(unsigned long) data;
	struct rq *rq;
	struct mos_rq *mos_rq;
	bool balance_tick_enabled = false;

	rq = cpu_rq(cpu);
	mos_rq = &(rq->mos);
	mos_rq->idle = current;
	mos_rq->idle_pid = current->pid;

	local_irq_disable();
	vtime_init_idle(current, cpu);
	init_idle_preempt_count(current, cpu);
	local_irq_enable();

	/* Barrier prior to reading lwkcpu in the while loop. */
	smp_rmb(); /* Pairs with barrier in mos_sched_deactivate */

	while (rq->lwkcpu) {
		__current_set_polling();
		tick_nohz_idle_enter();
		balance_tick_enabled = balance_pull(true, false);


		while (!need_resched() && rq->lwkcpu) {
			rmb(); /* sync need_resched and polling settings */
			local_irq_disable();
			arch_cpu_idle_enter();
			/*
			 * Check if the idle task must be rescheduled. If it
			 * is the case, exit idle after re-enabling
			 * the local irq.
			 */
			if (need_resched())
				local_irq_enable();
			else
				mos_idle_poll_halt_wait(mos_rq, cpu);
			arch_cpu_idle_exit();
		}
		mos_rq->tstamp_exit_idle = sched_clock();

		/*
		 * Since we fell out of the loop above, we know
		 * TIF_NEED_RESCHED must be set, propagate it into
		 * PREEMPT_NEED_RESCHED.
		 */
		preempt_set_need_resched();
		if (balance_tick_enabled)
			stop_balance_tick(mos_rq);
		tick_nohz_idle_exit();
		__current_clr_polling();
		/*
		 * We promise to call sched_ttwu_pending and reschedule
		 * if need_resched is set while polling is set.  That
		 * means that clearing polling needs to be visible
		 * before doing these things.
		 */
		smp_mb__after_atomic();
		flush_smp_call_function_from_idle();
		schedule_preempt_disabled();
		/*
		 * Barrier prior to reading lwkcpu in the while loop.
		 * Pairs with barrier in mos_sched_deactive.
		 */
		smp_rmb();
	}
	/* Exiting. Remove special idle thread treatment to allow normal exit */
	current->mos.thread_type  = mos_thread_type_guest;
	return 0;
}

/*
 * Setup and launch idle thread
 */
static void idle_task_prepare(int cpu)
{
	struct rq *rq;
	struct mos_rq *mos_rq;
	struct task_struct *p;
	cpumask_var_t new_mask;

	rq = cpu_rq(cpu);
	mos_rq = &(rq->mos);

	/* If already initialized, we wake up the task so that it can
	 * re-evaluate its C-state and adjust to the new idle control
	 * specification. If it was in a deep sleep it will be
	 * brought back to C1 in preparation for use by the process.
	*/
	if (mos_rq->idle) {
		resched_cpu(cpu);
		return;
	}
	/*
	 * Create the idle task.
	 * We are using the 'on_node" interface to avoid waking up the task at
	 * this time.
	 */
	p = kthread_create_on_node(mos_idle_main, (void *)(unsigned long)cpu,
				     cpu_to_node(cpu), "mos_idle/%d", cpu);
	if (IS_ERR(p)) {
		mos_ras(MOS_SCHEDULER_WARNING,
		    "%s: mos_idle thread create failure for CPU=%u.",
		    __func__, cpu);
		return;
	}
	/*
	 * The task is in the stopped state and will not execute until we
	 * wake it up. Modify its affinity mask so it wakes up on the desired
	 * CPU.
	 */
	if (alloc_cpumask_var(&new_mask, GFP_KERNEL)) {
		cpumask_clear(new_mask);
		cpumask_set_cpu(cpu, new_mask);
		set_cpus_allowed_ptr(p, new_mask);
		free_cpumask_var(new_mask);
	} else {
		mos_ras(MOS_SCHEDULER_WARNING,
		"%s: mos_idle cpumask allocation failure for CPU=%u.",
		__func__, cpu);
		return;
	}
	trace_mos_idle_init(cpu);

	/* Initialize the task as the mos_idle task */
	p->prio = MOS_IDLE_PRIO;
	p->normal_prio = MOS_IDLE_PRIO;
	rq->mos.idle = p;

	/*
	 *  Wake up on the designated LWK CPU. This will send us into
	 *  the assimilation flow and this task will be transformed from
	 *  the fair scheduling class into the mos scheduling class. The task
	 *  will then be enqueued and start to execute for the first time.
	 *  It will permanently be positioned as a low priority task on the
	 *  mos runqueue and wedge itself in as the new idle task.
	 */
	wake_up_process(p);
}

/*
 * Prepare the scheduler to accept the current process which has now reserved
 * the CPUs in its mos cpu mask.
 */
void mos_sched_prepare_launch(void)
{
	int cpu;
	struct mos_process_t *mos_process = current->mos_process;

	for_each_cpu(cpu, mos_process->lwkcpus) {

		struct mos_rq *mos_rq = &cpu_rq(cpu)->mos;

		/* initialize mos run queue */
		mos_rq->compute_commits = 0;
		mos_rq->utility_commits = 0;
		atomic_set(&mos_rq->exclusive_pid, 0);
		sched_stats_prepare_launch(&mos_rq->stats);

		/* Set the owning process */
		mos_rq->owner = current->mos_process;

		/* Set the requested idle control */
		mos_rq->idle_mechanism = mos_process->idle_mechanism;
		mos_rq->idle_boundary = mos_process->idle_boundary;
		mos_rq->balancer = mos_process->balancer;
		mos_rq->balancer_parm1 = mos_process->balancer_parm1;
		mos_rq->balancer_parm2 = mos_process->balancer_parm2;
		mos_rq->balancer_parm3 = mos_process->balancer_parm3;
		mos_rq->mwait_supported = mwait_supported;
		mos_rq->mwait_tlbs_flushed = mwait_deep_sleep_tlbs_flushed;
		cpumask_copy(mos_rq->reserved_cpus, mos_process->lwkcpus);
	}
	smp_mb(); /* idle tasks need to see the current owner */

	for_each_cpu(cpu, mos_process->lwkcpus)
		idle_task_prepare(cpu); /* prepare the idle task */

	/* Save the original cpus_allowed mask */
	cpumask_copy(mos_process->original_cpus_allowed, current->cpus_ptr);
}

static int lwksched_process_init(struct mos_process_t *mosp)
{

	if (!zalloc_cpumask_var(&mosp->original_cpus_allowed, GFP_KERNEL)) {
		mos_ras(MOS_SCHEDULER_ERROR,
			"%s: CPU mask allocation failure.", __func__);
		return -ENOMEM;
	}
	atomic_set(&mosp->threads_created, 0); /* threads created */
	mosp->num_util_threads = 0;
	mosp->mce_modifications_active = 0;
	mosp->enable_rr = MOS_TIMESLICE;
	mosp->disable_setaffinity = 0;
	mosp->sched_stats = 0;
	mosp->balancer = BalancerType_None;
	mosp->balancer_parm1 = 0;
	mosp->balancer_parm2 = 0;
	mosp->balancer_parm3 = 0;
	raw_spin_lock_init(&mosp->balancer_lock);
	INIT_LIST_HEAD(&mosp->util_list);
	mutex_init(&mosp->util_list_lock);
	mosp->max_cpus_for_util = -1;
	mosp->max_util_threads_per_cpu = 1;
	mosp->cmci_threshold = CMCI_THRESHOLD_MAX;
	mosp->correctable_mcheck_polling = 0;
	mosp->overcommit_behavior = mos_commit_cpu_scope_OnlyUtilityCommits;
	mosp->allowed_cpus_per_util = AllowMultipleCpusPerUtilThread;
	if (likely(mwait_supported)) {
		mosp->idle_mechanism = Idle_Mechanism_MWAIT;
		mosp->idle_boundary = Idle_Boundary_RESERVED;
	} else {
		mosp->idle_mechanism = Idle_Mechanism_HALT;
		mosp->idle_boundary = Idle_Boundary_ONLINE;
	}

	return 0;
}

static int lwksched_process_start(struct mos_process_t *mosp)
{

	mos_sched_prepare_launch();
	mce_lwkprocess_begin(mosp->lwkcpus, mosp->cmci_threshold,
				mosp->correctable_mcheck_polling);
	mosp->mce_modifications_active = 1;

	return 0;
}

/* Scheduler cleanup required as each thread exits */
static void lwksched_thread_exit(struct mos_process_t *mosp)
{
	/* Cleanup CPU commits */
	uncommit_cpu(current);

	if (current->mos.thread_type == mos_thread_type_utility) {
		/* Remove the task from the moveable list */
		mutex_lock(&mosp->util_list_lock);
		/* Do we need to remove task from the moveable list */
		if (current->mos.on_moveable_list) {
			/* Remove utility thread from the moveable list */
			list_del(&current->mos.util_list);
			current->mos.on_moveable_list = false;
		}
		mutex_unlock(&mosp->util_list_lock);

		/* Cleanup utility thread key table */
		if (current->mos.active_hints.key) {
			int i;

			/* Search key table for a match */
			raw_spin_lock(&util_grp_lock);
			for (i = 0; i < UTIL_GROUP_LIMIT; i++) {
				if (util_grp.entry[i].key ==
				    current->mos.active_hints.key) {
					/* Decrement the reference count */
					if (!(--(util_grp.entry[i].refcount)))
						util_grp.entry[i].key = 0;
					break;
				}
			}
			raw_spin_unlock(&util_grp_lock);
		}
	}
 }

static void stats_summarize(struct mos_sched_stats *pstats,
			    struct mos_sched_stats *stats,
			    int detail_level, int tgid, int cpu,
			    int util_cpu)
{
	if (stats->max_compute_level) {
		if (stats->max_compute_level > pstats->max_compute_level)
			pstats->max_compute_level = stats->max_compute_level;
		if (stats->max_util_level > pstats->max_util_level)
			pstats->max_util_level = stats->max_util_level;
		if (stats->max_running > pstats->max_running)
			pstats->max_running = stats->max_running;
		pstats->guest_dispatch += stats->guest_dispatch;
		pstats->timer_pop += stats->timer_pop;
		pstats->sysc_migr += stats->sysc_migr;
		pstats->setaffinity += stats->setaffinity;
		pstats->pushed += stats->pushed;
		pstats->balance_from += stats->balance_from;
		pstats->balance_to += stats->balance_to;
		if (((detail_level == 1) &&
		    (stats->max_compute_level > 1)) ||
		    (detail_level > 2)) {
			pr_info("mOS-sched: PID=%d cpuid=%2d max_compute=%d max_util=%d max_running=%d guest_dispatch=%d timer_pop=%d setaffinity=%d balance_from=%d balance_to=%d pushed=%d sysc_migr=%d\n",
				tgid, cpu,
				stats->max_compute_level,
				stats->max_util_level,
				stats->max_running - 1, /* remove mOS idle */
				stats->guest_dispatch,
				stats->timer_pop,
				stats->setaffinity,
				stats->balance_from,
				stats->balance_to,
				stats->pushed,
				stats->sysc_migr
			    );
		}
	}
}

static void sched_stats_summarize(struct mos_process_t *mosp)
{
	/* Summarize and output statistics for the process */
	int detail_level = mosp->sched_stats;
	int tgid = mosp->tgid;

	if (detail_level > 0) {
		int cpu;
		int cpus = 0;
		struct mos_sched_stats pstats;

		sched_stats_init(&pstats);
		for_each_cpu(cpu, mosp->lwkcpus) {
			struct mos_sched_stats *stats = &cpu_rq(cpu)->mos.stats;

			stats_summarize(&pstats, stats, detail_level,
					tgid, cpu, 0);
			cpus++;
		}
		if (((detail_level ==  1) &&
		    (pstats.max_compute_level > 1)) ||
		    (detail_level > 1))
			pr_info("mOS-sched: PID=%d threads=%d cpus=%2d max_compute=%d max_util=%d max_running=%d guest_dispatch=%d timer_pop=%d setaffinity=%d balancer_actions=%d pushed=%d sysc_migr=%d\n",
			tgid,
			atomic_read(&mosp->threads_created)+1,
			cpus,
			pstats.max_compute_level,
			pstats.max_util_level,
			pstats.max_running - 1, /* remove mOS idle */
			pstats.guest_dispatch,
			pstats.timer_pop,
			pstats.setaffinity,
			pstats.balance_from,
			pstats.pushed,
			pstats.sysc_migr);
		if (detail_level > 1) {
			int i;

			for (i = 0; i < UTIL_GROUP_LIMIT; i++)
				if (util_grp.entry[i].key)
					pr_info("mOS-sched: UTI key=%ld refcount=%d\n",
					    util_grp.entry[i].key,
					    util_grp.entry[i].refcount);
		}
	}
}

static void sleep_on_process_exit(struct mos_process_t *mosp)
{
	int cpu;

	for_each_cpu(cpu, mosp->lwkcpus) {
		struct mos_rq *mos = &cpu_rq(cpu)->mos;

		mos->owner = 0;
	}
	smp_mb(); /* idle tasks need to see the change to owner */

	for_each_cpu(cpu, mosp->lwkcpus)
		/* Kick idle tasks causing them to re-evaluate their C-state */
		resched_cpu(cpu);
}

static void lwksched_process_exit(struct mos_process_t *mosp)
{
	/* Cleanup the utility mask */
	cpumask_clear(mosp->utilcpus);

	/* Drive the LWK CPUs into low power state if supported. */
	sleep_on_process_exit(mosp);

	/* Process the scheduler end of job statistics */
	sched_stats_summarize(mosp);

	/* Re-enable correctable machine check interrupts and polling */
	if (mosp->mce_modifications_active) {
		mce_lwkprocess_end(current->mos_process->lwkcpus,
				   mosp->cmci_threshold ? true : false,
				   !mosp->correctable_mcheck_polling);
		mosp->mce_modifications_active = 0;
	}
	/* Free the allocated cpumask */
	free_cpumask_var(mosp->original_cpus_allowed);
}

static struct mos_process_callbacks_t lwksched_callbacks = {
	.mos_process_init = lwksched_process_init,
	.mos_process_start = lwksched_process_start,
	.mos_thread_exit = lwksched_thread_exit,
	.mos_process_exit = lwksched_process_exit,
};

static int lwksched_enable_rr(const char *val,
			      struct mos_process_t *mosp)
{
	int rc, msecs, min_msecs;

	min_msecs = jiffies_to_msecs(1);
	if (!val)
		goto invalid;
	rc = kstrtoint(val, 0, &msecs);

	if (rc)
		goto invalid;
	/* Allow a zero value to indicate no rr time-slicing */
	if (!msecs) {
		mosp->enable_rr = 0;
		return 0;
	}
	/* Specified value minimum need to be >= timer frequency */
	if (msecs < min_msecs)
		goto invalid;
	mosp->enable_rr = msecs_to_jiffies(msecs);

	return 0;
invalid:
	mos_ras(MOS_SCHEDULER_ERROR,
	"%s: Illegal value (%s). Minimum valid timeslice is %d",
	       __func__, val, min_msecs);
	return -EINVAL;
}

static int lwksched_disable_setaffinity(const char *val,
			      struct mos_process_t *mosp)
{
	int rc, syscall_errno;

	if (!val)
		goto invalid;
	rc = kstrtoint(val, 0, &syscall_errno);

	if (rc)
		goto invalid;

	if (syscall_errno < 0)
		goto invalid;

	mosp->disable_setaffinity = ++syscall_errno;

	return 0;
invalid:
	mos_ras(MOS_SCHEDULER_ERROR,
		"%s: Illegal value (%s). Expected >= 0.", __func__, val);
	return -EINVAL;
}

static int lwksched_stats(const char *val, struct mos_process_t *mosp)
{
	int rc, level;

	if (!val)
		goto invalid;
	rc = kstrtoint(val, 0, &level);

	if (rc || (level < 0))
		goto invalid;

	mosp->sched_stats = level;

	return 0;
invalid:
	mos_ras(MOS_SCHEDULER_ERROR, "%s: Illegal value (%s).", __func__, val);
	return -EINVAL;
}

static int lwksched_util_threshold(const char *val, struct mos_process_t *mosp)
{
	int rc;
	char *max_cpus_str, *max_thread_str;

	if (!val)
		goto invalid;
	max_thread_str = kstrdup(val, GFP_KERNEL);
	if (!max_thread_str)
		goto invalid;
	max_cpus_str = strsep(&max_thread_str, ":");
	if (!max_thread_str || !max_cpus_str)
		goto invalid;
	rc = kstrtoint(max_thread_str, 0, &mosp->max_util_threads_per_cpu);
	if (rc)
		goto invalid;
	if (mosp->max_util_threads_per_cpu < 0)
		goto invalid;
	rc = kstrtoint(max_cpus_str, 0, &mosp->max_cpus_for_util);
	if (rc)
		goto invalid;
	if ((mosp->max_cpus_for_util != -1) &&
	    (cpumask_empty(mosp->utilcpus))) {
		mos_ras(MOS_SCHEDULER_ERROR,
		    "%s: Illegal threshold value (%s) due to no utility CPUs configured",
		    __func__, val);
		return -EINVAL;
	}
	return 0;
invalid:
	mos_ras(MOS_SCHEDULER_ERROR, "%s: Illegal value (%s).", __func__, val);
	return -EINVAL;
}

static int lwksched_overcommit_behavior(const char *val,
					struct mos_process_t *mosp)
{
	int behavior;

	if (!val)
		goto invalid;
	if (kstrtoint(val, 0, &behavior))
		goto invalid;
	switch (behavior) {
	case mos_commit_cpu_scope_AllCommits:
	case mos_commit_cpu_scope_OnlyComputeCommits:
	case mos_commit_cpu_scope_OnlyUtilityCommits:
		mosp->overcommit_behavior = behavior;
		return 0;
	}
invalid:
	mos_ras(MOS_SCHEDULER_ERROR, "%s: Illegal value (%s).", __func__, val);
	return -EINVAL;
}

static int lwksched_one_cpu_per_util(const char *val,
				     struct mos_process_t *mosp)
{
	mosp->allowed_cpus_per_util = AllowOnlyOneCpuPerUtilThread;
	return 0;
}

static int lwksched_enable_balancer(const char *val,
				     struct mos_process_t *mosp)
{
	int rc = -EINVAL;
	unsigned int balancer_parm1, balancer_parm2, balancer_parm3;
	char *balancer_type;
	char *balancer_parms_st;
	char *balancer_parm1_st;
	char *balancer_parm2_st;
	char *balancer_parm3_st;

	if (!val) {
		mosp->balancer = BalancerType_Pull;
		mosp->balancer_parm1 = BALANCER_PULL_DEFAULT_PARM1;
		mosp->balancer_parm2 = BALANCER_PULL_DEFAULT_PARM2;
		mosp->balancer_parm3 = BALANCER_PULL_DEFAULT_PARM3;
		return 0;
	}
	balancer_parms_st = kstrdup(val, GFP_KERNEL);
	if (!balancer_parms_st)
		return -ENOMEM;
	balancer_type = strsep(&balancer_parms_st, ",");
	if (!strcmp(balancer_type, "pull")) {
		mosp->balancer = BalancerType_Pull;
		mosp->balancer_parm1 = BALANCER_PULL_DEFAULT_PARM1;
		mosp->balancer_parm2 = BALANCER_PULL_DEFAULT_PARM2;
		mosp->balancer_parm3 = BALANCER_PULL_DEFAULT_PARM3;
	} else if (!strcmp(balancer_type, "push")) {
		mosp->balancer = BalancerType_Push;
		mosp->balancer_parm1 = BALANCER_PUSH_DEFAULT_PARM1;
		mosp->balancer_parm2 = BALANCER_PUSH_DEFAULT_PARM2;
		mosp->balancer_parm3 = BALANCER_PUSH_DEFAULT_PARM3;
	} else {
		mos_ras(MOS_SCHEDULER_ERROR, "%s: Invalid balance type (%s).",
		    __func__, balancer_type);
		goto leave;
	}
	if (balancer_parms_st) {
		balancer_parm2_st = balancer_parms_st;
		balancer_parm1_st = strsep(&balancer_parm2_st, ",");

		if (kstrtou32(balancer_parm1_st, 0, &balancer_parm1)) {
			mos_ras(MOS_SCHEDULER_ERROR,
				"%s: Illegal balance parameter (%s).",
				__func__, balancer_parm1_st);
			goto leave;
		}
		mosp->balancer_parm1 = balancer_parm1;
		if (balancer_parm2_st) {
			balancer_parm3_st = balancer_parm2_st;
			balancer_parm2_st = strsep(&balancer_parm3_st, ",");

			if (kstrtou32(balancer_parm2_st, 0, &balancer_parm2)) {
				mos_ras(MOS_SCHEDULER_ERROR,
					"%s: Illegal balance parameter (%s).",
					__func__, balancer_parm2_st);
				goto leave;
			}
			mosp->balancer_parm2 = balancer_parm2;
			if (balancer_parm3_st) {
				if (kstrtou32(balancer_parm3_st, 0,
						&balancer_parm3)) {
					mos_ras(MOS_SCHEDULER_ERROR,
					"%s: Illegal balance parameter (%s).",
						__func__, balancer_parm3_st);
					goto leave;
				}
				mosp->balancer_parm3 = balancer_parm3;
			}
		}
	}
	rc = 0;
leave:
	kfree(balancer_type);
	return rc;
}


static int lwksched_idle_control(const char *val, struct mos_process_t *mosp)
{
	char *mechanism_str = NULL;
	char *boundary_str = NULL;
	int rc = 0;

	if (!val) {
		mos_ras(MOS_SCHEDULER_ERROR,
		    "%s: Required value=<mechanism,boundary> not specified.",
		    __func__);
		rc = -EINVAL;
		goto leave;
	}
	boundary_str = kstrdup(val, GFP_KERNEL);
	if (!boundary_str)
		return -ENOMEM;
	mechanism_str = strsep(&boundary_str, ",");
	if (!boundary_str) {
		mos_ras(MOS_SCHEDULER_ERROR,
			"%s: Missing boundary specification: %s",
			__func__, val);
		rc = -EINVAL;
		goto leave;
	}
	/* Mechanism processing */
	if (!strcmp(mechanism_str, "mwait")) {
		if (mwait_supported)
			mosp->idle_mechanism = Idle_Mechanism_MWAIT;
		else {
			mos_ras(MOS_SCHEDULER_ERROR,
				"%s: MWAIT not supported on current platform.",
				__func__);
			rc = -EINVAL;
			goto leave;
		}
	} else if (!strcmp(mechanism_str, "halt"))
		mosp->idle_mechanism = Idle_Mechanism_HALT;
	else if (!strcmp(mechanism_str, "poll"))
		mosp->idle_mechanism = Idle_Mechanism_POLL;
	else {
		mos_ras(MOS_SCHEDULER_ERROR, "%s: Invalid mechanism (%s).",
		    __func__, mechanism_str);
		rc = -EINVAL;
		goto leave;
	}
	/* Boundary processing */
	if (!strcmp(boundary_str, "none"))
		mosp->idle_boundary = Idle_Boundary_NONE;
	else if (!strcmp(boundary_str, "committed"))
		mosp->idle_boundary = Idle_Boundary_COMMITTED;
	else if (!strcmp(boundary_str, "reserved"))
		mosp->idle_boundary = Idle_Boundary_RESERVED;
	else if (!strcmp(boundary_str, "online"))
		mosp->idle_boundary = Idle_Boundary_ONLINE;
	else {
		mos_ras(MOS_SCHEDULER_ERROR, "%s: Invalid boundary (%s).",
			__func__, boundary_str);
		rc = -EINVAL;
		goto leave;
	}
leave:
	kfree(mechanism_str);
	return rc;
}

static int lwksched_cmci_control(const char *val, struct mos_process_t *mosp)
{
	char *threshold_str = NULL;
	char *poll_enable_str = NULL;

	if (!val)
		goto invalid;
	poll_enable_str = kstrdup(val, GFP_KERNEL);
	if (!poll_enable_str)
		goto invalid;
	threshold_str = strsep(&poll_enable_str, ",");
	if (!poll_enable_str || !threshold_str)
		goto invalid;
	if (!strcmp(threshold_str, "max-threshold"))
		mosp->cmci_threshold = CMCI_THRESHOLD_MAX;
	else if (!strcmp(threshold_str, "disable-cmci"))
		mosp->cmci_threshold = 0;
	else if (kstrtoint(threshold_str, 0, &mosp->cmci_threshold))
		goto invalid;
	if (!strcmp(poll_enable_str, "enable-poll"))
		mosp->correctable_mcheck_polling = 1;
	else if (!strcmp(poll_enable_str, "disable-poll"))
		mosp->correctable_mcheck_polling = 0;
	else
		goto invalid;
	if (mosp->cmci_threshold > CMCI_THRESHOLD_MAX)
		goto invalid;
	kfree(threshold_str);
	return 0;
invalid:
	mos_ras(MOS_SCHEDULER_ERROR, "%s: Illegal value (%s).", __func__, val);
	kfree(threshold_str);
	return -EINVAL;
}


static int __init lwksched_mod_init(void)
{
	raw_spin_lock_init(&util_grp_lock);

	mos_register_process_callbacks(&lwksched_callbacks);

	mos_register_option_callback("lwksched-enable-rr",
				     lwksched_enable_rr);

	mos_register_option_callback("lwksched-disable-setaffinity",
				     lwksched_disable_setaffinity);
	mos_register_option_callback("lwksched-stats",
				     lwksched_stats);
	mos_register_option_callback("util-threshold",
				     lwksched_util_threshold);
	mos_register_option_callback("overcommit-behavior",
				     lwksched_overcommit_behavior);
	mos_register_option_callback("one-cpu-per-util",
				     lwksched_one_cpu_per_util);
	mos_register_option_callback("idle-control",
				     lwksched_idle_control);
	mos_register_option_callback("cmci-control",
				     lwksched_cmci_control);
	mos_register_option_callback("enable-balancer",
				     lwksched_enable_balancer);
	return 0;
}

subsys_initcall(lwksched_mod_init);

static void mos_timer_fn(struct timer_list *t)
{
	struct mos_rq *mos = &this_rq()->mos;

	if (&mos->api_timer != t)
		mos_ras(MOS_SCHEDULER_WARNING,
			"%s: API timer callback running on an unexpected CPU.",
			__func__);

	mos->api_timeout = 1;
	/* Runs in same CPU that is testing for timeout. No fence needed */
}

static int timer_init(cpumask_var_t lwkcpus)
{
	int cpu;

	for_each_cpu(cpu, lwkcpus) {

		struct mos_rq *mos_rq = &(cpu_rq(cpu)->mos);
		struct timer_list *t;

		/* Setup the mwait API timer */
		t = &mos_rq->api_timer;
		timer_setup(t, mos_timer_fn, TIMER_PINNED);
		mos_rq->api_timeout = 0;

		/* Setup the balancer timer */
		hrtimer_init(&mos_rq->balance_timer, CLOCK_MONOTONIC,
			     HRTIMER_MODE_ABS_PINNED);
		mos_rq->balance_timer.function = balance_tick;
		mos_rq->balance_tick_started = false;
	}
	return 0;
}

static int lwksched_topology_init(void)
{
	int i;

	for_each_online_cpu(i) {
		struct rq *rq;

		rq = cpu_rq(i);
		init_mos_topology(rq);
	}
	return 0;
}

/*
 * Early initialization called from Linux sched_init
 */
int __init init_sched_mos(void)
{
	int i;

	for_each_cpu_not(i, cpu_possible_mask) {
		cpumask_clear(per_cpu_ptr(&lwkcpus_mask, i));
	}

	for_each_possible_cpu(i) {
		cpumask_clear(per_cpu_ptr(&lwkcpus_mask, i));
	}
	if (!zalloc_cpumask_var(&saved_wq_mask, GFP_KERNEL))

		mos_ras(MOS_SCHEDULER_WARNING,
			"%s: CPU mask allocation failure.", __func__);

	return 0;
}

/*
 * Mark a CPU as LWK.
 * It is expected that the CPU is offline.
 */
int mos_sched_mark_cpu(int cpu)
{
	cpumask_t *lwkcpus = this_cpu_ptr(&lwkcpus_mask);
	struct rq *rq;

	if (!cpumask_test_cpu(cpu, lwkcpus))
		return -EINVAL;

	rq = cpu_rq(cpu);
	init_mos_rq(rq);
	/* Initialization seen before turning on an lwkcpu */
	smp_mb();
	rq->lwkcpu = 1;

	return 0;
}

/*
 * Initialize scheduler for the cpu mask provided. It is
 * expected that these CPUs are not in use by Linux
 */
int mos_sched_init(void)
{
	int i;
	cpumask_var_t wq_mask;
	cpumask_t *unbound_cpumask;
	cpumask_t *lwkcpus = this_cpu_ptr(&lwkcpus_mask);

	/* Get unbound mask from the workqueue and lock the workqueue pool */
	unbound_cpumask = workqueue_get_unbound_cpumask();
	/* Save the unbound mask for future restoration */
	cpumask_copy(saved_wq_mask, unbound_cpumask);
	/* Release the lock on the workqueue pool */
	workqueue_put_unbound_cpumask();

	if (alloc_cpumask_var(&wq_mask, GFP_KERNEL)) {
		int rc;

		/* Generate a mask of all Linux CPUs excluding lwk CPUs */
		cpumask_andnot(wq_mask, cpu_possible_mask, lwkcpus);
		rc = workqueue_set_unbound_cpumask(wq_mask);
		if (!rc)
			pr_info("mOS-sched: set unbound workqueue cpumask to %*pbl\n",
					cpumask_pr_args(wq_mask));
		else
			mos_ras(MOS_SCHEDULER_WARNING,
				"%s: Failed setting unbound workqueue cpumask. rc=%d",
				__func__, rc);
		free_cpumask_var(wq_mask);
	} else
		mos_ras(MOS_SCHEDULER_WARNING,
			"%s: CPU mask allocation failure.", __func__);

	probe_mwait_capabilities();

	for_each_possible_cpu(i) {
		struct rq *rq;

		rq = cpu_rq(i);

		/* If CPU offlining is inlined, we do the init
		 * for LWK CPUS only after offlining the core */
		if (!cpumask_test_cpu(i, lwkcpus)) {
			init_mos_rq(rq);
			/* Initialization seen before turning on an lwkcpu */
			smp_mb();
			rq->lwkcpu = 0;
		}
	}

	/* Initialize the utility group key table */
	memset(&util_grp, 0, sizeof(struct util_group));

	return 0;
}

/*
 * Activate LWK CPUs after they have been prepared for LWK use
 */
int mos_sched_activate(cpumask_var_t new_lwkcpus)
{
	int lwkcpu;

	lwksched_topology_init();
	timer_init(new_lwkcpus);

	/* Create the idle tasks on each LWK CPU */
	for_each_cpu(lwkcpu, new_lwkcpus)
		idle_task_prepare(lwkcpu);

	return 0;
}

/*
 * Cleanup when LWK CPUs are being returned to Linux
 */
int mos_sched_deactivate(cpumask_var_t back_to_linux)
{
	int adios;
	struct rq *rq;
	struct mos_rq *mos_rq;
	struct task_struct *idle_task;

	preempt_disable();
	for_each_cpu(adios, back_to_linux) {
		rq = cpu_rq(adios);
		mos_rq = &rq->mos;
		/* Indicate that this is no longer an LWK CPU */
		rq->lwkcpu = 0;
		/*
		 * Make sure lwkcpu=0 is seen before the kick and
		 * before any kthreads are awoken during the offlining
		 * actions. The pairing is with rmb barriers in the
		 * mos_idle_main,  try_to_wake_up, and schedule.
		 */
		smp_mb();
		/* Force each mos idle thread to exit */
		idle_task = mos_rq->idle;
		if (idle_task) {
			/* Kick idle thread to re-evaluate rq->lwkcpu */
			resched_cpu(adios);
			/* Do not continue until we are sure it exited */
			kthread_stop(idle_task);
			mos_rq->idle = NULL;
			mos_rq->idle_pid = 0;
		}
	}
	preempt_enable();

	return 0;
}

/*
 * Exit scheduler for returning CPUs back to Linux
 */
int mos_sched_exit(void)
{
	int cpu, rc;
	int total_guests = 0;
	int total_givebacks = 0;

	for_each_possible_cpu(cpu) {
		struct mos_rq *mos = &cpu_rq(cpu)->mos;

		total_guests += mos->stats.guests;
		total_givebacks += mos->stats.givebacks;

		free_cpumask_var(mos->reserved_cpus);
	}
	pr_info("mOS-sched: Giving back %d of %d assimilated tasks.\n",
				total_givebacks, total_guests);

	rc = workqueue_set_unbound_cpumask(saved_wq_mask);

	if (!rc)
		pr_info("mOS-sched: Restored unbound workqueue cpumask to %*pbl\n",
					cpumask_pr_args(saved_wq_mask));

	else
		mos_ras(MOS_SCHEDULER_WARNING,
			"%s: Failed setting unbound workqueue cpumask. rc=%d",
				__func__, rc);
	return 0;
}

static int placement_conflict(unsigned int place, unsigned int behavior,
						unsigned long location_key)
{
	unsigned int rqst, count;

	for (rqst = place & PLACEMENT_CONFLICTS, count = 0; rqst; rqst >>= 1) {
		if (count)
			/* Still in the loop so there is another bit on */
			return 1;
		count += rqst & 1;
	}
	/* We can never honor exclusive placement on a Linux CPU. Disallow the
	 * the attempted request.
	 */
	if ((behavior & MOS_CLONE_ATTR_EXCL) &&
	    (place & MOS_CLONE_ATTR_FWK_CPU))
		return 1;
	/* We do not support combined use of a location key and explicit
	 * memory domain specification.
	 */
	if (location_key && (place & MOS_CLONE_ATTR_USE_NODE_SET))
		return 1;
	return 0;
}

/* Copy a node mask from user space. */
static int get_nodes(nodemask_t *nodes, const unsigned long __user *nmask,
		     unsigned long maxnode)
{
	unsigned long k;
	unsigned long nlongs;
	unsigned long endmask;

	--maxnode;
	nodes_clear(*nodes);
	if (maxnode == 0 || !nmask)
		return 0;
	if (maxnode > PAGE_SIZE*BITS_PER_BYTE)
		return -EINVAL;

	nlongs = BITS_TO_LONGS(maxnode);
	if ((maxnode % BITS_PER_LONG) == 0)
		endmask = ~0UL;
	else
		endmask = (1UL << (maxnode % BITS_PER_LONG)) - 1;

	/*
	 * When the user specified more nodes than supported just check
	 * if the non supported part is all zero.
	 */
	if (nlongs > BITS_TO_LONGS(MAX_NUMNODES)) {
		if (nlongs > PAGE_SIZE/sizeof(long))
			return -EINVAL;
		for (k = BITS_TO_LONGS(MAX_NUMNODES); k < nlongs; k++) {
			unsigned long t;

			if (get_user(t, nmask + k))
				return -EFAULT;
			if (k == nlongs - 1) {
				if (t & endmask)
					return -EINVAL;
			} else if (t)
				return -EINVAL;
		}
		nlongs = BITS_TO_LONGS(MAX_NUMNODES);
		endmask = ~0UL;
	}

	if (copy_from_user(nodes_addr(*nodes), nmask,
			   nlongs*sizeof(unsigned long)))
		return -EFAULT;
	nodes_addr(*nodes)[nlongs-1] &= endmask;
	return 0;
}

SYSCALL_DEFINE5(mos_set_clone_attr,
		struct mos_clone_attr __user *, attrib,
		unsigned long, max_nodes,
		unsigned long __user *, user_nodes,
		struct mos_clone_result __user *, result,
		unsigned long, location_key)
{
	int rc;
	struct mos_clone_attr lp;
	struct mos_clone_hints *hints = &current->mos.clone_hints;

	if (!is_mostask())
		return -EINVAL;

	if (unlikely(copy_from_user(&lp, attrib,
			sizeof(struct mos_clone_attr))))
		/* Could not read the clone attributes from user */
		return -EFAULT;

	if (unlikely(lp.size != sizeof(struct mos_clone_attr)))
		/* Interface structure size mismatch between user and kernel */
		return -EINVAL;

	if ((rc = get_nodes(&hints->nodes, user_nodes, max_nodes)))
		/* Error reading the user node mask */
		return rc;

	if (unlikely(lp.flags & MOS_CLONE_ATTR_CLEAR)) {
		/* Clear all previously saved clone attributes */
		trace_mos_clone_attr_cleared(hints->behavior, hints->location);
		hints->flags = 0;
		hints->behavior = 0;
		hints->location = 0;
		hints->key = 0;
		nodes_clear(hints->nodes);
		hints->result = NULL;
		return 0;
	}
	if (placement_conflict(lp.placement, lp.behavior, location_key))
		/* Conflicting placement directives */
		return -EINVAL;

	if (lp.placement & MOS_CLONE_ATTR_USE_NODE_SET) {
		if (nodes_empty(hints->nodes))
			/* No nodes specified in node mask */
			return -EINVAL;
	}
	if ((unlikely(lp.behavior & MOS_CLONE_ATTR_HPRIO) &&
	    (lp.behavior & MOS_CLONE_ATTR_LPRIO)))
		/* Conflicting behavior attributes */
		return -EINVAL;
	if (lp.placement & MOS_CLONE_ATTR_FABRIC_INT) {
		/* Force placement on FWK CPUs for fabric interrupt request */
		lp.placement |= MOS_CLONE_ATTR_FWK_CPU;
	}
	if ((lp.placement & MOS_CLONE_ATTR_LWK_CPU) &&
	    (lp.placement & MOS_CLONE_ATTR_FWK_CPU)) {
		/* Cannot be on both a FWK and LWK CPU */
		return -EINVAL;
	}
	if (location_key)
		/* Store the key for location grouping */
		hints->key = location_key;

	if (result) {
		struct mos_clone_result result_init;

		result_init.behavior = lp.behavior ?
					MOS_CLONE_BEHAVIOR_REQUESTED : 0;
		result_init.placement = lp.placement ?
					MOS_CLONE_PLACEMENT_REQUESTED : 0;

		if (copy_to_user(result, &result_init,
			sizeof(struct mos_clone_result)))
			/* Could not initialize the clone attribute results */
			return -EFAULT;
	}
	/*
	 * Pass hints to the next clone syscall. We will
	 * process this information in task_fork_mos()
	 */
	hints->flags = lp.flags;
	hints->behavior = lp.behavior;
	hints->location = lp.placement;
	hints->result = result;

	trace_mos_clone_attr_active(hints->behavior, hints->location);

	return 0;
}

SYSCALL_DEFINE4(mos_mwait,
		enum mos_mwait_sleep, sleep_level,
		unsigned long __user *, loc,
		unsigned long, previous,
		unsigned int, timeout_msecs)
{
	unsigned int mwait_sleep;
	unsigned long ecx = 1; /* mwait break on interrupt */
	unsigned long eax;
	unsigned long now;
	unsigned long expire_time;
	unsigned int cpu;
	struct rq *rq;
	struct mos_rq *mos_rq;
	long rc = 0;

	if (!is_mostask())
		return -EINVAL;
	switch (sleep_level) {
	case mos_mwait_sleep_normal:
		mwait_sleep = shallow_sleep_mwait;
		break;
	case mos_mwait_sleep_deep:
		mwait_sleep = deep_sleep_mwait;
		break;
	default:
		return -EINVAL;
	};
	preempt_disable();
	cpu = smp_processor_id();
	rq = cpu_rq(cpu);
	if (!rq->lwkcpu) {
		preempt_enable();
		return -EINVAL;
	}
	mos_rq = &rq->mos;
	expire_time = jiffies + msecs_to_jiffies(timeout_msecs);
	mos_rq->api_timeout = 0;
	if (timeout_msecs)
		mod_timer(&mos_rq->api_timer, expire_time);
	eax = MWAIT_HINT(mwait_sleep);
	if (unlikely(get_user(now, loc)))
		rc = -EFAULT;
	else if (likely(now == previous)) {
		for (;;) {
			if (user_access_begin(loc, 64)) {
				__monitor((void *)loc, 0, 0);
				user_access_end();
				/* Must re-test after monitor is set */
				if (unlikely(__get_user(now, loc))) {
					rc = -EFAULT;
					break;
				}
				if (likely(now == previous)) {
					trace_mos_mwait_api_entry(ecx, eax);
					__mwait(eax, ecx);
					rc++;
					trace_mos_mwait_api_exit(ecx, eax);
					if (unlikely(__get_user(now, loc))) {
						rc = -EFAULT;
						break;
					}
					if (now != previous)
						break;
					if (unlikely(signal_pending(current))) {
						rc = -EINTR;
						break;
					}
					cond_resched();
				} else
					break;
				if (mos_rq->api_timeout) {
					/* Return errno if timed-out waiting */
					rc = -EBUSY;
					break;
				}
			} else
				rc = -EFAULT;
		}
	}
	if (timeout_msecs && !mos_rq->api_timeout)
		/* note: del_timer() is tolerant if timeout occurs here */
		del_timer(&mos_rq->api_timer);

	preempt_enable();
	return rc;
}

/*
 * The following are the class functions called from the Linux core scheduler.
 * These interfaces are called when the mOS tasks interface with the Linux
 * scheduler.
 */

/*
 * Resistance is futile, you will be assimilated. When a task is enqueued
 * to an LWK CPU, it will be taken over by the mOS scheduler. The
 * scheduler class of the task will be changed to be the scheduling class
 * of the mOS scheduler. The task will abide by the scheduling rules of
 * the mOS scheduler from this point forward. We surface the existing
 * SCHED_FIFO policy for our mOS class in order to keep the runtime and tools
 * happy. Since the mOS class behaviors are very close to the SCHED_FIFO
 * behaviors, this policy is a natural fit. In the future when we support
 * time preemption, we will surface the SCHED_RR policy to represent this
 * behavior.
 */
void assimilate_task_mos(struct rq *rq, struct task_struct *p)
{
	struct mos_process_t *mosp;

	/*
	 * If this task has already been assimilated, and we are on an
	 * lwkcpu, return. This should be the most common path through
	 * this function after the app has been launched.
	 */
	if (likely(p->mos.assimilated)) {
		if (likely(rq->lwkcpu))
			return;
		else if (unlikely((p->mos.thread_type ==
						mos_thread_type_guest))) {
			/* LWK CPUs are likely being returned to Linux due to
			 * the destruction of the LWK partition.
			 * Another possibility is a rogue kthread that was
			 * affinitized to a LWK CPU and now is affinitized to
			 * a Linux CPU. We need to give this assimilated Linux
			 * kthread back to the Linux scheduler. We already
			 * hold the runqueue lock  and we know we are at the
			 * point just prior to calling the enqueue_task method
			 * on the scheduler class. It is safe to change the
			 * scheduling class back to the task's original class.
			 */
			p->sched_class = p->mos.orig_class;
			p->policy = p->mos.orig_policy;
			p->mos.assimilated = 0;
			/* Is this an mOS idle thread exiting */
			if (p->normal_prio != MOS_IDLE_PRIO) {
				rq->mos.stats.givebacks++;
				trace_mos_giveback_thread(p);
			}
		}
	}
	if (!rq->lwkcpu)
		return;
	/*
	 * If this is a new mOS process, convert it. This flow will be enterred
	 * when an mos process is being launched on an LWK core for the first
	 * time.
	 */
	mosp = p->mos_process;
	if (mosp) {
		p->policy = mosp->enable_rr ? SCHED_RR : SCHED_FIFO;
		p->prio = MOS_DEFAULT_PRIO;
		p->normal_prio = MOS_DEFAULT_PRIO;
		p->rt_priority = MOS_DEFAULT_USER_PRIO;
		p->sched_class = &mos_sched_class;
		p->mos.assimilated = 1;
		p->mos.thread_type = mos_thread_type_normal;
		p->mos.time_slice = p->mos.orig_time_slice =
			mosp->enable_rr ? mosp->enable_rr : MOS_TIMESLICE;

		trace_mos_assimilate_launch(p);

		return;
	}
	/*
	 * For now, let these classes enter on their own queues. We will
	 * decide how to best deal with these classes at a later time.
	 */
	else if ((p->sched_class == &stop_sched_class) ||
	    (p->sched_class == &idle_sched_class)) {
		return;
	}
	/*
	 * Handle the other tasks that are trying to run on our
	 * LWK CPUs. If they run on our CPUs then they must play by
	 * our rules.
	 */
	if ((strncmp(p->comm, "ksoftirqd", 9)) &&
	    (strncmp(p->comm, "cpuhp", 5)) &&
	    (strncmp(p->comm, "mos_idle", 8))) {
		/* Un-expected task. Warn and continue with assimilation */
		mos_ras(MOS_SCHEDULER_WARNING,
			"%s: Unexpected assimilation of task %s. Cpus_allowed: %*pbl",
			__func__, p->comm, cpumask_pr_args(p->cpus_ptr));
	}
	p->mos.orig_class = p->sched_class;
	p->mos.orig_policy = p->policy;

	if ((p->sched_class == &dl_sched_class) ||
	    (p->sched_class == &rt_sched_class) ||
	    (p->sched_class == &fair_sched_class)) {
		p->mos.assimilated = 1;
	} else {
		mos_ras(MOS_SCHEDULER_WARNING,
			"%s: Unrecognized scheduling class. Policy=%d",
			__func__, p->policy);
	}
	if (p->mos.assimilated) {
		p->sched_class = &mos_sched_class;
		p->mos.time_slice = p->mos.orig_time_slice = MOS_TIMESLICE;
		if (p == rq->mos.idle) {
			p->mos.thread_type = mos_thread_type_idle;
			trace_mos_assimilate_idle(p);
		} else {
			p->mos.thread_type = mos_thread_type_guest;
			rq->mos.stats.guests++;
			trace_mos_assimilate_guest(p);
		}
	}
}

/*
 * Update the current task's runtime statistics. Skip current tasks that
 * are not in our scheduling class.
 */
static void update_curr_mos(struct rq *rq)
{
	struct task_struct *curr = rq->curr;
	u64 delta_exec;

	if (curr->sched_class != &mos_sched_class)
		return;
	if (curr->mos.thread_type == mos_thread_type_idle)
		return;

	delta_exec = rq_clock_task(rq) - curr->se.exec_start;
	if (unlikely((s64)delta_exec <= 0))
		return;

	schedstat_set(curr->stats.exec_max,
		      max(curr->stats.exec_max, delta_exec));

	curr->se.prev_sum_exec_runtime = curr->se.sum_exec_runtime;

	curr->se.sum_exec_runtime += delta_exec;

	curr->se.exec_start = rq_clock_task(rq);
}

static void
enqueue_task_mos(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_mos_entity *mos_se = &p->mos;
	struct mos_rq *mos_rq = mos_rq_of_rq(rq);
	struct mos_prio_array *array = &mos_rq->active;
	int qindex = mos_rq_index(p->prio);
	struct list_head *queue = array->queue + qindex;

	if (flags & ENQUEUE_HEAD)
		list_add(&mos_se->run_list, queue);
	else
		list_add_tail(&mos_se->run_list, queue);
	__set_bit(qindex, array->bitmap);

	mos_rq->mos_nr_running++;

	if (mos_rq->mos_nr_running > mos_rq->stats.max_running)
		mos_rq->stats.max_running = mos_rq->mos_nr_running;

	if (p->policy == SCHED_RR) {
		/* Are we trasitioning into an overcommmitted condition */
		if (mos_rq->rr_nr_running++ == 1)
			/* timestamp when we became overcommitted */
			mos_rq->tstamp_overcommitted = sched_clock();
	}

	add_nr_running(rq, 1);

}

static void dequeue_task_mos(struct rq *rq, struct task_struct *p, int flags)
{
	struct sched_mos_entity *mos_se = &p->mos;
	struct mos_rq *mos_rq = mos_rq_of_rq(rq);
	struct mos_prio_array *array = &mos_rq->active;
	int qindex = mos_rq_index(p->prio);

	/* If this is the mOS idle thread, do not dequeue */
	if (p->mos.thread_type != mos_thread_type_idle) {

		update_curr_mos(rq);

		list_del_init(&mos_se->run_list);
		if (list_empty(array->queue + qindex))
			__clear_bit(qindex, array->bitmap);

		mos_rq->mos_nr_running--;

		sub_nr_running(rq, 1);

		if (p->policy == SCHED_RR)
			if (mos_rq->rr_nr_running-- == 2)
				mos_rq->tstamp_overcommitted = 0;
	}
}

static void requeue_task_mos(struct rq *rq, struct task_struct *p, int head)
{
	struct sched_mos_entity *mos_se = &p->mos;
	struct mos_rq *mos_rq = mos_rq_of_rq(rq);
	int qindex = mos_rq_index(p->prio);

	if (on_mos_rq(mos_se)) {
		struct mos_prio_array *array = &mos_rq->active;
		struct list_head *queue = array->queue + qindex;

		if (head)
			list_move(&mos_se->run_list, queue);
		else
			list_move_tail(&mos_se->run_list, queue);
	}
}

static void yield_task_mos(struct rq *rq)
{
	requeue_task_mos(rq, rq->curr, 0);
}


static void
check_preempt_curr_mos(struct rq *rq, struct task_struct *p, int flags)
{
	if (mos_rq_index(p->prio) < mos_rq_index(rq->curr->prio)) {
		resched_curr(rq);
		return;
	}
}

static struct task_struct *
pick_next_task_mos(struct rq *rq)
{
	struct task_struct *p;
	struct mos_rq *mos_rq = &rq->mos;
	struct sched_mos_entity *mos_se;
	struct mos_prio_array *array = &mos_rq->active;
	struct list_head *queue;
	int idx;

	if (unlikely(!mos_rq->mos_nr_running))
		return NULL;

	idx = sched_find_first_bit(array->bitmap);
	BUG_ON(idx > MOS_RQ_MAX_INDEX);

	queue = array->queue + idx;
	mos_se = list_entry(queue->next, struct sched_mos_entity, run_list);
	BUG_ON(!mos_se);

	p = mos_task_of(mos_se);

	if (unlikely(p->mos.thread_type == mos_thread_type_idle))
		schedstat_inc(rq->sched_goidle);
	else
		p->se.exec_start = rq_clock_task(rq);

	if (unlikely(p->mos.thread_type == mos_thread_type_guest))
		mos_rq->stats.guest_dispatch++;

	return p;
}

static void put_prev_task_mos(struct rq *rq, struct task_struct *p)
{
	if (likely(p->mos.thread_type != mos_thread_type_idle))
		update_curr_mos(rq);
}

#ifdef CONFIG_SMP

static int
select_task_rq_mos(struct task_struct *p, int cpu, int wake_flags)
{
	int result;
	int tcpu, ncpu = cpu;

	if (unlikely(!p->mos_process))
		return cpu;

	if (likely(wake_flags & SD_BALANCE_WAKE)) {
		tcpu = select_main_thread_home(p);
		if (tcpu >= 0)
			ncpu = tcpu;
		else if (likely((p->mos.cpu_home >= 0) &&
		    (cpumask_test_cpu(p->mos.cpu_home, p->cpus_ptr))))
			ncpu = p->mos.cpu_home;
	}
	/* Is this a clone operation */
	else if (wake_flags & SD_BALANCE_FORK) {
		/* Find the best cpu candidate for the mOS clone operation */
		ncpu = select_cpu_candidate(p, COMMIT_MAX);
		/* If a negative value is returned, use original CPU */
		if (ncpu < 0)
			ncpu = cpu;

		trace_mos_clone_cpu_assign(ncpu, p);

		return ncpu;
	} else {
		tcpu = select_main_thread_home(p);
		if (tcpu >= 0)
			ncpu = tcpu;
	}
	/* Are we waking on the LWK side? */
	if (likely((cpumask_intersects(p->cpus_ptr,
					this_cpu_ptr(&lwkcpus_mask))))) {
		/* Primary wakeup path */
		if (likely(cpumask_test_cpu(ncpu, p->cpus_ptr))) {
			if (unlikely(is_overcommitted(ncpu))) {
				/* Look for a better candidate */
				result = select_cpu_candidate(p, 0);
				if (result >= 0)
					ncpu = result;
			}
		} else {
			/* Need to select a cpu in the allowed mask */
			ncpu = select_cpu_candidate(p, COMMIT_MAX);
			/* If a negative value is returned, use original CPU */
			if (ncpu < 0)
				ncpu = cpu;
		}
	}
	return ncpu;
}

static void set_cpus_allowed_mos(struct task_struct *p,
				const struct cpumask *new_mask)
{
	cpumask_copy(&p->cpus_mask, new_mask);
	p->nr_cpus_allowed = cpumask_weight(new_mask);
}

static void rq_online_mos(struct rq *rq)
{
	/* Managed by mOS scheduler */
}

static void rq_offline_mos(struct rq *rq)
{
	/* Managed by mOS scheduler */
}

static void task_woken_mos(struct rq *rq, struct task_struct *p)
{
	/* Managed by mOS scheduler. No pushing. */
}

static void switched_from_mos(struct rq *rq, struct task_struct *p)
{
	/* Managed by mOS scheduler. No pulling */
}

static int balance_mos(struct rq *rq, struct task_struct *p, struct rq_flags *rf)
{
	return sched_stop_runnable(rq) || nr_running_mos(rq);
}

#endif

static void set_next_task_mos(struct rq *rq, struct task_struct *p, bool first)
{
	p->se.exec_start = rq_clock_task(rq);
}

/*
 * With NOHZ_FULL active, calls to the following function may be from a
 * Linux CPU targeting an LWK CPU's run-queue. These remote calls will be made
 * from an unbound kworker task.
 */
static void task_tick_mos(struct rq *rq, struct task_struct *p, int queued)
{
	struct sched_mos_entity *mos_se = &p->mos;

	update_curr_mos(rq);
	/*
	 * Only trace conditions that are of interest. We do not want to
	 * flood the trace buffers with entries we do not care about
	 */
	if (rq->lwkcpu && /* Is the target rq associated with an LWK CPU */
	    rq->mos.owner /* Is there an lwk proc that has this CPU reserved */
	    ) {
		rq->mos.stats.timer_pop++;
		trace_mos_timer_tick(p, cpu_of(rq));
	}
	/*
	 * mOS tasks with timesliced enabled is essentially
	 * a SCHED_RR behavior. We will be using the SCHED_RR
	 * value in the policy field to distinguish this from
	 * the normal non-timesliced behavior which is
	 * represented by the SCHED_FIFO value in the policy
	 * field of the mOS task. Note that the mOS Idle task will never present
	 * itself as SCHED_RR
	 */
	if (rq->lwkcpu && p->policy != SCHED_RR)
		return;

	if (--p->mos.time_slice)
		return;

	if ((mos_se->run_list.prev != mos_se->run_list.next) &&
	    (rq->mos.balancer == BalancerType_Push))
		balance_push(rq);

	p->mos.time_slice = p->mos.orig_time_slice;

	/*
	 * Optionally balance and requeue to the end of queue if we are not
	 * the only element on the queue.
	 */
	if (mos_se->run_list.prev != mos_se->run_list.next) {
		requeue_task_mos(rq, p, 0);
		resched_curr(rq);
	}
}

static unsigned int
get_rr_interval_mos(struct rq *rq, struct task_struct *task)
{
	/*
	 * mOS tasks with timesliced enabled is essentially
	 * a SCHED_RR behavior. We will be using the SCHED_RR
	 * value in the policy field to distinguish this from
	 * the normal non-timesliced behavior which is
	 * represented by the SCHED_FIFO value in the policy
	 * field of the mOS task.
	 */
	if (task->policy == SCHED_RR)
		return task->mos.orig_time_slice;
	else
		return 0;
	return 0;
}

static void
prio_changed_mos(struct rq *rq, struct task_struct *p, int oldprio)
{
	if (!task_on_rq_queued(p))
		return;

	if (rq->curr == p) {
		/* Reschedule on drop of prio */
		if (mos_rq_index(oldprio) < mos_rq_index(p->prio))
			resched_curr(rq);
	} else {
		/*
		 * This task is not running, but if it is
		 * greater than the current running task
		 * then reschedule.
		 */
		if (mos_rq_index(p->prio) < mos_rq_index(rq->curr->prio))
			resched_curr(rq);
	}
}

static void switched_to_mos(struct rq *rq, struct task_struct *p)
{
	if (task_on_rq_queued(p) && rq->curr != p) {
		if (mos_rq_index(p->prio) < mos_rq_index(rq->curr->prio))
			resched_curr(rq);
	}
}

/*
 * Called on fork with the child task as argument from the parent's context
 *  - child not yet on the tasklist
 *  - preemption disabled
 */
static void task_fork_mos(struct task_struct *p)
{
	struct mos_process_t *proc = current->mos_process;
	struct mos_clone_hints *clone_hints = &current->mos.clone_hints;

	p->prio = current->prio;
	p->normal_prio = current->prio;

	/* We need to remove the commit placed on the CPU that called clone.
	 * This occurred in core.c->sched_fork->__select_task_cpu. This needs
	 * to be done prior to selecting the target CPU for this new thread
	 * which occurs in core.c->wake_up_new_task.
	 */
	uncommit_cpu(p);

	/*
	 * We need to set the cpus allowed mask appropriately. If this is
	 * a normal thread creation, we use the cpus_allowed mask provided to
	 * this lwk process. If this is a utility thread, we set a cpus_allowed
	 * mask to the utility thread that we assign. If this is a
	 * fork of a full process (not a thread within our thread group) then
	 * we will set the cpus_allowed mask to the original Linux mask that
	 * this process had when it existed in the Linux world.
	 */
	if (p->mos.clone_flags & CLONE_THREAD) {
		int thread_count =
			atomic_inc_return(&proc->threads_created);

		/*
		 * If the clone hints are telling us this is supposed to
		 * be a utility thread, or if the YOD option to heuristically
		 * assign utility threads is set, then go select an appropriate
		 * CPU for the thread.
		 */
		if (likely((thread_count > proc->num_util_threads) &&
			   !(clone_hints->flags & MOS_CLONE_ATTR_UTIL))) {
			/*
			 *  We are placing a thread within our LWK process. Set
			 *  up the appropriate cpus_allowed mask
			 */
			set_cpus_allowed_mos(p, proc->lwkcpus);

			/*
			 * If needed, make room for this worker thread so that
			 * it can run alone on an LWK CPU.
			 */
			push_utility_threads(p);

		} else {
			set_utility_cpus_allowed(p, thread_count, clone_hints);
		}
	} else {
		/*
		 * This is a fork of a full process, we will default the
		 * scheduling policy and priority to the default Linux
		 * values.
		 */
		move_to_linux_scheduler(p, 0);

		/*
		 * We set cpus_allowed mask to be the original mask prior to
		 * running on the LWK CPUs.
		 */

		set_cpus_allowed_mos(p, proc->original_cpus_allowed);
	}
	/* Cleanup the clone hints */
	clear_clone_hints(p);
}

void mos_set_task_cpu(struct task_struct *p, int new_cpu)
{
	if (cpu_rq(new_cpu)->lwkcpu &&
	    p->mos_process &&
	    new_cpu != p->mos.cpu_home) {
		/* Release a previous commit if it exists */
		uncommit_cpu(p);
		/* Commit to the new cpu */
		commit_cpu(p, new_cpu);
	}
}
/*
 * Called when the cpus_allowed mask is being changed and
 * a new CPU must be selected for a migration.
 */
int mos_select_next_cpu(struct task_struct *p, const struct cpumask *new_mask)
{
	/*
	 * If this is the initial thread of the process and if the CPU
	 * it was originally launched on is currently uncommitted and it's
	 * affinity mask now contains this CPU, use it. This covers the
	 * case when OMP does its topology investigation to find the available
	 * CPUs. We want the initial thread to return to its original CPU
	 * when the affinity mask is set back to the full mask.
	 */
	int cpu = select_main_thread_home(p);

	if (cpu >= 0)
		return cpu;
	/*
	 * If current cpu is in the new mask, use it.
	 */
	if (cpumask_test_cpu(task_cpu(p), new_mask))
		return task_cpu(p);
	/*
	 * Is there a valid committed LWK CPU already established for
	 * this task and is this CPU is in the new cpus allowed mask
	 */
	if ((p->mos.cpu_home >= 0) &&
	    (cpumask_test_cpu(p->mos.cpu_home, new_mask)))
		return p->mos.cpu_home;
	/*
	 * Are we moving to an LWK CPU and no committed CPU home
	 * has been established yet
	 */
	if (cpumask_subset(new_mask, p->mos_process->lwkcpus)) {
		cpu = select_cpu_candidate(p, COMMIT_MAX);
		if (unlikely(cpu < 0)) {
			mos_ras(MOS_SCHEDULER_WARNING,
			    "%s: Maximum commit level reached.",
			    __func__);
			cpu = cpumask_first(new_mask);
			if (unlikely((cpu == nr_cpu_ids))) {
				cpu = 0;
				mos_ras(MOS_SCHEDULER_WARNING,
				    "%s: No CPUs in the new LWK CPU mask.",
				    __func__);
			}
		}
		return cpu;
	}
	/* This must be a utility thread being moved to a Linux CPU */
	return cpumask_any_and(cpu_online_mask, new_mask);
}

/*
 * Called from the core scheduler for a wakeup when an un-assimilated
 * mos_process is detected (i.e. not running under that mos scheduling
 * class yet). This condition indicates that a new mos process is being
 * launched for the first time on the LWK CPUs.
 */
int mos_select_cpu_candidate(struct task_struct *p, int cpu)
{
	int ncpu = cpu;

	/*
	 * Test to see if the current CPU is in the allowed mask. If it is
	 * not in the current mask, then we are in the migration wakeup
	 * after the setaffinty was done to launch the new mos process.
	 */
	if (likely(!cpumask_test_cpu(cpu, p->cpus_ptr))) {
		/*
		 * Verify that the cpus_allowed mask is in the LWK world.
		 * This is very likely true assuming we have been called
		 * under the expected conditions
		 */
		if (likely(cpumask_subset(p->cpus_ptr,
					  p->mos_process->lwkcpus))) {
			ncpu = select_cpu_candidate(p, COMMIT_MAX);
			if (unlikely(ncpu < 0)) {
				mos_ras(MOS_SCHEDULER_WARNING,
				    "%s: Maximum commit level reached.",
				    __func__);
				ncpu = cpumask_first(p->cpus_ptr);
				if (unlikely(cpu == nr_cpu_ids)) {
					ncpu = 0;
					mos_ras(MOS_SCHEDULER_WARNING,
					    "%s: No CPUs in the new LWK CPU mask.",
					    __func__);
				}
			}
		}
	}
	return ncpu;
}

/* mOS scheduler class function table */
const struct sched_class mos_sched_class 
	__attribute__((section("__mos_sched_class"))) = {
	.enqueue_task		= enqueue_task_mos,
	.dequeue_task		= dequeue_task_mos,
	.yield_task		= yield_task_mos,
	.check_preempt_curr	= check_preempt_curr_mos,
	.pick_next_task		= pick_next_task_mos,
	.put_prev_task		= put_prev_task_mos,

#ifdef CONFIG_SMP
	.balance		= balance_mos,
	.select_task_rq		= select_task_rq_mos,
	.set_cpus_allowed       = set_cpus_allowed_common,
	.rq_online              = rq_online_mos,
	.rq_offline             = rq_offline_mos,
	.task_woken		= task_woken_mos,
	.switched_from		= switched_from_mos,
#endif
	.set_next_task          = set_next_task_mos,
	.task_tick		= task_tick_mos,
	.get_rr_interval	= get_rr_interval_mos,
	.prio_changed		= prio_changed_mos,
	.switched_to		= switched_to_mos,
	.update_curr		= update_curr_mos,
	.task_fork		= task_fork_mos,
};

