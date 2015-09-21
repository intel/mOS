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

#include <stdarg.h>
#include <linux/mos.h>
#include <linux/ftrace.h>
#include <linux/compiler.h>
#include <linux/hrtimer.h>
#include <linux/cpumask.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/vtime.h>
#include <linux/cacheinfo.h>
#include <linux/topology.h>

#define CREATE_TRACE_POINTS
#include <trace/events/mos.h>

/*
 * default timeslice is 100 msecs. Used when an mOS task has been enabled for
 * timeslicing.
 */
#define MOS_TIMESLICE		(100 * HZ / 1000)
#define COMMIT_NOLIMIT		INT_MAX		/* No limit */

enum MatchType {FirstAvail = 0,
		SameCore,
		SameL1,
		SameL2,
		SameL3,
		SameNuma,
		OtherCore,
		OtherL1,
		OtherL2,
		OtherL3,
		OtherNuma,
		};

static inline struct task_struct *mos_task_of(struct sched_mos_entity *mos_se)
{
	return container_of(mos_se, struct task_struct, mos);
}

static inline struct mos_rq *mos_rq_of_rq(struct rq *rq)
{
	return &rq->mos;
}

static void sched_stats_init(struct mos_sched_stats *stats)
{
	memset(stats, 0, sizeof(struct mos_sched_stats));
}

static void init_mos_topology(struct rq *rq)
{
	struct cpu_cacheinfo *cci;
	struct cacheinfo *ci;
	int i;
	int cpu;
	struct mos_rq *mos_rq = &rq->mos;

	/* Get the numa node identifier associated with this CPU */
	mos_rq->numa_id = cpu_to_node(rq->cpu);

	cpu = cpumask_first(topology_sibling_cpumask(rq->cpu));
	if (cpu < nr_cpu_ids) {
		/*
		 * Generate a unique core identifier value equal to the first
		 * CPUID in the list of CPUs associated with this core.
		 */
		mos_rq->core_id = cpu;

		/* Generate a hyperthread index value for this CPU */
		for (i = 0; cpu != rq->cpu; i++)
			cpu = cpumask_next(cpu,
				topology_sibling_cpumask(rq->cpu));
		mos_rq->tindex = i;
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
				mos_rq->l1c_id =
					cpumask_first(&ci->shared_cpu_map);
			else if (ci->level == 2)
				mos_rq->l2c_id =
					cpumask_first(&ci->shared_cpu_map);
			else if (ci->level == 3)
				mos_rq->l3c_id =
					cpumask_first(&ci->shared_cpu_map);
		}
	}
}

static void init_mos_rq(struct mos_rq *mos_rq)
{
	struct mos_prio_array *array;
	int i;

	array = &mos_rq->active;
	for (i = 0; i <= MOS_RQ_MAX_INDEX; i++) {
		INIT_LIST_HEAD(array->queue + i);
		__clear_bit(i, array->bitmap);
	}
	/* delimiter for bitsearch: */
	__set_bit(MOS_RQ_MAX_INDEX+1, array->bitmap);

	mos_rq->mos_nr_running = 0;
	mos_rq->rr_nr_running = 0;
	mos_rq->mos_time = 0;
	mos_rq->mos_runtime = 0;
	sched_stats_init(&mos_rq->stats);
	atomic_set(&mos_rq->commit_level, 0);
	/*
	 * Initialize topology fields to indicate not available.
	 * These fields will be set later in the boot after the
	 * topology information has been constructed.
	 */
	mos_rq->core_id = -1;
	mos_rq->l1c_id = -1;
	mos_rq->l2c_id = -1;
	mos_rq->l3c_id = -1;
	mos_rq->tindex = -1;
}



static inline int on_mos_rq(struct sched_mos_entity *mos_se)
{
	return !list_empty(&mos_se->run_list);
}

static int cpu_commit_level(int cpu)
{
	struct mos_rq *mos_rq = &(cpu_rq(cpu)->mos);

	return atomic_read(&mos_rq->commit_level);
}

static void uncommit_cpu(struct task_struct *p)
{
	if (p->mos.cpu_home >= 0) {
		int cpu = p->mos.cpu_home;
		struct mos_rq *mos_rq = &cpu_rq(cpu)->mos;
		int commit = atomic_dec_if_positive(&mos_rq->commit_level);

		p->mos.cpu_home = -1;

		trace_mos_cpu_uncommit(p, cpu, commit);
	}
}

static int commit_cpu(struct task_struct *p, int cpu)
{
	struct mos_rq *mos_rq;
	int commit = 0;

	if (cpu >= 0) {
		mos_rq = &cpu_rq(cpu)->mos;
		commit = atomic_inc_return(&mos_rq->commit_level);
		p->mos.cpu_home = cpu;
		if (commit > mos_rq->stats.max_commit_level)
			mos_rq->stats.max_commit_level = commit;
		trace_mos_cpu_commit(p, cpu, commit);

	}
	return commit;
}

/*
 * Attempt to find a CPU within the commit level limit and affinity
 * matching requested.
 */
static int _select_cpu_candidate(struct task_struct *p,
				int commit_level_limit,
				bool reverse,
				enum MatchType type,
				int id,
				int range)
{
	int cpu, commitment, n;
	struct mos_rq *mos_rq;
	int *cpu_list = p->mos_process->lwkcpus_sequence;
	int fpath = cpumask_equal(&p->cpus_allowed, p->mos_process->lwkcpus);
	int lastindex = (range) ? (range - 1) : p->mos_process->num_lwkcpus - 1;

	/*
	 * Using the lwkcpus_sequence list in the mos_process object, look for
	 * the least committed CPU starting at one end of the list and
	 * and walking sequentially through it.
	 */
	for (commitment = 0; commitment <= commit_level_limit; commitment++) {
		for (n = 0; n <= lastindex; n++) {
			cpu = reverse ? cpu_list[lastindex - n] : cpu_list[n];
			mos_rq = &cpu_rq(cpu)->mos;
			if ((type != FirstAvail) &&
			    ((type == SameNuma && id != mos_rq->numa_id) ||
			     (type == SameCore && id != mos_rq->core_id) ||
			     (type == SameL1 && id != mos_rq->l1c_id) ||
			     (type == SameL2 && id != mos_rq->l2c_id) ||
			     (type == SameL3 && id != mos_rq->l3c_id) ||
			     (type == OtherNuma && id == mos_rq->numa_id) ||
			     (type == OtherCore && id == mos_rq->core_id) ||
			     (type == OtherL1 && id == mos_rq->l1c_id) ||
			     (type == OtherL2 && id == mos_rq->l2c_id) ||
			     (type == OtherL3 && id == mos_rq->l3c_id)
			    ))
				continue;
			if (fpath ||
			    cpumask_test_cpu(cpu, &(p->cpus_allowed))) {
				if (atomic_read(&mos_rq->commit_level) ==
						commitment) {
					trace_mos_cpu_select(p, cpu,
							     commitment,
							     type, id);
					return cpu;
				}
			}
		}
	}
	/* No CPU is available at the requested commitment limit and topology */
	trace_mos_cpu_select_unavail(p, commit_level_limit, type, id);

	return -1;
}

static inline int select_cpu_candidate(struct task_struct *p,
				       int commit_level_limit)
{
	return _select_cpu_candidate(p, commit_level_limit, 0,
				     FirstAvail, 0, 0);
}

static inline int initial_cpu_if_uncommitted(struct task_struct *p)
{
	return _select_cpu_candidate(p, 0, 0, FirstAvail, 0, 1);
}

extern struct rq *sched_context_switch(struct rq *, struct task_struct *,
				       struct task_struct *);

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
		WARN_ONCE(1, "priority = 0x%x", priority);
	}
	return qindex;
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
	struct mos_process_t *mosp = p->mos_process;

	/*
	 * If this task has already been assimilated, return. This should
	 * be the most common path through this function after the app
	 * has been launched. */
	if (likely(p->mos.assimilated))
		return;

	/*
	 * If this is a new mOS process, convert it. This flow will be enterred
	 * when an mos process is being launched on an LWK core for the first
	 * time.
	 */
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
		p->mos.move_syscalls_disable = mosp->move_syscalls_disable;

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
	if ((strncmp(p->comm, "kworker", 7)) &&
	    (strncmp(p->comm, "ksoftirqd", 9)) &&
	    (strncmp(p->comm, "cpuhp", 5)) &&
	    (strncmp(p->comm, "mos_idle", 8))) {
		/*
		 * The systemd-udevd process shows up at boot time on each
		 * of our CPUs and is eventually affinitized to Linux CPUs.
		 * We do not want to assimilate this Linux process since it will
		 * be spending the remainder of its life on Linux CPUs. We exit
		 * before affinitizing this task into the mOS scheduler so that
		 *  we do no disturb system behavior.
		 */
		if (!strncmp(p->comm, "systemd-udevd", 13))
			return;
		/*
		 * Ignore the initial boot task, which is also
		 * the CPU0 idle task. We will be inserting our own
		 * mOS idle tasks on all LWK CPUs after Linux is initialized.
		 */
		if (!strncmp(p->comm, "swapper", 7))
			return;
		/*
		 * Un-expected task. Cut a trace and continue. In the
		 * future we may want to get more aggressive.
		 */
		trace_mos_assimilate_unexpected(p);
		pr_warn("mOS: Unexpected assimilation of task %s. Cpus_allowed: %*pbl\n",
			p->comm, cpumask_pr_args(tsk_cpus_allowed(p)));

	}
	if (p->sched_class == &dl_sched_class) {
		trace_mos_assimilate_deadline(p);
		p->mos.assimilated = 1;
	} else if (p->sched_class == &rt_sched_class) {
		trace_mos_assimilate_rt(p);
		p->mos.assimilated = 1;
	} else if (p->sched_class == &fair_sched_class) {
		trace_mos_assimilate_fair(p);
		p->mos.assimilated = 1;
	} else
		trace_mos_assimilate_unrecognized(p);

	if (p->mos.assimilated) {
		p->sched_class = &mos_sched_class;
		p->mos.time_slice = p->mos.orig_time_slice = MOS_TIMESLICE;
		if (p == rq->mos.idle)
			p->mos.thread_type = mos_thread_type_idle;
		else {
			p->mos.thread_type = mos_thread_type_guest;
			rq->mos.stats.guests++;
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

	schedstat_set(curr->se.statistics.exec_max,
		      max(curr->se.statistics.exec_max, delta_exec));

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

	if (p->policy == SCHED_RR)
		mos_rq->rr_nr_running++;

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
			mos_rq->rr_nr_running--;
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
pick_next_task_mos(struct rq *rq, struct task_struct *prev, struct pin_cookie cookie)
{
	struct task_struct *p;
	struct mos_rq *mos_rq = &rq->mos;
	struct sched_mos_entity *mos_se;
	struct mos_prio_array *array = &mos_rq->active;
	struct list_head *queue;
	int idx;

	if (likely(prev->sched_class == &mos_sched_class))
		update_curr_mos(rq);

	if (unlikely(!mos_rq->mos_nr_running))
		return NULL;

	put_prev_task(rq, prev);

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
	else
		rq_last_tick_reset(rq);
}

#ifdef CONFIG_SMP

static int
select_task_rq_mos(struct task_struct *p, int cpu, int sd_flag, int flags)
{
	int result;
	int ncpu = cpu;

	if (unlikely(!p->mos_process))
		return cpu;

	if (likely(sd_flag == SD_BALANCE_WAKE)) {
		if (likely((p->mos.cpu_home >= 0) &&
		    (cpumask_test_cpu(p->mos.cpu_home, &p->cpus_allowed))))
			ncpu = p->mos.cpu_home;
	}
	/* Is this a clone operation */
	else if (sd_flag == SD_BALANCE_FORK) {

		/* Find the best cpu candidate for the mOS clone operation */
		ncpu = select_cpu_candidate(p, COMMIT_NOLIMIT);

		trace_mos_clone_cpu_assign(ncpu, p);

		return ncpu;
	}
	/* Are we waking on the LWK side? */
	if (likely((cpumask_intersects(&p->cpus_allowed,
					this_cpu_ptr(&lwkcpus_mask))))) {
		/* Primary wakeup path */
		if (likely(cpumask_test_cpu(ncpu, tsk_cpus_allowed(p)))) {
			if (unlikely((cpu_commit_level(ncpu) > 1) )) {
				/* Look for a better candidate */
				result = select_cpu_candidate(p, 0);
				if (result >= 0)
					ncpu = result;
			}
		} else {
			/* Need to select a cpu in the allowed mask */
			ncpu = select_cpu_candidate(p, COMMIT_NOLIMIT);
		}
	}
	return ncpu;
}

static void set_cpus_allowed_mos(struct task_struct *p,
				const struct cpumask *new_mask)
{
	cpumask_copy(&p->cpus_allowed, new_mask);
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

#endif

static void set_curr_task_mos(struct rq *rq)
{
	struct task_struct *p = rq->curr;

	p->se.exec_start = rq_clock_task(rq);

}

static void task_tick_mos(struct rq *rq, struct task_struct *p, int queued)
{
	struct sched_mos_entity *mos_se = &p->mos;

	update_curr_mos(rq);
	if (rq->lwkcpu) {
		rq->mos.stats.timer_pop++;
		trace_mos_timer_tick(p);
	}
	/*
	 * mOS tasks with timesliced enabled is essentially
	 * a SCHED_RR behavior. We will be using the SCHED_RR
	 * value in the policy field to distinguish this from
	 * the normal non-timesliced behavior which is
	 * represented by the SCHED_FIFO value in the policy
	 * field of the mOS task.
	 */
	if (rq->lwkcpu && p->policy != SCHED_RR)
		return;

	if (--p->mos.time_slice)
		return;

	p->mos.time_slice = p->mos.orig_time_slice;

	/*
	 * Requeue to the end of queue if we are not
	 * the only element on the queue.
	 */
	if (mos_se->run_list.prev != mos_se->run_list.next) {
		requeue_task_mos(rq, p, 0);
		resched_curr(rq);
		return;
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

static inline int utility_thread_moveable(void)
{
	return 1;
}
static void set_utility_cpus_allowed(struct task_struct *p, int which_thread)
{

	cpumask_var_t new_mask;
	int util_cpu = -1;
	struct mos_process_t *proc = p->mos_process;
	bool add_to_list = 0;

	/* We are placing a thread on a Utility CPU */
	if (zalloc_cpumask_var(&new_mask, GFP_KERNEL)) {

		/*
		 * Search for an uncommitted CPU in the reverse order
		 * in an attempt to stay away from worker threads
		 */
		util_cpu = _select_cpu_candidate(p, 0, 1, FirstAvail, 0, 0);

		/* Did we find a CPU? */
		if (util_cpu < 0) {
			/* Time to use our shared utility CPU pool */
			int commit;
			struct mos_rq *mos_rq;
			bool found;

			/*
			 * We are sharing utility CPUs with other mos
			 * processes therefore we want to round-robin
			 * the utility threads. Set the policy to
			 * SCHED_RR. We are still in control using our
			 * mos scheduling class.
			 */
			p->policy = SCHED_RR;

			/*
			 * Using the shared utility cpu mask, look for the least
			 * committed CPU starting with the first CPU in the
			 * mask and stepping sequencially through it.
			 */
			for (commit = 0, found = 0; !found; commit++) {
				for_each_cpu(util_cpu, proc->utilcpus) {
					mos_rq = &cpu_rq(util_cpu)->mos;
					if (atomic_read(
					       &mos_rq->commit_level) == commit
							) {
						found = 1;
						break;
					}
				}
			}
		} else if (utility_thread_moveable())
			/*
			 * If this is a moveable util thread, chain
			 * onto the list of movelable utilty threads which are
			 * executing on LWK CPUs. Add to the front of the list.
			 * Since the util threads are allocated from the end of
			 * the sequence list, later when a util thread is
			 * selected for pushing, it will push the CPU that was
			 * next in the sequence for the non-util threads,
			 * thereby preserving the desired allocation sequence
			 */
			add_to_list = 1;

		if (likely((util_cpu >= 0) && (util_cpu < nr_cpu_ids))) {
			cpumask_set_cpu(util_cpu, new_mask);

			/* Set the cpus allowed mask for the utility thread */
			set_cpus_allowed_mos(p, new_mask);
#ifdef CONFIG_MOS_MOVE_SYSCALLS
			/* Keep task where it belongs for syscall return */
			cpumask_copy(&p->mos_savedmask, new_mask);
#endif

			/* Mark this mos thread as a utility thread */
			p->mos.thread_type = mos_thread_type_utility;

			if (add_to_list) {
				/* Grab the utility list lock */
				mutex_lock(&proc->util_list_lock);

				commit_cpu(p, util_cpu);
				list_add(&p->mos.util_list, &proc->util_list);

				/* Unlock the utility list */
				mutex_unlock(&proc->util_list_lock);
			} else
				commit_cpu(p, util_cpu);

			trace_mos_util_thread_assigned(util_cpu);
		} else
			pr_warn("Utility cpu selection failure in %s.\n",
					__func__);
		free_cpumask_var(new_mask);
	} else
		pr_warn("CPU mask allocation failure in %s.\n", __func__);
}

static void push_utility_thread(struct task_struct *p)
{
	struct task_struct *util_thread;
	struct mos_process_t *proc = p->mos_process;
	int cpu;

	/* Are there any uncommitted CPUs remaining */
	cpu = select_cpu_candidate(p, 0);
	if (cpu < 0) {
		/* Grab the utility list lock */
		mutex_lock(&proc->util_list_lock);

		/* Are there any moveable util threads occupying LWKCPUs */
		util_thread = list_first_entry_or_null(&proc->util_list,
							struct task_struct,
							mos.util_list);
		if (util_thread) {
			bool found;
			int util_cpu;
			int commit;
			struct mos_rq *mos_rq;

			cpumask_var_t new_mask;

			/* remove the utility thread from the list */
			list_del(&util_thread->mos.util_list);

			/* find least committed shared utility cpu */
			for (commit = 0, found = 0; !found; commit++) {
				for_each_cpu(util_cpu, proc->utilcpus) {
					mos_rq = &cpu_rq(util_cpu)->mos;
					if (atomic_read(
					       &mos_rq->commit_level) == commit
							) {
						found = 1;
						break;
					}
				}
			}

			/* Move util_thread to util_cpu */
			if (zalloc_cpumask_var(&new_mask, GFP_KERNEL)) {

				int from_cpu = util_thread->mos.cpu_home;

				/* Update the commit counts */
				uncommit_cpu(util_thread);
				commit = commit_cpu(util_thread, util_cpu);

				cpumask_set_cpu(util_cpu, new_mask);
				set_cpus_allowed_ptr(util_thread, new_mask);

				/* Trace the push */
				trace_mos_util_thread_pushed(from_cpu,
							     util_cpu,
							     util_thread,
							     commit);

				free_cpumask_var(new_mask);
			}
	       }
	       mutex_unlock(&proc->util_list_lock);
	}
}

/*
 * Called on fork with the child task as argument from the parent's context
 *  - child not yet on the tasklist
 *  - preemption disabled
 */
static void task_fork_mos(struct task_struct *p)
{
	struct mos_process_t *proc = p->mos_process;

	p->prio = current->prio;
	p->normal_prio = current->prio;
	p->mos.thread_type = mos_thread_type_normal;
	p->mos.cpu_home = -1;

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

		/* NOTE: If clone could tell us that this is supposed to
		 * be a utility thread, this is where we would make that
		 * test and take the else leg to setup the utility
		 * thread CPU
		 */
		if (likely(thread_count > proc->num_util_threads)) {
			/*
			 *  We are placing a thread within our LWK process. Set
			 *  up the appropriate cpus_allowed mask
			 */
			set_cpus_allowed_mos(p, proc->lwkcpus);

			/* Push utility thread off an lwkcpu if needed */
			push_utility_thread(p);

		} else
			set_utility_cpus_allowed(p, thread_count);
	} else {
		/*
		 * This is a fork of a full process, we will default the
		 * scheduling policy and priority to the default Linux
		 * values.
		 */
		p->policy = SCHED_NORMAL;
		p->static_prio = NICE_TO_PRIO(0);
		p->rt_priority = 0;
		p->prio = p->normal_prio = p->static_prio;
		p->se.load.weight =
			sched_prio_to_weight[p->static_prio - MAX_RT_PRIO];
		p->se.load.inv_weight =
			sched_prio_to_wmult[p->static_prio - MAX_RT_PRIO];
		p->sched_class = &fair_sched_class;

		/*
		 * We set cpus_allowed mask to be the original mask prior to
		 * running on the LWK CPUs.
		 */
		set_cpus_allowed_mos(p, proc->original_cpus_allowed);
#ifdef CONFIG_MOS_MOVE_SYSCALLS
		/* Prime the saved mask for the syscall migration mechanism */
		cpumask_copy(&p->mos_savedmask, proc->original_cpus_allowed);
#endif
	}
}

void mos_set_task_cpu(struct task_struct *p, int new_cpu)
{
	if (task_cpu(p) != new_cpu &&
	    cpu_rq(new_cpu)->lwkcpu &&
	    p->mos_process &&
	    new_cpu != p->mos.cpu_home) {
		/* Release a previous commit if it exists */
		uncommit_cpu(p);
		/* Commit to the new cpu */
		commit_cpu(p, new_cpu);
	}
}

/* This is end of the list of functions called by the Linux core scheduler */

/*
 * This is the mOS idle loop.
 */
static int mos_idle_main(void *data)
{
	int cpu = (int)(unsigned long) data;
	struct rq *rq;
	struct mos_rq *mos_rq;

	rq = cpu_rq(cpu);
	mos_rq = &(rq->mos);
	mos_rq->idle = current;
	mos_rq->idle_pid = current->pid;

	local_irq_disable();
	vtime_init_idle(current, cpu);
	init_idle_preempt_count(current, cpu);
	local_irq_enable();

	while (1) {
		__current_set_polling();
		tick_nohz_idle_enter();

		while (!need_resched()) {
			rmb(); /* sync need_resched and polling settings */
			local_irq_disable();
			arch_cpu_idle_enter();
			/*
			 * Check if the idle task must be rescheduled. If it
			 * is the case, exit the function after re-enabling
			 * the local irq.
			 */
			if (need_resched())
				local_irq_enable();
			else {
				/* Tell the RCU framework entering idle */
				rcu_idle_enter();

				if (current_clr_polling_and_test())
					local_irq_enable();
				else {
					stop_critical_timings();
					/* Re-enable and halting the CPU */
					safe_halt();
					/* Running again */
					start_critical_timings();
				}
				__current_set_polling();

				rcu_idle_exit();
			}
			arch_cpu_idle_exit();
		}
		/*
		 * Since we fell out of the loop above, we know
		 * TIF_NEED_RESCHED must be set, propagate it into
		 * PREEMPT_NEED_RESCHED.
		 */
		preempt_set_need_resched();
		tick_nohz_idle_exit();
		__current_clr_polling();
		/*
		 * We promise to call sched_ttwu_pending and reschedule
		 * if need_resched is set while polling is set.  That
		 * means that clearing polling needs to be visible
		 * before doing these things.
		 */
		smp_mb__after_atomic();
		sched_ttwu_pending();
		schedule_preempt_disabled();
	}
	return 0;
}

/*
 * Setup and launch idle threads
 */
static void idle_task_create(int cpu)
{
	struct rq *rq;
	struct mos_rq *mos_rq;
	struct task_struct *p;
	cpumask_var_t new_mask;

	rq = cpu_rq(cpu);
	mos_rq = &(rq->mos);

	/* If already initialized just return */
	if (mos_rq->idle)
		return;
	/*
	 * Create the idle task.
	 * We are using the 'on_node" interface to avoid waking up the task at
	 * this time.
	 */
	p = kthread_create_on_node(mos_idle_main, (void *)(unsigned long)cpu,
				     cpu_to_node(cpu), "mos_idle/%d", cpu);
	if (IS_ERR(p)) {
		pr_err("(!) mos_idle thread create failure for CPU=%u in %s.\n",
				cpu, __func__);
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
		pr_err("(!) mos_idle cpumask allocation failure for CPU=%u in %s.\n",
			cpu, __func__);
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

	for_each_cpu(cpu, current->mos_process->lwkcpus) {

		struct mos_rq *mos = &cpu_rq(cpu)->mos;

		/* create the idle tasks if needed */
		idle_task_create(cpu);

		/* initialize mos run queue */
		atomic_set(&mos->commit_level, 0);
		sched_stats_init(&mos->stats);
	}

	/* Save the original cpus_allowed mask */
	cpumask_copy(current->mos_process->original_cpus_allowed,
		     &current->cpus_allowed);

}
/*
 * This is called when an mos thread is exiting for any reason.
 */
void mos_sched_exit_thread(void)
{
	/* Cleanup CPU commits */
	uncommit_cpu(current);
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
	if (p->pid == p->tgid) {
		int cpu;

		cpu = initial_cpu_if_uncommitted(p);
		if (cpu >= 0)
			return cpu;
	}
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
	if (cpumask_subset(new_mask, p->mos_process->lwkcpus))
		return select_cpu_candidate(p, COMMIT_NOLIMIT);
	/*
	 * All other conditions pick first cpu in the new mask
	 */
	return cpumask_any_and(cpu_active_mask, new_mask);
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
	if (likely(!cpumask_test_cpu(cpu, tsk_cpus_allowed(p)))) {
		/*
		 * Verify that the cpus_allowed mask is in the LWK world.
		 * This is very likely true assuming we have been called
		 * under the expected conditions
		 */
		if (likely(cpumask_subset(tsk_cpus_allowed(p),
					  p->mos_process->lwkcpus)))
			ncpu = select_cpu_candidate(p, COMMIT_NOLIMIT);
	}
	return ncpu;
}

/*
 * Called from Linux when attempting to set the cpus allowed mask
 * for a kthread daemon that is not required to be bound to a specific
 * processor (e.g. kcompactd, kswapd). This function replaces the
 * Linux set_cpus_allowed_ptr method in order to remove LWK CPUs from
 * the supplied mask. If there are no CPUs remaining after removing the
 * LWK CPUs from the mask, the cpus allowed pointer in the task is used
 * as a starting point and the LWK CPUs are removed from that mask.
 * If this also results in no CPUs in the mask, the mask of the non-LWK
 * CPUs is used.
 */
void mos_set_cpus_allowed_kthread(struct task_struct *p,
				  const struct cpumask *cpumask)
{
	cpumask_var_t new_mask;
	cpumask_t *lwkcpus = this_cpu_ptr(&lwkcpus_mask);

	if (alloc_cpumask_var(&new_mask, GFP_KERNEL)) {
		/* exclude the lwk cpus from requested cpu mask */
		cpumask_andnot(new_mask, cpumask, lwkcpus);
		if (!(cpumask_intersects(new_mask, cpu_online_mask))) {
			/* exclude lwkcpus from current cpus_allowed */
			cpumask_andnot(new_mask, tsk_cpus_allowed(p), lwkcpus);
			if (!(cpumask_intersects(new_mask, cpu_online_mask)))
				/* generate mask of all the Linux CPUs */
				cpumask_andnot(new_mask, cpu_possible_mask,
						lwkcpus);
		}
		set_cpus_allowed_ptr(p, new_mask);
		free_cpumask_var(new_mask);
	} else
		pr_warn("CPU mask allocation failure in %s.\n", __func__);
}

/*
 * Called from the core scheduler's sched_init. Perform the very
 * early boot time initializations required for the mOS scheduler.
*/
void __init mos_sched_init(void)
{
	int i;
	cpumask_t *mask = per_cpu_ptr(&lwkcpus_mask, 0);

	for_each_possible_cpu(i) {
		struct rq *rq;

		rq = cpu_rq(i);
		init_mos_rq(&rq->mos);
		if (cpumask_test_cpu(i, mask))
			rq->lwkcpu = 1;
		else
			rq->lwkcpu = 0;
	}
	/* Mark the LWK CPUs as isolated */
	cpumask_or(cpu_isolated_map, cpu_isolated_map, mask);
}


/* mOS scheduler class function table */
const struct sched_class mos_sched_class = {
	.next			= &dl_sched_class,
	.enqueue_task		= enqueue_task_mos,
	.dequeue_task		= dequeue_task_mos,
	.yield_task		= yield_task_mos,
	.check_preempt_curr	= check_preempt_curr_mos,
	.pick_next_task		= pick_next_task_mos,
	.put_prev_task		= put_prev_task_mos,

#ifdef CONFIG_SMP
	.select_task_rq		= select_task_rq_mos,
	.set_cpus_allowed       = set_cpus_allowed_mos,
	.rq_online              = rq_online_mos,
	.rq_offline             = rq_offline_mos,
	.task_woken		= task_woken_mos,
	.switched_from		= switched_from_mos,
#endif
	.set_curr_task          = set_curr_task_mos,
	.task_tick		= task_tick_mos,
	.get_rr_interval	= get_rr_interval_mos,
	.prio_changed		= prio_changed_mos,
	.switched_to		= switched_to_mos,
	.update_curr		= update_curr_mos,
	.task_fork		= task_fork_mos,
};

static int lwksched_process_init(struct mos_process_t *mosp)
{

	if (!zalloc_cpumask_var(&mosp->original_cpus_allowed, GFP_KERNEL)) {
		pr_warn("CPU mask allocation failure in %s.\n", __func__);
		return -ENOMEM;
	}
	atomic_set(&mosp->threads_created, 0); /* threads created */
	mosp->num_util_threads = 0;
	mosp->move_syscalls_disable = 0;
	mosp->enable_rr = 0;
	mosp->disable_setaffinity = 0;
	mosp->sched_stats = 0;
	INIT_LIST_HEAD(&mosp->util_list);
	mutex_init(&mosp->util_list_lock);

	return 0;
}

static int lwksched_process_start(struct mos_process_t *mosp)
{
	mos_sched_prepare_launch();

	return 0;
}

static void lwksched_thread_exit(struct mos_process_t *mosp)
{
	/* Scheduler cleanup required as each thread exits */
	mos_sched_exit_thread();
}

static void stats_summarize(struct mos_sched_stats *pstats,
			    struct mos_sched_stats *stats,
			    int detail_level, int tgid, int cpu,
			    int util_cpu)
{
	if (stats->max_commit_level) {
		if (stats->max_commit_level > pstats->max_commit_level)
			pstats->max_commit_level = stats->max_commit_level;
		if (stats->max_running > pstats->max_running)
			pstats->max_running = stats->max_running;
		pstats->guest_dispatch += stats->guest_dispatch;
		pstats->timer_pop += stats->timer_pop;
		pstats->sysc_migr += stats->sysc_migr;
		pstats->setaffinity += stats->setaffinity;
		if (((detail_level == 1) &&
		    (stats->max_commit_level > 1)) ||
		    (detail_level > 2)) {
			pr_info("mos_sched: PID=%d cpuid=%2d max_commit=%d max_running=%d guest_dispatch=%d timer_pop=%d setaffinity=%d sysc_migr= %d %s\n",
				tgid, cpu,
				stats->max_commit_level,
				stats->max_running - 1, /* remove mOS idle */
				stats->guest_dispatch,
				stats->timer_pop,
				stats->setaffinity,
				stats->sysc_migr,
				(util_cpu) ? "util-cpu" : "");
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
		    (pstats.max_commit_level > 1)) ||
		    (detail_level > 1))
			pr_info("mos_sched: PID=%d threads=%d cpus=%2d max_commit=%d max_running=%d guest_dispatch=%d timer_pop=%d setaffinity=%d sysc_migr=%d\n",
			tgid,
			atomic_read(&mosp->threads_created)+1,
			cpus, pstats.max_commit_level,
			pstats.max_running - 1, /* remove mOS idle */
			pstats.guest_dispatch,
			pstats.timer_pop,
			pstats.setaffinity,
			pstats.sysc_migr);
	}
}
static void lwksched_process_exit(struct mos_process_t *mosp)
{
	/* Cleanup the utility mask */
	cpumask_clear(mosp->utilcpus);

	/* Process the scheduler end of job statistics */
	sched_stats_summarize(mosp);
}

static struct mos_process_callbacks_t lwksched_callbacks = {
	.mos_process_init = lwksched_process_init,
	.mos_process_start = lwksched_process_start,
	.mos_thread_exit = lwksched_thread_exit,
	.mos_process_exit = lwksched_process_exit,
};

static int lwksched_move_syscalls_disable(const char *ignored,
					 struct mos_process_t *mosp)
{
	mosp->move_syscalls_disable = 1;
	return 0;
}

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
	if (!msecs)
		return 0;
	/* Specified value minimum need to be >= timer frequency */
	if (msecs < min_msecs)
		goto invalid;
	mosp->enable_rr = msecs_to_jiffies(msecs);

	return 0;
invalid:
	pr_err("(!) Illegal value (%s) in %s. Minimum valid timeslice is %d\n",
	       val, __func__, min_msecs);
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
	pr_err("(!) Illegal value (%s) in %s. Expected >= 0.\n",
	       val, __func__);
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
	pr_err("(!) Illegal value (%s) in %s.\n",
	       val, __func__);
	return -EINVAL;
}

static int __init lwksched_topology_init(void)
{
	int i;

	for_each_present_cpu(i) {
		struct rq *rq;

		rq = cpu_rq(i);
		init_mos_topology(rq);
	}
	return 0;
}
/* must be called after subsys init */
late_initcall(lwksched_topology_init);

static int __init lwksched_mod_init(void)
{
	cpumask_var_t wq_mask;
	cpumask_t *lwkcpus = this_cpu_ptr(&lwkcpus_mask);

	if (alloc_cpumask_var(&wq_mask, GFP_KERNEL)) {
		int rc;

		/* generate a mask excluding lwk cpus */
		cpumask_andnot(wq_mask, cpu_possible_mask, lwkcpus);
		rc = workqueue_set_unbound_cpumask(wq_mask);
		if (!rc)
			pr_info("mOS: set unbound workqueue to %*pbl  rc=%d\n",
				cpumask_pr_args(wq_mask), rc);
		else
			pr_warn("mOS: failed setting unbound workqueue rc=%d\n",
				rc);
		free_cpumask_var(wq_mask);
	} else
		pr_warn("CPU mask allocation failure in %s.\n", __func__);

	mos_register_process_callbacks(&lwksched_callbacks);

	mos_register_option_callback("move-syscalls-disable",
				     lwksched_move_syscalls_disable);

	mos_register_option_callback("lwksched-enable-rr",
				     lwksched_enable_rr);

	mos_register_option_callback("lwksched-disable-setaffinity",
				     lwksched_disable_setaffinity);
	mos_register_option_callback("lwksched-stats",
				     lwksched_stats);
	return 0;
}

subsys_initcall(lwksched_mod_init);

/*
 * this_rq_lock - lock this runqueue and disable interrupts.
 */
static struct rq *this_rq_lock(void)
	__acquires(rq->lock)
{
	struct rq *rq;

	local_irq_disable();
	rq = this_rq();
	raw_spin_lock(&rq->lock);

	return rq;
}

/*
 * lwk_sys_sched_yield - yield the current processor to other
 * threads of equal prioity.
 *
 * Return: 0.
 */
asmlinkage long lwk_sys_sched_yield(void)
{
	struct rq *rq;

	/*
	 * Are we the only thread at this priority?
	 * In most HPC environments this will be true
	 */
	if (list_is_singular(&current->mos.run_list))
		return 0;

	/*
	 * Go through the full yield processing. We have other runnable
	 * threads that we must consider
	 */
	rq = this_rq_lock();

	schedstat_inc(rq->yld_count);
	current->sched_class->yield_task(rq);

	__release(rq->lock);
	spin_release(&rq->lock.dep_map, 1, _THIS_IP_);
	do_raw_spin_unlock(&rq->lock);
	sched_preempt_enable_no_resched();

	schedule();

	return 0;
}
