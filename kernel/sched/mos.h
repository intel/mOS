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
 *  kernel/sched/mos.h
 */

#include <linux/sched.h>
#include <linux/mos.h>

#ifdef CONFIG_MOS_FOR_HPC

static inline void assimilate_mos(struct rq *rq, struct task_struct *p)
{
	assimilate_task_mos(rq, p);
}

static inline bool is_mos_process(struct task_struct *p)
{
	return p->mos_process ? true : false;
}

static inline void bump_syscall_migrate_count_mos(void)
{
	this_rq()->mos.stats.sysc_migr++;
}

static inline void bump_setaffinity_count_mos(void)
{
		/* Bump the count of mOS setaffinity */
		this_rq()->mos.stats.setaffinity++;
}

static inline int nr_running_mos(struct rq *rq)
{
	return rq->mos.mos_nr_running;
}

static inline int nr_rr_running_mos(struct rq *rq)
{
	return rq->mos.rr_nr_running;
}

static inline bool is_assimilated_mos(struct task_struct *p)
{
	return p->mos.assimilated ? true : false;
}

static inline int select_cpu_candidate_mos(struct task_struct *p, int cpu)
{
	return mos_select_cpu_candidate(p, cpu);
}

static inline bool is_lwkrq(struct rq *rq)
{
	return rq->lwkcpu ? true : false;
}

static inline bool is_mos_sched_class(struct task_struct *p)
{
	return ((p->sched_class == &mos_sched_class) ? true : false);
}

static inline void init_scheduler_mos(void)
{
	init_sched_mos();
}

static inline void init_run_list_mos(struct task_struct *p)
{
	INIT_LIST_HEAD(&p->mos.run_list);
}

static inline void init_util_list_mos(struct task_struct *p)
{
	INIT_LIST_HEAD(&p->mos.util_list);
}

static inline void set_sched_class_mos(struct task_struct *p)
{
	p->sched_class = &mos_sched_class;
}

static inline void set_to_lwkcpus_mos(cpumask_var_t mask,
				    struct task_struct *p)
{
	cpumask_copy(mask, p->mos_process->lwkcpus);
}

static inline void set_to_lwkcpus_and_utilcpus_mos(cpumask_var_t mask,
					    struct task_struct *p)
{
	cpumask_copy(mask, p->mos_process->lwkcpus);
	cpumask_or(mask, mask, p->mos_process->utilcpus);
}

static inline bool is_setaffinity_disabled_mos(struct task_struct *p,
					      int *retval)
{
	/* Is sched_setaffinity disabled for this mOS process */
	if (p->mos_process->disable_setaffinity &&
	    p->mos.assimilated) {
		*retval = -(p->mos_process->disable_setaffinity - 1);
		return true;
	}
	return false;
}

static inline int select_next_cpu_mos(struct task_struct *p,
					const struct cpumask *newmask)
{
	return mos_select_next_cpu(p, newmask);
}

static inline void set_clone_flags_mos(struct task_struct *p,
					unsigned long clone_flags)
{
	p->mos.clone_flags = clone_flags;
}

static inline cpumask_t *lwkcpus_mask_mos(void)
{
	return this_cpu_ptr(&lwkcpus_mask);
}

static inline bool is_migration_mask_valid_mos(const cpumask_t *mask,
						struct task_struct *p)
{
	if (cpumask_subset(mask, p->mos_process->lwkcpus) ||
	    cpumask_subset(mask, p->mos_process->utilcpus))
		return true;
	return false;
}

static inline void init_fork_mos(struct task_struct *p)
{
	p->mos.cpu_home = -1;
	p->mos.thread_type = mos_thread_type_normal;
	init_run_list_mos(p);
	init_util_list_mos(p);
}

static inline bool is_lwkcpu(void)
{
	return (this_cpu_ptr(&runqueues)->lwkcpu ? 1 : 0);
}

static inline struct list_head *mos_runlist(void)
{
	return &current->mos.run_list;
}

#else

static inline void assimilate_mos(struct rq *rq, struct task_struct *p)
{}

static inline bool is_mos_process(struct task_struct *p)
{
	return false;
}

static inline void bump_syscall_migrate_count_mos(void)
{}

static inline void bump_setaffinity_count_mos(void)
{}

static inline int nr_running_mos(struct rq *rq)
{
	return 0;
}

static inline int nr_rr_running_mos(struct rq *rq)
{
	return 0;
}

static inline bool is_assimilated_mos(struct task_struct *p)
{
	return false;
}

static inline int select_cpu_candidate_mos(struct task_struct *p, int cpu)
{
	return -1;
}

static inline bool is_lwkrq(struct rq *rq)
{
	return false;
}

static inline bool is_mos_sched_class(struct task_struct *p)
{
	return false;
}

static inline void init_scheduler_mos(void)
{}

static inline void init_run_list_mos(struct task_struct *p)
{}

static inline void init_util_list_mos(struct task_struct *p)
{}

static inline void set_sched_class_mos(struct task_struct *p)
{}

static inline void set_to_lwkcpus_mos(cpumask_var_t mask,
				    struct task_struct *p)
{}

static inline void set_to_lwkcpus_and_utilcpus_mos(cpumask_var_t mask,
					    struct task_struct *p)
{}

static inline bool is_setaffinity_disabled_mos(struct task_struct *p,
					      int *retval)
{
	return false;
}

static inline int select_next_cpu_mos(struct task_struct *p,
					const struct cpumask *newmask)
{
	return -1;
}

static inline void set_clone_flags_mos(struct task_struct *p,
					unsigned long clone_flags)
{}

static inline cpumask_t *lwkcpus_mask_mos(void)
{
	return NULL;
}

static inline bool is_migration_mask_valid_mos(const cpumask_t *mask,
						struct task_struct *p)
{
	return false;
}

static inline void init_fork_mos(struct task_struct *p)
{}

static inline bool is_lwkcpu(void)
{
	return false;
}

static inline struct list_head *mos_runlist(void)
{
	return NULL;
}

#endif

