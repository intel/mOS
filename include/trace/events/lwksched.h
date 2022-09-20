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

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mos
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE lwksched

#if !defined(_TRACE_LWKSCHED_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LWKSCHED_H

#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <linux/binfmts.h>

char *mos_show_cpumatch_type(int m);
char *mos_show_commit_cpu_scope(int s);
char *mos_show_sched_policy(int p);
char *mos_show_thread_type(int t);
char *mos_show_underflow(int t);

#ifdef CREATE_TRACE_POINTS

char *mos_show_cpumatch_type(int m)
{
	switch (m) {
	case mos_match_cpu_FirstAvail:
		return "FirstAvail";
	case mos_match_cpu_SameCore:
		return "SameCore";
	case mos_match_cpu_SameL1:
		return "SameL1";
	case mos_match_cpu_SameL2:
		return "SameL2";
	case mos_match_cpu_SameL3:
		return "SameL3";
	case mos_match_cpu_SameDomain:
		return "SameDomain";
	case mos_match_cpu_OtherCore:
		return "OtherCore";
	case mos_match_cpu_OtherL1:
		return "OtherL1";
	case mos_match_cpu_OtherL2:
		return "OtherL2";
	case mos_match_cpu_OtherL3:
		return "OtherL3";
	case mos_match_cpu_OtherDomain:
		return "OtherDomain";
	case mos_match_cpu_InNMask:
		return "InNMask";
	default:
		return "Unknown";
	}
}

char *mos_show_commit_cpu_scope(int s)
{
	switch (s) {
	case mos_commit_cpu_scope_AllCommits:
		return "AllCommits";
	case mos_commit_cpu_scope_OnlyComputeCommits:
		return "OnlyComputeCommits";
	case mos_commit_cpu_scope_OnlyUtilityCommits:
		return "OnlyUtilityCommits";
	default:
		return "Unknown";
	}
}

char *mos_show_sched_policy(int p)
{
	switch (p) {
	case SCHED_FIFO:
		return "SCHED_FIFO";
	case SCHED_NORMAL:
		return "SCHED_NORMAL";
	case SCHED_RR:
		return "SCHED_RR";
	case SCHED_DEADLINE:
		return "SCHED_DEADLINE";
	case SCHED_IDLE:
		return "SCHED_IDLE";
	case SCHED_BATCH:
		return "SCHED_BATCH";
	default:
		return "Unknown";
	}
}

char *mos_show_thread_type(int t)
{
	switch (t) {
	case mos_thread_type_normal:
		return "Normal";
	case mos_thread_type_utility:
		return "Utility";
	case mos_thread_type_idle:
		return "Idle";
	case mos_thread_type_guest:
		return "Guest";
	default:
		return "Unknown";
	}
}

char *mos_show_underflow(int t)
{
	return t ? "Underflow" : "";
}

char *mos_show_overflow(int t)
{
	return t ? "Overflow" : "";
}

#endif /* CREATE_TRACE_POINTS */

DECLARE_EVENT_CLASS(mos_assimilate_template,

	TP_PROTO(struct task_struct *p),

	TP_ARGS(p),

	TP_STRUCT__entry(
		__array(char, comm, TASK_COMM_LEN)
		__field(int, cpu)
		__field(int, policy)
		__field(int, thread_type)
		__field(int, nr_cpus)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->cpu = task_cpu(p);
		__entry->policy	= p->policy;
		__entry->thread_type = p->mos.thread_type;
		__entry->nr_cpus = p->nr_cpus_allowed;
	),

	TP_printk("comm=%s cpu=%d policy=%d:%s type=%d:%s nr_cpus=%d",
		__entry->comm, __entry->cpu, __entry->policy,
		mos_show_sched_policy(__entry->policy),
		__entry->thread_type,
		mos_show_thread_type(__entry->thread_type),
		__entry->nr_cpus)
);

/*
 * Tracepoint for assimilating an mos process at launch time
 */
DEFINE_EVENT(mos_assimilate_template, mos_assimilate_launch,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));

/*
 * Tracepoint for assimilating a guest
 */
DEFINE_EVENT(mos_assimilate_template, mos_assimilate_guest,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

/*
 * Tracepoint for assimilating the mOS idle thread
 */
DEFINE_EVENT(mos_assimilate_template, mos_assimilate_idle,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

/*
 * Tracepoint for give back thread to Linux scheduler
 */
DEFINE_EVENT(mos_assimilate_template, mos_giveback_thread,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

/*
 * Tracepoint for cpu assignment manager result
 */
TRACE_EVENT(mos_clone_cpu_assign,

	TP_PROTO(int cpu, struct task_struct *p),

	TP_ARGS(cpu, p),

	TP_STRUCT__entry(
		__field(int, cpu)
		__field(int, pid)
		__field(int, nr_cpus)
	),

	TP_fast_assign(
		__entry->cpu = cpu;
		__entry->pid = p->pid;
		__entry->nr_cpus = p->nr_cpus_allowed;
	),

	TP_printk("target cpu=%d pid=%d num cpus allowed=%d",
		  __entry->cpu, __entry->pid, __entry->nr_cpus)
);

/*
 * Tracepoint for timer tick
 */
TRACE_EVENT(mos_timer_tick,

	TP_PROTO(struct task_struct *p, int cpu),

	TP_ARGS(p, cpu),

	TP_STRUCT__entry(
		__field(int, policy)
		__field(int, nr_cpus)
		__field(int, cpu)
	),

	TP_fast_assign(
		__entry->policy	= p->policy;
		__entry->nr_cpus = p->nr_cpus_allowed;
		__entry->cpu = cpu;
	),

	TP_printk("cpu=%d policy=%d:%s num cpus allowed=%d",
		__entry->cpu,
		__entry->policy, mos_show_sched_policy(__entry->policy),
		__entry->nr_cpus)
);

/*
 * Tracepoint for balance tick
 */
TRACE_EVENT(mos_balancer_tick,

	TP_PROTO(struct mos_rq *mos_rq),

	TP_ARGS(mos_rq),

	TP_STRUCT__entry(
		__field(unsigned int, period)
	),

	TP_fast_assign(
		__entry->period = mos_rq->balancer_parm1;
	),

	TP_printk("current period(ns)=%d", __entry->period)
);

/*
 * Tracepoint for balance tick start
 */
TRACE_EVENT(mos_balancer_tick_start,

	TP_PROTO(struct mos_rq *mos_rq),

	TP_ARGS(mos_rq),

	TP_STRUCT__entry(
		__field(unsigned int, period)
	),

	TP_fast_assign(
		__entry->period = mos_rq->balancer_parm1;
	),

	TP_printk("period(ms)=%d", __entry->period)
);

/*
 * Tracepoint for balance tick stop
 */
TRACE_EVENT(mos_balancer_tick_stop,

	TP_PROTO(struct mos_rq *mos_rq),

	TP_ARGS(mos_rq),

	TP_STRUCT__entry(
		__field(unsigned int, period)
	),

	TP_fast_assign(
		__entry->period = mos_rq->balancer_parm1;
	),

	TP_printk("period(ms)=%d", __entry->period)
);


/*
 * mOS idle init
 */
TRACE_EVENT(mos_idle_init,

	TP_PROTO(int cpu),

	TP_ARGS(cpu),

	TP_STRUCT__entry(
		__field(int, cpu)
	),

	TP_fast_assign(
		__entry->cpu = cpu;
	),

	TP_printk("create for cpu=%d", __entry->cpu)
);

/*
 * CPU committed to an mOS task
 */
TRACE_EVENT(mos_cpu_commit,

	TP_PROTO(struct task_struct *p, int cpu, int32_t compute_commit,
		 int32_t utility_commit, int overflow),

	TP_ARGS(p, cpu, compute_commit, utility_commit, overflow),

	TP_STRUCT__entry(
		__field(int, pid)
		__field(int, cpu)
		__field(int, compute_commit)
		__field(int, util_commit)
		__field(int, overflow)
	),

	TP_fast_assign(
		__entry->pid = p->pid;
		__entry->cpu = cpu;
		__entry->compute_commit = compute_commit;
		__entry->util_commit = utility_commit;
		__entry->overflow = overflow;
	),

	TP_printk("pid=%d cpu=%d compute_level=%d util_level=%d %s",
		  __entry->pid, __entry->cpu, __entry->compute_commit,
		  __entry->util_commit, mos_show_overflow(__entry->overflow))
);

/*
 * CPU uncommitted to an mOS task
 */
TRACE_EVENT(mos_cpu_uncommit,

	TP_PROTO(struct task_struct *p, int cpu, int32_t compute_commit,
		 int32_t utility_commit, int underflow),

	TP_ARGS(p, cpu, compute_commit, utility_commit, underflow),

	TP_STRUCT__entry(
		__field(int, pid)
		__field(int, cpu)
		__field(int, compute_commit)
		__field(int, util_commit)
		__field(int, underflow)
	),

	TP_fast_assign(
		__entry->pid = p->pid;
		__entry->cpu = cpu;
		__entry->compute_commit = compute_commit;
		__entry->util_commit = utility_commit;
		__entry->underflow = underflow;
	),

	TP_printk("pid=%d cpu=%d compute_level=%d util_level=%d %s",
		  __entry->pid, __entry->cpu, __entry->compute_commit,
		  __entry->util_commit, mos_show_underflow(__entry->underflow))
);

/*
 * Template for the cpu select events
 */
DECLARE_EVENT_CLASS(mos_cpu_select_template,

	TP_PROTO(struct task_struct *p, int cpu, int commit_type,
		 int commit_level, int match_type, int match_id, int range,
		 int exclusive_pid),

	TP_ARGS(p, cpu, commit_type, commit_level, match_type, match_id,
		range, exclusive_pid),

	TP_STRUCT__entry(
		__field(int, pid)
		__field(int, cpu)
		__field(int, commit_type)
		__field(int, commit_level)
		__field(int, match_type)
		__field(int, match_id)
		__field(int, range)
		__field(int, exclusive_pid)
	),

	TP_fast_assign(
		__entry->pid = p->pid;
		__entry->cpu = cpu;
		__entry->commit_type = commit_type;
		__entry->commit_level = commit_level;
		__entry->match_type = match_type;
		__entry->match_id = match_id;
		__entry->range = range;
		__entry->exclusive_pid = exclusive_pid;
	),

	TP_printk(
		"pid=%d cpu=%d commit type=%d:%s commit lvl=%d match type=%d:%s match id=%d range=%d excl pid=%d",
		__entry->pid, __entry->cpu, __entry->commit_type,
		mos_show_commit_cpu_scope(__entry->commit_type),
		__entry->commit_level, __entry->match_type,
		mos_show_cpumatch_type(__entry->match_type),
		__entry->match_id, __entry->range, __entry->exclusive_pid)
);

/*
 * CPU selected for wakeup, migration, or clone
 */
DEFINE_EVENT(mos_cpu_select_template, mos_cpu_select,
		TP_PROTO(struct task_struct *p, int cpu, int commit_type,
		 int commit_level, int match_type, int match_id, int range,
		 int exclusive_pid),
		TP_ARGS(p, cpu, commit_type, commit_level, match_type, match_id,
		range, exclusive_pid));

/*
 * No CPU available at specified commit level
 */
DEFINE_EVENT(mos_cpu_select_template, mos_cpu_select_unavail,
		TP_PROTO(struct task_struct *p, int cpu, int commit_type,
		 int commit_level, int match_type, int match_id, int range,
		 int exclusive_pid),
		TP_ARGS(p, cpu, commit_type, commit_level, match_type, match_id,
		range, exclusive_pid));

/*
 * Thread has been assigned to a utility CPU
 */
TRACE_EVENT(mos_util_thread_assigned,

	TP_PROTO(int cpu, int num_cpus, int placed),

	TP_ARGS(cpu, num_cpus, placed),

	TP_STRUCT__entry(
		__field(int, cpu)
		__field(int, num_cpus)
		__field(int, placed)
	),

	TP_fast_assign(
		__entry->cpu = cpu;
		__entry->num_cpus = num_cpus;
		__entry->placed = placed;
	),

	TP_printk("cpu=%d num_cpus_allowed=%d placement_honored=%d",
		__entry->cpu, __entry->num_cpus, __entry->placed)
);

/*
 * Utility thread as been pushed to a shared utility CPU
 */
TRACE_EVENT(mos_util_thread_pushed,

	TP_PROTO(int from_cpu, int to_cpu, struct task_struct *p, int num_cpus,
		 int placed),

	TP_ARGS(from_cpu, to_cpu, p, num_cpus, placed),

	TP_STRUCT__entry(
		__field(int, from_cpu)
		__field(int, to_cpu)
		__field(int, pid)
		__field(int, num_cpus)
		__field(int, placed)
	),

	TP_fast_assign(
		__entry->from_cpu = from_cpu;
		__entry->to_cpu = to_cpu;
		__entry->pid = p->pid;
		__entry->num_cpus = num_cpus;
		__entry->placed = placed;
	),

	TP_printk(
		"pid=%d from=%d to=%d num_cpus_allowed=%d placement_honored=%d",
		__entry->pid, __entry->from_cpu,
		__entry->to_cpu, __entry->num_cpus, __entry->placed)
);

/*
 * Clone attributes have been activated for the current task
 */
TRACE_EVENT(mos_clone_attr_active,

	TP_PROTO(unsigned int behavior, unsigned int placement),

	TP_ARGS(behavior, placement),

	TP_STRUCT__entry(
		__field(unsigned int, behavior)
		__field(unsigned int, placement)
	),

	TP_fast_assign(
		__entry->behavior = behavior;
		__entry->placement = placement;
	),

	TP_printk("behavior=%d placement=%d",
		__entry->behavior, __entry->placement)
);

/*
 * Clone attributes have been cleared within the current task
 */
TRACE_EVENT(mos_clone_attr_cleared,

	TP_PROTO(unsigned int behavior, unsigned int placement),

	TP_ARGS(behavior, placement),

	TP_STRUCT__entry(
		__field(unsigned int, behavior)
		__field(unsigned int, placement)
	),

	TP_fast_assign(
		__entry->behavior = behavior;
		__entry->placement = placement;
	),

	TP_printk("previous behavior=%d placement=%d",
		__entry->behavior, __entry->placement)
);


/*
 * Select an appropriate CPU for the main thread
 */
TRACE_EVENT(mos_select_main_thread_home,

	TP_PROTO(struct task_struct *p, int cpu),

	TP_ARGS(p, cpu),

	TP_STRUCT__entry(
		__field(int, pid)
		__field(int, from_cpu)
		__field(int, to_cpu)
	),

	TP_fast_assign(
		__entry->pid = p->pid;
		__entry->from_cpu = p->mos.cpu_home;
		__entry->to_cpu = cpu;
	),

	TP_printk("pid=%d from cpu=%d to cpu=%d",
		  __entry->pid, __entry->from_cpu, __entry->to_cpu)
);

/*
 * Maximum and Minimum MWAIT CSTATES configured for use
 */
TRACE_EVENT(mos_mwait_cstates_configured,

	TP_PROTO(unsigned int min_cstate, unsigned int max_cstate,
		 unsigned int ecx, unsigned int substates),

	TP_ARGS(min_cstate, max_cstate, ecx, substates),

	TP_STRUCT__entry(
		__field(unsigned int, min_cstate)
		__field(unsigned int, max_cstate)
		__field(unsigned int, ecx)
		__field(unsigned int, substates)
	),

	TP_fast_assign(
		__entry->min_cstate = min_cstate;
		__entry->max_cstate = max_cstate;
		__entry->ecx = ecx;
		__entry->substates = substates;
	),

	TP_printk("hints min=%08x max=%08x ecx=%08x substates=%08x",
		  __entry->min_cstate, __entry->max_cstate, __entry->ecx,
		  __entry->substates)
);

/*
 * MWAIT API entering mwait
 */
TRACE_EVENT(mos_mwait_api_entry,

	TP_PROTO(unsigned int ecx, unsigned int eax),

	TP_ARGS(ecx, eax),

	TP_STRUCT__entry(
		__field(unsigned int, ecx)
		__field(unsigned int, eax)
	),

	TP_fast_assign(
		__entry->ecx = ecx;
		__entry->eax = eax;
	),

	TP_printk("Enter MWAIT... ecx=%08x eax=%08x",
			__entry->ecx, __entry->eax)
);

/*
 * MWAIT API exiting mwait
 */
TRACE_EVENT(mos_mwait_api_exit,

	TP_PROTO(unsigned int ecx, unsigned int eax),

	TP_ARGS(ecx, eax),

	TP_STRUCT__entry(
		__field(unsigned int, ecx)
		__field(unsigned int, eax)
	),

	TP_fast_assign(
		__entry->ecx = ecx;
		__entry->eax = eax;
	),

	TP_printk("...Leave MWAIT ecx=%08x eax=%08x",
			__entry->ecx, __entry->eax)
);

/*
 * Balancer migration action
 */
TRACE_EVENT(mos_balance,

	TP_PROTO(int pid, unsigned int from_cpu, unsigned int to_cpu, unsigned long src_load, unsigned long tgt_load),

	TP_ARGS(pid, from_cpu, to_cpu, src_load, tgt_load),

	TP_STRUCT__entry(
		__field(unsigned int, pid)
		__field(unsigned int, from_cpu)
		__field(unsigned int, to_cpu)
		__field(unsigned long, src_load)
		__field(unsigned long, tgt_load)
	),

	TP_fast_assign(
		__entry->pid = pid;
		__entry->from_cpu = from_cpu;
		__entry->to_cpu = to_cpu;
		__entry->src_load = src_load;
		__entry->tgt_load = tgt_load;
	),

	TP_printk(
	"Balancer moving pid=%d from cpu=%d -> cpu=%d, load=%lu -> %lu",
			__entry->pid, __entry->from_cpu, __entry->to_cpu,
			__entry->src_load, __entry->tgt_load)
);

#endif /* _TRACE_MOS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
