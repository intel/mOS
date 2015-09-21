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

#if !defined(_TRACE_MOS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_MOS_H

#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <linux/binfmts.h>


DECLARE_EVENT_CLASS(mos_assimilate_template,

	TP_PROTO(struct task_struct *p),

	TP_ARGS(p),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	int,	cpu			)
		__field(	int,	nr_cpus 		)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->cpu		= task_cpu(p);
		__entry->nr_cpus	= p->nr_cpus_allowed;
	),

	TP_printk("comm=%s cpu=%d nr_cpus=%d",
		  __entry->comm, __entry->cpu, __entry->nr_cpus)
);

/*
 * Tracepoint for assimilating an mos process at launch time
 */
DEFINE_EVENT(mos_assimilate_template, mos_assimilate_launch,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));

/*
 * Tracepoint for assimilating a deadline class task
 */
DEFINE_EVENT(mos_assimilate_template, mos_assimilate_deadline,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));

/*
 * Tracepoint for assimilating a fair class task
 */
DEFINE_EVENT(mos_assimilate_template, mos_assimilate_fair,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

/*
 * Tracepoint for assimilating a rt class task
 */
DEFINE_EVENT(mos_assimilate_template, mos_assimilate_rt,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

/*
 * Tracepoint for assimilate unrecognized class
 */
DEFINE_EVENT(mos_assimilate_template, mos_assimilate_unrecognized,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

/*
 * Tracepoint for assimilate unexpected process
 */
DEFINE_EVENT(mos_assimilate_template, mos_assimilate_unexpected,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

/*
 * Tracepoint for cpu assignment manager result
 */
TRACE_EVENT(mos_clone_cpu_assign,

	TP_PROTO(int cpu, struct task_struct *p),

	TP_ARGS(cpu, p),

	TP_STRUCT__entry(
		__field(	int,	cpu			)
		__field(	int,	pid 			)
		__field(	int,	nr_cpus 		)
	),

	TP_fast_assign(
		__entry->cpu		= cpu;
		__entry->pid		= p->pid;
		__entry->nr_cpus	= p->nr_cpus_allowed;
	),

	TP_printk("target cpu=%d pid=%d num cpus allowed=%d",
		  __entry->cpu, __entry->pid, __entry->nr_cpus)
);

/*
 * Tracepoint for timer tick
 */
TRACE_EVENT(mos_timer_tick,

	TP_PROTO(struct task_struct *p),

	TP_ARGS(p),

	TP_STRUCT__entry(
		__field(	int,	policy			)
		__field(	int,	nr_cpus 		)
	),

	TP_fast_assign(
		__entry->policy		= p->policy;
		__entry->nr_cpus	= p->nr_cpus_allowed;
	),

	TP_printk("policy=%d num cpus allowed=%d",
		  __entry->policy, __entry->nr_cpus)
);


/*
 * mOS idle init
 */
TRACE_EVENT(mos_idle_init,

	TP_PROTO(int cpu),

	TP_ARGS(cpu),

	TP_STRUCT__entry(
		__field(	int,	cpu			)
	),

	TP_fast_assign(
		__entry->cpu		= cpu;
	),

	TP_printk("create for cpu=%d",
		  __entry->cpu)
);

/*
 * CPU committed to an mOS task
 */
TRACE_EVENT(mos_cpu_commit,

	TP_PROTO(struct task_struct *p, int cpu, int commit),

	TP_ARGS(p, cpu, commit),

	TP_STRUCT__entry(
		__field(	int,	pid			)
		__field(	int,	cpu			)
		__field(	int,	commit			)
	),

	TP_fast_assign(
		__entry->pid		= p->pid;
		__entry->cpu		= cpu;
		__entry->commit		= commit;
	),

	TP_printk("pid=%d cpu=%d level=%d",
		  __entry->pid, __entry->cpu, __entry->commit)
);

/*
 * CPU uncommitted to an mOS task
 */
TRACE_EVENT(mos_cpu_uncommit,

	TP_PROTO(struct task_struct *p, int cpu, int commit),

	TP_ARGS(p, cpu, commit),

	TP_STRUCT__entry(
		__field(	int,	pid			)
		__field(	int,	cpu			)
		__field(	int,	commit			)
	),

	TP_fast_assign(
		__entry->pid		= p->pid;
		__entry->cpu		= cpu;
		__entry->commit		= commit;
	),

	TP_printk("pid=%d cpu=%d level=%d",
		  __entry->pid, __entry->cpu, __entry->commit)
);

/*
 * No CPU available at specified commit level
 */
TRACE_EVENT(mos_cpu_select_unavail,

	TP_PROTO(struct task_struct *p, int commit, int type, int id),

	TP_ARGS(p, commit, type, id),

	TP_STRUCT__entry(
		__field(	int,	pid			)
		__field(	int,	commit			)
		__field(	int,	type			)
		__field(	int,	id			)
	),

	TP_fast_assign(
		__entry->pid		= p->pid;
		__entry->commit		= commit;
		__entry->type		= type;
		__entry->id		= id;
	),

	TP_printk("pid=%d requested commit level=%d type=%d id=%d",
		  __entry->pid, __entry->commit, __entry->type, __entry->id)
);

/*
 * CPU selected for wakeup, migration, or clone
 */
TRACE_EVENT(mos_cpu_select,

	TP_PROTO(struct task_struct *p, int cpu, int commit, int type, int id),

	TP_ARGS(p, cpu, commit, type, id),

	TP_STRUCT__entry(
		__field(	int,	pid			)
		__field(	int,	cpu			)
		__field(	int,	commit			)
		__field(	int,	type			)
		__field(	int,	id			)
	),

	TP_fast_assign(
		__entry->pid		= p->pid;
		__entry->cpu		= cpu;
		__entry->commit		= commit;
		__entry->type		= type;
		__entry->id		= id;
	),

	TP_printk("pid=%d cpu=%d commit level=%d type=%d id=%d",
		  __entry->pid, __entry->cpu, __entry->commit, __entry->type,
		  __entry->id)
);

/*
 * Thread has been assigned to a utility CPU
 */
TRACE_EVENT(mos_util_thread_assigned,

	TP_PROTO(int cpu),

	TP_ARGS(cpu),

	TP_STRUCT__entry(
		__field(	int,	cpu			)
	),

	TP_fast_assign(
		__entry->cpu		= cpu;
	),

	TP_printk("cpu=%d", __entry->cpu)
);

/*
 * Utility thread as been pushed to a shared utility CPU
 */
TRACE_EVENT(mos_util_thread_pushed,

	TP_PROTO(int from_cpu, int to_cpu, struct task_struct *p, int commit),

	TP_ARGS(from_cpu, to_cpu, p, commit),

	TP_STRUCT__entry(
		__field(	int,	from_cpu		)
		__field(	int,	to_cpu			)
		__field(	int,	pid			)
		__field(	int,	commit			)
	),

	TP_fast_assign(
		__entry->from_cpu	= from_cpu;
		__entry->to_cpu		= to_cpu;
		__entry->pid		= p->pid;
		__entry->commit		= commit;
	),

	TP_printk("pid=%d from=%d to=%d commit=%d",
		__entry->pid, __entry->from_cpu,
		__entry->to_cpu, __entry->commit)
);

#endif /* _TRACE_MOS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
