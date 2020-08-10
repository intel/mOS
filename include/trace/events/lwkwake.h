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
#define TRACE_SYSTEM mos_idle
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE lwkwake

#if !defined(_TRACE_LWKWAKE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_LWKWAKE_H

#include <linux/sched.h>
#include <linux/tracepoint.h>
#include <linux/binfmts.h>

/*
 * The following trace events can occur a very high rates. They are purposely
 * packaged in a separate TRACE_SYSTEM, outside of the mos TRACE_SYSTEM so that
 * when enabling all of the trace events in the mos TRACE_SYSTEM by way of
 * 'echo 1 > ...events/mos/enabled', the buffers are not over-run by these
 * events. When using these events, it is expected that filtering mechanisms,
 * such as TRACING_CPUMASK, are used to limit the quantity.
 */

/*
 * IDLE task entering mwait
 */
TRACE_EVENT(mos_idle_mwait_entry,

	TP_PROTO(unsigned int ecx, unsigned int eax),

	TP_ARGS(ecx, eax),

	TP_STRUCT__entry(
		__field(	unsigned int,	ecx	)
		__field(	unsigned int,	eax	)
	),

	TP_fast_assign(
		__entry->ecx		= ecx;
		__entry->eax		= eax;
	),

	TP_printk("Enter MWAIT... ecx=%08x eax=%08x",
			__entry->ecx, __entry->eax)
);

/*
 * IDLE task exiting mwait
 */
TRACE_EVENT(mos_idle_mwait_exit,

	TP_PROTO(unsigned int ecx, unsigned int eax),

	TP_ARGS(ecx, eax),

	TP_STRUCT__entry(
		__field(	unsigned int,	ecx	)
		__field(	unsigned int,	eax	)
	),

	TP_fast_assign(
		__entry->ecx	= ecx;
		__entry->eax	= eax;
	),

	TP_printk("...Leave MWAIT ecx=%08x eax=%08x",
			__entry->ecx, __entry->eax)
);

/*
 * IDLE task entering halt
 * @i: dummy arg to make macro happy
 */
TRACE_EVENT(mos_idle_halt_entry,

	TP_PROTO(int i),

	TP_ARGS(i),

	TP_STRUCT__entry(
		__field(	unsigned int,	i	)
	),

	TP_fast_assign(
		__entry->i	= i;
	),

	TP_printk("%s", "Enter HALT...")
);

/*
 * IDLE task exiting halt
 * @i: dummy arg to make macro happy
 */
TRACE_EVENT(mos_idle_halt_exit,

	TP_PROTO(int i),

	TP_ARGS(i),

	TP_STRUCT__entry(
		__field(	unsigned int,	i	)
	),

	TP_fast_assign(
		__entry->i	= i;
	),

	TP_printk("%s", "...Leave HALT")
);

/*
 * IDLE task enter polling
 * @i: dummy arg to make macro happy
 */
TRACE_EVENT(mos_idle_poll_entry,

	TP_PROTO(int i),

	TP_ARGS(i),

	TP_STRUCT__entry(
		__field(	unsigned int,	i	)
	),

	TP_fast_assign(
		__entry->i	= i;
	),

	TP_printk("%s", "Begin polling...")
);

/*
 * IDLE task exiting polling
 * @i: dummy arg to make macro happy
 */
TRACE_EVENT(mos_idle_poll_exit,

	TP_PROTO(int i),

	TP_ARGS(i),

	TP_STRUCT__entry(
		__field(	unsigned int,	i	)
	),

	TP_fast_assign(
		__entry->i	= i;
	),

	TP_printk("%s", "...Exit polling")
);

#endif /* _TRACE_MOS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
