/*
 * Multi Operating System (mOS)
 * Copyright (c) 2018-2019, Intel Corporation.
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

#ifndef _LINUX_MOSRAS_H
#define _LINUX_MOSRAS_H

#ifdef CONFIG_MOS_FOR_HPC

extern int mos_ras(const char *event_id, const char *fmt, ...);

#else

static inline int mos_ras(const char *event_id, const char *fmt, ...)
{
	return 0;
};

#endif

/**
 * EventType: 1001000001
 * Severity:  Debug
 * Component: Test
 * Msg:       This event is for testing only.
 */
#define MOS_TEST_EVENT "mOSTestEvent"

/**
 * EventType: 1001000002
 * Severity:  Error
 * Component: lwkctl
 * Msg:       An error occurred during dynamic partitioning.
 * ControlOperation: ErrorOnNode
 */
#define MOS_LWKCTL_FAILURE "mOSLwkctlFailure"

/**
 * EventType: 1001000003
 * Severity:  Warning
 * Component: lwkctl
 * Msg:       An warning occurred during dynamic partitioning.
 */
#define MOS_LWKCTL_WARNING "mOSLwkctlWarning"

/**
 * EventType: 1001000004
 * Severity:  Error
 * Component: lwkprocess
 * Msg:       An unexpected error occurred in an LWK process.
 * ControlOperation: KillJobOnNode
 */
#define MOS_LWK_PROCESS_ERROR "mOSLwkProcessError"

/**
 * EventType: 1001000005
 * Severity:  Error
 * Component: boot
 * Msg:       An unexpected error occurred during boot.
 * ControlOperation: ErrorOnNode
 */
#define MOS_BOOT_ERROR "mOSBootError"

/**
 * EventType: 1001000006
 * Severity:  Error
 * Component: lwkprocess
 * Msg:       An unexpected error occurred in an LWK process.  The hosting node is considered unstable.
 * ControlOperation: ErrorAndKillJobOnNode
 */
#define MOS_LWK_PROCESS_ERROR_UNSTABLE_NODE "mOSLwkProcessErrorUnstableNode"

/**
 * EventType: 1001000007
 * Severity:  Warning
 * Component: mOSKernel
 * Msg:       An unexpected event occurred in mOS kernel.
 */
#define MOS_KERNEL_WARNING "mOSKernelWarning"

/**
 * EventType: 1001000008
 * Severity:  Error
 * Component: mOSKernel
 * Msg:       An unexpected error occurred in mOS kernel.
 * ControlOperation: ErrorOnNode
 */
#define MOS_KERNEL_ERROR "mOSKernelError"

/* Events for the LWK memory component have the range 1001100000-101199999 */

/**
 * EventType: 1001100000
 * Severity:  Error
 * Component: lwkmem
 * Msg:       A process level fatal error occurred in LWK memory.
 * ControlOperation: KillJobOnNode
 */
#define MOS_LWKMEM_PROCESS_ERROR "mOSLwkmemProcessError"

/**
 * EventType: 1001100001
 * Severity:  Warning
 * Component: lwkmem
 * Msg:       A process level warning occurred in LWK memory.
 */
#define MOS_LWKMEM_PROCESS_WARNING "mOSLwkmemProcessWarning"

/**
 * EventType: 1001100002
 * Severity:  Warning
 * Component: lwkmem
 * Msg:       An unexpected problem was detected during boot.
 */
#define MOS_LWKMEM_BOOT_WARNING "mOSLwkmemBootWarning"

/* Events for the LWK scheduler component have the range 1001200000-101299999 */

/**
 * EventType: 1001200001
 * Severity:  Warning
 * Component: Scheduler
 * Msg:       A warning occurred in the Scheduler.
 */
#define MOS_SCHEDULER_WARNING "mOSSchedulerWarning"

/**
 * EventType: 1001200002
 * Severity:  Error
 * Component: Scheduler
 * Msg:    An unexpected error occurred in the Scheduler.
 * ControlOperation: KillJobOnNode
 */
#define MOS_SCHEDULER_ERROR "mOSSchedulerError"


#endif
