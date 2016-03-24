# Multi Operating System (mOS)
# Copyright (c) 2016, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

LINUX_DEFAULT_CMDLINE = \
	intel_idle.max_cstate=1 \
	intel_pstate=disable \
	nmi_watchdog=0 \
	acpi_irq_nobalance \
	idle=halt

MOS_DEFAULT_CMDLINE = \
	lwkmem_debug=0

KERNEL_CMDLINE ?= \
	$(LINUX_DEFAULT_CMDLINE) \
	$(MOS_DEFAULT_CMDLINE) \
	$${MOS_DEFAULT_MEM} \
	$${MOS_DEFAULT_CPUS}
