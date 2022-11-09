# Multi Operating System (mOS)
# Copyright (c) 2017, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

hostprogs := lwkctl
scriptprogs-y := lwkctl.sh lwkctl.1.man
mos-lib-objs := ../lib/mos_cpuset.o
lwkctl-objs := lwkctl_sysfs.o lwkctl_irq.o lwkctl.o
lwkctl-objs += $(mos-lib-objs)

ifeq ($(CONFIG_MOS_ONEAPI_LEVELZERO),y)
HOSTCFLAGS_lwkctl.o := -DCONFIG_MOS_ONEAPI_LEVELZERO
HOSTLDLIBS_lwkctl := -lm
HOSTLDLIBS_lwkctl += -lze_loader
endif

lwkctl.sh_installname := lwkctl
lwkctl.sh_installpath := /usr/bin
lwkctl.1.man_installname := lwkctl.1
lwkctl.1.man_installpath := /usr/share/man/man1

include $(src)/../Makefile.tool
