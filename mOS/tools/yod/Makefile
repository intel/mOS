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

hostprogs := yod
scriptprogs-y := yod.sh yod.1.man 02-mos.rules
mos-lib-objs := ../lib/mos_cpuset.o
yod-objs := yod.o mos_plugin.o test_plugin.o yod_cpuset.o layout.o numa.o
yod-objs += $(mos-lib-objs)

HOSTLDLIBS_yod := -lm

yod.sh_installname := yod
yod.sh_installpath := /usr/bin
yod.1.man_installname := yod.1
yod.1.man_installpath := /usr/share/man/man1
02-mos.rules_installname := 02-mos.rules
02-mos.rules_installpath := /etc/udev/rules.d

include $(src)/../Makefile.tool
