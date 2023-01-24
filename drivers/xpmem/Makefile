# Multi Operating System (mOS)
# Copyright (c) 2018, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

ccflags-y += -I../../include/uapi/xpmem/
obj-$(CONFIG_XPMEM) += xpmem.o
xpmem-objs := xpmem_attach.o xpmem_get.o xpmem_main.o xpmem_make.o xpmem_misc.o xpmem_mmu_notifier.o xpmem_pfn.o
