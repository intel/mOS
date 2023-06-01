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

header-y += xpmem/
header-y += xpmem.h

major := 0
minor := 0
soname := libxpmem.so.$(major)

hostprogs := libxpmem
scriptprogs-y := 56-xpmem.rules libxpmem.link xpmem.link
libxpmem-objs := libxpmem.o

libxpmem_installname := libxpmem.so.$(major).$(minor)
libxpmem_installpath := /usr/lib64
libxpmem.link_target := libxpmem.so.$(major).$(minor)
libxpmem.link_installpath := /usr/lib64
libxpmem.link_installname := libxpmem.so
56-xpmem.rules_installname := 56-xpmem.rules
56-xpmem.rules_installpath := /etc/udev/rules.d
xpmem.link_installname := xpmem.h
xpmem.link_installpath := /usr/include
xpmem.link_target := /usr/src/x$(KERNELRELEASE)/include/linux/mos.h

HOSTLDLIBS_libxpmem := -shared -Wl,-soname,$(soname)
HOSTCFLAGS_libxpmem.o := -fPIC -I./include/uapi/xpmem

include $(src)/../Makefile.tool