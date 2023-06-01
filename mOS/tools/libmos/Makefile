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

header-y += linux/
header-y += mos.h
header-y += uti.h

major := 1
minor := 0
soname := libmos.so.$(major)

hostprogs := libmos
scriptprogs-y := mos_get_addr_info.2 libmos.link mos.link uti.link
libmos-objs := mossyscalls.o uti.o

libmos_installname := libmos.so.$(major).$(minor)
libmos_installpath := /usr/lib64
libmos.link_installname := libmos.so
libmos.link_installpath := /usr/lib64
libmos.link_target := libmos.so.$(major).$(minor)
uti.link_installname := uti.h
uti.link_installpath := /usr/include
uti.link_target := /usr/src/$(KERNELRELEASE)/include/linux/uti.h
mos.link_installname := mos.h
mos.link_installpath := /usr/include
mos.link_target := /usr/src/$(KERNELRELEASE)/include/linux/mos.h
mos_get_addr_info.2_installname := mos_get_addr_info.2
mos_get_addr_info.2_installpath := /usr/share/man/man2

HOSTLDLIBS_libmos := -shared -lpthread -Wl,-soname,$(soname)
HOSTCFLAGS_mossyscalls.o := -fPIC
HOSTCFLAGS_uti.o := -fPIC

include $(src)/../Makefile.tool
