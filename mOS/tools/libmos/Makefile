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

PHONY += _toolinst_ _toolinst_libmos _toolinst_mos_h _toolinst_uti_h _mos_get_addr_info_man _libmos_man_pages

major := 1
minor := 0
soname := libmos.so.$(major)
libmos := libmos.so.$(major).$(minor)
libmos_installpath := /usr/lib
libobjs := $(obj)/mossyscalls.o $(obj)/uti.o
mos_h_installpath := /usr/include
uti_h_installpath := /usr/include
mos_h_srcpath := $(obj)/../../../include/uapi/linux/
uti_h_srcpath := $(obj)/../../../include/uapi/linux/
man_2_installpath := /usr/share/man/man2

$(obj)/$(libmos): $(libobjs)
	$(CC) -shared -Wl,-soname,$(soname) -o $@ $^

$(libobjs): $(obj)/%.o: $(src)/%.c
	$(CC) $(CFLAGS) -I./include -fPIC -Wall -c $< -o $@

quiet_cmd_lib_install = INSTALL $(5)
      cmd_lib_install = mkdir -p $(3); cp $(2) $(3)/$(4)

_toolinst_libmos: $(obj)/$(libmos)
	$(call cmd,lib_install,$<,$(INSTALL_MOD_PATH)/$(libmos_installpath),$(notdir $<),$(libmos_installpath)/$(notdir $<))

_toolinst_mos_h: $(mos_h_srcpath)/mos.h
	$(call cmd,lib_install,$<,$(INSTALL_MOD_PATH)/$(mos_h_installpath),$(notdir $<),$(mos_h_installpath)/$(notdir $<))

_toolinst_uti_h: $(uti_h_srcpath)/uti.h
	$(call cmd,lib_install,$<,$(INSTALL_MOD_PATH)/$(uti_h_installpath),$(notdir $<),$(uti_h_installpath)/$(notdir $<))

_mos_get_addr_info_man: $(src)/mos_get_addr_info.2
	$(call cmd,lib_install,$<,$(INSTALL_MOD_PATH)/$(man_2_installpath),$(notdir $<),$(man_2_installpath)/$(notdir $<))

_libmos_man_pages: _mos_get_addr_info_man

_toolinst_: _toolinst_libmos _toolinst_mos_h _toolinst_uti_h _libmos_man_pages
