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

PHONY += _toolinst_ _toolinst_libxpmem _toolinst_xpmem_h

major := 0
minor := 0
soname := libxpmem.so.$(major)
libxpmem := libxpmem.so.$(major).$(minor)
libxpmem_installpath := /usr/lib
libobjs := $(obj)/libxpmem.o
xpmem_h_installpath := /usr/include
xpmem_h_srcpath := include/uapi/xpmem
xpmem_rules_installname := 56-xpmem.rules
xpmem_rules_installpath := /etc/udev/rules.d

$(obj)/$(libxpmem): $(libobjs)
	$(CC) -shared -Wl,-soname,$(soname) -o $@ $^

$(libobjs): $(obj)/%.o: $(src)/%.c
	(mkdir -p $(obj); $(CC) $(CFLAGS) -I./include/uapi/xpmem -fPIC -Wall -c $< -o $@)

quiet_cmd_lib_install = INSTALL $(5)
      cmd_lib_install = mkdir -p $(3); cp $(2) $(3)/$(4)

_toolinst_libxpmem: $(obj)/$(libxpmem)
	$(call cmd,lib_install,$<,$(INSTALL_MOD_PATH)/$(libxpmem_installpath),$(notdir $<),$(libxpmem_installpath)/$(notdir $<))

_toolinst_xpmem_h: $(xpmem_h_srcpath)/xpmem.h
	$(call cmd,lib_install,$<,$(INSTALL_MOD_PATH)/$(xpmem_h_installpath),$(notdir $<),$(xpmem_h_installpath)/$(notdir $<))

_toolinst_xpmem_rules: $(obj)/$(xpmem_rules_installname)
	$(call cmd,lib_install,$<,$(INSTALL_MOD_PATH)/$(xpmem_rules_installpath),$(notdir $<),$(xpmem_rules_installpath)/$(notdir $<))

_toolinst_: _toolinst_libxpmem _toolinst_xpmem_h _toolinst_xpmem_rules
