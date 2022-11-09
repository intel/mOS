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

mos_tools_inc := $(src)/../include
HOST_EXTRACFLAGS += -Wextra -g -I$(mos_tools_inc)

always-$(CONFIG_MOS_FOR_HPC) := $(hostprogs)

tools := $(hostprogs) $(scriptprogs-y)

quiet_cmd_tool_install = INSTALL $(5)
      cmd_tool_install = mkdir -p $(3); cp $(2) $(3)/$(4)

_toolinst_: $(tools:%=%_toolinst_)

_tool_path = $(if $($*_installpath),$(INSTALL_MOD_PATH)/$($*_installpath),$(MODLIB))
_tool_name = $(if $($*_installname),$($*_installname),$*)
_tool_prnt = $(if $($*_installpath),$($*_installpath)/)$(_tool_name)
$(tools:%=%_toolinst_): %_toolinst_: $(obj)/%
	$(call cmd,tool_install,$<,$(_tool_path),$(_tool_name),$(_tool_prnt))

PHONY += _toolinst_ $(tools:%=%_toolinst_)
