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

VIRSH ?= sudo virsh

TARGET_VM ?= $(MACHINE)
TARGET_HOST ?= $(shell $(VIRSH) domifaddr $(TARGET_VM) | sed -ne 's/ *vnet0 *[0-9a-f:]\+ *ipv[46] *\([^/]\+\).*/\1/p' | head -1)

console:
	$(VIRSH) console $(TARGET_VM)

reboot:
	$(VIRSH) reboot $(TARGET_VM)

power-cycle:
	$(VIRSH) destroy $(TARGET_VM) || :
	sleep 5
	$(VIRSH) start $(TARGET_VM)

pre-ktest::
	$(VIRSH) start $(TARGET_VM) || :
