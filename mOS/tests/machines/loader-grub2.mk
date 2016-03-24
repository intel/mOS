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

KERNEL_CMDLINE ?= $(error $$KERNEL_CMDLINE unset)

TARGET_INITRAMFS = $(subst vmlinuz-,initramfs-,$(TARGET_IMAGE)).img

pre-reboot::
	${TARGET_SUDO} grub2-editenv - set next_options='$(KERNEL_CMDLINE)'
	${TARGET_SUDO} grub2-reboot 'KTest Kernel'
