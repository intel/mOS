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

MACHINE ?= $(error $$MACHINE unset)
TMP_DIR ?= $(error $$TMP_DIR unset)
BUILD_DIR ?= $(error $$BUILD_DIR unset)
OUTPUT_DIR ?= $(error $$OUTPUT_DIR unset)
HOOKLIST ?= $(error $$HOOKLIST unset)

KERNEL_VERSION ?= $(error $$KERNEL_VERSION unset)
SSH_COMMAND ?= $(error $$SSH_COMMAND unset)
SRC_FILE ?= $(error $$SRC_FILE unset)
DST_FILE ?= $(error $$DST_FILE unset)

KTEST_CONFIG_OPTIONS ?=
CONFIG_COVERAGE = $(if $(filter gcov,$(KTEST_CONFIG_OPTIONS)),y)

test_subdir := $(shell realpath --relative-to=$(KTEST_KERNEL) $(KTEST_TESTS))

TARGET_SSH = ssh $(TARGET_USER)@$(TARGET_HOST)
TARGET_SUDO = sudo-on-target $(TARGET_USER)@$(TARGET_HOST)

.PHONY: all ssh scp install console pre-reboot reboot power-cycle
.PHONY: pre-ktest post-ktest
.PHONY: pre-build post-build
.PHONY: pre-install post-install
.PHONY: pre-test post-test

all:
	false #ERROR

# this is the order in which the hooks are executed
pre-ktest::
pre-test::
pre-build::
post-build::
pre-install::
post-install::
post-test::
post-ktest::

include cmdline.mk
include names/$(MACHINE).mk

pre-build::
	echo -ktest > $(OUTPUT_DIR)/localversion-9

ssh:
	$(TARGET_SUDO) $(SSH_COMMAND)

scp:
	scp $(SRC_FILE) $(TARGET_USER)@$(TARGET_HOST):$(DST_FILE)

install:
	$(TARGET_SUDO) bash -c 'rm -r /lib/modules/*-ktest-* || :'
	scp $(SRC_FILE) $(TARGET_USER)@$(TARGET_HOST):__target_install__
	$(TARGET_SUDO) mv -f __target_install__ $(DST_FILE)

include $(foreach h,$(HOOKLIST),ktests/$(h).mk)

.NOTPARALLEL:
override MAKEFLAGS :=
