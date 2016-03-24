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

pre-build::
	$(KTEST_SCRIPTS)/config -C $(BUILD_DIR) -O $(OUTPUT_DIR)
ifeq ($(CONFIG_COVERAGE),y)
	$(BUILD_DIR)/scripts/config --file $(OUTPUT_DIR)/.config \
		-e CONFIG_DEBUG_FS \
		-e CONFIG_GCOV_KERNEL \
		-e CONFIG_GCOV_PROFILE_ALL
	make -C $(BUILD_DIR) olddefconfig O=$(OUTPUT_DIR)
endif
	mv $(OUTPUT_DIR)/.config $(OUTPUT_DIR)/config.mos

ifeq ($(CONFIG_COVERAGE),y)
gcov-tar = mos-gcov

post-install::
	$(TARGET_SUDO) 'mount -t debugfs none /sys/kernel/debug || :'
	scp $(KTEST_TESTS)/bin/gather-coverage.sh \
		$(TARGET_USER)@$(TARGET_HOST):

post-test::
	$(TARGET_SUDO) sh gather-coverage.sh $(gcov-tar)
	scp $(TARGET_USER)@$(TARGET_HOST):$(gcov-tar).tgz \
		$(KTEST_OUTPUT)/$(gcov-tar).tgz
endif
