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

suite-out = $(OUTPUT_DIR)/$(test_subdir)
suite-tar = mos-suite

post-build::
	make -C $(KTEST_TESTS) copy-source OUTPUT=$(suite-out)
	make -C $(KTEST_TESTS) KERNEL=$(OUTPUT_DIR) OUTPUT=$(suite-out)
	tar -czf $(KTEST_OUTPUT)/$(suite-tar).tgz \
		--transform='s/^\./$(suite-tar)/' -C $(suite-out) .

post-install::
	scp $(KTEST_OUTPUT)/$(suite-tar).tgz $(TARGET_USER)@$(TARGET_HOST):
	$(TARGET_SSH) 'rm -fr $(suite-tar); tar -xf $(suite-tar).tgz'

post-test::
	true

.PHONY: suite

suite:
	$(TARGET_SUDO) time $(suite-tar)/suite -vv --unbuffered
