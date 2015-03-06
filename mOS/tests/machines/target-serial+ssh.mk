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

REBOOT_OPTIONS ?=

TARGET_HOST ?= $(MACHINE)

# Without with-pty, running "ktest -m mos-slave2" in one xterm while
# running "screen -r mos-slave2" in another hangs during reboot, causing
# ktest to assume the target died. However, once ktest and its children
# terminate, the screen session returns to life.
#
# I'm pretty sure this is ultimately because ktest.pl and this ssh share
# their controlling terminal. Decoupling them fixes the issue.

console:
	with-pty -- ssh -t $(CONTROL_HOST) screen -x $(TARGET_HOST)

reboot:
	false

power-cycle:
	ssh $(CONTROL_HOST) ./reboot $(REBOOT_OPTIONS) $(TARGET_HOST)
