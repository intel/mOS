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

KERNEL ?= $(abspath $(dir $(abspath $(dir $(CURDIR)))))
OUTPUT ?= $(CURDIR)

find_tests = $(shell find $(testdirs) -type f -name $(1))
testdirs := $(sort $(dir $(wildcard */*.py)))
kbuild := $(call find_tests,Kbuild)
systap := $(call find_tests,'*.stp')

targets := $(kbuild) $(systap)
tests := $(sort $(patsubst %/, %, $(dir $(targets))))

.PHONY: all clean help copy-source
.PHONY: kbuild stap kbuild-clean stap-clean
.PHONY: $(targets) $(tests) $(tests:%=%-all) $(tests:%=%-clean)
.PHONY: $(tests:%=%-kbuild) $(tests:%=%-stap)
.PHONY: $(tests:%=%-kbuild-clean) $(tests:%=%-stap-clean)

# the 'convienience targets'

all: kbuild stap
clean: kbuild-clean stap-clean

help:
	@printf '\n'
	@printf 'Supported Variables:\n'
	@printf '\t%-10s %s\n' \
		'KERNEL' 'path to kernel build directory' \
		'OUTPUT' 'path to test build/source directory'
	@printf '\n'
	@printf 'Supported Targets:\n'
	@printf '\t%s\n' help all clean copy-source
	@printf '\t%s{,-clean}\n' kbuild stap
	@printf '\t%s{,-kbuild,-stap}{,-clean}\n' $(tests)
	@printf '\n'
	@false

copy-source:
	[ "$(OUTPUT)" != "$(CURDIR)" ]
	mkdir -p $(OUTPUT)
	cp -a suite *.py $(testdirs) $(OUTPUT)

kbuild: $(tests:%=%-kbuild)
stap: $(tests:%=%-stap)

kbuild-clean: $(tests:%=%-kbuild-clean)
stap-clean: $(tests:%=%-stap-clean)

define test-targets
$(1): $(1)-all
$(1)-all: $(1)-kbuild $(1)-stap
$(1)-clean: $(1)-kbuild-clean $(1)-stap-clean

$(1)-kbuild: $(filter $(1)/Kbuild, $(targets))
$(1)-stap: $(filter $(1)/%.stp, $(targets))

$(1)-kbuild-clean: $(patsubst %,%-clean,$(filter $(1)/Kbuild, $(targets)))
$(1)-stap-clean: $(patsubst %,%-clean,$(filter $(1)/%.stp, $(targets)))
endef

$(foreach t,$(tests),$(eval $(call test-targets,$(t))))

$(kbuild): %/Kbuild:
	$(MAKE) -C $(KERNEL) M=$(OUTPUT)/$* modules

$(kbuild:%=%-clean): %/Kbuild-clean:
	$(MAKE) -C $(KERNEL) M=$(OUTPUT)/$* clean

$(systap): %.stp:
	mkdir -p $(OUTPUT)/$(dir $@)
	cd $(OUTPUT)/$(dir $@) && stap -v -p 4 -r $(KERNEL) \
		$(notdir $@) -m $(notdir $*)_stap.ko

$(systap:%=%-clean): %.stp-clean:
	rm -f $(OUTPUT)/$*_stap.ko
