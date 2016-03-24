#!/bin/sh

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

if [ $# -ne 1 ] || [ -z "$1" ]; then
	echo "Usage: $0 <output-dir>" 1>&2
	exit 1
fi

d=/sys/kernel/debug/gcov
set -xe

rm -fr "$1"

# a funky approach really is necessary; plain tar doesn't work
# see Documentation/gcov.txt, Appendix B
find $d -type d -exec mkdir -p "$1/{}" ";"
find $d -name '*.gcda' -exec sh -c "cat <\$0 >'$1'/\$0" "{}" ";"
find $d -name '*.gcno' -exec sh -c "cp -d \$0 '$1'/\$0" "{}" ";"

tar -czf "$1.tgz" -C "$1$d" .
echo > $d/reset
