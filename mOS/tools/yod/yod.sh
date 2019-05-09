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

yod="/lib/modules/`uname -r`/yod"
if ! [ -x "$yod" ]; then
	cat 1>&2 <<EOF
$0: `uname -r` is not a mOS kernel

If you want to run yod anyway, you must invoke one directly; look in
/lib/modules/*/yod.
EOF
	exit 1
fi
exec "$yod" "$@"
