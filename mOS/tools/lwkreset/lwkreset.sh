#!/bin/sh

# Multi Operating System (mOS)
# Copyright (c) 2019, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

lwkreset="/lib/modules/`uname -r`/lwkreset"
if ! [ -x "$lwkreset" ]; then
	cat 1>&2 <<EOF
$0: `uname -r` is not an mOS kernel.

If you want to run lwkreset anyway, you must invoke one directly; look in
/lib/modules/*/lwkreset.
EOF
	exit 1
fi
exec "$lwkreset" "$@"
