#!/bin/bash
#
# Multi Operating System (mOS for HPC)
# Copyright (c) 2018, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#

MOSVIEW=
PROCID=

function help() {
    echo "Usage: mosview [OPTIONS] [CMD] [ARGS]" >&2
    echo "" >&2
    echo "OPTIONS" >&2
    echo "-s VIEW   Runs command CMD in the specified mOS view" >&2
    echo "          VIEW - linux, lwk, all" >&2
    echo "-p PID    If -s VIEW is specified then the mOS view of PID will" >&2
    echo "          be set to VIEW otherwise prints current mOS view of PID" >&2
    echo "-h        Display this help" >&2
}

function print_mos_view() {
    pdir=/proc/$1
    if [[ ! -e $pdir ]]; then
        echo "mosview: PID $1 does not exist"
        exit 1
    fi
    MOSVIEW_GET=$(cat ${pdir}/mos_view)
    echo "mosview: mOS view of PID $1 - [$MOSVIEW_GET]"
}

# $1 - pid of process
# $2 - mOS view to be set
function set_mos_view() {
    pdir=/proc/$1
    if [[ ! -e $pdir ]]; then
        echo "mosview: PID $1 does not exist"
        exit 1
    fi

    # Set the requested mOS view
    echo $2 > ${pdir}/mos_view
    # Verify
    MOSVIEW_SET=$(cat ${pdir}/mos_view)
    if [[ $2 != $MOSVIEW_SET ]]; then
        echo "mosview: PID $1 failed to set mOS view: $2"
        exit 1
    fi
}

# Make sure the kernel is mOS kernel
if [[ ! -e /proc/self/mos_view ]]; then
    echo "mosview: Not a mOS kernel [ `uname -r` ]"
    exit 1
fi

# If no args are supplied then print help
if [[ $# -eq 0 ]]; then
    help
    exit 0
fi

# Parse command line args
while getopts ":hs:p:" opt; do
    case $opt in
    s)
	case $OPTARG in
	    linux | lwk | all)
		MOSVIEW=$OPTARG
		;;
	    *)
		echo "mosview: Invalid mOS view: $OPTARG" >&2
		help
		exit 1
		;;
	esac
	;;
   p)
        PROCID=$OPTARG
        ;;
   h)
	help
	exit 0
	;;
    \?)
	echo "mosview: Invalid option: -$OPTARG" >&2
	help
	exit 1
	;;
    :)
	echo "mosview: Option -$OPTARG requires an argument." >&2
	help
	exit 1
	;;
    esac
done

if [[ $MOSVIEW != "" ]]; then
    if [[ $PROCID != "" ]]; then
        set_mos_view $PROCID $MOSVIEW
        print_mos_view $PROCID
    else
        shift 2
        if test -z "$1"; then
            echo "mosview: Invalid input specify a target command or PID"
            help
            exit 1
        else
            set_mos_view self $MOSVIEW
            exec "$@"
        fi
    fi
elif [[ $PROCID != "" ]]; then
        print_mos_view $PROCID
fi
