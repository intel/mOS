#!/bin/bash

# Simple command line argument check
if [ -z $1 ]; then
    echo "Usage: build-mos.sh <kernel-source root>"
    exit 1
fi

if ! [ -f $1/series.conf ]; then
    echo "$1 is not a kernel-source root directory"
    exit 1
else
    KSRCDIR=$(readlink -f $1)
fi

# Set base reference to mOS source root
RUNDIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
MOSDIR=${RUNDIR%/mOS/_build}

source ${RUNDIR}/mOS.conf

# Switch to the correct kernel-source branch
cd ${KSRCDIR}
if ! [ "$(git rev-parse --short HEAD)" = "${KS_HEAD}" ]; then
    echo "Checking out kernel-source HEAD: ${KS_HEAD}"
    git stash
    if ! git switch --detach ${KS_HEAD}; then
        echo "error: could not check out ${KS_HEAD}"
        exit 1
    fi
    if ! git reset --hard; then
        echo "error: could not reset branch ${KS_HEAD}"
        exit 1
    fi
fi

# Download any missing kernel.org source files
if ! [ -f linux-${KVER}.tar.xz ]; then
    KVER_X="v`echo ${KVER} | cut -d"." -f1`.x"
	echo "Downloading linux-${KVER}.tar.xz..."
    if ! wget https://cdn.kernel.org/pub/linux/kernel/${KVER_X}/linux-${KVER}.tar.xz 2>/dev/null; then
        echo "error: downloading (.xz) source for kernel ${KVER}"
        exit 1
    fi
fi
if ! [ -f linux-${KVER}.tar.sign ]; then
	echo "Downloading linux-${KVER}.tar.sign..."
    if ! wget https://cdn.kernel.org/pub/linux/kernel/${KVER_X}/linux-${KVER}.tar.sign 2>/dev/null; then
        echo "error: downloading signature for kernel ${KVER}"
        exit 1
    fi
fi

# Update kernel sources with mOS
cd $MOSDIR

MOS_HEAD=$(git rev-parse --short HEAD)

# Create a new patchfile
git -p diff $KERNEL_HEAD -- ':!*mOS/_build*' > $KSRCDIR/patches.kabi/mOS.patch

# Copy the mOS kernel config as a new configuration flavor
cat $MOSDIR/config.mos > $KSRCDIR/config/x86_64/mOS

# Update the build configuration in kernel-source
cd $KSRCDIR

# Turn off all kernel builds except for mOS
printf "+x86_64\tx86_64/mOS\n" > config.conf

# Add the mOS patch to the list of kernel patches
if ! grep -q "/mOS.patch" series.conf; then
    printf "\tpatches.kabi/mOS.patch\n" >> series.conf
fi

# Update the description file
if ! grep -q "=== kernel-mOS ===" rpm/package-descriptions; then
    cat ${RUNDIR}/description >> rpm/package-descriptions
fi

# Update the specfile templates
# Update the kernel package requirements
sed -i "/^# The following is copied to the -base subpackage/e cat ${RUNDIR}/spec-requires" rpm/kernel-binary.spec.in
# Add the mOS package to the kernel specfile just before the changelog
sed -i "/^%changelog/e cat ${RUNDIR}/spec-package" rpm/kernel-binary.spec.in
# Force the release to match the kernel-mOS release
sed -i "/^Release:.*%kernel_source_release/d" rpm/kernel-syms.spec.in
# Disable the vanilla source build
sed -i "/^%define do_vanilla/c\%define do_vanilla 0" rpm/kernel-source.spec.in


# Generate the new kernel source tarball and specfiles
rm -f kernel-source/*
./scripts/tar-up.sh -a x86_64 -f mOS -rs "$RELEASE+mOS_$MOS_HEAD"

# Prepare the local RPM build tree
# Get the current build directory
BUILD_DIR=$(rpmbuild -E "%_topdir")
# Copy the new sources to the build tree
cp -a kernel-source/* ${BUILD_DIR}/SOURCES/
# Restore the previous branch
git reset --hard
git switch --discard-changes -
# Move the specfiles
cd ${BUILD_DIR}
mv SOURCES/*.spec SPECS/
# Build the RPMs
echo "### Building kernel-syms" && sleep 3
if ! rpmbuild -bb --define 'opensuse_bs 1' SPECS/kernel-syms.spec; then
    echo "error: Could not build kernel-syms"
    exit 1
fi
echo "### Building kernel-source" && sleep 3
if ! rpmbuild -bb SPECS/kernel-source.spec; then
    echo "error: Could not build kernel-source"
    exit 1
fi
echo "### Building kernel-mOS" && sleep 3
if ! rpmbuild -bb SPECS/kernel-mOS.spec; then
    echo "error: Could not build kernel-mOS"
    exit 1
fi

printf "\n\n======== DONE ========\n"
ls -1 ${BUILD_DIR}/RPMS/*
