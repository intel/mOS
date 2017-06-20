# Multi Operating System (mOS)
# Copyright (c) 2017, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.

from mostests import *
from mosunit import run
from mostests import run as run_bin
from yod import CpuSet
from yod import CpuTopology
import subprocess
import collections
import math

def create_and_verify(obj, lwkcpus_spec, sccpus_req, lwkcpus_req, v='-v 0'):
    def get_cpus():
        sccpus = CpuSet(0)
        lwkcpus = CpuSet(0)

        op, rc = run(['lwkctl', v, '-s'])

        lines = op.splitlines()
        for l in lines:
            if l.startswith('Syscall CPU(s):'):
                f,m,s = l.partition('Syscall CPU(s):')
                s = s.strip()
                if s != '':
                    sccpus.fromList(s)
            if l.startswith('LWK     CPU(s):'):
                f,m,s = l.partition('LWK     CPU(s):')
                s = s.strip()
                if s != '':
                    lwkcpus.fromList(s)
        return sccpus, lwkcpus

    def get_profile(spec=None):
        if spec == None:
            op, rc = run(['lwkctl', v, '-s', '-r'])
        else:
            op, rc = spec, 0
        for token in op.split():
            if token.startswith('lwkcpu_profile='):
                f,m,l = token.partition('lwkcpu_profile=')
                return l
        return ''

    # Create LWK partition
    out, rc = run(['sudo', 'lwkctl', v, '-c', lwkcpus_spec])

    # Read and verify LWK partition  using lwkctl -s

    # Verify CPUs
    sccpus, lwkcpus = get_cpus()
    if sccpus != sccpus_req or lwkcpus != lwkcpus_req:
        if sccpus != sccpus_req:
            logging.error('Mismatch : Syscall CPUs')
            logging.error('Requested: {}'.format(sccpus_req.toList()))
            logging.error('Created  : {}'.format(sccpus.toList()))
        if lwkcpus != spec.lwkcpus:
            logging.error('Mismatch : LWK CPUs')
            logging.error('Requested: {}'.format(lwkcpus_req.toList()))
            logging.error('Created  : {}'.format(lwkcpus.toList()))

    assert(sccpus == sccpus_req)
    assert(lwkcpus == lwkcpus_req)

    # Verify LWK CPU profile
    profile_req = get_profile(lwkcpus_spec)
    profile_set = get_profile()

    msg = 'LWKCPU profile requested: {} set: {}'.format(profile_req, profile_set)
    logging.debug(msg)
    if (profile_req == 'debug'):
        assert(profile_set == profile_req), 'Mismatch: ' + msg
    else:
        assert(profile_set == 'normal'), 'Mismatch: ' + msg

    # Run tests on LWK
    yod(obj, '-u', 0, '../lwksched/aff_scan', '-efm')

    # Delete partition
    run(['sudo', 'lwkctl', v, '-d'])

    # Read and verify using lwkctl -s
    sccpus, lwkcpus = get_cpus()
    profile_set = get_profile()

    assert(sccpus == CpuSet(0))
    assert(lwkcpus == CpuSet(0))
    assert(profile_set == '')

    # Run tests on Linux
    run_bin(obj, '../lwksched/aff_scan')

class Spec:
    def __init__(self, topology=None):
        if topology is None:
            self.topology = CpuTopology()
        else:
            self.topology = topology

    # Create LWKCPU partition spec for the specified fraction of
    # CPUs to be of LWKCPUs
    def create_lwkcpu_spec(self, ratio):
        lwkcpuspec = 'lwkcpus='
        self.lwkcpus = CpuSet(0)
        self.sccpus = CpuSet(0)
        self.n_cpus = self.topology.allcpus.countCpus()

        assert(self.n_cpus > 0), "Invalid topology"
        if ratio >= 1:
            lwkcpuspec += '0.{}'.format(self.topology.allcpus.toList())
            return lwkcpuspec
        elif ratio <= 0:
            return lwkcpuspec

        self.n_lwkcpus = int(ratio * self.n_cpus)
        self.n_linuxcpus = self.n_cpus - self.n_lwkcpus
        lwkcpus_per_sc_cpu = math.ceil(self.n_lwkcpus/self.n_linuxcpus)

        assert(self.n_lwkcpus > 0), 'Invalid no. of LWKCPUs'
        assert(self.n_linuxcpus > 0), 'Invalid no. of Linux CPUs'
        assert(lwkcpus_per_sc_cpu > 0), 'Invalid no. of LWKCPUs per syscall CPU'

        logging.debug('Total CPUs      : {}'.format(self.n_cpus))
        logging.debug('Total LWK CPUs  : {}'.format(self.n_lwkcpus))
        logging.debug('Total Linux CPUs: {}'.format(self.n_linuxcpus))
        logging.debug('LWK CPUs per syscall CPU: {}'.format(lwkcpus_per_sc_cpu))

        sc = 0
        lwkcpus_count = 0
        mask = CpuSet(0)

        for i in range(self.n_linuxcpus, self.n_cpus):
            if lwkcpus_count >= lwkcpus_per_sc_cpu:
                if lwkcpuspec != 'lwkcpus=':
                    lwkcpuspec += ':'
                lwkcpuspec += '{}.{}'.format(sc, mask.toList())
                self.lwkcpus += mask
                self.sccpus += self.topology.allcpus.nthCpu(sc+1)
                sc += 1
                mask = CpuSet(0)
                lwkcpus_count = 0

            mask += self.topology.allcpus.nthCpu(i+1)
            lwkcpus_count += 1

        if lwkcpus_count != 0:
            if lwkcpuspec != 'lwkcpus=':
                lwkcpuspec += ':'
            lwkcpuspec += '{}.{}'.format(sc, mask.toList())
            self.lwkcpus += mask
            self.sccpus += self.topology.allcpus.nthCpu(sc+1)
        return lwkcpuspec

class Partition(TestCase):
    require = [ LWKCTL, YOD ]

    def test_valid_partition(self):
        v = '-v 3' if ARGS.test_debug else '-v 0'

        # Partition CPUs in following ratio between Linux and LWK
        ratio = [ 0.25, 0.5, 0.75, 0.90 ]
        spec = Spec()

        for r in ratio:
            logging.debug('Testing LWK CPUs fraction: {}'.format(r))
            s = spec.create_lwkcpu_spec(r)
            self.assertNotEqual(s, 'lwkcpus=', 'Failed to create LWK partition spec')
            create_and_verify(self, s, spec.sccpus, spec.lwkcpus, v)

    def test_invalid_partition(self):
        v = '-v 3' if ARGS.test_debug else '-v 0'

        spec = Spec()
        lwkcpus_spec = spec.create_lwkcpu_spec(0.90)

        self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWK partition spec')

        # Manufacture an invalid spec by adding invalid CPU numbers
        N = spec.n_cpus
        lwkcpus_spec += ':{}.{}-{}'.format(N, N+1, N+10)

        logging.debug('Trying to create LWK partition: ' + lwkcpus_spec)

        # Try to create a partition with CPUs which are not present
        out, rc = run(['sudo', 'lwkctl', v, '-c', lwkcpus_spec])
        self.assertFalse(rc == 0, 'Created LWK partition for invalid spec: {}'.format(lwkcpus_spec))

    def test_invalid_spec(self):
        v = '-v 3' if ARGS.test_debug else '-v 0'

        spec = Spec()
        lwkcpus_spec = spec.create_lwkcpu_spec(0.90)
        self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWK partition spec')

        invalid_lwkcpu_spec = [ lwkcpus_spec.strip('lwkcpus='),    # Missing lwkcpus=
                                lwkcpus_spec.strip('lwkcpus'),     # Missing lwkcpus
                                lwkcpus_spec.replace('lwkcpus', 'lwkcpu'),  # Typo in lwkcpus
                                lwkcpus_spec.replace('=', ' '),    # Missing '=' sign
                                lwkcpus_spec.replace('.', ',', 1), # Missing syscall CPU to LWK CPU mapping
                                lwkcpus_spec.replace(lwkcpus_spec, '@*$^)_!#'), # Total garbage
                              ]
        if lwkcpus_spec.find(':') != -1:
            invalid_lwkcpu_spec += [ lwkcpus_spec.replace(':', ',', 1) ] # Missing delimiter ':' between mappings ]

        for s in invalid_lwkcpu_spec:
            logging.debug('Testing spec: ' + s)
            out, rc = run(['sudo', 'lwkctl', v, '-c', s])
            self.assertFalse(rc == 0, 'Created LWK partition for invalid spec: {}'.format(s))

class Profile(TestCase):
    require = [ LWKCTL, YOD ]

    def test_profiles(self):
        profiles = [ 'normal',  # normal profile, this is also the default profile
                     'debug',   # debug profile with no filtering of hotplug states
                     '',        # Test case for testing default profile
                     'normal1', # Invalid profiles, kernel should use default profile
                     'debug8',
                     '123' ]

        v = '-v 3' if ARGS.test_debug else '-v 0'
        spec = Spec()
        lwkcpus_spec = spec.create_lwkcpu_spec(0.90)

        for p in profiles:
            if p != '':
                p = ' lwkcpu_profile=' + p
            s = lwkcpus_spec + p
            logging.debug('Testing spec: ' + s)
            create_and_verify(self, s, spec.sccpus, spec.lwkcpus, v)

