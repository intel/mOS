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
import fileinput
lwkmem_static=False

def create_and_verify(obj, lwk_spec, sccpus_req, lwkcpus_req, v='0'):
    def get_cpus():
        sccpus = CpuSet(0)
        lwkcpus = CpuSet(0)

        op, rc = run(['lwkctl', '-v', v, '-s'])

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
            op, rc = run(['lwkctl', '-v', v, '-s', '-r'])
        else:
            op, rc = spec, 0
        for token in op.split():
            if token.startswith('lwkcpu_profile='):
                f,m,l = token.partition('lwkcpu_profile=')
                return l
        return ''

    def get_lwkmem(spec=None):
        if spec == None:
            op, rc = run(['lwkctl', '-v', v, '-s', '-r'])
        else:
            op, rc = spec, 0
        units = ['K', 'M', 'G', 'T', 'P', 'E']
        total_size = 0
        for token in op.split():
            if token.startswith('lwkmem='):
                f,m,l = token.partition('=')
                l = l.strip()
                if l != '':
                    for node_spec in l.split(','):
                        node,delimiter,size = node_spec.partition(':')
                        if delimiter == '':
                            size = node
                        size = size.strip()
                        if size != '':
                            multiplier = 1
                            if size.endswith(('K', 'M', 'G', 'T', 'P', 'E')):
                                for u in units:
                                    index = size.find(u)
                                    if index != -1:
                                        multiplier = 1024**(1+units.index(u))
                                        break
                                size = size.strip('KMGTPE')
                            total_size += int(size) * multiplier
        return total_size

    # Create LWK partition
    lwk_spec = lwk_spec.strip()
    out, rc = run(['sudo', 'lwkctl', '-v', v, '-c', lwk_spec])

    # Read and verify LWK partition  using lwkctl -s

    # Verify CPUs
    sccpus, lwkcpus = get_cpus()
    if sccpus != sccpus_req or lwkcpus != lwkcpus_req:
        if sccpus != sccpus_req:
            logging.error('Mismatch : Syscall CPUs')
            logging.error('Requested: {}'.format(sccpus_req.toList()))
            logging.error('Created  : {}'.format(sccpus.toList()))
        if lwkcpus != lwkcpus_req:
            logging.error('Mismatch : LWK CPUs')
            logging.error('Requested: {}'.format(lwkcpus_req.toList()))
            logging.error('Created  : {}'.format(lwkcpus.toList()))

    assert(sccpus == sccpus_req)
    assert(lwkcpus == lwkcpus_req)

    # Verify LWK CPU profile
    profile_req = get_profile(lwk_spec)
    profile_set = get_profile()
    msg = 'LWKCPU profile requested: {} set: {}'.format(profile_req, profile_set)
    logging.debug(msg)
    if (profile_req == 'debug'):
        assert(profile_set == profile_req), 'Mismatch: ' + msg
    else:
        assert(profile_set == 'normal'), 'Mismatch: ' + msg

    # Verify LWK Memory
    if not lwkmem_static:
        lwkmem_req = get_lwkmem(lwk_spec)
        lwkmem_set = get_lwkmem()
        msg = 'LWKMEM requested {} allocated {}'.format(lwkmem_req, lwkmem_set)
        logging.debug(msg)

        if lwkmem_req != 0:
            assert(lwkmem_set > 0), 'LWK memory partition was not created'
            assert(lwkmem_set <= lwkmem_req), 'Mismatch ' + msg

    # Run tests on LWK
    yod(obj, '-u', 0, '../lwksched/aff_scan', '-efm')

    if not lwkmem_static:
        yod(obj, '../lwkmem/maptest', '--verbose', '--type', 'anonymous', '--num', 10, '--size', 4096, '--iterations', 10)

    # Delete partition
    run(['sudo', 'lwkctl', '-v', v, '-d'])

    # Read and verify using lwkctl -s
    sccpus, lwkcpus = get_cpus()
    profile_set = get_profile()

    assert(sccpus == CpuSet(0))
    assert(lwkcpus == CpuSet(0))
    assert(profile_set == '')

    if not lwkmem_static:
        lwkmem_set = get_lwkmem()
        assert(lwkmem_set == 0), 'Failed to delete LWKMEM partition'

    # Run tests on Linux
    run_bin(obj, '../lwksched/aff_scan')

class Spec:
    def __init__(self, topology=None):
        global lwkmem_static

        if topology is None:
            self.topology = CpuTopology()
        else:
            self.topology = topology

        fname='/proc/cmdline'
        idx1= idx2 = -1
        for line in fileinput.input(fname, mode='r'):
            idx1 = line.find('lwkmem_static')
            if idx1 != -1:
                idx2 = line.find('lwkmem=')
        fileinput.close()

        if idx1 != -1:
            if idx2 != -1:
                lwkmem_static = idx1 < idx2
            else:
                lwkmem_static = True

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

    def create_lwkmem_spec(self, ratio):
        def get_node_spec(node, size):
            if size <= 0:
                return ''
            unit = ['K', 'M', 'G', 'T', 'P', 'E']
            q = size
            for i in range(0,len(unit)):
                q, r = divmod(q, 1024)
                if q == 0 or r != 0:
                    break
            if i != 0:
                return '{}:{}{}'.format(int(node), size // (1 << (10*i)), unit[i-1])
            else:
                return '{}:{}'.format(int(node), size)

        if lwkmem_static:
            op, rc = run(['lwkctl', '-v', '0', '-s', '-r'])
            for token in op.split():
                if token.startswith('lwkmem='):
                    if token != 'lwkmem=':
                        return token
            return ''

        lwkmem_spec='lwkmem='
        movable_mem = []
        fname='/proc/buddyinfo'
        for line in fileinput.input(fname, mode='r'):
            if line.startswith('Node'):
                tokens = line.split()
                if tokens[0] == 'Node' and tokens[3] == 'Movable':
                    order = pages = 0
                    for t in tokens[4:]:
                        pages += int(t) * (1 << order)
                        order += 1
                    node = int(tokens[1].strip(' ,'))
                    movable_mem += [(node, math.floor(pages * 4096 * ratio))]
        fileinput.close()

        for node,size in movable_mem:
            node_spec = get_node_spec(node, size)
            if node_spec != '':
                if lwkmem_spec != 'lwkmem=':
                    lwkmem_spec += ','
                lwkmem_spec += node_spec

        if lwkmem_spec == 'lwkmem=':
            return ''
        else:
            return lwkmem_spec

class Partition(TestCase):
    require = [ LWKCTL, YOD ]

    def test_valid_partition(self):
        v = '3' if ARGS.test_debug else '0'

        # Partition CPUs in following ratio between Linux and LWK
        ratio = [ 0.25, 0.5, 0.75, 0.90 ]
        spec = Spec()

        for r in ratio:
            logging.debug('Testing LWK CPUs fraction: {}'.format(r))
            lwkcpus_spec = spec.create_lwkcpu_spec(r)
            self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWKCPU partition spec')
            lwkmem_spec = spec.create_lwkmem_spec(r)
            self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')
            s = '{} {}'.format(lwkcpus_spec, lwkmem_spec)
            logging.debug('Testing LWK partition spec: {}'.format(s))
            create_and_verify(self, s, spec.sccpus, spec.lwkcpus, v)

    @unittest.skipUnless(ARGS.all_tests, 'Long running test.')
    def test_recreate_repeat(self):
        for count in range(4):
            logging.debug('Test count: {}'.format(count + 1))
            self.test_valid_partition()

    def test_invalid_partition(self):
        v = '3' if ARGS.test_debug else '0'

        spec = Spec()
        lwkcpus_spec = spec.create_lwkcpu_spec(0.90)
        self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWKCPU partition spec')
        lwkmem_spec = spec.create_lwkmem_spec(0.90)
        self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')

        # Manufacture an invalid spec by adding invalid CPU numbers
        N = spec.n_cpus
        lwkcpus_spec += ':{}.{}-{}'.format(N, N+1, N+10)

        # Try to create a partition with CPUs which are not present
        s = '{} {}'.format(lwkcpus_spec, lwkmem_spec)
        logging.debug('Testing LWK partition: {}'.format(s))

        out, rc = run(['sudo', 'lwkctl', '-v', v, '-c', s])
        self.assertFalse(rc == 0, 'Created LWK partition for invalid spec: {}'.format(s))

    def test_invalid_spec(self):
        v = '3' if ARGS.test_debug else '0'

        spec = Spec()
        lwkcpus_spec = spec.create_lwkcpu_spec(0.90)
        self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWK partition spec')
        lwkmem_spec = spec.create_lwkmem_spec(0.90)
        self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')

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
            s = '{} {}'.format(s, lwkmem_spec)
            logging.debug('Testing spec: ' + s)
            out, rc = run(['sudo', 'lwkctl', '-v', v, '-c', s])
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

        v = '3' if ARGS.test_debug else '0'
        spec = Spec()
        lwkcpus_spec = spec.create_lwkcpu_spec(0.90)
        self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWK partition spec')
        lwkmem_spec = spec.create_lwkmem_spec(0.90)
        self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')

        for p in profiles:
            if p != '':
                p = 'lwkcpu_profile={}'.format(p)
                s = '{} {} {}'.format(lwkcpus_spec, p, lwkmem_spec)
            else:
                s = '{} {}'.format(lwkcpus_spec, lwkmem_spec)

            logging.debug('Testing spec: {}'.format(s))
            create_and_verify(self, s, spec.sccpus, spec.lwkcpus, v)
