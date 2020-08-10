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
import re
lwkmem_static=False

def create_and_verify(obj, lwk_spec, utilcpus_req, lwkcpus_req, v='0', autogen=False):
    def get_cpus():
        utilcpus = CpuSet(0)
        lwkcpus = CpuSet(0)

        op, rc = run(['lwkctl', '-v', v, '-s'])

        lines = op.splitlines()
        for l in lines:
            if l.startswith('Utility CPU(s):'):
                f,m,s = l.partition('Utility CPU(s):')
                s = s.split('[')[0].strip()
                if s != '':
                    utilcpus.fromList(s)
            if l.startswith('LWK     CPU(s):'):
                f,m,s = l.partition('LWK     CPU(s):')
                s = s.split('[')[0].strip()
                if s != '':
                    lwkcpus.fromList(s)
        return utilcpus, lwkcpus

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

    def lwkcpus_auto():
        with open('/sys/kernel/mOS/lwk_config', 'r') as f:
            data=f.read().rstrip('\n')
            m = re.search("auto=\S*cpu\S*", data)
            if m:
                return True
        return False

    def lwkmem_auto():
        with open('/sys/kernel/mOS/lwk_config', 'r') as f:
            data=f.read().rstrip('\n')
            m = re.search("auto=\S*mem\S*", data)
            if m:
                return True
        return False;

    # Create LWK partition
    lwk_spec = lwk_spec.strip()
    out, rc = run(['lwkctl', '-v', v, '-c', lwk_spec, '--force'], requiresRoot=True)

    # Read and verify LWK partition  using lwkctl -s

    # Verify CPUs
    lwkcpus_auto_set = lwkcpus_auto()
    if not autogen:
        utilcpus, lwkcpus = get_cpus()
        if utilcpus != utilcpus_req:
            logging.error('Mismatch : Syscall CPUs')
            logging.error('Requested: {}'.format(utilcpus_req.toList()))
            logging.error('Created  : {}'.format(utilcpus.toList()))
        if lwkcpus != lwkcpus_req:
            logging.error('Mismatch : LWK CPUs')
            logging.error('Requested: {}'.format(lwkcpus_req.toList()))
            logging.error('Created  : {}'.format(lwkcpus.toList()))
        if lwkcpus_auto_set:
            logging.error('The lwkcpus_auto indicator is set')

        assert(utilcpus == utilcpus_req)
        assert(lwkcpus == lwkcpus_req)
        assert(lwkcpus_auto_set == False)
    else:
        if not lwkcpus_auto_set:
            logging.error('The lwkcpus_auto indicator is not set')
            assert(lwkcpus_auto == True)

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

    if not lwkmem_static and not autogen:
        lwkmem_req = get_lwkmem(lwk_spec)
        lwkmem_set = get_lwkmem()
        msg = 'LWKMEM requested {} allocated {}'.format(lwkmem_req, lwkmem_set)
        logging.debug(msg)

        if lwkmem_req != 0:
            assert(lwkmem_set > 0), 'LWK memory partition was not created'
            assert(lwkmem_set <= lwkmem_req), 'Mismatch ' + msg

    lwkmem_auto_set = lwkmem_auto()
    if not autogen:
        if lwkmem_auto_set:
            logging.error('The lwkmem_auto indicator is set')
            assert(lwkmem_auto_set == False)
    else:
        if not lwkmem_auto_set:
            logging.error('The lwkmem_auto indicator is not set')
            assert(lwkmem_auto_set == True)

    # Run tests on LWK
    yod(obj, '-u', 0, '../lwksched/aff_scan', '-efm')

    if not lwkmem_static:
        yod(obj, '../lwkmem/maptest', '--verbose', '--type', 'anonymous', '--num', 10, '--size', 4096, '--iterations', 10)

    # Delete partition
    run(['lwkctl', '-v', v, '-d', '--force'], requiresRoot=True)

    # Read and verify using lwkctl -s
    utilcpus, lwkcpus = get_cpus()
    profile_set = get_profile()

    assert(utilcpus == CpuSet(0))
    assert(lwkcpus == CpuSet(0))
    assert(profile_set == '')

    if not lwkmem_static:
        lwkmem_set = get_lwkmem()
        assert(lwkmem_set == 0), 'Failed to delete LWKMEM partition'

    # Run tests on Linux
    run_bin(obj, '../lwksched/aff_scan')

class Spec:
    def __init__(self):
        global lwkmem_static
        self.topology = CpuTopology()
        assert(self.topology.allcpus.countCpus() > 0), "Invalid topology"
        self.cache = dict()

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

    # Create an LWKCPU partition spec that has fraction of CPUs (as specified
    # by ratio) assigned to LWK out of maximum possible LWK partition size on
    # a given hardware.
    # If,
    #   ratio = 0,      No LWK partition
    #   ratio = 1,      Maximum possible LWK partition on a given hardware
    #   ratio = 0.25,   1/4 of maximum possible LWK partition
    #   ratio = 0.5,    1/2 of maximum possible LWK partition
    def create_lwkcpu_spec(self, ratio, noutility_cpus=False):
        KEY_FMT = 'ratio_{}_noutility_cpus_{}'

        def clearFirstNCores(cs, N):
            cpumask = CpuSet(0)
            for i in range(N):
                cpumask += cs.selectNthBy(i + 1, self.topology.cores)
            return cs - cpumask

        def clearLastNCores(cs, N):
            cpumask = CpuSet(0)
            nthCore = cs.countBy(self.topology.cores)
            for i in range(N):
                cpumask += cs.selectNthBy(nthCore, self.topology.cores)
                nthCore -= 1
            return cs - cpumask

        def update_cache_lwkcpuspec(ratio, noutility_cpus, value):
            key = KEY_FMT.format(ratio, noutility_cpus)
            self.cache[key] = value

        # Try to look up for a cached spec before computing from scratch
        key = KEY_FMT.format(ratio, noutility_cpus)
        if key in self.cache:
            return self.cache[key]

        # Manufacture one and store in the cache
        lwkcpuspec = 'lwkcpus='
        utilcpus = CpuSet(0)
        lwkcpus = CpuSet(0)

        if ratio <= 0:
            return lwkcpuspec, utilcpus, lwkcpus

        if ratio > 1:
            ratio = 1

        # Consider core 0 as Linux core irrespective of topology.
        core0_cpus = self.topology.nodes[0].selectNthBy(1, self.topology.cores)

        numa_nodes = len(self.topology.nodes)
        node_utilcpus = self.topology.nodes.copy()
        node_lwkcpus = self.topology.nodes.copy()
        node_lwkcpus[0] -= core0_cpus

        # Find base minimum utility CPUs for the given hardware. These are the
        # number of Linux CPUs left after balancing number of LWK CPUs across
        # NUMA nodes. We do not scale the number of utility CPUs with ratio.
        # Instead we scale only the number of LWK CPUs using the given ratio.
        lwkcorespn_max = min(*[node.countBy(self.topology.cores) for node in node_lwkcpus])
        lwkcorespn = math.ceil(lwkcorespn_max * ratio)
        logging.debug('LWK cores per node: {} max x {} ratio = {}'.format(lwkcorespn_max, ratio, lwkcorespn))

        # Create maps of Linux and LWK cpus for every node
        total_util_cpus = 0
        for n in range(numa_nodes):
            node_utilcpus[n] = clearLastNCores(node_utilcpus[n], lwkcorespn_max)
            node_lwkcpus[n] -= node_utilcpus[n]

            if lwkcorespn_max != lwkcorespn:
                node_lwkcpus[n] = clearFirstNCores(node_lwkcpus[n], lwkcorespn_max - lwkcorespn)

            lwkcpus += node_lwkcpus[n]
            utilcpus += node_utilcpus[n]
            total_util_cpus += node_utilcpus[n].countCpus()
            logging.debug('Node[{}] Linux CPUs : {}'.format(n, node_utilcpus[n].toList()))
            logging.debug('Node[{}] LWK CPUs   : {}'.format(n, node_lwkcpus[n].toList()))

            if noutility_cpus == True:
                if lwkcpuspec != 'lwkcpus=':
                    lwkcpuspec += ':'
                lwkcpuspec += '{}'.format(node_lwkcpus[n].toList())

        # If there are no utility cpus requested then we are done here
        if noutility_cpus == True:
            rval = (lwkcpuspec, CpuSet(0), lwkcpus)
            update_cache_lwkcpuspec(ratio, True, rval)
            return rval

        # Assign LWKCPUs to Utility CPU mapping
        utilitycpuspn = int(total_util_cpus / numa_nodes)
        assert(utilitycpuspn >= 1), 'Utility CPUs {} lesser than NUMA nodes {}'.format(total_util_cpus, numa_nodes)

        lwkcores_per_utilitycpu = int(lwkcorespn / utilitycpuspn)
        if lwkcores_per_utilitycpu < 1:
            lwkcores_per_utilitycpu = 1

        # Compute LWKCPU specification for each node
        logging.debug('Utility cpus per node     : {}'.format(utilitycpuspn))
        logging.debug('LWK cores per utility cpus: {}'.format(lwkcores_per_utilitycpu))
        for n in range(numa_nodes):
            for i in range(1, utilitycpuspn + 1):
                subgroup_cpumask = CpuSet(0)
                for j in range(lwkcores_per_utilitycpu):
                    cpumask = node_lwkcpus[n].selectNthBy(1, self.topology.cores)
                    subgroup_cpumask += cpumask
                    node_lwkcpus[n] -= cpumask

                # Add any remaining LWK CPUs due to the truncation
                # from integer division to the last subgroup
                if i == utilitycpuspn and node_lwkcpus[n].isEmpty() == False:
                    subgroup_cpumask += node_lwkcpus[n]
                    node_lwkcpus[n] -= node_lwkcpus[n]

                # Pick a target utility CPU
                # Try current node first
                utilcpumask = node_utilcpus[n].nthCpu(1)
                if utilcpumask.isEmpty() == False:
                    node_utilcpus[n] -= utilcpumask
                else:
                    # If there is no utility CPU on this node
                    # then try to get one from other NUMA nodes
                    for m in range(numa_nodes):
                        utilcpumask = node_utilcpus[m].nthCpu(1)
                        if utilcpumask.isEmpty() == False:
                            node_utilcpus[m] -= utilcpumask
                            break
                assert(utilcpumask.isEmpty() == False), 'Node[{}]: Ran out of utility cpus to assign'.format(n)
                assert(utilcpumask.countCpus() == 1), 'Node[{}]: More than 1 utility cpus selected: {}'.format(n)

                if lwkcpuspec != 'lwkcpus=':
                    lwkcpuspec += ':'
                node_lwkcpuspec = '{}.{}'.format(utilcpumask.toList(), subgroup_cpumask.toList())
                lwkcpuspec += node_lwkcpuspec
                logging.debug('Node[{}] LWKCPU spec: {}'.format(n, node_lwkcpuspec))

            assert(node_lwkcpus[n].countCpus() == 0), 'Node[{}]: LWKCPUs {} are not assigned a utility CPU'.format(n, node_lwkcpus[n].toList())
        logging.debug('LWKCPU spec: {}'.format(lwkcpuspec))
        rval = (lwkcpuspec, utilcpus, lwkcpus)
        update_cache_lwkcpuspec(ratio, False, rval)
        return rval

    def create_lwkmem_spec(self, ratio, align=False):
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

        op, rc = run(['sync'], requiresRoot=True)
        logging.debug('sync returned rc={} {}'.format(rc,op))
        op, rc = run(['sh', '-c', 'echo 1 > /proc/sys/vm/drop_caches'], requiresRoot=True)
        logging.debug('Drop caches returned rc={} {}'.format(rc,op))

        with open('/sys/kernel/mOS/lwkmem') as f:
            lwkmemsize = f.read().split()

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
                    cur_size = int(lwkmemsize[node]) if node < len(lwkmemsize) else 0
                    size = math.floor((pages *4096 + cur_size) * ratio)
                    # precise=yes requests must be made on a 128M boundary due
                    # to limitations in the offlining of pages by the kernel
                    if align == True:
                        size  = math.floor(size / (128 * 1024 * 1024)) * (128 * 1024 * 1024)
                    movable_mem += [(node, size)]
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


    def write_to_ras_file(self, fil, content):
        fname = '/'.join(['/sys/kernel/mOS/ras', fil])
        with open(fname, 'w') as sysfile:
            n = sysfile.write(content)
            rc = n == len(content)
            logging.debug('Wrote "{}" to {} rc={}.'.format(content, fname, rc))
            return rc


# Global spec object to generate LWK specification. This avoids
# repeated topology discovery and caches LWKCPU specifications.
spec = Spec()

class Partition(TestCase):
    require = [ LWKCTL, YOD ]

    def test_valid_partition(self):
        v = '3' if ARGS.test_debug else '0'

        # Partition CPUs in following ratio between Linux and LWK
        ratio = [ 0.25, 0.5, 0.75, 0.90 ]
        for r in ratio:
            logging.debug('Testing LWK CPUs fraction: {}'.format(r))
            lwkcpus_spec, utilcpus, lwkcpus = spec.create_lwkcpu_spec(r)
            self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWKCPU partition spec')
            lwkmem_spec = spec.create_lwkmem_spec(r)
            self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')
            s = '{} {}'.format(lwkcpus_spec, lwkmem_spec)
            logging.debug('Testing LWK partition spec: {}'.format(s))
            create_and_verify(self, s, utilcpus, lwkcpus, v)

    def test_valid_no_syscall_cpus(self):
        v = '3' if ARGS.test_debug else '0'

        # Partition CPUs in following ratio between Linux and LWK
        lwkcpus_spec, utilcpus, lwkcpus = spec.create_lwkcpu_spec(0.90)
        self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWKCPU partition spec')
        lwkmem_spec = spec.create_lwkmem_spec(0.90)
        self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')

        # No utility CPUs specified
        # Extract the utility CPUs from the lwkcpus specification
        regex = re.compile("[=:](\d+\.)")
        for m in regex.finditer(lwkcpus_spec):
            lwkcpus_spec = lwkcpus_spec.replace(m.group(1), '', 1)

        s = '{} {}'.format(lwkcpus_spec, lwkmem_spec)
        logging.debug('Testing LWK partition spec: {}'.format(s))
        create_and_verify(self, s, CpuSet(0), lwkcpus, v)

        # Utility CPUs exist but are are not syscall targets
        # Append the Utility CPUs to end of the lwkcpus specification
        s = '{}:{}. {}'.format(lwkcpus_spec, utilcpus.toList(), lwkmem_spec)
        logging.debug('Testing LWK partition spec: {}'.format(s))
        create_and_verify(self, s, utilcpus, lwkcpus, v)

    def test_lwkcpu_lwkmem_auto(self):
        v = '3' if ARGS.test_debug else '0'

        # Partition CPUs in following ratio between Linux and LWK
        lwkcpus_spec = 'lwkcpus=auto'
        lwkmem_spec = 'lwkmem=auto'

        s = '{} {}'.format(lwkcpus_spec, lwkmem_spec)
        logging.debug('Testing LWK partition spec: {}'.format(s))
        create_and_verify(self, s, CpuSet(0), CpuSet(0), v, True)

    @unittest.skipUnless(ARGS.all_tests, 'Long running test.')
    def test_recreate_repeat(self):
        for count in range(4):
            logging.debug('Test count: {}'.format(count + 1))
            self.test_valid_partition()

    def test_invalid_partition(self):
        v = '3' if ARGS.test_debug else '0'

        lwkcpus_spec, utilcpus, lwkcpus = spec.create_lwkcpu_spec(0.90)
        self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWKCPU partition spec')
        lwkmem_spec = spec.create_lwkmem_spec(0.90)
        self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')

        # Manufacture an invalid spec by adding invalid CPU numbers
        N = spec.topology.allcpus.countCpus()
        lwkcpus_spec += ':{}.{}-{}'.format(N, N+1, N+10)

        # Try to create a partition with CPUs which are not present
        s = '{} {}'.format(lwkcpus_spec, lwkmem_spec)
        logging.debug('Testing LWK partition: {}'.format(s))

        out, rc = run(['lwkctl', '-v', v, '-c', s, '--force'], requiresRoot=True)
        self.assertFalse(rc == 0, 'Created LWK partition for invalid spec: {}'.format(s))

    def test_precise_yes(self):
        v = '3' if ARGS.test_debug else '0'

        lwkcpus_spec, utilcpus, lwkcpus = spec.create_lwkcpu_spec(0.90)
        self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWKCPU partition spec')
        # Request available memory
        lwkmem_spec = spec.create_lwkmem_spec(0.90, True)
        self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')

        s = '{} {}'.format(lwkcpus_spec, lwkmem_spec)
        logging.debug('Testing LWK partition: {}'.format(s))

        out, rc = run(['lwkctl', '-v', v, '-c', s, '-p', 'yes', '--force'], requiresRoot=True)
        self.assertTrue(rc == 0, 'Could not create precise partition with available memory: {}'.format(s))

    def test_precise_yes_exceed(self):
            v = '3' if ARGS.test_debug else '0'

            lwkcpus_spec, utilcpus, lwkcpus = spec.create_lwkcpu_spec(0.90)
            self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWKCPU partition spec')
            # Request memory above what is available
            lwkmem_spec = spec.create_lwkmem_spec(1.5, True)
            self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')

            # Try to create a partition with larger memory than available
            s = '{} {}'.format(lwkcpus_spec, lwkmem_spec)
            logging.debug('Testing LWK partition: {}'.format(s))

            out, rc = run(['lwkctl', '-v', v, '-c', s, '-p', 'yes', '--force'], requiresRoot=True)
            self.assertFalse(rc == 0 and lwkmem_static == False, 'Created LWK partition when memory spec exceeding available: {}'.format(s))

    def test_precise_no(self):
        v = '3' if ARGS.test_debug else '0'

        lwkcpus_spec, utilcpus, lwkcpus = spec.create_lwkcpu_spec(0.90)
        self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWKCPU partition spec')
        # Request memory above what is available
        lwkmem_spec = spec.create_lwkmem_spec(1.5)
        self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')

        # Try to create a partition with larger memory than available
        s = '{} {}'.format(lwkcpus_spec, lwkmem_spec)
        logging.debug('Testing LWK partition: {}'.format(s))

        out, rc = run(['lwkctl', '-v', v, '-c', s, '-p', 'no', '--force'], requiresRoot=True)
        self.assertTrue(rc == 0, 'Failed to create LWK partition for memory spec exceeding available: {}'.format(s))

    def test_precise_default(self):
        v = '3' if ARGS.test_debug else '0'

        lwkcpus_spec, utilcpus, lwkcpus = spec.create_lwkcpu_spec(0.90)
        self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWKCPU partition spec')
        # Request memory above what is available
        lwkmem_spec = spec.create_lwkmem_spec(1.5)
        self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')
        s = '{} {}'.format(lwkcpus_spec, lwkmem_spec)

        logging.debug('Testing spec: {}'.format(s))
        create_and_verify(self, s, utilcpus, lwkcpus, v)

    def test_invalid_spec(self):
        v = '3' if ARGS.test_debug else '0'

        lwkcpus_spec, utilcpus, lwkcpus = spec.create_lwkcpu_spec(0.90)
        self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWK partition spec')
        lwkmem_spec = spec.create_lwkmem_spec(0.90)
        self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')

        invalid_lwkcpu_spec = [ lwkcpus_spec.strip('lwkcpus='),    # Missing lwkcpus=
                                lwkcpus_spec.strip('lwkcpus'),     # Missing lwkcpus
                                lwkcpus_spec.replace('lwkcpus', 'lwkcpu'),  # Typo in lwkcpus
                                lwkcpus_spec.replace('=', ' '),    # Missing '=' sign
                                lwkcpus_spec.replace('.', ','),    # Missing LWK CPUs
                                lwkcpus_spec.replace(lwkcpus_spec, '@*$^)_!#'), # Total garbage
                              ]
        if lwkcpus_spec.find(':') != -1:
            invalid_lwkcpu_spec += [ lwkcpus_spec.replace(':', ',', 1) ] # Missing delimiter ':' between mappings ]

        for s in invalid_lwkcpu_spec:
            s = '{} {}'.format(s, lwkmem_spec)
            logging.debug('Testing spec: ' + s)
            out, rc = run(['lwkctl', '-v', v, '-c', s, '--force'], requiresRoot=True)
            self.assertFalse(rc == 0, 'Created LWK partition for invalid spec: {}'.format(s))

    def test_busy_with_job(self):
            v = '3' if ARGS.test_debug else '0'

            lwkcpus_spec, utilcpus, lwkcpus = spec.create_lwkcpu_spec(0.90)
            self.assertNotEqual(lwkcpus_spec, 'lwkcpus=', 'Failed to create LWKCPU partition spec')
            # Request memory above what is available
            lwkmem_spec = spec.create_lwkmem_spec(0.9, True)
            self.assertNotEqual(lwkmem_spec, 'lwkmem=', 'Failed to create LWKMEM partition spec')

            # Insert a jobid into the RAS subsystem:
            rc = spec.write_to_ras_file('jobid', '1234567')
            self.assertTrue(rc, 'Could not write to jobid file.')

            # Try to create a partition with larger memory than available
            s = '{} {}'.format(lwkcpus_spec, lwkmem_spec)
            logging.debug('Testing LWK partition: {}'.format(s))

            out, rc = run(['lwkctl', '-v', v, '-c', s,], requiresRoot=True)
            self.assertFalse(rc == 0, 'Created LWK partition even though job is active.')

            out, rc = run(['lwkctl', '-v', v, '-c', s, '--force'], requiresRoot=True)
            self.assertTrue(rc == 0, 'Could not create LWK partition with --force.')

            rc = spec.write_to_ras_file('jobid', ' ')
            self.assertTrue(rc, 'Could not write to jobid file.')

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
        lwkcpus_spec, utilcpus, lwkcpus = spec.create_lwkcpu_spec(0.90)
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
            create_and_verify(self, s, utilcpus, lwkcpus, v)
