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

from mostests import *
import yod

logger = logging.getLogger()

class AlgorithmUnitTests(yod.YodTestCase):
    yod_plugin = 'knl.plugin'
    yod_lscpu = 'knl.lscpu'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        # We'll plug-in two memory groups a la SNC-4 mode on KNL
        cls.var['I_LWKMEM_GROUPS'] = '0-3 4-7'

        cls.distances = [
            "10 21 21 21 41 41 41 31",
            "21 10 21 21 31 41 41 41",
            "21 21 10 21 41 31 41 41",
            "21 21 21 10 41 41 31 41",
            "41 31 41 41 10 41 41 41",
            "41 41 31 41 41 10 41 41",
            "41 41 41 31 41 41 10 41",
            "31 41 41 41 41 41 41 10",
            ]

        for i, dist in enumerate(cls.distances):
            dmap_path = '/'.join([cls.var['FS_DIR'], 'distance%d' % i])
            with open(dmap_path, 'w') as dmap:
                dmap.write(dist)

        logger.debug('KNL plugin established %s --> #-CPUS=%s -> %s',
                     cls.yod_plugin, cls.topology.allcpus.countCpus(),
                     cls.topology.allcpus)

        # The (default) designated CPU set is obtained by removing the
        # first core from each node:
        cls.designated = cls.topology.allcpus
        for node in cls.topology.nodes:
            cls.designated -= node.selectNthBy(1, cls.topology.cores)

        cls.test_env['YOD_MAX_CPUS'] = str(cls.topology.allcpus.countCpus())
        cls.var['I_LWKCPUS'] = str(cls.designated)

    def setUp(self):
        super().setUp()

        dram_size = 16 * 1024 * 1024 * 1024
        mcdram_size = 4 * 1024 * 1024 * 1024
        nvram_size = 0

        self.lwkmem = [dram_size] * 4  +  [mcdram_size] * 4
        self.mem_groups = [[0, 1, 2, 3], [4, 5, 6, 7]]
        self.mem_group_names = ['dram', 'mcdram']

        self.n_desig_cores = self.designated.countBy(self.topology.cores)
        self.n_desig_cpus = self.designated.countCpus()
        self.n_mem_nodes = len(self.lwkmem)
        self.n_mem_groups = len(self.mem_groups)

        self.var['I_LWKMEM'] = strseq(self.lwkmem)
        self.var['I_LWKMEM_RESERVED'] = strseq([0] * self.n_mem_nodes)

    def nearest(self, cpu_nid, group):
        mindist = sys.maxsize
        result = -1
        dmap = intlist(self.distances[cpu_nid])
        for mem_nid in self.mem_groups[group]:
            if dmap[mem_nid] < mindist:
                result = mem_nid
                mindist = dmap[mem_nid]
        return result

    def sumByGroup(self, intList):
        '''Add up the elements of intList by group.'''

        result = [0] * len(self.mem_groups)

        for n, elem in enumerate(intList):
            for g, grp in enumerate(self.mem_groups):
                if n in grp:
                    result[g] += elem
        return result

    def check_lwkmem_domain_info(self):
        info = get_file(self.var['FS_LWKMEM_DOMAIN_INFO']).strip('\0')
        self.assertEqual(info, self.domain_info)

    def test_simple_one_core(self):
        core_mask = self.designated.selectNthBy(1, self.topology.cores)
        lwkmem_by_group = self.sumByGroup(intlist(self.var['I_LWKMEM']))
        lwkmem_rsvd = [0] * self.n_mem_nodes

        for g, grp in enumerate(self.mem_groups):
            nid = grp[0]
            lwkmem_rsvd[nid] = lwkmem_by_group[g] // self.n_desig_cores

        logger.debug('lwkmem_rsvd = %s', strseq(lwkmem_rsvd, ','))

        cmd = ['%RESOURCES%', 1 / self.n_desig_cores, '--resource_algorithm', 'simple',
               '%AFFINITY_TEST%', '--lwkcpus_reserved', str(core_mask),
               '--lwkmem_reserved', strseq(lwkmem_rsvd, ',')]
        self.expand_and_run(cmd, 0)

    def test_simple_one_core_w_reserve(self):
        # Select the first CPU from all designated and pre-reserve it.
        # Then determine the next available (complete) core.
        rsvd_cpu = self.designated.nthCpu(1)
        core_mask = self.designated - rsvd_cpu
        core_mask = core_mask.filterBy(self.topology.cores).selectNthBy(1, self.topology.cores)

        # Memory to be reserved is going to be 1/Nth of designated
        # memory from each group.  Furthermore, the memory will come
        # from the first NID in each group.
        lwkmem_rsvd = [0] * self.n_mem_nodes
        lwkmem_by_group = self.sumByGroup(intlist(self.var['I_LWKMEM']))

        for g, grp in enumerate(self.mem_groups):
            nid = grp[0]
            lwkmem_rsvd[nid] = lwkmem_by_group[g] // self.n_desig_cores
        logger.debug('lwkmem_rsvd = %s', strseq(lwkmem_rsvd, ','))

        self.var['I_LWKCPUS_RESERVED'] = str(rsvd_cpu)

        cmd = ['%RESOURCES%', 1 / self.n_desig_cores, '--resource_algorithm', 'simple',
               '%AFFINITY_TEST%',
               '--lwkcpus_reserved', str(rsvd_cpu + core_mask),
               '--lwkmem_reserved', strseq(lwkmem_rsvd, ',')]
        self.expand_and_run(cmd, 0)

    def test_numa_one_domain_cpus_resvd(self):
        # For every CPU domain D, reserve a CPU in all other domains
        # and launch a job.  The NUMA alogorithm should place the job
        # on domain D, reserving memory that is near D.

        # Construct a list of designted CPUs by domain
        nodes = []
        for nid in range(len(self.topology.nodes)):
            nodes.append(self.designated & self.topology.allcpus.selectNthBy(nid + 1, self.topology.nodes))

        # For every CPU domain ...
        for nid, node in enumerate(self.topology.nodes):
            lwkcpus_request = nodes[nid]
            lwkmem_reserved = [0] * self.n_mem_nodes
            lwkcpus_reserved = yod.CpuSet(0)

            # Pre-reserve one CPU from every other CPU domain:
            for other_nid in range(len(self.topology.nodes)):
                if nid == other_nid:
                    continue
                lwkcpus_reserved += nodes[other_nid].nthCpu(1)
            self.var['I_LWKCPUS_RESERVED'] = str(lwkcpus_reserved)

            # Find the memory in each group that is nearest
            # to the CPU domain:
            self.domain_info = ''
            prefix = ''
            for g in range(self.n_mem_groups):
                nearest_nid = self.nearest(nid, g)
                lwkmem_reserved[nearest_nid] = self.lwkmem[nearest_nid]
                self.domain_info += '{}{}={}'.format(prefix, self.mem_group_names[g], nearest_nid)
                prefix = ' '

            self.var['I_LWKCPUS_RESERVED'] = str(lwkcpus_reserved)

            cmd = ['-v', 2, '%RESOURCES%', '.25', '--resource_algorithm', 'numa',
                   '%AFFINITY_TEST%',
                   '--lwkcpus_reserved', str(lwkcpus_request+lwkcpus_reserved),
                   '--lwkmem_reserved', strseq(lwkmem_reserved, ',')]
            self.expand_and_run(cmd, 0, postrun=[self.check_lwkmem_domain_info])

    def test_numa_one_domain_mem_resvd(self):
        # For every CPU domain D, reserve some memory in all far
        # memory and launch a job.  The NUMA alogorithm should place
        # the job on domain D.

        # For every CPU domain ...
        for nid in range(len(self.topology.nodes)):
            lwkcpus_request = self.designated & self.topology.allcpus.selectNthBy(nid + 1, self.topology.nodes)

            lwkmem_reserved_before = [0] * self.n_mem_nodes
            lwkmem_reserved_after = [0] * self.n_mem_nodes

            # Reserve 2MB in every memory domain that is not
            # the nearest to the CPU domain:
            self.domain_info = ''
            prefix = ''
            for g in range(self.n_mem_groups):
                nearest_nid = self.nearest(nid, g)
                lwkmem_reserved_after[nearest_nid] = self.lwkmem[nearest_nid]
                self.domain_info += '{}{}={}'.format(prefix, self.mem_group_names[g], nearest_nid)
                prefix = ' '
                for mem_nid in self.mem_groups[g]:
                    if mem_nid != nearest_nid:
                        lwkmem_reserved_before[mem_nid] = lwkmem_reserved_after[mem_nid] = 2 * 1024 * 1024

            self.var['I_LWKMEM_RESERVED'] = strseq(lwkmem_reserved_before)

            cmd = ['-v', 0, '%RESOURCES%', '.25', '--resource_algorithm', 'numa',
                   '%AFFINITY_TEST%',
                   '--lwkcpus_reserved', str(lwkcpus_request),
                   '--lwkmem_reserved', strseq(lwkmem_reserved_after, ',')]
            self.expand_and_run(cmd, 0, postrun=[self.check_lwkmem_domain_info])

    def test_numa_pack_domain(self):
        # Pre-reserve a portion of NUMA domain N and launch a job that
        # will logically fit into the remainder of domain N.  Ensure that
        # it is, indeed, packed into the remaining space.

        # Construct a list of designated CPUs by domain
        nodes = []
        for nid in range(len(self.topology.nodes)):
            nodes.append(self.designated & self.topology.allcpus.selectNthBy(nid + 1, self.topology.nodes))

        # Pre-reserve the first half of domain 1, and select the second half
        # for this request.

        n_cores = nodes[1].countBy(self.topology.cores)
        n_half = n_cores // 2

        lwkcpus_reserved = yod.CpuSet(0)
        lwkcpus_request = yod.CpuSet(0)
        for n in range(1, n_half + 1):
            lwkcpus_reserved += nodes[1].selectNthBy(n, self.topology.cores)
            lwkcpus_request += nodes[1].selectNthBy(n_half + n, self.topology.cores)
        lwkcpus_reserved += nodes[0]

        # Now pre-reserve the memory from domain 0 and half of the memory
        # from domain 1.  Note that n_cores might be odd and therefore
        # 2 * n_half might not equal n_cores.

        lwkmem_reserved_before = [0] * self.n_mem_nodes
        lwkmem_reserved_after = [0] * self.n_mem_nodes

        self.domain_info = ''
        prefix = ''

        for g in range(self.n_mem_groups):
            n = self.nearest(0, g)
            lwkmem_reserved_before[n] = lwkmem_reserved_after[n] = self.lwkmem[n]

            n = self.nearest(1, g)
            lwkmem_reserved_before[n] = self.lwkmem[n] // 2
            lwkmem_reserved_after[n] = self.lwkmem[n]
            self.domain_info += '{}{}={}'.format(prefix, self.mem_group_names[g], n)
            prefix = ' '

        self.var['I_LWKCPUS_RESERVED'] = str(lwkcpus_reserved)
        self.var['I_LWKMEM_RESERVED'] = strseq(lwkmem_reserved_before)

        cmd = ['-v', 2, '%RESOURCES%', '.125', '--resource_algorithm', 'numa',
               '%AFFINITY_TEST%',
               '--lwkcpus_reserved', str(lwkcpus_reserved+lwkcpus_request),
               '--lwkmem_reserved', strseq(lwkmem_reserved_after, ',')]
        self.expand_and_run(cmd, 0, postrun=[self.check_lwkmem_domain_info])

    def test_numa_step_over_domain(self):
        # Pre-reserve all of NUMA domain 0 and some memory from domain 1.
        # Then  launch a quarter-node job.  This should skip over domains
        # 0 and 1 and land on domain 2.

        # Construct a list of designted CPUs by domain
        nodes = []
        for nid in range(len(self.topology.nodes)):
            nodes.append(self.designated & self.topology.allcpus.selectNthBy(nid + 1, self.topology.nodes))

        # Pre-reserve all of the CPUs and memory from domain 0, and some memory
        # (but no CPUs) from domain 1:

        lwkcpus_reserved = nodes[0]
        lwkcpus_request = nodes[2]
        lwkmem_reserved_before = [0] * self.n_mem_nodes
        lwkmem_reserved_after = [0] * self.n_mem_nodes

        self.domain_info = ''
        prefix = ''

        for g in range(self.n_mem_groups):
            n = self.nearest(0, g)
            lwkmem_reserved_before[n] = lwkmem_reserved_after[n] = self.lwkmem[n]

            n = self.nearest(1, g)
            lwkmem_reserved_before[n] = lwkmem_reserved_after[n] = 2 * 1024 * 1024

            n = self.nearest(2, g)
            lwkmem_reserved_after[n] = self.lwkmem[n]

            self.domain_info += '{}{}={}'.format(prefix, self.mem_group_names[g], n)
            prefix = ' '

        self.var['I_LWKCPUS_RESERVED'] = str(lwkcpus_reserved)
        self.var['I_LWKMEM_RESERVED'] = strseq(lwkmem_reserved_before)

        cmd = ['-v', 2, '%RESOURCES%', '.25', '--resource_algorithm', 'numa',
               '%AFFINITY_TEST%',
               '--lwkcpus_reserved', str(lwkcpus_reserved + lwkcpus_request),
               '--lwkmem_reserved', strseq(lwkmem_reserved_after, ',')]
        self.expand_and_run(cmd, 0, postrun=[self.check_lwkmem_domain_info])

    def test_numa_half_node(self):
        # Pre-reserve portions of two NUMA domains and launch a half-node
        # job. Validate that the completely free domains are the ones
        # selected.

        # Construct a list of designted CPUs by domain
        nodes = []
        for nid in range(len(self.topology.nodes)):
            nodes.append(self.designated & self.topology.allcpus.selectNthBy(nid + 1, self.topology.nodes))

        for c in range(len(self.topology.nodes)):
            for m in range(len(self.topology.nodes)):
                m = (c + 1 + m) % len(self.topology.nodes)

                if m == c:
                    continue

                lwkcpus_request = yod.CpuSet(0)
                lwkmem_reserved_before = lwkmem_reserved_after = [0] * self.n_mem_nodes

                # Reserve a CPU from the "c" node
                lwkcpus_reserved = nodes[c].nthCpu(1)

                # Reserve memory from the "m" node's nearest memory

                for g in range(self.n_mem_groups):
                    n = self.nearest(m, g)
                    lwkmem_reserved_before[n] = lwkmem_reserved_after[n] = 2 * 1024 * 1024

                self.var['I_LWKCPUS_RESERVED'] = str(lwkcpus_reserved)
                self.var['I_LWKMEM_RESERVED'] = strseq(lwkmem_reserved_before)

                # Now gather up resources from the free domains:

                dom_info = {'dram': [], 'mcdram': []}

                for n in range(len(self.topology.nodes)):
                    if n == c or n == m:
                        continue
                    lwkcpus_request += nodes[n]

                    for g in range(self.n_mem_groups):
                        lwkmem_reserved_after[self.nearest(n, g)] = self.lwkmem[self.nearest(n, g)]
                        dom_info[self.mem_group_names[g]].append(str(self.nearest(n, g)))

                self.domain_info = 'dram={} mcdram={}'.format(','.join(dom_info['dram']), ','.join(dom_info['mcdram']))

                cmd = ['-v', 2, '%RESOURCES%', '.5', '--resource_algorithm', 'numa',
                       '%AFFINITY_TEST%',
                       '--lwkcpus_reserved', str(lwkcpus_reserved+lwkcpus_request),
                       '--lwkmem_reserved', strseq(lwkmem_reserved_after, ',')]
                self.expand_and_run(cmd, 0, postrun=[self.check_lwkmem_domain_info])

    def test_numa_half_node_scattered(self):
        # Pre-reserve portions of all four NUMA domains and launch a
        # half-node job.

        # Construct a list of designted CPUs by domain
        nodes = []
        lwkcpus_reserved = yod.CpuSet(0)
        lwkcpus_request = yod.CpuSet(0)

        lwkmem_reserved_before = [0] * self.n_mem_nodes
        lwkmem_reserved_after = [0] * self.n_mem_nodes

        cores_remaining = self.designated.countBy(self.topology.cores) // 2
        dom_info = {'dram': [], 'mcdram': []}

        for nid in range(len(self.topology.nodes)):
            nodes.append(self.designated & self.topology.allcpus.selectNthBy(nid + 1, self.topology.nodes))

            remaining = nodes[nid]
            n_cores = remaining.countBy(self.topology.cores)
            n_half = n_cores // 2

            for core in range(n_half):
                selected = remaining.selectNthBy(1, self.topology.cores)
                lwkcpus_reserved += selected
                remaining -= selected

            while not remaining.isEmpty() and cores_remaining > 0:
                selected = remaining.selectNthBy(1, self.topology.cores)
                lwkcpus_request += selected
                remaining -= selected
                cores_remaining -= 1

            for group in range(self.n_mem_groups):
                nearest = self.nearest(nid, group)
                lwkmem_reserved_before[nearest] = self.lwkmem[nearest] // 2
                lwkmem_reserved_after[nearest] = int(self.lwkmem[nearest])
                dom_info[self.mem_group_names[group]].append(str(nearest))

        self.var['I_LWKCPUS_RESERVED'] = str(lwkcpus_reserved)
        self.var['I_LWKMEM_RESERVED'] = strseq(lwkmem_reserved_before)
        self.domain_info = 'dram={} mcdram={}'.format(','.join(dom_info['dram']), ','.join(dom_info['mcdram']))

        cmd = ['-v', 2, '%RESOURCES%', '.5', '--resource_algorithm', 'numa',
               '%AFFINITY_TEST%',
               '--lwkcpus_reserved', str(lwkcpus_reserved+lwkcpus_request),
               '--lwkmem_reserved', strseq(lwkmem_reserved_after, ',')]
        self.expand_and_run(cmd, 0, postrun=[self.check_lwkmem_domain_info])

    def test_reserve_memory_from_cpus(self):
        # Tests scenarios where CPUs (not cores) are selected from the
        # same node. The reserved memory should match that node.

        lwkmem_by_group = self.sumByGroup(intlist(self.var['I_LWKMEM']))
        total_mem = sum(lwkmem_by_group)

        # for every node and for every n in [1, ...,
        # number-of-cpus-this-node], launch on n CPUs from that node.
        # The reserved memory should correspond to the node.
        for nid, node in enumerate(self.topology.nodes):
            node = node & self.designated
            for ncpus in range(1, node.countCpus() + 1):
                cpus = yod.CpuSet(0)
                lwkmem_request = [0] * self.n_mem_nodes

                for c in range(ncpus):
                    cpus += node.nthCpu(c + 1)

                self.domain_info = ''
                prefix = ''

                for g in range(self.n_mem_groups):
                    nearest_nid = self.nearest(nid, g)
                    ratio = lwkmem_by_group[g] / total_mem
                    lwkmem_request[nearest_nid] = int(20 * 1024 * 1024 * ratio)
                    self.domain_info += '{}{}={}'.format(prefix, self.mem_group_names[g], nearest_nid)
                    prefix = ' '

                cmd = ['--verbose', 2, '-c', str(cpus), '-M', '20M',
                       '--resource_algorithm', 'numa', '%AFFINITY_TEST%',
                       '--lwkcpus_reserved', str(cpus),
                       '--lwkmem_reserved', strseq(lwkmem_request, ',')]
                self.expand_and_run(cmd, 0, postrun=[self.check_lwkmem_domain_info])



    def test_layout(self):
        cpus = '1,2,9,10,13,14,21,22,25,26,33,34,37-39,46,47,55,56,107,108,115,116,167,168,175,176,227,228,235,236,287'

        # The following patterns were independently generated.  I took
        # the first two (complete) tiles from nodes 0 and 1 from the
        # standard designated set.  This is a large enough set to test
        # the different sort orders.

        patterns = [
            ('node,tile,core,cpu', '37,1,55,9,107,2,56,10,108,13,115,21,167,14,116,22,168,25,175,33,227,26,176,34,228,38,235,46,287,39,236,47'),
            ('node,tile,cpu,core', '37,1,55,9,108,13,115,21,168,25,175,33,228,38,235,46,107,2,56,10,167,14,116,22,227,26,176,34,287,39,236,47'),
            ('node,core,tile,cpu', '37,1,107,2,55,9,56,10,108,13,167,14,115,21,116,22,168,25,227,26,175,33,176,34,228,38,287,39,235,46,236,47'),
            ('node,core,cpu,tile', '37,1,107,2,108,13,167,14,168,25,227,26,228,38,287,39,55,9,56,10,115,21,116,22,175,33,176,34,235,46,236,47'),
            ('node,cpu,tile,core', '37,1,108,13,168,25,228,38,55,9,115,21,175,33,235,46,107,2,167,14,227,26,287,39,56,10,116,22,176,34,236,47'),
            ('node,cpu,core,tile', '37,1,108,13,168,25,228,38,107,2,167,14,227,26,287,39,55,9,115,21,175,33,235,46,56,10,116,22,176,34,236,47'),
            ('tile,node,core,cpu', '37,55,1,9,107,56,2,10,108,115,13,21,167,116,14,22,168,175,25,33,227,176,26,34,228,235,38,46,287,236,39,47'),
            ('tile,node,cpu,core', '37,55,1,9,108,115,13,21,168,175,25,33,228,235,38,46,107,56,2,10,167,116,14,22,227,176,26,34,287,236,39,47'),
            ('tile,core,node,cpu', '37,55,107,56,1,9,2,10,108,115,167,116,13,21,14,22,168,175,227,176,25,33,26,34,228,235,287,236,38,46,39,47'),
            ('tile,core,cpu,node', '37,55,107,56,108,115,167,116,168,175,227,176,228,235,287,236,1,9,2,10,13,21,14,22,25,33,26,34,38,46,39,47'),
            ('tile,cpu,node,core', '37,55,108,115,168,175,228,235,1,9,13,21,25,33,38,46,107,56,167,116,227,176,287,236,2,10,14,22,26,34,39,47'),
            ('tile,cpu,core,node', '37,55,108,115,168,175,228,235,107,56,167,116,227,176,287,236,1,9,13,21,25,33,38,46,2,10,14,22,26,34,39,47'),
            ('core,node,tile,cpu', '37,107,1,2,55,56,9,10,108,167,13,14,115,116,21,22,168,227,25,26,175,176,33,34,228,287,38,39,235,236,46,47'),
            ('core,node,cpu,tile', '37,107,1,2,108,167,13,14,168,227,25,26,228,287,38,39,55,56,9,10,115,116,21,22,175,176,33,34,235,236,46,47'),
            ('core,tile,node,cpu', '37,107,55,56,1,2,9,10,108,167,115,116,13,14,21,22,168,227,175,176,25,26,33,34,228,287,235,236,38,39,46,47'),
            ('core,tile,cpu,node', '37,107,55,56,108,167,115,116,168,227,175,176,228,287,235,236,1,2,9,10,13,14,21,22,25,26,33,34,38,39,46,47'),
            ('core,cpu,node,tile', '37,107,108,167,168,227,228,287,1,2,13,14,25,26,38,39,55,56,115,116,175,176,235,236,9,10,21,22,33,34,46,47'),
            ('core,cpu,tile,node', '37,107,108,167,168,227,228,287,55,56,115,116,175,176,235,236,1,2,13,14,25,26,38,39,9,10,21,22,33,34,46,47'),
            ('cpu,node,tile,core', '37,108,168,228,1,13,25,38,55,115,175,235,9,21,33,46,107,167,227,287,2,14,26,39,56,116,176,236,10,22,34,47'),
            ('cpu,node,core,tile', '37,108,168,228,1,13,25,38,107,167,227,287,2,14,26,39,55,115,175,235,9,21,33,46,56,116,176,236,10,22,34,47'),
            ('cpu,tile,node,core', '37,108,168,228,55,115,175,235,1,13,25,38,9,21,33,46,107,167,227,287,56,116,176,236,2,14,26,39,10,22,34,47'),
            ('cpu,tile,core,node', '37,108,168,228,55,115,175,235,107,167,227,287,56,116,176,236,1,13,25,38,9,21,33,46,2,14,26,39,10,22,34,47'),
            ('cpu,core,node,tile', '37,108,168,228,107,167,227,287,1,13,25,38,2,14,26,39,55,115,175,235,56,116,176,236,9,21,33,46,10,22,34,47'),
            ('cpu,core,tile,node', '37,108,168,228,107,167,227,287,55,115,175,235,56,116,176,236,1,13,25,38,2,14,26,39,9,21,33,46,10,22,34,47'),
        ]

        for descr, layout in patterns:
            cmd = ['--verbose', 3, '--layout', descr, '-c', str(cpus),
                   '-M', 'all', '%HELLO%']
            self.expand_and_run(cmd, 0)

            actual = get_file(self.var['FS_LWKCPUS_SEQUENCE'])
            self.assertEqual(layout, actual)
