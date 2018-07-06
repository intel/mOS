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
            "10 21 21 21 31 41 41 41",
            "21 10 21 21 41 31 41 41",
            "21 21 10 21 41 41 31 41",
            "21 21 21 10 41 41 41 31",
            "31 41 41 41 10 41 41 41",
            "41 31 41 41 41 10 41 41",
            "41 41 31 41 41 41 10 41",
            "41 41 41 31 41 41 41 10",
            ]

        for i, dist in enumerate(cls.distances):
            dmap_path = '/'.join([cls.var['FS_DIR'], 'distance%d' % i])
            with open(dmap_path, 'w') as dmap:
                dmap.write(dist)

        logger.debug('KNL plugin established %s --> #-CPUS=%s -> %s',
                     cls.yod_plugin, cls.topology.allcpus.countCpus(),
                     cls.topology.allcpus)

        # The (default) designated CPU set for KNL:
        cls.designated = yod.CpuSet(0).fromList('2-17,20-67,70-85,88-135,138-153,156-203,206-221,224-271')

        cls.test_env['YOD_MAX_CPUS'] = str(cls.topology.allcpus.countCpus())
        cls.var['I_LWKCPUS'] = str(cls.designated)

    def setUp(self):
        super().setUp()

        dram_size = 16 * 1024 * 1024 * 1024
        hbm_size = 4 * 1024 * 1024 * 1024
        nvram_size = 0

        self.lwkmem = [dram_size] * 4  +  [hbm_size] * 4
        self.mem_groups = [[0, 1, 2, 3], [4, 5, 6, 7]]
        self.mem_group_names = ['dram', 'hbm']

        self.n_desig_cores = self.designated.countBy(self.topology.cores)
        self.n_desig_cpus = self.designated.countCpus()
        self.n_mem_nodes = len(self.lwkmem)
        self.n_mem_groups = len(self.mem_groups)

        self.lwkmem_reserved = [0] * self.n_mem_nodes
        self.lwkmem_request = [0] * self.n_mem_nodes

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
        # The domain info map associates memory types with domains,
        # e.g. "dram=1 hbm=4".  So we don't really care about the order
        # within the content.
        actual = sorted(get_file(self.var['FS_LWKMEM_DOMAIN_INFO']).strip('\0').split())
        expected = sorted(self.domain_info.split())
        self.assertEqual(actual, expected)

    def test_simple_one_core(self):
        self.lwkcpus_request = self.get_n_cores(1)
        lwkmem_by_group = self.sumByGroup(self.lwkmem)

        # Requested memory is 1/Nth of the overall amount from each memory
        # group.  And it comes from the NID that is nearest to the CPUs in
        # NID 0:
        for g, grp in enumerate(self.mem_groups):
            nid = self.nearest(0, g)
            self.lwkmem_request[nid] = lwkmem_by_group[g] // self.n_desig_cores

        cmd = ['%RESOURCES%', 1 / self.n_desig_cores,
               '%AFFINITY_TEST%', '--lwkcpus_reserved', str(self.lwkcpus_request),
               '--lwkmem_reserved', strseq(self.lwkmem_request, ',')]
        self.expand_and_run(cmd, 0)

    def test_simple_one_core_w_reserve(self):
        # Select the first CPU from all designated and pre-reserve it.
        # Then determine the next available (complete) core.
        rsvd_cpu = self.designated.nthCpu(1)
        available_cpus = self.designated - rsvd_cpu
        self.lwkcpus_request = self.get_n_cores(1, fromcpus=available_cpus)

        # Requested memory is 1/Nth of the overall amount from each memory
        # group.  And it comes from the NID that is nearest to the CPUs in
        # NID 0:
        lwkmem_by_group = self.sumByGroup(self.lwkmem)
        for g, grp in enumerate(self.mem_groups):
            nid = self.nearest(0, g)
            self.lwkmem_request[nid] = lwkmem_by_group[g] // self.n_desig_cores

        self.var['I_LWKCPUS_RESERVED'] = str(rsvd_cpu)

        cmd = ['%RESOURCES%', 1 / self.n_desig_cores,
               '%AFFINITY_TEST%',
               '--lwkcpus_reserved', str(rsvd_cpu + self.lwkcpus_request),
               '--lwkmem_reserved', strseq(self.lwkmem_request, ',')]
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
            self.lwkcpus_request = nodes[nid]
            self.lwkmem_request = [0] * self.n_mem_nodes
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
                self.lwkmem_request[nearest_nid] = self.lwkmem[nearest_nid]
                self.domain_info += '{}{}={}'.format(prefix, self.mem_group_names[g], nearest_nid)
                prefix = ' '

            self.var['I_LWKCPUS_RESERVED'] = str(lwkcpus_reserved)

            cmd = ['-v', 2, '%RESOURCES%', '.25', '%AFFINITY_TEST%',
                   '--lwkcpus_reserved', str(self.lwkcpus_request + lwkcpus_reserved),
                   '--lwkmem_reserved', strseq(self.lwkmem_request, ',')]
            self.expand_and_run(cmd, 0, postrun=[self.check_lwkmem_domain_info])

    def test_numa_one_domain_mem_resvd(self):
        # For every CPU domain D, reserve some memory in all far
        # memory and launch a job.  The NUMA alogorithm should place
        # the job on domain D.

        # For every CPU domain ...
        for nid in range(len(self.topology.nodes)):
            self.lwkcpus_request = self.designated & self.topology.allcpus.selectNthBy(nid + 1, self.topology.nodes)

            self.lwkmem_reserved = [0] * self.n_mem_nodes
            self.lwkmem_request  = [0] * self.n_mem_nodes

            # Reserve 2MB in every memory domain that is not
            # the nearest to the CPU domain:
            self.domain_info = ''
            prefix = ''
            for g in range(self.n_mem_groups):
                nearest_nid = self.nearest(nid, g)
                self.lwkmem_request[nearest_nid] = self.lwkmem[nearest_nid]
                self.domain_info += '{}{}={}'.format(prefix, self.mem_group_names[g], nearest_nid)
                prefix = ' '
                for mem_nid in self.mem_groups[g]:
                    if mem_nid != nearest_nid:
                        self.lwkmem_reserved[mem_nid] = 2 * 1024 * 1024

            # The reserved memory (as seen by the launched process) is the total
            # of the pre-reserved and requested memory:
            lwkmem_reserved_after = list(a + b for a,b in zip(self.lwkmem_reserved, self.lwkmem_request))

            cmd = ['-v', 0, '%RESOURCES%', '.25', '%AFFINITY_TEST%',
                   '--lwkcpus_reserved', str(self.lwkcpus_request),
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
        self.lwkcpus_request = yod.CpuSet(0)
        for n in range(1, n_half + 1):
            lwkcpus_reserved += nodes[1].selectNthBy(n, self.topology.cores)
            self.lwkcpus_request += nodes[1].selectNthBy(n_half + n, self.topology.cores)
        lwkcpus_reserved += nodes[0]

        # Now pre-reserve the memory from domain 0 and half of the memory
        # from domain 1.  Note that n_cores might be odd and therefore
        # 2 * n_half might not equal n_cores.

        self.domain_info = ''
        prefix = ''

        for g in range(self.n_mem_groups):
            n = self.nearest(0, g)
            self.lwkmem_reserved[n] = self.lwkmem[n]

            n = self.nearest(1, g)
            self.lwkmem_reserved[n] = self.lwkmem[n] // 2
            self.lwkmem_request[n] = self.lwkmem[n] // 2
            self.domain_info += '{}{}={}'.format(prefix, self.mem_group_names[g], n)
            prefix = ' '

        self.var['I_LWKCPUS_RESERVED'] = str(lwkcpus_reserved)

        # The reserved memory (as seen by the launched process) is the total
        # of the pre-reserved and requested memory:
        lwkmem_reserved_after = list(a + b for a,b in zip(self.lwkmem_reserved, self.lwkmem_request))

        cmd = ['-v', 2, '%RESOURCES%', '.125', '%AFFINITY_TEST%',
               '--lwkcpus_reserved', str(lwkcpus_reserved+self.lwkcpus_request),
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
        self.lwkcpus_request = nodes[2]
        self.domain_info = ''
        prefix = ''

        for g in range(self.n_mem_groups):
            n = self.nearest(0, g)
            self.lwkmem_reserved[n] = self.lwkmem[n]

            n = self.nearest(1, g)
            self.lwkmem_reserved[n] = 2 * 1024 * 1024

            n = self.nearest(2, g)
            self.lwkmem_request[n] = self.lwkmem[n]

            self.domain_info += '{}{}={}'.format(prefix, self.mem_group_names[g], n)
            prefix = ' '

        self.var['I_LWKCPUS_RESERVED'] = str(lwkcpus_reserved)

        # The reserved memory (as seen by the launched process) is the total
        # of the pre-reserved and requested memory:
        lwkmem_reserved_after = list(a + b for a,b in zip(self.lwkmem_reserved, self.lwkmem_request))

        cmd = ['-v', 2, '%RESOURCES%', '.25', '%AFFINITY_TEST%',
               '--lwkcpus_reserved', str(lwkcpus_reserved + self.lwkcpus_request),
               '--lwkmem_reserved', strseq(lwkmem_reserved_after, ',')]
        self.expand_and_run(cmd, 0, postrun=[self.check_lwkmem_domain_info])

    @unittest.skip('broken')
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

                self.lwkcpus_request = yod.CpuSet(0)
                self.lwkmem_reserved = [0] * self.n_mem_nodes
                self.lwkmem_request  = [0] * self.n_mem_nodes

                # Reserve a CPU from the "c" node
                lwkcpus_reserved = nodes[c].nthCpu(1)

                # Reserve memory from the "m" node's nearest memory

                for g in range(self.n_mem_groups):
                    n = self.nearest(m, g)
                    self.lwkmem_reserved[n] = 2 * 1024 * 1024

                self.var['I_LWKCPUS_RESERVED'] = str(lwkcpus_reserved)

                # Now gather up resources from the free domains:

                dom_info = {'dram': [], 'hbm': []}

                for n in range(len(self.topology.nodes)):
                    if n == c or n == m:
                        continue
                    self.lwkcpus_request += nodes[n]

                    for g in range(self.n_mem_groups):
                        self.lwkmem_request[self.nearest(n, g)] = self.lwkmem[self.nearest(n, g)]
                        dom_info[self.mem_group_names[g]].append(str(self.nearest(n, g)))

                self.domain_info = 'dram={} hbm={}'.format(','.join(dom_info['dram']), ','.join(dom_info['hbm']))

                # The reserved memory (as seen by the launched process) is the total
                # of the pre-reserved and requested memory:
                lwkmem_reserved_after = list(a + b for a,b in zip(self.lwkmem_reserved, self.lwkmem_request))

                cmd = ['-v', 2, '%RESOURCES%', '.5', '%AFFINITY_TEST%',
                       '--lwkcpus_reserved', str(lwkcpus_reserved + self.lwkcpus_request),
                       '--lwkmem_reserved', strseq(lwkmem_reserved_after, ',')]
                self.expand_and_run(cmd, 0, postrun=[self.check_lwkmem_domain_info])

    def test_numa_half_node_scattered(self):
        # Pre-reserve portions of all four NUMA domains and launch a
        # half-node job.

        # Construct a list of designted CPUs by domain
        nodes = []
        lwkcpus_reserved = yod.CpuSet(0)
        self.lwkcpus_request = yod.CpuSet(0)

        cores_remaining = self.designated.countBy(self.topology.cores) // 2
        dom_info = {'dram': [], 'hbm': []}

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
                self.lwkcpus_request += selected
                remaining -= selected
                cores_remaining -= 1

            for group in range(self.n_mem_groups):
                nearest = self.nearest(nid, group)
                self.lwkmem_reserved[nearest] = self.lwkmem[nearest] // 2
                self.lwkmem_request[nearest] = self.lwkmem[nearest] // 2
                dom_info[self.mem_group_names[group]].append(str(nearest))

        self.var['I_LWKCPUS_RESERVED'] = str(lwkcpus_reserved)
        self.domain_info = 'dram={} hbm={}'.format(','.join(dom_info['dram']), ','.join(dom_info['hbm']))

        # The lwkmem_reserved status (as seen by the launched process) is the total
        # of the pre-reserved and the requested memory:
        lwkmem_reserved_after = list(a + b for a,b in zip(self.lwkmem_reserved, self.lwkmem_request))

        cmd = ['-v', 2, '%RESOURCES%', '.5', '%AFFINITY_TEST%',
               '--lwkcpus_reserved', str(lwkcpus_reserved + self.lwkcpus_request),
               '--lwkmem_reserved', strseq(lwkmem_reserved_after, ',')]
        self.expand_and_run(cmd, 0, postrun=[self.check_lwkmem_domain_info])

    def test_reserve_memory_from_cpus(self):
        # Tests scenarios where CPUs (not cores) are selected from the
        # same node. The reserved memory should match that node.

        lwkmem_by_group = self.sumByGroup(self.lwkmem)
        total_mem = sum(lwkmem_by_group)

        # for every node and for every n in [1, ...,
        # number-of-cpus-this-node], launch on n CPUs from that node.
        # The reserved memory should correspond to the node.
        for nid, node in enumerate(self.topology.nodes):
            node = node & self.designated
            for ncpus in range(1, node.countCpus() + 1):
                self.lwkcpus_request = yod.CpuSet(0)
                self.lwkmem_request = [0] * self.n_mem_nodes

                for c in range(ncpus):
                    self.lwkcpus_request += node.nthCpu(c + 1)

                self.domain_info = ''
                prefix = ''

                for g in range(self.n_mem_groups):
                    nearest_nid = self.nearest(nid, g)
                    ratio = lwkmem_by_group[g] / total_mem
                    self.lwkmem_request[nearest_nid] = int(20 * 1024 * 1024 * ratio)
                    self.domain_info += '{}{}={}'.format(prefix, self.mem_group_names[g], nearest_nid)
                    prefix = ' '

                cmd = ['--verbose', 2, '-c', str(self.lwkcpus_request), '-M', '20M',
                       '%AFFINITY_TEST%',
                       '--lwkcpus_reserved', str(self.lwkcpus_request),
                       '--lwkmem_reserved', strseq(self.lwkmem_request, ',')]
                self.expand_and_run(cmd, 0, postrun=[self.check_lwkmem_domain_info])



    def test_layout(self):

        self.lwkcpus_request = '2-5,20-23,70-73,88-91,138-141,156-159,206-209,224-227'
        self.lwkmem_request = self.lwkmem # requesting all memory

        # The following patterns were independently generated.  I took
        # the first two (complete) tiles from nodes 0 and 1 from the
        # standard designated set.  This is a large enough set to test
        # the different sort orders.

        patterns = [
            ('node,tile,core,cpu', '2,20,4,22,3,21,5,23,70,88,72,90,71,89,73,91,138,156,140,158,139,157,141,159,206,224,208,226,207,225,209,227'),
            ('node,tile,cpu,core', '2,20,4,22,70,88,72,90,138,156,140,158,206,224,208,226,3,21,5,23,71,89,73,91,139,157,141,159,207,225,209,227'),
            ('node,core,tile,cpu', '2,20,3,21,4,22,5,23,70,88,71,89,72,90,73,91,138,156,139,157,140,158,141,159,206,224,207,225,208,226,209,227'),
            ('node,core,cpu,tile', '2,20,3,21,70,88,71,89,138,156,139,157,206,224,207,225,4,22,5,23,72,90,73,91,140,158,141,159,208,226,209,227'),
            ('node,cpu,tile,core', '2,20,70,88,138,156,206,224,4,22,72,90,140,158,208,226,3,21,71,89,139,157,207,225,5,23,73,91,141,159,209,227'),
            ('node,cpu,core,tile', '2,20,70,88,138,156,206,224,3,21,71,89,139,157,207,225,4,22,72,90,140,158,208,226,5,23,73,91,141,159,209,227'),
            ('tile,node,core,cpu', '2,4,20,22,3,5,21,23,70,72,88,90,71,73,89,91,138,140,156,158,139,141,157,159,206,208,224,226,207,209,225,227'),
            ('tile,node,cpu,core', '2,4,20,22,70,72,88,90,138,140,156,158,206,208,224,226,3,5,21,23,71,73,89,91,139,141,157,159,207,209,225,227'),
            ('tile,core,node,cpu', '2,4,3,5,20,22,21,23,70,72,71,73,88,90,89,91,138,140,139,141,156,158,157,159,206,208,207,209,224,226,225,227'),
            ('tile,core,cpu,node', '2,4,3,5,70,72,71,73,138,140,139,141,206,208,207,209,20,22,21,23,88,90,89,91,156,158,157,159,224,226,225,227'),
            ('tile,cpu,node,core', '2,4,70,72,138,140,206,208,20,22,88,90,156,158,224,226,3,5,71,73,139,141,207,209,21,23,89,91,157,159,225,227'),
            ('tile,cpu,core,node', '2,4,70,72,138,140,206,208,3,5,71,73,139,141,207,209,20,22,88,90,156,158,224,226,21,23,89,91,157,159,225,227'),
            ('core,node,tile,cpu', '2,3,20,21,4,5,22,23,70,71,88,89,72,73,90,91,138,139,156,157,140,141,158,159,206,207,224,225,208,209,226,227'),
            ('core,node,cpu,tile', '2,3,20,21,70,71,88,89,138,139,156,157,206,207,224,225,4,5,22,23,72,73,90,91,140,141,158,159,208,209,226,227'),
            ('core,tile,node,cpu', '2,3,4,5,20,21,22,23,70,71,72,73,88,89,90,91,138,139,140,141,156,157,158,159,206,207,208,209,224,225,226,227'),
            ('core,tile,cpu,node', '2,3,4,5,70,71,72,73,138,139,140,141,206,207,208,209,20,21,22,23,88,89,90,91,156,157,158,159,224,225,226,227'),
            ('core,cpu,node,tile', '2,3,70,71,138,139,206,207,20,21,88,89,156,157,224,225,4,5,72,73,140,141,208,209,22,23,90,91,158,159,226,227'),
            ('core,cpu,tile,node', '2,3,70,71,138,139,206,207,4,5,72,73,140,141,208,209,20,21,88,89,156,157,224,225,22,23,90,91,158,159,226,227'),
            ('cpu,node,tile,core', '2,70,138,206,20,88,156,224,4,72,140,208,22,90,158,226,3,71,139,207,21,89,157,225,5,73,141,209,23,91,159,227'),
            ('cpu,node,core,tile', '2,70,138,206,20,88,156,224,3,71,139,207,21,89,157,225,4,72,140,208,22,90,158,226,5,73,141,209,23,91,159,227'),
            ('cpu,tile,node,core', '2,70,138,206,4,72,140,208,20,88,156,224,22,90,158,226,3,71,139,207,5,73,141,209,21,89,157,225,23,91,159,227'),
            ('cpu,tile,core,node', '2,70,138,206,4,72,140,208,3,71,139,207,5,73,141,209,20,88,156,224,22,90,158,226,21,89,157,225,23,91,159,227'),
            ('cpu,core,node,tile', '2,70,138,206,3,71,139,207,20,88,156,224,21,89,157,225,4,72,140,208,5,73,141,209,22,90,158,226,23,91,159,227'),
            ('cpu,core,tile,node', '2,70,138,206,3,71,139,207,4,72,140,208,5,73,141,209,20,88,156,224,21,89,157,225,22,90,158,226,23,91,159,227'),
        ]

        for descr, layout in patterns:
            cmd = ['--verbose', 3, '--layout', descr, '-c', str(self.lwkcpus_request),
                   '-M', 'all', '%HELLO%']

            self.expand_and_run(cmd, 0)

            actual = get_file(self.var['FS_LWKCPUS_SEQUENCE'])
            self.assertEqual(layout, actual)
