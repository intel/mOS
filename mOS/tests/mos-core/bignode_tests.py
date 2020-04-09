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

class BigNodeTests(yod.YodTestCase):
    yod_plugin = 'bignode.plugin'
    yod_lscpu = 'bignode.lscpu'

    @classmethod
    def setUpClass(cls):

        super().setUpClass()

        # --------------------------------------------------------------
        # Populate the distance map with a pre-computed distance file.
        # And push the contents down into the plugin directory in the
        # expected format.
        # --------------------------------------------------------------

        cls.distances = []
        with open(os.path.join(os.path.dirname(__file__), 'bignode.distances')) as dist:
            for line in dist:
                cls.distances.append(line)

        for i, dist in enumerate(cls.distances):
            dmap_path = '/'.join([cls.var['FS_DIR'], 'distance%d' % i])
            with open(dmap_path, 'w') as dmap:
                dmap.write(dist)

        # --------------------------------------------------------------
        # There is 128G of HBM spread equally among the NUMA domains.
        # There is no DRAM and there is no NVRAM.
        # --------------------------------------------------------------

        cls.n_nids = len(cls.distances)
        cls.lwkmem = [8 * 1024 * 1024 * 1024] * cls.n_nids
        cls.total_mem_designated = sum(cls.lwkmem)
        cls.lwkmem_reserved = [0] * cls.n_nids
        cls.lwkmem_request = [0] * cls.n_nids
        cls.mem_group_names = ['dram', 'hbm', 'nvram']
        cls.var['I_LWKMEM_GROUPS'] = '-1 0-{} -1'.format(cls.n_nids - 1)

        # --------------------------------------------------------------
        # The (default) designated CPU set for BigNode:  The lscpu plugin
        # file was constructed such that there is one extra Xeon core
        # in every nodelet.  Remove the first core from each of these
        # nodelets from the set of LWK CPUs.
        # --------------------------------------------------------------

        node_types = { 5: 1,  # Remove 1 core  from nodes with 5 cores
                       4: 0,  # Remove 0 cores from nodes with 4 cores
        }

        cls.designated = cls.topology.allcpus

        for i, node in enumerate(cls.topology.nodes):
            count = node.countBy(cls.topology.cores)
            if count in node_types:
                count = node_types[count]
                while count > 0:
                    core = node.selectNthBy(count, cls.topology.cores)
                    logger.debug('Removing CPUs {} from node {}'.format(core, i))
                    cls.designated -= core
                    count -= 1
            else:
                logger.warning('(!) Node {} has {} cores.  This is unexpected.'.format(i, count))

        cls.n_desig_cores = cls.designated.countBy(cls.topology.cores)
        cls.n_desig_cpus = cls.designated.countCpus()

        logger.debug('BigNode plugin established All CPUS:{} [{}]  Designated:{} [{}]'.format(cls.topology.allcpus, cls.topology.allcpus.countCpus(), cls.designated, cls.designated.countCpus()))

        # Tell yod how many CPUs it can expected in CPU set masks:
        cls.test_env['YOD_MAX_CPUS'] = str(cls.topology.allcpus.countCpus())

        # Establish the default, designated LWK CPUs:
        cls.var['I_LWKCPUS'] = str(cls.designated)


    def setUp(self):
        super().setUp()


    def nearest(self, nid, order):

        # --------------------------------------------------------------
        # Return a list of NIDs (in order) that are Nth order distance
        # away from the given NID.  That is, order=1 is typically
        # just the NID itself.  Order=2 is the NID plus the next closest
        # NIDs, and so on.
        # --------------------------------------------------------------

        distances = list(int(n) for n in self.distances[nid].split(' '))
        ordered_distances = sorted(list(x for x in set(int(y) for y in self.distances[nid].split(' '))))

        if order <= 0 or order > len(ordered_distances):
            logger.error('nearest(nid={}, order={}) : order must be in the range [1,{}).'.format(nid, order, len(ordered_distances)))
            return None

        ordered_distances = ordered_distances[:order]
        result = []

        for i, n in enumerate(distances):
            if n in ordered_distances:
                result.append(i)

        logger.debug('nearest(nid={} order={}) distancess={} nodes={}'.format(nid, order, ordered_distances, result))

        return result


    def test_simple_one_core(self):

        # --------------------------------------------------------------
        # A trivial test:  Reserve just one core:
        # --------------------------------------------------------------

        self.lwkcpus_request = self.designated.selectNthBy(1, self.topology.cores)
        self.lwkmem_request = [0] * self.n_nids
        self.lwkmem_request[0] = self.total_mem_designated // self.n_desig_cores

        cmd = ['-v', '2', '-R', 1 / self.n_desig_cores,
               '%AFFINITY_TEST%', '--lwkcpus_reserved', str(self.lwkcpus_request),
               '--lwkmem_reserved', strseq(self.lwkmem_request, ',')]
        self.expand_and_run(cmd, 0)


    def _test_order_n(self, N):

        # --------------------------------------------------------------
        # Test the NUMA algorithm for envelopes of depth N.  This is
        # done as follows:
        #    1. Iterate through the envelopes for depth N.
        #    2. Given the selected envelope, pre-reserve some small
        #       amount of resource from all of the other envelopes.
        #    3. Launch a job that will fit exactly into an envelop for
        #       depth N and ensure that it lands on the selected
        #       envelope.
        # --------------------------------------------------------------

        #self.test_env['YOD_VERBOSE'] = '2'

        def pre_reserve(i, envelopes):

            lwkcpus_reserved = yod.CpuSet(0)

            for j, envelope in enumerate(envelopes):

                if j == i:
                    continue

                # --------------------------------------------------------------
                # Reserve one core and memory from envelope j.  To mix things
                # up, we use the envelope's index (modulo its length) to target
                # one of the NIDs in the envelope:
                # --------------------------------------------------------------

                nid = envelope[j % len(envelope)]
                lwkcpus_reserved += (self.designated & self.topology.nodes[nid]).selectNthBy(1, self.topology.cores)
                self.lwkmem_reserved[nid] = self.total_mem_designated // self.n_desig_cores

            self.var['I_LWKCPUS_RESERVED'] = str(lwkcpus_reserved)
            return lwkcpus_reserved


        # --------------------------------------------------------------
        # Construct the envelopes for order N
        # --------------------------------------------------------------

        envelopes = []
        for nid in range(self.n_nids):
            nearest = self.nearest(nid, N)
            if not nearest in envelopes:
                envelopes.append(nearest)
                logger.debug('Discovered envelope: {}'.format(nearest))

        #  --------------------------------------------------------------
        # Per the above above description, iterate, pre-reserve and
        # test:
        # --------------------------------------------------------------

        for i, envelope in enumerate(envelopes):

            self.lwkmem_request = [0] * self.n_nids
            self.lwkmem_reserved = [0] * self.n_nids
            self.lwkcpus_request = yod.CpuSet(0)

            lwkcpus_reserved = pre_reserve(i, envelopes)

            for nid in envelope:
                cpus = self.designated & self.topology.nodes[nid]
                self.lwkcpus_request += cpus
                self.lwkmem_request[nid] = self.total_mem_designated // self.n_desig_cores * cpus.countBy(self.topology.cores)

            lwkcpus_reserved_after = self.lwkcpus_request + lwkcpus_reserved
            lwkmem_reserved_after = list(a + b for a,b in zip(self.lwkmem_reserved, self.lwkmem_request))

            cmd = ['-v', '2', '-R', '{}/{}'.format(self.lwkcpus_request.countBy(self.topology.cores), self.n_desig_cores),
                   '%AFFINITY_TEST%', '--lwkcpus_reserved', str(lwkcpus_reserved_after),
                   '--lwkmem_reserved', strseq(lwkmem_reserved_after, ',')]

            self.expand_and_run(cmd, 0)

    def test_one_node(self):
        self._test_order_n(1)

    def test_one_die(self):
        self._test_order_n(2)

    def test_one_nodelet(self):
        self._test_order_n(3)

    def test_indirect_memory(self):

        #  --------------------------------------------------------------
        # For every NUMA domain, launch on a selected CPU from that
        # domain and validate that the reserved memory comes from the
        # same domain.
        #  --------------------------------------------------------------

        for nid, node in enumerate(self.topology.nodes):
            cpu = (self.designated & node).nthCpu(1)

            self.lwkmem_request = [0] * self.n_nids
            self.lwkmem_request[nid] = 64 * 1024 * 1024

            logger.debug('Selecting CPU {} from node {} : {}'.format(cpu, nid, node))

            cmd = ['-v', '2', '--cpu', str(cpu), '--mem', '64M',
                   '%AFFINITY_TEST%', '--lwkcpus_reserved', str(cpu),
                   '--lwkmem_reserved', strseq(self.lwkmem_request)]
            self.expand_and_run(cmd, 0)


    def test_indirect_memory_ratios(self):

        # --------------------------------------------------------------
        # Select 1 CPU from node 1, 2 CPUs from node 2, and so on up
        # to 5 nodes.  Validate that the reserved memory is in
        # proportion.
        # --------------------------------------------------------------

        self.lwkmem_request = [0] * self.n_nids

        lwkcpu_request = yod.CpuSet(0)

        for nid in range(1,6):
            for i in range(1, nid + 1):
                lwkcpu_request += (self.designated & self.topology.nodes[nid]).nthCpu(i)
                self.lwkmem_request[nid] += 16 * 1024 * 1024

        mem = sum(self.lwkmem_request)

        cmd = ['-v', '2', '--cpu', str(lwkcpu_request), '--mem', str(mem),
                   '%AFFINITY_TEST%', '--lwkcpus_reserved', str(lwkcpu_request),
                   '--lwkmem_reserved', strseq(self.lwkmem_request)]

        self.expand_and_run(cmd, 0)
