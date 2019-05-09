# Multi Operating System (mOS)
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

from mostests import *
import subprocess
import time
import threading

#import re
#import random

logger = logging.getLogger()

GiB = 1024**3
MiB = 1024**2
KiB = 1024**1
xpmem_shmem_file='/tmp/xpmem.file'

class XpMem(TestCase):
    require = [YOD, '/sys/kernel/mOS/lwkmem', '/dev/xpmem']

    def __del__(self):
        if os.path.isfile(xpmem_shmem_file):
            os.remove(xpmem_shmem_file)

    def _is_running_on_mos(self):
        try:
            return len(get_file('/sys/kernel/mOS/lwkcpus')) > 0
        except FileNotFoundError as fnfe:
            return False

    def _launch(self, cmd, nprocs=1, requiresMos=False):
        try:
            if self._is_running_on_mos():
                cmd = '{} -R 1/{} '.format(YOD, nprocs) + cmd
            elif requiresMos:
                logging.warn('This test requires mOS')
                return None
            logging.debug('Launching "{}"'.format(cmd))
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, bufsize=0, stderr=subprocess.STDOUT, universal_newlines=True);
            return p
        except subprocess.CalledProcessError as err:
            logging.error('(E) {}'.format(err.output))
            return None

    def _StdoutReader(self, proc):
        line = proc.stdout.readline()
        while line:
            logging.debug(line.rstrip())
            line = proc.stdout.readline()

    def _launchXpmemTasks(self, task1_name, task1_cmd,task2_name, task2_cmd):
        procs = [[None, None, task1_name, task1_cmd],
                 [None, None, task2_name, task2_cmd]]
        PROC, RDR, NAME, CMD = tuple(i for i in range(4))
        for p in procs:
            p[PROC] = self._launch(p[CMD], nprocs=2)
            p[RDR] = threading.Thread(target=self._StdoutReader, name='{}-stdout-reader'.format(p[NAME]), args=(p[PROC],))
            p[RDR].start()
            if procs.index(p) != len(procs) - 1:
                time.sleep(.5)

        def _poll():
            return tuple(p[PROC].poll() for p in procs)

        status = _poll()
        while None in status:
            for i in range(2):
                if status[i] != None and status[i] < 0:
                    procs[1 if i == 0 else 0][PROC].terminate()
            time.sleep(0.1)
            status = _poll()
        return status

    def _test_xpmem(self, size=4096, num=1, granularity=1, shutdown="canonical", popts=None, copts=None):

        # These tests are somewhat unique in that they must lanuch *two* LWK
        # processes.  Furthermore, Python's support for multi-threaded
        # tasks is not so hot.  Instead, we spawn two sub-processes and
        # alternate grabbing output from the corresponding output streams.

        # Also, it takes a little bit of time for the producer to establish
        # the shared memory region and pass the shared info (XpMem segment ID
        # and such).  So pause for one second before spawning the consumer.

        path = path_of(self)
        producer = '{}/xpmem --producer --size {} --num {} --granularity {} --shutdown {}'.format(path, size, num, granularity, shutdown)
        if popts != None:
            producer += ' {}'.format(popts)

        consumer = '{}/xpmem --consumer'.format(path)
        if copts != None:
            consumer += ' {}'.format(copts)

        producerExitStat, consumerExitStat = self._launchXpmemTasks('producer', producer, 'consumer', consumer)
        if copts == '--munmap':
            assert consumerExitStat < 0, 'Consumer was not terminated, exit status {}'.format(consumerExitStat)

    def test_xpmem_buffer_sizes(self):
        # Test shared segment sizes in powers of two from 4k to 1G
        # Furthermore, test both the canonical shutdown (consumer
        # detaches before producer destroys shared segment) and the
        # inverted path:
        for n in range(12,31):
            N = 2**n
            for s in ['canonical', 'inverted']:
                self._test_xpmem(size=N, shutdown=s)

    def test_xpmem_sim(self):
        # Simulate that passing of multiple messages between producer
        # and consumer process
        for sz, n, g in [(4 * KiB, 10, 1), (2 * MiB, 10, 1), (64 * MiB, 100, 10)]:
            self._test_xpmem(size=sz, num=n, granularity=g)

    def test_xpmem_early_term(self):
        # Testing early exit of processes without freeing up XPMEM resources,
        # these tests should not break kernel.
        for sz, n, g in [(4 * KiB, 10, 1), (2 * MiB, 10, 1), (64 * MiB, 100, 10)]:
            self._test_xpmem(size=sz, num=n, granularity=g, shutdown='eterm-p-c-alive')
            self._test_xpmem(size=sz, num=n, granularity=g, shutdown='eterm-p-c-dead')
            self._test_xpmem(size=sz, num=n, granularity=g, shutdown='eterm-c-p-alive')
            self._test_xpmem(size=sz, num=n, granularity=g, shutdown='eterm-c-p-dead')

    def test_xpmem_munmap(self):
        # Testing of munmap of XPMEM segments both in producer and consumer.
        # In producer munmap is a valid operation and all consumers page table
        # need to be invalidated upon an munamp in the producer
        #
        # In the consumer munmap on an XPMEM attached memory is an invalid operation
        # kernel should send SIGKILL for the process making such an attempt
        for sz, n, g in [(4 * KiB, 10, 1), (2 * MiB, 10, 1), (64 * MiB, 100, 10)]:
            self._test_xpmem(size=sz, num=n, granularity=g, popts='--munmap')
            self._test_xpmem(size=sz, num=n, granularity=g, copts='--munmap')

    def test_xpmem_invalid_usage(self):
        binary = '{}/xpmem_invalid_usage'.format(path_of(self))
        def getNumTests():
            p = self._launch('{} --help'.format(binary))
            out = p.stdout.readline()
            while out:
                if out.startswith('Total test cases:'):
                    return int(out.split(':')[1])
                out = p.stdout.readline()
            return 0

        N = getNumTests()
        assert N > 0, 'Found no test cases supported'

        for test in range(N):
            c = dict()
            for task in ['owner', 'nonowner']:
                c[task] = '{} --{} --test {}'.format(binary, task, test)
            s1, s2 = self._launchXpmemTasks('owner', c['owner'], 'nonowner', c['nonowner'])
            assert s1 == 0, 'Owner process returned {}'.format(s1)
            assert s2 == 0, 'Non-owner process returned {}'.format(s2)

    def test_xpmem_mem_types(self):
        binary = '{}/xpmem_mem_types'.format(path_of(self))
        nonowner = '{} --nonowner'.format(binary)

        for size in [ 4 * KiB, 1 * MiB, 2 * MiB, 16 * MiB, 1 * GiB, 2 * GiB ]:
            for alignment in  [ 4 * KiB, 2 * MiB, 1 * GiB ]:
                if alignment > size:
                    continue
                types = 'heap,anon_private,anon_shared,mmap_file,stack_main,stack_thread,eas'
                if size <= 128 * MiB:
                    types += ',static'
                if size >= 1 * MiB:
                    types +=',anon_mixed,anon_mixed_inv'

                owner = '{} --owner --type {} --size {} --align {}'.format(binary, types, size, alignment)
                s1, s2 = self._launchXpmemTasks('owner', owner, 'nonowner', nonowner)
                assert s1 == 0, 'Owner process returned {}'.format(s1)
                assert s2 == 0, 'Non-owner process returned {}'.format(s2)
