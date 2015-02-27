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

# File paths
# procfs
PROCFS_MEMINFO = '/proc/meminfo'
# sysfs
SYSFS_NODE = '/sys/devices/system/node'
SYSFS_MOS_LWKCONFIG = '/sys/kernel/mOS/lwk_config'
# mOS view interface
MOSVIEW_PATH = '/proc/{}/mos_view'
MOSVIEW_CURRENT = MOSVIEW_PATH.format('self')
# Misc global vars
VALID_MOSVIEWS = ['linux', 'lwk', 'all']
NUMA_NODES = cpulist(get_file('{}/online'.format(SYSFS_NODE)))
MOSVIEW_SAVED = ''

def mos_view_exists():
    return os.path.isfile(MOSVIEW_CURRENT)

def set_mos_view(pid, mos_view):
    MOSVIEW_PROC=MOSVIEW_PATH.format(pid)

    with open(MOSVIEW_PROC, 'w') as f:
        f.write(mos_view)
    return mos_view == get_file(MOSVIEW_PROC)

def save_mos_view():
    MOSVIEW_SAVED = get_file(MOSVIEW_CURRENT)

def restore_mos_view():
    set_mos_view('self', MOSVIEW_SAVED)

@unittest.skipUnless(IS_MOS, 'tests require mOS')
class Memory(TestCase):
    def get_lwkmem(self, N=None):
        op = get_file(SYSFS_MOS_LWKCONFIG)
        units = ['K', 'M', 'G', 'T', 'P', 'E']
        total_size = 0

        for token in op.split():
            if token.startswith('lwkmem='):
                f, m, l = token.partition('=')
                l = l.strip()
                if l != '':
                    for node_spec in l.split(','):
                        node, delimiter, size = node_spec.partition(':')
                        if N != None and int(node) != N:
                            continue
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

    def verify_meminfo(self, path, node=None):
        def contains(line, subfields):
            for s in subfields:
                if line.find(s) != -1:
                    return s
            return None

        self.assertTrue(mos_view_exists(), 'Unable to find mOS view interface')

        implemented = [ 'MemTotal',
                        'MemFree',
                        'MemUsed',
                        'MemAvailable' ]
        exceptions =  [ 'DirectMap' ]

        save_mos_view()
        # Kernel exports meminfo in kB, so convert lwkmem total to kB
        lwkmem_total = self.get_lwkmem(node) / 1024

        for mos_view in VALID_MOSVIEWS:
            set_mos_view('self', mos_view)
            meminfo = dict()
            with open(path, 'r') as f:
                for line in f:
                    subfield = contains(line, implemented)
                    if subfield:
                        tok = line.split(':')[1].split()
                        self.assertEqual(tok[1].strip(), 'kB', 'Kernel representation of meminfo units has changed')
                        meminfo[subfield] = int(tok[0])
                    elif mos_view == 'lwk':
                        if contains(line, exceptions) == None:
                            val = int(line.split(':')[1].split()[0])
                            self.assertEqual(val, 0, 'Invalid meminfo subfield value in lwk view: {}'.format(line))
            MemTotal = meminfo['MemTotal']
            MemFree =  meminfo['MemFree']
            # In lwk view,
            #       1. MemTotal must be = total designated lwkmem
            #       2. All other fields other then the ones in implements and
            #          exception list above must be zeros as tested above
            if mos_view == 'lwk':
                self.assertEqual(MemTotal, lwkmem_total, 'Node {}: Invalid MemTotal in lwk view'.format(node))

            # General,
            #       1. MemFree <= MemTotal
            #       2. MemUsed <= MemTotal (for node meminfo in sysfs)
            #       3. MemTotal == MemFree + MemUsed (for node meminfo in sysfs)
            #       4. MemAvailable <= MemTotal (for meminfo in procfs)
            self.assertTrue(MemFree <= MemTotal, 'Node {}: MemFree {} > MemTotal {}'.format(node, MemFree, MemTotal))

            if node != None:
                MemUsed = meminfo['MemUsed']
                self.assertTrue(MemUsed <= MemTotal, 'Node {}: MemUsed {} > MemTotal {}'.format(node, MemUsed, MemTotal))
                self.assertEqual(MemTotal, MemFree + MemUsed, 'Node {}: MemTotal {} != MemFree {} + MemUsed {}'.format(node, MemTotal, MemFree, MemUsed))
            else:
                MemAvailable=meminfo['MemAvailable']
                self.assertTrue(MemAvailable <= MemTotal, 'MemAvailable {} > MemTotal {}'.format(MemAvailable, MemTotal))
        restore_mos_view()

    def test_proc_meminfo(self):
        self.verify_meminfo(PROCFS_MEMINFO)

    def test_sys_node_meminfo(self):
        for n in NUMA_NODES:
            self.verify_meminfo('{}/node{}/meminfo'.format(SYSFS_NODE, n), n)
