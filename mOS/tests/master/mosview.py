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
import stat

# File paths
# procfs
PROCFS_CPUINFO = '/proc/cpuinfo'
PROCFS_STAT = '/proc/stat'
# sysfs
SYSFS_CPU = '/sys/devices/system/cpu'
SYSFS_NODE = '/sys/devices/system/node'
SYSFS_CPU_ONLINE =  '{}/online'.format(SYSFS_CPU)
SYSFS_CPU_OFFLINE = '{}/offline'.format(SYSFS_CPU)
SYSFS_CPU_PRESENT = '{}/present'.format(SYSFS_CPU)
# mOS view interface
MOSVIEW_PATH = '/proc/{}/mos_view'
MOSVIEW_CURRENT = MOSVIEW_PATH.format('self')
MOSVIEW_INIT = MOSVIEW_PATH.format('1')
# Misc global vars
MOSVIEW_PERM = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH
VALID_MOSVIEWS = ['linux', 'lwk', 'all']
NUMA_NODES = cpulist(get_file('{}/online'.format(SYSFS_NODE)))
LWKCPU_MASK = int(LWK_CPUS)
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

def fork_and_verify(mos_view):
    if set_mos_view('self', mos_view):
        parent_mos_view = get_file(MOSVIEW_CURRENT)

        pid = os.fork()

        if pid:
            pid, status = os.wait()
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status) == os.EX_OK
        else:
            if parent_mos_view == get_file(MOSVIEW_CURRENT):
                os._exit(os.EX_OK)
            else:
                os._exit(os.EX_OSERR)

    return False

def get_procfs_stat_mask(path):
    mask = 0
    with open(path, 'r') as f:
        for line in f:
            if line.startswith('cpu'):
                cpu_str = line.split()[0].replace('cpu', '')
                if cpu_str != '':
                    cpu = int(cpu_str)
                    mask |= 1 << cpu
    return cpulist(mask)

def get_procfs_cpuinfo_mask(path):
    mask = 0
    with open(path, 'r') as f:
        for line in f:
            if line.find('processor') != -1:
                tok = line.split()
                cpu = int(tok[2].strip())
                mask |= (1 << cpu)
    return cpulist(mask)

def get_cpu_mask_sysfs_list(path):
    return cpulist(get_file(path))

def get_cpu_mask_sysfs_map(path):
    return cpulist(mask = get_file(path))

def get_sysfs_cpu_dev_online(path):
    mask = 0
    for cpu in os.listdir(path):
        if cpu.startswith('cpu'):
            online='{}/{}/online'.format(path, cpu)
            if (os.path.exists(online)):
                if get_file(online) == '1':
                    c = int(cpu.replace('cpu', ''))
                    mask |= 1 << c
    return cpulist(mask)

@unittest.skipUnless(IS_MOS, 'tests require mOS')
class Basic(TestCase):
    def test_init_proc_mos_view(self):
        self.assertTrue(mos_view_exists(), 'Unable to find mOS view interface')
        init_mos_view = get_file(MOSVIEW_INIT)
        self.assertEqual(init_mos_view, 'all', 'Invalid mOS view [{}] set for init process'.format(init_mos_view))

    def test_mos_view_permissions(self):
        permissions=os.stat(MOSVIEW_CURRENT).st_mode & 0o777
        self.assertEqual(permissions, MOSVIEW_PERM, 'Invalid permissions: {0:o}'.format(permissions))

    def test_mos_view_rw(self):
        self.assertTrue(mos_view_exists(), 'Unable to find mOS view interface')
        save_mos_view()
        for mos_view in VALID_MOSVIEWS:
            self.assertTrue(set_mos_view('self', mos_view), 'Failed to set mOS view [{}]'.format(mos_view))
        restore_mos_view()

    def test_mos_view_inherit_parent(self):
        self.assertTrue(mos_view_exists(), 'Unable to find mOS view interface')
        save_mos_view()
        for mos_view in VALID_MOSVIEWS:
            self.assertTrue(fork_and_verify(mos_view), 'Failed to verify inheritance of mOS view: {}'.format(mos_view))
        restore_mos_view()

@unittest.skipUnless(IS_MOS, 'tests require mOS')
class CPU(TestCase):
    def verify_cpumask(self, get_mask, path, Type=None):
        self.assertTrue(mos_view_exists(), 'Unable to find mOS view interface')
        save_mos_view()
        masks = dict()
        for mos_view in VALID_MOSVIEWS:
            set_mos_view('self', mos_view)
            masks[mos_view] = get_mask(path)

        if Type == 'offline':
            # For linux view all LWK cpus must be shown as offline. There could be Linux offlined CPUs
            cond = int(masks['linux']) & LWKCPU_MASK == LWKCPU_MASK
            self.assertTrue(cond, 'Invalid mOS view CPUs in linux view')
            # For lwk and all view only non-LWK CPUs must be shown offline
            cond = int(masks['lwk']) & LWKCPU_MASK
            self.assertTrue(cond == 0, 'Invalid mOS view CPUs in lwk view')
            cond = int(masks['all']) & LWKCPU_MASK
            self.assertTrue(cond == 0, 'Invalid mOS view CPUs in all view')
        else:
            # In lwk view the mask should have only LWK CPUs
            if Type == 'node':
                cond = int(masks['lwk']) & LWKCPU_MASK == int(masks['lwk'])
            else:
                cond = int(masks['lwk']) == LWKCPU_MASK
            self.assertTrue(cond, 'Invalid mOS view CPUs in lwk view')

            # CPUs in linux view should not be present in lwk view and vice versa
            intersection = int(masks['linux']) & int(masks['lwk'])
            # CPUs in all view should be the union set of CPUs in linux and lwk views
            union = int(masks['linux']) | int(masks['lwk'])

            self.assertTrue(intersection == 0, 'CPUs in both linux and lwk view: [{}]'.format(cpulist(intersection)))
            self.assertTrue(union == int(masks['all']), 'CPUs in linux + lwk view != all view -> {}'.format(masks))
        restore_mos_view()

    def test_proc_cpuinfo(self):
        self.verify_cpumask(get_procfs_cpuinfo_mask, '/proc/cpuinfo')

    def test_proc_stat(self):
        self.verify_cpumask(get_procfs_stat_mask, PROCFS_STAT)

    def test_sys_cpus_online(self):
        self.verify_cpumask(get_cpu_mask_sysfs_list, SYSFS_CPU_ONLINE)

    def test_sys_cpus_offline(self):
        self.verify_cpumask(get_cpu_mask_sysfs_list, SYSFS_CPU_OFFLINE, 'offline')

    def test_sys_cpus_present(self):
        self.verify_cpumask(get_cpu_mask_sysfs_list, SYSFS_CPU_PRESENT)

    def test_sys_cpus_device_online(self):
        self.verify_cpumask(get_sysfs_cpu_dev_online, SYSFS_CPU)

    def test_sys_node_cpumap(self):
        for n in NUMA_NODES:
            self.verify_cpumask(get_cpu_mask_sysfs_map, '{}/node{}/cpumap'.format(SYSFS_NODE, n), 'node')

    def test_sys_node_cpulist(self):
        for n in NUMA_NODES:
            self.verify_cpumask(get_cpu_mask_sysfs_list, '{}/node{}/cpulist'.format(SYSFS_NODE, n), 'node')
