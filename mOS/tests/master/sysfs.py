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
import stat

logger = logging.getLogger()

def statmode(s):
    bits = [stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR,
            stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP,
            stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH]
    assert len(s) == len(bits) and all(c in 'rwx-' for c in s)
    return sum(bit if c == mode else 0
               for c, mode, bit in zip(s, 'rwxrwxrwx', bits))

@unittest.skipUnless(IS_MOS, 'tests require mOS')
class Basics(TestCase):
    sysfs = '/sys/kernel/mOS'
    expectations = {
        'version':                  statmode('r--r--r--'),
        'lwkcpus':                  statmode('r--r--r--'),
        'lwkcpus_mask':             statmode('r--r--r--'),
        'lwkcpus_request':          statmode('-w--w--w-'),
        'lwkcpus_request_mask':     statmode('-w--w--w-'),
        'lwkcpus_reserved':         statmode('rw-r--r--'),
        'lwkcpus_reserved_mask':    statmode('rw-r--r--'),
        'lwkcpus_sequence':         statmode('-w--w--w-'),
        'lwkmem':                   statmode('r--r--r--'),
        'lwkmem_request':           statmode('-w--w--w-'),
        'lwkmem_reserved':          statmode('r--r--r--'),
        'lwkmem_domain_info':       statmode('-w--w--w-'),
        'lwk_options':              statmode('-w--w--w-'),
        'lwkcpus_syscall':          statmode('r--r--r--'),
        'lwkcpus_syscall_mask':     statmode('r--r--r--'),
        'lwk_util_threads':         statmode('-w--w--w-'),
        }

    @unittest.expectedFailure
    def test_permissions(self):
        # Verify sysfs permissions match expected ones.
        for path, mode in self.expectations.items():
            with self.subTest(path=path, mode=oct(mode)):
                st = os.stat(os.path.join(self.sysfs, path))
                self.assertEqual(st.st_mode & 0o777, mode,
                                 'permissions should match: ' + path)

    def test_read(self):
        # Verify readable sysfs files can be read.
        for path, mode in self.expectations.items():
            if stat.S_IROTH & mode:
                with self.subTest(path=path):
                    with open(os.path.join(self.sysfs, path), 'r') as f:
                        logger.debug('contents of %s', path)
                        for n, line in enumerate(f):
                            logger.debug('%4d %s', n, line.rstrip())
                        logger.debug('%4d <EOF>', n + 1)

    def test_lwkcpus(self):
        # Verify lwkcpus file matches the kernel boot arguments.
        logger.debug('kernel cmdline: lwkcpus=%s syscpus=%s normcpus=%s',
                     LWK_CPUS, SYSCALL_CPUS, NORMAL_CPUS)
        actual = cpulist(get_file(os.path.join(self.sysfs, 'lwkcpus')))
        self.assertEqual(LWK_CPUS, actual,
                         'lwkcpus should have expected value')

    @unittest.skip('TODO')
    def test_lwkcpus_mask(self):
        # Verify lwkcpus_mask file matches the kernel boot arguments.
        pass
