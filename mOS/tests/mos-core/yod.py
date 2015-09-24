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
import argparse
import subprocess
import collections
import copy

logger = logging.getLogger()

class affinity_test:
    '''Implement most of this test program in Python since it's way less
    code, and we can share implementation with the test suite.'''
    def __init__(self, command):
        p = argparse.ArgumentParser(prog=type(self).__name__)
        p.add_argument('--affinity', action='store')
        p.add_argument('--echo', action='store_true')
        p.add_argument('--commas', action='store_true')
        p.add_argument('--lwkmem_reserved', action='store')
        p.add_argument('--lwkcpus_reserved', action='store')
        self.args = p.parse_args(command)
    def __call__(self, test, stdout):
        def cpus(v):
            if v.startswith('0x'):
                return cpulist(int(v[2:].replace(',', ''), 16))
            return cpulist(v)
        def mems(v):
            s = sum(int(m, 0) for m in v.replace(',', ' ').split())
            return s // (2 * 1024**2)  # may round down
        def lines(l):
            l = l.split(' ', 1)
            return l if len(l) > 1 else (l[0], '')
        attrs = {'affinity': cpus,
                 'lwkcpus_reserved': cpus,
                 'lwkmem_reserved': mems}
        act = dict(lines(l) for l in stdout.splitlines())
        for n, f in attrs.items():
            if getattr(self.args, n):
                test.assertEqual(f(getattr(self.args, n)),
                                 f(act[n].strip()),
                                 '{} should match'.format(n))

WRAPPED = {
    './affinity_test': affinity_test,
    }

def launch(test, command, env={}):
    '''Launch command, return both the output and return code.'''
    for prog, wrapper in WRAPPED.items():
        try:
            i = command.index(prog)
        except ValueError:
            continue
        command[i+1:], obj = [], wrapper(command[i+1:])
        obj = None if '--dry-run' in command else obj  # a yod option
        break
    else:
        obj = None

    r, o, e = yod(test, *command, env=env, pipe='o', assertion=None)
    if r == 0 and obj is not None:
        obj(test, o)
    return (o, r)

class CpuTopology:
    lscpuRow = collections.namedtuple('lscpuRow',
        ['cpu', 'node', 'socket', 'core', 'tile'])

    def __init__(self, lscpu=None):
        if lscpu is None:
            # Invoke lscpu and parse the results.  Construct lists of
            # nodes, tiles and cores.
            lscpu = subprocess.check_output(['lscpu', '--online', '-p'],
                                            stderr=subprocess.STDOUT,
                                            universal_newlines=True)

        self.lscpu = []
        cols = 'CPU', 'Node', 'Socket', 'Core', 'L2'
        for line in lscpu.splitlines():
            if line.startswith('#'):
                line = line[1:].lstrip().split(',')
                if all(c in line for c in cols):
                    header = {c: i for i, c in enumerate(line)}
                continue

            line = line.split(',')
            self.lscpu.append(self.lscpuRow(*[int(line[header[c]], 10)
                                              for c in cols]))
        assert self.lscpu

        def cs(attr, index):
            return CpuSet(sum(1 << row.cpu for row in self.lscpu
                              if getattr(row, attr) == index))
        mcpu, mnode, mskt, mcore, mtile = map(max, zip(*self.lscpu))
        self.nodes = [cs('node', i) for i in range(mnode + 1)]
        self.tiles = [cs('tile', i) for i in range(mtile + 1)]
        self.cores = [cs('core', i) for i in range(mcore + 1)]
        self.allcpus_mask = sum(1 << row.cpu for row in self.lscpu)
        self.allcpus = CpuSet(self.allcpus_mask)

class CpuSet:
    def __init__(self, m):
        self.mask = m

    def __repr__(self):
        return self.toList()

    def __int__(self):
        return self.mask

    def __add__(self, other):
        return CpuSet(self.mask | other.mask)

    def __sub__(self, other):
        return CpuSet(self.mask & ~other.mask)

    def __and__(self, other):
        return CpuSet(self.mask & other.mask)

    def __eq__(self, other):
        return self.mask == other.mask

    def __ne__(self, other):
        return self.mask != other.mask

    def toList(self):
        mask = self.mask

        result = ''
        i = 0

        def _addComma(s):
            if len(s) > 0:
                return ','
            return ''

        while (mask):
            if mask & 3 == 3:
                start = str(i)
                while mask & 3 == 3:
                    mask >>= 1
                    i += 1
                result += _addComma(result) + start + '-' + str(i)
            elif mask & 1:
                result += _addComma(result) + str(i)
            i += 1
            mask >>= 1

        return result

    def fromList(self, s):
        self.mask = 0
        for elem in s.split(','):
            if '-' in elem[1:]:
                first, last = elem.split('-')
                for n in range(int(first), int(last) + 1):
                    self.mask |= 1 << n
            else:
                self.mask |= 1 << int(elem)
        return self

    def countCpus(self):
        '''Counts the number of CPUs in this CPU set.'''
        return bin(self.mask).count('1')

    def nthCpu(self, nth):
        '''Returns a new CPU set consisting of the nth CPU (in ascending
        order) from this CPU set.  Note that numbering starts at
        one, i.e. to get the first CPU, use nthCpu(1,x).  If there
        are fewer than "nth" CPUs in this set, the empty CPU set is returned.'''

        msk = bin(self.mask)
        N = self.countCpus()

        if nth <= 0 or N < nth:
            return CpuSet(0)

        msk = msk.replace('1', 'y', N - nth)
        return CpuSet(1 << (len(msk) - msk.find('1') - 1))

    def filterBy(self, partition):
        '''Returns a new CPU set that is reduced to include only the
        entire entities descibed by "partition".  For example, to reduce
        a CPU set "c" to contain only entire cores, invoke
        c.filterBy(CpuSet.cores).'''

        result = self.mask
        for p in partition:
            if result & p.mask != p.mask:
                result &= ~p.mask

        return CpuSet(result)

    def selectNthBy(self, nth, partition):
        '''Walks the given partition over this CPU set and returns
        the nth element that was present.  If there were fewer than
        "nth" elements present, then return the empty CPU set.  Note
        that counting starts at one (not zero).  For example, to
        construct the 3rd complete core in a give set s, invoke
        s.selectNthBy(3, CpuSet.cores)'''

        if nth <= 0:
            return CpuSet(0)

        for p in partition:
            if self.mask & p.mask == p.mask:
                nth -= 1
                if nth == 0:
                    # return a copy to be safe
                    return CpuSet(p.mask)
        return CpuSet(0)

    def countBy(self, partition):
        '''Counts the number of elements described by "partition"
        contained in this CpuSet.  For example, to count the number
        of complete cores in s, invoke s.countBy(CpuSet.cores).'''

        result = 0

        for p in partition:
            if self.mask & p.mask == p.mask:
                result += 1

        return result

    def isEmpty(self):
        return self.mask == 0

    def isSubsetOf(self, other):
        diff = self.mask ^ other.mask
        return (diff == 0) or (diff & self.mask == 0 and diff & ~other.mask == 0)

class YodTestCase(TestCase):
    require = [YOD, './affinity_test']

    yod_plugin = 'yod.plugin'
    yod_lscpu = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        base_dir = os.path.join('/tmp', os.environ['USER'])
        state_dir = os.path.join(base_dir, 'yod')
        plugin = os.path.join(base_dir, cls.yod_plugin or 'mos.plugin')

        lscpu = None
        if cls.yod_lscpu:
            lscpu = get_file(os.path.join(os.path.dirname(__file__),
                                          cls.yod_lscpu))

        # derived classes mustn't share instances
        cls.topology = CpuTopology(lscpu)
        cls.test_env = {}  # read-only in except in setUpClass
        cls.var = {}  # may be changed in tests (as self.var)

        # Environment vars that control yod, including the test plugin
        # data:
        if cls.yod_plugin:
            cls.test_env['YOD_TST_PLUGIN'] = plugin

        # Ensure that the directories for test plugin and mock sysfs exist.
        for path in [base_dir, state_dir]:
            if os.path.isdir(path):
                pass
            elif os.path.exists(path):
                logger.error('ERROR: {} is not a directory.  Move it out of the way and retry.'.format(path))
                sys.exit(-1)
            else:
                os.makedirs(path)

        # Construct the unit test plugin for yod; this must be done
        # prior to invoking the utils, which also uses the plugin file.
        with open(plugin, 'w') as f:
            f.write('CPU,Core,Tile,Node\n')
            for row in cls.topology.lscpu:
                f.write('{},{},{},{}\n'.format(row.cpu, row.core,
                                               row.tile, row.node))

        # Various environment variables for test binaries (yod and payloads):

        cls.var['HELLO'] = '/bin/echo'
        cls.var['AFFINITY_TEST'] = './affinity_test'

        # Some generally useful values to have:
        cls.var['ALLCPUS'] = str(cls.topology.allcpus)

        # Various environment variables for the test plugin sysfs.  These
        # mirror an actual mOS sysfs subsystem. The "FS_*" variables
        # identify the file path names.  The "I_*" variables represent
        # the initial state of the corresponding file prior to each
        # test.  Tests will clone this dictionary and may override the
        # "I_*" values to suite the needs of that particular test.

        cls.var['FS_DIR'] = state_dir
        cls.var['FS_LWKCPUS'] = '/'.join((state_dir, 'lwkcpus'))
        cls.var['FS_LWKCPUS_RESERVED'] = '/'.join((state_dir, 'lwkcpus_reserved'))
        cls.var['FS_LWKCPUS_SEQUENCE'] = '/'.join((state_dir, 'lwkcpus_sequence'))
        cls.var['FS_LWK_UTIL_THREADS'] = '/'.join((state_dir, 'lwk_util_threads'))
        cls.var['FS_LWKMEM'] = '/'.join((state_dir, 'lwkmem'))
        cls.var['FS_LWKMEM_RESERVED'] = '/'.join((state_dir, 'lwkmem_reserved'))
        cls.var['FS_LWKMEM_GROUPS'] = '/'.join((state_dir, 'lwkmem_groups'))
        cls.var['FS_LWKMEM_DOMAIN_INFO'] = '/'.join((state_dir, 'lwkmem_domain_info'))
        cls.var['FS_LWK_OPTIONS'] = '/'.join((state_dir, 'lwk_options'))

        cls.var['I_LWKCPUS'] = cls.var['ALLCPUS']
        cls.var['I_LWKCPUS_RESERVED'] = ' '
        cls.var['I_LWK_UTIL_THREADS'] = '0'

        if ARGS.test_yod_scalar:
            cls.var['I_LWKMEM'] = '68719476736' # 64G
            cls.var['I_LWKMEM_RESERVED'] = '0'
        else:
            cls.var['I_LWKMEM'] = '34359738368 34359738368' # 64G
            cls.var['I_LWKMEM_RESERVED'] = '0 0'

        cls.var['I_LWKMEM_DOMAIN_INFO'] = ''
        cls.var['I_LWK_OPTIONS'] = ''

        # By default, put all possible nids in memory group 0
        nids = cpulist(get_file('/sys/devices/system/node/possible'))
        cls.var['I_LWKMEM_GROUPS'] = str(nids)
        largest = max(nids)
        twenty_ones = ["21"] * largest
        for nid in range(largest + 1):
            dist = []
            if nid > 0:
                dist = twenty_ones[:nid]
            dist += ["10"]
            if nid < largest:
                dist += twenty_ones[:largest - nid]
            with open('/'.join([state_dir, "distance" + str(nid)]), 'w') as dmap:
                dmap.write(' '.join(dist))

        # Establish sustitution lists.  These help test variations
        # of yod without replication.  For example, a specific
        # test might specify '%CORES%', which may then be expanded
        # into its two forms (-C, --cores).

        cls.substitutions = {
            '%CORES%':          ['--cores', '-C'],
            '%CPUS%':           ['--cpus', '-c'],
            '%UTIL_THREADS%':   ['--util_threads', '-u'],
            '%MEM%':            ['--mem', '-M'],
            '%RESOURCES%':      ['--resources', '-R'],
            '%VERBOSE%':        ['--verbose', '-v'],
            '%OPT%':            ['--opt', '-o'],
            '%HELP%':           ['--help', '-h'],
            '%AFFINITY_TEST%':  [cls.var['AFFINITY_TEST']],
            '%HELLO%':          [cls.var['HELLO']],
            }

    def setUp(self):
        # clone the variable table so that a test may override default
        # values, like the set of designated LWK CPUs:
        self.var = copy.copy(self.__class__.var)
        self.reset_sysfs()

    def reset_sysfs(self):
        '''Reset the mock sysfs used by the yod test plugin.'''

        sysfs_reset = [
            (self.var['FS_LWKCPUS'], self.var['I_LWKCPUS']),
            (self.var['FS_LWKCPUS_RESERVED'], self.var['I_LWKCPUS_RESERVED']),
            (self.var['FS_LWKMEM'], self.var['I_LWKMEM']),
            (self.var['FS_LWKMEM_RESERVED'], self.var['I_LWKMEM_RESERVED']),
            (self.var['FS_LWKMEM_GROUPS'], self.var['I_LWKMEM_GROUPS']),
            (self.var['FS_LWKCPUS_SEQUENCE'], ''),
            (self.var['FS_LWK_UTIL_THREADS'], self.var['I_LWK_UTIL_THREADS']),
            (self.var['FS_LWK_OPTIONS'], self.var['I_LWK_OPTIONS']),
        ]

        for file, value in sysfs_reset:
            with open(file, 'w') as fd:
                fd.write(value)
                logging.debug('(SYSFS) {} <- {}'.format(file, value))

    def expand_and_run(self, cmd, expected, env={}, postrun=[]):
        '''Expands cmd (using the substitutions lists) and launches
        each expanded command via yod.'''

        tenv = dict((k, str(v))
                    for d in (self.test_env, env)
                    for k, v in d.items())
        cmd = [str(x) for x in cmd]
        logging.debug('Expanding and running cmd="yod {}" expected={}'.format(' '.join(cmd), expected))
        cmds = self.expand_command(cmd)

        for c in cmds:
            with self.subTest('cmd={}'.format(' '.join(c))):
                self.reset_sysfs()
                logging.debug('Executing id={} cmd="{}"'.format(self.id(), ' '.join(c)))
                out, actual = launch(self, c, env=tenv)
                logging.debug('rc={} expected={} out={}'.format(actual, expected, out.replace('\n', '\n\t')))
                self.assertEqual(actual, expected)

                for assertion in postrun:
                    assertion()

    def expand_command(self, cmd):
        '''Expands cmd into a list of commands, using the substitutions.'''

        def substitute(key, lst, values):

            if not key in lst:
                return [lst]

            result = []

            for v in values:
                tmp = copy.copy(lst)
                while key in tmp:
                    n = tmp.index(key)
                    tmp[n] = v
                result.append(tmp)

            return result

        result = [cmd]

        for key in self.substitutions.keys():
            if key in cmd:
                newresult = []
                for lst in result:
                    for v in substitute(key, lst, self.substitutions[key]):
                        newresult.append(v)
                result = newresult
        return result

    def get_designated_lwkcpus(self):
        return CpuSet(0).fromList(self.var['I_LWKCPUS'])

    def get_n_cores(self, n, fromcpus=None, algorithm='numa'):

        logger.debug('(>) get_n_cores n={} from={} alg={}'.format(n, fromcpus, algorithm))

        if fromcpus is None:
            fromcpus = self.get_designated_lwkcpus()

        if fromcpus.countBy(self.topology.cores) < n:
            return None

        result = CpuSet(0)

        if algorithm == 'numa':
            for node in self.topology.nodes:
                for c in range(node.countBy(self.topology.cores)):
                    core = node.selectNthBy(c+1, self.topology.cores)
                    if fromcpus & core == core:
                        logger.debug('get_n_cores: selecting {}th numa core: {}'.format(n, core))
                        n -= 1
                        result += core
                        if n == 0:
                            logger.debug('get_n_cores result={}'.format(result))
                            return result

        elif algorithm == 'simple':
            for core in self.topology.cores:
                if fromcpus & core == core:
                    logger.debug('get_n_cores: selecting {}th simple core: {}'.format(n, core))
                    n -= 1
                    result += core
                    if n == 0:
                        logger.debug('get_n_cores result={}'.format(result))
                        return result
        else:
            logger.error('get_n_cores: Unsupported algorithm {}'.format(algorithm))

        logger.error('get_n_cores: Should not get here!')
        return None
