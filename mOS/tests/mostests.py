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

import sys, os, unittest, logging
import inspect as _inspect
import subprocess as _subprocess
import shlex as _shlex
import collections as _collections
import contextlib as _contextlib
import tempfile as _tempfile

from __main__ import ARGS

_logger = logging.getLogger()

# test infrastructure

class MissingTool(object):
    def __init__(self, filename):
        self.tool = filename
    def __bool__(self):
        return False
    def __str__(self):
        return self.tool

def import_from_file(filename):
    '''import filename and return the resulting module object'''
    from importlib.machinery import SourceFileLoader
    mod = _inspect.getmodule(_inspect.stack()[1][0])
    fp = os.path.join(os.path.dirname(mod.__file__), filename)
    name = os.path.splitext(os.path.basename(fp))[0]
    return SourceFileLoader(name, fp).load_module(name)

def path_of(obj):
    '''return the directory of the file that defined obj'''
    cls = obj if isinstance(obj, type) else obj.__class__
    return os.path.dirname(_inspect.getfile(cls))

def _backquote(command):
    return _subprocess.check_output(command).decode('utf8').strip()

def _cmdline(path='/proc/cmdline'):
    with open(path, 'r') as f:
        # it's valid to use double-quotes on the kernel command line
        cmd = dict((kv.split('=', 1) if '=' in kv else (kv, None))
                   for kv in _shlex.split(f.read()))
        logging.debug('{} -> {!r}'.format(path, cmd))
    return cmd

def _find_tool(filename, condition=True, PATH=True):
    if condition:
        d = getattr(ARGS, filename, None)
        if d:
            return os.path.abspath(d)
        path = os.getenv('PATH', '/usr/local/bin:/bin:/usr/bin').split(':') \
               if PATH else []
        path.insert(0, os.path.dirname(__file__))
        path.insert(0, os.path.join('/lib/modules', KERNELRELEASE))
        for p in path:
            p = os.path.join(p, filename)
            if os.access(p, os.X_OK):
                p = os.path.abspath(p)
                _logger.info('found %s: %s', filename, p)
                return os.path.abspath(p)
    _logger.info('missing %s', filename)
    return MissingTool(filename)

def _lwkcpus(liststr):
    '''parse the Linux kernel command line option'''
    if liststr:
        for part in liststr.split(':'):
            dst, src = (cpulist(p) for p in part.split('.'))
            yield CPUoffloads(dst, src)

# classes/functions used by multiple test modules

CPUoffloads = _collections.namedtuple('CPUoffloads', ['dst', 'src'])

class cpulist(_collections.Set):
    '''A set of CPUs'''

    def __init__(self, obj=None, mask=None):
        '''initialize from a str (Linux list or mask), an int (bitmap),
        or an iterable of ints (CPU numbers)'''
        assert obj is None or mask is None

        def parse_list(s):
            for xy in s.split(','):
                if xy:
                    x, y = xy.split('-') if '-' in xy else (xy, xy)
                    for cpu in range(int(x), int(y) + 1):
                        yield cpu

        if obj is None and mask is None:
            self._bits = 0
        elif mask is not None:  # str in Linux CPU mask format
            self._bits = int(''.join(s.split(',')), 16)
        elif isinstance(obj, str):  # str in Linux CPU list format
            self._bits = sum(1 << cpu for cpu in parse_list(obj))
        elif isinstance(obj, int):  # int (a bitmap)
            self._bits = int(obj)
        elif isinstance(obj, self.__class__):
            self._bits = obj._bits
        else:  # iterable of ints (CPU numbers)
            self._bits = sum(1 << cpu for cpu in obj)

    def __repr__(self):
        # possibly useful from the REPL
        return '{}({!r})'.format(self.__class__.__name__, self.__str__())

    def __int__(self):
        '''convert to an int (a bitmap)'''
        return sum(1 << cpu for cpu in self)

    def __iter__(self):
        '''convert to an interable of ints (CPU numbers)'''
        for cpu in range(self._bits.bit_length()):
            if (1 << cpu) & self._bits:
                yield cpu

    def __str__(self):
        '''convert to Linux kernel list format'''
        def ranges(seq):
            while seq:
                for i, cpu in enumerate(seq):
                    if cpu - i != seq[0]:
                        break
                else:
                    i += 1
                yield seq[0], seq[i-1]
                seq = seq[i:]
        return ','.join('{}'.format(b) if b == e else '{}-{}'.format(b, e)
                        for b, e in ranges(list(self)))

    def mask(self):
        '''convert to Linux kernel mask format'''
        m = ''.join(reversed('{:x}'.format(int(self))))
        m = ','.join(m[i:i+8] for i in range(0, len(m), 8))
        return ''.join(reversed(m))

    def __contains__(self, v):
        if isinstance(v, int):
            return bool((1 << v) & self._bits)
        raise TypeError('must be {} not {}'.format(int, type(v)))

    def __len__(self):
        return bin(self._bits).count('1')

    def __getitem__(self, index):
        item = tuple(self)[index]
        return self.__class__(item) if isinstance(index, slice) else item

    def whole(self, partitions):
        return cpulistlist(p for p in partitions if self & p == p)

    @classmethod
    def OR(cls, iterable):
        u = cls(0)
        for o in iterable:
            u = u | o
        return u

class cpulistlist(_collections.Sequence):
    '''A set of sets of CPUs'''

    def __init__(self, iterable):
        self._list = [cpulist(o) for o in iterable]

    def __getitem__(self, index):
        item = self._list[index]
        return self.__class__(item) if isinstance(index, slice) else item

    def __len__(self):
        return len(self._list)

    @property
    def OR(self):
        return cpulist.OR(self._list)

def intlist(text, delim=None, base=10):
    return [int(i, base) for i in text.split(delim)]

def strseq(seq, delim=' '):
    return delim.join(str(i) for i in seq)

def notNone(first, second):
    return first if first is not None else second

def get_file(path):
    with open(path, 'r') as f:
        txt = f.read().strip()
    _logger.debug('%s: %r', path, txt)
    return txt

# facts about the running kernel

KERNELRELEASE = _backquote(['uname', '-r'])
IS_MOS = os.path.exists('/sys/kernel/mOS')

# parsed kernel command line arguments (verbatim)

CMDLINE = _cmdline()
LWKCPUS = list(_lwkcpus(CMDLINE.get('lwkcpus')))

# parsed kernel CPU state / groups

POSSIBLE_CPUS = cpulist(get_file('/sys/devices/system/cpu/possible'))
ONLINE_CPUS = cpulist(get_file('/sys/devices/system/cpu/online'))
CONFIG_NR_CPUS = int(get_file('/sys/devices/system/cpu/kernel_max')) + 1
MAX_CPUS = max(POSSIBLE_CPUS) + 1

EVANESCENCE_MAP = [CPUoffloads(o.dst & ONLINE_CPUS, o.src & ONLINE_CPUS)
                   for o in LWKCPUS]

# these CPUs offload syscalls to other CPUs
LWK_CPUS = cpulist.OR(o.src for o in EVANESCENCE_MAP)
if IS_MOS:
    assert LWK_CPUS == cpulist(get_file('/sys/kernel/mOS/lwkcpus'))
# these CPUs receive offloads from other CPUs
SYSCALL_CPUS = cpulist.OR(o.dst for o in EVANESCENCE_MAP)
# these CPUs neither offload nor receive offloads
NORMAL_CPUS = ONLINE_CPUS - LWK_CPUS - SYSCALL_CPUS

# helpers for running programs (without/with yod)

STAPRUN = _find_tool('staprun')
YOD = _find_tool('yod', IS_MOS, PATH=False)

def run(test, *command, env={}, bg=False, pipe='', assertion=True):
    # run(...) -> return code
    # run(..., bg=True) -> context manager which returns Popen instance
    # run(..., pipe='oe') -> return code, stdout, stderr
    assert bg or 'i' not in pipe
    assert all(s in 'ioe' for s in pipe)

    def writeout(s, f):
        if s is not None:
            sys.stdout.write(s)
        elif f is not None:
            f.seek(0)
            for line in f:
                f.write(line)
            f.close()

    @_contextlib.contextmanager
    def manager():
        _logger.debug('exec [%s] {%s} at %s',
                      ' '.join(_shlex.quote(v) for v in command),
                      ' '.join('{}={}'.format(k, _shlex.quote(v))
                               for k, v in env.items()),
                      where)
        sys.stdout.flush()
        sys.stderr.flush()
        p = _subprocess.Popen(command, env=e, cwd=where, shell=False,
                              stdin=fi, stdout=fo, stderr=fe,
                              universal_newlines=True, close_fds=True)
        captured[-1] = p
        yield p
        stdout, stderr = p.communicate()
        writeout(stdout, fo)
        writeout(stderr, fe)
        captured[:-1] = stdout, stderr
        check_returncode(test, p.returncode, assertion)

    where = path_of(test)
    command = [str(v) for v in command]
    env = {k: str(v) for k, v in env.items()}
    e = dict(os.environ)
    e.update(env)
    fi = _subprocess.PIPE if 'i' in pipe else _subprocess.DEVNULL
    fo = _subprocess.PIPE if 'o' in pipe else None
    fe = _subprocess.PIPE if 'e' in pipe else None
    if not ARGS.unbuffered:
        fo = _tempfile.TemporaryFile() if fo is None else fo
        fe = _tempfile.TemporaryFile() if fe is None else fe

    captured = [None, None, -1]
    if bg:
        return manager()
    with manager() as p:
        pass
    stdout, stderr, p = captured

    if 'o' in pipe or 'e' in pipe:
        return p.returncode, stdout, stderr
    return p.returncode

def check_returncode(test, returncode, assertion):
    if returncode < 0:
        _logger.debug('killed by signal %d', -returncode)
    else:
        _logger.debug('returned %d', returncode)
    if isinstance(test, unittest.TestCase):
        test.assertCommand(returncode, assertion)
    else:
        assert returncode >= 0
        if assertion is None:
            pass
        elif assertion:
            assert returncode == 0
        else:
            assert returncode > 0

def yod(test, *command, **kw):
    if YOD:  # you should require YOD if it's mandatory
        command = [YOD] + list(command)
    return run(test, *command, **kw)

# mOS TestCase class

def _inherited_list(cls, attr):
    return set(v for c in cls.__mro__ for v in getattr(c, attr, []))

class TestCase(unittest.TestCase):
    require = []
    modules = []

    @classmethod
    def skipClass(cls, reason, *args, **kw):
        msg = '{}.{} {}'.format(path_of(cls), cls.__name__,
                                reason.format(*args, **kw))
        raise unittest.SkipTest(msg)

    @classmethod
    def setUpClass(cls):
        require = _inherited_list(cls, 'require')
        modules = _inherited_list(cls, 'modules')
        require.update(modules)
        _logger.debug('require %s', require)
        _logger.debug('insmod %s', modules)

        for f in require:
            if isinstance(f, MissingTool) or \
               not os.path.exists(os.path.join(path_of(cls), f)):
                cls.skipClass('requires a missing file: {}', f)

        if modules and os.geteuid() != 0:
            cls.skipClass('requires root to insmod')
        for m in modules:
            run(cls, '/sbin/insmod', m)

    def skipTest(self, reason, *args, **kw):
        super().skipTest(reason.format(*args, **kw))

    if sys.version_info < (3, 4):  # preserve compatibility
        @_contextlib.contextmanager
        def subTest(self, msg=None, **params):
            _logger.debug('%s%s', '' if msg is None else msg + ' ',
                          ' '.join(['%s=%s' % kv for kv in params.items()]))
            yield

    def assertCommand(self, returncode, result):
        self.assertFalse(returncode ==  -6, 'command killed by SIGABRT')
        self.assertFalse(returncode ==  -7, 'command killed by SIGBUS')
        self.assertFalse(returncode ==  -8, 'command killed by SIGFPE')
        self.assertFalse(returncode == -11, 'command killed by SIGSEGV')
        self.assertFalse(returncode < 0, 'command killed by a signal')
        if result is None:
            pass
        elif result:
            self.assertEqual(returncode, 0, 'command should succeed')
        else:
            self.assertGreater(returncode, 0, 'command should fail')

    @classmethod
    def tearDownClass(cls):
        modules = _inherited_list(cls, 'modules')
        _logger.debug('rmmod %s', modules)

        for m in modules:
            run(cls, '/sbin/rmmod', m)
