#!/usr/bin/env python3
#
# Multi Operating System (mOS for HPC)
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
#

import argparse
import subprocess
import sys
import logging
import re

FORMAT_STRING = '[%(asctime)s] [%(levelname)-8s]  %(message)s'


def fatal(s):
    logging.error('FATAL ERROR: {}'.format(s))
    sys.exit(-1)


def verbose(s):
    if not args.quiet:
        logging.info(s)


def run(cmd, logger=logging.debug):
    '''Run the command; return the output and status.'''
    try:
        logger('cmd={}'.format(cmd))
        out = ''
        p = subprocess.Popen(cmd, stderr=subprocess.STDOUT, universal_newlines=True, bufsize=0, stdout=subprocess.PIPE)
        line = p.stdout.readline()
        while line:
            logger('{}'.format(line.rstrip()))
            out += line
            line = p.stdout.readline()
        p.wait()
        return out, p.returncode
    except subprocess.CalledProcessError as err:
        logger('Command "{}" returned {}.'.format(' '.join(cmd), err.returncode))
        return err.output, err.returncode


def noop():
    pass


PRESENT = re.compile('(.*) matching tests')

def top_level_is_present(component):
    '''Determine if tests of a component are present.'''

    out, rc = run(['./suite', '-l', component])

    if rc != 0:
        fatal('Could not list test cases.')

    for line in out.split('\n'):
        m = PRESENT.match(line)
        if m:
            return m.group(1) != '0'

    logging.warning('Assuming that {} is present.'.format(component))
    return True

lwk_partition_descr = None

def save_lwk_partition():
    logging.info('Saving LWK partition spec and deleting current LWK partition ...')

    global lwk_partition_descr

    lwk_partition_descr, rc = run(['lwkctl', '--show', '--raw'])
    
    if rc == 0:
        out, rc = run(['sudo', 'lwkctl', '--delete', 'all'])

    if rc:
        fatal('Could not remove LWK partition.')

def restore_lwk_partition():
    logging.info('Restoring LWK partition ...')

    # Use the LWK partition description that we snapshotted above
    # to restore the node to its prior configuration.
    out, rc = run(['sudo', 'lwkctl', '-v', '2', '-c', lwk_partition_descr], logger=logging.info)

    if rc != 0:
        fatal('Non-zero status from lwkctl when restoring LWK partition.')

def mos_core_precheck():
    return top_level_is_present('mos-core/*')

def mos_core_setup():
    '''Prepare to run mos-core tests.  To do this, tear down the existing
    LWK partition.'''
    save_lwk_partition()

def mos_core_teardown():
    '''All mos-core tests are complete.  Re-establish the LWK partiion so
    that other tests can run in a true LWK environment.'''
    restore_lwk_partition()

def lwkctl_precheck():
    return top_level_is_present('lwkctl/*') and top_level_is_present('lwksched.*') and top_level_is_present('lwkmem/lwkmem.*')

def lwkctl_setup():
    save_lwk_partition()

def lwkctl_teardown():
    restore_lwk_partition()

def partition_tests(test_list):
    '''Break the test list into different groups.  Each group has
    a pre-execution handler and a post-execution handler.'''

    # The grouping at this time is mos-core, lwkctl and all
    # other tests

    MOS_CORE = (mos_core_precheck, mos_core_setup, mos_core_teardown)
    STANDARD = (None, noop, noop)
    LWKCTL   = (lwkctl_precheck, lwkctl_setup, lwkctl_teardown)

    result = dict()

    if test_list is None:

        # If no filters were specified, we use wild-carded partitions.
        # Passing these to the suite executor improves efficiency
        # relativate to passing each test one at a time.
        # Note that the period rather than a slash in the lwksched
        # specifier is not a typo

        return {
            STANDARD : ['master/*', 'lwkmem/*', 'lwksched.*'],
            MOS_CORE : ['mos-core/*'],
            LWKCTL   : ['lwkctl/*']
        }

    BUCKETS = {
        'mos-core/yod-unit-tests' : MOS_CORE,
        'mos-core/algorithm_unit_tests' : MOS_CORE,
        'lwkctl' : LWKCTL
    }

    for t in test_list:
        added = False
        for key in BUCKETS:
            def add_if_necessary(key, dct):
                if not key in dct:
                    dct[key] = list()
            if t.find(key) >= 0:
                add_if_necessary(BUCKETS[key], result)
                result[BUCKETS[key]].append(t)
                added = True
                continue

        if added:
            continue

        add_if_necessary(STANDARD, result)
        result[STANDARD].append(t)

    return result


def get_filtered_test_list(filters):
    '''Get a list of tests.  This may be a subset of all available
    tests per the filters argument.'''

    test_list = list()

    if filters is not None:

        raw_list, rc = run(['./suite', '-l'], logger=logging.debug)

        if rc:
            error('Could not formulate test list.')
            sys.exit(-1)

        for t in raw_list.split('\n'):
            t = t.strip()
            for f in filters:
                if t.find(f) >= 0:
                    logging.debug('Including test "{}" ...'.format(t))
                    test_list.append(t)
                    continue

    return test_list


TESTS_RUN = re.compile('Ran (.*) tests in (.*)s')
FAILED_STATUS = re.compile('FAILED \((.*)\)')
OK_STATUS = re.compile('OK \((.*)\)')

def run_test(t):
    '''Run a test.  Not that test here might be an larger grouping
    of tests, e.g. master/*.'''

    verbose('Running test {} ...'.format(t))
    cmd = ['./suite', '-v']
    if args.all_tests:
        cmd += ['--all-tests']
    cmd += [t]
    out, rc = run(cmd, logger=logging.debug)

    def get_run_status(m):
        return 'No tests were executed.' if m.group(1) == '0' else m.group(0)

    def get_summary_status(m):
        return m.group(1)

    status = list()

    # Scrape through the output and glean some additional and interesting
    # status.

    for l in out.split('\n'):
        for regex, handler in [(TESTS_RUN, get_run_status), (FAILED_STATUS, get_summary_status), (OK_STATUS, get_summary_status)]:
            m = regex.match(l)
            if m:
                s = handler(m)
                if s is not None:
                    status.append(s)

    logging.info('Test {} {} [{}]'.format(t, 'FAILED' if rc != 0 else 'PASSED', ', '.join(status)))
    if rc != 0:
        logging.info('ERROR INFO:\n\t{}'.format(out.replace('\n', '\n\t')))
    return rc


def main():

    global args

    parser = argparse.ArgumentParser(description='Run mOS unit tests.')
    parser.add_argument('-f', '--filter', action='append', help='Filter tests.')
    parser.add_argument('--all-tests', action='store_true', help='Execute all tests, including long-running production tests.')
    parser.add_argument('--diagnose', action='store_true', help='Gather additional debug information for failing tests.')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug.')
    parser.add_argument('-q', '--quiet', action='store_true', help='Be less verbose')
    args = parser.parse_args()

    logging.basicConfig(format=FORMAT_STRING, datefmt='%m/%d/%Y %I:%M:%S', level=logging.INFO)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    test_list = None

    if args.filter:
        test_list = get_filtered_test_list(args.filter)

        if len(test_list) == 0:
            logging.info('There are no tests matching your filter.')
            return

    test_partition = partition_tests(test_list)
    failures = list()

    logging.info('Running {} tests ...'.format(len(test_list) if test_list is not None else 'all'))

    for (precheck, setup, teardown) in test_partition:

        if precheck is not None and not precheck():
            continue

        setup()

        for t in test_partition[(precheck, setup, teardown)]:
            rc = run_test(t)
            if rc != 0:
                failures.append(t)

        teardown()

    logging.info('There were {} failures.'.format(len(failures)))

    if (len(failures) > 0):
        logging.info('Failing tests:\n  {}'.format('\n  '.join(failures)))

    # In diagnosing mode, rerun the tests with additional levels of verbosity
    # so that the failure can be analyzed.

    if args.diagnose:
        for t in failures:
            logging.info('{} Details for {} {}'.format('-'*16, t, '-'*16))
            cmd = ['./suite', '-vv', '--unbuffered']
            if args.all_tests:
                cmd += ['--all-tests']
            cmd += [t]
            out, rc = run(cmd)
            logging.info('rc={}\n{}'.format(rc, out))

if __name__ == '__main__':
    main()

