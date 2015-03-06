#!/usr/bin/env python3
#
# Multi Operating System (mOS for HPC)
# Copyright (c) 2019, Intel Corporation.
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
import copy
import json
import re
import sys

def debug(s):
    if args.debug:
        print('(D) {}'.format(s))

def fatal(s):
    print('(E) {}'.format(s))
    sys.exit(-1)

def main():

    global args

    parser = argparse.ArgumentParser(description='tbd.')
    parser.add_argument('-f', '--file', action='append', required=True)
    parser.add_argument('-d', '--debug', action='store_true')
    args = parser.parse_args()

    #
    #  * EventType: 1001100000
    #  * Severity:  Error
    #  * Component: lwkmem
    #  * Msg:       A process level fatal error occurred in LWK memory.
    #  */
    #  #define MOS_LWKMEM_PROCESS_ERROR "mOSLwkmemProcessError"
    #

    EVENT_TYPE_EXPR = re.compile('.*\*\s+EventType:\s+(.*)')
    SEVERITY_EXPR = re.compile('.*\*\s+Severity:\s+(.*)')
    COMPONENT_EXPR = re.compile('.*\*\s+Component:\s+(.*)')
    MSG_EXPR = re.compile('.*\*\s+Msg:\s+(.*)')
    CONTROL_OPERATION_EXPR = re.compile('.*\*\s+ControlOperation:\s+(.*)')
    DEFINE_EXPR = re.compile('#define (\w+)\s+"(\w+)"')

    SEVERITIES = {
        'Debug': 'DEBUG',
        'Informational': 'INFO',
        'Warning': 'WARN',
        'Error': 'ERROR',
        'Fatal': 'FATAL'}

    KEYS = ('EventType', 'Severity', 'ControlOperation', 'Category', 'Component', 'Msg', 'DescriptiveName')
    OPTIONAL_KEYS = ('ControlOperation', )

    CONTROL_OPERATIONS = (

        'ErrorOnNode', #                    Mark the node in error (and take it away from the resource manager).
        'ErrorAndKillJobOnNode', #          Mark the node in error and kill any jobs running on this node.
        'ErrorAndPwrOffNode', #             Mark the node in error and power off the node.
        'ErrorAndKillJobAndPwrOffNode', #   Mark the node in error and kill any jobs running on this node and power off the node.
        'ErrorAndShutdownNode', #           Mark the node in error and shut down the node.
        'ErrorAndKillJobAndShutdownNode', # Mark the node in error and kill any jobs running on this node and shut down the node.
        'IncreaseFanSpeed', #               Increase the fan speed on the node.
        'KillJobOnNode',  #                 Kill any  jobs running on this node.
        'ErrorAndPowerCycleNode',
        'ErrorAndResetNode',
    )

    catalog = list()
    current_file, current_line, current_line_no = None, None, None

    def _fail_(s):
        fatal('{}\n\t{}\n\tLine: {}\n\tFile: {}'.format(s, current_line, current_line_no, current_file))



    def _handle_attribute_(m, state, name, keywords):

        value = m.group(1)

        if name in state:
            _fail_('Illegal state: "{}" already specified.'.format(name))

        # The optional keywords argument provides an enumeration
        # of legal values.  If it is a dictionary, it also provides
        # a mapping to the externalized attribute value.

        if keywords and not value in keywords:
            _fail_('"{}" is not a legal value for {}.'.format(value, name))

        if keywords and type(keywords) is dict:
            value = keywords[value]

        state[name] = value


    def _handle_define_(m, state, key, na):

        def_name, def_string = m.group(1), m.group(2)

        state[key]  = def_string

        state['Category'] = 'mOS'

        for k in KEYS:
            if not k in state:
                if not k in OPTIONAL_KEYS:
                    _fail_('Missing attribute {} in {}.'.format(k, def_name))
                state[k] = None

        if state['Msg'].endswith('.'):
            state['Msg'] = state['Msg'][0:-1] + ':'

        catalog.append(copy.deepcopy(state))
        state.clear()



    PARSER_INFO = (
        (EVENT_TYPE_EXPR, 'EventType', None, _handle_attribute_),
        (SEVERITY_EXPR, 'Severity', SEVERITIES, _handle_attribute_),
        (COMPONENT_EXPR, 'Component', None, _handle_attribute_),
        (CONTROL_OPERATION_EXPR, 'ControlOperation', CONTROL_OPERATIONS, _handle_attribute_),
        (MSG_EXPR, 'Msg', None, _handle_attribute_),
        (DEFINE_EXPR, 'DescriptiveName', None, _handle_define_),
    )

    event = dict()

    for current_file in args.file:
        with open(current_file) as src:

            current_line_no = 0

            for current_line in src:

                current_line = current_line.rstrip()
                current_line_no += 1

                debug(current_line.rstrip())

                for expr, key, keywords, handler in PARSER_INFO:
                    m = expr.match(current_line)
                    if m:
                        handler(m, event, key, keywords)
                        continue

    print(json.dumps(catalog, sort_keys=True, indent=4))

if __name__ == '__main__':
    main()
