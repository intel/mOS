#!/usr/bin/env python3

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


import sys, re

re_pid = re.compile(r'.*?\(([0-9]+)\):')
re_syscall = re.compile(r':( +)(?:-->|<--).* cpu=([0-9]+)')
re_mos_linux = re.compile(r': *m([<>])L ([{}]) cpu=([0-9]+) nest=([0-9]+)')

def _cpu(cpu, from_cpu, to_cpu):
	if cpu == from_cpu: txt = 'from'
	elif cpu == to_cpu: txt = 'to'
	else: txt = '???'
	return '%d(%s)' % (cpu, txt)

def _pid(line):
	return re_pid.match(line).group(1)

def onepid_motion(subtrace, from_cpu, to_cpu):
	current_cpu = -1
	for line in subtrace:
		m = re_syscall.search(line)
		if m:
			nest, cpu = m.groups()
			nest = len(nest) > 1
			cpu = int(cpu)
			assert any([
				not nest and cpu == from_cpu,
				nest and cpu == current_cpu,
				]), 'syscall: nest=%s cpu=%s\n\t%s' % (
					nest, _cpu(cpu, from_cpu, to_cpu), line)
			continue

		m = re_mos_linux.search(line)
		if m:
			enter, call, cpu, nest = m.groups()
			enter = enter == '>'
			leave = not enter
			call = call == '{'
			ret = not call
			cpu = int(cpu)
			nest = int(nest) > 0
			assert any([
				not nest and enter and call and cpu == from_cpu,
				not nest and enter and ret and cpu == to_cpu,
				not nest and leave and call and cpu == to_cpu,
				not nest and leave and ret and cpu == from_cpu,
				nest and cpu == to_cpu,
				]), 'mos_linux_%s: %s cpu=%s nest=%s\n\t%s' % (
					'enter' if enter else 'leave',
					'call' if call else 'return',
					_cpu(cpu, from_cpu, to_cpu), nest, line)
			current_cpu = cpu
			continue

		assert False, 'no matching regex:\n\t%s' % line

def ruleset_motion(trace, from_cpu, to_cpu):
	from_cpu = int(from_cpu)
	to_cpu = int(to_cpu)

	pids = set(_pid(line) for line in trace)
	for pid in pids:
		subtrace = [line for line in trace if _pid(line) == pid]
		onepid_motion(subtrace, from_cpu, to_cpu)

def ruleset_taskset(trace, before_from, before_to, after_from, after_to):
	# bake in a little knowledge of the test's behavior
	for i in reversed(range(len(trace))):
		if '_wait4]' in trace[i]:
			break
	else:
		assert False, 'could not split trace into before and after taskset'

	# everything before return of wait4, including child /bin/sh and taskset
	ruleset_motion(trace[:i-2], before_from, before_to)
	# call/return of mos_linux_leave during return of wait4
	ruleset_motion(trace[i-2:i], after_from, after_from)
	# return of wait4 and onward
	ruleset_motion(trace[i:], after_from, after_to)

def main(tracefile, ruleset, *args):
	trace = open(tracefile, 'r').read()

	if '=== ERROR' in trace:
		print('%s: trace contains ERROR indicator' % tracefile)
		return 42

	trace = [line for line in trace.splitlines() if ':' in line]
	try:
		eval('ruleset_' + ruleset)(trace, *args)
	except AssertionError as e:
		print('%s: ruleset %s failure: %s' % (tracefile, ruleset, e.message))
		return 1
	except NameError:
		print('%s: invalid ruleset %s' % (tracefile, ruleset))
		return 2

	print('%s: ruleset %s: PASS' % (tracefile, ruleset))
	return 0

if __name__ == '__main__':
	sys.exit(main(*sys.argv[1:]))
