#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The two additions to the policy engine of the Surface Pro 11 stick payload runner's tests that the el2mem and hashbig payloads need
(tools/sp11_payload_testlib.py, tools/sp11_payload_memcheck.py; docs/SP11-PAYLOAD-EL2MEM.md, "The policy engine"): the memory
discipline of the policy keys `read_only` and `bulk_reads`, and the AT S1E2R form of `allow`.

    python3 tools/test-q1n1-sp11-payload-memcheck.py

  * EngineEquivalence: the engine of the base commit d48b0af, frozen verbatim in tools/testdata/sp11-payload-engine-d48b0af.txt (and
    checked against git), against the engine of this tree on the five older payload binaries and a corpus of seeded variants of them,
    under all five older policies: the same sentences, and a policy of the base commit is exactly what it was.
  * MemcheckCases: the checker on synthetic disassembly, more than fifty cases: what a store may go through, what a load may go through,
    spills and reloads of pointers, the slots a store forgets, joins, calls, tail branches, stack-pointer arithmetic, and the policy keys.
  * MemcheckMutants: about thirty seeded bugs in tools/sp11_payload_memcheck.py, each of which the cases must catch (each runs in its
    own process: a checker that hangs is caught too).
  * EngineKeys: the tables are the base commit's plus the additions, the AT encoding space, the keys on real binaries, the command line.

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
from unittest import mock
import concurrent.futures
import json
import re
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_mmu_testkit as kit  # noqa: E402
import sp11_payload_memcheck as memcheck  # noqa: E402
import sp11_payload_testlib as lib  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-memcheck-test'
MODULE = ROOT / 'tools' / 'sp11_payload_memcheck.py'
FROZEN = ROOT / 'tools' / 'testdata' / 'sp11-payload-engine-d48b0af.txt'
BASE_COMMIT = 'd48b0af'
READELF = kit.READELF
run = lib.run
OLDER = ('psci', 'state', 'timer', 'usbsmmu', 'cpuon')


# ---- synthetic disassembly ---------------------------------------------------------------------------------------------------

def listing(**bodies):
    """llvm-objdump -d text for synthetic functions, in the order given: function number k starts at 0x1000 * k, every instruction
    takes four bytes, `name:` defines a label, and `@name` in an operand is the address of the label or function `name`."""
    labels, rows, starts = {}, [], {}
    for number, (name, body) in enumerate(bodies.items(), 1):
        address = 0x1000 * number
        starts[name] = address
        for item in body:
            if item.endswith(':'):
                labels[item[:-1]] = address
            else:
                rows.append((name, address, item))
                address += 4
    labels.update(starts)
    lines, current = [], None
    for name, address, item in rows:
        if name != current:
            lines += ['', f'{starts[name]:016x} <{name}>:']
            current = name
        item = re.sub(r'@(\w+)', lambda found: f'{labels[found.group(1)]:#x} <{found.group(1)}>', item)
        lines.append(f'    {address:x}: {item}')
    return '\n'.join(lines) + '\n'


RO = {'read_only': True}
BULK = {'read_only': True, 'bulk_reads': True}
MANY_STORES = ['str w1, [x0]'] * 15 + ['ret']

# (name, policy, the sentences expected, in order, each as a fragment it must contain, and no others, the functions)
CASES = [
    # -- what a store may go through: the stack, and a pointer above the frame
    ('a-store-through-sp', RO, [], dict(_start=['sub sp, sp, #32', 'str w1, [sp, #8]', 'str x2, [sp, #16]', 'add sp, sp, #32', 'ret'])),
    ('a-store-through-sp-and-a-register-offset', RO, [], dict(_start=['str w1, [sp, x2]', 'ret'])),
    ('a-store-through-the-arguments', RO, ['a store in _start at 0x1000'], dict(_start=['str w1, [x0, #4]', 'ret'])),
    ('a-store-through-the-arguments-and-a-register-offset', RO, ['a store in _start at 0x1000'], dict(_start=['str w1, [x0, x2]', 'ret'])),
    ('a-store-through-a-pointer-the-arguments-hold', RO, ['a store in _start at 0x1004'],
     dict(_start=['ldr x1, [x0, #8]', 'str w2, [x1]', 'ret'])),
    ('a-store-through-the-image', RO, ['a store in _start at 0x1008'],
     dict(_start=['adrp x1, 0x9000 <table>', 'ldr w2, [x1, #8]', 'str w2, [x1, #8]', 'ret'])),
    ('a-store-through-a-mov-of-sp', RO, [], dict(_start=['mov x1, sp', 'str w2, [x1]', 'ret'])),
    ('a-store-through-sp-plus-a-register', RO, [], dict(_start=['add x1, sp, x2', 'str w3, [x1]', 'ret'])),
    ('a-store-through-sp-plus-the-arguments-is-nothing', RO, ['a store in _start at 0x1004'],
     dict(_start=['add x1, sp, x0', 'str w2, [x1]', 'ret'])),
    ('a-store-through-a-register-written-as-w-is-nothing', RO, ['a store in _start at 0x1004'],
     dict(_start=['mov w0, wzr', 'str w1, [x0]', 'ret'])),
    ('a-store-through-an-orred-pointer-is-nothing', RO, ['a store in _start at 0x1008'],
     dict(_start=['add x1, sp, #0', 'orr x1, x1, #0x8', 'str w2, [x1]', 'ret'])),
    ('a-store-through-a-madd-of-a-stack-addend', RO, [], dict(_start=['add x4, sp, #0', 'madd x1, x2, x3, x4', 'str w5, [x1]', 'ret'])),
    ('a-store-through-a-madd-of-an-unknown-addend', RO, ['a store in _start at 0x1004'],
     dict(_start=['madd x1, x2, x3, x4', 'str w5, [x1]', 'ret'])),
    ('a-store-through-a-csel-of-two-stack-pointers', RO, [],
     dict(_start=['add x1, sp, #0', 'add x2, sp, #8', 'csel x3, x1, x2, eq', 'str w4, [x3]', 'ret'])),
    ('a-store-through-a-csel-with-an-unknown-operand', RO, ['a store in _start at 0x1008'],
     dict(_start=['add x1, sp, #0', 'csel x3, x1, x2, eq', 'str w4, [x3]', 'ret'])),
    ('the-bulk-key-never-allows-a-store', BULK, ['a store in _start at 0x1000'], dict(_start=['str w1, [x0, #4]', 'ret'])),
    # -- what a load may go through
    ('a-load-through-a-pointer-the-arguments-hold', RO, [], dict(_start=['ldr x1, [x0, #8]', 'ldr w2, [x1, #4]', 'ret'])),
    ('a-load-through-a-pointer-loaded-through-a-pointer', RO, ['a load in _start at 0x1008'],
     dict(_start=['ldr x1, [x0, #8]', 'ldr x2, [x1]', 'ldr w3, [x2]', 'ret'])),
    ('the-same-load-with-bulk-reads', BULK, [], dict(_start=['ldr x1, [x0, #8]', 'ldr x2, [x1]', 'ldr w3, [x2]', 'ret'])),
    ('a-literal-load-is-an-image-load', RO, ['a load in _start at 0x1004'],
     dict(_start=['ldr x1, @lit', 'ldr w2, [x1]', 'ret', 'lit:'])),
    ('a-load-through-a-register-offset', RO, [], dict(_start=['ldr w1, [x0, x2]', 'ret'])),
    ('a-load-through-the-image', RO, [], dict(_start=['adrp x1, 0x9000 <table>', 'ldr w2, [x1, #8]', 'ret'])),
    # -- spills and reloads of pointers, and the slots a store forgets
    ('a-stack-pointer-spilled-and-reloaded-stays-the-stack', RO, [],
     dict(_start=['sub sp, sp, #48', 'add x1, sp, #16', 'str x1, [sp, #8]', 'mov x1, xzr', 'ldr x2, [sp, #8]', 'str w3, [x2]',
                  'add sp, sp, #48', 'ret'])),
    ('an-unknown-value-spilled-and-reloaded-is-unknown', RO, ['a store in _start at 0x100c'],
     dict(_start=['sub sp, sp, #48', 'str x4, [sp, #8]', 'ldr x2, [sp, #8]', 'str w3, [x2]', 'add sp, sp, #48', 'ret'])),
    ('a-byte-store-over-a-spilled-pointer-forgets-it', RO, ['a store in _start at 0x1014'],
     dict(_start=['sub sp, sp, #48', 'add x1, sp, #16', 'str x1, [sp, #8]', 'strb wzr, [sp, #10]', 'ldr x2, [sp, #8]', 'str w3, [x2]',
                  'add sp, sp, #48', 'ret'])),
    ('a-store-through-a-stack-pointer-of-unknown-offset-forgets-every-slot', RO, ['a store in _start at 0x1018'],
     dict(_start=['sub sp, sp, #48', 'add x1, sp, #16', 'str x1, [sp, #8]', 'add x5, sp, x6', 'str wzr, [x5]', 'ldr x2, [sp, #8]',
                  'str w3, [x2]', 'ret'])),
    ('a-store-at-a-register-offset-from-sp-forgets-every-slot', RO, ['a store in _start at 0x1014'],
     dict(_start=['sub sp, sp, #48', 'add x1, sp, #16', 'str x1, [sp, #8]', 'str wzr, [sp, x6]', 'ldr x2, [sp, #8]', 'str w3, [x2]',
                  'ret'])),
    ('a-store-through-a-pointer-above-the-frame-keeps-the-slots', RO, [],
     dict(_start=['sub sp, sp, #32', 'add x0, sp, #0', 'bl @f', 'ret'],
          f=['sub sp, sp, #32', 'add x1, sp, #16', 'str x1, [sp, #8]', 'str wzr, [x0]', 'ldr x2, [sp, #8]', 'str w3, [x2]',
             'add sp, sp, #32', 'ret'])),
    ('pre-index-and-post-index-find-the-slot', RO, [],
     dict(_start=['add x1, sp, #0', 'str x1, [sp, #-16]!', 'ldr x2, [sp], #16', 'str w3, [x2]', 'ret'])),
    ('a-post-index-load-moves-sp', RO, [],
     dict(_start=['sub sp, sp, #16', 'add x1, sp, #0', 'str x1, [sp, #8]', 'ldr x2, [sp], #8', 'ldr x3, [sp]', 'str w4, [x3]', 'ret'])),
    ('a-pair-is-stored-and-loaded-as-two-slots', RO, [],
     dict(_start=['add x1, sp, #0', 'add x2, sp, #8', 'stp x1, x2, [sp, #-32]', 'ldp x4, x5, [sp, #-32]', 'str w6, [x4]', 'str w6, [x5]',
                  'ret'])),
    ('an-unscaled-store-and-load-find-the-slot', RO, [],
     dict(_start=['add x1, sp, #0', 'stur x1, [sp, #-8]', 'ldur x2, [sp, #-8]', 'str w3, [x2]', 'ret'])),
    ('sp-moves-down-and-up-and-the-slot-is-found', RO, [],
     dict(_start=['sub sp, sp, #16', 'add x1, sp, #0', 'str x1, [sp, #8]', 'add sp, sp, #16', 'sub sp, sp, #16', 'ldr x2, [sp, #8]',
                  'str w3, [x2]', 'add sp, sp, #16', 'ret'])),
    ('a-shifted-immediate-is-shifted', RO, [],
     dict(_start=['sub sp, sp, #1, lsl #12', 'add x1, sp, #0', 'str x1, [sp, #8]', 'add sp, sp, #4096', 'sub sp, sp, #1, lsl #12',
                  'ldr x2, [sp, #8]', 'str w3, [x2]', 'add sp, sp, #1, lsl #12', 'ret'])),
    # -- joins
    ('a-join-of-a-stack-pointer-and-an-image-pointer-is-readable-not-writable', RO, ['a store in _start at 0x1014'],
     dict(_start=['cbz x1, @other', 'add x2, sp, #0', 'b @join', 'other:', 'adrp x2, 0x9000 <table>', 'join:', 'ldr w3, [x2]',
                  'str w3, [x2]', 'ret'])),
    ('a-join-with-an-unknown-value-is-unknown', RO, ['a store in _start at 0x100c', 'a load in _start at 0x1008'],
     dict(_start=['cbz x1, @join', 'add x2, sp, #0', 'join:', 'ldr w3, [x2]', 'str w3, [x2]', 'ret'])),
    ('the-same-join-with-bulk-reads-refuses-only-the-store', BULK, ['a store in _start at 0x100c'],
     dict(_start=['cbz x1, @join', 'add x2, sp, #0', 'join:', 'ldr w3, [x2]', 'str w3, [x2]', 'ret'])),
    ('a-join-of-two-stack-offsets-is-the-stack', RO, [],
     dict(_start=['cbz x1, @other', 'add x2, sp, #8', 'b @join', 'other:', 'add x2, sp, #16', 'join:', 'str w3, [x2]', 'ret'])),
    ('a-join-of-a-pointer-above-the-frame-and-the-stack-is-the-stack', RO, [],
     dict(_start=['sub sp, sp, #16', 'add x0, sp, #0', 'bl @f', 'ret'],
          f=['cbz x1, @a', 'add x2, sp, #0', 'b @j', 'a:', 'mov x2, x0', 'j:', 'str w3, [x2]', 'ret'])),
    ('a-loop-that-moves-a-stack-pointer-converges', RO, [],
     dict(_start=['add x1, sp, #0', 'loop:', 'str wzr, [x1]', 'add x1, x1, #4', 'cmp x1, x3', 'b.ne @loop', 'ret'])),
    ('code-nothing-reaches-is-not-analysed', RO, [], dict(_start=['b @end', 'str w1, [x0]', 'end:', 'ret'])),
    # -- calls and branches
    ('a-callee-is-given-the-arguments-pointer-it-was-called-with', RO, ['a store in f at 0x2000'],
     dict(_start=['bl @f', 'ret'], f=['str w1, [x0]', 'ret'])),
    ('a-call-clobbers-the-caller-saved-registers', RO, ['a store in _start at 0x1008'],
     dict(_start=['add x1, sp, #0', 'bl @f', 'str w2, [x1]', 'ret'], f=['ret'])),
    ('a-call-leaves-the-callee-saved-registers', RO, [],
     dict(_start=['add x19, sp, #0', 'bl @f', 'str w2, [x19]', 'ret'], f=['ret'])),
    ('an-indirect-call-clobbers-the-caller-saved-registers', RO, ['a store in _start at 0x1008'],
     dict(_start=['add x1, sp, #0', 'blr x8', 'str w2, [x1]', 'ret'])),
    ('a-callee-saved-stack-pointer-reaches-the-callee', RO, [],
     dict(_start=['sub sp, sp, #16', 'add x19, sp, #0', 'bl @f', 'ret'], f=['str w1, [x19]', 'ret'])),
    ('a-tail-branch-passes-the-argument-registers', RO, [],
     dict(_start=['add x1, sp, #0', 'b @f'], f=['str w2, [x1]', 'ret'])),
    ('a-tail-branch-does-not-pass-a-scratch-register', RO, ['a store in f at 0x2000'],
     dict(_start=['add x9, sp, #0', 'b @f'], f=['str w2, [x9]', 'ret'])),
    ('a-function-nothing-calls-is-checked-with-nothing-known', RO, ['a store in dead at 0x2000'],
     dict(_start=['ret'], dead=['str w1, [x0]', 'ret'])),
    ('an-indirect-branch-is-refused', RO, ['an indirect branch (br) in _start at 0x1000'], dict(_start=['br x1'])),
    ('a-branch-into-the-middle-of-a-function-is-refused', RO, ['a branch in _start at 0x1000 to 0x2004'],
     dict(_start=['bl @mid', 'ret'], f=['nop', 'mid:', 'nop', 'ret'])),
    # -- sp
    ('sp-set-from-something-that-is-not-the-stack-is-refused', RO, ['sp is set in _start at 0x1000'], dict(_start=['mov sp, x1', 'ret'])),
    ('sp-set-from-a-frame-pointer-is-fine', RO, [], dict(_start=['add x29, sp, #0', 'mov sp, x29', 'ret'])),
    # -- the policy keys, and the report
    ('without-the-keys-nothing-is-analysed', {}, [], dict(_start=['str w1, [x0]', 'br x1'])),
    ('bulk-reads-without-read-only-is-a-policy-error', {'bulk_reads': True}, ['the policy has bulk_reads without read_only'],
     dict(_start=['ret'])),
    ('a-disassembly-without-start-says-so', RO, ['the disassembly has no _start'], dict(main=['ret'])),
    ('more-than-twelve-sentences-are-cut-and-counted', RO,
     [f'a store in _start at {0x1000 + 4 * i:#x}' for i in range(12)] + ['3 more'], dict(_start=MANY_STORES)),
]


def judge(module, name, policy, expect, bodies):
    """(whether `module` answers the case as expected, what it answered)."""
    found = module.memory_violations(listing(**bodies), policy)
    return len(found) == len(expect) and all(want in sentence for want, sentence in zip(expect, found)), found


def evaluate(module):
    """The names of the cases `module` (the checker, or a copy of it with a bug) answers wrongly."""
    return [case[0] for case in CASES if not judge(module, *case)[0]]


class MemcheckCases(unittest.TestCase):
    def test_there_are_more_than_fifty_cases_with_distinct_names(self):
        names = [case[0] for case in CASES]
        self.assertEqual(len(set(names)), len(names))
        self.assertGreaterEqual(len(names), 50)

    def test_the_checker_answers_every_case_as_expected(self):
        for name, policy, expect, bodies in CASES:
            with self.subTest(case=name):
                ok, found = judge(memcheck, name, policy, expect, bodies)
                self.assertTrue(ok, f'expected {expect}, found {found}')

    def test_loads_and_stores_are_reported_with_the_function_the_address_the_base_and_its_class(self):
        problems, loads, stores = memcheck.analyse(listing(
            _start=['sub sp, sp, #16', 'str w1, [sp, #8]', 'ldr x2, [x0, #8]', 'ldr w3, [x2]', 'ret']))
        self.assertEqual(problems, [])
        self.assertEqual([(s[0], s[1], s[2], s[4], s[5]) for s in stores], [('_start', 0x1004, 'str', 'sp', memcheck.STACK)])
        self.assertEqual([(l[0], l[1], l[4], l[5]) for l in loads],
                         [('_start', 0x1008, 'x0', memcheck.ARGS), ('_start', 0x100c, 'x2', memcheck.ARGS1)])

    def test_the_command_line_summarises_a_binary(self):
        out = BUILD / 'cli'
        done, elf, _ = lib.build_payload(ROOT / 'payloads' / 'state.c', out, name='state', check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        shown = run([sys.executable, '-B', str(MODULE), '--objdump', 'llvm-objdump', str(elf)])
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertRegex(shown.stdout, r'^\d+ loads, \d+ stores, 0 problems\n')
        self.assertEqual(run([sys.executable, '-B', str(MODULE)]).returncode, 2)


# The seeded bugs of the checker: (name, text it holds exactly once, what it says instead).
MUTANTS = [
    ('a-pointer-above-the-frame-is-not-the-stack', 'STACKISH = {STACK, CALLER}', 'STACKISH = {STACK}'),
    ('a-pointer-read-from-the-arguments-is-not-a-pointer', 'POINTERS = {STACK, CALLER, IMAGE, READABLE, ARGS, ARGS1}',
     'POINTERS = {STACK, CALLER, IMAGE, READABLE, ARGS}'),
    ('a-join-with-anything-is-readable', '    return READABLE if {ca, cb} <= POINTERS else OTHER', '    return READABLE'),
    ('a-join-of-stack-and-above-the-frame-is-readable', '    if {ca, cb} <= STACKISH:\n        return STACK\n', '    if False:\n        return STACK\n'),
    ('a-store-through-an-unknown-offset-keeps-the-slots', '            new.slots.clear()\n', '            pass\n'),
    ('a-narrow-store-keeps-the-slot-it-overlaps',
     '            for key in [k for k in new.slots if k < address + total and k + 8 > address]:\n                del new.slots[key]\n',
     '            for key in []:\n                del new.slots[key]\n'),
    ('a-callee-is-given-the-callers-stack-pointer-as-its-own', '        regs[index] = CALLER if value in STACKISH else value',
     '        regs[index] = value'),
    ('a-call-clobbers-nothing', '    for index in CALL_CLOBBERED:\n        new.regs[index] = OTHER\n',
     '    for index in []:\n        new.regs[index] = OTHER\n'),
    ('no-register-is-callee-saved', 'CALLEE_SAVED = list(range(19, 30))', 'CALLEE_SAVED = []'),
    ('a-load-through-the-arguments-gives-an-unknown-value', '            elif base_class == ARGS:\n                value = ARGS1\n',
     '            elif base_class == ARGS:\n                value = OTHER\n'),
    ('an-indirect-branch-is-allowed', "            if mnemonic == 'br':", '            if False:'),
    ('a-branch-into-the-middle-of-a-function-is-allowed',
     '            elif direct and not (target is not None and start <= target < end) and target not in by_start:', '            elif False:'),
    ('sp-may-be-set-from-anything', "                if operands[0] != 'sp' or not (from_sp or from_stack):", '                if False:'),
    ('madd-is-always-the-stack', '            result = cls(get(old, operands[3])) if cls(get(old, operands[3])) in POINTERS else OTHER',
     '            result = STACK'),
    ('csel-is-its-first-operand', '            result = join_value(first, second) if cls(first) in POINTERS and cls(second) in POINTERS else OTHER',
     '            result = first'),
    ('a-pointer-plus-anything-is-the-pointer',
     '                if cls(first) in POINTERS and cls(second) not in POINTERS:\n                    result = cls(first)\n'
     "                elif cls(second) in POINTERS and cls(first) not in POINTERS and mnemonic.startswith('add'):\n"
     '                    result = cls(second)\n',
     '                if cls(first) in POINTERS:\n                    result = cls(first)\n'),
    ('sub-of-sp-adds', "                value = offset_value(source, delta if mnemonic == 'add' else -delta) if delta is not None else cls(source)",
     '                value = offset_value(source, delta) if delta is not None else cls(source)'),
    ('a-pre-index-does-not-move-the-base', '        put(state, base, offset_value(get(old, base), offset or 0))', '        pass'),
    ('a-post-index-load-does-not-move-the-base', '    if memory[3] or memory[4] is not None or memory[5]:\n        write_back(new, memory, old)\n',
     '    pass\n'),
    ('a-pair-stores-both-registers-in-the-second-slot', '                        new.slots[address + 8 * position] = get(old, name)',
     '                        new.slots[address + 8] = get(old, name)'),
    ('a-pair-load-writes-one-register', "    return operands[:2] if mnemonic in ('ldp', 'ldpsw', 'ldnp') else operands[:1]", '    return operands[:1]'),
    ('bulk-reads-without-read-only-is-fine', "    if policy.get('bulk_reads') and not policy.get('read_only'):", '    if False:'),
    ('bulk-reads-do-not-allow-loads', "    if not policy.get('bulk_reads'):\n        for name, address, mnemonic, operands, base, klass in loads:",
     "    if True:\n        for name, address, mnemonic, operands, base, klass in loads:"),
    ('the-report-is-not-cut', 'MESSAGES_MAX = 12', 'MESSAGES_MAX = 100'),
    ('a-function-nothing-calls-is-not-analysed', '        unreached = [name for _, name in ordered if name not in entries]', '        unreached = []'),
    ('a-literal-load-is-an-unknown-load', '                              cls(get(state, memory[1])) if memory else IMAGE))',
     '                              cls(get(state, memory[1])) if memory else OTHER))'),
    ('an-unconditional-branch-falls-through', "        fall, flows = mnemonic not in ('ret', 'br', 'b'), []", "        fall, flows = mnemonic not in ('ret', 'br'), []"),
    ('a-shift-is-ignored', '            value = value << int(match.group(1)) if match else None', '            value = value if match else None'),
    ('a-tail-branch-is-not-a-call',
     "        if (mnemonic == 'bl' or (branch and not inside)) and target in by_start:", "        if mnemonic == 'bl' and target in by_start:"),
    ('an-indirect-call-clobbers-nothing', "        after = after_call(state) if mnemonic in ('bl', 'blr', 'smc') else transfer(state, mnemonic, operands)",
     "        after = after_call(state) if mnemonic in ('bl', 'smc') else transfer(state, mnemonic, operands)"),
    ('a-register-offset-is-an-immediate-of-zero', "        offset = 0 if second is None else immediate(second)",
     "        offset = 0 if second is None or not second.startswith('#') else immediate(second)"),
]


def evaluate_in_a_process(path):
    done = subprocess.run([sys.executable, '-B', __file__, '--evaluate', str(path)], capture_output=True, text=True, timeout=90)
    if done.returncode:
        return 'caught', f'it crashes: {done.stderr.strip().splitlines()[-1:]}'
    return ('caught' if json.loads(done.stdout) else 'survived'), json.loads(done.stdout)


class MemcheckMutants(unittest.TestCase):
    def test_the_unmutated_copy_answers_every_case_and_the_evaluator_works_in_its_own_process(self):
        out = BUILD / 'mutants'
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        (out / 'control.py').write_text(MODULE.read_text(encoding='utf-8'), encoding='utf-8')
        done = subprocess.run([sys.executable, '-B', __file__, '--evaluate', str(out / 'control.py')], capture_output=True, text=True,
                              timeout=90)
        self.assertEqual((done.returncode, json.loads(done.stdout)), (0, []), done.stderr)

    def test_there_are_enough_distinct_seeded_bugs_each_in_the_text_exactly_once(self):
        text = MODULE.read_text(encoding='utf-8')
        names = [name for name, _, _ in MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertGreaterEqual(len(names), 30)
        for name, needle, replacement in MUTANTS:
            self.assertEqual(text.count(needle), 1, f'{name}: {needle[:70]!r}')
            self.assertNotEqual(needle, replacement, name)

    def test_every_seeded_bug_of_the_checker_is_caught_by_some_case(self):
        text = MODULE.read_text(encoding='utf-8')
        out = BUILD / 'mutants'
        out.mkdir(parents=True, exist_ok=True)

        def one(item):
            name, needle, replacement = item
            path = out / f'{name}.py'
            path.write_text(text.replace(needle, replacement, 1), encoding='utf-8')
            try:
                return name, *evaluate_in_a_process(path)
            except subprocess.TimeoutExpired:
                return name, 'caught', 'it hangs'
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(one, MUTANTS))
        for name, status, detail in results:
            with self.subTest(mutant=name):
                self.assertEqual(status, 'caught', f'{status}: {detail}')


# ---- the engine against the frozen engine of the base commit ----------------------------------------------------------------

ANCHOR = 'payload_entry(const struct q1n1_payload_args *a)\n{\n'
FORMS = {
    'clean': '', 'msr-vbar-el2': 'msr vbar_el2, x0', 'msr-daifset': 'msr daifset, #15', 'dc-civac': 'dc civac, x0', 'dc-cvac': 'dc cvac, x0',
    'wfe': 'wfe', 'sev': 'sev', 'isb': 'isb', 'dsb': 'dsb sy', 'hvc': 'hvc #0', 'smc': 'smc #0', 'eret': 'eret', 'tlbi': 'tlbi alle2',
    'at-s1e2r': 'at s1e2r, x0', 'at-s1e2w': 'at s1e2w, x0', 'ldxr': 'ldxr x9, [sp]', 'word': '.inst 0xffffffff',
}
READS = {'mrs-cntvoff': 'S3_4_C14_C0_3', 'mrs-cntpoff': 'S3_4_C14_C0_6', 'mrs-midr': 'midr_el1', 'mrs-par': 'par_el1',
         'mrs-dfr1': 'id_aa64dfr1_el1', 'mrs-isar2': 'id_aa64isar2_el1', 'mrs-pfr2': 'id_aa64pfr2_el1'}
# The three registers the engine now spells by encoding: the base engine says their name where this one says s3_0_c0_cN_M, in the one
# sentence that lists the registers read. The verdict is the same, and so is every other sentence.
SPELLED = {'mrs-dfr1', 'mrs-isar2', 'mrs-pfr2'}
# The ALLOW_WORDS rows the later payloads (cnthctl, el1trap) add: exact forms of the instructions they alone may hold.
TIMER_ALLOW_WORDS = {('eret', ''), ('hvc', '#0'), ('hvc', '#0x1'), ('hvc', '#0x2'), ('ic', 'ivau'), ('msr', 'cnthctl_el2'),
                     ('msr', 'elr_el2'), ('msr', 'hcr_el2'), ('msr', 'sctlr_el1'), ('msr', 'spsr_el2'), ('msr', 'vbar_el1')}
NEW_TABLE_ENTRIES = {'ALLOW_WORDS': {('at', 's1e2r'), ('at', 's1e2w'), ('dc', 'cvac')} | TIMER_ALLOW_WORDS,      # the two retprobe adds: a write translation and a clean
                     'SYSTEM_REGISTER_ALIASES': {'id_aa64dfr1_el1', 'id_aa64isar2_el1', 'id_aa64pfr2_el1'}}


def asm(text, clobbers='"memory"'):
    return [(ANCHOR, ANCHOR + (f'    __asm__ volatile("{text}" ::: {clobbers});\n' if text else ''))]


def frozen_engine():
    """The base commit's tables and binary_violations, executed with the names of the library it takes from outside itself."""
    namespace = {name: getattr(lib, name) for name in ('Counter', 'Path', 're', 'struct', 'run', 'CNTVOFF_EL2', 'CNTPOFF_EL2',
                                                       'smc_function_ids')}
    exec(FROZEN.read_text(encoding='utf-8'), namespace)
    return namespace


def base_file():
    shown = subprocess.run(['git', 'show', f'{BASE_COMMIT}:tools/sp11_payload_testlib.py'], cwd=ROOT, capture_output=True, text=True)
    if shown.returncode:
        raise unittest.SkipTest(f'the base commit {BASE_COMMIT} is not in this repository: {shown.stderr.strip()[:80]}')
    return shown.stdout


class EngineEquivalence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kit.need_tools(cls)
        cls.old = staticmethod(frozen_engine()['binary_violations'])
        shutil.rmtree(BUILD / 'corpus', ignore_errors=True)
        cls.builder = kit.Builder(BUILD / 'corpus')
        jobs = [(p, n, asm(t)) for p in OLDER for n, t in FORMS.items()]
        jobs += [(p, n, asm(f'mrs x0, {r}', '"x0", "memory"')) for p in OLDER for n, r in READS.items()]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            cls.corpus = list(pool.map(lambda job: (job[0], job[1], cls.builder.build(job[0], f'{job[0]}-{job[1]}', job[2])), jobs))
        for payload, name, (done, _, _) in cls.corpus:
            if done.returncode:
                raise RuntimeError(f'{payload}-{name} did not build: {done.stderr[-600:]}')

    def test_the_frozen_engine_is_the_one_of_the_base_commit(self):
        old = re.search(r'^# Mnemonics no payload has a use for.*?(?=^_DIRECT_BRANCH = )', base_file(), re.M | re.S).group(0)
        frozen = FROZEN.read_text(encoding='utf-8')
        self.assertEqual(old.rstrip(), frozen[frozen.index('# Mnemonics no payload has a use for'):].rstrip())

    def test_the_new_engine_answers_exactly_as_the_frozen_one_on_every_binary_under_every_older_policy(self):
        self.assertEqual(len(self.corpus), len(OLDER) * (len(FORMS) + len(READS)))

        def compare(item):
            payload, name, (_, elf, flat) = item
            return [(payload, name, policy, self.old(elf, flat, lib.POLICIES[policy], READELF()),
                     lib.binary_violations(elf, flat, lib.POLICIES[policy], READELF())) for policy in OLDER]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            rows = [row for rows in pool.map(compare, self.corpus) for row in rows]
        kinds = set()
        for payload, name, policy, old, new in rows:
            with self.subTest(binary=f'{payload}-{name}', policy=policy):
                if name in SPELLED:
                    self.assertTrue(old and new)
                    self.assertEqual([s for s in old if not s.startswith('registers read')],
                                     [s for s in new if not s.startswith('registers read')])
                else:
                    self.assertEqual(old, new)
            kinds |= {re.sub(r'[ 0-9\[].*', '', sentence) for sentence in old}
        self.assertLessEqual({'forbidden', 'a', 'exclusive', 'the', 'registers'}, kinds, 'the corpus must exercise the refusals')
        self.assertEqual(sum(1 for *_, old, new in rows if not old), sum(1 for *_, old, new in rows if not new))
        self.assertGreaterEqual(sum(1 for *_, old, new in rows if not new), len(OLDER), 'each older payload passes its own policy')

    def test_the_new_policies_pass_the_new_engine_and_the_old_engine_cannot_know_the_at_form(self):
        out = BUILD / 'new'
        for name in ('el2mem', 'hashbig'):
            with self.subTest(payload=name):
                done, elf, flat = lib.build_payload(ROOT / 'payloads' / f'{name}.c', out, name=name, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(lib.binary_violations(elf, flat, lib.POLICIES[name], READELF()), [])
                old = self.old(elf, flat, lib.POLICIES[name], READELF())
                self.assertIn('no encoding is known for the allowed form at s1e2r', old)
                if name == 'el2mem':
                    self.assertTrue(any(s.startswith('registers read') for s in old), 'and it spells three registers another way')

    def test_the_memory_hook_costs_an_older_policy_nothing(self):
        for payload, name, (_, elf, flat) in self.corpus:
            if name != 'clean':
                continue
            with self.subTest(payload=payload), mock.patch.object(lib, '_memcheck', side_effect=AssertionError('imported')):
                self.assertEqual(lib.binary_violations(elf, flat, lib.POLICIES[payload], READELF()), [])


class EngineKeys(unittest.TestCase):
    def test_the_older_policies_are_the_base_commits(self):
        text = base_file()
        base = {}
        exec(text[text.index('STATE_REGISTERS = {'):text.index('# Mnemonics no payload has a use for')], base)
        self.assertEqual(set(base['POLICIES']), set(OLDER))
        for name in OLDER:
            with self.subTest(policy=name):
                self.assertEqual(lib.POLICIES[name], base['POLICIES'][name])
                self.assertFalse({'read_only', 'bulk_reads'} & set(lib.POLICIES[name]))

    def test_every_table_is_the_base_commits_plus_the_additions_and_nothing_else(self):
        old = frozen_engine()
        for name in ('FORBIDDEN', 'TIMER_OFFSETS', 'FORBIDDEN_WORDS', 'BARRIER_WORDS', 'OFFSET_NAMES'):
            self.assertEqual(getattr(lib, name), old[name], name)
        for name in ('EXCLUSIVE', 'ATOMIC'):
            self.assertEqual(getattr(lib, name).pattern, old[name].pattern, name)
        for name, added in NEW_TABLE_ENTRIES.items():
            now = getattr(lib, name)
            self.assertEqual(set(now) - set(old[name]), added, name)
            self.assertEqual({key: now[key] for key in old[name]}, old[name], f'{name}: an old entry changed')

    def test_the_new_policies_name_the_memory_keys(self):
        self.assertTrue(lib.POLICIES['el2mem']['read_only'])
        self.assertNotIn('bulk_reads', lib.POLICIES['el2mem'], 'only hashbig reads a file in place')
        self.assertTrue(lib.POLICIES['hashbig']['read_only'] and lib.POLICIES['hashbig']['bulk_reads'])
        for name in ('el2mem', 'hashbig'):
            self.assertEqual(lib.POLICIES[name]['allow'], {'at': {'s1e2r'}})
            self.assertEqual(lib.POLICIES[name]['smc'], 0)
            self.assertLessEqual({'dsb', 'dmb', 'sev', 'sevl', 'sb'}, lib.POLICIES[name]['forbid'])
            self.assertNotIn('isb', lib.POLICIES[name]['forbid'], 'the ISB after the AT is required')

    def test_of_the_whole_at_encoding_space_only_s1e2r_is_allowed_and_for_every_register(self):
        what, mask, value = lib.ALLOW_WORDS[('at', 's1e2r')]
        self.assertEqual(what, 'sys')
        forms = {}
        for op1 in range(8):
            for op2 in range(8):
                forms[(op1, op2)] = [0xd5080000 | op1 << 16 | 7 << 12 | 8 << 8 | op2 << 5 | rt for rt in range(32)]
        allowed = {key for key, words in forms.items() if any(w & mask == value for w in words)}
        self.assertEqual(allowed, {(4, 0)}, 'AT S1E2R is SYS #4, C7, C8, #0')
        self.assertTrue(all(w & mask == value for w in forms[(4, 0)]), 'every Xt, XZR included')
        self.assertTrue(all(w & lib.FORBIDDEN_WORDS['sys'][0] == lib.FORBIDDEN_WORDS['sys'][1] for words in forms.values() for w in words),
                        'every AT is in the class the engine refuses unless the form is allowed')
        self.assertEqual(sum(1 for w in range(0xd50c7800, 0xd50c7820) if w & mask == value), 32)

    def test_a_policy_with_bulk_reads_and_no_read_only_is_refused_by_the_engine_itself(self):
        out = BUILD / 'keys'
        done, elf, flat = lib.build_payload(ROOT / 'payloads' / 'state.c', out, name='state', check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(lib.binary_violations(elf, flat, lib.POLICIES['state'], READELF()), [])
        refused = lib.binary_violations(elf, flat, dict(lib.POLICIES['state'], bulk_reads=True), READELF())
        self.assertEqual(refused[0], 'the policy has bulk_reads without read_only')
        read_only = lib.binary_violations(elf, flat, dict(lib.POLICIES['state'], read_only=True), READELF())
        self.assertEqual(read_only, [], 'the state payload reads and writes only through the stack and what it is given')

    def test_the_spelling_of_the_three_id_registers_is_the_architectures(self):
        self.assertEqual({lib.SYSTEM_REGISTER_ALIASES[name] for name in NEW_TABLE_ENTRIES['SYSTEM_REGISTER_ALIASES']},
                         {'s3_0_c0_c5_1', 's3_0_c0_c6_2', 's3_0_c0_c4_2'})
        for name, encoding in (('id_aa64dfr1_el1', (3, 0, 0, 5, 1)), ('id_aa64isar2_el1', (3, 0, 0, 6, 2)), ('id_aa64pfr2_el1', (3, 0, 0, 4, 2))):
            self.assertEqual(lib.SYSTEM_REGISTER_ALIASES[name], 's%d_%d_c%d_c%d_%d' % encoding, name)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--evaluate']:
        print(json.dumps(evaluate(kit.load_module('memcheck_under_test', sys.argv[2]))))
        sys.exit(0)
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
