#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The timer payload of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-TIMER.md, with the pointers to it in
docs/SP11-PAYLOAD.md): its host test, its seeded bugs, the allow-list of its binary, the order the compiler gave it, the
manifest chain that carries it, and the documents' agreement with the source and with each other.

    python3 tools/test-q1n1-sp11-payload-timer.py

  * TimerNative: tools/test-q1n1-sp11-payload-timer.c (the exact reads and lines against a scripted register file and
    counter: every NEXT line before its read, the hazards last, CNTPOFF_EL2 only when ECV >= 2 and only at the very end,
    nothing when not at EL2, the bounded poll, the bracket in modular arithmetic, hostile registers, the line budget of
    the chain), built and run by the machinery of tools/test-q1n1-sp11-payload.py.
  * TimerMutants: seeded bugs in timer.c, each applied to a copy of the sources, each of which that program must reject.
  * TimerBinary: the allow-list of tools/sp11_payload_testlib.py applied to timer.bin (MRS of the twelve documented
    registers and nothing else, no barrier, each timer offset read exactly once) and to the other two payloads (which
    must be refused if they name CNTVOFF_EL2 or CNTPOFF_EL2); timer built with one forbidden thing added, each named
    by the check; the compiled order (the hazards the last two reads, each right after the call that prints its NEXT
    line) and builds that break it.
  * TimerChain: the manifest tool and the runner's own validator on the chain `state.bin psci.bin timer.bin`, three of
    the five files, in that order.
  * TimerDocAgreement: docs/SP11-PAYLOAD-TIMER.md's register table, printed lines, numbers and placement are the
    source's, and its links and those of docs/SP11-PAYLOAD.md (the stub, the catalogue row, the Tests rows, the stick
    row, the order rule) resolve in both directions; TimerDocMutants seeds mistakes in either document that these tests
    must refuse. (The planning table of "The chain" is checked in tools/test-q1n1-sp11-payload-chain.py.)

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
import concurrent.futures
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The machinery of the native suite, with a build directory of this file's own so that the suites can run side by side.
native = load_module('sp11_payload_native_for_timer', ROOT / 'tools' / 'test-q1n1-sp11-payload.py')
native.BUILD = ROOT / 'build' / 'sp11-payload-timer-test'
BUILD = native.BUILD
DOC = ROOT / 'docs' / 'SP11-PAYLOAD.md'
DOC_TIMER = ROOT / 'docs' / 'SP11-PAYLOAD-TIMER.md'
UEFI = ROOT / 'platform' / 'uefi'
READELF = lambda: shutil.which('llvm-readelf', path=lib.ENV['PATH']) or 'llvm-readelf'  # noqa: E731
run, have = lib.run, lib.have


class TimerNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_the_timer_suites_pass(self):
        native.Native._check(self, 'timer')

    def test_each_suite_runs_alone(self):
        done, binary = native.build_program('timer', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite in ('order', 'ecv', 'el', 'poll', 'bracket', 'hostile', 'budget', 'args'):
            with self.subTest(suite=suite):
                code, output = native.run_program(binary, suite)
                self.assertEqual(code, 0, output)
                self.assertRegex(output, r'PASS: 1 payload timer suites, \d+ checks')


# ---- seeded bugs in timer.c ----------------------------------------------------------------------------------------------

TIMER = 'payloads/timer.c'
NEXT_V = '    say(a, "NEXT CNTVOFF_EL2");\n    uint64_t voff = SYSREG(S3_4_C14_C0_3);\n'
NEXT_P = '        say(a, "NEXT CNTPOFF_EL2");\n        uint64_t poff = SYSREG(S3_4_C14_C0_6);\n'
POLL_LINE = '    show3(a, "POLL_ADVANCED", latest != first, "POLL_READS", reads, "POLL_DELTA", latest - first);\n'
HELD_LINE = '    for (unsigned i = 0; i < ROUNDS; i++) held += virtual_count[i] + voff - before[i] <= after[i] - before[i];\n'
EL_CHECK = '    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {\n'
CNTVCT_PRINT = '        if (i == 0) show(a, "CNTVCT_EL0", virtual_count[0]);\n'
LONG_LINE = 'a->ops.puts(PREFIX "DONE ' + 'X' * 100 + '");\n'
MUTANTS = [
    # -- the hazards: last, announced, once
    ('timer-reads-cntpoff-first', TIMER, [(
        '    /* Context. */\n    uint64_t mmfr0 = SYSREG(ID_AA64MMFR0_EL1);\n',
        '    (void)SYSREG(S3_4_C14_C0_6);\n    /* Context. */\n    uint64_t mmfr0 = SYSREG(ID_AA64MMFR0_EL1);\n')], ['timer'], None),
    ('timer-reads-cntpoff-when-ecv-is-below-two', TIMER, [(
        '    if (ecv >= ECV_HAS_CNTPOFF) {\n', '    if (ecv >= 0) {\n')], ['timer'], None),
    ('timer-reads-cntpoff-only-when-ecv-is-above-two', TIMER, [(
        '    if (ecv >= ECV_HAS_CNTPOFF) {\n', '    if (ecv > ECV_HAS_CNTPOFF) {\n')], ['timer'], None),
    ('timer-prints-next-after-the-cntvoff-read', TIMER, [(
        NEXT_V, '    uint64_t voff = SYSREG(S3_4_C14_C0_3);\n    say(a, "NEXT CNTVOFF_EL2");\n')], ['timer'], None),
    ('timer-prints-next-after-the-cntpoff-read', TIMER, [(
        NEXT_P, '        uint64_t poff = SYSREG(S3_4_C14_C0_6);\n        say(a, "NEXT CNTPOFF_EL2");\n')], ['timer'], None),
    ('timer-never-announces-cntvoff', TIMER, [(NEXT_V, '    uint64_t voff = SYSREG(S3_4_C14_C0_3);\n')], ['timer'], None),
    ('timer-announces-the-wrong-register', TIMER, [(
        '    say(a, "NEXT CNTVOFF_EL2");\n', '    say(a, "NEXT CNTPOFF_EL2");\n')], ['timer'], None),
    ('timer-reads-cntvoff-before-the-safe-group-is-printed', TIMER, [(
        CNTVCT_PRINT, '        if (i == 0) { (void)SYSREG(S3_4_C14_C0_3); show(a, "CNTVCT_EL0", virtual_count[0]); }\n')], ['timer'], None),
    ('timer-reads-cntpoff-twice', TIMER, [(
        '        uint64_t poff = SYSREG(S3_4_C14_C0_6);\n',
        '        (void)SYSREG(S3_4_C14_C0_6);\n        uint64_t poff = SYSREG(S3_4_C14_C0_6);\n')], ['timer'], None),
    ('timer-prints-done-before-the-last-access', TIMER, [(
        '    /* HAZARD 2, the very last access. */\n    if (ecv >= ECV_HAS_CNTPOFF) {\n',
        '    /* HAZARD 2, the very last access. */\n    say(a, "DONE");\n    if (ecv >= ECV_HAS_CNTPOFF) {\n')], ['timer'], None),
    ('timer-touches-cntkctl-el1', TIMER, [(POLL_LINE, POLL_LINE + '    (void)SYSREG(cntkctl_el1);\n')], ['timer'], None),
    ('timer-reads-the-counter-through-the-runner', TIMER, [(
        '    uint64_t first = SYSREG(CNTPCT_EL0);\n', '    uint64_t first = a->ops.counter();\n')], ['timer'], None),
    # -- the poll
    ('timer-polls-without-a-bound', TIMER, [(
        '    while (reads < POLL_READS_MAX && latest == first) {\n', '    while (latest == first) {\n')], ['timer'], None),
    ('timer-poll-bound-is-one-too-many', TIMER, [(
        '#define POLL_READS_MAX 200000u\n', '#define POLL_READS_MAX 200001u\n')], ['timer'], None),
    ('timer-poll-delta-is-the-last-value', TIMER, [('"POLL_DELTA", latest - first);', '"POLL_DELTA", latest);')], ['timer'], None),
    # -- the fields
    ('timer-reads-ecv-from-the-wrong-bits', TIMER, [(
        '    uint64_t ecv = mmfr0 >> 60 & 15;\n', '    uint64_t ecv = mmfr0 >> 56 & 15;\n')], ['timer'], None),
    ('timer-reads-the-cnthctl-ecv-bit-from-bit-13', TIMER, [('"ECV", hctl >> 12 & 1);', '"ECV", hctl >> 13 & 1);')], ['timer'], None),
    ('timer-swaps-e2h-and-tge', TIMER, [('"E2H", hcr >> 34 & 1, "TGE", hcr >> 27 & 1);', '"E2H", hcr >> 27 & 1, "TGE", hcr >> 34 & 1);')],
     ['timer'], None),
    ('timer-reads-the-physical-count-for-the-virtual', TIMER, [(
        '        virtual_count[i] = SYSREG(CNTVCT_EL0);\n', '        virtual_count[i] = SYSREG(CNTPCT_EL0);\n')], ['timer'], None),
    ('timer-prints-cntvoff-under-the-name-of-cntpoff', TIMER, [(
        '    show(a, "CNTVOFF_EL2", voff);\n', '    show(a, "CNTPOFF_EL2", voff);\n')], ['timer'], None),
    # -- the bracket
    ('timer-brackets-without-modular-arithmetic', TIMER, [(
        HELD_LINE, '    for (unsigned i = 0; i < ROUNDS; i++) held += virtual_count[i] + voff >= before[i] && virtual_count[i] + voff <= after[i];\n')],
     ['timer'], None),
    ('timer-subtracts-the-offset-instead-of-adding-it', TIMER, [(
        'held += virtual_count[i] + voff - before[i] <=', 'held += virtual_count[i] - voff - before[i] <=')], ['timer'], None),
    ('timer-calls-it-within-when-one-round-held', TIMER, [('held == ROUNDS,', 'held > 0,')], ['timer'], None),
    ('timer-makes-one-round', TIMER, [('#define ROUNDS 8u\n', '#define ROUNDS 1u\n')], ['timer'], None),
    # -- CurrentEL and the page
    ('timer-reads-on-at-any-el', TIMER, [(EL_CHECK, '    if ((SYSREG(CurrentEL) >> 2 & 3) != 2 && 0) {\n')], ['timer'], None),
    ('timer-compares-the-whole-currentel', TIMER, [(EL_CHECK, '    if (SYSREG(CurrentEL) != 8) {\n')], ['timer'], None),
    ('timer-does-not-say-it-skipped', TIMER, [('        say(a, "SKIPPED_NOT_AT_EL2");\n', '')], ['timer'], None),
    ('timer-has-no-line-for-ecv-below-two', TIMER, [(
        '    } else {\n        say(a, "CNTPOFF_EL2 N/A (ECV BELOW 2)");\n    }\n', '    }\n')], ['timer'], None),
    ('timer-writes-the-brief-literal-with-a-less-than-sign', TIMER, [(
        '"CNTPOFF_EL2 N/A (ECV BELOW 2)"', '"CNTPOFF_EL2 N/A (ECV<2)"')], ['timer'], None),
    ('timer-prints-a-lower-case-key', TIMER, [('SHOW("CNTFRQ_EL0", CNTFRQ_EL0);', 'SHOW("cntfrq_el0", CNTFRQ_EL0);')], ['timer'], None),
    ('timer-prints-a-line-of-a-hundred-and-twenty-characters', TIMER, [('    say(a, "DONE");\n    return 0;\n', '    ' + LONG_LINE + '    return 0;\n')],
     ['timer'], None),
]


class TimerMutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    _build = staticmethod(native.Mutants._build)

    def _evaluate(self, *mutant):
        return native.Mutants._evaluate(self, *mutant)

    def test_there_are_enough_distinct_mutants_and_they_all_target_the_payload(self):
        names = [m[0] for m in MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertFalse({m[0] for m in native.MUTANTS} & set(names), 'a name the native suite already uses')
        self.assertGreaterEqual(len(names), 20)
        self.assertEqual({m[1] for m in MUTANTS}, {TIMER})
        for wanted in ('reads-cntpoff-first', 'reads-cntpoff-when-ecv-is-below-two', 'prints-next-after-the-cntvoff-read',
                       'touches-cntkctl-el1', 'reads-cntvoff-before-the-safe-group-is-printed', 'polls-without-a-bound',
                       'reads-ecv-from-the-wrong-bits'):
            self.assertIn(f'timer-{wanted}', names)

    def test_every_seeded_bug_is_caught(self):
        workers = max(1, min(4, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {m[0]: pool.submit(self._evaluate, *m) for m in MUTANTS}
            results = {name: future.result() for name, future in futures.items()}
        for name, (status, detail) in results.items():
            with self.subTest(mutant=name):
                self.assertEqual(status, 'caught', f'{status}: {detail}')


# ---- the binary --------------------------------------------------------------------------------------------------------

ANCHOR = '    /* HAZARD 1. */\n'
BAD_BINARIES = [
    # (name, [(needle, replacement)], what the allow-list check must say)
    ('a-write-to-cntkctl-el1', [(ANCHOR, ANCHOR + '    __asm__ volatile("msr cntkctl_el1, xzr" ::: "memory");\n')], 'msr'),
    ('a-write-to-cntvoff-el2', [(ANCHOR, ANCHOR + '    __asm__ volatile("msr cntvoff_el2, xzr" ::: "memory");\n')], 'msr'),
    ('a-write-to-cntpoff-el2', [(ANCHOR, ANCHOR + '    __asm__ volatile("msr S3_4_C14_C0_6, xzr" ::: "memory");\n')], 'msr'),
    ('an-isb', [(ANCHOR, ANCHOR + '    __asm__ volatile("isb");\n')], 'isb'),
    ('a-dsb', [(ANCHOR, ANCHOR + '    __asm__ volatile("dsb sy" ::: "memory");\n')], 'dsb'),
    ('a-dmb', [(ANCHOR, ANCHOR + '    __asm__ volatile("dmb sy" ::: "memory");\n')], 'dmb'),
    ('a-second-cntvoff-read', [(ANCHOR, ANCHOR + '    (void)SYSREG(S3_4_C14_C0_3);\n')], 'is read 2 times'),
    ('a-second-cntpoff-read', [(ANCHOR, ANCHOR + '    (void)SYSREG(S3_4_C14_C0_6);\n')], 'is read 2 times'),
    ('cntpoff-is-not-read', [('SYSREG(S3_4_C14_C0_6)', '0')], 'is read 0 times'),
    ('a-read-of-cntkctl-el1', [(ANCHOR, ANCHOR + '    (void)SYSREG(cntkctl_el1);\n')], 'registers read'),
    ('a-read-of-the-self-synchronised-counter', [(ANCHOR, ANCHOR + '    (void)SYSREG(S3_3_C14_C0_5);\n')], 'registers read'),
    ('an-hvc', [(ANCHOR, ANCHOR + '    __asm__ volatile("hvc #0" ::: "memory");\n')], 'hvc'),
    ('an-svc', [(ANCHOR, ANCHOR + '    __asm__ volatile("svc #0" ::: "memory");\n')], 'svc'),
    ('an-smc', [(ANCHOR, ANCHOR + '    __asm__ volatile("smc #0" ::: "memory");\n')], 'smc'),
    ('a-cache-operation', [(ANCHOR, ANCHOR + '    __asm__ volatile("dc civac, %0" :: "r"(a) : "memory");\n')], 'dc'),
    ('a-tlb-operation', [(ANCHOR, ANCHOR + '    __asm__ volatile("tlbi vmalle1" ::: "memory");\n')], 'tlbi'),
    ('a-wfi', [(ANCHOR, ANCHOR + '    __asm__ volatile("wfi");\n')], 'wfi'),
    ('an-eret', [(ANCHOR, ANCHOR + '    __asm__ volatile("eret");\n')], 'eret'),
    ('an-exclusive-load', [(ANCHOR, ANCHOR + '    __asm__ volatile("ldxr x9, [sp]" ::: "x9", "memory");\n')], 'ldxr'),
    ('a-word-that-is-no-instruction', [(ANCHOR, ANCHOR + '    __asm__ volatile(".inst 0xffffffff");\n')], 'not a known instruction'),
]
# Builds that pass the allow-list (MRS of the documented registers, each offset once) and still break the order.
ORDER_BREAKERS = [
    ('next-printed-after-the-cntvoff-read', [(NEXT_V, '    uint64_t voff = SYSREG(S3_4_C14_C0_3);\n    say(a, "NEXT CNTVOFF_EL2");\n')], 'CNTVOFF'),
    ('next-printed-after-the-cntpoff-read', [(NEXT_P, '        uint64_t poff = SYSREG(S3_4_C14_C0_6);\n        say(a, "NEXT CNTPOFF_EL2");\n')], 'CNTPOFF'),
    ('a-line-between-next-and-the-cntpoff-read', [(
        NEXT_P, '        say(a, "NEXT CNTPOFF_EL2");\n        say(a, "WAITING");\n        uint64_t poff = SYSREG(S3_4_C14_C0_6);\n')], 'CNTPOFF'),
    ('a-line-between-next-and-the-cntvoff-read', [(
        NEXT_V, '    say(a, "NEXT CNTVOFF_EL2");\n    say(a, "WAITING");\n    uint64_t voff = SYSREG(S3_4_C14_C0_3);\n')], 'CNTVOFF'),
    ('next-names-the-other-register', [('    say(a, "NEXT CNTVOFF_EL2");\n', '    say(a, "NEXT CNTPOFF_EL2");\n')], 'CNTVOFF'),
    ('a-counter-read-after-the-last-hazard', [(
        '    say(a, "DONE");\n    return 0;\n', '    say(a, "DONE");\n    show(a, "CNTPCT_EL0", SYSREG(CNTPCT_EL0));\n    return 0;\n')],
     'not CNTVOFF_EL2 then CNTPOFF_EL2'),
]


class TimerBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'ld.lld', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy'):
            if not have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        cls.out = BUILD / 'bad-binaries'
        shutil.rmtree(cls.out, ignore_errors=True)
        cls.out.mkdir(parents=True)
        cls.sources = {name: (ROOT / 'payloads' / f'{name}.c').read_text(encoding='utf-8') for name in ('timer', 'state', 'psci')}

    def build(self, payload, name, edits):
        text = self.sources[payload]
        for needle, replacement in edits:
            self.assertEqual(text.count(needle), 1, f'{name}: {needle[:60]!r} is not in {payload}.c exactly once')
            text = text.replace(needle, replacement, 1)
        path = self.out / f'{name}.c'
        path.write_text(text, encoding='utf-8')
        return lib.build_payload(path, self.out, name=name, check=False)

    def test_the_unmodified_payload_is_clean_and_in_order(self):
        done, elf, flat = self.build('timer', 'control', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(lib.binary_violations(elf, flat, lib.POLICIES['timer'], READELF()), [])
        self.assertEqual(lib.hazard_order_violations(elf, flat), [])

    def test_only_the_timer_payload_may_name_the_timer_offsets(self):
        self.assertEqual([name for name, policy in lib.POLICIES.items() if policy.get('timer_offsets')], ['timer'])
        for name, policy in lib.POLICIES.items():
            with self.subTest(payload=name):
                has = {lib.CNTVOFF_EL2, lib.CNTPOFF_EL2} & policy['registers']
                self.assertEqual(bool(has), name == 'timer')
                self.assertEqual(policy['smc'], 0 if name != 'psci' else 1)
        self.assertEqual(lib.POLICIES['timer']['registers'] - {lib.CNTVOFF_EL2, lib.CNTPOFF_EL2}, lib.TIMER_REGISTERS - {lib.CNTVOFF_EL2, lib.CNTPOFF_EL2})
        self.assertGreaterEqual(lib.POLICIES['timer']['forbid'], {'isb', 'dsb', 'dmb'})

    def test_every_forbidden_addition_is_named_by_the_allow_list_check(self):
        self.assertGreaterEqual(len(BAD_BINARIES), 12)
        for name, edits, expected in BAD_BINARIES:
            with self.subTest(binary=name):
                done, elf, flat = self.build('timer', name, edits)
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                problems = lib.binary_violations(elf, flat, lib.POLICIES['timer'], READELF())
                self.assertTrue(problems, 'the check passed a binary it must refuse')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_state_and_psci_are_refused_if_they_name_a_timer_offset(self):
        anchors = {'state': '    SHOW("CNTFRQ_EL0", cntfrq_el0);\n', 'psci': '    say(a, "NEXT SMCCC");\n'}
        for payload, anchor in anchors.items():
            for register in ('cntvoff_el2', 'S3_4_C14_C0_3', 'S3_4_C14_C0_6'):
                with self.subTest(payload=payload, register=register):
                    done, elf, flat = self.build(payload, f'{payload}-reads-{register}',
                                                 [(anchor, anchor + f'    (void)SYSREG({register});\n')])
                    self.assertEqual(done.returncode, 0, done.stderr[-500:])
                    problems = lib.binary_violations(elf, flat, lib.POLICIES[payload], READELF())
                    self.assertTrue(any('the code names' in p for p in problems), problems)
                    self.assertTrue(any('registers read' in p for p in problems), problems)
        # And the other way round: the timer payload is not state or psci, whichever policy it is held to.
        done, elf, flat = self.build('timer', 'timer-as-state', [])
        for other in ('state', 'psci'):
            self.assertTrue(any('the code names' in p for p in lib.binary_violations(elf, flat, lib.POLICIES[other], READELF())))

    def test_the_compiled_order_has_the_hazards_last_each_right_after_its_next_line(self):
        self.assertGreaterEqual(len(ORDER_BREAKERS), 5)
        for name, edits, expected in ORDER_BREAKERS:
            with self.subTest(binary=name):
                done, elf, flat = self.build('timer', name, edits)
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                self.assertEqual(lib.binary_violations(elf, flat, lib.POLICIES['timer'], READELF()), [],
                                 'this build is meant to pass the allow-list and break only the order')
                problems = lib.hazard_order_violations(elf, flat)
                self.assertTrue(problems, 'the order check passed a build that prints after the read')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_the_timer_binary_holds_each_offset_once_and_fits_one_page(self):
        done, elf, flat = self.build('timer', 'size', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertLessEqual(Path(flat).stat().st_size, 4096)
        dis = run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout.lower()
        self.assertEqual(len(re.findall(r'mrs\s+\w+,\s*(?:cntvoff_el2|s3_4_c14_c0_3)\b', dis)), 1)
        self.assertEqual(len(re.findall(r'mrs\s+\w+,\s*(?:cntpoff_el2|s3_4_c14_c0_6)\b', dis)), 1)
        self.assertNotIn('msr', {line.split()[1] for line in dis.splitlines() if re.match(r'\s+[0-9a-f]+:\s', line)})


# ---- the manifest chain ------------------------------------------------------------------------------------------------


class TimerChain(unittest.TestCase):
    tool = ROOT / 'tools' / 'sp11_payload_manifest.py'

    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'ld.lld', 'make', 'llvm-objcopy'):
            if not have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        cls.out = BUILD / 'chain-payloads'
        shutil.rmtree(cls.out, ignore_errors=True)
        done = run(['make', '-f', 'platform/uefi/Makefile', f'OUT={cls.out.relative_to(ROOT)}', 'payloads'])
        if done.returncode:
            raise RuntimeError('make payloads failed:\n' + done.stdout[-1500:] + done.stderr[-1500:])
        cls.bins = {name: (cls.out / 'payloads' / f'{name}.bin') for name in ('state', 'psci', 'timer')}

    def stick(self, order):
        base = BUILD / 'chain-stick' / '-'.join(order)
        shutil.rmtree(base, ignore_errors=True)
        done = run(['python3', '-B', str(self.tool), '--out-dir', str(base)] + [str(self.bins[name]) for name in order])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        return base, done

    def entries(self, base):
        raw = (base / 'SP11' / 'PAYLOAD.MAN').read_bytes()
        magic, version, count, size = struct.unpack_from('<4Q', raw)
        self.assertEqual(magic, int.from_bytes(b'Q1N1PLD1', 'little'))
        return [struct.unpack_from('<Q32s256s', raw, 32 + i * size) for i in range(count)], raw

    def test_state_psci_timer_is_three_of_the_five_files_in_that_order(self):
        base, done = self.stick(('state', 'psci', 'timer'))
        entries, raw = self.entries(base)
        self.assertEqual(len(entries), 3)
        self.assertEqual([e[2].rstrip(b'\0').decode() for e in entries], ['\\SP11\\STATE.BIN', '\\SP11\\PSCI.BIN', '\\SP11\\TIMER.BIN'])
        for (size, digest, _), name in zip(entries, ('state', 'psci', 'timer')):
            data = self.bins[name].read_bytes()
            self.assertEqual((size, digest), (len(data), hashlib.sha256(data).digest()))
        for text in ('(INDEX=0, payload, called in manifest order)', '(INDEX=1, payload, called in manifest order)',
                     '(INDEX=2, payload, called in manifest order)', 'SP11\\TIMER.BIN'):
            self.assertIn(text, done.stdout)
        self.assertEqual(sorted(p.name for p in (base / 'SP11').iterdir()), ['PAYLOAD.MAN', 'PSCI.BIN', 'STATE.BIN', 'TIMER.BIN'])
        self.assertEqual((base / 'SP11' / 'TIMER.BIN').read_bytes(), self.bins['timer'].read_bytes())

    def test_the_runners_own_validator_and_loader_take_the_chain_as_three_payloads(self):
        harness = BUILD / 'kinds-harness'
        sources = [ROOT / 'tools' / 'testdata' / 'sp11-payload-kinds-harness.c'] + [
            UEFI / name for name in ('sp11-payload-load.c', 'sp11-payload-plan.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c')]
        done = run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1',
                    '-I', str(UEFI)] + [str(s) for s in sources] + ['-o', str(harness)])
        self.assertEqual(done.returncode, 0, done.stderr)
        base, _ = self.stick(('state', 'psci', 'timer'))
        ours = run([str(harness), str(base / 'SP11' / 'PAYLOAD.MAN')])
        self.assertEqual(ours.returncode, 0, ours.stdout + ours.stderr)
        self.assertEqual(ours.stdout.splitlines(), ['\\SP11\\STATE.BIN code', '\\SP11\\PSCI.BIN code', '\\SP11\\TIMER.BIN code'])
        # Image, memory-map buffer and preload table take three of slbounce's eight declared ranges; the chain takes three more.
        header = (UEFI / 'sp11-payload.h').read_text(encoding='utf-8')
        ranges = (UEFI / 'sp11-ebs-ranges.h').read_text(encoding='utf-8')
        used = int(re.search(r'#define Q1N1_PAYLOAD_BASE_RANGES (\d+)u', header).group(1))
        capacity = int(re.search(r'#define SP11_EBS_MAX_RANGES (\d+)u', ranges).group(1))
        self.assertLessEqual(used + 3, capacity)
        self.assertEqual(capacity - used, 5, 'the manifest holds five files at most: three payloads leave room for two data files')

    def test_order_is_whatever_the_operator_gives_so_the_docs_must_say_timer_goes_last(self):
        # The tool keeps the order it is given: nothing in it knows which payload may stall the board.
        base, _ = self.stick(('timer', 'state', 'psci'))
        entries, _ = self.entries(base)
        self.assertEqual([e[2].rstrip(b'\0').decode() for e in entries], ['\\SP11\\TIMER.BIN', '\\SP11\\STATE.BIN', '\\SP11\\PSCI.BIN'])
        doc = DOC.read_text(encoding='utf-8')
        self.assertIn('state.bin psci.bin timer.bin', doc)
        self.assertRegex(doc, r'(?i)timer.{0,80}\blast\b|\blast\b.{0,80}timer')


# ---- the documentation -------------------------------------------------------------------------------------------------

NUMBER_WORDS = {1: 'one', 2: 'two', 3: 'three', 4: 'four', 5: 'five', 6: 'six', 7: 'seven', 8: 'eight', 9: 'nine', 10: 'ten'}
PAGE_FONT = re.compile(r'^[A-Z0-9 :\-./=?()_]*$')
# What the printed-lines block of the document leaves to prose: the two control registers its comment says "likewise" for,
# and the two lines that are not KEY=VALUE lines of the main path.
OMITTED_FROM_THE_BLOCK = [('show', ('CNTV_CTL_EL0',)), ('show', ('CNTHP_CTL_EL2',)), ('say', 'SKIPPED_NOT_AT_EL2'),
                          ('say', 'CNTPOFF_EL2 N/A (ECV BELOW 2)')]


def mc_encodings(operands):
    """The bytes llvm-mc gives `mrs x0, <operand>`, one string per operand (CNTPOFF_EL2 by name needs FEAT_ECV)."""
    done = lib.run(['llvm-mc', '-triple=aarch64', '-mattr=+ecv', '-show-encoding'],
                   input=''.join(f'mrs x0, {operand}\n' for operand in operands))
    found = re.findall(r'encoding: \[([^\]]*)\]', done.stdout)
    assert done.returncode == 0 and len(found) == len(operands), done.stderr
    return found


LINK = re.compile(r'(?<!!)\[[^\]\n]+\]\(([^)\s]+)\)')


def anchors_of(text):
    """The anchors GitHub gives the headings of a Markdown document: lower case, everything but letters, digits, spaces,
    underscores and hyphens dropped, spaces to hyphens. Headings inside code fences are not headings."""
    outside = re.sub(r'```.*?```', '', text, flags=re.S)
    return {re.sub(r'[^a-z0-9 _-]', '', title.strip().lower()).replace(' ', '-')
            for title in re.findall(r'^#{1,6} +(.+?) *$', outside, re.M)}


class TimerDocAgreement(unittest.TestCase):
    """The documents say what timer.c does: the register table, printed lines and numbers of docs/SP11-PAYLOAD-TIMER.md
    are read from the document and compared with the source, with what the host test pins and (the encodings) with the
    assembler; the pointers in docs/SP11-PAYLOAD.md (stub, catalogue row, Tests rows, stick row, order rule) and the
    links of both documents are checked against each other."""
    TEXT = None     # a changed copy of docs/SP11-PAYLOAD-TIMER.md, for TimerDocMutants
    MAIN = None     # a changed copy of docs/SP11-PAYLOAD.md, for TimerDocMutants

    @classmethod
    def setUpClass(cls):
        cls.doc = DOC_TIMER.read_text(encoding='utf-8') if cls.TEXT is None else cls.TEXT
        cls.main = DOC.read_text(encoding='utf-8') if cls.MAIN is None else cls.MAIN
        cls.source = (ROOT / 'payloads' / 'timer.c').read_text(encoding='utf-8')
        cls.host = (ROOT / 'tools' / 'test-q1n1-sp11-payload-timer.c').read_text(encoding='utf-8')
        cls.section = cls.doc                           # the whole document is the payload's
        cls.flat = ' '.join(cls.doc.split())            # the paragraphs are wrapped: phrases are looked up with the wraps undone
        entry = cls.source.index('uint64_t payload_entry(const struct q1n1_payload_args *a)\n{')
        cls.body = re.sub(r'/\*.*?\*/', '', cls.source[entry:], flags=re.S)

    def mentions(self, phrase, text=None):
        self.assertTrue(phrase in (self.flat if text is None else ' '.join(text.split())), f'the document does not say {phrase!r}')

    def rows(self):
        table = self.section[self.section.index('<!-- timer-registers -->'):self.section.index('<!-- /timer-registers -->')]
        return re.findall(r'^\| `([A-Za-z0-9_]+)` \| `(S3_\d_C\d+_C\d+_\d)` \| ([^|]+?) \| (.+) \|$', table, re.M)

    def block_lines(self):
        block = re.search(r'```\n(PAYLOAD TIMER .*?)```', self.section, re.S).group(1)
        return [re.split(r'\s{2,}\(', raw)[0].rstrip() for raw in block.splitlines()]

    def source_events(self):
        events = []
        for call, args in re.findall(r'\b(say|show[234]?|SHOW)\(([^;]*);', self.body):
            quoted = re.findall(r'"([^"]*)"', args)
            events.append(('say', quoted[0]) if call == 'say' else ('show', tuple(quoted)))
        return events

    def test_the_register_table_lists_exactly_the_registers_the_payload_reads(self):
        rows = self.rows()
        self.assertEqual(len(rows), 12)
        documented = {code.lower() if name in ('CNTVOFF_EL2', 'CNTPOFF_EL2') else name.lower() for name, code, _, _ in rows}
        read = re.findall(r'SYSREG\((\w+)\)', self.body) + re.findall(r'\bSHOW\("[A-Z0-9_]+", (\w+)\)', self.body)
        self.assertEqual(documented, {register.lower() for register in read})
        self.assertEqual(documented, lib.TIMER_REGISTERS)
        self.mentions('exactly the twelve')

    @unittest.skipUnless(lib.have('llvm-mc'), 'llvm-mc not installed')
    def test_every_encoding_in_the_table_is_its_registers_encoding(self):
        rows = self.rows()
        by_name = mc_encodings([name for name, _, _, _ in rows])
        self.assertEqual(by_name, mc_encodings([code for _, code, _, _ in rows]))
        self.assertEqual(len(set(by_name)), len(rows))

    def test_the_hazards_are_the_last_two_rows_and_the_evidence_is_labelled(self):
        rows = self.rows()
        self.assertEqual([(name, group) for name, _, group, _ in rows[-2:]], [('CNTVOFF_EL2', 'HAZARD 1'), ('CNTPOFF_EL2', 'HAZARD 2')])
        self.assertEqual([group for _, _, group, _ in rows].count('SAFE'), 7)
        evidence = {name: text for name, _, _, text in rows}
        for name, text in evidence.items():
            self.assertRegex(text, r'VERIFIED|INFERRED|OBSERVED|UNKNOWN|as above', name)
        for name in ('CNTVOFF_EL2', 'CNTPOFF_EL2'):
            self.assertIn('INFERRED', evidence[name])
            self.assertIn('VERIFIED register', evidence[name])
        self.assertIn('UNKNOWN', evidence['CNTFRQ_EL0'])
        self.assertIn('Oryon X1', evidence['CNTVOFF_EL2'])
        self.assertIn('ECV >= 2', evidence['CNTPOFF_EL2'])
        self.assertIn('OBSERVED', evidence['ID_AA64MMFR0_EL1'])

    def test_the_bit_positions_the_bound_and_the_rounds_are_the_sources(self):
        shift = int(re.search(r'mmfr0 >> (\d+) & 15', self.source).group(1))
        self.mentions(f'ECV is bits {shift + 3}:{shift} ')
        self.mentions(f'ECV is bit {int(re.search(r"hctl >> (\d+) & 1", self.source).group(1))};')
        bound = int(re.search(r'#define POLL_READS_MAX (\d+)u', self.source).group(1))
        self.assertEqual(self.flat.count(f'{bound} reads'), 2)
        rounds = int(re.search(r'#define ROUNDS (\d+)u', self.source).group(1))
        self.mentions(f'there are {NUMBER_WORDS[rounds]} rounds')
        self.mentions(f'HELD=0X{rounds:X} OF=0X{rounds:X}')
        self.mentions(f'ECV >= {int(re.search(r"#define ECV_HAS_CNTPOFF (\d+)u", self.source).group(1))}')

    def test_the_printed_lines_in_the_document_are_the_lines_the_payload_prints_in_order(self):
        events = []
        for line in self.block_lines():
            text = line[len('PAYLOAD TIMER '):]
            keys = re.findall(r'([A-Z0-9_]+)=', text)
            events.append(('show', tuple(keys)) if keys else ('say', text))
        wanted = [event for event in self.source_events() if event not in OMITTED_FROM_THE_BLOCK]
        self.assertEqual(events, wanted)
        for event in OMITTED_FROM_THE_BLOCK:
            self.mentions(event[1] if event[0] == 'say' else event[1][0])
        self.mentions('(likewise CNTV_CTL_EL0, CNTHP_CTL_EL2)')
        self.mentions('PAYLOAD TIMER SKIPPED_NOT_AT_EL2')

    def test_the_hazards_come_last_in_the_printed_block_each_after_its_next_line(self):
        lines = [line[len('PAYLOAD TIMER '):] for line in self.block_lines()]
        self.assertEqual(lines.index('NEXT CNTVOFF_EL2') + 1, next(i for i, l in enumerate(lines) if l.startswith('CNTVOFF_EL2=')))
        self.assertEqual(lines.index('NEXT CNTPOFF_EL2') + 1, next(i for i, l in enumerate(lines) if l.startswith('CNTPOFF_EL2=')))
        self.assertLess(lines.index('NEXT CNTVOFF_EL2'), lines.index('NEXT CNTPOFF_EL2'))
        self.assertEqual(lines[-1], 'DONE')
        self.assertEqual(lines[-2][:12], 'CNTPOFF_EL2=')
        # Everything the SAFE group prints comes before the first hazard.
        for key in ('CNTFRQ_EL0=', 'CNTHCTL_EL2=', 'CNTP_CTL_EL0=', 'CNTPCT_EL0=', 'POLL_ADVANCED=', 'CNTVCT_EL0='):
            self.assertLess(next(i for i, l in enumerate(lines) if l.startswith(key)), lines.index('NEXT CNTVOFF_EL2'), key)

    def test_every_printed_line_is_in_the_page_font_and_within_a_hundred_characters(self):
        for line in self.block_lines():
            with self.subTest(line=line):
                self.assertLessEqual(len(line), 100)
                self.assertRegex(line, PAGE_FONT)

    def test_the_line_counts_and_the_budget_are_the_numbers_the_host_test_pins(self):
        most = int(re.search(r'timer_most == (\d+)', self.host).group(1))
        self.mentions(f'{most} lines when ECV >= 2, {most - 1} below, 1 off EL2 (')
        state_most, psci_most, psci_qemu, state_usual = map(int, re.search(
            r'state_most = (\d+), psci_most = (\d+), psci_qemu = (\d+), state_usual = (\d+)', self.host).groups())
        runner, worst, qemu = map(int, re.search(r'RUNNER\(3, 3\) == (\d+) && worst == (\d+) && qemu == (\d+)', self.host).groups())
        rows = int(re.search(r'unit\.rows == (\d+)', self.host).group(1))
        small = int(re.search(r'RUNNER\(2, 2\) \+ state_most \+ timer_most == (\d+)', self.host).group(1))
        stock = int(re.search(r'#define Q1N1_PAYLOAD_REGION_LINES (\d+)u', (UEFI / 'sp11-payload.h').read_text(encoding='utf-8')).group(1))
        self.assertEqual((runner, worst, qemu, rows, small, stock), (13, 81, 72, 89, 47, 60))
        for phrase in (f'The runner adds {runner} lines', f'`state` ({state_usual}; {state_most} with E2H set)',
                       f'`psci` ({psci_qemu} under QEMU, {psci_most} at most)', f'`timer` ({most}; {most - 1} below ECV 2)',
                       f'{qemu} lines under QEMU', f'{worst} at most', f'{rows} rows on the unit', f'{stock} in the stock layout',
                       f'{NUMBER_WORDS[rows - worst]} rows to spare', f'{small} at most, fits'):
            self.mentions(phrase)

    def test_the_documents_put_timer_last_wherever_they_give_an_order(self):
        self.mentions('`timer.bin` goes **last**')
        self.mentions('`state.bin psci.bin timer.bin`')
        chain = self.main[self.main.index('## The chain'):self.main.index('## Payload ABI v1')]
        self.mentions('**Order.** A payload that may stall the board goes **last**', chain)
        self.mentions('`timer` is one (`state.bin psci.bin timer.bin`, never `timer.bin` first)', chain)
        stick = self.main[self.main.index('## On the stick'):self.main.index('## The manifest')]
        self.assertRegex(stick, r'state\.bin\s+\S*psci\.bin\s+\S*timer\.bin')
        self.assertRegex(stick, r'\| `SP11\\TIMER\.BIN` \|[^\n]*manifest index 2, \*\*last\*\*')

    def test_the_main_document_points_at_this_one_from_its_stub_the_catalogue_and_the_tests(self):
        start = self.main.index('## Payload `timer`')
        stub = self.main[start:self.main.index('\n## ', start)]
        for phrase in ('goes **last** in a chain', '[SP11-PAYLOAD-TIMER.md](SP11-PAYLOAD-TIMER.md)', 'EXPERIMENTAL; hardware NOT RUN',
                       'nothing of it is OBSERVED on the unit'):
            self.mentions(phrase, stub)
        catalogue = self.main[self.main.index('## Line catalogue'):self.main.index('## Failure modes')]
        self.mentions('| `PAYLOAD TIMER ...` |', catalogue)
        tests = self.main[self.main.index('## Tests'):self.main.index('## Safety')]
        for command in ('test-q1n1-sp11-payload-timer.py', 'test-q1n1-sp11-payload-qemu-timer.py'):
            self.mentions(f'python3 tools/{command}`', tests)
        for claim in (f'{len(MUTANTS)} seeded-bug mutants', f'{len(BAD_BINARIES)} seeded bad binaries',
                      f'{len(ORDER_BREAKERS)} that break the compiled order', f'with {len(DOC_MUTANTS)} seeded mistakes'):
            self.mentions(claim, tests)
        self.mentions('eight native programs', tests)
        self.mentions('`timer` `MRS` of its twelve registers and no barrier', tests)

    def test_this_document_says_why_it_exists_where_it_goes_and_what_is_known(self):
        for word in ('EXPERIMENTAL; hardware NOT RUN', 'Hardware NOT RUN', 'UNKNOWN', 'INFERRED', 'OBSERVED', 'VERIFIED',
                     'It may stall the whole board', 'goes **last**'):
            self.mentions(word)
        self.mentions('the unit\'s CNTFRQ_EL0 (until it is read)')
        self.mentions('INFERRED and untested: that SCR_EL3.ECVEn = 0 explains a CNTPOFF_EL2 stall')

    def test_both_documents_start_with_their_licence_line_and_stay_within_the_size_limit(self):
        for name, text in (('SP11-PAYLOAD.md', self.main), ('SP11-PAYLOAD-TIMER.md', self.doc)):
            with self.subTest(document=name):
                self.assertEqual(text.splitlines()[0], '<!-- SPDX-License-Identifier: MIT -->')
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                self.assertLess(len(text.splitlines()), 1500)

    def test_the_two_documents_link_each_other_and_every_relative_link_and_anchor_resolves(self):
        texts = {'SP11-PAYLOAD.md': self.main, 'SP11-PAYLOAD-TIMER.md': self.doc}
        links = {name: LINK.findall(text) for name, text in texts.items()}
        self.assertTrue(any(t.startswith('SP11-PAYLOAD-TIMER.md') for t in links['SP11-PAYLOAD.md']), 'the main document does not link here')
        self.assertTrue(any(t.startswith('SP11-PAYLOAD.md') for t in links['SP11-PAYLOAD-TIMER.md']), 'this document does not link back')
        self.assertIn('SP11-PAYLOAD-TIMER.md#what-it-prints', links['SP11-PAYLOAD.md'])
        for name, targets in links.items():
            for target in targets:
                with self.subTest(document=name, link=target):
                    if re.match(r'[a-z][a-z0-9+.-]*:', target):
                        continue                                    # a link to another site: not this test's business
                    path, _, fragment = target.partition('#')
                    other = path or name
                    if other in texts:
                        text = texts[other]
                    else:
                        self.assertTrue((DOC.parent / other).is_file(), f'{target}: {other} is not a file')
                        text = (DOC.parent / other).read_text(encoding='utf-8')
                    if fragment:
                        self.assertIn(fragment, anchors_of(text), f'{target}: {other} has no such heading')


def _replace(old, new, count=1):
    def mutate(doc):
        assert old in doc, old
        return doc.replace(old, new, count)
    return mutate


def _swap(first, second):
    def mutate(doc):
        lines = doc.split('\n')
        a = next(i for i, line in enumerate(lines) if line.startswith(first))
        b = next(i for i, line in enumerate(lines) if line.startswith(second))
        lines[a], lines[b] = lines[b], lines[a]
        return '\n'.join(lines)
    return mutate


TIMER_DOC_MUTANTS = [
    ('a-register-encoding-is-wrong', _replace('| `CNTPOFF_EL2` | `S3_4_C14_C0_6` |', '| `CNTPOFF_EL2` | `S3_4_C14_C0_5` |')),
    ('cntvoff-has-the-encoding-of-cntpoff', _replace('| `CNTVOFF_EL2` | `S3_4_C14_C0_3` |', '| `CNTVOFF_EL2` | `S3_4_C14_C0_6` |')),
    ('a-register-row-is-forgotten', _replace('| `CNTHP_CTL_EL2` | `S3_4_C14_C2_1` | SAFE | as above |\n', '')),
    ('a-thirteenth-register-appears', _replace('<!-- /timer-registers -->', '| `CNTKCTL_EL1` | `S3_0_C14_C1_0` | SAFE | VERIFIED |\n<!-- /timer-registers -->')),
    ('the-hazard-rows-are-swapped', _swap('| `CNTVOFF_EL2` | `S3_4_C14_C0_3`', '| `CNTPOFF_EL2` | `S3_4_C14_C0_6`')),
    ('a-hazard-is-called-verified-not-inferred', _replace('the leading suspect (INFERRED, untested)', 'the leading suspect (VERIFIED)')),
    ('the-frequency-is-claimed-observed', _replace("the unit's value is UNKNOWN", "the unit's value is OBSERVED")),
    ('the-hazard-lines-are-swapped-in-the-printed-block', _swap('PAYLOAD TIMER NEXT CNTVOFF_EL2', 'PAYLOAD TIMER NEXT CNTPOFF_EL2')),
    ('the-next-line-before-cntpoff-is-forgotten', _replace('PAYLOAD TIMER NEXT CNTPOFF_EL2', 'PAYLOAD TIMER CNTPOFF_EL2=0X..')),
    ('the-ecv-below-two-line-has-a-less-than-sign', _replace('CNTPOFF_EL2 N/A (ECV BELOW 2)', 'CNTPOFF_EL2 N/A (ECV<2)', count=-1)),
    ('the-ecv-field-is-the-wrong-bits', _replace('ECV is bits 63:60', 'ECV is bits 59:56')),
    ('the-cnthctl-ecv-bit-is-wrong', _replace('ECV is bit 12;', 'ECV is bit 13;')),
    ('the-poll-bound-is-wrong', _replace('polled at most 200000 reads', 'polled at most 20000 reads')),
    ('the-rounds-are-wrong', _replace('there are eight rounds', 'there are four rounds')),
    ('the-worst-case-is-wrong', _replace('81 at most', '71 at most')),
    ('the-region-is-wrong', _replace('89 rows on the unit', '90 rows on the unit')),
    ('the-qemu-total-is-wrong', _replace('72 lines under QEMU', '70 lines under QEMU')),
    ('the-line-count-is-wrong', _replace('16 lines when ECV >= 2, 15 below, 1 off EL2 (', '17 lines when ECV >= 2, 16 below, 1 off EL2 (')),
    ('the-docs-put-timer-first', _replace('`timer.bin` goes **last**', '`timer.bin` goes **first**')),
    ('hardware-is-claimed-run', _replace('Hardware NOT RUN: nothing of this payload is OBSERVED on the unit', 'Hardware run: all of this payload is OBSERVED on the unit')),
    ('a-printed-line-is-over-a-hundred-characters', _replace('PAYLOAD TIMER DONE\n```', 'PAYLOAD TIMER DONE ' + 'X' * 90 + '\n```')),
    ('a-key-is-renamed', _replace('POLL_ADVANCED=0X1', 'POLL_MOVED=0X1')),
    ('the-frequency-is-said-to-be-known', _replace('UNKNOWN until read', 'known: 19.2 MHz')),
    ('the-ecv-explanation-is-called-observed', _replace('INFERRED and untested: that SCR_EL3.ECVEn = 0', 'OBSERVED: that SCR_EL3.ECVEn = 0')),
    ('the-licence-line-is-gone', _replace('<!-- SPDX-License-Identifier: MIT -->\n', '')),
    ('the-links-back-name-a-file-that-does-not-exist', _replace('](SP11-PAYLOAD.md', '](SP11-PAYLOAD-OLD.md', count=-1)),
    ('an-anchor-of-this-document-does-not-resolve', _replace('SP11-PAYLOAD.md#line-catalogue', 'SP11-PAYLOAD.md#line-catalog')),
    ('the-link-to-the-chain-section-is-renamed', _replace('#the-chain-several-payloads-in-one-boot', '#the-chain', count=-1)),
]
# The same for the pointers in docs/SP11-PAYLOAD.md.
MAIN_DOC_MUTANTS = [
    ('the-chain-order-paragraph-is-weakened', _replace('**Order.** A payload that may stall the board goes **last**', '**Order.** A payload that may stall the board goes **anywhere**')),
    ('the-order-example-puts-timer-first', _replace('(`state.bin psci.bin timer.bin`, never `timer.bin` first)', '(`timer.bin psci.bin state.bin`)')),
    ('the-stick-row-is-renamed', _replace('| `SP11\\TIMER.BIN` |', '| `SP11\\TIMER.EXE` |')),
    ('the-stick-row-is-not-last', _replace('manifest index 2, **last**: it may stall the board', 'manifest index 2')),
    ('the-catalogue-row-is-gone', _replace('| `PAYLOAD TIMER ...` |', '| `PAYLOAD CLOCK ...` |')),
    ('the-mutant-count-is-wrong', _replace(f'{len(MUTANTS)} seeded-bug mutants', f'{len(MUTANTS) - 1} seeded-bug mutants')),
    ('the-order-breaker-count-is-wrong', _replace(f'{len(ORDER_BREAKERS)} that break the compiled order', f'{len(ORDER_BREAKERS) - 1} that break the compiled order')),
    ('the-stub-lost-its-pointer', _replace('[SP11-PAYLOAD-TIMER.md](SP11-PAYLOAD-TIMER.md). EXPERIMENTAL', 'SP11-PAYLOAD-TIMER.md. EXPERIMENTAL')),
    ('the-stub-claims-the-hardware-ran', _replace('SP11-PAYLOAD-TIMER.md). EXPERIMENTAL; hardware NOT RUN: nothing of it is OBSERVED on the unit.', 'SP11-PAYLOAD-TIMER.md). EXPERIMENTAL; hardware run: all of it is OBSERVED on the unit.')),
    ('the-catalogue-anchor-does-not-resolve', _replace('SP11-PAYLOAD-TIMER.md#what-it-prints', 'SP11-PAYLOAD-TIMER.md#what-it-says')),
    ('the-tests-row-forgot-the-eighth-program', _replace('eight native programs', 'seven native programs')),
    ('the-build-row-forgot-the-timer-allow-list', _replace('`timer` `MRS` of its twelve registers and no barrier; ', '')),
    ('the-licence-line-is-gone-from-the-main-document', _replace('<!-- SPDX-License-Identifier: MIT -->\n', '')),
]
DOC_MUTANTS = [(name, 'timer', mutate) for name, mutate in TIMER_DOC_MUTANTS] + [(name, 'main', mutate) for name, mutate in MAIN_DOC_MUTANTS]


class TimerDocMutants(unittest.TestCase):
    """The agreement tests above must be able to fail: each seeded mistake in either document is refused by one."""

    @staticmethod
    def outcome(timer_text=None, main_text=None):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(
            type('Changed', (TimerDocAgreement,), {'TEXT': timer_text, 'MAIN': main_text}))
        result = unittest.TestResult()
        suite.run(result)
        return result

    def test_the_unchanged_documents_pass_through_the_same_mechanism(self):
        result = self.outcome(DOC_TIMER.read_text(encoding='utf-8'), DOC.read_text(encoding='utf-8'))
        self.assertTrue(result.wasSuccessful(), [str(f[1])[-300:] for f in result.failures + result.errors])
        self.assertGreaterEqual(result.testsRun, 13)
        if lib.have('llvm-mc'):
            self.assertEqual(result.skipped, [], 'a skipped agreement test proves nothing')

    def test_every_seeded_mistake_in_either_document_is_refused(self):
        originals = {'timer': DOC_TIMER.read_text(encoding='utf-8'), 'main': DOC.read_text(encoding='utf-8')}
        self.assertGreaterEqual(len(DOC_MUTANTS), 30)
        self.assertEqual(len({name for name, _, _ in DOC_MUTANTS}), len(DOC_MUTANTS))
        self.assertTrue({which for _, which, _ in DOC_MUTANTS} == {'timer', 'main'}, 'both documents have seeded mistakes')
        for name, which, mutate in DOC_MUTANTS:
            with self.subTest(mutant=name):
                changed = mutate(originals[which])
                self.assertNotEqual(changed, originals[which])
                result = self.outcome(*((changed, None) if which == 'timer' else (None, changed)))
                self.assertFalse(result.wasSuccessful(), 'every agreement test still passed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
