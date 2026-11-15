#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The cnthctl payload of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-CNTHCTL.md): its host test, its seeded bugs, the
allow-list of its binary and its stick. The QEMU run is tools/test-q1n1-sp11-payload-qemu-cnthctl.py, the document's test
tools/test-q1n1-sp11-payload-cnthctl-doc.py.

    python3 tools/test-q1n1-sp11-payload-cnthctl.py          # the suites
    python3 tools/test-q1n1-sp11-payload-cnthctl.py facts    # size, digest and instruction inventory of the built binary

  * CnthctlNative: tools/test-q1n1-sp11-payload-cnthctl.c (six suites over a modelled machine whose CNTHCTL_EL2 can hold the bits,
    drop them as RES0, hold only one, and refuse or delay the write that puts the old value back; an independent oracle of the whole
    page, the writes and the return value; 6000 random worlds), built and run by the machinery of tools/test-q1n1-sp11-payload.py
    under ASan and UBSan.
  * CnthctlSource: what no run shows -- the ops the source calls, that the registers it names are the policy's, one MSR site, the
    monitor's own formula (read from the Snapintosh tree when SNAPINTOSH_DIR names it), that ECV is never set, that none of the
    registers that must not be touched is named, no writable global.
  * CnthctlMutants: seeded bugs in cnthctl.c, each applied to a copy of the sources and each of which the host program must reject.
  * CnthctlBinary: the allow-list applied to cnthctl.bin (five registers read, `msr cnthctl_el2` and nothing else written, ISB the
    only barrier) with seeded bad binaries and a flat binary patched so that only the encoding layer can see it, and the build's
    reproducibility.
  * CnthctlStick: the manifest tool and the runner's own validator on a stick that holds cnthctl.bin alone, and on one that also
    holds `psci` before it.

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
import concurrent.futures
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_ecv_lib as ecv  # noqa: E402

native = ecv.load_module('sp11_payload_native_for_cnthctl', ROOT / 'tools' / 'test-q1n1-sp11-payload.py')
native.BUILD = ROOT / 'build' / 'sp11-payload-cnthctl-test'
# The shared machinery knows the older payloads; this payload joins it here, in this copy of the module only.
native.PROGRAMS['cnthctl'] = ('tools/test-q1n1-sp11-payload-cnthctl.c', ['sp11-payload-text.c'], 6, 25000, 'cnthctl')
native.HOST_PAYLOADS['cnthctl'] = 'cnthctl.c'
native.PAYLOADS_COPIED = native.PAYLOADS_COPIED + ['cnthctl.c']
BUILD = native.BUILD
SOURCE = ROOT / 'payloads' / 'cnthctl.c'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-CNTHCTL.md'
READELF, run, have = ecv.READELF, lib.run, lib.have
code_of, Builder, asm, read, facts, need_tools = ecv.code_of, ecv.Builder, ecv.asm, ecv.read, ecv.facts, ecv.need_tools
SUITES = ('order', 'worlds', 'refuse', 'clock', 'fuzz', 'args')
OWN_FILES = [SOURCE, ROOT / 'tools' / 'test-q1n1-sp11-payload-cnthctl.c', ROOT / 'tools' / 'test-q1n1-sp11-payload-cnthctl.py',
             ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu-cnthctl.py', ROOT / 'tools' / 'test-q1n1-sp11-payload-cnthctl-doc.py',
             ROOT / 'tools' / 'sp11_payload_ecv_lib.py']
LINES_MAX = 11


class CnthctlNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_the_cnthctl_suites_pass(self):
        native.Native._check(self, 'cnthctl')

    def test_each_suite_runs_alone(self):
        done, binary = native.build_program('cnthctl', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite in SUITES:
            with self.subTest(suite=suite):
                code, output = native.run_program(binary, suite)
                self.assertEqual(code, 0, output)
                self.assertRegex(output, r'PASS: 1 payload cnthctl suites, \d+ checks')

    def test_the_most_lines_are_measured(self):
        done, binary = native.build_program('cnthctl', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary, 'lines-report')
        self.assertEqual(code, 0, output)
        self.assertEqual(output.strip(), f'LINES_MAX={LINES_MAX}')


class CnthctlSource(unittest.TestCase):
    code = code_of(SOURCE)

    def test_the_source_calls_only_the_counter_and_hex_ops_and_the_helpers_puts(self):
        self.assertEqual(set(re.findall(r'ops\.(\w+)', self.code)), {'counter'}, 'never load32')
        util = code_of(ROOT / 'payloads' / 'payload-util.h')
        self.assertEqual(set(re.findall(r'ops\.(\w+)', util)), {'hex', 'puts'})

    def test_the_registers_the_source_names_are_the_ones_the_policy_lists(self):
        named = {name.lower() for name in re.findall(r'SYSREG\((\w+)\)', self.code)} - {'name'}
        self.assertEqual(named, lib.POLICIES['cnthctl']['registers'])

    def test_the_registers_that_must_not_be_touched_are_not_named_in_code(self):
        for forbidden in ('CNTPOFF', 'S3_4_C14_C0_6', 'CNTVOFF', 'S3_4_C14_C0_3', 'CNTKCTL', 'CNTV_CTL', 'CNTP_CTL', 'CNTVCT', 'CNTPCT'):
            with self.subTest(register=forbidden):
                self.assertNotIn(forbidden, self.code.upper())

    def test_there_is_one_msr_one_isb_and_it_writes_cnthctl_el2(self):
        self.assertEqual(re.findall(r'"(msr[^"]*)"', self.code), ['msr cnthctl_el2, %0'])
        self.assertEqual(self.code.count('"isb"'), 1)
        for mnemonic in ('smc', 'hvc', 'svc', 'eret', 'wfi', 'wfe', 'dsb', 'dmb', 'sev', 'tlbi', 'dc ', 'ic ', ' at '):
            self.assertNotIn(f'"{mnemonic}', self.code)
        self.assertEqual(len(re.findall(r'\bwrite_cnthctl_el2\(', self.code)) - 1, 3, 'the value, OLD, and the one retry')

    def test_the_value_is_the_monitors_formula_and_ecv_is_never_set(self):
        self.assertIn('p.wanted = (p.old & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;', self.code)
        for define, value in (('EL1_PHYSICAL_BITS', 'UINT64_C(3)'), ('EL1TVT_BIT', '(UINT64_C(1) << 13)'), ('EL1TVCT_BIT', '(UINT64_C(1) << 14)'),
                              ('ECV_BIT', '(UINT64_C(1) << 12)'), ('WAIT_BEFORE_WRITE_S', '8u')):
            self.assertIn(f'#define {define} {value}', self.code)
        self.assertEqual(len(re.findall(r'\bECV_BIT\b', self.code)), 2, 'defined, and one of the bits an OLD may not have set')
        self.assertIn('say(a, "NEXT CNTHCTL_EL2 WRITE AFTER 8 S");', self.code)

    def test_the_formula_is_the_one_in_the_monitors_source(self):
        tree = os.environ.get('SNAPINTOSH_DIR')
        path = Path(tree) / 'probes' / 'xnuboot' / 'prepare.c' if tree else None
        if not path or not path.is_file():
            self.skipTest('SNAPINTOSH_DIR does not name a Snapintosh tree: the monitor source is not compared')
        text = path.read_text(encoding='utf-8')
        self.assertIn('guest_cnthctl = (vcpu_of(c)->save_cnthctl & ~3UL) | (1UL<<14) | (1UL<<13);', text)
        self.assertIn('msr cnthctl_el2, %0; isb', text)

    def test_no_writable_global_and_every_table_is_constant(self):
        for declaration in re.findall(r'^static\b[^\n(]*;', self.code, re.M):
            self.assertRegex(declaration, r'\bconst\b|\binline\b', declaration)
        self.assertEqual(re.findall(r'^static (?!const|inline|__attribute__)[^\n(]*$', self.code, re.M), [])

    def test_the_files_are_within_the_size_limits(self):
        for path in OWN_FILES:
            if not path.exists():
                continue
            with self.subTest(file=path.name):
                text = path.read_text(encoding='utf-8')
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                self.assertIn('SPDX-License-Identifier: MIT', text[:200])


# ---- seeded bugs in cnthctl.c ----------------------------------------------------------------------------------------------

FILE = 'payloads/cnthctl.c'
FORMULA = '    p.wanted = (p.old & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;\n'
NEXT_LINE = '    say(a, "NEXT CNTHCTL_EL2 WRITE AFTER 8 S");\n'
WAIT = '    if (!wait_seconds(a, hz, WAIT_BEFORE_WRITE_S)) {\n        say(a, "REFUSED=COUNTER_STUCK");\n        return 0;\n    }\n'
FIRST_WRITE = '    write_cnthctl_el2(p->wanted);\n    isb();\n    p->read_back = read_cnthctl_el2();\n'
RESTORE = '    write_cnthctl_el2(p->old);\n    isb();\n    p->restored = read_cnthctl_el2();\n'
RETRY = '        write_cnthctl_el2(p->old);\n        isb();\n        p->after_retry = read_cnthctl_el2();\n        p->retried = 1;\n'


def sub(name, old, new):
    return ('cnthctl-' + name, FILE, [(old, new)], ['cnthctl'], None)


def drop(name, statement):
    return sub(name, statement, '')


MUTANTS = [
    # -- the value: the monitor's formula
    sub('clears-no-el1-physical-bit', FORMULA, '    p.wanted = p.old | EL1TVCT_BIT | EL1TVT_BIT;\n'),
    sub('clears-only-bit-0', '#define EL1_PHYSICAL_BITS UINT64_C(3)', '#define EL1_PHYSICAL_BITS UINT64_C(1)'),
    sub('clears-bits-3-to-0', '#define EL1_PHYSICAL_BITS UINT64_C(3)', '#define EL1_PHYSICAL_BITS UINT64_C(15)'),
    sub('sets-ecv-as-well', FORMULA, '    p.wanted = (p.old & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT | ECV_BIT;\n'),
    sub('sets-only-bit-14', FORMULA, '    p.wanted = (p.old & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT;\n'),
    sub('sets-only-bit-13', FORMULA, '    p.wanted = (p.old & ~EL1_PHYSICAL_BITS) | EL1TVT_BIT;\n'),
    sub('bit-13-is-bit-15', '#define EL1TVT_BIT (UINT64_C(1) << 13)', '#define EL1TVT_BIT (UINT64_C(1) << 15)'),
    sub('bit-14-is-bit-16', '#define EL1TVCT_BIT (UINT64_C(1) << 14)', '#define EL1TVCT_BIT (UINT64_C(1) << 16)'),
    sub('drops-the-rest-of-old', FORMULA, '    p.wanted = EL1TVCT_BIT | EL1TVT_BIT;\n'),
    # -- the restore
    sub('never-restores', RESTORE, '    p->restored = read_cnthctl_el2();\n'),
    sub('restores-the-value-under-test', RESTORE, '    write_cnthctl_el2(p->wanted);\n    isb();\n    p->restored = read_cnthctl_el2();\n'),
    sub('restores-what-it-read-back', RESTORE, '    write_cnthctl_el2(p->read_back);\n    isb();\n    p->restored = read_cnthctl_el2();\n'),
    sub('restores-zero', RESTORE, '    write_cnthctl_el2(0);\n    isb();\n    p->restored = read_cnthctl_el2();\n'),
    sub('never-retries', '    if (p->restored != p->old) {\n', '    if (0) {\n'),
    sub('always-retries', '    if (p->restored != p->old) {\n', '    if (1) {\n'),
    sub('retries-twice', RETRY, RETRY + '        write_cnthctl_el2(p->old);\n        isb();\n        p->after_retry = read_cnthctl_el2();\n'),
    sub('retries-with-the-wrong-value', RETRY, RETRY.replace('write_cnthctl_el2(p->old)', 'write_cnthctl_el2(p->wanted)')),
    sub('does-not-read-after-the-retry', RETRY, '        write_cnthctl_el2(p->old);\n        isb();\n        p->retried = 1;\n'),
    # -- barriers and order inside the window
    sub('no-isb-after-the-first-write', FIRST_WRITE, '    write_cnthctl_el2(p->wanted);\n    p->read_back = read_cnthctl_el2();\n'),
    sub('no-isb-after-the-restore', RESTORE, '    write_cnthctl_el2(p->old);\n    p->restored = read_cnthctl_el2();\n'),
    sub('no-isb-after-the-retry', RETRY, '        write_cnthctl_el2(p->old);\n        p->after_retry = read_cnthctl_el2();\n        p->retried = 1;\n'),
    sub('reads-before-the-isb', FIRST_WRITE, '    write_cnthctl_el2(p->wanted);\n    p->read_back = read_cnthctl_el2();\n    isb();\n'),
    sub('reads-another-register-inside-the-window', FIRST_WRITE, FIRST_WRITE + '    (void)SYSREG(hcr_el2);\n'),
    sub('reads-cntpoff-el2', '    p.old = read_cnthctl_el2();\n', '    p.old = read_cnthctl_el2();\n    (void)SYSREG(S3_4_C14_C0_6);\n'),
    sub('reads-cntvoff-el2', '    p.old = read_cnthctl_el2();\n', '    p.old = read_cnthctl_el2();\n    (void)SYSREG(S3_4_C14_C0_3);\n'),
    # -- announce, wait, then the write
    sub('waits-one-second-not-eight', '#define WAIT_BEFORE_WRITE_S 8u', '#define WAIT_BEFORE_WRITE_S 1u'),
    sub('waits-eighty-seconds', '#define WAIT_BEFORE_WRITE_S 8u', '#define WAIT_BEFORE_WRITE_S 80u'),
    sub('does-not-wait', WAIT, '    if (0) {\n        say(a, "REFUSED=COUNTER_STUCK");\n        return 0;\n    }\n'),
    sub('writes-before-the-wait', NEXT_LINE + WAIT + '    write_and_restore(&p);\n', '    write_and_restore(&p);\n' + NEXT_LINE + WAIT),
    sub('announces-after-the-wait', NEXT_LINE + WAIT, WAIT + NEXT_LINE),
    drop('never-announces', NEXT_LINE),
    sub('waits-at-a-fixed-19-2-mhz', 'if (now - start >= hz * seconds) return 1;', 'if (now - start >= 19200000u * seconds) return 1;'),
    sub('does-not-bound-the-frequency', 'hz = cntfrq >= COUNTER_HZ_MIN && cntfrq <= COUNTER_HZ_MAX ? cntfrq : COUNTER_HZ_DEFAULT;', 'hz = cntfrq;'),
    sub('frequency-lower-bound-is-one-too-high', '#define COUNTER_HZ_MIN 1000000u', '#define COUNTER_HZ_MIN 1000001u'),
    sub('frequency-upper-bound-excludes-one-ghz', 'cntfrq <= COUNTER_HZ_MAX ?', 'cntfrq < COUNTER_HZ_MAX ?'),
    sub('waits-one-read-too-long', 'if (now - start >= hz * seconds) return 1;', 'if (now - start > hz * seconds) return 1;'),
    sub('counts-from-zero-not-from-the-first-read', 'if (now - start >= hz * seconds) return 1;', 'if (now >= hz * seconds) return 1;'),
    sub('gives-up-on-a-slow-counter', '#define COUNTER_STUCK_READS 2000000u', '#define COUNTER_STUCK_READS 20u'),
    sub('waits-ten-times-as-long-for-a-stuck-counter', '#define COUNTER_STUCK_READS 2000000u', '#define COUNTER_STUCK_READS 20000000u'),
    sub('goes-on-with-a-stuck-counter', WAIT, '    wait_seconds(a, hz, WAIT_BEFORE_WRITE_S);\n    if (0) {\n        say(a, "REFUSED=COUNTER_STUCK");\n        return 0;\n    }\n'),
    # -- what it refuses
    drop('does-not-check-the-arguments', '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n'),
    sub('runs-at-any-el', 'if ((current_el >> 2 & 3) != 2) {', 'if (0) {'),
    sub('takes-el3-for-el2', 'if ((current_el >> 2 & 3) != 2) {', 'if ((current_el >> 2 & 3) < 2) {'),
    sub('does-not-check-for-the-counter-op', '    if (!a->ops.counter) {\n', '    if (0) {\n'),
    sub('does-not-refuse-e2h', '    if (hcr >> 34 & 1) {\n', '    if (0) {\n'),
    sub('e2h-is-bit-33', '    if (hcr >> 34 & 1) {\n', '    if (hcr >> 33 & 1) {\n'),
    sub('does-not-refuse-an-old-with-bits-set', '    if (p.old & OLD_REFUSED_BITS) {\n', '    if (0) {\n'),
    sub('refuses-only-an-old-with-ecv-set', '#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT)', '#define OLD_REFUSED_BITS (ECV_BIT)'),
    sub('refuses-an-old-with-bit-15-set', '#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT)', '#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT | (UINT64_C(1) << 15))'),
    # -- the page and the verdict
    sub('reports-the-stuck-bits-from-the-value-written', 'unsigned stuck = (unsigned)(p->read_back >> 13 & 1) + (unsigned)(p->read_back >> 14 & 1);',
        'unsigned stuck = (unsigned)(p->wanted >> 13 & 1) + (unsigned)(p->wanted >> 14 & 1);'),
    sub('reports-one-bit-as-yes', 'stuck == 2 ? "BITS13_14_STUCK=YES"', 'stuck >= 1 ? "BITS13_14_STUCK=YES"'),
    sub('reports-one-bit-as-no', 'stuck == 0 ? "BITS13_14_STUCK=NO" : "BITS13_14_STUCK=PARTIAL"', 'stuck <= 1 ? "BITS13_14_STUCK=NO" : "BITS13_14_STUCK=PARTIAL"'),
    sub('reports-no-bit-as-partial', 'stuck == 0 ? "BITS13_14_STUCK=NO" : "BITS13_14_STUCK=PARTIAL"', 'stuck == 3 ? "BITS13_14_STUCK=NO" : "BITS13_14_STUCK=PARTIAL"'),
    sub('says-the-read-back-is-the-value', 'p->read_back == p->wanted ? " R_EQ_V=YES"', '1 ? " R_EQ_V=YES"'),
    sub('says-restored-from-the-first-read', '    if (p->after_retry == p->old) {\n        say(a, "RESTORED=YES");', '    if (p->restored == p->old) {\n        say(a, "RESTORED=YES");'),
    sub('says-restored-without-looking', '    if (p->after_retry == p->old) {\n        say(a, "RESTORED=YES");', '    if (1) {\n        say(a, "RESTORED=YES");'),
    drop('does-not-shout-that-it-could-not-restore', '    say(a, "POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD");\n'),
    sub('returns-zero-when-it-could-not-restore', 'return p.after_retry == p.old ? 0 : RET_NOT_RESTORED;', 'return 0;'),
    sub('returns-nonzero-when-it-restored', 'return p.after_retry == p.old ? 0 : RET_NOT_RESTORED;', 'return RET_NOT_RESTORED;'),
    sub('prints-ecv-from-the-wrong-field', 'field(a, &line, "ECV", mmfr0 >> 60 & 15);', 'field(a, &line, "ECV", mmfr0 >> 56 & 15);'),
    sub('prints-the-new-value-as-old', '    field(a, &line, "OLD", p->old);\n    field(a, &line, "V", p->wanted);\n', '    field(a, &line, "OLD", p->wanted);\n    field(a, &line, "V", p->wanted);\n'),
    sub('prints-the-first-read-as-the-second', '    field(a, &line, "R2", p->restored);\n', '    field(a, &line, "R2", p->read_back);\n'),
]


class CnthctlMutants(unittest.TestCase):
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
        self.assertGreaterEqual(len(names), 50)
        self.assertEqual({m[1] for m in MUTANTS}, {FILE})
        for wanted in ('clears-no-el1-physical-bit', 'sets-ecv-as-well', 'never-restores', 'never-retries', 'retries-twice', 'no-isb-after-the-first-write',
                       'waits-one-second-not-eight', 'does-not-wait', 'writes-before-the-wait', 'announces-after-the-wait', 'never-announces',
                       'runs-at-any-el', 'does-not-refuse-e2h', 'does-not-refuse-an-old-with-bits-set', 'goes-on-with-a-stuck-counter',
                       'returns-zero-when-it-could-not-restore', 'reads-cntpoff-el2', 'reads-another-register-inside-the-window'):
            self.assertIn(f'cnthctl-{wanted}', names)

    def test_the_unmutated_control_passes_from_a_copy(self):
        directory = BUILD / 'control'
        native.copy_tree(directory)
        done, binary = self._build('cnthctl', directory, relaxed=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary)
        self.assertEqual(code, 0, output[-600:])

    def test_every_seeded_bug_is_caught(self):
        workers = max(1, min(4, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {m[0]: pool.submit(self._evaluate, *m) for m in MUTANTS}
            results = {name: future.result() for name, future in futures.items()}
        for name, (status, detail) in results.items():
            with self.subTest(mutant=name):
                self.assertEqual(status, 'caught', f'{status}: {detail}')


# ---- the binary ------------------------------------------------------------------------------------------------------------

BAD_BINARIES = [
    # (name, [(needle, replacement)], what the allow-list check must say)
    ('a-read-of-cntpoff-el2', read('S3_4_C14_C0_6'), 'the code names'),
    ('a-write-to-cntpoff-el2', asm('msr S3_4_C14_C0_6, xzr'), 'the code names'),
    ('a-read-of-cntvoff-el2', read('S3_4_C14_C0_3'), 'the code names'),
    ('a-read-of-cntvoff-el2-by-name', read('cntvoff_el2'), 'the code names'),
    ('a-write-to-cntvoff-el2', asm('msr cntvoff_el2, xzr'), 'forbidden instruction msr cntvoff_el2'),
    ('a-write-to-cntkctl-el1', asm('msr cntkctl_el1, xzr'), 'forbidden instruction msr cntkctl_el1'),
    ('a-write-to-hcr-el2', asm('msr hcr_el2, xzr'), 'forbidden instruction msr hcr_el2'),
    ('a-write-to-sctlr-el2', asm('msr sctlr_el2, xzr'), 'forbidden instruction msr sctlr_el2'),
    ('a-write-to-vbar-el2', asm('msr vbar_el2, xzr'), 'forbidden instruction msr vbar_el2'),
    ('a-write-to-elr-el2', asm('msr elr_el2, xzr'), 'forbidden instruction msr elr_el2'),
    ('a-write-to-spsr-el2', asm('msr spsr_el2, xzr'), 'forbidden instruction msr spsr_el2'),
    ('a-write-to-sctlr-el1', asm('msr sctlr_el1, xzr'), 'forbidden instruction msr sctlr_el1'),
    ('a-write-to-vbar-el1', asm('msr vbar_el1, xzr'), 'forbidden instruction msr vbar_el1'),
    ('a-write-to-cnthp-ctl-el2', asm('msr cnthp_ctl_el2, xzr'), 'forbidden instruction msr cnthp_ctl_el2'),
    ('a-write-to-daifclr', asm('msr daifclr, #15'), 'forbidden instruction msr daifclr'),
    ('a-write-to-daifset', asm('msr daifset, #15'), 'forbidden instruction msr daifset'),
    ('a-write-to-spsel', asm('msr spsel, #1'), 'forbidden instruction msr spsel'),
    ('a-read-of-an-unlisted-register', read('ttbr0_el2'), 'registers read'),
    ('a-read-of-the-virtual-counter', read('CNTVCT_EL0'), 'registers read'),
    ('a-read-of-the-physical-counter', read('CNTPCT_EL0'), 'registers read'),
    ('a-read-of-the-virtual-timer-control', read('CNTV_CTL_EL0'), 'registers read'),
    ('an-smc', asm('smc #0'), '1 smc instructions'),
    ('an-hvc', asm('hvc #0'), 'hvc'),
    ('an-svc', asm('svc #0'), 'svc'),
    ('an-eret', asm('eret'), 'eret'),
    ('a-wfi', asm('wfi'), 'wfi'),
    ('a-wfe', asm('wfe'), 'forbidden instruction wfe'),
    ('an-sev', asm('sev'), 'sev'),
    ('a-dsb', asm('dsb sy'), 'dsb'),
    ('a-dmb', asm('dmb sy'), 'dmb'),
    ('a-tlb-operation', asm('tlbi alle2'), 'tlbi'),
    ('an-instruction-cache-operation', asm('ic iallu'), 'forbidden instruction ic'),
    ('a-data-cache-operation', asm('dc civac, x0'), 'forbidden instruction dc'),
    ('an-address-translation', asm('at s1e2r, x0'), 'forbidden instruction at'),
    ('an-exclusive-load', asm('ldxr x9, [sp]'), 'ldxr'),
    ('an-atomic-add', asm('.arch_extension lse\\n ldadd x9, x10, [sp]'), 'ldadd'),
    ('a-word-that-is-no-instruction', asm('.inst 0xffffffff'), 'not a known instruction'),
]


class CnthctlBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.out = BUILD / 'bad-binaries'
        cls.builder = Builder(cls.out)
        done, cls.elf, cls.flat = cls.builder.build('cnthctl', 'control', [], check=True)
        if done.returncode:
            raise RuntimeError(done.stderr[-1500:])

    def test_the_unmodified_payload_is_clean_and_fits_the_policy(self):
        policy = lib.POLICIES['cnthctl']
        self.assertEqual(lib.binary_violations(self.elf, self.flat, policy, READELF()), [])
        self.assertEqual(policy['allow'], {'msr': {'cnthctl_el2'}})
        self.assertEqual(policy['smc'], 0)
        self.assertGreaterEqual(policy['forbid'], {'dsb', 'dmb', 'sb', 'sev', 'sevl'})
        self.assertNotIn('isb', policy['forbid'])
        self.assertFalse({'smc_ids', 'single_reads', 'timer_offsets'} & set(policy))
        self.assertEqual(policy['registers'], {'currentel', 'hcr_el2', 'id_aa64mmfr0_el1', 'cntfrq_el0', 'cnthctl_el2'})
        self.assertLessEqual(Path(self.flat).stat().st_size, policy['bytes'])

    def test_the_instruction_inventory_is_what_the_document_says(self):
        f = facts(self.elf, self.flat)
        self.assertEqual(set(f['mrs']), lib.POLICIES['cnthctl']['registers'])
        self.assertEqual(dict(f['msr']), {'cnthctl_el2': 1}, 'one MSR site, CNTHCTL_EL2')
        self.assertEqual(f['mnemonics']['isb'], 1, 'one ISB site, called after each of the three writes')
        for mnemonic in ('smc', 'hvc', 'svc', 'eret', 'wfi', 'wfe', 'sev', 'sevl', 'dsb', 'dmb', 'sb', 'tlbi', 'ic', 'dc', 'at', 'sys', 'sysl', 'brk', 'hlt'):
            self.assertEqual(f['mnemonics'][mnemonic], 0, mnemonic)
        self.assertFalse([m for m in f['mnemonics'] if re.match(r'^(ldx|ldax|stx|stlx|cas|swp|ldadd|ldset|ldclr|ldeor)', m)])
        self.assertEqual(f['mrs']['cnthctl_el2'], 1, 'one read site, which the three read-backs call')

    def test_every_forbidden_addition_is_named_by_the_allow_list_check(self):
        self.assertGreaterEqual(len(BAD_BINARIES), 30)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            built = list(pool.map(lambda b: (b, self.builder.build('cnthctl', b[0], b[1])), BAD_BINARIES))
        for (name, _, expected), (done, elf, flat) in built:
            with self.subTest(binary=name):
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                problems = lib.binary_violations(elf, flat, lib.POLICIES['cnthctl'], READELF())
                self.assertTrue(problems, 'the check passed a binary it must refuse')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_a_flat_binary_patched_behind_the_disassembly_is_caught_by_the_encoding_layer_alone(self):
        data = bytearray(Path(self.flat).read_bytes())
        words = struct.unpack(f'<{len(data) // 4}I', bytes(data[:len(data) // 4 * 4]))
        policy = lib.POLICIES['cnthctl']
        self.assertEqual(lib.binary_violations(self.elf, self.flat, policy, READELF()), [])
        wanted = (
            ('msr cnthctl_el2 to msr hcr_el2', lambda w: w & 0xffffffe0 == 0xd51ce100, lambda w: 0xd51c1100 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr cntvoff_el2', lambda w: w & 0xffffffe0 == 0xd51ce100, lambda w: 0xd51ce060 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr cntkctl_el1', lambda w: w & 0xffffffe0 == 0xd51ce100, lambda w: 0xd518e100 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr daifset', lambda w: w & 0xffffffe0 == 0xd51ce100, lambda w: 0xd50340df, 'msr-immediate'),
            ('isb to dsb', lambda w: w == 0xd5033fdf, lambda w: 0xd5033f9f, 'dsb'),
            ('isb to dmb', lambda w: w == 0xd5033fdf, lambda w: 0xd5033fbf, 'dmb'),
            ('isb to wfe', lambda w: w == 0xd5033fdf, lambda w: 0xd503205f, 'wfe'),
            ('isb to wfi', lambda w: w == 0xd5033fdf, lambda w: 0xd503207f, 'wfi'),
            ('isb to eret', lambda w: w == 0xd5033fdf, lambda w: 0xd69f03e0, 'eret'),
            ('isb to hvc', lambda w: w == 0xd5033fdf, lambda w: 0xd4000002, 'hvc'),
            ('isb to svc', lambda w: w == 0xd5033fdf, lambda w: 0xd4000001, 'svc'),
            ('isb to smc', lambda w: w == 0xd5033fdf, lambda w: 0xd4000003, 'smc'),
            ('isb to dc civac', lambda w: w == 0xd5033fdf, lambda w: 0xd50b7e20, 'sys'),
        )
        for label, is_target, patch, what in wanted:
            with self.subTest(patch=label):
                at = next(i for i, w in enumerate(words) if is_target(w))
                patched = bytearray(data)
                struct.pack_into('<I', patched, at * 4, patch(words[at]))
                path = self.out / 'patched.bin'
                path.write_bytes(patched)
                problems = lib.binary_violations(self.elf, path, policy, READELF())
                expected = 'words of the code encode smc' if what == 'smc' else f'a word of the code encodes {what}'
                self.assertTrue(any(expected in p for p in problems), problems)

    def test_the_binary_is_refused_under_every_other_policy_and_the_others_under_its_own(self):
        for other in ('state', 'psci', 'timer', 'usbsmmu', 'cpuon'):
            with self.subTest(policy=other):
                self.assertTrue(lib.binary_violations(self.elf, self.flat, lib.POLICIES[other], READELF()))
        out = BUILD / 'others'
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        for other in ('state', 'psci', 'timer', 'usbsmmu', 'cpuon'):
            with self.subTest(payload=other):
                done, o_elf, o_flat = lib.build_payload(ROOT / 'payloads' / f'{other}.c', out, name=other, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertTrue(lib.binary_violations(o_elf, o_flat, lib.POLICIES['cnthctl'], READELF()),
                                f'{other} passes the cnthctl policy: the policy is too loose')

    def test_the_msr_form_is_allowed_to_cnthctl_el2_alone_and_to_no_other_payload(self):
        self.assertEqual({name for name, policy in lib.POLICIES.items() if 'cnthctl_el2' in policy.get('allow', {}).get('msr', ())},
                         {'cnthctl'} | ({'el1trap'} if 'el1trap' in lib.POLICIES else set()))
        self.assertEqual(lib.ALLOW_WORDS[('msr', 'cnthctl_el2')], ('msr-register', 0xffffffe0, 0xd51ce100))

    def test_two_builds_from_the_same_tree_are_byte_identical(self):
        done, _, flat = Builder(BUILD / 'again').build('cnthctl', 'control', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(Path(flat).read_bytes(), Path(self.flat).read_bytes())
        self.assertEqual(Path(self.flat).read_bytes()[:4], bytes.fromhex('5f2403d5'), 'BTI c first, as the runner expects')


class CnthctlStick(unittest.TestCase):
    tool = ROOT / 'tools' / 'sp11_payload_manifest.py'

    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.out = BUILD / 'stick-payloads'
        shutil.rmtree(cls.out, ignore_errors=True)
        done = run(['make', '-f', 'platform/uefi/Makefile', f'OUT={cls.out.relative_to(ROOT)}', 'payloads'])
        if done.returncode:
            raise RuntimeError('make payloads failed:\n' + done.stdout[-1500:] + done.stderr[-1500:])
        cls.bins = {name: cls.out / 'payloads' / f'{name}.bin' for name in ('state', 'psci', 'cnthctl')}

    def stick(self, order):
        base = BUILD / 'stick' / '-'.join(order)
        shutil.rmtree(base, ignore_errors=True)
        done = run(['python3', '-B', str(self.tool), '--out-dir', str(base)] + [str(self.bins[name]) for name in order])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        return base, done

    def entries(self, base):
        raw = (base / 'SP11' / 'PAYLOAD.MAN').read_bytes()
        magic, version, count, size = struct.unpack_from('<4Q', raw)
        self.assertEqual(magic, int.from_bytes(b'Q1N1PLD1', 'little'))
        return [struct.unpack_from('<Q32s256s', raw, 32 + i * size) for i in range(count)]

    def test_cnthctl_alone_is_one_payload_and_the_stick_holds_the_manifest_and_the_file(self):
        base, done = self.stick(('cnthctl',))
        entries = self.entries(base)
        self.assertEqual([e[2].rstrip(b'\0').decode() for e in entries], ['\\SP11\\CNTHCTL.BIN'])
        data = self.bins['cnthctl'].read_bytes()
        self.assertEqual((entries[0][0], entries[0][1]), (len(data), hashlib.sha256(data).digest()))
        self.assertEqual(sorted(p.name for p in (base / 'SP11').iterdir()), ['CNTHCTL.BIN', 'PAYLOAD.MAN'])
        self.assertEqual((base / 'SP11' / 'CNTHCTL.BIN').read_bytes(), data)
        self.assertIn('(INDEX=0, payload, called in manifest order)', done.stdout)

    def test_the_runners_own_validator_and_loader_take_it_as_a_payload_alone_and_after_psci(self):
        harness = BUILD / 'kinds-harness'
        sources = [ROOT / 'tools' / 'testdata' / 'sp11-payload-kinds-harness.c'] + [
            native.UEFI / name for name in ('sp11-payload-load.c', 'sp11-payload-plan.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c')]
        done = run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1',
                    '-I', str(native.UEFI)] + [str(s) for s in sources] + ['-o', str(harness)])
        self.assertEqual(done.returncode, 0, done.stderr)
        for order, expected in ((('cnthctl',), ['\\SP11\\CNTHCTL.BIN code']),
                                (('psci', 'cnthctl'), ['\\SP11\\PSCI.BIN code', '\\SP11\\CNTHCTL.BIN code'])):
            with self.subTest(order=order):
                base, _ = self.stick(order)
                ours = run([str(harness), str(base / 'SP11' / 'PAYLOAD.MAN')])
                self.assertEqual(ours.returncode, 0, ours.stdout + ours.stderr)
                self.assertEqual(ours.stdout.splitlines(), expected)

    def test_the_binary_is_a_few_kilobytes_and_one_range_is_declared_whatever_its_size(self):
        self.assertLessEqual(self.bins['cnthctl'].stat().st_size, lib.POLICIES['cnthctl']['bytes'])
        self.assertGreater(self.bins['cnthctl'].stat().st_size, 1024)


def facts_main():
    need_tools()
    done, elf, flat = Builder(BUILD / 'facts').build('cnthctl', 'cnthctl', [], check=True)
    if done.returncode:
        sys.exit(done.stderr)
    f = facts(elf, flat)
    print(f'cnthctl.bin: {f["bytes"]} bytes, sha256 {f["sha256"]}, {f["instructions"]} instructions')
    print('mnemonics:', ', '.join(f'{m} {n}' for m, n in sorted(f['mnemonics'].items())))
    print('registers read:', ', '.join(f'{r} x{n}' for r, n in sorted(f['mrs'].items())))
    print('msr operands:', dict(f['msr']))
    print('allow-list violations:', lib.binary_violations(elf, flat, lib.POLICIES['cnthctl'], READELF()))


if __name__ == '__main__':
    if sys.argv[1:] == ['facts']:
        facts_main()
    else:
        sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
