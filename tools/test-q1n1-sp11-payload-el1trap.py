#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The el1trap payload of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-EL1TRAP.md): its host test, its seeded bugs, the
allow-list of its binary, the audit of its EL1 stub and vector tables, and its stick. The QEMU run is
tools/test-q1n1-sp11-payload-qemu-el1trap.py, the document's test tools/test-q1n1-sp11-payload-el1trap-doc.py.

    python3 tools/test-q1n1-sp11-payload-el1trap.py          # the suites
    python3 tools/test-q1n1-sp11-payload-el1trap.py facts    # size, digest and instruction inventory of the built binary

  * El1trapNative: tools/test-q1n1-sp11-payload-el1trap.c (nine suites over a modelled machine, a predictor and a checker of the order
    and the page, 6000 random worlds), built and run by the machinery of tools/test-q1n1-sp11-payload.py under ASan and UBSan.
  * El1trapSource: what no run shows -- the ops the source calls, the registers and MSRs it names, the constants the document gives,
    the monitor's own formula (when SNAPINTOSH_DIR names the tree), that ECV is never set, no writable global.
  * El1trapMutants: seeded bugs in el1trap.c, each applied to a copy of the sources and each of which the host program must reject.
  * El1trapBinary: the allow-list applied to el1trap.bin with seeded bad binaries and a flat binary patched so that only the encoding
    layer can see it; the encodings this payload added to the engine; the inventory of the code; the EL1 stub and both vector tables.
  * El1trapStick: the manifest tool and the runner's own validator on a stick that holds el1trap.bin alone, and after `psci`.

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

native = ecv.load_module('sp11_payload_native_for_el1trap', ROOT / 'tools' / 'test-q1n1-sp11-payload.py')
native.BUILD = ROOT / 'build' / 'sp11-payload-el1trap-test'
# The shared machinery knows the older payloads; this payload joins it here, in this copy of the module only.
native.PROGRAMS['el1trap'] = ('tools/test-q1n1-sp11-payload-el1trap.c', ['sp11-payload-text.c'], 9, 100000, 'el1trap')
native.HOST_PAYLOADS['el1trap'] = 'el1trap.c'
native.PAYLOADS_COPIED = native.PAYLOADS_COPIED + ['el1trap.c']
BUILD = native.BUILD
SOURCE = ROOT / 'payloads' / 'el1trap.c'
READELF, run, have = ecv.READELF, lib.run, lib.have
code_of, Builder, asm, read, facts, need_tools = ecv.code_of, ecv.Builder, ecv.asm, ecv.read, ecv.facts, ecv.need_tools
SUITES = ('order', 'accesses', 'ends', 'probe', 'held', 'refuse', 'clock', 'fuzz', 'args')
OWN_FILES = [SOURCE] + [ROOT / 'tools' / name for name in (
    'test-q1n1-sp11-payload-el1trap.c', 'test-q1n1-sp11-payload-el1trap.py', 'test-q1n1-sp11-payload-qemu-el1trap.py',
    'test-q1n1-sp11-payload-el1trap-doc.py', 'sp11_payload_ecv_lib.py')]
LINES_MAX = 37
POLICY = lib.POLICIES['el1trap']
OTHERS = ('state', 'psci', 'timer', 'usbsmmu', 'cpuon', 'cnthctl')


class El1trapNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_the_el1trap_suites_pass(self):
        native.Native._check(self, 'el1trap')

    def test_each_suite_runs_alone(self):
        done, binary = native.build_program('el1trap', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite in SUITES:
            with self.subTest(suite=suite):
                code, output = native.run_program(binary, suite)
                self.assertEqual(code, 0, output)
                self.assertRegex(output, r'PASS: 1 payload el1trap suites, \d+ checks')

    def test_the_most_lines_are_measured(self):
        done, binary = native.build_program('el1trap', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary, 'lines-report')
        self.assertEqual(code, 0, output)
        self.assertEqual(output.strip(), f'LINES_MAX={LINES_MAX}')


class El1trapSource(unittest.TestCase):
    code = code_of(SOURCE)

    def test_the_source_calls_only_the_counter_op_and_the_helpers_hex_and_puts(self):
        self.assertEqual(set(re.findall(r'ops\.(\w+)', self.code)), {'counter'}, 'never load32')
        self.assertEqual(set(re.findall(r'ops\.(\w+)', code_of(ROOT / 'payloads' / 'payload-util.h'))), {'hex', 'puts'})

    def test_the_registers_the_source_and_its_assembly_read_are_the_ones_the_policy_lists(self):
        named = {name.lower() for name in re.findall(r'SYSREG\((\w+)\)', self.code)} - {'name'}
        named |= {name.lower() for name in re.findall(r'mrs x\d+, (\w+)', self.code)}
        self.assertEqual(named, POLICY['registers'])

    def test_the_msrs_the_source_and_its_assembly_have_are_the_ones_the_policy_allows(self):
        named = set(re.findall(r'msr (\w+), (?:%0|x\d+)', self.code))
        self.assertEqual(named, POLICY['allow']['msr'])
        self.assertEqual(sorted(re.findall(r'(?<![\w])(hvc) #(\w+)', self.code)), [('hvc', '0'), ('hvc', '1'), ('hvc', '2')])
        for mnemonic in ('smc', 'svc', 'wfi', 'wfe', 'sev', 'dmb', 'tlbi', ' at ', 'ldxr', 'stxr', 'cas ', 'swp'):
            self.assertNotIn(f'"{mnemonic}', self.code)
            self.assertNotIn(f'    {mnemonic}', self.code.replace('\n', '\n ').replace('__asm__', ''))

    def test_the_registers_that_must_not_be_touched_are_not_named_in_code(self):
        for forbidden in ('CNTPOFF', 'S3_4_C14_C0_6', 'CNTVOFF', 'S3_4_C14_C0_3', 'CNTKCTL', 'CNTV_CVAL', 'CNTV_TVAL', 'CNTP_CTL', 'CNTP_CVAL',
                          'CNTP_TVAL', 'CNTHP', 'CNTHV', 'CNTPS', 'SP_EL1', 'SP_EL0', 'TCR_', 'TTBR', 'MAIR', 'CPTR', 'MDCR', 'SCR_EL3'):
            with self.subTest(register=forbidden):
                self.assertNotIn(forbidden, self.code.upper())

    def test_the_values_written_are_the_documents(self):
        for define, value in (('HCR_EXCURSION', '(UINT64_C(1) << 31)'), ('SCTLR_EL1_EXCURSION', 'UINT64_C(0x30500800)'),
                              ('EL1_PHYSICAL_BITS', 'UINT64_C(3)'), ('EL1TVT_BIT', '(UINT64_C(1) << 13)'), ('EL1TVCT_BIT', '(UINT64_C(1) << 14)'),
                              ('ECV_BIT', '(UINT64_C(1) << 12)'), ('WAIT_BEFORE_EXCURSION_S', '8u'), ('DEADLINE_S', '1u'), ('TRAPS_MAX', '8'),
                              ('ENTRIES_BUDGET', '8'), ('ENTRIES_FATAL', '24'), ('STACK_KEPT_BYTES', '(16u * 1024u)'), ('CACHE_STEP', '16u'),
                              ('COUNTER_STUCK_READS', '2000000u'), ('DAIF_MASKED', 'UINT64_C(0x3c0)')):
            self.assertRegex(self.code, rf'#define {define}\s+{re.escape(value)}')
        self.assertIn('r.wanted[R_CNTHCTL] = (cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;', self.code)
        self.assertIn('mov x2, #0x3c5', self.code)
        self.assertIn('mov x13, #0x3c9', self.code)
        self.assertEqual(len(re.findall(r'\bECV_BIT\b', self.code)), 3, 'defined, in OLD_REFUSED_BITS, and in the check of the read-back')
        self.assertIn('#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT)', self.code)

    def test_sctlr_el1_is_linuxs_init_value_with_the_mmu_off(self):
        bits = (29, 28, 22, 20, 11)      # LSMAOE, nTLSMD, EIS, TSCXT, EOS: INIT_SCTLR_EL1_MMU_OFF in Linux 7475ea8b5861 (facts only)
        self.assertEqual(sum(1 << b for b in bits), 0x30500800)
        tree = os.environ.get('LINUX_DIR')
        path = Path(tree) / 'arch' / 'arm64' / 'include' / 'asm' / 'sysreg.h' if tree else None
        if not path or not path.is_file():
            self.skipTest('LINUX_DIR does not name a Linux tree: INIT_SCTLR_EL1_MMU_OFF is not compared')
        text = path.read_text(encoding='utf-8', errors='replace')
        found = re.search(r'#define INIT_SCTLR_EL1_MMU_OFF\s*\\?\s*(.*?)\n\n', text, re.S)
        self.assertTrue(found)
        for name in ('LSMAOE', 'nTLSMD', 'EIS', 'TSCXT', 'EOS'):
            self.assertIn(name, found.group(1))

    def test_the_formula_is_the_one_in_the_monitors_source(self):
        tree = os.environ.get('SNAPINTOSH_DIR')
        path = Path(tree) / 'probes' / 'xnuboot' / 'prepare.c' if tree else None
        if not path or not path.is_file():
            self.skipTest('SNAPINTOSH_DIR does not name a Snapintosh tree: the monitor source is not compared')
        self.assertIn('guest_cnthctl = (vcpu_of(c)->save_cnthctl & ~3UL) | (1UL<<14) | (1UL<<13);', path.read_text(encoding='utf-8'))

    def test_no_writable_global_and_every_table_is_constant(self):
        for declaration in re.findall(r'^static\b[^\n(]*;', self.code, re.M):
            self.assertRegex(declaration, r'\bconst\b|\binline\b', declaration)
        self.assertEqual(re.findall(r'^static (?!const|inline|__attribute__)[^\n(]*$', self.code, re.M), [])
        self.assertNotIn('.data', self.code)
        self.assertNotIn('.bss', self.code)

    def test_the_files_are_within_the_size_limits(self):
        for path in OWN_FILES:
            if not path.exists():
                continue
            with self.subTest(file=path.name):
                text = path.read_text(encoding='utf-8')
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                self.assertIn('SPDX-License-Identifier: MIT', text[:200])


# ---- seeded bugs in el1trap.c ----------------------------------------------------------------------------------------------

FILE = 'payloads/el1trap.c'
WRITES = ('    write_vbar_el1(r->wanted[R_VBAR1]);\n    write_sctlr_el1(r->wanted[R_SCTLR]);\n    write_cnthctl_el2(r->wanted[R_CNTHCTL]);\n'
          '    write_hcr_el2(r->wanted[R_HCR]);\n    isb();\n')
RESTORE = ('    for (unsigned i = 0; i <= R_VBAR1; i++) write_register(i, r->saved[i]);    /* HCR_EL2 first: the reverse of the order it was set in */\n'
           '    isb();\n')
RETRY = '        write_register(i, r->saved[i]);\n        isb();\n        w->restored[i] = read_register(i);\n        w->retried |= 1u << i;\n'
PROBE = '    prepare(&r, &w.probe, MODE_PROBE);\n    RUN(&w.probe, EL1_STUB);\n    w.probe_done = 1;\n'
VBAR2_RETRY = ('    if (w.restored[R_VBAR2] != r.saved[R_VBAR2]) {      /* el1trap_run puts it back; one more write if that did not hold */\n'
               '        write_register(R_VBAR2, r.saved[R_VBAR2]);\n        isb();\n        w.restored[R_VBAR2] = read_register(R_VBAR2);\n'
               '        w.retried |= 1u << R_VBAR2;\n    }\n')
NEXT_AFTER = '    say(&r.out, "NEXT EL1 EXCURSION AFTER 8 S");\n'
WAIT = '    if (!wait_seconds(a, r.hz, WAIT_BEFORE_EXCURSION_S)) {\n        say(&r.out, "REFUSED=COUNTER_STUCK");\n        return 0;\n    }\n'
NEXT = '    say(&r.out, "NEXT EL1 EXCURSION");\n'
CLEAN = '    for (uint64_t at = start & ~(uint64_t)(CACHE_STEP - 1); at < start + bytes; at += CACHE_STEP) dc_civac(at);\n'
INVALIDATE = '    for (uint64_t at = start & ~(uint64_t)(CACHE_STEP - 1); at < start + bytes; at += CACHE_STEP) ic_ivau(at);\n'
HCR_CHECKED = '#define HCR_BITS_CHECKED ((UINT64_C(1) << 31) | (UINT64_C(1) << 34) | (UINT64_C(1) << 27) | (UINT64_C(1) << 29) | UINT64_C(1) | \\\n'
SCTLR_CHECKED = ('#define SCTLR_EL1_BITS_CHECKED (UINT64_C(0x1) | UINT64_C(0x2) | UINT64_C(0x4) | UINT64_C(0x1000) | UINT64_C(0x80000) | '
                 'UINT64_C(0x1000000) | \\\n')


def sub(name, old, new):
    return ('el1trap-' + name, FILE, [(old, new)], ['el1trap'], None)


def drop(name, statement):
    return sub(name, statement, '')


def hcr_bit(name, old):
    return sub(f'hcr-check-misses-{name}', HCR_CHECKED, HCR_CHECKED.replace(old, '', 1))


def sctlr_bit(name, old):
    return sub(f'sctlr-check-misses-{name}', SCTLR_CHECKED, SCTLR_CHECKED.replace(old, '', 1))


MUTANTS = [
    # -- the values the excursion writes
    sub('hcr-also-sets-tge', '#define HCR_EXCURSION (UINT64_C(1) << 31)', '#define HCR_EXCURSION ((UINT64_C(1) << 31) | (UINT64_C(1) << 27))'),
    sub('hcr-also-sets-imo', '#define HCR_EXCURSION (UINT64_C(1) << 31)', '#define HCR_EXCURSION ((UINT64_C(1) << 31) | (UINT64_C(1) << 4))'),
    sub('hcr-also-sets-hcd', '#define HCR_EXCURSION (UINT64_C(1) << 31)', '#define HCR_EXCURSION ((UINT64_C(1) << 31) | (UINT64_C(1) << 29))'),
    sub('hcr-also-sets-e2h', '#define HCR_EXCURSION (UINT64_C(1) << 31)', '#define HCR_EXCURSION ((UINT64_C(1) << 31) | (UINT64_C(1) << 34))'),
    sub('hcr-without-rw', '#define HCR_EXCURSION (UINT64_C(1) << 31)', '#define HCR_EXCURSION UINT64_C(0)'),
    sub('sctlr-sets-the-mmu', 'UINT64_C(0x30500800)', 'UINT64_C(0x30500801)'),
    sub('sctlr-sets-the-data-cache', 'UINT64_C(0x30500800)', 'UINT64_C(0x30500804)'),
    sub('sctlr-sets-the-instruction-cache', 'UINT64_C(0x30500800)', 'UINT64_C(0x30501800)'),
    sub('sctlr-sets-span-as-well', 'UINT64_C(0x30500800)', 'UINT64_C(0x30D00800)'),
    sub('cnthctl-keeps-the-el1-physical-bits', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;', 'cnthctl | EL1TVCT_BIT | EL1TVT_BIT;'),
    sub('cnthctl-clears-only-bit-0', '#define EL1_PHYSICAL_BITS UINT64_C(3)', '#define EL1_PHYSICAL_BITS UINT64_C(1)'),
    sub('cnthctl-sets-ecv-as-well', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT | ECV_BIT;'),
    sub('cnthctl-sets-only-bit-14', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT;'),
    sub('cnthctl-sets-only-bit-13', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;', '(cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVT_BIT;'),
    sub('cnthctl-bit-13-is-bit-15', '#define EL1TVT_BIT (UINT64_C(1) << 13)', '#define EL1TVT_BIT (UINT64_C(1) << 15)'),
    sub('vbar-el1-is-the-el2-table', '    r.wanted[R_VBAR1] = EL1_VECTORS;\n', '    r.wanted[R_VBAR1] = EL2_VECTORS;\n'),
    # -- the order of the writes, the barriers, the read-back, the put-back
    sub('hcr-is-written-first', WRITES, '    write_hcr_el2(r->wanted[R_HCR]);\n    write_vbar_el1(r->wanted[R_VBAR1]);\n    write_sctlr_el1(r->wanted[R_SCTLR]);\n'
                                        '    write_cnthctl_el2(r->wanted[R_CNTHCTL]);\n    isb();\n'),
    sub('cnthctl-is-written-before-sctlr', WRITES, '    write_vbar_el1(r->wanted[R_VBAR1]);\n    write_cnthctl_el2(r->wanted[R_CNTHCTL]);\n'
                                                   '    write_sctlr_el1(r->wanted[R_SCTLR]);\n    write_hcr_el2(r->wanted[R_HCR]);\n    isb();\n'),
    sub('no-isb-before-the-read-back', WRITES, WRITES.replace('    isb();\n', '')),
    sub('no-isb-after-the-put-back', RESTORE, RESTORE.replace('    isb();\n', '')),
    sub('puts-back-in-the-order-set', RESTORE, '    for (unsigned i = R_VBAR1 + 1; i > 0; i--) write_register(i - 1, r->saved[i - 1]);\n    isb();\n'),
    sub('never-puts-vbar-el1-back', RESTORE, RESTORE.replace('i <= R_VBAR1', 'i < R_VBAR1')),
    sub('never-retries', '        if (w->restored[i] == r->saved[i]) continue;\n        write_register(i, r->saved[i]);\n',
        '        if (1) continue;\n        write_register(i, r->saved[i]);\n'),
    sub('always-retries', '        if (w->restored[i] == r->saved[i]) continue;\n        write_register(i, r->saved[i]);\n',
        '        if (0) continue;\n        write_register(i, r->saved[i]);\n'),
    sub('retries-without-an-isb', RETRY, RETRY.replace('        isb();\n', '')),
    sub('retries-with-the-value-under-test', RETRY, RETRY.replace('write_register(i, r->saved[i]);', 'write_register(i, r->wanted[i % 4]);')),
    sub('does-not-read-after-the-retry', RETRY, RETRY.replace('        w->restored[i] = read_register(i);\n', '')),
    sub('runs-without-checking-the-writes', '    w->held = (uint32_t)writes_held(r, w->readback);\n', '    w->held = 1;\n'),
    sub('never-runs', '    if (w->held) {\n', '    if (0) {\n'),
    sub('reads-the-registers-back-before-writing', WRITES + '    for (unsigned i = 0; i < R_VBAR2; i++) w->readback[i] = read_register(i);\n',
        '    for (unsigned i = 0; i < R_VBAR2; i++) w->readback[i] = read_register(i);\n' + WRITES),
    sub('reads-another-register-inside-the-window', '    w->held = (uint32_t)writes_held(r, w->readback);\n',
        '    w->held = (uint32_t)writes_held(r, w->readback);\n    (void)SYSREG(esr_el2);\n'),
    # -- the held check: each bit that decides whether EL1 can be entered
    sub('ignores-hcr-in-the-held-check', '    return (readback[R_HCR] & HCR_BITS_CHECKED) == (r->wanted[R_HCR] & HCR_BITS_CHECKED) &&\n', '    return 1 &&\n'),
    sub('ignores-sctlr-in-the-held-check', '           (readback[R_SCTLR] & SCTLR_EL1_BITS_CHECKED) == (r->wanted[R_SCTLR] & SCTLR_EL1_BITS_CHECKED) &&\n', '           1 &&\n'),
    sub('ignores-vbar-in-the-held-check', '           readback[R_VBAR1] == r->wanted[R_VBAR1] && !(readback[R_CNTHCTL] & ECV_BIT);', '           !(readback[R_CNTHCTL] & ECV_BIT);'),
    sub('ignores-ecv-in-the-held-check', '           readback[R_VBAR1] == r->wanted[R_VBAR1] && !(readback[R_CNTHCTL] & ECV_BIT);', '           readback[R_VBAR1] == r->wanted[R_VBAR1];'),
    sub('hcr-check-misses-rw', HCR_CHECKED, HCR_CHECKED.replace('((UINT64_C(1) << 31) | ', '(', 1)),
    hcr_bit('e2h', '(UINT64_C(1) << 34) | '),
    hcr_bit('tge', '(UINT64_C(1) << 27) | '),
    hcr_bit('hcd', '(UINT64_C(1) << 29) | '),
    hcr_bit('vm', 'UINT64_C(1) | \\\n'),
    sub('hcr-check-misses-fmo', '(UINT64_C(7) << 3))        /* RW, E2H', '(UINT64_C(6) << 3))        /* RW, E2H'),
    sub('hcr-check-misses-imo', '(UINT64_C(7) << 3))        /* RW, E2H', '(UINT64_C(5) << 3))        /* RW, E2H'),
    sub('hcr-check-misses-amo', '(UINT64_C(7) << 3))        /* RW, E2H', '(UINT64_C(3) << 3))        /* RW, E2H'),
    sctlr_bit('m', 'UINT64_C(0x1) | '),
    sctlr_bit('a', 'UINT64_C(0x2) | '),
    sctlr_bit('c', 'UINT64_C(0x4) | '),
    sctlr_bit('i', 'UINT64_C(0x1000) | '),
    sctlr_bit('wxn', 'UINT64_C(0x80000) | '),
    sctlr_bit('e0e', 'UINT64_C(0x1000000) | \\\n'),
    sub('sctlr-check-misses-ee', '| \\\n                                UINT64_C(0x2000000))', ')'),
    # -- the probe
    drop('never-probes', PROBE),
    sub('probe-is-an-excursion', 'prepare(&r, &w.probe, MODE_PROBE);', 'prepare(&r, &w.probe, MODE_EXCURSION);'),
    sub('ignores-a-failed-probe', '    if (!w.probe.probe_ok || w.probe.reason || w.restored[R_VBAR2] != r.saved[R_VBAR2]) {\n', '    if (0) {\n'),
    sub('ignores-vbar-el2-that-is-not-back', ' || w.restored[R_VBAR2] != r.saved[R_VBAR2]) {\n        row(&line);\n        word(&line, "HVC_AT_EL2=FAILED");', ') {\n        row(&line);\n        word(&line, "HVC_AT_EL2=FAILED");'),
    drop('does-not-put-vbar-el2-back-after-the-probe', VBAR2_RETRY),
    sub('probe-failure-says-restored-without-looking', '        for (unsigned i = 0; i < R_VBAR2; i++) w.restored[i] = r.saved[i];     /* nothing but VBAR_EL2 was ever changed */\n',
        '        for (unsigned i = 0; i < R_COUNT; i++) w.restored[i] = r.saved[i];\n'),
    # -- announce, wait, then the work
    drop('never-announces-the-wait', NEXT_AFTER),
    drop('never-announces-the-excursion', NEXT),
    sub('announces-the-excursion-after-the-window', NEXT + '\n    excursion_window(&r, &w);\n', '\n    excursion_window(&r, &w);\n' + NEXT),
    sub('waits-before-announcing', NEXT_AFTER + WAIT, WAIT + NEXT_AFTER),
    sub('does-not-wait', WAIT, '    if (0) {\n        say(&r.out, "REFUSED=COUNTER_STUCK");\n        return 0;\n    }\n'),
    sub('goes-on-with-a-stuck-counter', WAIT, '    wait_seconds(a, r.hz, WAIT_BEFORE_EXCURSION_S);\n'),
    sub('waits-one-second-not-eight', '#define WAIT_BEFORE_EXCURSION_S 8u', '#define WAIT_BEFORE_EXCURSION_S 1u'),
    sub('waits-eighty-seconds', '#define WAIT_BEFORE_EXCURSION_S 8u', '#define WAIT_BEFORE_EXCURSION_S 80u'),
    sub('waits-at-a-fixed-19-2-mhz', 'if (now - start >= hz * seconds) return 1;', 'if (now - start >= 19200000u * seconds) return 1;'),
    sub('does-not-bound-the-frequency', 'r.hz = cntfrq >= COUNTER_HZ_MIN && cntfrq <= COUNTER_HZ_MAX ? cntfrq : COUNTER_HZ_DEFAULT;', 'r.hz = cntfrq;'),
    sub('frequency-lower-bound-is-one-too-high', '#define COUNTER_HZ_MIN 1000000u', '#define COUNTER_HZ_MIN 1000001u'),
    sub('frequency-upper-bound-excludes-one-ghz', 'cntfrq <= COUNTER_HZ_MAX ?', 'cntfrq < COUNTER_HZ_MAX ?'),
    sub('waits-one-read-too-long', 'if (now - start >= hz * seconds) return 1;', 'if (now - start > hz * seconds) return 1;'),
    sub('counts-from-zero-not-from-the-first-read', 'if (now - start >= hz * seconds) return 1;', 'if (now >= hz * seconds) return 1;'),
    sub('gives-up-on-a-slow-counter', '#define COUNTER_STUCK_READS 2000000u', '#define COUNTER_STUCK_READS 20u'),
    sub('deadline-is-zero-seconds', '#define DEADLINE_S 1u', '#define DEADLINE_S 0u'),
    sub('deadline-ignores-the-frequency', '    e->deadline = r->a->ops.counter() + r->hz * DEADLINE_S;\n', '    e->deadline = r->a->ops.counter() + DEADLINE_S;\n'),
    # -- the image is made visible to a core that fetches without its caches
    drop('does-not-clean-the-image', CLEAN),
    drop('does-not-invalidate-the-instruction-cache', INVALIDATE),
    sub('no-barrier-between-clean-and-invalidate', '    dsb_sy();\n' + INVALIDATE, INVALIDATE),
    sub('no-barrier-after-the-invalidate', 'ic_ivau(at);\n    dsb_sy();\n    isb();\n', 'ic_ivau(at);\n    isb();\n'),
    sub('no-isb-after-the-cache-work', '    dsb_sy();\n    isb();\n}\n', '    dsb_sy();\n}\n'),
    sub('cache-step-is-32', '#define CACHE_STEP 16u', '#define CACHE_STEP 32u'),
    sub('cleans-all_but_the_last_line', 'at < start + bytes; at += CACHE_STEP) dc_civac(at);', 'at + CACHE_STEP < start + bytes; at += CACHE_STEP) dc_civac(at);'),
    sub('cleans-from-the-unaligned-start', CLEAN, CLEAN.replace('start & ~(uint64_t)(CACHE_STEP - 1)', 'start')),
    # -- what it refuses
    drop('does-not-check-the-arguments', '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n'),
    sub('runs-at-any-el', '    if ((current_el >> 2 & 3) != 2) {\n', '    if (0) {\n'),
    sub('takes-el3-for-el2', '    if ((current_el >> 2 & 3) != 2) {\n', '    if ((current_el >> 2 & 3) < 2) {\n'),
    sub('does-not-check-for-the-counter-op', '    if (!a->ops.counter) {\n', '    if (0) {\n'),
    sub('does-not-check-the-layout', '    if (!layout_ok(a)) {\n', '    if (0) {\n'),
    sub('layout-ignores-the-start-of-the-image', 'if (el2 < base || el2 + 2048 > end', 'if (el2 + 2048 > end'),
    sub('layout-ignores-the-end-of-the-stub', 'stub + EL1_STUB_BYTES > end', 'stub + 4 > end'),
    sub('layout-ignores-a-huge-image', 'if (a->payload_size >= (UINT64_C(1) << 32) || end < base) return 0;', 'if (end < base) return 0;'),
    drop('does-not-refuse-e2h', '    if (hcr >> 34 & 1) return "REFUSED=E2H";\n'),
    sub('e2h-is-bit-33', '    if (hcr >> 34 & 1) return "REFUSED=E2H";\n', '    if (hcr >> 33 & 1) return "REFUSED=E2H";\n'),
    drop('does-not-refuse-a-core-without-aarch64-el1', '    if ((pfr0 >> 4 & 15) == 0) return "REFUSED=NO_EL1_AARCH64";\n'),
    sub('el1-field-is-bits-11-to-8', '    if ((pfr0 >> 4 & 15) == 0) return "REFUSED=NO_EL1_AARCH64";\n', '    if ((pfr0 >> 8 & 15) == 0) return "REFUSED=NO_EL1_AARCH64";\n'),
    drop('does-not-refuse-unmasked-interrupts', '    if ((daif & DAIF_MASKED) != DAIF_MASKED) return "REFUSED=DAIF_NOT_MASKED";\n'),
    sub('refuses-only-when-all-of-daif-is-unmasked', '(daif & DAIF_MASKED) != DAIF_MASKED', '!(daif & DAIF_MASKED)'),
    drop('does-not-refuse-sp0', '    if (!(spsel & 1)) return "REFUSED=SPSEL_NOT_EL2H";\n'),
    drop('does-not-refuse-an-old-with-bits-set', '    if (cnthctl & OLD_REFUSED_BITS) return "REFUSED=OLD_HAS_BITS_12_TO_14";\n'),
    sub('refuses-only-an-old-with-ecv-set', '#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT)', '#define OLD_REFUSED_BITS (ECV_BIT)'),
    sub('refuses-an-old-with-bit-15-set', '#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT)', '#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT | (UINT64_C(1) << 15))'),
    sub('does-not-check-the-stack', 'if (sp < r->a->stack_base + STACK_KEPT_BYTES || sp > r->a->stack_base + r->a->stack_size) return "REFUSED=STACK";',
        'if (0) return "REFUSED=STACK";'),
    sub('stack-low-bound-is-off-by-one', 'sp < r->a->stack_base + STACK_KEPT_BYTES', 'sp <= r->a->stack_base + STACK_KEPT_BYTES'),
    sub('stack-high-bound-is-off-by-one', 'sp > r->a->stack_base + r->a->stack_size', 'sp >= r->a->stack_base + r->a->stack_size'),
    sub('keeps-only-8-kib-of-stack', '#define STACK_KEPT_BYTES (16u * 1024u)', '#define STACK_KEPT_BYTES (8u * 1024u)'),
    # -- the page and the verdict
    sub('effective-when-either-ecv-read-traps', 'trapped[ACCESS_VCT] && trapped[ACCESS_VTIMER] ? "TRAPS_EFFECTIVE"', 'trapped[ACCESS_VCT] || trapped[ACCESS_VTIMER] ? "TRAPS_EFFECTIVE"'),
    sub('inert-when-either-ecv-read-does-not-trap', '!trapped[ACCESS_VCT] && !trapped[ACCESS_VTIMER] ? "TRAPS_INERT"', '!trapped[ACCESS_VCT] || !trapped[ACCESS_VTIMER] ? "TRAPS_INERT"'),
    sub('verdict-ignores-the-control', '!trapped[ACCESS_CONTROL] ? "CONTROL_NOT_TRAPPED"', '0 ? "CONTROL_NOT_TRAPPED"'),
    drop('does-not-say-when-cntfrq-trapped', '        if (trapped[ACCESS_FRQ]) word(&line, "CNTFRQ_EL0_TRAPPED");\n'),
    sub('bits-yes-when-either-sticks', 'bits == 2 ? "BITS13_14_IN_READBACK=YES"', 'bits >= 1 ? "BITS13_14_IN_READBACK=YES"'),
    sub('bits-from-nothing', 'unsigned bits = (unsigned)(readback_cnthctl >> 13 & 1) + (unsigned)(readback_cnthctl >> 14 & 1);', 'unsigned bits = 2;'),
    sub('does-not-check-the-iss', '(t->esr & ISS_MASK) == expected_iss(i) ? "ISS_OK=YES"', '1 ? "ISS_OK=YES"'),
    sub('does-not-check-the-class', '(t->esr >> 26 & 63) == EC_TRAPPED_SYSREG &&', '1 &&'),
    sub('expected-iss-has-no-rt', '((uint64_t)i << 5) |', '((uint64_t)0 << 5) |'),
    sub('expected-iss-op2-in-the-wrong-place', '((uint64_t)e[4] << 17)', '((uint64_t)e[4] << 16)'),
    sub('matches-traps-by-order-not-by-elr', 'if (e->trap[k].elr == at) return &e->trap[k];', 'if (k == i) return &e->trap[k];'),
    sub('names-a-reason-wrongly', '"NONE", "OK", "BUDGET"', '"NONE", "BUDGET"'),
    sub('prints-no-trap-records-of-an-end', 'k < TRAPS_MAX; k++) {\n        row(&line);\n        word(&line, "TRAP");', 'k < 0; k++) {\n        row(&line);\n        word(&line, "TRAP");'),
    sub('does-not-print-what-an-el1-vector-reported', '    if (e->reason == END_EL1_EXCEPTION) {\n', '    if (0) {\n'),
    sub('reports-an-end-as-ok', '    } else if (w.e.reason == END_HVC) {\n', '    } else if (1) {\n'),
    sub('prints-the-vbar-address-not-the-offset', 'w.readback[R_VBAR1] - a->payload_base, "SCTLR_EL1", "VBAR_EL1_OFFSET"', 'w.readback[R_VBAR1], "SCTLR_EL1", "VBAR_EL1_OFFSET"'),
    sub('says-restored-without-looking', '    if (!bad) {\n        say(&r->out, "RESTORED=YES");', '    if (1) {\n        say(&r->out, "RESTORED=YES");'),
    sub('does-not-compare-vbar-el2', '    for (unsigned i = 0; i < R_COUNT; i++) bad += w->restored[i] != r->saved[i];\n', '    for (unsigned i = 0; i < R_VBAR2; i++) bad += w->restored[i] != r->saved[i];\n'),
    drop('does-not-shout-that-it-could-not-restore', '    say(&r->out, "POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD");\n'),
    sub('returns-0-when-it-could-not-restore', '    if (!report_restore(&r, &w)) return RET_NOT_RESTORED;\n    return w.held', '    report_restore(&r, &w);\n    return w.held'),
    sub('returns-0-when-the-excursion-did-not-end-well', 'return w.held && w.e.reason == END_HVC ? 0 : RET_NOT_OK;', 'return 0;'),
    sub('returns-2-when-it-did-not-restore', '#define RET_NOT_RESTORED 3u', '#define RET_NOT_RESTORED 2u'),
    # -- registers that must not be touched
    sub('reads-cntpoff-el2', '    current_el = SYSREG(CurrentEL);\n', '    current_el = SYSREG(CurrentEL);\n    (void)SYSREG(S3_4_C14_C0_6);\n'),
    sub('reads-cntvoff-el2', '    current_el = SYSREG(CurrentEL);\n', '    current_el = SYSREG(CurrentEL);\n    (void)SYSREG(S3_4_C14_C0_3);\n'),
]


class El1trapMutants(unittest.TestCase):
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
        self.assertGreaterEqual(len(names), 100)
        self.assertEqual({m[1] for m in MUTANTS}, {FILE})
        for wanted in ('hcr-also-sets-tge', 'sctlr-sets-the-mmu', 'cnthctl-sets-ecv-as-well', 'hcr-is-written-first', 'never-puts-vbar-el1-back',
                       'never-retries', 'runs-without-checking-the-writes', 'hcr-check-misses-e2h', 'sctlr-check-misses-wxn', 'never-probes',
                       'ignores-a-failed-probe', 'does-not-wait', 'does-not-clean-the-image', 'does-not-invalidate-the-instruction-cache',
                       'runs-at-any-el', 'does-not-refuse-e2h', 'does-not-refuse-an-old-with-bits-set', 'does-not-check-the-stack',
                       'verdict-ignores-the-control', 'does-not-check-the-iss', 'returns-0-when-it-could-not-restore', 'reads-cntpoff-el2'):
            self.assertIn(f'el1trap-{wanted}', names)

    def test_the_unmutated_control_passes_from_a_copy(self):
        directory = BUILD / 'control'
        native.copy_tree(directory)
        done, binary = self._build('el1trap', directory, relaxed=False)
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
    ('a-write-to-cntvoff-el2', asm('msr cntvoff_el2, xzr'), 'forbidden instruction msr cntvoff_el2'),
    ('a-write-to-cntkctl-el1', asm('msr cntkctl_el1, xzr'), 'forbidden instruction msr cntkctl_el1'),
    ('a-write-to-cntv-ctl-el0', asm('msr cntv_ctl_el0, xzr'), 'forbidden instruction msr cntv_ctl_el0'),
    ('a-write-to-cnthp-ctl-el2', asm('msr cnthp_ctl_el2, xzr'), 'forbidden instruction msr cnthp_ctl_el2'),
    ('a-write-to-sctlr-el2', asm('msr sctlr_el2, xzr'), 'forbidden instruction msr sctlr_el2'),
    ('a-write-to-tcr-el2', asm('msr tcr_el2, xzr'), 'forbidden instruction msr tcr_el2'),
    ('a-write-to-ttbr0-el2', asm('msr ttbr0_el2, xzr'), 'forbidden instruction msr ttbr0_el2'),
    ('a-write-to-vttbr-el2', asm('msr vttbr_el2, xzr'), 'forbidden instruction msr vttbr_el2'),
    ('a-write-to-vtcr-el2', asm('msr vtcr_el2, xzr'), 'forbidden instruction msr vtcr_el2'),
    ('a-write-to-scr-el3', asm('msr scr_el3, xzr'), 'forbidden instruction msr scr_el3'),
    ('a-write-to-esr-el2', asm('msr esr_el2, xzr'), 'forbidden instruction msr esr_el2'),
    ('a-write-to-far-el2', asm('msr far_el2, xzr'), 'forbidden instruction msr far_el2'),
    ('a-write-to-elr-el1', asm('msr elr_el1, xzr'), 'forbidden instruction msr elr_el1'),
    ('a-write-to-spsr-el1', asm('msr spsr_el1, xzr'), 'forbidden instruction msr spsr_el1'),
    ('a-write-to-sp-el1', asm('msr sp_el1, xzr'), 'forbidden instruction msr sp_el1'),
    ('a-write-to-daifclr', asm('msr daifclr, #15'), 'forbidden instruction msr daifclr'),
    ('a-write-to-daifset', asm('msr daifset, #15'), 'forbidden instruction msr daifset'),
    ('a-write-to-spsel', asm('msr spsel, #1'), 'forbidden instruction msr spsel'),
    ('a-read-of-an-unlisted-register', read('ttbr0_el2'), 'registers read'),
    ('a-read-of-sctlr-el2', read('sctlr_el2'), 'registers read'),
    ('a-read-of-the-physical-timer-control', read('CNTP_CTL_EL0'), 'registers read'),
    ('an-smc', asm('smc #0'), '1 smc instructions'),
    ('an-hvc-with-another-immediate', asm('hvc #3'), 'forbidden instruction hvc #0x3'),
    ('an-hvc-with-a-large-immediate', asm('hvc #0xffff'), 'forbidden instruction hvc #0xffff'),
    ('an-svc', asm('svc #0'), 'svc'),
    ('a-wfi', asm('wfi'), 'wfi'),
    ('a-wfe', asm('wfe'), 'forbidden instruction wfe'),
    ('an-sev', asm('sev'), 'sev'),
    ('a-dmb', asm('dmb sy'), 'dmb'),
    ('a-tlb-operation', asm('tlbi alle2'), 'tlbi'),
    ('an-instruction-cache-operation-to-the-point-of-unification', asm('ic iallu'), 'forbidden instruction ic iallu'),
    ('a-data-cache-clean', asm('dc cvac, x0'), 'forbidden instruction dc cvac'),
    ('a-data-cache-zero', asm('dc zva, x0'), 'forbidden instruction dc zva'),
    ('an-address-translation', asm('at s1e2r, x0'), 'forbidden instruction at'),
    ('an-exclusive-load', asm('ldxr x9, [sp]'), 'ldxr'),
    ('an-atomic-add', asm('.arch_extension lse\\n ldadd x9, x10, [sp]'), 'ldadd'),
    ('a-word-that-is-no-instruction', asm('.inst 0xffffffff'), 'not a known instruction'),
]


def llvm_mc(text):
    done = run(['llvm-mc', '-triple=aarch64', '-mattr=+v8.4a', '-show-encoding'], input=text)
    found = re.findall(r'encoding: \[((?:0x[0-9a-f]{2},?)+)\]', done.stdout)
    return [struct.unpack('<I', bytes(int(b, 16) for b in encoding.split(',')))[0] for encoding in found]


class El1trapBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.out = BUILD / 'bad-binaries'
        cls.builder = Builder(cls.out)
        done, cls.elf, cls.flat = cls.builder.build('el1trap', 'control', [], check=True)
        if done.returncode:
            raise RuntimeError(done.stderr[-1500:])
        cls.text = run(['llvm-objdump', '-d', '--no-show-raw-insn', str(cls.elf)]).stdout
        cls.symbols = {m.group(2): int(m.group(1), 16) for m in re.finditer(r'^([0-9a-f]+) <(\w+)>:$', cls.text, re.M)}

    def test_the_unmodified_payload_is_clean_and_fits_the_policy(self):
        self.assertEqual(lib.binary_violations(self.elf, self.flat, POLICY, READELF()), [])
        self.assertEqual(POLICY['allow'], {'msr': {'hcr_el2', 'cnthctl_el2', 'sctlr_el1', 'vbar_el1', 'vbar_el2', 'spsr_el2', 'elr_el2'},
                                           'hvc': {'#0', '#0x1', '#0x2'}, 'eret': {''}, 'dc': {'civac'}, 'ic': {'ivau'}})
        self.assertEqual(POLICY['smc'], 0)
        self.assertGreaterEqual(POLICY['forbid'], {'dmb', 'sb', 'sev', 'sevl'})
        self.assertFalse({'isb', 'dsb'} & POLICY['forbid'])
        self.assertFalse({'smc_ids', 'single_reads', 'timer_offsets'} & set(POLICY))
        self.assertEqual(len(POLICY['registers']), 21)
        self.assertLessEqual(Path(self.flat).stat().st_size, POLICY['bytes'])

    def test_the_instruction_inventory_is_what_the_document_says(self):
        f = facts(self.elf, self.flat)
        self.assertEqual(set(f['mrs']), POLICY['registers'])
        self.assertEqual(dict(f['msr']), {'vbar_el2': 4, 'elr_el2': 4, 'spsr_el2': 3, 'hcr_el2': 1, 'cnthctl_el2': 1, 'sctlr_el1': 1, 'vbar_el1': 1})
        self.assertEqual((f['mnemonics']['mrs'], f['mnemonics']['msr']), (27, 15))
        self.assertEqual(dict(f['hvc']), {'#0x1': 16, '#0': 1, '#0x2': 1}, 'sixteen EL1 vector entries, the stub, the probe')
        self.assertEqual((f['mnemonics']['eret'], f['mnemonics']['isb'], f['mnemonics']['dsb'], f['mnemonics']['udf']), (4, 4, 1, 1))
        self.assertEqual((dict(f['dc']), dict(f['ic'])), ({'civac': 1}, {'ivau': 1}))
        for mnemonic in ('smc', 'svc', 'wfi', 'wfe', 'sev', 'sevl', 'dmb', 'sb', 'tlbi', 'at', 'sys', 'sysl', 'brk', 'hlt'):
            self.assertEqual(f['mnemonics'][mnemonic], 0, mnemonic)
        self.assertFalse([m for m in f['mnemonics'] if re.match(r'^(ldx|ldax|stx|stlx|cas|swp|ldadd|ldset|ldclr|ldeor)', m)])

    def test_the_el1_stub_is_five_instructions_with_no_branch_and_no_memory_access(self):
        start, end = self.symbols['el1trap_stub'], self.symbols.get('el1trap_stub_end')
        stub = [(a, m, o.split('//')[0].strip().lower()) for a, m, o in self.listing() if start <= a < (end or start + 20)]
        self.assertEqual([(m, o) for _, m, o in stub], [('mrs', 'x0, cntvct_el0'), ('mrs', 'x1, cntv_ctl_el0'), ('mrs', 'x2, cntfrq_el0'),
                                                         ('mrs', 'x3, cntpct_el0'), ('hvc', '#0')])
        self.assertEqual([a for a, _, _ in stub], [start + 4 * i for i in range(5)])
        data = Path(self.flat).read_bytes()
        self.assertEqual(struct.unpack_from('<5I', data, start), (0xd53be040, 0xd53be321, 0xd53be002, 0xd53be023, 0xd4000002),
                         'MRS CNTVCT_EL0, CNTV_CTL_EL0, CNTFRQ_EL0, CNTPCT_EL0 into x0 to x3, and HVC #0')

    def listing(self):
        found = (re.match(r'\s+([0-9a-f]+):\s+(\S+)\s*(.*)$', line) for line in self.text.splitlines())
        return [(int(m.group(1), 16), m.group(2).lower(), m.group(3)) for m in found if m]

    def test_both_vector_tables_are_two_kib_aligned_and_every_entry_is_two_instructions_as_the_document_says(self):
        el2, el1, common = self.symbols['el1trap_vectors_el2'], self.symbols['el1trap_vectors_el1'], self.symbols['el1trap_el2_common']
        self.assertEqual((el2 % 2048, el1 % 2048), (0, 0), 'VBAR_ELx keeps bits 10:0 reserved')
        self.assertEqual(el1 - el2, 2048)
        by_address = {a: (m, o.split('//')[0].strip().lower()) for a, m, o in self.listing()}
        for n in range(16):
            with self.subTest(entry=n):
                self.assertEqual(by_address[el2 + 128 * n][0], 'mov')
                self.assertEqual(int(by_address[el2 + 128 * n][1].split('#')[1], 0), n)
                self.assertTrue(by_address[el2 + 128 * n][1].startswith('x15,'), 'the vector number is in x15')
                branch = by_address[el2 + 128 * n + 4]
                self.assertEqual(branch[0], 'b')
                self.assertEqual(int(branch[1].split()[0], 16), common, 'every EL2 entry goes to the one handler')
                self.assertEqual(by_address[el1 + 128 * n][0], 'mov')
                self.assertTrue(by_address[el1 + 128 * n][1].startswith('x16,'), 'the vector number is in x16')
                self.assertEqual(int(by_address[el1 + 128 * n][1].split('#')[1], 0), n)
                self.assertEqual(by_address[el1 + 128 * n + 4], ('hvc', '#0x1'), 'every EL1 entry reports by HVC #1')
                for offset in (8, 64, 124) if n < 15 else (8,):     # the rest of an entry is padding that is never executed
                    self.assertEqual(by_address[el2 + 128 * n + offset][0], 'nop')
                    self.assertEqual(by_address[el1 + 128 * n + offset][0], 'nop')

    def test_every_forbidden_addition_is_named_by_the_allow_list_check(self):
        self.assertGreaterEqual(len(BAD_BINARIES), 40)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            built = list(pool.map(lambda b: (b, self.builder.build('el1trap', b[0], b[1])), BAD_BINARIES))
        for (name, _, expected), (done, elf, flat) in built:
            with self.subTest(binary=name):
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                problems = lib.binary_violations(elf, flat, POLICY, READELF())
                self.assertTrue(problems, 'the check passed a binary it must refuse')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_a_flat_binary_patched_behind_the_disassembly_is_caught_by_the_encoding_layer_alone(self):
        data = bytearray(Path(self.flat).read_bytes())
        words = struct.unpack(f'<{len(data) // 4}I', bytes(data[:len(data) // 4 * 4]))
        self.assertEqual(lib.binary_violations(self.elf, self.flat, POLICY, READELF()), [])
        msr = lambda w: w & 0xffffffe0 == 0xd51ce100                  # noqa: E731  msr cnthctl_el2
        isb = lambda w: w == 0xd5033fdf                               # noqa: E731
        wanted = (
            ('msr cnthctl_el2 to msr cntvoff_el2', msr, lambda w: 0xd51ce060 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr cntkctl_el1', msr, lambda w: 0xd518e100 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr sctlr_el2', msr, lambda w: 0xd51c1000 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr tcr_el2', msr, lambda w: 0xd51c2040 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr elr_el1', msr, lambda w: 0xd5184020 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr daifset', msr, lambda w: 0xd50340df, 'msr-immediate'),
            ('hvc #1 to hvc #3', lambda w: w == 0xd4000022, lambda w: 0xd4000062, 'hvc'),
            ('hvc #1 to svc #1', lambda w: w == 0xd4000022, lambda w: 0xd4000021, 'svc'),
            ('hvc #1 to smc #0', lambda w: w == 0xd4000022, lambda w: 0xd4000003, 'smc'),
            ('isb to dmb', isb, lambda w: 0xd5033fbf, 'dmb'),
            ('isb to wfe', isb, lambda w: 0xd503205f, 'wfe'),
            ('isb to wfi', isb, lambda w: 0xd503207f, 'wfi'),
            ('isb to dc cvac', isb, lambda w: 0xd50b7a20, 'sys'),
            ('isb to ic iallu', isb, lambda w: 0xd508751f, 'sys'),
        )
        for label, is_target, patch, what in wanted:
            with self.subTest(patch=label):
                at = next(i for i, w in enumerate(words) if is_target(w))
                patched = bytearray(data)
                struct.pack_into('<I', patched, at * 4, patch(words[at]))
                path = self.out / 'patched.bin'
                path.write_bytes(patched)
                problems = lib.binary_violations(self.elf, path, POLICY, READELF())
                expected = 'words of the code encode smc' if what == 'smc' else f'a word of the code encodes {what}'
                self.assertTrue(any(expected in p for p in problems), problems)

    @unittest.skipUnless(have('llvm-mc'), 'llvm-mc not installed')
    def test_the_encodings_this_payload_added_to_the_engine_are_what_llvm_mc_says(self):
        for form, text in ((('eret', ''), 'eret'), (('hvc', '#0'), 'hvc #0'), (('hvc', '#0x1'), 'hvc #1'), (('hvc', '#0x2'), 'hvc #2'),
                           (('ic', 'ivau'), 'ic ivau, x0'), (('msr', 'cnthctl_el2'), 'msr cnthctl_el2, x0'), (('msr', 'elr_el2'), 'msr elr_el2, x0'),
                           (('msr', 'hcr_el2'), 'msr hcr_el2, x0'), (('msr', 'sctlr_el1'), 'msr sctlr_el1, x0'), (('msr', 'spsr_el2'), 'msr spsr_el2, x0'),
                           (('msr', 'vbar_el1'), 'msr vbar_el1, x0'), (('msr', 'vbar_el2'), 'msr vbar_el2, x0')):
            with self.subTest(form=form):
                _, mask, value = lib.ALLOW_WORDS[form]
                word = llvm_mc(text + '\n')[0]
                register = text.endswith(', x0') and form[0] in ('msr', 'ic')
                self.assertEqual(word & mask, value, f'{word:#x} {mask:#x} {value:#x}')
                if register:
                    self.assertEqual(mask, 0xffffffe0, 'every Rt is allowed, nothing else')
                    self.assertEqual(llvm_mc(text.replace('x0', 'x17') + '\n')[0] & mask, value)

    def test_the_binary_is_refused_under_every_other_policy_and_the_others_under_its_own(self):
        for other in OTHERS:
            with self.subTest(policy=other):
                self.assertTrue(lib.binary_violations(self.elf, self.flat, lib.POLICIES[other], READELF()))
        out = BUILD / 'others'
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        for other in OTHERS:
            with self.subTest(payload=other):
                done, o_elf, o_flat = lib.build_payload(ROOT / 'payloads' / f'{other}.c', out, name=other, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertTrue(lib.binary_violations(o_elf, o_flat, POLICY, READELF()), f'{other} passes the el1trap policy: the policy is too loose')

    def test_the_forms_are_allowed_to_this_payload_and_to_no_older_one_except_where_the_document_says(self):
        for mnemonic, form, only in (('msr', 'cnthctl_el2', {'cnthctl', 'el1trap'}), ('msr', 'hcr_el2', {'el1trap'}), ('msr', 'sctlr_el1', {'el1trap'}),
                                     ('msr', 'vbar_el1', {'el1trap'}), ('msr', 'spsr_el2', {'el1trap'}), ('msr', 'elr_el2', {'el1trap'}),
                                     ('hvc', '#0x1', {'el1trap'}), ('eret', '', {'el1trap'}), ('ic', 'ivau', {'el1trap'})):
            with self.subTest(form=(mnemonic, form)):
                self.assertEqual({name for name, policy in lib.POLICIES.items() if form in policy.get('allow', {}).get(mnemonic, ())} - {'cpuon', 'el2mem'},
                                 only)

    def test_two_builds_from_the_same_tree_are_byte_identical(self):
        done, _, flat = Builder(BUILD / 'again').build('el1trap', 'control', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(Path(flat).read_bytes(), Path(self.flat).read_bytes())
        self.assertEqual(Path(self.flat).read_bytes()[:4], bytes.fromhex('5f2403d5'), 'BTI c first, as the runner expects')


class El1trapStick(unittest.TestCase):
    tool = ROOT / 'tools' / 'sp11_payload_manifest.py'

    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.out = BUILD / 'stick-payloads'
        shutil.rmtree(cls.out, ignore_errors=True)
        done = run(['make', '-f', 'platform/uefi/Makefile', f'OUT={cls.out.relative_to(ROOT)}', 'payloads'])
        if done.returncode:
            raise RuntimeError('make payloads failed:\n' + done.stdout[-1500:] + done.stderr[-1500:])
        cls.bins = {name: cls.out / 'payloads' / f'{name}.bin' for name in ('state', 'psci', 'el1trap')}

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

    def test_el1trap_alone_is_one_payload_and_the_stick_holds_the_manifest_and_the_file(self):
        base, done = self.stick(('el1trap',))
        entries = self.entries(base)
        self.assertEqual([e[2].rstrip(b'\0').decode() for e in entries], ['\\SP11\\EL1TRAP.BIN'])
        data = self.bins['el1trap'].read_bytes()
        self.assertEqual((entries[0][0], entries[0][1]), (len(data), hashlib.sha256(data).digest()))
        self.assertEqual(sorted(p.name for p in (base / 'SP11').iterdir()), ['EL1TRAP.BIN', 'PAYLOAD.MAN'])
        self.assertEqual((base / 'SP11' / 'EL1TRAP.BIN').read_bytes(), data)
        self.assertIn('(INDEX=0, payload, called in manifest order)', done.stdout)

    def test_the_runners_own_validator_and_loader_take_it_as_a_payload_alone_and_after_psci(self):
        harness = BUILD / 'kinds-harness'
        sources = [ROOT / 'tools' / 'testdata' / 'sp11-payload-kinds-harness.c'] + [
            native.UEFI / name for name in ('sp11-payload-load.c', 'sp11-payload-plan.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c')]
        done = run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1',
                    '-I', str(native.UEFI)] + [str(s) for s in sources] + ['-o', str(harness)])
        self.assertEqual(done.returncode, 0, done.stderr)
        for order, expected in ((('el1trap',), ['\\SP11\\EL1TRAP.BIN code']),
                                (('psci', 'el1trap'), ['\\SP11\\PSCI.BIN code', '\\SP11\\EL1TRAP.BIN code'])):
            with self.subTest(order=order):
                base, _ = self.stick(order)
                ours = run([str(harness), str(base / 'SP11' / 'PAYLOAD.MAN')])
                self.assertEqual(ours.returncode, 0, ours.stdout + ours.stderr)
                self.assertEqual(ours.stdout.splitlines(), expected)

    def test_the_binary_is_a_few_pages_and_inside_its_policy(self):
        self.assertLessEqual(self.bins['el1trap'].stat().st_size, POLICY['bytes'])
        self.assertGreater(self.bins['el1trap'].stat().st_size, 8192, 'the two 2 KiB tables and the code')


def facts_main():
    need_tools()
    done, elf, flat = Builder(BUILD / 'facts').build('el1trap', 'el1trap', [], check=True)
    if done.returncode:
        sys.exit(done.stderr)
    f = facts(elf, flat)
    print(f'el1trap.bin: {f["bytes"]} bytes, sha256 {f["sha256"]}, {f["instructions"]} instructions')
    print('mnemonics:', ', '.join(f'{m} {n}' for m, n in sorted(f['mnemonics'].items())))
    print('registers read:', ', '.join(f'{r} x{n}' for r, n in sorted(f['mrs'].items())))
    print('msr operands:', dict(f['msr']), 'hvc:', dict(f['hvc']), 'dc:', dict(f['dc']), 'ic:', dict(f['ic']))
    print('allow-list violations:', lib.binary_violations(elf, flat, POLICY, READELF()))


if __name__ == '__main__':
    if sys.argv[1:] == ['facts']:
        facts_main()
    else:
        sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
