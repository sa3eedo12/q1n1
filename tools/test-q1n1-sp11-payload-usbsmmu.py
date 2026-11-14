#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The usbsmmu payload ("S0b") of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-USBSMMU.md): its host test, its
seeded bugs, the allow-list of its binary and the manifest chain that carries it. The documents are checked against the source
by tools/test-q1n1-sp11-payload-usbsmmu-doc.py.

    python3 tools/test-q1n1-sp11-payload-usbsmmu.py

  * UsbsmmuNative: tools/test-q1n1-sp11-payload-usbsmmu.c (ten suites over a scripted platform: the three MMIO windows, RAM and
    the UEFI memory map; every load checked against what may be read, a NEXT line before each group, the page tables walked and
    compared with independently built ones, an abort at every load, hostile registers, the line and load budgets), built and
    run by the machinery of tools/test-q1n1-sp11-payload.py; the source audit of what the payload may touch.
  * UsbsmmuMutants: seeded bugs in usbsmmu.c, each applied to a copy of the sources and each of which that program must reject,
    and an unmutated control.
  * UsbsmmuBinary: the allow-list of tools/sp11_payload_testlib.py applied to usbsmmu.bin (MRS of CurrentEL and nothing else,
    no barrier, no SMC, no write, no timer offset) with seeded bad binaries, and to the other policies.
  * UsbsmmuChain: the manifest tool and the runner's own validator on the chain `psci.bin usbsmmu.bin timer.bin`.

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
native = load_module('sp11_payload_native_for_usbsmmu', ROOT / 'tools' / 'test-q1n1-sp11-payload.py')
native.BUILD = ROOT / 'build' / 'sp11-payload-usbsmmu-test'
BUILD = native.BUILD
SOURCE = ROOT / 'payloads' / 'usbsmmu.c'
UEFI = ROOT / 'platform' / 'uefi'
READELF = lambda: shutil.which('llvm-readelf', path=lib.ENV['PATH']) or 'llvm-readelf'  # noqa: E731
run, have = lib.run, lib.have
SUITES = ('unit', 'xhc', 'rings', 'slots', 'smmu', 'bank', 'walk', 'faults', 'hostile', 'el')


class UsbsmmuNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_the_usbsmmu_suites_pass(self):
        native.Native._check(self, 'usbsmmu')

    def test_each_suite_runs_alone(self):
        done, binary = native.build_program('usbsmmu', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite in SUITES:
            with self.subTest(suite=suite):
                code, output = native.run_program(binary, suite)
                self.assertEqual(code, 0, output)
                self.assertRegex(output, r'PASS: 1 payload usbsmmu suites, \d+ checks')

    def test_the_most_lines_and_loads_are_measured_and_within_their_budgets(self):
        done, binary = native.build_program('usbsmmu', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary, 'lines-report')
        self.assertEqual(code, 0, output)
        report = {key: int(value) for key, value in re.findall(r'^([A-Z_]+)=(\d+)$', output, re.M)}
        self.assertEqual(report['LINES_MAX'], 24, 'the worst case is exactly the budget: the hostile suites reach it')
        self.assertTrue(0 < report['LOADS_MAX'] <= 3000, report)

    def test_the_source_calls_only_load32_puts_and_hex_and_reads_only_currentel(self):
        code = re.sub(r'/\*.*?\*/', '', SOURCE.read_text(encoding='utf-8'), flags=re.S)
        self.assertEqual(set(re.findall(r'ops\.(\w+)', code)), {'load32'}, 'the payload itself calls only the load op')
        util = re.sub(r'/\*.*?\*/', '', (ROOT / 'payloads' / 'payload-util.h').read_text(encoding='utf-8'), flags=re.S)
        self.assertEqual({op for op in re.findall(r'ops\.(\w+)', util)}, {'hex', 'puts'}, 'the helpers it uses call hex and puts')
        self.assertEqual(set(re.findall(r'SYSREG\((\w+)\)', code)) - {'name'}, {'CurrentEL'})
        self.assertEqual(code.count('__asm__'), 1, 'one inline assembly: the MRS')
        self.assertEqual(len(re.findall(r'\(uintptr_t\)', code)), 1, 'one address made into a pointer: the runner\'s memory map')
        self.assertEqual(len(re.findall(r'\bvolatile\b', code)), 3, 'the MRS and the two zeroing loops over its own stack')

    def test_no_writable_global_and_every_table_is_constant(self):
        code = re.sub(r'/\*.*?\*/', '', SOURCE.read_text(encoding='utf-8'), flags=re.S)
        for declaration in re.findall(r'^static\b[^\n(]*;', code, re.M):
            self.assertRegex(declaration, r'\bconst\b|\binline\b', declaration)
        self.assertLess(SOURCE.stat().st_size, 50 * 1024)
        self.assertLess(len(SOURCE.read_text(encoding='utf-8').splitlines()), 1500)


# ---- seeded bugs in usbsmmu.c --------------------------------------------------------------------------------------------

FILE = 'payloads/usbsmmu.c'
BANK_PAGE = '    emit(c, &next);\n\n    c->failed = 0;\n    ok = !rd32(c, WIN_SMMU, gr1 + GR1_CBAR(n), &b->cbar, "CBAR") && !rd32(c, WIN_SMMU, gr1 + GR1_CBA2R(n), &b->cba2r, "CBA2R");\n'
BANK_REGS = '    c->failed = 0;\n    ok = !rd32(c, WIN_SMMU, gr1 + GR1_CBAR(n), &b->cbar, "CBAR") && !rd32(c, WIN_SMMU, gr1 + GR1_CBA2R(n), &b->cba2r, "CBA2R");\n'
TABLE_STEP = '} else if (level < 3 && desc & 2) {'
OA = '(desc & ((UINT64_C(1) << 48) - 1) & ~(span - 1))'
RAM_LOAD = '    return rc ? rc : load(c, addr, value);\n'
EL_CHECK = 'if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {'
STREAM_CHECK = 's->type[k] != 0 || s->cbndx[k] >= s->numcb) continue;'
MATCH_RULE = '(stream_id[k] ^ (smr & 0xffffu)) & ~(smr >> 16 & 0xffffu) & implemented'
BLOCK_RULE = 'return level == 2 || (pg == 12 && level == 1);'
MAP_GUARD = 'if (pages >= (UINT64_C(1) << 40) || start + pages * 4096u < start) return;'
ZERO_TEST = '!(b->cbar | b->cba2r | b->sctlr | b->tcr | b->ttbr0)'


def sub(name, old, new):
    return ('usbsmmu-' + name, FILE, [(old, new)], ['usbsmmu'], None)


def drop(name, statement):
    return sub(name, statement, '')


MUTANTS = [
    # -- the walk: levels, masks, descriptor kinds, attributes
    sub('walks-with-the-wrong-level-shift', 'uint32_t shift = w->pg + w->bpl * (3 - level), bits', 'uint32_t shift = w->pg + w->bpl * (4 - level), bits'),
    sub('keeps-attribute-bits-in-the-output-address', OA, '(desc & ((UINT64_C(1) << 48) - 1))'),
    sub('masks-the-output-address-to-47-bits', OA, OA.replace('<< 48', '<< 47')),
    sub('takes-a-block-for-a-table', TABLE_STEP, '} else if (level < 3) {'),
    sub('descends-past-level-3', TABLE_STEP, '} else if (desc & 2) {'),
    ('usbsmmu-walks-without-a-depth-bound', FILE, [(TABLE_STEP, '} else if (desc & 2) {'),
                                                   ('for (unsigned step = 0; step < 4 && !done; step++) {', 'for (unsigned step = 0; !done; step++) {')],
     ['usbsmmu'], None),
    sub('allows-a-level-1-block-with-large-granules', BLOCK_RULE, 'return level == 2 || level == 1;'),
    sub('allows-no-level-1-block', BLOCK_RULE, 'return level == 2;'),
    sub('starts-one-level-too-deep', 'w->pg + w->bpl * (3 - level) + w->bpl >= w->ias', 'w->pg + w->bpl * (3 - level) + w->bpl > w->ias'),
    sub('follows-an-unmasked-table-address', 'table = desc & w->table_mask;', 'table = desc;'),
    sub('reads-ap-from-the-wrong-bit', 'desc >> 7 & 1 ? ".RO" : ".RW"', 'desc >> 6 & 1 ? ".RO" : ".RW"'),
    drop('ignores-the-access-flag', '    if (!(desc >> 10 & 1)) tx(&item, ".NOAF");\n'),
    sub('indexes-mair-with-the-wrong-bits', 'index = desc >> 2 & 7,', 'index = desc >> 3 & 7,'),
    sub('swaps-write-back-and-non-cacheable', 'attr == 0xff ? ".WB" : attr == 0x44 ? ".NC"', 'attr == 0xff ? ".NC" : attr == 0x44 ? ".WB"'),
    sub('calls-a-block-a-page', 'kw(&o, level == 3 ? "PAGE" : "BLOCK");', 'kw(&o, level == 3 ? "BLOCK" : "PAGE");'),
    sub('claims-every-mapping-is-identity', '*identity = oa == iova;', '*identity = 1;'),
    sub('walks-outside-the-input-range', 'if (iova >> w->ias) {', 'if (0 && iova >> w->ias) {'),
    sub('swaps-the-16k-and-64k-granules', 'w->pg = tg0 == 0 ? 12u : tg0 == 2 ? 14u : 16u;', 'w->pg = tg0 == 0 ? 12u : tg0 == 2 ? 16u : 14u;'),
    # -- banks the walk does not model
    drop('does-not-check-the-ttbr0-alignment', '    if (w->root & (bytes - 1)) return WY_TTBR0_MISALIGNED;\n'),
    drop('walks-a-stage-2-only-bank', '    if (type == 0) return WY_STAGE2_ONLY;\n'),
    drop('walks-a-nested-bank', '    if (type == 3) return WY_NESTED;\n'),
    drop('walks-a-bank-with-the-mmu-off', '    if (!(b->sctlr & 1)) return WY_M0;\n'),
    drop('walks-with-ttbr0-walks-disabled', '    if (b->tcr >> 7 & 1) return WY_EPD0;\n'),
    drop('walks-a-32-bit-bank', '    if (!(b->cba2r & 1)) return WY_VA64_0;\n'),
    drop('walks-the-reserved-granule', '    if (tg0 == 3) return WY_TG0;\n'),
    drop('walks-any-input-size', '    if (t0sz < 16 || t0sz > 39) return WY_T0SZ;\n'),
    # -- a bank that reads all zero is its own reason: not stage 2 only, not stage 1 off
    drop('takes-an-all-zero-bank-for-stage-2-only', '    if (' + ZERO_TEST + ') return WY_ALL_ZERO;\n'),
    sub('takes-an-all-zero-bank-for-stage-1-off', 'return WY_ALL_ZERO;', 'return WY_M0;'),
    sub('calls-a-bank-all-zero-when-any-register-is-zero', ZERO_TEST, '!(b->cbar & b->cba2r & b->sctlr & b->tcr & b->ttbr0)'),
    sub('ignores-cbar-in-the-all-zero-test', ZERO_TEST, '!(b->cba2r | b->sctlr | b->tcr | b->ttbr0)'),
    sub('ignores-cba2r-in-the-all-zero-test', ZERO_TEST, '!(b->cbar | b->sctlr | b->tcr | b->ttbr0)'),
    sub('ignores-sctlr-in-the-all-zero-test', ZERO_TEST, '!(b->cbar | b->cba2r | b->tcr | b->ttbr0)'),
    sub('ignores-tcr-in-the-all-zero-test', ZERO_TEST, '!(b->cbar | b->cba2r | b->sctlr | b->ttbr0)'),
    sub('ignores-ttbr0-in-the-all-zero-test', ZERO_TEST, '!(b->cbar | b->cba2r | b->sctlr | b->tcr)'),
    # -- RAM only where the memory map says it is RAM
    sub('loads-ram-without-the-memory-map', RAM_LOAD, '    return load(c, addr, value);\n'),
    sub('dereferences-ram-without-the-load-op', RAM_LOAD, '    if (rc) return rc;\n    *value = *(volatile const uint32_t *)(uintptr_t)addr;\n    return RD_OK;\n'),
    sub('takes-reserved-memory-for-ram', 'return (type >= 1 && type <= 7) || type == 9;', 'return type <= 7 || type == 9;'),
    sub('takes-acpi-nvs-for-ram', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 1 && type <= 7) || type == 9 || type == 10;'),
    sub('refuses-loader-code', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 2 && type <= 7) || type == 9;'),
    sub('does-not-check-the-last-byte-of-a-word', 'end < 2; end++) {', 'end < 1; end++) {'),
    sub('loads-an-address-the-map-does-not-list', 'if (!in_ram) return RD_NOT_IN_MAP;', 'if (!in_ram) continue;'),
    sub('counts-one-byte-past-a-descriptor', 'at - start >= le64(d + 24) * 4096u', 'at - start > le64(d + 24) * 4096u'),
    drop('trusts-a-map-of-any-size', '    if (entries > MAP_DESCRIPTORS_MAX) return;\n'),
    sub('trusts-a-misaligned-stride', 'a->map_stride > MAP_STRIDE_MAX || (a->map_stride & 7) ||', 'a->map_stride > MAP_STRIDE_MAX ||'),
    sub('trusts-a-map-that-contradicts-itself', MAP_GUARD, '(void)start;'),
    # -- the SMMU: streams, banks, pages
    sub('accepts-a-bank-equal-to-numcb', STREAM_CHECK, 's->type[k] != 0 || s->cbndx[k] > s->numcb) continue;'),
    sub('reads-bank-2-for-bank-3', 'read_bank(c, &c->bank, banks[0]);', 'read_bank(c, &c->bank, banks[0] - 1);'),
    sub('reads-bank-4-for-bank-3', 'read_bank(c, &c->bank, banks[0]);', 'read_bank(c, &c->bank, banks[0] + 1);'),
    sub('reads-every-bank', '    read_bank(c, &c->bank, banks[0]);\n',
        '    for (uint32_t i = 0; i < c->smmu.numcb && i < 8; i++) read_bank(c, &c->bank, i);\n'),
    sub('prints-next-cb-after-the-reads', BANK_PAGE, BANK_REGS + '    emit(c, &next);\n'),
    sub('ignores-the-stream-mask', MATCH_RULE, '(stream_id[k] ^ (smr & 0xffffu)) & implemented'),
    drop('ignores-the-smr-valid-bit', '        if (!(smr >> 31)) continue;\n'),
    sub('follows-a-bypass-stream', '|| s->type[k] != 0 || s->cbndx[k]', '|| s->cbndx[k]'),
    sub('miscounts-the-register-pages', 's->numpage = 2u << (s->id1 >> 28 & 7);', 's->numpage = 1u << (s->id1 >> 28 & 7);'),
    drop('scans-extended-stream-ids', '    if (s->exid) return;\n'),
    sub('scans-one-smr-too-many', 'unsigned limit = s->numsmrg < SMR_SCANNED_MAX ? s->numsmrg : SMR_SCANNED_MAX;',
        'unsigned limit = s->numsmrg + 1 < SMR_SCANNED_MAX ? s->numsmrg + 1 : SMR_SCANNED_MAX;'),
    sub('reads-the-fault-address-without-a-fault', 'if (s->gfsr && room(c, 1, RESERVE_AFTER_SMMU + 1)) {', 'if (room(c, 1, RESERVE_AFTER_SMMU + 1)) {'),
    sub('trusts-a-larger-smmu-window', '{0x15000000u, 0x100000u}', '{0x15000000u, 0x200000u}'),
    sub('reads-par-of-the-bank', '!rd32(c, WIN_SMMU, page + CB_FSR, &b->fsr, "FSR");',
        '!rd32(c, WIN_SMMU, page + CB_FSR, &b->fsr, "FSR") && !rd32(c, WIN_SMMU, page + 0x50, &b->fsynr0, "PAR");'),
    # -- the xHC and its structures in RAM
    sub('ignores-the-context-size', 'uint32_t ctxsize = x->hcc1 >> 2 & 1 ? 64u : 32u, head[4];', 'uint32_t ctxsize = 32u, head[4];'),
    sub('decodes-hce-from-bit-13', 'static const uint8_t sts_bit[9] = {0, 2, 3, 4, 8, 9, 10, 11, 12};',
        'static const uint8_t sts_bit[9] = {0, 2, 3, 4, 8, 9, 10, 11, 13};'),
    sub('does-not-wrap-the-event-ring', '(k ? (here + size - k) % size : here)', '(k ? here - k : here)'),
    sub('leaves-the-event-ring-unbounded', '(erdp & ~UINT64_C(0xf)) - seg < (uint64_t)size * 16u)', '(erdp & ~UINT64_C(0xf)) - seg < (uint64_t)size * 16u * 64u)'),
    drop('scans-slots-without-a-clamp', '    if (scan > SLOTS_SCANNED) scan = SLOTS_SCANNED;\n'),
    sub('skips-the-dcbaa-alignment', 'if (!x->dcbaap || (x->dcbaap & 0x3f)) {', 'if (!x->dcbaap) {'),
    sub('skips-the-context-alignment', 'int rc = (entry & 0x3f) ? RD_ALIGN : read_words(c, entry, head, 4);', 'int rc = read_words(c, entry, head, 4);'),
    drop('keeps-reading-a-window-after-an-abort', '        if (rc == RD_FAULT || rc == RD_BAD_OP) c->dead[win] = 1;\n'),
    sub('does-not-bound-the-window', '} else if (off >= windows[win].size || windows[win].size - off < 4) {', '} else if (0) {'),
    sub('takes-all-ones-for-an-xhc', 'if (!x->cap0 || x->cap0 == 0xffffffffu) {', 'if (!x->cap0) {'),
    sub('skips-the-dwc3-id-check', '} else if (id == 0 || id == 0xffffffffu) {', '} else if (0) {'),
    # -- limits, the exception level and the NEXT lines
    sub('prints-up-to-forty-lines', '#define LINE_CAP 24u', '#define LINE_CAP 40u'),
    sub('reads-at-any-el', EL_CHECK, 'if (0) {'),
    sub('compares-the-whole-currentel', EL_CHECK, 'if (SYSREG(CurrentEL) != 8) {'),
    drop('does-not-say-it-skipped', '        say(&c, "SKIPPED_NOT_AT_EL2");\n'),
    sub('changes-the-prefix', '#define PREFIX "PAYLOAD USBSMMU "', '#define PREFIX "PAYLOAD USB "'),
    sub('does-not-check-for-load32', '    if (!a->ops.load32) {', '    if (0) {'),
    sub('prints-next-u0-after-the-reads', '    say(c, "NEXT U0");\n    read_xhc(c, 0);\n', '    read_xhc(c, 0);\n    say(c, "NEXT U0");\n'),
    sub('prints-next-smmu-after-the-reads', '    say(c, "NEXT SMMU");\n    read_smmu_global(c);\n', '    read_smmu_global(c);\n    say(c, "NEXT SMMU");\n'),
    drop('never-announces-the-rings', '    say(c, "NEXT RINGS");\n'),
    drop('never-announces-the-walk', '    say(c, "NEXT WALK");\n'),
    sub('lets-the-probes-take-the-summary-line', 'allowed = LINE_CAP > c->lines + 1 ? LINE_CAP - c->lines - 1 : 0;', 'allowed = LINE_CAP > c->lines ? LINE_CAP - c->lines : 0;'),
    drop('keeps-two-probes-on-one-page', '        if (list[i].iova >> 12 == iova >> 12) return;\n'),
    sub('reads-a-second-bank-without-room', 'if (room(c, 4, RESERVE_AFTER_CB)) read_bank(', 'if (1) read_bank('),
]


class UsbsmmuMutants(unittest.TestCase):
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
        self.assertEqual({m[1] for m in MUTANTS}, {FILE})
        for wanted in ('walks-with-the-wrong-level-shift', 'masks-the-output-address-to-47-bits', 'takes-a-block-for-a-table',
                       'loads-ram-without-the-memory-map', 'descends-past-level-3', 'accepts-a-bank-equal-to-numcb',
                       'reads-bank-2-for-bank-3', 'prints-next-cb-after-the-reads', 'reads-every-bank', 'ignores-the-context-size',
                       'decodes-hce-from-bit-13', 'walks-without-a-depth-bound', 'prints-up-to-forty-lines',
                       'takes-an-all-zero-bank-for-stage-2-only', 'takes-an-all-zero-bank-for-stage-1-off'):
            self.assertIn(f'usbsmmu-{wanted}', names)

    def test_the_unmutated_control_passes_from_a_copy(self):
        directory = BUILD / 'control'
        native.copy_tree(directory)
        done, binary = self._build('usbsmmu', directory, relaxed=False)
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


# ---- the binary --------------------------------------------------------------------------------------------------------

ANCHOR = '    map_init(&c);\n'


def asm(text):
    return [(ANCHOR, ANCHOR + f'    __asm__ volatile("{text}" ::: "memory");\n')]


def read(register):
    return [(ANCHOR, ANCHOR + f'    (void)SYSREG({register});\n')]


BAD_BINARIES = [
    # (name, [(needle, replacement)], what the allow-list check must say)
    ('a-write-to-a-system-register', asm('msr tpidr_el2, xzr'), 'msr'),
    ('a-write-to-cntvoff-el2', asm('msr cntvoff_el2, xzr'), 'msr'),
    ('a-write-to-cntpoff-el2', asm('msr S3_4_C14_C0_6, xzr'), 'msr'),
    ('an-isb', asm('isb'), 'isb'),
    ('a-dsb', asm('dsb sy'), 'dsb'),
    ('a-dmb', asm('dmb sy'), 'dmb'),
    ('a-read-of-cntvoff-el2', read('S3_4_C14_C0_3'), 'the code names'),
    ('a-read-of-cntpoff-el2', read('S3_4_C14_C0_6'), 'the code names'),
    ('a-read-of-midr-el1', read('MIDR_EL1'), 'registers read'),
    ('a-read-of-the-counter', read('CNTPCT_EL0'), 'registers read'),
    ('a-read-of-par-el1', read('PAR_EL1'), 'registers read'),
    ('an-hvc', asm('hvc #0'), 'hvc'),
    ('an-svc', asm('svc #0'), 'svc'),
    ('an-smc', asm('smc #0'), 'smc'),
    ('an-eret', asm('eret'), 'eret'),
    ('a-wfi', asm('wfi'), 'wfi'),
    ('a-wfe', asm('wfe'), 'wfe'),
    ('a-cache-operation', asm('dc civac, x0'), 'dc'),
    ('a-tlb-operation', asm('tlbi vmalle1'), 'tlbi'),
    ('an-address-translation', asm('at s1e1r, x0'), 'at'),
    ('an-exclusive-load', asm('ldxr x9, [sp]'), 'ldxr'),
    ('an-atomic-add', asm('.arch_extension lse\\n ldadd x9, x10, [sp]'), 'ldadd'),
    ('a-word-that-is-no-instruction', asm('.inst 0xffffffff'), 'not a known instruction'),
]


class UsbsmmuBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'ld.lld', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy'):
            if not have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        cls.out = BUILD / 'bad-binaries'
        shutil.rmtree(cls.out, ignore_errors=True)
        cls.out.mkdir(parents=True)
        cls.source = SOURCE.read_text(encoding='utf-8')

    def build(self, name, edits):
        text = self.source
        for needle, replacement in edits:
            self.assertEqual(text.count(needle), 1, f'{name}: {needle[:60]!r} is not in usbsmmu.c exactly once')
            text = text.replace(needle, replacement, 1)
        path = self.out / f'{name}.c'
        path.write_text(text, encoding='utf-8')
        return lib.build_payload(path, self.out, name=name, check=False)

    def test_the_unmodified_payload_is_clean_and_fits_the_policy(self):
        done, elf, flat = self.build('control', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        policy = lib.POLICIES['usbsmmu']
        self.assertEqual(lib.binary_violations(elf, flat, policy, READELF()), [])
        self.assertEqual((policy['registers'], policy['smc']), ({'currentel'}, 0))
        self.assertGreaterEqual(policy['forbid'], {'isb', 'dsb', 'dmb', 'sb'})
        self.assertFalse(policy.get('timer_offsets'), 'usbsmmu must not be allowed the timer offsets')
        size = Path(flat).stat().st_size
        self.assertTrue(8192 < size <= policy['bytes'], f'{size} bytes: the policy budget should be a suitable one, not a loose one')
        self.assertLessEqual(policy['bytes'], 20480)

    def test_exactly_one_mrs_of_currentel_and_no_other_system_instruction(self):
        done, elf, flat = self.build('mrs-count', [])
        dis = run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout.lower()
        instructions = [m.group(1) for m in (re.match(r'\s+[0-9a-f]+:\s+(\S+)', line) for line in dis.splitlines()) if m]
        self.assertEqual(instructions.count('mrs'), 1)
        self.assertEqual(len(re.findall(r'mrs\s+\w+,\s*currentel\b', dis)), 1)
        for mnemonic in ('msr', 'sys', 'sysl', 'smc', 'hvc', 'svc', 'eret', 'wfi', 'wfe', 'isb', 'dsb', 'dmb', 'dc', 'ic', 'tlbi', 'at'):
            self.assertNotIn(mnemonic, instructions)

    def test_every_forbidden_addition_is_named_by_the_allow_list_check(self):
        self.assertGreaterEqual(len(BAD_BINARIES), 20)
        for name, edits, expected in BAD_BINARIES:
            with self.subTest(binary=name):
                done, elf, flat = self.build(name, edits)
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                problems = lib.binary_violations(elf, flat, lib.POLICIES['usbsmmu'], READELF())
                self.assertTrue(problems, 'the check passed a binary it must refuse')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_only_the_timer_payload_may_name_the_timer_offsets_and_only_psci_may_have_an_smc(self):
        self.assertEqual([name for name, policy in lib.POLICIES.items() if policy.get('timer_offsets')], ['timer'])
        self.assertEqual({name: policy['smc'] for name, policy in lib.POLICIES.items()}, {'state': 0, 'psci': 1, 'timer': 0, 'usbsmmu': 0})
        self.assertEqual({lib.CNTVOFF_EL2, lib.CNTPOFF_EL2} & lib.POLICIES['usbsmmu']['registers'], set())
        self.assertEqual(lib.POLICIES['state']['bytes'], 4096)
        self.assertEqual(lib.POLICIES['psci']['registers'], {'currentel', 'mpidr_el1'})
        self.assertEqual(lib.POLICIES['timer']['registers'], lib.TIMER_REGISTERS)

    def test_the_binary_is_refused_under_every_other_policy_and_the_others_under_its_own(self):
        done, elf, flat = self.build('under-others', [])
        for other in ('state', 'psci', 'timer'):
            with self.subTest(policy=other):
                self.assertTrue(lib.binary_violations(elf, flat, lib.POLICIES[other], READELF()))
        out = BUILD / 'others'
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        for other in ('state', 'psci', 'timer'):
            with self.subTest(payload=other):
                done, o_elf, o_flat = lib.build_payload(ROOT / 'payloads' / f'{other}.c', out, name=other, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertTrue(lib.binary_violations(o_elf, o_flat, lib.POLICIES['usbsmmu'], READELF()),
                                f'{other} passes the usbsmmu policy: the policy is too loose')

    def test_a_read_of_a_timer_offset_is_named_by_encoding_whichever_spelling_is_used(self):
        for register in ('cntvoff_el2', 'CNTVOFF_EL2', 'S3_4_C14_C0_3', 'S3_4_C14_C0_6'):
            with self.subTest(register=register):
                done, elf, flat = self.build('reads-' + register, read(register))
                self.assertEqual(done.returncode, 0, done.stderr[-500:])
                problems = lib.binary_violations(elf, flat, lib.POLICIES['usbsmmu'], READELF())
                self.assertTrue(any('the code names' in p for p in problems), problems)
                self.assertTrue(any('registers read' in p for p in problems), problems)


# ---- the manifest chain ------------------------------------------------------------------------------------------------


class UsbsmmuChain(unittest.TestCase):
    tool = ROOT / 'tools' / 'sp11_payload_manifest.py'
    CHAIN = ('psci', 'usbsmmu', 'timer')

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
        cls.bins = {name: (cls.out / 'payloads' / f'{name}.bin') for name in ('state', 'psci', 'usbsmmu', 'timer')}

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
        return [struct.unpack_from('<Q32s256s', raw, 32 + i * size) for i in range(count)]

    def test_psci_usbsmmu_timer_is_three_of_the_five_files_in_that_order(self):
        base, done = self.stick(self.CHAIN)
        entries = self.entries(base)
        self.assertEqual([e[2].rstrip(b'\0').decode() for e in entries], ['\\SP11\\PSCI.BIN', '\\SP11\\USBSMMU.BIN', '\\SP11\\TIMER.BIN'])
        for (size, digest, _), name in zip(entries, self.CHAIN):
            data = self.bins[name].read_bytes()
            self.assertEqual((size, digest), (len(data), hashlib.sha256(data).digest()))
        for text in ('(INDEX=0, payload, called in manifest order)', '(INDEX=1, payload, called in manifest order)',
                     '(INDEX=2, payload, called in manifest order)', 'SP11\\USBSMMU.BIN'):
            self.assertIn(text, done.stdout)
        self.assertEqual(sorted(p.name for p in (base / 'SP11').iterdir()), ['PAYLOAD.MAN', 'PSCI.BIN', 'TIMER.BIN', 'USBSMMU.BIN'])
        self.assertEqual((base / 'SP11' / 'USBSMMU.BIN').read_bytes(), self.bins['usbsmmu'].read_bytes())

    def test_the_runners_own_validator_and_loader_take_the_chain_as_three_payloads(self):
        harness = BUILD / 'kinds-harness'
        sources = [ROOT / 'tools' / 'testdata' / 'sp11-payload-kinds-harness.c'] + [
            UEFI / name for name in ('sp11-payload-load.c', 'sp11-payload-plan.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c')]
        done = run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1',
                    '-I', str(UEFI)] + [str(s) for s in sources] + ['-o', str(harness)])
        self.assertEqual(done.returncode, 0, done.stderr)
        base, _ = self.stick(self.CHAIN)
        ours = run([str(harness), str(base / 'SP11' / 'PAYLOAD.MAN')])
        self.assertEqual(ours.returncode, 0, ours.stdout + ours.stderr)
        self.assertEqual(ours.stdout.splitlines(), ['\\SP11\\PSCI.BIN code', '\\SP11\\USBSMMU.BIN code', '\\SP11\\TIMER.BIN code'])

    def test_four_payloads_are_four_of_the_five_files_and_a_data_file_may_follow(self):
        base, _ = self.stick(('state', 'psci', 'usbsmmu', 'timer'))
        self.assertEqual(len(self.entries(base)), 4)
        self.assertEqual(sorted(p.name for p in (base / 'SP11').iterdir()), ['PAYLOAD.MAN', 'PSCI.BIN', 'STATE.BIN', 'TIMER.BIN', 'USBSMMU.BIN'])

    def test_usbsmmu_stays_a_handful_of_pages(self):
        size = self.bins['usbsmmu'].stat().st_size
        self.assertLessEqual(size, lib.POLICIES['usbsmmu']['bytes'])
        self.assertLess(-(-size // 4096), 8, 'the runner reads, declares and hashes every page of it')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
