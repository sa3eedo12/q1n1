#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The smmuprobe payload of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-SMMUPROBE.md): its host test, its seeded bugs and
the allow-list of its binary. The document is checked by tools/test-q1n1-sp11-payload-smmuprobe-doc.py, the engine of the memory check by
tools/test-q1n1-sp11-payload-memcheck.py.

    python3 tools/test-q1n1-sp11-payload-smmuprobe.py

  * SmmuprobeNative: tools/test-q1n1-sp11-payload-smmuprobe.c (ten suites over a modelled machine: scripted configuration pages, SMMU
    registers and RAM that fault where they are told to, a translation model, a memory map pressed against PROT_NONE pages, a clock; every
    load judged as it is made; a fuzz against an oracle written another way), built and run by the machinery of
    tools/test-q1n1-sp11-payload.py under ASan and UBSan, and again with a 14-line and a 10-line page and with a load cap of 20.
  * SmmuprobeSource: what no run shows (the ops it calls, the registers it names, one AT, no writable global, the font, the order of its
    groups, the constants against config/boards/sp11.json when SNAPINTOSH_DIR is set).
  * SmmuprobeMutants: seeded bugs in smmuprobe.c, payload-mmu.h and payload-page.h, each of which the host program must reject.
  * SmmuprobeBinary: the allow-list applied to smmuprobe.bin (MRS of three registers, exactly AT S1E2R, one ISB, stores only through the
    stack, loads only through the stack, the image, the arguments and pointers they hold: every device word is read through load32) with
    seeded bad binaries, and the build's reproducibility.

The policy of the binary is local to this file: the shared registry of tools/sp11_payload_testlib.py is not extended, so the shared build
test does not audit this payload. Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
import json
import os
import re
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_mmu_testkit as kit  # noqa: E402
import sp11_payload_testlib as lib  # noqa: E402

SUITES = ('unit', 'config', 'smmu', 'verdict', 'ack', 'pages', 'tablepages', 'ram', 'counter', 'el', 'budget', 'worst', 'fuzz')
MOST_LINES = 30                         # the worst world and the fuzz print at most this many of the 36 lines
native = kit.native_module('smmuprobe')
native.PROGRAMS['smmuprobe'] = ('tools/test-q1n1-sp11-payload-smmuprobe.c', ['sp11-payload-text.c'], len(SUITES), 30000, 'smmuprobe')
native.HOST_PAYLOADS['smmuprobe'] = 'smmuprobe.c'
native.PAYLOADS_COPIED = list(native.PAYLOADS_COPIED) + ['smmuprobe.c']
BUILD = native.BUILD
SOURCE = ROOT / 'payloads' / 'smmuprobe.c'
TOOLS = ROOT / 'tools'
run, have, READELF = lib.run, lib.have, kit.READELF
POLICY = {'registers': {'currentel', 'cntfrq_el0', 'par_el1'}, 'smc': 0, 'bytes': 16384, 'forbid': {'dsb', 'dmb', 'sb', 'sev', 'sevl'},
          'allow': {'at': {'s1e2r'}}, 'read_only': True}
OWN_FILES = [SOURCE, TOOLS / 'test-q1n1-sp11-payload-smmuprobe.c', TOOLS / 'test-q1n1-sp11-payload-smmuprobe-world.h',
             TOOLS / 'test-q1n1-sp11-payload-smmuprobe-fuzz.h', Path(__file__)]


def variant(name, flags, suites):
    """The host program built with `flags` (a smaller page or load cap), run on `suites`: (build result, {suite: (code, output)})."""
    out = BUILD / f'variant-{name}'
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'test-smmuprobe'
    cmd = ['clang'] + native.SANITIZE + native.GATES + ['-I', str(native.UEFI), '-I', str(native.PAYLOADS), '-DQ1N1_PAYLOAD_HOST_TEST=1'] + flags + [
        str(TOOLS / 'test-q1n1-sp11-payload-smmuprobe.c'), str(native.UEFI / 'sp11-payload-text.c'), str(SOURCE), '-o', str(binary)]
    done = run(cmd)
    return done, {s: native.run_program(binary, s) for s in suites} if done.returncode == 0 else {}


class SmmuprobeNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_the_suites_pass(self):
        native.Native._check(self, 'smmuprobe')

    def test_each_suite_runs_alone(self):
        done, binary = native.build_program('smmuprobe', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite in SUITES:
            with self.subTest(suite=suite):
                code, output = native.run_program(binary, suite)
                self.assertEqual(code, 0, output)
                self.assertRegex(output, r'PASS: 1 payload smmuprobe suites, \d+ checks')

    def test_the_most_lines_are_measured_and_are_within_the_budget_with_room(self):
        done, binary = native.build_program('smmuprobe', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary, 'lines-report')
        self.assertEqual((code, output.strip()), (0, f'LINES_MAX={MOST_LINES}'), 'the worst world and the fuzz print at most 30 of the 36 lines')

    def test_a_smaller_page_drops_lines_and_counts_them_but_never_the_next_lines_the_verdict_or_the_last(self):
        for lines in (14, 10):
            with self.subTest(budget=lines):
                done, results = variant(f'page{lines}', [f'-DTEST_BUDGET={lines}', f'-DPL_PAGE_LINES={lines}u'], ('budget', 'worst', 'fuzz'))
                self.assertEqual(done.returncode, 0, done.stderr)
                for suite, (code, output) in results.items():
                    self.assertEqual(code, 0, f'{suite}: {output[-400:]}')

    def test_a_small_load_cap_stops_the_loads_and_says_so(self):
        done, results = variant('cap20', ['-DTEST_LOAD_CAP=20', '-DLOAD_CAP=20u'], ('budget',))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(results['budget'][0], 0, results['budget'][1])


class SmmuprobeSource(unittest.TestCase):
    code = kit.code_of(SOURCE)
    header = kit.code_of(ROOT / 'payloads' / 'payload-mmu.h')
    page = kit.code_of(ROOT / 'payloads' / 'payload-page.h')

    def test_the_payload_calls_only_load32_and_counter_and_the_helpers_puts_and_hex(self):
        self.assertEqual(set(re.findall(r'ops\.(\w+)', self.code)), {'load32', 'counter'})
        helpers = kit.code_of(ROOT / 'payloads' / 'payload-util.h') + self.page + self.header
        self.assertEqual(set(re.findall(r'ops\.(\w+)', helpers)), {'puts', 'hex'})

    def test_every_device_and_ram_word_is_read_by_one_call_of_load32(self):
        self.assertEqual(len(re.findall(r'ops\.load32\(', self.code)), 1, 'the one chokepoint, rd()')
        self.assertEqual(len(re.findall(r'!a->ops\.load32', self.code)), 1)
        self.assertEqual(re.findall(r'\bvolatile\b(?!\s*\()', self.code), [], 'no raw pointer: every word of a device or of RAM comes from the op')

    def test_the_registers_the_source_names_are_the_policys(self):
        named = {name.lower() for name in re.findall(r'SYSREG\((\w+)\)', self.code)} - {'name'}
        self.assertEqual({lib.SYSTEM_REGISTER_ALIASES.get(n, n) for n in named}, POLICY['registers'] - {'par_el1'})
        self.assertNotRegex(self.code.upper(), r'CNTPOFF|CNTVOFF|S3_4_C14_C0_[36]', 'the timer offsets are never named')

    def test_one_at_one_isb_one_read_of_par_el1_and_no_other_inline_assembly(self):
        self.assertEqual(self.header.count('at s1e2r'), 1)
        self.assertEqual(len(re.findall(r'__asm__', self.header)), 1)
        self.assertEqual(len(re.findall(r'__asm__', self.code)), 1, 'the MRS macro')
        self.assertNotRegex(self.header + self.code, r'\b(msr|dc |ic |tlbi|smc|hvc)\b')

    def test_no_writable_global_and_every_table_is_constant(self):
        for text in (self.code, self.header, self.page):
            for declaration in re.findall(r'^static\b[^\n(]*;', text, re.M):
                self.assertRegex(declaration, r'\bconst\b|\binline\b', declaration)
            self.assertEqual(re.findall(r'^static (?!const|inline|__attribute__)[^\n(]*$', text, re.M), [])

    def test_the_names_are_returned_from_switches_not_looked_up_in_a_table(self):
        self.assertNotRegex(self.code, r'mode_name|why_name', 'a pointer table needs relocations the ELF check refuses')
        self.assertEqual(len(re.findall(r'^INLINE_NAME const char \*(mode|why)_text', self.code, re.M)), 2)

    def test_the_groups_come_in_the_documented_order_each_behind_its_next_line(self):
        entry = self.code[self.code.index('uint64_t payload_entry(const struct q1n1_payload_args *a)\n{'):]
        order = [entry.index(token) for token in ('"START"', 'REFUSED', '"MAP"', 'report_head(a, &c, "RP"', 'report_head(a, &c, "EP"',
                                                  'announce(a, PG(&c), freq, "PCIE_CAPS")', 'report_pcie(a, &c, "RP.PCIE"',
                                                  'report_aer(a, &c, "EP.AER"', 'announce(a, PG(&c), freq, "SMMU_REGISTERS")',
                                                  'read_smmu(a, &c, &view)', 'report_stream(', 'say_verdict(', '"DONE"')]
        self.assertEqual(order, sorted(order))
        self.assertEqual(entry.count('announce('), 2)
        self.assertEqual(entry.count('read_smmu('), 1)
        self.assertEqual(len(re.findall(r'pl_say\(a, p, "NEXT", text\.buf, 1\)', self.code)), 1, 'a NEXT line is essential')

    def test_the_registers_it_reads_are_the_briefs_in_the_briefs_order(self):
        rows = re.findall(r'\{"(\w+)", (0x[0-9a-f]+), (\d)\}', self.code)
        self.assertEqual([r[0] for r in rows], ['IDR0', 'IDR1', 'IDR2', 'IDR3', 'IDR4', 'IDR5', 'IIDR', 'AIDR', 'CR0', 'CR0ACK', 'GBPA',
                                                'GERROR', 'STRTAB_BASE', 'STRTAB_CFG'])
        self.assertEqual([int(r[1], 16) for r in rows], [0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x44, 0x60, 0x80, 0x88])
        self.assertEqual([r[2] for r in rows], ['0'] * 12 + ['1', '0'], 'only STRTAB_BASE is 64 bits')
        self.assertIn('#define SMMU_READ_END 0x90u', self.code, 'no register above STRTAB_BASE_CFG is read')

    def test_the_files_are_within_the_size_limits_and_carry_the_licence(self):
        for path in OWN_FILES:
            with self.subTest(file=path.name):
                text = path.read_text(encoding='utf-8')
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                self.assertIn('SPDX-License-Identifier: MIT', text[:200])
                text.encode('ascii')

    def test_the_text_it_prints_is_in_the_page_font(self):
        for literal in re.findall(r'"([^"\n]*)"', self.code + self.header + self.page):
            if literal.endswith('.h') or re.search(r'%|\\n|mrs ', literal) or literal in ('=r', 'r', 'memory'):
                continue                                              # an include, and the inline assemblies
            self.assertRegex(literal, r'^[A-Z0-9:\-./=?()_ ]*$', literal)

    def test_the_constants_are_the_descriptors_when_the_snapintosh_tree_is_given(self):
        tree = os.environ.get('SNAPINTOSH_DIR')
        if not tree or not (Path(tree) / 'config' / 'boards' / 'sp11.json').is_file():
            self.skipTest('SNAPINTOSH_DIR not set (or no config/boards/sp11.json in it): the constants are not compared with the descriptor')
        board = json.loads((Path(tree) / 'config' / 'boards' / 'sp11.json').read_text(encoding='utf-8'))
        if 'storage' not in board:
            self.skipTest('the descriptor of SNAPINTOSH_DIR has no storage section: the constants are not compared with it')
        nvme = board['storage']['nvme']
        value = lambda name: int(re.search(rf'#define {name} \(?(?:UINT64_C\()?(0x[0-9a-fA-F]+|\d+)', self.code).group(1), 0)  # noqa: E731
        self.assertEqual(int(nvme['ecam']['base'], 16), value('ECAM_BASE'))
        self.assertEqual((nvme['root_port']['bus'], nvme['root_port']['device'], nvme['root_port']['function']), (value('RP_BUS'), 0, 0))
        self.assertEqual((nvme['endpoint']['bus'], nvme['endpoint']['device'], nvme['endpoint']['function']), (value('EP_BUS'), 0, 0))
        self.assertEqual(int(nvme['stream']['rid_base'], 16), 0)
        rid = nvme['endpoint']['bus'] << 8
        self.assertEqual(rid, value('EP_RID'))
        self.assertEqual(int(nvme['stream']['stream_base'], 16), value('STREAM_BASE'))
        smmu = {s['name']: s for s in board['smmu']}[nvme['smmu']]
        self.assertEqual((smmu['kind'], int(smmu['base'], 16)), ('smmu-v3', value('SMMU_BASE')))
        self.assertEqual(nvme['segment'], 6)


FILE = 'payloads/smmuprobe.c'
HEADER = 'payloads/payload-mmu.h'
PAGE = 'payloads/payload-page.h'


def sub(name, old, new, file=FILE):
    return kit.mutant('smmuprobe', name, file, old, new)


def multi(name, edits):
    """A seeded bug of several edits at once (a caller's bug and the guard that would have stopped it): (name, file, edits, programs, error)."""
    return (f'smmuprobe-{name}', FILE, edits, ['smmuprobe'], None)


MUTANTS = [
    # -- the reading discipline: which words are read, and never after a read that did not return
    sub('caller-page-bound-off-by-one', 'if (f->dead || off >= CFG_PAGE_BYTES) return r;', 'if (f->dead || off > CFG_PAGE_BYTES) return r;'),
    multi('caller-and-guard-bounds-off-by-one', [
        ('if (f->dead || off >= CFG_PAGE_BYTES) return r;', 'if (f->dead || off > CFG_PAGE_BYTES) return r;'),
        ('addr < ENDPOINT_PAGE + CFG_PAGE_BYTES) return 1;', 'addr <= ENDPOINT_PAGE + CFG_PAGE_BYTES) return 1;')]),
    sub('the-entry-is-read-64-bytes-late', 'w[i] = rd64(a, c, ste + 8u * i);', 'w[i] = rd64(a, c, ste + 64u + 8u * i);'),
    multi('the-entry-is-read-64-bytes-late-and-the-guard-is-open', [
        ('w[i] = rd64(a, c, ste + 8u * i);', 'w[i] = rd64(a, c, ste + 64u + 8u * i);'),
        ('return c->ram_hi && addr >= c->ram_lo && addr < c->ram_hi && c->ram_hi - addr >= 4u;', 'return c->ram_hi != 0;')]),
    sub('a-failed-config-read-does-not-stop-the-function', 'if (r.state != RS_VALUE) f->dead = 1;', ''),
    sub('a-failed-smmu-read-does-not-stop-the-group', 'if (v->reg[i].state != RS_VALUE) stopped = 1;', ''),
    sub('a-failed-low-word-does-not-stop-the-pair', 'if (lo.state != RS_VALUE) return lo;', ''),
    sub('the-entry-is-read-on-after-a-fault', 'if (w[i].state != RS_VALUE) return 0;', ''),
    sub('the-high-word-is-eight-bytes-on', 'hi = rd(a, c, addr + 4u);', 'hi = rd(a, c, addr + 8u);'),
    sub('the-pair-drops-its-high-word', 'lo.value |= hi.value << 32;', ''),
    sub('the-entry-has-three-doublewords', 'for (unsigned i = 0; i < 4u; i++) {\n        w[i] = rd64', 'for (unsigned i = 0; i < 3u; i++) {\n        w[i] = rd64'),
    sub('the-faults-are-counted-as-refusals', 'if (r.state == RS_FAULT) c->faults++;', 'if (r.state == RS_FAULT) c->refused++;'),
    sub('the-loads-are-not-counted', 'c->loads++;', ''),
    # -- which RAM is read: usable types only, any overlap with another type refuses, the edges
    sub('reserved-memory-is-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 0 && type <= 7) || type == 9;'),
    sub('unusable-memory-is-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 1 && type <= 8) || type == 9;'),
    sub('mmio-is-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 1 && type <= 7) || type == 9 || type == 11;'),
    sub('acpi-nvs-for-reclaim', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 1 && type <= 7) || type == 10;'),
    sub('acpi-reclaim-is-not-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return type >= 1 && type <= 7;'),
    sub('loader-code-is-not-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 2 && type <= 7) || type == 9;'),
    sub('conventional-memory-is-not-readable', 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 1 && type <= 6) || type == 9;'),
    sub('every-type-is-approved', 'if (!usable_type(*type)) return 0;', ''),
    sub('another-type-overlapping-is-ignored', 'if (!usable_type((int)d.type)) return (int)d.type;', 'if (!usable_type((int)d.type)) continue;'),
    sub('a-descriptor-just-after-overlaps', 'addr + bytes <= d.start) continue;', 'addr + bytes < d.start) continue;'),
    sub('a-descriptor-just-before-overlaps', 'addr >= d.end || ', 'addr > d.end || '),
    sub('the-last-bytes-of-an-extent-are-refused', 'd.end - addr >= bytes) found', 'd.end - addr > bytes) found'),
    sub('an-unreadable-map-is-read', 'if (pl_map_check(a) != PL_MAP_OK) return -2;', ''),
    sub('the-entry-approval-is-eight-bytes', 'approve_ram(a, c, ste, SIZE_STE, &type)', 'approve_ram(a, c, ste, 8u, &type)'),
    # -- where the entry is
    sub('the-descriptor-slot-is-four-bytes', '*l1_at = base + (sid >> split) * 8u;', '*l1_at = base + (sid >> split) * 4u;'),
    sub('the-descriptor-slot-shifts-one-more', '*l1_at = base + (sid >> split) * 8u;', '*l1_at = base + (sid >> (split + 1u)) * 8u;'),
    sub('a-linear-entry-is-32-bytes', '*ste = base + sid * SIZE_STE;', '*ste = base + sid * 32u;'),
    sub('a-level-2-entry-is-32-bytes', '*ste = (l1->value & ADDR_51_6) + index * SIZE_STE;', '*ste = (l1->value & ADDR_51_6) + index * 32u;'),
    sub('the-index-mask-is-too-wide', 'index = sid & (((uint64_t)1 << split) - 1u);', 'index = sid & (((uint64_t)1 << (split + 8u)) - 1u);'),
    sub('the-base-is-48-bits', '#define ADDR_51_6 UINT64_C(0x000fffffffffffc0)', '#define ADDR_51_6 UINT64_C(0x0000ffffffffffc0)'),
    sub('the-base-keeps-its-low-bits', '#define ADDR_51_6 UINT64_C(0x000fffffffffffc0)', '#define ADDR_51_6 UINT64_C(0x000fffffffffffff)'),
    sub('the-translation-table-is-48-bits', '#define ADDR_51_4 UINT64_C(0x000ffffffffffff0)', '#define ADDR_51_4 UINT64_C(0x0000fffffffffff0)'),
    sub('the-stream-id-is-beyond-the-end-of-a-table-one-bit-late', 'if (sid >> log2size) return W_SID_BEYOND_TABLE;',
        'if (sid >> (log2size + 1u)) return W_SID_BEYOND_TABLE;'),
    sub('format-2-is-two-levels', 'if (fmt > 1u) return W_FORMAT;', 'if (fmt > 2u) return W_FORMAT;'),
    sub('split-8-is-refused-and-9-accepted', 'if (split != 6u && split != 8u && split != 10u) return W_SPLIT;',
        'if (split != 6u && split != 9u && split != 10u) return W_SPLIT;'),
    sub('the-span-is-four-bits', 'span = l1->value & 0x1fu;', 'span = l1->value & 0xfu;'),
    sub('the-span-is-the-entry-count', 'if (index >> (span - 1u)) return W_L2_SPAN;', 'if (index >> span) return W_L2_SPAN;'),
    sub('the-span-has-one-entry-fewer', 'if (index >> (span - 1u)) return W_L2_SPAN;', 'if (index >> (span - 2u)) return W_L2_SPAN;'),
    sub('a-missing-level-2-table-is-not-noticed', 'if (!span) return W_NO_L2;', ''),
    sub('a-failed-descriptor-read-is-not-noticed', 'if (l1->state != RS_VALUE) return W_L1_NOT_READ;', ''),
    # -- what the entry and the registers say
    sub('abort-config-is-bypass', 'case 0: return M_ABORT;', 'case 0: return M_BYPASS;'),
    sub('stage-1-config-is-stage-2', 'case 5: return M_S1;', 'case 5: return M_S2;'),
    sub('both-stages-config-is-stage-1', 'case 7: return M_S1S2;', 'case 7: return M_S1;'),
    sub('an-invalid-entry-is-decoded-by-its-config', 'if (!(dw0 & 1u)) return M_INVALID;', ''),
    sub('gbpa-abort-is-bit-21', 'gbpa->value >> 20 & 1u ? M_ABORT_GLOBAL', 'gbpa->value >> 21 & 1u ? M_ABORT_GLOBAL'),
    sub('smmuen-is-bit-1', 'if (!(ack->value & 1u)) {', 'if (!(ack->value & 2u)) {'),
    sub('a-missing-gbpa-is-not-noticed', 'if (gbpa->state != RS_VALUE) {', 'if (0) {'),
    sub('one-table-register-is-enough', 'if (tab->state != RS_VALUE || cfgreg->state != RS_VALUE) {', 'if (tab->state != RS_VALUE && cfgreg->state != RS_VALUE) {'),
    sub('a-missing-cr0-is-not-noticed', 'if (cr0->state != RS_VALUE) {', 'if (0) {'),
    sub('a-missing-cr0ack-is-not-noticed', 'if (ack->state != RS_VALUE) {', 'if (0) {'),
    sub('a-cr0ack-that-differs-is-not-noticed', 'if (cr0->value != ack->value) {', 'if (0) {'),
    sub('only-the-enable-bit-of-cr0ack-is-compared', 'if (cr0->value != ack->value) {', 'if ((cr0->value ^ ack->value) & 1u) {'),
    sub('only-the-low-byte-of-cr0ack-is-compared', 'if (cr0->value != ack->value) {', 'if ((cr0->value ^ ack->value) & 0xffu) {'),
    sub('a-disagreement-is-only-noticed-when-the-ack-says-enabled', 'if (cr0->value != ack->value) {', 'if (cr0->value != ack->value && ack->value & 1u) {'),
    sub('a-skipped-group-is-not-said', 'verdict.why = W_SKIPPED;', ''),
    sub('config-is-two-bits', 'pl_add_dec(a, PG(c), "CONFIG", w[0].value >> 1 & 7u);', 'pl_add_dec(a, PG(c), "CONFIG", w[0].value >> 1 & 3u);'),
    sub('sl0-from-the-wrong-bits', 'pl_add_dec(a, PG(c), "SL0", w[2].value >> 38 & 3u);', 'pl_add_dec(a, PG(c), "SL0", w[2].value >> 37 & 3u);'),
    sub('tg-from-the-wrong-bits', 'pl_add_dec(a, PG(c), "TG", w[2].value >> 46 & 3u);', 'pl_add_dec(a, PG(c), "TG", w[2].value >> 45 & 3u);'),
    sub('aa64-from-the-wrong-bit', 'pl_add_dec(a, PG(c), "AA64", w[2].value >> 51 & 1u);', 'pl_add_dec(a, PG(c), "AA64", w[2].value >> 52 & 1u);'),
    sub('t0sz-from-the-wrong-bits', 'pl_add_dec(a, PG(c), "T0SZ", w[2].value >> 32 & 0x3fu);', 'pl_add_dec(a, PG(c), "T0SZ", w[2].value >> 33 & 0x3fu);'),
    sub('vmid-is-eight-bits', 'pl_add_dec(a, PG(c), "VMID", w[2].value & 0xffffu);', 'pl_add_dec(a, PG(c), "VMID", w[2].value & 0xffu);'),
    sub('the-entry-is-not-asked-of-the-mmu', '    if (add_walk(a, c, "MAP", ste, 0) != PS_OK) {', '    if (0) {'),
    sub('the-descriptor-is-not-asked-of-the-mmu', '    pl_walk_page(*l1_at, l1_walk);\n', ''),
    sub('the-registers-tried-are-not-counted', 'v->made++;', ''),
    # -- the configuration space
    sub('an-absent-function-is-read-on', '        pl_page_add(a, PG(c), "ABSENT");\n        f->dead = 1;', '        pl_page_add(a, PG(c), "ABSENT");'),
    sub('a-vendor-of-ones-is-not-absent', ' || (id.value & 0xffffu) == 0xffffu)', ')'),
    sub('the-multi-function-bit-hides-a-bridge', 'else if (hdr.state == RS_VALUE && (hdr.value >> 16 & 0x7fu) == 1u) {',
        'else if (hdr.state == RS_VALUE && (hdr.value >> 16 & 0xffu) == 1u) {'),
    sub('status-bit-4-is-bit-19', 'if (cmd.state == RS_VALUE && (cmd.value >> 20 & 1u)) {', 'if (cmd.state == RS_VALUE && (cmd.value >> 19 & 1u)) {'),
    sub('the-capability-pointer-is-not-aligned', 'h->cap_ptr = (uint8_t)(ptr.value & 0xfcu);', 'h->cap_ptr = (uint8_t)(ptr.value & 0xffu);'),
    sub('the-capability-list-is-walked-32-times', '#define CAP_STEPS 16u', '#define CAP_STEPS 32u'),
    sub('the-extended-list-is-walked-48-times', '#define EXT_STEPS 24u', '#define EXT_STEPS 48u'),
    sub('a-pointer-below-0x40-is-followed', 'ptr >= 0x40u && ptr < 0x100u;', 'ptr >= 0x30u && ptr < 0x100u;'),
    sub('the-capability-id-is-sixteen-bits', '(r.value & 0xffu) == CAP_PCIE', '(r.value & 0xffffu) == CAP_PCIE'),
    sub('a-next-pointer-is-not-aligned', 'ptr = (uint32_t)(r.value >> 8) & 0xfcu;', 'ptr = (uint32_t)(r.value >> 8) & 0xffu;'),
    sub('the-port-type-is-bit-21', 'h->pcie_type = (uint8_t)(hdr.value >> 20 & 15u);', 'h->pcie_type = (uint8_t)(hdr.value >> 21 & 15u);'),
    sub('version-1-has-link-registers-2', 'if (version >= 2u) {', 'if (version >= 1u) {'),
    sub('the-version-is-one-bit-up', 'version = (uint32_t)(hdr.value >> 16 & 15u);', 'version = (uint32_t)(hdr.value >> 17 & 15u);'),
    sub('the-aer-id-is-eight-bits', '(r.value & 0xffffu) == EXT_AER', '(r.value & 0xffu) == EXT_AER'),
    sub('an-extended-pointer-is-not-aligned', 'ptr = (uint32_t)(r.value >> 20) & 0xffcu;', 'ptr = (uint32_t)(r.value >> 20) & 0xfffu;'),
    sub('an-all-ones-extended-header-is-followed', ' || r.value == 0xffffffffu) break;', ') break;'),
    sub('a-faulting-aer-header-is-called-none', 'r.state == RS_FAULT ? "AER=FAULT" : ', ''),
    sub('every-bridge-has-a-root-error-status', 'if (h->pcie_type == PCIE_TYPE_ROOT_PORT)', 'if (h->pcie_type != 0)'),
    sub('the-link-speed-table-stops-at-gen5', 'speed >= 1u && speed <= 6u ? "GEN" : "SPEED"', 'speed >= 1u && speed <= 5u ? "GEN" : "SPEED"'),
    sub('the-link-width-is-five-bits', 'width = sta >> 4 & 63u;', 'width = sta >> 4 & 31u;'),
    sub('dlla-without-the-capability', 'if (cap.state == RS_VALUE && (cap.value >> 20 & 1u)) pl_add_dec', 'if (cap.state == RS_VALUE) pl_add_dec'),
    sub('dlla-is-bit-28', 'dw.value >> 29 & 1u);', 'dw.value >> 28 & 1u);'),
    # -- the waits and the guards of the entry
    sub('the-wait-is-nothing', '#define WAIT_BEFORE_READ_S 8u', '#define WAIT_BEFORE_READ_S 0u'),
    sub('the-wait-is-eighty-seconds', '#define WAIT_BEFORE_READ_S 8u', '#define WAIT_BEFORE_READ_S 80u'),
    sub('a-counter-going-back-ends-the-wait', '        if (now < start) return 0;\n', ''),
    sub('a-stuck-counter-is-waited-for-ever', 'if (++same >= COUNTER_STUCK_READS) return 0;', 'if (++same >= COUNTER_STUCK_READS) return 1;'),
    sub('the-counter-op-is-not-checked', 'if (!a->ops.counter) {', 'if (0) {'),
    sub('a-frequency-of-zero-is-used', 'if (freq < COUNTER_HZ_MIN || freq > COUNTER_HZ_MAX) freq = COUNTER_HZ_DEFAULT;', ''),
    sub('the-lowest-frequency-is-refused', 'if (freq < COUNTER_HZ_MIN ||', 'if (freq <= COUNTER_HZ_MIN ||'),
    sub('the-highest-frequency-is-refused', 'freq > COUNTER_HZ_MAX)', 'freq >= COUNTER_HZ_MAX)'),
    sub('it-runs-below-el2', 'if ((current_el >> 2 & 3) != 2) {', 'if (0) {'),
    sub('el3-is-taken-for-el2', 'if ((current_el >> 2 & 3) != 2) {', 'if ((current_el >> 2 & 3) < 2) {'),
    sub('the-arguments-are-not-checked', '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n', ''),
    sub('a-missing-load-op-is-not-noticed', 'if (!a->ops.load32) {', 'if (0) {'),
    sub('the-stream-is-the-wrong-rid', '#define EP_RID 0x100u', '#define EP_RID 0x101u'),
    sub('the-stream-base-is-wrong', '#define STREAM_BASE UINT64_C(0x60000)', '#define STREAM_BASE UINT64_C(0x50000)'),
    sub('the-smmu-is-elsewhere', '#define SMMU_BASE UINT64_C(0x15400000)', '#define SMMU_BASE UINT64_C(0x15410000)'),
    sub('the-ecam-is-elsewhere', '#define ECAM_BASE UINT64_C(0x70000000)', '#define ECAM_BASE UINT64_C(0x70100000)'),
    sub('the-endpoint-is-on-bus-2', '#define EP_BUS 1u', '#define EP_BUS 2u'),
    sub('the-first-register-is-the-second', '{"IDR0", 0x00, 0}', '{"IDR0", 0x04, 0}'),
    sub('gbpa-is-read-at-the-wrong-offset', '{"GBPA", 0x44, 0}', '{"GBPA", 0x48, 0}'),
    sub('strtab-base-is-a-single-word', '{"STRTAB_BASE", 0x80, 1}', '{"STRTAB_BASE", 0x80, 0}'),
    # -- what the MMU said of a page: nothing is read where it says no
    sub('an-unmapped-page-may-be-read', '    if (!w->mapped) return PS_UNMAPPED;\n', ''),
    sub('a-normal-page-of-a-device-may-be-read', '    if (device && pl_attr_class(w->attr) != PL_ATTR_DEVICE) return PS_NOT_DEVICE;\n', ''),
    sub('only-non-cacheable-normal-is-refused-for-a-device', 'if (device && pl_attr_class(w->attr) != PL_ATTR_DEVICE)', 'if (device && pl_attr_class(w->attr) == PL_ATTR_NC)'),
    sub('write-back-normal-is-allowed-for-a-device', 'if (device && pl_attr_class(w->attr) != PL_ATTR_DEVICE)', 'if (device && pl_attr_class(w->attr) < PL_ATTR_WB)'),
    sub('ram-is-held-to-the-device-rule-in-the-descriptor', 'page_verdict(l1_walk, 0) != PS_OK', 'page_verdict(l1_walk, 1) != PS_OK'),
    sub('ram-is-held-to-the-device-rule-in-the-entry', 'add_walk(a, c, "MAP", ste, 0) != PS_OK', 'add_walk(a, c, "MAP", ste, 1) != PS_OK'),
    sub('an-unmapped-descriptor-is-read', '    if (page_verdict(l1_walk, 0) != PS_OK) return W_L1_UNMAPPED;\n', ''),
    sub('an-unmapped-entry-is-read', 'add_walk(a, c, "MAP", ste, 0) != PS_OK', 'add_walk(a, c, "MAP", ste, 0) == PS_UNASKED'),
    sub('the-gate-of-rd-is-open', '    } else if (page_approval(c, addr) != PS_OK) {', '    } else if (0) {'),
    sub('the-root-ports-page-is-not-asked-for-a-device', 'c.approved[PAGE_RP] = (uint8_t)add_walk(a, &c, "RP", ROOT_PORT_PAGE, 1);',
        'c.approved[PAGE_RP] = (uint8_t)add_walk(a, &c, "RP", ROOT_PORT_PAGE, 0);'),
    sub('the-endpoints-page-is-not-asked-for-a-device', 'c.approved[PAGE_EP] = (uint8_t)add_walk(a, &c, "EP", ENDPOINT_PAGE, 1);',
        'c.approved[PAGE_EP] = (uint8_t)add_walk(a, &c, "EP", ENDPOINT_PAGE, 0);'),
    sub('the-smmus-page-is-not-asked-for-a-device', 'c.approved[PAGE_SMMU] = (uint8_t)add_walk(a, &c, "SMMU", SMMU_BASE, 1);',
        'c.approved[PAGE_SMMU] = (uint8_t)add_walk(a, &c, "SMMU", SMMU_BASE, 0);'),
    sub('the-endpoints-approval-is-the-root-ports', 'if (addr >= ENDPOINT_PAGE && addr < ENDPOINT_PAGE + CFG_PAGE_BYTES) return c->approved[PAGE_EP];',
        'if (addr >= ENDPOINT_PAGE && addr < ENDPOINT_PAGE + CFG_PAGE_BYTES) return c->approved[PAGE_RP];'),
    sub('the-root-ports-approval-is-the-endpoints', 'if (addr >= ROOT_PORT_PAGE && addr < ROOT_PORT_PAGE + CFG_PAGE_BYTES) return c->approved[PAGE_RP];',
        'if (addr >= ROOT_PORT_PAGE && addr < ROOT_PORT_PAGE + CFG_PAGE_BYTES) return c->approved[PAGE_EP];'),
    sub('the-smmu-group-is-run-though-the-mmu-said-no', 'if (c.approved[PAGE_SMMU] != PS_OK) {', 'if (0) {'),
    sub('the-smmu-page-reasons-are-swapped', 'c.approved[PAGE_SMMU] == PS_UNMAPPED ? W_SMMU_UNMAPPED : W_SMMU_NOT_DEVICE',
        'c.approved[PAGE_SMMU] == PS_UNMAPPED ? W_SMMU_NOT_DEVICE : W_SMMU_UNMAPPED'),
    # -- the translation answers it shows (payload-mmu.h)
    sub('par-f-is-inverted', 'w->mapped = !(par & 1);', 'w->mapped = par & 1;', HEADER),
    sub('sh-from-the-wrong-bits', '(uint8_t)(par >> 7 & 3)', '(uint8_t)(par >> 8 & 3)', HEADER),
    sub('attr-from-the-wrong-bits', '(uint8_t)(par >> 56)', '(uint8_t)(par >> 55)', HEADER),
    sub('identity-is-never-checked', 'w->ident = w->mapped && w->pa == (va & UINT64_C(0x000ffffffffff000));', 'w->ident = w->mapped;', HEADER),
    sub('a-stride-below-40-is-accepted', 'if (stride < PL_DESC_BYTES_MIN) return PL_MAP_STRIDE_BELOW_40;', '', HEADER),
    sub('a-stride-of-44-is-accepted', 'if (stride & 7u) return PL_MAP_STRIDE_NOT_8;', '', HEADER),
    sub('a-partial-descriptor-is-accepted', 'if (!size || size % stride) return PL_MAP_SIZE;', 'if (!size) return PL_MAP_SIZE;', HEADER),
    sub('a-huge-count-is-accepted', 'if (size / stride > PL_DESCRIPTORS_MAX) return PL_MAP_TOO_MANY;', '', HEADER),
    sub('an-unaligned-descriptor-is-used', '(d->start & (PL_PAGE_BYTES - 1)) || ', '', HEADER),
]

# Built with a 14-line page: the lines that may not be dropped, and the count of the dropped ones.
BUDGET_MUTANTS = [
    ('next-lines-may-be-dropped', FILE, [('pl_say(a, p, "NEXT", text.buf, 1);', 'pl_say(a, p, "NEXT", text.buf, 0);')]),
    ('the-last-line-may-be-dropped', FILE, [('pl_page_open(PG(&c), "DONE", 1);', 'pl_page_open(PG(&c), "DONE", 0);')]),
    ('the-verdict-may-be-dropped', FILE, [('pl_page_open(PG(c), "VERDICT", 1);', 'pl_page_open(PG(c), "VERDICT", 0);')]),
    ('nothing-is-reserved', FILE, [('#define ESSENTIAL_LINES 4u', '#define ESSENTIAL_LINES 0u')]),
    ('dropped-lines-are-not-counted', PAGE, [('        p->suppressed++;\n', '')]),
]
# Built with a load cap of 20: the cap itself, what the payload says of a read it refused, and that a refused read is counted.
CAP_MUTANTS = [
    ('the-cap-is-one-more', FILE, [('if (c->loads >= LOAD_CAP) {', 'if (c->loads > LOAD_CAP) {')]),
    ('a-refusal-is-called-a-fault', FILE, [('r.state = rc == Q1N1_PAYLOAD_LOAD_E_FAULT ? RS_FAULT : RS_REFUSED;', 'r.state = RS_FAULT;')]),
    ('a-refusal-hides-the-code', FILE, [('        pl_text(&item, "REFUSED:");\n        pl_dec(&item, r.code);', '        pl_text(&item, "REFUSED:");')]),
]


class SmmuprobeMutants(unittest.TestCase):
    _build = staticmethod(native.Mutants._build)

    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_there_are_enough_distinct_mutants_and_every_file_has_one(self):
        names = [m[0] for m in MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertGreaterEqual(len(names), 90)
        self.assertEqual({m[1] for m in MUTANTS}, {FILE, HEADER})

    def test_the_unmutated_control_passes_from_a_copy(self):
        directory = BUILD / 'control'
        native.copy_tree(directory)
        done, binary = native.Mutants._build('smmuprobe', directory, False)
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary)
        self.assertEqual(code, 0, output[-600:])

    def test_every_seeded_bug_is_caught(self):
        kit.run_mutants(native, MUTANTS, self)

    def _built_with(self, name, file, edits, flags, suites):
        directory = BUILD / f'{name}'
        native.copy_tree(directory)
        path = directory / file
        text = path.read_text(encoding='utf-8')
        for needle, replacement in edits:
            self.assertEqual(text.count(needle), 1, needle)
            text = text.replace(needle, replacement, 1)
        path.write_text(text, encoding='utf-8')
        binary = directory / 'bin' / 'test-smmuprobe-variant'
        binary.parent.mkdir(parents=True, exist_ok=True)
        cmd = ['clang'] + native.SANITIZE + native.RELAXED + native.GATES + [
            '-I', str(directory / 'uefi'), '-I', str(directory / 'payloads'), '-DQ1N1_PAYLOAD_HOST_TEST=1'] + flags + [
            str(TOOLS / 'test-q1n1-sp11-payload-smmuprobe.c'), str(directory / 'uefi' / 'sp11-payload-text.c'),
            str(directory / 'payloads' / 'smmuprobe.c'), '-o', str(binary)]
        done = run(cmd)
        self.assertEqual(done.returncode, 0, done.stderr[-400:])
        return any(native.run_program(binary, suite)[0] != 0 for suite in suites)

    def test_every_seeded_budget_bug_is_caught_by_the_page_built_small(self):
        for name, file, edits in BUDGET_MUTANTS:
            with self.subTest(mutant=name):
                self.assertTrue(self._built_with(f'budget-{name}', file, edits, ['-DTEST_BUDGET=14', '-DPL_PAGE_LINES=14u'], ('budget', 'worst')),
                                'the small page still passed')

    def test_every_seeded_cap_bug_is_caught_by_the_cap_built_small(self):
        for name, file, edits in CAP_MUTANTS:
            with self.subTest(mutant=name):
                self.assertTrue(self._built_with(f'cap-{name}', file, edits, ['-DTEST_LOAD_CAP=20', '-DLOAD_CAP=20u'], ('budget',)),
                                'the small cap still passed')


ANCHOR = '    pl_page_open(PG(&c), "START", 0);\n'
READ_SMMU = '            v->reg[i] = smmu_regs[i].wide ? rd64(a, c, at) : rd(a, c, at);\n'
DESCRIPTOR = '        if (!pl_desc_read(a, i, &d) || addr >= d.end || addr + bytes <= d.start) continue;\n'


def after(anchor, text):
    return [(anchor, anchor + text)]


BAD_BINARIES = [
    # (name, edits to smmuprobe.c, what the check must say)
    ('an-msr', after(ANCHOR, '    __asm__ volatile("msr daifset, #2" ::: "memory");\n'), 'msr'),
    ('a-dc', after(ANCHOR, '    __asm__ volatile("dc civac, %0" :: "r"(a) : "memory");\n'), 'dc'),
    ('an-ic', after(ANCHOR, '    __asm__ volatile("ic iallu" ::: "memory");\n'), 'ic'),
    ('a-tlbi', after(ANCHOR, '    __asm__ volatile("tlbi vmalle1" ::: "memory");\n'), 'tlbi'),
    ('at-s1e2w', after(ANCHOR, '    __asm__ volatile("at s1e2w, %0" :: "r"(a) : "memory");\n'), 'forbidden instruction at s1e2w'),
    ('at-s1e1r', after(ANCHOR, '    __asm__ volatile("at s1e1r, %0" :: "r"(a) : "memory");\n'), 'forbidden instruction at s1e1r'),
    ('an-smc', after(ANCHOR, '    __asm__ volatile("smc #0" ::: "memory");\n'), 'smc'),
    ('an-hvc', after(ANCHOR, '    __asm__ volatile("hvc #0" ::: "memory");\n'), 'hvc'),
    ('a-dsb', after(ANCHOR, '    __asm__ volatile("dsb sy" ::: "memory");\n'), 'dsb'),
    ('a-dmb', after(ANCHOR, '    __asm__ volatile("dmb sy" ::: "memory");\n'), 'dmb'),
    ('a-wfe', after(ANCHOR, '    __asm__ volatile("wfe");\n'), 'wfe'),
    ('an-eret', after(ANCHOR, '    __asm__ volatile("eret");\n'), 'eret'),
    ('an-exclusive-load', after(ANCHOR, '    __asm__ volatile("ldxr x9, [sp]" ::: "x9", "memory");\n'), 'ldxr'),
    ('an-atomic-add', after(ANCHOR, '    __asm__ volatile(".arch_extension lse\\n ldadd x9, x10, [sp]" ::: "x9", "x10", "memory");\n'), 'ldadd'),
    ('a-word-that-is-no-instruction', after(ANCHOR, '    __asm__ volatile(".inst 0xffffffff");\n'), 'not a known instruction'),
    ('a-read-of-midr', after(ANCHOR, '    (void)SYSREG(midr_el1);\n'), 'registers read'),
    ('a-read-of-cntpoff-el2', after(ANCHOR, '    (void)SYSREG(S3_4_C14_C0_6);\n'), 'the code names'),
    # the point of the payload: nothing is written, and no device word is read but through load32
    ('a-write-of-cr0', after(ANCHOR, '    *(volatile uint32_t *)(uintptr_t)(SMMU_BASE + 0x20) = 0;\n'), 'a store in payload_entry'),
    ('a-config-write', after(ANCHOR, '    *(volatile uint32_t *)(uintptr_t)(ENDPOINT_PAGE + 0x04) = 6;\n'), 'a store in payload_entry'),
    ('a-doorbell-write', after(ANCHOR, '    *(volatile uint32_t *)(uintptr_t)0x60801000 = 1;\n'), 'a store in payload_entry'),
    ('a-store-through-a-register-value', after(READ_SMMU, '            *(volatile uint32_t *)(uintptr_t)v->reg[i].value = 0;\n'), 'a store in read_smmu'),
    ('a-store-through-the-map-pointer', after(ANCHOR, '    *(volatile uint64_t *)(uintptr_t)a->map_base = 0;\n'), 'a store in payload_entry'),
    ('a-store-to-the-arguments', after(ANCHOR, '    ((struct q1n1_payload_args *)(uintptr_t)a)->reserved[0] = 1;\n'), 'a store in payload_entry'),
    ('an-unguarded-read-of-the-smmu', after(ANCHOR, '    (void)*(volatile const uint32_t *)(uintptr_t)SMMU_BASE;\n'), 'a load in payload_entry'),
    ('an-unguarded-read-of-config-space', after(ANCHOR, '    (void)*(volatile const uint32_t *)(uintptr_t)ENDPOINT_PAGE;\n'), 'a load in payload_entry'),
    ('a-read-through-a-descriptor-address', after(DESCRIPTOR, '        (void)*(volatile const uint32_t *)(uintptr_t)d.start;\n'), 'a load in map_type_of'),
    ('a-store-through-a-descriptor-address', after(DESCRIPTOR, '        *(volatile uint32_t *)(uintptr_t)d.start = 0;\n'), 'a store in map_type_of'),
]


class SmmuprobeBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kit.need_tools(cls)
        cls.out = BUILD / 'binary'
        shutil.rmtree(cls.out, ignore_errors=True)
        cls.builder = kit.Builder(cls.out)
        done, cls.elf, cls.flat = cls.builder.build('smmuprobe', 'smmuprobe', [], check=True)
        if done.returncode:
            raise RuntimeError('smmuprobe did not build:\n' + done.stderr[-1500:])
        cls.facts = kit.facts(cls.elf, cls.flat)

    def test_the_binary_holds_only_what_its_policy_allows(self):
        self.assertEqual(lib.binary_violations(self.elf, self.flat, POLICY, READELF()), [])

    def test_exactly_one_at_one_isb_and_three_registers_read(self):
        f = self.facts
        self.assertEqual((f['mnemonics']['at'], f['mnemonics']['isb'], f['mrs']['par_el1']), (1, 1, 1))
        self.assertEqual(set(f['mrs']), POLICY['registers'])
        self.assertNotIn('dsb', f['mnemonics'])
        for banned in ('msr', 'dc', 'ic', 'tlbi', 'smc', 'hvc', 'svc', 'eret', 'wfe', 'wfi', 'sys'):
            self.assertNotIn(banned, f['mnemonics'])
        self.assertLessEqual(f['bytes'], POLICY['bytes'])

    def test_the_binary_has_no_store_but_to_the_stack_by_the_memory_check_and_the_check_is_not_vacuous(self):
        # `read_only` is the policy's own key: the same binary under the policy without it still passes, and the seeded bad binaries below
        # pass without it: the memory check is what refuses them.
        loose = {k: v for k, v in POLICY.items() if k != 'read_only'}
        done, elf, flat = self.builder.build('smmuprobe', 'loose', after(ANCHOR, '    *(volatile uint32_t *)(uintptr_t)(SMMU_BASE + 0x20) = 0;\n'))
        self.assertEqual(done.returncode, 0, done.stderr[-500:])
        self.assertEqual(lib.binary_violations(elf, flat, loose, READELF()), [], 'a store the allow-list alone does not see')
        self.assertTrue(lib.binary_violations(elf, flat, POLICY, READELF()), 'the memory check sees it')

    def test_seeded_bad_binaries_are_each_refused_for_the_right_reason(self):
        self.assertGreaterEqual(len(BAD_BINARIES), 25)
        for name, edits, expected in BAD_BINARIES:
            with self.subTest(binary=name):
                done, elf, flat = self.builder.build('smmuprobe', name, edits)
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                problems = lib.binary_violations(elf, flat, POLICY, READELF())
                self.assertTrue(problems, 'the check passed a binary it must refuse')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_the_other_policies_refuse_it_and_it_refuses_their_binaries(self):
        for other in ('state', 'psci', 'timer', 'usbsmmu', 'cpuon', 'el2mem'):
            with self.subTest(policy=other):
                self.assertTrue(lib.binary_violations(self.elf, self.flat, lib.POLICIES[other], READELF()))
        older = BUILD / 'older'
        shutil.rmtree(older, ignore_errors=True)
        older.mkdir(parents=True)
        for other in ('el2mem', 'hashbig', 'usbsmmu'):
            with self.subTest(payload=other):
                done, elf, flat = lib.build_payload(ROOT / 'payloads' / f'{other}.c', older, name=other, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertTrue(lib.binary_violations(elf, flat, POLICY, READELF()))

    def test_two_builds_are_byte_identical_and_the_entry_is_at_offset_zero(self):
        done, _, flat = kit.Builder(BUILD / 'again').build('smmuprobe', 'smmuprobe', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(Path(flat).read_bytes(), Path(self.flat).read_bytes())
        self.assertEqual(Path(self.flat).read_bytes()[:4], bytes.fromhex('5f2403d5'), 'BTI c first, as the runner expects')

    def test_the_makefile_builds_it_with_the_other_payloads_and_the_same_bytes(self):
        out = BUILD / 'make'
        shutil.rmtree(out, ignore_errors=True)
        done = run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', 'payloads'])
        self.assertEqual(done.returncode, 0, done.stderr[-800:])
        self.assertEqual((out / 'payloads' / 'smmuprobe.bin').read_bytes(), Path(self.flat).read_bytes())


def facts_main():
    kit.need_tools(None)
    out = BUILD / 'facts'
    done, elf, flat = kit.Builder(out).build('smmuprobe', 'smmuprobe', [], check=True)
    if done.returncode:
        sys.exit(done.stderr)
    f = kit.facts(elf, flat)
    print(f'smmuprobe.bin: {f["bytes"]} bytes, sha256 {f["sha256"]}, {f["instructions"]} instructions')
    print('registers read:', ', '.join(f'{r} x{n}' for r, n in sorted(f['mrs'].items())))
    print('allow-list violations:', lib.binary_violations(elf, flat, POLICY, READELF()))


if __name__ == '__main__':
    if sys.argv[1:] == ['facts']:
        facts_main()
    else:
        sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
