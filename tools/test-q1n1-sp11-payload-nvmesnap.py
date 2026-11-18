#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The nvmesnap payload of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-NVMESNAP.md): its host test, its seeded bugs and the allow-list of
its binary. The document is checked by tools/test-q1n1-sp11-payload-nvmesnap-doc.py, the registers and the descriptor by
tools/test-q1n1-sp11-payload-nvmesnap-refs.py, the binary under QEMU by tools/test-q1n1-sp11-payload-qemu-nvmesnap.py, the engine of the memory check by
tools/test-q1n1-sp11-payload-memcheck.py.

    python3 tools/test-q1n1-sp11-payload-nvmesnap.py

  * NvmesnapNative: tools/test-q1n1-sp11-payload-nvmesnap.c (thirteen suites over a modelled machine: scripted configuration pages, controller registers
    and RAM that fault where they are told to, a translation model, a memory map pressed against PROT_NONE pages, a clock; every load judged as it is
    made; a fuzz against an oracle written another way), built and run by the machinery of tools/test-q1n1-sp11-payload.py under ASan and UBSan, and
    again with a 14-line and a 10-line page, with load caps of 20 and 10, and with the bound on the reads of a wait lowered to 1000.
  * NvmesnapSource: what no run shows (the ops it calls, the registers it names, one AT, no writable global, the font, the order of its blocks, the
    offsets it reads, the constants against config/boards/sp11.json when SNAPINTOSH_DIR is set).
  * NvmesnapMutants: seeded bugs in nvmesnap.c, payload-mmu.h and payload-page.h (tools/sp11_payload_nvmesnap_mutants.py and its second part
    tools/sp11_payload_nvmesnap_mutants_more.py), each of which the host program must reject for its own reason, one build and one run at a time.
  * NvmesnapBinary: the allow-list applied to nvmesnap.bin (MRS of three registers, exactly AT S1E2R, one ISB, stores only through the stack, loads only
    through the stack, the image, the arguments and pointers they hold: every device word is read through load32) with seeded bad binaries, and the
    build's reproducibility.

The policy of the binary is the shared registry's, `POLICIES['nvmesnap']` of tools/sp11_payload_testlib.py, which the shared build test
(tools/test-q1n1-sp11-payload-build.py) applies to this binary as well. Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
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
import sp11_payload_nvmesnap_mutants as mut  # noqa: E402
import sp11_payload_testlib as lib  # noqa: E402

SUITES = mut.SUITES
MOST_LINES = 33                         # the worst world and the fuzz print at most this many of the 34 lines
native = kit.native_module('nvmesnap')
native.PROGRAMS['nvmesnap'] = ('tools/test-q1n1-sp11-payload-nvmesnap.c', ['sp11-payload-text.c'], len(SUITES), 70000, 'nvmesnap')
native.HOST_PAYLOADS['nvmesnap'] = 'nvmesnap.c'
native.PAYLOADS_COPIED = list(native.PAYLOADS_COPIED) + ['nvmesnap.c']
BUILD = native.BUILD
SOURCE = ROOT / 'payloads' / 'nvmesnap.c'
TOOLS = ROOT / 'tools'
run, have, READELF = lib.run, lib.have, kit.READELF
POLICY = lib.POLICIES['nvmesnap']
OWN_FILES = [SOURCE, TOOLS / 'test-q1n1-sp11-payload-nvmesnap.c', TOOLS / 'test-q1n1-sp11-payload-nvmesnap-world.h',
             TOOLS / 'test-q1n1-sp11-payload-nvmesnap-gates.h', TOOLS / 'test-q1n1-sp11-payload-nvmesnap-fuzz.h', TOOLS / 'test-q1n1-sp11-payload-nvmesnap-queues.h',
             TOOLS / 'sp11_payload_nvmesnap_mutants.py', TOOLS / 'sp11_payload_nvmesnap_mutants_more.py', TOOLS / 'sp11_payload_nvmesnap_reasons.py',
             TOOLS / 'test-q1n1-sp11-payload-nvmesnap-doc.py', TOOLS / 'test-q1n1-sp11-payload-nvmesnap-refs.py',
             TOOLS / 'test-q1n1-sp11-payload-qemu-nvmesnap.py', Path(__file__)]
VARIANTS = {'page14': (mut.PAGE14, ('budget', 'worst', 'fuzz')), 'page10': (('-DTEST_BUDGET=10', '-DPL_PAGE_LINES=10u'), ('budget', 'worst', 'fuzz')),
            'cap20': (mut.CAP20, ('budget',)), 'cap10': (mut.CAP10, ('budget',)), 'spin': (mut.SPIN, ('counter', 'fuzz'))}


def variant(name, directory=None):
    """The host program built with the flags of VARIANTS[name], from the tree or from a copy of it, run on its suites: (build result, {suite: (code, output)})."""
    flags, suites = VARIANTS[name]
    out = BUILD / f'variant-{name}'
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'test-nvmesnap'
    uefi, payloads, source = (directory / 'uefi', directory / 'payloads', directory / 'payloads' / 'nvmesnap.c') if directory else (
        native.UEFI, native.PAYLOADS, SOURCE)
    cmd = ['clang'] + native.SANITIZE + native.GATES + ['-I', str(uefi), '-I', str(payloads), '-DQ1N1_PAYLOAD_HOST_TEST=1'] + list(flags) + [
        str(TOOLS / 'test-q1n1-sp11-payload-nvmesnap.c'), str(uefi / 'sp11-payload-text.c'), str(source), '-o', str(binary)]
    done = run(cmd)
    return done, {s: native.run_program(binary, s) for s in suites} if done.returncode == 0 else {}


class NvmesnapNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_the_suites_pass(self):
        native.Native._check(self, 'nvmesnap')

    def test_each_suite_runs_alone(self):
        done, binary = native.build_program('nvmesnap', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite in SUITES:
            with self.subTest(suite=suite):
                code, output = native.run_program(binary, suite)
                self.assertEqual(code, 0, output)
                self.assertRegex(output, r'PASS: 1 payload nvmesnap suites, \d+ checks')

    def test_the_most_lines_are_measured_and_are_within_the_budget_with_room(self):
        done, binary = native.build_program('nvmesnap', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary, 'lines-report')
        self.assertEqual((code, output.strip()), (0, f'LINES_MAX={MOST_LINES}'), 'the worst world and the fuzz print at most 33 of the 34 lines')

    def test_a_smaller_page_drops_lines_and_counts_them_but_never_the_next_lines_the_verdict_or_the_last(self):
        for name in ('page14', 'page10'):
            with self.subTest(variant=name):
                done, results = variant(name)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(sorted(results), sorted(VARIANTS[name][1]))
                for suite, (code, output) in results.items():
                    self.assertEqual(code, 0, f'{suite}: {output[-400:]}')

    def test_a_small_load_cap_stops_the_loads_and_says_so(self):
        for name in ('cap20', 'cap10'):
            with self.subTest(variant=name):
                done, results = variant(name)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(results['budget'][0], 0, results['budget'][1])

    def test_a_lowered_bound_on_the_reads_of_a_wait_is_told_from_a_dead_counter(self):
        done, results = variant('spin')
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite, (code, output) in results.items():
            self.assertEqual(code, 0, f'{suite}: {output[-400:]}')


class NvmesnapSource(unittest.TestCase):
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
        self.assertNotRegex(self.code, r'\w+_name\s*\[|static const char \*', 'a pointer table needs relocations the ELF check refuses')
        self.assertEqual(re.findall(r'^INLINE_NAME const char \*(\w+)_text', self.code, re.M), ['why', 'link', 'ctrl', 'queues'])

    def test_the_blocks_come_in_the_documented_order_each_behind_its_next_line(self):
        entry = self.code[self.code.index('uint64_t payload_entry(const struct q1n1_payload_args *a)\n{'):]
        tokens = ('"START"', '"REFUSED", "NOT_AT_EL2"', '"REFUSED", "NO_LOAD_OP"', '"MAP"', 'report_head(a, &c, "RP"', 'report_head(a, &c, "EP"',
                  'gate_headers(&snap)', 'announce(a, PG(&c), freq, "CAPS")', 'read_caps(a, &c, &rp', 'report_link(a, &c, "RP.LINK"', 'read_caps(a, &c, &ep',
                  'report_pm(', 'report_link(a, &c, "EP.LINK"', 'gate_registers(&snap, &bar)', 'ram_overlap(a, bar, NVME_READ_END)',
                  'pl_walk_page(bar, &bar_walk)', 'say_gate(', 'announce(a, PG(&c), freq, "NVME_REGS")', 'read_nvme(a, &c, &view, 0, NR_FIRST_BLOCK)',
                  'report_ctrl(', 'why_block(&view, &ctrl, 0, NR_FIRST_BLOCK)', 'announce(a, PG(&c), freq, "NVME_AQ")',
                  'read_nvme(a, &c, &view, NR_FIRST_BLOCK, NR_COUNT)', 'settle_ctrl(', 'report_aq(', 'why_block(&view, &ctrl, NR_FIRST_BLOCK, NR_COUNT)',
                  'read_queues(', 'say_verdict(', '"DONE"')
        order = [entry.index(token) for token in tokens]
        self.assertEqual(order, sorted(order))
        self.assertEqual(entry.count('announce('), 3)
        for once in ('read_queues(', 'gate_registers(', 'ram_overlap(', 'report_ctrl(', 'settle_ctrl(', 'report_aq('):
            self.assertEqual(entry.count(once), 1, once)
        self.assertEqual(entry.count('read_nvme('), 2, 'one call per block')
        self.assertEqual(len(re.findall(r'pl_say\(a, p, "NEXT", text\.buf, 1\)', self.code)), 1, 'a NEXT line is essential')
        self.assertEqual(len(re.findall(r'pl_say\(a, PG\(c\), "NEXT", "ADMIN_QUEUES", 1\)', self.code)), 1)
        self.assertIn('#define ESSENTIAL_LINES 6u', self.code, 'the four NEXT lines, the verdict and the last line')

    def test_the_controller_registers_it_reads_are_the_x2_images_seven_one_twice_in_the_documented_order_and_no_other(self):
        rows = re.findall(r'\{"(\w+)", (0x[0-9a-f]+), (\d)\}', self.code)
        self.assertEqual([r[0] for r in rows], ['CAP', 'CSTS', 'CC', 'VS', 'CSTS2', 'AQA', 'ASQ', 'ACQ'])
        self.assertEqual([int(r[1], 16) for r in rows], [0x00, 0x1c, 0x14, 0x08, 0x1c, 0x24, 0x28, 0x30])
        self.assertEqual([r[2] for r in rows], ['1', '0', '0', '0', '0', '0', '1', '1'], 'CAP, ASQ and ACQ are 64 bits: two loads, low word first')
        self.assertIn('#define NR_FIRST_BLOCK 4u', self.code)
        # The first load of each block is a register Linux reads (CAP; CSTS again), and the three Linux never reads come last, behind that second reading.
        self.assertEqual((rows[0][0], rows[4][0], rows[4][1]), ('CAP', 'CSTS2', rows[1][1]))
        self.assertEqual([r[0] for r in rows[5:]], ['AQA', 'ASQ', 'ACQ'])
        self.assertIn('#define NVME_READ_END 0x38u', self.code, 'nothing at or above 0x38 is read: the doorbells start at 0x1000')
        self.assertEqual(re.findall(r'at \+ 4u \* words\[i\]', self.code), ['at + 4u * words[i]'])

    def test_the_bound_on_the_reads_of_a_wait_is_32_bits_and_a_dead_counter_is_told_from_it(self):
        self.assertIn('#define SPIN_MAX 0xffffffffu', self.code)
        self.assertIn('#define COUNTER_STUCK_READS 2000000u', self.code)
        self.assertEqual(len(re.findall(r'return WAIT_SPIN;', self.code)), 1)
        self.assertEqual(len(re.findall(r'return WAIT_DEAD;', self.code)), 2, 'a counter that stands still, and one that goes back')
        self.assertIn('"SKIPPED=SPIN_BOUND"', self.code)
        self.assertIn('"SKIPPED=COUNTER_UNUSABLE"', self.code)

    def test_the_configuration_dwords_it_reads_are_listed_here_and_no_other(self):
        offsets = re.findall(r'cfg\(a, c, f, ([^)]*)\)', self.code)
        self.assertEqual(offsets, ['0x00', '0x04', '0x08', '0x0c', '0x10', '0x14', '0x18', '0x20', '0x34', 'ptr', 'ptr + 0x04u', 'ptr + 0x0cu', 'ptr + 0x10u'])
        self.assertIn('static const uint8_t sqe_words[6] = {0, 6, 7, 1, 10, 11};', self.code)
        self.assertIn('static const uint8_t cqe_words[3] = {3, 2, 0};', self.code)
        for define in ('#define PEEK_ENTRIES 2u', '#define SQE_BYTES 64u', '#define CQE_BYTES 16u', '#define CAP_STEPS 16u'):
            self.assertIn(define, self.code)

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
        self.assertEqual(nvme['segment'], 6)
        self.assertEqual(int(nvme['ecam']['base'], 16), value('ECAM_BASE'))
        for key, bus in (('root_port', 'RP_BUS'), ('endpoint', 'EP_BUS')):
            self.assertEqual((nvme[key]['bus'], nvme[key]['device'], nvme[key]['function']), (value(bus), 0, 0), key)
        self.assertEqual(int(nvme['root_port']['class_code'], 16) >> 8, value('CLASS_BRIDGE'))
        self.assertEqual(int(nvme['endpoint']['class_code'], 16), value('CLASS_NVME'))
        self.assertEqual((nvme['ecam']['start_bus'], nvme['ecam']['end_bus']), (value('RP_BUS'), value('EP_BUS')), 'the allocation holds exactly the two buses read')


class NvmesnapMutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_there_are_enough_distinct_mutants_and_every_file_has_one(self):
        names = [m[0] for m in mut.MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertGreaterEqual(len(names), 300)
        self.assertEqual({m[1] for m in mut.MUTANTS}, {mut.FILE, mut.HEADER, mut.PAGE})

    def test_every_needle_occurs_exactly_once_and_every_mutant_names_real_suites_and_a_reason(self):
        self.assertEqual([bad for m in mut.MUTANTS for bad in mut.stale(m)], [])
        for name, _, edits, suites, _, flags in mut.MUTANTS:
            self.assertTrue(suites and set(suites) <= set(SUITES), name)
            self.assertTrue(all(old != new for old, new in edits), f'{name} changes nothing')
            self.assertIn(name, mut.REASONS, f'{name} has no reason to be rejected for')
            re.compile(mut.REASONS[name])
            self.assertTrue(set(flags) <= set(mut.PAGE14 + mut.CAP20 + mut.CAP10 + mut.SPIN), name)
        self.assertEqual(set(mut.REASONS) - {m[0] for m in mut.MUTANTS}, set(), 'a reason for a mutant that does not exist')

    def test_the_unmutated_control_passes_from_a_copy_and_so_does_each_variant(self):
        directory = BUILD / 'control'
        native.copy_tree(directory)
        done, binary = native.Mutants._build('nvmesnap', directory, False)
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary)
        self.assertEqual(code, 0, output[-600:])
        for name in VARIANTS:
            with self.subTest(variant=name):
                done, results = variant(name, directory)
                self.assertEqual(done.returncode, 0, done.stderr)
                for suite, (code, output) in results.items():
                    self.assertEqual(code, 0, f'{suite}: {output[-400:]}')

    def test_every_seeded_bug_is_caught_for_its_own_reason(self):
        work = BUILD / 'mutants'
        for m in mut.MUTANTS:
            status, detail, _ = mut.evaluate(native, m, work, ROOT)
            shutil.rmtree(work / m[0], ignore_errors=True)
            with self.subTest(mutant=m[0]):
                self.assertEqual(status, 'caught', detail)


ANCHOR = '    pl_page_open(PG(&c), "START", 0);\n'
READ_NVME = '            v->made++;\n'
NV_AT = '            uint64_t at = c->bar0 + nvme_regs[i].offset;\n'
READ_SLOT = '        w[i] = rd(a, c, at + 4u * words[i]);\n'
MAP_TYPE = '        if (!usable_type((int)d.type)) return (int)d.type;\n'
RAM_OVERLAP = '        if (usable_type((int)d.type)) return 1;\n'


def after(anchor, text):
    return [(anchor, anchor + text)]


BAD_BINARIES = [
    # (name, edits to nvmesnap.c, what the check must say)
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
    ('a-write-of-cc', after(ANCHOR, '    *(volatile uint32_t *)(uintptr_t)(UINT64_C(0x70300014)) = 0;\n'), 'a store in payload_entry'),
    ('a-doorbell-write', after(ANCHOR, '    *(volatile uint32_t *)(uintptr_t)0x70301000 = 1;\n'), 'a store in payload_entry'),
    ('a-config-write', after(ANCHOR, '    *(volatile uint32_t *)(uintptr_t)(ENDPOINT_PAGE + 0x04) = 6;\n'), 'a store in payload_entry'),
    ('a-store-through-a-register-value', after(READ_NVME, '            *(volatile uint32_t *)(uintptr_t)v->reg[i].value = 0;\n'), 'a store in read_nvme'),
    ('a-store-through-the-map-pointer', after(ANCHOR, '    *(volatile uint64_t *)(uintptr_t)a->map_base = 0;\n'), 'a store in payload_entry'),
    ('a-store-to-the-arguments', after(ANCHOR, '    ((struct q1n1_payload_args *)(uintptr_t)a)->reserved[0] = 1;\n'), 'a store in payload_entry'),
    ('an-unguarded-read-of-the-controller', after(ANCHOR, '    (void)*(volatile const uint32_t *)(uintptr_t)UINT64_C(0x70300000);\n'), 'a load in payload_entry'),
    ('an-unguarded-read-of-config-space', after(ANCHOR, '    (void)*(volatile const uint32_t *)(uintptr_t)ENDPOINT_PAGE;\n'), 'a load in payload_entry'),
    ('a-read-through-a-descriptor-address', after(MAP_TYPE, '        (void)*(volatile const uint32_t *)(uintptr_t)d.start;\n'), 'a load in map_type_of'),
    ('a-store-through-a-descriptor-address', after(RAM_OVERLAP, '        *(volatile uint32_t *)(uintptr_t)d.start = 0;\n'), 'a store in ram_overlap'),
    # an unguarded load, not only a store: through a register value, through the base of the controller's window, through a queue address
    ('an-unguarded-read-through-a-register-value', after(READ_NVME, '            (void)*(volatile const uint32_t *)(uintptr_t)v->reg[i].value;\n'), 'a load in read_nvme'),
    ('an-unguarded-read-at-the-controller-window', after(NV_AT, '            (void)*(volatile const uint32_t *)(uintptr_t)at;\n'), 'a load in read_nvme'),
    ('an-unguarded-read-of-a-queue-word', after(READ_SLOT, '        (void)*(volatile const uint32_t *)(uintptr_t)(at + 4u * words[i]);\n'), 'a load in read_slot'),
    ('a-store-through-a-queue-address', after(READ_SLOT, '        *(volatile uint32_t *)(uintptr_t)(at + 4u * words[i]) = 0;\n'), 'a store in read_slot'),
]


class NvmesnapBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kit.need_tools(cls)
        cls.out = BUILD / 'binary'
        shutil.rmtree(cls.out, ignore_errors=True)
        cls.builder = kit.Builder(cls.out)
        done, cls.elf, cls.flat = cls.builder.build('nvmesnap', 'nvmesnap', [], check=True)
        if done.returncode:
            raise RuntimeError('nvmesnap did not build:\n' + done.stderr[-1500:])
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
        # `read_only` is the policy's own key: the same binary under the policy without it still passes, and the seeded bad binaries below pass the
        # allow-list without it: the memory check is what refuses them.
        loose = {k: v for k, v in POLICY.items() if k != 'read_only'}
        done, elf, flat = self.builder.build('nvmesnap', 'loose', after(ANCHOR, '    *(volatile uint32_t *)(uintptr_t)(UINT64_C(0x70300014)) = 0;\n'))
        self.assertEqual(done.returncode, 0, done.stderr[-500:])
        self.assertEqual(lib.binary_violations(elf, flat, loose, READELF()), [], 'a store the allow-list alone does not see')
        self.assertTrue(lib.binary_violations(elf, flat, POLICY, READELF()), 'the memory check sees it')

    def test_seeded_bad_binaries_are_each_refused_for_the_right_reason(self):
        self.assertGreaterEqual(len(BAD_BINARIES), 30)
        for name, edits, expected in BAD_BINARIES:
            with self.subTest(binary=name):
                done, elf, flat = self.builder.build('nvmesnap', name, edits)
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
        done, _, flat = kit.Builder(BUILD / 'again').build('nvmesnap', 'nvmesnap', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(Path(flat).read_bytes(), Path(self.flat).read_bytes())
        self.assertEqual(Path(self.flat).read_bytes()[:4], bytes.fromhex('5f2403d5'), 'BTI c first, as the runner expects')

    def test_the_makefile_builds_it_with_the_other_payloads_and_the_same_bytes(self):
        out = BUILD / 'make'
        shutil.rmtree(out, ignore_errors=True)
        done = run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', 'payloads'])
        self.assertEqual(done.returncode, 0, done.stderr[-800:])
        self.assertEqual((out / 'payloads' / 'nvmesnap.bin').read_bytes(), Path(self.flat).read_bytes())


def facts_main():
    kit.need_tools(None)
    out = BUILD / 'facts'
    done, elf, flat = kit.Builder(out).build('nvmesnap', 'nvmesnap', [], check=True)
    if done.returncode:
        sys.exit(done.stderr)
    f = kit.facts(elf, flat)
    print(f'nvmesnap.bin: {f["bytes"]} bytes, sha256 {f["sha256"]}, {f["instructions"]} instructions')
    print('registers read:', ', '.join(f'{r} x{n}' for r, n in sorted(f['mrs'].items())))
    print('allow-list violations:', lib.binary_violations(elf, flat, POLICY, READELF()))


if __name__ == '__main__':
    if sys.argv[1:] == ['facts']:
        facts_main()
    else:
        sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
