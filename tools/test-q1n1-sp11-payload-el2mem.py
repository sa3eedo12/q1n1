#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The el2mem payload of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-EL2MEM.md): its host test, its seeded bugs and the
allow-list of its binary. The documents are checked by tools/test-q1n1-sp11-payload-mmu-doc.py, the QEMU run is
tools/test-q1n1-sp11-payload-qemu-el2mem.py, the engine by tools/test-q1n1-sp11-payload-memcheck.py.

    python3 tools/test-q1n1-sp11-payload-el2mem.py

  * El2memNative: tools/test-q1n1-sp11-payload-el2mem.c (ten suites over a modelled machine: AT S1E2R as a list of ranges, a scripted
    register file, a clock, a guarded load, a memory map pressed against PROT_NONE pages), built and run by the machinery of
    tools/test-q1n1-sp11-payload.py under ASan and UBSan, and again with a 14-line page to see the budget work.
  * El2memSource: what no run shows (the ops it calls, the registers it names, one AT, no writable global, the font).
  * El2memMutants: seeded bugs in el2mem.c, payload-mmu.h and payload-page.h, each of which the host program must reject.
  * El2memBinary: the allow-list applied to el2mem.bin (MRS of its registers, exactly AT S1E2R, one ISB, stores only through the
    stack, loads only through the stack, the image, the arguments and pointers they hold) with seeded bad binaries, the five older
    payloads still byte for byte what they were, and the build's reproducibility.

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
import hashlib
import re
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_mmu_testkit as kit  # noqa: E402
import sp11_payload_testlib as lib  # noqa: E402

native = kit.native_module('el2mem')
BUILD = native.BUILD
SOURCE = ROOT / 'payloads' / 'el2mem.c'
run, have, READELF = lib.run, lib.have, kit.READELF
SUITES = ('unit', 'scan', 'faulty', 'map', 'counter', 'el', 'args', 'budget', 'worst', 'fuzz')
# The five payloads of the base commit and the digests the hardware runs pinned: they must stay what they were.
OLDER = {
    'psci': 'd391a9c8cbeecd00d56dba6cce241d8f9655a737c010e586b64492a8ae5ec122',
    'state': '427ecf310c0116c58c0040f14a6c0a536a5ac1d4ef2ffc7635b44ccfb0a421bb',
    'timer': '68cace99e5a20086988edd2673cce6aa4b90518101e10a624acef8e4a5ff7abd',
    'usbsmmu': '9f0260dc5b2f910f3f3b316acfc6fc0607ff61bf407a51e38e8e2b887e7c368f',
    'cpuon': '3b4bfda7d59f923c21641472a4bc532fff61e4967e6e0b15dccbd023e632d09e',
}


def budget_variant(lines):
    """The host program built with a smaller page (PL_PAGE_LINES and the test's TEST_BUDGET), or the build's failure."""
    out = BUILD / f'variant-{lines}'
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'test-el2mem'
    cmd = ['clang'] + native.SANITIZE + native.GATES + ['-I', str(native.UEFI), '-I', str(native.PAYLOADS), '-DQ1N1_PAYLOAD_HOST_TEST=1',
                                                         f'-DTEST_BUDGET={lines}', f'-DPL_PAGE_LINES={lines}u',
                                                         str(ROOT / 'tools' / 'test-q1n1-sp11-payload-el2mem.c'),
                                                         str(native.UEFI / 'sp11-payload-text.c'), str(SOURCE), '-o', str(binary)]
    return run(cmd), binary


class El2memNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_the_el2mem_suites_pass(self):
        native.Native._check(self, 'el2mem')

    def test_each_suite_runs_alone(self):
        done, binary = native.build_program('el2mem', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite in SUITES:
            with self.subTest(suite=suite):
                code, output = native.run_program(binary, suite)
                self.assertEqual(code, 0, output)
                self.assertRegex(output, r'PASS: 1 payload el2mem suites, \d+ checks')

    def test_the_most_lines_are_measured_and_exactly_the_budget(self):
        done, binary = native.build_program('el2mem', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary, 'lines-report')
        self.assertEqual((code, output.strip()), (0, 'LINES_MAX=26'), 'the worst world reaches the budget and never passes it')

    def test_a_smaller_page_drops_lines_and_counts_them_but_never_the_next_lines_or_the_last(self):
        for lines in (14, 10):
            with self.subTest(budget=lines):
                done, binary = budget_variant(lines)
                self.assertEqual(done.returncode, 0, done.stderr)
                for suite in ('budget', 'worst', 'fuzz'):
                    code, output = native.run_program(binary, suite)
                    self.assertEqual(code, 0, output)


class El2memSource(unittest.TestCase):
    code = kit.code_of(SOURCE)
    header = kit.code_of(ROOT / 'payloads' / 'payload-mmu.h')
    page = kit.code_of(ROOT / 'payloads' / 'payload-page.h')

    def test_the_payload_calls_only_load32_counter_and_the_helpers_puts_and_hex(self):
        self.assertEqual(set(re.findall(r'ops\.(\w+)', self.code)), {'load32', 'counter'})
        self.assertEqual(set(re.findall(r'ops\.(\w+)', kit.code_of(ROOT / 'payloads' / 'payload-util.h') + self.page + self.header)), {'puts', 'hex'})

    def test_the_registers_the_source_names_are_the_policys(self):
        named = {name.lower() for name in re.findall(r'SYSREG\((\w+)\)', self.code)} - {'name'}
        policy = lib.POLICIES['el2mem']['registers'] - {'par_el1'}
        aliases = lib.SYSTEM_REGISTER_ALIASES
        self.assertEqual({aliases.get(name, name) for name in named}, policy)
        self.assertNotRegex(self.code.upper(), r'CNTPOFF|CNTVOFF|S3_4_C14_C0_[36]', 'the timer offsets are never named')

    def test_one_at_one_isb_one_read_of_par_el1_and_no_other_inline_assembly(self):
        self.assertEqual(self.header.count('at s1e2r'), 1)
        self.assertEqual(len(re.findall(r'__asm__', self.header)), 1)
        self.assertEqual(len(re.findall(r'__asm__', self.code)), 1, 'the MRS macro')
        self.assertIn('at s1e2r, %1\\n\\tisb\\n\\tmrs %0, par_el1', self.header)
        self.assertNotRegex(self.header + self.code, r'\b(msr|dc |ic |tlbi|smc|hvc)\b')

    def test_no_writable_global_and_every_table_is_constant(self):
        for text in (self.code, self.header, self.page):
            for declaration in re.findall(r'^static\b[^\n(]*;', text, re.M):
                self.assertRegex(declaration, r'\bconst\b|\binline\b', declaration)
            self.assertEqual(re.findall(r'^static (?!const|inline|__attribute__)[^\n(]*$', text, re.M), [])

    def test_the_files_are_within_the_size_limits_and_carry_the_licence(self):
        for path in (SOURCE, ROOT / 'payloads' / 'payload-mmu.h', ROOT / 'payloads' / 'payload-page.h',
                     ROOT / 'tools' / 'test-q1n1-sp11-payload-el2mem.c', ROOT / 'tools' / 'test-q1n1-sp11-payload-mmu-world.h',
                     ROOT / 'tools' / 'sp11_payload_memcheck.py', ROOT / 'tools' / 'sp11_payload_mmu_testkit.py', Path(__file__)):
            with self.subTest(file=path.name):
                text = path.read_text(encoding='utf-8')
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                self.assertIn('SPDX-License-Identifier: MIT', text[:200])

    def test_the_text_it_prints_is_in_the_page_font(self):
        for literal in re.findall(r'"([^"\n]*)"', self.code + self.header + self.page):
            if literal.endswith('.h') or re.search(r'%|\\n|mrs ', literal) or literal in ('=r', 'r', 'memory'):
                continue                                              # an include, and the inline assemblies
            self.assertRegex(literal, r'^[A-Z0-9:\-./=?()_ ]*$', literal)


FILE = 'payloads/el2mem.c'
HEADER = 'payloads/payload-mmu.h'
PAGE = 'payloads/payload-page.h'


def sub(name, old, new, file=FILE):
    return kit.mutant('el2mem', name, file, old, new)


MUTANTS = [
    # -- the scan: which pages it asks about
    sub('scan-misses-the-last-page', 'uint64_t last = e->end - PL_PAGE_BYTES, at = e->start;', 'uint64_t last = e->end - 2 * PL_PAGE_BYTES, at = e->start;'),
    sub('scan-stride-is-4-mib', '#define BLOCK_2M (UINT64_C(2) << 20)', '#define BLOCK_2M (UINT64_C(4) << 20)'),
    sub('scan-steps-from-the-start', 'at = (at & ~(BLOCK_2M - 1)) + BLOCK_2M;', 'at = at + BLOCK_2M;'),
    sub('scan-skips-the-first-page', '    for (;;) {\n        probe(s, at);\n        if (at >= last) break;',
        '    for (;;) {\n        if (at != e->start) probe(s, at);\n        if (at >= last) break;'),
    sub('adjacent-descriptors-are-not-merged', 'd.start <= end && d.end > end', 'd.start < end && d.end > end'),
    sub('conventional-is-loader-data', '#define PL_EFI_CONVENTIONAL 7u', '#define PL_EFI_CONVENTIONAL 2u', HEADER),
    sub('extents-beyond-64-are-scanned', 'if (s->extents < EXTENTS_MAX) s->extent[s->extents_scanned++] = e;', 's->extent[s->extents_scanned++ % EXTENTS_MAX] = e;'),
    sub('one-more-descriptor-than-the-map-has', 'for (uint64_t i = 0; i < count; i++) {\n        if (!pl_desc_read(a, i, &d)) {',
        'for (uint64_t i = 0; i <= count; i++) {\n        if (!pl_desc_read(a, i, &d)) {'),
    # -- the loads
    sub('loads-without-the-at-check', 'if (!w.mapped) {\n        pl_text(&item, "SKIPPED_NOT_MAPPED");', 'if (0) {\n        pl_text(&item, "SKIPPED_NOT_MAPPED");'),
    sub('bank-last-word-is-past-the-end', 'ok += load_word(a, p, "BANK_LAST", s->bank_span.end - 4u);', 'ok += load_word(a, p, "BANK_LAST", s->bank_span.end);'),
    sub('low-extent-is-the-smallest', 'if (clipped - e.start > s->low.end - s->low.start) {', 'if (!s->low.end || clipped - e.start < s->low.end - s->low.start) {'),
    sub('low-extent-is-not-clipped', 'uint64_t clipped = e.end < LOW_LIMIT ? e.end : LOW_LIMIT;', 'uint64_t clipped = e.end;'),
    sub('an-abort-is-counted-as-read', 'if (rc) {\n            pl_text(&item, "ERR");', 'if (0) {\n            pl_text(&item, "ERR");'),
    sub('the-abort-code-is-hidden', 'pl_text(&item, "ERR");', 'pl_text(&item, "OK");'),
    # -- what it reports
    sub('the-bank-has-no-line', '            report_bank(a, &p, &s);\n', ''),
    sub('the-bank-is-always-uniform', 'if (!s->bank_faults && s->bank_same == s->bank_probes) {', 'if (1) {'),
    sub('the-controls-are-not-run', '            report_control(a, &p, &s);\n', ''),
    sub('the-verdict-ignores-faults', 's.faults ? "SCAN_HAS_FAULTS" : ', ''),
    sub('outliers-are-not-capped', '#define OUTLIERS_MAX 5u', '#define OUTLIERS_MAX 50u'),
    sub('the-page-is-27-lines', '#define PL_PAGE_LINES 26u', '#define PL_PAGE_LINES 27u'),
    # -- the decode
    sub('par-f-is-inverted', 'w->mapped = !(par & 1);', 'w->mapped = par & 1;', HEADER),
    sub('attr-from-the-wrong-bits', '(uint8_t)(par >> 56)', '(uint8_t)(par >> 55)', HEADER),
    sub('sh-from-the-wrong-bits', '(uint8_t)(par >> 7 & 3)', '(uint8_t)(par >> 8 & 3)', HEADER),
    sub('fst-from-the-wrong-bits', '(uint8_t)(par >> 1 & 63)', '(uint8_t)(par >> 2 & 63)', HEADER),
    sub('identity-is-never-checked', 'w->ident = w->mapped && w->pa == (va & UINT64_C(0x000ffffffffff000));', 'w->ident = w->mapped;', HEADER),
    sub('device-is-called-non-cacheable', 'return (inner & 3u) == 0 ? PL_ATTR_DEVICE : PL_ATTR_OTHER;', 'return (inner & 3u) == 0 ? PL_ATTR_NC : PL_ATTR_OTHER;', HEADER),
    sub('write-back-needs-only-one-nibble', 'if (outer >> 2 == 3 && inner >> 2 == 3) return PL_ATTR_WB;', 'if (outer >> 2 == 3 || inner >> 2 == 3) return PL_ATTR_WB;', HEADER),
    sub('the-fault-level-is-dropped', 'pl_text(line, fst & 3 ? "_L" : "_L0");', 'pl_text(line, "_L0");', HEADER),
    # -- the map: what is refused, and what is never read
    sub('a-zero-stride-is-accepted', 'if (stride < PL_DESC_BYTES_MIN) return PL_MAP_STRIDE_BELOW_40;', '', HEADER),
    sub('a-stride-of-44-is-accepted', 'if (stride & 7u) return PL_MAP_STRIDE_NOT_8;', '', HEADER),
    sub('a-partial-descriptor-is-accepted', 'if (!size || size % stride) return PL_MAP_SIZE;', 'if (!size) return PL_MAP_SIZE;', HEADER),
    sub('a-misaligned-base-is-accepted', '(base & 7u) || ', '', HEADER),
    sub('a-huge-count-is-accepted', 'if (size / stride > PL_DESCRIPTORS_MAX) return PL_MAP_TOO_MANY;', '', HEADER),
    sub('a-wrapping-buffer-is-accepted', ' || size > PL_ADDRESS_LIMIT - base', '', HEADER),
    sub('pages-are-read-from-the-wrong-field', '*(const pl_u64a *)(p + 24)', '*(const pl_u64a *)(p + 16)', HEADER),
    sub('an-unaligned-descriptor-is-used', '(d->start & (PL_PAGE_BYTES - 1)) || ', '', HEADER),
    sub('an-overflowing-descriptor-is-used', 'pages > (PL_ADDRESS_LIMIT - d->start) / PL_PAGE_BYTES', '0', HEADER),
    # -- the registers that may trap: announced, eight seconds, then read
    sub('the-wait-is-nothing', '#define WAIT_BEFORE_READ_S 8u', '#define WAIT_BEFORE_READ_S 0u'),
    sub('the-wait-is-eight-milliseconds', 'if (now - start >= seconds * freq) return 1;', 'if (now - start >= seconds * freq / 1000) return 1;'),
    sub('a-counter-going-back-ends-the-wait', '        if (now < start) return 0;\n', ''),
    sub('mdscr-is-read-before-its-next-line', 'if (!announce(a, p, freq, "MDSCR_EL1")) return made;\n    value = SYSREG(mdscr_el1);',
        'value = SYSREG(mdscr_el1);\n    if (!announce(a, p, freq, "MDSCR_EL1")) return made;'),
    sub('the-counter-op-is-not-checked', 'if (!a->ops.counter) {', 'if (0) {'),
    sub('a-stuck-counter-is-waited-for-ever', 'if (++same >= COUNTER_STUCK_READS) return 0;', 'if (++same >= COUNTER_STUCK_READS) return 1;'),
    sub('cntpoff-is-read', 'pl_add_hex(a, p, "REVIDR", SYSREG(revidr_el1));', 'pl_add_hex(a, p, "REVIDR", SYSREG(S3_4_C14_C0_6));'),
    sub('a-frequency-of-zero-is-used', 'if (freq < COUNTER_HZ_MIN || freq > COUNTER_HZ_MAX) freq = COUNTER_HZ_DEFAULT;', ''),
    # -- where it runs
    sub('it-runs-below-el2', 'if ((current_el >> 2 & 3) != 2) {', 'if (0) {'),
    sub('el3-is-taken-for-el2', 'if ((current_el >> 2 & 3) != 2) {', 'if ((current_el >> 2 & 3) < 2) {'),
    sub('the-arguments-are-not-checked', '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n', ''),
]

BUDGET_MUTANTS = [
    # Built with a 14-line page: the lines that may not be dropped, and the count of the dropped ones.
    ('next-lines-may-be-dropped', FILE, [('pl_say(a, p, "NEXT", text.buf, 1);', 'pl_say(a, p, "NEXT", text.buf, 0);')]),
    ('the-last-line-may-be-dropped', FILE, [('pl_page_open(&p, "DONE", 1);', 'pl_page_open(&p, "DONE", 0);')]),
    ('nothing-is-reserved', FILE, [('#define ESSENTIAL_LINES 4u', '#define ESSENTIAL_LINES 0u')]),
    ('dropped-lines-are-not-counted', PAGE, [('        p->suppressed++;\n', '')]),
]


class El2memMutants(unittest.TestCase):
    _build = staticmethod(native.Mutants._build)

    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_there_are_enough_distinct_mutants_and_every_file_has_one(self):
        names = [m[0] for m in MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertGreaterEqual(len(names), 40)
        self.assertEqual({m[1] for m in MUTANTS}, {FILE, HEADER})

    def test_the_unmutated_control_passes_from_a_copy(self):
        directory = BUILD / 'control'
        native.copy_tree(directory)
        done, binary = native.Mutants._build('el2mem', directory, False)
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary)
        self.assertEqual(code, 0, output[-600:])

    def test_every_seeded_bug_is_caught(self):
        kit.run_mutants(native, MUTANTS, self)

    def test_every_seeded_budget_bug_is_caught_by_the_page_built_small(self):
        for name, file, edits in BUDGET_MUTANTS:
            with self.subTest(mutant=name):
                directory = BUILD / f'budget-{name}'
                native.copy_tree(directory)
                path = directory / file
                text = path.read_text(encoding='utf-8')
                for needle, replacement in edits:
                    self.assertEqual(text.count(needle), 1, needle)
                    text = text.replace(needle, replacement, 1)
                path.write_text(text, encoding='utf-8')
                binary = directory / 'bin' / 'test-el2mem14'
                binary.parent.mkdir(parents=True, exist_ok=True)
                cmd = ['clang'] + native.SANITIZE + native.RELAXED + native.GATES + [
                    '-I', str(directory / 'uefi'), '-I', str(directory / 'payloads'), '-DQ1N1_PAYLOAD_HOST_TEST=1', '-DTEST_BUDGET=14',
                    '-DPL_PAGE_LINES=14u', str(ROOT / 'tools' / 'test-q1n1-sp11-payload-el2mem.c'),
                    str(directory / 'uefi' / 'sp11-payload-text.c'), str(directory / 'payloads' / 'el2mem.c'), '-o', str(binary)]
                done = run(cmd)
                self.assertEqual(done.returncode, 0, done.stderr[-400:])
                caught = [native.run_program(binary, suite)[0] != 0 for suite in ('budget', 'worst')]
                self.assertTrue(any(caught), 'the small page still passed')


ANCHOR = '    pl_page_open(&p, "START", 0);\n'
SURVEY = '            s->type_start[d.type] = d.start;\n'


def after(anchor, text):
    return [(anchor, anchor + text)]


BAD_BINARIES = [
    # (name, edits to el2mem.c, what the check must say)
    ('an-msr', after(ANCHOR, '    __asm__ volatile("msr daifset, #2" ::: "memory");\n'), 'msr'),
    ('a-dc', after(ANCHOR, '    __asm__ volatile("dc civac, %0" :: "r"(a) : "memory");\n'), 'dc'),
    ('an-ic', after(ANCHOR, '    __asm__ volatile("ic iallu" ::: "memory");\n'), 'ic'),
    ('a-tlbi', after(ANCHOR, '    __asm__ volatile("tlbi vmalle1" ::: "memory");\n'), 'tlbi'),
    ('at-s1e2w', after(ANCHOR, '    __asm__ volatile("at s1e2w, %0" :: "r"(a) : "memory");\n'), 'forbidden instruction at s1e2w'),
    ('at-s1e1r', after(ANCHOR, '    __asm__ volatile("at s1e1r, %0" :: "r"(a) : "memory");\n'), 'forbidden instruction at s1e1r'),
    ('at-s12e1w', after(ANCHOR, '    __asm__ volatile("at s12e1w, %0" :: "r"(a) : "memory");\n'), 'forbidden instruction at s12e1w'),
    ('an-smc', after(ANCHOR, '    __asm__ volatile("smc #0" ::: "memory");\n'), 'smc'),
    ('an-hvc', after(ANCHOR, '    __asm__ volatile("hvc #0" ::: "memory");\n'), 'hvc'),
    ('a-dsb', after(ANCHOR, '    __asm__ volatile("dsb sy" ::: "memory");\n'), 'dsb'),
    ('a-dmb', after(ANCHOR, '    __asm__ volatile("dmb sy" ::: "memory");\n'), 'dmb'),
    ('a-wfe', after(ANCHOR, '    __asm__ volatile("wfe");\n'), 'wfe'),
    ('an-eret', after(ANCHOR, '    __asm__ volatile("eret");\n'), 'eret'),
    ('an-exclusive-load', after(ANCHOR, '    __asm__ volatile("ldxr x9, [sp]" ::: "x9", "memory");\n'), 'ldxr'),
    ('an-atomic-add', after(ANCHOR, '    __asm__ volatile(".arch_extension lse\\n ldadd x9, x10, [sp]" ::: "x9", "x10", "memory");\n'), 'ldadd'),
    ('a-word-that-is-no-instruction', after(ANCHOR, '    __asm__ volatile(".inst 0xffffffff");\n'), 'not a known instruction'),
    ('a-read-of-cntpoff-el2', after(ANCHOR, '    (void)SYSREG(S3_4_C14_C0_6);\n'), 'the code names'),
    ('a-read-of-cntvoff-el2', after(ANCHOR, '    (void)SYSREG(cntvoff_el2);\n'), 'the code names'),
    ('a-read-of-midr', after(ANCHOR, '    (void)SYSREG(midr_el1);\n'), 'registers read'),
    ('a-store-through-a-descriptor-address', after(SURVEY, '            *(volatile uint32_t *)(uintptr_t)d.start = 0;\n'), 'a store in map_survey'),
    ('a-store-through-the-map-pointer', after(ANCHOR, '    *(volatile uint64_t *)(uintptr_t)a->map_base = 0;\n'), 'a store in payload_entry'),
    ('a-store-to-the-arguments', after(ANCHOR, '    ((struct q1n1_payload_args *)(uintptr_t)a)->reserved[0] = 1;\n'), 'a store in payload_entry'),
    ('a-load-through-a-descriptor-address', after(SURVEY, '            (void)*(volatile const uint32_t *)(uintptr_t)d.start;\n'), 'a load in map_survey'),
]


class El2memBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kit.need_tools(cls)
        cls.out = BUILD / 'binary'
        shutil.rmtree(cls.out, ignore_errors=True)
        cls.builder = kit.Builder(cls.out)
        done, cls.elf, cls.flat = cls.builder.build('el2mem', 'el2mem', [], check=True)
        if done.returncode:
            raise RuntimeError('el2mem did not build:\n' + done.stderr[-1500:])
        cls.facts = kit.facts(cls.elf, cls.flat)

    def test_the_binary_holds_only_what_its_policy_allows(self):
        self.assertEqual(lib.binary_violations(self.elf, self.flat, lib.POLICIES['el2mem'], READELF()), [])

    def test_exactly_one_at_one_isb_and_one_read_of_par_el1(self):
        f = self.facts
        self.assertEqual((f['mnemonics']['at'], f['mnemonics']['isb'], f['mrs']['par_el1']), (1, 1, 1))
        self.assertEqual(set(f['mrs']), lib.POLICIES['el2mem']['registers'])
        self.assertNotIn('dsb', f['mnemonics'])
        for banned in ('msr', 'dc', 'ic', 'tlbi', 'smc', 'hvc', 'svc', 'eret', 'wfe', 'wfi', 'sys'):
            self.assertNotIn(banned, f['mnemonics'])
        self.assertLessEqual(f['bytes'], lib.POLICIES['el2mem']['bytes'])

    def test_the_hazard_reads_are_last_and_each_has_its_next_line_before_it(self):
        dis = run(['llvm-objdump', '-d', '--no-show-raw-insn', str(self.elf)]).stdout
        reads = [m.group(1).lower() for m in re.finditer(r'\bmrs\s+\w+, (\w+)', dis)]
        function = dis[dis.index('<report_hazards>:'):]
        function = function[:function.index('\n\n')]
        in_function = [m.group(1).lower() for m in re.finditer(r'\bmrs\s+\w+, (\w+)', function)]
        self.assertEqual(in_function, ['mdscr_el1', 'oslsr_el1', 'icc_sre_el2'])
        self.assertEqual(function.count('<announce>'), 3, 'each read is behind a call of announce')
        self.assertLess(function.index('<announce>'), function.index('MDSCR_EL1'))
        self.assertEqual(sorted(reads).count('par_el1'), 1)

    def test_seeded_bad_binaries_are_each_refused_for_the_right_reason(self):
        self.assertGreaterEqual(len(BAD_BINARIES), 20)
        for name, edits, expected in BAD_BINARIES:
            with self.subTest(binary=name):
                done, elf, flat = self.builder.build('el2mem', name, edits)
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                problems = lib.binary_violations(elf, flat, lib.POLICIES['el2mem'], READELF())
                self.assertTrue(problems, 'the check passed a binary it must refuse')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_the_other_policies_refuse_it_and_it_refuses_their_binaries(self):
        for other in OLDER:
            with self.subTest(policy=other):
                self.assertTrue(lib.binary_violations(self.elf, self.flat, lib.POLICIES[other], READELF()))
        older = BUILD / 'older'
        shutil.rmtree(older, ignore_errors=True)
        older.mkdir(parents=True)
        for other in OLDER:
            with self.subTest(payload=other):
                done, elf, flat = lib.build_payload(ROOT / 'payloads' / f'{other}.c', older, name=other, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertTrue(lib.binary_violations(elf, flat, lib.POLICIES['el2mem'], READELF()))

    def test_the_five_older_payloads_are_byte_for_byte_what_the_hardware_runs_pinned(self):
        older = BUILD / 'older'
        for name, digest in OLDER.items():
            with self.subTest(payload=name):
                done, _, flat = lib.build_payload(ROOT / 'payloads' / f'{name}.c', older, name=name, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(hashlib.sha256(Path(flat).read_bytes()).hexdigest(), digest)

    def test_the_shared_build_test_builds_and_audits_both_payloads_because_it_walks_every_policy(self):
        build_test = (ROOT / 'tools' / 'test-q1n1-sp11-payload-build.py').read_text(encoding='utf-8')
        self.assertIn('POLICY = lib.POLICIES', build_test)
        self.assertIn('for name in cls.POLICY}', build_test)
        self.assertLessEqual({'el2mem', 'hashbig'}, set(lib.POLICIES))

    def test_two_builds_are_byte_identical_and_the_entry_is_at_offset_zero(self):
        done, _, flat = kit.Builder(BUILD / 'again').build('el2mem', 'el2mem', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(Path(flat).read_bytes(), Path(self.flat).read_bytes())
        self.assertEqual(Path(self.flat).read_bytes()[:4], bytes.fromhex('5f2403d5'), 'BTI c first, as the runner expects')


def facts_main():
    kit.need_tools(None)
    out = BUILD / 'facts'
    done, elf, flat = kit.Builder(out).build('el2mem', 'el2mem', [], check=True)
    if done.returncode:
        sys.exit(done.stderr)
    f = kit.facts(elf, flat)
    print(f'el2mem.bin: {f["bytes"]} bytes, sha256 {f["sha256"]}, {f["instructions"]} instructions')
    print('registers read:', ', '.join(f'{r} x{n}' for r, n in sorted(f['mrs'].items())))
    print('allow-list violations:', lib.binary_violations(elf, flat, lib.POLICIES['el2mem'], READELF()))


if __name__ == '__main__':
    if sys.argv[1:] == ['facts']:
        facts_main()
    else:
        sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
