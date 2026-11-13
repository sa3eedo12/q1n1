#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native tests, seeded-bug mutants and source audits for stage S0 of the Surface Pro 11 stick-log
survey (platform/uefi/sp11-stk-*.[ch]; docs/SP11-STK-SURVEY.md; design: docs/SP11-STICK-LOG.md of the
paired Snapintosh repository, section 3.5/3.6, stage S0, Appendix A).

    python3 tools/test-q1n1-sp11-stk.py

Runs, under ASan and UBSan:
  * Native: the four native programs, each built from the real sources --
    tools/test-q1n1-sp11-stk.c (text, device paths, gate, verdict, SMMU verdict, memory map, the
    bounded xHCI and SMR walkers, layout), tools/test-q1n1-sp11-stk-bounds.c (the walk over the
    firmware's slot contexts and the most P2 lines there can be), tools/test-q1n1-sp11-stk-el2.c (the
    EL2 sequencer against a fake SoC: golden lines, fault injection at every load, worst case, budget)
    and tools/test-q1n1-sp11-stk-p2.c (the P2 firmware queries against a fake firmware);
  * Mutants: seeded bugs, each applied to a copy of the sources under build/, each of which the
    programs must reject (a program that fails, or hangs, catches it), against an unmutated control
    that must pass the same way;
  * SourceAudit: properties no run can show -- SPDX lines, that nothing in the survey stores, that
    P2 never asks for a string descriptor or writes, that the main.c glue forwards loads only, that no
    machine identifier is in any new file, and (with SNAPINTOSH_DIR) that every register offset and
    every line and field name matches Appendix A.

SNAPINTOSH_DIR: the paired Snapintosh checkout (SKIP the Appendix A comparisons without it). Nothing
is written outside build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
import concurrent.futures
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
UEFI = ROOT / 'platform' / 'uefi'
BUILD = ROOT / 'build' / 'sp11-stk-test'
LLVM = ('/opt/homebrew/opt/llvm/bin', '/opt/homebrew/opt/lld/bin', '/opt/homebrew/bin')
ENV = dict(os.environ, PATH=os.pathsep.join(LLVM + (os.environ.get('PATH', ''),)), PYTHONDONTWRITEBYTECODE='1')
SANITIZE = ['-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
            '-Wall', '-Wextra', '-Werror']
# The survey files compile to nothing unless both gates are defined on the command line.
GATES = ['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_STK_SURVEY=1']
SNAPINTOSH_DIR = os.environ.get('SNAPINTOSH_DIR')
RUN_TIMEOUT = 120

COMMON = ['sp11-stk-text.c', 'sp11-stk-path.c', 'sp11-stk-rules.c']
# name: (test program, survey sources it links, suites it must run, fewest checks it must make, label)
PROGRAMS = {
    'logic': ('tools/test-q1n1-sp11-stk.c', COMMON + ['sp11-fbgop.c'], 9, 59000, 'logic'),
    'bounds': ('tools/test-q1n1-sp11-stk-bounds.c', COMMON + ['sp11-stk-p2fmt.c'], 2, 25, 'bounds'),
    'el2': ('tools/test-q1n1-sp11-stk-el2.c', COMMON + ['sp11-stk-el2.c', 'sp11-fbgop.c'], 10, 5000, 'EL2'),
    'p2': ('tools/test-q1n1-sp11-stk-p2.c',
           COMMON + ['sp11-stk-el2.c', 'sp11-stk-p2fmt.c', 'sp11-stk-p2.c', 'sp11-fbgop.c'], 4, 1000, 'P2'),
}
SOURCES_COPIED = sorted(p.name for p in UEFI.glob('sp11-stk-*')) + ['sp11-fbgop.c', 'sp11-fbgop.h', 'efi.h']

SURVEY_SOURCES = sorted(UEFI.glob('sp11-stk-*.c'))
SURVEY_FILES = sorted(UEFI.glob('sp11-stk-*'))
NEW_FILES = SURVEY_FILES + sorted((ROOT / 'tools').glob('test-q1n1-sp11-stk*')) + [ROOT / 'docs' / 'SP11-STK-SURVEY.md']


def run(cmd, cwd=ROOT, timeout=None, **kw):
    return subprocess.run(cmd, cwd=cwd, env=ENV, capture_output=True, text=True, timeout=timeout, **kw)


def have(tool):
    return shutil.which(tool, path=ENV['PATH']) is not None


def build_program(name, source_dir, out_dir, relaxed=False):
    """Compiles one native program against the sources in source_dir. Returns (completed, binary).
    A mutant may leave a variable unused; that is no reason for it not to build."""
    out_dir.mkdir(parents=True, exist_ok=True)
    test_c, libs = PROGRAMS[name][:2]
    binary = out_dir / f'test-{name}'
    extra = ['-Wno-unused-variable', '-Wno-unused-parameter', '-Wno-unused-function',
             '-Wno-unused-but-set-variable'] if relaxed else []
    cmd = (['clang'] + SANITIZE + extra + GATES + ['-I', str(source_dir), str(ROOT / test_c)] +
           [str(Path(source_dir) / lib) for lib in libs] + ['-o', str(binary)])
    return run(cmd), binary


def run_program(binary):
    """(returncode, output); a hang is reported as returncode None."""
    try:
        done = run([str(binary), 'all'], timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired as hung:
        return None, (hung.stdout or '') if isinstance(hung.stdout, str) else ''
    return done.returncode, done.stdout + done.stderr


class Native(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def _check(self, name):
        _, _, suites, minimum, label = PROGRAMS[name]
        done, binary = build_program(name, UEFI, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = run_program(binary)
        self.assertEqual(code, 0, output)
        found = re.search(rf'PASS: (\d+) stick-log survey {label} suites, (\d+) checks', output)
        self.assertIsNotNone(found, output)
        self.assertEqual(int(found.group(1)), suites, output)
        self.assertGreaterEqual(int(found.group(2)), minimum, 'a suite stopped checking what it used to')
        self.assertNotIn('FAIL', output)

    def test_pure_logic_suites_pass(self):
        self._check('logic')

    def test_bounded_walker_and_line_bound_suites_pass(self):
        self._check('bounds')

    def test_el2_sequencer_suites_pass(self):
        self._check('el2')

    def test_p2_query_suites_pass(self):
        self._check('p2')


# One seeded bug per property the survey's safety rests on. Each edit's needle must occur exactly once,
# so a change to the source that moves a target is reported as a stale mutant and not as a survivor.
# Third item: the programs that must reject it.
MUTANTS = [
    ('store-instead-of-load', 'sp11-stk-el2.c',
     [('return ops->guarded(ops->ctx, STK_G_COPY32,', 'return ops->guarded(ops->ctx, STK_G_SET32,')], ['el2']),
    ('gate-inverted', 'sp11-stk-rules.c',
     [('if (!(gdscr->v >> 31)) return STK_GATE_OFF;', 'if ((gdscr->v >> 31)) return STK_GATE_OFF;')], ['logic', 'el2']),
    ('gate-ignores-clocks', 'sp11-stk-rules.c',
     [('else if (clk[i].v >> 31) return STK_GATE_PARTIAL;', 'else if (0) return STK_GATE_PARTIAL;')], ['logic']),
    ('controller-read-without-gate', 'sp11-stk-el2.c',
     [('    if (c->gate != STK_GATE_ON) {\n        char reason[16];', '    if (0) {\n        char reason[16];')], ['el2']),
    ('xecp-loop-bound-removed', 'sp11-stk-rules.c',
     [('for (unsigned n = 0; n < STK_XECP_MAX_CAPS; n++) {', 'for (unsigned n = 0;; n++) {')], ['logic']),
    ('ram-check-removed', 'sp11-stk-el2.c',
     [('if (!e->a->map_ok || !stk_map_range_is_ram(e->a->map, e->a->map_count, phys, size)) {', 'if (0) {')], ['el2']),
    ('vendor-and-product-id-printed', 'sp11-stk-p2.c',
     [('io->bcd_usb = (uint16_t)(dev[STK_USB_BCD_USB] | dev[STK_USB_BCD_USB + 1] << 8);',
       'io->bcd_usb = (uint16_t)(dev[8] | dev[9] << 8);')], ['p2']),
    ('smr-scan-bound-removed', 'sp11-stk-rules.c',
     [('if (numsmrg > STK_SMR_MAX) numsmrg = STK_SMR_MAX;', '')], ['logic']),
    ('s2cr-type-decode-swapped', 'sp11-stk-rules.c',
     [('if (s->type == 0) return STK_SMMU_TRANS;', 'if (s->type == 0) return STK_SMMU_BYPASS;'),
      ('if (s->type == 1) return STK_SMMU_BYPASS;', 'if (s->type == 1) return STK_SMMU_TRANS;')], ['logic']),
    ('line-cap-101', 'sp11-stk-survey.h',
     [('#define STK_LINE_MAX 100u', '#define STK_LINE_MAX 101u')], ['logic', 'el2', 'p2', 'bounds']),
    ('line-budget-61', 'sp11-stk-survey.h',
     [('#define STK_MAX_LINES 60u', '#define STK_MAX_LINES 61u')], ['logic', 'el2']),
    ('inconsistent-rule-dropped', 'sp11-stk-rules.c',
     [('return (ccs && !pp) || (ped && !ccs) || (ped && !pp) || sc == 0xffffffffu;', 'return sc == 0xffffffffu;')],
     ['logic']),
    ('ccs-without-pp-allowed', 'sp11-stk-rules.c',
     [('return (ccs && !pp) || (ped && !ccs)', 'return (0 && ccs && !pp) || (ped && !ccs)')], ['logic']),
    ('device-path-bound-removed', 'sp11-stk-path.c',
     [('if (len > max_bytes - off) { out->status = STK_DP_TRUNCATED; break; }', '')], ['logic']),
    ('next-smmu-omitted', 'sp11-stk-el2.c',
     [('next(e, "SMMU", 1);', '')], ['el2']),
    ('window-range-unchecked', 'sp11-stk-el2.c',
     [('if ((off & 3) || off >= w->size || w->size - off < 4) return STK_E_RANGE;', 'if (off & 3) return STK_E_RANGE;')],
     ['el2']),
    ('mapping-attribute-unchecked', 'sp11-stk-el2.c',
     [('if (attr != STK_ATTR_DEVICE) {', 'if (0) {')], ['el2']),
    ('memory-map-window-refusal-dropped', 'sp11-stk-el2.c',
     [('!stk_map_range_allows_device(args->map, args->map_count, win->base, win->size) ? STK_E_MAP_RAM',
       '0 ? STK_E_MAP_RAM')], ['el2']),
    ('fault-does-not-stop-the-controller', 'sp11-stk-el2.c',
     [('        c->stopped = 1;\n        c->obs.fault = 1;', '        c->obs.fault = 1;')], ['el2']),
    ('font-folding-removed', 'sp11-stk-text.c',
     [("if (!in_font(*text)) *text = '_';", '')], ['logic', 'el2', 'p2']),
    ('slot-pointer-alignment-unchecked', 'sp11-stk-rules.c',
     [('if (entry & (DCBAA_ALIGN - 1)) { s->err = STK_E_RANGE; continue; }', '')], ['bounds', 'el2']),
    ('slot-count-unbounded', 'sp11-stk-rules.c',
     [('if (slots > STK_SLOTS_SCANNED) slots = STK_SLOTS_SCANNED;', '')], ['bounds']),
    ('ancestor-usb-io-accepted', 'sp11-stk-p2.c',
     [('matched < dp->last_usb_end ||', '')], ['p2']),
    ('baseline-read-on-the-wrong-controller', 'sp11-stk-p2.c',
     [('!stk_dp_is_prefix(hcdp, STK_DP_MAX_BYTES, self, dp.bytes, dp.first_usb_offset))', '0)')], ['p2']),
    ('baseline-without-version-check', 'sp11-stk-p2.c',
     [('#define XHCI_VERSION_MAX 0x01ffu', '#define XHCI_VERSION_MAX 0xffffu')], ['p2']),
    ('pool-buffer-leaked', 'sp11-stk-p2.c',
     [('if (bs->free_pool) bs->free_pool(resources);', '')], ['p2']),
    ('dropped-p2-lines-not-reported', 'sp11-stk-text.c',
     [('if (p2->dropped) {', 'if (0) {')], ['bounds']),
]


class Mutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _copy_sources(directory):
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True)
        for name in SOURCES_COPIED:
            shutil.copy(UEFI / name, directory / name)

    def _evaluate(self, name, fname, edits, programs):
        """(status, detail): 'caught', 'survived', 'stale' (target not found) or 'broken' (no build)."""
        directory = BUILD / f'mutant-{name}'
        self._copy_sources(directory)
        text = (directory / fname).read_text(encoding='utf-8')
        for needle, replacement in edits:
            if text.count(needle) != 1:
                return 'stale', f'target not found exactly once in {fname}: {needle[:60]!r}'
            text = text.replace(needle, replacement, 1)
        (directory / fname).write_text(text, encoding='utf-8')
        for program in programs:
            done, binary = build_program(program, directory, directory, relaxed=True)
            if done.returncode != 0:
                return 'broken', f'{program} did not compile: {done.stderr[-400:]}'
            code, output = run_program(binary)
            if code != 0:
                return 'caught', f'{program}: ' + ('hang' if code is None else output.strip().splitlines()[-1][:120])
        return 'survived', 'every named program still passed'

    def test_the_unmutated_control_passes_from_a_copy(self):
        directory = BUILD / 'control'
        self._copy_sources(directory)
        for program in PROGRAMS:
            done, binary = build_program(program, directory, directory)
            self.assertEqual(done.returncode, 0, done.stderr)
            code, output = run_program(binary)
            self.assertEqual(code, 0, f'{program}: {output[-600:]}')

    def test_there_are_enough_distinct_mutants(self):
        self.assertGreaterEqual(len(MUTANTS), 8)
        self.assertEqual(len({m[0] for m in MUTANTS}), len(MUTANTS))

    def test_every_seeded_bug_is_caught(self):
        workers = max(1, min(4, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {m[0]: pool.submit(self._evaluate, *m) for m in MUTANTS}
            results = {name: future.result() for name, future in futures.items()}
        for name, (status, detail) in results.items():
            with self.subTest(mutant=name):
                self.assertEqual(status, 'caught', f'{status}: {detail}')


class SourceAudit(unittest.TestCase):
    @staticmethod
    def read(path):
        return Path(path).read_text(encoding='utf-8')

    def test_new_files_carry_spdx_mit(self):
        for path in NEW_FILES:
            if path.suffix == '.md' or not path.exists():
                continue
            with self.subTest(file=path.name):
                self.assertIn('SPDX-License-Identifier: MIT', self.read(path)[:200])

    def test_the_survey_never_stores(self):
        for path in SURVEY_SOURCES:
            text = self.read(path)
            with self.subTest(file=path.name):
                self.assertNotIn('STK_G_SET32', text)
                self.assertNotIn('volatile', text, 'a raw access: every load goes through stk_ops.guarded')
                for banned in ('memset32', 'live_write32', 'write32', 'memcpy64'):
                    self.assertNotIn(banned, text)
        el2 = self.read(UEFI / 'sp11-stk-el2.c')
        self.assertEqual(len(re.findall(r'->guarded\(', el2)), 1)
        self.assertIn('return ops->guarded(ops->ctx, STK_G_COPY32,', el2)
        # The header names the forbidden kind once, to say it is forbidden.
        header = self.read(UEFI / 'sp11-stk-survey.h')
        self.assertEqual(len(re.findall(r'\bSTK_G_SET32\b', header)), 2)   # the definition and its comment

    def test_p2_only_reads_what_it_is_allowed_to(self):
        for name in ('sp11-stk-p2.c', 'sp11-stk-p2fmt.c'):
            text = self.read(UEFI / name)
            code = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
            for banned in ('get_string_descriptor', 'get_supported_languages', 'control_transfer', 'bulk_transfer',
                           'interrupt_transfer', 'isochronous', 'port_reset', 'mem.write', 'io.write', 'pci.write',
                           'allocate_pool', 'allocate_pages', 'get_memory_map', 'exit_boot_services',
                           'set_bar_attributes', 'attributes ='):
                with self.subTest(file=name, banned=banned):
                    self.assertNotIn(banned, code)
        code = re.sub(r'/\*.*?\*/', '', self.read(UEFI / 'sp11-stk-p2.c'), flags=re.S)
        # The device descriptor is indexed only for bcdUSB (and cleared by a loop); never at the
        # offsets of the vendor id, the product id or the serial number's string index.
        for index in re.findall(r'\bdev\[([^\]]+)\]', code):
            self.assertIn(index.strip(), ('STK_USB_BCD_USB', 'STK_USB_BCD_USB + 1', 'STK_USB_DEVICE_DESC_BYTES', 'i'), index)
        self.assertNotIn('idVendor', code)
        self.assertNotIn('idProduct', code)

    def test_the_main_c_glue_forwards_loads_only(self):
        main_c = self.read(UEFI / 'main.c')
        start = main_c.index('static int stk_guarded(')
        body = main_c[start:main_c.index('\n}\n', start)]
        self.assertIn('if (kind != STK_G_COPY32) return 1;', body)
        self.assertIn('return live_guarded(0, dst, src, size);', body)
        glue = main_c[main_c.index('/* ---- Stick-log survey (sp11-stk-survey.h): the platform side'):
                      main_c.index('#endif /* Q1N1_SP11_STK_SURVEY */')]
        self.assertEqual(len(re.findall(r'live_guarded\(', glue)), 1)   # the one call, in stk_guarded
        for banned in ('live_write32', 'memset32', 'q1n1_memcpy64'):
            self.assertNotIn(banned, glue)

    def test_every_survey_line_is_under_the_gate_in_main_c(self):
        main_c = self.read(UEFI / 'main.c')
        for needle in ('sp11_stk_el2_survey', 'stk_p2_collect', 'stk_requested = 1;', 'STK P3 SKIPPED=NOT_AT_EL2'):
            for at in [m.start() for m in re.finditer(re.escape(needle), main_c)]:
                # The preprocessor conditionals open at that point; an #else or #elif of the gate is
                # the code that runs with the gate off, so it does not count.
                stack = []
                for found in re.finditer(r'^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif)\b(.*)$', main_c[:at], flags=re.M):
                    kind, rest = found.group(1), found.group(2).split('/*')[0].strip()
                    if kind in ('if', 'ifdef', 'ifndef'):
                        stack.append((kind, rest))
                    elif kind in ('elif', 'else'):
                        stack[-1] = (kind, rest)
                    else:
                        stack.pop()
                self.assertIn(('if', 'Q1N1_SP11_STK_SURVEY'), stack, f'{needle} at offset {at} is outside the survey gate')

    def test_the_survey_runs_only_from_the_el2_flow(self):
        main_c = self.read(UEFI / 'main.c')
        at = main_c.index('stk_requested = 1;')
        context = main_c[max(0, at - 900):at + 200]
        self.assertIn('--el2', context)
        self.assertEqual(main_c.count('stk_requested = 1;'), 1)

    def test_no_machine_identifiers_in_new_files(self):
        # Built from pieces so that this file does not contain what it looks for.
        paths = '|'.join(['/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/'])
        pattern = re.compile(paths + r'|\.loc' + r'al\b|\bsae' + r'ed\b|host' + r'name|' +
                             r'\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', re.I)
        for path in NEW_FILES:
            if not path.exists():
                continue
            for number, line in enumerate(self.read(path).splitlines(), 1):
                with self.subTest(file=path.name, line=number):
                    self.assertIsNone(pattern.search(line), line)

    def test_survey_files_are_not_oversized(self):
        sources = SURVEY_SOURCES + sorted((ROOT / 'tools').glob('test-q1n1-sp11-stk*.c'))
        self.assertGreaterEqual(len(sources), 10)
        for path in sources:
            text = self.read(path)
            with self.subTest(file=path.name):
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)

    @unittest.skipUnless(SNAPINTOSH_DIR, 'SNAPINTOSH_DIR not set: no design document to compare against')
    def test_register_offsets_are_the_ones_appendix_a_lists(self):
        doc = self.read(Path(SNAPINTOSH_DIR) / 'docs' / 'SP11-STICK-LOG.md')
        doc_numbers = {int(n, 16) for n in re.findall(r'0x([0-9a-fA-F]+)', doc)}
        el2 = self.read(UEFI / 'sp11-stk-el2.c')
        region = el2[el2.index('const struct stk_window stk_windows'):el2.index('/* xHCI registers:')]
        region = re.sub(r'/\*.*?\*/', '', region, flags=re.S)
        smmu = '\n'.join(line for line in el2.splitlines() if line.startswith('#define SMMU_'))
        rules = '\n'.join(line for line in self.read(UEFI / 'sp11-stk-rules.c').splitlines()
                          if line.startswith('#define SMMU_'))
        constants = {int(n, 16) for n in re.findall(r'0x([0-9a-fA-F]+)', region + smmu + rules)}
        self.assertGreater(len(constants), 30)
        # GLUE_BASE + 0x10 / + 0x30 are written as sums in the source and as +0x10 / +0x30 in the table.
        missing = sorted(hex(c) for c in constants if c not in doc_numbers)
        self.assertEqual(missing, [], 'register constants the design document does not list')

    @unittest.skipUnless(SNAPINTOSH_DIR, 'SNAPINTOSH_DIR not set: no design document to compare against')
    def test_line_and_field_names_are_the_ones_appendix_a_lists(self):
        doc = self.read(Path(SNAPINTOSH_DIR) / 'docs' / 'SP11-STICK-LOG.md')
        appendix = doc[doc.index('## Appendix A.'):doc.index('## Appendix B.')]
        sources = '\n'.join(self.read(p) for p in SURVEY_SOURCES)
        keys = set()
        for row in appendix.splitlines():
            cells = [c.strip() for c in row.split('|')]
            if len(cells) < 4 or not cells[1].startswith('`STK'):
                continue
            keys.update(re.findall(r'\b([A-Z][A-Z0-9]*)(?:<[a-z]+>)?=', cells[2]))
        keys -= {'PATH'}   # printed through the device path formatter's own key
        self.assertGreater(len(keys), 60)
        absent = sorted(k for k in keys if f'"{k}"' not in sources and f'{k}=' not in sources)
        self.assertEqual(absent, [], 'field names Appendix A lists that no survey source prints')
        for line in ('STK P2 BUILD', 'STK P2 SELF', 'STK P2 HUB', 'STK P2 BLK', 'STK P2 USBIO', 'STK P2 HC',
                     'STK NEXT', 'STK P3 MAP', 'STK P3 GCC', 'STK P3 GATE', 'STK P3 SMMU', 'STK P3 VERDICT'):
            self.assertIn(f'"{line}', sources)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
