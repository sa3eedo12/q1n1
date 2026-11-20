#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests of the payload dispsnap (payloads/dispsnap.c, docs/SP11-PAYLOAD-DISPSNAP.md).

    python3 tools/test-q1n1-sp11-payload-dispsnap.py
    python3 tools/test-q1n1-sp11-payload-dispsnap-refs.py     (the pinned reference copies: SKIP without them)
    python3 tools/test-q1n1-sp11-payload-qemu-dispsnap.py     (the structural run under QEMU's EDK2)

  Harness       the native host test (tools/test-q1n1-sp11-payload-dispsnap.c: the suites; tools/test-q1n1-sp11-payload-dispsnap-model.h: a fake register file of the
                four blocks with the harness's own list of registers (the study's dump list), its own statement of the gates, the order and NEXT rules, the counter and the
                page; a fault at every address, hostile words, the gates in both directions, the frame counter, the caps) built under ASan and UBSan at the shipped caps,
                with smaller line and load caps and with a small bound on the wait (the `spin` suite)
  CompiledCode  the compiled code: the IR audit (tools/sp11_payload_dispsnap_audit.py: no number is turned into a pointer, every store's root is the payload's own
                stack) on the real source and on hand-written faulty IR, the `dispsnap` policy of tools/sp11_payload_testlib.py on the linked binary (an allow-list of
                instructions and the `read_only` memory check), the stack depth, two builds that are byte for byte the same, and the manifest tool on the chain
                `dispsnap` then `xhci0`
  Mutants       seeded bugs (tools/sp11_payload_dispsnap_mutants.py): each must be rejected by the suites it names, for the reason it names
  Doc           docs/SP11-PAYLOAD-DISPSNAP.md against the register table of the source, the host model's pages and numbers, the ledger of citations (every file:line the
                document cites is one the pinned-copy test has verified), the chain budget and the list of what could not be verified

SKIPs, never passes, without clang, ld.lld, make and llvm-objdump. It writes only under build/sp11-payload-dispsnap/. Nothing here ran on hardware.
Evidence: EXPERIMENTAL (host model and compiled code only)."""
from pathlib import Path
import re
import shutil
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_dispsnap_audit as audit  # noqa: E402
import sp11_payload_dispsnap_mutants as mutants  # noqa: E402
import sp11_payload_dispsnap_refs as refs  # noqa: E402
import sp11_payload_xhci_audit as xa  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-dispsnap'
HARNESS = ROOT / 'tools' / 'test-q1n1-sp11-payload-dispsnap.c'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-DISPSNAP.md'
EVIDENCE = ROOT / 'docs' / 'SP11-PAYLOAD-DISPSNAP-EVIDENCE.md'
SOURCE = ROOT / 'payloads' / 'dispsnap.c'
REGS = ROOT / 'payloads' / 'dispsnap-regs.h'
MAKE_ARGS = ['-f', 'platform/uefi/Makefile']
TOOLS = ('clang', 'ld.lld', 'make', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy')
SUITES = ('unit', 'cold', 'gate', 'faults', 'storm', 'drift', 'stream', 'frames', 'counter', 'el', 'budget')


def need_tools():
    for tool in TOOLS:
        if not lib.have(tool):
            raise unittest.SkipTest(f'{tool} not installed')


def build_harness(name, *defs, sanitize=True):
    BUILD.mkdir(parents=True, exist_ok=True)
    out = BUILD / name
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-DQ1N1_PAYLOAD_HOST_TEST=1', '-Iplatform/uefi', '-Ipayloads', *defs]
    if sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=undefined']
    done = lib.run(['clang', *flags, '-o', str(out), str(HARNESS)])
    if done.returncode:
        raise RuntimeError('the host test did not build:\n' + done.stderr[-2000:])
    return out


class Harness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()

    def run_harness(self, binary):
        done = lib.run([str(binary)], timeout=600)
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-3000:])
        found = re.search(r'CHECKS (\d+) FAILS (\d+) MAXLINES (\d+) MAXLOADS (\d+) LINE_CAP (\d+) LOAD_CAP (\d+)', done.stdout)
        self.assertTrue(found, done.stdout)
        self.assertEqual(found.group(2), '0')
        return done.stdout, [int(x) for x in found.groups()]

    def test_shipped_caps(self):
        out, (checks, fails, max_lines, max_loads, line_cap, load_cap) = self.run_harness(build_harness('shipped'))
        for suite in SUITES:
            self.assertRegex(out, rf'suite {suite}\s+ok')
        self.assertEqual((line_cap, load_cap), (34, 48))
        self.assertLessEqual(max_lines, 34, 'the widest page does not pass the cap')
        self.assertEqual(max_loads, 32, 'the loads of both snapshots with every gate open, inside the cap the payload asserts')
        self.assertGreater(checks, 800)

    def test_smaller_caps(self):
        for name, defs, line_cap, load_cap in (('lines20', ('-DDISPSNAP_LINE_CAP=20u',), 20, 48), ('lines12', ('-DDISPSNAP_LINE_CAP=12u',), 12, 48),
                                               ('lines6', ('-DDISPSNAP_LINE_CAP=6u',), 6, 48), ('loads20', ('-DDISPSNAP_LOAD_CAP=20u',), 34, 20),
                                               ('both', ('-DDISPSNAP_LOAD_CAP=12u', '-DDISPSNAP_LINE_CAP=26u'), 26, 12)):
            with self.subTest(caps=name):
                out, numbers = self.run_harness(build_harness(name, *defs))
                self.assertRegex(out, r'suite caps\s+ok')
                self.assertEqual((numbers[4], numbers[5]), (line_cap, load_cap))
                self.assertLessEqual(numbers[2], line_cap)
                self.assertLessEqual(numbers[3], load_cap)

    def test_a_small_bound_on_the_wait_makes_the_difference_between_a_slow_counter_and_a_dead_one_testable(self):
        # the shipped bound is 2^32-1 reads, which no model run reaches: a build with a bound of 3 million says SPIN for a counter that moves and never gets there, and not NO_COUNTER
        out, numbers = self.run_harness(build_harness('spin', '-DDISPSNAP_SPIN_MAX=3000000u'))
        self.assertRegex(out, r'suite spin\s+ok')
        self.assertRegex(out, r'suite counter\s+ok')
        self.assertEqual((numbers[4], numbers[5]), (34, 48))


# Faulty IR that the audit must reject, one defect each, and clean IR it must accept: texts, so that the audit is held to what it says whatever the compiler writes.
GOOD_IR = '''
@.str = private unnamed_addr constant [3 x i8] c"A\\00\\00", align 1
define internal void @callee(ptr noundef %p) {
  store i32 1, ptr %p, align 4
  ret void
}
define i64 @payload_entry(ptr noundef %a) {
  %s = alloca i32, align 4
  %g = getelementptr inbounds i8, ptr %s, i64 0
  store volatile i8 0, ptr %g, align 1
  call void @callee(ptr noundef %s)
  call void @callee(ptr noundef %g)
  ret i64 0
}
'''
FAULTY_IR = {
    'inttoptr store': ('define i64 @payload_entry(ptr noundef %a) {\n  %q = inttoptr i64 1048576 to ptr\n  store volatile i32 0, ptr %q, align 4\n  ret i64 0\n}\n',
                       'integer-to-pointer'),
    'inttoptr load': ('define i64 @payload_entry(ptr noundef %a) {\n  %q = inttoptr i64 1048576 to ptr\n  %v = load volatile i32, ptr %q, align 4\n  ret i64 0\n}\n',
                      'integer-to-pointer'),
    'store through the arguments': ('define i64 @payload_entry(ptr noundef %a) {\n  store i64 1, ptr %a, align 8\n  ret i64 0\n}\n', 'arguments'),
    'store through a loaded pointer': ('define i64 @payload_entry(ptr noundef %a) {\n  %s = alloca ptr, align 8\n  %l = load ptr, ptr %s, align 8\n'
                                       '  store i32 0, ptr %l, align 4\n  ret i64 0\n}\n', 'not its own stack'),
    'a loaded pointer handed to a call': ('define internal void @callee(ptr noundef %p) {\n  ret void\n}\n'
                                          'define i64 @payload_entry(ptr noundef %a) {\n  %s = alloca ptr, align 8\n  %l = load ptr, ptr %s, align 8\n'
                                          '  call void @callee(ptr noundef %l)\n  ret i64 0\n}\n', 'could store through'),
    'the arguments handed to a call': ('define internal void @callee(ptr noundef %p) {\n  ret void\n}\n'
                                       'define i64 @payload_entry(ptr noundef %a) {\n  call void @callee(ptr noundef %a)\n  ret i64 0\n}\n', 'could store through'),
    'a constant handed to an indirect call': ('@.str = private unnamed_addr constant [2 x i8] c"A\\00", align 1\n'
                                              'define i64 @payload_entry(ptr noundef %a) {\n  %s = alloca ptr, align 8\n  %f = load ptr, ptr %s, align 8\n'
                                              '  call void %f(ptr noundef @.str)\n  ret i64 0\n}\n', 'indirect call'),
    'a writable global': ('@g = internal global i32 0, align 4\ndefine i64 @payload_entry(ptr noundef %a) {\n  ret i64 0\n}\n', 'writable global'),
    'a libcall': ('declare ptr @memcpy(ptr, ptr, i64)\ndefine i64 @payload_entry(ptr noundef %a) {\n  %s = alloca i32, align 4\n'
                  '  %c = call ptr @memcpy(ptr noundef %s, ptr noundef %s, i64 4)\n  ret i64 0\n}\n', 'does not define'),
    'a memset into the arguments': ('declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)\ndefine i64 @payload_entry(ptr noundef %a) {\n'
                                    '  call void @llvm.memset.p0.i64(ptr %a, i8 0, i64 8, i1 false)\n  ret i64 0\n}\n', 'memset'),
    'an atomic': ('define i64 @payload_entry(ptr noundef %a) {\n  %s = alloca i32, align 4\n  %x = atomicrmw add ptr %s, i32 1 seq_cst\n  ret i64 0\n}\n', 'atomic'),
}


class CompiledCode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        shutil.rmtree(BUILD / 'a', ignore_errors=True)
        shutil.rmtree(BUILD / 'b', ignore_errors=True)
        for name in ('a', 'b'):
            done = lib.run(['make'] + MAKE_ARGS + [f'OUT={(BUILD / name).relative_to(ROOT)}', 'payloads'])
            if done.returncode:
                raise RuntimeError('make payloads failed:\n' + done.stdout[-1500:] + done.stderr[-1500:])
        cls.elf, cls.flat = BUILD / 'a' / 'payloads' / 'dispsnap.elf', BUILD / 'a' / 'payloads' / 'dispsnap.bin'

    def test_two_builds_are_the_same_bytes(self):
        a, b = BUILD / 'a' / 'payloads', BUILD / 'b' / 'payloads'
        names = sorted(p.name for p in a.glob('*.bin'))
        self.assertIn('dispsnap.bin', names)
        for name in names:
            with self.subTest(payload=name):
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes())
        self.assertEqual((a / 'dispsnap.elf').read_bytes(), (b / 'dispsnap.elf').read_bytes())

    def test_it_is_within_what_the_policy_declares(self):
        self.assertLessEqual(self.flat.stat().st_size, lib.POLICIES['dispsnap']['bytes'])
        self.assertEqual(lib.POLICIES['dispsnap']['registers'], {'currentel', 'cntfrq_el0'})
        self.assertEqual(lib.POLICIES['dispsnap']['smc'], 0)
        self.assertTrue(lib.POLICIES['dispsnap']['read_only'])
        self.assertGreaterEqual(lib.POLICIES['dispsnap']['forbid'], {'isb', 'dsb', 'dmb', 'sb'})

    def test_the_binary_holds_only_what_the_policy_allows(self):
        # MRS of CurrentEL and CNTFRQ_EL0, no SMC, no barrier, no system instruction, and every store through the payload's own stack and every load through the
        # stack, its image, the arguments or a pointer they hold (tools/sp11_payload_memcheck.py proves it from the disassembly).
        self.assertEqual(lib.binary_violations(self.elf, self.flat, lib.POLICIES['dispsnap'], 'llvm-readelf'), [])

    def test_the_policy_refuses_the_other_payloads(self):
        for other in ('state', 'usbsmmu', 'psci', 'timer'):
            with self.subTest(binary=other):
                problems = lib.binary_violations(BUILD / 'a' / 'payloads' / f'{other}.elf', BUILD / 'a' / 'payloads' / f'{other}.bin',
                                                 lib.POLICIES['dispsnap'], 'llvm-readelf')
                self.assertTrue(problems)

    def test_the_ir_audit_passes_the_source(self):
        problems, counts = audit.provenance(audit.build_ir(SOURCE, BUILD / 'ir'))
        self.assertEqual(problems, [])
        self.assertGreater(counts['stores'], 30)
        self.assertLessEqual(set(counts['by_root']), {'S', 'P'}, 'every store is rooted in an alloca or in a pointer parameter whose callers pass one')
        self.assertEqual(counts['memory_intrinsics'], 0)
        self.assertGreaterEqual(counts['indirect_calls'], 4, 'the four ops are called through function pointers')

    def test_the_ir_audit_rejects_what_it_says_it_rejects(self):
        problems, _ = audit.provenance(GOOD_IR)
        self.assertEqual(problems, [])
        for label, (text, word) in FAULTY_IR.items():
            with self.subTest(defect=label):
                problems, _ = audit.provenance(text)
                self.assertTrue(problems, 'the audit passed it')
                self.assertTrue(any(word in p for p in problems), problems)

    def test_the_ir_audit_agrees_with_the_xhci_audit_on_roots(self):
        # The pointer-root walk is the xhci audit's; a loaded pointer has root L there and nowhere here may one be a store root or a call argument.
        functions, _ = xa.parse_functions(FAULTY_IR['store through a loaded pointer'][0])
        self.assertEqual(xa.roots(functions[0], '%l'), {'L'})

    def test_the_stack_the_payload_uses(self):
        sizes = audit.frame_sizes(SOURCE, BUILD / 'ir')
        dis = lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(self.elf)]).stdout
        used, path = audit.stack_depth(sizes, dis)
        self.assertEqual(path[0], 'payload_entry')
        self.assertLessEqual(used, audit.STACK_USABLE)
        self.assertGreater(sizes['payload_entry'], 800, 'the context (two snapshots) is in the entry frame')

    def test_the_manifest_tool_takes_dispsnap_in_front_of_either_xhci_payload_in_that_order(self):
        # The chain of the document: the runner calls the files in manifest order, so dispsnap (read-only) comes first and the payload that writes last.
        built = BUILD / 'a' / 'payloads'
        for xhci in ('xhci0', 'xhci1'):
            with self.subTest(second=xhci):
                out = BUILD / f'stick-{xhci}'
                shutil.rmtree(out, ignore_errors=True)
                done = lib.run(['python3', '-B', str(ROOT / 'tools' / 'sp11_payload_manifest.py'), '--out-dir', str(out.relative_to(ROOT)),
                                str((built / 'dispsnap.bin').relative_to(ROOT)), str((built / f'{xhci}.bin').relative_to(ROOT))])
                self.assertEqual(done.returncode, 0, done.stderr)
                stick = out / 'SP11'
                self.assertEqual(sorted(p.name for p in stick.iterdir()), ['DISPSNAP.BIN', 'PAYLOAD.MAN', f'{xhci.upper()}.BIN'])
                manifest = (stick / 'PAYLOAD.MAN').read_bytes()
                magic, version, count, entry = struct.unpack_from('<4Q', manifest)
                self.assertEqual((version, count), (1, 2))
                names = [struct.unpack_from('<Q32s256s', manifest, 32 + i * entry)[2].rstrip(b'\0').decode() for i in range(count)]
                self.assertEqual(names, ['\\SP11\\DISPSNAP.BIN', f'\\SP11\\{xhci.upper()}.BIN'])
                self.assertEqual((stick / 'DISPSNAP.BIN').read_bytes(), (built / 'dispsnap.bin').read_bytes())
                self.assertIn('DISPSNAP.BIN', done.stdout)
                shutil.rmtree(out, ignore_errors=True)


class Mutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()

    def test_the_sources_as_they_are_pass_everything(self):
        result = mutants.run_mutant(None, BUILD / 'mut' / 'baseline')
        for suite, (rejected, detail) in result.items():
            with self.subTest(suite=suite):
                if rejected is None:
                    self.skipTest(detail)
                self.assertFalse(rejected, f'{suite} rejects the unedited sources: {detail}')

    def test_each_mutant_names_its_reasons_and_its_needles_are_in_the_sources(self):
        names = {m[0] for m in mutants.MUTANTS}
        brief = {'display-register-clock-gate-removed', 'display-gate-removed', 'store-to-window', 'store-to-framebuffer', 'no-next-line', 'unbounded-wait',
                 'retry-after-fault', 'dead-window-ignored', 'line-overflow', 'wait-zero', 'store-through-args', 'unguarded-load'}
        self.assertLessEqual(brief, names)
        # what the two reviews of the sibling payload found missing: a wrong base for every window, a swap of two windows or roles, a load (not only a store) that is not load32,
        # a dropped NEXT line before each kind of read, the gates that fail to read, the window a read names, the cell of a window of zeros, the zero value of the verdict
        for window in ('gcc', 'dispcc', 'mdss', 'dpu'):
            self.assertIn(f'{window}-window-base-drift', names, 'a wrong base is seeded for every window')
        self.assertLessEqual({'unguarded-load', 'no-next-gcc', 'no-next-mdss', 'no-next-dpu', 'no-next-wait', 's2-without-next', 'dahb-failed-read-reported-as-off',
                              'ver-failed-read-reported-as-zero', 'all-ones-clock-decoded', 'spin-bound-too-small', 'spin-bound-removed', 'spin-token-reused',
                              'backwards-counter-ignored', 'window-range-unchecked', 'enable-clear-decoded-as-on', 'display-verdict-zero-is-on',
                              'frame-counter-read-without-enable', 'dt-from-the-wrong-reading', 'map-base-lies', 'dahb-offset-next-word', 'ahbc-offset-a16',
                              'mdpc-offset-a16', 'status-reads-avr-control'}, names)
        self.assertEqual(len(names), len(mutants.MUTANTS), 'a mutant name is used twice')
        self.assertEqual(set(mutants.REASONS), names, 'every mutant has its reasons and every reason a mutant')
        text = {f: (ROOT / 'payloads' / f).read_text(encoding='utf-8') for f in mutants.SOURCES}
        for mutant in mutants.MUTANTS:
            name, what, _, expect, capped = mutant
            with self.subTest(mutant=name):
                self.assertEqual(mutants.stale(mutant, text), [], 'a needle that is not in the sources exactly once')
                reasons = set(mutants.REASONS[name])
                for suite in expect:
                    self.assertTrue(suite in reasons or (suite == mutants.H and capped and 'harness-capped' in reasons), f'{suite} has no reason for {name}')
                for suite in reasons:
                    self.assertTrue(suite in expect or (suite == 'harness-capped' and capped), f'a reason for {suite}, which {name} does not expect to reject it')

    def test_each_mutant_is_rejected_by_the_suites_it_names_for_its_own_reason(self):
        for mutant in mutants.MUTANTS:
            name, what, _, expect, capped = mutant
            with self.subTest(mutant=name, what=what):
                try:
                    result = mutants.run_mutant(mutant, BUILD / 'mut' / name)
                finally:
                    shutil.rmtree(BUILD / 'mut' / name, ignore_errors=True)
                skipped = []
                for suite, pattern in mutants.REASONS[name].items():
                    rejected, detail = result[suite]
                    if rejected is None:
                        skipped.append(suite)
                        continue
                    self.assertTrue(rejected, f'{suite} does not reject it: {detail}')
                    self.assertRegex(detail, pattern, f'{suite} rejects it, but not for the reason it should')
                if skipped:
                    self.skipTest(f'{skipped} could not run (no pinned reference copies); the others rejected it for their reasons')


class Doc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.text = DOC.read_text(encoding='utf-8')
        cls.evidence = EVIDENCE.read_text(encoding='utf-8')
        cls.regs_text = REGS.read_text(encoding='utf-8')
        cls.rows = refs.parse_rows(cls.regs_text)
        cls.page = build_harness('page')
        cls.sibling = {name: (ROOT / 'docs' / name).read_text(encoding='utf-8') for name in ('SP11-PAYLOAD.md', 'SP11-PAYLOAD-XHCI.md')}

    def block(self, name):
        found = re.search(rf'<!-- {name} -->\n(.*?)<!-- /{name} -->', self.text, re.S)
        self.assertTrue(found, f'the document has no <!-- {name} --> block')
        return found.group(1)

    def table_rows(self, text):
        """[[cells]] of the data rows of a Markdown table in `text` (the header and the rule excluded)."""
        rows = [[cell.strip() for cell in line.strip().strip('|').split('|')] for line in text.splitlines() if line.startswith('|')]
        return rows[2:]

    def measured(self):
        done = lib.run([str(self.page), '--numbers'])
        self.assertEqual(done.returncode, 0, done.stderr)
        return {name: int(value) for name, value in (line.split() for line in done.stdout.splitlines())}

    def register_table(self):
        """{key: the raw row} of the document's register table (the one that starts `| Block | Key | Offset |`)."""
        table, in_table = {}, False
        for line in self.text.splitlines():
            if line.startswith('| Block | Key | Offset |'):
                in_table = True
                continue
            if in_table and not line.startswith('|'):
                break
            if in_table and not set(line) <= set('|- '):
                cells = line.split('|')
                key = cells[2].strip().strip('`')
                self.assertNotIn(key, table, f'{key} has two rows of the register table')
                table[key] = line
        return table

    def test_every_register_of_the_table_is_in_the_document_with_its_offset(self):
        self.assertEqual(len(self.rows), 25)
        table = self.register_table()
        for key, window, expression, dec, flags in self.rows:
            with self.subTest(key=key):
                self.assertIn(key, table, f'{key} has no row of the register table')
                offset = refs.row_offset(self.regs_text, expression)
                self.assertIn(f'`{offset:#x}`', table[key])

    def test_the_document_names_no_register_the_table_lacks(self):
        self.assertEqual(set(self.register_table()), {row[0] for row in self.rows})

    def test_the_pages_of_the_document_are_the_ones_the_host_model_prints(self):
        for block, scenario in (('page-open', 'unit'),):
            with self.subTest(page=block):
                done = lib.run([str(self.page), '--page', scenario])
                self.assertEqual(done.returncode, 0, done.stderr)
                shown = re.search(r'```\n(.*?)```', self.block(block), re.S)
                self.assertTrue(shown, f'the {block} block holds no code block')
                self.assertEqual(shown.group(1), done.stdout)

    def test_the_numbers_of_the_document_are_the_ones_the_host_model_measures(self):
        stated = {row[0].strip('`'): int(row[1]) for row in self.table_rows(self.block('numbers'))}
        self.assertEqual(stated, self.measured())

    def test_the_excerpts_of_the_document_are_lines_of_the_pages_the_host_model_prints(self):
        for block, scenario in (('cold-lines', 'cold'), ('dahboff-lines', 'dahboff'), ('s2gated-lines', 's2gated'), ('hwctl-lines', 'hwctl'), ('part-lines', 'part'),
                                ('dispccabort-lines', 'dispccabort'), ('mdssabort-lines', 'mdssabort'), ('dpuabort-lines', 'dpuabort'), ('noflc-lines', 'noflc'),
                                ('nocounter-lines', 'nocounter'), ('stalled-lines', 'stalled'), ('idle-lines', 'idle')):
            with self.subTest(excerpt=block):
                done = lib.run([str(self.page), '--scenario', scenario])
                self.assertEqual(done.returncode, 0, done.stderr)
                shown = re.search(r'```\n(.*?)```', self.block(block), re.S).group(1).splitlines()
                page = done.stdout.splitlines()
                at = -1
                for line in shown:
                    self.assertIn(line, page[at + 1:], f'{line!r} is not a later line of the page of {scenario}')
                    at = page.index(line, at + 1)

    def test_the_chain_budget_of_the_document_is_the_arithmetic_of_the_runner_and_the_two_pages(self):
        measured = self.measured()
        runner, xhci = self.sibling['SP11-PAYLOAD.md'], self.sibling['SP11-PAYLOAD-XHCI.md']
        self.assertRegex(runner, r'\| runner, once per boot: `LOADED` for each file \(payload or data\), `READY` \| files \+ 1 \|')
        self.assertRegex(runner, r'\| runner, for each payload: `VERIFY`, `CALL`, `DONE` \| 3 \|')
        panel = int(re.search(r"\| panel region, the unit's 2880 x 1920 panel \| (\d+) \|", runner).group(1))
        xhci_nominal = int(re.search(r'A nominal page is (\d+) lines', xhci).group(1))
        xhci_most = int(re.search(r'At most (\d+) lines of 100 characters per call', xhci).group(1))
        once, each = 2 + 1, 3 * 2                      # two files, two payloads
        expected = {
            'runner once': (once, once), 'runner per payload': (each, each), 'dispsnap': (measured['open_lines'], measured['line_cap']),
            'xhci': (xhci_nominal, xhci_most), 'total': (once + each + measured['open_lines'] + xhci_nominal, once + each + measured['line_cap'] + xhci_most),
            'panel': (panel, panel),
        }
        stated = {}
        labels = (('`LOADED`', 'runner once'), ('`VERIFY`', 'runner per payload'), ('`dispsnap`', 'dispsnap'), ('`xhci0`', 'xhci'), ('total', 'total'),
                  ('panel region', 'panel'))
        for row in self.table_rows(self.block('dispsnap-chain-budget')):
            label = next((name for start, name in labels if row[0].startswith(start)), row[0])
            stated[label] = (int(row[1]), int(row[2]))
        self.assertEqual(stated, expected)
        self.assertLessEqual(expected['total'][1], panel, 'the worst case of the chain fits the rows of the panel')
        self.assertGreaterEqual(panel - expected['total'][1], 6, 'and leaves six rows to spare: the line cap of dispsnap is what keeps them')

    def test_every_citation_of_the_document_is_in_the_ledger_and_every_ledger_entry_is_cited(self):
        ledger = refs.ledger_index()
        cited = set(refs.cited(self.text))
        self.assertEqual(sorted(cited - set(ledger)), [], 'a file:line the pinned-copy test has not verified')
        self.assertEqual(sorted(set(ledger) - cited), [], 'a ledger entry the document does not use')

    def test_what_could_not_be_verified_is_the_list_of_the_pinned_copy_test(self):
        section = re.search(r'\*\*What could not be verified\.\*\*(.*?)\n## ', self.text, re.S)
        self.assertTrue(section, 'the document has no "What could not be verified" paragraph')
        self.assertEqual(set(re.findall(r'\bUV\d\b', section.group(1))), set(refs.UNVERIFIED))
        self.assertEqual(set(re.findall(r'\bUV\d\b', self.text)), set(refs.UNVERIFIED), 'an unverified item outside the paragraph that lists them')

    def test_the_pinned_files_of_the_document_are_the_module_s(self):
        for name, (digest, _) in refs.PINNED.items():
            with self.subTest(file=name):
                self.assertIn(digest, self.evidence, f'the digest of {name} is not in the evidence document')
                self.assertIn(refs.LINUX_PATH[name], self.evidence)
        self.assertIn(refs.LINUX_REVISION, self.evidence)
        self.assertIn(refs.LINUX_REVISION, self.text)

    def test_the_things_the_document_must_say_plainly(self):
        paragraphs = [p for p in re.split(r'\n\s*\n', self.text) if not p.startswith(('|', '<!--', '```'))]

        def one(*needles):
            found = [p for p in paragraphs if all(n in p for n in needles)]
            self.assertTrue(found, f'no paragraph holds all of {needles}')
            return found[0]

        self.assertRegex(one('EXPERIMENTAL', 'hardware NOT RUN'), r'authorises|authorizes')
        self.assertRegex(one('framebuffer', 'scanout', 'never'), r'(?i)never (read|touch)')
        self.assertRegex(one('clear-on-read', 'AUX_DATA', 'INTR_STATUS'), r'(?i)not read')
        self.assertRegex(one('CLK_OFF', 'NOC_FSM_STATUS', 'cbc:54-58', 'cb:63-71'), r'raw')
        self.assertRegex(one('gdsc:61-91', 'dc:1512-1522', 'PWR_ON', 'HW_CTRL'), r'hardware')
        self.assertRegex(one('SError', 'synchronous'), r'neither caught nor printed')
        self.assertRegex(one('2 minutes after `END`', '10 minutes after `PAYLOAD CALL`', 'no `END`'), r'later')
        self.assertRegex(one('HZ=0X124F800', '19.2 MHz'), r'(?s)real time.*GAP_MS')
        self.assertRegex(one('never fired on the unit', 'FAULTS=', 'QEMU run has no fault'), r'first\s+real test.*`FAULT:6`')
        self.assertRegex(one('Common mode', 'one author'), r'independent reviewer')
        self.assertRegex(one('payload_emit', 'no barrier'), r'UNKNOWN')
        self.assertRegex(one('EL2 stage-1', 'MDSS', 'dispcc'), r'UNKNOWN')
        one('hi:333-335', 'hi:339', 'hi:491')
        for token in ('`FAULT:6`', '`SKIP`', '`NA`', '`BUDGET`', '`NOFLC`', '`.ON`', '`.OFF`', '`.ODD`', '`DG`', '`DISP=ON`', '`DISP=OFF`', '`DISP=HWCTL`', '`DISP=PART`', '`DISP=UNK`',
                      '`GATED BY DAHB`', '`GATED BY DAHBERR`', '`GATED BY VER`', '`GATED BY VERERR`', '`DRIFT`', '`NEXT WAIT 8 S`', '`NEXT S2', '`S2 DISPCC GATED BY', '`GCC=SAME`',
                      '`S2 SKIPPED NO_COUNTER`', '`S2 SKIPPED SPIN`', '`SKIPPED_NOT_AT_EL2`', '`REFUSED_NO_LOAD32`', '`MAP`', '`GOP`', '`DT`', '`FRB`'):
            self.assertIn(token, self.text, f'the decode of {token} is missing')
        for hazard in ('H0', 'H1', 'H2', 'H3', 'H4', 'H5'):
            self.assertIn(hazard, self.text)
        self.assertNotIn('the end line always', self.text)
        self.assertNotIn('`GATED`', self.text, 'no value is ever printed as GATED: a gated block prints one line')

    def test_the_document_chains_dispsnap_in_front_of_the_xhci_payloads_the_way_the_manifest_tool_takes_it(self):
        chain = re.search(r'\n## Chaining it in front of the xHCI payloads\n(.*?)\n## ', self.text, re.S)
        self.assertTrue(chain, 'the document has no chaining section')
        self.assertRegex(chain.group(1), r'python3 tools/sp11_payload_manifest\.py --out-dir \S+ \S*dispsnap\.bin \S*xhci[01]\.bin')
        self.assertLess(chain.group(1).index('DISPSNAP.BIN'), chain.group(1).index('XHCI0.BIN'))
        self.assertIn('manifest order', chain.group(1))

    def outcome_section(self):
        section = re.search(r'\n## What each page would mean\n(.*?)\n## ', self.text, re.S)
        self.assertTrue(section, 'the document has no outcome section')
        return section.group(1)

    def printable_tokens(self):
        """The tokens the payload can print that report something other than a plain value, taken from its sources: the reasons a block is not read, the display verdicts, the lines
        it says whole, the tokens that replace a value, and the decodes that refuse to decode; and the situations of the film that no source prints (a q1n1 fault page or a reset
        after END, recovery, what to do next)."""
        regs, source = REGS.read_text(encoding='utf-8'), SOURCE.read_text(encoding='utf-8')
        reasons = [r for r in re.findall(r'"([^"]*)"', re.search(r'reason_name\[REASONS\]\[\d+\] = \{([^}]*)\}', regs).group(1)) if r]
        verdicts = ['DISP=' + v for v in re.findall(r'"([A-Z]+)"', re.search(r'disp_name\[DX_STATES\]\[\d+\] = \{([^}]*)\}', regs).group(1)) if v != 'ON']
        said = sorted(set(re.findall(r'"((?:S2 )?(?:SKIPPED|REFUSED)[A-Z0-9_ ]*)"', source)))
        side = re.search(r'void side\(.*?\n}\n', source, re.S).group(0)
        values = re.findall(r'tx\(line, "([A-Z:]+)"\)', side)
        odd = ['.ODD', 'MAJ=ODD']
        extra = ['NEXT WAIT 8 S', 'CUTS=', 'MORE=', 'DRIFT CHANGED', 'GATED BY', 'fault page', 'reset', 'recovery', 'boot the stick again']
        tokens = reasons + verdicts + said + values + odd + extra
        self.assertEqual(sorted(reasons), sorted(['DISP=UNK', 'DISP=OFF', 'DISP=HWCTL', 'DISP=PART', 'DAHB', 'DAHBERR', 'VER', 'VERERR']) or [])
        self.assertEqual(said, sorted(['S2 SKIPPED NO_COUNTER', 'S2 SKIPPED SPIN', 'SKIPPED_NOT_AT_EL2', 'REFUSED_NO_LOAD32']))
        self.assertEqual(sorted(values), sorted(['FAULT:', 'SKIP', 'BUDGET', 'NOFLC', 'NA']), 'a value the page can print under another name: the document has to know it')
        return tokens

    @staticmethod
    def outcome_gaps(section, tokens):
        """The tokens that no row of the outcome table names: a token counts when it stands in a code span of a row (a reason as `GATED BY <it>` or alone, but not as the first letters
        of another token: DAHB is not DAHBERR), or, for the plain words, anywhere in a row."""
        rows = [line for line in section.splitlines() if line.startswith('|')]
        gaps = []
        for token in tokens:
            if token.islower():
                found = any(token in row.lower() for row in rows)
            else:
                found = any(re.search(rf'`[^`]*(?<![A-Z0-9_=]){re.escape(token)}(?![A-Z_])[^`]*`', row) for row in rows)
            if not found:
                gaps.append(token)
        return gaps

    def test_the_outcome_table_has_a_row_for_every_token_the_payload_can_print(self):
        section = self.outcome_section()
        rows = self.table_rows(section)
        self.assertGreaterEqual(len(rows), 16)
        self.assertLessEqual(len(rows), 24)
        for needle in ('ACTIVE', 'INACTIVE', 'UNKNOWN', 'INCONSISTENT', 'DISP=HWCTL', 'FAULT:6'):
            self.assertIn(needle, section)
        tokens = self.printable_tokens()
        self.assertEqual(self.outcome_gaps(section, tokens), [], 'a token the payload can print that the outcome table does not explain')

    def test_a_missing_outcome_row_is_found(self):
        # the check above must be able to fail: without a row, exactly the tokens only that row named are reported
        lines = self.outcome_section().splitlines()
        rows = [line for line in lines if line.startswith('|')][2:]
        tokens = self.printable_tokens()
        sole = 0
        for row in rows:
            rest = '\n'.join(r for r in rows if r != row)
            only = [t for t in tokens if self.outcome_gaps(row, [t]) == [] and self.outcome_gaps(rest, [t]) == [t]]
            with self.subTest(row=row[:50]):
                self.assertEqual(sorted(self.outcome_gaps(rest, tokens)), sorted(only))
            sole += bool(only)
        self.assertGreaterEqual(sole, 6, 'the rows hold too few tokens of their own: the table explains nothing a reader could not find elsewhere')

    def test_the_safety_table_names_every_seeded_bug_once(self):
        section = re.search(r'\n## Safety rules, each with the seeded bug that must be refused\n(.*?)\n## ', self.evidence, re.S)
        self.assertTrue(section)
        named = [name for row in self.table_rows(section.group(1)) for name in re.findall(r'`([a-z0-9]+(?:-[a-z0-9]+)+)`', row[2])]
        self.assertEqual(sorted(named), sorted(m[0] for m in mutants.MUTANTS))

    def test_the_tests_table_names_every_suite_and_the_number_of_seeded_bugs(self):
        done = lib.run([str(self.page)])
        suites = re.findall(r'^suite (\w+)', done.stdout, re.M)
        self.assertEqual(suites, [s for s in SUITES])
        for suite in suites:
            self.assertIn(f'`{suite}`', self.evidence, f'the suite {suite} is not named')
        self.assertIn('`spin`', self.evidence)
        self.assertIn(f'{len(mutants.MUTANTS)} seeded bugs', self.evidence)
        for command in ('tools/test-q1n1-sp11-payload-dispsnap.py', 'tools/test-q1n1-sp11-payload-dispsnap-refs.py', 'tools/test-q1n1-sp11-payload-qemu-dispsnap.py'):
            self.assertIn(f'python3 {command}', self.evidence)

    def test_the_document_carries_its_evidence_labels_and_says_nothing_ran(self):
        for needle in ('EXPERIMENTAL', 'NOT RUN', 'VERIFIED', 'OBSERVED', 'INFERRED', 'UNIMPLEMENTED', 'UNKNOWN'):
            self.assertIn(needle, self.text)
        for needle in ('EXPERIMENTAL', 'NOT RUN'):
            self.assertIn(needle, self.evidence)
        self.assertNotRegex(self.text, r'(?i)\bran on the unit\b.*dispsnap')

    def test_the_two_documents_name_each_other_and_stay_inside_the_size_limit(self):
        self.assertIn('SP11-PAYLOAD-DISPSNAP-EVIDENCE.md', self.text)
        self.assertIn('SP11-PAYLOAD-DISPSNAP.md', self.evidence)
        for path in (DOC, EVIDENCE):
            self.assertLess(path.stat().st_size, 50 * 1024, f'{path.name} is over 50 KiB')
            self.assertLess(len(path.read_text(encoding='utf-8').splitlines()), 1500)

    def test_relative_links_resolve(self):
        for text in (self.text, self.evidence):
            for target in re.findall(r'\]\((?!https?:)([^)#]+)(?:#[^)]*)?\)', text):
                self.assertTrue((DOC.parent / target).exists(), target)


if __name__ == '__main__':
    unittest.main(verbosity=2)
