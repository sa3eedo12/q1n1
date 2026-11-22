#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests of the payload write table (docs/SP11-PAYLOAD-WTAB.md): the runner's side, the table tool, the policy tooling and the seeded bugs.

    python3 tools/test-q1n1-sp11-payload-wtab.py

  TableTool     tools/sp11_wtab.py: the reference table, the layout, the reasons (the C enum's list), the generated header, the note
  Differential  the runner's refusal rules (C, tools/test-q1n1-sp11-payload-wtab.c --validate-many) against the tool's (Python, validate_blob) on thousands of
                damaged tables: the same answer for each
  Harness       the native host test (tools/test-q1n1-sp11-payload-wtab*.c: twelve suites, a fake device that faults, raises an SError, sticks, hangs and runs
                on a counter that lies, and ops that are handed pointers) under ASan and UBSan
  CompiledCode  the reference payload (tools/wtab-ref/ref-payload.c) as a payload: the IR audit, the binary audit and the `wtabref` policy say nothing against it;
                two builds are byte for byte the same; the audits refuse hand-written faulty IR
  Mutants       seeded bugs (tools/sp11_payload_wtab_mutants.py) of the payload, the table and the runner: each is refused by its own check
  DefaultOff    with the gate at zero the runner's sources preprocess to the same text as with every gated line removed; the Makefile plans the same commands
  GateOffBuild  the runner image of the base commit (derived from the history) and of this tree with the gate off are one byte string; with the gate on, one
                other, reproducible image that holds the table's lines

Writes only under build/sp11-payload-wtab/. It SKIPs, and never passes, without clang, ld.lld, make, llvm-objdump, llvm-nm, llvm-readelf and llvm-objcopy.
Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model and compiled code only)."""
import copy
import hashlib
import json
from pathlib import Path
import random
import re
import shutil
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_wtab_audit as audit  # noqa: E402
import sp11_payload_wtab_mutants as mutants  # noqa: E402
import sp11_wtab as wtab  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-wtab'
UEFI = ROOT / 'platform' / 'uefi'
HARNESS_SOURCES = tuple(ROOT / 'tools' / f'test-q1n1-sp11-payload-wtab{part}.c' for part in ('', '-rules', '-open', '-faults', '-ops'))
REF_JSON = ROOT / 'tools' / 'wtab-ref' / 'ref.json'
REF_C = ROOT / 'tools' / 'wtab-ref' / 'ref-payload.c'
RUNNER_C = UEFI / 'sp11-payload-wtab.c'
ABI_H = UEFI / 'sp11-payload-wtab-abi.h'
RUNNER_SOURCES = ('sp11-payload-run.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c')
TOOLS = ('clang', 'ld.lld', 'make', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy', 'llvm-nm')
SUITES = ('validate', 'run', 'lines', 'stops', 'undo', 'open', 'faults', 'gate', 'hang', 'finish', 'chain', 'ops')
DEFINES = ['-DQ1N1_PAYLOAD_HOST_TEST=1', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1', '-DQ1N1_SP11_WTAB=1']


def need_tools():
    for tool in TOOLS:
        if not lib.have(tool):
            raise unittest.SkipTest(f'{tool} not installed')


def ref_table(edit=None):
    source = json.loads(REF_JSON.read_text(encoding='utf-8'))
    if edit:
        edit(source)
    return wtab.Table(source)


def write_header(directory, table):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'wtab-ref-table.h').write_text(wtab.emit_c(table), encoding='utf-8')
    return directory


def build_harness(name, header_dir, runner_text=None, ref_source=None, allow_draft=False, run_text=None, extra_flags=()):
    """The host harness under ASan and UBSan; `runner_text` replaces the runner's table source (a seeded bug), `run_text` the runner loop's (sp11-payload-run.c, the ops),
    `ref_source` the reference payload, `allow_draft` builds the runner that takes a table named as a draft (the default runner, like the Makefile's, does not) and `extra_flags`
    go to the compiler."""
    out = BUILD / name
    out.mkdir(parents=True, exist_ok=True)
    runner = RUNNER_C
    if runner_text is not None:
        runner = out / 'sp11-payload-wtab.c'
        runner.write_text(runner_text, encoding='utf-8')
    loop = UEFI / 'sp11-payload-run.c'
    if run_text is not None:
        loop = out / 'sp11-payload-run.c'
        loop.write_text(run_text, encoding='utf-8')
    ref = ref_source or REF_C
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined',
             *DEFINES, f'-DREF_PAYLOAD_SOURCE="{ref}"', '-I.', f'-I{UEFI}', f'-I{ROOT / "payloads"}', f'-I{ROOT / "tools"}', f'-I{header_dir}', *extra_flags]
    if allow_draft:
        flags.append('-DQ1N1_WTAB_ALLOW_DRAFT=1')
    binary = out / 'harness'
    done = lib.run(['clang', *flags, '-o', str(binary), *map(str, HARNESS_SOURCES), str(runner), *[str(loop if s == 'sp11-payload-run.c' else UEFI / s) for s in RUNNER_SOURCES]])
    if done.returncode:
        raise RuntimeError('the host test did not build:\n' + done.stderr[-2500:])
    return binary


def run_harness(binary, *args, timeout=600):
    return subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=timeout, cwd=ROOT,
                          env=dict(lib.ENV, ASAN_OPTIONS='detect_stack_use_after_return=0:detect_leaks=0'))


def failed_checks(text):
    return set(re.findall(r'^FAIL (\S+/\S+(?: [^(]*?)?) \(', text, re.M))


class TableTool(unittest.TestCase):
    def test_the_reference_table_is_clean_and_has_the_packed_layout(self):
        table = ref_table()
        self.assertEqual(wtab.problems(table), [])
        blob = table.pack()
        self.assertEqual(len(blob), 64 + 88 * 4 + 16 * 1)
        self.assertEqual(wtab.validate_blob(blob), ('OK', None))
        self.assertEqual(table.sha256(), wtab.hashlib.sha256(blob).hexdigest())

    def test_the_reasons_are_the_c_enum_in_the_c_order(self):
        text = ABI_H.read_text(encoding='utf-8')
        block = re.search(r'#define Q1N1_WTAB_REASONS\(X\)(.*?)\nenum \{', text, re.S).group(1)
        names = re.findall(r'X\((\w+)\)', re.sub(r'/\*.*?\*/', '', block, flags=re.S))
        self.assertEqual(tuple(names), wtab.REASONS)

    def test_the_layout_constants_are_the_headers(self):
        text = ABI_H.read_text(encoding='utf-8')
        for name, value in (('Q1N1_WTAB_ROWS_MAX', wtab.ROWS_MAX), ('Q1N1_WTAB_WINDOWS_MAX', wtab.WINDOWS_MAX), ('Q1N1_WTAB_STEPS_MAX', wtab.STEPS_MAX),
                            ('Q1N1_WTAB_PAUSE_MAX_S', wtab.PAUSE_MAX_S), ('Q1N1_WTAB_POLL_MAX_US', wtab.POLL_MAX_US), ('Q1N1_WTAB_DELAY_MAX_US', wtab.DELAY_MAX_US)):
            self.assertRegex(text, rf'#define {name} {value}u')
        for assertion, size in (('sizeof(struct q1n1_wtab_header) == ', wtab.HEADER.size), ('sizeof(struct q1n1_wtab_row) == ', wtab.ROW.size),
                                ('sizeof(struct q1n1_wtab_window) == ', wtab.WINDOW.size)):
            self.assertIn(f'{assertion}{size},', text)
        runner = (UEFI / 'sp11-payload-wtab.h').read_text(encoding='utf-8')
        self.assertRegex(runner, rf'Q1N1_WTAB_LINES_MAX {wtab.LINES_MAX}u')
        self.assertRegex(runner, rf'Q1N1_WTAB_REFUSED_LINES {wtab.REFUSED_LINES}u')
        self.assertEqual(wtab.MAGIC, int.from_bytes(b'Q1N1WTB1', 'little'))
        self.assertIn('0x31425457314e3151', text)

    def test_the_files_of_the_framework_start_with_their_license_line(self):
        for path in (REF_JSON, REF_C, ABI_H, RUNNER_C, UEFI / 'sp11-payload-wtab.h', ROOT / 'payloads' / 'payload-wtab.h', ROOT / 'tools' / 'sp11_wtab.py',
                     ROOT / 'tools' / 'sp11_payload_wtab_audit.py', ROOT / 'tools' / 'sp11_payload_wtab_mutants.py', ROOT / 'tools' / 'test-q1n1-sp11-payload-wtab-fixture.h', *HARNESS_SOURCES):
            self.assertIn('SPDX-License-Identifier: MIT', path.read_text(encoding='utf-8')[:200], str(path))
        self.assertEqual(json.loads(REF_JSON.read_text(encoding='utf-8'))['spdx'], 'SPDX-License-Identifier: MIT')

    def test_the_generated_header_is_the_table_and_is_deterministic(self):
        table = ref_table()
        text = wtab.emit_c(table)
        self.assertEqual(text, wtab.emit_c(ref_table()))
        self.assertIn(table.sha256(), text)
        for i, row in enumerate(table.rows):
            self.assertIn(f'#define WROW_{wtab.c_name(row.tag)} {i}u', text)
        self.assertIn('_Static_assert(sizeof wtab_wtabref == 432', text)

    def test_the_note_names_every_row_and_the_digest_the_runner_prints(self):
        table = ref_table()
        note = wtab.render_note(table, 'REFPAYLOAD', 'ab' * 32)
        self.assertEqual(note, wtab.render_note(table, 'REFPAYLOAD', 'ab' * 32))
        self.assertIn(table.sha256(), note)
        self.assertIn(f'SHA={table.sha256()[:16].upper()}', note)
        for row in table.rows:
            self.assertIn(f'{row.addr:#010x}', note)
            self.assertIn(row.tag, note)
        self.assertIn('HANG: none', note)
        changed = wtab.render_note(ref_table(lambda t: t['rows'][2].update(value='0x1', mask='0x1', why='other')), 'REFPAYLOAD', 'ab' * 32)
        self.assertNotEqual(note, changed)

    def test_the_note_says_how_to_read_a_hang_and_names_the_four_digests_the_operator_quotes(self):
        table = ref_table()
        note = wtab.render_note(table, 'REFPAYLOAD', 'ab' * 32, 'cd' * 32)
        self.assertIn('runner          the WTAB=1 runner image  SHA-256 ' + 'cd' * 32, note)
        self.assertIn('payload         REFPAYLOAD  SHA-256 ' + 'ab' * 32, note)
        self.assertIn('the operator quotes four SHA-256 values: of this note, of the table above, of the payload and of the runner image', note)
        self.assertIn('A stop with no WTAB line after PAYLOAD CALL is in the open itself (the counter', note)
        self.assertIn("may also be in the payload's own reads between two rows and not in the next row.", note)
        self.assertIn('INFERRED, never observed on the unit: a hard power-off returns every register this table touches to its power-on state.', note)
        self.assertNotIn('skipped when they already are', note)
        self.assertIn('runner          the WTAB=1 runner image  SHA-256 (not given)', wtab.render_note(table, 'REFPAYLOAD', 'ab' * 32))
        with_reads = wtab.render_note(ref_table(lambda t: t['note'].update(reads='the table\'s own reads')), 'REFPAYLOAD', 'ab' * 32)
        self.assertIn("reads between two rows (the table's own reads) and not in the next row.", with_reads)
        shown = subprocess.run([sys.executable, '-B', str(ROOT / 'tools' / 'sp11_wtab.py'), 'note', str(REF_JSON), '--payload', 'REFPAYLOAD', '--payload-sha', 'ab' * 32,
                                '--runner-sha', 'cd' * 32], capture_output=True, text=True)
        self.assertEqual((shown.returncode, shown.stdout), (0, note), shown.stderr)

    def test_the_note_says_what_the_reviewed_bytes_carry_and_what_the_runner_refuses_for_the_payload(self):
        table = ref_table()
        note = wtab.render_note(table, 'REFPAYLOAD', 'ab' * 32, 'cd' * 32)
        self.assertIn('and puts them back and, by the reviewed bytes of the payload named above, nothing else; a hang during the change leaves it changed until a hard power-off.', note)
        self.assertIn('a stop after fewer ATTR lines than the table has rows is in the page walk of the first row that has no ATTR line yet', note)
        self.assertIn('ops.hex writes only inside the payload\'s stack and ops.puts reads only from its stack or its image', note)
        self.assertIn('"PAYLOAD OP REFUSED" line of the page', note)

    def test_the_note_tool_quotes_a_digest_only_when_it_is_one(self):
        table = ref_table()
        for bad in ('zzz', 'ab' * 4, 'ab' * 31 + 'a', 'ab' * 33, 'g' * 64, ''):
            for argument in (dict(payload_sha=bad), dict(runner_sha=bad)):
                with self.assertRaises(ValueError, msg=repr((bad, argument))):
                    wtab.render_note(table, 'REFPAYLOAD', **argument)
        self.assertEqual(wtab.render_note(table, 'REFPAYLOAD', 'AB' * 32, 'CD' * 32), wtab.render_note(table, 'REFPAYLOAD', 'ab' * 32, 'cd' * 32), 'quoted in lower case')
        shown = subprocess.run([sys.executable, '-B', str(ROOT / 'tools' / 'sp11_wtab.py'), 'note', str(REF_JSON), '--payload', 'REFPAYLOAD', '--payload-sha', 'ab' * 8],
                               capture_output=True, text=True)
        self.assertEqual((shown.returncode, shown.stdout), (1, ''))
        self.assertIn('is not a SHA-256', shown.stderr)

    def test_the_author_s_own_rules(self):
        def problems_of(edit):
            return wtab.problems(ref_table(edit))
        self.assertTrue(any('no why' in p for p in problems_of(lambda t: t['rows'][1].pop('why'))))
        self.assertTrue(any('not an evidence label' in p for p in problems_of(lambda t: t['rows'][1].update(label='SURE'))))
        self.assertTrue(any('none of the allowed blocks' in p for p in problems_of(lambda t: t['rows'][1].update(addr='0x02001000'))))
        self.assertTrue(any('same tag' in p for p in problems_of(lambda t: (t['rows'][3].update(tag='CLKA'), t['windows'][0].update(after_row=3)))))
        self.assertTrue(any('cut it' in p for p in problems_of(lambda t: (t['rows'][3].update(tag='TOOLONGTAG'), t['windows'][0].update(after_row=3)))))
        self.assertTrue(any('ROW_UNDO' in p for p in problems_of(lambda t: t['rows'][2].update(undo={'kind': 'none'}))))


class Differential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.binary = build_harness('differential', write_header(BUILD / 'ref', ref_table()))

    def corpus(self):
        rng = random.Random(20261122)
        good = ref_table().pack()

        def rows_of(count, step=0):
            """`count` copies of the table's write row CLKA, all in one step, with no window: a table at the edge of the line budget (5 rows) or past it (6)."""
            blob = bytearray(good[:64] + good[64 + 88 * 2:64 + 88 * 3] * count)
            for k in range(count):
                struct.pack_into('<H', blob, 64 + 88 * k + 64, step)
            struct.pack_into('<IIIII', blob, 12, 64 + 88 * count, count, 0, 1, 0)
            struct.pack_into('<I', blob, 24, 1)
            struct.pack_into('<I', blob, 32, 1)
            return bytes(blob)
        six, five = rows_of(6), rows_of(5)
        overlap = bytearray(good + good[-16:])
        struct.pack_into('<I', overlap, 12, len(overlap))
        struct.pack_into('<I', overlap, 20, 2)
        struct.pack_into('<I', overlap, len(good) + 0, struct.unpack_from('<I', good, len(good) - 16)[0] + 0x80)
        cases = [good, six, five, bytes(overlap)]
        for name in (b'WTABREF-DRAFT', b'-DRAFT', b'X-DRAFT-', b'WTABREF-DRAFTS', b'DRAFT'):
            named = bytearray(good)
            named[48:64] = name.ljust(16, b'\0')
            cases.append(bytes(named))
        for i in range(0, len(good) - 3, 4):
            original = struct.unpack_from('<I', good, i)[0]
            for value in (0, 1, 2, 3, 0x80000000, 0xffffffff, (original + 1) & 0xffffffff, (original - 1) & 0xffffffff, original ^ 0x80, original ^ 0x10000):
                blob = bytearray(good)
                struct.pack_into('<I', blob, i, value)
                cases.append(bytes(blob))
        for blob in (good, six[:64 + 88 * 2], five[:64 + 88 * 2]):
            for i in range(len(blob)):
                for value in (0, 0xff, blob[i] ^ 1, 0x41, 0x61):
                    damaged = bytearray(blob)
                    damaged[i] = value
                    cases.append(bytes(damaged))
        for _ in range(3000):
            damaged = bytearray(good)
            for _ in range(rng.randint(1, 4)):
                damaged[rng.randrange(len(damaged))] = rng.randrange(256)
            cases.append(bytes(damaged))
        for _ in range(300):
            cases.append(good[:rng.randrange(0, len(good))])
        for n in (0, 1, 63, 64, 65, len(good) - 1, len(good)):
            cases.append(good[:n])
        return cases

    def test_the_runner_and_the_tool_refuse_for_the_same_reason_the_same_row(self):
        cases = self.corpus()
        path = BUILD / 'differential' / 'corpus.bin'
        path.write_bytes(b''.join(struct.pack('<I', len(c)) + c for c in cases))
        done = run_harness(self.binary, '--validate-many', str(path))
        self.assertEqual(done.returncode, 0, done.stderr[-1500:])
        answers = done.stdout.split('\n')[:-1]
        self.assertEqual(len(answers), len(cases))
        different, reasons = [], set()
        for blob, answer in zip(cases, answers):
            reason, index = wtab.validate_blob(blob)
            reasons.add(reason)
            if answer != f'{reason} {-1 if index is None else index}':
                different.append((answer, reason, index, blob[:8].hex()))
        self.assertEqual(different[:5], [], f'{len(different)} of {len(cases)} differ')
        # the corpus must reach most of the table rules or it proves little
        table_rules = set(wtab.REASONS[:wtab.REASONS.index('DRAFT') + 1]) - {'OK'}
        self.assertEqual(reasons & table_rules, table_rules, sorted(table_rules - reasons))
        self.assertGreater(len(cases), 5000)


class Harness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()

    def test_every_suite_of_the_native_host_test_passes(self):
        binary = build_harness('control', write_header(BUILD / 'ref', ref_table()))
        done = run_harness(binary)
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-3000:])
        for suite in SUITES:
            self.assertRegex(done.stdout, rf'suite {suite}\s+ok')
        found = re.search(r'CHECKS (\d+) FAILS (\d+)', done.stdout)
        self.assertEqual(found.group(2), '0')
        self.assertGreater(int(found.group(1)), 340)

    def test_the_runner_built_to_take_a_draft_passes_the_same_suites(self):
        binary = build_harness('control-draft', write_header(BUILD / 'ref', ref_table()), allow_draft=True)
        done = run_harness(binary)
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-3000:])
        self.assertRegex(done.stdout, r'CHECKS \d+ FAILS 0')


class CompiledCode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.table = ref_table()
        cls.header = write_header(BUILD / 'ref', cls.table)
        cls.findings, cls.facts = audit.audit(REF_C, BUILD / 'ref-build', [f'-I{cls.header}'], approved_sha256=cls.table.sha256(),
                                              register_offset_stores=lib.POLICIES['wtabref']['register_offset_stores'])

    def test_the_reference_payload_passes_every_audit(self):
        self.assertEqual(self.findings, [])
        facts = self.facts['ir']
        self.assertEqual((facts['open_calls'], facts['row_calls'], facts['unwind_calls']), (1, 4, 1))
        self.assertEqual(facts['rows_asked'], {0: 1, 1: 1, 2: 1, 3: 1})
        self.assertEqual(self.facts['table']['rows'], 4)

    def test_the_policy_of_the_test_suite_accepts_it_too(self):
        done = lib.binary_violations(self.facts['elf'], self.facts['flat'], lib.POLICIES['wtabref'])
        self.assertEqual(done, [])
        policy = dict(lib.POLICIES['wtabref'], write_table={'table_sha256': '0' * 64})
        self.assertTrue(any(p.startswith('TABLE_SHA') for p in lib.binary_violations(self.facts['elf'], self.facts['flat'], policy)))
        no_memory = {k: v for k, v in lib.POLICIES['wtabref'].items() if k != 'read_only'}
        self.assertTrue(any('needs read_only' in p for p in lib.binary_violations(self.facts['elf'], self.facts['flat'], no_memory)))

    def test_two_builds_are_byte_for_byte_the_same(self):
        done, elf, flat = lib.build_payload(REF_C, BUILD / 'ref-build-2', extra_cflags=[f'-I{self.header}'])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(Path(flat).read_bytes(), Path(self.facts['flat']).read_bytes())

    def test_the_payload_binary_is_a_page_or_two_and_has_no_store_but_the_stack(self):
        self.assertLess(Path(self.facts['flat']).stat().st_size, 4096)
        problems, loads, stores = lib._memcheck().analyse(lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', self.facts['elf']]).stdout, ops=True)
        self.assertEqual(problems, [])
        self.assertTrue(stores and all(klass in ('S', 'C') for *_, klass in stores))


GOOD_IR = '''
@wtab_t = internal constant [4 x i8] zeroinitializer, align 8
@.str = private unnamed_addr constant [3 x i8] c"A\\00\\00", align 1
define i64 @payload_entry(ptr noundef %0) {
  %2 = alloca i32, align 4
  %3 = getelementptr inbounds nuw i8, ptr %0, i64 120
  %4 = load ptr, ptr %3, align 8
  %5 = getelementptr inbounds nuw i8, ptr %0, i64 152
  %6 = load ptr, ptr %5, align 8
  %7 = getelementptr inbounds nuw i8, ptr %6, i64 16
  %8 = load ptr, ptr %7, align 8
  %9 = getelementptr inbounds nuw i8, ptr %6, i64 24
  %10 = load ptr, ptr %9, align 8
  tail call void %4(ptr noundef nonnull @.str)
  store i32 1, ptr %2, align 4
  %11 = tail call i32 %8(ptr noundef nonnull @wtab_t)
  %12 = tail call i32 %10(i32 noundef 0)
  %13 = tail call i32 %10(i32 noundef 1)
  ret i64 0
}
'''
# A pointer moved by a computed index `%idx` that the payload hands to a helper: the helper's own store through its parameter looks like a plain store.
HANDED_INDEXED = '  %idx = add i64 1, 2\n  %p = getelementptr inbounds i8, ptr %2, i64 %idx\n  {call}\n  ret i64 0\n'
HELPER_IR = 'define internal void @poke(ptr noundef %0) {\n  store i32 1, ptr %0, align 4\n  ret void\n}\n'
FAULTY_IR = [
    ('a number made a pointer and stored through', GOOD_IR.replace('  store i32 1, ptr %2, align 4\n',
                                                                   '  %x = inttoptr i64 16809984 to ptr\n  store volatile i32 1, ptr %x, align 4\n'), {'INTTOPTR', 'STORE_INTTOPTR'}),
    ('a store through the arguments', GOOD_IR.replace('  store i32 1, ptr %2, align 4\n', '  store i32 1, ptr %0, align 4\n'), {'STORE_ARGS'}),
    ('a store through a loaded pointer', GOOD_IR.replace('  store i32 1, ptr %2, align 4\n', '  store i32 1, ptr %6, align 4\n'), {'STORE_LOADED'}),
    ('a store to a global', GOOD_IR.replace('  store i32 1, ptr %2, align 4\n', '  store i32 1, ptr @wtab_t, align 4\n'), {'STORE_GLOBAL'}),
    ('a call through a pointer that is no op', GOOD_IR.replace('  %12 = tail call i32 %10(i32 noundef 0)\n', '  %y = load ptr, ptr %2, align 8\n  %12 = tail call i32 %y(i32 noundef 0)\n'),
     {'CALL_TARGET_UNKNOWN', 'ROW_COVERAGE'}),
    ('a call through an op of another table', GOOD_IR.replace('i64 24\n  %10', 'i64 40\n  %10'), {'CALL_TARGET_UNKNOWN', 'ROW_COVERAGE'}),
    ('a libcall', GOOD_IR.replace('  ret i64 0\n', '  call void @memset(ptr %2, i32 0, i64 4)\n  ret i64 0\n'), {'CALL_UNDEFINED'}),
    ('open with the stack', GOOD_IR.replace('@wtab_t)', '%2)'), {'OPEN_ARGUMENT'}),
    ('open twice', GOOD_IR.replace('  %12 =', '  %o2 = tail call i32 %8(ptr noundef nonnull @wtab_t)\n  %12 ='), {'OPEN_COUNT'}),
    ('a row that comes from a load', GOOD_IR.replace('i32 noundef 1)', 'i32 noundef %w)').replace('  %13 =', '  %w = load i32, ptr %2, align 4\n  %13 ='),
     {'ROW_INDEX_NOT_CONSTANT', 'ROW_COVERAGE'}),
    ('a row out of range', GOOD_IR.replace('i32 noundef 1)', 'i32 noundef 9)'), {'ROW_INDEX_RANGE', 'ROW_COVERAGE'}),
    ('a row asked for twice', GOOD_IR.replace('i32 noundef 1)', 'i32 noundef 0)'), {'ROW_COVERAGE'}),
    ('a row with two arguments', GOOD_IR.replace('%10(i32 noundef 0)', '%10(i32 noundef 0, i32 noundef 1)'), {'ROW_ARITY'}),
    ('inline assembly', GOOD_IR.replace('  ret i64 0\n', '  call void asm sideeffect "nop", ""()\n  ret i64 0\n'), {'INLINE_ASM'}),
    ('a pointer to a constant handed to hex', GOOD_IR.replace('  tail call void %4(ptr noundef nonnull @.str)\n',
                                                              '  %h = getelementptr inbounds nuw i8, ptr %0, i64 128\n  %hh = load ptr, ptr %h, align 8\n  tail call i32 %hh(ptr noundef nonnull @.str)\n'),
     {'CALL_ARGUMENT_ROOT'}),
    ('a store through a select of a device literal and a stack address (a constant expression operand must not drop out of the set)',
     GOOD_IR.replace('  store i32 1, ptr %2, align 4\n', '  %c = icmp eq i64 0, 0\n  %p = select i1 %c, ptr inttoptr (i64 16809984 to ptr), ptr %2\n  store volatile i32 1, ptr %p, align 4\n'),
     {'STORE_INTTOPTR'}),
    ('a store through a phi of a stack address and a device literal',
     GOOD_IR.replace('  store i32 1, ptr %2, align 4\n', '  %p = phi ptr [ %2, %entry ], [ inttoptr (i64 16809984 to ptr), %loop ]\n  store volatile i32 1, ptr %p, align 4\n'),
     {'STORE_INTTOPTR'}),
    ('a select with an operand the audit cannot read',
     GOOD_IR.replace('  store i32 1, ptr %2, align 4\n', '  %c = icmp eq i64 0, 0\n  %p = select i1 %c, ptr %x, ptr %2\n  store volatile i32 1, ptr %p, align 4\n'), {'STORE_UNKNOWN'}),
    ('a stack store through an index that is not a literal',
     GOOD_IR.replace('  store i32 1, ptr %2, align 4\n', '  %idx = add i64 1, 2\n  %p = getelementptr inbounds i8, ptr %2, i64 %idx\n  store i32 1, ptr %p, align 4\n'), {'STORE_INDEXED'}),
    ('open of an address inside the table constant (the whole operand is compared)',
     GOOD_IR.replace('ptr noundef nonnull @wtab_t)', 'ptr noundef nonnull getelementptr inbounds (i8, ptr @wtab_t, i64 8))'), {'OPEN_ARGUMENT'}),
    ('a stack pointer moved by a computed index and handed to a function of the module, which stores through it',
     GOOD_IR.replace('  ret i64 0\n', HANDED_INDEXED.format(call='call void @poke(ptr noundef %p)')) + HELPER_IR, {'CALL_ARGUMENT_INDEXED'}),
    ('the same through a select with a literal-index pointer',
     GOOD_IR.replace('  ret i64 0\n', HANDED_INDEXED.format(call='%c = icmp eq i64 0, 0\n  %s = select i1 %c, ptr %2, ptr %p\n  call void @poke(ptr noundef %s)')) + HELPER_IR,
     {'CALL_ARGUMENT_INDEXED'}),
]


class IrAudit(unittest.TestCase):
    def test_the_clean_text_passes_and_every_faulty_text_is_refused_for_its_own_reason(self):
        found, facts = audit.ir_problems(GOOD_IR + '\n', 2, 'wtab_t')
        self.assertEqual(found, [])
        self.assertEqual(facts['rows_asked'], {0: 1, 1: 1})
        seen = {}
        for name, text, codes in FAULTY_IR:
            self.assertNotEqual(text, GOOD_IR, name)
            found, _ = audit.ir_problems(text + '\n', 2, 'wtab_t')
            self.assertTrue(codes <= audit.codes_of(found), f'{name}: wanted {sorted(codes)}, got {found}')
            seen[name] = audit.codes_of(found)
        # the first code of each seeded bug is its own: no two seeded stores, calls or indices are refused only for the same reason
        primary = [sorted(codes)[0] for _, _, codes in FAULTY_IR]
        self.assertGreaterEqual(len(set(primary)), 12)

    def test_a_phi_or_select_of_literals_is_still_a_literal_and_a_loop_variable_is_not(self):
        ir = GOOD_IR.replace('  %12 = tail call i32 %10(i32 noundef 0)\n  %13 = tail call i32 %10(i32 noundef 1)\n',
                             '  %c = icmp eq i32 0, 0\n  %s = select i1 %c, i32 0, i32 1\n  %12 = tail call i32 %10(i32 noundef %s)\n'
                             '  %13 = tail call i32 %10(i32 noundef 1)\n')
        found, facts = audit.ir_problems(ir + '\n', 2, 'wtab_t')
        self.assertEqual(sorted(audit.codes_of(found)), ['ROW_COVERAGE'])     # 0 and 1 from the select, 1 again: row 1 twice
        self.assertEqual(facts['rows_asked'], {0: 1, 1: 2})

    def test_a_pointer_moved_by_a_computed_index_is_refused_as_an_argument_of_a_function_of_the_module_and_nowhere_else(self):
        moved = GOOD_IR.replace('  ret i64 0\n', HANDED_INDEXED.format(call='call void @poke(ptr noundef %p)')) + HELPER_IR
        for name, text, indexed_ok in (
                ('the control: a literal index', moved.replace('i64 %idx', 'i64 3'), ()),
                ('an intrinsic is not a function that stores through its parameter',
                 moved.replace('call void @poke(ptr noundef %p)', 'call void @llvm.lifetime.start.p0(i64 4, ptr %p)'), ()),
                ('the stack pointer itself', moved.replace('call void @poke(ptr noundef %p)', 'call void @poke(ptr noundef %2)'), ())):
            found, _ = audit.ir_problems(text + '\n', 2, 'wtab_t', indexed_ok=indexed_ok)
            self.assertEqual(found, [], name)
        found, _ = audit.ir_problems(moved + '\n', 2, 'wtab_t')
        self.assertEqual(audit.codes_of(found), {'CALL_ARGUMENT_INDEXED'})
        found, _ = audit.ir_problems(moved + '\n', 2, 'wtab_t', indexed_ok={'payload_entry'})
        self.assertEqual(audit.codes_of(found), {'CALL_ARGUMENT_INDEXED'}, 'a function the policy names may store through an index; it may not hand the moved pointer on')

    def test_the_codes_are_documented(self):
        for _, _, codes in FAULTY_IR:
            self.assertLessEqual(codes, set(audit.CODES))
        self.assertLessEqual({'READ_NOT_GATED', 'READ_ADDRESS_NOT_CONSTANT'}, set(audit.CODES))

    def test_a_read_is_a_literal_in_a_readable_block_or_a_window_of_the_table(self):
        read = ('  %r = getelementptr inbounds nuw i8, ptr %0, i64 136\n  %rr = load ptr, ptr %r, align 8\n'
                '  %v = tail call i32 %rr(i64 noundef ADDRESS, ptr noundef nonnull %2)\n  ret i64 0\n')
        ir = GOOD_IR.replace('  ret i64 0\n', read)
        found, facts = audit.ir_problems(ir.replace('ADDRESS', '100') + '\n', 2, 'wtab_t', readable=[(0, 4096)])
        self.assertEqual((found, facts['reads']), ([], 1))
        found, _ = audit.ir_problems(ir.replace('ADDRESS', '5000') + '\n', 2, 'wtab_t', readable=[(0, 4096)])
        self.assertEqual(audit.codes_of(found), {'READ_NOT_GATED'})
        found, _ = audit.ir_problems(ir.replace('ADDRESS', '5000') + '\n', 2, 'wtab_t', readable=[(0, 4096)], windows=[(4992, 16)])
        self.assertEqual(found, [], 'a window of the table is readable once the runner opens it')
        found, _ = audit.ir_problems(ir.replace('ADDRESS', '%w').replace('  %v =', '  %w = load i64, ptr %2, align 8\n  %v =') + '\n', 2, 'wtab_t', readable=[(0, 4096)])
        self.assertEqual(audit.codes_of(found), {'READ_ADDRESS_NOT_CONSTANT'})


class Mutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.table = ref_table()
        cls.header = write_header(BUILD / 'ref', cls.table)
        cls.source = REF_C.read_text(encoding='utf-8')

    def judge(self, name, source_text, header_dir, sha):
        out = BUILD / 'payload-mutants' / re.sub(r'\W+', '-', name)[:40]
        out.mkdir(parents=True, exist_ok=True)
        path = out / 'ref-payload.c'
        path.write_text(source_text, encoding='utf-8')
        findings, facts = audit.audit(path, out / 'build', [f'-I{header_dir}'], approved_sha256=sha, register_offset_stores=lib.POLICIES['wtabref']['register_offset_stores'])
        policy_found = []
        self.without_key = []
        if 'elf' in facts:
            policy_found = lib.binary_violations(facts['elf'], facts['flat'], lib.POLICIES['wtabref'])
            self.without_key = lib.binary_violations(facts['elf'], facts['flat'], {k: v for k, v in lib.POLICIES['wtabref'].items() if k != 'register_offset_stores'})
        return findings, policy_found

    def test_the_unchanged_control_passes_through_the_same_mechanism(self):
        findings, policy = self.judge('control', self.source, self.header, self.table.sha256())
        self.assertEqual((findings, policy), ([], []))

    def test_every_seeded_payload_bug_is_refused_for_its_own_reason(self):
        primary = []
        for name, old, new, wanted, unwanted in mutants.PAYLOAD_MUTANTS:
            with self.subTest(bug=name):
                text = self.source
                if name in mutants.PAYLOAD_PREAMBLE:
                    text = mutants.apply_once(text, *mutants.PAYLOAD_PREAMBLE[name])
                text = mutants.apply_once(text, old, new)
                if name in mutants.PAYLOAD_SECOND_EDIT:
                    text = mutants.apply_once(text, *mutants.PAYLOAD_SECOND_EDIT[name])
                findings, policy = self.judge(name, text, self.header, self.table.sha256())
                got = audit.codes_of(findings)
                self.assertTrue(wanted <= got, f'wanted {sorted(wanted)}, got {sorted(got)}: {findings[:4]}')
                self.assertFalse(unwanted & got, f'{sorted(unwanted & got)} should not be among {sorted(got)}')
                self.assertTrue(findings or policy, name)
                if name in mutants.POLICY_PHRASE:
                    self.assertTrue(any(mutants.POLICY_PHRASE[name] in p for p in policy), f'the read_only policy said {policy[:3]}')
                    if name in mutants.NEEDS_KEY:
                        self.assertEqual(self.without_key, [], 'without the register_offset_stores key the binary policy passes this seed: the key is what stops it')
                primary.append(sorted(wanted)[0])
        self.assertGreaterEqual(len(set(primary)), 8, primary)

    def test_every_seeded_table_bug_is_refused_for_its_own_reason(self):
        for name, edit, wanted, unwanted in mutants.TABLE_MUTANTS:
            with self.subTest(bug=name):
                table = ref_table(edit)
                header = write_header(BUILD / 'table-mutants' / re.sub(r'\W+', '-', name)[:40], table)
                findings, _ = self.judge(name, self.source, header, self.table.sha256())
                got = audit.codes_of(findings)
                self.assertTrue(wanted <= got, f'wanted {sorted(wanted)}, got {sorted(got)}')
                self.assertFalse(unwanted & got, f'{sorted(unwanted & got)} should not be among {sorted(got)}')
        refused = [wtab.validate_blob(ref_table(edit).pack())[0] for _, edit, _, _ in mutants.TABLE_MUTANTS]
        self.assertEqual(refused, ['OK', 'ROW_UNDO', 'ROW_NO_READBACK', 'WIN_ROW_READS'])

    def test_every_seeded_runner_bug_fails_the_checks_that_name_it(self):
        text = RUNNER_C.read_text(encoding='utf-8')
        for index, (name, old, new, checks) in enumerate(mutants.RUNNER_MUTANTS):
            with self.subTest(bug=name):
                mutated = mutants.apply_once(text, old, new)
                binary = build_harness(f'runner-mutant-{index}', self.header, runner_text=mutated)
                done = run_harness(binary, timeout=900)
                self.assertNotEqual(done.returncode, 0, 'the seeded bug passed the host test')
                got = failed_checks(done.stderr)
                self.assertTrue(checks <= got, f'wanted {sorted(checks)}, failed {sorted(got)[:8]}')
        self.assertGreaterEqual(len(mutants.RUNNER_MUTANTS), 20)

    def test_every_seeded_bug_of_the_runner_loops_ops_fails_the_checks_that_name_it(self):
        text = (UEFI / 'sp11-payload-run.c').read_text(encoding='utf-8')
        for index, (name, old, new, checks) in enumerate(mutants.OPS_RUNNER_MUTANTS):
            with self.subTest(bug=name):
                binary = build_harness(f'ops-mutant-{index}', self.header, run_text=mutants.apply_once(text, old, new))
                done = run_harness(binary, timeout=900)
                self.assertNotEqual(done.returncode, 0, 'the seeded bug passed the host test')
                got = failed_checks(done.stderr)
                self.assertTrue(checks <= got, f'wanted {sorted(checks)}, failed {sorted(got)[:8]}')

    def seed_source(self, body):
        text = mutants.apply_once(self.source, *mutants.OPS_SEED_PREAMBLE)
        return mutants.apply_once(text, mutants.OPS_SEED_AFTER, mutants.OPS_SEED_AFTER + '    {\n' + mutants.SEEDED_SLOT + body + '    }\n')

    def seed_run(self, name, text, **kwargs):
        """The seeded payload compiled into the host harness (SEED_TARGET is the harness' own buffer) and run once through the real runner loop."""
        out = BUILD / 'seed-runs' / re.sub(r'\W+', '-', name)[:30]
        out.mkdir(parents=True, exist_ok=True)
        (out / 'ref-payload.c').write_text(text, encoding='utf-8')
        binary = build_harness(f'seed-run-{out.name}-{kwargs.get("tag", "real")}', self.header, ref_source=out / 'ref-payload.c', run_text=kwargs.get('run_text'),
                               extra_flags=['-DSEED_EXTERN=1', '-DSEED_TARGET=(uint64_t)(uintptr_t)seed_buffer', '-fno-sanitize=pointer-overflow'])   # the seeds wrap a pointer on purpose
        done = run_harness(binary, '--seed-run')
        self.assertEqual(done.returncode, 0, done.stderr[-1500:])
        found = re.search(r'^SEED status=(-?\d+) called=(\d+) refused=(\d+) op_lines=(\d+) leaked=(\d+) buffer=([0-9A-F]{16})$', done.stdout, re.M)
        self.assertIsNotNone(found, done.stdout[-500:])
        return dict(zip(('status', 'called', 'refused', 'op_lines', 'leaked'), map(int, found.groups()[:5])), buffer=found.group(6))

    def test_the_seeds_that_hand_an_op_a_pointer_pass_the_tools_and_are_refused_by_the_runner(self):
        """S38, S39, S40: no tool says anything (the limit the documents state), the runner refuses the pointer when the code runs and the buffer is as it was; against a runner
        without the check the same seed shows the damage."""
        text = (UEFI / 'sp11-payload-run.c').read_text(encoding='utf-8')
        untouched = '534545444C45414B'        # "SEEDLEAK"
        broken = {'hex': 0, 'puts': 1, 'load32': 5}       # the OPS_RUNNER_MUTANTS index that removes the check of the op
        for name, op, body in mutants.OPS_SEEDS:
            with self.subTest(seed=name):
                source = self.seed_source(body)
                findings, policy = self.judge(name, source, self.header, self.table.sha256())
                self.assertEqual((findings, policy), ([], []), 'a tool now sees this seed: update the documents and this pin')
                ran = self.seed_run(name, source)
                self.assertEqual((ran['status'], ran['called'], ran['refused'], ran['leaked'], ran['buffer']), (0, 1, 1, 0, untouched), ran)
                self.assertEqual(ran['op_lines'], 0 if op == 'load32' else 1, 'hex and puts say so on the page once; load32 refuses as before')
                at = broken[op]
                old, new = mutants.OPS_RUNNER_MUTANTS[at][1:3]
                damaged = self.seed_run(name, source, run_text=mutants.apply_once(text, old, new), tag='broken')
                self.assertEqual(damaged['refused'], 0, damaged)
                if op == 'hex':
                    self.assertTrue(damaged['buffer'].startswith('305831323334'), damaged)      # "0X1234"
                elif op == 'puts':
                    self.assertEqual(damaged['leaked'], 1, damaged)
                else:
                    self.assertTrue(damaged['buffer'].startswith('FFFFFFFF'), damaged)

    def test_a_seeded_text_that_is_not_there_is_an_error_not_a_pass(self):
        with self.assertRaises(ValueError):
            mutants.apply_once('abc', 'x', 'y')
        with self.assertRaises(ValueError):
            mutants.apply_once('abab', 'a', 'y')


def strip_gate(text):
    """`text` without the lines of every `#if Q1N1_SP11_WTAB` block (nesting counted); the gate's own definition and its `#error` are kept: they preprocess to nothing."""
    out, depth, stripping = [], 0, False
    for line in text.splitlines(keepends=True):
        word = line.strip()
        if stripping:
            depth += bool(re.match(r'#\s*if', word))
            depth -= bool(re.match(r'#\s*endif', word))
            if depth == 0:
                stripping = False
            continue
        if re.match(r'#\s*if\s+Q1N1_SP11_WTAB\s*$', word):
            stripping, depth = True, 1
            continue
        out.append(line)
    return ''.join(out)


class DefaultOff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()

    def preprocess(self, path, *defs):
        done = lib.run(['clang', '-E', '-P', '-std=gnu11', f'-I{UEFI}', *defs, str(path)])
        self.assertEqual(done.returncode, 0, done.stderr[-800:])
        return done.stdout

    def test_the_runner_sources_preprocess_to_the_same_text_as_with_every_gated_line_removed(self):
        out = BUILD / 'strip'
        out.mkdir(parents=True, exist_ok=True)
        names = ('sp11-payload-run.c', 'sp11-payload.h', 'main.c')
        for name in names:
            (out / name).write_text(strip_gate((UEFI / name).read_text(encoding='utf-8')), encoding='utf-8')
        defs = ('-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1')
        for name in ('sp11-payload-run.c', 'main.c'):
            with self.subTest(file=name):
                self.assertTrue(self.preprocess(UEFI / name, *defs) == self.preprocess(out / name, *defs), 'the gate changed the preprocessed text')
                self.assertTrue(self.preprocess(UEFI / name, *defs, '-DQ1N1_SP11_WTAB=0') == self.preprocess(out / name, *defs), 'WTAB=0 is not the stripped text')
        for name in names:
            self.assertIn('Q1N1_SP11_WTAB', (UEFI / name).read_text(encoding='utf-8'))
            if name != 'sp11-payload.h':     # the header only defines the gate and refuses it without the runner: both preprocess to nothing
                self.assertNotEqual((UEFI / name).read_text(encoding='utf-8'), strip_gate((UEFI / name).read_text(encoding='utf-8')), name)

    def test_the_new_files_compile_to_nothing_with_the_gate_or_the_runner_off(self):
        out = BUILD / 'off'
        out.mkdir(parents=True, exist_ok=True)
        for defs in (('-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1', '-DQ1N1_SP11_WTAB=0'), ('-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1'), ()):
            obj = out / 'wtab.o'
            done = lib.run(['clang', '-std=gnu11', '-O2', '-c', f'-I{UEFI}', *defs, str(RUNNER_C), '-o', str(obj)])
            self.assertEqual(done.returncode, 0, done.stderr[-500:])
            symbols = [s for s in lib.run(['llvm-nm', '--defined-only', str(obj)]).stdout.splitlines() if not s.endswith(' ltmp0')]    # the empty Mach-O object's section label
            self.assertEqual(symbols, [], f'{defs}: the object defines {symbols[:5]}')
        on = lib.run(['clang', '-std=gnu11', '-O2', '-c', f'-I{UEFI}', *DEFINES[1:], str(RUNNER_C), '-o', str(out / 'wtab-on.o')])
        self.assertEqual(on.returncode, 0, on.stderr[-500:])
        self.assertIn('q1n1_wtab_begin', lib.run(['llvm-nm', '--defined-only', str(out / 'wtab-on.o')]).stdout)

    def test_the_gate_without_the_runner_is_an_error(self):
        done = lib.run(['clang', '-E', '-std=gnu11', f'-I{UEFI}', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=0', '-DQ1N1_SP11_WTAB=1', str(UEFI / 'sp11-payload.h')])
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('Q1N1_SP11_WTAB=1 needs Q1N1_SP11_PAYLOAD=1', done.stderr)

    def dry_run(self, *args):
        done = lib.run(['make', '-n', '-f', 'platform/uefi/Makefile', 'SP11=1', 'SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c',
                        'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c', 'OUT=build/dryrun-gate', 'PAYLOAD=1', *args, 'payload-runner'])
        self.assertEqual(done.returncode, 0, done.stderr[-800:])
        return done.stdout

    def test_the_makefile_plans_the_same_commands_with_the_gate_at_zero_and_one_more_object_with_it_on(self):
        default = self.dry_run()
        self.assertTrue(default == self.dry_run('WTAB=0'), 'WTAB=0 plans other commands than the default')
        self.assertFalse('wtab' in default)
        on = self.dry_run('WTAB=1')
        self.assertIn('-DQ1N1_SP11_WTAB=1', on)
        self.assertIn('sp11-payload-wtab.obj', on)
        self.assertGreaterEqual(on.count('-DQ1N1_SP11_WTAB=1'), 5)
        self.assertNotIn('ALLOW_DRAFT', on, 'the runner of WTAB=1 must refuse a table named as a draft')
        self.assertNotIn('ALLOW_DRAFT', (UEFI / 'Makefile').read_text(encoding='utf-8'))

    def test_the_mapping_classification_is_the_one_the_survey_uses(self):
        main_c = re.sub(r'/\*.*?\*/', '', (UEFI / 'main.c').read_text(encoding='utf-8'), flags=re.S)
        stk = re.search(r'static int stk_attr\(void \*ctx, uint64_t phys\)\n\{\n(.*?)\n\}', main_c, re.S).group(1)
        mine = re.search(r'static int wtab_attr\(uint32_t pa\)\n\{\n(.*?)\n\}', main_c, re.S).group(1)
        mine = mine.replace('Q1N1_WTAB_ATTR_', 'STK_ATTR_').replace('live_attr(0, pa, &attr)', 'live_attr(ctx, phys, &attr)')
        self.assertEqual(re.sub(r'\s+', ' ', mine).strip(), re.sub(r'\s+', ' ', stk).strip(), 'wtab_attr must classify exactly as stk_attr does')

    def test_the_gate_adds_one_guarded_load_and_one_guarded_store_to_main_c_and_nothing_else_names_the_table(self):
        main_c = (UEFI / 'main.c').read_text(encoding='utf-8')
        code = '\n'.join(re.findall(r'^#if Q1N1_SP11_WTAB\n(.*?)^#endif', main_c, re.S | re.M))
        self.assertEqual(sorted(re.findall(r'live_guarded\(([^;]*)\);', code)), ['0, (uintptr_t)out, pa, 4', '2, pa, value, 4'],
                         'the table\'s glue is one guarded 32-bit load into the runner\'s variable and one guarded 32-bit store of a value')
        self.assertIsNone(re.search(r'volatile|memset32|memcpy64|__asm__|write32', code))
        self.assertEqual(code.count('q1n1_wtab_attach('), 1)
        for name in ('main.c', 'sp11-payload-run.c'):
            self.assertNotRegex(strip_gate((UEFI / name).read_text(encoding='utf-8')), r'(?i)wtab', f'{name} names the write table outside its gate')
        header = strip_gate((UEFI / 'sp11-payload.h').read_text(encoding='utf-8'))
        self.assertEqual([line for line in header.splitlines() if re.search(r'(?i)wtab|write table', line)],
                         [line for line in header.splitlines() if re.search(r'Q1N1_SP11_WTAB|write table', line)], 'the header names the table beyond its gate macro')
        self.assertNotIn('q1n1_wtab', header)

    def test_the_gate_without_the_runner_is_an_error_in_the_makefile(self):
        done = lib.run(['make', '-n', '-f', 'platform/uefi/Makefile', 'WTAB=1'])
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('WTAB=1 needs PAYLOAD=1', done.stderr)


def series_parent(repo=ROOT):
    """The commit this series sits on, derived and not pinned: the parent of the commit that added the runner's table source, else HEAD (the series is not committed yet).
    The gate-off runner of this tree must be that commit's runner byte for byte."""
    added = lib.run(['git', 'log', '--diff-filter=A', '--format=%H', '--', 'platform/uefi/sp11-payload-wtab.c'], cwd=repo).stdout.split()
    return f'{added[-1]}^' if added else 'HEAD'


BASE_COMMIT = series_parent()
RECIPE = ['SP11=1', 'PAYLOAD=1', 'SP11_BUILD_STAMP=A9F00F9CCBB5', 'SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c',
          'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c', 'LD=lld-link /Brepro']


class GateOffBuild(unittest.TestCase):
    """The runner as an image, built with the SP11 fixture tables: from the base commit and from this tree with the gate off (one byte string), and with the gate on."""
    @classmethod
    def setUpClass(cls):
        if not (lib.have('clang') and lib.have('lld-link') and lib.have('make')):
            raise unittest.SkipTest('clang, lld-link or make not installed')
        if lib.run(['git', 'cat-file', '-e', f'{BASE_COMMIT}^{{commit}}']).returncode != 0:
            raise unittest.SkipTest(f'git cannot name {BASE_COMMIT}')

    @staticmethod
    def base_tree():
        rev = lib.run(['git', 'rev-parse', BASE_COMMIT], cwd=ROOT).stdout.strip()
        target = BUILD / f'base-{rev[:12]}'
        if not (target / 'platform' / 'uefi' / 'main.c').exists():
            shutil.rmtree(target, ignore_errors=True)
            target.mkdir(parents=True)
            archive = subprocess.run(['git', 'archive', rev], cwd=ROOT, capture_output=True, check=True).stdout
            subprocess.run(['tar', '-x', '-C', str(target)], input=archive, check=True)
        return target

    def image(self, tree, out, *extra):
        shutil.rmtree(tree / out, ignore_errors=True)
        done = lib.run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out}', *RECIPE[:3], *extra, *RECIPE[3:], 'payload-runner'], cwd=tree)
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-1500:])
        return (tree / out / 'q1n1-payload.efi').read_bytes()

    def test_the_base_of_the_gate_off_comparison_is_derived_from_the_history_and_not_pinned(self):
        """In a scratch repository the base is HEAD until a commit adds the table source, then that commit's parent, whatever comes after."""
        repo = BUILD / 'series-parent'
        shutil.rmtree(repo, ignore_errors=True)
        repo.mkdir(parents=True)
        env = dict(lib.ENV, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.invalid', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.invalid',
                   GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null')

        def git(*args):
            done = subprocess.run(['git', *args], cwd=repo, capture_output=True, text=True, env=env)
            self.assertEqual(done.returncode, 0, done.stderr)
            return done.stdout.strip()

        def commit(path, text):
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(text, encoding='utf-8')
            git('add', '-A')
            git('commit', '-q', '-m', path)
            return git('rev-parse', 'HEAD')
        git('init', '-q')
        base = commit('base.txt', 'base\n')
        self.assertEqual(series_parent(repo), 'HEAD')
        series = commit('platform/uefi/sp11-payload-wtab.c', '/* the series */\n')
        self.assertEqual(git('rev-parse', series_parent(repo)), base)
        commit('later.txt', 'later\n')
        self.assertEqual(git('rev-parse', series_parent(repo)), base, f'a commit after {series[:7]} moved the base')

    def test_with_the_gate_off_the_runner_is_the_base_commits_runner_and_with_it_on_it_builds_to_one_image(self):
        base = self.base_tree()
        pinned = self.image(base, 'build/pinned')
        self.assertEqual(pinned, self.image(base, 'build/pinned-b'), 'the base commit\'s runner is not reproducible')
        default = self.image(ROOT, 'build/wtab-test/default')
        off = self.image(ROOT, 'build/wtab-test/off', 'WTAB=0')
        self.assertEqual(default, off)
        self.assertEqual(hashlib.sha256(off).hexdigest(), hashlib.sha256(pinned).hexdigest(), 'the gate at zero changed the runner')
        on_a = self.image(ROOT, 'build/wtab-test/on-a', 'WTAB=1')
        on_b = self.image(ROOT, 'build/wtab-test/on-b', 'WTAB=1')
        self.assertEqual(on_a, on_b, 'the runner with the gate on is not reproducible')
        self.assertNotEqual(on_a, off)
        for text in (b'WTAB OPEN', b'WTAB STOP WHY=', b'WTAB END RESULT=', b'WTAB AUTO_UNWIND', b'WTAB READ REFUSED', b'NEXT STEP'):
            self.assertIn(text, on_a)
            self.assertNotIn(text, off)


if __name__ == '__main__':
    unittest.main()
