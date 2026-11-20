#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests of the payload inputsnap (payloads/inputsnap.c, docs/SP11-PAYLOAD-INPUTSNAP.md).

    python3 tools/test-q1n1-sp11-payload-inputsnap.py
    python3 tools/test-q1n1-sp11-payload-inputsnap-refs.py     (the pinned reference copies: SKIP without them)
    python3 tools/test-q1n1-sp11-payload-qemu-inputsnap.py     (the binary behind the runner under QEMU: SKIP without QEMU and EDK2)

  Harness       the native host test (tools/test-q1n1-sp11-payload-inputsnap.c: the suites; tools/test-q1n1-sp11-payload-inputsnap-model.h: a model of the five
                windows with the harness's own list of registers, the order, NEXT and gate rules, the counter and the page; a fault at every address, hostile words,
                the gating of an engine whose clock words are not all read ON, the caps) built under ASan and UBSan at the shipped caps and with smaller line and load caps
  CompiledCode  the compiled code: the IR audit (tools/sp11_payload_inputsnap_audit.py: no number is turned into a pointer, every store's root is the payload's own
                stack) on the real source and on hand-written faulty IR, the `inputsnap` policy (registered by that module) on the linked binary (an allow-list of
                instructions and the `read_only` memory check), the stack depth, two builds that are byte for byte the same, and the manifest tool on the chain
                `inputsnap` then `xhci0`
  Mutants       seeded bugs (tools/sp11_payload_inputsnap_mutants.py): each must be rejected by the suites it names, for the reason it names; and a seeded bug of the document (its
                outcome table without the row of a token), which the document check must name
  Doc           docs/SP11-PAYLOAD-INPUTSNAP.md and its companion docs/SP11-PAYLOAD-INPUTSNAP-REGISTERS.md against the register table of the source, the host model's page and
                numbers, the ledger of citations (tools/sp11_payload_inputsnap_refs.py: every file:line a document cites is one the pinned-copy test has verified), the table of
                what Linux reads, the outcome table (a row for every string the payload can print and every token a page of the host model shows), the premise of Gate A, the
                chain budget and the list of what could not be verified

SKIPs, never passes, without clang, ld.lld, make and llvm-objdump. It writes only under build/sp11-payload-inputsnap/. Nothing here ran on hardware.
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
import sp11_payload_inputsnap_audit as audit  # noqa: E402
import sp11_payload_inputsnap_mutants as mutants  # noqa: E402
import sp11_payload_inputsnap_refs as refs  # noqa: E402
import sp11_payload_xhci_audit as xa  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-inputsnap'
HARNESS = ROOT / 'tools' / 'test-q1n1-sp11-payload-inputsnap.c'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-INPUTSNAP.md'
SOURCE = ROOT / 'payloads' / 'inputsnap.c'
REGS = ROOT / 'payloads' / 'inputsnap-regs.h'
MAKE_ARGS = ['-f', 'platform/uefi/Makefile']
TOOLS = ('clang', 'ld.lld', 'make', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy')
SUITES = ('table', 'unit', 'decode', 'gate', 'drift', 'note', 'stream', 'order', 'faults', 'faults2', 'faults3', 'wide', 'storm', 'counter', 'spin', 'el', 'budget')


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


REGDOC = ROOT / 'docs' / 'SP11-PAYLOAD-INPUTSNAP-REGISTERS.md'
# The late blocks' names as the register table writes them (the table's block ids are B_XU2 and so on).
BLOCK_NAME = {'XU2': 'X U2', 'XS10': 'X S10', 'XGIC': 'X GIC'}
# Every string of the payload that can reach the page, and the row of the document's outcome table that says what it means; None is structure that is no outcome (the prefix, the key
# line, units, the names of decoded fields, which the decoding bullets list). A string that is in neither this table nor the payload fails the test: a token cannot be added to the
# payload without a row of the table saying what it means.
LITERAL_ROWS = {
    ' ': None, ' BLK=': 'BLK', ' CMP=': 'DRIFT CHANGED', ' CUTS=': 'CUTS', ' DEFAULT': 'DEFAULT', ' FAULTS=': 'END', ' GAP=': None, ' GAP_MS=': 'END', ' LINES=': 'END',
    ' LOST=': 'DRIFT CHANGED', ' MORE=': 'MORE', ' S': None, ' SKIP ': 'S2 <window> SKIP GATED OFF', ' SKIPS=': 'END', '-': 'DU', '.HW': '.HW', '.ODD': '.ODD', '.OFF': '.OFF',
    '.ON': '.ON', '=': None, '=r': None, 'BUDGET': 'BUDGET', 'CHG:': 'GCC=CHG:<n>', 'CTS': None, 'DG': 'DG', 'DRIFT CHANGED=': 'DRIFT CHANGED', 'DRIFT NONE': 'DRIFT NONE',
    'DT': 'DT', 'DU': 'DU', 'END LOADS=': 'END', 'FAULT:': 'FAULT:6', 'GATED': 'GATED', 'GATED ERR': 'GATED ERR', 'GATED OFF': 'GATED OFF', 'GCC=': 'GCC=SAME',
    'KEY=VALUE FAULT:6=ABORT SKIP=AFTER ONE GATED=NOT READ ODD=DECODE NOT VALID': None, 'M': None, 'NA': 'NA', 'NEXT ': 'NEXT <block>', 'NEXT S2 ': 'NEXT <block>',
    'NEXT WAIT ': 'NEXT <block>', 'ODD': 'ODD', 'PAYLOAD INPUTSNAP ': None, 'PR': None, 'READ ONLY EL=2 HZ=': None, 'REFUSED_NO_LOAD32': 'REFUSED_NO_LOAD32', 'RXN': None, 'S': None,
    'S2 ': 'S2 <window> SKIP GATED OFF', 'S2 SKIPPED NO_COUNTER': 'S2 SKIPPED NO_COUNTER', 'S2 SKIPPED SPIN': 'S2 SKIPPED SPIN', 'SAME': 'GCC=SAME', 'SKIP': 'SKIP',
    'SKIPPED_NOT_AT_EL2': 'SKIPPED_NOT_AT_EL2', 'TXN': None, 'inputsnap-regs.h': None, 'mrs %0, ': None, 'payload-util.h': None,
    'inputsnap: block and window numbers agree': None, 'inputsnap: the loads of both snapshots and of the late blocks fit the load cap': None,
    'inputsnap: the shortest page fits the line cap': None,
}
# What a run can end in that is no string of the payload, and the one reading the document builds on: rows of the table too. The second row is the text that `S2 `, ` SKIP ` and
# `GATED ERR` make together: its sibling `S2 <window> SKIP GATED OFF` is the one the strings map to.
RUN_OUTCOMES = ('no END line', 'q1n1 fault page', 'recovery', 'Gate A', 'S2 <window> SKIP GATED ERR')
# How the tokens of a page are recognised: (a regular expression over a line of the page without its prefix, the row of the outcome table).
PAGE_TOKENS = (
    (r'\.ON\b', '.ON'), (r'\.OFF\b', '.OFF'), (r'\.HW\b', '.HW'), (r'\.ODD\b', '.ODD'), (r'=FAULT:\d+', 'FAULT:6'), (r'[=-]SKIP\b', 'SKIP'),
    (r'^(?:X )?\w+ GATED OFF$', 'GATED OFF'), (r'^(?:X )?\w+ GATED ERR$', 'GATED ERR'), (r'^S2 \w+ SKIP GATED OFF', 'S2 <window> SKIP GATED OFF'),
    (r'^S2 \w+ SKIP GATED ERR', 'S2 <window> SKIP GATED ERR'), (r'-GATED\b', 'GATED'), (r'=ODD\b', 'ODD'), (r'=BUDGET\b', 'BUDGET'), (r'=NA\b', 'NA'), (r'CUTS=[1-9]', 'CUTS'),
    (r' MORE=', 'MORE'), (r'^DRIFT NONE ', 'DRIFT NONE'), (r'^DRIFT CHANGED=', 'DRIFT CHANGED'), (r'GCC=SAME', 'GCC=SAME'), (r'GCC=CHG:\d+', 'GCC=CHG:<n>'), (r'^DU ', 'DU'),
    (r'^DT ', 'DT'), (r'^DG ', 'DG'), (r'^S2 SKIPPED NO_COUNTER$', 'S2 SKIPPED NO_COUNTER'), (r'^S2 SKIPPED SPIN$', 'S2 SKIPPED SPIN'), (r' BLK=', 'BLK'),
    (r'HZ=\S+ DEFAULT\b', 'DEFAULT'), (r'^SKIPPED_NOT_AT_EL2$', 'SKIPPED_NOT_AT_EL2'), (r'^REFUSED_NO_LOAD32$', 'REFUSED_NO_LOAD32'), (r'^NEXT ', 'NEXT <block>'),
    (r'^END LOADS=', 'END'),
)
# The scenarios the host test prints a page for (`--scenario`); `slow` needs the build with the smaller wait bound and BUDGET the one with the smaller load cap.
SCENARIOS = ('unit', 'wide', 'wideflip', 'flip', 'rx', 'three', 'twogroups', 'gated', 'u2gated', 'u2err', 's2gated', 's2err', 'u2abort', 'xabort', 'gccabort', 's2abort', 'odd',
             'nocounter', 'stuck', 'back', 'hzdefault', 'el1', 'noload32')


def source_literals():
    """The string literals of the payload's code (comments left out)."""
    code = re.sub(r'/\*.*?\*/', '', SOURCE.read_text(encoding='utf-8'), flags=re.S)
    return set(re.findall(r'"((?:[^"\\\n]|\\.)*)"', code))


def required_rows():
    """The rows the outcome table must have: one for every string of the payload that means something, and the outcomes of a run."""
    return sorted({row for row in LITERAL_ROWS.values() if row} | set(RUN_OUTCOMES))


def outcome_rows(text):
    """{token: the cells of its row} of the outcome table of a document (the table that starts `| Token | What it says |`): the first cell of a row holds its tokens in backticks."""
    found, in_table = {}, False
    for line in text.splitlines():
        if line.startswith('| Token | What it says |'):
            in_table = True
            continue
        if in_table and not line.startswith('|'):
            break
        if in_table and not set(line) <= set('|- '):
            cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
            for token in re.findall(r'`([^`]+)`', cells[0]):
                found[token] = cells
    return found


def outcome_missing(text, wanted):
    """The tokens of `wanted` that no row of the outcome table of `text` has."""
    have = outcome_rows(text)
    return sorted(token for token in wanted if token not in have)


class Harness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()

    def run_harness(self, binary):
        done = lib.run([str(binary)], timeout=900)
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-3000:])
        found = re.search(r'CHECKS (\d+) FAILS (\d+) MAXLINES (\d+) MAXLOADS (\d+) LINE_CAP (\d+) LOAD_CAP (\d+)', done.stdout)
        self.assertTrue(found, done.stdout)
        self.assertEqual(found.group(2), '0')
        return done.stdout, [int(x) for x in found.groups()]

    def test_shipped_caps(self):
        out, (checks, fails, max_lines, max_loads, line_cap, load_cap) = self.run_harness(build_harness('shipped'))
        for suite in SUITES:
            self.assertRegex(out, rf'suite {suite}\s+ok')
        self.assertEqual((line_cap, load_cap), (34, 400))
        self.assertLessEqual(max_lines, 34)
        self.assertEqual(max_loads, 86 + 19 + 27, 'the loads of both snapshots and of the late blocks when every row is read, inside the cap the payload asserts')
        self.assertGreater(checks, 3000)

    def test_smaller_caps(self):
        for name, defs, line_cap, load_cap in (('lines20', ('-DINPUTSNAP_LINE_CAP=20u',), 20, 400), ('lines12', ('-DINPUTSNAP_LINE_CAP=12u',), 12, 400),
                                               ('lines6', ('-DINPUTSNAP_LINE_CAP=6u',), 6, 400), ('loads60', ('-DINPUTSNAP_LOAD_CAP=60u',), 34, 60),
                                               ('both', ('-DINPUTSNAP_LOAD_CAP=30u', '-DINPUTSNAP_LINE_CAP=26u'), 26, 30)):
            with self.subTest(caps=name):
                out, numbers = self.run_harness(build_harness(name, *defs))
                self.assertRegex(out, r'suite caps\s+ok')
                self.assertEqual((numbers[4], numbers[5]), (line_cap, load_cap))
                self.assertLessEqual(numbers[2], line_cap)
                self.assertLessEqual(numbers[3], load_cap)

    def test_a_smaller_spin_bound_ends_a_slow_wait_as_SPIN_and_not_as_a_dead_counter(self):
        # The shipped bound is 2^32 - 1 reads of the counter. With 4 million (more than the 2 million identical reads of a dead counter, fewer than the 8 million a counter that
        # advances once per read at 1 MHz needs) the same slow counter reaches the bound and the page says SPIN, while a stuck or backwards counter is still NO_COUNTER.
        out, numbers = self.run_harness(build_harness('spin', '-DINPUTSNAP_SPIN_MAX=4000000u'))
        self.assertRegex(out, r'suite spin\s+ok')
        self.assertEqual((numbers[4], numbers[5]), (34, 400))


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
        cls.elf, cls.flat = BUILD / 'a' / 'payloads' / 'inputsnap.elf', BUILD / 'a' / 'payloads' / 'inputsnap.bin'

    def test_two_builds_are_the_same_bytes(self):
        a, b = BUILD / 'a' / 'payloads', BUILD / 'b' / 'payloads'
        names = sorted(p.name for p in a.glob('*.bin'))
        self.assertIn('inputsnap.bin', names)
        for name in names:
            with self.subTest(payload=name):
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes())

    def test_it_is_within_what_the_policy_declares(self):
        policy = lib.POLICIES['inputsnap']
        self.assertLessEqual(self.flat.stat().st_size, policy['bytes'])
        self.assertEqual(policy['registers'], {'currentel', 'cntfrq_el0'})
        self.assertEqual(policy['smc'], 0)
        self.assertTrue(policy['read_only'])
        self.assertGreaterEqual(policy['forbid'], {'isb', 'dsb', 'dmb', 'sb'})

    def test_the_binary_holds_only_what_the_policy_allows(self):
        # MRS of CurrentEL and CNTFRQ_EL0, no SMC, no barrier, no system instruction, and every store through the payload's own stack and every load through the
        # stack, its image, the arguments or a pointer they hold (tools/sp11_payload_memcheck.py proves it from the disassembly).
        self.assertEqual(lib.binary_violations(self.elf, self.flat, lib.POLICIES['inputsnap'], 'llvm-readelf'), [])

    def test_the_policy_refuses_the_other_payloads(self):
        for other in ('state', 'usbsmmu', 'psci', 'timer'):
            with self.subTest(binary=other):
                problems = lib.binary_violations(BUILD / 'a' / 'payloads' / f'{other}.elf', BUILD / 'a' / 'payloads' / f'{other}.bin',
                                                 lib.POLICIES['inputsnap'], 'llvm-readelf')
                self.assertTrue(problems)

    def test_the_ir_audit_passes_the_source(self):
        problems, counts = audit.provenance(audit.build_ir(SOURCE, BUILD / 'ir'))
        self.assertEqual(problems, [])
        self.assertGreater(counts['stores'], 50)
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
        self.assertGreater(sizes['payload_entry'], 3000, 'the context (two snapshots) is in the entry frame')

    def test_the_stick_name_is_inputsnp_because_the_runners_names_are_8_3(self):
        # `inputsnap.bin` has a nine-letter stem: the manifest tool refuses it (the runner's stick names are 8.3, so that no FAT long-name alias is in question), and the
        # copy that goes on the stick is `inputsnp.bin`, the same bytes. The payload, its page prefix and its document keep the name `inputsnap`.
        done = lib.run(['python3', '-B', str(ROOT / 'tools' / 'sp11_payload_manifest.py'), '--out-dir', str((BUILD / 'stick-refused').relative_to(ROOT)),
                        str(self.flat.relative_to(ROOT))])
        self.assertEqual(done.returncode, 1)
        self.assertIn('cannot be a stick name', done.stderr)
        self.assertFalse((BUILD / 'stick-refused').exists(), 'a refused name writes nothing')

    def test_the_manifest_tool_takes_inputsnp_in_front_of_either_xhci_payload_in_that_order(self):
        # The chain of the document: the runner calls the files in manifest order, so inputsnap (read-only) comes first and the payload that writes last.
        built = BUILD / 'a' / 'payloads'
        named = BUILD / 'named'
        shutil.rmtree(named, ignore_errors=True)
        named.mkdir(parents=True)
        shutil.copyfile(built / 'inputsnap.bin', named / 'inputsnp.bin')
        for xhci in ('xhci0', 'xhci1'):
            with self.subTest(second=xhci):
                out = BUILD / f'stick-{xhci}'
                shutil.rmtree(out, ignore_errors=True)
                done = lib.run(['python3', '-B', str(ROOT / 'tools' / 'sp11_payload_manifest.py'), '--out-dir', str(out.relative_to(ROOT)),
                                str((named / 'inputsnp.bin').relative_to(ROOT)), str((built / f'{xhci}.bin').relative_to(ROOT))])
                self.assertEqual(done.returncode, 0, done.stderr)
                stick = out / 'SP11'
                self.assertEqual(sorted(p.name for p in stick.iterdir()), ['INPUTSNP.BIN', 'PAYLOAD.MAN', f'{xhci.upper()}.BIN'])
                manifest = (stick / 'PAYLOAD.MAN').read_bytes()
                magic, version, count, entry = struct.unpack_from('<4Q', manifest)
                self.assertEqual((version, count), (1, 2))
                names = [struct.unpack_from('<Q32s256s', manifest, 32 + i * entry)[2].rstrip(b'\0').decode() for i in range(count)]
                self.assertEqual(names, ['\\SP11\\INPUTSNP.BIN', f'\\SP11\\{xhci.upper()}.BIN'])
                self.assertEqual((stick / 'INPUTSNP.BIN').read_bytes(), (built / 'inputsnap.bin').read_bytes())
                self.assertIn('INPUTSNP.BIN', done.stdout)
                shutil.rmtree(out, ignore_errors=True)
        shutil.rmtree(named, ignore_errors=True)


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

    def test_there_are_the_twenty_the_brief_names_and_each_names_its_reasons(self):
        names = {m[0] for m in mutants.MUTANTS}
        brief = {'store-to-window', 'fifo-window-read', 'no-next-line', 'retry-after-fault', 'dead-window-ignored', 'gate-removed', 'gate-fails-open',
                 'tlmm-before-gcc', 'wait-zero', 'store-through-args', 'line-overflow', 'cbcr-polarity'}
        self.assertLessEqual(brief, names)
        self.assertGreaterEqual(len(names), 20)
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

    def test_a_document_without_the_row_of_a_token_is_refused_for_that_token_and_no_other(self):
        text = DOC.read_text(encoding='utf-8')
        self.assertEqual(outcome_missing(text, required_rows()), [], 'the document as it is has every row')
        for name, what, token in mutants.DOC_MUTANTS:
            with self.subTest(mutant=name, what=what):
                rows = [line for line in text.splitlines() if line.startswith(f'| `{token}`')]
                self.assertEqual(len(rows), 1, 'the row to take out is there once')
                mutated = text.replace(rows[0] + '\n', '')
                self.assertNotEqual(mutated, text)
                self.assertEqual(outcome_missing(mutated, required_rows()), [token])


class Doc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.text = DOC.read_text(encoding='utf-8')
        cls.regtext = REGDOC.read_text(encoding='utf-8')
        cls.alltext = cls.text + '\n' + cls.regtext
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
        """{(block, key): the raw row} of the register table of the companion document (the one that starts `| Block | Key | Offset |`)."""
        table, in_table = {}, False
        for line in self.regtext.splitlines():
            if line.startswith('| Block | Key | Offset |'):
                in_table = True
                continue
            if in_table and not line.startswith('|'):
                break
            if in_table and not set(line) <= set('|- '):
                cells = [c.strip() for c in line.strip().strip('|').split('|')]
                for block in cells[0].split('/'):
                    name = (block, cells[1].strip('`'))
                    self.assertNotIn(name, table, f'{name} has two rows of the register table')
                    table[name] = line
        return table

    def test_every_register_of_the_table_is_in_the_document_with_its_offset(self):
        self.assertEqual(len(self.rows), 110)
        table = self.register_table()
        for row in self.rows:
            name = (BLOCK_NAME.get(row['block'][2:], row['block'][2:]), row['key'])
            with self.subTest(block=name[0], key=name[1]):
                self.assertIn(name, table, f'{name} has no row of the register table')
                self.assertIn(f'`0x{row["off"]:x}`', table[name].replace(' ', ''), f'the row of {name} does not give its offset')

    def test_the_document_names_no_register_the_table_lacks(self):
        self.assertEqual(set(self.register_table()), {(BLOCK_NAME.get(row['block'][2:], row['block'][2:]), row['key']) for row in self.rows})

    def test_the_page_of_the_document_is_the_one_the_host_model_prints(self):
        done = lib.run([str(self.page), '--page'])
        self.assertEqual(done.returncode, 0, done.stderr)
        shown = re.search(r'```\n(.*?)```', self.block('page'), re.S)
        self.assertTrue(shown, 'the page block holds no code block')
        self.assertEqual(shown.group(1), done.stdout)

    def test_the_numbers_of_the_document_are_the_ones_the_host_model_measures(self):
        stated = {row[0].strip('`'): int(row[1]) for row in self.table_rows(self.block('numbers'))}
        self.assertEqual(stated, self.measured())

    def test_the_excerpts_of_the_document_are_lines_of_the_pages_the_host_model_prints(self):
        for block, scenario in (('gated-lines', 'gated'), ('s2gated-lines', 's2gated'), ('abort-lines', 'u2abort'), ('drift-lines', 'three')):
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
            'runner once': (once, once), 'runner per payload': (each, each), 'inputsnap': (measured['unit_lines'], measured['line_cap']),
            'xhci': (xhci_nominal, xhci_most), 'total': (once + each + measured['unit_lines'] + xhci_nominal, once + each + measured['line_cap'] + xhci_most),
            'panel': (panel, panel),
        }
        stated = {}
        labels = (('`LOADED`', 'runner once'), ('`VERIFY`', 'runner per payload'), ('`inputsnap`', 'inputsnap'), ('`xhci0`', 'xhci'), ('total', 'total'),
                  ('panel region', 'panel'))
        for row in self.table_rows(self.block('inputsnap-chain-budget')):
            label = next((name for start, name in labels if row[0].startswith(start)), row[0])
            stated[label] = (int(row[1]), int(row[2]))
        self.assertEqual(stated, expected)
        self.assertLessEqual(expected['total'][1], panel, 'the worst case of the chain fits the rows of the panel')
        self.assertGreaterEqual(panel - expected['total'][1], 6, 'and leaves six rows to spare: the line cap of inputsnap is what keeps them')

    def test_every_citation_of_the_document_is_in_the_ledger_and_every_ledger_entry_is_cited(self):
        ledger = refs.ledger_index()
        cited = set(refs.cited(self.alltext))
        self.assertEqual(sorted(cited - set(ledger)), [], 'a file:line the pinned-copy test has not verified')
        self.assertEqual(sorted(set(ledger) - cited), [], 'a ledger entry the documents do not use')

    def test_each_register_row_cites_the_lines_that_name_its_offset(self):
        table = self.register_table()
        index = refs.ledger_index()
        wanted = {'B_GCC': ('gcc',), 'B_GIC': ('gic', 'gicc', 'gic3'), 'B_U2': ('gse', 'gser'), 'B_S10': ('gse',), 'B_TLMM': ('pin',), 'B_XU2': ('gse', 'gser'),
                  'B_XS10': ('gse',), 'B_XGIC': ('gic', 'gicc', 'gic3')}
        for row in self.rows:
            cited = [entry for entry in refs.cited(table[(BLOCK_NAME.get(row['block'][2:], row['block'][2:]), row['key'])]) if entry[0] in wanted[row['block']]]
            with self.subTest(block=row['block'], key=row['key']):
                self.assertTrue(cited, 'the row cites no line of the file that names its register')
                if row['block'] == 'B_GCC' and row['key'].startswith('VT'):
                    self.assertTrue(any(re.search(rf'enable_reg = 0x{row["off"]:x}', index[entry]) for entry in cited), 'a vote word is named by an enable_reg line')
                elif row['block'] == 'B_GCC':
                    self.assertTrue(any(re.search(rf'halt_reg = 0x{row["off"]:x}', index[entry]) for entry in cited), 'a clock word is named by its halt_reg line')
                elif row['block'] in ('B_U2', 'B_S10', 'B_XU2', 'B_XS10'):
                    self.assertTrue(any(re.search(rf'\b0x{row["off"]:x}\b', index[entry]) for entry in cited), f'no cited line names 0x{row["off"]:x}')

    def reads_table(self):
        """[(tokens, reads, cells)] of the table of what Linux reads in the companion document: `reads` is True for `yes`, False for `**no**`."""
        found, in_table = [], False
        for line in self.regtext.splitlines():
            if line.startswith('| Words | Linux reads them |'):
                in_table = True
                continue
            if in_table and not line.startswith('|'):
                break
            if in_table and not set(line) <= set('|- '):
                cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
                self.assertTrue(cells[1].startswith(('yes', '**no**')), cells)
                found.append((re.findall(r'`([^`]+)`', cells[0]), cells[1].startswith('yes'), cells))
        return found

    def test_the_table_of_what_linux_reads_agrees_with_the_register_table_and_cites_what_the_ledger_pins_for_each_word(self):
        def covers(token, key):
            return re.fullmatch(re.escape(token[:-3]) + r'\d+', key) if token.endswith('<n>') else token == key

        table = self.reads_table()
        fresh = {row['key'] for row in self.rows if 'F_FRESH' in row['flags']}
        plain = {row['key'] for row in self.rows if 'F_FRESH' not in row['flags']}
        self.assertEqual(fresh & plain, set(), 'a key is in a late block and not in one')
        self.assertEqual(len(fresh), 19, 'the 24 words of the late blocks are 19 keys (CM CS CK CC DIF are in two engines)')
        for tokens, reads, cells in table:
            for token in tokens:
                self.assertTrue(any(covers(token, row['key']) for row in self.rows), f'{token} names no register of the table')
        for row in self.rows:
            key = row['key']
            with self.subTest(block=row['block'], key=key):
                hit = [(reads, cells) for tokens, reads, cells in table if any(covers(token, key) for token in tokens)]
                wanted_reads = key in plain
                self.assertTrue(any(reads == wanted_reads for reads, _ in hit), f'no row says that Linux {"reads" if wanted_reads else "does not read"} {key}')
                self.assertTrue(all(reads == wanted_reads for reads, _ in hit), f'a row contradicts the others about {key}')
                cited = set(refs.cited(' '.join(cells[2] for reads, cells in hit)))
                if wanted_reads:
                    self.assertTrue(refs.reads_for(row['block'], key), f'the ledger pins no read of {key}')
                    self.assertLessEqual(set(refs.reads_for(row['block'], key)), cited)
                else:
                    self.assertEqual(refs.reads_for(row['block'], key), [])
                    self.assertLessEqual(set(refs.never_read(row['block'], key)[1]), cited)

    def test_what_could_not_be_verified_is_the_list_of_the_pinned_copy_test(self):
        section = re.search(r'\*\*What could not be verified\.\*\*(.*?)\Z', self.text, re.S)
        self.assertTrue(section, 'the document has no "What could not be verified" paragraph')
        self.assertEqual(set(re.findall(r'\bUV\d\b', section.group(1))), set(refs.UNVERIFIED))
        self.assertEqual(set(re.findall(r'\bUV\d\b', self.alltext)), set(refs.UNVERIFIED), 'an unverified item outside the paragraph that lists them')

    def test_the_fetch_commands_and_digests_of_the_document_are_the_ones_the_ledger_pins(self):
        for name, (path, digest) in refs.FETCHED.items():
            with self.subTest(file=name):
                self.assertIn(digest, self.regtext)
                self.assertIn(f'{refs.LINUX_REVISION}/{path}', self.regtext)
        for name, digest in {**refs.PINNED, **refs.UNPINNED}.items():
            self.assertIn(digest[:8], self.regtext, f'{name} is not named with its digest')

    def test_the_things_the_document_must_say_plainly(self):
        paragraphs = [p for p in re.split(r'\n\s*\n', self.alltext) if not p.startswith(('|', '<!--', '```'))]

        def one(*needles):
            found = [p for p in paragraphs if all(n in p for n in needles)]
            self.assertTrue(found, f'no paragraph holds all of {needles}')
            return found[0]

        self.assertRegex(one('CLK_OFF', 'HW_CTL', 'hwcg', 'cbc:17-26', 'cbc:54-57', 'cbc:72'), r'(?s)four AHB clocks')
        self.assertRegex(one('GATED ERR', 'GATED OFF', 'fails closed', 'abort'), r'(?s)unknown clock is not read through.*failed read is not reported as the clock it gates')
        self.assertRegex(one('IFD', 'DMA', 'ODD', 'CTS', 'gser:1237-1241'), r'(?s)only when `IFD` bit 0 and `DMA` bit 0 are both 0.*only when `PR` is 2')
        self.assertRegex(one('SError', 'synchronous'), r'neither caught nor printed')
        self.assertRegex(one('FIFO', '0x700', '0x780', 'gse:113-114'), r'never')
        self.assertRegex(one('GICD_CTLR', '0x10', 'UV3'), r'OBSERVED')
        self.assertRegex(one('DIFF', 'drift'), r'interpretation')
        self.assertRegex(one('gpio44', 'den:1198-1199'), r'never read')
        self.assertRegex(one('UV4', 'TLMM', 'never read on the unit'), r'FAULT:6')
        self.assertRegex(one('PAYLOAD CALL', '62 s', 'at least 2 minutes'), r'later')
        self.assertRegex(one('HZ=0X124F800', '19.2 MHz'), r'(?s)real time.*GAP_MS')
        self.assertRegex(one('Gate A', 'PR=2', 'IFD=0', 'DMA=0', 'premise'), r'(?s)GATED OFF')
        self.assertRegex(one('run A', 'run B', 'Type Cover', 'AC power'), r'(?s)authoris')
        self.assertRegex(one('Type Cover', '2026-11-18 00:32', 'premise of Gate A'), r'(?s)OBSERVED as a report.*no photo.*UNKNOWN.*does not show that the state\s+survives ExitBootServices')
        self.assertRegex(one('24 words no pinned driver reads', 'late blocks', 'F_BREAK'), r'(?s)first load of every block is a word Linux reads.*exception')
        one('EXPERIMENTAL', 'hardware NOT RUN')
        one('clk-branch.c', refs.UNPINNED['clk-branch.c'][:8])
        for hazard in ('H0', 'H1', 'H2', 'H3', 'H4', 'H5'):
            self.assertIn(hazard, self.text)
        for token in ('`PR`', '`TXN`', '`RXN`', '`CTS`', '`DG`', '`DU`', '`DT`', '`E240`', '`C616`', '`R834`', '`NEXT WAIT 8 S`', '`NEXT S2 <window>`', '`DRIFT`', '`GCC=SAME`',
                      '`S2 SKIPPED NO_COUNTER`', '`S2 SKIPPED SPIN`'):
            self.assertIn(token, self.text, f'the decode of {token} is missing')
        self.assertNotIn('the end line always', self.text)

    def test_every_token_the_payload_can_print_has_a_row_in_the_outcome_table(self):
        literals = source_literals()
        self.assertEqual(sorted(literals - set(LITERAL_ROWS)), [], 'the payload prints a string the outcome check does not know: say what it means in a row of the table and list it')
        self.assertEqual(sorted(set(LITERAL_ROWS) - literals), [], 'a string the outcome check lists is not in the payload any more')
        self.assertEqual(outcome_missing(self.text, required_rows()), [], 'a token with no row in the outcome table')

    def test_the_tokens_of_every_page_the_host_model_prints_have_a_row_in_the_outcome_table(self):
        spin = build_harness('page-spin', '-DINPUTSNAP_SPIN_MAX=4000000u', sanitize=False)
        loads = build_harness('page-loads', '-DINPUTSNAP_LOAD_CAP=60u', sanitize=False)
        seen = set()
        for binary, scenario in [(self.page, name) for name in SCENARIOS] + [(spin, 'slow'), (loads, 'unit')]:
            done = lib.run([str(binary), '--scenario', scenario])
            self.assertEqual(done.returncode, 0, done.stderr)
            for line in done.stdout.splitlines():
                line = line[len('PAYLOAD INPUTSNAP '):] if line.startswith('PAYLOAD INPUTSNAP ') else line
                seen |= {row for pattern, row in PAGE_TOKENS if re.search(pattern, line)}
        for expected in ('.ON', '.OFF', '.HW', '.ODD', 'FAULT:6', 'SKIP', 'GATED OFF', 'GATED ERR', 'S2 <window> SKIP GATED OFF', 'S2 <window> SKIP GATED ERR', 'ODD', 'BUDGET', 'CUTS', 'MORE',
                         'DRIFT NONE', 'DRIFT CHANGED', 'GCC=SAME', 'GCC=CHG:<n>', 'DU', 'DT', 'DG', 'S2 SKIPPED NO_COUNTER', 'S2 SKIPPED SPIN', 'BLK', 'DEFAULT', 'SKIPPED_NOT_AT_EL2',
                         'REFUSED_NO_LOAD32', 'NEXT <block>', 'END'):
            self.assertIn(expected, seen, f'no scenario of the host model prints {expected}: the table would describe a token nothing shows')
        self.assertLessEqual(seen, set(required_rows()))
        self.assertEqual(outcome_missing(self.text, seen), [])

    def test_the_outcome_table_says_what_a_run_can_end_in(self):
        rows = outcome_rows(self.text)
        self.assertIn('2^32 - 1', rows['S2 SKIPPED SPIN'][1])
        self.assertIn('stands still for 2 million reads', rows['S2 SKIPPED NO_COUNTER'][1])
        self.assertIn('never called `OFF`', rows['GATED ERR'][1])
        self.assertIn('stop', rows['FAULT:6'][1] + rows['GATED OFF'][2])
        self.assertIn('later word', rows['FAULT:6'][2])
        self.assertIn('unreachable in the shipped build', rows['BUDGET'][2])
        self.assertIn('the payload wrote nothing', rows['recovery'][1])
        self.assertIn('boot the stick again', rows['recovery'][2])
        self.assertIn('after the `END` line', rows['q1n1 fault page'][1])
        self.assertIn('INFERRED', rows['q1n1 fault page'][1])

    def test_the_premise_of_gate_a_is_the_operators_report_with_its_label_and_what_it_does_not_show(self):
        row = outcome_rows(self.text)['Gate A']
        what = row[1]
        for needle in ('Premise, OBSERVED', "the operator's own report", 'one unit', '2026-11-18 00:32', 'no photo', 'not a measurement of this payload',
                       'Type Cover keyboard types in the Surface UEFI', 'shell or setup menu not stated', 'touch and pen not reported: UNKNOWN', 'INFERRED from it',
                       'not permanently off', 'UNKNOWN: that any of it survives ExitBootServices and the bounce', 'that is what the page reads'):
            self.assertIn(needle, what)
        self.assertNotRegex(what, r'OBSERVED[^.]*survives', 'the survival of the state across the hand-off is not observed')

    def test_the_document_chains_inputsnap_in_front_of_the_xhci_payloads_the_way_the_manifest_tool_takes_it(self):
        chain = re.search(r'\n## Chaining it in front of the xHCI payloads\n(.*?)\n## ', self.text, re.S)
        self.assertTrue(chain, 'the document has no chaining section')
        self.assertRegex(chain.group(1), r'python3 tools/sp11_payload_manifest\.py --out-dir \S+ \S*inputsnp\.bin \S*xhci[01]\.bin')
        self.assertLess(chain.group(1).index('INPUTSNP.BIN'), chain.group(1).index('XHCI0.BIN'))
        self.assertIn('manifest order', chain.group(1))
        self.assertRegex(chain.group(1), r'(?s)INPUTSNAP\.BIN.*8\.3')

    def test_the_safety_table_names_every_seeded_bug_once(self):
        section = re.search(r'\n## Safety rules, each with the seeded bug that must be refused\n(.*?)\n## ', self.text, re.S)
        self.assertTrue(section)
        named = [name for row in self.table_rows(section.group(1)) for name in re.findall(r'`([a-z0-9]+(?:-[a-z0-9]+)+)`', row[2])]
        self.assertEqual(sorted(named), sorted(m[0] for m in mutants.MUTANTS))

    def test_the_tests_table_names_every_suite_and_the_number_of_seeded_bugs(self):
        done = lib.run([str(self.page)])
        suites = re.findall(r'^suite (\w+)', done.stdout, re.M)
        self.assertEqual(suites, list(SUITES))
        for suite in suites + ['caps']:
            self.assertIn(f'`{suite}`', self.text, f'the suite {suite} is not named')
        self.assertIn(f'{len(mutants.MUTANTS)} seeded bugs of the payload and {len(mutants.DOC_MUTANTS)} seeded bug of this document', self.text)
        for command in ('tools/test-q1n1-sp11-payload-inputsnap.py', 'tools/test-q1n1-sp11-payload-inputsnap-refs.py', 'tools/test-q1n1-sp11-payload-qemu-inputsnap.py'):
            self.assertIn(f'python3 {command}', self.text)

    def test_the_document_carries_its_evidence_labels_and_says_nothing_ran(self):
        for needle in ('EXPERIMENTAL', 'NOT RUN', 'VERIFIED', 'OBSERVED', 'INFERRED', 'UNIMPLEMENTED', 'UNKNOWN'):
            self.assertIn(needle, self.text)
        self.assertNotRegex(self.alltext, r'(?i)\bran on the unit\b.*inputsnap')

    def test_the_files_stay_within_the_size_rules(self):
        tools = ROOT / 'tools'
        for path in (SOURCE, REGS, HARNESS, DOC, REGDOC, tools / 'test-q1n1-sp11-payload-inputsnap-model.h', tools / 'test-q1n1-sp11-payload-inputsnap-limits.inc', Path(__file__),
                     tools / 'sp11_payload_inputsnap_mutants.py', tools / 'sp11_payload_inputsnap_refs.py', tools / 'sp11_payload_inputsnap_audit.py',
                     tools / 'test-q1n1-sp11-payload-inputsnap-refs.py', tools / 'test-q1n1-sp11-payload-qemu-inputsnap.py'):
            with self.subTest(file=path.name):
                self.assertLess(path.stat().st_size, 50 * 1024)
                self.assertLess(len(path.read_text(encoding='utf-8').splitlines()), 1500)

    def test_relative_links_resolve(self):
        for text in (self.text, self.regtext):
            for target in re.findall(r'\]\((?!https?:)([^)#]+)(?:#[^)]*)?\)', text):
                self.assertTrue((DOC.parent / target).exists(), target)

    def test_the_two_documents_link_to_each_other(self):
        self.assertIn('(SP11-PAYLOAD-INPUTSNAP-REGISTERS.md#the-register-table)', self.text)
        self.assertIn('(SP11-PAYLOAD-INPUTSNAP-REGISTERS.md#which-words-linux-reads)', self.text)
        self.assertIn('(SP11-PAYLOAD-INPUTSNAP-REGISTERS.md#fetching-the-reference-copies)', self.text)
        self.assertIn('(SP11-PAYLOAD-INPUTSNAP.md)', self.regtext)
        for anchor in ('the-register-table', 'which-words-linux-reads', 'fetching-the-reference-copies'):
            title = anchor.replace('-', ' ')
            self.assertIsNotNone(re.search(rf'^## {title}$', self.regtext, re.M | re.I), f'the companion document has no section {title}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
