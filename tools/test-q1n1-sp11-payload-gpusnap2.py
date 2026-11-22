#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests of the payload gpusnap2 (payloads/gpusnap2.c, docs/SP11-PAYLOAD-GPUSNAP2.md and its evidence document).

    python3 tools/test-q1n1-sp11-payload-gpusnap2.py
    python3 tools/test-q1n1-sp11-payload-gpusnap2-refs.py       (the pinned reference copies: SKIP without GPUSNAP2_REFS_DIR and SNAPINTOSH_DIR)
    python3 tools/test-q1n1-sp11-payload-qemu-gpusnap2.py       (QEMU/EDK2 at EL2: the payload behind the runner)

  Harness       the native host test (tools/test-q1n1-sp11-payload-gpusnap2.c and its model and suites) built under ASan and UBSan at the shipped caps, and with smaller line and load
                caps (only the cap suite then)
  CompiledCode  the IR audit (tools/sp11_payload_gpusnap2_audit.py: no number is turned into a pointer, every store's root is the payload's own stack) on the real source and on
                hand-written faulty IR, the `gpusnap2` policy of tools/sp11_payload_testlib.py on the linked binary, the stack depth, the Makefile's build against the test's own, two
                builds that are byte for byte the same, and the manifest tool on a chain
  Mutants       seeded bugs (tools/sp11_payload_gpusnap2_mutants.py): each must be rejected by the stage it names, for the reason it names
  Doc, Evidence the two documents against the header, the host model's pages and numbers, the pinned-file table, the mutants and the tests (the ledger of citations is checked by
                tools/test-q1n1-sp11-payload-gpusnap2-refs.py: its class `Ledger` needs no pinned copy, its class `Refs` reads them)
  DocMistakes   one wrong statement each in a copy of a document: the check that names it must refuse it

SKIPs, never passes, without clang, ld.lld, make and llvm-objdump. It writes only under build/sp11-payload-gpusnap2/. Nothing here ran on hardware.
Evidence: EXPERIMENTAL (host model and compiled code only)."""
import functools
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_gpusnap2_audit as audit  # noqa: E402
import sp11_payload_gpusnap2_mutants as mutants  # noqa: E402
import sp11_payload_gpusnap2_refs as refs  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-gpusnap2'
HARNESS = ROOT / 'tools' / 'test-q1n1-sp11-payload-gpusnap2.c'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-GPUSNAP2.md'
EVIDENCE = ROOT / 'docs' / 'SP11-PAYLOAD-GPUSNAP2-EVIDENCE.md'
SOURCE = ROOT / 'payloads' / 'gpusnap2.c'
REGS = ROOT / 'payloads' / 'gpusnap2-regs.h'
TOOLS = ('clang', 'ld.lld', 'make', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy')
SUITES = ('unit', 'order', 'tsens', 'gpucc', 'map', 'cmddb', 'rsc', 'qfprom', 'gates', 'faults', 'hang', 'random', 'storm', 'budget', 'el')
PREFIX = 'PAYLOAD GPUSNAP2 '


def need_tools():
    for tool in TOOLS:
        if not lib.have(tool):
            raise unittest.SkipTest(f'{tool} not installed')


def build_harness(name, *defs, source=None, sanitize=True, werror=True):
    """The host test, built under ASan and UBSan; `source` is a mutant payload (GPUSNAP2_SRC)."""
    BUILD.mkdir(parents=True, exist_ok=True)
    out = BUILD / name
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror' if werror else '-Wno-error', '-DQ1N1_PAYLOAD_HOST_TEST=1', '-Iplatform/uefi', '-Ipayloads', *defs]
    if source:
        flags.append(f'-DGPUSNAP2_SRC="{source}"')
    if sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=undefined']
    done = lib.run(['clang', *flags, '-o', str(out), str(HARNESS)])
    if done.returncode:
        raise RuntimeError('the host test did not build:\n' + done.stderr[-2000:])
    return out


def suite_results(text):
    return dict(re.findall(r'^suite (\w+)\s+(ok|FAIL)$', text, re.M))


def c_value(text):
    text = re.sub(r'\b(0x[0-9a-fA-F]+|\d+)[uUlL]*\b', r'\1', text.split('/*')[0]).strip()
    if not re.fullmatch(r'[0-9a-fx<>()+* -]+', text):
        raise ValueError(f'not a plain constant: {text!r}')
    return eval(text, {'__builtins__': {}})


def header_value(name):
    found = re.search(rf'^#define {name} (.+)$', REGS.read_text(encoding='utf-8'), re.M)
    if not found:
        raise KeyError(name)
    return c_value(found.group(1))


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
        results = suite_results(out)
        self.assertEqual(tuple(results), SUITES)
        self.assertEqual(set(results.values()), {'ok'})
        self.assertEqual((line_cap, load_cap), (34, 2048))
        numbers = dict(re.findall(r'(\w+) (\d+)', model_output('--numbers')))
        self.assertEqual(max_lines, int(numbers['PAGE_LINES']), 'the nominal page is the longest one, and it is the page the header derives')
        self.assertEqual(int(numbers['PAGE_LINES']), 31, 'three lines inside the cap of 34')
        self.assertLessEqual(max_loads, int(numbers['LOADS_MAX']))
        self.assertGreaterEqual(max_loads, int(numbers['LOADS_MAX']) - 60, 'the worst-case world reaches the bound the header derives')
        self.assertGreater(checks, 70000)

    def test_smaller_caps(self):
        for name, defs, line_cap, load_cap in (
                ('lines30', ('-DGPUSNAP2_LINE_CAP=30u',), 30, 2048), ('lines28', ('-DGPUSNAP2_LINE_CAP=28u',), 28, 2048), ('lines20', ('-DGPUSNAP2_LINE_CAP=20u',), 20, 2048),
                ('lines12', ('-DGPUSNAP2_LINE_CAP=12u',), 12, 2048), ('lines6', ('-DGPUSNAP2_LINE_CAP=6u',), 6, 2048), ('lines5', ('-DGPUSNAP2_LINE_CAP=5u',), 5, 2048),
                ('lines2', ('-DGPUSNAP2_LINE_CAP=2u',), 2, 2048), ('loads1000', ('-DGPUSNAP2_LOAD_CAP=1000u',), 34, 1000), ('loads100', ('-DGPUSNAP2_LOAD_CAP=100u',), 34, 100),
                ('loads30', ('-DGPUSNAP2_LOAD_CAP=30u',), 34, 30), ('loads8', ('-DGPUSNAP2_LOAD_CAP=8u',), 34, 8), ('both', ('-DGPUSNAP2_LOAD_CAP=30u', '-DGPUSNAP2_LINE_CAP=26u'), 26, 30)):
            with self.subTest(caps=name):
                out, numbers = self.run_harness(build_harness(name, *defs))
                self.assertEqual(suite_results(out), {'caps': 'ok'})
                self.assertEqual((numbers[4], numbers[5]), (line_cap, load_cap))
                self.assertLessEqual(numbers[2], line_cap)
                self.assertLessEqual(numbers[3], load_cap)


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
    'inttoptr load of the database': ('define i64 @payload_entry(ptr noundef %a) {\n  %q = inttoptr i64 2176843776 to ptr\n  %v = load volatile i32, ptr %q, align 4\n  ret i64 0\n}\n',
                                      'integer-to-pointer'),
    'a constant inttoptr in a store': ('define i64 @payload_entry(ptr noundef %a) {\n  store volatile i32 0, ptr inttoptr (i64 391708680 to ptr), align 4\n  ret i64 0\n}\n', 'integer-to-pointer'),
    'store through the arguments': ('define i64 @payload_entry(ptr noundef %a) {\n  store i64 1, ptr %a, align 8\n  ret i64 0\n}\n', 'arguments'),
    'store through a loaded pointer': ('define i64 @payload_entry(ptr noundef %a) {\n  %s = alloca ptr, align 8\n  %l = load ptr, ptr %s, align 8\n'
                                       '  store i32 0, ptr %l, align 4\n  ret i64 0\n}\n', 'not its own stack'),
    'a loaded pointer handed to a call': ('define internal void @callee(ptr noundef %p) {\n  ret void\n}\ndefine i64 @payload_entry(ptr noundef %a) {\n'
                                          '  %s = alloca ptr, align 8\n  %l = load ptr, ptr %s, align 8\n  call void @callee(ptr noundef %l)\n  ret i64 0\n}\n',
                                          'which the callee could store through'),
    'a loaded pointer handed to an indirect call': ('define i64 @payload_entry(ptr noundef %a) {\n  %s = alloca ptr, align 8\n  %l = load ptr, ptr %s, align 8\n'
                                                    '  %f = load ptr, ptr %s, align 8\n  call void %f(ptr noundef %l)\n  ret i64 0\n}\n',
                                                    'which the callee could store through'),
    'memset into the arguments': ('declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)\ndefine i64 @payload_entry(ptr noundef %a) {\n'
                                  '  call void @llvm.memset.p0.i64(ptr %a, i8 0, i64 8, i1 false)\n  ret i64 0\n}\n', 'memset, memcpy or memmove'),
    'a libcall the module does not define': ('declare ptr @memcpy(ptr, ptr, i64)\ndefine i64 @payload_entry(ptr noundef %a) {\n  %s = alloca i64, align 8\n'
                                             '  %r = call ptr @memcpy(ptr %s, ptr %s, i64 8)\n  ret i64 0\n}\n', 'does not define'),
    'a writable global': ('@counter = internal global i32 0, align 4\ndefine i64 @payload_entry(ptr noundef %a) {\n  ret i64 0\n}\n', 'writable global'),
    'a volatile store to a global': ('@counter = internal global i32 0, align 4\ndefine i64 @payload_entry(ptr noundef %a) {\n'
                                     '  store volatile i32 1, ptr @counter, align 4\n  ret i64 0\n}\n', 'not its own stack'),
    'an atomic': ('define i64 @payload_entry(ptr noundef %a) {\n  %s = alloca i32, align 4\n  %o = atomicrmw add ptr %s, i32 1 seq_cst, align 4\n  ret i64 0\n}\n', 'atomic'),
    'a fence': ('define i64 @payload_entry(ptr noundef %a) {\n  fence seq_cst\n  ret i64 0\n}\n', 'fence'),
    'a store through a parameter of the entry': ('define i64 @payload_entry(ptr noundef %a, ptr noundef %b) {\n  store i32 1, ptr %b, align 4\n  ret i64 0\n}\n', 'arguments'),
}


class CompiledCode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        BUILD.mkdir(parents=True, exist_ok=True)
        cls.ir = audit.build_ir(SOURCE, BUILD / 'ir')
        cls.done, cls.elf, cls.flat = lib.build_payload(SOURCE, BUILD / 'a')

    def test_the_payload_builds_with_the_makefile_flags(self):
        self.assertEqual(self.done.returncode, 0, self.done.stderr[-1500:])
        self.assertTrue(self.flat.is_file())

    def test_the_ir_audit_passes_on_the_real_source(self):
        problems, counts = audit.provenance(self.ir)
        self.assertEqual(problems, [])
        self.assertEqual(set(counts['by_root']), {'S', 'P'}, 'every store of the payload is rooted in its own stack or a pointer parameter')
        self.assertGreater(counts['stores'], 100)
        self.assertGreater(counts['indirect_calls'], 2, 'the three ops are called, not stored through')
        self.assertEqual(counts['memory_intrinsics'], 0)

    def test_the_ir_audit_accepts_clean_ir_and_rejects_each_faulty_text(self):
        problems, _ = audit.provenance(GOOD_IR)
        self.assertEqual(problems, [])
        for name, (text, reason) in FAULTY_IR.items():
            with self.subTest(fault=name):
                problems, _ = audit.provenance(text)
                self.assertTrue(any(reason in problem for problem in problems), (name, problems))

    def test_the_binary_policy_holds(self):
        policy = lib.POLICIES['gpusnap2']
        self.assertEqual(lib.binary_violations(self.elf, self.flat, policy), [])
        self.assertEqual(policy['registers'], {'currentel'})
        self.assertTrue(policy['read_only'] and not policy.get('bulk_reads') and policy['smc'] == 0)
        size = self.flat.stat().st_size
        self.assertLessEqual(size, policy['bytes'])
        self.assertEqual(self.flat.read_bytes()[:4], bytes.fromhex('5f2403d5'), 'the start stub: BTI c, then B payload_entry at offset 0')

    def test_the_policy_refuses_what_a_read_only_payload_may_not_hold(self):
        problems = lib.binary_violations(self.elf, self.flat, dict(lib.POLICIES['gpusnap2'], registers={'currentel', 'cntfrq_el0', 'par_el1'}))
        self.assertTrue(any('registers read' in problem for problem in problems), problems)
        problems = lib.binary_violations(self.elf, self.flat, dict(lib.POLICIES['gpusnap2'], smc=1))
        self.assertTrue(any('0 smc instructions' in problem for problem in problems), problems)
        problems = lib.binary_violations(self.elf, self.flat, dict(lib.POLICIES['gpusnap2'], bytes=1024))
        self.assertTrue(any('bytes, the policy allows 1024' in problem for problem in problems), problems)

    def test_the_stack_the_payload_needs_is_far_below_what_the_abi_leaves(self):
        sizes = audit.frame_sizes(SOURCE, BUILD / 'stack')
        disassembly = lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(self.elf)]).stdout
        depth, path = audit.stack_depth(sizes, disassembly)
        self.assertLess(depth, audit.STACK_USABLE, path)
        self.assertLess(depth, 8192, f'the deepest chain of frames is {depth} bytes: {path}')

    def test_two_builds_are_byte_for_byte_the_same(self):
        done, elf, flat = lib.build_payload(SOURCE, BUILD / 'b')
        self.assertEqual(done.returncode, 0)
        self.assertEqual(flat.read_bytes(), self.flat.read_bytes())
        self.assertEqual(elf.read_bytes(), self.elf.read_bytes())

    def test_the_makefile_builds_the_same_bytes(self):
        out = BUILD / 'make-out'
        shutil.rmtree(out, ignore_errors=True)
        done = lib.run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j1', f'{out.relative_to(ROOT)}/payloads/gpusnap2.bin'])
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-1500:])
        self.assertEqual((out / 'payloads' / 'gpusnap2.bin').read_bytes(), self.flat.read_bytes())
        plan = lib.run(['make', '-n', '-f', 'platform/uefi/Makefile', f'OUT={(BUILD / "plan-out").relative_to(ROOT)}', 'payloads'])
        self.assertEqual(plan.returncode, 0, plan.stderr[-800:])
        self.assertIn('payloads/gpusnap2.c', plan.stdout, 'the wildcard of the Makefile finds the new file with no edit of the Makefile')

    def test_the_manifest_tool_lists_it_alone_and_in_a_chain(self):
        done, _, psci = lib.build_payload(ROOT / 'payloads' / 'psci.c', BUILD / 'psci')
        self.assertEqual(done.returncode, 0)
        for name, files in (('alone', [self.flat]), ('chain', [self.flat, psci])):
            out = BUILD / f'stick-{name}'
            shutil.rmtree(out, ignore_errors=True)
            made = lib.run(['python3', '-B', 'tools/sp11_payload_manifest.py', '--out-dir', str(out)] + [str(f) for f in files])
            self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
            self.assertTrue((out / 'SP11' / 'GPUSNAP2.BIN').is_file(), made.stdout)
            self.assertEqual((out / 'SP11' / 'GPUSNAP2.BIN').read_bytes(), self.flat.read_bytes())
            self.assertIn('GPUSNAP2.BIN', made.stdout)
        self.assertLess(made.stdout.index('GPUSNAP2.BIN'), made.stdout.index('PSCI.BIN'), 'the tool keeps the order it is given')


class Mutants(unittest.TestCase):
    """Every seeded bug is refused by the stage it names, for the reason it names. The mutant files are written below build/sp11-payload-gpusnap2/mutants/<name>/."""

    @classmethod
    def setUpClass(cls):
        need_tools()

    @staticmethod
    def write(mutant):
        directory = BUILD / 'mutants' / mutant.name
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True)
        for path in (SOURCE, REGS):
            (directory / path.name).write_text(path.read_text(encoding='utf-8'), encoding='utf-8')
        target = directory / Path(mutant.file).name
        text = target.read_text(encoding='utf-8')
        assert text.count(mutant.old) == 1, f'{mutant.name}: the pattern occurs {text.count(mutant.old)} times'
        target.write_text(text.replace(mutant.old, mutant.new), encoding='utf-8')
        return directory

    def test_every_pattern_is_in_the_source_exactly_once(self):
        for mutant in mutants.MUTANTS:
            text = (ROOT / mutant.file).read_text(encoding='utf-8')
            self.assertEqual(text.count(mutant.old), 1, mutant.name)
            self.assertNotEqual(mutant.old, mutant.new, mutant.name)

    def test_the_names_are_unique_and_every_stage_is_one_the_runner_knows(self):
        names = [mutant.name for mutant in mutants.MUTANTS]
        self.assertEqual(len(names), len(set(names)))
        self.assertLessEqual({mutant.stage for mutant in mutants.MUTANTS}, {'harness', 'caps', 'audit', 'binary', 'stack'})
        self.assertGreaterEqual(len(names), 100)
        for suite in SUITES:
            self.assertTrue(any(suite in mutant.suites for mutant in mutants.MUTANTS if mutant.stage == 'harness') or suite in ('hang', 'storm', 'random', 'budget', 'faults'),
                            f'no seeded bug names the {suite} suite')

    def refuse(self, mutant):
        directory = self.write(mutant)
        source = directory / 'gpusnap2.c'
        if mutant.stage in ('harness', 'caps'):
            try:
                binary = build_harness('mutant-' + mutant.name, *mutant.defs, source=source, werror=False)
            except RuntimeError as error:
                self.fail(f'{mutant.name}: the seeded bug does not compile, so nothing was shown: {error}')
            try:
                done = lib.run([str(binary)], timeout=300)
            except subprocess.TimeoutExpired:
                self.fail(f'{mutant.name}: timed out; the seeded bug must be refused by a failed check, not a hang')
            output = done.stdout + done.stderr
            self.assertNotEqual(done.returncode, 0, f'{mutant.name}: the host test passed on a seeded bug')
            failed = {name for name, result in suite_results(done.stdout).items() if result == 'FAIL'}
            self.assertTrue(set(mutant.suites) <= failed, f'{mutant.name}: wanted {mutant.suites} among the failing suites, got {sorted(failed)}')
            self.assertIn(mutant.reason, output, f'{mutant.name}: refused, but not for the reason it names')
        elif mutant.stage == 'audit':
            problems, _ = audit.provenance(audit.build_ir(source, BUILD / 'mutir' / mutant.name, extra=('-Wno-error',)))
            self.assertTrue(any(mutant.reason in problem for problem in problems), (mutant.name, problems))
        elif mutant.stage == 'binary':
            done, elf, flat = lib.build_payload(source, BUILD / 'mutbin' / mutant.name, name='gpusnap2', extra_cflags=('-Wno-error',))
            if done.returncode:
                self.assertIn(mutant.reason, done.stdout + done.stderr, mutant.name)
            else:
                problems = lib.binary_violations(elf, flat, lib.POLICIES['gpusnap2'])
                self.assertTrue(any(mutant.reason in problem for problem in problems), (mutant.name, problems))
        else:
            done, elf, _ = lib.build_payload(source, BUILD / 'mutbin' / mutant.name, name='gpusnap2', extra_cflags=('-Wno-error',))
            self.assertEqual(done.returncode, 0, done.stderr[-800:])
            sizes = audit.frame_sizes(source, BUILD / 'mutstack' / mutant.name)
            depth, _ = audit.stack_depth(sizes, lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout)
            self.assertGreater(depth, audit.STACK_USABLE, mutant.name)

    def test_each_seeded_bug_is_refused_for_its_own_reason(self):
        for mutant in mutants.MUTANTS:
            with self.subTest(mutant=mutant.name, stage=mutant.stage):
                self.refuse(mutant)
                shutil.rmtree(BUILD / 'mutants' / mutant.name, ignore_errors=True)
                shutil.rmtree(BUILD / 'mutir' / mutant.name, ignore_errors=True)
                shutil.rmtree(BUILD / 'mutbin' / mutant.name, ignore_errors=True)
                (BUILD / ('mutant-' + mutant.name)).unlink(missing_ok=True)
                shutil.rmtree(BUILD / ('mutant-' + mutant.name + '.dSYM'), ignore_errors=True)


@functools.lru_cache(maxsize=None)
def model_output(*options):
    """What the host test prints for `--page [scenario]` or `--numbers`: its model's pages and numbers, which the document quotes."""
    return lib.run([str(build_harness('doc')), *options]).stdout


def table_rows(block):
    """The cells of every row of a Markdown table in `block`, its header row and its rule row left out."""
    rows = [[cell.strip() for cell in line.strip().strip('|').split('|')]
            for line in block.splitlines() if line.startswith('|') and not re.fullmatch(r'\|[\s|:-]+\|', line)]
    return rows[1:]


def header_windows():
    """[(base, size)] of the seven windows of the header, in its order."""
    body = re.search(r'windows\[WIN_MAP\] = \{(.*?)\n\};', REGS.read_text(encoding='utf-8'), re.S).group(1).replace('CMDDB_BYTES', '0x20000u')
    return [(c_value(base), c_value(size)) for base, size in re.findall(r'\{(0x[0-9a-fA-F]+u), (0x[0-9a-fA-F]+u), 0\}', body)]


def header_rows():
    """[(window name, offset, key)] of the register table of the header, in reading order."""
    return [(win[4:], int(off, 16), key) for win, off, key in re.findall(r'ROW\((WIN_\w+), (0x[0-9a-f]+), \w+, "(\w+)"\)', REGS.read_text(encoding='utf-8'))]


def header_layouts():
    """[(major, enable, addr, data, stride)] of the two RSC layouts."""
    return [tuple(c_value(v) for v in row) for row in re.findall(r'\{(\d), (0x[0-9a-f]+u), (0x[0-9a-f]+u), (0x[0-9a-f]+u), (\d+u), \{0, 0, 0\}\}', REGS.read_text(encoding='utf-8'))]


def slug(heading):
    """The anchor GitHub makes of a heading."""
    return re.sub(r'\s', '-', re.sub(r'[^\w\s-]', '', heading.strip().lower()))


def flat(text):
    return ' '.join(text.split())


MACHINE_PATH = '\n' + '/Us' + 'ers/someone/tree\n'


class DocChecks(unittest.TestCase):
    """What the two documents share: the checks are run on `self.text`, which DocMistakes replaces by a document with one wrong statement in it."""
    path = DOC
    titles = ()

    @classmethod
    def setUpClass(cls):
        if cls is DocChecks:
            raise unittest.SkipTest('the base of the document checks')
        cls.text = cls.path.read_text(encoding='utf-8')

    def block(self, name):
        found = re.search(rf'<!-- {name} -->\n(.*?)<!-- /{name} -->', self.text, re.S)
        self.assertIsNotNone(found, f'the document has no <!-- {name} --> block')
        return found.group(1)

    def fenced(self, name):
        return re.search(r'```\n(.*?)```', self.block(name), re.S).group(1).splitlines()

    def check_page(self, name, *options):
        page = model_output('--page', *options).splitlines()
        self.assertEqual(self.fenced(name), page, f'regenerate the sample with: <host test> --page {" ".join(options)}')
        self.assertLessEqual(len(page), header_value('GPUSNAP2_LINE_CAP'))
        for line in page:
            self.assertTrue(line.startswith(PREFIX), line)
            self.assertLessEqual(len(line), 100, line)

    def test_the_document_keeps_its_own_rules(self):
        self.assertTrue(self.text.startswith('<!-- SPDX-License-Identifier: MIT -->\n'))
        self.assertLess(self.path.stat().st_size, 50 * 1024)
        self.assertLess(len(self.text.splitlines()), 1500)
        for title in self.titles:
            self.assertIn(f'\n## {title}\n', self.text)
        self.assertIn('Status: EXPERIMENTAL; hardware NOT RUN', self.text)
        paths = '|'.join(['/Us' + 'ers/', '/Vol' + 'umes/', '/priv' + 'ate/', '/ho' + 'me/'])      # built from pieces: this file must not hold what it looks for
        self.assertIsNone(re.search(paths, self.text), 'the document names a path of a machine')

    def test_the_links_resolve(self):
        links = re.findall(r'\]\(([^)#\s]+)(?:#([^)\s]+))?\)', self.text)
        self.assertTrue(links)
        for target, anchor in links:
            if '://' in target:
                continue
            path = (self.path.parent / target).resolve()
            self.assertTrue(path.is_file(), target)
            if anchor:
                headings = [slug(line.lstrip('#')) for line in path.read_text(encoding='utf-8').splitlines() if line.startswith('#')]
                self.assertIn(anchor, headings, f'{target}#{anchor}')


class Doc(DocChecks):
    """docs/SP11-PAYLOAD-GPUSNAP2.md against the header, the host model and the tests."""
    path = DOC
    titles = ('1. What it reads', '2. The page', '3. Hazards, and what the order is for', '4. The chain budget', '5. Tests', '6. What it answers, and what it does not',
              "7. The operator's note (nothing here authorises a run)", '8. Evidence ledger and pins', '9. Not verified')

    def test_the_document_says_hardware_not_run_and_the_first_reads_are_unknown_risk(self):
        self.assertIn('* Hardware: NOT RUN.', self.text)
        text = flat(self.text)
        self.assertIn('the first read of the command database, the first read of the apps RSC and the first read of the QFPROM are of UNKNOWN risk', text)
        operator = flat(re.search(r"\n## 7\. .*?\n(.*?)\n## 8\. ", self.text, re.S).group(1))
        self.assertIn('The first reads of the command database, of the apps RSC and of the QFPROM are of unknown risk', operator)
        self.assertIn('An independent review (2026-11-22) found the binary named in that note safe for one read-only run', operator)

    def test_the_page_is_the_models_page(self):
        self.check_page('page')

    def test_the_numbers_are_the_models_numbers(self):
        numbers = model_output('--numbers').strip()
        self.assertEqual(self.block('numbers').strip(), numbers)
        values = dict(re.findall(r'(\w+) (\d+)', numbers))
        text = flat(self.text)
        self.assertIn(f'A nominal page is {values["LINES"]} lines and {values["LOADS"]} loads', text)
        self.assertIn(f'the loads every block can make at most add up to {values["LOADS_MAX"]}', text)
        self.assertIn(f'At most {header_value("GPUSNAP2_LINE_CAP")} lines of at most 100 characters', text)
        self.assertIn(f'keeps to {header_value("GPUSNAP2_LINE_CAP")} lines and {header_value("GPUSNAP2_LOAD_CAP")} loads', text)
        self.assertIn(f'CAP={header_value("GPUSNAP2_LOAD_CAP")}/{header_value("GPUSNAP2_LINE_CAP")}', self.text)

    def test_the_chain_budget_is_the_runners_arithmetic(self):
        rows = table_rows(self.block('chain-budget'))
        self.assertGreaterEqual(len(rows), 3)
        for _, cell, left in rows:
            found = re.fullmatch(r'\((\d+) \+ 1\) \+ (?:(\d+) x )?3((?: \+ \d+)+) = (\d+)', cell)
            self.assertIsNotNone(found, cell)
            files, per_payload, total = int(found[1]), int(found[2] or 1), int(found[4])
            counts = [int(count) for count in re.findall(r'\d+', found[3])]
            self.assertEqual((len(counts), per_payload), (files, files), cell)
            self.assertEqual(files + 1 + 3 * files + sum(counts), total, cell)
            self.assertEqual(counts[0], header_value('GPUSNAP2_LINE_CAP'), cell)
            self.assertLessEqual(max(counts), 40, 'the ABI allows 40 lines per call')
            if total <= 89:
                self.assertEqual(left, str(89 - total), cell)
            else:
                self.assertTrue(left.startswith('none'), cell)
        self.assertIn('alone in its boot it needs 39 rows, within the 73 drawn in boot 29', flat(self.text))
        self.assertIn('a chain of the two is 77 rows, more than the 73 ever seen drawn', flat(self.text))

    def test_the_window_and_register_tables_are_the_headers(self):
        windows = header_windows()
        names = ['TSROT', 'TTM', 'GCC', 'GPUCC', 'CMDDB', 'RSC2', 'QFPROM']
        blocks = table_rows(re.search(r'(\| Block \| Window \|.*?)\n\n', self.text, re.S).group(1))
        self.assertEqual([row[1] for row in blocks[:7]], names)
        self.assertEqual(blocks[7][:2], ['UEFI memory map', 'MAP'])
        for row, (base, size) in zip(blocks, windows):
            self.assertEqual((int(row[2], 16), int(row[3], 16)), (base, size), row[1])
        rows = table_rows(re.search(r'(\| # \| Window \| Offset \|.*?)\n\n', self.text, re.S).group(1))
        want = header_rows()
        self.assertEqual(len(rows), len(want))
        for n, (row, (window, offset, key)) in enumerate(zip(rows, want), 1):
            self.assertEqual((row[0], row[1], int(row[2], 16), row[3].split()[-1]), (str(n), window, offset, key), row[3])
        tsens = table_rows(re.search(r'(\| Window \| Offset \| Register \| Fields and use \|.*?)\n\n', self.text, re.S).group(1))
        self.assertEqual([(row[0], row[1]) for row in tsens], [('TSROT', f'0x{header_value("SROT_HW_VER"):02x}'), ('TSROT', f'0x{header_value("SROT_CTRL"):02x}'),
                                                              ('TTM', f'0x{header_value("TM_STATUS"):x} + 4n')])
        self.assertEqual(tsens[2][2], f'Sn_STATUS, n = {header_value("TS_FIRST")} to {header_value("TS_FIRST") + header_value("TS_COUNT") - 1}')
        base, entry, rsc_hdr = header_value('CMDDB_HDR_BYTES'), header_value('CMDDB_ENTRY_BYTES'), header_value('CMDDB_RSC_HDR_BYTES')
        db = table_rows(re.search(r'(\| Offset \| What \| Read when, and why a read is harmless \|.*?)\n\n', self.text, re.S).group(1))
        self.assertEqual([row[0] for row in db], ['+0, +4', f'+{header_value("CMDDB_RSC_HDR_OFF")} + {rsc_hdr}i, +{header_value("CMDDB_RSC_HDR_OFF") + 4} + {rsc_hdr}i',
                                                  f'0x{base:x} + header_offset + {entry}j', f'0x{base:x} + data_offset + offset'])
        text = flat(self.text)
        self.assertIn(f'one word 0x{header_value("CMDDB_MAGIC"):08x}', text)
        self.assertIn(f'at most {header_value("CMDDB_ENTRY_MAX")} per header and {header_value("CMDDB_SCAN_MAX")} in all', text)
        self.assertIn(f'up to eight 16-bit levels (five words at most)', text)
        self.assertEqual(header_value('LEVELS_MAX') // 2 + 1, 5)
        self.assertIn('#define CMDDB_AUX_WORDS (LEVELS_MAX / 2u + 1u)', REGS.read_text(encoding='utf-8'))
        two, three = header_layouts()
        stride, tcs = header_value('RSC_TCS_STRIDE'), header_value('RSC_TCS_BASE')
        rsc = table_rows(re.search(r'(\| Offset \| Register \| Read when, and why a read is harmless \|.*?)\n\n', self.text, re.S).group(1))
        self.assertEqual([row[0] for row in rsc], [f'0x{header_value("RSC_DRV_ID"):02x}', f'0x{header_value("RSC_DRV_SOLVER"):02x}, 0x{header_value("RSC_DRV_CHLD"):02x}',
                                                   f'0x{tcs:x}, 0x{tcs + header_value("RSC_IRQ_STATUS"):x}', f'0x{tcs:x} + {stride} t + 0x{two[1]:x} or 0x{three[1]:x}',
                                                   f'+ 0x{two[2]:x} + {two[4]} j or 0x{three[2]:x} + {three[4]} j', f'+ 0x{two[3]:x} + {two[4]} j or 0x{three[3]:x} + {three[4]} j'])
        self.assertIn(f'A TCS is {stride} bytes apart from 0x{tcs:x}', text)
        self.assertIn(f'The two layouts are `rpmh_rsc_reg_offset_ver_2_7` (command stride {two[4]}) and `_ver_3_0` (stride {three[4]}), both with a TCS stride of {stride}', text)
        word, shift, mask = header_value('QFPROM_WORD'), header_value('QFPROM_FUSE_SHIFT'), header_value('QFPROM_FUSE_MASK')
        self.assertIn(f'the fuse is bits {shift + mask.bit_length() - 1}:{shift} of the word at 0x{word:x}', text)
        bins = re.findall(r'\{(\d+), (\d)\}', REGS.read_text(encoding='utf-8').split('speedbins[5] = ')[1].split(';')[0])
        self.assertIn('the catalog: ' + ', '.join(f'{fuse} to {bin_}' for fuse, bin_ in bins), text)

    def test_the_bit_fields_and_numbers_the_document_states_are_the_headers(self):
        facts = (
            ('EN bit 0', header_value('CTRL_EN') == 1),
            ('SW_RST bit 1', header_value('CTRL_SW_RST') == 2),
            ('SENSOR_EN bits 18:3', header_value('CTRL_SENSOR_SHIFT') == 3 and header_value('CTRL_SENSOR_MASK') == 0xffff),
            ('CODE_OR_TEMP bit 21', header_value('CTRL_CODE_OR_TEMP') == 1 << 21),
            ('VALID 21', header_value('ST_VALID') == 1 << 21),
            ('bits 26:22', header_value('ST_ID_SHIFT') == 22 and header_value('ST_ID_MASK') == 0x1f),
            ('31:27', header_value('ST_RESERVED_SHIFT') == 27 and header_value('ST_ID_SHIFT') + 5 == 27),
            ('outside -40.0 to 120.0 C', (header_value('TEMP_MIN_TENTHS'), header_value('TEMP_MAX_TENTHS')) == (-400, 1200)),
            ('CLK_OFF (bit 31)', header_value('CBCR_CLK_OFF_BIT') == 31),
            ('CLK_ENABLE (bit 0)', header_value('CBCR_ENABLE_BIT') == 0),
            ('NoC FSM status of ON', header_value('CBCR_FSM_SHIFT') == 28 and header_value('CBCR_FSM_MASK') == 7 and header_value('CBCR_FSM_ON') == 2),
            ('OUTCTRL bit 0, LOCK_DET bit 31', header_value('PLL_OUTCTRL_BIT') == 0 and header_value('PLL_LOCK_DET_BIT') == 31),
            ('RUN is 1', header_value('PLL_RUN_BIT') == 0),
            ('source select bits 10:8', header_value('RCG_SRC_SHIFT') == 8 and header_value('RCG_SRC_MASK') == 7),
            ('PWR_ON as bit 31', header_value('GDSC_PWR_ON_BIT') == 31),
            ('major 23:16, minor 15:8', header_value('RSC_MAJOR_SHIFT') == 16 and header_value('RSC_MINOR_SHIFT') == 8),
            ('TCS count of drv-2 in bits 17:12', header_value('RSC_NUM_TCS_SHIFT') * header_value('RSC_DRV_NUMBER') == 12 and header_value('RSC_NUM_TCS_MASK') == 0x3f),
            ('NCPT 31:27', header_value('RSC_NCPT_SHIFT') == 27 and header_value('RSC_NCPT_MASK') == 0x1f),
            ('the TCS count must be 7 or more', header_value('RSC_TCS_NUM') == 7),
            ('the maximum number of commands is 16', header_value('RSC_CMDS_MAX') == 16),
            ('a 16-bit command mask', header_value('RSC_CMDS_MAX') == 16),
            ('major 2 and 3 only', header_layouts()[0][0] == 2 and header_layouts()[1][0] == 3),
            ('tcs-offset 0xd00, drv-id 2', header_value('RSC_TCS_BASE') == 0xd00 and header_value('RSC_DRV_NUMBER') == 2),
            ('active 0 to 2, sleep 3 and 4, wake 5 and 6', (header_value('RSC_TCS_ACTIVE'), header_value('RSC_TCS_SLEEP'), header_value('RSC_TCS_WAKE'), header_value('RSC_WAKE_COUNT')) == (0, 3, 5, 2)),
            ('four words of each of 320 descriptors', header_value('MAP_DESC_MAX') == 320),
            ('more hits than 8', header_value('MAP_HITS_MAX') == 8),
            ('past 48 bits', header_value('MAP_ADDR_LIMIT') == 1 << 48),
            ('ARC (type 3) or BCM (type 5)', (header_value('CMDDB_SLV_ARC'), header_value('CMDDB_SLV_BCM')) == (3, 5)),
        )
        for phrase, holds in facts:
            self.assertIn(phrase, flat(self.text), phrase)
            self.assertTrue(holds, phrase)
        abi = (ROOT / 'platform' / 'uefi' / 'sp11-payload-abi.h').read_text(encoding='utf-8')
        self.assertIn('allows 40 lines and 4096 loads', flat(self.text))
        self.assertIn('#define Q1N1_PAYLOAD_LINES_MAX 40u', abi)
        self.assertIn('#define Q1N1_PAYLOAD_LOADS_MAX 4096u', abi)

    def test_the_tokens_the_document_names_are_the_sources(self):
        source = SOURCE.read_text(encoding='utf-8') + REGS.read_text(encoding='utf-8')
        names = [name for name in re.findall(r'"(\w*)"', re.search(r'reason_name\[REASONS\]\[8\] = \{(.*?)\};', source, re.S).group(1)) if name]
        verdicts = [name for name in re.findall(r'"(\w+)"', re.search(r'map_name\[MAP_STATES\]\[8\] = \{(.*?)\};', source, re.S).group(1))]
        self.assertEqual(names, ['AHB', 'AHBERR', 'MAP', 'MAGIC', 'ID', 'VER', 'TCS'])
        self.assertEqual(verdicts, ['NA', 'OPEN', 'NONE', 'TYPE', 'PART', 'BAD', 'ERR'])
        for token in ('FAULT:', 'SKIP', 'BUDGET', 'NONE', 'PART', 'EMPTY', 'RANGE', 'CODE', 'CTLERR', 'GATED BY', 'GATED', 'SKIPPED_NOT_AT_EL2', 'REFUSED_NO_LOAD32', 'NEXT ', 'READ ONLY EL=2 CAP=',
                      'END LOADS=', 'CMDDB MAP', 'ID=', 'W118='):
            self.assertIn(token.strip(), self.text, token)
            self.assertIn(token.strip(), source, token)
        for name in names:
            self.assertIsNotNone(re.search(rf'\b{name}\b', self.text), name)
        for name in verdicts[1:]:
            self.assertIn(f'`{name}`', self.text, name)

    def test_the_outcome_table_has_a_row_for_every_outcome_the_page_can_show(self):
        section = re.search(r'\n## 6\. .*?\n(.*?)\n## 7\. ', self.text, re.S).group(1)
        shown = ' '.join(row[0] for row in table_rows(section))
        for outcome in ('T3 VER=FAULT:6 GATED', 'T3 C5', 'ODD=', 'GCC CFGA=', 'GPUCC GATED BY AHB', 'EN=OFF', 'EN=ON LK=1', 'a GPUCC word `FAULT:6`', 'CMDDB GATED BY MAP',
                        'HDR VER=FAULT:6 MAGIC=SKIP', 'MAGIC=BAD', 'CMDDB ADDR', 'a target `NONE` or `PART`', 'RSC2 ID=FAULT:6', 'GFX=-', 'RSC2 EN W5=0 W6=0', 'QFPROM W118=',
                        '`BUDGET`', '`CUTS` above 0', 'the last line is a `NEXT` line', '`END` is on the page'):
            self.assertIn(outcome, shown, outcome)
        self.assertIn('boot the stick again', section)

    def test_the_counts_and_the_suites_the_document_names_are_the_tests(self):
        harness = (ROOT / 'tools' / 'test-q1n1-sp11-payload-gpusnap2-suites.inc').read_text(encoding='utf-8')
        text = flat(self.text)
        self.assertIn(f'{len(FAULTY_IR)} hand-written faulty texts', text)
        for worlds in (1500, 600):
            self.assertIn(f'i < {worlds}', harness)
        self.assertIn('1500 random worlds against the page oracle and 600 with aborts', text)
        self.assertEqual(len(re.findall(r'CASE\("', harness[harness.index('static int suite_map'):harness.index('#undef CASE')])), 44)
        self.assertIn('44 named memory maps', text)
        section = re.search(r"The host program's suites:(.*?)\n\n", self.text, re.S).group(1)
        for suite in SUITES:
            self.assertIn(f'`{suite}`', section, suite)

    def test_the_unverified_items_are_listed_with_their_ids(self):
        section = self.text[self.text.index('\n## 9. Not verified'):]
        self.assertEqual(sorted(set(re.findall(r'\*\*(UV\d+)\*\*', section))), sorted(refs.UNVERIFIED))


class Evidence(DocChecks):
    """docs/SP11-PAYLOAD-GPUSNAP2-EVIDENCE.md against the refs module, the mutants module and the host model."""
    path = EVIDENCE
    titles = ('A. Pinned files', 'B. The seeded bugs', 'C. The gated page and the abort page', 'D. What QEMU shows')

    def test_the_pinned_table_is_the_refs_module(self):
        section = re.search(r'\n## A\. .*?\n(.*?)\n## B\. ', self.text, re.S).group(1)
        rows = {row[0].strip('`'): row for row in table_rows(re.search(r'(\| File \|.*?)\n\n', section, re.S).group(1))}
        self.assertEqual(set(rows), set(refs.PINNED))
        for name, (sha, where) in refs.PINNED.items():
            self.assertEqual((rows[name][1].strip('`'), rows[name][2].strip('`'), rows[name][3]), (refs.LINUX_PATH[name], sha, where), name)
        self.assertIn(refs.LINUX_REVISION, self.text)

    def test_every_seeded_bug_is_listed_and_the_counts_are_the_modules(self):
        by_stage = {stage: sum(1 for m in mutants.MUTANTS if m.stage == stage) for stage in ('harness', 'caps', 'audit', 'binary', 'stack')}
        text = flat(self.block('mutants'))
        self.assertIn(f'{len(mutants.MUTANTS)} seeded bugs', text)
        self.assertIn(f'{by_stage["harness"]} rejected by the host program, {by_stage["caps"]} by the host program built with small caps, {by_stage["audit"]} by the IR audit, '
                      f'{by_stage["binary"]} by the binary policy and {by_stage["stack"]} by the stack check', text)
        listed = re.findall(r'`([a-z0-9][a-z0-9-]+)`', self.text)
        for mutant in mutants.MUTANTS:
            self.assertIn(mutant.name, listed, mutant.name)

    def test_the_other_pages_are_the_models_pages(self):
        self.check_page('page-gated', 'gated')
        self.check_page('page-aborts', 'aborts')

    def test_the_qemu_block_has_the_shape_of_a_page(self):
        shown = self.fenced('qemu-lines')
        self.assertEqual(shown[0], PREFIX + 'READ ONLY EL=2 CAP=2048/34')
        self.assertTrue(shown[-1].startswith(PREFIX + 'END LOADS='), shown[-1])
        self.assertLessEqual(len(shown), header_value('GPUSNAP2_LINE_CAP'))


# One wrong statement each in a copy of a document: the check named must refuse it (the test of a test).
MISTAKES = (
    ('a-gpucc-offset-moved', Doc, '| 20 | GPUCC | 0x9150 | MEM |', '| 20 | GPUCC | 0x9154 | MEM |', 'test_the_window_and_register_tables_are_the_headers'),
    ('a-window-base-moved', Doc, '| QFPROM | QFPROM | 0x221c8000 | 0x1000 |', '| QFPROM | QFPROM | 0x221c9000 | 0x1000 |', 'test_the_window_and_register_tables_are_the_headers'),
    ('a-window-size-moved', Doc, '| CMDDB | 0x81c60000 | 0x20000 |', '| CMDDB | 0x81c60000 | 0x10000 |', 'test_the_window_and_register_tables_are_the_headers'),
    ('a-sensor-offset-moved', Doc, '| TTM | 0xa0 + 4n |', '| TTM | 0xa4 + 4n |', 'test_the_window_and_register_tables_are_the_headers'),
    ('the-sensor-range-is-misquoted', Doc, 'n = 5 to 12', 'n = 4 to 11', 'test_the_window_and_register_tables_are_the_headers'),
    ('an-rsc-offset-moved', Doc, '| 0xd00 + 672 t + 0x1c or 0x2c |', '| 0xd00 + 672 t + 0x1c or 0x30 |', 'test_the_window_and_register_tables_are_the_headers'),
    ('the-tcs-stride-is-misquoted', Doc, 'A TCS is 672 bytes apart from 0xd00', 'A TCS is 640 bytes apart from 0xd00', 'test_the_window_and_register_tables_are_the_headers'),
    ('a-database-offset-moved', Doc, '| 0x90 + header_offset + 24j |', '| 0x80 + header_offset + 24j |', 'test_the_window_and_register_tables_are_the_headers'),
    ('the-entry-cap-is-misquoted', Doc, 'at most 128 per header and 256 in all', 'at most 129 per header and 256 in all', 'test_the_window_and_register_tables_are_the_headers'),
    ('the-magic-is-misquoted', Doc, 'one word 0x0c0330db', 'one word 0x0c0330dc', 'test_the_window_and_register_tables_are_the_headers'),
    ('the-speed-bin-table-is-misquoted', Doc, '59 to 1, 7 to 2', '59 to 2, 7 to 2', 'test_the_window_and_register_tables_are_the_headers'),
    ('the-fuse-field-is-misquoted', Doc, 'so the fuse is bits 22:15 of the', 'so the fuse is bits 21:14 of the', 'test_the_window_and_register_tables_are_the_headers'),
    ('a-bit-field-moved', Doc, 'VALID 21', 'VALID 20', 'test_the_bit_fields_and_numbers_the_document_states_are_the_headers'),
    ('the-sensor-number-field-is-moved', Doc, 'bits 26:22', 'bits 25:22', 'test_the_bit_fields_and_numbers_the_document_states_are_the_headers'),
    ('the-version-majors-are-misquoted', Doc, 'major 2 and 3 only', 'major 2 only', 'test_the_bit_fields_and_numbers_the_document_states_are_the_headers'),
    ('the-tcs-gate-is-misquoted', Doc, 'the TCS count must be 7 or more', 'the TCS count must be 8 or more', 'test_the_bit_fields_and_numbers_the_document_states_are_the_headers'),
    ('the-abi-allowance-is-misquoted', Doc, 'allows 40 lines and 4096 loads', 'allows 40 lines and 4097 loads', 'test_the_bit_fields_and_numbers_the_document_states_are_the_headers'),
    ('the-line-cap-is-misquoted', Doc, 'At most 34 lines of at most 100 characters', 'At most 35 lines of at most 100 characters', 'test_the_numbers_are_the_models_numbers'),
    ('the-load-cap-is-misquoted', Doc, 'keeps to 34 lines and 2048 loads', 'keeps to 34 lines and 2047 loads', 'test_the_numbers_are_the_models_numbers'),
    ('the-nominal-page-is-misquoted', Doc, 'A nominal page is 31 lines and 1026 loads', 'A nominal page is 32 lines and 1026 loads', 'test_the_numbers_are_the_models_numbers'),
    ('the-numbers-are-edited', Doc, 'LOADS 1026 LINE_CAP', 'LOADS 1027 LINE_CAP', 'test_the_numbers_are_the_models_numbers'),
    ('the-load-bound-is-misquoted', Doc, 'add up to 1971', 'add up to 1972', 'test_the_numbers_are_the_models_numbers'),
    ('the-chain-total-is-wrong', Doc, '+ 34 + 40 = 83 |', '+ 34 + 40 = 84 |', 'test_the_chain_budget_is_the_runners_arithmetic'),
    ('the-rows-left-are-wrong', Doc, '= 83 | 6 |', '= 83 | 7 |', 'test_the_chain_budget_is_the_runners_arithmetic'),
    ('the-page-sample-is-edited', Doc, 'PAYLOAD GPUSNAP2 GCC CFGA=1.ON', 'PAYLOAD GPUSNAP2 GCC CFGA=1.OFF', 'test_the_page_is_the_models_page'),
    ('a-line-of-the-page-sample-is-dropped', Doc, 'PAYLOAD GPUSNAP2 QFPROM W118=0X1D9234 FUSE=59 SB=1\n', '', 'test_the_page_is_the_models_page'),
    ('a-suite-is-misnamed', Doc, '`storm` (hostile', '`storn` (hostile', 'test_the_counts_and_the_suites_the_document_names_are_the_tests'),
    ('the-faulty-texts-are-miscounted', Doc, '14 hand-written faulty texts', '13 hand-written faulty texts', 'test_the_counts_and_the_suites_the_document_names_are_the_tests'),
    ('the-random-worlds-are-miscounted', Doc, '1500 random worlds', '1501 random worlds', 'test_the_counts_and_the_suites_the_document_names_are_the_tests'),
    ('the-map-cases-are-miscounted', Doc, '44 named memory maps', '45 named memory maps', 'test_the_counts_and_the_suites_the_document_names_are_the_tests'),
    ('a-token-is-renamed', Doc, 'REFUSED_NO_LOAD32', 'REFUSED_NO_LOAD', 'test_the_tokens_the_document_names_are_the_sources'),
    ('a-gate-reason-is-renamed', Doc, 'AHBERR', 'AHBERROR', 'test_the_tokens_the_document_names_are_the_sources'),
    ('a-link-is-broken', Doc, '(SP11-PAYLOAD-RESULTS.md)', '(SP11-PAYLOAD-RESULT.md)', 'test_the_links_resolve'),
    ('an-anchor-is-broken', Doc, 'SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot', 'SP11-PAYLOAD.md#the-chain', 'test_the_links_resolve'),
    ('the-status-label-is-dropped', Doc, 'Status: EXPERIMENTAL; hardware NOT RUN', 'Status: EXPERIMENTAL', 'test_the_document_keeps_its_own_rules'),
    ('a-machine-path-is-named', Doc, '\n## 9. Not verified\n', '\n## 9. Not verified\n' + MACHINE_PATH, 'test_the_document_keeps_its_own_rules'),
    ('hardware-is-said-to-have-run', Doc, '* Hardware: NOT RUN.', '* Hardware: run.', 'test_the_document_says_hardware_not_run_and_the_first_reads_are_unknown_risk'),
    ('the-unknown-risk-is-softened', Doc, 'are of UNKNOWN risk', 'are of low risk', 'test_the_document_says_hardware_not_run_and_the_first_reads_are_unknown_risk'),
    ('the-operators-note-drops-the-unknown-risk', Doc, 'are of unknown risk**: nobody has read them', 'are of low risk**: nobody has read them', 'test_the_document_says_hardware_not_run_and_the_first_reads_are_unknown_risk'),
    ('an-unverified-item-is-dropped', Doc, '**UV4**', 'UV4', 'test_the_unverified_items_are_listed_with_their_ids'),
    ('the-recovery-sentence-is-dropped', Doc, 'boot the stick again', 'start again', 'test_the_outcome_table_has_a_row_for_every_outcome_the_page_can_show'),
    ('an-outcome-row-is-renamed', Doc, '`CMDDB MAP ... OPEN` then `HDR VER=FAULT:6 MAGIC=SKIP`', '`CMDDB MAP ... OPEN` then `HDR VER=FAULT:5 MAGIC=SKIP`', 'test_the_outcome_table_has_a_row_for_every_outcome_the_page_can_show'),
    ('a-digest-is-edited', Evidence, '`d5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0`', '`d5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e1`', 'test_the_pinned_table_is_the_refs_module'),
    ('a-pin-moves-to-another-document', Evidence, '| `qfprom.c` | `drivers/nvmem/qfprom.c` |', '| `qfprom.c` | `drivers/nvmem/qfprom2.c` |', 'test_the_pinned_table_is_the_refs_module'),
    ('the-seeded-bug-count-is-wrong', Evidence, '257 seeded bugs', '258 seeded bugs', 'test_every_seeded_bug_is_listed_and_the_counts_are_the_modules'),
    ('a-stage-count-is-wrong', Evidence, '9 by the IR audit', '8 by the IR audit', 'test_every_seeded_bug_is_listed_and_the_counts_are_the_modules'),
    ('a-seeded-bug-is-renamed', Evidence, '`sensors-last`', '`sensors-first`', 'test_every_seeded_bug_is_listed_and_the_counts_are_the_modules'),
    ('the-gated-page-is-edited', Evidence, 'PAYLOAD GPUSNAP2 GPUCC GATED BY AHB\n', 'PAYLOAD GPUSNAP2 GPUCC GATED BY AHBERR\n', 'test_the_other_pages_are_the_models_pages'),
    ('the-abort-page-is-edited', Evidence, 'PAYLOAD GPUSNAP2 RSC2 ID=FAULT:6', 'PAYLOAD GPUSNAP2 RSC2 ID=FAULT:5', 'test_the_other_pages_are_the_models_pages'),
    ('the-evidence-status-label-is-dropped', Evidence, 'Status: EXPERIMENTAL; hardware NOT RUN', 'Status: EXPERIMENTAL', 'test_the_document_keeps_its_own_rules'),
    ('a-section-is-renamed', Evidence, '## D. What QEMU shows', '## D. What QEMU saw', 'test_the_document_keeps_its_own_rules'),
    ('the-evidence-link-is-broken', Evidence, '(SP11-PAYLOAD-GPUSNAP2.md)', '(SP11-PAYLOAD-GPUSNAP3.md)', 'test_the_links_resolve'),
)


class DocMistakes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()

    def test_each_seeded_mistake_in_a_document_is_refused_by_the_check_that_names_it(self):
        names = [name for name, *_ in MISTAKES]
        self.assertEqual(len(names), len(set(names)))
        originals = {cls: cls.path.read_text(encoding='utf-8') for cls in (Doc, Evidence)}
        for name, cls, old, new, expected in MISTAKES:
            with self.subTest(mistake=name):
                original = originals[cls]
                self.assertIn(old, original, 'the pattern is not in the document')
                methods = [method for method in dir(cls) if method.startswith('test_')]
                self.assertIn(expected, methods)
                refused = set()
                for method in methods:
                    check = cls(method)
                    check.text = original.replace(old, new)
                    try:
                        getattr(check, method)()
                    except Exception:   # noqa: BLE001 - a broken document may fail a check by any exception
                        refused.add(method)
                self.assertIn(expected, refused, f'{name}: refused by {sorted(refused)}, not by {expected}')
        # The same checks pass on the documents as they are (not a vacuous refusal).
        for cls, original in originals.items():
            for method in [method for method in dir(cls) if method.startswith('test_')]:
                check = cls(method)
                check.text = original
                getattr(check, method)()


if __name__ == '__main__':
    unittest.main()
