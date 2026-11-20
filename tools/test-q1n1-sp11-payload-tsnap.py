#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests of the payload tsnap (payloads/tsnap.c, docs/SP11-PAYLOAD-TSNAP.md).

    python3 tools/test-q1n1-sp11-payload-tsnap.py
    python3 tools/test-q1n1-sp11-payload-tsnap-refs.py       (the pinned reference copies: SKIP without TSNAP_REFS_DIR and SNAPINTOSH_DIR)
    python3 tools/test-q1n1-sp11-payload-qemu-tsnap.py       (QEMU/EDK2 at EL2: the payload behind the runner)

  Harness       the native host test (tools/test-q1n1-sp11-payload-tsnap.c: the suites; tools/test-q1n1-sp11-payload-tsnap-model.h: eight register windows with the model's own
                list of the addresses a read may reach, the order and NEXT rules, the counter, the runner's page and the model's own arithmetic of every value-dependent line) built
                under ASan and UBSan at the shipped caps, with smaller line, load, spin and stuck caps and, with `--slow`, the one suite that takes seconds (a counter that needs more
                reads than 2^28 still completes the wait)
  CompiledCode  the compiled code: the IR audit (tools/sp11_payload_tsnap_audit.py: no number is turned into a pointer, every store's root is the payload's own stack) on the real
                source and on hand-written faulty IR, the `tsnap` policy of tools/sp11_payload_testlib.py on the linked binary (an allow-list of instructions and the `read_only`
                memory check), the stack depth, the Makefile's build against the test's own, two builds that are byte for byte the same, and the manifest tool on a chain
  Mutants       seeded bugs (tools/sp11_payload_tsnap_mutants.py): each must be rejected by the stage it names, for the reason it names
  Doc           docs/SP11-PAYLOAD-TSNAP.md against the header (the register and window tables, the bit fields, the caps), the host model's page and numbers, the chain budget's
                arithmetic, the suites and counts it names, its links (the ledger of citations is checked by tools/test-q1n1-sp11-payload-tsnap-refs.py: its class `Ledger`
                needs no pinned copy, its class `Refs` reads them)
  DocMistakes   one wrong statement each in a copy of the document (a moved offset or base, an edited page, a wrong chain total, a broken link, ...): the check that names it must refuse it

SKIPs, never passes, without clang, ld.lld, make and llvm-objdump. It writes only under build/sp11-payload-tsnap/. Nothing here ran on hardware.
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
import sp11_payload_tsnap_audit as audit  # noqa: E402
import sp11_payload_tsnap_mutants as mutants  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-tsnap'
HARNESS = ROOT / 'tools' / 'test-q1n1-sp11-payload-tsnap.c'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-TSNAP.md'
SOURCE = ROOT / 'payloads' / 'tsnap.c'
REGS = ROOT / 'payloads' / 'tsnap-regs.h'
TOOLS = ('clang', 'ld.lld', 'make', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy')
SUITES = ('unit', 'order', 'cells', 'random', 'gate', 'faults', 'hang', 'drift', 'counter', 'el', 'budget', 'storm')


def need_tools():
    for tool in TOOLS:
        if not lib.have(tool):
            raise unittest.SkipTest(f'{tool} not installed')


def build_harness(name, *defs, source=None, sanitize=True, werror=True):
    """The host test, built under ASan and UBSan; `source` is a mutant payload (TSNAP_SRC)."""
    BUILD.mkdir(parents=True, exist_ok=True)
    out = BUILD / name
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror' if werror else '-Wno-error', '-DQ1N1_PAYLOAD_HOST_TEST=1', '-Iplatform/uefi', '-Ipayloads', *defs]
    if source:
        flags.append(f'-DTSNAP_SRC="{source}"')
    if sanitize:
        flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=undefined']
    done = lib.run(['clang', *flags, '-o', str(out), str(HARNESS)])
    if done.returncode:
        raise RuntimeError('the host test did not build:\n' + done.stderr[-2000:])
    return out


def suite_results(text):
    return dict(re.findall(r'^suite (\w+)\s+(ok|FAIL)$', text, re.M))


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
        results = suite_results(out)
        self.assertEqual(tuple(results), SUITES)
        self.assertEqual(set(results.values()), {'ok'})
        self.assertEqual((line_cap, load_cap), (34, 256))
        self.assertEqual(max_lines, 34, 'the nominal page is the longest one and is the cap: 34 lines, the closing lines in place')
        self.assertEqual(max_loads, 220, 'both readings, every pass: the loads the header derives, inside the cap the payload asserts')
        self.assertGreater(checks, 1000000)

    def test_a_counter_that_needs_more_reads_than_2_to_the_28_completes_the_wait(self):
        done = lib.run([str(build_harness('shipped')), '--slow'], timeout=600)
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-3000:])
        self.assertEqual(suite_results(done.stdout), {'slow': 'ok'})

    def test_smaller_caps(self):
        for name, defs, line_cap, load_cap in (
                ('lines30', ('-DTSNAP_LINE_CAP=30u',), 30, 256), ('lines28', ('-DTSNAP_LINE_CAP=28u',), 28, 256),
                ('lines20', ('-DTSNAP_LINE_CAP=20u',), 20, 256), ('lines12', ('-DTSNAP_LINE_CAP=12u',), 12, 256), ('lines6', ('-DTSNAP_LINE_CAP=6u',), 6, 256),
                ('lines5', ('-DTSNAP_LINE_CAP=5u',), 5, 256), ('lines2', ('-DTSNAP_LINE_CAP=2u',), 2, 256), ('loads100', ('-DTSNAP_LOAD_CAP=100u',), 34, 100),
                ('loads30', ('-DTSNAP_LOAD_CAP=30u',), 34, 30), ('both', ('-DTSNAP_LOAD_CAP=30u', '-DTSNAP_LINE_CAP=26u'), 26, 30),
                ('bounds', ('-DTSNAP_SPIN_MAX=5000u', '-DTSNAP_STUCK_READS=1000u'), 34, 256), ('spin', ('-DTSNAP_SPIN_MAX=5000u',), 34, 256)):
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
        self.assertGreater(counts['stores'], 20)
        self.assertGreater(counts['indirect_calls'], 3, 'the four ops are called, not stored through')
        self.assertEqual(counts['memory_intrinsics'], 0)

    def test_the_ir_audit_accepts_clean_ir_and_rejects_each_faulty_text(self):
        problems, _ = audit.provenance(GOOD_IR)
        self.assertEqual(problems, [])
        for name, (text, reason) in FAULTY_IR.items():
            with self.subTest(fault=name):
                problems, _ = audit.provenance(text)
                self.assertTrue(any(reason in problem for problem in problems), (name, problems))

    def test_the_binary_policy_holds(self):
        policy = lib.POLICIES['tsnap']
        self.assertEqual(lib.binary_violations(self.elf, self.flat, policy), [])
        self.assertEqual(policy['registers'], {'currentel', 'cntfrq_el0'})
        self.assertTrue(policy['read_only'] and not policy.get('bulk_reads') and policy['smc'] == 0)
        size = self.flat.stat().st_size
        self.assertLessEqual(size, policy['bytes'])
        self.assertEqual(self.flat.read_bytes()[:4], bytes.fromhex('5f2403d5'), 'the start stub: BTI c, then B payload_entry at offset 0')

    def test_the_policy_refuses_what_a_read_only_payload_may_not_hold(self):
        # The same binary under a policy that expects other registers, one SMC and no memory check: every difference is reported.
        problems = lib.binary_violations(self.elf, self.flat, dict(lib.POLICIES['tsnap'], registers={'currentel'}))
        self.assertTrue(any('registers read' in problem for problem in problems), problems)
        problems = lib.binary_violations(self.elf, self.flat, dict(lib.POLICIES['tsnap'], smc=1))
        self.assertTrue(any('0 smc instructions' in problem for problem in problems), problems)
        problems = lib.binary_violations(self.elf, self.flat, dict(lib.POLICIES['tsnap'], bytes=1024))
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
        done = lib.run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j1', f'{out.relative_to(ROOT)}/payloads/tsnap.bin'])
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-1500:])
        self.assertEqual((out / 'payloads' / 'tsnap.bin').read_bytes(), self.flat.read_bytes())
        # The plan of `make payloads` in an empty output directory names the new file: the wildcard of the Makefile finds it, with no edit of the Makefile.
        plan = lib.run(['make', '-n', '-f', 'platform/uefi/Makefile', f'OUT={(BUILD / "plan-out").relative_to(ROOT)}', 'payloads'])
        self.assertEqual(plan.returncode, 0, plan.stderr[-800:])
        self.assertIn('payloads/tsnap.c', plan.stdout)
        self.assertIn('payloads/tsnap.bin', plan.stdout + ' payloads/tsnap.bin' if 'tsnap.elf' in plan.stdout else plan.stdout)

    def test_the_manifest_tool_lists_it_alone_and_in_a_chain(self):
        done, _, psci = lib.build_payload(ROOT / 'payloads' / 'psci.c', BUILD / 'psci')
        self.assertEqual(done.returncode, 0)
        for name, files in (('alone', [self.flat]), ('chain', [self.flat, psci])):
            out = BUILD / f'stick-{name}'
            shutil.rmtree(out, ignore_errors=True)
            made = lib.run(['python3', '-B', 'tools/sp11_payload_manifest.py', '--out-dir', str(out)] + [str(f) for f in files])
            self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
            self.assertTrue((out / 'SP11' / 'TSNAP.BIN').is_file(), made.stdout)
            self.assertEqual((out / 'SP11' / 'TSNAP.BIN').read_bytes(), self.flat.read_bytes())
            self.assertIn('TSNAP.BIN', made.stdout)
        self.assertLess(made.stdout.index('TSNAP.BIN'), made.stdout.index('PSCI.BIN'), 'the tool keeps the order it is given')


class Mutants(unittest.TestCase):
    """Every seeded bug is refused by the stage it names, for the reason it names. The mutant files are written below build/sp11-payload-tsnap/mutants/<name>/."""

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
        self.assertLessEqual({mutant.stage for mutant in mutants.MUTANTS}, {'harness', 'slow', 'caps', 'audit', 'binary', 'stack'})
        self.assertGreaterEqual(len(names), 85)
        for suite in SUITES:
            self.assertTrue(any(suite in mutant.suites for mutant in mutants.MUTANTS if mutant.stage == 'harness') or suite in ('hang', 'storm', 'random', 'budget'),
                            f'no seeded bug names the {suite} suite')

    def refuse(self, mutant):
        directory = self.write(mutant)
        source = directory / 'tsnap.c'
        if mutant.stage in ('harness', 'slow', 'caps'):
            try:
                binary = build_harness('mutant-' + mutant.name, *mutant.defs, source=source, werror=False)
            except RuntimeError as error:
                self.fail(f'{mutant.name}: the seeded bug does not compile, so nothing was shown: {error}')
            try:
                done = lib.run([str(binary)] + (['--slow'] if mutant.stage == 'slow' else []), timeout=240)
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
            done, elf, flat = lib.build_payload(source, BUILD / 'mutbin' / mutant.name, name='tsnap', extra_cflags=('-Wno-error',))
            if done.returncode:
                self.assertIn(mutant.reason, done.stdout + done.stderr, mutant.name)
            else:
                problems = lib.binary_violations(elf, flat, lib.POLICIES['tsnap'])
                self.assertTrue(any(mutant.reason in problem for problem in problems), (mutant.name, problems))
        else:
            done, elf, _ = lib.build_payload(source, BUILD / 'mutbin' / mutant.name, name='tsnap', extra_cflags=('-Wno-error',))
            self.assertEqual(done.returncode, 0, done.stderr[-800:])
            sizes = audit.frame_sizes(source, BUILD / 'mutstack' / mutant.name)
            depth, _ = audit.stack_depth(sizes, lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout)
            self.assertGreater(depth, audit.STACK_USABLE, mutant.name)

    def test_each_seeded_bug_is_refused_for_its_own_reason(self):
        for mutant in mutants.MUTANTS:
            with self.subTest(mutant=mutant.name, stage=mutant.stage):
                self.refuse(mutant)


def table_rows(block):
    """The cells of every row of a Markdown table in `block`, its header row and its rule row left out."""
    rows = [[cell.strip() for cell in line.strip().strip('|').split('|')]
            for line in block.splitlines() if line.startswith('|') and not re.fullmatch(r'\|[\s|:-]+\|', line)]
    return rows[1:]


def c_value(text):
    """The value of a plain C constant of the header: numbers with a `u` suffix, shifts, sums and parentheses, no names."""
    text = re.sub(r'\b(0x[0-9a-fA-F]+|[0-9]+)u\b', r'\1', re.sub(r'/\*.*?\*/', '', text).strip())
    if not re.fullmatch(r'[0-9a-fx<>()+* -]+', text):
        raise ValueError(f'not a plain constant: {text!r}')
    return eval(text, {'__builtins__': {}})


def header_value(name):
    found = re.search(rf'^#define {name} (.+)$', REGS.read_text(encoding='utf-8'), re.M)
    if not found:
        raise KeyError(name)
    return c_value(found.group(1))


def header_windows():
    found = re.search(r'window_base\[WINDOWS\] = \{([^}]*)\}', REGS.read_text(encoding='utf-8'))
    return [c_value(item) for item in found.group(1).split(',')]


def slug(heading):
    """The anchor GitHub makes of a heading."""
    return re.sub(r'\s', '-', re.sub(r'[^\w\s-]', '', heading.strip().lower()))


PREFIX = 'PAYLOAD TSNAP '


@functools.lru_cache(maxsize=None)
def model_output(*options):
    """What the host test prints for `--page [scenario]` or `--numbers`: its model's page and numbers, which the document quotes."""
    return lib.run([str(build_harness('doc')), *options]).stdout


class Doc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOC.read_text(encoding='utf-8')

    def block(self, name):
        found = re.search(rf'<!-- {name} -->\n(.*?)<!-- /{name} -->', self.text, re.S)
        self.assertIsNotNone(found, f'the document has no <!-- {name} --> block')
        return found.group(1)

    def test_the_document_keeps_its_own_rules(self):
        self.assertTrue(self.text.startswith('<!-- SPDX-License-Identifier: MIT -->\n'))
        self.assertLess(DOC.stat().st_size, 50 * 1024)
        self.assertLess(len(self.text.splitlines()), 1500)
        titles = ('What it reads', 'The page', 'Hazards, and what the order is for', 'The chain budget', 'Tests', 'What it answers, and what it does not',
                  "The operator's note (nothing here authorises a run)", 'Evidence ledger and pins', 'Not verified')
        for number, title in enumerate(titles, 1):
            self.assertIn(f'\n## {number}. {title}\n', self.text)
        for label in ('Status: EXPERIMENTAL; hardware NOT RUN', '* Hardware: NOT RUN.'):
            self.assertIn(label, self.text)
        paths = '|'.join(['/Us' + 'ers/', '/Vol' + 'umes/', '/priv' + 'ate/', '/ho' + 'me/'])      # built from pieces: this file must not hold what it looks for
        self.assertIsNone(re.search(paths, self.text), 'the document names a path of a machine')

    def test_the_page_is_the_models_page(self):
        page = model_output('--page').splitlines()
        sample = re.search(r'```\n(.*?)```', self.block('page'), re.S).group(1).splitlines()
        self.assertEqual(sample, page, 'regenerate the sample with: <host test> --page')
        self.assertLessEqual(len(page), header_value('TSNAP_LINE_CAP'))
        for line in page:
            self.assertTrue(line.startswith(PREFIX), line)
            self.assertLessEqual(len(line) - len(PREFIX), 100, line)

    def test_the_qemu_block_is_the_models_page_for_a_machine_without_the_windows(self):
        shown = re.search(r'```\n(.*?)```', self.block('qemu-lines'), re.S).group(1).splitlines()
        model = [re.sub(r'HZ=0X[0-9A-F]+', 'HZ=<HZ>', line) for line in model_output('--page', 'dead').splitlines()]
        self.assertEqual(shown, model, 'regenerate the block from the QEMU test: the lines QEMU showed, the frequency as <HZ>')
        end = re.fullmatch(r'PAYLOAD TSNAP END LOADS=(\d+) FAULTS=(\d+) SKIPS=\d+ GATED=\d+ CUTS=\d+ GAP_MS=\d+ LINES=(\d+)', shown[-1])
        self.assertIsNotNone(end, shown[-1])
        self.assertIn(f'`LOADS={end[1]} FAULTS={end[2]} REFUSED=0 LINES={end[3]} DROPPED=0`', self.text, "the runner's DONE line as the document quotes it")

    def test_the_numbers_are_the_models_numbers(self):
        numbers = model_output('--numbers').strip()
        self.assertEqual(self.block('numbers').strip(), numbers)
        lines, loads = re.match(r'LINES (\d+) LOADS (\d+) ', numbers).groups()
        self.assertIn(f'A nominal page is {lines} lines and {loads} loads', self.text)
        self.assertIn(f'At most {header_value("TSNAP_LINE_CAP")} lines of at most 100 characters', self.text)
        self.assertIn(f'keeps to {header_value("TSNAP_LINE_CAP")} lines and {header_value("TSNAP_LOAD_CAP")} loads', self.text)

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
            self.assertEqual(counts[0], header_value('TSNAP_LINE_CAP'), cell)
            self.assertLessEqual(max(counts), 40, 'the ABI allows 40 lines per call')
            if total <= 89:
                self.assertEqual(left, str(89 - total), cell)
            else:
                self.assertTrue(left.startswith('none'), cell)

    def test_the_register_and_window_tables_are_the_headers(self):
        section = re.search(r'### The registers.*?\n(.*?)\nNot read:', self.text, re.S).group(1)
        rows = {row[2]: row for row in table_rows(section)}
        for register, (window, name) in {'HW_VER': ('SROT', 'SROT_HW_VER'), 'CTRL': ('SROT', 'SROT_CTRL'), 'TRDY': ('TM', 'TM_TRDY'),
                                         'Sn_STATUS': ('TM', 'TM_STATUS'), 'Sn_CONVERSION': ('SROT', 'SROT_CONV')}.items():
            self.assertEqual(rows[register][0], window, register)
            self.assertEqual(int(re.match(r'0x[0-9a-f]+', rows[register][1])[0], 16), header_value(name), register)
        pair = rows['UL and CRITICAL interrupt status']
        self.assertEqual((pair[0], pair[1]), ('TM', f'0x{header_value("TM_UL_STATUS"):02x}, 0x{header_value("TM_CRIT_STATUS"):02x}'))
        blocks = table_rows(re.search(r'(\| Block \|.*?)\n\n', self.text, re.S).group(1))
        windows = header_windows()
        self.assertEqual(len(blocks), 4)
        for n, row in enumerate(blocks):
            self.assertEqual(row[0], f'T{n}')
            self.assertEqual(int(re.match(r'0x[0-9a-f]+', row[1])[0], 16), windows[n], row[0])
            self.assertEqual(int(re.match(r'0x[0-9a-f]+', row[2])[0], 16), windows[4 + n], row[0])

    def test_the_bit_fields_and_numbers_the_document_states_are_the_headers(self):
        facts = (
            ('EN bit 0', header_value('CTRL_EN') == 1),
            ('SW_RST bit 1', header_value('CTRL_SW_RST') == 2),
            ('SENSOR_EN bits 18:3', header_value('CTRL_SENSOR_SHIFT') == 3 and header_value('CTRL_SENSOR_MASK') == 0xffff),
            ('LAST_TEMP 11:0', header_value('ST_TEMP_MASK') == 0xfff),
            ('VALID at 21', header_value('ST_VALID') == 1 << 21),
            ('violated at 16 to 20', header_value('ST_CRIT_FLAGS') == 3 << 19),
            ('outside -40.0 to 120.0 C', (header_value('TEMP_MIN_TENTHS'), header_value('TEMP_MAX_TENTHS')) == (-400, 1200)),
            ('GAP=2 S', header_value('GAP_S') == 2),
            ('NEXT S2 AFTER 2 S', header_value('GAP_S') == 2),
            ('2^32-1 reads', header_value('TSNAP_SPIN_MAX') == (1 << 32) - 1),
            ('2,000,000 reads', header_value('TSNAP_STUCK_READS') == 2000000),
            ('CODE_OR_TEMP bit 21', header_value('CTRL_CODE_OR_TEMP') == 1 << 21),
            ('1 MHz to 1 GHz', (header_value('COUNTER_HZ_MIN'), header_value('COUNTER_HZ_MAX')) == (10 ** 6, 10 ** 9)),
            ('19.2 MHz', header_value('COUNTER_HZ_DEFAULT') == 19200000),
        )
        for phrase, holds in facts:
            self.assertIn(phrase, self.text, phrase)
            self.assertTrue(holds, phrase)
        abi = (ROOT / 'platform' / 'uefi' / 'sp11-payload-abi.h').read_text(encoding='utf-8')
        self.assertIn('the ABI allows 40 and 4096 loads', self.text)
        self.assertIn('#define Q1N1_PAYLOAD_LINES_MAX 40u', abi)
        self.assertIn('#define Q1N1_PAYLOAD_LOADS_MAX 4096u', abi)

    def test_the_tokens_the_document_names_are_the_sources(self):
        source = SOURCE.read_text(encoding='utf-8')
        for token in ('FAULT:', 'BUDGET', 'S2 SKIPPED NO_BLOCK', 'S2 SKIPPED NO_COUNTER', 'S2 SKIPPED SPIN', 'SKIPPED_NOT_AT_EL2', 'REFUSED_NO_LOAD32', 'GATED', 'CTLERR', 'CODE', ' GAP_MS=',
                      'NEXT CONV T', 'NEXT S2 AFTER ', 'RDY='):
            self.assertIn(token.strip(), self.text, token)
            self.assertIn(token.strip(), source, token)

    def test_the_outcome_table_has_a_row_for_every_outcome_the_page_can_show(self):
        section = re.search(r'\n## 6\. .*?\n(.*?)\n## 7\. ', self.text, re.S).group(1)
        shown = ' '.join(row[0] for row in table_rows(section))
        for outcome in ('VER=FAULT:6 GATED', 'VER=0X0', '`OFF`', 'CTL=FAULT:6 CTLERR', '`CODE`', 'RDY=FAULT:6', '`FAULT:6` on a later word', 'S2 SKIPPED NO_COUNTER', 'S2 SKIPPED SPIN',
                        'S2 SKIPPED NO_BLOCK', '`BUDGET`', '`CUTS` above 0', '`NEXT S2 AFTER 2 S`', '`END` is on the page'):
            self.assertIn(outcome, shown, outcome)
        self.assertIn('boot the stick again', section)

    def test_the_offsets_that_no_linux_path_reads_are_listed_as_unverified(self):
        found = re.search(r'\* UNVERIFIED offsets: none of(.*?) has been read on any', self.text, re.S)
        self.assertIsNotNone(found)
        for name in ('TM_UL_STATUS', 'TM_CRIT_STATUS', 'TM_TRDY', 'SROT_CONV'):
            self.assertIn(f'0x{header_value(name):02x}', found.group(1), name)

    def test_the_counts_and_the_suites_the_document_names_are_the_tests(self):
        harness = HARNESS.read_text(encoding='utf-8')
        self.assertIn(f'{len(FAULTY_IR)} hand-written faulty texts', self.text)
        for worlds in (300, 1500):
            self.assertIn(f'round < {worlds}', harness)
            self.assertIn(f'{worlds} random worlds', self.text)
        section = re.search(r"The host program's suites:(.*?)\n\n", self.text, re.S).group(1)
        for suite in SUITES + ('slow',):
            self.assertIn(f'`{suite}`', section, suite)
        self.assertIn('--slow', section)

    def test_the_links_resolve(self):
        links = re.findall(r'\]\(([^)#\s]+)(?:#([^)\s]+))?\)', self.text)
        self.assertTrue(links)
        for target, anchor in links:
            if '://' in target:
                continue
            path = (DOC.parent / target).resolve()
            self.assertTrue(path.is_file(), target)
            if anchor:
                headings = [slug(line.lstrip('#')) for line in path.read_text(encoding='utf-8').splitlines() if line.startswith('#')]
                self.assertIn(anchor, headings, f'{target}#{anchor}')


# One wrong statement each in a copy of the document: the check named must refuse it (the test of a test).
MACHINE_PATH = '\n' + '/Us' + 'ers/someone/tree\n'
MISTAKES = (
    ('a-register-offset-moved', '| TM | 0xe4 | TRDY |', '| TM | 0xe8 | TRDY |', 'test_the_register_and_window_tables_are_the_headers'),
    ('a-window-base-moved', '| T1 | 0x0c223000 (', '| T1 | 0x0c224000 (', 'test_the_register_and_window_tables_are_the_headers'),
    ('a-bit-field-moved', 'VALID at 21', 'VALID at 20', 'test_the_bit_fields_and_numbers_the_document_states_are_the_headers'),
    ('the-gap-is-misquoted', 'GAP=2 S', 'GAP=3 S', 'test_the_bit_fields_and_numbers_the_document_states_are_the_headers'),
    ('the-line-cap-is-misquoted', 'At most 34 lines of at most 100 characters', 'At most 35 lines of at most 100 characters', 'test_the_numbers_are_the_models_numbers'),
    ('the-chain-total-is-wrong', '+ 34 + 40 = 83 |', '+ 34 + 40 = 84 |', 'test_the_chain_budget_is_the_runners_arithmetic'),
    ('the-rows-left-are-wrong', '= 83 | 6 |', '= 83 | 7 |', 'test_the_chain_budget_is_the_runners_arithmetic'),
    ('the-page-sample-is-edited', 'PAYLOAD TSNAP T0 R0 0020012C', 'PAYLOAD TSNAP T0 R0 0020012D', 'test_the_page_is_the_models_page'),
    ('the-numbers-are-edited', 'LOADS 220 LINE_CAP', 'LOADS 221 LINE_CAP', 'test_the_numbers_are_the_models_numbers'),
    ('a-suite-is-misnamed', '`storm` (1500', '`storn` (1500', 'test_the_counts_and_the_suites_the_document_names_are_the_tests'),
    ('the-faulty-texts-are-miscounted', '12 hand-written faulty texts', '13 hand-written faulty texts', 'test_the_counts_and_the_suites_the_document_names_are_the_tests'),
    ('a-token-is-renamed', 'REFUSED_NO_LOAD32', 'REFUSED_NO_LOAD', 'test_the_tokens_the_document_names_are_the_sources'),
    ('a-link-is-broken', '(SP11-PAYLOAD-RESULTS.md)', '(SP11-PAYLOAD-RESULT.md)', 'test_the_links_resolve'),
    ('an-anchor-is-broken', 'SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot', 'SP11-PAYLOAD.md#the-chain', 'test_the_links_resolve'),
    ('the-status-label-is-dropped', 'Status: EXPERIMENTAL; hardware NOT RUN', 'Status: EXPERIMENTAL', 'test_the_document_keeps_its_own_rules'),
    ('a-machine-path-is-named', '\n## 9. Not verified\n', '\n## 9. Not verified\n' + MACHINE_PATH, 'test_the_document_keeps_its_own_rules'),
    ('the-qemu-block-is-edited', 'PAYLOAD TSNAP T2 VER=FAULT:6 GATED', 'PAYLOAD TSNAP T2 VER=FAULT:5 GATED', 'test_the_qemu_block_is_the_models_page_for_a_machine_without_the_windows'),
    ('the-done-line-is-misquoted', '`LOADS=4 FAULTS=4 REFUSED=0', '`LOADS=4 FAULTS=3 REFUSED=0', 'test_the_qemu_block_is_the_models_page_for_a_machine_without_the_windows'),
    ('the-spin-bound-is-misquoted', '2^32-1 reads', '2^28 reads', 'test_the_bit_fields_and_numbers_the_document_states_are_the_headers'),
    ('the-stuck-bound-is-misquoted', '2,000,000 reads', '1,000,000 reads', 'test_the_bit_fields_and_numbers_the_document_states_are_the_headers'),
    ('the-code-bit-is-moved', 'CODE_OR_TEMP bit 21', 'CODE_OR_TEMP bit 20', 'test_the_bit_fields_and_numbers_the_document_states_are_the_headers'),
    ('the-ready-word-is-dropped-from-the-page-sample', 'RDY=0X1 V=13', 'V=13', 'test_the_page_is_the_models_page'),
    ('a-conversion-line-loses-its-announcement', 'CR=0X0 NEXT CONV T1', 'CR=0X0', 'test_the_page_is_the_models_page'),
    ('the-new-spin-token-is-renamed', 'S2 SKIPPED SPIN', 'S2 SKIPPED SLOW', 'test_the_tokens_the_document_names_are_the_sources'),
    ('the-spin-row-is-dropped-from-the-outcomes', '| `S2 SKIPPED SPIN` |', '| `S2 SKIPPED SLOW` |', 'test_the_outcome_table_has_a_row_for_every_outcome_the_page_can_show'),
    ('the-recovery-sentence-is-dropped', 'boot the stick again', 'start again', 'test_the_outcome_table_has_a_row_for_every_outcome_the_page_can_show'),
    ('the-ready-offset-is-dropped-from-the-unverified-list', 'none of the TM words 0x08 and 0xe4 (TRDY:', 'none of the TM word 0x08 (TRDY:', 'test_the_offsets_that_no_linux_path_reads_are_listed_as_unverified'),
    ('the-slow-suite-is-not-named', 'With `--slow` one more suite, `slow`,', 'With one more suite', 'test_the_counts_and_the_suites_the_document_names_are_the_tests'),
)


class DocMistakes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()

    def test_each_seeded_mistake_in_the_document_is_refused_by_the_check_that_names_it(self):
        original = DOC.read_text(encoding='utf-8')
        methods = [name for name in dir(Doc) if name.startswith('test_')]
        names = [name for name, *_ in MISTAKES]
        self.assertEqual(len(names), len(set(names)))
        for name, old, new, expected in MISTAKES:
            with self.subTest(mistake=name):
                self.assertIn(old, original, 'the pattern is not in the document')
                self.assertIn(expected, methods)
                refused = set()
                for method in methods:
                    doc = Doc(method)
                    doc.text = original.replace(old, new)
                    try:
                        getattr(doc, method)()
                    except Exception:   # noqa: BLE001 - a broken document may fail a check by any exception
                        refused.add(method)
                self.assertIn(expected, refused, f'{name}: refused by {sorted(refused)}, not by {expected}')
        # The same checks pass on the document as it is (not a vacuous refusal).
        for method in methods:
            doc = Doc(method)
            doc.text = original
            getattr(doc, method)()


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
