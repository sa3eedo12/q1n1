#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests of the payload inpsnap2 (payloads/inpsnap2.c, docs/SP11-PAYLOAD-INPSNAP2.md and its evidence document).

    python3 tools/test-q1n1-sp11-payload-inpsnap2.py
    python3 tools/test-q1n1-sp11-payload-inpsnap2-doc.py          (the two documents against the header, the host model's pages and numbers, the mutants and the tests)
    INPSNAP2_REFS_DIR=<dir>[:<dir>...] SNAPINTOSH_DIR=<main checkout> python3 tools/test-q1n1-sp11-payload-inpsnap2-refs.py     (the pinned Linux copies: SKIP without them)
    python3 tools/test-q1n1-sp11-payload-qemu-inpsnap2.py         (the binary behind the runner under QEMU: SKIP without QEMU and EDK2)

  Harness       the native host test (tools/test-q1n1-sp11-payload-inpsnap2.c and its model and suites) built under ASan and UBSan at the shipped caps, and with smaller line and load
                caps (only the cap suite then)
  CompiledCode  the IR audit (tools/sp11_payload_inpsnap2_audit.py: no number is turned into a pointer, every store's root is the payload's own stack: the base, not the offset) on the real
                source and on hand-written faulty IR, the `inpsnap2` policy (the entry of the shared table, which that module also registers) on the linked binary, a fresh interpreter's view of
                the shared table against that module's policy, the stack depth, two builds that are byte for byte the same, the Makefile's build against the test's own, and the manifest tool on a chain
  Mutants       seeded bugs (tools/sp11_payload_inpsnap2_mutants.py and its `_more`): each must be rejected by the stage it names, for the reason it names

SKIPs, never passes, without clang, ld.lld, make and llvm-objdump. It writes only under build/sp11-payload-inpsnap2/. Nothing here ran on hardware.
Evidence: EXPERIMENTAL (host model and compiled code only)."""
from pathlib import Path
import json
import re
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_inpsnap2_audit as audit  # noqa: E402
import sp11_payload_inpsnap2_mutants as mutants  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-inpsnap2'
HARNESS = ROOT / 'tools' / 'test-q1n1-sp11-payload-inpsnap2.c'
SOURCE = ROOT / 'payloads' / 'inpsnap2.c'
TOOLS = ('clang', 'ld.lld', 'make', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy')
SUITES = ('table', 'unit', 'decode', 'crc', 'gate', 'stop', 'faults', 'hang', 'random', 'units', 'el')


def need_tools():
    for tool in TOOLS:
        if not lib.have(tool):
            raise unittest.SkipTest(f'{tool} not installed')


def build_harness(name, *defs):
    """The host test over the shipped source, under ASan and UBSan, with -Werror."""
    BUILD.mkdir(parents=True, exist_ok=True)
    out = BUILD / name
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-DQ1N1_PAYLOAD_HOST_TEST=1', '-Iplatform/uefi', '-Ipayloads', *defs, '-fsanitize=address,undefined',
             '-fno-sanitize-recover=undefined']
    done = lib.run(['clang', *flags, '-o', str(out), str(HARNESS)])
    if done.returncode:
        raise RuntimeError('the host test did not build:\n' + done.stderr[-2000:])
    return out


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
        results = mutants.suite_results(out)
        self.assertEqual(tuple(results), SUITES)
        self.assertEqual(set(results.values()), {'ok'})
        self.assertEqual((line_cap, load_cap), (24, 44))
        self.assertEqual((max_lines, max_loads), (21, 44), 'the nominal page is the longest one: 21 lines and every row once')
        self.assertGreater(checks, 30000)

    def test_smaller_caps(self):
        for name, defs, line_cap, load_cap in (
                ('lines22', ('-DINPSNAP2_LINE_CAP=22u',), 22, 44), ('lines20', ('-DINPSNAP2_LINE_CAP=20u',), 20, 44), ('lines12', ('-DINPSNAP2_LINE_CAP=12u',), 12, 44),
                ('lines6', ('-DINPSNAP2_LINE_CAP=6u',), 6, 44), ('lines3', ('-DINPSNAP2_LINE_CAP=3u',), 3, 44), ('lines2', ('-DINPSNAP2_LINE_CAP=2u',), 2, 44),
                ('loads40', ('-DINPSNAP2_LOAD_CAP=40u',), 24, 40), ('loads30', ('-DINPSNAP2_LOAD_CAP=30u',), 24, 30), ('loads8', ('-DINPSNAP2_LOAD_CAP=8u',), 24, 8),
                ('loads1', ('-DINPSNAP2_LOAD_CAP=1u',), 24, 1), ('both', ('-DINPSNAP2_LOAD_CAP=30u', '-DINPSNAP2_LINE_CAP=16u'), 16, 30)):
            with self.subTest(caps=name):
                out, numbers = self.run_harness(build_harness(name, *defs))
                self.assertEqual(mutants.suite_results(out), {'caps': 'ok'})
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
    'inttoptr store': ('define i64 @payload_entry(ptr noundef %a) {\n  %q = inttoptr i64 1048576 to ptr\n  store volatile i32 0, ptr %q, align 4\n  ret i64 0\n}\n', 'integer-to-pointer'),
    'inttoptr load of the wrapper': ('define i64 @payload_entry(ptr noundef %a) {\n  %q = inttoptr i64 12320772 to ptr\n  %v = load volatile i32, ptr %q, align 4\n  ret i64 0\n}\n',
                                     'integer-to-pointer'),
    'a constant inttoptr in a store': ('define i64 @payload_entry(ptr noundef %a) {\n  store volatile i32 0, ptr inttoptr (i64 1048584 to ptr), align 4\n  ret i64 0\n}\n',
                                       'not its own stack'),
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
    'a fence': ('define i64 @payload_entry(ptr noundef %a) {\n  fence seq_cst\n  ret i64 0\n}\n', 'fence'),
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
        self.assertGreater(counts['stores'], 50)
        self.assertGreaterEqual(counts['indirect_calls'], 3, 'the three ops are called, not stored through')
        self.assertEqual(counts['memory_intrinsics'], 0)

    def test_the_ir_audit_accepts_clean_ir_and_rejects_each_faulty_text(self):
        problems, _ = audit.provenance(GOOD_IR)
        self.assertEqual(problems, [])
        for name, (text, reason) in FAULTY_IR.items():
            with self.subTest(fault=name):
                problems, _ = audit.provenance(text)
                self.assertTrue(any(reason in problem for problem in problems), (name, problems))

    def test_the_binary_policy_holds(self):
        policy = lib.POLICIES['inpsnap2']
        self.assertEqual(lib.binary_violations(self.elf, self.flat, policy), [])
        self.assertEqual(policy['registers'], {'currentel'}, 'CurrentEL and nothing else: no counter, no wait')
        self.assertTrue(policy['read_only'] and not policy.get('bulk_reads') and policy['smc'] == 0)
        self.assertGreaterEqual(policy['forbid'], {'isb', 'dsb', 'dmb', 'sb'})
        self.assertLessEqual(self.flat.stat().st_size, policy['bytes'])
        self.assertEqual(self.flat.read_bytes()[:4], bytes.fromhex('5f2403d5'), 'the start stub: BTI c, then B payload_entry at offset 0')

    def test_the_shared_table_has_the_entry_on_its_own_and_it_is_the_audit_modules_policy(self):
        # The audit module registers its POLICY with setdefault, which would hide a missing or a different entry of the shared table: a fresh interpreter imports the shared module alone.
        code = f'import json, sys; sys.path.insert(0, {str(ROOT / "tools")!r}); import sp11_payload_testlib as lib; p = lib.POLICIES.get("inpsnap2"); '
        code += 'print(json.dumps(None if p is None else {k: sorted(v) if isinstance(v, set) else v for k, v in p.items()}, sort_keys=True))'
        done = lib.run([sys.executable, '-B', '-c', code])
        self.assertEqual(done.returncode, 0, done.stderr[-500:])
        want = {key: sorted(value) if isinstance(value, set) else value for key, value in audit.POLICY.items()}
        self.assertEqual(json.loads(done.stdout), want, 'tools/sp11_payload_testlib.py must hold the same inpsnap2 policy as tools/sp11_payload_inpsnap2_audit.py')

    def test_the_policy_refuses_what_a_read_only_payload_may_not_hold(self):
        problems = lib.binary_violations(self.elf, self.flat, dict(lib.POLICIES['inpsnap2'], registers={'currentel', 'cntfrq_el0', 'par_el1'}))
        self.assertTrue(any('registers read' in problem for problem in problems), problems)
        problems = lib.binary_violations(self.elf, self.flat, dict(lib.POLICIES['inpsnap2'], smc=1))
        self.assertTrue(any('0 smc instructions' in problem for problem in problems) or any('smc' in problem for problem in problems), problems)
        problems = lib.binary_violations(self.elf, self.flat, dict(lib.POLICIES['inpsnap2'], bytes=1024))
        self.assertTrue(any('bytes, the policy allows 1024' in problem for problem in problems), problems)

    def test_the_policy_refuses_the_other_payloads(self):
        for other in ('state', 'tsnap', 'timer'):
            with self.subTest(binary=other):
                done, elf, flat = lib.build_payload(ROOT / 'payloads' / f'{other}.c', BUILD / other)
                self.assertEqual(done.returncode, 0, done.stderr[-800:])
                self.assertTrue(lib.binary_violations(elf, flat, lib.POLICIES['inpsnap2']), 'the policy of inpsnap2 holds only what inpsnap2 holds')

    def test_the_stack_the_payload_needs_is_far_below_what_the_abi_leaves(self):
        sizes = audit.frame_sizes(SOURCE, BUILD / 'stack')
        disassembly = lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(self.elf)]).stdout
        depth, path = audit.stack_depth(sizes, disassembly)
        self.assertEqual(path[0], 'payload_entry')
        self.assertLess(depth, audit.STACK_USABLE, path)
        self.assertLess(depth, 2048, f'the deepest chain of frames is {depth} bytes: {path}')

    def test_two_builds_are_byte_for_byte_the_same(self):
        done, elf, flat = lib.build_payload(SOURCE, BUILD / 'b')
        self.assertEqual(done.returncode, 0)
        self.assertEqual(flat.read_bytes(), self.flat.read_bytes())
        self.assertEqual(elf.read_bytes(), self.elf.read_bytes())

    def test_the_makefile_builds_the_same_bytes(self):
        out = BUILD / 'make-out'
        shutil.rmtree(out, ignore_errors=True)
        done = lib.run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j1', f'{out.relative_to(ROOT)}/payloads/inpsnap2.bin'])
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-1500:])
        self.assertEqual((out / 'payloads' / 'inpsnap2.bin').read_bytes(), self.flat.read_bytes())
        plan = lib.run(['make', '-n', '-f', 'platform/uefi/Makefile', f'OUT={(BUILD / "plan-out").relative_to(ROOT)}', 'payloads'])
        self.assertEqual(plan.returncode, 0, plan.stderr[-800:])
        self.assertIn('payloads/inpsnap2.c', plan.stdout, 'the wildcard of the Makefile finds the new file with no edit of the Makefile')

    def test_the_stick_name_is_inpsnap2_and_a_chain_keeps_the_order_it_is_given(self):
        # `inpsnap2` has eight letters, so the file on the stick is INPSNAP2.BIN, the same bytes (the runner's names are 8.3).
        done, _, tsnap = lib.build_payload(ROOT / 'payloads' / 'tsnap.c', BUILD / 'tsnap-chain')
        self.assertEqual(done.returncode, 0)
        for name, files in (('alone', [self.flat]), ('chain', [tsnap, self.flat])):
            out = BUILD / f'stick-{name}'
            shutil.rmtree(out, ignore_errors=True)
            made = lib.run(['python3', '-B', 'tools/sp11_payload_manifest.py', '--out-dir', str(out.relative_to(ROOT))] + [str(f.relative_to(ROOT)) for f in files])
            self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
            self.assertTrue((out / 'SP11' / 'INPSNAP2.BIN').is_file(), made.stdout)
            self.assertEqual((out / 'SP11' / 'INPSNAP2.BIN').read_bytes(), self.flat.read_bytes())
            self.assertIn('INPSNAP2.BIN', made.stdout)
        self.assertLess(made.stdout.index('TSNAP.BIN'), made.stdout.index('INPSNAP2.BIN'), 'the tool keeps the order it is given')


class Mutants(unittest.TestCase):
    """Every seeded bug is refused by the stage it names, for the reason it names. The mutant files are written below build/sp11-payload-inpsnap2/mutants/<name>/."""

    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.all = mutants.all_mutants(ROOT)

    def test_every_needle_is_in_the_sources_exactly_once(self):
        texts = {f: (ROOT / f).read_text(encoding='utf-8') for f in (mutants.C, mutants.H)}
        for mutant in self.all:
            self.assertEqual(mutants.stale(mutant, texts), [], mutant.name)
            for _, old, new in mutant.edits:
                self.assertNotEqual(old, new, mutant.name)

    def test_the_names_are_unique_and_every_stage_is_one_the_runner_knows(self):
        names = [mutant.name for mutant in self.all]
        self.assertEqual(len(names), len(set(names)))
        self.assertLessEqual({mutant.stage for mutant in self.all}, set(mutants.STAGES))
        self.assertGreaterEqual(len(names), 400)
        for mutant in self.all:
            with self.subTest(mutant=mutant.name):
                self.assertTrue(mutant.reason, 'a seeded bug names the reason it must be refused for')
                self.assertNotIn('TBD', mutant.reason)
                if mutant.stage == 'caps':
                    self.assertTrue(mutant.defs and set(mutant.suites) == {'caps'})
                if mutant.stage in ('harness', 'caps'):
                    self.assertLessEqual(set(mutant.suites), set(SUITES) | {'caps'})
        for suite in SUITES:
            self.assertTrue(any(suite in mutant.suites for mutant in self.all if mutant.stage == 'harness') or suite in ('hang', 'random', 'faults', 'crc', 'gate'),
                            f'no seeded bug names the {suite} suite')

    def test_the_sources_as_they_are_pass_the_host_test(self):
        source = mutants.apply(None, BUILD / 'mutants' / 'baseline' / 'src')
        built, binary = mutants.build_harness(source, BUILD / 'mutants' / 'baseline' / 'harness')
        self.assertEqual(built.returncode, 0, built.stderr[-800:])
        done = lib.run([str(binary)], timeout=300)
        self.assertEqual(done.returncode, 0, done.stdout[-800:] + done.stderr[-800:])
        shutil.rmtree(BUILD / 'mutants' / 'baseline', ignore_errors=True)

    def test_each_seeded_bug_is_refused_for_its_own_reason(self):
        for mutant in self.all:
            with self.subTest(mutant=mutant.name, stage=mutant.stage):
                work = BUILD / 'mutants' / mutant.name
                try:
                    refused, why = mutants.check(mutant, work, ROOT)
                finally:
                    shutil.rmtree(work, ignore_errors=True)
                self.assertTrue(refused, f'{mutant.name}: {why}')


if __name__ == '__main__':
    unittest.main()
