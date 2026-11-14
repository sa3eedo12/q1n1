#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The chain and the psci payload of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD.md): their native
tests, seeded bugs, seeded-bad binaries, the manifest tool's classification of files, and the documentation's
agreement with the sources.

    python3 tools/test-q1n1-sp11-payload-chain.py

  * ChainNative: tools/test-q1n1-sp11-payload-chain.c (several payloads in one boot: order, the hash taken again
    before each call, the stop conditions, the per-call budgets, the arguments, the lines) and
    tools/test-q1n1-sp11-payload-psci.c (the psci payload against a scripted register file and a scripted SMC),
    built and run by the machinery of tools/test-q1n1-sp11-payload.py.
  * ChainMutants: seeded bugs in the loader's classification of files, in the chain and in the psci payload, each
    applied to a copy of the sources, each of which the programs must reject.
  * SeededBadBinaries: psci built with one forbidden thing added (a second SMC, an HVC, an MSR, a read of
    CNTVOFF_EL2, an exclusive, a cache operation...), each of which the allow-list check of
    tools/sp11_payload_testlib.py (the one tools/test-q1n1-sp11-payload-build.py applies to the real binaries) must
    name.
  * ManifestChain: tools/sp11_payload_manifest.py classifies files by extension as the runner does (the first must
    be a payload, the order is the order given, the same limits), writes for state.bin alone the manifest it always
    did, and agrees with the runner's own classification (a small C harness) on every name; ManifestChainMutants
    runs seeded bugs in the tool against those tests.
  * DocAgreement: the documentation's id, register and line tables are the ones in the sources; DocMutants seeds
    mistakes in the document that these tests must refuse.

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
import concurrent.futures
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import preload  # noqa: E402
import sp11_payload_testlib as lib  # noqa: E402


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The machinery of the native suite: building the programs, running them, copying the tree for a mutant. Its build
# directory is changed to one of this file's own, so that the two suites can run side by side.
native = load_module('sp11_payload_native', ROOT / 'tools' / 'test-q1n1-sp11-payload.py')
native.BUILD = ROOT / 'build' / 'sp11-payload-chain-test'
BUILD = native.BUILD
TOOLS = Path(os.environ.get('Q1N1_PAYLOAD_TOOLS_DIR', ROOT / 'tools'))
SCRATCH = BUILD / os.environ.get('Q1N1_PAYLOAD_TOOLS_TAG', 'main')
DOC = ROOT / 'docs' / 'SP11-PAYLOAD.md'
UEFI = ROOT / 'platform' / 'uefi'
READELF = lambda: shutil.which('llvm-readelf', path=lib.ENV['PATH']) or 'llvm-readelf'  # noqa: E731
run, have = lib.run, lib.have


class ChainNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_the_chain_suites_pass(self):
        native.Native._check(self, 'chain')

    def test_the_psci_payload_passes_its_host_test(self):
        native.Native._check(self, 'psci')

    def test_each_program_runs_one_suite_at_a_time(self):
        for name, suite in (('chain', 'verify'), ('psci', 'decode')):
            with self.subTest(program=name):
                done, binary = native.build_program(name, native.UEFI, native.PAYLOADS, BUILD / 'native')
                self.assertEqual(done.returncode, 0, done.stderr)
                code, output = native.run_program(binary, suite)
                self.assertEqual(code, 0, output)
                self.assertRegex(output, rf'PASS: 1 payload {name} suites, \d+ checks')


# ---- seeded bugs in the sources ---------------------------------------------------------------------------------------

LOAD, RUNC, PSCI = 'uefi/sp11-payload-load.c', 'uefi/sp11-payload-run.c', 'payloads/psci.c'
CHECK_ONE = "pl_keyed_hex(a, PREFIX, \"MPIDR_EL1\", SYSREG(mpidr_el1));\n"
MUTANTS = [
    # -- which files are payloads
    ('loader-every-file-is-a-payload', LOAD, [(
        'entry->memory_type = q1n1_payload_path_is_code(want->path) ? Q1N1_PAYLOAD_TYPE_CODE : Q1N1_PAYLOAD_TYPE_DATA;',
        'entry->memory_type = Q1N1_PAYLOAD_TYPE_CODE;')], ['load'], None),
    ('loader-only-file-0-is-a-payload', LOAD, [(
        'entry->memory_type = q1n1_payload_path_is_code(want->path) ? Q1N1_PAYLOAD_TYPE_CODE : Q1N1_PAYLOAD_TYPE_DATA;',
        'entry->memory_type = index == 0 ? Q1N1_PAYLOAD_TYPE_CODE : Q1N1_PAYLOAD_TYPE_DATA;')], ['load'], None),
    ('loader-treats-the-extension-case-sensitively', LOAD, [(
        '    return equal_nocase(path + length - 4, ".BIN");',
        "    return path[length - 4] == '.' && path[length - 3] == 'B' && path[length - 2] == 'I' && path[length - 1] == 'N';")],
     ['load'], None),
    ('loader-accepts-a-data-first-file', LOAD, [(
        '    if (!q1n1_payload_path_is_code(manifest.files[0].path)) return Q1N1_PAYLOAD_E_FILE0_NOT_BIN;\n', '')], ['load'], None),
    ('loader-accepts-bin-without-the-dot', LOAD, [(
        '    if (length < name + 5) return 0;\n    return equal_nocase(path + length - 4, ".BIN");',
        '    if (length < name + 4) return 0;\n    return equal_nocase(path + length - 3, "BIN");')], ['load'], None),
    ('loader-accepts-an-empty-stem', LOAD, [(
        '    if (length < name + 5) return 0;', '    if (length < name + 4) return 0;')], ['load'], None),
    ('loader-judges-the-whole-path-not-the-file-name', LOAD, [(
        "        if (path[length] == '\\\\') name = length + 1;", '        if (0) name = length + 1;')], ['load'], None),
    ('loader-forgets-the-payload-count', LOAD, [(
        '    out->code_count += q1n1_payload_file_is_code(entry);\n', '')], ['load'], None),
    ('loader-does-not-name-the-file-0-refusal', LOAD, [(
        '    case Q1N1_PAYLOAD_E_FILE0_NOT_BIN: return "FILE0_NOT_BIN";\n', '')], ['load'], None),
    # -- the chain
    ('chain-calls-data-files', RUNC, [
        ('        if (!q1n1_payload_file_is_code(file)) continue;     /* data is found through the table, never called */\n', ''),
        ('    /* Only a payload is hashed here, and only a payload is ever called. */\n'
         '    if (!q1n1_payload_file_is_code(&loaded->file[index])) return 0;\n', '')], ['chain'], None),
    ('chain-calls-in-reverse-order', RUNC, [(
        '    for (uint32_t index = 0; index < loaded->count && index < Q1N1_PAYLOAD_MAX_FILES; index++) {',
        '    for (uint32_t index = loaded->count < Q1N1_PAYLOAD_MAX_FILES ? loaded->count : Q1N1_PAYLOAD_MAX_FILES; index-- > 0;) {')],
     ['chain'], None),
    ('chain-skips-the-second-hash-of-the-later-payloads', RUNC, [(
        '        if (!q1n1_payload_verify_in_place(loaded, index)) {',
        '        if (index == 0 && !q1n1_payload_verify_in_place(loaded, index)) {')], ['chain'], None),
    ('chain-hashes-the-first-payload-for-every-payload', RUNC, [(
        '    return q1n1_preload_verify(table, index);', '    return q1n1_preload_verify(table, 0);')], ['chain'], None),
    ('chain-does-not-reset-the-budgets-for-each-payload', RUNC, [
        ('        session.lines = session.dropped = session.loads = session.faults = session.refused = 0;\n', ''),
        ('    session.env = env;\n',
         '    session.env = env;\n    session.lines = session.dropped = session.loads = session.faults = session.refused = 0;\n')],
     ['chain'], None),
    ('chain-arms-the-guard-words-only-once', RUNC, [
        ('        for (unsigned i = 0; i < GUARD_WORDS; i++) guard[i] = GUARD_PATTERN;\n', ''),
        ('    volatile uint64_t *guard = (volatile uint64_t *)(uintptr_t)loaded->stack_base;\n',
         '    volatile uint64_t *guard = (volatile uint64_t *)(uintptr_t)loaded->stack_base;\n'
         '    for (unsigned i = 0; i < GUARD_WORDS; i++) guard[i] = GUARD_PATTERN;\n')], ['chain'], None),
    ('chain-runs-past-a-corrupted-guard', RUNC, [(
        '            emit_chain_stopped(env, index, "STACK_OVERFLOW");\n            return result->status;\n',
        '            emit_chain_stopped(env, index, "STACK_OVERFLOW");\n')], ['chain'], None),
    ('chain-checks-only-the-first-guard-word', RUNC, [(
        'for (unsigned i = 0; i < GUARD_WORDS; i++) intact &= guard[i] == GUARD_PATTERN;',
        'for (unsigned i = 0; i < 1; i++) intact &= guard[i] == GUARD_PATTERN;')], ['chain'], None),
    ('chain-syncs-only-the-first-payloads-pages', RUNC, [(
        '        env->sync_code(file->base, file->alloc);',
        '        env->sync_code(loaded->file[0].base, loaded->file[0].alloc);')], ['chain'], None),
    ('chain-calls-a-payload-with-another-payloads-base', RUNC, [(
        '        args.payload_base = file->base;', '        args.payload_base = loaded->file[0].base;')], ['chain'], None),
    ('chain-calls-another-payloads-entry', RUNC, [(
        'uint64_t value = env->call(file->base, &args, args.stack_base + args.stack_size);',
        'uint64_t value = env->call(loaded->file[0].base, &args, args.stack_base + args.stack_size);')], ['chain'], None),
    ('chain-stops-on-a-nonzero-return', RUNC, [(
        '        result->called++;\n', '        result->called++;\n        if (value) return result->status;\n')], ['chain'], None),
    ('chain-never-names-a-hash-stop', RUNC, [(
        '            emit_chain_stopped(env, index, "HASH_AT_EL2");\n', '')], ['chain'], None),
    ('chain-names-the-wrong-reason-for-an-overflow', RUNC, [(
        '            emit_chain_stopped(env, index, "STACK_OVERFLOW");', '            emit_chain_stopped(env, index, "HASH_AT_EL2");')],
     ['chain'], None),
    ('chain-names-the-wrong-index-in-the-call-line', RUNC, [(
        '        q1n1_payload_fmt_dec(text, sizeof text, index);', '        q1n1_payload_fmt_dec(text, sizeof text, 0);')],
     ['chain'], None),
    ('chain-reports-the-wrong-index-in-the-done-line', RUNC, [(
        '        q1n1_payload_line_begin(&line, "PAYLOAD DONE");\n        q1n1_payload_line_dec(&line, "INDEX", index);\n',
        '        q1n1_payload_line_begin(&line, "PAYLOAD DONE");\n        q1n1_payload_line_dec(&line, "INDEX", 0);\n')],
     ['chain'], None),
    ('chain-forgets-how-many-were-called', RUNC, [('        result->called++;\n', '')], ['chain'], None),
    ('chain-compares-only-its-own-table-entry', RUNC, [(
        '    for (uint32_t i = 0; i < loaded->count; i++) {\n        const struct q1n1_cached_file *entry = &table->files[i];',
        '    for (uint32_t i = index; i < index + 1; i++) {\n        const struct q1n1_cached_file *entry = &table->files[i];')],
     ['chain'], None),
    ('chain-does-not-rebuild-the-argument-block', RUNC, [(
        '        for (size_t i = 0; i < sizeof args; i++) raw[i] = 0;\n', '')], ['chain'], None),
    # -- the psci payload
    ('psci-issues-an-id-outside-the-five', PSCI, [(
        '#define FUNCTION_SMCCC_VERSION 0x80000000u', '#define FUNCTION_SMCCC_VERSION 0x84000001u')], ['psci'], None),
    ('psci-issues-cpu-on-instead-of-asking-about-it', PSCI, [(
        '        regs[0] = FUNCTION_PSCI_FEATURES;\n        regs[1] = feature_id[index];\n', '        regs[0] = feature_id[index];\n')],
     ['psci'], None),
    ('psci-calls-at-el1', PSCI, [('    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {', '    if (0) {')], ['psci'], None),
    ('psci-changes-an-mpidr', PSCI, [(
        '0x20000, 0x20100, 0x20200, 0x20300,', '0x20000, 0x20100, 0x20201, 0x20300,')], ['psci'], None),
    ('psci-drops-a-next-line', PSCI, [('    say(a, "NEXT FEATURES");\n', '')], ['psci'], None),
    ('psci-names-the-affinity-states-the-wrong-way-round', PSCI, [(
        'static const char state_name[3][11] = {"ON", "OFF", "ON_PENDING"};',
        'static const char state_name[3][11] = {"OFF", "ON", "ON_PENDING"};')], ['psci'], None),
    ('psci-has-a-second-smc-call-site', PSCI, [
        ('OUT_OF_LINE uint64_t smc_query(enum query which, unsigned index)\n{\n',
         'OUT_OF_LINE void smc_again(uint64_t regs[4])\n{\n    pl_host_smc(regs);\n}\n\n'
         'OUT_OF_LINE uint64_t smc_query(enum query which, unsigned index)\n{\n'),
        ('        regs[2] = 0;                    /* lowest affinity level: the CPU itself */\n',
         '        regs[2] = 0;                    /* lowest affinity level: the CPU itself */\n'
         '        smc_again(regs);\n        return regs[0];\n')], ['psci'], None),
    ('psci-asks-about-an-id-outside-its-table', PSCI, [(
        '0xC400000Eu, 0xC4000012u,', '0xC400000Eu, 0xC4000013u,')], ['psci'], None),
    ('psci-uses-lowest-affinity-level-one', PSCI, [(
        '        regs[2] = 0;                    /* lowest affinity level: the CPU itself */', '        regs[2] = 1;')], ['psci'], None),
    ('psci-leaves-an-unused-argument-register-set', PSCI, [(
        '    uint64_t regs[4] = {0, 0, 0, 0};', '    uint64_t regs[4] = {0, 0, 0, 1};')], ['psci'], None),
    ('psci-prints-a-character-outside-the-font', PSCI, [('        pl_text(item, "(-");', '        pl_text(item, "[-");')], ['psci'], None),
    ('psci-announces-the-affinity-group-after-its-calls', PSCI, [(
        '    say(a, "NEXT AFFINITY");\n    uint64_t state[CPU_COUNT];\n'
        '    for (unsigned i = 0; i < CPU_COUNT; i++) state[i] = smc_query(QUERY_AFFINITY_INFO, i);\n',
        '    uint64_t state[CPU_COUNT];\n'
        '    for (unsigned i = 0; i < CPU_COUNT; i++) state[i] = smc_query(QUERY_AFFINITY_INFO, i);\n    say(a, "NEXT AFFINITY");\n')],
     ['psci'], None),
    ('psci-cuts-lines-instead-of-wrapping-them', PSCI, [(
        '    if (r->line.len + 1 + r->item.len > Q1N1_PAYLOAD_LINE_MAX) {', '    if (0) {')], ['psci'], None),
    ('psci-reads-the-affinity-result-as-32-bits', PSCI, [(
        '    unsigned error = how == DECODE_STATE64 ? error_code(UINT64_C(0) - x0) : error_code((uint32_t)(0u - w0));',
        '    unsigned error = error_code((uint32_t)(0u - w0));')], ['psci'], None),
    ('psci-returns-failure', PSCI, [(
        '    report_result(&r, "SMCCC_VERSION", 0, smccc, DECODE_VERSION32);\n    report_end(&r);\n    return 0;',
        '    report_result(&r, "SMCCC_VERSION", 0, smccc, DECODE_VERSION32);\n    report_end(&r);\n    return 1;')], ['psci'], None),
    ('psci-does-not-print-the-mpidr', PSCI, [('    ' + CHECK_ONE, '')], ['psci'], None),
    ('psci-reads-cntvoff-el2', PSCI, [('    ' + CHECK_ONE, '    ' + CHECK_ONE + '    (void)SYSREG(cntvoff_el2);\n')], ['psci'], None),
    ('psci-shifts-the-minor-version', PSCI, [('        pl_dec(item, w0 & 0xffff);', '        pl_dec(item, w0 & 0xff);')], ['psci'], None),
    ('psci-asks-smccc-before-anything-else', PSCI, [
        ('    say(a, "NEXT SMCCC");\n    uint64_t smccc = smc_query(QUERY_SMCCC_VERSION, 0);\n', '    say(a, "NEXT SMCCC");\n'),
        ('    say(a, "NEXT VERSION");\n', '    uint64_t smccc = smc_query(QUERY_SMCCC_VERSION, 0);\n    say(a, "NEXT VERSION");\n')],
     ['psci'], None),
    ('psci-swaps-two-feature-names', PSCI, [(
        '"CPU_SUSPEND", "CPU_OFF", "CPU_ON", "AFFINITY_INFO", "MIGRATE_INFO_TYPE",',
        '"CPU_SUSPEND", "CPU_ON", "CPU_OFF", "AFFINITY_INFO", "MIGRATE_INFO_TYPE",')], ['psci'], None),
]


class ChainMutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    _build = staticmethod(native.Mutants._build)

    def _evaluate(self, *mutant):
        # The native suite's own evaluator: 'caught', 'survived', 'stale' (a target not found once) or 'broken'.
        return native.Mutants._evaluate(self, *mutant)

    def test_there_are_enough_distinct_mutants_and_every_file_has_one(self):
        names = [m[0] for m in MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertFalse({m[0] for m in native.MUTANTS} & set(names), 'a name the native suite already uses')
        self.assertGreaterEqual(len([n for n in names if n.startswith('chain-')]), 12)
        self.assertGreaterEqual(len([n for n in names if n.startswith('psci-')]), 8)
        self.assertGreaterEqual(len([n for n in names if n.startswith('loader-')]), 5)
        self.assertEqual({m[1] for m in MUTANTS}, {LOAD, RUNC, PSCI})

    def test_every_seeded_bug_is_caught(self):
        workers = max(1, min(4, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {m[0]: pool.submit(self._evaluate, *m) for m in MUTANTS}
            results = {name: future.result() for name, future in futures.items()}
        for name, (status, detail) in results.items():
            with self.subTest(mutant=name):
                self.assertEqual(status, 'caught', f'{status}: {detail}')


# ---- psci built with a forbidden thing added -------------------------------------------------------------------------

ANCHOR = '    say(a, "NEXT SMCCC");\n'
BAD_BINARIES = [
    # (name, [(needle, replacement)], what the allow-list check must say)
    ('a-second-smc-call-site', [(ANCHOR, ANCHOR + '    __asm__ volatile("smc #0" ::: "memory");\n')], 'smc'),
    ('an-hvc-instead-of-the-smc', [('"smc #0"', '"hvc #0"')], 'hvc'),
    ('an-smc-with-another-immediate', [('"smc #0"', '"smc #1"')], 'immediate'),
    ('a-write-to-a-system-register', [(ANCHOR, ANCHOR + '    __asm__ volatile("msr daifset, #2" ::: "memory");\n')], 'msr'),
    ('a-read-of-cntvoff-el2', [(ANCHOR, ANCHOR + '    (void)SYSREG(cntvoff_el2);\n')], 'the code names'),
    ('a-read-of-cntpoff-el2', [(ANCHOR, ANCHOR + '    (void)SYSREG(S3_4_C14_C0_6);\n')], 'the code names'),
    ('a-read-of-another-register', [(ANCHOR, ANCHOR + '    (void)SYSREG(midr_el1);\n')], 'registers read'),
    ('an-exclusive-load', [(ANCHOR, ANCHOR + '    __asm__ volatile("ldxr x9, [sp]" ::: "x9", "memory");\n')], 'ldxr'),
    ('a-cache-operation', [(ANCHOR, ANCHOR + '    __asm__ volatile("dc civac, %0" :: "r"(a) : "memory");\n')], 'dc'),
    ('a-tlb-operation', [(ANCHOR, ANCHOR + '    __asm__ volatile("tlbi vmalle1" ::: "memory");\n')], 'tlbi'),
    ('a-wfe', [(ANCHOR, ANCHOR + '    __asm__ volatile("wfe");\n')], 'wfe'),
    ('an-eret', [(ANCHOR, ANCHOR + '    __asm__ volatile("eret");\n')], 'eret'),
    ('a-word-that-is-no-instruction', [(ANCHOR, ANCHOR + '    __asm__ volatile(".inst 0xffffffff");\n')], 'not a known instruction'),
]


class SeededBadBinaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'ld.lld', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy'):
            if not have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        cls.out = BUILD / 'bad-binaries'
        shutil.rmtree(cls.out, ignore_errors=True)
        cls.out.mkdir(parents=True)
        cls.source = (ROOT / 'payloads' / 'psci.c').read_text(encoding='utf-8')

    def build(self, name, edits):
        text = self.source
        for needle, replacement in edits:
            self.assertEqual(text.count(needle), 1, f'{name}: {needle[:60]!r} is not in psci.c exactly once')
            text = text.replace(needle, replacement, 1)
        path = self.out / f'{name}.c'
        path.write_text(text, encoding='utf-8')
        return lib.build_payload(path, self.out, name=name, check=False)

    def test_the_unmutated_payload_is_clean(self):
        done, elf, flat = self.build('control', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(lib.binary_violations(elf, flat, lib.POLICIES['psci'], READELF()), [])

    def test_every_forbidden_addition_is_named_by_the_allow_list_check(self):
        self.assertGreaterEqual(len(BAD_BINARIES), 12)
        for name, edits, expected in BAD_BINARIES:
            with self.subTest(binary=name):
                done, elf, flat = self.build(name, edits)
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                problems = lib.binary_violations(elf, flat, lib.POLICIES['psci'], READELF())
                self.assertTrue(problems, 'the check passed a binary it must refuse')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_state_may_not_hold_an_smc_at_all(self):
        done, elf, flat = lib.build_payload(ROOT / 'payloads' / 'psci.c', self.out, name='psci-as-state', check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        problems = lib.binary_violations(elf, flat, lib.POLICIES['state'], READELF())
        self.assertTrue(any('smc' in p for p in problems), problems)
        self.assertTrue(any('registers read' in p for p in problems), problems)

    def test_the_exclusive_and_atomic_patterns_match_what_they_should(self):
        for yes in ('ldxr', 'ldxrb', 'ldxrh', 'ldxp', 'ldaxr', 'ldaxp', 'stxr', 'stxp', 'stlxr', 'stlxp', 'stlxrb', 'casal',
                    'casa', 'casalb', 'casp', 'caspal', 'swp', 'swpal', 'ldadd', 'ldaddal', 'ldsetah', 'stclr', 'stumaxl', 'ldeor'):
            self.assertTrue(lib.EXCLUSIVE.match(yes) or lib.ATOMIC.match(yes), yes)
        for no in ('ldr', 'str', 'ldp', 'stp', 'ldar', 'stlr', 'ldrb', 'strb', 'ldurb', 'add', 'adrp', 'subs', 'csel', 'cbz', 'ldrsw',
                   'stur', 'strh', 'ldrh', 'and', 'orr', 'mrs', 'smc', 'bl', 'blr', 'ret', 'bti', 'ubfx', 'lsr', 'lsl', 'mov', 'movk'):
            self.assertFalse(lib.EXCLUSIVE.match(no) or lib.ATOMIC.match(no), no)


# ---- the manifest tool -------------------------------------------------------------------------------------------------

# What tools/sp11_payload_manifest.py wrote for a lone state.bin (the bytes below) and for state.bin with a data file,
# recorded from the tool at the commit before the chain: the chain must not change either.
GOLDEN_STATE_ONLY = (328, '8db228e6c11711d822d0586d264c67d652daf824479cf4d1f72a4869453e7db2')
GOLDEN_STATE_AND_DATA = (624, 'dcf1360ca1315660a4709355d966ec07d14f701b4ac6897a1bae935298ba438a')
GOLDEN_PAYLOAD, GOLDEN_DATA = bytes(range(256)) * 4, bytes(range(251)) * 20


class ManifestChain(unittest.TestCase):
    tool = TOOLS / 'sp11_payload_manifest.py'

    @classmethod
    def setUpClass(cls):
        SCRATCH.mkdir(parents=True, exist_ok=True)
        cls.module = load_module('sp11_payload_manifest_chain_under_test', cls.tool)

    def inputs(self, case, files):
        base = SCRATCH / 'chain' / case
        shutil.rmtree(base, ignore_errors=True)
        paths = []
        for name, data in files.items():
            path = base / 'in' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            paths.append(path)
        return base, paths

    def tool_run(self, out, *paths):
        return run(['python3', '-B', str(self.tool), '--out-dir', str(out)] + [str(p) for p in paths])

    def kinds(self, files):
        base, paths = self.inputs('kinds', files)
        manifest, entries = self.module.build(paths)
        return [(path, kind) for path, _, _, _, kind in entries]

    def test_the_kind_is_the_extension_and_the_order_is_the_order_given(self):
        files = {'state.bin': bytes(8), 'data.dat': bytes(8), 'Psci.BIN': bytes(8), 'notes.txt': bytes(8), 'x.Bin': bytes(8)}
        base, paths = self.inputs('mixed', files)
        done = self.tool_run(base / 'out', *paths)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.kinds(files), [('\\SP11\\STATE.BIN', 'payload'), ('\\SP11\\DATA.DAT', 'data'),
                                             ('\\SP11\\PSCI.BIN', 'payload'), ('\\SP11\\NOTES.TXT', 'data'), ('\\SP11\\X.BIN', 'payload')])
        magic, version, count, entry = struct.unpack_from('<4Q', (base / 'out' / 'SP11' / 'PAYLOAD.MAN').read_bytes())
        self.assertEqual(count, 5)
        listed = [struct.unpack_from('<Q32s256s', (base / 'out' / 'SP11' / 'PAYLOAD.MAN').read_bytes(), 32 + i * entry)[2]
                  .rstrip(b'\0').decode() for i in range(5)]
        self.assertEqual(listed, ['\\SP11\\STATE.BIN', '\\SP11\\DATA.DAT', '\\SP11\\PSCI.BIN', '\\SP11\\NOTES.TXT', '\\SP11\\X.BIN'])
        # The files are copied under their stick names, in capitals, and nothing else is written.
        self.assertEqual(sorted(p.name for p in (base / 'out' / 'SP11').iterdir()),
                         ['DATA.DAT', 'NOTES.TXT', 'PAYLOAD.MAN', 'PSCI.BIN', 'STATE.BIN', 'X.BIN'])

    def test_what_will_be_called_is_said_in_the_output(self):
        base, paths = self.inputs('say', {'state.bin': bytes(8), 'data.dat': bytes(8), 'psci.bin': bytes(8)})
        done = self.tool_run(base / 'out', *paths)
        self.assertEqual(done.returncode, 0, done.stderr)
        for text in ('SP11\\STATE.BIN', '(INDEX=0, payload, called in manifest order)', '(INDEX=1, data, never called)',
                     '(INDEX=2, payload, called in manifest order)', 'SP11\\Q1N1-PAYLOAD.EFI --el2'):
            self.assertIn(text, done.stdout)

    def test_the_extension_is_matched_without_regard_to_case_and_only_as_the_end_of_the_name(self):
        for name in ('psci.bin', 'psci.BIN', 'psci.Bin', 'PSCI.bIn', 'a.bin', 'a-b_c.bin'):
            with self.subTest(name=name):
                self.assertEqual(self.kinds({'state.bin': bytes(8), name: bytes(8)})[1][1], 'payload')
        for name in ('xbin.dat', 'bin.txt', 'a.bi', 'a.b', 'a.dat', 'notbin.da', 'bin_.txt', 'a.bn'):
            with self.subTest(name=name):
                self.assertEqual(self.kinds({'state.bin': bytes(8), name: bytes(8)})[1][1], 'data')
        for name in ('bin', 'a.bin.txt', 'a.b.bin', 'a.binx', 'toolongname.bin', 'a b.bin'):
            with self.subTest(name=name):       # no 8.3 stick name: refused before any kind matters
                base, paths = self.inputs('lookalike', {'state.bin': bytes(8), name: bytes(8)})
                self.assertEqual(self.tool_run(base / 'out', *paths).returncode, 1)

    def test_the_first_file_must_be_a_payload(self):
        for first in ('data.dat', 'notes.txt', 'state.bi', 'bin.dat'):
            with self.subTest(first=first):
                base, paths = self.inputs('first', {first: bytes(8), 'state.bin': bytes(8)})
                done = self.tool_run(base / 'out', *paths)
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertIn('must be a payload', done.stderr)
                self.assertFalse((base / 'out').exists(), 'a refusal must not leave a half-written stick tree')
        base, paths = self.inputs('lone-data', {'data.dat': bytes(8)})
        self.assertEqual(self.tool_run(base / 'out', *paths).returncode, 1)
        self.assertFalse((base / 'out').exists())

    def test_the_limits_are_the_same_for_every_payload_and_every_file(self):
        base, paths = self.inputs('five', {f'f{i}.{"bin" if i % 2 == 0 else "dat"}': bytes(8) for i in range(5)})
        self.assertEqual(self.tool_run(base / 'out', *paths).returncode, 0)
        base, paths = self.inputs('six', {f'f{i}.bin': bytes(8) for i in range(6)})
        done = self.tool_run(base / 'out', *paths)
        self.assertEqual(done.returncode, 1)
        self.assertIn('takes 1 to 5', done.stderr)
        # A later payload is as long as one instruction at least, which a data file need not be.
        base, paths = self.inputs('short-later', {'state.bin': bytes(8), 'psci.bin': bytes(3)})
        done = self.tool_run(base / 'out', *paths)
        self.assertEqual((done.returncode, 'shorter than one instruction' in done.stderr), (1, True), done.stderr)
        base, paths = self.inputs('short-data', {'state.bin': bytes(8), 'data.dat': bytes(1)})
        self.assertEqual(self.tool_run(base / 'out', *paths).returncode, 0)
        # 256 MiB is the most for any file, a later payload included; a byte more is refused before it is read.
        edge = SCRATCH / 'chain' / 'edge'
        shutil.rmtree(edge, ignore_errors=True)
        edge.mkdir(parents=True)
        first, big, over = edge / 'FIRST.BIN', edge / 'BIG.BIN', edge / 'OVER.BIN'
        first.write_bytes(bytes(8))
        for path, size in ((big, 256 << 20), (over, (256 << 20) + 1)):
            with open(path, 'wb') as handle:
                handle.truncate(size)
        self.assertEqual(self.module.build([first, big])[1][1][1], 256 << 20)
        with self.assertRaises(ValueError) as refused:
            self.module.build([first, over])
        self.assertIn('between 1 byte', str(refused.exception))
        for name in ('f.bin', 'F.DAT'):      # the 8.3 rule holds for data as for payloads
            base, paths = self.inputs('names', {'state.bin': bytes(8), name: bytes(8)})
            self.assertEqual(self.tool_run(base / 'out', *paths).returncode, 0)
        base, paths = self.inputs('long-data-name', {'state.bin': bytes(8), 'a-very-long-name.dat': bytes(8)})
        self.assertEqual(self.tool_run(base / 'out', *paths).returncode, 1)
        base, paths = self.inputs('reserved', {'state.bin': bytes(8), 'payload.man': bytes(8)})
        self.assertEqual(self.tool_run(base / 'out', *paths).returncode, 1)

    def test_a_lone_state_bin_gets_exactly_the_manifest_it_always_got(self):
        base, paths = self.inputs('golden', {'state.bin': GOLDEN_PAYLOAD})
        self.assertEqual(self.tool_run(base / 'out', *paths).returncode, 0)
        manifest = (base / 'out' / 'SP11' / 'PAYLOAD.MAN').read_bytes()
        self.assertEqual((len(manifest), hashlib.sha256(manifest).hexdigest()), GOLDEN_STATE_ONLY)
        # And it is what the format's own writer makes of the same list.
        self.assertEqual(manifest, preload.manifest([('\\SP11\\STATE.BIN', len(GOLDEN_PAYLOAD), hashlib.sha256(GOLDEN_PAYLOAD).hexdigest())]))
        self.assertEqual(sorted(p.name for p in (base / 'out' / 'SP11').iterdir()), ['PAYLOAD.MAN', 'STATE.BIN'])
        base, paths = self.inputs('golden2', {'state.bin': GOLDEN_PAYLOAD, 'data.dat': GOLDEN_DATA})
        self.assertEqual(self.tool_run(base / 'out', *paths).returncode, 0)
        manifest = (base / 'out' / 'SP11' / 'PAYLOAD.MAN').read_bytes()
        self.assertEqual((len(manifest), hashlib.sha256(manifest).hexdigest()), GOLDEN_STATE_AND_DATA)

    @unittest.skipUnless(have('clang'), 'clang not installed')
    def test_the_runner_and_the_tool_agree_on_which_files_are_called(self):
        harness = SCRATCH / 'kinds-harness'
        sources = [ROOT / 'tools' / 'testdata' / 'sp11-payload-kinds-harness.c'] + [
            UEFI / name for name in ('sp11-payload-load.c', 'sp11-payload-plan.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c')]
        done = run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1',
                    '-I', str(UEFI)] + [str(s) for s in sources] + ['-o', str(harness)])
        self.assertEqual(done.returncode, 0, done.stderr)
        names = ('state.bin', 'data.dat', 'Psci.BIN', 'notes.txt', 'x.Bin')
        base, paths = self.inputs('agree', {name: bytes(8) for name in names})
        self.assertEqual(self.tool_run(base / 'out', *paths).returncode, 0)
        ours = run([str(harness), str(base / 'out' / 'SP11' / 'PAYLOAD.MAN')])
        self.assertEqual(ours.returncode, 0, ours.stdout + ours.stderr)
        theirs = {path: 'code' if kind == 'payload' else 'data' for path, kind in self.kinds({n: bytes(8) for n in names})}
        self.assertEqual(dict(line.split() for line in ours.stdout.splitlines()), theirs)
        self.assertEqual(sorted(theirs.values()), ['code', 'code', 'code', 'data', 'data'])


def _manifest_mutants():
    tool = 'sp11_payload_manifest.py'
    return [
        ('manifest-calls-everything', tool, "kind = 'payload' if is_payload(name) else 'data'", "kind = 'payload'"),
        ('manifest-calls-only-the-first-file', tool, "kind = 'payload' if is_payload(name) else 'data'",
         "kind = 'payload' if index == 0 else 'data'"),
        ('manifest-matches-the-extension-case-sensitively', tool, "kind = 'payload' if is_payload(name) else 'data'",
         "kind = 'payload' if local.name.endswith('.bin') else 'data'"),
        ('manifest-lets-data-come-first', tool, "if index == 0 and kind != 'payload':", 'if False:'),
        ('manifest-checks-the-length-of-the-first-payload-only', tool, "if kind == 'payload' and size < 4:", 'if index == 0 and size < 4:'),
        ('manifest-reorders-the-files', tool, 'paths = [Path(p) for p in paths]', 'paths = sorted(Path(p) for p in paths)'),
        ('manifest-takes-the-wrong-extension', tool, "CODE_SUFFIX = '.BIN'", "CODE_SUFFIX = '.DAT'"),
        ('manifest-says-data-is-called', tool, "'data, never called'", "'data, called'"),
        ('manifest-does-not-say-the-index', tool, '(INDEX={index}, {role})', '({role})'),
        ('manifest-matches-a-shorter-extension', tool, 'return name.upper().endswith(CODE_SUFFIX)', "return name.upper().endswith('.BI')"),
    ]


class ManifestChainMutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        BUILD.mkdir(parents=True, exist_ok=True)

    def _evaluate(self, name, fname, needle, replacement):
        directory = BUILD / f'toolmut-{name}'
        shutil.rmtree(directory, ignore_errors=True)
        (directory / 'tools').mkdir(parents=True)
        for tool in ('sp11_payload_manifest.py', 'sp11_payload_elfcheck.py', 'preload.py'):
            shutil.copy(ROOT / 'tools' / tool, directory / 'tools' / tool)
        path = directory / 'tools' / fname
        text = path.read_text(encoding='utf-8')
        if needle is not None:
            if text.count(needle) != 1:
                return 'stale', f'target not found exactly once in {fname}: {needle[:70]!r}'
            path.write_text(text.replace(needle, replacement, 1), encoding='utf-8')
        env = dict(lib.ENV, Q1N1_PAYLOAD_TOOLS_DIR=str(directory / 'tools'),
                   Q1N1_PAYLOAD_TOOLS_TAG='m' + hashlib.sha1(name.encode()).hexdigest()[:10])
        done = subprocess.run(['python3', '-B', str(Path(__file__).resolve()), 'ManifestChain'], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=600)
        if needle is None:
            return ('control-ok' if done.returncode == 0 else 'control-failed'), done.stderr[-600:]
        if done.returncode != 0:
            last = [line for line in done.stderr.splitlines() if line.startswith(('FAIL', 'ERROR'))]
            return 'caught', last[0][:120] if last else 'a test failed'
        return 'survived', 'the manifest tests still passed'

    def test_the_unmutated_control_passes_through_the_same_mechanism(self):
        status, detail = self._evaluate('control', 'sp11_payload_manifest.py', None, None)
        self.assertEqual(status, 'control-ok', detail)

    def test_every_seeded_tool_bug_is_caught(self):
        mutants = _manifest_mutants()
        self.assertGreaterEqual(len(mutants), 8)
        self.assertEqual(len({m[0] for m in mutants}), len(mutants))
        workers = max(1, min(4, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {m[0]: pool.submit(self._evaluate, *m) for m in mutants}
            results = {name: future.result() for name, future in futures.items()}
        for name, (status, detail) in results.items():
            with self.subTest(mutant=name):
                self.assertEqual(status, 'caught', f'{status}: {detail}')


class DocAgreement(unittest.TestCase):
    """The documentation says what the sources do: the tables are read from the document and compared with the C."""
    TEXT = None     # a changed copy of the document, for DocMutants

    @classmethod
    def setUpClass(cls):
        cls.doc = DOC.read_text(encoding='utf-8') if cls.TEXT is None else cls.TEXT
        cls.psci = (ROOT / 'payloads' / 'psci.c').read_text(encoding='utf-8')
        cls.run_c = (UEFI / 'sp11-payload-run.c').read_text(encoding='utf-8')
        cls.load_c = (UEFI / 'sp11-payload-load.c').read_text(encoding='utf-8')
        cls.main_c = (UEFI / 'main.c').read_text(encoding='utf-8')

    def section(self, name):
        start, end = f'<!-- {name} -->', f'<!-- /{name} -->'
        self.assertIn(start, self.doc)
        return self.doc[self.doc.index(start):self.doc.index(end)]

    def rows(self, name):
        return re.findall(r'^\| `([A-Z0-9_]+)` \| `(0x[0-9A-Fa-f]+)` \|', self.section(name), re.M)

    def array(self, name, element):
        body = re.search(rf'{name}\[[A-Z_0-9\]\[]*\]?\s*=\s*\{{(.*?)\}};', self.psci, re.S)
        self.assertIsNotNone(body, name)
        return re.findall(element, body.group(1))

    def test_the_five_function_ids_in_the_document_are_the_five_the_payload_defines(self):
        defined = {name: int(value, 16) for name, value in re.findall(r'#define FUNCTION_([A-Z_0-9]+) (0x[0-9A-Fa-f]+)u', self.psci)}
        documented = {name: int(value, 16) for name, value in self.rows('psci-ids')}
        self.assertEqual(len(defined), 5)
        self.assertEqual(documented, defined)

    def test_the_ten_features_in_the_document_are_the_ten_the_payload_asks_about_in_order(self):
        ids = [int(v, 16) for v in self.array('feature_id', r'0x[0-9A-Fa-f]+')]
        names = self.array('feature_name', r'"([A-Z_0-9]+)"')
        self.assertEqual(len(ids), 10)
        self.assertEqual([(n, int(v, 16)) for n, v in self.rows('psci-features')], list(zip(names, ids)))

    def test_the_twelve_affinities_in_the_document_are_the_ones_the_payload_asks_about(self):
        asked = [int(v, 16) for v in self.array('cpu_affinity', r'0x[0-9A-Fa-f]+')]
        documented = [int(v, 16) for v in re.findall(r'`(0x[0-9A-Fa-f]+)`', self.section('psci-mpidrs'))]
        self.assertEqual(len(asked), 12)
        self.assertEqual(documented, asked)

    def test_every_decode_name_the_payload_prints_is_in_the_document(self):
        errors = self.array('error_name', r'"([A-Z_]+)"')
        self.assertEqual(len(errors), 9)
        for number, name in enumerate(errors, 1):
            self.assertIn(f'`{name}(-{number})`', self.doc)
        for name in self.array('tos_name', r'"([A-Z_]+)"') + self.array('state_name', r'"([A-Z_]+)"'):
            self.assertIn(f'`{name}`', self.doc)

    def test_the_doc_lists_every_refusal_the_loader_can_print(self):
        names = set(re.findall(r'case Q1N1_PAYLOAD_E_[A-Z0-9_]+: return "([A-Z0-9_]+)";', self.load_c))
        self.assertIn('FILE0_NOT_BIN', names)
        failure = self.doc[self.doc.index('## Failure modes before the bounce'):self.doc.index('## Tests')]
        documented = {name for cell in re.findall(r'^\| ([^|]+) \|', failure, re.M)
                      for name in re.findall(r'`([A-Z0-9_]+)`', cell)}
        self.assertEqual(documented, names)

    def test_the_two_stop_reasons_are_the_two_the_runner_prints_and_the_doc_names(self):
        reasons = re.findall(r'emit_chain_stopped\(env, index, "([A-Z0-9_]+)"\)', self.run_c)
        self.assertEqual(sorted(reasons), ['HASH_AT_EL2', 'STACK_OVERFLOW'])
        chain = self.doc[self.doc.index('## The chain'):self.doc.index('## Payload ABI v1')]
        for reason in reasons:
            self.assertIn(f'| `{reason}` |', chain)
        self.assertIn('PAYLOAD CHAIN STOPPED INDEX=<n> REASON=<reason>', chain)

    def test_the_done_line_in_the_catalogue_has_the_runners_keys_in_the_runners_order(self):
        template = re.search(r'`PAYLOAD DONE (INDEX=n .*?)`', self.doc).group(1)
        documented = re.findall(r'([A-Z]+)=', template)
        block = self.run_c[self.run_c.index('"PAYLOAD DONE"'):]
        block = block[:block.index('emit_line')]
        emitted = re.findall(r'"([A-Z]+)"|"(STACK)=OK"', block)
        self.assertEqual(documented, [a or b for a, b in emitted])

    def test_the_ready_line_says_how_many_payloads_it_will_call(self):
        catalogue = self.doc[self.doc.index('## Line catalogue'):self.doc.index('## Failure modes')]
        self.assertIn('| `PAYLOAD READY FILES=n RANGES=n CODE=k` |', catalogue)
        for key in ('FILES', 'RANGES', 'CODE'):
            self.assertIn(f'q1n1_payload_line_dec(&ready, "{key}"', self.main_c)

    def test_the_extension_rule_is_the_same_literal_in_the_tool_the_loader_and_the_document(self):
        suffix = load_module('sp11_payload_manifest_doc', TOOLS / 'sp11_payload_manifest.py').CODE_SUFFIX
        self.assertEqual(suffix, '.BIN')
        self.assertIn(f'equal_nocase(path + length - {len(suffix)}, "{suffix}")', self.load_c)
        self.assertIn('`<stem>.BIN`', self.doc)

    def test_the_stick_file_names_in_the_document_are_the_ones_the_tool_writes(self):
        base = SCRATCH / 'doc-stick'
        shutil.rmtree(base, ignore_errors=True)
        (base / 'in').mkdir(parents=True)
        for name in ('state.bin', 'psci.bin'):
            (base / 'in' / name).write_bytes(bytes(range(64)))
        done = run(['python3', '-B', str(TOOLS / 'sp11_payload_manifest.py'), '--out-dir', str(base / 'out'),
                    str(base / 'in' / 'state.bin'), str(base / 'in' / 'psci.bin')])
        self.assertEqual(done.returncode, 0, done.stderr)
        written = sorted(p.name for p in (base / 'out' / 'SP11').iterdir())
        self.assertEqual(written, ['PAYLOAD.MAN', 'PSCI.BIN', 'STATE.BIN'])
        table = self.doc[self.doc.index('## On the stick'):self.doc.index('## The manifest')]
        for name in written + ['Q1N1-PAYLOAD.EFI']:
            self.assertIn(f'| `SP11\\{name}` |', table)
        self.assertIn('{state,psci}.bin', self.doc)

    def test_the_document_says_what_the_status_is(self):
        for word in ('EXPERIMENTAL', 'hardware NOT RUN', 'OBSERVED', 'INFERRED', 'UNKNOWN', 'VERIFIED'):
            self.assertIn(word, self.doc)


def _replace(old, new, count=1):
    def mutate(doc):
        assert old in doc, old
        return doc.replace(old, new, count)
    return mutate


def _swap(first, second):
    def mutate(doc):
        lines = doc.split('\n')
        a = next(i for i, line in enumerate(lines) if line.startswith(first))
        b = next(i for i, line in enumerate(lines) if line.startswith(second))
        lines[a], lines[b] = lines[b], lines[a]
        return '\n'.join(lines)
    return mutate


DOC_MUTANTS = [
    ('a-function-id-is-wrong', _replace('| `PSCI_FEATURES` | `0x8400000A` | SMC32 |', '| `PSCI_FEATURES` | `0x8400000B` | SMC32 |')),
    ('a-sixth-function-id-appears', _replace('<!-- /psci-ids -->', '| `CPU_ON` | `0xC4000003` | SMC64 | 0 | 0 | none | none |\n<!-- /psci-ids -->')),
    ('the-features-are-in-another-order', _swap('| `CPU_OFF` | `0x84000002`', '| `CPU_ON` | `0xC4000003`')),
    ('a-feature-is-forgotten', _replace('| `SYSTEM_RESET2` | `0xC4000012` | the PSCI 1.1 reset with a reset type exists |\n', '')),
    ('an-affinity-is-wrong', _replace('`0x10200`, `0x10300` | OBSERVED (MADT) |', '`0x10200`, `0x10301` | OBSERVED (MADT) |')),
    ('a-refusal-is-renamed', _replace('| `FILE0_NOT_BIN` |', '| `FILE0_NOT_BINARY` |')),
    ('a-stop-reason-is-renamed', _replace('| `STACK_OVERFLOW` | payload n overwrote', '| `STACK_SMASHED` | payload n overwrote')),
    ('the-done-keys-are-reordered', _replace('LOADS=.. FAULTS=.. REFUSED=..', 'FAULTS=.. LOADS=.. REFUSED=..')),
    ('the-ready-count-is-dropped', _replace('| `PAYLOAD READY FILES=n RANGES=n CODE=k` |', '| `PAYLOAD READY FILES=n RANGES=n` |')),
    ('a-stick-file-has-another-name', _replace('| `SP11\\PSCI.BIN` |', '| `SP11\\PSCI.EXE` |')),
    ('a-decode-name-is-wrong', _replace('`INVALID_PARAMETERS(-2)`', '`INVALID_PARAMETER(-2)`', count=-1)),
    ('the-suffix-is-another-case', _replace('`<stem>.BIN`', '`<stem>.bin`', count=-1)),
    ('the-hardware-status-is-claimed', _replace('hardware NOT RUN', 'hardware qualified', count=-1)),
]


class DocMutants(unittest.TestCase):
    """The agreement tests above must be able to fail: each seeded mistake in the document is refused by one."""

    @staticmethod
    def outcome(text):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(type('Changed', (DocAgreement,), {'TEXT': text}))
        result = unittest.TestResult()
        suite.run(result)
        return result

    def test_the_unchanged_document_passes_through_the_same_mechanism(self):
        result = self.outcome(DOC.read_text(encoding='utf-8'))
        self.assertTrue(result.wasSuccessful(), [str(f[1])[-300:] for f in result.failures + result.errors])
        self.assertGreaterEqual(result.testsRun, 10)

    def test_every_seeded_mistake_in_the_document_is_refused(self):
        original = DOC.read_text(encoding='utf-8')
        self.assertGreaterEqual(len(DOC_MUTANTS), 12)
        for name, mutate in DOC_MUTANTS:
            with self.subTest(mutant=name):
                changed = mutate(original)
                self.assertNotEqual(changed, original)
                self.assertFalse(self.outcome(changed).wasSuccessful(), 'every agreement test still passed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
