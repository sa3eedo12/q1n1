#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The cpuon payload of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-CPUON.md): its host test, its seeded bugs,
the allow-list of its binary, and the proof that the allow-list engine's new optional keys left every older policy as strict as
it was. The QEMU run is tools/test-q1n1-sp11-payload-qemu-cpuon.py.

    python3 tools/test-q1n1-sp11-payload-cpuon.py          # the suites
    python3 tools/test-q1n1-sp11-payload-cpuon.py facts    # size, digest and instruction inventory of the built binary

  * CpuonNative: tools/test-q1n1-sp11-payload-cpuon.c (ten suites over a modelled machine: scripted PSCI, a counter, and a cache
    that agrees with memory only through cache maintenance; an independent oracle of the page; 2500 random worlds), built and
    run by the machinery of tools/test-q1n1-sp11-payload.py.
  * CpuonSource: what no run shows -- the ops the source calls, that the registers it names are the policy's, that the host
    model and the assembly pass an SMC the same arguments, that every function id is one literal, no writable global.
  * CpuonMutants: seeded bugs in cpuon.c, each applied to a copy of the sources and each of which the host program must reject.
  * CpuonBinary: the allow-list applied to cpuon.bin (the fifteen registers, MSR of VBAR_EL2 and DAIFSet only, DC CIVAC and
    IVAC only, three `smc #0` with their function ids read from the code) with seeded bad binaries, a flat binary patched so
    that only the encoding layer can see it, the other policies, and the build's reproducibility.
  * CpuonEngine: the same engine on the older payloads -- the same answers as the engine of the base commit (a frozen copy in
    tools/testdata/) on every binary of a corpus under every older policy, and every instruction cpuon may use is still refused
    to the others; the id reader and the policy checks on synthetic input.
  * CpuonDoc: see tools/test-q1n1-sp11-payload-cpuon-doc.py (the document against the source, the model and the binary).

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
import concurrent.futures
from collections import Counter
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
import sp11_payload_testlib as lib  # noqa: E402


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The machinery of the native suite, with a build directory of this file's own so that the suites can run side by side.
native = load_module('sp11_payload_native_for_cpuon', ROOT / 'tools' / 'test-q1n1-sp11-payload.py')
native.BUILD = ROOT / 'build' / 'sp11-payload-cpuon-test'
BUILD = native.BUILD
SOURCE = ROOT / 'payloads' / 'cpuon.c'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-CPUON.md'
OLD_ENGINE = ROOT / 'tools' / 'testdata' / 'sp11-payload-engine-a9f00f9.txt'
BASE_COMMIT = 'a9f00f9'
READELF = lambda: shutil.which('llvm-readelf', path=lib.ENV['PATH']) or 'llvm-readelf'  # noqa: E731
run, have = lib.run, lib.have
SUITES = ('ids', 'el', 'normal', 'affinity', 'cpu_on', 'cores', 'counter', 'refuse', 'args', 'fuzz')
OWN_FILES = [SOURCE, ROOT / 'tools' / 'test-q1n1-sp11-payload-cpuon.c', ROOT / 'tools' / 'test-q1n1-sp11-payload-cpuon-world.h',
             ROOT / 'tools' / 'test-q1n1-sp11-payload-cpuon.py', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu-cpuon.py', OLD_ENGINE]
OLD_POLICIES = ('state', 'psci', 'timer', 'usbsmmu')


def code_of(path):
    """A source file without its comments."""
    return re.sub(r'//[^\n]*', '', re.sub(r'/\*.*?\*/', '', Path(path).read_text(encoding='utf-8'), flags=re.S))


def function_body(code, name):
    at = code.index(f' {name}(')
    start = code.index('{', at)
    depth, end = 0, start
    while True:
        depth += {'{': 1, '}': -1}.get(code[end], 0)
        if depth == 0:
            return code[start:end + 1]
        end += 1


class CpuonNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_the_cpuon_suites_pass(self):
        native.Native._check(self, 'cpuon')

    def test_each_suite_runs_alone(self):
        done, binary = native.build_program('cpuon', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite in SUITES:
            with self.subTest(suite=suite):
                code, output = native.run_program(binary, suite)
                self.assertEqual(code, 0, output)
                self.assertRegex(output, r'PASS: 1 payload cpuon suites, \d+ checks')

    def test_the_most_lines_are_measured_and_exactly_the_budget(self):
        done, binary = native.build_program('cpuon', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary, 'lines-report')
        self.assertEqual(code, 0, output)
        self.assertEqual(output.strip(), 'LINES_MAX=40', 'the worst world reaches the ABI budget and never passes it')


class CpuonSource(unittest.TestCase):
    code = code_of(SOURCE)

    def test_the_source_calls_only_the_counter_and_hex_ops_and_the_helpers_puts(self):
        self.assertEqual(set(re.findall(r'ops\.(\w+)', self.code)), {'counter', 'hex'}, 'never load32')
        util = code_of(ROOT / 'payloads' / 'payload-util.h')
        self.assertEqual(set(re.findall(r'ops\.(\w+)', util)), {'hex', 'puts'})

    def test_the_registers_the_source_names_are_the_ones_the_policy_lists(self):
        primary = set(re.findall(r'SYSREG\((\w+)\)', self.code)) - {'name'}
        stub = set(re.findall(r'READ_STORE\("(\w+)"', self.code)) | set(re.findall(r'"\s+mrs x\d, (\w+)\\n"', self.code))
        policy = lib.POLICIES['cpuon']
        self.assertEqual({name.lower() for name in primary | stub}, policy['registers'] | policy['single_reads'])
        self.assertEqual(primary, {'CurrentEL', 'mpidr_el1', 'CNTFRQ_EL0', 'midr_el1', 'id_aa64mmfr0_el1', 'id_aa64isar0_el1',
                                   'id_aa64pfr0_el1'}, 'the primary reads seven registers and no others')
        self.assertIn('S3_4_C14_C0_3', stub, 'CNTVOFF_EL2 is read by the stub, by encoding')
        self.assertNotRegex(self.code.upper(), r'CNTPOFF|S3_4_C14_C0_6', 'CNTPOFF_EL2 is never named in code')

    def test_the_host_model_and_the_assembly_pass_an_smc_the_same_arguments(self):
        for name in ('smc_cpu_on', 'smc_affinity_info'):
            body = function_body(self.code, name)
            host = re.search(r'uint64_t regs\[4\] = \{([^}]*)\};', body).group(1)
            asm = dict(re.findall(r'register uint64_t (x\d) __asm__\("x\d"\) = ([^;]+);', body))
            self.assertEqual([part.strip() for part in host.split(',')], [asm[f'x{i}'] for i in range(4)], name)
            self.assertEqual(body.count('smc #0'), 1)

    def test_every_function_id_is_one_literal_and_there_are_three_smc_sites(self):
        self.assertEqual(len(re.findall(r'0xC4000003u', self.code)), 1)
        self.assertEqual(len(re.findall(r'0xC4000004u', self.code)), 1)
        self.assertEqual(self.code.count('smc #0'), 3, 'the two helpers and the stub')
        self.assertEqual(len(re.findall(r'\bsmc_cpu_on\(', self.code)) - 1, 1, 'CPU_ON is called from one place')
        stub = self.code[self.code.index('cpuon_finish:'):self.code.index('cpuon_park:')]
        self.assertIn('mov w0, #2', stub)
        self.assertIn('movk w0, #0x8400, lsl #16', stub, 'CPU_OFF, 0x84000002, in the stub')
        for forbidden in ('0x84000008', '0x84000009', '0xC4000001', '0x84000001', 'SYSTEM_OFF(', 'SYSTEM_RESET(', 'CPU_SUSPEND('):
            self.assertNotIn(forbidden, self.code)

    def test_no_writable_global_and_every_table_is_constant(self):
        for declaration in re.findall(r'^static\b[^\n(]*;', self.code, re.M):
            self.assertRegex(declaration, r'\bconst\b|\binline\b', declaration)
        self.assertEqual(re.findall(r'^static (?!const|inline|__attribute__)[^\n(]*$', self.code, re.M), [])

    def test_the_stub_reads_no_memory_and_has_no_stack(self):
        stub = self.code[self.code.index('cpuon_entry:'):self.code.index('.popsection')]
        instructions = re.findall(r'^\s*"\s+(\w+)', stub, re.M)
        self.assertGreater(len(instructions), 20)
        for instruction in instructions:
            self.assertNotIn(instruction, ('ldr', 'ldp', 'ldur', 'ldxr', 'ldar', 'stp', 'bl', 'blr', 'ret'), instruction)
        self.assertNotRegex(stub, r'\bsp\b')

    def test_the_files_are_within_the_size_limits(self):
        for path in OWN_FILES:
            with self.subTest(file=path.name):
                text = path.read_text(encoding='utf-8')
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                self.assertIn('SPDX-License-Identifier: MIT', text[:200])


# ---- seeded bugs in cpuon.c ------------------------------------------------------------------------------------------------

FILE = 'payloads/cpuon.c'
WAIT = '    if (!wait_ms(r, WAIT_BEFORE_CPU_ON_S * 1000u)) {\n        say(&r->out, "%s", "SKIPPED=COUNTER_STUCK", 0);'
P1_ANNOUNCE = '    pl_begin(&text);\n    pl_hex(r->a, &text, c->affinity);\n    say_next_cpu_on(r, text.buf);\n'
P1_WAIT = WAIT % 'P1' + '\n        return 0;\n    }\n'
P2_ANNOUNCE = '    say_next_cpu_on(r, "ALL");\n'
P2_WAIT = WAIT % 'P2' + '\n        return;\n    }\n'
START_ALL = '    for (unsigned i = 0; i < n; i++) start_core(r, list[i], (unsigned)(list[i] - r->core));\n'
ELIGIBLE = '        c->eligible = c->probe == 1;\n'
PREPARE_END = '    clean_invalidate_range(r->slot_base, SLOT_REGION_BYTES);\n    dsb_sy();\n}\n'
FLAG_READ = '    dc_ivac(slot);\n    dsb_sy();\n    return kind_of(load64(slot + OFF_DONE));\n'
REPORT_READ = '    invalidate_range(slot, SLOT_BYTES);\n    dsb_sy();\n    for (unsigned i = 0; i < SLOT_WORDS; i++)'


def sub(name, old, new):
    return ('cpuon-' + name, FILE, [(old, new)], ['cpuon'], None)


def drop(name, statement):
    return sub(name, statement, '')


MUTANTS = [
    # -- who is ever started: only a core that answered exactly OFF, never the boot CPU
    drop('probes-the-boot-cpu', '        if (c->boot) continue;\n'),
    sub('takes-on-for-off', ELIGIBLE, '        c->eligible = c->probe <= 1;\n'),
    sub('takes-the-low-half-of-the-answer-for-off', ELIGIBLE, '        c->eligible = (uint32_t)c->probe == 1;\n'),
    sub('takes-anything-but-on-for-off', ELIGIBLE, '        c->eligible = c->probe != 0;\n'),
    sub('retries-a-refused-cpu-on', '    c->started = (uint32_t)c->on_raw == 0;\n    return c->started;\n',
        '    c->started = (uint32_t)c->on_raw == 0;\n    if (!c->started) {\n        c->on_raw = smc_cpu_on(c->affinity, r->entry, c->slot);\n'
        '        c->started = (uint32_t)c->on_raw == 0;\n    }\n    return c->started;\n'),
    sub('counts-an-error-as-started', '    c->started = (uint32_t)c->on_raw == 0;\n', '    c->started = 1;\n'),
    sub('starts-an-affinity-that-is-not-in-the-table', '    c->on_raw = smc_cpu_on(c->affinity, r->entry, c->slot);\n',
        '    c->on_raw = smc_cpu_on(c->affinity | 1u, r->entry, c->slot);\n'),
    # -- the three PSCI calls
    sub('cpu-on-is-cpu-suspend', '#define FUNCTION_CPU_ON 0xC4000003u', '#define FUNCTION_CPU_ON 0xC4000001u'),
    sub('affinity-info-is-the-smc32-call', '#define FUNCTION_AFFINITY_INFO 0xC4000004u', '#define FUNCTION_AFFINITY_INFO 0x84000004u'),
    sub('affinity-info-asks-at-level-1', '    uint64_t regs[4] = {FUNCTION_AFFINITY_INFO, affinity, 0, 0};\n',
        '    uint64_t regs[4] = {FUNCTION_AFFINITY_INFO, affinity, 1, 0};\n'),
    sub('cpu-on-has-no-context', '    uint64_t regs[4] = {FUNCTION_CPU_ON, target, entry, context};\n', '    uint64_t regs[4] = {FUNCTION_CPU_ON, target, entry, 0};\n'),
    sub('cpu-on-swaps-entry-and-context', '    c->on_raw = smc_cpu_on(c->affinity, r->entry, c->slot);\n', '    c->on_raw = smc_cpu_on(c->affinity, c->slot, r->entry);\n'),
    # -- slots: one per core, whole lines, never stored into after the clean
    sub('shares-one-slot-between-cores', '    c->slot = r->slot_base + (uint64_t)slot_index * SLOT_BYTES;\n', '    c->slot = r->slot_base;\n'),
    sub('puts-slots-a-line-apart', '    c->slot = r->slot_base + (uint64_t)slot_index * SLOT_BYTES;\n', '    c->slot = r->slot_base + (uint64_t)slot_index * 64u;\n'),
    sub('starts-phase-one-in-the-slot-phase-two-uses', '    start_core(r, c, 0);\n', '    start_core(r, c, 1);\n'),
    sub('numbers-the-phase-two-slots-by-position', 'start_core(r, list[i], (unsigned)(list[i] - r->core));', 'start_core(r, list[i], i);'),
    sub('clears-the-flag-after-the-clean', '    c->called = 1;\n', '    c->called = 1;\n    *(volatile uint64_t *)(uintptr_t)c->slot = 0;\n'),
    sub('keeps-phase-one-in-the-phase-two-struct', '    *c = r->core[PHASE1_TARGET];\n', '    c = &r->core[PHASE1_TARGET];\n'),
    # -- cache maintenance before a start
    drop('does-not-clean-the-image', '    clean_invalidate_range(r->a->payload_base, r->a->payload_size);\n'),
    sub('cleans-one-page-of-the-image', 'clean_invalidate_range(r->a->payload_base, r->a->payload_size);', 'clean_invalidate_range(r->a->payload_base, 4096);'),
    drop('does-not-clean-the-slots', '    clean_invalidate_range(r->slot_base, SLOT_REGION_BYTES);\n'),
    sub('does-not-fence-the-cleaning', PREPARE_END, '    clean_invalidate_range(r->slot_base, SLOT_REGION_BYTES);\n}\n'),
    drop('does-not-zero-the-slots', '    for (unsigned i = 0; i < SLOT_REGION_BYTES / 8; i++) word[i] = 0;\n'),
    sub('zeroes-half-the-slots', 'i < SLOT_REGION_BYTES / 8; i++) word[i] = 0;', 'i < SLOT_REGION_BYTES / 16; i++) word[i] = 0;'),
    sub('invalidates-where-it-must-clean', 'dc_civac(at);', 'dc_ivac(at);'),
    # -- cache maintenance before a read
    sub('reads-the-flag-without-invalidating', FLAG_READ, '    dsb_sy();\n    return kind_of(load64(slot + OFF_DONE));\n'),
    sub('reads-the-flag-without-a-barrier', FLAG_READ, '    dc_ivac(slot);\n    return kind_of(load64(slot + OFF_DONE));\n'),
    sub('reads-the-report-without-invalidating-it', REPORT_READ, '    dsb_sy();\n    for (unsigned i = 0; i < SLOT_WORDS; i++)'),
    sub('invalidates-one-line-of-the-report', 'invalidate_range(slot, SLOT_BYTES);', 'invalidate_range(slot, 64);'),
    sub('reads-the-report-without-a-barrier', '    invalidate_range(slot, SLOT_BYTES);\n    dsb_sy();\n', '    invalidate_range(slot, SLOT_BYTES);\n'),
    # -- announce, wait, then the risky call
    sub('waits-one-second-not-eight', '#define WAIT_BEFORE_CPU_ON_S 8u', '#define WAIT_BEFORE_CPU_ON_S 1u'),
    sub('skips-the-wait-in-phase-one', WAIT % 'P1', '    if (0) {\n        say(&r->out, "P1", "SKIPPED=COUNTER_STUCK", 0);'),
    sub('skips-the-wait-in-phase-two', WAIT % 'P2', '    if (0) {\n        say(&r->out, "P2", "SKIPPED=COUNTER_STUCK", 0);'),
    sub('goes-on-with-a-stuck-counter-in-phase-one', WAIT % 'P1',
        '    wait_ms(r, WAIT_BEFORE_CPU_ON_S * 1000u);\n    if (0) {\n        say(&r->out, "P1", "SKIPPED=COUNTER_STUCK", 0);'),
    sub('goes-on-with-a-stuck-counter-in-phase-two', WAIT % 'P2',
        '    wait_ms(r, WAIT_BEFORE_CPU_ON_S * 1000u);\n    if (0) {\n        say(&r->out, "P2", "SKIPPED=COUNTER_STUCK", 0);'),
    sub('announces-phase-one-after-the-wait', P1_ANNOUNCE + P1_WAIT, P1_WAIT + P1_ANNOUNCE),
    sub('announces-phase-two-after-the-wait', P2_ANNOUNCE + P2_WAIT, P2_WAIT + P2_ANNOUNCE),
    drop('never-announces-phase-one', '    say_next_cpu_on(r, text.buf);\n'),
    drop('never-announces-phase-two', P2_ANNOUNCE),
    drop('never-announces-the-preparation', '    say(&r->out, "NEXT", "PREPARE", 1);\n'),
    drop('never-announces-the-probe', '    say(&r->out, "NEXT", "AFFINITY", 1);\n'),
    sub('prints-between-the-calls-of-the-batch', START_ALL,
        '    for (unsigned i = 0; i < n; i++) {\n        start_core(r, list[i], (unsigned)(list[i] - r->core));\n        say(&r->out, "P2", "STARTED", 0);\n    }\n'),
    # -- when phase 2 may run, and what a normal phase 1 is
    sub('runs-phase-two-after-an-abnormal-phase-one', '    if (normal) phase_two(&r, targets, count);\n    else say(&r.out, "P2", "SKIPPED=P1_NOT_NORMAL", 0);\n',
        '    phase_two(&r, targets, count);\n'),
    sub('calls-every-phase-one-normal', '    return !why;\n', '    return 1;\n'),
    drop('ignores-a-core-that-never-went-off', '    if (!c->off) why |= WHY_NOT_OFF;\n'),
    drop('ignores-a-fault', '        if (kind == KIND_FAULT) why |= WHY_FAULT;\n'),
    drop('ignores-a-wrong-mpidr', '            if (!mpidr_matches(c, &rep)) why |= WHY_MPIDR;\n'),
    drop('ignores-different-id-registers', '            if (id_differences(r, &rep)) why |= WHY_IDS;\n'),
    drop('ignores-another-counter-frequency', '            if (rep.w[OFF_CNTFRQ / 8] != r->cntfrq) why |= WHY_FRQ;\n'),
    sub('takes-a-report-from-another-el-for-el2', 'if (kind == KIND_OTHER_EL || (rep.w[OFF_CURRENTEL / 8] >> 2 & 3) != 2) why |= WHY_NOT_EL2;',
        'if (kind == KIND_OTHER_EL) why |= WHY_NOT_EL2;'),
    # -- timeouts and the wait for OFF
    sub('takes-any-answer-but-on-for-off', 'if (list[i]->last_state == 1) list[i]->off = 1;', 'if (list[i]->last_state != 0) list[i]->off = 1;'),
    sub('waits-ten-seconds-for-the-flag', '#define REPORT_TIMEOUT_ONE_MS 1000u', '#define REPORT_TIMEOUT_ONE_MS 10000u'),
    sub('waits-a-tenth-of-the-time-for-all-flags', '#define REPORT_TIMEOUT_ALL_MS 2000u', '#define REPORT_TIMEOUT_ALL_MS 200u'),
    sub('waits-a-tenth-of-the-time-for-off', '#define OFF_TIMEOUT_MS 2000u', '#define OFF_TIMEOUT_MS 200u'),
    sub('polls-affinity-info-as-fast-as-it-can', '#define OFF_POLL_SPACING_MS 1u', '#define OFF_POLL_SPACING_MS 0u'),
    # -- the page: lines, counts, the verdict of the run
    sub('reserves-no-lines', '#define LINES_RESERVED 6u', '#define LINES_RESERVED 0u'),
    drop('does-not-count-the-lines-it-drops', '        o->suppressed++;\n'),
    sub('counts-an-unreported-core-as-reported', 't.reported += list[i]->started && list[i]->kind != KIND_NONE;', 't.reported += list[i]->started;'),
    sub('counts-a-core-that-is-not-off-as-off', 't.off += list[i]->started && list[i]->off;', 't.off += list[i]->started;'),
    drop('does-not-count-a-phase-two-core-left-running', '    for (unsigned i = 0; i < CORE_COUNT; i++) left += r.core[i].started && !r.core[i].off;\n'),
    drop('does-not-count-the-phase-one-core-left-running', '    left += r.first.started && !r.first.off;\n'),
    sub('returns-zero-with-a-core-left-running', '    return left ? 2 : 0;\n', '    return 0;\n'),
    sub('says-success-for-any-cpu-on-answer', '    if ((uint32_t)raw == 0) {\n        pl_text(item, ":SUCCESS");', '    if (1) {\n        pl_text(item, ":SUCCESS");'),
    sub('names-error-minus-ten', 'if (negated - 1u >= 9u) return 0;', 'if (negated - 1u > 9u) return 0;'),
    sub('ignores-the-counter-frequency-in-the-distance', 'int64_t us = (int64_t)(magnitude * 1000000u / r->freq);', 'int64_t us = (int64_t)(magnitude * 1000000u / 19200000u);'),
    sub('forgets-the-sign-of-the-distance', '    return ticks < 0 ? -us : us;\n', '    return us;\n'),
    sub('compares-the-whole-mpidr', 'return (rep->w[OFF_MPIDR / 8] & AFFINITY_MASK) == c->affinity;', 'return rep->w[OFF_MPIDR / 8] == c->affinity;'),
    sub('compares-the-wrong-id-registers', '    static const uint8_t where[4] = {OFF_MIDR, OFF_MMFR0, OFF_ISAR0, OFF_PFR0};\n    unsigned mask = 0;',
        '    static const uint8_t where[4] = {OFF_MIDR, OFF_ISAR0, OFF_MMFR0, OFF_PFR0};\n    unsigned mask = 0;'),
    # -- where it runs and what it refuses
    sub('runs-at-any-el', 'if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {', 'if (0) {'),
    drop('does-not-check-for-the-counter-op', '    if (!a->ops.counter) return "NO_COUNTER";\n'),
    drop('does-not-check-the-stack-alignment', '(a->stack_base & 127) ||'),
    sub('keeps-no-stack', 'sp < slots_end + STACK_KEPT_BYTES ||', 'sp < slots_end ||'),
    drop('does-not-check-that-the-entry-is-in-the-image', 'r->entry < a->payload_base || r->entry >= image_end ||'),
    sub('does-not-check-that-the-vectors-are-in-the-image', 'r->entry >= image_end || vectors < a->payload_base || vectors >= image_end)', 'r->entry >= image_end)'),
    drop('takes-an-image-of-four-gib', 'a->payload_size >= (UINT64_C(1) << 32) ||'),
    sub('takes-a-stack-pointer-above-the-stack', 'sp > a->stack_base + a->stack_size)', '0)'),
    drop('does-not-check-the-arguments', '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n'),
]


class CpuonMutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    _build = staticmethod(native.Mutants._build)

    def _evaluate(self, *mutant):
        return native.Mutants._evaluate(self, *mutant)

    def test_there_are_enough_distinct_mutants_and_they_all_target_the_payload(self):
        names = [m[0] for m in MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertFalse({m[0] for m in native.MUTANTS} & set(names), 'a name the native suite already uses')
        self.assertGreaterEqual(len(names), 60)
        self.assertEqual({m[1] for m in MUTANTS}, {FILE})
        for wanted in ('probes-the-boot-cpu', 'takes-on-for-off', 'retries-a-refused-cpu-on', 'does-not-clean-the-image',
                       'does-not-clean-the-slots', 'does-not-fence-the-cleaning', 'reads-the-flag-without-invalidating',
                       'reads-the-report-without-invalidating-it', 'waits-one-second-not-eight', 'skips-the-wait-in-phase-one',
                       'skips-the-wait-in-phase-two', 'announces-phase-one-after-the-wait', 'never-announces-the-preparation',
                       'runs-phase-two-after-an-abnormal-phase-one', 'cpu-on-is-cpu-suspend', 'shares-one-slot-between-cores',
                       'clears-the-flag-after-the-clean', 'prints-between-the-calls-of-the-batch', 'polls-affinity-info-as-fast-as-it-can',
                       'returns-zero-with-a-core-left-running', 'goes-on-with-a-stuck-counter-in-phase-one'):
            self.assertIn(f'cpuon-{wanted}', names)

    def test_the_unmutated_control_passes_from_a_copy(self):
        directory = BUILD / 'control'
        native.copy_tree(directory)
        done, binary = self._build('cpuon', directory, relaxed=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary)
        self.assertEqual(code, 0, output[-600:])

    def test_every_seeded_bug_is_caught(self):
        workers = max(1, min(4, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {m[0]: pool.submit(self._evaluate, *m) for m in MUTANTS}
            results = {name: future.result() for name, future in futures.items()}
        for name, (status, detail) in results.items():
            with self.subTest(mutant=name):
                self.assertEqual(status, 'caught', f'{status}: {detail}')


# ---- the binary --------------------------------------------------------------------------------------------------------------

ANCHOR = 'payload_entry(const struct q1n1_payload_args *a)\n{\n'


def asm(text, clobbers='"memory"'):
    return [(ANCHOR, ANCHOR + (f'    __asm__ volatile("{text}" ::: {clobbers});\n' if text else ''))]


def read(register):
    return asm(f'mrs x0, {register}', '"x0", "memory"')


BAD_BINARIES = [
    # (name, [(needle, replacement)], what the allow-list check must say)
    ('a-read-of-cntpoff-el2', read('S3_4_C14_C0_6'), 'the code names'),
    ('a-write-to-cntpoff-el2', asm('msr S3_4_C14_C0_6, xzr'), 'forbidden instruction msr'),
    ('a-second-read-of-cntvoff-el2', read('S3_4_C14_C0_3'), 'is read 2 times'),
    ('a-second-read-of-cntvoff-el2-by-name', read('cntvoff_el2'), 'is read 2 times'),
    ('a-write-to-cntvoff-el2', asm('msr cntvoff_el2, xzr'), 'forbidden instruction msr cntvoff_el2'),
    ('a-read-of-an-unlisted-register', read('ttbr0_el2'), 'registers read'),
    ('a-read-of-the-virtual-counter', read('CNTVCT_EL0'), 'registers read'),
    ('an-extra-smc', asm('smc #0'), '4 smc instructions'),
    ('an-extra-smc-with-a-readable-id', asm('mov w0, #8\\n movk w0, #0x8400, lsl #16\\n smc #0'), 'smc function ids'),
    ('an-smc-with-another-immediate', asm('smc #1'), 'another immediate than #0'),
    ('a-different-cpu-on-id', [('#define FUNCTION_CPU_ON 0xC4000003u', '#define FUNCTION_CPU_ON 0x84000009u')], 'smc function ids'),
    ('the-smc32-cpu-on-id', [('#define FUNCTION_CPU_ON 0xC4000003u', '#define FUNCTION_CPU_ON 0x84000003u')], 'smc function ids'),
    ('a-different-affinity-info-id', [('#define FUNCTION_AFFINITY_INFO 0xC4000004u', '#define FUNCTION_AFFINITY_INFO 0xC4000001u')], 'smc function ids'),
    ('a-different-cpu-off-id', [('    "    mov w0, #2\\n"', '    "    mov w0, #8\\n"')], 'smc function ids'),
    ('an-id-the-code-cannot-prove', [('    register uint64_t x0 __asm__("x0") = FUNCTION_CPU_ON;\n',
                                      '    volatile uint64_t id_ = FUNCTION_CPU_ON;\n    register uint64_t x0 __asm__("x0") = id_;\n')], 'cannot be read'),
    ('an-msr-to-sctlr-el2', asm('msr sctlr_el2, xzr'), 'forbidden instruction msr sctlr_el2'),
    ('an-msr-to-hcr-el2', asm('msr hcr_el2, xzr'), 'forbidden instruction msr hcr_el2'),
    ('an-msr-to-elr-el2', asm('msr elr_el2, xzr'), 'forbidden instruction msr elr_el2'),
    ('an-msr-to-tpidr-el2', asm('msr tpidr_el2, xzr'), 'forbidden instruction msr tpidr_el2'),
    ('an-msr-to-vbar-el1', asm('msr vbar_el1, xzr'), 'forbidden instruction msr vbar_el1'),
    ('an-msr-to-daifclr', asm('msr daifclr, #15'), 'forbidden instruction msr daifclr'),
    ('an-msr-to-spsel', asm('msr spsel, #1'), 'forbidden instruction msr spsel'),
    ('an-hvc', asm('hvc #0'), 'hvc'),
    ('an-svc', asm('svc #0'), 'svc'),
    ('an-eret', asm('eret'), 'eret'),
    ('a-wfi', asm('wfi'), 'wfi'),
    ('an-sev', asm('sev'), 'sev'),
    ('an-sevl', asm('sevl'), 'sevl'),
    ('a-dmb', asm('dmb sy'), 'dmb'),
    ('a-tlb-operation', asm('tlbi alle2'), 'tlbi'),
    ('an-instruction-cache-operation', asm('ic iallu'), 'forbidden instruction ic'),
    ('an-address-translation', asm('at s1e2r, x0'), 'forbidden instruction at'),
    ('a-clean-without-invalidate', asm('dc cvac, x0'), 'forbidden instruction dc cvac'),
    ('a-zeroing-operation', asm('dc zva, x0'), 'forbidden instruction dc zva'),
    ('a-set-way-operation', asm('dc cisw, x0'), 'forbidden instruction dc cisw'),
    ('an-exclusive-load', asm('ldxr x9, [sp]'), 'ldxr'),
    ('an-atomic-add', asm('.arch_extension lse\\n ldadd x9, x10, [sp]'), 'ldadd'),
    ('a-word-that-is-no-instruction', asm('.inst 0xffffffff'), 'not a known instruction'),
]
# Instructions put into each older payload: each form cpuon's policy allows must be refused to the others, and the new engine
# must answer exactly as the old on all of them.
CORPUS_FORMS = {
    'clean': '', 'msr-vbar-el2': 'msr vbar_el2, x0', 'msr-daifset': 'msr daifset, #15', 'msr-sctlr-el2': 'msr sctlr_el2, xzr',
    'msr-cntvoff': 'msr cntvoff_el2, xzr', 'dc-civac': 'dc civac, x0', 'dc-ivac': 'dc ivac, x0', 'dc-cvac': 'dc cvac, x0', 'wfe': 'wfe',
    'wfi': 'wfi', 'sev': 'sev', 'isb': 'isb', 'dsb': 'dsb sy', 'dmb': 'dmb sy', 'hvc': 'hvc #0', 'svc': 'svc #0', 'smc': 'smc #0',
    'eret': 'eret', 'tlbi': 'tlbi alle2', 'ic': 'ic iallu', 'at': 'at s1e2r, x0', 'ldxr': 'ldxr x9, [sp]', 'word': '.inst 0xffffffff',
}
CORPUS_READS = {'mrs-cntvoff': 'S3_4_C14_C0_3', 'mrs-cntpoff': 'S3_4_C14_C0_6', 'mrs-midr': 'midr_el1', 'mrs-vbar-el2': 'vbar_el2'}
THE_NEW_FORMS = {'msr-vbar-el2': 'msr', 'msr-daifset': 'msr', 'dc-civac': 'dc', 'dc-ivac': 'dc', 'wfe': 'wfe'}


class Builder:
    """Builds a copy of a payload with edits, below one directory."""

    def __init__(self, directory):
        self.out = directory
        shutil.rmtree(self.out, ignore_errors=True)
        self.out.mkdir(parents=True)

    def build(self, payload, name, edits, check=False):
        text = (ROOT / 'payloads' / f'{payload}.c').read_text(encoding='utf-8')
        for needle, replacement in edits:
            assert text.count(needle) == 1, f'{name}: {needle[:60]!r} is not in {payload}.c exactly once'
            text = text.replace(needle, replacement, 1)
        path = self.out / f'{name}.c'
        path.write_text(text, encoding='utf-8')
        return lib.build_payload(path, self.out, name=name, check=check)


def need_tools():
    for tool in ('clang', 'ld.lld', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy'):
        if not have(tool):
            raise unittest.SkipTest(f'{tool} not installed')


def facts(elf, flat):
    """What the binary holds, as the document states it."""
    dis = run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout
    found = (re.match(r'\s+[0-9a-f]+:\s+(\S+)\s*(.*)$', line) for line in dis.splitlines())
    instructions = [(m.group(1).lower(), m.group(2).split('//')[0].strip()) for m in found if m]
    data = Path(flat).read_bytes()
    ids, unreadable = lib.smc_function_ids(dis)
    first = lambda operands: operands.split(',')[0].strip().lower()  # noqa: E731
    last = lambda operands: operands.split(',')[-1].strip().lower()  # noqa: E731
    return {
        'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'instructions': len(instructions),
        'mnemonics': Counter(m for m, _ in instructions),
        'mrs': Counter(lib.SYSTEM_REGISTER_ALIASES.get(last(o), last(o)) for m, o in instructions if m == 'mrs'),
        'msr': Counter(first(o) for m, o in instructions if m == 'msr'), 'dc': Counter(first(o) for m, o in instructions if m == 'dc'),
        'smc': [o for m, o in instructions if m == 'smc'], 'smc_ids': sorted(ids), 'smc_unreadable': unreadable,
    }


class CpuonBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.out = BUILD / 'bad-binaries'
        cls.builder = Builder(cls.out)
        done, cls.elf, cls.flat = cls.builder.build('cpuon', 'control', [], check=True)
        if done.returncode:
            raise RuntimeError(done.stderr[-1500:])

    def test_the_unmodified_payload_is_clean_and_fits_the_policy(self):
        policy = lib.POLICIES['cpuon']
        self.assertEqual(lib.binary_violations(self.elf, self.flat, policy, READELF()), [])
        self.assertEqual((policy['smc'], policy['single_reads'], policy['smc_ids']),
                         (3, {lib.CNTVOFF_EL2}, (0x84000002, 0xC4000003, 0xC4000004)))
        self.assertEqual(policy['allow'], {'msr': {'vbar_el2', 'daifset'}, 'dc': {'civac', 'ivac'}, 'wfe': {''}})
        self.assertGreaterEqual(policy['forbid'], {'dmb', 'sb', 'sev', 'sevl'})
        self.assertFalse(policy.get('timer_offsets'), 'cpuon must not be allowed the timer offsets as the timer payload is')
        self.assertNotIn(lib.CNTPOFF_EL2, policy['registers'] | policy['single_reads'])
        size = Path(self.flat).stat().st_size
        self.assertTrue(8192 < size <= policy['bytes'] <= 20480, f'{size} bytes against a budget of {policy["bytes"]}')

    def test_the_instruction_inventory_is_what_the_document_says(self):
        f = facts(self.elf, self.flat)
        self.assertEqual(set(f['mrs']) - {lib.CNTVOFF_EL2}, lib.POLICIES['cpuon']['registers'])
        self.assertEqual(f['mrs'][lib.CNTVOFF_EL2], 1, 'CNTVOFF_EL2 is read once, by the stub')
        self.assertEqual(dict(f['msr']), {'vbar_el2': 1, 'daifset': 1})
        self.assertEqual(dict(f['dc']), {'civac': 4, 'ivac': 1})
        self.assertEqual((f['smc'], f['smc_ids'], f['smc_unreadable']), (['#0'] * 3, [0x84000002, 0xC4000003, 0xC4000004], []))
        self.assertEqual((f['mnemonics']['wfe'], f['mnemonics']['isb'], f['mnemonics']['dsb']), (1, 1, 7))
        for mnemonic in ('hvc', 'svc', 'eret', 'wfi', 'sev', 'sevl', 'dmb', 'tlbi', 'ic', 'at', 'sys', 'sysl', 'brk', 'hlt'):
            self.assertEqual(f['mnemonics'][mnemonic], 0, mnemonic)
        self.assertFalse([m for m in f['mnemonics'] if re.match(r'^(ldx|ldax|stx|stlx|cas|swp|ldadd|ldset|ldclr|ldeor)', m)])

    def test_every_forbidden_addition_is_named_by_the_allow_list_check(self):
        self.assertGreaterEqual(len(BAD_BINARIES), 30)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            built = list(pool.map(lambda b: (b, self.builder.build('cpuon', b[0], b[1])), BAD_BINARIES))
        for (name, _, expected), (done, elf, flat) in built:
            with self.subTest(binary=name):
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                problems = lib.binary_violations(elf, flat, lib.POLICIES['cpuon'], READELF())
                self.assertTrue(problems, 'the check passed a binary it must refuse')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_a_flat_binary_patched_behind_the_disassembly_is_caught_by_the_encoding_layer_alone(self):
        data = bytearray(Path(self.flat).read_bytes())
        words = struct.unpack(f'<{len(data) // 4}I', bytes(data))
        policy = lib.POLICIES['cpuon']
        self.assertEqual(lib.binary_violations(self.elf, self.flat, policy, READELF()), [])
        wanted = (
            ('msr vbar_el2, x3 to msr sctlr_el2, x3', lambda w: w & 0xffffffe0 == 0xd51cc000, lambda w: 0xd51c1000 | w & 31, 'msr-register'),
            ('msr daifset to msr daifclr', lambda w: w & 0xfffff0ff == 0xd50340df, lambda w: w & ~0xff | 0xff, 'msr-immediate'),
            ('dc civac to dc cvac', lambda w: w & 0xffffffe0 == 0xd50b7e20, lambda w: 0xd50b7a20 | w & 31, 'sys'),
            ('dc ivac to dc isw', lambda w: w & 0xffffffe0 == 0xd5087620, lambda w: 0xd5087640 | w & 31, 'sys'),
            ('wfe to wfi', lambda w: w == 0xd503205f, lambda w: 0xd503207f, 'wfi'),
            ('smc to hvc', lambda w: w == 0xd4000003, lambda w: 0xd4000002, 'hvc'),
            ('smc to svc', lambda w: w == 0xd4000003, lambda w: 0xd4000001, 'svc'),
            ('dsb to dmb', lambda w: w == 0xd5033f9f, lambda w: 0xd5033fbf, 'dmb'),
        )
        for label, is_target, patch, what in wanted:
            with self.subTest(patch=label):
                at = next(i for i, w in enumerate(words) if is_target(w))
                patched = bytearray(data)
                struct.pack_into('<I', patched, at * 4, patch(words[at]))
                path = self.out / 'patched.bin'
                path.write_bytes(patched)
                problems = lib.binary_violations(self.elf, path, policy, READELF())
                self.assertTrue(any(f'a word of the code encodes {what}' in p for p in problems), problems)

    def test_the_binary_is_refused_under_every_other_policy_and_the_others_under_its_own(self):
        for other in OLD_POLICIES:
            with self.subTest(policy=other):
                self.assertTrue(lib.binary_violations(self.elf, self.flat, lib.POLICIES[other], READELF()))
        out = BUILD / 'others'
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        for other in OLD_POLICIES:
            with self.subTest(payload=other):
                done, o_elf, o_flat = lib.build_payload(ROOT / 'payloads' / f'{other}.c', out, name=other, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertTrue(lib.binary_violations(o_elf, o_flat, lib.POLICIES['cpuon'], READELF()),
                                f'{other} passes the cpuon policy: the policy is too loose')

    def test_two_builds_from_the_same_tree_are_byte_identical(self):
        done, _, flat = Builder(BUILD / 'again').build('cpuon', 'control', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(Path(flat).read_bytes(), Path(self.flat).read_bytes())
        self.assertEqual(Path(self.flat).read_bytes()[:4], bytes.fromhex('5f2403d5'), 'BTI c first, as the runner expects')


class CpuonEngine(unittest.TestCase):
    """The engine's new keys against the engine of the base commit, and the id reader on synthetic input."""
    LEGACY_BARRIER_WORDS = {'isb': (0xfffff0ff, 0xd50330df), 'dsb': (0xfffff0ff, 0xd503309f), 'dmb': (0xfffff0ff, 0xd50330bf)}

    @classmethod
    def setUpClass(cls):
        need_tools()
        names = ('Counter', 'Path', 're', 'struct', 'run', 'FORBIDDEN', 'EXCLUSIVE', 'ATOMIC', 'TIMER_OFFSETS', 'FORBIDDEN_WORDS',
                 'SYSTEM_REGISTER_ALIASES', 'CNTVOFF_EL2', 'CNTPOFF_EL2')
        namespace = {name: getattr(lib, name) for name in names}
        namespace['BARRIER_WORDS'] = cls.LEGACY_BARRIER_WORDS
        exec(OLD_ENGINE.read_text(encoding='utf-8'), namespace)
        cls.old_engine = staticmethod(namespace['binary_violations'])
        cls.builder = Builder(BUILD / 'corpus')
        jobs = [(p, n, asm(t)) for p in OLD_POLICIES for n, t in CORPUS_FORMS.items()]
        jobs += [(p, n, read(r)) for p in OLD_POLICIES for n, r in CORPUS_READS.items()]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            cls.corpus = list(pool.map(lambda j: (j[0], j[1], cls.builder.build(j[0], f'{j[0]}-{j[1]}', j[2])), jobs))
        for payload, name, (done, _, _) in cls.corpus:
            if done.returncode:
                raise RuntimeError(f'{payload}-{name} did not build: {done.stderr[-600:]}')

    def test_the_frozen_old_engine_is_the_one_of_the_base_commit(self):
        shown = subprocess.run(['git', 'show', f'{BASE_COMMIT}:tools/sp11_payload_testlib.py'], cwd=ROOT, capture_output=True, text=True)
        if shown.returncode:
            self.skipTest(f'the base commit {BASE_COMMIT} is not in this repository: {shown.stderr.strip()[:80]}')
        old = re.search(r'^def binary_violations\(.*?(?=^def _string_at)', shown.stdout, re.M | re.S).group(0)
        frozen = OLD_ENGINE.read_text(encoding='utf-8')
        self.assertEqual(old.rstrip(), frozen[frozen.index('def binary_violations'):].rstrip())

    def test_the_older_policies_do_not_use_the_new_keys(self):
        for name in OLD_POLICIES:
            self.assertFalse({'allow', 'smc_ids', 'single_reads'} & set(lib.POLICIES[name]), name)
        self.assertLessEqual(set(OLD_POLICIES) | {'cpuon'}, set(lib.POLICIES))
        self.assertEqual(lib.POLICIES['state']['registers'], lib.STATE_REGISTERS)

    def test_the_new_engine_answers_exactly_as_the_old_on_every_corpus_binary_under_every_older_policy(self):
        self.assertGreaterEqual(len(self.corpus), 4 * (len(CORPUS_FORMS) + len(CORPUS_READS)))

        def compare(item):
            payload, name, (_, elf, flat) = item
            return [(payload, name, policy, self.old_engine(elf, flat, lib.POLICIES[policy], READELF()),
                     lib.binary_violations(elf, flat, lib.POLICIES[policy], READELF())) for policy in OLD_POLICIES]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = [row for rows in pool.map(compare, self.corpus) for row in rows]
        refused = 0
        for payload, name, policy, old, new in results:
            with self.subTest(binary=f'{payload}-{name}', policy=policy):
                self.assertEqual(old, new)
            refused += bool(old)
        self.assertGreater(refused, len(results) // 2, 'the corpus must exercise the refusals, not only the clean cases')

    def test_every_clean_binary_still_passes_its_own_policy_and_only_its_own(self):
        for payload, name, (_, elf, flat) in self.corpus:
            if name != 'clean':
                continue
            for policy in OLD_POLICIES:
                with self.subTest(payload=payload, policy=policy):
                    problems = lib.binary_violations(elf, flat, lib.POLICIES[policy], READELF())
                    self.assertEqual(problems == [], payload == policy, problems[:3])

    def test_an_instruction_cpuon_may_use_is_refused_in_every_other_payload(self):
        for payload, name, (_, elf, flat) in self.corpus:
            if name not in THE_NEW_FORMS:
                continue
            with self.subTest(payload=payload, form=name):
                problems = lib.binary_violations(elf, flat, lib.POLICIES[payload], READELF())
                self.assertTrue(any(f'forbidden instruction {THE_NEW_FORMS[name]}' in p for p in problems), problems)
                self.assertTrue(any('a word of the code encodes' in p for p in problems), 'the encoding layer says so too')

    def test_the_timer_offsets_stay_with_the_payloads_that_may_read_them(self):
        for payload, name, (_, elf, flat) in self.corpus:
            if name not in ('mrs-cntvoff', 'mrs-cntpoff'):
                continue
            with self.subTest(payload=payload, form=name):
                problems = lib.binary_violations(elf, flat, lib.POLICIES[payload], READELF())
                self.assertTrue(any('the code names' in p for p in problems) or payload == 'timer', problems)

    # -- the id reader and the policy checks, on synthetic input ---------------------------------------------------------------
    @staticmethod
    def dis(*body):
        lines = ['0000000000001000 <f>:']
        for at, item in enumerate(body):
            lines.append(item if item.startswith('0') else f'    {0x1000 + 4 * at:x}: {item}')
        return '\n'.join(lines) + '\n'

    def ids(self, *body):
        return lib.smc_function_ids(self.dis(*body))

    def test_the_id_reader_reads_a_straight_line_run_into_w0_or_x0(self):
        self.assertEqual(self.ids('mov w0, #0x2   // =2', 'movk w0, #0x8400, lsl #16', 'smc #0')[0], [0x84000002])
        self.assertEqual(self.ids('mov w0, #0x3', 'mov x1, xzr', 'movk w0, #0xc400, lsl #16', 'mov x3, xzr', 'smc #0'), ([0xc4000003], []))
        self.assertEqual(self.ids('mov x0, #0x4', 'movk x0, #0xc400, lsl #16', 'smc #0')[0], [0xc4000004])
        self.assertEqual(self.ids('mov w0, #0x1', 'movk w0, #0xc400, lsl #16', 'movk w0, #0x4', 'smc #0')[0], [0xc4000004])
        self.assertEqual(self.ids('mov w0, #0xfffffffe   // =4294967294', 'smc #0')[0], [0xfffffffe])
        self.assertEqual(self.ids('mov w0, #-2', 'smc #0')[0], [0xfffffffe])
        self.assertEqual(self.ids('movz w0, #0x8400, lsl #16', 'movk w0, #0x8', 'smc #0')[0], [0x84000008])
        self.assertEqual(self.ids('mov w0, #0x2', 'smc #0', 'mov w0, #0x3', 'smc #0')[0], [2, 3])

    def test_an_id_that_cannot_be_proved_is_unreadable_never_a_pass(self):
        cases = {
            'no definition': ('smc #0',),
            'w0 from a register': ('mov w0, w1', 'smc #0'),
            'w0 loaded': ('ldr w0, [sp]', 'smc #0'),
            'w0 computed': ('mov w0, #0x2', 'add w0, w0, #0x1', 'smc #0'),
            'w0 named by something else': ('mov w0, #0x2', 'mov x1, x0', 'smc #0'),
            'a call between': ('mov w0, #0x2', 'bl 0x2000 <g>', 'smc #0'),
            'a branch between': ('mov w0, #0x2', 'cbz x1, 0x2000 <g>', 'smc #0'),
            'a return between': ('mov w0, #0x2', 'ret', 'smc #0'),
            'a symbol between': ('mov w0, #0x2', '0000000000001010 <g>:', 'smc #0'),
            'only a movk': ('movk w0, #0x8400, lsl #16', 'smc #0'),
            'a halfword w0 does not have': ('mov w0, #0x2', 'movk w0, #0x8400, lsl #32', 'smc #0'),
            'a join inside the run': ('mov w0, #0x2', 'movk w0, #0x8400, lsl #16', 'smc #0', 'b.eq 0x1004 <f+0x4>'),
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                ids, unreadable = self.ids(*body)
                self.assertEqual((ids, len(unreadable)), ([], 1), (ids, unreadable))
        self.assertEqual(self.ids('mov w0, #0x2', 'smc #0', 'smc #0')[0], [2], 'the second of two smc in a row has no id of its own')
        self.assertEqual(len(self.ids('mov w0, #0x2', 'smc #0', 'smc #0')[1]), 1)
        self.assertEqual(self.ids('mov w0, #0x2', 'smc #0', 'b.eq 0x1000 <f>')[0], [2], 'a branch back to the first instruction, after the smc, is no join')

    def test_a_policy_that_contradicts_itself_or_names_a_form_with_no_encoding_is_refused(self):
        done, elf, flat = Builder(BUILD / 'policy-errors').build('cpuon', 'control', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        base = lib.POLICIES['cpuon']
        self.assertEqual(lib.binary_violations(elf, flat, base, READELF()), [])
        for label, change, expected in (
                ('cntpoff-in-single-reads', {'single_reads': {lib.CNTVOFF_EL2, lib.CNTPOFF_EL2}}, 'never returns on this unit'),
                ('wfe-allowed-and-forbidden', {'forbid': {'wfe', 'dmb'}}, 'both allows and forbids wfe'),
                ('a-form-with-no-encoding', {'allow': {'msr': {'vbar_el2', 'daifset', 'spsel'}, 'dc': {'civac', 'ivac'}, 'wfe': {''}}},
                 'no encoding is known for the allowed form msr spsel'),
                ('dc-not-allowed', {'allow': {'msr': {'vbar_el2', 'daifset'}, 'wfe': {''}}}, 'forbidden instruction dc'),
                ('one-id-too-few', {'smc_ids': (0xC4000003, 0xC4000004)}, 'smc function ids'),
                ('cntvoff-not-allowed', {'single_reads': set()}, 'the code names'),
                ('smc-count-too-low', {'smc': 2}, '3 smc instructions'),
                ('too-few-bytes', {'bytes': 4096}, 'bytes, the policy allows 4096')):
            with self.subTest(policy=label):
                problems = lib.binary_violations(elf, flat, dict(base, **change), READELF())
                self.assertTrue(any(expected in p for p in problems), problems)


def facts_main():
    need_tools()
    done, elf, flat = Builder(BUILD / 'facts').build('cpuon', 'cpuon', [], check=True)
    if done.returncode:
        sys.exit(done.stderr)
    f = facts(elf, flat)
    print(f'cpuon.bin: {f["bytes"]} bytes, sha256 {f["sha256"]}, {f["instructions"]} instructions')
    print('mnemonics:', ', '.join(f'{m} {n}' for m, n in sorted(f['mnemonics'].items())))
    print('registers read:', ', '.join(f'{r} x{n}' for r, n in sorted(f['mrs'].items())))
    print('msr operands:', dict(f['msr']))
    print('dc operands:', dict(f['dc']))
    print('smc:', f['smc'], 'function ids', [hex(i) for i in f['smc_ids']], 'unreadable', f['smc_unreadable'])
    print('allow-list violations:', lib.binary_violations(elf, flat, lib.POLICIES['cpuon'], READELF()))


if __name__ == '__main__':
    if sys.argv[1:] == ['facts']:
        facts_main()
    else:
        sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
