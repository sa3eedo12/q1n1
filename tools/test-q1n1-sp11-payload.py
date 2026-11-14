#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native tests, seeded-bug mutants and source audits for the Surface Pro 11 stick payload runner
(platform/uefi/sp11-payload-*, payloads/, docs/SP11-PAYLOAD.md and docs/SP11-PAYLOAD-TIMER.md).

    python3 tools/test-q1n1-sp11-payload.py

Runs, under ASan and UBSan:
  * Native: the native programs, each built from the real sources --
    tools/test-q1n1-sp11-payload-load.c (the volume-only loader against a fake firmware: ConnectController
    and every other call outside the loader's list is a tripwire, a manifest on a second volume is never
    read, nothing is written; which files are payloads by name), -plan.c (declared ranges, the memory-map
    rules slbounce applies, the text layer, the ABI layout), -run.c (the EL2 sequence for one payload, the
    second hash, the ops and the load32 policy), -chain.c (several payloads in one boot), -state.c (the
    reference payload against a scripted register file), -psci.c (the psci payload against a scripted
    register file and a scripted SMC) and -timer.c (the timer payload against a scripted register file and
    counter);
  * Mutants: seeded bugs, each applied to a copy of the sources under build/, each of which the programs
    must reject (a failing, hanging or -- for the ABI -- non-compiling program catches it), against an
    unmutated control that must pass the same way. The chain's and psci's own seeded bugs are in
    tools/test-q1n1-sp11-payload-chain.py and the timer's in tools/test-q1n1-sp11-payload-timer.py, which
    run them through the same machinery;
  * SourceAudit: what no run can show -- SPDX lines, that the loader makes only its listed firmware calls,
    that nothing of the runner stores, that the main.c glue forwards loads only and is wholly under the
    gate, that nothing of it sits between the last GetMemoryMap and ExitBootServices, the constants shared
    with slbounce, that the documentation's ABI table is the compiled one, that both documents start with their
    licence line and stay within the size limit, and that no machine identifier is in any new file.

SLBOUNCE_SP11_DIR (the paired slbounce fork) adds the comparison of the runner's memory-map verdicts with
slbounce's own sp11_sweep_range over 30000 random maps; without it that comparison is SKIPPED, and said
to be. Nothing is written outside build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
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
PAYLOADS = ROOT / 'payloads'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD.md'
DOC_TIMER = ROOT / 'docs' / 'SP11-PAYLOAD-TIMER.md'
DOCS = [DOC, DOC_TIMER]
BUILD = ROOT / 'build' / 'sp11-payload-test'
LLVM = ('/opt/homebrew/opt/llvm/bin', '/opt/homebrew/opt/lld/bin', '/opt/homebrew/bin')
ENV = dict(os.environ, PATH=os.pathsep.join(LLVM + (os.environ.get('PATH', ''),)), PYTHONDONTWRITEBYTECODE='1')
SANITIZE = ['-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
            '-Wall', '-Wextra', '-Werror']
# A mutant may leave a variable unused; that is no reason for it not to build.
RELAXED = ['-Wno-unused-variable', '-Wno-unused-parameter', '-Wno-unused-function', '-Wno-unused-but-set-variable']
GATES = ['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1']
SLBOUNCE_DIR = os.environ.get('SLBOUNCE_SP11_DIR')
RUN_TIMEOUT = 120

# name: test program, runner sources it links, suites it must run, fewest checks, PASS label
PROGRAMS = {
    'load': ('tools/test-q1n1-sp11-payload-load.c',
             ['sp11-payload-load.c', 'sp11-payload-plan.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c'],
             6, 13000, 'loader'),
    'plan': ('tools/test-q1n1-sp11-payload-plan.c', ['sp11-payload-plan.c', 'sp11-payload-text.c'], 6, 20000, 'plan'),
    'run': ('tools/test-q1n1-sp11-payload-run.c',
            ['sp11-payload-run.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c'], 5, 140, 'run'),
    'chain': ('tools/test-q1n1-sp11-payload-chain.c',
              ['sp11-payload-run.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c'], 6, 220, 'chain'),
    'state': ('tools/test-q1n1-sp11-payload-state.c', ['sp11-payload-text.c'], 3, 900, 'state'),
    'psci': ('tools/test-q1n1-sp11-payload-psci.c', ['sp11-payload-text.c'], 7, 90000, 'psci'),
    'timer': ('tools/test-q1n1-sp11-payload-timer.c', ['sp11-payload-text.c'], 8, 8000, 'timer'),
}
# The programs that test a payload's own source, built natively with a scripted register file (and SMC).
HOST_PAYLOADS = {'state': 'state.c', 'psci': 'psci.c', 'timer': 'timer.c'}
# What a copy of the tree needs: the runner, its dependencies, the survey's text file (the panel layout the
# runner copies is compared with it) and the payload sources.
UEFI_COPIED = sorted(p.name for p in UEFI.glob('sp11-payload*')) + [
    'preload.c', 'preload.h', 'sha256.c', 'sha256.h', 'efi.h', 'sp11-ebs-ranges.h', 'sp11-fbgop.c', 'sp11-fbgop.h',
    'sp11-stk-text.c', 'sp11-stk-survey.h']
PAYLOADS_COPIED = ['payload-util.h', 'state.c', 'psci.c', 'timer.c']

NEW_SOURCES = sorted(UEFI.glob('sp11-payload*')) + sorted(PAYLOADS.glob('*')) + sorted(
    (ROOT / 'tools').glob('test-q1n1-sp11-payload*')) + sorted((ROOT / 'tools').glob('sp11_payload_*')) + sorted(
    (ROOT / 'tools' / 'testdata').glob('sp11-payload-*'))


def run(cmd, cwd=ROOT, timeout=None, **kw):
    return subprocess.run(cmd, cwd=cwd, env=ENV, capture_output=True, text=True, timeout=timeout, **kw)


def have(tool):
    return shutil.which(tool, path=ENV['PATH']) is not None


def slbounce_source():
    return Path(SLBOUNCE_DIR) / 'src' if SLBOUNCE_DIR and (Path(SLBOUNCE_DIR) / 'src' / 'sp11_scoped_sweep.c').is_file() else None


def build_program(name, uefi, payloads, out_dir, relaxed=False):
    """Compiles one native program against the sources in `uefi` (and `payloads`). Returns
    (completed process, binary). The plan program also links the survey's text file, for the layout
    comparison, and slbounce's sweep, when the fork is given."""
    out_dir.mkdir(parents=True, exist_ok=True)
    test_c, libs = PROGRAMS[name][:2]
    binary = out_dir / f'test-{name}'
    flags = ['-I', str(uefi), '-I', str(payloads), '-DQ1N1_PAYLOAD_HOST_TEST=1'] if name in HOST_PAYLOADS else ['-I', str(uefi)]
    objects = [str((Path(uefi) / lib).resolve()) for lib in libs]
    if name in HOST_PAYLOADS:
        objects.append(str((Path(payloads) / HOST_PAYLOADS[name]).resolve()))
    if name == 'plan':
        survey = Path(uefi) / 'sp11-stk-text.c'
        if survey.is_file():
            obj = out_dir / 'stk-text.o'
            done = run(['clang', '-std=gnu11', '-O1', '-g', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_STK_SURVEY=1',
                        '-I', str(uefi), '-c', str(survey), '-o', str(obj)])
            if done.returncode:
                return done, binary
            objects.append(str(obj))
            flags.append('-DHAVE_SURVEY_LAYOUT')
        sweep = slbounce_source()
        if sweep:
            objects.append(str(sweep / 'sp11_scoped_sweep.c'))
            flags += ['-I', str(sweep), '-DHAVE_SLBOUNCE_SWEEP', '-DSLBOUNCE_SCOPED_SWEEP']
    cmd = ['clang'] + SANITIZE + (RELAXED if relaxed else []) + GATES + flags + [str(ROOT / test_c)] + objects + ['-o', str(binary)]
    return run(cmd), binary


def run_program(binary, *args):
    """(returncode, output); a hang is reported as returncode None."""
    try:
        done = run([str(binary)] + (list(args) or ['all']), timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired as hung:
        return None, (hung.stdout or '') if isinstance(hung.stdout, str) else ''
    return done.returncode, done.stdout + done.stderr


class Native(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def _check(self, name, minimum=None):
        _, _, suites, fewest, label = PROGRAMS[name]
        done, binary = build_program(name, UEFI, PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = run_program(binary)
        self.assertEqual(code, 0, output)
        found = re.search(rf'PASS: (\d+) payload {label} suites, (\d+) checks', output)
        self.assertIsNotNone(found, output)
        self.assertEqual(int(found.group(1)), suites, output)
        self.assertGreaterEqual(int(found.group(2)), minimum or fewest, 'a suite stopped checking what it used to')
        self.assertNotIn('FAIL', output)
        return output

    def test_loader_suites_pass_and_nothing_outside_the_boot_volume_is_touched(self):
        self._check('load')

    def test_plan_map_text_and_abi_suites_pass(self):
        output = self._check('plan', 58000 if slbounce_source() else None)
        if slbounce_source():
            self.assertNotIn('SKIP: slbounce', output, 'the comparison with slbounce was asked for and did not run')
        self.assertNotIn('SKIP: survey', output, 'the layout comparison with the survey did not run')

    @unittest.skipUnless(slbounce_source(), 'SLBOUNCE_SP11_DIR not set: no slbounce sweep to compare with')
    def test_the_runner_predicts_slbounces_verdict_on_random_maps(self):
        done, binary = build_program('plan', UEFI, PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = run_program(binary, 'slbounce')
        self.assertEqual(code, 0, output)
        self.assertRegex(output, r'PASS: 1 payload plan suites, [3-9]\d{4} checks')

    def test_run_suites_pass(self):
        self._check('run')

    def test_the_reference_payload_reads_only_what_it_documents(self):
        self._check('state')

    def test_each_program_runs_one_suite_at_a_time(self):
        done, binary = build_program('plan', UEFI, PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = run_program(binary, 'precheck')
        self.assertEqual(code, 0, output)
        self.assertRegex(output, r'PASS: 1 payload plan suites, \d+ checks')


# One seeded bug per property the runner's safety rests on. Each edit's needle must occur exactly once, so
# a change to the source that moves a target is reported as a stale mutant and not as a survivor.
# (name, file below the copy's root, [(needle, replacement)], programs that must reject it, build error that
# counts as rejecting it). The programs are listed in the order they are tried.
ALL = ['load', 'plan', 'run', 'chain', 'state', 'psci', 'timer']
LOAD = 'uefi/sp11-payload-load.c'
PLAN = 'uefi/sp11-payload-plan.c'
RUNC = 'uefi/sp11-payload-run.c'
TEXT = 'uefi/sp11-payload-text.c'
HDR = 'uefi/sp11-payload.h'
ABI = 'uefi/sp11-payload-abi.h'
STATE = 'payloads/state.c'
MUTANTS = [
    # -- the loader: one volume, read only, exactly what the manifest says
    ('loader-connects-a-controller', LOAD, [(
        '    if (!image->device) return Q1N1_PAYLOAD_E_NO_DEVICE;\n',
        '    if (!image->device) return Q1N1_PAYLOAD_E_NO_DEVICE;\n    bs->connect_controller(image->device, NULL, NULL, 1);\n')], ['load'], None),
    ('loader-enumerates-the-volumes', LOAD, [(
        '    efi_status status = bs->handle_protocol(image->device, &fs_guid, (void **)&fs);\n',
        '    efi_handle *all = NULL;\n    uint64_t all_n = 0;\n    bs->locate_handle_buffer(2, &fs_guid, NULL, &all_n, &all);\n'
        '    efi_status status = bs->handle_protocol(image->device, &fs_guid, (void **)&fs);\n')], ['load'], None),
    ('loader-opens-files-for-writing', HDR, [(
        '#define Q1N1_PAYLOAD_FILE_MODE_READ 1u', '#define Q1N1_PAYLOAD_FILE_MODE_READ 3u')], ['load'], None),
    ('loader-accepts-bytes-after-the-end', LOAD, [(
        '    return status ? status : n ? EFI_INVALID_PARAMETER : 0;', '    return status;')], ['load'], None),
    ('loader-skips-the-size-check', LOAD, [(
        '    if (status || bytes != want->size) {', '    if (status) {')], ['load'], None),
    ('loader-skips-the-hash-check', LOAD, [(
        '    if (!digest_equal(entry->sha256, want->sha256)) {', '    if (0) {')], ['load'], None),
    ('loader-compares-eight-digest-bytes', LOAD, [(
        '    for (unsigned i = 0; i < 32; i++) different |= (uint8_t)(a[i] ^ b[i]);',
        '    for (unsigned i = 0; i < 8; i++) different |= (uint8_t)(a[i] ^ b[i]);')], ['load'], None),
    ('loader-leaves-the-last-page-unzeroed', LOAD, [(
        '    zero((uint8_t *)(uintptr_t)entry->base + bytes, entry->alloc - bytes);\n', '')], ['load'], None),
    ('loader-allocates-the-payload-as-data', LOAD, [(
        'entry->memory_type = q1n1_payload_path_is_code(want->path) ? Q1N1_PAYLOAD_TYPE_CODE : Q1N1_PAYLOAD_TYPE_DATA;',
        'entry->memory_type = Q1N1_PAYLOAD_TYPE_DATA;')], ['load'], None),
    ('loader-release-leaks-the-stack', LOAD, [(
        '    if (loaded->stack_base) bs->free_pages(loaded->stack_base, loaded->stack_alloc / PAGE_BYTES);\n', '')],
     ['load'], None),
    ('loader-leaks-a-file-that-failed-its-hash', LOAD, [(
        '    out->count = index + 1;     /* from here on release() frees it */', '    out->count = index;')], ['load'], None),
    ('loader-accepts-a-sixth-file', LOAD, [(
        '    if (manifest.count > Q1N1_PAYLOAD_MAX_FILES) {', '    if (manifest.count > Q1N1_PAYLOAD_MAX_FILES + 1) {')],
     ['load'], None),
    ('loader-accepts-paths-outside-the-directory', LOAD, [(
        '        if (!starts_with_nocase(f->path, Q1N1_PAYLOAD_DIR) || equal_nocase(f->path, Q1N1_PAYLOAD_MANIFEST_PATH))',
        '        if (equal_nocase(f->path, Q1N1_PAYLOAD_MANIFEST_PATH))')], ['load'], None),
    ('loader-accepts-the-manifest-as-a-file', LOAD, [(
        '        if (!starts_with_nocase(f->path, Q1N1_PAYLOAD_DIR) || equal_nocase(f->path, Q1N1_PAYLOAD_MANIFEST_PATH))',
        '        if (!starts_with_nocase(f->path, Q1N1_PAYLOAD_DIR))')], ['load'], None),
    ('loader-compares-paths-case-sensitively', LOAD, [(
        "    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + 32) : c;", '    return c;')], ['load'], None),
    ('loader-has-no-file-size-limit', LOAD, [(
        '        if (f->size > Q1N1_PAYLOAD_MAX_FILE_BYTES) {', '        if (0) {')], ['load'], None),
    ('loader-accepts-a-directory-as-a-file', LOAD, [(
        '        (data[FILE_INFO_ATTRIBUTE_WORD] & EFI_FILE_DIRECTORY))', '        0)')], ['load'], None),
    ('loader-keeps-the-volume-root-open', LOAD, [(
        '    root->close(root);\n    if (!err) err = build_table(bs, out, diag);', '    if (!err) err = build_table(bs, out, diag);')],
     ['load'], None),
    ('loader-accepts-a-page-zero-allocation', LOAD, [(
        '    if (!status && (!address || (address & (PAGE_BYTES - 1)))) {', '    if (0) {')], ['load'], None),
    ('loader-skips-manifest-validation', LOAD, [(
        '    if (!q1n1_preload_manifest_valid(&manifest, bytes)) return Q1N1_PAYLOAD_E_MANIFEST_BAD;\n', '')], ['load'], None),
    ('loader-reads-an-oversized-manifest', LOAD, [(
        '    if (!status && bytes > sizeof manifest) {', '    if (0) {')], ['load'], None),
    ('loader-table-count-is-wrong', LOAD, [(
        '    cache->count = manifest.count;', '    cache->count = manifest.count + 1;')], ['load'], None),
    ('header-names-the-a16-manifest', HDR, [(
        '#define Q1N1_PAYLOAD_MANIFEST_PATH "\\\\SP11\\\\PAYLOAD.MAN"',
        '#define Q1N1_PAYLOAD_MANIFEST_PATH "\\\\Snapintosh\\\\q1n1-preload.bin"')], ['load', 'plan'], None),
    ('header-accepts-any-directory', HDR, [(
        '#define Q1N1_PAYLOAD_DIR "\\\\SP11\\\\"', '#define Q1N1_PAYLOAD_DIR "\\\\"')], ['load'], None),
    ('header-refusal-status-is-success', HDR, [(
        '#define Q1N1_PAYLOAD_STATUS_REFUSED EFI_ERROR(21)', '#define Q1N1_PAYLOAD_STATUS_REFUSED 0')], ['plan'], None),
    ('header-payload-is-not-code-memory', HDR, [(
        '#define Q1N1_PAYLOAD_TYPE_CODE 1u', '#define Q1N1_PAYLOAD_TYPE_CODE 2u')], ['load'], None),
    # -- the declared ranges and slbounce's rules
    ('plan-declares-the-framebuffer', PLAN, [(
        '            if (ranges_overlap(&t->range[i], &fb)) return Q1N1_PLAN_FRAMEBUFFER;',
        '            if (0) return Q1N1_PLAN_FRAMEBUFFER;')], ['plan'], None),
    ('plan-allows-overlapping-ranges', PLAN, [(
        '            if (ranges_overlap(&t->range[i], &t->range[j])) return Q1N1_PLAN_OVERLAP;',
        '            if (0) return Q1N1_PLAN_OVERLAP;')], ['plan'], None),
    ('plan-capacity-unchecked', PLAN, [(
        '    if (t->count > SP11_EBS_MAX_RANGES) return Q1N1_PLAN_TOO_MANY;\n', '')], ['plan'], None),
    ('plan-append-capacity-off-by-one', PLAN, [(
        '    if (loaded->count > Q1N1_PAYLOAD_MAX_FILES || table->count + loaded->count > SP11_EBS_MAX_RANGES)',
        '    if (loaded->count > Q1N1_PAYLOAD_MAX_FILES || table->count + loaded->count > SP11_EBS_MAX_RANGES + 1)')],
     ['plan', 'load'], None),
    ('plan-allows-a-wrapping-range', PLAN, [(
        '        if (t->range[i].base + t->range[i].size < t->range[i].base) return Q1N1_PLAN_WRAP;',
        '        if (0) return Q1N1_PLAN_WRAP;')], ['plan'], None),
    ('plan-chunk-budget-off-by-one', PLAN, [(
        '        if (chunks_for(t->range[i].size, t->chunk_cap) > Q1N1_PAYLOAD_SWEEP_MAX_OPS) return Q1N1_PLAN_TOO_LARGE;',
        '        if (chunks_for(t->range[i].size, t->chunk_cap) >= Q1N1_PAYLOAD_SWEEP_MAX_OPS) return Q1N1_PLAN_TOO_LARGE;')],
     ['plan'], None),
    ('plan-map-accepts-a-range-in-two-descriptors', PLAN, [(
        '        if (matches != 1) return Q1N1_PLAN_NOT_CONTAINED;', '        if (matches == 0) return Q1N1_PLAN_NOT_CONTAINED;')],
     ['plan'], None),
    ('plan-map-sweeps-type-7', PLAN, [(
        '    return (type >= 1 && type <= 6) || type == 9;', '    return (type >= 1 && type <= 7) || type == 9;')], ['plan'], None),
    ('plan-map-ignores-write-back', PLAN, [(
        '        if (!(map[covering].attribute & ATTRIBUTE_WB)) return Q1N1_PLAN_NOT_WB;', '        if (0) return Q1N1_PLAN_NOT_WB;')],
     ['plan'], None),
    ('plan-labels-dropped', PLAN, [(
        '    for (uint32_t i = 0; i < loaded->count; i++) labels[table->count + i] = file_label[i];',
        '    (void)labels; (void)file_label;')], ['plan'], None),
    ('plan-a-refusal-changes-the-table', PLAN, [(
        '    if (status) return status;\n    for (uint32_t i = 0; i < loaded->count; i++) labels',
        '    if (status) { *table = candidate; return status; }\n    for (uint32_t i = 0; i < loaded->count; i++) labels')],
     ['plan'], None),
    ('plan-map-contains-one-byte-too-far', PLAN, [(
        '            if (map[i].base <= base && base + size <= map[i].base + map[i].pages * 4096u) {',
        '            if (map[i].base <= base && base + size <= map[i].base + map[i].pages * 4096u + 1) {')], ['plan'], None),
    ('plan-precheck-ignores-the-plan', PLAN, [(
        '    if (plan_status) {\n        diag->plan = plan_status;', '    if (0) {\n        diag->plan = plan_status;')], ['plan'], None),
    ('plan-precheck-ignores-a-failed-declaration', PLAN, [(
        '    if (declared_status) {\n        diag->efi = declared_status;', '    if (0) {\n        diag->efi = declared_status;')],
     ['plan'], None),
    ('plan-map-reports-the-wrong-range', PLAN, [('        *failing = r;\n', '        *failing = 0;\n')], ['plan'], None),
    # -- the EL2 half: the second hash, the order, the ops
    ('run-skips-the-second-hash', RUNC, [(
        '    if (!q1n1_payload_verify_in_place(loaded, index)) {', '    if (0) {')], ['run'], None),
    ('run-names-the-call-after-making-it', RUNC, [(
        '        emit_line(env, &line);\n        uint64_t value = env->call(file->base, &args, args.stack_base + args.stack_size);\n',
        '        uint64_t value = env->call(file->base, &args, args.stack_base + args.stack_size);\n        emit_line(env, &line);\n')],
     ['run'], None),
    ('run-calls-without-cache-maintenance', RUNC, [(
        '        env->sync_code(file->base, file->alloc);\n', '')], ['run'], None),
    ('run-does-not-check-the-table-count', RUNC, [(
        '    if (table->count != loaded->count) return 0;\n', '')], ['run'], None),
    ('run-does-not-check-the-table-digest', RUNC, [('        if (different) return 0;', '        if (0) return 0;')], ['run'], None),
    ('run-does-not-check-the-table-base', RUNC, [(
        '        if (entry->base != own->base || entry->file.size != own->bytes || entry->allocation != own->alloc) return 0;',
        '        if (entry->file.size != own->bytes) return 0;')], ['run'], None),
    ('run-load32-destination-unchecked', RUNC, [(
        '    if (stack_size < 4 || where < stack_base || where - stack_base > stack_size - 4) return Q1N1_PAYLOAD_LOAD_E_OUT;',
        '    if (stack_size < 4) return Q1N1_PAYLOAD_LOAD_E_OUT;')], ['run'], None),
    ('run-load32-budget-off-by-one', RUNC, [(
        '    if (loads_done >= Q1N1_PAYLOAD_LOADS_MAX) return Q1N1_PAYLOAD_LOAD_E_BUDGET;',
        '    if (loads_done > Q1N1_PAYLOAD_LOADS_MAX) return Q1N1_PAYLOAD_LOAD_E_BUDGET;')], ['run'], None),
    ('run-load32-alignment-unchecked', RUNC, [(
        '    if ((addr & 3) || (where & 3)) return Q1N1_PAYLOAD_LOAD_E_ALIGN;', '    if (0) return Q1N1_PAYLOAD_LOAD_E_ALIGN;')],
     ['run'], None),
    ('run-load32-beyond-48-bits', RUNC, [(
        '    if (addr > ADDRESS_LIMIT - 4) return Q1N1_PAYLOAD_LOAD_E_RANGE;', '    if (0) return Q1N1_PAYLOAD_LOAD_E_RANGE;')],
     ['run'], None),
    ('run-load32-asks-for-a-store', RUNC, [(
        '    if (session.env->guarded(Q1N1_PAYLOAD_G_COPY32,', '    if (session.env->guarded(Q1N1_PAYLOAD_G_SET32,')], ['run'], None),
    ('run-load32-reads-into-the-payloads-word', RUNC, [(
        '(uint64_t)(uintptr_t)&value, addr, 4)) {', '(uint64_t)(uintptr_t)out, addr, 4)) {')], ['run'], None),
    ('run-puts-has-no-line-budget', RUNC, [(
        '    if (session.lines >= Q1N1_PAYLOAD_LINES_MAX) {', '    if (0) {')], ['run'], None),
    ('run-puts-does-not-sanitize', RUNC, [('    q1n1_payload_sanitize(text);\n', '')], ['run'], None),
    ('run-puts-has-no-length-cap', RUNC, [(
        '    while (line[n] && n < Q1N1_PAYLOAD_LINE_MAX) {', '    while (line[n] && n < Q1N1_PAYLOAD_LINE_MAX + 40) {')], ['run'], None),
    ('run-does-not-check-the-stack-guard', RUNC, [('intact &= guard[i] == GUARD_PATTERN;', 'intact &= 1;')], ['run'], None),
    ('run-an-empty-load-is-not-refused', RUNC, [(
        '    if (!loaded->count || !loaded->stack_base || !code) {', '    if (0) {')], ['run'], None),
    ('run-passes-the-wrong-stack-top', RUNC, [(
        'env->call(file->base, &args, args.stack_base + args.stack_size);',
        'env->call(file->base, &args, args.stack_base);')], ['run'], None),
    ('run-passes-the-wrong-abi-version', RUNC, [(
        '    args.version = Q1N1_PAYLOAD_ABI_VERSION;', '    args.version = Q1N1_PAYLOAD_ABI_VERSION + 1;')], ['run'], None),
    ('run-does-not-clear-the-arguments', RUNC, [(
        '    for (size_t i = 0; i < sizeof args; i++) raw[i] = 0;', '    for (size_t i = 0; i < sizeof args; i++) raw[i] = 0xa5;')],
     ['run'], None),
    ('run-drops-the-return-value', RUNC, [('        done->retval = value;', '        done->retval = 0;')], ['run'], None),
    ('run-reports-a-hash-refusal-as-success', RUNC, [(
        '        result->status = Q1N1_PAYLOAD_RUN_HASH;', '        result->status = Q1N1_PAYLOAD_RUN_OK;')], ['run'], None),
    ('run-calls-a-payload-that-failed-its-hash', RUNC, [(
        '            emit_chain_stopped(env, index, "HASH_AT_EL2");\n            return result->status;\n',
        '            emit_chain_stopped(env, index, "HASH_AT_EL2");\n')], ['run'], None),
    # -- text, ABI, and the reference payload
    ('text-hex-in-lower-case', TEXT, [(
        '    do { digits[n++] = "0123456789ABCDEF"[value & 15]; value >>= 4; } while (value);',
        '    do { digits[n++] = "0123456789abcdef"[value & 15]; value >>= 4; } while (value);')], ['plan', 'run'], None),
    ('text-panel-gap-moved', TEXT, [('#define GAP 24u', '#define GAP 25u')], ['plan'], None),
    ('text-sanitize-keeps-lower-case', TEXT, [(
        "        if (*text >= 'a' && *text <= 'z') *text = (char)(*text - 32);\n", '')], ['plan', 'run'], None),
    ('text-digest-uses-the-wrong-nibble', TEXT, [(
        '        text[2 * i] = "0123456789ABCDEF"[digest[i] >> 4];', '        text[2 * i] = "0123456789ABCDEF"[digest[i] >> 3];')],
     ['plan', 'run', 'load'], None),
    ('abi-field-inserted-before-the-payload-base', ABI, [(
        '    uint32_t size;              /* sizeof(struct q1n1_payload_args) the runner filled in */\n',
        '    uint32_t size;              /* sizeof(struct q1n1_payload_args) the runner filled in */\n    uint32_t inserted;\n')],
     ['plan'], 'payload ABI'),
    ('abi-op-inserted-before-puts', ABI, [(
        'struct q1n1_payload_ops {\n', 'struct q1n1_payload_ops {\n    void (*first)(void);\n')], ['plan'], 'payload ABI'),
    ('abi-gains-a-store-op', ABI, [(
        '    uint64_t (*counter)(void);\n', '    uint64_t (*counter)(void);\n    void (*store32)(uint64_t addr, uint32_t value);\n')],
     ['plan'], 'payload ABI'),
    ('abi-version-bumped', ABI, [('#define Q1N1_PAYLOAD_ABI_VERSION 1u', '#define Q1N1_PAYLOAD_ABI_VERSION 2u')], ['plan', 'run'], None),
    ('abi-stack-halved', ABI, [(
        '#define Q1N1_PAYLOAD_STACK_BYTES (64u * 1024u)', '#define Q1N1_PAYLOAD_STACK_BYTES (32u * 1024u)')], ['plan', 'load'], None),
    ('state-reads-el2-registers-at-any-level', STATE, [('    if (current_el >> 2 == 2) {', '    if (1) {')], ['state'], None),
    ('state-reads-ttbr1-without-e2h', STATE, [(
        '        if (hcr >> 34 & 1) SHOW("TTBR1_EL2", S3_4_C2_C0_1);', '        SHOW("TTBR1_EL2", S3_4_C2_C0_1);')], ['state'], None),
    ('state-reads-the-timer-offset', STATE, [(
        '        SHOW("CNTHCTL_EL2", cnthctl_el2);\n', '        SHOW("CNTHCTL_EL2", cnthctl_el2);\n        SHOW("CNTVOFF_EL2", cntvoff_el2);\n')],
     ['state'], None),
    ('state-trusts-its-arguments', STATE, [(
        '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n', '')], ['state'], None),
    ('state-prints-the-wrong-register', STATE, [(
        '        SHOW("TCR_EL2", tcr_el2);', '        SHOW("TCR_EL2", ttbr0_el2);')], ['state'], None),
    ('state-e2h-is-the-wrong-bit', STATE, [('hcr >> 34 & 1', 'hcr >> 35 & 1')], ['state'], None),
    ('state-returns-failure', STATE, [('    SHOW("SPSEL", SPSel);\n    return 0;', '    SHOW("SPSEL", SPSel);\n    return 1;')], ['state'], None),
]


def copy_tree(directory):
    shutil.rmtree(directory, ignore_errors=True)
    (directory / 'uefi').mkdir(parents=True)
    (directory / 'payloads').mkdir()
    for name in UEFI_COPIED:
        shutil.copy(UEFI / name, directory / 'uefi' / name)
    for name in PAYLOADS_COPIED:
        shutil.copy(PAYLOADS / name, directory / 'payloads' / name)


class Mutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _build(program, directory, relaxed):
        return build_program(program, directory / 'uefi', directory / 'payloads', directory / 'bin', relaxed=relaxed)

    def _evaluate(self, name, fname, edits, programs, build_error):
        """(status, detail): 'caught', 'survived', 'stale' (target not found once) or 'broken' (no build)."""
        directory = BUILD / f'mutant-{name}'
        copy_tree(directory)
        path = directory / fname
        text = path.read_text(encoding='utf-8')
        for needle, replacement in edits:
            if text.count(needle) != 1:
                return 'stale', f'target not found exactly once in {fname}: {needle[:70]!r}'
            text = text.replace(needle, replacement, 1)
        path.write_text(text, encoding='utf-8')
        for program in programs:
            done, binary = self._build(program, directory, relaxed=True)
            if done.returncode != 0:
                if build_error and build_error in done.stderr:
                    return 'caught', f'{program}: the build refuses it ({build_error})'
                return 'broken', f'{program} did not compile: {done.stderr[-400:]}'
            code, output = run_program(binary)
            if code != 0:
                return 'caught', f'{program}: ' + ('hang' if code is None else output.strip().splitlines()[-1][:120])
        return 'survived', 'every named program still passed'

    def test_the_unmutated_control_passes_from_a_copy(self):
        directory = BUILD / 'control'
        copy_tree(directory)
        for program in ALL:
            done, binary = self._build(program, directory, relaxed=False)
            self.assertEqual(done.returncode, 0, done.stderr)
            code, output = run_program(binary)
            self.assertEqual(code, 0, f'{program}: {output[-600:]}')

    def test_there_are_enough_distinct_mutants(self):
        self.assertGreaterEqual(len(MUTANTS), 60)
        self.assertEqual(len({m[0] for m in MUTANTS}), len(MUTANTS))
        files = {m[1] for m in MUTANTS}
        self.assertTrue({LOAD, PLAN, RUNC, TEXT, HDR, ABI, STATE} <= files, 'a source file has no seeded bug')

    def test_every_seeded_bug_is_caught(self):
        workers = max(1, min(4, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {m[0]: pool.submit(self._evaluate, *m) for m in MUTANTS}
            results = {name: future.result() for name, future in futures.items()}
        for name, (status, detail) in results.items():
            with self.subTest(mutant=name):
                self.assertEqual(status, 'caught', f'{status}: {detail}')


def strip_comments(text):
    return re.sub(r'//[^\n]*', '', re.sub(r'/\*.*?\*/', '', text, flags=re.S))


class SourceAudit(unittest.TestCase):
    @staticmethod
    def read(path):
        return Path(path).read_text(encoding='utf-8')

    def code(self, name):
        return strip_comments(self.read(UEFI / name))

    def test_new_files_carry_spdx_mit(self):
        self.assertGreaterEqual(len(NEW_SOURCES), 20)
        for path in NEW_SOURCES:
            with self.subTest(file=path.name):
                self.assertIn('SPDX-License-Identifier: MIT', self.read(path)[:200])
        for path in DOCS:
            with self.subTest(file=path.name):
                self.assertEqual(self.read(path).splitlines()[0], '<!-- SPDX-License-Identifier: MIT -->')

    def test_the_loader_makes_only_its_listed_firmware_calls(self):
        code = self.code('sp11-payload-load.c')
        calls = set(re.findall(r'\b(\w+)->(\w+)\(', code))
        allowed = {('bs', 'handle_protocol'), ('bs', 'allocate_pages'), ('bs', 'free_pages'), ('fs', 'open_volume'),
                   ('root', 'open'), ('root', 'close'), ('file', 'get_info'), ('file', 'read'), ('file', 'close')}
        self.assertEqual(sorted(calls - allowed), [], 'a firmware call the loader is not allowed')
        for banned in ('connect_controller', 'locate_handle', 'locate_protocol', 'open_protocol', 'free_pool',
                       'allocate_pool', 'get_memory_map', 'exit_boot_services', 'set_watchdog', '->write(', 'delete_file',
                       'set_position', 'flush', 'disconnect_controller', 'EFI_BLOCK', 'block_io', 'partition'):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, code)
        # Open is always a read: one constant, never an expression.
        self.assertEqual(len(re.findall(r'->open\(', code)), 2)
        self.assertEqual(len(re.findall(r'root->open\(root, &file, name, Q1N1_PAYLOAD_FILE_MODE_READ, 0\)', code)), 2)
        self.assertEqual(len(re.findall(r'handle_protocol\(', code)), 1)
        self.assertIn('handle_protocol(image->device,', code)

    def test_the_a16_manifest_path_is_only_ever_named_in_a_comment(self):
        for path in sorted(UEFI.glob('sp11-payload*')):
            with self.subTest(file=path.name):
                self.assertNotIn('snapintosh', strip_comments(self.read(path)).lower())
                self.assertNotIn('q1n1-preload', strip_comments(self.read(path)).lower())

    def test_the_runner_never_stores(self):
        code = self.code('sp11-payload-run.c')
        self.assertNotIn('G_SET32', code)
        self.assertEqual(len(re.findall(r'->guarded\(', code)), 1)
        self.assertIn('->guarded(Q1N1_PAYLOAD_G_COPY32,', code)
        self.assertEqual(code.count('volatile'), 2, 'only the stack guard words are accessed volatile')
        for banned in ('memset32', 'live_write32', 'write32', 'memcpy64', 'msr', 'asm'):
            self.assertNotIn(banned, code)
        abi = self.read(UEFI / 'sp11-payload-abi.h')
        ops = abi[abi.index('struct q1n1_payload_ops {'):abi.index('};', abi.index('struct q1n1_payload_ops {'))]
        fields = re.findall(r'\(\*(\w+)\)', ops)
        self.assertEqual(fields, ['puts', 'hex', 'load32', 'counter'], 'the ops table is the four documented ops')

    def test_the_main_c_glue_forwards_loads_only(self):
        main_c = self.read(UEFI / 'main.c')
        start = main_c.index('static int payload_guarded(')
        body = main_c[start:main_c.index('\n}\n', start)]
        self.assertIn('return kind == Q1N1_PAYLOAD_G_COPY32 ? live_guarded(0, dst, src, size) : 1;', body)
        glue = main_c[main_c.index('/* ---- Stick payload runner (sp11-payload.h): the platform side'):
                      main_c.index('#endif /* Q1N1_SP11_PAYLOAD */')]
        self.assertEqual(len(re.findall(r'live_guarded\(', glue)), 1)
        for banned in ('live_write32', 'memset32', 'q1n1_memcpy64', 'G_SET32'):
            self.assertNotIn(banned, glue)

    def test_every_runner_line_is_under_the_gate_in_main_c(self):
        main_c = self.read(UEFI / 'main.c')
        needles = ('sp11_payload_el2_run', 'sp11_payload_prepare', 'sp11_payload_precheck', 'sp11_payload_flow',
                   'payload_requested = 1;', 'PAYLOAD SKIPPED=NOT_AT_EL2', 'q1n1_payload_', 'payload_loaded', 'payload_plan_status')
        for needle in needles:
            places = [m.start() for m in re.finditer(re.escape(needle), main_c)]
            self.assertTrue(places, needle)
            for at in places:
                # The conditionals open at that point; an #else of the gate is the code that runs with it off.
                stack = []
                for found in re.finditer(r'^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif)\b(.*)$', main_c[:at], flags=re.M):
                    kind, rest = found.group(1), found.group(2).split('/*')[0].strip()
                    if kind in ('if', 'ifdef', 'ifndef'):
                        stack.append((kind, rest))
                    elif kind in ('elif', 'else'):
                        stack[-1] = (kind, rest)
                    else:
                        stack.pop()
                self.assertIn(('if', 'Q1N1_SP11_PAYLOAD'), stack, f'{needle} at offset {at} is outside the payload gate')

    def test_the_runner_runs_only_from_the_el2_flow_and_prepares_before_leaving(self):
        main_c = self.read(UEFI / 'main.c')
        at = main_c.index('static efi_status sp11_payload_flow(')
        flow = main_c[at:main_c.index('\n}\n', at)]
        self.assertLess(flow.index('sp11_payload_prepare('), flow.index('leave_firmware('))
        self.assertLess(flow.index('leave_firmware('), flow.index('q1n1_payload_release('))
        self.assertEqual(main_c.count('return sp11_payload_flow('), 1)
        call = main_c.index('return sp11_payload_flow(')
        context = main_c[max(0, call - 2500):call]
        self.assertIn('"--el2"', context)
        self.assertEqual(main_c.count('payload_requested = 1;'), 1)
        self.assertEqual(main_c.count('q1n1_payload_prepare('), 1)

    def test_nothing_of_the_runner_is_between_the_final_memory_map_and_exit_boot_services(self):
        main_c = self.read(UEFI / 'main.c')
        at = main_c.index('static efi_status leave_firmware(')
        body = main_c[at:main_c.index('\n}\n', at)]
        loop = body.index('for (unsigned attempt = 0; attempt < 3; attempt++) {')
        self.assertLess(body.index('sp11_payload_precheck('), loop, 'the precheck is before the retry loop')
        after = body[loop:]
        for banned in ('payload', 'PAYLOAD', 'allocate_pages', 'allocate_pool', 'handle_protocol', 'locate_', 'free_pages'):
            self.assertNotIn(banned, after, f'{banned} inside the retry loop')
        self.assertEqual(after.count('get_memory_map('), 1)
        self.assertEqual(after.count('exit_boot_services('), 1)
        # Everything that allocates is before: the precheck reads the map into the buffer, it does not allocate.
        precheck = main_c[main_c.index('static efi_status sp11_payload_precheck('):main_c.index('static efi_status leave_firmware(')]
        self.assertNotIn('allocate_', precheck)

    def test_the_declared_table_is_built_before_the_precheck_and_never_declares_the_framebuffer(self):
        main_c = self.read(UEFI / 'main.c')
        at = main_c.index('static void sp11_declare_ranges(')
        body = main_c[at:main_c.index('\n}\n', at)]
        self.assertNotIn('info.fb_base', body)
        self.assertIn('(uintptr_t)fb.pixels, fb.bytes);', body, 'the framebuffer is passed to be kept out, nothing else')
        self.assertIn('t.chunk_cap = 1u << 20;', body)

    def test_no_machine_identifiers_in_new_files(self):
        # Built from pieces so that this file does not contain what it looks for.
        paths = '|'.join(['/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/'])
        pattern = re.compile(paths + r'|\.loc' + r'al\b|\bsae' + r'ed\b|host' + r'name|' +
                             r'\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', re.I)
        for path in NEW_SOURCES + DOCS:
            if not path.exists():
                continue
            for number, line in enumerate(self.read(path).splitlines(), 1):
                with self.subTest(file=path.name, line=number):
                    self.assertIsNone(pattern.search(line), line)

    def test_new_files_are_not_oversized(self):
        for path in NEW_SOURCES + DOCS:
            if not path.exists():
                continue
            text = self.read(path)
            with self.subTest(file=path.name):
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)

    def test_the_constants_the_runner_derives_are_consistent(self):
        header = self.read(UEFI / 'sp11-payload.h')
        ranges = self.read(UEFI / 'sp11-ebs-ranges.h')
        max_ranges = int(re.search(r'#define SP11_EBS_MAX_RANGES (\d+)u', ranges).group(1))
        base = int(re.search(r'#define Q1N1_PAYLOAD_BASE_RANGES (\d+)u', header).group(1))
        self.assertEqual((max_ranges, base), (8, 3), 'the image, the map and the preload table are three of eight')
        self.assertIn('#define Q1N1_PAYLOAD_MAX_FILES (SP11_EBS_MAX_RANGES - Q1N1_PAYLOAD_BASE_RANGES)', header)
        self.assertEqual(int(re.search(r'#define Q1N1_PAYLOAD_SWEEP_MAX_OPS (\d+)u', header).group(1)), 256)
        self.assertIn('#define Q1N1_PAYLOAD_MAX_FILE_BYTES ((uint64_t)Q1N1_PAYLOAD_SWEEP_MAX_OPS << 20)', header)

    @unittest.skipUnless(SLBOUNCE_DIR, 'SLBOUNCE_SP11_DIR not set: the slbounce side of the constants is not compared')
    def test_the_constants_shared_with_slbounce_are_the_same(self):
        header = self.read(UEFI / 'sp11-payload.h')
        bounce = self.read(Path(SLBOUNCE_DIR) / 'src' / 'bounce_main.c')
        self.assertEqual(int(re.search(r'#define SP11_SWEEP_MAX_OPS (\d+)u', bounce).group(1)),
                         int(re.search(r'#define Q1N1_PAYLOAD_SWEEP_MAX_OPS (\d+)u', header).group(1)))
        theirs = self.read(Path(SLBOUNCE_DIR) / 'src' / 'sp11-ebs-ranges.h')
        ours = self.read(UEFI / 'sp11-ebs-ranges.h')
        self.assertEqual(theirs, ours, 'the declared-ranges header differs from slbounce\'s copy')

    def test_the_documentation_abi_table_is_the_compiled_layout(self):
        if not DOC.exists():
            self.skipTest('docs/SP11-PAYLOAD.md does not exist yet')
        done, binary = build_program('plan', UEFI, PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = run_program(binary, 'abi-table')
        self.assertEqual(code, 0, output)
        compiled = dict(line.split() for line in output.splitlines())
        doc = self.read(DOC)
        section = doc[doc.index('<!-- abi-table -->'):doc.index('<!-- /abi-table -->')]
        rows = re.findall(r'^\| (\d+) \| (\d+) \| `([a-z_0-9.\[\]]+)` \|', section, re.M)
        self.assertGreaterEqual(len(rows), 24)
        documented = {}
        for offset, _, field in rows:
            documented[('q1n1_payload_args.' + field) if not field.startswith('ops.') else ('q1n1_payload_ops.' + field[4:])] = offset
        for field, offset in documented.items():
            key = field.replace('[5]', '')
            self.assertEqual(compiled.get(key), offset, f'{field}: documented {offset}, compiled {compiled.get(key)}')
        self.assertEqual({k for k in compiled if '.' in k}, {k.replace('[5]', '') for k in documented},
                         'a field the documentation does not list, or the reverse')
        self.assertIn(f'{compiled["q1n1_payload_args"]} bytes', doc)

    def test_the_documented_registers_are_the_ones_the_payload_reads(self):
        if not DOC.exists():
            self.skipTest('docs/SP11-PAYLOAD.md does not exist yet')
        source = self.read(PAYLOADS / 'state.c')
        keys = re.findall(r'(?:SHOW|show)\((?:a, )?"([A-Z0-9_]+)"', source)
        keys.append('EL2REGS')
        doc = self.read(DOC)
        section = doc[doc.index('<!-- registers -->'):doc.index('<!-- /registers -->')]
        documented = re.findall(r'^\| `([A-Z0-9_]+)` \|', section, re.M)
        self.assertEqual(sorted(set(documented)), sorted(set(keys + ['CURRENTEL'])))
        self.assertGreaterEqual(len(documented), 20)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
