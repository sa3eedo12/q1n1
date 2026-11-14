#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host-tool, payload-binary and default-off tests of the Surface Pro 11 stick payload runner
(docs/SP11-PAYLOAD.md).

    python3 tools/test-q1n1-sp11-payload-build.py

  * ManifestTool: tools/sp11_payload_manifest.py (the stick tree and its manifest): names, limits,
    determinism, that the runner's own validator accepts what it writes, that only --out-dir is written.
  * ElfCheck: tools/sp11_payload_elfcheck.py against real payload ELFs built with the Makefile's flags: the
    reference payload passes; an absolute pointer table, an absolute address built with MOVZ/MOVK, a writable
    global, a position-dependent link and an unreadable file are each refused.
  * PayloadBinary: the built `state`, `psci` and `timer` payloads: entry at offset 0, within their pages, identical when
    linked at another base, only what each one's allow-list says (state: the documented MRS; psci: MRS of
    CurrentEL and MPIDR_EL1 and exactly one `smc #0`; timer: MRS of its twelve timer and counter registers, no
    barrier; no payload: any other system or exclusive instruction; only timer: CNTVOFF_EL2 and CNTPOFF_EL2),
    `make payloads` reproducible and running the check, and a payload with an absolute relocation fails the
    Makefile's build. The allow-list is tools/sp11_payload_testlib.py's, which tools/test-q1n1-sp11-payload-chain.py
    and tools/test-q1n1-sp11-payload-timer.py also run against seeded-bad builds.
  * ToolMutants: seeded bugs in the two tools, each of which ManifestTool or ElfCheck must reject (the same
    classes are run against the mutated copy through Q1N1_PAYLOAD_TOOLS_DIR), and an unmutated control.
  * PayloadDefaultOff: with Q1N1_SP11_PAYLOAD at 0 (the default) every file of the runner compiles to nothing,
    main.c preprocesses to the same text and the default, plain SP11 and survey builds are byte-identical to
    the commit before the runner (Q1N1_SP11_BASE_DIR: `git archive 8235433` is enough; SKIP without); the
    gate is refused without SNAP_PLATFORM_SP11 and with the survey; PAYLOAD=1 builds q1n1-payload.efi and
    changes no other artefact.

Nothing is written outside build/ and, for the comparison builds, the base tree's own build/ directory.
Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model and link check only)."""
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
import sp11_payload_testlib as lib  # noqa: E402

UEFI = ROOT / 'platform' / 'uefi'
BUILD = ROOT / 'build' / 'sp11-payload-build-test'
TOOLS = Path(os.environ.get('Q1N1_PAYLOAD_TOOLS_DIR', ROOT / 'tools'))
SCRATCH = BUILD / os.environ.get('Q1N1_PAYLOAD_TOOLS_TAG', 'main')
run, have = lib.run, lib.have
SP11_BASE = os.environ.get('Q1N1_SP11_BASE_DIR')
MAKE_ARGS = ['-f', 'platform/uefi/Makefile']
SP11_FIXTURES = ['SP11=1', 'SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c',
                 'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c']
SP11_ARTEFACTS = ('q1n1.efi', 'q1n1-stage.bin', 'q1n1-stage-alt.bin', 'q1n1-stage-qemu.bin', 'q1n1-stage-qemu-alt.bin')
RUNNER_SOURCES = sorted(UEFI.glob('sp11-payload-*.c')) + sorted(UEFI.glob('sp11-payload-*.S'))
MANIFEST_MAGIC = 0x31444C50314E3151
TOOL_NAMES = ('sp11_payload_manifest.py', 'sp11_payload_elfcheck.py', 'preload.py')
READELF = lambda: shutil.which('llvm-readelf', path=lib.ENV['PATH']) or 'llvm-readelf'  # noqa: E731


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ManifestTool(unittest.TestCase):
    tool = TOOLS / 'sp11_payload_manifest.py'

    @classmethod
    def setUpClass(cls):
        SCRATCH.mkdir(parents=True, exist_ok=True)

    def inputs(self, case, files):
        base = SCRATCH / 'manifest' / case
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

    @staticmethod
    def decode(manifest):
        magic, version, count, entry = struct.unpack_from('<4Q', manifest)
        entries = []
        for i in range(count):
            size, digest, path = struct.unpack_from('<Q32s256s', manifest, 32 + i * entry)
            entries.append((size, digest.hex(), path.rstrip(b'\0').decode()))
        return magic, version, count, entry, entries

    def test_writes_the_manifest_and_the_copies_in_capitals(self):
        payload, data = bytes([0x1f, 0x20, 0x03, 0xd5]) * 50, bytes(range(256)) * 28
        base, paths = self.inputs('ok', {'state.bin': payload, 'data.dat': data})
        done = self.tool_run(base / 'out', *paths)
        self.assertEqual(done.returncode, 0, done.stderr)
        stick = base / 'out' / 'SP11'
        self.assertEqual(sorted(p.name for p in (base / 'out').iterdir()), ['SP11'])
        self.assertEqual(sorted(p.name for p in stick.iterdir()), ['DATA.DAT', 'PAYLOAD.MAN', 'STATE.BIN'])
        self.assertEqual((stick / 'STATE.BIN').read_bytes(), payload)
        self.assertEqual((stick / 'DATA.DAT').read_bytes(), data)
        magic, version, count, entry, entries = self.decode((stick / 'PAYLOAD.MAN').read_bytes())
        self.assertEqual((magic, version, count, entry), (MANIFEST_MAGIC, 1, 2, 296))
        self.assertEqual(entries, [(len(payload), hashlib.sha256(payload).hexdigest(), '\\SP11\\STATE.BIN'),
                                   (len(data), hashlib.sha256(data).hexdigest(), '\\SP11\\DATA.DAT')])

    def test_prints_what_to_copy_and_the_one_command_to_run(self):
        payload = bytes(64)
        base, paths = self.inputs('say', {'state.bin': payload})
        done = self.tool_run(base / 'out', *paths)
        self.assertEqual(done.returncode, 0, done.stderr)
        for text in ('SP11\\PAYLOAD.MAN', 'SP11\\STATE.BIN', 'SP11\\Q1N1-PAYLOAD.EFI --el2', 'make PAYLOAD=1 payload-runner',
                     hashlib.sha256(payload).hexdigest()[:16].upper()):
            self.assertIn(text, done.stdout)

    def test_the_output_is_deterministic_and_holds_no_host_path(self):
        base, paths = self.inputs('det', {'state.bin': bytes(range(100))})
        self.assertEqual(self.tool_run(base / 'a', *paths).returncode, 0)
        self.assertEqual(self.tool_run(base / 'b', *paths).returncode, 0)
        first = (base / 'a' / 'SP11' / 'PAYLOAD.MAN').read_bytes()
        self.assertEqual(first, (base / 'b' / 'SP11' / 'PAYLOAD.MAN').read_bytes())
        for needle in (str(ROOT).encode(), str(base).encode(), b'/Us' + b'ers', b'build/'):
            self.assertNotIn(needle, first)

    @unittest.skipUnless(have('clang'), 'clang not installed')
    def test_the_runners_own_validator_accepts_what_the_tool_writes(self):
        harness = SCRATCH / 'validate.c'
        harness.write_text(
            '#include <stdio.h>\n#include <stdlib.h>\n#include "preload.h"\n'
            'static struct q1n1_preload_manifest m;\n'
            'int main(int argc, char **argv) {\n'
            '    FILE *f = fopen(argv[1], "rb"); if (!f) return 2;\n'
            '    size_t n = fread(&m, 1, sizeof m, f); fclose(f);\n'
            '    printf("%d\\n", q1n1_preload_manifest_valid(&m, n)); return 0; }\n', encoding='utf-8')
        binary = SCRATCH / 'validate'
        done = run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-I', str(UEFI), str(harness),
                    str(UEFI / 'preload.c'), str(UEFI / 'sha256.c'), '-o', str(binary)])
        self.assertEqual(done.returncode, 0, done.stderr)
        base, paths = self.inputs('valid', {'state.bin': bytes(range(100)), 'data.dat': bytes(range(200))})
        self.assertEqual(self.tool_run(base / 'out', *paths).returncode, 0)
        manifest = base / 'out' / 'SP11' / 'PAYLOAD.MAN'
        self.assertEqual(run([str(binary), str(manifest)]).stdout.strip(), '1')
        damaged = bytearray(manifest.read_bytes())
        damaged[0] ^= 0x40
        (base / 'damaged.man').write_bytes(bytes(damaged))
        self.assertEqual(run([str(binary), str(base / 'damaged.man')]).stdout.strip(), '0')

    def test_refuses_what_the_runner_would_refuse_and_writes_nothing(self):
        cases = {
            'six files': ({f'f{i}.bin': bytes(8) for i in range(6)}, 'takes 1 to 5'),
            'empty file': ({'state.bin': bytes(8), 'empty.bin': b''}, 'between 1 byte'),
            'short payload': ({'state.bin': bytes(3)}, 'shorter than one instruction'),
            'long name': ({'state.bin': bytes(8), 'toolongname.bin': bytes(8)}, 'cannot be a stick name'),
            'long extension': ({'state.bin': bytes(8), 'data.bind': bytes(8)}, 'cannot be a stick name'),
            'two dots': ({'state.bin': bytes(8), 'a.b.c': bytes(8)}, 'cannot be a stick name'),
            'space': ({'state.bin': bytes(8), 'a b.bin': bytes(8)}, 'cannot be a stick name'),
            'the manifest name': ({'state.bin': bytes(8), 'payload.man': bytes(8)}, 'reserved'),
            'duplicate in another case': ({'state.bin': bytes(8), 'sub/STATE.BIN': bytes(8)}, 'duplicate'),
        }
        for label, (files, message) in cases.items():
            with self.subTest(case=label):
                base, paths = self.inputs('refuse', files)
                done = self.tool_run(base / 'out', *paths)
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertIn(message, done.stderr)
                self.assertFalse((base / 'out').exists(), 'a refusal must not leave a half-written stick tree')
        base, paths = self.inputs('missing', {'state.bin': bytes(8)})
        done = self.tool_run(base / 'out', paths[0], base / 'in' / 'nothere.bin')
        self.assertEqual(done.returncode, 1)
        self.assertIn('is not a file', done.stderr)
        done = self.tool_run(base / 'out', base / 'in')
        self.assertEqual(done.returncode, 1)
        self.assertEqual(self.tool_run(base / 'out').returncode, 2, 'no file at all is a usage error')

    def test_the_size_limit_is_exactly_256_mib_and_is_checked_before_reading(self):
        module = load_module('sp11_payload_manifest_under_test', self.tool)
        base = SCRATCH / 'manifest' / 'size'
        shutil.rmtree(base, ignore_errors=True)
        base.mkdir(parents=True)
        edge, over = base / 'EDGE.BIN', base / 'OVER.BIN'
        for path, size in ((edge, 256 << 20), (over, (256 << 20) + 1)):
            with open(path, 'wb') as handle:
                handle.truncate(size)
        manifest, entries = module.build([edge])
        self.assertEqual(entries[0][1], 256 << 20)
        with self.assertRaises(ValueError) as refused:
            module.build([over])
        self.assertIn('between 1 byte', str(refused.exception))
        self.assertEqual(module.MAX_FILES, 5)

    def test_only_the_out_dir_is_written_and_the_inputs_are_untouched(self):
        base, paths = self.inputs('writes', {'state.bin': bytes(range(64))})
        before = {p: p.read_bytes() for p in paths}
        self.assertEqual(self.tool_run(base / 'out', *paths).returncode, 0)
        after = sorted(str(p.relative_to(base)) for p in base.rglob('*'))
        self.assertEqual(after, ['in', 'in/state.bin', 'out', 'out/SP11', 'out/SP11/PAYLOAD.MAN', 'out/SP11/STATE.BIN'])
        self.assertEqual({p: p.read_bytes() for p in paths}, before)


GOOD_ABS = '''#include "payload-util.h"
static const char *const names[] = {"ONE", "TWO", "THREE"};
uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    if (!pl_args_ok(a)) return 1;
    for (uint32_t i = 0; i < a->payload_size % 3 + 1; i++) a->ops.puts(names[i]);
    return 0;
}
'''
PLAIN_STRING = '''#include "payload-util.h"
uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    if (!pl_args_ok(a)) return 1;
    a->ops.puts("HELLO");
    return 0;
}
'''
WRITABLE_BSS = '''#include "payload-util.h"
static uint32_t counter;
uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    if (!pl_args_ok(a)) return 1;
    counter += (uint32_t)a->payload_size;
    return counter;
}
'''
WRITABLE_DATA = WRITABLE_BSS.replace('static uint32_t counter;', 'static uint32_t counter = 5;')


class ElfCheck(unittest.TestCase):
    tool = TOOLS / 'sp11_payload_elfcheck.py'

    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'ld.lld', 'llvm-readelf', 'llvm-objcopy'):
            if not have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        shutil.rmtree(SCRATCH / 'elf', ignore_errors=True)
        SCRATCH.mkdir(parents=True, exist_ok=True)

    def build(self, name, source, extra=()):
        directory = SCRATCH / 'elf'
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f'{name}.c'
        if isinstance(source, str):
            path.write_text(source, encoding='utf-8')
        else:
            shutil.copy(source, path)
        return lib.build_payload(path, directory, name=name, extra_cflags=extra, check=False)

    def check(self, elf, readelf=None):
        return run(['python3', '-B', str(self.tool), '--readelf', readelf or READELF(), str(elf)])

    def test_the_reference_payload_is_position_independent(self):
        done, elf, _ = self.build('good', ROOT / 'payloads' / 'state.c')
        self.assertEqual(done.returncode, 0, done.stderr)
        checked = self.check(elf)
        self.assertEqual((checked.returncode, checked.stderr), (0, ''))

    def test_an_absolute_pointer_table_is_refused(self):
        done, elf, _ = self.build('abs64', GOOD_ABS)
        self.assertEqual(done.returncode, 0, done.stderr)
        relocations = run([READELF(), '-r', '--wide', str(elf)]).stdout
        self.assertIn('R_AARCH64_ABS64', relocations, 'the fixture no longer produces an absolute relocation')
        checked = self.check(elf)
        self.assertEqual(checked.returncode, 1)
        self.assertIn('R_AARCH64_ABS64', checked.stderr)
        self.assertIn('depends on the load address', checked.stderr)
        self.assertIn('NOT position independent', checked.stderr)

    def test_an_address_built_with_movz_and_movk_is_refused(self):
        done, elf, _ = self.build('movw', PLAIN_STRING, extra=('-mcmodel=large',))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn('R_AARCH64_MOVW_UABS', run([READELF(), '-r', '--wide', str(elf)]).stdout)
        checked = self.check(elf)
        self.assertEqual(checked.returncode, 1)
        self.assertIn('R_AARCH64_MOVW_UABS', checked.stderr)

    def test_the_plain_string_payload_is_accepted_because_the_small_model_is_pc_relative(self):
        done, elf, _ = self.build('plain', PLAIN_STRING)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.check(elf).returncode, 0)

    def test_a_writable_global_does_not_link(self):
        for name, source in (('bss', WRITABLE_BSS), ('data', WRITABLE_DATA)):
            with self.subTest(kind=name):
                done, _, flat = self.build(name, source)
                self.assertNotEqual(done.returncode, 0)
                self.assertIn('no writable globals', done.stderr)
                self.assertFalse(flat.exists(), 'a payload with a writable global was flattened')

    def test_a_program_header_or_section_that_needs_a_loader_is_refused(self):
        # The payload linker script cannot produce these (lld refuses a TLS symbol without PT_TLS, and the script
        # discards the rest), so the check is shown the readelf text of a real payload with one added.
        done, elf, _ = self.build('headers', ROOT / 'payloads' / 'state.c')
        self.assertEqual(done.returncode, 0, done.stderr)
        module = load_module('sp11_payload_elfcheck_under_test', self.tool)
        text = module.run_readelf(READELF(), elf)
        self.assertEqual(module.problems(elf, READELF()), [])
        self.assertIn('\n  LOAD ', text)
        for kind in ('TLS', 'DYNAMIC', 'INTERP', 'GNU_RELRO', 'NOTE'):
            with self.subTest(segment=kind):
                module.run_readelf = lambda readelf, path, doctored=text.replace(
                    '\n  LOAD ', f'\n  {kind} 0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 R 0x1\n  LOAD ', 1): doctored
                self.assertIn(f'program header {kind} needs a loader', '\n'.join(module.problems(elf, READELF())))
        for section in ('.got', '.dynamic', '.tbss', '.init_array'):
            with self.subTest(section=section):
                module.run_readelf = lambda readelf, path, doctored=text.replace(
                    '\n  [', f'\n  [99] {section} PROGBITS 0000000000000000 000000 000008 00 WA 0 0 8\n  [', 1): doctored
                self.assertIn(f'section {section} needs a loader', '\n'.join(module.problems(elf, READELF())))

    def test_a_position_dependent_link_is_refused(self):
        done, elf, _ = self.build('good2', ROOT / 'payloads' / 'state.c')
        self.assertEqual(done.returncode, 0, done.stderr)
        directory = SCRATCH / 'elf'
        shared = directory / 'shared.elf'
        linked = run(['ld.lld', '-pie', '-nostdlib', '-z', 'norelro', '--build-id=none', '--emit-relocs', '-T',
                      str(ROOT / 'payloads' / 'payload.ld'), '-o', str(shared), str(directory / 'good2-start.o'),
                      str(directory / 'good2.o')])
        self.assertEqual(linked.returncode, 0, linked.stderr)
        checked = self.check(shared)
        self.assertEqual(checked.returncode, 1)
        self.assertIn('not a static executable', checked.stderr)

    def test_a_check_that_cannot_run_is_not_a_pass(self):
        done, elf, _ = self.build('good3', ROOT / 'payloads' / 'state.c')
        self.assertEqual(done.returncode, 0, done.stderr)
        for label, checked in (('no readelf', self.check(elf, readelf='/nonexistent/llvm-readelf')),
                               ('no file', self.check(SCRATCH / 'elf' / 'nothere.elf')),
                               ('not an ELF', self.check(ROOT / 'payloads' / 'state.c'))):
            with self.subTest(case=label):
                self.assertEqual(checked.returncode, 2, checked.stderr)
                self.assertIn('could not run', checked.stderr)


class PayloadBinary(unittest.TestCase):
    # The allow-list mechanism is tools/sp11_payload_testlib.py's POLICIES and binary_violations, one entry per payload,
    # shared with the seeded-bug builds of tools/test-q1n1-sp11-payload-chain.py and -timer.py: `state` is MRS only,
    # `psci` is MRS of CurrentEL and MPIDR_EL1 plus exactly one SMC, `timer` is MRS of its twelve timer and counter
    # registers (the only payload that may read CNTVOFF_EL2 and CNTPOFF_EL2) and no barrier.
    POLICY = lib.POLICIES

    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'ld.lld', 'make', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy'):
            if not have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        cls.out = BUILD / 'binary'
        shutil.rmtree(cls.out, ignore_errors=True)
        done = run(['make'] + MAKE_ARGS + [f'OUT={cls.out.relative_to(ROOT)}', 'payloads'])
        if done.returncode:
            raise RuntimeError('make payloads failed:\n' + done.stdout[-2000:] + done.stderr[-2000:])
        cls.bins = {name: (cls.out / 'payloads' / f'{name}.elf', cls.out / 'payloads' / f'{name}.bin') for name in cls.POLICY}
        cls.elf, cls.flat = cls.bins['state']

    def test_entry_is_at_offset_zero(self):
        for name, (_, flat) in self.bins.items():
            with self.subTest(payload=name):
                first, second = struct.unpack_from('<II', flat.read_bytes())
                self.assertEqual(first, 0xd503245f, 'BTI c is the first instruction')
                self.assertEqual(second >> 26, 0b000101, 'then an unconditional PC-relative branch to payload_entry')

    def test_it_stays_within_its_pages_and_has_no_relocation_the_check_refuses(self):
        for name, (elf, flat) in self.bins.items():
            with self.subTest(payload=name):
                self.assertLessEqual(flat.stat().st_size, self.POLICY[name]['bytes'], 'one range is declared whatever its size')
                done = run(['python3', '-B', str(ROOT / 'tools' / 'sp11_payload_elfcheck.py'), '--readelf', READELF(), str(elf)])
                self.assertEqual(done.returncode, 0, done.stderr)
        self.assertLessEqual(self.flat.stat().st_size, 4096, 'the reference payload is one page')

    def test_linked_at_another_address_the_bytes_are_the_same(self):
        script = (ROOT / 'payloads' / 'payload.ld').read_text(encoding='utf-8')
        self.assertEqual(script.count('. = 0;'), 1)
        moved = SCRATCH / 'moved'
        moved.mkdir(parents=True, exist_ok=True)
        (moved / 'moved.ld').write_text(script.replace('. = 0;', '. = 0x7000000000;'), encoding='utf-8')
        for name, (_, flat) in self.bins.items():
            with self.subTest(payload=name):
                objs = [str(self.out / 'payloads' / 'start.o'), str(self.out / 'payloads' / f'{name}.o')]
                linked = run(['ld.lld'] + lib.makefile_flags('PAYLOAD_LDFLAGS') + ['-T', str(moved / 'moved.ld'), '-o',
                             str(moved / f'{name}-moved.elf')] + objs)
                self.assertEqual(linked.returncode, 0, linked.stderr)
                self.assertEqual(run(['llvm-objcopy', '-O', 'binary', str(moved / f'{name}-moved.elf'),
                                      str(moved / f'{name}-moved.bin')]).returncode, 0)
                self.assertEqual((moved / f'{name}-moved.bin').read_bytes(), flat.read_bytes(),
                                 'the payload depends on the address it is linked at')

    def test_the_code_holds_only_what_its_policy_allows(self):
        # state: MRS of the documented registers and nothing else. psci: MRS of CurrentEL and MPIDR_EL1 and exactly one
        # `smc #0`. timer: MRS of its twelve timer and counter registers, CNTVOFF_EL2 and CNTPOFF_EL2 once each, no
        # barrier, and no SMC. None of them: HVC, SVC, MSR, SYS, DC, IC, TLBI, AT, ERET, WFI, WFE, exclusives or atomics,
        # a word that is not a known instruction; and only timer may name CNTVOFF_EL2 or CNTPOFF_EL2. Checked by the
        # disassembly and, independently, by the encoding of every aligned word of the flat binary's code.
        for name, (elf, flat) in self.bins.items():
            with self.subTest(payload=name):
                self.assertEqual(lib.binary_violations(elf, flat, self.POLICY[name], READELF()), [])
        self.assertEqual(self.POLICY['state']['smc'], 0, 'the reference payload executes no SMC at all')
        self.assertEqual(self.POLICY['psci']['smc'], 1)
        self.assertEqual(self.POLICY['timer']['smc'], 0)
        self.assertEqual([name for name, policy in self.POLICY.items() if policy.get('timer_offsets')], ['timer'])
        offsets = {lib.CNTVOFF_EL2, lib.CNTPOFF_EL2}
        self.assertEqual(self.POLICY['timer']['registers'] & offsets, offsets)
        timer_elf, timer_flat = self.bins['timer']
        for other in ('state', 'psci'):
            with self.subTest(refused_under=other):
                self.assertFalse(offsets & self.POLICY[other]['registers'])
                problems = lib.binary_violations(timer_elf, timer_flat, self.POLICY[other], READELF())
                self.assertTrue(any('the code names' in p for p in problems), 'the timer binary must be refused under this policy')

    def test_make_payloads_is_reproducible(self):
        again = BUILD / 'binary-again'
        shutil.rmtree(again, ignore_errors=True)
        done = run(['make'] + MAKE_ARGS + [f'OUT={again.relative_to(ROOT)}', 'payloads'])
        self.assertEqual(done.returncode, 0, done.stderr)
        for name, (_, flat) in self.bins.items():
            with self.subTest(payload=name):
                self.assertEqual((again / 'payloads' / f'{name}.bin').read_bytes(), flat.read_bytes())

    def test_the_makefile_runs_the_check_between_the_link_and_the_flattening(self):
        done = run(['make', '-n'] + MAKE_ARGS + ['OUT=build/dryrun-payloads', 'payloads'])
        self.assertEqual(done.returncode, 0, done.stderr)
        lines = done.stdout.splitlines()
        for name in self.bins:
            with self.subTest(payload=name):
                link = next(i for i, line in enumerate(lines) if 'ld.lld' in line and f'payloads/{name}.elf' in line)
                check = next(i for i, line in enumerate(lines) if 'sp11_payload_elfcheck.py' in line and f'payloads/{name}.elf' in line)
                flatten = next(i for i, line in enumerate(lines) if 'objcopy' in line and f'payloads/{name}.bin' in line)
                self.assertLess(link, check)
                self.assertLess(check, flatten)

    def test_the_makefile_flags_keep_a_payload_freestanding_and_pc_relative(self):
        cflags = lib.payload_cflags()
        for flag in ('--target=aarch64-unknown-none-elf', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                     '-mgeneral-regs-only', '-mno-outline-atomics', '-fno-pic', '-fno-pie', '-mcmodel=small',
                     '-fno-jump-tables', '-Werror'):
            self.assertIn(flag, cflags)
        for flag in ('-fPIC', '-fpic', '-fPIE', '-mcmodel=large', '-mcmodel=tiny'):
            self.assertNotIn(flag, cflags)
        ldflags = lib.makefile_flags('PAYLOAD_LDFLAGS')
        for flag in ('-static', '-nostdlib', '--emit-relocs'):
            self.assertIn(flag, ldflags)
        self.assertNotIn('-pie', ldflags)

    def test_a_payload_with_an_absolute_relocation_fails_the_makefile_build(self):
        tree = BUILD / 'minitree'
        shutil.rmtree(tree, ignore_errors=True)
        for name in ('platform/uefi/Makefile', 'platform/uefi/sp11-payload-abi.h', 'payloads/start.S', 'payloads/payload.ld',
                     'payloads/payload-util.h', 'payloads/state.c', 'tools/sp11_payload_elfcheck.py'):
            (tree / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / name, tree / name)
        good = run(['make'] + MAKE_ARGS + ['OUT=out', 'payloads'], cwd=tree)
        self.assertEqual(good.returncode, 0, good.stdout[-1500:] + good.stderr[-1500:])
        self.assertTrue((tree / 'out' / 'payloads' / 'state.bin').is_file())
        (tree / 'payloads' / 'pointers.c').write_text(GOOD_ABS, encoding='utf-8')
        bad = run(['make'] + MAKE_ARGS + ['OUT=out', 'payloads'], cwd=tree)
        self.assertNotEqual(bad.returncode, 0, 'a payload with an absolute relocation was built')
        self.assertIn('NOT position independent', bad.stderr)
        self.assertFalse((tree / 'out' / 'payloads' / 'pointers.bin').exists())


def _tool_mutants():
    manifest, elfcheck = 'sp11_payload_manifest.py', 'sp11_payload_elfcheck.py'
    return [
        ('manifest-takes-a-sixth-file', manifest, 'MAX_FILES = SLBOUNCE_COUNT_BASE - BASE_RANGES', 'MAX_FILES = SLBOUNCE_COUNT_BASE - BASE_RANGES + 1'),
        ('manifest-allows-bigger-files', manifest, 'MAX_FILE_BYTES = 256 << 20', 'MAX_FILE_BYTES = 512 << 20'),
        ('manifest-accepts-any-name', manifest, "NAME = re.compile(r'^[A-Z0-9_-]{1,8}\\.[A-Z0-9_-]{1,3}$')", "NAME = re.compile(r'^.+$')"),
        ('manifest-allows-the-reserved-name', manifest, '    if name == MANIFEST_NAME:', '    if False:'),
        ('manifest-accepts-an-empty-file', manifest, 'if not 0 < size <= MAX_FILE_BYTES:', 'if not 0 <= size <= MAX_FILE_BYTES:'),
        ('manifest-accepts-a-short-payload', manifest, "if kind == 'payload' and size < 4:", "if kind == 'payload' and size < 0:"),
        ('manifest-writes-below-the-wrong-directory', manifest, "STICK_DIR = 'SP11'", "STICK_DIR = 'SP12'"),
        ('manifest-writes-before-validating', manifest, '    manifest, entries = build(paths)\n    target = Path(out_dir) / STICK_DIR\n    target.mkdir(parents=True, exist_ok=True)\n',
         '    target = Path(out_dir) / STICK_DIR\n    target.mkdir(parents=True, exist_ok=True)\n    manifest, entries = build(paths)\n'),
        ('elfcheck-accepts-absolute-pointers', elfcheck, "'R_AARCH64_LDST128_ABS_LO12_NC', 'R_AARCH64_PREL16'",
         "'R_AARCH64_LDST128_ABS_LO12_NC', 'R_AARCH64_ABS64', 'R_AARCH64_PREL16'"),
        ('elfcheck-ignores-relocations', elfcheck, '        if kind not in PC_RELATIVE:', '        if False:'),
        ('elfcheck-accepts-a-shared-object', elfcheck, "    if not header.get('Type', '').startswith('EXEC'):", '    if False:'),
        ('elfcheck-ignores-program-headers', elfcheck, '        if kind not in ALLOWED_SEGMENTS:', '        if False:'),
        ('elfcheck-passes-a-check-that-could-not-run', elfcheck, '        return 2\n', '        return 0\n'),
    ]


class ToolMutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'ld.lld', 'llvm-readelf', 'llvm-objcopy'):
            if not have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def _evaluate(self, name, fname, needle, replacement):
        directory = BUILD / f'toolmut-{name}'
        shutil.rmtree(directory, ignore_errors=True)
        (directory / 'tools').mkdir(parents=True)
        for tool in TOOL_NAMES:
            shutil.copy(ROOT / 'tools' / tool, directory / 'tools' / tool)
        path = directory / 'tools' / fname
        text = path.read_text(encoding='utf-8')
        if needle is not None:
            if text.count(needle) != 1:
                return 'stale', f'target not found exactly once in {fname}: {needle[:70]!r}'
            path.write_text(text.replace(needle, replacement, 1), encoding='utf-8')
        env = dict(lib.ENV, Q1N1_PAYLOAD_TOOLS_DIR=str(directory / 'tools'),
                   Q1N1_PAYLOAD_TOOLS_TAG='m' + hashlib.sha1(name.encode()).hexdigest()[:10])
        done = subprocess.run(['python3', '-B', str(Path(__file__).resolve()), 'ManifestTool', 'ElfCheck'], cwd=ROOT,
                              env=env, capture_output=True, text=True, timeout=600)
        if needle is None:
            return ('control-ok' if done.returncode == 0 else 'control-failed'), done.stderr[-600:]
        if done.returncode != 0:
            last = [line for line in done.stderr.splitlines() if line.startswith(('FAIL', 'ERROR'))]
            return 'caught', last[0][:120] if last else 'a test failed'
        return 'survived', 'both tool test classes still passed'

    def test_the_unmutated_control_passes_through_the_same_mechanism(self):
        status, detail = self._evaluate('control', 'sp11_payload_manifest.py', None, None)
        self.assertEqual(status, 'control-ok', detail)

    def test_there_are_enough_distinct_tool_mutants(self):
        mutants = _tool_mutants()
        self.assertGreaterEqual(len(mutants), 12)
        self.assertEqual(len({m[0] for m in mutants}), len(mutants))

    def test_every_seeded_tool_bug_is_caught(self):
        workers = max(1, min(4, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {m[0]: pool.submit(self._evaluate, *m) for m in _tool_mutants()}
            results = {name: future.result() for name, future in futures.items()}
        for name, (status, detail) in results.items():
            with self.subTest(mutant=name):
                self.assertEqual(status, 'caught', f'{status}: {detail}')


class PayloadDefaultOff(unittest.TestCase):
    SP11_DEFINES = ['-DSNAP_PLATFORM_SP11=1', '-DSP11_BUILD_STAMP="PROOF"']
    SP11_MAKE_FLAGS = '-DSNAP_PLATFORM_SP11=1 -DSP11_BUILD_STAMP=\\"PROOF\\"'
    _built = {}

    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def preprocess_main(self, tree, *defines):
        done = run(['clang', '-E', '-P', '-Iplatform/uefi'] + list(defines) + ['platform/uefi/main.c'], cwd=tree)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def _clean_build(self, tree, extra_args=(), out='out', extra_flags=''):
        out_dir = Path(tree) / out
        shutil.rmtree(out_dir, ignore_errors=True)
        # COFF objects carry a link timestamp; -mno-incremental-linker-compatible zeroes it and /Brepro makes
        # the image byte-reproducible (the entry suite's established precedent). A CFLAGS given on the command
        # line replaces the Makefile's own, so an SP11 build has to say its defines here.
        flags = ('--target=aarch64-pc-windows-msvc -O2 -ffreestanding -fno-builtin -fno-stack-protector '
                 '-fshort-wchar -mgeneral-regs-only -mno-outline-atomics -Wall -Wextra -Werror '
                 '-Iplatform/uefi -MMD -MP -mno-incremental-linker-compatible')
        if extra_flags:
            flags += ' ' + extra_flags
        done = run(['make'] + MAKE_ARGS + [f'OUT={out}'] + list(extra_args) + ['-j4', 'all', 'LD=lld-link /Brepro',
                                                                              f'CFLAGS={flags}'], cwd=tree)
        self.assertEqual(done.returncode, 0, done.stdout[-2000:] + done.stderr[-2000:])
        return out_dir

    def _build(self, tree, label, extra_args=(), sp11=True):
        key = (str(tree), label)
        if key not in self._built:
            self._built[key] = self._clean_build(tree, (SP11_FIXTURES if sp11 else []) + list(extra_args),
                                                 out=f'build/out-{label}', extra_flags=self.SP11_MAKE_FLAGS if sp11 else '')
        return self._built[key]

    def make_lines(self, tree, *args):
        done = run(['make', '-n'] + MAKE_ARGS + ['OUT=build/dryrun'] + list(args), cwd=tree)
        self.assertEqual(done.returncode, 0, done.stderr)
        return [' '.join(line.split()) for line in done.stdout.splitlines()]

    # -- the gate at zero changes nothing -----------------------------------------------------------------
    def test_the_gate_at_zero_changes_nothing_in_main_c(self):
        for defines in ([], self.SP11_DEFINES, self.SP11_DEFINES + ['-DQ1N1_SP11_STK_SURVEY=1']):
            self.assertEqual(self.preprocess_main(ROOT, *defines), self.preprocess_main(ROOT, *defines, '-DQ1N1_SP11_PAYLOAD=0'))

    def test_the_gate_changes_main_c_when_set(self):
        self.assertNotEqual(self.preprocess_main(ROOT, *self.SP11_DEFINES),
                            self.preprocess_main(ROOT, *self.SP11_DEFINES, '-DQ1N1_SP11_PAYLOAD=1'))

    @unittest.skipUnless(SP11_BASE, 'Q1N1_SP11_BASE_DIR not set: no pre-runner tree to compare against')
    def test_main_c_preprocesses_identically_to_the_pre_runner_tree(self):
        for defines in ([], self.SP11_DEFINES, self.SP11_DEFINES + ['-DQ1N1_SP11_STK_SURVEY=1']):
            for extra in ([], ['-DQ1N1_SP11_PAYLOAD=0']):
                with self.subTest(defines=defines, extra=extra):
                    self.assertEqual(self.preprocess_main(ROOT, *defines, *extra), self.preprocess_main(Path(SP11_BASE), *defines))

    def test_the_gate_without_sp11_is_an_error_in_every_runner_file(self):
        names = ['platform/uefi/main.c'] + [str(p.relative_to(ROOT)) for p in RUNNER_SOURCES]
        self.assertGreaterEqual(len(names), 6)
        for name in names:
            language = ['-x', 'assembler-with-cpp'] if name.endswith('.S') else []
            for defines in (['-DQ1N1_SP11_PAYLOAD=1'], ['-DSNAP_PLATFORM_SP11=0', '-DQ1N1_SP11_PAYLOAD=1']):
                with self.subTest(file=name, defines=defines):
                    done = run(['clang', '-E', '-P', '-Iplatform/uefi'] + language + defines + [name])
                    self.assertNotEqual(done.returncode, 0, 'the gate without SP11 was accepted')
                    self.assertIn('needs SNAP_PLATFORM_SP11=1', done.stderr)

    def test_the_gate_with_the_survey_is_an_error(self):
        for name in ['platform/uefi/main.c'] + [str(p.relative_to(ROOT)) for p in RUNNER_SOURCES if p.suffix == '.c']:
            with self.subTest(file=name):
                done = run(['clang', '-E', '-P', '-Iplatform/uefi', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1',
                            '-DQ1N1_SP11_STK_SURVEY=1', name])
                self.assertNotEqual(done.returncode, 0)
                self.assertIn('cannot be combined', done.stderr)

    @unittest.skipUnless(have('llvm-nm'), 'llvm-nm not installed')
    def test_every_runner_file_compiles_to_nothing_with_the_gate_off(self):
        flags = ['--target=aarch64-pc-windows-msvc', '-O2', '-ffreestanding', '-fno-builtin', '-fshort-wchar',
                 '-mgeneral-regs-only', '-Wall', '-Wextra', '-Werror', '-Iplatform/uefi']
        self.assertGreaterEqual(len(RUNNER_SOURCES), 5)
        for source in RUNNER_SOURCES:
            # An assembler file takes no warning flags: they would be "unused" and -Werror would refuse them.
            use = ['--target=aarch64-pc-windows-msvc', '-Iplatform/uefi'] if source.suffix == '.S' else flags
            for defines in ([], ['-DSNAP_PLATFORM_SP11=1'], ['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=0']):
                with self.subTest(file=source.name, defines=defines):
                    obj = BUILD / f'{source.stem}.gate-off.obj'
                    done = run(['clang'] + use + defines + ['-c', str(source), '-o', str(obj)])
                    self.assertEqual(done.returncode, 0, done.stderr)
                    left = [line for line in run(['llvm-nm', str(obj)]).stdout.splitlines()
                            if line.strip() and '@feat.00' not in line]
                    self.assertEqual(left, [], 'the object is not empty with the gate off')

    # -- the Makefile -------------------------------------------------------------------------------------------
    def test_the_makefile_refuses_the_runner_without_sp11_and_with_the_survey(self):
        for args in (['PAYLOAD=1', 'all'], ['PAYLOAD=1', 'payload-runner']):
            done = run(['make', '-n'] + MAKE_ARGS + ['OUT=build/dryrun'] + args)
            self.assertNotEqual(done.returncode, 0)
            self.assertIn('PAYLOAD=1 needs SP11=1', done.stdout + done.stderr)
        done = run(['make', '-n'] + MAKE_ARGS + ['OUT=build/dryrun'] + SP11_FIXTURES + ['PAYLOAD=1', 'STK_SURVEY=1', 'all'])
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('cannot be combined', done.stdout + done.stderr)

    def test_an_explicit_payload_off_leaves_the_make_command_lines_alone(self):
        for extra in ([], SP11_FIXTURES + ['SP11_BUILD_STAMP=PROOF'], SP11_FIXTURES + ['SP11_BUILD_STAMP=PROOF', 'STK_SURVEY=1']):
            plain = self.make_lines(ROOT, *extra, 'all')
            explicit = self.make_lines(ROOT, *extra, 'PAYLOAD=0', 'all')
            self.assertEqual(plain, explicit)
            self.assertNotIn('payload', ' '.join(plain).lower())

    @unittest.skipUnless(SP11_BASE, 'Q1N1_SP11_BASE_DIR not set: no pre-runner tree to compare against')
    def test_make_command_lines_are_unchanged_from_the_pre_runner_tree(self):
        for extra in ([], SP11_FIXTURES + ['SP11_BUILD_STAMP=PROOF'], SP11_FIXTURES + ['SP11_BUILD_STAMP=PROOF', 'STK_SURVEY=1']):
            with self.subTest(args=extra):
                mine, base = self.make_lines(ROOT, *extra, 'all'), self.make_lines(Path(SP11_BASE), *extra, 'all')
                self.assertGreater(len(mine), 20)
                self.assertEqual(mine, base)

    def test_the_makefile_builds_every_runner_source(self):
        makefile = (UEFI / 'Makefile').read_text(encoding='utf-8')
        block = makefile[makefile.index('PAYLOAD_OBJS :='):makefile.index('PAYLOAD_HEADERS :=')]
        listed = set(re.findall(r'sp11-payload-([a-z0-9]+)\.obj', block))
        self.assertEqual(listed, {p.stem[len('sp11-payload-'):] for p in RUNNER_SOURCES})

    # -- the builds -------------------------------------------------------------------------------------------------
    @unittest.skipUnless(SP11_BASE, 'Q1N1_SP11_BASE_DIR not set: no pre-runner tree to compare against')
    @unittest.skipUnless(have('lld-link') and have('ld.lld'), 'lld-link or ld.lld not installed')
    def test_default_plain_sp11_and_survey_builds_are_byte_identical_to_the_pre_runner_tree(self):
        pairs = (('default', [], False, ('q1n1.efi', 'q1n1-stage.bin', 'q1n1-stage-alt.bin', 'q1n1-stage-qemu.bin', 'q1n1-stage-qemu-alt.bin')),
                 ('sp11', [], True, SP11_ARTEFACTS + ('sp11-fbgop.obj', 'sp11-stage-table.obj', 'sp11-usb-ports.obj')),
                 ('survey', ['STK_SURVEY=1'], True, SP11_ARTEFACTS + ('q1n1-stk.efi', 'main-stk.obj', 'sp11-stk-text.obj',
                                                                      'sp11-stk-el2.obj', 'sp11-stk-p2.obj')))
        for label, args, sp11, artefacts in pairs:
            with self.subTest(build=label):
                mine = self._build(ROOT, f'{label}-mine', args, sp11)
                base = self._build(Path(SP11_BASE), f'{label}-base', args, sp11)
                for artefact in artefacts:
                    self.assertEqual((mine / artefact).read_bytes(), (base / artefact).read_bytes(), f'{artefact} differs')
                self.assertFalse((mine / 'q1n1-payload.efi').exists())

    @unittest.skipUnless(have('lld-link') and have('ld.lld'), 'lld-link or ld.lld not installed')
    def test_the_runner_build_makes_its_own_image_and_changes_nothing_else(self):
        plain = self._build(ROOT, 'sp11-mine')
        runner = self._build(ROOT, 'payload', ['PAYLOAD=1'])
        for artefact in SP11_ARTEFACTS + ('sp11-fbgop.obj', 'sp11-stage-table.obj', 'sp11-usb-ports.obj'):
            self.assertEqual((plain / artefact).read_bytes(), (runner / artefact).read_bytes(),
                             f'{artefact} changed when the runner was built')
        image, normal = (runner / 'q1n1-payload.efi').read_bytes(), (plain / 'q1n1.efi').read_bytes()
        self.assertNotEqual(image, normal)
        for text in (b'PAYLOAD CALL', b'PAYLOAD VERIFY=OK', b'PAYLOAD REFUSED=', b'PAYLOAD SKIPPED=NOT_AT_EL2', b'PAYLOAD READY',
                     b'PAYLOAD DONE', b'PAYLOAD CHAIN STOPPED', b'FILE0_NOT_BIN'):
            self.assertIn(text, image)
            self.assertNotIn(text, normal)
            self.assertNotIn(text, (runner / 'q1n1.efi').read_bytes())
        self.assertFalse((plain / 'q1n1-payload.efi').exists())
        for name in ('main-payload.obj', 'sp11-payload-text.obj', 'sp11-payload-plan.obj', 'sp11-payload-load.obj',
                     'sp11-payload-run.obj', 'sp11-payload-call.obj'):
            self.assertTrue((runner / name).is_file(), name)
            self.assertFalse((plain / name).exists(), name)
        self.assertTrue((runner / 'payloads' / 'state.bin').is_file())
        self.assertFalse((plain / 'payloads').exists(), 'a build without PAYLOAD makes no payload')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
