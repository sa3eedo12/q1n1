#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native tests for the default-off Surface Pro 11 USB port path (SNAP_PLATFORM_SP11) and proof that it is off.

    python3 tools/test-q1n1-sp11-usb-ports.py

Runs, under ASan and UBSan:
  * tools/test-q1n1-sp11-table.c   the table and controller validators, hand-written valid and faulty tables;
  * tools/test-q1n1-sp11-usb-ports.c the real usb-ports.c with mocked controllers and a table instead of A16 bases.

And checks the gate is off by default:
  * `-DSNAP_PLATFORM_SP11=0` preprocesses usb-ports.c exactly as no define does;
  * the SP11 object carries no A16 base or core-id immediate, the default object still does (a control);
  * the default Makefile command lines are the same as the pristine tree's, when Q1N1_BASE_DIR names one (otherwise
    SKIP), and SP11=1 without a table is refused;
  * the SP11=1 wiring compiles and links with a fixture table (a link check, never run).

Q1N1_BASE_DIR: a pristine q1n1 tree to compare the default build against (SKIP when unset). Nothing is written outside
build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model).
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'build' / 'sp11-usb-ports-test'
LLVM = ('/opt/homebrew/opt/llvm/bin', '/opt/homebrew/opt/lld/bin', '/opt/homebrew/bin')
ENV = dict(os.environ, PATH=os.pathsep.join(LLVM + (os.environ.get('PATH', ''),)), PYTHONDONTWRITEBYTECODE='1')
SANITIZE = ['-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
            '-Wall', '-Wextra', '-Werror', '-Iplatform/uefi']
STAGE_FLAGS = ['--target=aarch64-unknown-none-elf', '-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
               '-mgeneral-regs-only', '-mno-outline-atomics', '-fno-pic', '-mcmodel=small', '-Wall', '-Wextra',
               '-Werror', '-Iplatform/uefi', '-DQ1N1_STAGE']
BASE = os.environ.get('Q1N1_BASE_DIR')


def run(cmd, cwd=ROOT, **kw):
    return subprocess.run(cmd, cwd=cwd, env=ENV, capture_output=True, text=True, **kw)


def have(tool):
    return shutil.which(tool, path=ENV['PATH']) is not None


class Native(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        BUILD.mkdir(parents=True, exist_ok=True)

    def build_and_run(self, name, sources, extra, args=()):
        binary = BUILD / name
        done = run(['clang'] + SANITIZE + ['-DSNAP_PLATFORM_SP11=1'] + extra + sources + ['-o', str(binary)])
        self.assertEqual(done.returncode, 0, done.stderr)
        return run([str(binary)] + list(args))

    def test_table_and_controller_validators(self):
        done = self.build_and_run('table-self', ['tools/test-q1n1-sp11-table.c', 'platform/uefi/sp11-usb-ports.c'],
                                  ['-DSP11_HARNESS_OWN_TABLE'], ['self'])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('PASS', done.stdout)

    def test_manager_follows_the_table(self):
        done = self.build_and_run('manager', ['tools/test-q1n1-sp11-usb-ports.c', 'platform/uefi/usb-ports.c',
                                               'platform/uefi/sp11-usb-ports.c'], [])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('PASS', done.stdout)

    def test_a_build_without_the_gate_does_not_compile_the_validator(self):
        done = run(['clang'] + SANITIZE + ['-c', 'platform/uefi/sp11-usb-ports.c', '-o', str(BUILD / 'off.o')])
        self.assertEqual(done.returncode, 0, done.stderr)
        symbols = run(['llvm-nm', str(BUILD / 'off.o')]) if have('llvm-nm') else None
        if symbols is None:
            self.skipTest('llvm-nm not installed')
        self.assertNotIn('q1n1_sp11', symbols.stdout)

    def test_a_generated_table_cannot_compile_without_the_gate(self):
        done = run(['clang'] + SANITIZE + ['-fsyntax-only', 'tools/testdata/sp11-usb-table-fixture.c'])
        self.assertNotEqual(done.returncode, 0)


class DefaultOff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        BUILD.mkdir(parents=True, exist_ok=True)

    def preprocess(self, *defines):
        done = run(['clang', '-E', '-P', '-Iplatform/uefi'] + list(defines) + ['platform/uefi/usb-ports.c'])
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def test_defining_the_gate_as_zero_changes_nothing(self):
        self.assertEqual(self.preprocess(), self.preprocess('-DSNAP_PLATFORM_SP11=0'))

    def test_the_gate_changes_the_preprocessed_manager(self):
        self.assertNotEqual(self.preprocess(), self.preprocess('-DSNAP_PLATFORM_SP11=1'))

    def compile_stage(self, tree, name, *defines):
        out = BUILD / name
        done = run(['clang'] + STAGE_FLAGS + list(defines) + ['-c', 'platform/uefi/usb-ports.c', '-o', str(out)], cwd=tree)
        self.assertEqual(done.returncode, 0, done.stderr)
        return out

    def test_a16_immediates_are_gone_from_the_sp11_object_and_present_in_the_default_one(self):
        if not have('llvm-objdump'):
            self.skipTest('llvm-objdump not installed')
        texts = {}
        for name, defines in (('default.o', ()), ('sp11.o', ('-DSNAP_PLATFORM_SP11=1',))):
            out = self.compile_stage(ROOT, name, *defines)
            texts[name] = run(['llvm-objdump', '-d', '--no-show-raw-insn', str(out)]).stdout.lower()
        for immediate in ('0xa600000', '0xa800000', '0x3331', '0x3130'):
            self.assertIn(immediate, texts['default.o'], f'control: the A16 object should use {immediate}')
            self.assertNotIn(immediate, texts['sp11.o'], f'the SP11 object still carries the A16 value {immediate}')

    @unittest.skipUnless(BASE, 'Q1N1_BASE_DIR not set: no pristine tree to compare against')
    def test_default_object_is_byte_identical_to_the_pristine_tree(self):
        base = Path(BASE)
        self.assertTrue((base / 'platform/uefi/usb-ports.c').is_file(), 'Q1N1_BASE_DIR is not a q1n1 tree')
        mine = self.compile_stage(ROOT, 'mine.o').read_bytes()
        pristine = self.compile_stage(base, 'pristine.o').read_bytes()
        self.assertEqual(mine, pristine)

    @unittest.skipUnless(BASE, 'Q1N1_BASE_DIR not set: no pristine tree to compare against')
    def test_default_make_command_lines_are_unchanged(self):
        lines = {}
        for label, tree in (('mine', ROOT), ('pristine', Path(BASE))):
            done = run(['make', '-n', '-f', 'platform/uefi/Makefile', 'OUT=build/dryrun', 'all'], cwd=tree)
            self.assertEqual(done.returncode, 0, done.stderr)
            lines[label] = [' '.join(line.split()) for line in done.stdout.splitlines()]
        self.assertGreater(len(lines['mine']), 20)
        self.assertEqual(lines['mine'], lines['pristine'])

    @unittest.skipUnless(BASE and shutil.which('lld-link', path=ENV['PATH']) and shutil.which('ld.lld', path=ENV['PATH']),
                         'Q1N1_BASE_DIR not set, or lld-link/ld.lld not installed')
    def test_the_whole_default_build_is_identical_to_the_pristine_tree(self):
        # COFF objects carry a link timestamp: -mno-incremental-linker-compatible zeroes it and /Brepro makes the image
        # deterministic. The same overrides are used for both trees, and the pristine tree is only read: its outputs go
        # to an absolute OUT under this tree's build/.
        flags = ('--target=aarch64-pc-windows-msvc -O2 -ffreestanding -fno-builtin -fno-stack-protector -fshort-wchar '
                 '-mgeneral-regs-only -mno-outline-atomics -Wall -Wextra -Werror -Iplatform/uefi -MMD -MP '
                 '-mno-incremental-linker-compatible')
        built = {}
        for label, tree in (('mine', ROOT), ('pristine', Path(BASE))):
            out = BUILD / f'full-{label}'
            shutil.rmtree(out, ignore_errors=True)
            done = run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out}', '-j2', 'all', 'LD=lld-link /Brepro',
                        f'CFLAGS={flags}'], cwd=tree)
            self.assertEqual(done.returncode, 0, done.stderr[-1500:])
            built[label] = {p.relative_to(out).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in out.rglob('*') if p.is_file() and p.suffix != '.d'}
        self.assertGreater(len(built['mine']), 40)
        self.assertEqual(built['mine'], built['pristine'])

    def test_sp11_without_a_table_is_refused(self):
        done = run(['make', '-n', '-f', 'platform/uefi/Makefile', 'OUT=build/dryrun', 'SP11=1', 'all'])
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('SP11_USB_TABLE_C', done.stdout + done.stderr)

    @unittest.skipUnless(shutil.which('lld-link', path=ENV['PATH']) and shutil.which('ld.lld', path=ENV['PATH']),
                         'lld-link or ld.lld not installed')
    def test_sp11_wiring_compiles_and_links_with_a_fixture_table(self):
        out = BUILD / 'link-check'
        shutil.rmtree(out, ignore_errors=True)
        # SP11_STAGE_TABLE_C: this patch's own build now also gates on the chainload
        # candidate table (sp11-stage-table.h, docs/SP11-Q1N1-BOOT-STUDY.md section 9.1,
        # tools/test-q1n1-sp11-entry.py), added on top of this USB-table gate by a later
        # SP11=1 consumer; both are required together now, so this pre-existing test supplies
        # both fixtures, same fail-closed posture, not a relaxation of either gate.
        done = run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j2', 'all', 'SP11=1',
                    'SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c',
                    'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c'])
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-1500:])
        for artefact in ('q1n1.efi', 'q1n1-stage.bin', 'stage/sp11-usb-ports.obj', 'stage/sp11-usb-table.obj'):
            self.assertTrue((out / artefact).is_file(), artefact)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
