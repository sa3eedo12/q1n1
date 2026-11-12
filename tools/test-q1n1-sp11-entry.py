#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native tests, cross-checks and the default-off proof for q1n1's SP11 entry/chainload/console
patch (docs/SP11-Q1N1-BOOT-STUDY.md sections 4.4/7.2, 5.3-5.5, 8, 9), built on top of the already-
landed, already-verified sa3eedo12-sp11-host-link branch (platform/uefi/sp11-usb-ports.*,
docs/BOARD-INFO.md).

    python3 tools/test-q1n1-sp11-entry.py

Runs, under ASan and UBSan:
  * Native: tools/test-q1n1-sp11-entry.c's own gop/stage/ranges/entry checks (64 total);
  * ModelMatchesSource: the entry-model's quoted conditional literally still appears in
    platform/uefi/main.c, so the host model (which cannot read a real CurrentEL) cannot silently
    drift from the function it mirrors;
  * SharedHeader: platform/uefi/sp11-ebs-ranges.h is byte-identical to the Snapintosh SP11 fork of
    slbounce's own copy (src/sp11-ebs-ranges.h) -- the one piece of this patch that has to agree
    across both repositories (SKIP without SLBOUNCE_SP11_DIR);
  * Mutations: one seeded bug each in sp11-fbgop.c (the GOP tier-2 "SAME" agreement check) and
    sp11-stage-table.c (the A16-address refusal) is confirmed to break the Native self-tests;
  * DefaultOff: with SNAP_PLATFORM_SP11 unset (or 0), platform/uefi/main.c preprocesses
    identically either way; the whole q1n1.efi/stage build is byte-identical to
    Q1N1_HOSTLINK_BASE_DIR's own (the sa3eedo12-sp11-host-link branch tip, not the A16 pinned
    commit -- B2/B3's own gate is the baseline this patch builds on, not the far earlier upstream
    pin); make -n command lines are unchanged; SP11=1 without either required table is refused
    (SP11_USB_TABLE_C, inherited from B2/B3, and the new SP11_STAGE_TABLE_C); and the full SP11=1
    wiring compiles and links with both fixture tables (a link check, never run).

Q1N1_HOSTLINK_BASE_DIR: a pristine q1n1 checkout at the sa3eedo12-sp11-host-link branch tip (SKIP
every comparison test without it). SLBOUNCE_SP11_DIR: the paired Snapintosh SP11 fork of slbounce
(SKIP SharedHeader without it). Nothing is written outside build/. Hardware: NOT RUN. Evidence:
EXPERIMENTAL (host model/link-check only)."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'build' / 'sp11-entry-test'
LLVM = ('/opt/homebrew/opt/llvm/bin', '/opt/homebrew/opt/lld/bin', '/opt/homebrew/bin')
ENV = dict(os.environ, PATH=os.pathsep.join(LLVM + (os.environ.get('PATH', ''),)), PYTHONDONTWRITEBYTECODE='1')
SANITIZE = ['-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
            '-Wall', '-Wextra', '-Werror', '-Iplatform/uefi']
HOSTLINK_BASE = os.environ.get('Q1N1_HOSTLINK_BASE_DIR')
SLBOUNCE_SP11_DIR = os.environ.get('SLBOUNCE_SP11_DIR')
MAKE_ARGS = ['-f', 'platform/uefi/Makefile']


def run(cmd, cwd=ROOT, **kw):
    return subprocess.run(cmd, cwd=cwd, env=ENV, capture_output=True, text=True, **kw)


def have(tool):
    return shutil.which(tool, path=ENV['PATH']) is not None


class Native(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def _build(self, name, extra_sources=()):
        binary = BUILD / name
        sources = ['tools/test-q1n1-sp11-entry.c', 'platform/uefi/sp11-fbgop.c',
                  'platform/uefi/sp11-stage-table.c'] + list(extra_sources)
        done = run(['clang'] + SANITIZE + ['-DSNAP_PLATFORM_SP11=1'] + sources + ['-o', str(binary)])
        return done, binary

    def test_all_four_groups_pass(self):
        done, binary = self._build('test-entry')
        self.assertEqual(done.returncode, 0, done.stderr)
        done = run([str(binary)])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        for label in ('GOP', 'stage-table', 'declared-ranges', 'entry-model'):
            self.assertIn(f'PASS', done.stdout)
        self.assertEqual(done.stdout.count('PASS'), 4, done.stdout)


class ModelMatchesSource(unittest.TestCase):
    """test-q1n1-sp11-entry.c's model of q1n1_main() cannot read a real CurrentEL, so it is a
    transcription, not the real function; this confirms the transcription still matches."""

    def test_the_quoted_conditional_is_still_in_main_c(self):
        main_c = (ROOT / 'platform/uefi/main.c').read_text(encoding='utf-8')
        self.assertIn('if (mode != MODE_FOOTHOLD && current_el() != 2)', main_c)
        self.assertIn('if (mode != MODE_FOOTHOLD) proxy_main();', main_c)
        # And in the order the model assumes: the refusal check's own block must end (its closing
        # brace) before the unconditional proxy_main() dispatch line, not after.
        halt_at = main_c.index('if (mode != MODE_FOOTHOLD && current_el() != 2)')
        dispatch_at = main_c.index('if (mode != MODE_FOOTHOLD) proxy_main();')
        self.assertLess(halt_at, dispatch_at)

    def test_the_mode_constants_match(self):
        main_c = (ROOT / 'platform/uefi/main.c').read_text(encoding='utf-8')
        self.assertIn('#define MODE_FOOTHOLD 0', main_c)
        self.assertIn('#define MODE_USB_PROXY 1', main_c)
        self.assertIn('#define MODE_UART_PROXY 2', main_c)


class SharedHeader(unittest.TestCase):
    """sp11-ebs-ranges.h is the one ABI this patch has to keep identical across both repositories
    (q1n1's platform/uefi/ and the paired slbounce fork's src/); see that header's own comment."""

    @unittest.skipUnless(SLBOUNCE_SP11_DIR, 'SLBOUNCE_SP11_DIR not set: no paired slbounce fork to compare against')
    def test_byte_identical_to_the_slbounce_copy(self):
        mine = (ROOT / 'platform/uefi/sp11-ebs-ranges.h').read_text(encoding='utf-8')
        theirs_path = Path(SLBOUNCE_SP11_DIR) / 'src/sp11-ebs-ranges.h'
        self.assertTrue(theirs_path.is_file(), f'{theirs_path} missing')
        self.assertEqual(mine, theirs_path.read_text(encoding='utf-8'))


class Mutations(unittest.TestCase):
    """One seeded bug per new validator (not an exhaustive battery: sp11-fbgop.c and
    sp11-stage-table.c are independent reimplementations/new designs, not ports of an existing
    upstream oracle the way the scoped sweep is, so there is no second-language model to seed
    mutations into in parallel -- each mutation here is checked the same way
    tools/test-q1n1-sp11-usb-ports.py's own established pattern does: rebuild, confirm the self-
    tests that exercise the mutated rule now fail)."""

    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def _build_and_run(self, mutant_dir, mutated_name, mutated_text, mode):
        mutant_dir.mkdir(parents=True, exist_ok=True)
        (mutant_dir / mutated_name).write_text(mutated_text, encoding='utf-8')
        other = 'sp11-stage-table.c' if mutated_name == 'sp11-fbgop.c' else 'sp11-fbgop.c'
        shutil.copy(ROOT / 'platform/uefi' / other, mutant_dir / other)
        for header in ('sp11-fbgop.h', 'sp11-stage-table.h', 'sp11-ebs-ranges.h'):
            shutil.copy(ROOT / 'platform/uefi' / header, mutant_dir / header)
        binary = mutant_dir / 'test-entry-mutant'
        done = run(['clang'] + SANITIZE + ['-DSNAP_PLATFORM_SP11=1', '-I', str(mutant_dir),
                    'tools/test-q1n1-sp11-entry.c', str(mutant_dir / 'sp11-fbgop.c'),
                    str(mutant_dir / 'sp11-stage-table.c'), '-o', str(binary)])
        self.assertEqual(done.returncode, 0, done.stderr)
        return run([str(binary), mode])

    def test_dropping_the_same_framebuffer_agreement_check_is_caught(self):
        src = (ROOT / 'platform/uefi/sp11-fbgop.c').read_text(encoding='utf-8')
        needle = 'else if (!same_framebuffer(&cand[first], &cand[i])) differ = 1;'
        self.assertIn(needle, src, 'mutation target not found (source changed?)')
        # `&& 0`, not a bare `if (0)`: same_framebuffer's only call site must still call it, so the
        # mutation disables the *check* without making the static helper function itself unused
        # (which -Wextra -Werror, the real build's own flags, would refuse to compile at all --
        # the mutant must still build, only misbehave).
        mutated = src.replace(needle, 'else if (!same_framebuffer(&cand[first], &cand[i]) && 0) differ = 1;', 1)
        done = self._build_and_run(BUILD / 'mutant-gop-same', 'sp11-fbgop.c', mutated, 'gop')
        self.assertNotEqual(done.returncode, 0, 'mutation did not break anything: still refused disagreeing GOPs')

    def test_dropping_the_a16_base_refusal_is_caught(self):
        src = (ROOT / 'platform/uefi/sp11-stage-table.c').read_text(encoding='utf-8')
        needle = 'if (is_a16_candidate(base)) return Q1N1_SP11_STAGE_ERR_A16_BASE;'
        self.assertIn(needle, src, 'mutation target not found (source changed?)')
        mutated = src.replace(needle, 'if (is_a16_candidate(base) && 0) return Q1N1_SP11_STAGE_ERR_A16_BASE;', 1)
        done = self._build_and_run(BUILD / 'mutant-stage-a16', 'sp11-stage-table.c', mutated, 'stage')
        self.assertNotEqual(done.returncode, 0, 'mutation did not break anything: still refused an A16 stage address')


class DefaultOff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def preprocess_main(self, tree, *defines):
        done = run(['clang', '-E', '-P', '-Iplatform/uefi'] + list(defines) + ['platform/uefi/main.c'], cwd=tree)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def test_defining_the_gate_as_zero_changes_nothing_in_main_c(self):
        self.assertEqual(self.preprocess_main(ROOT), self.preprocess_main(ROOT, '-DSNAP_PLATFORM_SP11=0'))

    def test_the_gate_changes_preprocessed_main_c(self):
        self.assertNotEqual(self.preprocess_main(ROOT), self.preprocess_main(ROOT, '-DSNAP_PLATFORM_SP11=1'))

    def _clean_build(self, tree, extra_args=(), out='out', deterministic=False):
        out_dir = Path(tree) / out
        if out_dir.exists():
            shutil.rmtree(out_dir)
        cmd = ['make'] + MAKE_ARGS + [f'OUT={out}'] + list(extra_args) + ['-j4', 'all']
        if deterministic:
            # COFF objects carry a link timestamp; -mno-incremental-linker-compatible zeroes it
            # and /Brepro makes the image byte-reproducible. Mirrors the established precedent
            # for this exact problem, tools/test-q1n1-sp11-usb-ports.py's own
            # test_the_whole_default_build_is_identical_to_the_pristine_tree.
            flags = ('--target=aarch64-pc-windows-msvc -O2 -ffreestanding -fno-builtin -fno-stack-protector '
                     '-fshort-wchar -mgeneral-regs-only -mno-outline-atomics -Wall -Wextra -Werror '
                     '-Iplatform/uefi -MMD -MP -mno-incremental-linker-compatible')
            cmd += ['LD=lld-link /Brepro', f'CFLAGS={flags}']
        done = run(cmd, cwd=tree)
        self.assertEqual(done.returncode, 0, done.stdout[-2000:] + done.stderr[-2000:])
        return out_dir

    @unittest.skipUnless(HOSTLINK_BASE, 'Q1N1_HOSTLINK_BASE_DIR not set: no pristine tree to compare against')
    @unittest.skipUnless(have('lld-link') and have('ld.lld'), 'lld-link or ld.lld not installed')
    def test_default_build_is_byte_identical_to_the_hostlink_base(self):
        mine = self._clean_build(ROOT, deterministic=True)
        base = self._clean_build(Path(HOSTLINK_BASE), deterministic=True)
        for artefact in ('q1n1.efi', 'q1n1-stage.bin', 'q1n1-stage-alt.bin', 'q1n1-stage-qemu.bin',
                        'q1n1-stage-qemu-alt.bin'):
            self.assertEqual((mine / artefact).read_bytes(), (base / artefact).read_bytes(), f'{artefact} differs')

    @unittest.skipUnless(HOSTLINK_BASE, 'Q1N1_HOSTLINK_BASE_DIR not set: no pristine tree to compare against')
    def test_default_make_command_lines_are_unchanged(self):
        lines = {}
        for label, tree in (('mine', ROOT), ('hostlink_base', Path(HOSTLINK_BASE))):
            done = run(['make', '-n'] + MAKE_ARGS + ['OUT=build/dryrun', 'all'], cwd=tree)
            self.assertEqual(done.returncode, 0, done.stderr)
            lines[label] = [' '.join(line.split()) for line in done.stdout.splitlines()]
        self.assertGreater(len(lines['mine']), 20)
        self.assertEqual(lines['mine'], lines['hostlink_base'])

    def test_sp11_without_usb_table_is_refused(self):
        done = run(['make', '-n'] + MAKE_ARGS + ['OUT=build/dryrun', 'SP11=1',
                    'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c', 'all'])
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('SP11_USB_TABLE_C', done.stdout + done.stderr)

    def test_sp11_without_stage_table_is_refused(self):
        done = run(['make', '-n'] + MAKE_ARGS + ['OUT=build/dryrun', 'SP11=1',
                    'SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c', 'all'])
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('SP11_STAGE_TABLE_C', done.stdout + done.stderr)

    @unittest.skipUnless(have('lld-link') and have('ld.lld'), 'lld-link or ld.lld not installed')
    def test_sp11_wiring_compiles_and_links_with_fixture_tables(self):
        out = BUILD / 'link-check'
        shutil.rmtree(out, ignore_errors=True)
        done = run(['make'] + MAKE_ARGS + [f'OUT={out.relative_to(ROOT)}', '-j4', 'all', 'SP11=1',
                    'SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c',
                    'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c'])
        self.assertEqual(done.returncode, 0, done.stdout[-2000:] + done.stderr[-2000:])
        for artefact in ('q1n1.efi', 'q1n1-stage.bin', 'q1n1-stage-alt.bin', 'sp11-fbgop.obj',
                        'sp11-stage-table.obj', 'sp11-stage-candidates.obj'):
            self.assertTrue((out / artefact).is_file(), artefact)

    @unittest.skipUnless(have('lld-link') and have('ld.lld'), 'lld-link or ld.lld not installed')
    def test_the_gate_changes_the_build_when_set(self):
        # The converse control, mirroring the paired slbounce patch's own test of the same name.
        default_out = self._clean_build(ROOT)
        default_hash = (default_out / 'q1n1.efi').read_bytes()
        gated_out = self._clean_build(ROOT, ['SP11=1', 'SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c',
                                             'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c'],
                                      out='out-gated')
        self.assertNotEqual((gated_out / 'q1n1.efi').read_bytes(), default_hash)
        shutil.rmtree(gated_out, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
