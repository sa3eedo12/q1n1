#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native tests, cross-checks and the default-off proof for q1n1's SP11 entry/chainload/console
patch (docs/SP11-Q1N1-BOOT-STUDY.md sections 4.4/7.2, 5.3-5.5, 8, 9), built on top of the already-
landed, already-verified sa3eedo12-sp11-host-link branch (platform/uefi/sp11-usb-ports.*,
docs/BOARD-INFO.md).

    python3 tools/test-q1n1-sp11-entry.py

Runs, under ASan and UBSan:
  * Native: tools/test-q1n1-sp11-entry.c's own gop/stage/ranges/entry checks (102 total);
  * ModelMatchesSource: the entry-model's quoted conditional literally still appears in
    platform/uefi/main.c, so the host model (which cannot read a real CurrentEL) cannot silently
    drift from the function it mirrors;
  * SharedHeader: platform/uefi/sp11-ebs-ranges.h is byte-identical to the Snapintosh SP11 fork of
    slbounce's own copy (src/sp11-ebs-ranges.h) -- the one piece of this patch that has to agree
    across both repositories (SKIP without SLBOUNCE_SP11_DIR);
  * Mutations: seeded bugs in sp11-fbgop.c (the GOP tier-2 "SAME" agreement check, the memory-map
    parser's refusal of a map it cannot hold, its page-count and attribute offsets, and the "exactly
    one descriptor" rule of range facts) and sp11-stage-table.c (the A16-address refusal) are each
    confirmed to break the Native self-tests;
  * DefaultOff: with SNAP_PLATFORM_SP11 unset (or 0), platform/uefi/main.c preprocesses
    identically either way; the whole q1n1.efi/stage build is byte-identical to
    Q1N1_HOSTLINK_BASE_DIR's own (the sa3eedo12-sp11-host-link branch tip, not the A16 pinned
    commit -- B2/B3's own gate is the baseline this patch builds on, not the far earlier upstream
    pin); make -n command lines are unchanged; SP11=1 without either required table is refused
    (SP11_USB_TABLE_C, inherited from B2/B3, and the new SP11_STAGE_TABLE_C); and the full SP11=1
    wiring compiles and links with both fixture tables (a link check, never run).
    The stage S0 stick-log survey (Q1N1_SP11_STK_SURVEY, docs/SP11-STK-SURVEY.md) is covered the same
    way: its gate at 0 changes nothing in main.c's preprocessed text, with or without SP11; at 1
    without SP11 it is an #error in main.c and in every survey file, and the Makefile refuses
    STK_SURVEY=1 without SP11=1; every survey file compiles to an object with no symbols with the gate
    off; the default build's and the plain SP11=1 build's make -n lines are unchanged; with
    Q1N1_SP11_BASE_DIR (below) the plain SP11=1 q1n1.efi, stages and preprocessed main.c are
    byte-identical to the tree before the survey; and the survey build makes its own q1n1-stk.efi
    (the only image with the survey's text in it) and leaves every other artefact byte-identical.

Q1N1_HOSTLINK_BASE_DIR: a pristine q1n1 checkout at the sa3eedo12-sp11-host-link branch tip (SKIP
every comparison test without it). Q1N1_SP11_BASE_DIR: a pristine q1n1 checkout of the commit the
survey was applied on top of (`git archive` of it is enough; SKIP the SP11 comparisons without it).
SLBOUNCE_SP11_DIR: the paired Snapintosh SP11 fork of slbounce (SKIP SharedHeader without it).
Nothing is written outside build/ and, for the comparison builds, the base trees' own out*/
directories. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model/link-check only)."""
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
SP11_BASE = os.environ.get('Q1N1_SP11_BASE_DIR')
SLBOUNCE_SP11_DIR = os.environ.get('SLBOUNCE_SP11_DIR')
MAKE_ARGS = ['-f', 'platform/uefi/Makefile']
SP11_FIXTURES = ['SP11=1', 'SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c',
                 'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c']
SP11_ARTEFACTS = ('q1n1.efi', 'q1n1-stage.bin', 'q1n1-stage-alt.bin', 'q1n1-stage-qemu.bin', 'q1n1-stage-qemu-alt.bin')
STK_SOURCES = sorted((ROOT / 'platform/uefi').glob('sp11-stk-*.c'))


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

    def test_find_framebuffer_uses_the_tested_parser_and_a_full_size_buffer(self):
        """The host tests cover q1n1_sp11_gop_map_parse, not the call site: a copy of the parsing
        written back into main.c, or the buffer shrunk back below what this unit's firmware demands
        (the next test), would pass them all. Hardware attempt 3 (2026-11-12) is the reason this is
        pinned."""
        main_c = (ROOT / 'platform/uefi/main.c').read_text(encoding='utf-8')
        self.assertIn('q1n1_sp11_gop_map_parse(map_buf, map_size, map_stride, map_entries,', main_c)
        self.assertIn('#define SP11_GOP_MAP_BUF_BYTES (128u * 1024u)', main_c)
        self.assertIn('#define SP11_GOP_MAX_MAP_ENTRIES (SP11_GOP_MAP_BUF_BYTES / 40u)', main_c)
        self.assertIn('static uint8_t map_buf[SP11_GOP_MAP_BUF_BYTES] __attribute__((aligned(16)));', main_c)
        # The old in-line decoder (silently capped at 512) must not come back.
        self.assertNotIn('if (entries > SP11_GOP_MAX_MAP_ENTRIES) entries = SP11_GOP_MAX_MAP_ENTRIES;', main_c)

    def test_the_gop_map_buffer_keeps_headroom_over_the_firmwares_demand(self):
        """OBSERVED on the unit (2026-11-13, attempt 6): given a 24,576-byte buffer, GetMemoryMap returns
        EFI_BUFFER_TOO_SMALL and asks for 33,504 bytes (698 descriptors), although the map it returns to
        a larger buffer is 10,848 to 11,136 bytes (226 to 232 descriptors). The firmware checks the
        buffer against that larger figure, not against the map it would return. That is why commit
        bdff824's 512 x 48-byte buffer made the GOP selection refuse (attempt 3) while the unit's map
        itself fit. The buffer must stay at least twice the demand; the figure varies with what has
        been allocated, and slbounce adds entries before q1n1 runs."""
        main_c = (ROOT / 'platform/uefi/main.c').read_text(encoding='utf-8')
        found = re.search(r'#define SP11_GOP_MAP_BUF_BYTES \((\d+)u \* (\d+)u\)', main_c)
        self.assertIsNotNone(found, 'SP11_GOP_MAP_BUF_BYTES is no longer a literal product of two numbers')
        self.assertGreaterEqual(int(found.group(1)) * int(found.group(2)), 2 * 33504)

    def test_the_diagnostic_declares_its_ranges_and_never_the_framebuffer(self):
        """Three defects hardware attempt 3's follow-up work found: --el2 declared nothing (it read
        a global only --boot sets), the framebuffer is RESERVED memory the scoped sweep refuses, and
        the declaration was conditional on a mode the diagnostic never has."""
        main_c = (ROOT / 'platform/uefi/main.c').read_text(encoding='utf-8')
        start = main_c.index('static void sp11_declare_ranges')
        declare = main_c[start:main_c.index('static void sp11_report_ebs', start)]
        self.assertIn('struct efi_runtime_services *runtime = st->runtime_services;', declare)
        self.assertNotIn('rt->', declare)
        self.assertIn('struct sp11_ebs_range ranges[6]', declare)
        self.assertNotIn('info.fb_base', declare)
        self.assertIn('    sp11_declare_ranges(st, map, MAP_BYTES);', main_c)
        self.assertNotIn('if (mode != MODE_FOOTHOLD) sp11_declare_ranges', main_c)
        self.assertIn('info.image_base = (uintptr_t)image->image_base;', main_c)


class El2StateReport(unittest.TestCase):
    """The post-ExitBootServices page reads EL2 registers. Those reads are the one thing on it that can
    take the exception path or wedge the core, so what they are, where they run and how they are
    spelled is pinned here."""

    @classmethod
    def setUpClass(cls):
        cls.main_c = (ROOT / 'platform/uefi/main.c').read_text(encoding='utf-8')
        start = cls.main_c.index('static void sp11_report_el2_state(void)')
        cls.body = cls.main_c[start:cls.main_c.index('static void sp11_draw_uptime', start)]

    def test_the_call_is_guarded_by_the_current_el(self):
        # At EL1 an EL2 register read is UNDEFINED; the page must say so instead of reading.
        self.assertIn('if (el == 2) sp11_report_el2_state();', self.main_c)
        self.assertIn('EL2 STATE NOT READ (NOT AT EL2)', self.main_c)

    def test_the_suspect_timer_offset_registers_are_never_read(self):
        # T03 touched CNTVOFF_EL2 and CNTPOFF_EL2 when the X2 image stalled and the board reset;
        # Linux treats CNTVOFF_EL2 as broken on Oryon X1. Nothing on the page may wedge the core.
        for banned in ('cntvoff', 'cntpoff', 's3_4_c14_c0_3', 's3_4_c14_c0_6'):
            self.assertNotIn(banned, self.body.lower())

    def test_ttbr1_is_read_only_with_e2h_set(self):
        self.assertIn('if ((hcr >> 34) & 1) field("TTBR1_EL2 ", SP11_SYSREG(S3_4_C2_C0_1));', self.body)

    @unittest.skipUnless(have('clang') and have('llvm-objcopy'), 'clang or llvm-objcopy not installed')
    def test_the_raw_ttbr1_encoding_is_the_named_register(self):
        # The name is accepted only with FEAT_VHE in the target, so the page spells it by encoding;
        # QEMU cannot exercise the E2H branch, so the spelling is checked against the named form here.
        BUILD.mkdir(parents=True, exist_ok=True)
        code = {}
        for label, text, flags in (('named', 'mrs x0, ttbr1_el2', ['-march=armv8.1-a']),
                                   ('raw', 'mrs x0, S3_4_C2_C0_1', [])):
            source, obj, binary = (BUILD / f'ttbr1-{label}.{ext}' for ext in ('s', 'o', 'bin'))
            source.write_text(f'.text\n{text}\n', encoding='utf-8')
            done = run(['clang', '--target=aarch64-none-elf'] + flags + ['-c', str(source), '-o', str(obj)])
            self.assertEqual(done.returncode, 0, done.stderr)
            done = run(['llvm-objcopy', '-O', 'binary', '--only-section=.text', str(obj), str(binary)])
            self.assertEqual(done.returncode, 0, done.stderr)
            code[label] = binary.read_bytes()
        self.assertEqual(len(code['raw']), 4)
        self.assertEqual(code['raw'], code['named'])


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

    def test_truncating_an_oversized_map_instead_of_refusing_it_is_caught(self):
        src = (ROOT / 'platform/uefi/sp11-fbgop.c').read_text(encoding='utf-8')
        needle = 'if (entries > capacity) return Q1N1_SP11_MAP_TOO_MANY;'
        self.assertIn(needle, src, 'mutation target not found (source changed?)')
        # The exact defect hardware attempt 3 exposed: a copy cut short silently loses the
        # descriptors at the end of the array, the framebuffer's among them.
        mutated = src.replace(needle, 'if (entries > capacity) entries = capacity;', 1)
        done = self._build_and_run(BUILD / 'mutant-map-truncate', 'sp11-fbgop.c', mutated, 'gop')
        self.assertNotEqual(done.returncode, 0, 'mutation did not break anything: a long map was silently truncated')

    def test_reading_the_page_count_from_the_wrong_offset_is_caught(self):
        src = (ROOT / 'platform/uefi/sp11-fbgop.c').read_text(encoding='utf-8')
        needle = 'out[n].pages = le64(e + 24);'
        self.assertIn(needle, src, 'mutation target not found (source changed?)')
        mutated = src.replace(needle, 'out[n].pages = le64(e + 32);', 1)  # the attribute field
        done = self._build_and_run(BUILD / 'mutant-map-pages', 'sp11-fbgop.c', mutated, 'gop')
        self.assertNotEqual(done.returncode, 0, 'mutation did not break anything: pages read from the wrong field')

    def test_reading_the_attribute_from_the_wrong_offset_is_caught(self):
        src = (ROOT / 'platform/uefi/sp11-fbgop.c').read_text(encoding='utf-8')
        needle = 'out[n].attribute = le64(e + 32);'
        self.assertIn(needle, src, 'mutation target not found (source changed?)')
        mutated = src.replace(needle, 'out[n].attribute = le64(e + 24);', 1)  # the page count
        done = self._build_and_run(BUILD / 'mutant-map-attribute', 'sp11-fbgop.c', mutated, 'gop')
        self.assertNotEqual(done.returncode, 0, 'mutation did not break anything: attribute read from the wrong field')

    def test_calling_a_range_contained_without_exactly_one_descriptor_is_caught(self):
        src = (ROOT / 'platform/uefi/sp11-fbgop.c').read_text(encoding='utf-8')
        needle = 'out->contained = out->overlapping == 1 && first_holds_all;'
        self.assertIn(needle, src, 'mutation target not found (source changed?)')
        mutated = src.replace(needle, 'out->contained = first_holds_all;', 1)
        done = self._build_and_run(BUILD / 'mutant-range-contained', 'sp11-fbgop.c', mutated, 'gop')
        self.assertNotEqual(done.returncode, 0, 'mutation did not break anything: an overlapped range was "contained"')

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

    def _clean_build(self, tree, extra_args=(), out='out', deterministic=False, extra_flags=''):
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
            if extra_flags:
                # A CFLAGS given on the command line replaces the Makefile's own, including what its
                # SP11 block appends, so an SP11 build has to say its defines here.
                flags += ' ' + extra_flags
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

    # ---- Stage S0 stick-log survey: Q1N1_SP11_STK_SURVEY (default 0, needs SP11, own image) -----------

    SP11_DEFINES = ['-DSNAP_PLATFORM_SP11=1', '-DSP11_BUILD_STAMP="PROOF"']
    # The same defines for a make command line: a CFLAGS given there replaces the Makefile's own.
    SP11_MAKE_FLAGS = '-DSNAP_PLATFORM_SP11=1 -DSP11_BUILD_STAMP=\\"PROOF\\"'
    _built = {}

    def _sp11_build(self, tree, label, extra_args=()):
        key = (str(tree), label)
        if key not in self._built:
            self._built[key] = self._clean_build(tree, SP11_FIXTURES + list(extra_args), out=f'build/out-{label}',
                                                 deterministic=True, extra_flags=self.SP11_MAKE_FLAGS)
        return self._built[key]

    def test_the_survey_gate_at_zero_changes_nothing_in_main_c(self):
        self.assertEqual(self.preprocess_main(ROOT), self.preprocess_main(ROOT, '-DQ1N1_SP11_STK_SURVEY=0'))
        self.assertEqual(self.preprocess_main(ROOT, *self.SP11_DEFINES),
                         self.preprocess_main(ROOT, *self.SP11_DEFINES, '-DQ1N1_SP11_STK_SURVEY=0'))

    def test_the_survey_gate_changes_main_c_when_set(self):
        self.assertNotEqual(self.preprocess_main(ROOT, *self.SP11_DEFINES),
                            self.preprocess_main(ROOT, *self.SP11_DEFINES, '-DQ1N1_SP11_STK_SURVEY=1'))

    def test_the_survey_gate_without_sp11_is_an_error_in_every_survey_file(self):
        names = ['platform/uefi/main.c'] + [str(p.relative_to(ROOT)) for p in STK_SOURCES]
        self.assertGreaterEqual(len(names), 7)
        for name in names:
            for defines in (['-DQ1N1_SP11_STK_SURVEY=1'], ['-DSNAP_PLATFORM_SP11=0', '-DQ1N1_SP11_STK_SURVEY=1']):
                with self.subTest(file=name, defines=defines):
                    done = run(['clang', '-E', '-P', '-Iplatform/uefi'] + defines + [name])
                    self.assertNotEqual(done.returncode, 0, 'the gate without SP11 was accepted')
                    self.assertIn('needs SNAP_PLATFORM_SP11=1', done.stderr)

    @unittest.skipUnless(have('llvm-nm'), 'llvm-nm not installed')
    def test_every_survey_file_compiles_to_nothing_with_the_gate_off(self):
        flags = ['--target=aarch64-pc-windows-msvc', '-O2', '-ffreestanding', '-fno-builtin', '-fshort-wchar',
                 '-mgeneral-regs-only', '-Wall', '-Wextra', '-Werror', '-Iplatform/uefi']
        self.assertGreaterEqual(len(STK_SOURCES), 6)
        for source in STK_SOURCES:
            for defines in ([], ['-DSNAP_PLATFORM_SP11=1'], ['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_STK_SURVEY=0']):
                with self.subTest(file=source.name, defines=defines):
                    obj = BUILD / f'{source.stem}.gate-off.obj'
                    done = run(['clang'] + flags + defines + ['-c', str(source), '-o', str(obj)])
                    self.assertEqual(done.returncode, 0, done.stderr)
                    symbols = run(['llvm-nm', str(obj)])
                    # Every COFF object carries the @feat.00 marker; anything else is code or data.
                    left = [line for line in symbols.stdout.splitlines() if line.strip() and '@feat.00' not in line]
                    self.assertEqual(left, [], 'the object is not empty with the gate off')

    def test_the_makefile_refuses_the_survey_without_sp11(self):
        done = run(['make', '-n'] + MAKE_ARGS + ['OUT=build/dryrun', 'STK_SURVEY=1', 'all'])
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('STK_SURVEY=1 needs SP11=1', done.stdout + done.stderr)
        done = run(['make', '-n'] + MAKE_ARGS + ['OUT=build/dryrun', 'STK_SURVEY=1', 'stk-survey'])
        self.assertNotEqual(done.returncode, 0)

    def test_an_explicit_survey_off_leaves_the_make_command_lines_alone(self):
        for extra in ([], SP11_FIXTURES + ['SP11_BUILD_STAMP=PROOF']):
            plain = run(['make', '-n'] + MAKE_ARGS + ['OUT=build/dryrun'] + extra + ['all'])
            explicit = run(['make', '-n'] + MAKE_ARGS + ['OUT=build/dryrun'] + extra + ['STK_SURVEY=0', 'all'])
            self.assertEqual(plain.returncode, 0, plain.stderr)
            self.assertEqual(plain.stdout, explicit.stdout)
            self.assertNotIn('stk', plain.stdout.lower())

    def test_the_makefile_builds_every_survey_source(self):
        makefile = (ROOT / 'platform/uefi/Makefile').read_text(encoding='utf-8')
        block = makefile[makefile.index('STK_OBJS :='):makefile.index('STK_HEADERS :=')]
        listed = set(re.findall(r'sp11-stk-([a-z0-9]+)\.obj', block))
        present = {p.stem[len('sp11-stk-'):] for p in STK_SOURCES}
        self.assertEqual(listed, present)

    @unittest.skipUnless(SP11_BASE, 'Q1N1_SP11_BASE_DIR not set: no pre-survey SP11 tree to compare against')
    def test_plain_sp11_main_c_preprocesses_identically_to_the_pre_survey_tree(self):
        for defines in ([], self.SP11_DEFINES):
            self.assertEqual(self.preprocess_main(ROOT, *defines), self.preprocess_main(Path(SP11_BASE), *defines))

    @unittest.skipUnless(SP11_BASE, 'Q1N1_SP11_BASE_DIR not set: no pre-survey SP11 tree to compare against')
    def test_plain_sp11_make_command_lines_are_unchanged(self):
        lines = {}
        for label, tree in (('mine', ROOT), ('base', Path(SP11_BASE))):
            done = run(['make', '-n'] + MAKE_ARGS + ['OUT=build/dryrun'] + SP11_FIXTURES +
                       ['SP11_BUILD_STAMP=PROOF', 'all'], cwd=tree)
            self.assertEqual(done.returncode, 0, done.stderr)
            lines[label] = [' '.join(line.split()) for line in done.stdout.splitlines()]
        self.assertGreater(len(lines['mine']), 20)
        self.assertEqual(lines['mine'], lines['base'])

    @unittest.skipUnless(SP11_BASE, 'Q1N1_SP11_BASE_DIR not set: no pre-survey SP11 tree to compare against')
    @unittest.skipUnless(have('lld-link') and have('ld.lld'), 'lld-link or ld.lld not installed')
    def test_plain_sp11_build_is_byte_identical_to_the_pre_survey_tree(self):
        mine = self._sp11_build(ROOT, 'sp11-plain')
        base = self._sp11_build(Path(SP11_BASE), 'sp11-base')
        for artefact in SP11_ARTEFACTS + ('sp11-fbgop.obj', 'sp11-stage-table.obj'):
            self.assertEqual((mine / artefact).read_bytes(), (base / artefact).read_bytes(), f'{artefact} differs')
        self.assertFalse((mine / 'q1n1-stk.efi').exists())

    @unittest.skipUnless(have('lld-link') and have('ld.lld'), 'lld-link or ld.lld not installed')
    def test_the_survey_build_makes_its_own_image_and_changes_nothing_else(self):
        plain = self._sp11_build(ROOT, 'sp11-plain')
        survey = self._sp11_build(ROOT, 'sp11-stk', ['STK_SURVEY=1'])
        for artefact in SP11_ARTEFACTS + ('sp11-fbgop.obj', 'sp11-stage-table.obj', 'sp11-usb-ports.obj'):
            self.assertEqual((plain / artefact).read_bytes(), (survey / artefact).read_bytes(),
                             f'{artefact} changed when the survey was built')
        image = (survey / 'q1n1-stk.efi').read_bytes()
        normal = (plain / 'q1n1.efi').read_bytes()
        self.assertNotEqual(image, normal)
        # Only the survey image has the survey's text in it.
        for text in (b'STK P3 VERDICT', b'STK NEXT', b'STK P2 BUILD', b'STK P3 SMMU'):
            self.assertIn(text, image)
            self.assertNotIn(text, normal)
            self.assertNotIn(text, (survey / 'q1n1.efi').read_bytes())
        self.assertFalse((plain / 'q1n1-stk.efi').exists())
        # The survey objects exist only in the survey build.
        for name in ('main-stk.obj', 'sp11-stk-text.obj', 'sp11-stk-el2.obj', 'sp11-stk-p2.obj'):
            self.assertTrue((survey / name).is_file(), name)
            self.assertFalse((plain / name).exists(), name)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
