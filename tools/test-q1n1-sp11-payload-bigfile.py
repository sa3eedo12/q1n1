#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Gate-at-zero proofs, source audits and the document check for the runner's big-file gate (docs/SP11-PAYLOAD-BIGFILE.md).

    python3 tools/test-q1n1-sp11-payload-bigfile.py

The behaviour of the gate is tested where the runner's other behaviour is: the loader and plan programs (tools/test-q1n1-sp11-payload-load.c, -plan.c, with
-load-big.h and -plan-big.h) built with the gate on at two chunk caps, and their seeded bugs (tools/sp11_payload_bigfile_mutants.py), in
tools/test-q1n1-sp11-payload.py; the manifest tool's limits and its faulty inputs in tools/test-q1n1-sp11-payload-build.py; the QEMU/EDK2 boots with a file over 256 MiB
in tools/test-q1n1-sp11-payload-qemu.py. This file holds what none of them can: that with Q1N1_SP11_BIGFILE at 0 (the default) nothing changed, that the gate's constants and
its glue in main.c are what the document says, and the document itself.

  * BigfileGateOff: every runner file preprocesses to the text of the base commit with the gate at 0 (and with it unset), compiles to the same object bytes, the
    Makefile's command lines are the base commit's, the gate without the runner is an error, a bad chunk cap or a 32-bit target does not compile, and with the gate
    on the define is on exactly the runner's compile lines.
  * BigfileSource: the constants of the header, that the loader asks for the top of RAM in one place, that all of main.c's glue is under the gate, that the manifest
    tool and the header agree.
  * BigfileBuild: the runner as an image, built twice with the gate off (the pinned runner) and twice on; only with Q1N1_BIGFILE_BUILDS=1 (each build is a minute of
    compiling and the proof is also run by the build script), SKIPPED otherwise, and said to be.
  * BigfileDoc: the document starts with its licence line, stays within the size limit, names the gate and its numbers as the source has them, carries the evidence
    labels and says what is UNKNOWN; docs/SP11-PAYLOAD.md points to it.

Nothing is written outside build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_manifest as manifest_tool  # noqa: E402

UEFI = ROOT / 'platform' / 'uefi'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-BIGFILE.md'
BUILD = ROOT / 'build' / 'bigfile-test'
BASE_COMMIT = 'e448f9a'
LLVM = ('/opt/homebrew/opt/llvm/bin', '/opt/homebrew/opt/lld/bin', '/opt/homebrew/bin')
ENV = dict(os.environ, PATH=os.pathsep.join(LLVM + (os.environ.get('PATH', ''),)), PYTHONDONTWRITEBYTECODE='1')
FIXTURES = ['SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c', 'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c']
RECIPE = ['SP11=1', 'PAYLOAD=1'] + FIXTURES + ['LD=lld-link /Brepro']
RUNNER_FILES = ['sp11-payload-text.c', 'sp11-payload-plan.c', 'sp11-payload-load.c', 'sp11-payload-run.c']
COMPILE = ['--target=aarch64-pc-windows-msvc', '-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fshort-wchar', '-mgeneral-regs-only',
           '-mno-outline-atomics', '-Wall', '-Wextra', '-Werror', '-Iplatform/uefi', '-mno-incremental-linker-compatible']
GATES = ['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1', '-DSP11_BUILD_STAMP="PROOF"']


def run(cmd, cwd=ROOT, timeout=900, **kw):
    return subprocess.run(cmd, cwd=cwd, env=ENV, capture_output=True, text=True, timeout=timeout, **kw)


def have(tool):
    return shutil.which(tool, path=ENV['PATH']) is not None


def read(path):
    return Path(path).read_text(encoding='utf-8')


def base_tree():
    """The tree at the commit this gate was built on, extracted under build/ (None when git cannot name it)."""
    if run(['git', 'cat-file', '-e', f'{BASE_COMMIT}^{{commit}}']).returncode != 0:
        return None
    target = BUILD / 'base'
    if not (target / 'platform' / 'uefi' / 'main.c').exists():
        shutil.rmtree(target, ignore_errors=True)
        target.mkdir(parents=True)
        archive = subprocess.run(['git', 'archive', BASE_COMMIT], cwd=ROOT, capture_output=True, check=True).stdout
        subprocess.run(['tar', '-x', '-C', str(target)], input=archive, check=True)
    return target


def conditional_stack(text, at):
    """The #if conditions open at offset `at`: an #else of one is the code that runs with it off."""
    stack = []
    for found in re.finditer(r'^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif)\b(.*)$', text[:at], flags=re.M):
        kind, rest = found.group(1), found.group(2).split('/*')[0].strip()
        if kind in ('if', 'ifdef', 'ifndef'):
            stack.append((kind, rest))
        elif kind in ('elif', 'else'):
            stack[-1] = (kind, rest)
        else:
            stack.pop()
    return stack


class BigfileGateOff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def preprocess(self, tree, name, *defines):
        done = run(['clang', '-E', '-P', '-Iplatform/uefi'] + list(defines) + [f'platform/uefi/{name}'], cwd=tree)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def test_the_runners_files_preprocess_as_at_the_base_commit_with_the_gate_off_or_unset(self):
        base = base_tree()
        if base is None:
            self.skipTest(f'git cannot name {BASE_COMMIT}')
        for name in ['main.c'] + RUNNER_FILES:
            for defines in (['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1'], ['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1', '-DQ1N1_SP11_SMMUMAP=1'],
                            ['-DSNAP_PLATFORM_SP11=1'], []):
                with self.subTest(file=name, defines=defines):
                    want = self.preprocess(base, name, *defines)
                    self.assertEqual(self.preprocess(ROOT, name, *defines), want)
                    if 'PAYLOAD' in ' '.join(defines):
                        self.assertEqual(self.preprocess(ROOT, name, *defines, '-DQ1N1_SP11_BIGFILE=0'), want)

    def test_every_runner_file_compiles_to_the_base_commits_object_bytes_with_the_gate_off(self):
        base = base_tree()
        if base is None:
            self.skipTest(f'git cannot name {BASE_COMMIT}')
        for name in ['main.c'] + RUNNER_FILES:
            for extra in ([], ['-DQ1N1_SP11_SMMUMAP=1']):
                with self.subTest(file=name, extra=extra):
                    objects = []
                    for tree, label, more in ((ROOT, 'mine', []), (ROOT, 'mine0', ['-DQ1N1_SP11_BIGFILE=0']), (base, 'base', [])):
                        obj = BUILD / f'{name}.{"smmu." if extra else ""}{label}.obj'
                        done = run(['clang'] + COMPILE + GATES + extra + more + ['-c', f'platform/uefi/{name}', '-o', str(obj)], cwd=tree)
                        self.assertEqual(done.returncode, 0, done.stderr)
                        objects.append(obj.read_bytes())
                    self.assertEqual(objects[0], objects[2], f'{name}: the object differs from the base commit\'s with the gate unset')
                    self.assertEqual(objects[1], objects[2], f'{name}: the object differs from the base commit\'s with the gate at 0')

    def test_the_gate_without_the_runner_is_an_error_in_every_runner_file(self):
        for name in RUNNER_FILES:
            with self.subTest(file=name):
                done = run(['clang', '-E', '-P', '-Iplatform/uefi', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_BIGFILE=1', str(UEFI / name)])
                self.assertNotEqual(done.returncode, 0)
                self.assertIn('needs Q1N1_SP11_PAYLOAD=1', done.stderr)

    def test_a_bad_chunk_cap_a_bad_ceiling_and_a_narrow_size_t_do_not_compile(self):
        flags = ['-fsyntax-only', '-std=gnu11', '-Iplatform/uefi', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1', '-DQ1N1_SP11_BIGFILE=1']
        for cap in ('0u', '32u', '100u', '12288u', '16384u'):
            with self.subTest(cap=cap):
                done = run(['clang'] + flags + [f'-DQ1N1_SP11_BIGFILE_CHUNK_KIB={cap}', str(UEFI / 'sp11-payload-plan.c')])
                self.assertNotEqual(done.returncode, 0)
                self.assertIn('the chunk cap is a power of two from 64 KiB to 8 MiB', done.stderr)
        for cap in ('64u', '256u', '1024u', '4096u', '8192u'):
            with self.subTest(cap=cap):
                done = run(['clang'] + flags + [f'-DQ1N1_SP11_BIGFILE_CHUNK_KIB={cap}', str(UEFI / 'sp11-payload-plan.c')])
                self.assertEqual(done.returncode, 0, done.stderr)
        done = run(['clang', '--target=armv7-none-eabi', '-ffreestanding', '-fsyntax-only', '-std=gnu11', '-Iplatform/uefi', '-DSNAP_PLATFORM_SP11=1',
                    '-DQ1N1_SP11_PAYLOAD=1', '-DQ1N1_SP11_BIGFILE=1', str(UEFI / 'sp11-payload-plan.c')])
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('needs a 64-bit size_t', done.stderr)

    def make_lines(self, tree, *args):
        done = run(['make', '-n', '-f', 'platform/uefi/Makefile', 'OUT=build/dryrun'] + FIXTURES + ['SP11_BUILD_STAMP=PROOF'] + list(args), cwd=tree)
        self.assertEqual(done.returncode, 0, done.stderr)
        return [' '.join(line.split()) for line in done.stdout.replace('\\\n', ' ').splitlines()]

    def newer_payloads(self, base):
        """The payloads this tree has and the base commit lacks: `all` builds them, so their command lines are not the base's to compare."""
        return {path.stem for path in (ROOT / 'payloads').glob('*.c')} - {path.stem for path in (base / 'payloads').glob('*.c')}

    def test_the_makefiles_command_lines_are_the_base_commits_with_the_gate_off(self):
        base = base_tree()
        if base is None:
            self.skipTest(f'git cannot name {BASE_COMMIT}')
        newer = self.newer_payloads(base)
        about_newer = re.compile(r'/(?:%s)(?:[./\s]|$)' % '|'.join(sorted(newer))) if newer else None
        for args in (['SP11=1', 'all'], ['SP11=1', 'PAYLOAD=1', 'payload-runner'], ['SP11=1', 'PAYLOAD=1', 'SMMUMAP=1', 'payload-runner'],
                     ['SP11=1', 'PAYLOAD=1', 'BIGFILE=0', 'payload-runner'], ['SP11=1', 'PAYLOAD=1', 'all']):
            with self.subTest(args=args):
                mine = self.make_lines(ROOT, *args)
                theirs = self.make_lines(base, *[a for a in args if a != 'BIGFILE=0'])
                if about_newer:
                    # `all` also creates the directory once for each newer payload's object, and those lines name no payload.
                    mine = [line for line in mine if not about_newer.search(line) and not line.startswith('mkdir -p ')]
                    theirs = [line for line in theirs if not line.startswith('mkdir -p ')]
                self.assertGreater(len(mine), 10)
                self.assertEqual(mine, theirs)
                self.assertNotIn('bigfile', ' '.join(mine).lower())

    def test_the_makefile_refuses_the_gate_without_the_runner(self):
        done = run(['make', '-n', '-f', 'platform/uefi/Makefile', 'OUT=build/dryrun'] + FIXTURES + ['SP11=1', 'BIGFILE=1', 'all'])
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('BIGFILE=1 needs PAYLOAD=1', done.stdout + done.stderr)

    def test_with_the_gate_on_its_defines_are_on_exactly_the_runners_compile_lines(self):
        for extra, objects in (([], {'main-payload.obj', 'sp11-payload-text.obj', 'sp11-payload-plan.obj', 'sp11-payload-load.obj', 'sp11-payload-run.obj',
                                     'sp11-payload-call.obj'}),
                               (['SMMUMAP=1'], {'main-payload.obj', 'sp11-payload-text.obj', 'sp11-payload-plan.obj', 'sp11-payload-load.obj',
                                                'sp11-payload-run.obj', 'sp11-payload-call.obj', 'sp11-smmumap.obj', 'sp11-smmumap-el2.obj'})):
            for kib in (None, '64'):
                with self.subTest(extra=extra, kib=kib):
                    lines = self.make_lines(ROOT, 'SP11=1', 'PAYLOAD=1', 'BIGFILE=1', *([f'BIGFILE_CHUNK_KIB={kib}'] if kib else []), *extra, 'payload-runner')
                    compiles = [line for line in lines if ' -c ' in line]
                    want = f'-DQ1N1_SP11_BIGFILE_CHUNK_KIB={kib or 8192}u'
                    with_define = {Path(re.search(r'-o (\S+)$', line).group(1)).name for line in compiles
                                   if '-DQ1N1_SP11_BIGFILE=1' in line and want in line}
                    self.assertEqual(with_define, objects)
                    self.assertTrue(all('BIGFILE' not in line for line in lines if line not in compiles or Path(re.search(r'-o (\S+)$', line).group(1)).name not in objects))


class BigfileSource(unittest.TestCase):
    def test_the_header_holds_the_documented_defaults_and_the_gate_off_limit_is_the_old_one(self):
        header = read(UEFI / 'sp11-payload.h')
        for text in ('#define Q1N1_SP11_BIGFILE_CHUNK_KIB 8192u', '#define Q1N1_SP11_BIGFILE_TOP UINT64_C(0xFFFFFFFFF)',
                     '#define Q1N1_PAYLOAD_CHUNK_BYTES ((uint32_t)Q1N1_SP11_BIGFILE_CHUNK_KIB << 10)',
                     '#define Q1N1_PAYLOAD_MAX_FILE_BYTES ((uint64_t)Q1N1_PAYLOAD_SWEEP_MAX_OPS * Q1N1_PAYLOAD_CHUNK_BYTES)',
                     '#define Q1N1_PAYLOAD_FILE_CEILING (UINT64_C(2) << 30)', '#define Q1N1_PAYLOAD_ALLOCATE_MAX_ADDRESS 1u',
                     '#define Q1N1_PAYLOAD_PROGRESS_BYTES (UINT64_C(64) << 20)', '#define Q1N1_PAYLOAD_SWEEP_MAX_OPS 256u',
                     '#define Q1N1_PAYLOAD_ALLOCATE_ANY_PAGES 0u'):
            self.assertEqual(header.count(text), 1, text)
        old = '#define Q1N1_PAYLOAD_MAX_FILE_BYTES ((uint64_t)Q1N1_PAYLOAD_SWEEP_MAX_OPS << 20)'
        at = header.index(old)
        opened, other = header.rindex('#if Q1N1_SP11_BIGFILE', 0, at), header.rindex('#else', 0, at)
        self.assertLess(opened, other, 'the old limit is the gate-off branch')
        self.assertNotIn('#endif', header[other:at])
        enum = header[header.index('Q1N1_PAYLOAD_E_DECLARE,'):]
        self.assertTrue(enum.index('Q1N1_PAYLOAD_E_FILE_NO_MEMORY') < enum.index('};'))
        self.assertEqual(conditional_stack(header, header.index('Q1N1_PAYLOAD_E_FILE_NO_MEMORY,'))[-1], ('if', 'Q1N1_SP11_BIGFILE'))

    def test_the_manifest_tool_and_the_header_agree_on_the_cap_and_the_limits(self):
        header = read(UEFI / 'sp11-payload.h')
        self.assertEqual(int(re.search(r'#define Q1N1_SP11_BIGFILE_CHUNK_KIB (\d+)u', header).group(1)), manifest_tool.CHUNK_KIB_MAX)
        self.assertEqual(int(re.search(r'Q1N1_SP11_BIGFILE_CHUNK_KIB >= (\d+)u', header).group(1)), manifest_tool.CHUNK_KIB_MIN)
        self.assertEqual(manifest_tool.SWEEP_MAX_OPS, int(re.search(r'#define Q1N1_PAYLOAD_SWEEP_MAX_OPS (\d+)u', header).group(1)))
        self.assertEqual(manifest_tool.FILE_CEILING, 2 << 30)
        self.assertEqual(manifest_tool.file_limit(manifest_tool.CHUNK_KIB_MAX), manifest_tool.FILE_CEILING)
        self.assertEqual(manifest_tool.file_limit(), manifest_tool.MAX_FILE_BYTES)

    def test_the_loader_asks_for_the_top_of_ram_in_one_place_and_only_for_data(self):
        load = read(UEFI / 'sp11-payload-load.c')
        self.assertEqual(load.count('bs->allocate_pages('), 2, 'the loader has two allocation sites: allocate() and allocate_top()')
        self.assertEqual(load.count('Q1N1_PAYLOAD_ALLOCATE_MAX_ADDRESS'), 1)
        self.assertEqual(load.count('allocate_top('), 2, 'its definition and the one use, in the data branch of load_file')
        self.assertIn('entry->memory_type == Q1N1_PAYLOAD_TYPE_DATA ? allocate_top(', load)
        self.assertEqual(load.count('q1n1_payload_top_ok('), 2)
        at = load.index('static int allocate_top(')
        self.assertEqual(conditional_stack(load, at)[-1], ('if', 'Q1N1_SP11_BIGFILE'))
        for banned in ('ALLOCATE_ADDRESS', 'allocate_pool', 'connect_controller', 'locate_handle'):
            self.assertNotIn(banned, load[at:load.index('static int load_file(')])

    def test_all_of_the_gates_glue_in_main_c_is_under_the_runners_gate_and_forwards_nothing_else(self):
        main = read(UEFI / 'main.c')
        places = [m.start() for m in re.finditer('Q1N1_SP11_BIGFILE', main)]
        self.assertGreaterEqual(len(places), 4)
        for at in places:
            self.assertIn(('if', 'Q1N1_SP11_PAYLOAD'), conditional_stack(main, at), f'a use of the gate at offset {at} is outside the runner\'s gate')
        for text in ('t.chunk_cap = Q1N1_PAYLOAD_CHUNK_BYTES;', 'q1n1_payload_set_progress(payload_progress);', 'q1n1_payload_line_begin(&unit, "PAYLOAD BIGFILE");',
                     'q1n1_payload_table_max_ops(&sp11_declared)', 'st->boot->set_watchdog(0, 0, 0, NULL);'):
            self.assertEqual(main.count(text), 1, text)
            self.assertEqual(conditional_stack(main, main.index(text))[-1], ('if', 'Q1N1_SP11_BIGFILE'), text)
        prepare = main[main.index('static efi_status sp11_payload_prepare('):main.index('#endif /* Q1N1_SP11_PAYLOAD */')]
        self.assertLess(prepare.index('q1n1_payload_set_progress('), prepare.index('set_watchdog(0, 0, 0, NULL);'))
        self.assertLess(prepare.index('set_watchdog(0, 0, 0, NULL);'), prepare.index('q1n1_payload_prepare('), 'the watchdog is disarmed before the first read')
        self.assertEqual(main.count('t.chunk_cap = 1u << 20;'), 1, 'the gate-off cap is where it was')
        declare = main[main.index('static void sp11_declare_ranges('):]
        self.assertLess(declare.index('t.chunk_cap = 1u << 20;'), declare.index('t.chunk_cap = Q1N1_PAYLOAD_CHUNK_BYTES;'))
        self.assertLess(declare.index('t.chunk_cap = Q1N1_PAYLOAD_CHUNK_BYTES;'), declare.index('q1n1_payload_plan_append('))
        precheck = main[main.index('static efi_status sp11_payload_precheck('):main.index('static efi_status leave_firmware(')]
        self.assertNotIn('allocate_', precheck)

    def test_slbounce_still_checks_the_chunk_cap_only_for_zero(self):
        sweep = os.environ.get('SLBOUNCE_SP11_DIR')
        if not sweep or not (Path(sweep) / 'src' / 'sp11_scoped_sweep.c').is_file():
            self.skipTest('SLBOUNCE_SP11_DIR not set: slbounce\'s side of the cap is not read')
        source = read(Path(sweep) / 'src' / 'sp11_scoped_sweep.c')
        self.assertEqual(len([line for line in source.splitlines() if 'chunk_cap' in line]), 3, 'the cap is read in three lines only')
        self.assertIn('if (chunk_cap == 0) return SP11_SWEEP_ERR_CHUNK_CAP;', source)
        self.assertIn('uint64_t take = remaining < chunk_cap ? remaining : chunk_cap;', source)
        ranges = read(Path(sweep) / 'src' / 'sp11-ebs-ranges.h')
        self.assertEqual(ranges, read(UEFI / 'sp11-ebs-ranges.h'))
        self.assertIn('if (t->chunk_cap == 0) return 0;', ranges)


class BigfileBuild(unittest.TestCase):
    """The runner as an image: built from the base commit and from this tree with the gate off (one byte string), and with the gate on."""
    @classmethod
    def setUpClass(cls):
        if os.environ.get('Q1N1_BIGFILE_BUILDS') != '1':
            raise unittest.SkipTest('Q1N1_BIGFILE_BUILDS=1 not set: the image builds are SKIPPED here (tools/ build script of the proof runs them)')
        if not (have('clang') and have('lld-link')):
            raise unittest.SkipTest('clang or lld-link not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def image(self, tree, out, stamp, *extra):
        shutil.rmtree(tree / out, ignore_errors=True)
        done = run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out}'] + RECIPE[:2] + list(extra) + [f'SP11_BUILD_STAMP={stamp}'] + RECIPE[2:] + ['payload-runner'],
                   cwd=tree)
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-1500:])
        return (tree / out / 'q1n1-payload.efi').read_bytes()

    def test_the_runner_with_the_gate_off_is_the_base_commits_runner_and_with_it_on_builds_to_one_image(self):
        base = base_tree()
        if base is None:
            self.skipTest(f'git cannot name {BASE_COMMIT}')
        pinned = self.image(base, 'build/pinned', 'A9F00F9CCBB5')
        off = self.image(ROOT, 'build/bigfile-test/off', 'A9F00F9CCBB5')
        off_b = self.image(ROOT, 'build/bigfile-test/off-b', 'A9F00F9CCBB5')
        self.assertEqual(off, off_b, 'the runner with the gate at zero is not reproducible')
        self.assertEqual(hashlib.sha256(off).hexdigest(), hashlib.sha256(pinned).hexdigest(), 'the gate at zero changed the runner')
        smm = self.image(ROOT, 'build/bigfile-test/smm', 'A9F00F9CCBB5', 'SMMUMAP=1')
        smm_base = self.image(base, 'build/pinned-smm', 'A9F00F9CCBB5', 'SMMUMAP=1')
        self.assertEqual(smm, smm_base, 'the mapping step\'s runner changed with the big-file gate at zero')
        on_a = self.image(ROOT, 'build/bigfile-test/on-a', 'E448F9A-W4BIG', 'BIGFILE=1')
        on_b = self.image(ROOT, 'build/bigfile-test/on-b', 'E448F9A-W4BIG', 'BIGFILE=1')
        self.assertEqual(on_a, on_b, 'the runner with the gate on is not reproducible')
        self.assertNotEqual(on_a, off)
        for text in (b'PAYLOAD BIGFILE\x00', b'FILE_NO_MEMORY\x00', b'PAYLOAD READ\x00', b'PAYLOAD HASH\x00'):
            self.assertTrue(text in on_a, f'{text!r} is not in the gate-on image')
            self.assertFalse(text in off, f'{text!r} is in the gate-off image')
        doc = read(DOC)
        rows = re.findall(r'\| ([\d,]+) B \| `([0-9a-f]{64})` \|', doc[doc.index('<!-- bigfile-digests -->'):doc.index('<!-- /bigfile-digests -->')])
        self.assertEqual([(int(size.replace(',', '')), digest) for size, digest in rows],
                         [(len(off), hashlib.sha256(off).hexdigest()), (len(on_a), hashlib.sha256(on_a).hexdigest())], 'the digest table is not these images')


class BigfileDoc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not DOC.exists():
            raise unittest.SkipTest('docs/SP11-PAYLOAD-BIGFILE.md does not exist yet')
        cls.text = read(DOC)
        cls.flat = re.sub(r'\s+', ' ', cls.text)

    def test_the_licence_line_the_size_and_the_links(self):
        self.assertTrue(self.text.startswith('<!-- SPDX-License-Identifier: MIT -->\n'))
        self.assertLess(len(self.text.encode('utf-8')), 50 * 1024)
        self.assertLess(len(self.text.splitlines()), 1500)
        for target in re.findall(r'\]\(([^)#\s]+\.md)(?:#[^)]*)?\)', self.text):
            self.assertTrue((ROOT / 'docs' / target).is_file(), f'{target} does not exist')
        for anchor in re.findall(r'\]\(#([^)]+)\)', self.text):
            headings = {re.sub(r'[^a-z0-9 -]', '', h.lower()).strip().replace(' ', '-') for h in re.findall(r'^#+ (.*)$', self.text, re.M)}
            self.assertIn(anchor, headings, f'#{anchor} is not a heading')

    def test_it_names_the_gate_the_defaults_and_the_numbers_as_the_source_has_them(self):
        for text in ('Q1N1_SP11_BIGFILE', 'BIGFILE=1', 'BIGFILE_CHUNK_KIB', 'FILE_NO_MEMORY', 'AllocateMaxAddress', '0xFFFFFFFFF', '8192 KiB', '8 MiB', '2 GiB',
                     '256 chunks', '64 MiB', 'PAYLOAD BIGFILE', 'PAYLOAD READ', 'PAYLOAD HASH', '--chunk-cap-kib', '4 GiB', 'hardware NOT RUN'):
            self.assertIn(text, self.flat, text)
        header = read(UEFI / 'sp11-payload.h')
        self.assertIn(f'{manifest_tool.CHUNK_KIB_MIN} KiB', self.flat)
        self.assertEqual(int(re.search(r'#define Q1N1_SP11_BIGFILE_CHUNK_KIB (\d+)u', header).group(1)), 8192)

    def test_the_evidence_labels_and_the_unknowns_are_there(self):
        for label in ('VERIFIED', 'OBSERVED', 'INFERRED', 'UNKNOWN', 'EXPERIMENTAL'):
            self.assertIn(label, self.text)
        for unknown in ('an 8 mib flush op', 'where this firmware places', 'one descriptor', 'read rate'):
            self.assertIn(unknown, self.flat.lower(), unknown)
        self.assertIn('UNKNOWN', self.text[self.text.index('## What is UNKNOWN'):])

    def test_the_main_document_points_to_it_and_lists_this_suite(self):
        main = read(ROOT / 'docs' / 'SP11-PAYLOAD.md')
        self.assertIn('SP11-PAYLOAD-BIGFILE.md', main)
        self.assertIn('test-q1n1-sp11-payload-bigfile.py', main)

    def test_the_document_is_free_of_machine_identifiers(self):
        for pattern in (r'/Us' + r'ers/', r'/ho' + r'me/', r'/Vol' + r'umes/', r'\bsae' + r'ed\b', r'host' + r'name'):
            self.assertIsNone(re.search(pattern, self.text), pattern)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
