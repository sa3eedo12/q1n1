#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The payload `tsnap` behind the runner, under QEMU's EDK2 shell (docs/SP11-PAYLOAD-TSNAP.md).

    python3 tools/test-q1n1-sp11-payload-qemu-tsnap.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), lays two sticks out as the stick is laid out (`tsnap` alone and `state tsnap`) and
boots QEMU's EDK2 shell on each, with a real ExitBootServices and a real EL2 (the stick layout, the boot driver and the helpers are those of test-q1n1-sp11-payload-qemu.py).

QEMU has none of the eight windows the payload reads: they lie in the `virt` machine's platform-bus region, where nothing is mapped. Every first load of a block, its
HW_VER, therefore answers with a fault, zeros or all ones, and the payload gates the block on any of the three (GATED, nothing else of that block is read). OBSERVED, QEMU 11.1.3
(`virt,virtualization=on`, `-cpu max`, `-smp 1`, TCG, EDK2 AArch64 stable202408): every load faults, so the page shows `VER=FAULT:6 GATED` four times, and the test holds it to the
host model's page for a machine in which every window aborts (`--page dead` of the host test), the counter frequency aside. So this test shows the part of the page that does not
depend on a window: the binary runs at EL2 behind the runner, uses only the ops, announces each block before its load, reports a faulted load as FAULT:6, gates every block, skips the
second reading because no block is readable (`S2 SKIPPED NO_BLOCK`: the wait on the counter and the second reading are therefore NOT exercised here, only by the host test's
model) and has no conversion pass (every block is gated, so none is left to read), prints at most 34 lines in the page font and ends with the line whose counters the runner's DONE line
agrees with. It shows nothing about the unit's windows (UNKNOWN, hardware NOT RUN) and nothing about a block that answers.

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image.
Evidence: EXPERIMENTAL (QEMU only); hardware NOT RUN. Writes only under build/sp11-payload-qemu-tsnap/ and, for the host model it compares the page with, build/sp11-payload-tsnap/."""
import concurrent.futures
import importlib.util
from pathlib import Path
import re
import shutil
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


qemu = load_module('sp11_payload_qemu_base_for_tsnap', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
host = load_module('sp11_payload_tsnap_host_for_qemu', ROOT / 'tools' / 'test-q1n1-sp11-payload-tsnap.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-tsnap'
sha, script, manifest, Boot = qemu.sha, qemu.script, qemu.manifest, qemu.Boot
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'
PREFIX = 'PAYLOAD TSNAP '
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-TSNAP.md'
# What a window that is not there can answer, and the token the page shows for it.
ABSENT = {'FAULT:6': 'a faulted load', '0X0': 'zeros', '0XFFFFFFFF': 'all ones'}


def normal(lines):
    """`lines` (without the prefix) as the document shows them: the counter frequency, which is QEMU's and not the model's, as a placeholder."""
    return [re.sub(r'HZ=0X[0-9A-F]+', 'HZ=<HZ>', line) for line in lines]


def chain_stick(entries):
    """The files of a stick: `entries` is [(file name, bytes)] in manifest order."""
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


class TsnapQemu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'lld-link', 'ld.lld', 'make', 'qemu-system-aarch64'):
            if not lib.have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        cls.firmware = qemu.helpers.find_firmware()
        if not cls.firmware:
            raise unittest.SkipTest('no EDK2 aarch64 firmware (set Q1N1_EDK2_CODE)')
        qemu.BUILD = BUILD
        shutil.rmtree(BUILD, ignore_errors=True)
        BUILD.mkdir(parents=True)
        out = BUILD / 'out'
        built = subprocess.run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j1', 'PAYLOAD=1']
                               + qemu.SP11_VARS + ['payload-runner', 'payloads'], cwd=ROOT, env=lib.ENV, capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError('PAYLOAD=1 build failed:\n' + built.stdout[-2000:] + built.stderr[-2000:])
        cls.runner = out / 'q1n1-payload.efi'
        cls.bins = {name: (out / 'payloads' / f'{name}.bin').read_bytes() for name in ('state', 'tsnap')}
        # The host test's page for a machine in which every window aborts: what the runner must show here, but for the counter frequency.
        model = host.build_harness('qemu-model', sanitize=False)
        cls.model = [line[len(PREFIX):] for line in lib.run([str(model), '--page', 'dead']).stdout.splitlines()]
        boots = [
            Boot('alone', chain_stick([('TSNAP.BIN', cls.bins['tsnap'])]), script(), marker='PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK '),
            Boot('after-state', chain_stick([('STATE.BIN', cls.bins['state']), ('TSNAP.BIN', cls.bins['tsnap'])]), script(),
                 marker='PAYLOAD DONE INDEX=1 RETURN=0X0 STACK=OK '),
        ]
        # One emulator at a time: two boots in parallel doubled the memory this test needs for no gain.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            cls.runs = {boot.name: boot for boot in pool.map(lambda boot: qemu.run_boot(boot, cls.runner, cls.firmware), boots)}

    def after(self, name):
        text = self.runs[name].text
        self.assertIn(AFTER, text, f'{name}: the bounce was never confirmed; inspect {BUILD / (name + ".log")}')
        return text.split(AFTER, 1)[1]

    def lines(self, name, prefixes=('PAYLOAD ',)):
        return [line for line in self.after(name).split('\n') if line.startswith(prefixes)]

    def printed(self, name):
        return [line[len(PREFIX):] for line in self.lines(name) if line.startswith(PREFIX)]

    def done(self, name, index):
        found = [line for line in self.lines(name) if line.startswith(f'PAYLOAD DONE INDEX={index} ')]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def answers(self, name):
        """[the token each block's first load answered], from the page: a block that answers anything else is a window QEMU has, which this test does not model."""
        found = []
        for n in range(4):
            lines = [line for line in self.printed(name) if line.startswith(f'T{n} VER=')]
            self.assertEqual(len(lines), 1, (n, lines))
            token = re.fullmatch(rf'T{n} VER=(\S+) GATED', lines[0])
            self.assertIsNotNone(token, f'T{n} is not gated: QEMU has a window the test does not model: {lines[0]}')
            self.assertIn(token.group(1), ABSENT, lines[0])
            found.append(token.group(1))
        return found

    def test_it_runs_to_the_end_behind_the_runner_alone_and_after_state(self):
        for name, index in (('alone', 0), ('after-state', 1)):
            with self.subTest(boot=name):
                faults = self.answers(name).count('FAULT:6')
                self.assertRegex(self.done(name, index), rf'^PAYLOAD DONE INDEX=\d RETURN=0X0 STACK=OK LOADS=4 FAULTS={faults} REFUSED=0 LINES=\d+ DROPPED=0$')
                self.assertNotIn('SYNCHRONOUS EXCEPTION', self.runs[name].text)
        self.assertEqual(normal(self.printed('alone')), normal(self.printed('after-state')))

    def test_the_page_has_its_structure_under_qemu(self):
        page = self.printed('alone')
        self.assertRegex(page[0], r'^READ ONLY EL=2 HZ=0X[0-9A-F]+ GAP=2 S$')
        self.assertTrue(page[1].startswith('KEY T0..T3=BLOCK '), page[1])
        nexts = [line for line in page if line.startswith('NEXT ')]
        self.assertEqual(nexts, ['NEXT T0', 'NEXT T1', 'NEXT T2', 'NEXT T3'], 'no wait and no conversion pass is announced when no block can be read again')
        order = [page.index(line) for line in nexts]
        self.assertEqual(order, sorted(order))
        for n in range(4):
            self.assertEqual(page[page.index(f'NEXT T{n}') + 1][:3], f'T{n} ', 'a block is printed right after its NEXT line')
        self.assertIn('S2 SKIPPED NO_BLOCK', page)
        self.assertFalse([line for line in page if line.startswith(('S2 T', 'NEXT S2', 'CONV ', 'NEXT CONV'))])
        self.assertTrue(any(line.startswith('SUM1 V=0/64 ') for line in page), page)
        self.assertTrue(any(line.startswith('SUM2 V=0/64 ') for line in page), page)
        faults = self.answers('alone').count('FAULT:6')
        found = re.fullmatch(rf'END LOADS=4 FAULTS={faults} SKIPS=0 GATED=4 CUTS=0 GAP_MS=0 LINES=(\d+)', page[-1])
        self.assertIsNotNone(found, page[-1])
        self.assertEqual(int(found.group(1)), len(page))
        self.assertLessEqual(len(page), 34)

    def test_the_page_is_the_models_page_for_a_machine_without_the_windows(self):
        self.assertGreater(len(self.model), 10)
        for name in self.runs:
            with self.subTest(boot=name):
                self.assertEqual(normal(self.printed(name)), normal(self.model))

    def test_the_counters_of_the_runner_agree_with_the_payload(self):
        line = self.done('alone', 0)
        self.assertIn(f'LOADS=4 FAULTS={self.answers("alone").count("FAULT:6")} ', line)
        self.assertIn(f'LINES={len(self.printed("alone"))} ', line)

    def test_it_prints_nothing_outside_the_page_font(self):
        for name in self.runs:
            for line in self.lines(name):
                self.assertIsNotNone(qemu.FONT_LINE.fullmatch(line), line)
                self.assertLessEqual(len(line), 100)

    def test_the_document_gives_the_lines_qemu_showed(self):
        doc = DOC.read_text(encoding='utf-8')
        block = re.search(r'<!-- qemu-lines -->\n```\n(.*?)```\n<!-- /qemu-lines -->', doc, re.S)
        self.assertIsNotNone(block, 'docs/SP11-PAYLOAD-TSNAP.md has no <!-- qemu-lines --> block')
        shown = block.group(1).splitlines()
        page = [PREFIX + line for line in normal(self.printed('alone'))]
        self.assertEqual(shown, page)

    def test_no_boot_changes_a_file_of_the_stick(self):
        for name, boot in self.runs.items():
            self.assertFalse(boot.changed, f'{name}: a file on the stick changed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
