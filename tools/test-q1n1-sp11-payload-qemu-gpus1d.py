#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The dry GPU stage S1 payload `gpus1d` and the runner's write table (WTAB=1) under QEMU's EDK2 shell (docs/SP11-PAYLOAD-WTAB.md).

    python3 tools/test-q1n1-sp11-payload-qemu-gpus1d.py

Builds the runner with WTAB=1 and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), lays a stick out as the stick is laid out and boots QEMU's EDK2 shell on it,
with a real ExitBootServices and a real EL2 (the stick layout, the boot driver and the helpers are those of test-q1n1-sp11-payload-qemu.py).

QEMU has no GCC: its `virt` machine maps flash and RAM where the S1 table's first row reads (0x00171004), so the row's guarded read either faults or finds a word that is not the
GCC AHB branch's. Either way the first row stops the run before anything is stored (`WTAB STOP WHY=FAULT|FOUND ROW=0`), and that is what this test holds: the table is opened by the
real runner at EL2, validated against the real memory map (the dry table writes nothing, so the map check is not exercised), the row's read goes through the real guarded load, the
stop prints before the END line, the payload sees the code, says so and returns 1, no `W` line and no store exist, and the lines are in the page font. It shows NOTHING about the
unit (UNKNOWN, hardware NOT RUN) and nothing about a store: the dry table has none, and a QEMU run of a table that writes would need a device model this test does not have. The `WTAB ATTR`
lines show what the real classification says for those four words under QEMU (not the unit's answer). A second boot carries the draft payload `gpus1` over the draft table: the runner as
the Makefile builds it (WTAB=1, no allowance for a draft) refuses it at open, and the payload says so and returns 3.

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image.
Evidence: EXPERIMENTAL (QEMU only); hardware NOT RUN. Writes only under build/sp11-payload-qemu-gpus1d/."""
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


qemu = load_module('sp11_payload_qemu_base_for_gpus1d', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-gpus1d'
sha, script, manifest, Boot = qemu.sha, qemu.script, qemu.manifest, qemu.Boot
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'


def stick(entries):
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


class Gpus1dQemu(unittest.TestCase):
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
        built = subprocess.run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j1', 'PAYLOAD=1', 'WTAB=1']
                               + qemu.SP11_VARS + ['payload-runner', 'payloads'], cwd=ROOT, env=lib.ENV, capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError('PAYLOAD=1 WTAB=1 build failed:\n' + built.stdout[-2000:] + built.stderr[-2000:])
        cls.runner = out / 'q1n1-payload.efi'
        cls.binary = (out / 'payloads' / 'gpus1d.bin').read_bytes()
        cls.draft_binary = (out / 'payloads' / 'gpus1.bin').read_bytes()
        boot = Boot('alone', stick([('GPUS1D.BIN', cls.binary)]), script(), marker='PAYLOAD DONE INDEX=0 ')
        cls.run_ = qemu.run_boot(boot, cls.runner, cls.firmware)
        boot = Boot('draft', stick([('GPUS1.BIN', cls.draft_binary)]), script(), marker='PAYLOAD DONE INDEX=0 ')
        cls.draft_run = qemu.run_boot(boot, cls.runner, cls.firmware)

    def lines(self, *prefixes, run=None):
        text = (run or self.run_).text
        self.assertIn(AFTER, text, f'the bounce was never confirmed; inspect {BUILD}')
        return [line for line in text.split(AFTER, 1)[1].split('\n') if line.startswith(prefixes or ('PAYLOAD ', 'WTAB ', 'W ', 'R ', 'C ', 'S ', 'U '))]

    def test_the_table_is_opened_and_the_first_row_stops_the_run_before_any_store(self):
        lines = self.lines()
        opened = [line for line in lines if line.startswith('WTAB OPEN ')]
        self.assertEqual(len(opened), 1, lines)
        self.assertRegex(opened[0], r'^WTAB OPEN GPUS1D ROWS=4 STEPS=1 SHA=2E2A5ADF1552AEA2$')
        attrs = [line for line in lines if line.startswith('WTAB ATTR ')]
        self.assertEqual(len(attrs), 4, lines)
        for tag, line in zip(('GCCAHB', 'GMURCG', 'HUBRCG', 'CXGDSC'), attrs):
            self.assertRegex(line, rf'^WTAB ATTR {tag} (DEVICE|NORMAL|NONE|UNKNOWN)$')
        self.assertLess(lines.index(attrs[-1]), lines.index(opened[0]), 'the mapping of every row is printed before the open line')
        stops = [line for line in lines if line.startswith('WTAB STOP ')]
        self.assertEqual(len(stops), 1, lines)
        self.assertRegex(stops[0], r'^WTAB STOP WHY=(FAULT|FOUND) ROW=0 ')
        ends = [line for line in lines if line.startswith('WTAB END ')]
        self.assertEqual(ends, ['WTAB END RESULT=RESTORED WHY=' + re.search(r'WHY=(\w+)', stops[0]).group(1) + ' ROWS=0 STORES=0 UNDOS=0 RESTORED=0 OF=0'])
        self.assertLess(lines.index(opened[0]), lines.index(stops[0]))
        self.assertLess(lines.index(stops[0]), lines.index(ends[0]))
        self.assertFalse([line for line in lines if re.match(r'^(W|R|U) \d', line)], 'a store was announced')

    def test_a_draft_table_is_refused_by_the_runner_as_the_makefile_builds_it(self):
        lines = self.lines(run=self.draft_run)
        self.assertEqual([line for line in lines if line.startswith('WTAB REFUSED')], ['WTAB REFUSED=DRAFT'], lines)
        self.assertFalse([line for line in lines if line.startswith(('WTAB OPEN', 'WTAB ATTR', 'WTAB STOP', 'WTAB END')) or re.match(r'^(W|R|U|C|S) \d', line)], lines)
        self.assertIn('PAYLOAD GPUS1 REFUSED=OPEN', lines)
        done = [line for line in lines if line.startswith('PAYLOAD DONE INDEX=0 ')]
        self.assertEqual(len(done), 1, lines)
        self.assertRegex(done[0], r'^PAYLOAD DONE INDEX=0 RETURN=0X3 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 ')

    def test_the_payload_sees_the_stop_and_the_runner_calls_it_done(self):
        lines = self.lines('PAYLOAD ')
        self.assertIn('PAYLOAD GPUS1 STOPPED=STEP0', lines)
        self.assertFalse([line for line in lines if line.startswith(('PAYLOAD GPUS1 BEFORE', 'PAYLOAD GPUS1 STATE', 'PAYLOAD GPUS1 END'))])
        done = [line for line in lines if line.startswith('PAYLOAD DONE INDEX=0 ')]
        self.assertEqual(len(done), 1, lines)
        self.assertRegex(done[0], r'^PAYLOAD DONE INDEX=0 RETURN=0X1 STACK=OK LOADS=\d+ FAULTS=\d+ REFUSED=0 LINES=\d+ DROPPED=0$')
        self.assertNotIn('SYNCHRONOUS EXCEPTION', self.run_.text)

    def test_every_line_is_in_the_page_font(self):
        for line in self.lines():
            self.assertIsNotNone(qemu.FONT_LINE.fullmatch(line), line)
            self.assertLessEqual(len(line), 100)

    def test_no_file_of_the_stick_changed(self):
        self.assertFalse(self.run_.changed)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
