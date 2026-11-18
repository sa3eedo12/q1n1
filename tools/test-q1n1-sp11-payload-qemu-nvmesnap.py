#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The payload `nvmesnap` behind the runner, under QEMU's EDK2 shell (docs/SP11-PAYLOAD-NVMESNAP.md).

    python3 tools/test-q1n1-sp11-payload-qemu-nvmesnap.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), lays two sticks out as the stick is laid out (`nvmesnap` alone and
`nvmesnap` then `smmuprobe`) and boots QEMU's EDK2 shell on each, with a real ExitBootServices and a real EL2 (the stick layout, the boot driver and the
helpers are those of test-q1n1-sp11-payload-qemu.py).

QEMU has none of what the payload reads: its `virt` machine has 512 MiB of RAM from 0x40000000 and no device at the PCIe addresses of the unit, so the
payload's questions are answered by the model, not by hardware. What that is, OBSERVED here and asserted: the MMU's answer for the root port's page (the
`MAP` line), and from it, by this test's own reading of the line, whether the page is one the payload may read (a Device mapping) or not. A page that is
not is never loaded from: the function is reported as not read (`RP_NOT_READ`), the controller's registers and the queues are never reached, the
payload prints no `NEXT` line, the runner counts no load, and the verdict and the last line are on the page. A page that is a Device mapping (it is not,
under QEMU's firmware; the branch is asserted so that a firmware that maps it so is not read as a pass without the reads) must make the loads the page
reports, and the runner must count them. What that proves: the binary runs at EL2 behind the runner, uses only the ops, keeps its stores on its own stack
(the runner would have refused the load destination otherwise), obeys the answer of the MMU, never prints more than 34 lines or a character outside the
page font, and the runner reports a normal DONE whose counters agree with the page, alone and in a chain with `smmuprobe` after it. What it does not:
anything about the unit's windows (UNKNOWN, hardware NOT RUN), the gates, the decode or the queues, which only the host test exercises.

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image.
Evidence: EXPERIMENTAL (QEMU only); hardware NOT RUN. Writes only under build/sp11-payload-qemu-nvmesnap/."""
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


qemu = load_module('sp11_payload_qemu_base_for_nvmesnap', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-nvmesnap'
script, manifest, Boot = qemu.script, qemu.manifest, qemu.Boot
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'
PREFIX = 'PAYLOAD NVMESNAP '
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-NVMESNAP.md'


def normal(lines):
    """`lines` (without the prefix) as the document shows them: the counter frequency and the fault status of a refused page as placeholders."""
    shown = []
    for line in lines:
        line = re.sub(r'FREQ=\d+', 'FREQ=<HZ>', line)
        line = re.sub(r'FAULT=0X[0-9A-F]+:\w+', 'FAULT=<FST>', line)
        shown.append(line)
    return shown


def chain_stick(entries):
    """The files of a stick: `entries` is [(file name, bytes)] in manifest order."""
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


def maps(line):
    """{'RP': walk, 'EP': walk} of a `MAP RP=... EP=...` line."""
    return dict(token.split('=', 1) for token in line.split()[1:])


class NvmesnapQemu(unittest.TestCase):
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
        cls.bins = {name: (out / 'payloads' / f'{name}.bin').read_bytes() for name in ('nvmesnap', 'smmuprobe')}
        boots = [
            Boot('alone', chain_stick([('NVMESNAP.BIN', cls.bins['nvmesnap'])]), script(), marker='PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK '),
            Boot('before-smmuprobe', chain_stick([('NVMESNAP.BIN', cls.bins['nvmesnap']), ('SMMUPROBE.BIN', cls.bins['smmuprobe'])]), script(),
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

    def printed(self, name, prefix=PREFIX):
        return [line[len(prefix):] for line in self.lines(name) if line.startswith(prefix)]

    def done(self, name, index):
        found = [line for line in self.lines(name) if line.startswith(f'PAYLOAD DONE INDEX={index} ')]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def refused_functions(self, name):
        """The functions whose page the MMU did not map as Device, by this test's own reading of the MAP line."""
        walks = maps(next(line for line in self.printed(name) if line.startswith('MAP ')))
        return sorted(function for function, walk in walks.items() if not walk.startswith('DEVICE'))

    def test_it_runs_to_the_end_behind_the_runner_alone_and_before_smmuprobe(self):
        for name, index in (('alone', 0), ('before-smmuprobe', 0)):
            with self.subTest(boot=name):
                self.assertRegex(self.done(name, index), r'^PAYLOAD DONE INDEX=\d RETURN=0X0 STACK=OK LOADS=\d+ FAULTS=\d+ REFUSED=\d+ LINES=\d+ DROPPED=0$')
                self.assertNotIn('SYNCHRONOUS EXCEPTION', self.runs[name].text)
        self.assertRegex(self.done('before-smmuprobe', 1), r'^PAYLOAD DONE INDEX=1 RETURN=0X0 STACK=OK ')
        self.assertEqual(normal(self.printed('alone')), normal(self.printed('before-smmuprobe')))
        chained = self.lines('before-smmuprobe', ('PAYLOAD NVMESNAP ', 'PAYLOAD SMMUPROBE '))
        last = max(i for i, line in enumerate(chained) if line.startswith('PAYLOAD NVMESNAP '))
        first = min(i for i, line in enumerate(chained) if line.startswith('PAYLOAD SMMUPROBE '))
        self.assertLess(last, first, 'nvmesnap runs and ends before smmuprobe starts')

    def test_the_page_has_its_structure_under_qemu(self):
        page = self.printed('alone')
        self.assertRegex(page[0], r'^START CURRENTEL=0X8 FREQ=\d+ ECAM=0X70000000 WINDOW=0X70300000$')
        self.assertTrue(page[1].startswith('MAP RP='), page[1])
        self.assertEqual(set(maps(page[1])), {'RP', 'EP'})
        self.assertTrue(page[-2].startswith('VERDICT '), page[-2])
        self.assertRegex(page[-1], r'^DONE NVME_GROUP_(RAN|SKIPPED) LOADS=\d+ FAULTS=\d+ REFUSED=\d+ NVME_TRIED=\d+$')
        self.assertLessEqual(len(page), 34)
        order = [i for i, line in enumerate(page) if line.startswith('NEXT ')]
        self.assertEqual(order, sorted(order))

    def test_the_mmus_answer_is_obeyed(self):
        page = self.printed('alone')
        refused = self.refused_functions('alone')
        for function in ('RP', 'EP'):
            line = next(line for line in page if line.startswith(f'{function} ID='))
            self.assertEqual(line.startswith(f'{function} ID=REFUSED:126'), function in refused, line)
        done = self.done('alone', 0)
        if len(refused) < 2:
            self.assertNotIn(' LOADS=0 ', done, 'a Device mapping was said to be read and the runner counted no load')
            return
        self.assertEqual([line for line in page if line.startswith('NEXT ')], [], 'no group is announced when neither function is read')
        self.assertIn('WHY=RP_NOT_READ', page[-2])
        self.assertRegex(done, r' LOADS=0 FAULTS=0 REFUSED=0 ', 'the runner made no load: the payload refused before it reached the op')
        self.assertTrue(page[-1].startswith('DONE NVME_GROUP_SKIPPED LOADS=0 FAULTS=0 REFUSED=2 NVME_TRIED=0'), page[-1])

    def test_the_counters_of_the_runner_agree_with_the_payload(self):
        line = self.done('alone', 0)
        printed = self.printed('alone')[-1]
        loads = int(re.search(r'LOADS=(\d+)', printed).group(1))
        self.assertIn(f'LOADS={loads} ', line)
        self.assertIn(f'LINES={len(self.printed("alone"))} ', line)

    def test_it_prints_nothing_outside_the_page_font(self):
        for name in self.runs:
            for line in self.lines(name):
                self.assertIsNotNone(qemu.FONT_LINE.fullmatch(line), line)
                self.assertLessEqual(len(line), 100)

    def test_the_document_gives_the_lines_qemu_showed(self):
        if len(self.refused_functions('alone')) < 2:
            self.skipTest('this firmware maps a PCIe page as Device: the document shows the page of the firmware it was written with')
        doc = DOC.read_text(encoding='utf-8')
        block = re.search(r'<!-- qemu-lines -->\n```\n(.*?)```\n<!-- /qemu-lines -->', doc, re.S)
        self.assertIsNotNone(block, 'docs/SP11-PAYLOAD-NVMESNAP.md has no <!-- qemu-lines --> block')
        self.assertEqual(block.group(1).splitlines(), [PREFIX + line for line in normal(self.printed('alone'))])

    def test_no_boot_changes_a_file_of_the_stick(self):
        for name, boot in self.runs.items():
            self.assertFalse(boot.changed, f'{name}: a file on the stick changed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
