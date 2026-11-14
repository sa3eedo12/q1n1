#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The chain `psci.bin usbsmmu.bin timer.bin` under QEMU's EDK2 shell (docs/SP11-PAYLOAD-USBSMMU.md).

    python3 tools/test-q1n1-sp11-payload-qemu-usbsmmu.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), lays three sticks out as the stick is
laid out (the chain of the unit, `usbsmmu` alone, and `state psci usbsmmu timer`) and boots QEMU's EDK2 shell on each, with a
real ExitBootServices and a real EL2 (the stick layout, the boot driver and the helpers are those of
test-q1n1-sp11-payload-qemu.py).

OBSERVED, QEMU 11.1.3 (`virt,virtualization=on`, `-cpu max`, `-smp 1`, TCG, EDK2 AArch64), and asserted here: QEMU has none of
the three windows the payload reads (usb_1_ss0, usb_1_ss1 and apps_smmu are the unit's, not the `virt` machine's). The two
USB windows lie in a hole of its memory map: the first guarded load of each aborts, the runner reports a faulted load and
the payload prints a FAULT line for it. The SMMU window lies inside the PCIe MMIO window, where nothing is mapped: its loads
answer all ones, which is what "nothing there" looks like, and the payload prints UNREADABLE and reads nothing more from it.
It skips what depends on them (DWC3, the rings, the context bank, the walk), prints no NEXT line for a group it does not
enter, finishes with a normal DONE and does not hang. The destination of every load is accepted by the runner (no
REFUSED=LOAD32: the payload's word is on its stack), and the counters of the DONE line agree with the four loads it made.
What that proves: the binary runs at EL2 behind the runner, uses only the ops and fails closed on both kinds of nothing. What
it does not: anything about the unit's windows (UNKNOWN, hardware NOT RUN), the page tables, the memory-map checks on real
descriptors, or the walk, which only the host test exercises.

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image; the pinned UEFI
Shell (SP11_UEFI_SHELL) is used for the unit's chain and the test says so when it is not set.
Evidence: EXPERIMENTAL (QEMU only); hardware NOT RUN. Writes only under build/sp11-payload-qemu-usbsmmu/."""
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


qemu = load_module('sp11_payload_qemu_base_for_usbsmmu', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-usbsmmu'
sha, script, manifest, Boot = qemu.sha, qemu.script, qemu.manifest, qemu.Boot
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'
PREFIX = 'PAYLOAD USBSMMU '
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-USBSMMU.md'
# What the payload printed under QEMU 11.1.3 (OBSERVED once per run of this test): the block docs/SP11-PAYLOAD-USBSMMU.md
# gives under "What QEMU shows", in order. The two USB windows abort at their first load; the SMMU window answers all ones.
USBSMMU_UNDER_QEMU = [
    'NEXT U0', 'U0 FAULT AT=CAP0', 'U1 FAULT AT=CAP0', 'DWC3 SKIPPED=U0_NOT_READ', 'NEXT SMMU',
    'SMMU UNREADABLE ID0=0XFFFFFFFF SCR0=0XFFFFFFFF', 'NEXT RINGS', 'RINGS SKIPPED=NO_XHC', 'CB SKIPPED=NO_STREAMS', 'WALK SKIPPED=NO_BANK',
]


def chain_stick(entries):
    """The files of a stick: `entries` is [(file name, bytes)] in manifest order."""
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


def digest(data):
    return sha(data)[:16].upper()


class UsbsmmuQemu(unittest.TestCase):
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
        built = subprocess.run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j4', 'PAYLOAD=1']
                               + qemu.SP11_VARS + ['payload-runner', 'payloads'], cwd=ROOT, env=lib.ENV, capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError('PAYLOAD=1 build failed:\n' + built.stdout[-2000:] + built.stderr[-2000:])
        cls.runner = out / 'q1n1-payload.efi'
        cls.bins = {name: (out / 'payloads' / f'{name}.bin').read_bytes() for name in ('state', 'psci', 'usbsmmu', 'timer')}
        cls.runs = cls._boots()

    @classmethod
    def _boots(cls):
        b = cls.bins
        pinned = bool(qemu.PINNED_SHELL and Path(qemu.PINNED_SHELL).is_file())
        boots = [
            Boot('unit-chain', chain_stick([('PSCI.BIN', b['psci']), ('USBSMMU.BIN', b['usbsmmu']), ('TIMER.BIN', b['timer'])]), script(),
                 pinned=pinned, marker='PAYLOAD DONE INDEX=2 RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=16 DROPPED=0\n'),
            Boot('alone', chain_stick([('USBSMMU.BIN', b['usbsmmu'])]), script(), marker='PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK '),
            Boot('four', chain_stick([('STATE.BIN', b['state']), ('PSCI.BIN', b['psci']), ('USBSMMU.BIN', b['usbsmmu']),
                                      ('TIMER.BIN', b['timer'])]), script(),
                 marker='PAYLOAD DONE INDEX=3 RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=16 DROPPED=0\n'),
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            return {boot.name: boot for boot in pool.map(lambda boot: qemu.run_boot(boot, cls.runner, cls.firmware), boots)}

    # -- what a boot printed ----------------------------------------------------------------------------------------------
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

    # -- the chain of the unit ---------------------------------------------------------------------------------------------
    def test_the_chain_of_the_unit_runs_psci_usbsmmu_timer_in_order_to_the_end(self):
        lines = self.lines('unit-chain')
        self.assertIn('PAYLOAD READY FILES=3 RANGES=6 CODE=3', self.runs['unit-chain'].text.split(AFTER, 1)[0])
        calls = [line for line in lines if line.startswith('PAYLOAD CALL ')]
        self.assertEqual(calls, [f'PAYLOAD CALL {i} {digest(self.bins[name])}' for i, name in enumerate(('psci', 'usbsmmu', 'timer'))])
        done = [line for line in lines if line.startswith('PAYLOAD DONE ')]
        self.assertEqual([line.split()[2] for line in done], ['INDEX=0', 'INDEX=1', 'INDEX=2'])
        self.assertTrue(all(' RETURN=0X0 STACK=OK ' in line for line in done))
        order = [i for i, line in enumerate(lines) if line.startswith(('PAYLOAD CALL 0', 'PAYLOAD PSCI ', 'PAYLOAD CALL 1', PREFIX,
                                                                       'PAYLOAD CALL 2', 'PAYLOAD TIMER '))]
        self.assertEqual(order, sorted(order))
        self.assertNotIn('SYNCHRONOUS EXCEPTION', self.runs['unit-chain'].text)

    def test_every_window_aborts_at_its_first_load_and_the_payload_says_so_and_goes_on(self):
        for name in ('unit-chain', 'alone', 'four'):
            with self.subTest(boot=name):
                self.assertEqual(self.printed(name), USBSMMU_UNDER_QEMU)

    def test_the_runner_accepted_every_destination_and_its_counters_agree_with_the_four_loads(self):
        # The payload loads once from each USB window (each aborts) and twice from the SMMU window (all ones). A destination
        # outside the payload's stack would be refused by the runner, and the payload would print REFUSED=LOAD32 for it.
        for name, index in (('unit-chain', 1), ('alone', 0), ('four', 2)):
            with self.subTest(boot=name):
                line = self.done(name, index)
                self.assertRegex(line, r'^PAYLOAD DONE INDEX=\d RETURN=0X0 STACK=OK LOADS=4 FAULTS=2 REFUSED=0 LINES=10 DROPPED=0$')
                self.assertNotIn('REFUSED=LOAD32', '\n'.join(self.printed(name)))

    def test_it_prints_nothing_the_unit_would_not_and_stays_within_the_budget(self):
        for name in ('unit-chain', 'alone', 'four'):
            for line in self.lines(name):
                self.assertIsNotNone(qemu.FONT_LINE.fullmatch(line), line)
                self.assertLessEqual(len(line), 100)
        self.assertLessEqual(len(self.printed('alone')), 24)

    def test_the_four_payload_chain_runs_state_first_and_every_payload_returns(self):
        lines = self.lines('four')
        calls = [line.split()[2] for line in lines if line.startswith('PAYLOAD CALL ')]
        self.assertEqual(calls, ['0', '1', '2', '3'])
        self.assertEqual(sum(line.startswith('PAYLOAD DONE ') for line in lines), 4)
        self.assertEqual(sum(line.startswith('PAYLOAD STATE ') for line in lines), 21)
        self.assertEqual(sum(line.startswith('PAYLOAD PSCI ') for line in lines), 22)

    def test_the_document_gives_the_lines_qemu_showed(self):
        doc = DOC.read_text(encoding='utf-8')
        block = re.search(r'<!-- qemu-lines -->\n```\n(.*?)```\n<!-- /qemu-lines -->', doc, re.S)
        self.assertIsNotNone(block, 'docs/SP11-PAYLOAD-USBSMMU.md has no <!-- qemu-lines --> block')
        self.assertEqual([line for line in block.group(1).splitlines()], [PREFIX + line for line in USBSMMU_UNDER_QEMU])

    @unittest.skipUnless(qemu.PINNED_SHELL and Path(qemu.PINNED_SHELL or '/nonexistent').is_file(), 'SP11_UEFI_SHELL not set')
    def test_the_chain_of_the_unit_ran_under_the_pinned_uefi_shell(self):
        self.assertTrue(self.runs['unit-chain'].pinned)
        booted = BUILD / 'unit-chain' / 'EFI' / 'BOOT' / 'BOOTAA64.EFI'
        self.assertEqual(sha(booted.read_bytes()), sha(Path(qemu.PINNED_SHELL).read_bytes()))
        self.assertIn('UEFI Interactive Shell', self.runs['unit-chain'].text)

    def test_no_boot_changes_a_file_of_the_stick(self):
        for name, boot in self.runs.items():
            self.assertFalse(boot.changed, f'{name}: a file on the stick changed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
