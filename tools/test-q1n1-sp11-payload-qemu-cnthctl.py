#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The cnthctl payload of the Surface Pro 11 stick payload runner at EL2 under QEMU's EDK2 shell (docs/SP11-PAYLOAD-CNTHCTL.md).

    python3 tools/test-q1n1-sp11-payload-qemu-cnthctl.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables) and boots QEMU on `virt,virtualization=on,
gic-version=3` with a stick that carries the real cnthctl.bin, in these worlds (the stick layout and helpers are those of
test-q1n1-sp11-payload-qemu.py, the boot driver is tools/sp11_payload_ecv_lib.py's because it needs a CPU model and the time each
line appeared):
  * `-cpu max` (ID_AA64MMFR0_EL1.ECV = 2): CNTHCTL_EL2 holds bits 13 and 14 as written, BITS13_14_STUCK=YES, the old value is back,
    and the eight-second wait before the write is real wall-clock time on QEMU's counter;
  * `-cpu cortex-a76` (ECV = 0): the bits are RES0 and read back as zero, BITS13_14_STUCK=NO, the old value is back;
  * a chain `state`, `cnthctl`, `state` on `-cpu max`: every register the `state` payload prints is identical before and after,
    so the payload really leaves the machine as it found it;
  * the same chain with a copy of cnthctl.c that never writes the old value back (one source edit, asserted): RESTORED=NO, the
    loud NOT_RESTORED line, the return value 2, and the second `state` shows CNTHCTL_EL2 = 0X6000: the failure is seen by the next
    payload, not hidden.
What it proves: the real binary, at a real EL2 with its MMU on, writes exactly its three values, reads them back, restores,
prints the page the host model prints and returns what the model says. What it does not prove: the unit's EL3 (whether
SCR_EL3.ECVEn lets the bits stick, or lets a write of them do anything), the unit's counter, or any trap (that is el1trap's
question, tools/test-q1n1-sp11-payload-qemu-el1trap.py). QEMU 11.1.3's `-cpu max` implements FEAT_ECV and its EL1TVT and EL1TVCT
fields; `-cpu cortex-a76` has none. Hardware NOT RUN. Evidence: EXPERIMENTAL (QEMU only).

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image. SP11_CNTHCTL_QEMU_ONLY
(comma-separated boot names) runs a subset for debugging; the assertions of the others then SKIP. Writes only under
build/sp11-payload-qemu-cnthctl/ (short names: a socket path may not exceed 104 characters)."""
import concurrent.futures
import os
from pathlib import Path
import re
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_ecv_lib as ecv  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-qemu-cnthctl'
SOURCE = ROOT / 'payloads' / 'cnthctl.c'
PREFIX = 'PAYLOAD CNTHCTL '
HEX = r'0X[0-9A-F]+'
ONLY = {name for name in os.environ.get('SP11_CNTHCTL_QEMU_ONLY', '').split(',') if name}
# Source edits of the one variant, each of which must apply exactly once: the two writes of the old value are dropped.
NO_RESTORE = [
    ('    write_cnthctl_el2(p->old);\n    isb();\n    p->restored = read_cnthctl_el2();\n', '    p->restored = read_cnthctl_el2();\n'),
    ('        write_cnthctl_el2(p->old);\n        isb();\n        p->after_retry = read_cnthctl_el2();\n',
     '        p->after_retry = read_cnthctl_el2();\n'),
]
STATE_KEYS = ('HCR_EL2', 'SCTLR_EL2', 'TCR_EL2', 'TTBR0_EL2', 'MAIR_EL2', 'VBAR_EL2', 'CPTR_EL2', 'CNTHCTL_EL2', 'CNTFRQ_EL0', 'DAIF', 'SPSEL')


def state_values(run, index):
    """The KEY=VALUE pairs of the index-th `state` page (0 for the first, 1 for the second) of a run."""
    lines = [line for line in run.text.split('\n') if line.startswith('PAYLOAD STATE ')]
    per = len(lines) // 2
    return dict(line[len('PAYLOAD STATE '):].split('=', 1) for line in lines[index * per:(index + 1) * per])


class CnthctlQemu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'lld-link', 'ld.lld', 'make', 'qemu-system-aarch64', 'llvm-objdump'):
            if not lib.have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        cls.firmware = ecv.find_firmware()
        if not cls.firmware:
            raise unittest.SkipTest('no EDK2 aarch64 firmware (set Q1N1_EDK2_CODE)')
        shutil.rmtree(BUILD, ignore_errors=True)
        BUILD.mkdir(parents=True)
        out = BUILD / 'out'
        cls.runner = ecv.build_runner_and_payloads(out)
        payload = lambda name: (out / 'payloads' / f'{name}.bin').read_bytes()  # noqa: E731
        cls.shipped = payload('cnthctl')
        done, _, flat = ecv.Builder(BUILD / 'variants').build('cnthctl', 'norestore', NO_RESTORE)
        if done.returncode:
            raise RuntimeError(done.stderr[-1500:])
        cls.variant = Path(flat).read_bytes()
        runs = [ecv.Run('max', ecv.stick([('CNTHCTL.BIN', cls.shipped)]), cpu='max'),
                ecv.Run('a76', ecv.stick([('CNTHCTL.BIN', cls.shipped)]), cpu='cortex-a76'),
                ecv.Run('chain', ecv.stick([('STATE.BIN', payload('state')), ('CNTHCTL.BIN', cls.shipped), ('STATE2.BIN', payload('state'))]),
                        cpu='max', marker=ecv.PREFIX_DONE + '2 '),
                ecv.Run('lost', ecv.stick([('STATE.BIN', payload('state')), ('CNTHCTL.BIN', cls.variant), ('STATE2.BIN', payload('state'))]),
                        cpu='max', marker=ecv.PREFIX_DONE + '2 ')]
        runs = [run for run in runs if not ONLY or run.name in ONLY]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            cls.runs = {run.name: run for run in pool.map(lambda r: ecv.run_boot(r, BUILD, cls.runner, cls.firmware), runs)}

    def run_of(self, name):
        if name not in self.runs:
            self.skipTest(f'{name} was not booted (SP11_CNTHCTL_QEMU_ONLY)')
        run = self.runs[name]
        self.assertIn(run.marker, run.text, f'{name} did not finish:\n{run.text[-1500:]}')
        return run

    def page(self, run, index=None):
        """The payload's own lines of the page, in order, without the prefix (of the cnthctl payload in a chain)."""
        return run.lines(PREFIX)

    # -- -cpu max: the bits stick ---------------------------------------------------------------------------------------------
    def test_with_ecv_the_bits_stick_the_old_value_is_back_and_the_page_is_the_models(self):
        run = self.run_of('max')
        page = self.page(run)
        self.assertEqual(len(page), 8, page)
        patterns = [rf'CURRENTEL=0X8 HCR_EL2={HEX} E2H=0X0', rf'ID_AA64MMFR0_EL1={HEX} ECV=0X2', rf'CNTHCTL_EL2 OLD=0X3 CNTFRQ_EL0=0X3B9ACA00',
                    'NEXT CNTHCTL_EL2 WRITE AFTER 8 S', 'OLD=0X3 V=0X6000', 'R=0X6000 R2=0X3', 'BITS13_14_STUCK=YES R_EQ_V=YES', 'RESTORED=YES']
        for line, pattern in zip(page, patterns):
            self.assertRegex(line, f'^{pattern}$')
        done = [line for line in run.text.split('\n') if line.startswith(ecv.PREFIX_DONE + '0 ')][0]
        self.assertRegex(done, r'RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=8 DROPPED=0')
        self.assertFalse(run.changed, 'a file of the stick changed')

    def test_the_wait_before_the_write_is_eight_seconds_of_wall_clock_time(self):
        run = self.run_of('max')
        seconds = ecv.wait_seconds(run, PREFIX + 'NEXT CNTHCTL_EL2 WRITE AFTER 8 S', PREFIX + 'OLD=0X3 V=0X6000')
        # QEMU's counter is 1 GHz and follows the host's clock; the serial log is read every 0.2 s, and a loaded machine adds to it.
        self.assertTrue(7.0 <= seconds <= 40.0, f'{seconds:.2f} s between the NEXT line and the result')

    # -- -cpu cortex-a76: the bits are RES0 --------------------------------------------------------------------------------------
    def test_without_ecv_the_bits_do_not_stick_and_the_old_value_is_back(self):
        run = self.run_of('a76')
        page = self.page(run)
        self.assertEqual(len(page), 8, page)
        self.assertRegex(page[1], rf'^ID_AA64MMFR0_EL1={HEX} ECV=0X0$')
        self.assertRegex(page[2], rf'^CNTHCTL_EL2 OLD=0X3 CNTFRQ_EL0={HEX}$')
        self.assertEqual(page[4:], ['OLD=0X3 V=0X6000', 'R=0X0 R2=0X3', 'BITS13_14_STUCK=NO R_EQ_V=NO', 'RESTORED=YES'])
        self.assertRegex(run.text, r'RETURN=0X0 STACK=OK')

    # -- the chain: the machine is left as found ---------------------------------------------------------------------------------
    def test_every_register_the_state_payload_prints_is_the_same_before_and_after(self):
        run = self.run_of('chain')
        before, after = state_values(run, 0), state_values(run, 1)
        self.assertTrue(set(STATE_KEYS) <= set(before), sorted(before))
        self.assertEqual(before, after)
        self.assertEqual(before['CNTHCTL_EL2'], '0X3')
        self.assertEqual(run.lines(PREFIX)[-1], 'RESTORED=YES')
        self.assertEqual(len(re.findall(r'PAYLOAD DONE INDEX=\d RETURN=0X0 ', run.text)), 3)

    # -- a payload that cannot restore says so, and the next payload sees it -----------------------------------------------------
    def test_a_copy_that_never_restores_is_loud_returns_two_and_leaves_the_bits_for_the_next_payload_to_see(self):
        source = SOURCE.read_text(encoding='utf-8')
        for needle, _ in NO_RESTORE:
            self.assertEqual(source.count(needle), 1, 'the variant edit must apply exactly once')
        run = self.run_of('lost')
        page = run.lines(PREFIX)
        self.assertIn('BITS13_14_STUCK=YES R_EQ_V=YES', page)
        self.assertIn('R=0X6000 R2=0X6000', page)
        self.assertIn('RESTORE_RETRY R3=0X6000', page)
        self.assertEqual(page[-3:], ['RESTORED=NO', 'NOT_RESTORED OLD=0X3 NOW=0X6000', 'POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD'])
        self.assertRegex(run.text, r'PAYLOAD DONE INDEX=1 RETURN=0X2 ')
        self.assertEqual(state_values(run, 0)['CNTHCTL_EL2'], '0X3')
        self.assertEqual(state_values(run, 1)['CNTHCTL_EL2'], '0X6000')
        # Everything else the second state page shows is as found.
        self.assertEqual({k: v for k, v in state_values(run, 0).items() if k != 'CNTHCTL_EL2'},
                         {k: v for k, v in state_values(run, 1).items() if k != 'CNTHCTL_EL2'})

    def test_the_shipped_binary_is_the_one_make_payloads_builds_and_the_variant_is_not_it(self):
        self.assertNotEqual(self.shipped, self.variant)
        self.assertEqual(self.shipped[:4], bytes.fromhex('5f2403d5'))


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
