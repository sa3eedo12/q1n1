#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The chain `state.bin psci.bin timer.bin` under QEMU's EDK2 shell, and what happens when the timer payload's hazardous
reads hang or fault (docs/SP11-PAYLOAD-TIMER.md).

    python3 tools/test-q1n1-sp11-payload-qemu-timer.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), the chain test's mark fixture, three
copies of timer.c with one edit each (the CNTPOFF_EL2 read replaced by an endless loop, the CNTVOFF_EL2 read replaced by
an endless loop, the CNTVOFF_EL2 read replaced by an undefined instruction) and a copy of the runner that forces the
panel region onto QEMU's 800x600 screen. It lays six sticks out as the stick is laid out and boots QEMU's EDK2 shell on
each, with a real ExitBootServices and a real EL2 (the stick layout, the boot driver and the screenshot helpers are those
of test-q1n1-sp11-payload-qemu.py).

OBSERVED, QEMU 11.1.3 (`virt,virtualization=on`, `-cpu max`, `-smp 1`, TCG, EDK2 AArch64), and asserted here: ID_AA64MMFR0_EL1.ECV
is 2, so the payload takes the CNTPOFF_EL2 path, and QEMU implements CNTPOFF_EL2 at EL2: the read completes and returns 0,
as the read of CNTVOFF_EL2 does. The counter runs at 1 GHz, advances between two reads, and CNTVCT + CNTVOFF_EL2 lies within
the CNTPCT reads around it in all eight rounds. All sixteen lines of the payload are on the log, and with the lines of
`state` and `psci` and the runner's own the chain is 72 lines (the figure docs/SP11-PAYLOAD-TIMER.md budgets against the
unit's panel region). What that proves: the payload runs to its end at EL2 behind the runner and prints what the host
test says it prints. What it does not: anything about the unit, whose firmware decides whether a read of CNTVOFF_EL2 or
CNTPOFF_EL2 returns, faults or stalls the board (UNKNOWN, hardware NOT RUN), and QEMU has no EL3 to trap to.

The stall and fault copies stand in for the unit's possible outcomes: a read that never completes must leave its NEXT line
as the last line of the log, and on the page when the region has rows; a read that faults must end in q1n1's fault page
(a red bar across the top) with the NEXT line the last on the log; and in a chain, all the lines before the timer
payload's are there. SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware
image; the pinned UEFI Shell (SP11_UEFI_SHELL) is used for the full chain and the test says so when it is not set.
Evidence: EXPERIMENTAL (QEMU only); hardware NOT RUN. Writes only under build/sp11-payload-qemu-timer/."""
import concurrent.futures
import importlib.util
from pathlib import Path
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


qemu = load_module('sp11_payload_qemu_base_for_timer', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-timer'
sha, script, manifest, Boot, bands = qemu.sha, qemu.script, qemu.manifest, qemu.Boot, qemu.bands
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'
TIMER_PREFIX = 'PAYLOAD TIMER '
# What the payload printed under QEMU 11.1.3 (OBSERVED once per run of this test; the counters vary from run to run).
HEX = r'0X[0-9A-F]+'
POSITIVE = r'0X[1-9A-F][0-9A-F]*'
TIMER_UNDER_QEMU = [
    rf'ID_AA64MMFR0_EL1={HEX} ECV=0X2', rf'HCR_EL2={HEX} E2H=0X[01] TGE=0X[01]', 'CNTFRQ_EL0=0X3B9ACA00', rf'CNTHCTL_EL2={HEX} ECV=0X0',
    'CNTP_CTL_EL0=0X0', 'CNTV_CTL_EL0=0X0', 'CNTHP_CTL_EL2=0X0', f'CNTPCT_EL0={POSITIVE}',
    f'POLL_ADVANCED=0X1 POLL_READS={POSITIVE} POLL_DELTA={POSITIVE}', f'CNTVCT_EL0={POSITIVE}', 'NEXT CNTVOFF_EL2', 'CNTVOFF_EL2=0X0',
    f'VCT_PLUS_VOFF_WITHIN_PCT=0X1 HELD=0X8 OF=0X8 OFFSET={HEX}', 'NEXT CNTPOFF_EL2', 'CNTPOFF_EL2=0X0', 'DONE',
]


def chain_stick(entries):
    """The files of a stick: `entries` is [(file name, bytes)] in manifest order."""
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


def digest(data):
    return sha(data)[:16].upper()


class TimerQemu(unittest.TestCase):
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
        cls.bins = {name: (out / 'payloads' / f'{name}.bin').read_bytes() for name in ('state', 'psci', 'timer')}
        result, _, flat = lib.build_payload(ROOT / 'tools' / 'testdata' / 'sp11-payload-fixture-mark.c', BUILD / 'fixtures', name='mark1',
                                            extra_cflags=('-DFIXTURE_MARK_ID=1',))
        if result.returncode:
            raise RuntimeError('fixture failed:\n' + result.stderr[-1500:])
        cls.mark = flat.read_bytes()
        # The timer payload with the one access that would hang the unit replaced by what each outcome looks like.
        source = (ROOT / 'payloads' / 'timer.c').read_text(encoding='utf-8')
        edits = {
            'stall-poff': ('        uint64_t poff = SYSREG(S3_4_C14_C0_6);\n', '        uint64_t poff = 0;\n        for (;;) __asm__ volatile("");\n'),
            'stall-voff': ('    uint64_t voff = SYSREG(S3_4_C14_C0_3);\n', '    uint64_t voff = 0;\n    for (;;) __asm__ volatile("");\n'),
            'fault-voff': ('    uint64_t voff = SYSREG(S3_4_C14_C0_3);\n', '    __asm__ volatile(".inst 0x00000000");\n    uint64_t voff = 0;\n'),
        }
        cls.variants = {}
        for name, (needle, replacement) in edits.items():
            assert source.count(needle) == 1, f'{name}: the edit does not apply'
            path = BUILD / 'variants' / f'timer-{name}.c'
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source.replace(needle, replacement, 1), encoding='utf-8')
            result, _, flat = lib.build_payload(path, BUILD / 'variants', name=f'timer-{name}')
            if result.returncode:
                raise RuntimeError(f'variant {name} failed:\n{result.stderr[-1500:]}')
            cls.variants[name] = flat.read_bytes()
        cls.drawn = qemu.PayloadQemu._variant('draw', *qemu.DRAW_EDIT, qemu.SP11_VARS)
        cls.runs = cls._boots()

    @classmethod
    def _boots(cls):
        state, psci, timer = cls.bins['state'], cls.bins['psci'], cls.bins['timer']
        v = cls.variants
        full = chain_stick([('STATE.BIN', state), ('PSCI.BIN', psci), ('TIMER.BIN', timer)])

        def short(name):
            return chain_stick([('M1.BIN', cls.mark), ('TIMER.BIN', v[name])])

        stalled_poff = f'{TIMER_PREFIX}NEXT CNTPOFF_EL2\n'
        boots = [
            Boot('chain3', full, script(), pinned=bool(qemu.PINNED_SHELL and Path(qemu.PINNED_SHELL).is_file()), shot_after=2,
                 marker='PAYLOAD DONE INDEX=2 RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=16 DROPPED=0\n'),
            Boot('chain-stall-poff', chain_stick([('STATE.BIN', state), ('PSCI.BIN', psci), ('TIMER.BIN', v['stall-poff'])]), script(),
                 marker=stalled_poff, shot_after=3),
            Boot('chain-stall-voff', chain_stick([('STATE.BIN', state), ('PSCI.BIN', psci), ('TIMER.BIN', v['stall-voff'])]), script(),
                 marker=f'{TIMER_PREFIX}NEXT CNTVOFF_EL2\n', shot_after=3),
            Boot('draw-stall', short('stall-poff'), script(), marker=stalled_poff, shot_after=6, image=cls.drawn),
            Boot('plain-stall', short('stall-poff'), script(), marker=stalled_poff, shot_after=6),
            Boot('fault-voff', short('fault-voff'), script(), marker=f'{TIMER_PREFIX}NEXT CNTVOFF_EL2\n', shot_after=6),
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            return {b.name: b for b in pool.map(lambda b: qemu.run_boot(b, cls.runner, cls.firmware), boots)}

    # -- what a boot printed ----------------------------------------------------------------------------------------------
    def after(self, name):
        text = self.runs[name].text
        self.assertIn(AFTER, text, f'{name}: the bounce was never confirmed; inspect {BUILD / (name + ".log")}')
        return text.split(AFTER, 1)[1]

    def lines(self, name, prefixes=('PAYLOAD ', 'FIXTURE ')):
        return [line for line in self.after(name).split('\n') if line.startswith(prefixes)]

    def top_pixel(self, name):
        width, _, pixels = self.runs[name].shot
        at = (2 * width + width // 2) * 3
        return pixels[at:at + 3]

    # -- the whole chain ---------------------------------------------------------------------------------------------------
    def test_the_chain_runs_state_psci_and_timer_in_order_and_the_timer_payload_prints_what_qemu_gives_it(self):
        lines = self.lines('chain3')
        self.assertIn('PAYLOAD READY FILES=3 RANGES=6 CODE=3', self.runs['chain3'].text.split(AFTER, 1)[0])
        calls = [line for line in lines if line.startswith('PAYLOAD CALL ')]
        self.assertEqual(calls, [f'PAYLOAD CALL {i} {digest(self.bins[name])}' for i, name in enumerate(('state', 'psci', 'timer'))])
        done = [line for line in lines if line.startswith('PAYLOAD DONE ')]
        self.assertEqual([line.split()[2] for line in done], ['INDEX=0', 'INDEX=1', 'INDEX=2'])
        self.assertTrue(all(' RETURN=0X0 STACK=OK ' in line for line in done))
        self.assertEqual([line.split('LINES=')[1].split()[0] for line in done], ['21', '22', '16'])
        timer = [line for line in lines if line.startswith(TIMER_PREFIX)]
        self.assertEqual(len(timer), len(TIMER_UNDER_QEMU))
        for line, pattern in zip(timer, TIMER_UNDER_QEMU):
            self.assertRegex(line, f'^{TIMER_PREFIX}{pattern}$')
        # In order: state's lines, psci's, then the timer's, each between its own CALL and DONE.
        order = [i for i, line in enumerate(lines) if line.startswith(('PAYLOAD CALL 0', 'PAYLOAD STATE ', 'PAYLOAD CALL 1', 'PAYLOAD PSCI ',
                                                                       'PAYLOAD CALL 2', TIMER_PREFIX))]
        self.assertEqual(order, sorted(order))
        self.assertNotIn('SYNCHRONOUS EXCEPTION', self.runs['chain3'].text)

    def test_the_timer_payload_agrees_with_state_about_what_both_read(self):
        lines = self.lines('chain3')
        state = {line.split('=')[0][len('PAYLOAD STATE '):]: line.split('=')[1] for line in lines if line.startswith('PAYLOAD STATE ')}
        timer = ' '.join(line[len(TIMER_PREFIX):] for line in lines if line.startswith(TIMER_PREFIX))
        for register in ('ID_AA64MMFR0_EL1', 'HCR_EL2', 'CNTFRQ_EL0', 'CNTHCTL_EL2'):
            self.assertIn(f'{register}={state[register]}', timer.split(), f'{register}: state and timer disagree')
        ecv = int(state['ID_AA64MMFR0_EL1'], 16) >> 60 & 15
        self.assertEqual(ecv, 2, 'QEMU -cpu max implements ECV 2 here: the CNTPOFF_EL2 path of the payload is the one under test')
        self.assertIn(f'ECV=0X{ecv:X}', timer.split())

    def test_the_whole_chain_is_seventy_two_lines_which_the_unit_panel_region_holds(self):
        # 3 notes and READY, three lines per payload, 21 of state, 22 of psci, 16 of timer; the doc budgets the same sum.
        lines = self.lines('chain3', ('PAYLOAD ',))
        self.assertEqual(len(lines), 4 + 9 + 21 + 22 + 16)
        self.assertEqual(len(lines), 72)
        self.assertLessEqual(len(lines) + 8 + 1, 89, 'psci may print eight lines more than it did here (30 at most), state one more')
        for line in lines:
            self.assertIsNotNone(qemu.FONT_LINE.fullmatch(line), line)
            self.assertLessEqual(len(line), 100)

    # -- a payload that stalls or faults at the hazard ------------------------------------------------------------------------
    def test_a_stall_at_cntpoff_leaves_its_next_line_last_and_every_line_before_it(self):
        lines = self.lines('chain-stall-poff', ('PAYLOAD ',))
        self.assertEqual(lines[-1], f'{TIMER_PREFIX}NEXT CNTPOFF_EL2')
        self.assertEqual(sum(line.startswith('PAYLOAD STATE ') for line in lines), 21)
        self.assertEqual(sum(line.startswith('PAYLOAD PSCI ') for line in lines), 22)
        self.assertEqual(len([line for line in lines if line.startswith(TIMER_PREFIX)]), 14, 'the timer lines up to and with the NEXT line')
        self.assertIn(f'{TIMER_PREFIX}CNTVOFF_EL2=0X0', lines)
        self.assertFalse(any(line.startswith(f'{TIMER_PREFIX}CNTPOFF_EL2=') or line.startswith('PAYLOAD DONE INDEX=2') for line in lines))
        self.assertEqual(sum(line.startswith('PAYLOAD DONE ') for line in lines), 2, 'state and psci came back, timer did not')

    def test_a_stall_at_cntvoff_leaves_its_next_line_last(self):
        lines = self.lines('chain-stall-voff', ('PAYLOAD ',))
        self.assertEqual(lines[-1], f'{TIMER_PREFIX}NEXT CNTVOFF_EL2')
        self.assertFalse(any(line.startswith((f'{TIMER_PREFIX}CNTVOFF_EL2=', f'{TIMER_PREFIX}VCT_PLUS', f'{TIMER_PREFIX}NEXT CNTPOFF')) for line in lines))
        self.assertEqual(len([line for line in lines if line.startswith(TIMER_PREFIX)]), 11)
        self.assertEqual(sum(line.startswith('PAYLOAD DONE ') for line in lines), 2)

    def test_the_next_line_is_on_the_page_when_the_payload_stalls_after_it(self):
        # The stock runner has no rows to draw on QEMU's 800x600 screen; the copy that forces a region draws every line the
        # runner and the payloads printed up to the stall: three notes, VERIFY, CALL, the mark and DONE of the first payload,
        # VERIFY, CALL and the timer's fourteen lines, the last of which is the NEXT line.
        printed = self.lines('draw-stall')
        self.assertEqual(printed[-1], f'{TIMER_PREFIX}NEXT CNTPOFF_EL2')
        self.assertEqual(len(printed), 3 + 4 + 2 + 14)
        stock, drawn = self.runs['plain-stall'].shot, self.runs['draw-stall'].shot
        self.assertEqual(stock[:2], drawn[:2])
        self.assertGreaterEqual(bands(drawn, stock), len(printed) - 1, 'fewer rows of text differ than the lines printed before the stall')
        self.assertEqual(self.lines('plain-stall')[-1], printed[-1])

    def test_a_fault_at_cntvoff_ends_in_q1ns_fault_page_with_its_next_line_last(self):
        lines = self.lines('fault-voff')
        self.assertEqual(lines[-1], f'{TIMER_PREFIX}NEXT CNTVOFF_EL2')
        self.assertNotIn('PAYLOAD DONE INDEX=1', '\n'.join(lines))
        top, quiet = self.top_pixel('fault-voff'), self.top_pixel('plain-stall')
        self.assertNotEqual(top, quiet, 'the top rows are the same as for a payload that is still running')
        self.assertGreater(max(top), 200)
        self.assertLess(sorted(top)[1], 120, 'the fault page paints a red bar across the top')

    def test_a_chain_that_runs_to_the_end_shows_no_fault_page(self):
        self.assertEqual(self.top_pixel('chain3'), self.top_pixel('plain-stall'))

    @unittest.skipUnless(qemu.PINNED_SHELL and Path(qemu.PINNED_SHELL or '/nonexistent').is_file(), 'SP11_UEFI_SHELL not set')
    def test_the_full_chain_ran_under_the_pinned_uefi_shell(self):
        # The stick of that boot holds the pinned Shell as its removable-media boot file, so that is the Shell that ran it.
        self.assertTrue(self.runs['chain3'].pinned)
        booted = BUILD / 'chain3' / 'EFI' / 'BOOT' / 'BOOTAA64.EFI'
        self.assertEqual(sha(booted.read_bytes()), sha(Path(qemu.PINNED_SHELL).read_bytes()))
        self.assertIn('UEFI Interactive Shell', self.runs['chain3'].text)

    def test_no_boot_changes_a_file_of_the_stick(self):
        for name, boot in self.runs.items():
            self.assertFalse(boot.changed, f'{name}: a file on the stick changed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
