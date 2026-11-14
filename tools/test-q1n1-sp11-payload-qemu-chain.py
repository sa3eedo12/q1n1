#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end checks of the payload CHAIN (several payloads called one after the other in one boot) and of the
`psci` payload under QEMU's EDK2 shell (docs/SP11-PAYLOAD.md).

    python3 tools/test-q1n1-sp11-payload-qemu-chain.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), the chain's fixtures
(tools/testdata/sp11-payload-fixture-*.c: marks that say which base and size they were called with, a payload that
makes more loads than one call may, one that damages a later payload) and two copies of the runner with one edit each
(the second payload is damaged after the first has returned; the panel region is forced onto QEMU's 800x600 screen).
It lays thirteen sticks out as the stick is laid out and boots QEMU's EDK2 shell on each (the stick layout, the boot
driver and the screenshot helpers are those of test-q1n1-sp11-payload-qemu.py).

What it proves, on the real call path (a real ExitBootServices, a real EL2): a manifest of payloads is called in
manifest order, each with the base and size of ITS file; a manifest entry that is not named <stem>.BIN (in any case)
is data and is never called, even when its bytes are a payload; five files use all eight declared ranges; a hash
that is wrong before the bounce refuses the whole run; a payload whose hash differs at EL2 is not called and the
chain says it stopped there (by a runner copy that damages it, and by a payload that damages a later one); a payload
that overwrites the guard words of its stack stops the chain; a hanging second payload is named by the last line, a
faulting one reaches q1n1's fault page, and the first payload's lines are on the serial log (and, with the region
forced onto the screen, on the page); the 40-line and 4096-load budgets are given to every payload in turn; a
manifest whose first file is data is refused; and the chain `state` then `psci` runs to the end.

What QEMU does with `smc #0` at EL2 without an EL3 (OBSERVED, QEMU 11.1.3, `-smp 1`, `-cpu max`): it does not fault,
it answers: the PSCI calls reach QEMU's own PSCI emulation (SMC conduit). The expected lines below are what it
answered. That proves the register convention, the decode and the page against a real SMC conduit; it proves
nothing about the unit's firmware, whose answers, and whether it answers at all after the Secure-Launch bounce,
are UNKNOWN (hardware NOT RUN). Evidence: EXPERIMENTAL (QEMU only). SKIPs, never passes, without clang, lld-link,
make, qemu-system-aarch64 or an EDK2 AArch64 firmware image. Writes only under build/sp11-payload-qemu-chain/."""
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


qemu = load_module('sp11_payload_qemu_base', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-chain'
sha, script, manifest, Boot, bands = qemu.sha, qemu.script, qemu.manifest, qemu.Boot, qemu.bands
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'
FONT_LINE = qemu.FONT_LINE

# What QEMU 11.1.3's PSCI emulation answered at EL2 (OBSERVED on QEMU only).
PSCI_UNDER_QEMU = [
    'PAYLOAD PSCI MPIDR_EL1=0X80000000',
    'PAYLOAD PSCI NEXT VERSION',
    'PAYLOAD PSCI VERSION PSCI_VERSION=0X10001:V1.1 MIGRATE_INFO_TYPE=0X2:TOS_MP',
    'PAYLOAD PSCI NEXT FEATURES',
    'PAYLOAD PSCI FEATURES CPU_SUSPEND=0X0 CPU_OFF=0X0 CPU_ON=0X0 AFFINITY_INFO=0X0 MIGRATE_INFO_TYPE=0X0',
    'PAYLOAD PSCI FEATURES SYSTEM_OFF=0X0 SYSTEM_RESET=0X0 PSCI_FEATURES=0X0',
    'PAYLOAD PSCI FEATURES SYSTEM_SUSPEND=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)',
    'PAYLOAD PSCI FEATURES SYSTEM_RESET2=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)',
    'PAYLOAD PSCI NEXT AFFINITY',
    'PAYLOAD PSCI AFFINITY 0X0=0X0:ON 0X100=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)',
] + [f'PAYLOAD PSCI AFFINITY 0X{mpidr:X}=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)'
     for mpidr in (0x200, 0x300, 0x10000, 0x10100, 0x10200, 0x10300, 0x20000, 0x20100, 0x20200, 0x20300)] + [
    'PAYLOAD PSCI NEXT SMCCC',
    'PAYLOAD PSCI SMCCC SMCCC_VERSION=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)',
]


def chain_stick(entries, tamper=None):
    """The files of a stick for a chain: `entries` is [(file name as the manifest spells it, bytes)] in manifest
    order; `tamper` maps a name to the other bytes the stick holds, whose digest the manifest does not have."""
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = (tamper or {}).get(name, data)
    return files


def flipped(data):
    """The file with the byte at 100 changed, as the damaging fixture and the damaged runner leave it."""
    return data[:100] + bytes([data[100] ^ 1]) + data[101:]


def digest(data):
    return sha(data)[:16].upper()


def done_line(index, value, stack='OK', loads=0, faults=0, refused=0, lines=1, dropped=0):
    return (f'PAYLOAD DONE INDEX={index} RETURN=0X{value:X} STACK={stack} LOADS={loads} FAULTS={faults} '
            f'REFUSED={refused} LINES={lines} DROPPED={dropped}')


class ChainQemu(unittest.TestCase):
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
        cls.state = (out / 'payloads' / 'state.bin').read_bytes()
        cls.psci = (out / 'payloads' / 'psci.bin').read_bytes()
        # Marks say who they are (the id is a compile-time constant, so each has bytes and a hash of its own; mark9
        # stands in for a data file that must never be called). The corrupting fixture damages manifest index 2.
        cls.fixture = {}
        for name, source, flags in (
                ('mark1', 'mark', ('-DFIXTURE_MARK_ID=1',)), ('mark2', 'mark', ('-DFIXTURE_MARK_ID=2',)),
                ('mark3', 'mark', ('-DFIXTURE_MARK_ID=3',)), ('mark9', 'mark', ('-DFIXTURE_MARK_ID=9',)),
                ('lines', 'lines', ()), ('budget', 'budget', ()), ('overflow', 'overflow', ()), ('hang', 'hang', ()),
                ('fault', 'fault', ()), ('corrupt', 'corrupt', ('-DFIXTURE_CORRUPT_TARGET=2',))):
            result, _, flat = lib.build_payload(ROOT / 'tools' / 'testdata' / f'sp11-payload-fixture-{source}.c', BUILD / 'fixtures',
                                                name=name, extra_cflags=flags)
            if result.returncode:
                raise RuntimeError(f'fixture {name} failed:\n{result.stderr[-1500:]}')
            cls.fixture[name] = flat.read_bytes()
        # What memory the bounce did not preserve, or a payload that scribbled on another, would look like to the
        # hash taken before the second call: the second payload's byte 100 changes after the first has returned.
        cls.damaged = qemu.PayloadQemu._variant(
            'damage', 'platform/uefi/sp11-payload-run.c', '        result->called++;\n',
            '        result->called++;\n        if (index == 0) ((volatile uint8_t *)(uintptr_t)loaded->file[1].base)[100] ^= 1;\n',
            qemu.SP11_VARS)
        cls.drawn = qemu.PayloadQemu._variant('draw', *qemu.DRAW_EDIT, qemu.SP11_VARS)
        cls.runs = cls._boots()

    @classmethod
    def _boots(cls):
        f = cls.fixture
        m1, m2, m3, m9 = f['mark1'], f['mark2'], f['mark3'], f['mark9']
        three = chain_stick([('M1.BIN', m1), ('M2.BIN', m2), ('M3.BIN', m3)])

        def second_is(name):
            return chain_stick([('M1.BIN', m1), (name.upper() + '.BIN', f[name]), ('M3.BIN', m3)])

        stopped = 'REASON=%s\n'
        boots = [
            Boot('three', three, script(), marker=done_line(2, 0x103) + '\n'),
            Boot('mixed', chain_stick([('M1.bin', m1), ('TRAP.DAT', m9), ('M2.Bin', m2), ('M3.bin', m3)]), script(),
                 marker=done_line(3, 0x103) + '\n'),
            Boot('five', chain_stick([('A.BIN', m1), ('B.BIN', m2), ('C.BIN', m3), ('D.BIN', m1), ('E.BIN', m2)]), script(),
                 marker=done_line(4, 0x102) + '\n'),
            Boot('badhash', chain_stick([('M1.BIN', m1), ('M2.BIN', m2)], tamper={'M2.BIN': flipped(m2)}), script()),
            Boot('stop', three, script(), image=cls.damaged, marker=stopped % 'HASH_AT_EL2'),
            Boot('corrupt', chain_stick([('M1.BIN', m1), ('C.BIN', f['corrupt']), ('M3.BIN', m3)]), script(),
                 marker=stopped % 'HASH_AT_EL2'),
            Boot('overflow', second_is('overflow'), script(), marker=stopped % 'STACK_OVERFLOW'),
            Boot('hang', second_is('hang'), script(), marker=f'PAYLOAD CALL 1 {digest(f["hang"])}\n', shot_after=6),
            Boot('hangdraw', second_is('hang'), script(), marker=f'PAYLOAD CALL 1 {digest(f["hang"])}\n', shot_after=6,
                 image=cls.drawn),
            Boot('fault', second_is('fault'), script(), marker=f'PAYLOAD CALL 1 {digest(f["fault"])}\n', shot_after=6),
            Boot('budget', chain_stick([('L1.BIN', f['lines']), ('B1.BIN', f['budget']), ('L2.BIN', f['lines']),
                                        ('B2.BIN', f['budget'])]), script(), marker=done_line(3, 0x4100, loads=4096, refused=4) + '\n'),
            Boot('psci', chain_stick([('STATE.BIN', cls.state), ('PSCI.BIN', cls.psci)]), script(), shot_after=2,
                 marker=done_line(1, 0, lines=22) + '\n'),
            Boot('file0', chain_stick([('STATE.DAT', cls.state), ('M1.BIN', m1)]), script()),
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            return {b.name: b for b in pool.map(lambda b: qemu.run_boot(b, cls.runner, cls.firmware), boots)}

    # -- what a boot printed ----------------------------------------------------------------------------------------
    def text(self, name):
        return self.runs[name].text

    def halves(self, name):
        text = self.text(name)
        self.assertIn(AFTER, text, f'{name}: the bounce was never confirmed; inspect {BUILD / (name + ".log")}')
        return text.split(AFTER, 1)

    def trace(self, name):
        """The runner's lines and the fixtures' lines after the bounce, in the order printed, without the notes the
        runner replays there."""
        after = self.halves(name)[1]
        return [line for line in after.split('\n') if line.startswith(('PAYLOAD ', 'FIXTURE '))
                and not line.startswith(('PAYLOAD LOADED', 'PAYLOAD READY'))]

    def loaded(self, name):
        """{manifest index: (base, bytes, memory type)} from the notes printed before the bounce."""
        notes = re.findall(r'PAYLOAD LOADED INDEX=(\d+) BASE=0X([0-9A-F]+) BYTES=(\d+) SHA=[0-9A-F]{16} TYPE=(\d)', self.halves(name)[0])
        return {int(i): (int(base, 16), int(size), int(kind)) for i, base, size, kind in notes}

    def assert_marks(self, name, calls):
        """`calls` is [(manifest index, mark id, bytes)] in the order they must have run: the trace begins with VERIFY,
        CALL, the mark's own line (the base and size it was called with) and DONE for each. Returns what follows."""
        loaded, want = self.loaded(name), []
        for index, ident, data in calls:
            want += ['PAYLOAD VERIFY=OK', f'PAYLOAD CALL {index} {digest(data)}',
                     f'FIXTURE MARK ID=0X{ident:X} BASE=0X{loaded[index][0]:X} SIZE=0X{len(data):X}', done_line(index, 0x100 + ident)]
        trace = self.trace(name)
        self.assertEqual(trace[:len(want)], want)
        return trace[len(want):]

    def swept(self, name):
        rows = re.findall(r'SP11 EBS: r(\d+) (\w+) base=0x[0-9A-F]+ size=0x[0-9A-F]+ desc=(\d+) type=(\d+) attr=(0x[0-9A-F]+) '
                          r'contained=(yes|NO)', self.halves(name)[1])
        for _, label, desc, kind, attribute, contained in rows:
            self.assertEqual((desc, contained), ('1', 'yes'), label)
            self.assertIn(int(kind), qemu.SWEPT_TYPES, label)
            self.assertTrue(int(attribute, 16) & qemu.EFI_MEMORY_WB, label)
        return [(label, int(kind)) for _, label, _, kind, _, _ in rows]

    def assert_refused(self, name, line_pattern):
        text = self.text(name)
        self.assertIn('Q1N1_SHELL_RETURN_OK', text, f'{name}: the script did not finish')
        self.assertRegex(text, line_pattern)
        for absent in ('Leaving firmware now', 'EL2 CONFIRMED', 'EXITBOOTSERVICES FAILED', 'PAYLOAD CALL', 'FIXTURE MARK'):
            self.assertNotIn(absent, text)
        statuses = re.findall(r'Q1N1_STATUS=(\S+)', text)
        self.assertTrue(statuses, 'the Shell did not report a status')
        self.assertEqual(statuses[-1].lower(), '0x15', 'a refusal returns EFI_ABORTED to the Shell')

    # -- order, base and size, kind -------------------------------------------------------------------------------------
    def test_three_payloads_run_in_manifest_order_each_with_its_own_base_and_size(self):
        rest = self.assert_marks('three', [(0, 1, self.fixture['mark1']), (1, 2, self.fixture['mark2']), (2, 3, self.fixture['mark3'])])
        self.assertEqual(rest, [], 'the runner printed something after the last payload that is not a stop')
        self.assertIn('PAYLOAD READY FILES=3 RANGES=6 CODE=3', self.halves('three')[0])
        bases = [base for base, _, _ in self.loaded('three').values()]
        self.assertEqual(len(set(bases)), 3, 'two files share a base')

    def test_data_is_never_called_and_the_extension_is_read_without_regard_to_case(self):
        f = self.fixture
        rest = self.assert_marks('mixed', [(0, 1, f['mark1']), (2, 2, f['mark2']), (3, 3, f['mark3'])])
        self.assertEqual(rest, [])
        text = self.text('mixed')
        self.assertNotIn('ID=0X9', text, 'the data file, which holds a working payload, was called')
        self.assertEqual(sum(line.startswith('PAYLOAD CALL ') for line in self.trace('mixed')), 3)
        self.assertIn('PAYLOAD READY FILES=4 RANGES=7 CODE=3', self.halves('mixed')[0])
        self.assertEqual([kind for _, _, kind in self.loaded('mixed').values()], [1, 2, 1, 1], 'code is EfiLoaderCode, data is EfiLoaderData')
        self.assertEqual([label for label, _ in self.swept('mixed')], ['image', 'map', 'preload', 'payload', 'file1', 'file2', 'file3'])

    def test_five_files_use_all_eight_declared_ranges_and_all_five_payloads_run(self):
        f = self.fixture
        rest = self.assert_marks('five', [(0, 1, f['mark1']), (1, 2, f['mark2']), (2, 3, f['mark3']), (3, 1, f['mark1']), (4, 2, f['mark2'])])
        self.assertEqual(rest, [])
        self.assertIn('PAYLOAD READY FILES=5 RANGES=8 CODE=5', self.halves('five')[0])
        self.assertIn('SP11 EBS: set_variable=0x0 ranges=8 chunk=0x100000', self.halves('five')[0])
        rows = self.swept('five')
        self.assertEqual([label for label, _ in rows], ['image', 'map', 'preload', 'payload', 'file1', 'file2', 'file3', 'file4'])
        self.assertEqual([kind for label, kind in rows if label.startswith(('payload', 'file'))], [1] * 5)

    def test_a_manifest_whose_first_file_is_data_is_refused_before_the_bounce(self):
        self.assert_refused('file0', r'PAYLOAD REFUSED=FILE0_NOT_BIN')

    # -- stops --------------------------------------------------------------------------------------------------------
    def test_a_hash_that_is_wrong_before_the_bounce_refuses_the_whole_chain(self):
        good, bad = digest(self.fixture['mark2']), digest(flipped(self.fixture['mark2']))
        self.assert_refused('badhash', rf'PAYLOAD REFUSED=HASH INDEX=1 WANT={good} HAVE={bad}')
        self.assertNotIn('FIXTURE', self.text('badhash'), 'the first payload ran although the chain was refused')

    def test_a_payload_whose_hash_changes_after_the_bounce_is_not_called_and_ends_the_chain(self):
        f = self.fixture
        # The same three files with the stock runner run to the end (test_three_...): the stop below is the damage.
        rest = self.assert_marks('stop', [(0, 1, f['mark1'])])
        self.assertEqual(rest, [f'PAYLOAD REFUSED=HASH_AT_EL2 INDEX=1 WANT={digest(f["mark2"])} HAVE={digest(flipped(f["mark2"]))}',
                                'PAYLOAD CHAIN STOPPED INDEX=1 REASON=HASH_AT_EL2'])
        self.assertNotIn('ID=0X2', self.text('stop'))
        self.assertNotIn('ID=0X3', self.text('stop'), 'a payload after the stop was called')

    def test_a_payload_that_damages_a_later_one_ends_the_chain_at_the_damaged_one(self):
        f = self.fixture
        rest = self.assert_marks('corrupt', [(0, 1, f['mark1'])])
        self.assertEqual(rest, ['PAYLOAD VERIFY=OK', f'PAYLOAD CALL 1 {digest(f["corrupt"])}',
                                'FIXTURE CORRUPT FLIPPED A BYTE OF A LATER PAYLOAD', done_line(1, 0),
                                f'PAYLOAD REFUSED=HASH_AT_EL2 INDEX=2 WANT={digest(f["mark3"])} HAVE={digest(flipped(f["mark3"]))}',
                                'PAYLOAD CHAIN STOPPED INDEX=2 REASON=HASH_AT_EL2'])
        self.assertNotIn('ID=0X3', self.text('corrupt'))

    def test_a_payload_that_overwrites_its_stack_guard_ends_the_chain(self):
        f = self.fixture
        rest = self.assert_marks('overflow', [(0, 1, f['mark1'])])
        self.assertEqual(rest, ['PAYLOAD VERIFY=OK', f'PAYLOAD CALL 1 {digest(f["overflow"])}',
                                'FIXTURE OVERFLOW WROTE THE LOWEST STACK WORD', done_line(1, 7, stack='OVERFLOW'),
                                'PAYLOAD CHAIN STOPPED INDEX=1 REASON=STACK_OVERFLOW'])
        self.assertNotIn('ID=0X3', self.text('overflow'))

    # -- a payload that hangs or faults ------------------------------------------------------------------------------------
    def test_a_second_payload_that_never_returns_is_named_by_the_last_line_with_the_first_payloads_lines_before_it(self):
        f = self.fixture
        rest = self.assert_marks('hang', [(0, 1, f['mark1'])])
        self.assertEqual(rest, ['PAYLOAD VERIFY=OK', f'PAYLOAD CALL 1 {digest(f["hang"])}'], 'something was printed after the hanging call')
        self.assertNotIn('PAYLOAD DONE INDEX=1', self.text('hang'))
        self.assertNotIn('ID=0X3', self.text('hang'))

    def test_the_first_payloads_lines_are_still_on_the_page_when_the_second_one_hangs(self):
        # The stock runner has no rows to draw on QEMU's 800x600 screen (see PayloadQemu); the copy that forces a region
        # draws every line the runner and the fixtures printed up to the hang: the three notes and READY, then VERIFY,
        # CALL, the mark and DONE of the first payload, then VERIFY and CALL of the second (OBSERVED: one band each).
        stock, drawn = self.runs['hang'].shot, self.runs['hangdraw'].shot
        self.assertIsNotNone(stock)
        self.assertIsNotNone(drawn)
        self.assertEqual(stock[:2], drawn[:2])
        self.assertEqual(self.assert_marks('hangdraw', [(0, 1, self.fixture['mark1'])])[-1], f'PAYLOAD CALL 1 {digest(self.fixture["hang"])}')
        printed = [line for line in self.halves('hangdraw')[1].split('\n') if line.startswith(('PAYLOAD ', 'FIXTURE '))]
        self.assertEqual(len(printed), 10)
        self.assertGreaterEqual(bands(drawn, stock), len(printed) - 1, 'fewer rows of text differ than the runner printed before the hang')

    def test_a_second_payload_that_faults_lands_in_q1ns_fault_page_after_the_first_payloads_lines(self):
        f = self.fixture
        rest = self.assert_marks('fault', [(0, 1, f['mark1'])])
        self.assertEqual(rest, ['PAYLOAD VERIFY=OK', f'PAYLOAD CALL 1 {digest(f["fault"])}'])
        self.assertNotIn('PAYLOAD DONE INDEX=1', self.text('fault'))
        width, _, pixels = self.runs['fault'].shot
        quiet = self.runs['hang'].shot[2]
        at = (2 * width + width // 2) * 3
        top, other = pixels[at:at + 3], quiet[at:at + 3]
        self.assertNotEqual(top, other, 'the top rows are the same as for a payload that is still running')
        self.assertGreater(max(top), 200)
        self.assertLess(sorted(top)[1], 120, 'the fault page paints a red bar across the top')

    # -- the budgets --------------------------------------------------------------------------------------------------
    def test_every_payload_gets_the_whole_of_the_line_and_load_budgets(self):
        f, want = self.fixture, []
        for index, kind in enumerate(('lines', 'budget', 'lines', 'budget')):
            want += ['PAYLOAD VERIFY=OK', f'PAYLOAD CALL {index} {digest(f[kind])}']
            if kind == 'lines':
                want += [f'FIXTURE LINE 0X{i:X}' for i in range(40)] + [done_line(index, 0x1234, lines=40, dropped=5)]
            else:
                want += ['FIXTURE BUDGET ANSWERED=0X1000 REFUSED=0X4', done_line(index, 0x4100, loads=4096, refused=4)]
        self.assertEqual(self.trace('budget'), want)

    # -- the psci payload under QEMU --------------------------------------------------------------------------------------
    def test_state_then_psci_run_to_the_end_and_psci_prints_what_qemus_psci_answered(self):
        trace = self.trace('psci')
        at = trace.index(f'PAYLOAD CALL 1 {digest(self.psci)}')
        state = trace[:at - 1]
        self.assertEqual(state[:2], ['PAYLOAD VERIFY=OK', f'PAYLOAD CALL 0 {digest(self.state)}'])
        self.assertEqual([line.split('=')[0][len('PAYLOAD STATE '):] for line in state[2:-1]], qemu.STATE_KEYS)
        self.assertEqual(state[-1], done_line(0, 0, lines=21))
        self.assertEqual(trace[at - 1], 'PAYLOAD VERIFY=OK')
        self.assertEqual(trace[at + 1:], PSCI_UNDER_QEMU + [done_line(1, 0, lines=22)])
        self.assertIn('PAYLOAD READY FILES=2 RANGES=5 CODE=2', self.halves('psci')[0])
        self.assertNotIn('SYNCHRONOUS EXCEPTION', self.text('psci'), 'smc faulted: QEMU did not answer')
        width, _, pixels = self.runs['psci'].shot
        at = (2 * width + width // 2) * 3
        self.assertEqual(pixels[at:at + 3], self.runs['hang'].shot[2][at:at + 3], "q1n1's fault page is up: the top bar is not the quiet one")

    # -- every boot ------------------------------------------------------------------------------------------------------
    def test_every_payload_line_is_in_the_page_font_and_within_a_hundred_characters(self):
        for name, boot in self.runs.items():
            for line in boot.text.split('\n'):
                if line.startswith(('PAYLOAD ', 'FIXTURE ')):
                    self.assertIsNotNone(FONT_LINE.fullmatch(line), f'{name}: {line}')

    def test_no_boot_changes_a_file_of_the_stick_or_faults_unless_it_was_made_to(self):
        for name, boot in self.runs.items():
            self.assertFalse(boot.changed, f'{name}: a file on the stick changed')
            if name != 'fault':
                self.assertNotIn('SYNCHRONOUS EXCEPTION', boot.text, name)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
