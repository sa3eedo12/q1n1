#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The el1trap payload of the Surface Pro 11 stick payload runner at EL2 under QEMU's EDK2 shell (docs/SP11-PAYLOAD-EL1TRAP.md).

    python3 tools/test-q1n1-sp11-payload-qemu-el1trap.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables) and boots QEMU on `virt,virtualization=on,
gic-version=3` with sticks that carry the real el1trap.bin, in these worlds (the stick layout and helpers are those of
test-q1n1-sp11-payload-qemu.py, the boot driver is tools/sp11_payload_ecv_lib.py's because it needs a CPU model and the time each
line appeared). This is the only place the assembly -- the HVC probe, the VBAR_EL2 swap, the ERET to an EL1 stub, the handler, both
vector tables -- runs, and it runs on QEMU's model of a core, not on the unit:
  * a chain `state`, `el1trap`, `state` on `-cpu max` (ECV = 2): the EL1 stub's reads of CNTVCT_EL0 and CNTV_CTL_EL0 and the control
    read of CNTPCT_EL0 trap to EL2 with the ESR the document derives (class 0x18, the ISS of each register), the read of CNTFRQ_EL0
    does not, the verdict is TRAPS_EFFECTIVE, everything is put back, and the two `state` pages are identical;
  * the payload alone on `-cpu cortex-a76` (ECV = 0): only the control traps, TRAPS_INERT, the bits read back as zero;
  * the same chain with a copy of el1trap.c edited once (each edit asserted to apply once) in each way an excursion can go wrong:
    the probe HVC undefined (no EL1 code runs, nothing but VBAR_EL2 was changed), the stub's first instruction UNDEFINED or an SVC
    (reported by an EL1 vector through HVC #1), the stub's last an HVC with another immediate, the stub looping on trapping reads
    (the entry budget), the deadline passed, two registers never put back (RESTORED=NO, the return value 3, and the next `state`
    shows them: the failure is not hidden);
  * a stub that never returns: the last line on the page is NEXT EL1 EXCURSION, nothing follows it (the residual risk the document
    names: an excursion that does not end cannot be bounded);
  * a handler that itself faults: after 24 entries it puts the runner's VBAR_EL2 back and executes UDF, and the runner's own fault
    page appears.
What it proves: the real binary at a real EL2 with its MMU on enters EL1 and comes back, and prints the pages the host model prints.
What it does not prove: the unit's EL3 (whether SCR_EL3.ECVEn lets the bits stick, whether the traps are effective there -- that is
the question), the unit's counter, or that HVC works there (the probe asks). QEMU 11.1.3's `-cpu max` implements FEAT_ECV and its
EL1TVT and EL1TVCT fields; `-cpu cortex-a76` has none. Hardware NOT RUN. Evidence: EXPERIMENTAL (QEMU only).

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image. SP11_EL1TRAP_QEMU_ONLY
(comma-separated boot names) runs a subset for debugging; the assertions of the others then SKIP. Writes only under
build/sp11-payload-qemu-el1trap/ (short names: a socket path may not exceed 104 characters)."""
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

BUILD = ROOT / 'build' / 'sp11-payload-qemu-el1trap'
SOURCE = ROOT / 'payloads' / 'el1trap.c'
PREFIX = 'PAYLOAD EL1TRAP '
HEX = r'0X[0-9A-F]+'
ONLY = {name for name in os.environ.get('SP11_EL1TRAP_QEMU_ONLY', '').split(',') if name}
STUB_FIRST = '"    mrs x0, cntvct_el0\\n"'
STUB_LAST = '"    hvc #0\\n"'
PUT_BACK = '    for (unsigned i = 0; i <= R_VBAR1; i++) write_register(i, r->saved[i]);'
RETRY = '        if (w->restored[i] == r->saved[i]) continue;\n        write_register(i, r->saved[i]);\n'
# One source edit each, every one of which must apply exactly once (Builder asserts it).
VARIANTS = {
    'probe': [('"    hvc #2\\n"', '"    udf #0\\n"')],                       # the probe's HVC is UNDEFINED
    'udf': [(STUB_FIRST, '"    udf #0\\n"')],                              # the stub's first instruction is UNDEFINED at EL1
    'svc': [(STUB_FIRST, '"    svc #0\\n"')],
    'hvc5': [(STUB_LAST, '"    hvc #5\\n"')],
    'loop': [(STUB_LAST, '"    b el1trap_stub\\n"')],                      # trapping reads for ever: the entry budget
    'hang': [(STUB_LAST, '"    b .\\n"')],                                 # EL1 never comes back
    'late': [('    e->deadline = r->a->ops.counter() + r->hz * DEADLINE_S;\n',                  # the excursion's deadline has passed at its first entry
              '    e->deadline = r->a->ops.counter() + (mode == MODE_EXCURSION ? 0 : r->hz * DEADLINE_S);\n')],
    'fatal': [('"    b.hi el1trap_fatal\\n"', '"    b.hi el1trap_fatal\\n"\n    "    udf #0\\n"')],     # the handler faults
    'lost': [(PUT_BACK, PUT_BACK.replace('i = 0', 'i = 2')), (RETRY, RETRY.replace('if (w->restored[i] == r->saved[i]) continue;', 'if (1) continue;'))],
}
STATE_KEYS = ('HCR_EL2', 'SCTLR_EL2', 'TCR_EL2', 'TTBR0_EL2', 'MAIR_EL2', 'VBAR_EL2', 'CPTR_EL2', 'CNTHCTL_EL2', 'CNTFRQ_EL0', 'DAIF', 'SPSEL')
EFFECTIVE = [r'CURRENTEL=0X8 HCR_EL2=0X8000038 E2H=0X0', r'DAIF=0X3C0 SPSEL=0X1 CNTFRQ_EL0=0X3B9ACA00', rf'ID_AA64MMFR0_EL1={HEX} ECV=0X2',
             rf'ID_AA64PFR0_EL1={HEX} EL1=0X[12]', rf'OLD CNTHCTL_EL2=0X3 SCTLR_EL1={HEX}', rf'OLD VBAR_EL1={HEX} VBAR_EL2={HEX}',
             rf'STUB_OFFSET={HEX} EL1_VECTORS_OFFSET={HEX} EL2_VECTORS_OFFSET={HEX}', 'NEXT EL1 EXCURSION AFTER 8 S', 'HVC_AT_EL2=OK',
             'WRITES HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000 SCTLR_EL1=0X30500800', 'NEXT EL1 EXCURSION', 'READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000',
             rf'READBACK SCTLR_EL1=0X30500800 VBAR_EL1_OFFSET={HEX}', 'CNTVCT_EL0 TRAPPED EC=0X18 ISS=0X34F801 ISS_OK=YES',
             'CNTV_CTL_EL0 TRAPPED EC=0X18 ISS=0X32F827 ISS_OK=YES', 'CNTFRQ_EL0 NOT_TRAPPED VALUE=0X3B9ACA00',
             'CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES', 'VERDICT=TRAPS_EFFECTIVE BITS13_14_IN_READBACK=YES',
             'EXCURSION OK ENTRIES=0X4 TRAPS=0X3', 'RESTORED=YES']


def state_values(run, index):
    """The KEY=VALUE pairs of the index-th `state` page (0 for the first, 1 for the second) of a run."""
    lines = [line for line in run.text.split('\n') if line.startswith('PAYLOAD STATE ')]
    per = len(lines) // 2
    return dict(line[len('PAYLOAD STATE '):].split('=', 1) for line in lines[index * per:(index + 1) * per])


class El1trapQemu(unittest.TestCase):
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
        cls.shipped, state = payload('el1trap'), payload('state')
        builder = ecv.Builder(BUILD / 'variants')
        cls.variants = {}
        for name, edits in VARIANTS.items():
            done, _, flat = builder.build('el1trap', name, edits)
            if done.returncode:
                raise RuntimeError(f'{name}: {done.stderr[-1500:]}')
            cls.variants[name] = Path(flat).read_bytes()
        chain = lambda name, data, **kw: ecv.Run(name, ecv.stick([('STATE.BIN', state), ('EL1TRAP.BIN', data), ('STATE2.BIN', state)]),  # noqa: E731
                                                  marker=ecv.PREFIX_DONE + '2 ', **kw)
        runs = [chain('max', cls.shipped), ecv.Run('a76', ecv.stick([('EL1TRAP.BIN', cls.shipped)]), cpu='cortex-a76')]
        runs += [chain(name, cls.variants[name]) for name in ('probe', 'udf', 'svc', 'hvc5', 'loop', 'late', 'lost')]
        runs += [ecv.Run('hang', ecv.stick([('EL1TRAP.BIN', cls.variants['hang'])]), marker=PREFIX + 'NEXT EL1 EXCURSION\n', grace=25, shot_after=1),
                 ecv.Run('fatal', ecv.stick([('EL1TRAP.BIN', cls.variants['fatal'])]), marker=PREFIX + 'NEXT EL1 EXCURSION AFTER 8 S\n', shot_after=24)]
        runs = [run for run in runs if not ONLY or run.name in ONLY]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            cls.runs = {run.name: run for run in pool.map(lambda r: ecv.run_boot(r, BUILD, cls.runner, cls.firmware), runs)}

    def run_of(self, name):
        if name not in self.runs:
            self.skipTest(f'{name} was not booted (SP11_EL1TRAP_QEMU_ONLY)')
        run = self.runs[name]
        self.assertIn(run.marker, run.text, f'{name} did not finish:\n{run.text[-1800:]}')
        return run

    def done(self, run, index):
        return [line for line in run.text.split('\n') if line.startswith(f'{ecv.PREFIX_DONE}{index} ')][0]

    # -- -cpu max: the traps are effective -------------------------------------------------------------------------------------
    def test_with_ecv_the_ecv_reads_and_the_control_trap_with_the_documents_iss_and_the_page_is_the_models(self):
        run = self.run_of('max')
        page = run.lines(PREFIX)
        self.assertEqual(len(page), len(EFFECTIVE), page)
        for line, pattern in zip(page, EFFECTIVE):
            self.assertRegex(line, f'^{pattern}$')
        stub, el1, el2 = (int(re.search(rf'{name}_OFFSET=0X([0-9A-F]+)', page[6]).group(1), 16) for name in ('STUB', 'EL1_VECTORS', 'EL2_VECTORS'))
        self.assertEqual((el1 - el2, el1 % 2048, el2 % 2048), (2048, 0, 0), 'both tables 2 KiB aligned inside the image, the EL1 table 2 KiB on')
        self.assertTrue(el1 < stub < el1 + 2048 + 256, 'the stub follows the EL1 table')
        self.assertEqual(int(re.search(r'VBAR_EL1_OFFSET=0X([0-9A-F]+)', page[12]).group(1), 16), el1, 'VBAR_EL1 was set to the EL1 table')
        self.assertRegex(self.done(run, 1), r'RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=20 DROPPED=0')
        self.assertFalse(run.changed, 'a file of the stick changed')

    def test_every_register_the_state_payload_prints_is_the_same_before_and_after_and_the_wait_is_real(self):
        run = self.run_of('max')
        before, after = state_values(run, 0), state_values(run, 1)
        self.assertTrue(set(STATE_KEYS) <= set(before), sorted(before))
        self.assertEqual(before, after)
        self.assertEqual((before['HCR_EL2'], before['CNTHCTL_EL2']), ('0X8000038', '0X3'))
        self.assertEqual(len(re.findall(r'PAYLOAD DONE INDEX=\d RETURN=0X0 ', run.text)), 3)
        seconds = ecv.wait_seconds(run, PREFIX + 'NEXT EL1 EXCURSION AFTER 8 S', PREFIX + 'HVC_AT_EL2=OK')
        self.assertTrue(7.0 <= seconds <= 40.0, f'{seconds:.2f} s between the NEXT line and the probe result (QEMU follows the host clock)')

    # -- -cpu cortex-a76: the ECV bits are RES0 ----------------------------------------------------------------------------------
    def test_without_ecv_only_the_control_traps_the_verdict_is_inert_and_the_bits_read_back_as_zero(self):
        run = self.run_of('a76')
        page = run.lines(PREFIX)
        self.assertEqual(len(page), 20, page)
        self.assertRegex(page[2], rf'^ID_AA64MMFR0_EL1={HEX} ECV=0X0$')
        self.assertEqual(page[11], 'READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=0X0')
        self.assertRegex(page[13], rf'^CNTVCT_EL0 NOT_TRAPPED VALUE={HEX}$')
        self.assertRegex(page[14], rf'^CNTV_CTL_EL0 NOT_TRAPPED VALUE={HEX}$')
        self.assertRegex(page[15], rf'^CNTFRQ_EL0 NOT_TRAPPED VALUE={HEX}$')
        self.assertEqual(page[16], 'CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES')
        self.assertEqual(page[17:], ['VERDICT=TRAPS_INERT BITS13_14_IN_READBACK=NO', 'EXCURSION OK ENTRIES=0X2 TRAPS=0X1', 'RESTORED=YES'])
        self.assertRegex(run.text, r'PAYLOAD DONE INDEX=0 RETURN=0X0 ')

    # -- the ways an excursion can go wrong, each reported and each put back ---------------------------------------------------
    def check_restored(self, run):
        before, after = state_values(run, 0), state_values(run, 1)
        self.assertEqual(before, after, 'the machine is left as found')
        self.assertEqual(run.lines(PREFIX)[-1], 'RESTORED=YES')

    def test_an_undefined_hvc_at_el2_runs_no_el1_code_and_changes_nothing(self):
        run = self.run_of('probe')
        page = run.lines(PREFIX)
        self.assertEqual(page[8], 'HVC_AT_EL2=FAILED EL2_EXCEPTION ENTRIES=0X1 VECTOR=0X4')
        self.assertRegex(page[9], rf'^HVC_AT_EL2 ESR_EL2=0X2000000 ELR_EL2={HEX}$')
        self.assertEqual(page[10:], ['REFUSED=HVC_AT_EL2', 'RESTORED=YES'])
        self.assertFalse([line for line in page if line.startswith(('WRITES', 'READBACK'))])
        self.assertRegex(self.done(run, 1), r'RETURN=0X2 ')
        self.check_restored(run)

    def test_an_exception_at_el1_is_caught_by_the_payloads_vector_and_reported_through_hvc_1(self):
        for name, esr in (('udf', '0X2000000'), ('svc', '0X56000000')):
            with self.subTest(stub=name):
                run = self.run_of(name)
                page = run.lines(PREFIX)
                self.assertEqual(page[13], 'EXCURSION EL1_EXCEPTION ENTRIES=0X1 TRAPS=0X0 VECTOR=0X8')
                self.assertRegex(page[14], rf'^ESR_EL2=0X5A000001 ELR_EL2={HEX}$')
                self.assertRegex(page[15], rf'^FAR_EL2={HEX} SPSR_EL2={HEX}$')
                spsr = int(page[15].split('SPSR_EL2=0X')[1], 16)
                self.assertEqual(spsr & 0x3ff, 0x3c5, 'EL1h with D, A, I and F masked (PAN comes up as well: SCTLR_EL1.SPAN is clear)')
                self.assertRegex(page[16], rf'^ESR_EL1={esr} ELR_EL1={HEX}$')
                self.assertRegex(page[17], rf'^FAR_EL1={HEX} EL1_VECTOR=0X4$')
                self.assertEqual(page[18:], ['ACCESSES_NOT_CLASSIFIED', 'RESTORED=YES'])
                self.assertRegex(self.done(run, 1), r'RETURN=0X2 ')
                self.check_restored(run)

    def test_an_hvc_with_another_immediate_ends_the_excursion_with_that_reason(self):
        run = self.run_of('hvc5')
        page = run.lines(PREFIX)
        self.assertEqual(page[13], 'EXCURSION UNEXPECTED_HVC_IMM ENTRIES=0X4 TRAPS=0X3 VECTOR=0X8')
        self.assertRegex(page[14], rf'^ESR_EL2=0X5A000005 ELR_EL2={HEX}$')
        self.assertEqual(len([line for line in page if line.startswith('TRAP ESR_EL2=')]), 3)
        self.assertRegex(self.done(run, 1), r'RETURN=0X2 ')
        self.check_restored(run)

    def test_trapping_reads_for_ever_end_at_the_entry_budget(self):
        run = self.run_of('loop')
        page = run.lines(PREFIX)
        self.assertEqual(page[13], 'EXCURSION BUDGET ENTRIES=0X9 TRAPS=0X8 VECTOR=0X8')
        records = [line for line in page if line.startswith('TRAP ESR_EL2=')]
        self.assertEqual(len(records), 8)
        self.assertEqual([r.split()[1] for r in records[:3]], ['ESR_EL2=0X6234F801', 'ESR_EL2=0X6232F827', 'ESR_EL2=0X6232F861'], 'in program order')
        self.assertRegex(self.done(run, 1), r'RETURN=0X2 ')
        self.check_restored(run)

    def test_a_deadline_that_has_passed_ends_the_excursion_at_the_first_entry(self):
        run = self.run_of('late')
        self.assertEqual(run.lines(PREFIX)[13], 'EXCURSION DEADLINE ENTRIES=0X1 TRAPS=0X0 VECTOR=0X8')
        self.assertRegex(run.lines(PREFIX)[14], rf'^ESR_EL2=0X6234F801 ELR_EL2={HEX}$')
        self.assertRegex(self.done(run, 1), r'RETURN=0X2 ')
        self.check_restored(run)

    # -- a payload that cannot put everything back says so, and the next payload sees it ---------------------------------------
    def test_a_copy_that_does_not_put_hcr_and_cnthctl_back_is_loud_returns_three_and_the_next_payload_sees_it(self):
        run = self.run_of('lost')
        page = run.lines(PREFIX)
        self.assertEqual(page[-4:], ['RESTORED=NO', 'NOT_RESTORED HCR_EL2 WANT=0X8000038 NOW=0X80000000',
                                     'NOT_RESTORED CNTHCTL_EL2 WANT=0X3 NOW=0X6000', 'POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD'])
        self.assertIn('EXCURSION OK ENTRIES=0X4 TRAPS=0X3', page)
        self.assertRegex(self.done(run, 1), r'RETURN=0X3 ')
        before, after = state_values(run, 0), state_values(run, 1)
        self.assertEqual((after['HCR_EL2'], after['CNTHCTL_EL2']), ('0X80000000', '0X6000'))
        self.assertEqual({k: v for k, v in before.items() if k not in ('HCR_EL2', 'CNTHCTL_EL2')},
                         {k: v for k, v in after.items() if k not in ('HCR_EL2', 'CNTHCTL_EL2')})

    # -- what cannot be bounded, and what is -------------------------------------------------------------------------------------
    @staticmethod
    def top_bar_is_red(run):
        """The pixel the base suite looks at: the runner's fault page paints a red bar across the top of the panel."""
        width, _, pixels = run.shot
        top = pixels[(2 * width + width // 2) * 3:(2 * width + width // 2) * 3 + 3]
        return max(top) > 200 and sorted(top)[1] < 120

    def test_a_stub_that_never_returns_leaves_next_el1_excursion_as_the_last_line(self):
        run = self.run_of('hang')
        lines = [line for line in run.text.split('\n') if line.startswith('PAYLOAD ')]
        self.assertEqual(lines[-1], PREFIX + 'NEXT EL1 EXCURSION')
        self.assertNotIn('PAYLOAD DONE', run.text)
        self.assertFalse(self.top_bar_is_red(run), 'a stub that loops is not a fault: the panel is the quiet one')

    def test_a_handler_that_faults_stops_after_24_entries_and_lands_in_the_runners_fault_page(self):
        run = self.run_of('fatal')
        lines = [line for line in run.text.split('\n') if line.startswith('PAYLOAD ')]
        self.assertEqual(lines[-1], PREFIX + 'NEXT EL1 EXCURSION AFTER 8 S', 'the first entry is the probe: it faults before HVC_AT_EL2=OK')
        self.assertNotIn('PAYLOAD DONE', run.text)
        self.assertTrue(self.top_bar_is_red(run), 'the recursion ended in UDF under the runner\'s own VBAR_EL2: its fault page, not a hang')

    def test_the_shipped_binary_is_the_one_make_payloads_builds_and_every_variant_is_a_different_binary(self):
        source = SOURCE.read_text(encoding='utf-8')
        for name, edits in VARIANTS.items():
            for needle, _ in edits:
                self.assertEqual(source.count(needle), 1, f'{name}: the variant edit must apply exactly once')
            self.assertNotEqual(self.variants[name], self.shipped, name)
        self.assertEqual(self.shipped[:4], bytes.fromhex('5f2403d5'))


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
