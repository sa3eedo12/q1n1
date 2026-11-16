#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The results document of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-RESULTS.md): the page the unit showed in boot 5,
the page of boots 8 and 9 and the page of boot 11, and what the document says about them, against the usbsmmu source and the other payload
documents.

    python3 tools/test-q1n1-sp11-payload-results-doc.py

  * ResultsDocAgreement: the page is well formed (41 lines, each in the page font and at most 100 characters) and each `DONE` line
    counts the lines between its `CALL` and itself; the register table of docs/SP11-PAYLOAD-USBSMMU.md gives, for every register boot 5
    read, the value on the page; the decoded numbers of the prose are what the page's raw registers decode to; the timer inference (the
    58 lines of boot 4, the 14th line of the timer payload) is the arithmetic of the page's counts and of the lines
    docs/SP11-PAYLOAD-TIMER.md prints; the claims stay at one unit and a few boots with the inferences labelled (the restart: cause
    UNKNOWN, `UPTIME` counted from before the chain, the restart probe's times UNKNOWN or INFERRED and no window claimed; the restart
    control with `psci` alone: the runner flow alone is not the cause, INFERRED strongly, and its payload and lines are boot 5's; the
    runner lines are the ones of docs/SP11-PAYLOAD-CPUON.md); the page of boots 8 and 9 (36 lines of `hashbig` and `el2mem`) is well
    formed, carries the numbers the unit printed and agrees with the arithmetic of its own values and with the rest of the section
    (the declared ranges, the placement of the file, the timing), with the writability of the bank, the cache clean and the EL3
    emulation of the three reads labelled as unknown or inferred and no VERIFIED anywhere in the section; the page of boot 11 (37 lines of
    `cnthctl` and `el1trap`) is well formed, carries the numbers the unit printed, and its values obey the monitor's formula, the ISS decode and
    the two forced bits of `SCTLR_EL1`, with the guest regime, the `SCR_EL3.ECVEn` dependence and the first-code claims labelled as the
    corrected facts say and no VERIFIED in the section; the document has its
    licence line, stays within the size limit and its links resolve; docs/SP11-PAYLOAD.md lists this suite and says what the boots
    showed.
  * ResultsDocMutants: seeded mistakes in the results document and in the register table of the usbsmmu document, each of which an
    agreement test must refuse.

Reads documents and the usbsmmu source only; writes nothing. Hardware: NOT RUN (this checks a document). Evidence: EXPERIMENTAL (host
only)."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402

DOCS = ROOT / 'docs'
RESULTS = DOCS / 'SP11-PAYLOAD-RESULTS.md'
USBSMMU = DOCS / 'SP11-PAYLOAD-USBSMMU.md'
TIMER = DOCS / 'SP11-PAYLOAD-TIMER.md'
MAIN = DOCS / 'SP11-PAYLOAD.md'
CPUON = DOCS / 'SP11-PAYLOAD-CPUON.md'
SOURCE = ROOT / 'payloads' / 'usbsmmu.c'
PAGE_FONT = re.compile(r'^[A-Z0-9 :\-./=?()_]*$')
# What the unit printed in boot 11, a piece of the page each: every one must be on the page of the results document.
UNIT11_VALUES = ('LOADED INDEX=0 BASE=0XCEA8D000 BYTES=3094 SHA=9F06B31DA4BDC395', 'LOADED INDEX=1 BASE=0XCEA88000 BYTES=15156 SHA=5074712516C1CF08',
                 'CNTHCTL_EL2 OLD=0X3 CNTFRQ_EL0=0X124F800', 'OLD=0X3 V=0X6000', 'R=0X6000 R2=0X3', 'BITS13_14_STUCK=YES R_EQ_V=YES', 'PAYLOAD CNTHCTL RESTORED=YES',
                 'ID_AA64MMFR0_EL1=0X2100122100001024 ECV=0X2', 'ID_AA64PFR0_EL1=0X1201201023111111 EL1=0X1', 'OLD CNTHCTL_EL2=0X3 SCTLR_EL1=0X100030D0198D',
                 'OLD VBAR_EL1=0XA7004000 VBAR_EL2=0XCE879000', 'STUB_OFFSET=0X1790 EL1_VECTORS_OFFSET=0X1000 EL2_VECTORS_OFFSET=0X800',
                 'WRITES HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000 SCTLR_EL1=0X30500800', 'READBACK SCTLR_EL1=0X30500980 VBAR_EL1_OFFSET=0X1000',
                 'CNTVCT_EL0 TRAPPED EC=0X18 ISS=0X34F801 ISS_OK=YES', 'CNTV_CTL_EL0 TRAPPED EC=0X18 ISS=0X32F827 ISS_OK=YES',
                 'CNTFRQ_EL0 NOT_TRAPPED VALUE=0X124F800', 'CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES',
                 'VERDICT=TRAPS_EFFECTIVE BITS13_14_IN_READBACK=YES', 'EXCURSION OK ENTRIES=0X4 TRAPS=0X3', 'PAYLOAD EL1TRAP RESTORED=YES',
                 'RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=8 DROPPED=0', 'RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=20 DROPPED=0')
# What the unit printed in boots 8 and 9, a piece of the page each: every one must be on the page of the results document.
UNIT_VALUES = ('LOADED INDEX=2 BASE=0XC3E65000 BYTES=150994944', 'FILE INDEX=2 BASE=0XC3E65000 BYTES=150994944 MIB=144',
               'ATTR FIRST=WB.OS.NS1 MID=WB.OS.NS1 LAST=WB.OS.NS1', 'HASH BYTES=150994944 TICKS=14204400 MS=739 MIBS=194',
               'MAP DESC=234 STRIDE=48 CONV_EXTENTS=17 CONV_MIB=31961', 'KEY RESULT=WB.OS.NS1 PROBES=16014',
               'BANK CONV_MIB=30720 PROBES=15361 ALL=MAPPED RESULT=WB.OS.NS1', 'ISAR2=0X10000012 MMFR1=0X111111312120 PAN=3 VH=1 HAFDBS=0',
               'MDCR_EL2=0X6', 'OSLSR_EL1 RAW=0X8 OSLK=0', 'ICC_SRE_EL2 RAW=0XF SRE=1 ENABLE=1', 'LOADS_OK=4 OF=4 HAZARD_READS=3')
# Each register of the usbsmmu document's table that boot 5 read and S0 had not, with the key it has on the page. `GBUSERRADDR1` is the high
# half of the one 64-bit `BERR` and `MAIR1` is printed only when it is not zero: they are checked on their own.
PAGE_KEYS = {'RT_ERSTSZ': 'ERSTSZ', 'DWC3_GDBGLTSSM': 'LTSSM', 'SMMU_ID1': 'ID1', 'SMMU_ID2': 'ID2', 'GR1_CBAR(n)': 'CBAR',
             'GR1_CBA2R(n)': 'CBA2R', 'CB_SCTLR': 'SCTLR', 'CB_TCR2': 'TCR2', 'CB_TTBR0': 'TTBR0', 'CB_TTBR1': 'TTBR1', 'CB_TCR': 'TCR',
             'CB_MAIR0': 'MAIR0', 'CB_FSR': 'FSR', 'CB_FAR': 'FAR', 'CB_FSYNR0': 'FSYNR0'}


def read(path):
    return path.read_text(encoding='utf-8')


class ResultsDocAgreement(unittest.TestCase):
    RESULTS = None   # a changed copy of docs/SP11-PAYLOAD-RESULTS.md, for ResultsDocMutants
    USBSMMU = None   # a changed copy of docs/SP11-PAYLOAD-USBSMMU.md, for ResultsDocMutants

    @classmethod
    def setUpClass(cls):
        cls.results = read(RESULTS) if cls.RESULTS is None else cls.RESULTS
        cls.usbsmmu = read(USBSMMU) if cls.USBSMMU is None else cls.USBSMMU
        cls.timer, cls.main, cls.cpuon = read(TIMER), read(MAIN), read(CPUON)
        cls.code = re.sub(r'/\*.*?\*/', '', read(SOURCE), flags=re.S)
        cls.flat = ' '.join(cls.results.split())        # the paragraphs are wrapped: phrases are looked up with the wraps undone

    def mentions(self, phrase, text=None):
        self.assertTrue(phrase in (self.flat if text is None else ' '.join(text.split())), f'the document does not say {phrase!r}')

    def define(self, name):
        return int(re.search(rf'#define {name} (\d+)u', self.code).group(1))

    def page(self):
        found = re.search(r'<!-- boot5-panel -->\n```\n(.*?)```\n<!-- /boot5-panel -->', self.results, re.S)
        self.assertIsNotNone(found, 'the results document has no <!-- boot5-panel --> block')
        return found.group(1).splitlines()

    def evidence(self):
        start, end = self.usbsmmu.index('<!-- usbsmmu-registers -->'), self.usbsmmu.index('<!-- /usbsmmu-registers -->')
        rows = re.findall(r'^\| `([A-Z][A-Z0-9_]*(?:\(n\))?)` \| `[^`]+` \| [^|]+? \| (.+) \|$', self.usbsmmu[start:end], re.M)
        return dict(rows)

    def test_the_page_is_well_formed_and_each_done_line_counts_the_lines_between_its_call_and_itself(self):
        lines = self.page()
        self.assertEqual(len(lines), 41)
        for line in lines:
            with self.subTest(line=line):
                self.assertTrue(line.startswith('PAYLOAD '))
                self.assertLessEqual(len(line), 100)
                self.assertRegex(line, PAGE_FONT)
        calls = [i for i, line in enumerate(lines) if line.startswith('PAYLOAD CALL ')]
        dones = [i for i, line in enumerate(lines) if line.startswith('PAYLOAD DONE ')]
        self.assertEqual((len(calls), len(dones)), (2, 2))
        self.assertEqual([line.split()[1] for line in lines[:calls[0] - 1]], ['LOADED', 'LOADED', 'READY'])
        for call, done in zip(calls, dones):
            self.assertEqual(lines[call - 1], 'PAYLOAD VERIFY=OK')
            self.assertEqual(int(re.search(r' LINES=(\d+) ', lines[done]).group(1)), done - call - 1, lines[done])
        self.assertTrue(all(line.startswith('PAYLOAD PSCI ') for line in lines[calls[0] + 1:dones[0]]))
        usbsmmu = lines[calls[1] + 1:dones[1]]
        self.assertTrue(all(line.startswith('PAYLOAD USBSMMU ') for line in usbsmmu))
        self.assertLessEqual(len(usbsmmu), self.define('LINE_CAP'))
        self.assertLessEqual(int(re.search(r' LOADS=(\d+) ', lines[dones[1]]).group(1)), self.define('LOAD_CAP'))

    def test_the_register_tables_boot_5_values_are_the_ones_on_the_page(self):
        page, evidence = '\n'.join(self.page()), self.evidence()
        for name, key in PAGE_KEYS.items():
            with self.subTest(register=name):
                on_page = re.search(rf'\b{key}=0X([0-9A-F]+)', page)
                in_table = re.search(r'boot 5 OBSERVED `0x([0-9A-F]+)`', evidence[name])
                self.assertTrue(on_page and in_table, f'{name}: {key}= on the page and a value in the table')
                self.assertEqual(int(in_table.group(1), 16), int(on_page.group(1), 16))
        self.assertIn(' BERR=0X0 ', page)
        self.assertIn('boot 5 OBSERVED 0 (`BERR=0X0`', evidence['DWC3_GBUSERRADDR1'])
        self.assertNotIn('MAIR1=', page)
        self.assertIn('boot 5 OBSERVED no `MAIR1=` on the page (INFERRED: it read 0)', evidence['CB_MAIR1'])

    def test_the_decoded_numbers_in_the_prose_are_the_pages_raw_registers(self):
        page = '\n'.join(self.page())
        value = lambda key: int(re.search(rf'\b{key}=0X([0-9A-F]+)', page).group(1), 16)  # noqa: E731
        id0, id1, id2, cbar, sctlr, fsr = (value(key) for key in ('ID0', 'ID1', 'ID2', 'CBAR', 'SCTLR', 'FSR'))
        self.mentions(f'ID0 `0x{id0:X}` ({id0 & 0xff} stream match registers), ID1 `0x{id1:X}` (NUMCB {id1 & 0xff}, '
                      f'NUMS2CB {id1 >> 16 & 0xff}, {64 if id1 >> 31 else 4} KiB pages, NUMPAGENDXB {id1 >> 28 & 7})')
        self.mentions(f'ID2 `0x{id2:X}` (IAS, OAS and UBS {40 if id2 & 15 == 2 else 0} bits; 4 KiB and 64 KiB granules)')
        self.assertEqual((id2 & 15, id2 >> 4 & 15, id2 >> 8 & 15, id2 >> 12 & 1, id2 >> 14 & 1), (2, 2, 2, 1, 1))
        self.assertEqual(id1 >> 16 & 0xff, 0, 'NUMS2CB is 0 on the unit: the NESTED row of the usbsmmu document says so')
        self.assertEqual(0x15000000 + (1 << ((id1 >> 28 & 7) + 1)) * 4096, value('CBBASE'), 'the bank base follows from NUMPAGENDXB')
        self.assertEqual((value('NCB'), value('SMRG')), (id1 & 0xff, id0 & 0xff))
        self.mentions(f'CBAR `0x{cbar:X}` is TYPE {cbar >> 16 & 3}, stage 1 followed by stage 2 (`NESTED`), with the VMID/CBNDX field '
                      f'{cbar & 0xff}, MemAttr {cbar >> 12 & 15} and BPSHCFG {cbar >> 8 & 3}')
        self.assertIn('TYPE=NESTED', page)
        self.assertEqual(cbar >> 16 & 3, 3)
        self.mentions(f'SCTLR `0x{sctlr:X}` (M {sctlr & 1}: **stage 1 is off**')
        self.assertEqual(sctlr & 1, 0)
        self.mentions(f'FSR is `0x{fsr:X}`')
        self.assertEqual(fsr, 1 << 10, 'bit 10 is the one the results call unknown')
        self.assertIn('STS=0X11:HCH.PCD', page)
        self.mentions('USBSTS `0x11` (HCH and PCD)')

    def test_the_timer_inference_is_the_arithmetic_of_the_pages_counts_and_the_timer_documents_lines(self):
        lines = self.page()
        psci, usbsmmu = (int(re.search(r' LINES=(\d+) ', line).group(1)) for line in lines if line.startswith('PAYLOAD DONE '))
        most = int(re.search(r'(\d+) lines when ECV >= 2', self.timer).group(1))
        printed = [re.split(r'\s{2,}\(', raw)[0].rstrip() for raw in re.search(r'```\n(PAYLOAD TIMER .*?)```', self.timer, re.S).group(1).splitlines()]
        self.assertEqual(printed[-3:], ['PAYLOAD TIMER NEXT CNTPOFF_EL2', 'PAYLOAD TIMER CNTPOFF_EL2=0X..', 'PAYLOAD TIMER DONE'])
        stopped_after = most - 2                       # the lines up to and with NEXT CNTPOFF_EL2: the value and DONE follow it
        notes = 3 + 1                                  # boot 4 had three files: three LOADED and READY
        total = notes + (psci + 3) + (usbsmmu + 3) + (2 + stopped_after)
        section = self.results[self.results.index('## Payload `timer` (boot 4)'):self.results.index('## Still UNKNOWN')]
        numbers = [int(n) for n in re.findall(r'^\| .+? \| (\d+) \|$', section, re.M)]
        self.assertEqual(numbers, [notes, psci + 3, usbsmmu + 3, 2 + stopped_after, total])
        self.assertEqual(total, sum(numbers[:-1]))
        for phrase in (f'held exactly {total} lines', f'(`psci` {psci} lines, `usbsmmu` {usbsmmu})', f'its {psci} lines, `DONE`',
                       f'its {usbsmmu} lines, `DONE`', f'then {stopped_after} lines',
                       f'The {stopped_after}th line the timer payload prints is `PAYLOAD TIMER NEXT CNTPOFF_EL2`'):
            self.mentions(phrase, section)

    def test_the_claims_stay_at_one_unit_and_few_boots_and_the_inferences_are_labelled(self):
        for phrase in ('**One unit, at most four boots of any payload: nothing here is a distribution**',
                       'The `state` payload has not run on the unit: NOT RUN.',
                       '**It did not return, INFERRED from a line count; its lines were never read.**',
                       'only if `psci` and `usbsmmu` printed as many lines in boot 4 as in boot 5 (not checked)',
                       'The cause stays INFERRED', 'whose verdict is UNKNOWN and stays so', 'SC2 is neither triggered nor cleared',
                       'it needs authorization A1, the first xHC register write at EL2; NOT granted', '**The cause is UNKNOWN:**',
                       'That is computed from the function (VERIFIED as a computation), not measured', 'the 89 rows are not',
                       'a hang followed by a watchdog reset is INFERRED',
                       # the restart: the cause stays UNKNOWN, UPTIME counts from before the chain, no time is known
                       '**The cause of the restart is UNKNOWN.**', 'counts from before the chain, not from its end',
                       'the restart came seconds after the chain ended, not 16 s later (INFERRED from the heartbeat code',
                       '**A restart was reported in two of the three `cpuon` boots (boot 7 and step 2); their times are UNKNOWN.**',
                       "step 2's is INFERRED, weakly, at `UPTIME` about 41 S or earlier, possibly before its chain ended",
                       'Step 3 was OBSERVED alive through `UPTIME 36 S`', '**INFERRED: the restart is not at one fixed `UPTIME`.**',
                       'alive at `UPTIME 123 S`', '**A plan can never run unattended.**', '(INFERRED, weak: it assumes that pace)',
                       # the restart control (psci alone): the runner flow alone is not the cause; `cpuon` is only associated with it
                       '**A read-only payload kept the page alive to `UPTIME 224 S` and `268 S` in two boots (OBSERVED once each).**',
                       '**So the runner flow alone is not what restarts the board (INFERRED strongly: two boots, evidence and not proof).**',
                       'INFERRED: a correlation over five boots, three of `cpuon` and two of `psci`; the cause is UNKNOWN',
                       'the runner flow alone is excluded by two long holds of a read-only payload, INFERRED strongly, evidence not proof',
                       # the high half of VBAR_EL2 differs between boots: OBSERVED in two crisp values; only the reason is INFERRED
                       '**The upper half of `VBAR_EL2` differs between boots (OBSERVED).**',
                       'What stays INFERRED is the reason: a randomised high-half EL2 image ran on those cores earlier; which software is unknown.',
                       'for the high half of `VBAR_EL2`, from boot to boot (OBSERVED;'):
            self.mentions(phrase)
        self.assertNotRegex(self.flat, r'(?i)hardware (qualified|passed)|did not reproduce|40 to 60|PLANNED, NOT RUN|\(and, INFERRED, from boot'
                                       r'|no observation beyond `UPTIME 10 S`|alone is not excluded|read-only chains did|at most three boots'
                                       r'|(?<!whether )the bank is writable|(?<!whether a )cache clean reaches DRAM')

    def test_the_restart_control_ran_the_psci_payload_of_boot_5_and_printed_its_lines(self):
        lines = self.page()
        loaded, done = lines[0], next(line for line in lines if line.startswith('PAYLOAD DONE INDEX=0 '))
        control = self.flat[self.flat.index('### The restart control'):self.flat.index('## Payloads `hashbig` and `el2mem` (boots 8 and 9)')]
        for base in ('0XCEAB3000', '0XCDDD4000'):
            self.mentions(re.sub(r'BASE=0X[0-9A-F]+', f'BASE={base}', loaded), control)
        self.mentions(done[len('PAYLOAD '):], control)
        self.assertIn(' LINES=15 ', done)
        self.mentions('the same 15 payload lines as boot 5', control)

    def test_the_runner_lines_the_results_quote_are_the_ones_of_the_cpuon_documents_page(self):
        for line in ('PAYLOAD LOADED INDEX=0 BASE=0XCE60A000 BYTES=18056 SHA=3B4BFDA7D59F923C TYPE=1',
                     'RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=40 DROPPED=0'):
            self.mentions(line)
            self.assertIn(line, self.cpuon, 'the cpuon document lacks it')
        for quoted in ('0xCE60A000', '0xCEA8B000', '0xCE5E5000', '0xFFFFFF9CEA002800', '0xFFFFFFB460602800'):     # the three bases, the two VBAR_EL2
            self.mentions(f'`{quoted}`')
            self.assertIn(f'`{quoted}`', self.cpuon, 'the cpuon document lacks the base or the value')

    def unit_page(self):
        found = re.search(r'<!-- boot9-panel -->\n```\n(.*?)```\n<!-- /boot9-panel -->', self.results, re.S)
        self.assertIsNotNone(found, 'the results document has no <!-- boot9-panel --> block')
        return found.group(1).splitlines()

    def test_the_page_of_boots_8_and_9_is_well_formed_pinned_and_agrees_with_its_arithmetic(self):
        lines = self.unit_page()
        text = '\n'.join(lines)
        self.assertEqual(len(lines), 36)
        for line in lines:
            with self.subTest(line=line):
                self.assertTrue(line.startswith('PAYLOAD '))
                self.assertLessEqual(len(line), 100)
                self.assertRegex(line, PAGE_FONT)
        calls = [i for i, line in enumerate(lines) if line.startswith('PAYLOAD CALL ')]
        dones = [i for i, line in enumerate(lines) if line.startswith('PAYLOAD DONE ')]
        self.assertEqual((len(calls), len(dones)), (2, 2))
        self.assertEqual([line.split()[1] for line in lines[:calls[0] - 1]], ['LOADED', 'LOADED', 'LOADED', 'READY'])
        for call, done in zip(calls, dones):
            self.assertEqual(lines[call - 1], 'PAYLOAD VERIFY=OK')
            self.assertEqual(int(re.search(r' LINES=(\d+) ', lines[done]).group(1)), done - call - 1, lines[done])
        self.assertTrue(all(line.startswith('PAYLOAD HASHBIG ') for line in lines[calls[0] + 1:dones[0]]))
        self.assertTrue(all(line.startswith('PAYLOAD EL2MEM ') for line in lines[calls[1] + 1:dones[1]]))
        for piece in UNIT_VALUES:
            self.assertIn(piece, text)
        size, ticks, ms, mibs = (int(n) for n in re.search(r'HASH BYTES=(\d+) TICKS=(\d+) MS=(\d+) MIBS=(\d+)', text).groups())
        freq = int(re.search(r'HASHBIG START CURRENTEL=0X8 FREQ=(\d+)', text).group(1))
        self.assertEqual((ms, mibs), (ticks * 1000 // freq, size * freq // (ticks * (1 << 20))))
        self.assertEqual((14204370 * 1000 // freq, size * freq // (14204370 * (1 << 20))), (ms, mibs), 'boot 8 gave the same MS and MIBS')
        self.assertLess(ticks, 25 * freq, 'the 25 s box was never near')
        loaded = re.search(r'LOADED INDEX=2 BASE=0X([0-9A-F]+) BYTES=(\d+) SHA=([0-9A-F]{16}) TYPE=2', text)
        base = int(loaded.group(1), 16)
        self.assertEqual((int(loaded.group(2)), size), (144 << 20, 144 << 20))
        self.assertIn(f'FILE INDEX=2 BASE=0X{base:X} BYTES={size} MIB=144', text)
        self.assertIn(f'DIGEST {loaded.group(3)} MATCH', text)
        self.assertEqual(int(re.search(r'LOW_LAST\(0X([0-9A-F]+)\)', text).group(1), 16) + 4, base, 'the low extent ends where the file begins')
        bank_mib = (0x1000000000 - 0x880000000) >> 20
        self.assertEqual([int(n) for n in re.search(r'BANK CONV_MIB=(\d+) PROBES=(\d+)', text).groups()], [bank_mib, bank_mib // 2 + 1])
        mmfr1, oslsr, sre = (int(re.search(pattern, text).group(1), 16) for pattern in (
            r'MMFR1=0X([0-9A-F]+)', r'OSLSR_EL1 RAW=0X([0-9A-F]+)', r'ICC_SRE_EL2 RAW=0X([0-9A-F]+)'))
        self.assertEqual([int(re.search(rf'\b{key}=(\d+)', text).group(1)) for key in ('PAN', 'VH', 'HAFDBS', 'OSLK', 'SRE', 'ENABLE')],
                         [mmfr1 >> 20 & 15, mmfr1 >> 8 & 15, mmfr1 & 15, oslsr >> 1 & 1, sre & 1, sre >> 3 & 1])
        self.assertEqual(int(re.search(r'CONV_MIB=(\d+)', text).group(1)), 32105 - (size >> 20), 'boot 6 held 32,105 MiB of Conventional memory')

    def test_the_section_of_boots_8_and_9_agrees_with_its_page_and_labels_what_it_does_not_show(self):
        section = self.flat[self.flat.index('## Payloads `hashbig` and `el2mem` (boots 8 and 9)'):self.flat.index('## Payloads `cnthctl` and `el1trap` (boot 11)')]
        text = '\n'.join(self.unit_page())
        base, size = int(re.search(r'LOADED INDEX=2 BASE=0X([0-9A-F]+)', text).group(1), 16), 144 << 20
        self.assertNotIn('VERIFIED', section, 'a hardware result is OBSERVED, and a decode of it INFERRED')
        el2mem, hashbig = (re.search(rf'LOADED INDEX={index} BASE=0X([0-9A-F]+) BYTES=(\d+)', text) for index in (1, 0))
        pages = -(-int(hashbig.group(2)) // 4096) * 4096     # the declared range of a file is whole pages
        self.mentions(f'the payload at `0x{int(el2mem.group(1), 16):X}`, the first file at `0x{int(hashbig.group(1), 16):X}` (`0x{pages:X}`)', section)
        self.mentions(f'the second at `0x{base:X}` (`0x{size:X}`)', section)
        self.mentions('`MEMORY DESCRIPTORS` `0xEA` (234:', section)
        self.assertEqual(0xEA, int(re.search(r'MAP DESC=(\d+)', text).group(1)))
        low = 0xA8000000
        self.mentions(f'{(base - low) >> 20} MiB. Together they make {(base + size - low) >> 20} MiB', section)
        self.mentions(f'The file ends at `0x{base + size:X}` (`0x{base:X} + 0x{size:X}`)', section)
        self.mentions(f'`LOW_FIRST`) to `0x{base:X}` (`LOW_LAST` is the word before it)', section)
        self.mentions('`HASH ... TICKS=14204370` (boot 9: `14204400`; `MS=739 MIBS=194` in both) and the four words `el2mem` read from RAM: '
                      '`BANK_FIRST(0X880000000)=0X59ADB1EB`, `BANK_LAST(0XFFFFFFFFC)=0XF30F158`, `LOW_FIRST(0XA8000000)=0X380001` and '
                      '`LOW_LAST(0XC3E64FFC)=0XEC6A2481`', section)
        for phrase in ('the plan\'s stop rule never triggered', 'no fault page) and neither video shows a restart',
                       'It is not a restart: `UPTIME` keeps counting (101 S at 110 s, 42 S at 54 s)',
                       'OBSERVED; only `AT S1E2R` and loads were made: whether the bank is writable at EL2 is UNKNOWN',
                       'OBSERVED; the names are the payload\'s decode of `PAR_EL1`',
                       'OBSERVED; that none was trapped to EL3 and emulated there is INFERRED (an EL3 handler that emulated a read would look the same)',
                       '**The decode (INFERRED: the Arm ARM was not re-read;', '**Placement (INFERRED from the printed addresses).**',
                       'One file size was seen by these boots, so that rule is INFERRED. The stick wrapper\'s dry run',
                       '`0xCCE64B40`, the same top after page rounding (INFERRED: that run printed no extent); that it holds for every size is UNKNOWN',
                       'The cause of the redraw is UNKNOWN', '**Not shown, UNKNOWN.**',
                       'whether a cache clean reaches DRAM, and whether a page in the bank survives the bounce',
                       'these boots issued no `CPU_ON` and neither video shows a restart', 'changes none of its labels',
                       '(INFERRED by subtraction: no frame shows them)', 'Three of the four words differ between the boots'):
            self.mentions(phrase, section)
        for phrase in ('The high bank (from `0x880000000`) is mapped write-back and readable at EL2 (OBSERVED, boots 8 and 9:',
                       'but whether it is writable at EL2 stage 1, whether a cache clean reaches DRAM there and whether a page there survives the bounce are UNKNOWN',
                       'three hazard reads of `el2mem` was trapped to EL3 and emulated there (all three returned; the page cannot tell: INFERRED only)',
                       'Boots 8 and 9 ([below](#payloads-hashbig-and-el2mem-boots-8-and-9)) add two read-only boots with no restart in their videos',
                       'eight of its nine payloads ran on the Surface Pro 11'):
            self.mentions(phrase)
        main = ' '.join(self.main.split())
        for phrase in ('ran together in boots 8 and 9 with a 144 MiB data file (OBSERVED, one unit, two boots:', 'was hashed at 194 MiB/s;',
                       'the bank\'s writability is UNKNOWN', 'measured what hashing one in place costs: 194 MiB/s for 144 MiB, OBSERVED in boots 8 and 9',
                       '**Mostly answered (OBSERVED, boots 5, 8 and 9):**', 'Whether the bank is also writable, and whether a page there survives the bounce, are UNKNOWN',
                       'a 144 MiB file passed it in boots 8 and 9, OBSERVED'):
            self.assertIn(phrase, main)
        for stale in ('as are the two read-only memory payloads', 'measures what hashing one in place costs, hardware NOT RUN',
                      'the high bank is untried (UNKNOWN)', 'Partly answered (OBSERVED, boot 5)'):
            self.assertNotIn(stale, main)
            self.assertNotIn(stale, self.flat)

    def boot11_page(self):
        found = re.search(r'<!-- boot11-panel -->\n```\n(.*?)```\n<!-- /boot11-panel -->', self.results, re.S)
        self.assertIsNotNone(found, 'the results document has no <!-- boot11-panel --> block')
        return found.group(1).splitlines()

    def test_the_page_of_boot_11_is_well_formed_pinned_and_agrees_with_its_arithmetic(self):
        lines = self.boot11_page()
        text = '\n'.join(lines)
        self.assertEqual(len(lines), 37)
        for line in lines:
            with self.subTest(line=line):
                self.assertTrue(line.startswith('PAYLOAD '))
                self.assertLessEqual(len(line), 100)
                self.assertRegex(line, PAGE_FONT)
        calls = [i for i, line in enumerate(lines) if line.startswith('PAYLOAD CALL ')]
        dones = [i for i, line in enumerate(lines) if line.startswith('PAYLOAD DONE ')]
        self.assertEqual((len(calls), len(dones)), (2, 2))
        self.assertEqual([line.split()[1] for line in lines[:calls[0] - 1]], ['LOADED', 'LOADED', 'READY'])
        for call, done in zip(calls, dones):
            self.assertEqual(lines[call - 1], 'PAYLOAD VERIFY=OK')
            self.assertEqual(int(re.search(r' LINES=(\d+) ', lines[done]).group(1)), done - call - 1, lines[done])
        self.assertEqual([int(re.search(r' LINES=(\d+) ', lines[done]).group(1)) for done in dones], [8, 20])
        self.assertTrue(all(line.startswith('PAYLOAD CNTHCTL ') for line in lines[calls[0] + 1:dones[0]]))
        self.assertTrue(all(line.startswith('PAYLOAD EL1TRAP ') for line in lines[calls[1] + 1:dones[1]]))
        for piece in UNIT11_VALUES:
            self.assertIn(piece, text)
        value = lambda pattern: int(re.search(pattern, text).group(1), 16)  # noqa: E731
        old, v, r, r2 = (value(rf'\b{key}=0X([0-9A-F]+)') for key in ('OLD', 'V', 'R', 'R2'))
        self.assertEqual(v, (old & ~3) | (1 << 14) | (1 << 13), "V is the monitor's formula")
        self.assertEqual((r >> 13 & 3, r == v, r2 == old), (3, True, True), 'BITS13_14_STUCK=YES, R_EQ_V=YES and RESTORED=YES follow from the values')
        pfr0 = value(r'ID_AA64PFR0_EL1=0X([0-9A-F]+)')
        self.assertEqual((value(r'ID_AA64MMFR0_EL1=0X([0-9A-F]+)') >> 60 & 15, text.count('ECV=0X2'), pfr0 & 15, pfr0 >> 4 & 15), (2, 2, 1, 1), 'ECV 2, EL0 and EL1 AArch64 only')
        self.assertEqual(value(r'CNTFRQ_EL0=0X([0-9A-F]+)'), 19200000)
        iss = lambda op0, op1, crn, crm, op2, rt: op0 << 20 | op2 << 17 | op1 << 14 | crn << 10 | rt << 5 | crm << 1 | 1  # noqa: E731
        self.assertEqual([value(rf'{register} (?:CONTROL )?TRAPPED EC=0X18 ISS=0X([0-9A-F]+)') for register in ('CNTVCT_EL0', 'CNTV_CTL_EL0', 'CNTPCT_EL0')],
                         [iss(3, 3, 14, 0, 2, 0), iss(3, 3, 14, 3, 1, 1), iss(3, 3, 14, 0, 1, 3)], 'the ISS of CNTVCT_EL0 into X0, CNTV_CTL_EL0 into X1, CNTPCT_EL0 into X3')
        self.assertEqual((value(r'ENTRIES=0X([0-9A-F]+)'), value(r'TRAPS=0X([0-9A-F]+)'), text.count(' TRAPPED EC=0X18 ')), (4, 3, 3), 'one entry per trapped read and one for the end')
        written = value(r'WRITES HCR_EL2=0X[0-9A-F]+ CNTHCTL_EL2=0X[0-9A-F]+ SCTLR_EL1=0X([0-9A-F]+)')
        self.assertEqual(value(r'READBACK SCTLR_EL1=0X([0-9A-F]+)') ^ written, 0x180, 'bits 7 and 8 differ')
        self.assertEqual(value(r'OLD CNTHCTL_EL2=0X[0-9A-F]+ SCTLR_EL1=0X([0-9A-F]+)') & 0x180, 0x180, 'and are set in the old SCTLR_EL1 too')
        stub, el1, el2 = (value(rf'{key}_OFFSET=0X([0-9A-F]+)') for key in ('STUB', 'EL1_VECTORS', 'EL2_VECTORS'))
        self.assertEqual((el1 - el2, el1 % 2048, el2 % 2048, value(r'VBAR_EL1_OFFSET=0X([0-9A-F]+)')), (2048, 0, 0, el1))
        self.assertTrue(el1 < stub < el1 + 2048 + 256 and stub < 15156)
        memhash = '\n'.join(self.unit_page())
        for index in (0, 1):
            self.assertEqual(re.search(rf'LOADED INDEX={index} BASE=0X([0-9A-F]+)', text).group(1), re.search(rf'LOADED INDEX={index} BASE=0X([0-9A-F]+)', memhash).group(1),
                             'the runner placed the two files where it did in boots 8 and 9')

    def test_the_section_of_boot_11_agrees_with_its_page_and_labels_what_it_does_not_show(self):
        section = self.flat[self.flat.index('## Payloads `cnthctl` and `el1trap` (boot 11)'):self.flat.index('## Payload `timer` (boot 4)')]
        self.assertNotIn('VERIFIED', section, 'a hardware result is OBSERVED, and a decode of it INFERRED')
        for phrase in ('The plan `timers` (2026-11-16, 11:44, after the `memhash` boots) ran one autorun step from the same stick',
                       'The operator authorised both by name and SHA-256 (about 11:20) for this one boot.',
                       "the operator's decision for this boot, and the stop rules stand", 'that agree on every line; it is not CRC-checked',
                       'Both payloads returned 0 (`RETURN=0X0 STACK=OK`) and printed `RESTORED=YES`; no refusal, no fault page, no stop rule, and the video shows no restart.',
                       "the register held exactly V and gave OLD back | OBSERVED |", '`HVC_AT_EL2=OK` | OBSERVED; that `SCR_EL3.HCE` is set and `HCR_EL2.HCD` clear is INFERRED |',
                       "OBSERVED, the first runner payload to do so (the X2 image's T02 had run an EL1 stub with an `ERET` path on the unit: 2026-11-11 and 2026-11-14, OBSERVED,",
                       'that the stub ran at EL1 follows from the traps (INFERRED)', '`CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES` | OBSERVED |',
                       'OBSERVED; why two bits differ: INFERRED, below', '**The decode (INFERRED: the Arm ARM was not re-read).**',
                       '**What follows for the monitor port (INFERRED).**', 'is **supported, not decided**',
                       "Whether bits 13 and 14 depend on `SCR_EL3.ECVEn` is UNKNOWN (the Arm ARM was not re-read); boot 11 neither confirms nor refutes the INFERRED explanation of boot 4's `timer` stall",
                       "**Not shown, UNKNOWN.** The traps were measured for the payload's own `HCR_EL2` `0x80000000` and `SCTLR_EL1` `0x30500800`, not for the monitor's guest regime",
                       'the payloads wrote nothing to it'):
            self.mentions(phrase, section)
        for phrase in ('eight of its nine payloads ran on the Surface Pro 11', 'in boot 11 (2026-11-16), `cnthctl` and `el1trap`, which write registers, in one boot',
                       "Whether `timer` stalls at the CNTPOFF_EL2 read (INFERRED only), why (SCR_EL3.ECVEn clear is INFERRED; boot 11 neither confirms nor refutes it,",
                       "hold in the monitor's guest regime, and whether bits 13 and 14 depend on `SCR_EL3.ECVEn`. NOT RUN: the monitor's entry, the timer interrupt through the GIC (PPI 26),"):
            self.mentions(phrase)
        main = ' '.join(self.main.split())
        for phrase in ('boots 4, 5, 7, 8, 9 and 11, build `A9F00F9CCBB5`; one unit, one boot each of those', '`el1trap` ([SP11-PAYLOAD-EL1TRAP.md](SP11-PAYLOAD-EL1TRAP.md)',
                       'ran together in boot 11 with that authorisation (OBSERVED, one unit, one boot: bits 14 and 13 of `CNTHCTL_EL2` stick and the old value comes back;',
                       '`el1trap` is the first runner payload to run code below EL2:', 'while `state` is **hardware NOT RUN**.'):
            self.assertIn(phrase, main)
        for stale in ('Neither have `cnthctl` and `el1trap`.', 'as are the two timer payloads that WRITE EL2 state', 'first code below EL2', 'INFERRED to need', 'do not fit it',
                      'the cause of the stall is UNKNOWN until it is'):
            self.assertNotIn(stale, main)
            self.assertNotIn(stale, self.flat)

    def test_the_document_starts_with_its_licence_line_stays_within_the_size_limit_and_every_link_resolves(self):
        self.assertEqual(self.results.splitlines()[0], '<!-- SPDX-License-Identifier: MIT -->')
        self.assertLess(len(self.results.encode('utf-8')), 50 * 1024)
        self.assertLess(len(self.results.splitlines()), 1500)
        self.assertEqual(lib.link_problems({'SP11-PAYLOAD-RESULTS.md': self.results}, DOCS), [])

    def test_the_main_document_lists_this_suite_with_its_count_of_seeded_mistakes(self):
        tests = self.main[self.main.index('## Tests'):self.main.index('## Safety')]
        self.mentions('python3 tools/test-q1n1-sp11-payload-results-doc.py`', tests)
        self.mentions(f'with {len(DOC_MUTANTS)} seeded mistakes in the two documents', tests)


def _replace(old, new, count=1):
    def mutate(doc):
        assert old in doc, old
        return doc.replace(old, new, count)
    return mutate


def _drop(prefix):
    def mutate(doc):
        lines = doc.split('\n')
        at = next(i for i, line in enumerate(lines) if line.startswith(prefix))
        return '\n'.join(lines[:at] + lines[at + 1:])
    return mutate


RESULTS_DOC_MUTANTS = [
    ('the-page-loses-a-line', _drop('PAYLOAD USBSMMU TRB SKIPPED=NO_SEG0')),
    ('a-line-count-is-wrong', _replace('LINES=17 DROPPED=0', 'LINES=18 DROPPED=0')),
    ('a-register-on-the-page-is-changed', _replace('ID1=0X6000005F', 'ID1=0X6000005E')),
    ('a-line-is-over-a-hundred-characters', _replace('PAYLOAD USBSMMU NEXT CB3\n', 'PAYLOAD USBSMMU NEXT CB3 ' + 'X' * 100 + '\n')),
    ('a-decode-is-wrong', _replace('NUMCB 95', 'NUMCB 96')),
    ('nums2cb-is-called-non-zero', _replace('NUMS2CB 0', 'NUMS2CB 1', count=-1)),
    ('the-timer-arithmetic-is-wrong', _replace('its 15 lines, `DONE` | 18 |', 'its 15 lines, `DONE` | 19 |')),
    ('the-timer-stall-is-called-observed', _replace('**It did not return, INFERRED from a line count; its lines were never read.**', '**It did not return: OBSERVED.**')),
    ('the-timer-inference-loses-its-condition', _replace('only if `psci` and `usbsmmu` printed as many lines in boot 4 as in boot 5 (not checked)', 'for certain')),
    ('the-nested-verdict-is-changed', _replace('whose verdict is UNKNOWN and stays so', 'whose verdict is SC2')),
    ('the-region-capacity-is-called-measured', _replace('That is computed from the function (VERIFIED as a computation), not measured', 'That was measured on the unit')),
    ('the-results-claim-a-distribution', _replace('**One unit, at most four boots of any payload: nothing', '**Every unit behaves so: nothing')),
    ('a-link-does-not-resolve', _replace('SP11-PAYLOAD-USBSMMU.md#what-the-outcomes-mean-for-the-next-step', 'SP11-PAYLOAD-USBSMMU.md#what-the-outcomes-mean')),
    ('the-licence-line-is-gone', _replace('<!-- SPDX-License-Identifier: MIT -->\n', '')),
    ('the-restart-cause-is-called-known', _replace('**The cause of the restart is UNKNOWN.**', '**The cause of the restart is the CPU_OFF.**')),
    ('the-restart-is-timed-from-the-wrong-start', _replace('the restart came seconds after the chain ended, not 16 s later', 'the page stayed up 16 s after the chain')),
    ('a-restart-window-is-claimed', _replace('**INFERRED: the restart is not at one fixed `UPTIME`.**', '**The restart comes at `UPTIME` 40 to 60 S.**')),
    ('step-3-is-seen-alive-for-longer', _replace('Step 3 was OBSERVED alive through `UPTIME 36 S`', 'Step 3 was OBSERVED alive through `UPTIME 60 S`')),
    ('the-plain-pages-time-is-dropped', _replace('alive at `UPTIME 123 S`', 'alive for minutes', count=-1)),
    ('step-2s-weak-inference-is-called-observed', _replace('(INFERRED, weak: it assumes that pace)', '(OBSERVED)')),
    ('a-runner-line-differs-from-the-cpuon-page', _replace('BYTES=18056 SHA=3B4BFDA7D59F923C', 'BYTES=18057 SHA=3B4BFDA7D59F923C')),
    # The page of boots 8 and 9 and the section around it.
    ('the-unit-base-is-changed', _replace('PAYLOAD LOADED INDEX=2 BASE=0XC3E65000', 'PAYLOAD LOADED INDEX=2 BASE=0XC3E65001')),
    ('the-unit-rate-is-changed', _replace('TICKS=14204400 MS=739 MIBS=194', 'TICKS=14204400 MS=739 MIBS=195')),
    ('the-unit-milliseconds-are-changed', _replace('TICKS=14204400 MS=739', 'TICKS=14204400 MS=740')),
    ('the-unit-ticks-are-changed', _replace('TICKS=14204400 MS=739', 'TICKS=14204401 MS=739')),
    ('the-unit-attributes-are-the-models', _replace('PAYLOAD HASHBIG ATTR FIRST=WB.OS.NS1 MID=WB.OS.NS1 LAST=WB.OS.NS1',
                                                    'PAYLOAD HASHBIG ATTR FIRST=WB.IS MID=WB.IS LAST=WB.IS')),
    ('the-unit-extent-total-is-changed', _replace('CONV_EXTENTS=17 CONV_MIB=31961', 'CONV_EXTENTS=17 CONV_MIB=31962')),
    ('the-unit-bank-probes-are-changed', _replace('CONV_MIB=30720 PROBES=15361', 'CONV_MIB=30720 PROBES=15360')),
    ('the-unit-pan-is-changed', _replace('PAN=3 VH=1 HAFDBS=0', 'PAN=2 VH=1 HAFDBS=0')),
    ('the-unit-mmfr1-is-changed', _replace('MMFR1=0X111111312120', 'MMFR1=0X111111312121')),
    ('the-unit-isar2-is-changed', _replace('ISAR2=0X10000012', 'ISAR2=0X10000013')),
    ('the-unit-mdcr-is-changed', _replace('MDCR_EL2=0X6', 'MDCR_EL2=0X7')),
    ('the-unit-oslsr-is-changed', _replace('OSLSR_EL1 RAW=0X8 OSLK=0', 'OSLSR_EL1 RAW=0X8 OSLK=1')),
    ('the-unit-icc-sre-is-changed', _replace('ICC_SRE_EL2 RAW=0XF SRE=1 ENABLE=1', 'ICC_SRE_EL2 RAW=0XE SRE=1 ENABLE=1')),
    ('the-unit-low-word-address-is-changed', _replace('LOW_LAST(0XC3E64FFC)', 'LOW_LAST(0XC3E65FFC)')),
    ('the-unit-descriptor-count-is-changed', _replace('MAP DESC=234', 'MAP DESC=235')),
    ('the-declared-range-of-the-file-is-wrong', _replace('the second at `0xC3E65000` (`0x9000000`)', 'the second at `0xC3E65000` (`0x8000000`)')),
    ('the-bank-is-called-writable', _replace('whether the bank is writable at EL2 is UNKNOWN', 'the bank is writable at EL2')),
    ('the-high-bank-is-called-writable-in-the-unknown-list', _replace('but whether it is writable at EL2 stage 1, whether a cache clean reaches DRAM there',
                                                                      'and it is writable at EL2 stage 1, a cache clean reaches DRAM there')),
    ('the-el3-claim-is-called-verified', _replace('that none was trapped to EL3 and emulated there is INFERRED', 'that none was trapped to EL3 and emulated there is VERIFIED')),
    ('the-placement-is-called-observed', _replace('**Placement (INFERRED from the printed addresses).**', '**Placement (OBSERVED).**')),
    ('the-low-remainder-is-wrong', _replace('446 MiB.', '447 MiB.')),
    ('the-boot-8-ticks-are-wrong', _replace('`HASH ... TICKS=14204370`', '`HASH ... TICKS=14204371`')),
    ('the-boot-8-words-are-wrong', _replace('`LOW_LAST(0XC3E64FFC)=0XEC6A2481`', '`LOW_LAST(0XC3E64FFC)=0XEC6A2480`')),
    ('a-restart-is-claimed-in-boots-8-and-9', _replace('page) and neither video shows a restart', 'page) and the board restarted in both')),
    ('the-redraw-is-called-a-restart', _replace('It is not a restart:', 'It is a restart:')),
    ('the-intro-counts-the-payloads-of-before', _replace('eight of its nine payloads ran on the Surface Pro 11', 'four of its five payloads ran on the Surface Pro 11')),
]


def _in_panel11(old, new):
    """A change inside the boot 11 page block only (the page of the CNTHCTL and EL1TRAP documents is checked against it elsewhere)."""
    def mutate(doc):
        start, end = doc.index('<!-- boot11-panel -->'), doc.index('<!-- /boot11-panel -->')
        assert old in doc[start:end], old
        return doc[:start] + doc[start:end].replace(old, new, 1) + doc[end:]
    return mutate


# The page of boot 11 and the section around it: every number and label of the page, and the claims the section must not make.
RESULTS_DOC_MUTANTS += [(f'the-boot-11-{name}', _in_panel11(old, new)) for name, old, new in (
    ('old-value-is-changed', 'CNTHCTL_EL2 OLD=0X3 CNTFRQ_EL0=0X124F800', 'CNTHCTL_EL2 OLD=0X1 CNTFRQ_EL0=0X124F800'), ('written-value-is-changed', 'OLD=0X3 V=0X6000', 'OLD=0X3 V=0X4000'),
    ('readback-is-changed', 'R=0X6000 R2=0X3', 'R=0X4000 R2=0X3'), ('restore-readback-is-changed', 'R=0X6000 R2=0X3', 'R=0X6000 R2=0X1'),
    ('stuck-verdict-is-changed', 'BITS13_14_STUCK=YES', 'BITS13_14_STUCK=NO'), ('equality-verdict-is-changed', 'R_EQ_V=YES', 'R_EQ_V=NO'),
    ('cnthctl-restore-verdict-is-changed', 'PAYLOAD CNTHCTL RESTORED=YES', 'PAYLOAD CNTHCTL RESTORED=NO'),
    ('el1trap-restore-verdict-is-changed', 'PAYLOAD EL1TRAP RESTORED=YES', 'PAYLOAD EL1TRAP RESTORED=NO'),
    ('counter-iss-is-changed', 'ISS=0X34F801', 'ISS=0X34F800'), ('timer-iss-is-changed', 'ISS=0X32F827', 'ISS=0X32F825'), ('control-iss-is-changed', 'ISS=0X32F861', 'ISS=0X32F860'),
    ('sctlr-readback-is-the-written-value', 'READBACK SCTLR_EL1=0X30500980', 'READBACK SCTLR_EL1=0X30500800'),
    ('old-sctlr-is-changed', 'SCTLR_EL1=0X100030D0198D', 'SCTLR_EL1=0X100030D0198C'), ('old-vbar-is-changed', 'OLD VBAR_EL1=0XA7004000', 'OLD VBAR_EL1=0XA7004001'),
    ('entries-are-changed', 'ENTRIES=0X4', 'ENTRIES=0X3'), ('traps-are-changed', 'TRAPS=0X3', 'TRAPS=0X4'),
    ('cnthctl-line-count-is-changed', 'REFUSED=0 LINES=8 DROPPED=0', 'REFUSED=0 LINES=9 DROPPED=0'),
    ('el1trap-line-count-is-changed', 'REFUSED=0 LINES=20 DROPPED=0', 'REFUSED=0 LINES=21 DROPPED=0'), ('verdict-is-inert', 'VERDICT=TRAPS_EFFECTIVE', 'VERDICT=TRAPS_INERT'),
    ('frequency-read-is-trapped', 'CNTFRQ_EL0 NOT_TRAPPED VALUE=0X124F800', 'CNTFRQ_EL0 TRAPPED EC=0X18 ISS=0X30F841 ISS_OK=YES'),
    ('base-is-changed', 'BASE=0XCEA88000', 'BASE=0XCEA89000'), ('digest-is-changed', 'SHA=5074712516C1CF08', 'SHA=5074712516C1CF09'), ('size-is-changed', 'BYTES=3094', 'BYTES=3095'),
    ('ecv-field-is-changed', 'ECV=0X2', 'ECV=0X0'), ('page-loses-a-line', 'PAYLOAD CNTHCTL NEXT CNTHCTL_EL2 WRITE AFTER 8 S\n', ''))]
RESULTS_DOC_MUTANTS += [(f'the-boot-11-{name}', _replace(old, new)) for name, old, new in (
    ('first-runner-payload-becomes-the-first-code-on-the-unit', 'the first runner payload to do so', 'the first code below EL2 run on the unit'),
    ('t02-citation-is-denied', 'T02 had run', 'T02 had not run'),
    ('ecven-dependence-is-called-known', 'Whether bits 13 and 14 depend on `SCR_EL3.ECVEn` is UNKNOWN (the Arm ARM was not re-read)', 'The traps need `SCR_EL3.ECVEn`'),
    ('timer-stall-is-called-explained', "boot 11 neither confirms nor refutes the INFERRED\nexplanation of boot 4's `timer` stall", "boot 11 explains boot 4's `timer` stall"),
    ('operator-decision-is-dropped', "the operator's decision for this boot, and the stop rules stand", 'the documented rule'),
    ('answers-are-called-verified', '**What the unit answered** (OBSERVED unless a cell says otherwise):', '**What the unit answered** (VERIFIED):'),
    ('decode-is-called-observed', '**The decode (INFERRED: the Arm ARM was not re-read).**', '**The decode (OBSERVED).**'),
    ('o1-is-called-decided', 'is **supported, not decided**', 'is **decided**'),
    ('guest-regime-limit-is-dropped', "not for the monitor's guest\nregime", "also for the monitor's guest\nregime"),
    ('hvc-claim-is-called-known', '| OBSERVED; that `SCR_EL3.HCE` is set and `HCR_EL2.HCD` clear is INFERRED |', '| OBSERVED; `SCR_EL3.HCE` is set and `HCR_EL2.HCD` clear |'),
    ('stub-at-el1-is-called-observed', 'that the stub ran at EL1 follows from the traps (INFERRED)', 'the stub ran at EL1 (OBSERVED)'),
    ('unknown-list-forgets-the-guest-regime', "guest\n  regime, and whether bits 13 and 14 depend on `SCR_EL3.ECVEn`.", 'guest\n  regime.'),
    ('timer-bullet-is-called-refuted', 'boot 11 neither confirms nor\n  refutes it', 'boot 11 refutes it'),
    ('intro-forgets-the-run', 'in boot 11 (2026-11-16), `cnthctl` and `el1trap`, which write', 'in boot 11 (2026-11-16), nothing, which write'))]
USBSMMU_DOC_MUTANTS = [
    ('a-boot-5-value-in-the-register-table-is-wrong', _replace('boot 5 OBSERVED `0x400` (bank 3;', 'boot 5 OBSERVED `0x401` (bank 3;')),
    ('a-boot-5-bus-error-is-wrong', _replace('boot 5 OBSERVED 0 (`BERR=0X0`, no latched bus error)', 'boot 5 OBSERVED 1 (`BERR=0X1`, a latched bus error)')),
    ('a-boot-5-value-is-dropped-from-the-register-table', _replace('| VERIFIED (`core.h:123`); boot 5 OBSERVED `0x9CC20026` |', '| VERIFIED (`core.h:123`) |')),
]
DOC_MUTANTS = ([(name, 'results', mutate) for name, mutate in RESULTS_DOC_MUTANTS]
               + [(name, 'usbsmmu', mutate) for name, mutate in USBSMMU_DOC_MUTANTS])


class ResultsDocMutants(unittest.TestCase):
    """The agreement tests above must be able to fail: each seeded mistake in either document is refused by one."""

    @staticmethod
    def outcome(results_text=None, usbsmmu_text=None):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(
            type('Changed', (ResultsDocAgreement,), {'RESULTS': results_text, 'USBSMMU': usbsmmu_text}))
        result = unittest.TestResult()
        suite.run(result)
        return result

    def test_the_unchanged_documents_pass_through_the_same_mechanism(self):
        result = self.outcome(read(RESULTS), read(USBSMMU))
        self.assertTrue(result.wasSuccessful(), [str(f[1])[-400:] for f in result.failures + result.errors])
        self.assertGreaterEqual(result.testsRun, 7)
        self.assertEqual(result.skipped, [], 'a skipped agreement test proves nothing')

    def test_every_seeded_mistake_in_either_document_is_refused(self):
        originals = {'results': read(RESULTS), 'usbsmmu': read(USBSMMU)}
        self.assertGreaterEqual(len(DOC_MUTANTS), 12)
        self.assertEqual(len({name for name, _, _ in DOC_MUTANTS}), len(DOC_MUTANTS))
        self.assertEqual({which for _, which, _ in DOC_MUTANTS}, {'results', 'usbsmmu'}, 'both documents have seeded mistakes')
        for name, which, mutate in DOC_MUTANTS:
            with self.subTest(mutant=name):
                changed = mutate(originals[which])
                self.assertNotEqual(changed, originals[which])
                result = self.outcome(**{which + '_text': changed})
                self.assertFalse(result.wasSuccessful(), 'every agreement test still passed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
