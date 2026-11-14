#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The results document of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-RESULTS.md): the page the unit showed in boot 5
and what the document says about it, against the usbsmmu source and the other payload documents.

    python3 tools/test-q1n1-sp11-payload-results-doc.py

  * ResultsDocAgreement: the page is well formed (41 lines, each in the page font and at most 100 characters) and each `DONE` line
    counts the lines between its `CALL` and itself; the register table of docs/SP11-PAYLOAD-USBSMMU.md gives, for every register boot 5
    read, the value on the page; the decoded numbers of the prose are what the page's raw registers decode to; the timer inference (the
    58 lines of boot 4, the 14th line of the timer payload) is the arithmetic of the page's counts and of the lines
    docs/SP11-PAYLOAD-TIMER.md prints; the claims stay at one unit and one boot with the inferences labelled; the document has its
    licence line, stays within the size limit and its links resolve; docs/SP11-PAYLOAD.md lists this suite.
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
SOURCE = ROOT / 'payloads' / 'usbsmmu.c'
PAGE_FONT = re.compile(r'^[A-Z0-9 :\-./=?()_]*$')
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
        cls.timer, cls.main = read(TIMER), read(MAIN)
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

    def test_the_claims_stay_at_one_unit_and_one_boot_and_the_inferences_are_labelled(self):
        for phrase in ('**One unit, one boot each: nothing here is a distribution**', 'The `state` payload has not run on the unit: NOT RUN.',
                       '**It did not return, INFERRED from a line count; its lines were never read.**',
                       'only if `psci` and `usbsmmu` printed as many lines in boot 4 as in boot 5 (not checked)',
                       'The cause stays INFERRED', 'whose verdict is UNKNOWN and stays so', 'SC2 is neither triggered nor cleared',
                       'it needs authorization A1, the first xHC register write at EL2; NOT granted', '**The cause is UNKNOWN:**',
                       'That is computed from the function (VERIFIED as a computation), not measured', 'the 89 rows are not',
                       'a hang followed by a watchdog reset is INFERRED'):
            self.mentions(phrase)
        self.assertNotRegex(self.flat, r'(?i)hardware (qualified|passed)')

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
    ('the-results-claim-a-distribution', _replace('**One unit, one boot each: nothing', '**Every unit behaves so: nothing')),
    ('a-link-does-not-resolve', _replace('SP11-PAYLOAD-USBSMMU.md#what-the-outcomes-mean-for-the-next-step', 'SP11-PAYLOAD-USBSMMU.md#what-the-outcomes-mean')),
    ('the-licence-line-is-gone', _replace('<!-- SPDX-License-Identifier: MIT -->\n', '')),
]
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
