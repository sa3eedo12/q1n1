#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""docs/SP11-PAYLOAD-CPUON.md against the source, the host model and the binary of the cpuon payload.

    python3 tools/test-q1n1-sp11-payload-cpuon-doc.py

What it holds the document to: the house rules (the licence line, the size limit, no machine identifier, the evidence labels, the
status: ran three times on the unit (boot 7 and two steps of the restart probe), never "hardware NOT RUN"); the function ids, the slot
layout and the instruction inventory against the source and the built binary, whose size and digest are those the unit's page shows;
the page of a normal run against what the host program prints; the unit's page (the crisp one of step 3) against itself (a whole
page, its counts, the entry states and the numbers the prose quotes, step 2's `VBAR_EL2` and the three bases among them); the
restart section's labels (its times UNKNOWN, the read-only control, no "not excluded"); every keyword the payload can print
against the document and every keyword of the line catalogue against the payload; the chain arithmetic against the runner's
planning table and the measured most lines; the QEMU panel's shape (the QEMU suite compares it with a real run). Writes only under
build/. Hardware: NOT RUN (this checks a document)."""
import importlib.util
from pathlib import Path
import re
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


driver = load_module('sp11_payload_cpuon_driver_for_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload-cpuon.py')
native = driver.native
DOC, SOURCE, RUNNER_DOC = driver.DOC, driver.SOURCE, ROOT / 'docs' / 'SP11-PAYLOAD.md'
LINE_WORD = re.compile(r'\b[A-Z][A-Z0-9_]{2,}\b')


def block(text, name):
    return text[text.index(f'<!-- {name} -->') + len(name) + 9:text.index(f'<!-- /{name} -->')]


def rows(section):
    return [[cell.strip() for cell in line.strip().strip('|').split('|')] for line in section.splitlines()
            if line.startswith('|') and not re.match(r'^\|[ \-|]+\|$', line)][1:]


class CpuonDoc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not DOC.exists():
            raise unittest.SkipTest('docs/SP11-PAYLOAD-CPUON.md does not exist')
        cls.text = DOC.read_text(encoding='utf-8')
        cls.code = driver.code_of(SOURCE)
        cls.source = SOURCE.read_text(encoding='utf-8')

    def program(self, *args):
        if not lib.have('clang'):
            self.skipTest('clang not installed')
        done, binary = native.build_program('cpuon', native.UEFI, native.PAYLOADS, driver.BUILD / 'doc')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary, *args)
        self.assertEqual(code, 0, output)
        return output

    # -- the house rules ----------------------------------------------------------------------------------------------------
    def test_the_document_follows_the_house_rules(self):
        self.assertEqual(self.text.splitlines()[0], '<!-- SPDX-License-Identifier: MIT -->')
        self.assertLess(len(self.text.splitlines()), 1500)
        self.assertLess(len(self.text.encode('utf-8')), 50 * 1024)
        for label in ('VERIFIED', 'OBSERVED', 'INFERRED', 'EXPERIMENTAL', 'UNIMPLEMENTED', 'UNKNOWN'):
            self.assertIn(label, self.text)
        flat = ' '.join(self.text.split())
        self.assertIn('**EXPERIMENTAL; ran three times on the unit (2026-11-15: boot 7 and steps 2 and 3 of the restart probe; one unit).**', flat)
        for stale in ('hardware NOT RUN', 'no value of this payload has been OBSERVED'):
            self.assertNotIn(stale, flat, 'it ran on the unit: the document must not say that it has not')
        paths = '|'.join(['/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/'])
        pattern = re.compile(paths + r'|\.loc' + r'al\b|\bsae' + r'ed\b|host' + r'name|\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', re.I)
        for number, line in enumerate(self.text.splitlines(), 1):
            self.assertIsNone(pattern.search(line), f'{number}: {line}')

    def test_the_links_resolve(self):
        problems = lib.link_problems({DOC.name: self.text, RUNNER_DOC.name: RUNNER_DOC.read_text(encoding='utf-8'),
                                      'SP11-PAYLOAD-PSCI.md': (ROOT / 'docs' / 'SP11-PAYLOAD-PSCI.md').read_text(encoding='utf-8')}, ROOT / 'docs')
        self.assertEqual([p for p in problems if DOC.name in p], [])

    # -- the source ---------------------------------------------------------------------------------------------------------------
    def test_the_function_id_table_is_the_source_and_the_policy(self):
        table = {row[0].strip('`'): row for row in rows(block(self.text, 'cpuon-ids'))}
        self.assertEqual(set(table), {'CPU_ON', 'AFFINITY_INFO', 'CPU_OFF'})
        in_source = {name: int(value, 16) for name, value in re.findall(r'#define FUNCTION_(\w+) (0x[0-9A-Fa-f]+)u', self.code)}
        self.assertEqual(in_source, {name: int(table[name][1].strip('`'), 16) for name in ('CPU_ON', 'AFFINITY_INFO')})
        self.assertEqual(sorted(int(row[1].strip('`'), 16) for row in table.values()), sorted(lib.POLICIES['cpuon']['smc_ids']))
        self.assertEqual({name: row[2] for name, row in table.items()}, {'CPU_ON': 'SMC64', 'AFFINITY_INFO': 'SMC64', 'CPU_OFF': 'SMC32'})

    def test_the_slot_table_is_the_sources_layout(self):
        names = {'done flag': 'DONE', '`CurrentEL`': 'CURRENTEL', '`MPIDR_EL1`': 'MPIDR', '`MIDR_EL1`': 'MIDR', '`SCTLR_EL2`': 'SCTLR',
                 '`HCR_EL2`': 'HCR', '`VBAR_EL2` as found': 'VBAR', '`CNTVOFF_EL2`': 'CNTVOFF', '`CNTFRQ_EL0`': 'CNTFRQ',
                 '`CNTPCT_EL0`': 'CNTPCT', '`ID_AA64MMFR0_EL1`': 'MMFR0', '`ID_AA64ISAR0_EL1`': 'ISAR0', '`ID_AA64PFR0_EL1`': 'PFR0',
                 '`ESR_EL2` (fault)': 'ESR', '`ELR_EL2` (fault)': 'ELR', '`FAR_EL2` (fault)': 'FAR', 'vector number (fault)': 'VECTOR',
                 'stage': 'STAGE', 'the answer of a `CPU_OFF` that returned': 'OFF_RETURN'}
        documented = {}
        for row in rows(block(self.text, 'cpuon-slot')):
            for offset, word in ((row[0], row[1]), (row[2], row[3])):
                if offset:
                    documented[names[word]] = int(offset)
        source = {name: int(value) for name, value in re.findall(r'^#define OFF_(\w+) (\d+)$', self.code, re.M)}
        self.assertEqual(documented, source)

    def test_every_keyword_the_payload_can_print_is_in_the_document_and_the_catalogue_names_only_such_keywords(self):
        literals = ' '.join(re.findall(r'"([^"\n]*)"', self.code))
        mine = set(LINE_WORD.findall(literals))
        self.assertGreater(len(mine), 60)
        for word in sorted(mine):
            self.assertIn(word, self.text, f'{word} can be printed and is not in the document')
        catalogue = {word for row in rows(block(self.text, 'cpuon-lines')) for word in LINE_WORD.findall(row[0])}
        placeholders = {'NAME', 'BOOT', 'MIDR', 'MMFR0', 'ISAR0', 'PFR0', 'ESR_EL2'}
        for word in sorted(catalogue - mine - placeholders):
            self.fail(f'{word} is in the line catalogue and nothing in the source prints it')

    def test_the_stub_installs_its_vectors_before_its_first_store_as_rule_7_says(self):
        stub = self.source[self.source.index('"cpuon_entry:'):self.source.index('"cpuon_fault:')]
        self.assertLess(stub.index('msr vbar_el2, x3'), stub.index('STORE('))
        self.assertIn('| 7 | The stub installs its vector table **before its first store**.', self.text)

    # -- the host model and the binary --------------------------------------------------------------------------------------------
    def test_the_page_of_a_normal_run_is_what_the_host_program_prints(self):
        printed = [line for line in self.program('page').splitlines() if line.startswith('PAYLOAD CPUON ')]
        documented = block(self.text, 'cpuon-page').replace('```', '').strip().splitlines()
        self.assertEqual(documented, printed)
        self.assertEqual(len(printed), 38)
        self.assertIn('(38 lines;', self.text)

    def test_the_unit_page_is_a_whole_page_and_the_numbers_the_prose_quotes_are_its_own(self):
        flat = ' '.join(self.text[self.text.index('## What the unit showed'):self.text.index('## What QEMU shows')].split())
        page = block(self.text, 'cpuon-unit-page').replace('```', '').strip().splitlines()
        call = next(i for i, line in enumerate(page) if line.startswith('PAYLOAD CALL '))
        payload, done = page[call + 1:-1], page[-1]
        self.assertEqual((len(page), call, len(payload)), (45, 3, 40), 'four runner lines, the 40 of the payload, DONE')
        self.assertTrue(done.startswith('PAYLOAD DONE ') and all(line.startswith('PAYLOAD CPUON ') for line in payload))
        self.assertIn(' LINES=40 ', done)
        digest, size = re.search(r'sha256 `([0-9a-f]{64})`', flat).group(1), int(re.search(r' BYTES=(\d+) ', page[0]).group(1))
        self.assertEqual(re.search(r' SHA=([0-9A-F]{16}) ', page[0]).group(1), digest[:16].upper())
        self.assertIn(f'{size:,} bytes', flat)
        wanted = 40 + int(re.search(r' SUPPRESSED=(\d+)', '\n'.join(payload)).group(1))
        self.assertIn(f'each run wanted {wanted} lines', flat)
        # phase 2: ten printed reports, nine register lines (and phase 1's one), six MIDR lines; the budget dropped 0X20200's register and
        # MIDR lines, all of 0X20300 and the POWER_OFF line
        p2 = [line for line in payload if ' P2 0X' in line]
        registers = [line for line in payload if ' SCTLR_EL2=' in line]
        self.assertEqual((sum(' EL=2 ' in line for line in p2), len(registers) - 1), (10, 9), 'ten printed reports, nine register lines')
        self.assertEqual(sum('MIDR=0X511F0011/BOOT=0X512F0011' in line for line in p2), 6, 'the six printed MIDR lines')
        self.assertEqual([sum(f' P2 {core} ' in line for line in payload) for core in ('0X20200', '0X20300')], [1, 0])
        self.assertFalse(any(' P2 POWER_OFF ' in line for line in payload))
        # the entry states: seven cores with HCR_EL2 0x80000000 and VBAR_EL2 0, three lines (0X100 twice, 0X10200) with 0x1488000038
        base = int(re.search(r' BASE=0X([0-9A-F]+) ', page[0]).group(1), 16)
        plain = [line for line in registers if line.endswith(' HCR_EL2=0X80000000 VBAR_EL2=0X0')]
        busy = [line for line in registers if ' HCR_EL2=0X1488000038 ' in line]
        self.assertEqual((len(plain), len(busy), len(registers)), (7, 3, 10))
        self.assertTrue(all(' SCTLR_EL2=0X30000000 ' in line for line in registers))
        first, again, other = (int(re.search(r'VBAR_EL2=0X([0-9A-F]+)', next(line for line in busy if key in line)).group(1), 16)
                               for key in (' P1 0X100 ', ' P2 0X100 ', ' P2 0X10200 '))
        self.assertEqual(first, other, 'both cores were entered from the same EL2 image')
        self.assertEqual(again, base + 0x800, "0X100's second start reads the vectors its own stub installed at the first")
        for quoted in (first, again, base):
            self.assertIn(f'`0x{quoted:X}`', flat)
        # the page is step 3's: boot 7's blurred page and step 2's crisp mid-chain photograph are carried by the prose alone
        step_2 = 0xFFFFFFB460602800
        self.assertNotEqual(step_2, first, 'the high-half VBAR_EL2 differs between boots')
        for quoted in (step_2, 0xCEA8B000, 0xCE5E5000):
            self.assertIn(f'`0x{quoted:X}`', flat)
        self.assertIn('differs between boots (OBSERVED, two crisp values', flat)
        self.assertNotIn('between boots is INFERRED', flat)
        latency = [int(re.search(r'DT_US=(\d+)', line).group(1)) for line in payload if 'DT_US=' in line]
        quick = [value for value in latency[1:] if value < 1000]
        self.assertEqual((latency[0], len(latency), len(quick)), (45, 11, 8))
        self.assertIn(f'eight took {min(quick)} to {max(quick)} in step 3', flat)

    def test_the_restart_section_says_what_is_unknown_and_claims_no_window(self):
        section = ' '.join(self.text[self.text.index('### The restart'):self.text.index('### What the runs did not show')].split())
        for phrase in ('The cause and the times are UNKNOWN', 'was therefore the first heartbeat after the chain', 'is not at one fixed `UPTIME`',
                       'alive at `UPTIME 123 S`', 'a plan cannot run unattended',
                       # the control (psci alone): the runner flow alone is not the cause; the link to CPU_ON and CPU_OFF stays a correlation
                       'was alive at `UPTIME 224 S` and `268 S` in two boots (OBSERVED once each; no restart reported)',
                       'so the runner flow alone is not what restarts the board (INFERRED strongly: evidence, not proof)',
                       'INFERRED: a correlation over five boots; the cause is UNKNOWN',
                       'a `cpuon` variant that starts and stops ONE core only', 'a variant that leaves cores running (never `CPU_OFF`',
                       'a film of a `cpuon` page until it restarts, to get the time'):
            self.assertIn(phrase, section)
        self.assertNotRegex(section, r'(?i)did not reproduce|40 to 60|no observation beyond|is not excluded|psci\.bin usbsmmu\.bin')
        self.assertNotIn('run the read-only chain as a control', self.text)

    def test_the_instruction_table_is_the_binary(self):
        driver.need_tools()
        done, elf, flat = driver.Builder(driver.BUILD / 'doc-binary').build('cpuon', 'cpuon', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        f = driver.facts(elf, flat)
        unit = block(self.text, 'cpuon-unit-page')
        self.assertEqual((f['bytes'], f['sha256']), (int(re.search(r' BYTES=(\d+) ', unit).group(1)), re.search(r'sha256\s+`([0-9a-f]{64})`', self.text).group(1)),
                         'the unit ran another binary than this tree builds, and the document says it is this one')
        section = block(self.text, 'cpuon-instructions')
        self.assertIn('| `DC` | `CIVAC` (4 sites), `IVAC` (1 site) |', section)
        self.assertEqual((f['dc']['civac'], f['dc']['ivac']), (4, 1))
        self.assertIn('| `DSB SY` | 7 sites; `ISB` 1 site |', section)
        self.assertEqual((f['mnemonics']['dsb'], f['mnemonics']['isb']), (7, 1))
        self.assertIn('| `WFE` | 1 site |', section)
        self.assertEqual(f['mnemonics']['wfe'], 1)
        self.assertIn('| `SMC #0` | 3 sites |', section)
        self.assertEqual(len(f['smc']), 3)
        self.assertIn('`VBAR_EL2` once, `DAIFSet` once', section)
        self.assertEqual(dict(f['msr']), {'vbar_el2': 1, 'daifset': 1})
        named = set()
        for row in rows(section):
            if row[0] == '`MRS`':
                named |= {token.lower() for token in re.findall(r'`(\w+)`', row[1])}
        named = {lib.CNTVOFF_EL2 if token in ('cntvoff_el2', lib.CNTVOFF_EL2) else token for token in named}
        policy = lib.POLICIES['cpuon']
        self.assertEqual(named, policy['registers'] | policy['single_reads'])
        self.assertEqual(sorted(f['mrs']), sorted(named))

    def test_the_chain_arithmetic_is_right_and_uses_the_measured_and_the_runners_numbers(self):
        runner = block(RUNNER_DOC.read_text(encoding='utf-8'), 'chain-budget')
        found = {key: re.search(pattern, runner) for key, pattern in (
            ('psci', r'\| `psci`, at most \| (\d+) \|'), ('usbsmmu', r'\| `usbsmmu`, at most \| (\d+) \|'), ('timer', r'\| `timer`, at most \| (\d+) \|'),
            ('unit', r"\| panel region, the unit's 2880 x 1920 panel \| (\d+) \|"),
            ('stock', r'\| panel region, the stock layout: the least it asks for \| (\d+) \|'))}
        if not all(found.values()):
            self.skipTest("the runner's planning table has another shape")
        n = {key: int(match.group(1)) for key, match in found.items()}
        most = int(self.program('lines-report').strip().split('=')[1])
        by = {row[0]: row for row in rows(block(self.text, 'cpuon-chain-budget'))}
        self.assertEqual(len(by), 3)
        for chain, formula, unit, stock in by.values():
            with self.subTest(chain=chain):
                self.assertRegex(formula, r'^[0-9 +()x]+ = \d+$')
                left, right = formula.split(' = ')
                self.assertEqual(eval(left.replace('x', '*')), int(right))
                self.assertEqual((unit, stock), ('yes' if int(right) <= n['unit'] else 'no', 'yes' if int(right) <= n['stock'] else 'no'))
        for chain, parts in (('`cpuon` alone', (2, 3, most)), ('`psci`, then `cpuon`', (3, 6, n['psci'], most)),
                             ('`psci`, `usbsmmu`, `timer`, then `cpuon`', (5, 12, n['psci'], n['usbsmmu'], n['timer'], most))):
            self.assertEqual(int(by[chain][1].split(' = ')[1]), sum(parts), chain)

    def test_the_decision_table_names_every_outcome_the_payload_can_reach(self):
        decisions = rows(block(self.text, 'cpuon-decisions'))
        self.assertGreaterEqual(len(decisions), 15)
        for row in decisions:
            self.assertEqual(len(row), 3)
            self.assertTrue(all(row), row)
        table = ' '.join(' '.join(row) for row in decisions)
        for word in ('NOT_STARTED', 'NO_REPORT', 'NOT_EL2', 'FAULT', 'MPIDR', 'IDS', 'FRQ', 'NOT_OFF', 'INVALID_ADDRESS', 'INVALID_PARAMETERS',
                     'DENIED', 'ALREADY_ON', 'ON_PENDING', 'ENTERED_AT_EL1', 'STILL_ON', 'CPU_ON_FAILED', 'P2 SKIPPED', 'DT_US', 'CNTVOFF_EL2'):
            self.assertIn(word, table, f'the decision table does not mention {word}')
        for word in ('NOT_STARTED', 'NO_REPORT', 'NOT_EL2', 'FAULT', 'MPIDR', 'IDS', 'FRQ', 'NOT_OFF'):
            self.assertIn(word, self.code, f'{word} is no reason the payload gives')

    def test_the_qemu_panel_has_the_shape_of_the_payloads_page(self):
        lines = block(self.text, 'cpuon-qemu-panel').replace('```', '').strip().splitlines()
        self.assertEqual(len(lines), 38)
        for line in lines:
            self.assertRegex(line, r'[A-Z0-9 :\-./=?()_]{1,86}')
            self.assertEqual(line.split()[0] in ('BOOT_CPU', 'NEXT', 'AFFINITY', 'P1', 'P2', 'CORES', 'NOT_DONE'), True, line)
        self.assertEqual([line for line in lines if line.startswith('NEXT')],
                         ['NEXT AFFINITY', 'NEXT PREPARE', 'NEXT CPU_ON 0X1 AFTER 8 S', 'NEXT CPU_ON ALL AFTER 8 S'])


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
