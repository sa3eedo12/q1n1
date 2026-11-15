#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""docs/SP11-PAYLOAD-CNTHCTL.md against the source, the host model and the binary of the cnthctl payload, and the same agreement
tests against 41 seeded mistakes in the document.

    python3 tools/test-q1n1-sp11-payload-cnthctl-doc.py

What it holds the document to: the house rules (the licence line, the size limit, no machine identifier, the evidence labels,
hardware NOT RUN, no run authorised); the write table, the bit table and the instruction table against the source and the built
binary (the encoding of `msr cnthctl_el2` is read from llvm-mc, not from the allow-list); the pages against what the host program
prints; every keyword the payload can print against the document and every keyword of the line catalogue against the payload; the
decision table (which outcome kills O1, which leaves it open); the numbers (eight seconds, the frequency bounds, the stuck-counter
read count, the most lines); the chain arithmetic against the runner's planning table; the QEMU panel's shape; the counts of the
tests table; the authorisation, the stop rule and the staging plan. Writes only under build/. Hardware: NOT RUN."""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_ecv_lib as ecv  # noqa: E402

driver = ecv.load_module('sp11_payload_cnthctl_driver_for_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload-cnthctl.py')
native = driver.native
DOC, SOURCE, RUNNER_DOC = driver.DOC, driver.SOURCE, ROOT / 'docs' / 'SP11-PAYLOAD.md'
LINE_WORD = re.compile(r'\b[A-Z][A-Z0-9_]{2,}\b')
block, rows = ecv.block, ecv.rows
_PROGRAM_OUTPUT = {}     # the host program's output by arguments: the document mutants would otherwise rebuild it for every copy
_BINARY_FACTS = []


def read_doc(name):
    return (ROOT / 'docs' / name).read_text(encoding='utf-8')


class CnthctlDocAgreement(unittest.TestCase):
    TEXT = None     # a changed copy of the document, for CnthctlDocMutants

    @classmethod
    def setUpClass(cls):
        if not DOC.exists():
            raise unittest.SkipTest('docs/SP11-PAYLOAD-CNTHCTL.md does not exist')
        cls.text = DOC.read_text(encoding='utf-8') if cls.TEXT is None else cls.TEXT
        cls.flat = ' '.join(cls.text.split())               # the paragraphs are wrapped: phrases are looked up with the wraps undone
        cls.code = driver.code_of(SOURCE)
        cls.source = SOURCE.read_text(encoding='utf-8')

    def says(self, phrase):
        self.assertIn(' '.join(phrase.split()), self.flat, f'the document does not say {phrase!r}')

    def program(self, *args):
        if not lib.have('clang'):
            self.skipTest('clang not installed')
        if args not in _PROGRAM_OUTPUT:
            done, binary = native.build_program('cnthctl', native.UEFI, native.PAYLOADS, driver.BUILD / 'doc')
            self.assertEqual(done.returncode, 0, done.stderr)
            code, output = native.run_program(binary, *args)
            self.assertEqual(code, 0, output)
            _PROGRAM_OUTPUT[args] = output
        return _PROGRAM_OUTPUT[args]

    def pages(self):
        """The host model's pages by title: {title: [lines]}."""
        pages, title = {}, None
        for line in self.program('page').splitlines():
            if line.startswith('# '):
                title = line[2:]
                pages[title] = []
            elif title:
                pages[title].append(line)
        return pages

    # -- the house rules ------------------------------------------------------------------------------------------------------
    def test_the_document_follows_the_house_rules(self):
        self.assertEqual(self.text.splitlines()[0], '<!-- SPDX-License-Identifier: MIT -->')
        self.assertLess(len(self.text.splitlines()), 1500)
        self.assertLess(len(self.text.encode('utf-8')), 50 * 1024)
        for label in ('VERIFIED', 'OBSERVED', 'INFERRED', 'EXPERIMENTAL', 'UNIMPLEMENTED', 'UNKNOWN'):
            self.assertIn(label, self.text)
        self.assertIn('hardware NOT RUN', self.text)
        self.says('**EXPERIMENTAL; hardware NOT RUN.**')
        self.says('no value of this payload has been OBSERVED on the unit')
        paths = '|'.join(['/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/'])
        pattern = re.compile(paths + r'|\.loc' + r'al\b|\bsae' + r'ed\b|host' + r'name|\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', re.I)
        for number, line in enumerate(self.text.splitlines(), 1):
            self.assertIsNone(pattern.search(line), f'{number}: {line}')

    def test_the_links_and_anchors_resolve(self):
        texts = {DOC.name: self.text}
        for other in ('SP11-PAYLOAD.md', 'SP11-PAYLOAD-TIMER.md', 'SP11-PAYLOAD-CPUON.md'):
            texts[other] = read_doc(other)
        if (ROOT / 'docs' / 'SP11-PAYLOAD-EL1TRAP.md').exists():
            texts['SP11-PAYLOAD-EL1TRAP.md'] = read_doc('SP11-PAYLOAD-EL1TRAP.md')
        self.assertEqual([p for p in lib.link_problems(texts, ROOT / 'docs') if p.startswith(DOC.name)], [])

    def test_nothing_is_authorised_here_and_the_authorisation_stop_rule_and_staging_are_stated(self):
        self.says('No run is authorised by this document, by its test, or by the fact that the file is on the stick.')
        self.says('the operator names the payload and its SHA-256 in writing before it runs on the unit')
        self.says('**Stop rule.** After the run the operator reads the page before anything else is run.')
        for word in ('`RESTORED=NO` or `NOT_RESTORED`', 'a page that ends at the `NEXT` line', 'a fault page', 'a board restart'):
            self.assertIn(word, self.text)
        self.says('`cnthctl` **alone** on its stick')
        self.says('`el1trap` is staged only after `BITS13_14_STUCK=YES` with `RESTORED=YES` was read')
        self.assertIn('build/stick/SP11/PAYLOAD.MAN', self.text)
        self.assertIn('build/stick/SP11/CNTHCTL.BIN', self.text)
        self.assertIn('python3 tools/sp11_payload_manifest.py --out-dir build/stick build/uefi/payloads/cnthctl.bin', self.text)
        self.says('Status of the staging: **proposed, NOT RUN**.')

    # -- the write, the bits, the instructions -----------------------------------------------------------------------------------
    def test_the_write_table_is_the_sources_three_writes_and_the_encoding_is_llvm_mcs(self):
        table = rows(block(self.text, 'cnthctl-write'))
        self.assertEqual([row[1] for row in table], ['first', 'second', 'third, only if R2 is not OLD'])
        self.assertTrue(all(row[0].startswith('`CNTHCTL_EL2`') for row in table))
        self.assertEqual(len(re.findall(r'\bwrite_cnthctl_el2\(', self.code)) - 1, 3)
        done = lib.run(['llvm-mc', '-triple=aarch64', '-show-encoding'], input='msr S3_4_C14_C1_0, x0\nmsr cnthctl_el2, x0\n')
        found = re.findall(r'encoding: \[([^\]]*)\]', done.stdout)
        self.assertEqual(len(found), 2, done.stderr)
        self.assertEqual(found[0], found[1], 'S3_4_C14_C1_0 is CNTHCTL_EL2')
        word = int.from_bytes(bytes(int(b, 16) for b in found[0].split(',')), 'little')
        self.assertEqual(word & 0xffffffe0, 0xd51ce100)
        self.assertEqual(lib.ALLOW_WORDS[('msr', 'cnthctl_el2')], ('msr-register', 0xffffffe0, word & 0xffffffe0))
        self.says('the encoding `0xd51ce100` under the mask `0xffffffe0`')

    def test_the_bit_table_is_the_sources_constants_and_the_formula(self):
        defines = {name: int(re.search(rf'#define {name} \(UINT64_C\(1\) << (\d+)\)', self.code).group(1))
                   for name in ('EL1TVT_BIT', 'EL1TVCT_BIT', 'ECV_BIT')}
        self.assertEqual(defines, {'EL1TVT_BIT': 13, 'EL1TVCT_BIT': 14, 'ECV_BIT': 12})
        self.assertEqual(re.search(r'#define EL1_PHYSICAL_BITS UINT64_C\((\d+)\)', self.code).group(1), '3')
        table = {row[0]: row for row in rows(block(self.text, 'cnthctl-bits'))}
        self.assertEqual(set(table), {'0', '1', '11:2', '12', '13', '14'})
        self.assertEqual({bit: table[bit][2] for bit in table},
                         {'0': 'cleared', '1': 'cleared', '11:2': 'as found in OLD', '12': '**never set**', '13': 'set', '14': 'set'})
        self.assertIn('`EL1TVT` (traps the EL1 virtual timer registers)', table['13'][1])
        self.assertIn('`EL1TVCT` (traps the EL1 virtual counter)', table['14'][1])
        self.assertIn('`ECV`', table['12'][1])
        self.says('`V = (OLD & ~3) | (1 << 14) | (1 << 13)`')

    def test_the_instruction_table_is_the_binary(self):
        driver.need_tools()
        if not _BINARY_FACTS:
            done, elf, flat = driver.Builder(driver.BUILD / 'doc-binary').build('cnthctl', 'cnthctl', [])
            self.assertEqual(done.returncode, 0, done.stderr)
            _BINARY_FACTS.append(driver.facts(elf, flat))
        f = _BINARY_FACTS[0]
        section = block(self.text, 'cnthctl-instructions')
        self.assertIn('| `MSR` | `CNTHCTL_EL2`, 1 site |', section)
        self.assertEqual(dict(f['msr']), {'cnthctl_el2': 1})
        self.assertIn('| `ISB` | 1 site |', section)
        self.assertEqual(f['mnemonics']['isb'], 1)
        self.assertIn('`CNTHCTL_EL2`, 1 site | one helper, called for OLD, R, R2 and R3', section)
        self.assertEqual(len(re.findall(r'\bread_cnthctl_el2\(\)', self.code)), 4)
        named = set()
        for row in rows(section):
            if row[0] == '`MRS`':
                named |= {token.lower() for token in re.findall(r'`(\w+)`', row[1])}
        self.assertEqual(named, lib.POLICIES['cnthctl']['registers'])
        self.assertEqual(set(f['mrs']), named)
        for word in ('CNTPOFF_EL2', 'CNTVOFF_EL2'):
            self.assertNotIn(word.lower(), ' '.join(i[1].lower() for i in f['instruction_list']))

    # -- what it prints -----------------------------------------------------------------------------------------------------------
    def test_every_keyword_the_payload_can_print_is_in_the_document_and_the_catalogue_names_only_such_keywords(self):
        literals = ' '.join(re.findall(r'"([^"\n]*)"', self.code))
        mine = set(LINE_WORD.findall(literals))
        self.assertGreater(len(mine), 25)
        lines_block = block(self.text, 'cnthctl-lines')
        for word in sorted(mine):
            self.assertIn(word, self.text, f'{word} can be printed and is not in the document')
            if word not in ('PAYLOAD', 'CNTHCTL'):       # the prefix of every line, said once above the catalogue
                self.assertIn(word, lines_block, f'{word} can be printed and is not in the line catalogue')
        catalogue = {word for row in rows(lines_block) for word in LINE_WORD.findall(row[0])}
        placeholders = {'YES', 'NO', 'PARTIAL'}
        for word in sorted(catalogue - mine - placeholders):
            self.fail(f'{word} is in the line catalogue and nothing in the source prints it')
        self.assertIn('`NEXT CNTHCTL_EL2 WRITE AFTER 8 S`', {row[0] for row in rows(lines_block)})

    def test_the_pages_are_what_the_host_program_prints(self):
        pages = self.pages()
        first = block(self.text, 'cnthctl-page').replace('```', '').strip().splitlines()
        self.assertEqual(first, pages['bits stick'])
        self.assertEqual(len(first), 8)
        self.says('A normal run is 8 lines')
        tails = {}
        title = None
        for line in block(self.text, 'cnthctl-pages').replace('```', '').strip().splitlines():
            if line.startswith('# '):
                title = line[2:]
                tails[title] = []
            else:
                tails[title].append(line)
        self.assertEqual(set(tails), {'bits do not stick', 'only bit 14 sticks', 'restore fails', 'restore needs the retry'})
        for title, tail in tails.items():
            with self.subTest(world=title):
                self.assertEqual(tail, pages[title][4:])
                self.assertEqual(pages[title][:4], first[:4], 'the first four lines are the same in every world')
        # A stuck-but-inert machine prints the first page: the host suite asserts it, the document says it.
        self.says('prints exactly the first page')

    def test_the_most_lines_and_the_numbers_are_the_sources(self):
        self.assertEqual(self.program('lines-report').strip(), f'LINES_MAX={driver.LINES_MAX}')
        self.says(f'At most {driver.LINES_MAX} lines')
        self.says(f'the most `cnthctl` prints over every EL and every machine it scripts: {driver.LINES_MAX}')
        defines = {name: value for name, value in re.findall(r'#define (\w+) (\d+)u', self.code)}
        self.assertEqual((defines['WAIT_BEFORE_WRITE_S'], defines['COUNTER_HZ_DEFAULT'], defines['COUNTER_HZ_MIN'], defines['COUNTER_HZ_MAX'],
                          defines['COUNTER_STUCK_READS']), ('8', '19200000', '1000000', '1000000000', '2000000'))
        self.says('eight seconds on the runner\'s counter')
        self.says('not between 1 MHz and 1 GHz, in which case the wait uses 19.2 MHz')
        self.says('two million equal reads in a row')
        self.assertIn('NEXT CNTHCTL_EL2 WRITE AFTER 8 S', self.text)
        self.assertEqual(self.code.count('NEXT CNTHCTL_EL2 WRITE AFTER 8 S'), 1)

    def test_the_chain_arithmetic_is_right_and_uses_the_measured_and_the_runners_numbers(self):
        runner = block(RUNNER_DOC.read_text(encoding='utf-8'), 'chain-budget')
        found = {key: re.search(pattern, runner) for key, pattern in (
            ('psci', r'\| `psci`, at most \| (\d+) \|'),
            ('unit', r"\| panel region, the unit's 2880 x 1920 panel \| (\d+) \|"),
            ('stock', r'\| panel region, the stock layout: the least it asks for \| (\d+) \|'))}
        if not all(found.values()):
            self.skipTest("the runner's planning table has another shape")
        n = {key: int(match.group(1)) for key, match in found.items()}
        most = int(self.program('lines-report').strip().split('=')[1])
        by = {row[0]: row for row in rows(block(self.text, 'cnthctl-chain-budget'))}
        self.assertEqual(set(by), {'`cnthctl` alone', '`psci`, then `cnthctl`'})
        for chain, formula, unit, stock in by.values():
            with self.subTest(chain=chain):
                self.assertRegex(formula, r'^[0-9 +()x]+ = \d+$')
                left, right = formula.split(' = ')
                self.assertEqual(eval(left.replace('x', '*')), int(right))
                self.assertEqual((unit, stock), ('yes' if int(right) <= n['unit'] else 'no', 'yes' if int(right) <= n['stock'] else 'no'))
        for chain, parts in (('`cnthctl` alone', (2, 3, most)), ('`psci`, then `cnthctl`', (3, 6, n['psci'], most))):
            self.assertEqual(int(by[chain][1].split(' = ')[1]), sum(parts), chain)

    # -- the decisions --------------------------------------------------------------------------------------------------------------
    def test_the_decision_table_names_every_outcome_and_says_which_ones_kill_o1(self):
        decisions = rows(block(self.text, 'cnthctl-decisions'))
        self.assertGreaterEqual(len(decisions), 11)
        for row in decisions:
            self.assertEqual(len(row), 3)
            self.assertTrue(all(row), row)
        table = ' '.join(' '.join(row) for row in decisions)
        for word in ('BITS13_14_STUCK=YES', 'BITS13_14_STUCK=NO', 'BITS13_14_STUCK=PARTIAL', 'R_EQ_V=NO', 'RESTORED=NO', 'RESTORE_RETRY',
                     'NOT_RESTORED', 'NEXT CNTHCTL_EL2 WRITE AFTER 8 S', 'REFUSED=E2H', 'REFUSED=OLD_HAS_BITS_12_TO_14', 'REFUSED=COUNTER_STUCK',
                     'REFUSED=NO_COUNTER', 'SKIPPED_NOT_AT_EL2', 'FREQ=DEFAULT', 'O1', 'O2', 'O3', 'O4', 'el1trap'):
            self.assertIn(word, table, f'the decision table does not mention {word}')
        by = {row[0]: row for row in decisions}
        yes = next(row for key, row in by.items() if key.startswith('`BITS13_14_STUCK=YES R_EQ_V=YES`'))
        no = next(row for key, row in by.items() if key.startswith('`BITS13_14_STUCK=NO`'))
        partial = next(row for key, row in by.items() if key.startswith('`BITS13_14_STUCK=PARTIAL`'))
        hang = next(row for key, row in by.items() if 'ends at `NEXT' in key)
        self.assertIn('**not eliminated and not decided**', yes[2])
        self.assertNotIn('eliminated**', yes[2].replace('not eliminated and not decided**', ''))
        self.assertIn('**O1 is eliminated**', no[2])
        self.assertIn('eliminated', partial[2])
        self.assertIn('**O1 is eliminated**', hang[2])
        for word in ('NOT_RESTORED', 'RESTORED=NO'):
            self.assertIn(word, self.code)

    def test_the_options_are_those_of_the_audit_and_o4_is_never(self):
        self.says('**O1** the A16 recipe')
        self.says('**O4** `CNTPOFF_EL2` / ECV level 2 ("never": a read of it stalls the board)')
        self.says('A "do not stick" answer here eliminates option O1 of the audit')
        self.says('a "stick" answer does **not** decide it, because a register can hold bits that trap nothing')

    def test_what_is_not_measured_is_not_called_observed(self):
        self.says('INFERRED from the architecture, which was not re-read')
        self.says('INFERRED, for example by `SCR_EL3.ECVEn` clear, which no payload can read')
        self.says('A write of `CNTHCTL_EL2` at EL2 is an ordinary EL2 access')
        for at in re.finditer(r'ECVEn', self.flat):
            self.assertRegex(self.flat[max(0, at.start() - 200):at.end() + 200], r'INFERRED|UNKNOWN', 'ECVEn is said as a fact')
        self.assertNotRegex(self.flat, r'(?i)OBSERVED[^.]{0,80}\bbits? 13\b')
        self.assertIn('restarts of the board have been seen after the `cpuon` payload'.lower(), self.flat.lower())
        self.says('INFERRED to be associated with its core power cycling (cause UNKNOWN)')

    # -- the QEMU block and the tests table -------------------------------------------------------------------------------------------
    def test_the_qemu_panel_has_the_shape_the_qemu_suite_asserts(self):
        lines = block(self.text, 'cnthctl-qemu-panel').replace('```', '').strip().splitlines()
        self.assertEqual(len(lines), 8)
        patterns = [r'CURRENTEL=0X8 HCR_EL2=0X[0-9A-F]+ E2H=0X0', r'ID_AA64MMFR0_EL1=0X[0-9A-F]+ ECV=0X2',
                    r'CNTHCTL_EL2 OLD=0X3 CNTFRQ_EL0=0X3B9ACA00', 'NEXT CNTHCTL_EL2 WRITE AFTER 8 S', 'OLD=0X3 V=0X6000', 'R=0X6000 R2=0X3',
                    'BITS13_14_STUCK=YES R_EQ_V=YES', 'RESTORED=YES']
        for line, pattern in zip(lines, patterns):
            self.assertRegex(line, f'^{pattern}$')
        qemu_source = (ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu-cnthctl.py').read_text(encoding='utf-8')
        for fragment in ("'BITS13_14_STUCK=YES R_EQ_V=YES'", "'R=0X6000 R2=0X3'", "'OLD=0X3 V=0X6000'", "'NEXT CNTHCTL_EL2 WRITE AFTER 8 S'"):
            self.assertIn(fragment, qemu_source)
        self.says('7 and 40 seconds')
        self.assertIn('7.0 <= seconds <= 40.0', qemu_source)

    def test_the_tests_table_counts_what_the_tests_hold(self):
        for claim in (f'{len(driver.MUTANTS)} seeded-bug mutants', f'{len(driver.BAD_BINARIES)} seeded bad binaries',
                      f'{len(DOC_MUTANTS)} seeded mistakes in the document', 'six suites', '6000 random worlds'):
            self.assertIn(claim, self.text)
        self.assertEqual(len(driver.SUITES), 6)
        host = (ROOT / 'tools' / 'test-q1n1-sp11-payload-cnthctl.c').read_text(encoding='utf-8')
        self.assertIn('i < 6000', host)
        self.assertGreaterEqual(len(driver.MUTANTS), 50)
        self.assertGreaterEqual(len(driver.BAD_BINARIES), 30)

    def test_the_other_documents_are_the_ones_it_names(self):
        for name in ('SP11-PAYLOAD.md', 'SP11-PAYLOAD-TIMER.md', 'SP11-PAYLOAD-CPUON.md'):
            self.assertTrue((ROOT / 'docs' / name).exists(), name)
        self.says('Its successor, [`el1trap`](SP11-PAYLOAD-EL1TRAP.md), is T-HW2 and only runs after this one.')


# ---- seeded mistakes in the document --------------------------------------------------------------------------------------------

def _replace(old, new, count=1):
    def mutate(doc):
        assert old in doc, old
        return doc.replace(old, new, count)
    return mutate


DOC_MUTANTS = [
    ('the-wait-in-the-lines-table-is-wrong', _replace('| `NEXT CNTHCTL_EL2 WRITE AFTER 8 S` | the write follows eight seconds after this line |',
                                                      '| `NEXT CNTHCTL_EL2 WRITE AFTER 5 S` | the write follows eight seconds after this line |')),
    ('the-wait-in-the-prose-is-wrong', _replace('then eight seconds on the runner\'s counter', 'then ten seconds on the runner\'s counter')),
    ('bit-13-is-renumbered', _replace('| 13 | `EL1TVT`', '| 15 | `EL1TVT`')),
    ('bit-14-is-called-the-timer', _replace('| 14 | `EL1TVCT` (traps the EL1 virtual counter)', '| 14 | `EL1TVCT` (traps the EL1 virtual timer)')),
    ('ecv-is-set-in-v', _replace('| 12 | `ECV` | **never set** |', '| 12 | `ECV` | set |')),
    ('bit-0-is-kept', _replace('physical counter) | cleared |', 'physical counter) | set |')),
    ('the-formula-is-wrong', _replace('`V = (OLD & ~3) | (1 << 14) | (1 << 13)`', '`V = (OLD & ~1) | (1 << 14) | (1 << 13)`')),
    ('two-msr-sites', _replace('| `MSR` | `CNTHCTL_EL2`, 1 site |', '| `MSR` | `CNTHCTL_EL2`, 2 sites |')),
    ('two-isb-sites', _replace('| `ISB` | 1 site |', '| `ISB` | 2 sites |')),
    ('an-mrs-register-is-forgotten', _replace('`CurrentEL`, `HCR_EL2`, `ID_AA64MMFR0_EL1`, `CNTFRQ_EL0` |', '`CurrentEL`, `HCR_EL2`, `ID_AA64MMFR0_EL1` |')),
    ('an-mrs-register-is-invented', _replace('`CurrentEL`, `HCR_EL2`, `ID_AA64MMFR0_EL1`, `CNTFRQ_EL0` |', '`CurrentEL`, `HCR_EL2`, `ID_AA64MMFR0_EL1`, `CNTFRQ_EL0`, `CNTVCT_EL0` |')),
    ('the-encoding-is-wrong', _replace('`0xd51ce100` under the mask', '`0xd51ce000` under the mask')),
    ('a-write-row-is-forgotten', _replace('| `CNTHCTL_EL2` | third, only if R2 is not OLD | OLD again | the one retry |\n', '')),
    ('the-first-page-changes', _replace('PAYLOAD CNTHCTL R=0X6000 R2=0X3\nPAYLOAD CNTHCTL BITS13_14_STUCK=YES R_EQ_V=YES\nPAYLOAD CNTHCTL RESTORED=YES\n```\n<!-- /cnthctl-page -->',
                                        'PAYLOAD CNTHCTL R=0X6000 R2=0X6000\nPAYLOAD CNTHCTL BITS13_14_STUCK=YES R_EQ_V=YES\nPAYLOAD CNTHCTL RESTORED=YES\n```\n<!-- /cnthctl-page -->')),
    ('a-tail-changes', _replace('PAYLOAD CNTHCTL BITS13_14_STUCK=PARTIAL R_EQ_V=NO', 'PAYLOAD CNTHCTL BITS13_14_STUCK=PARTIAL R_EQ_V=YES')),
    ('a-world-is-forgotten', _replace('# restore needs the retry\n', '# restore needs the retry once\n')),
    ('a-keyword-is-forgotten', _replace('| `RESTORED=NO`, `NOT_RESTORED OLD=0X.. NOW=0X..`, `POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD` |', '| `RESTORED=NO`, `NOT_RESTORED OLD=0X.. NOW=0X..` |')),
    ('a-keyword-is-invented', _replace('| `REFUSED=NO_COUNTER` | the runner gave no counter: nothing else was done |', '| `REFUSED=NO_COUNTER` | the runner gave no counter: nothing else was done |\n| `DONE` | the end |')),
    ('no-bits-is-called-not-eliminated', _replace('**O1 is eliminated**: the monitor\'s recipe cannot trap', '**O1 is open**: the monitor\'s recipe cannot trap')),
    ('stuck-is-called-eliminated', _replace('O1 is **not eliminated and not decided**', 'O1 is **eliminated**')),
    ('a-hang-is-called-harmless', _replace('the monitor must not write it. **O1 is eliminated**. Photograph', 'the monitor may write it. **O1 is open**. Photograph')),
    ('the-lines-maximum-is-wrong', _replace('At most 11 lines', 'At most 12 lines')),
    ('the-normal-run-is-wrong', _replace('A normal run is 8 lines', 'A normal run is 9 lines')),
    ('the-chain-sum-is-wrong', _replace('(1 + 1) + 3 + 11 = 16', '(1 + 1) + 3 + 11 = 17')),
    ('the-chain-verdict-is-wrong', _replace('| `psci`, then `cnthctl` | (2 + 1) + 3 x 2 + 30 + 11 = 50 | yes | yes |', '| `psci`, then `cnthctl` | (2 + 1) + 3 x 2 + 30 + 11 = 50 | yes | no |')),
    ('the-qemu-ecv-is-wrong', _replace('ID_AA64MMFR0_EL1=0X2100032310201126 ECV=0X2\nCNTHCTL_EL2 OLD=0X3 CNTFRQ_EL0=0X3B9ACA00', 'ID_AA64MMFR0_EL1=0X2100032310201126 ECV=0X0\nCNTHCTL_EL2 OLD=0X3 CNTFRQ_EL0=0X3B9ACA00')),
    ('the-qemu-wait-window-is-wrong', _replace('between 7 and 40 seconds', 'between 7 and 80 seconds')),
    ('the-mutant-count-is-wrong', _replace(f'{len(driver.MUTANTS)} seeded-bug mutants', f'{len(driver.MUTANTS) + 1} seeded-bug mutants')),
    ('the-bad-binary-count-is-wrong', _replace(f'{len(driver.BAD_BINARIES)} seeded bad binaries', f'{len(driver.BAD_BINARIES) - 1} seeded bad binaries')),
    ('the-licence-line-goes', lambda doc: doc.split('\n', 1)[1]),
    ('hardware-is-called-run', _replace('**EXPERIMENTAL; hardware NOT RUN.**', '**EXPERIMENTAL; hardware RUN.**')),
    ('the-unit-is-said-to-have-been-observed', _replace('no value of this payload has been OBSERVED on the unit', 'its values have been OBSERVED on the unit')),
    ('a-run-is-authorised', _replace('No run is authorised by this document', 'A run is authorised by this document')),
    ('the-stop-rule-forgets-the-restore', _replace('`RESTORED=NO` or `NOT_RESTORED`; a page', 'a page')),
    ('it-is-staged-with-psci', _replace('`cnthctl` **alone** on its stick', '`cnthctl` after `psci` on its stick')),
    ('el1trap-follows-any-answer', _replace('`el1trap` is staged only after `BITS13_14_STUCK=YES` with `RESTORED=YES`', '`el1trap` is staged after any answer')),
    ('an-unverified-claim-is-called-verified', _replace('(INFERRED from the architecture, which was not re-read)', '(VERIFIED from the architecture)')),
    ('a-link-is-broken', _replace('(SP11-PAYLOAD-TIMER.md)', '(SP11-PAYLOAD-TIMER-X.md)')),
    ('an-anchor-is-broken', _replace('#the-chain-several-payloads-in-one-boot)', '#the-chain-several-payloads-in-one-boots)')),
    ('a-machine-identifier-appears', _replace('# SP11 payload `cnthctl`', '# SP11 payload `cnthctl` at /Us' + 'ers/x')),
    ('the-document-is-too-big', lambda doc: doc + '\n' + 'x' * 52000),
]


class CnthctlDocMutants(unittest.TestCase):
    """The agreement tests above must be able to fail: each seeded mistake in the document is refused by one."""

    @staticmethod
    def outcome(text):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(type('Changed', (CnthctlDocAgreement,), {'TEXT': text}))
        result = unittest.TestResult()
        suite.run(result)
        return result

    def test_the_unchanged_document_passes_through_the_same_mechanism(self):
        result = self.outcome(DOC.read_text(encoding='utf-8'))
        self.assertTrue(result.wasSuccessful(), [str(f[1])[-400:] for f in result.failures + result.errors])
        self.assertGreaterEqual(result.testsRun, 14)
        self.assertEqual(result.skipped, [], 'a skipped agreement test proves nothing')

    def test_every_seeded_mistake_in_the_document_is_refused(self):
        original = DOC.read_text(encoding='utf-8')
        self.assertGreaterEqual(len(DOC_MUTANTS), 30)
        self.assertEqual(len({name for name, _ in DOC_MUTANTS}), len(DOC_MUTANTS))
        for name, mutate in DOC_MUTANTS:
            with self.subTest(mutant=name):
                changed = mutate(original)
                self.assertNotEqual(changed, original)
                self.assertFalse(self.outcome(changed).wasSuccessful(), 'every agreement test still passed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
