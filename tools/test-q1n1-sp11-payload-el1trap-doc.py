#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""docs/SP11-PAYLOAD-EL1TRAP.md against the source, the host model, the binary and the QEMU suite of the el1trap payload, and the same
agreement tests against 57 seeded mistakes in the document.

    python3 tools/test-q1n1-sp11-payload-el1trap-doc.py

What it holds the document to: the house rules (the licence line, the size limit, no machine identifier, the evidence labels, hardware
NOT RUN, no run authorised); the write, `HCR_EL2`, `SCTLR_EL1` and bit tables against the source's constants; the stub table against the
ISS computed from the words of the built stub (not from the payload's own table); the handler and bounds tables against the source;
the instruction table against the built binary; the pages against what the host program prints; every keyword the payload can print
against the document and every keyword of the line catalogue against the payload; the decision table (which verdict supports O1, which
kills it, which is void); the numbers; the chain arithmetic against the runner's planning table; the QEMU panel against the QEMU suite's
patterns; the counts of the tests table; the authorisation, the stop rule and the staging plan. Writes only under build/. Hardware: NOT RUN."""
import re
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_ecv_lib as ecv  # noqa: E402

driver = ecv.load_module('sp11_payload_el1trap_driver_for_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload-el1trap.py')
qemu = ecv.load_module('sp11_payload_el1trap_qemu_for_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu-el1trap.py')
native = driver.native
DOC, SOURCE, RUNNER_DOC = ROOT / 'docs' / 'SP11-PAYLOAD-EL1TRAP.md', driver.SOURCE, ROOT / 'docs' / 'SP11-PAYLOAD.md'
LINE_WORD = re.compile(r'\b[A-Z][A-Z0-9_]{2,}\b')
block, rows = ecv.block, ecv.rows
_PROGRAM_OUTPUT = {}
_BINARY = []
WORLDS = {'bits do not stick': 11, 'stuck but inert': 11, 'only bit 14 sticks': 11, 'control not trapped': 11, 'hvc undefined at el2': 8,
          'write not held': 11, 'restore fails': 11}


def read_doc(name):
    return (ROOT / 'docs' / name).read_text(encoding='utf-8')


def built():
    """(facts, ISS of each MRS word of the stub) of the built binary, cached."""
    if not _BINARY:
        driver.need_tools()
        done, elf, flat = driver.Builder(driver.BUILD / 'doc-binary').build('el1trap', 'el1trap', [])
        assert done.returncode == 0, done.stderr
        symbols = {m.group(2): int(m.group(1), 16) for m in re.finditer(r'^([0-9a-f]+) <(\w+)>:$', lib.run(['llvm-objdump', '-d', str(elf)]).stdout, re.M)}
        words = struct.unpack_from('<5I', Path(flat).read_bytes(), symbols['el1trap_stub'])
        iss = [(w >> 19 & 3) << 20 | (w >> 5 & 7) << 17 | (w >> 16 & 7) << 14 | (w >> 12 & 15) << 10 | (w & 31) << 5 | (w >> 8 & 15) << 1 | 1 for w in words[:4]]
        _BINARY.append((driver.facts(elf, flat), iss))
    return _BINARY[0]


class El1trapDocAgreement(unittest.TestCase):
    TEXT = None     # a changed copy of the document, for El1trapDocMutants

    @classmethod
    def setUpClass(cls):
        if not DOC.exists():
            raise unittest.SkipTest('docs/SP11-PAYLOAD-EL1TRAP.md does not exist')
        cls.text = DOC.read_text(encoding='utf-8') if cls.TEXT is None else cls.TEXT
        cls.flat = ' '.join(cls.text.split())               # the paragraphs are wrapped: phrases are looked up with the wraps undone
        cls.code = driver.code_of(SOURCE)

    def says(self, phrase):
        self.assertIn(' '.join(phrase.split()), self.flat, f'the document does not say {phrase!r}')

    def program(self, *args):
        if not lib.have('clang'):
            self.skipTest('clang not installed')
        if args not in _PROGRAM_OUTPUT:
            done, binary = native.build_program('el1trap', native.UEFI, native.PAYLOADS, driver.BUILD / 'doc')
            self.assertEqual(done.returncode, 0, done.stderr)
            code, output = native.run_program(binary, *args)
            self.assertEqual(code, 0, output)
            _PROGRAM_OUTPUT[args] = output
        return _PROGRAM_OUTPUT[args]

    def pages(self):
        pages, title = {}, None
        for line in self.program('page').splitlines():
            if line.startswith('# '):
                title = line[2:]
                pages[title] = []
            elif title:
                pages[title].append(line)
        return pages

    def table(self, name):
        return {row[0]: row for row in rows(block(self.text, name))}

    def define(self, name):
        return re.search(rf'#define {name}\s+(.+)', self.code).group(1).strip()

    def macro_value(self, name):
        """The value of a numeric macro, its continuation lines joined, with UINT64_C(x) read as x."""
        body = re.search(rf'#define {name}\s+((?:[^\n]*\\\n)*[^\n]*)', self.code).group(1).replace('\\\n', ' ')
        return eval(body.replace('UINT64_C', ''))

    # -- the house rules ------------------------------------------------------------------------------------------------------
    def test_the_document_follows_the_house_rules(self):
        self.assertEqual(self.text.splitlines()[0], '<!-- SPDX-License-Identifier: MIT -->')
        self.assertLess(len(self.text.splitlines()), 1500)
        self.assertLess(len(self.text.encode('utf-8')), 50 * 1024)
        for label in ('VERIFIED', 'OBSERVED', 'INFERRED', 'EXPERIMENTAL', 'UNIMPLEMENTED', 'UNKNOWN'):
            self.assertIn(label, self.text)
        self.assertIn('hardware NOT RUN', self.text)
        self.says('No value of this payload has been OBSERVED on the unit')
        paths = '|'.join(['/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/'])
        pattern = re.compile(paths + r'|\.loc' + r'al\b|\bsae' + r'ed\b|host' + r'name|\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', re.I)
        for number, line in enumerate(self.text.splitlines(), 1):
            self.assertIsNone(pattern.search(line), f'{number}: {line}')

    def test_the_links_and_anchors_resolve(self):
        texts = {DOC.name: self.text}
        for other in ('SP11-PAYLOAD.md', 'SP11-PAYLOAD-CNTHCTL.md', 'SP11-PAYLOAD-CPUON.md'):
            texts[other] = read_doc(other)
        self.assertEqual([p for p in lib.link_problems(texts, ROOT / 'docs') if p.startswith(DOC.name)], [])
        self.assertIn('## Staging plan', self.text, 'the cnthctl document links to it')

    def test_nothing_is_authorised_here_and_the_authorisation_stop_rule_and_staging_are_stated(self):
        self.says('No run is authorised by this document, by its test, or by the fact that the file is on the stick.')
        self.says('the operator names the payload and its SHA-256 in writing before it runs on the unit')
        self.says('**runs code at EL1**, which no payload has done')
        self.says('**Stop rule.** After the run the operator reads the page before anything else is run.')
        for word in ('`RESTORED=NO` or `NOT_RESTORED`', 'a page that ends at a `NEXT` line', 'a fault page', 'a board restart'):
            self.assertIn(word, self.text)
        self.says('`el1trap` **alone** on its stick, **only after** `cnthctl` printed `BITS13_14_STUCK=YES` with `RESTORED=YES`')
        self.says('it is not run in the same boot as `cpuon`')
        self.assertIn('python3 tools/sp11_payload_manifest.py --out-dir build/stick build/uefi/payloads/el1trap.bin', self.text)
        self.assertIn('build/stick/SP11/EL1TRAP.BIN', self.text)
        self.says('Status of the staging: **proposed, NOT RUN**.')

    # -- what it writes ---------------------------------------------------------------------------------------------------------
    def test_the_write_table_and_the_values_are_the_sources(self):
        table = rows(block(self.text, 'el1trap-write'))
        self.assertEqual([row[0].split()[0] for row in table], ['`VBAR_EL2`', '`SPSR_EL2`,', '`VBAR_EL1`', '`SCTLR_EL1`', '`CNTHCTL_EL2`', '`HCR_EL2`', 'the'])
        self.assertEqual(self.define('HCR_EXCURSION'), '(UINT64_C(1) << 31)')
        self.assertEqual(self.define('SCTLR_EL1_EXCURSION'), 'UINT64_C(0x30500800)')
        self.assertIn('`0x80000000`', table[5][2])
        self.assertIn('`0x30500800`', table[3][2])
        self.says('V = `(OLD & ~3) | (1 << 14) | (1 << 13)`')
        self.assertIn('r.wanted[R_CNTHCTL] = (cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;', self.code)
        order = re.findall(r'write_(\w+)\(r->wanted\[R_(\w+)\]\);', self.code)
        self.assertEqual([name for name, _ in order], ['vbar_el1', 'sctlr_el1', 'cnthctl_el2', 'hcr_el2'], 'the order of the table: first to fourth')
        self.assertEqual([row[3] for row in table[2:6]], ['first of the four writes', 'second', 'third', 'fourth'])
        self.says('VERIFIED against the monitor\'s source')
        self.says('`INIT_SCTLR_EL1_MMU_OFF` of Linux (VERIFIED against that name in commit 7475ea8b5861, GPL-2.0-only')

    def test_the_callers_pstate_the_registers_not_read_back_and_the_backwards_counter_are_what_the_source_does(self):
        kept = (self.macro_value('SPSR_KEPT_HIGH') << 16) | self.macro_value('SPSR_KEPT_LOW')
        self.assertEqual(kept, sum(1 << b for b in (12, 22, 23, 24, 25)), 'SSBS, PAN, UAO, DIT, TCO')
        self.assertEqual((self.macro_value('SPSR_EL2H_MASKED'), self.macro_value('E_CALLER_SPSR')), (0x3c9, 296))
        self.assertEqual(0x0000100030C5183D >> 44 & 1, 1, "DSSBS of the unit's SCTLR_EL2")
        self.assertIn('0x0000100030C5183D', self.text)
        self.says('the mask `0x3C01000`, built from the immediates `0x1000` and `0x3C0 << 16`')
        self.says('and the end of the excursion returns with `0x3C9` plus those of its bits that are `SSBS` (bit 12)')
        self.says('`SSBS` (bit 12) and `PAN`, `UAO`, `DIT`, `TCO` (bits 22 to 25)')
        self.says('`DSSBS` (bit 44) is set')
        self.says('A record with no capture (the probe did not run or failed) is zero, so the return is `0x3C9`, as before.')
        self.says('Not passed on: the flags (not part of a C call), `ALLINT` and any bit this payload does not know')
        self.says('`SPSR_EL2` and `ELR_EL2` are put back by the assembly and are **not** read back, and `RESTORED=YES` does not speak for them')
        self.says("the probe's handler also keeps `SPSR_EL2`, which that exception entry filled with the caller's PSTATE")
        self.says('A counter that does not run (two million equal reads in a row) or that runs backwards (a read below the first, which would end the wait at once)')
        self.assertIn('if (now < start) return 0;', self.code)
        self.assertRegex(self.code, r'mrs x14, spsr_el2\\n"\s*\n\s*"\s+str x14, \[x11, #" STR\(E_CALLER_SPSR\)', 'the probe keeps SPSR_EL2')
        self.assertIn('w->e.caller_spsr = w->probe.caller_spsr;', self.code)

    def test_the_hcr_table_is_the_sources_bits(self):
        table = self.table('el1trap-hcr')
        self.assertEqual({bit: row[2] for bit, row in table.items()},
                         {'31': 'set', '34': 'clear', '27': 'clear', '0': 'clear', '12': 'clear', '29': 'clear', '5:3': 'clear', 'the rest': 'clear'})
        self.assertEqual(self.macro_value('HCR_EXCURSION'), 0x80000000)
        self.assertEqual(self.macro_value('HCR_BITS_CHECKED'), sum(1 << b for b in (31, 34, 27, 29, 0, 12, 3, 4, 5)), 'RW, E2H, TGE, HCD, VM, DC, FMO, IMO, AMO')
        for name in ('`RW`', '`E2H`', '`TGE`', '`VM`', '`DC`', '`HCD`', '`AMO`, `IMO`, `FMO`'):
            self.assertIn(name, ' '.join(row[1] for row in table.values()))
        self.says('(`HCR_EL2` RW, E2H, TGE, VM, DC, HCD, FMO, IMO, AMO;')

    def test_the_sctlr_table_is_the_sources_value_bit_by_bit(self):
        table = self.table('el1trap-sctlr')
        set_bits = [int(b) for b in table['29, 28, 22, 20, 11'][0].split(', ')]
        clear_bits = [int(bit) for bit, row in table.items() if row[2] == 'clear']
        self.assertEqual(sum(1 << b for b in set_bits), 0x30500800)
        self.assertEqual(set(clear_bits), {0, 1, 2, 12, 19, 24, 25})
        self.assertFalse(sum(1 << b for b in clear_bits) & 0x30500800, 'a bit the table says is clear is set in the value')
        self.assertEqual(self.macro_value('SCTLR_EL1_EXCURSION'), 0x30500800)
        self.assertEqual(self.macro_value('SCTLR_EL1_BITS_CHECKED'), sum(1 << b for b in clear_bits), 'M, A, C, I, WXN, E0E, EE')
        self.assertEqual({row[1] for row in table.values() if row[2] == 'set'}, {'`LSMAOE`, `nTLSMD`, `EIS`, `TSCXT`, `EOS`'})
        self.says('An earlier value with `SPAN` set was wrong.')

    def test_the_cnthctl_bit_table_is_the_sources_constants(self):
        defines = {name: int(re.search(rf'#define {name} \(UINT64_C\(1\) << (\d+)\)', self.code).group(1)) for name in ('EL1TVT_BIT', 'EL1TVCT_BIT', 'ECV_BIT')}
        self.assertEqual(defines, {'EL1TVT_BIT': 13, 'EL1TVCT_BIT': 14, 'ECV_BIT': 12})
        self.assertEqual(self.define('EL1_PHYSICAL_BITS'), 'UINT64_C(3)')
        table = self.table('el1trap-bits')
        self.assertEqual({bit: table[bit][2] for bit in table}, {'0': 'cleared', '1': 'cleared', '11:2': 'as found in OLD', '12': '**never set**', '13': 'set', '14': 'set'})
        self.assertIn('`EL1TVT`', table['13'][1])
        self.assertIn('`EL1TVCT`', table['14'][1])
        self.assertIn('`ECV`', table['12'][1])

    # -- the stub, the handler, the bounds ----------------------------------------------------------------------------------------
    def test_the_stub_table_is_the_built_stub_and_its_iss_are_computed_from_its_words(self):
        _, iss = built()
        table = rows(block(self.text, 'el1trap-stub'))
        self.assertEqual([row[0] for row in table], ['`mrs x0, cntvct_el0`', '`mrs x1, cntv_ctl_el0`', '`mrs x2, cntfrq_el0`', '`mrs x3, cntpct_el0`', '`hvc #0`'])
        self.assertEqual([row[2] for row in table[:4]], [f'`{value:#X}`'.replace('0X', '0x') for value in iss])
        self.assertEqual([row[1].split(' (')[0].split(':')[0] for row in table[:4]],
                         ['traps', 'traps', 'does not trap', 'the control'])
        self.assertEqual(0x62000000 | iss[0], 0x6234F801)
        self.says('the layout of the architecture (INFERRED, not re-read) and the numbers above OBSERVED under QEMU')
        self.says('`ISS_OK=NO`')
        for number in ('0x34F801', '0x32F827', '0x32F861'):
            self.assertIn(number.replace('0x', '0X'), driver_pages(self))

    def test_the_handler_table_is_the_sources_decisions_and_the_bounds_are_its_numbers(self):
        handler = rows(block(self.text, 'el1trap-handler'))
        self.assertEqual(len(handler), 8)
        for fragment in ('cmp x13, #0x18', 'cmp x13, #0x16', 'cmp x15, #4', 'cmp x15, #8', 'cmp x14, #2', 'cmp x14, #1'):
            self.assertIn(fragment, self.code, fragment)
        bounds = self.table('el1trap-bounds')
        self.assertEqual((self.define('ENTRIES_BUDGET').split()[0], self.define('TRAPS_MAX'), self.define('DEADLINE_S'), self.define('ENTRIES_FATAL').split()[0]),
                         ('8', '8', '1u', '24'))
        self.assertEqual({k: v[1] for k, v in bounds.items()}, {
            'entries': '8: the ninth ends it', 'trap records': '8', 'deadline': '1 second of `CNTPCT_EL0`, checked at every entry', 'a handler that faults': '24 entries',
            'the stub': '5 instructions, no branch', 'an EL1 vector entry': '2 instructions', 'the wait before': '8 seconds', 'stack kept': '16 KiB'})
        self.assertEqual(self.define('STACK_KEPT_BYTES'), '(16u * 1024u)')
        self.says('**What is not bounded:** an instruction that never completes, and EL1 code that never reaches an entry')
        self.says('The last line on the page, `NEXT EL1 EXCURSION`, names it')

    def test_the_instruction_table_is_the_binary(self):
        f, _ = built()
        section = block(self.text, 'el1trap-instructions')
        by = {row[0]: row for row in rows(section)}
        self.assertEqual(by['`MRS`'][2], str(f['mnemonics']['mrs']))
        named = {token.lower() for token in re.findall(r'`(\w+)`', by['`MRS`'][1])}
        self.assertEqual(named, lib.POLICIES['el1trap']['registers'])
        self.assertEqual(set(f['mrs']), named)
        self.assertEqual({name.lower(): int(count) for name, count in re.findall(r'`(\w+)` (\d+)', by['`MSR`'][1])}, dict(f['msr']))
        self.assertEqual(by['`MSR`'][2], str(f['mnemonics']['msr']))
        self.assertEqual({imm: int(count) for imm, count in re.findall(r'`(#\d)` (\d+)', by['`HVC`'][1])}, {'#1': 16, '#0': 1, '#2': 1})
        self.assertEqual({'#0x1': 16, '#0': 1, '#0x2': 1}, dict(f['hvc']))
        for kind, mnemonic in (('`HVC`', 'hvc'), ('`ERET`', 'eret'), ('`ISB`', 'isb'), ('`DC CIVAC`', 'dc'), ('`IC IVAU`', 'ic'), ('`DSB`', 'dsb'), ('`UDF`', 'udf')):
            self.assertEqual(by[kind][2], str(f['mnemonics'][mnemonic]), kind)
        for word in ('CNTPOFF_EL2', 'CNTVOFF_EL2'):
            self.assertNotIn(word.lower(), ' '.join(i[1].lower() for i in f['instruction_list']))

    # -- what it prints ---------------------------------------------------------------------------------------------------------
    def test_every_keyword_the_payload_can_print_is_in_the_document_and_the_catalogue_names_only_such_keywords(self):
        literals = ' '.join(re.findall(r'"([^"\n]*)"', re.sub(r'__asm__\(.*?\);', '', self.code, flags=re.S)))
        mine = set(LINE_WORD.findall(literals))
        self.assertGreater(len(mine), 60)
        lines_block = block(self.text, 'el1trap-lines')
        for word in sorted(mine):
            self.assertIn(word, self.text, f'{word} can be printed and is not in the document')
            if word not in ('PAYLOAD', 'EL1TRAP'):       # the prefix of every line, said once above the catalogue
                self.assertIn(word, lines_block, f'{word} can be printed and is not in the line catalogue')
        catalogue = {word for row in rows(lines_block) for word in LINE_WORD.findall(row[0])}
        for word in sorted(catalogue - mine - {'YES', 'NO', 'PARTIAL', 'CONTROL', 'DEFAULT'}):
            self.fail(f'{word} is in the line catalogue and nothing in the source prints it')
        self.assertIn('`NEXT EL1 EXCURSION AFTER 8 S`', {row[0] for row in rows(lines_block)})

    def test_the_pages_are_what_the_host_program_prints(self):
        pages = self.pages()
        first = block(self.text, 'el1trap-page').replace('```', '').strip().splitlines()
        self.assertEqual(first, pages['traps effective'])
        self.assertEqual(len(first), 20)
        self.says('A normal run is 20 lines')
        tails, title = {}, None
        for line in block(self.text, 'el1trap-pages').replace('```', '').strip().splitlines():
            if line.startswith('# '):
                title = line[2:]
                tails[title] = []
            else:
                tails[title].append(line)
        self.assertEqual(set(tails), set(WORLDS))
        for title, tail in tails.items():
            with self.subTest(world=title):
                start = WORLDS[title]
                self.assertEqual(tail, pages[title][start:])
                self.assertEqual(pages[title][:start], first[:start], 'the first lines are the same in every world')
        self.says('For `hvc undefined at el2` the tail starts at line 8')

    def test_the_most_lines_and_the_numbers_are_the_sources(self):
        self.assertEqual(self.program('lines-report').strip(), f'LINES_MAX={driver.LINES_MAX}')
        self.says(f'At most {driver.LINES_MAX} lines')
        self.says(f'over every scripted end, both probe results, the traps effective or inert, and no register, four or all five not put back: {driver.LINES_MAX}')
        defines = dict(re.findall(r'#define (\w+) (\d+)u', self.code))
        self.assertEqual((defines['WAIT_BEFORE_EXCURSION_S'], defines['COUNTER_HZ_DEFAULT'], defines['COUNTER_HZ_MIN'], defines['COUNTER_HZ_MAX'],
                          defines['COUNTER_STUCK_READS']), ('8', '19200000', '1000000', '1000000000', '2000000'))
        self.says("eight seconds on the runner's counter")
        self.says('outside 1 MHz to 1 GHz and 19.2 MHz is used')
        self.says('two million equal reads in a row')
        self.assertEqual(self.code.count('NEXT EL1 EXCURSION AFTER 8 S'), 1)
        self.says('in 16-byte steps (the smallest line the architecture allows)')

    def test_the_chain_arithmetic_is_right_and_uses_the_measured_and_the_runners_numbers(self):
        runner = block(RUNNER_DOC.read_text(encoding='utf-8'), 'chain-budget')
        found = {key: re.search(pattern, runner) for key, pattern in (
            ('psci', r'\| `psci`, at most \| (\d+) \|'), ('unit', r"\| panel region, the unit's 2880 x 1920 panel \| (\d+) \|"),
            ('stock', r'\| panel region, the stock layout: the least it asks for \| (\d+) \|'))}
        if not all(found.values()):
            self.skipTest("the runner's planning table has another shape")
        n = {key: int(match.group(1)) for key, match in found.items()}
        most = int(self.program('lines-report').strip().split('=')[1])
        by = self.table('el1trap-chain-budget')
        self.assertEqual(set(by), {'`el1trap` alone', '`psci`, then `el1trap`'})
        for chain, formula, unit, stock in by.values():
            with self.subTest(chain=chain):
                self.assertRegex(formula, r'^[0-9 +()x]+ = \d+$')
                left, right = formula.split(' = ')
                self.assertEqual(eval(left.replace('x', '*')), int(right))
                self.assertEqual((unit, stock), ('yes' if int(right) <= n['unit'] else 'no', 'yes' if int(right) <= n['stock'] else 'no'))
        for chain, parts in (('`el1trap` alone', (2, 3, most)), ('`psci`, then `el1trap`', (3, 6, n['psci'], most))):
            self.assertEqual(int(by[chain][1].split(' = ')[1]), sum(parts), chain)

    # -- the decisions ----------------------------------------------------------------------------------------------------------
    def test_the_decision_table_names_every_outcome_and_says_which_ones_support_kill_or_void_o1(self):
        decisions = rows(block(self.text, 'el1trap-decisions'))
        self.assertGreaterEqual(len(decisions), 15)
        for row in decisions:
            self.assertEqual(len(row), 3)
            self.assertTrue(all(row), row)
        table = ' '.join(' '.join(row) for row in decisions)
        for word in ('TRAPS_EFFECTIVE', 'TRAPS_INERT', 'TRAPS_PARTIAL', 'CONTROL_NOT_TRAPPED', 'CNTFRQ_EL0_TRAPPED', 'HVC_AT_EL2=FAILED', 'REFUSED=HVC_AT_EL2',
                     'REFUSED=WRITE_NOT_HELD', 'EL1_EXCEPTION', 'BUDGET', 'DEADLINE', 'UNEXPECTED_CLASS', 'RESTORED=NO', 'NOT_RESTORED', 'NEXT EL1 EXCURSION AFTER 8 S',
                     'REFUSED=E2H', 'REFUSED=OLD_HAS_BITS_12_TO_14', 'REFUSED=COUNTER_STUCK', 'SKIPPED_NOT_AT_EL2', 'FREQ=DEFAULT', 'O1', 'O2', 'O3', 'O4'):
            self.assertIn(word, table, f'the decision table does not mention {word}')
        by = {row[0]: row for row in decisions}
        effective = next(row for key, row in by.items() if key.startswith('`VERDICT=TRAPS_EFFECTIVE`'))
        inert = next(row for key, row in by.items() if key.startswith('`VERDICT=TRAPS_INERT BITS13_14_IN_READBACK=YES`'))
        inert_no = next(row for key, row in by.items() if key.startswith('`VERDICT=TRAPS_INERT BITS13_14_IN_READBACK=NO`'))
        partial = next(row for key, row in by.items() if key.startswith('`VERDICT=TRAPS_PARTIAL`'))
        void = next(row for key, row in by.items() if key.startswith('`VERDICT=CONTROL_NOT_TRAPPED`'))
        hang = next(row for key, row in by.items() if 'ends at `NEXT EL1 EXCURSION`' in key)
        self.assertIn('O1 is **supported, not decided**', effective[2])
        self.assertNotIn('eliminated', effective[2])
        self.assertIn('**stuck but inert**', inert[1])
        for row in (inert, inert_no):
            self.assertIn('**O1 is eliminated**', row[2])
        self.assertIn('eliminated', partial[2])
        self.assertIn('the experiment is **void**: no answer about O1', void[2])
        self.assertNotIn('eliminated', void[2])
        self.assertIn('O1 undecided', hang[2])
        for word in ('NOT_RESTORED', 'RESTORED=NO', 'HVC_AT_EL2=FAILED', 'WRITE_NOT_HELD'):
            self.assertIn(word, self.code)

    def test_the_options_are_those_of_the_audit_and_o4_is_never(self):
        self.says('**O1** the A16 recipe')
        self.says('**O4** `CNTPOFF_EL2` / ECV level 2 ("never": a read of it stalls the board)')
        self.says('"Stuck but inert" is told apart from "effective" only by an access made at EL1.')

    def test_what_is_not_measured_is_not_called_observed(self):
        self.says('INFERRED, not re-read')
        for at in re.finditer(r'ECVEn|SCR_EL3\.HCE', self.flat):
            self.assertRegex(self.flat[max(0, at.start() - 220):at.end() + 220], r'INFERRED|UNKNOWN', 'an EL3 setting is said as a fact')
        self.assertNotRegex(self.flat, r'(?i)OBSERVED[^.]{0,80}\bbits? 13\b')
        self.says('Restarts of the board have been seen after the `cpuon` payload, INFERRED to be associated with its core power cycling (cause UNKNOWN)')
        self.says('stayed up for 224 s and 268 s in two boots')
        self.says('An EL1 excursion is a different kind of risk from a register write, and from a core power cycle.')
        self.says('that is QEMU, not the unit')

    # -- the QEMU block and the tests table ----------------------------------------------------------------------------------------
    def test_the_qemu_panel_has_the_shape_the_qemu_suite_asserts(self):
        lines = block(self.text, 'el1trap-qemu-panel').replace('```', '').strip().splitlines()
        self.assertEqual(len(lines), len(qemu.EFFECTIVE))
        for line, pattern in zip(lines, qemu.EFFECTIVE):
            self.assertRegex(line, f'^{pattern}$')
        offsets = {k: int(v, 16) for k, v in re.findall(r'(STUB|EL1_VECTORS|EL2_VECTORS)_OFFSET=0X([0-9A-F]+)', lines[6])}
        self.assertEqual((offsets['EL1_VECTORS'] - offsets['EL2_VECTORS'], offsets['EL1_VECTORS'] % 2048), (2048, 0))
        self.assertTrue(offsets['EL1_VECTORS'] < offsets['STUB'] < offsets['EL1_VECTORS'] + 2048 + 256)
        self.assertIn(f'VBAR_EL1_OFFSET=0X{offsets["EL1_VECTORS"]:X}', lines[12])
        qemu_source = (ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu-el1trap.py').read_text(encoding='utf-8')
        self.says('between 7 and 40 seconds')
        self.assertIn('7.0 <= seconds <= 40.0', qemu_source)
        self.says(f'{["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"][len(qemu.VARIANTS)]} copies of the source, each edited once')
        self.assertEqual(len(qemu.VARIANTS), 10)
        self.says('the tenth sets `SSBS`, `PAN`, `UAO` and `DIT` before the probe and prints them after the excursion (`PSTATE_KEPT=0X1C01000`')
        self.assertIn("PSTATE_KEPT=0X1C01000'", qemu_source)
        for pinned in ("'CNTV_CTL_EL0 NOT_TRAPPED VALUE=0X0'", '[1-9A-F][0-9A-F]*'):
            self.assertIn(pinned, qemu_source)
        self.says('`CNTV_CTL_EL0` reads `0X0`')

    def test_the_tests_table_counts_what_the_tests_hold(self):
        for claim in (f'{len(driver.MUTANTS)} seeded-bug mutants', f'{len(driver.BAD_BINARIES)} seeded bad binaries', f'{len(DOC_MUTANTS)} seeded mistakes in the document',
                      f'{len(driver.ASM_MUTANTS)} seeded edits of the assembly', 'nine suites', '6000 random worlds'):
            self.assertIn(claim, self.text)
        self.assertEqual(len(driver.SUITES), 9)
        host = ''.join((ROOT / 'tools' / name).read_text(encoding='utf-8') for name in ('test-q1n1-sp11-payload-el1trap.c', 'test-q1n1-sp11-payload-el1trap-tail.h'))
        self.assertIn('round < 6000', host)
        self.assertGreaterEqual(len(driver.MUTANTS), 100)
        self.assertGreaterEqual(len(driver.BAD_BINARIES), 35)
        self.assertGreaterEqual(len(driver.ASM_MUTANTS), 10)

    def test_the_other_documents_are_the_ones_it_names(self):
        for name in ('SP11-PAYLOAD.md', 'SP11-PAYLOAD-CNTHCTL.md', 'SP11-PAYLOAD-CPUON.md'):
            self.assertTrue((ROOT / 'docs' / name).exists(), name)
        self.says('Its predecessor is [`cnthctl`](SP11-PAYLOAD-CNTHCTL.md) (T-HW1')


def driver_pages(case):
    return ' '.join(case.program('page').splitlines())


# ---- seeded mistakes in the document ----------------------------------------------------------------------------------------------

def _replace(old, new, count=1):
    def mutate(doc):
        assert old in doc, old
        return doc.replace(old, new, count)
    return mutate


DOC_MUTANTS = [
    ('the-end-is-said-to-return-the-constant', _replace('the end of the excursion returns with `0x3C9` plus those of its bits', 'the end of the excursion returns with `0x3C9` and none of its bits')),
    ('the-unread-registers-are-said-to-be-read-back', _replace('are put back by the assembly and are **not** read back, and `RESTORED=YES` does not speak for them', 'are put back by the assembly and read back, and `RESTORED=YES` speaks for them')),
    ('the-backwards-counter-is-forgotten', _replace('or that runs\n   backwards (a read below the first, which would end the wait at once)', 'or that\n   runs fast')),
    ('dc-is-dropped-from-the-checked-bits', _replace('(`HCR_EL2` RW, E2H, TGE, VM, DC, HCD, FMO, IMO, AMO;', '(`HCR_EL2` RW, E2H, TGE, VM, HCD, FMO, IMO, AMO;')),
    ('dc-is-said-to-be-set', _replace('| 12 | `DC` | clear |', '| 12 | `DC` | set |')),
    ('the-kept-mask-is-wrong', _replace('the mask `0x3C01000`, built from', 'the mask `0x3C00000`, built from')),
    ('the-probe-handler-is-said-not-to-keep-spsr', _replace("the probe's handler\n   also keeps `SPSR_EL2`", "the probe's handler\n   also keeps `SPSR_EL1`")),
    ('the-pstate-variant-value-is-wrong', _replace('`PSTATE_KEPT=0X1C01000`', '`PSTATE_KEPT=0X3C01000`', count=-1)),
    ('the-assembly-mutant-count-is-wrong', _replace(f'{len(driver.ASM_MUTANTS)} seeded edits of the assembly', f'{len(driver.ASM_MUTANTS) + 1} seeded edits of the assembly')),
    ('the-wait-in-the-lines-table-is-wrong', _replace('| `NEXT EL1 EXCURSION AFTER 8 S` | what follows starts eight seconds after this line |', '| `NEXT EL1 EXCURSION AFTER 5 S` | what follows starts eight seconds after this line |')),
    ('the-wait-in-the-prose-is-wrong', _replace("then eight seconds on the runner's counter", "then ten seconds on the runner's counter")),
    ('the-hcr-value-is-wrong', _replace('| `HCR_EL2` | C | `0x80000000` | fourth |', '| `HCR_EL2` | C | `0x88000000` | fourth |')),
    ('the-sctlr-value-is-wrong', _replace('| `SCTLR_EL1` | C | `0x30500800` | second |', '| `SCTLR_EL1` | C | `0x30D00800` | second |')),
    ('the-write-order-is-wrong', _replace('| `VBAR_EL1` | C | the payload\'s EL1 vector table | first of the four writes |', '| `VBAR_EL1` | C | the payload\'s EL1 vector table | second |')),
    ('tge-is-set', _replace('| 27 | `TGE` | clear |', '| 27 | `TGE` | set |')),
    ('rw-is-clear', _replace('| 31 | `RW` | set |', '| 31 | `RW` | clear |')),
    ('the-mmu-is-on', _replace('| 0 | `M` | clear | MMU off', '| 0 | `M` | set | MMU off')),
    ('a-sctlr-bit-is-forgotten', _replace('| 29, 28, 22, 20, 11 |', '| 29, 28, 22, 20 |')),
    ('ecv-is-set-in-v', _replace('| 12 | `ECV` | **never set** |', '| 12 | `ECV` | set |')),
    ('bit-13-is-renumbered', _replace('| 13 | `EL1TVT`', '| 15 | `EL1TVT`')),
    ('an-iss-is-wrong', _replace('| `mrs x0, cntvct_el0` | traps (`EL1TVCT`) | `0x34F801` |', '| `mrs x0, cntvct_el0` | traps (`EL1TVCT`) | `0x34F800` |')),
    ('cntfrq-is-said-to-trap', _replace('| `mrs x2, cntfrq_el0` | does not trap:', '| `mrs x2, cntfrq_el0` | traps:')),
    ('the-stub-has-a-branch', _replace('| `hvc #0` | the stub is finished: returns to EL2 | - |\n', '| `b .` | the stub loops | - |\n')),
    ('the-mrs-count-is-wrong', _replace('| 28 | context, read-backs', '| 27 | context, read-backs')),
    ('an-msr-count-is-wrong', _replace('`VBAR_EL2` 4, `ELR_EL2` 4,', '`VBAR_EL2` 3, `ELR_EL2` 4,')),
    ('the-hvc-immediates-are-wrong', _replace('`#1` 16, `#0` 1, `#2` 1', '`#1` 15, `#0` 1, `#2` 1')),
    ('the-eret-count-is-wrong', _replace('| - | 4 | to the stub; after the probe', '| - | 3 | to the stub; after the probe')),
    ('the-entry-budget-is-wrong', _replace('| entries | 8: the ninth ends it |', '| entries | 9: the tenth ends it |')),
    ('the-deadline-is-wrong', _replace('| deadline | 1 second of `CNTPCT_EL0`', '| deadline | 10 seconds of `CNTPCT_EL0`')),
    ('the-fatal-count-is-wrong', _replace('| a handler that faults | 24 entries |', '| a handler that faults | 32 entries |')),
    ('a-handler-row-is-forgotten', _replace('| 8, another class | `UNEXPECTED_CLASS` | end |\n', '')),
    ('the-first-page-changes', _replace('PAYLOAD EL1TRAP EXCURSION OK ENTRIES=0X4 TRAPS=0X3\nPAYLOAD EL1TRAP RESTORED=YES\n```\n<!-- /el1trap-page -->',
                                         'PAYLOAD EL1TRAP EXCURSION OK ENTRIES=0X3 TRAPS=0X3\nPAYLOAD EL1TRAP RESTORED=YES\n```\n<!-- /el1trap-page -->')),
    ('a-tail-changes', _replace('PAYLOAD EL1TRAP VERDICT=TRAPS_PARTIAL BITS13_14_IN_READBACK=PARTIAL', 'PAYLOAD EL1TRAP VERDICT=TRAPS_EFFECTIVE BITS13_14_IN_READBACK=PARTIAL')),
    ('a-world-is-forgotten', _replace('# write not held\n', '# write not held once\n')),
    ('a-keyword-is-forgotten', _replace('| `RESTORED=NO`, `NOT_RESTORED <register> WANT=0X.. NOW=0X..`, `POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD` |', '| `RESTORED=NO`, `NOT_RESTORED <register> WANT=0X.. NOW=0X..` |')),
    ('a-keyword-is-invented', _replace('| `REFUSED=NO_COUNTER` | the runner gave no counter: nothing else was done |', '| `REFUSED=NO_COUNTER` | the runner gave no counter: nothing else was done |\n| `DONE` | the end |')),
    ('inert-is-called-supported', _replace('| **O1 is eliminated**: the monitor\'s recipe cannot trap the guest\'s counter and timer on this unit. INFERRED cause', '| **O1 is supported**: the monitor\'s recipe cannot trap the guest\'s counter and timer on this unit. INFERRED cause')),
    ('effective-is-called-eliminated', _replace('O1 is **supported, not decided**', 'O1 is **eliminated**')),
    ('a-void-experiment-is-called-an-answer', _replace('the experiment is **void**: no answer about O1.', 'the experiment says **O1 is eliminated**.')),
    ('the-lines-maximum-is-wrong', _replace('At most 37 lines', 'At most 36 lines')),
    ('the-normal-run-is-wrong', _replace('A normal run is 20 lines', 'A normal run is 21 lines')),
    ('the-chain-sum-is-wrong', _replace('(1 + 1) + 3 + 37 = 42', '(1 + 1) + 3 + 37 = 43')),
    ('the-chain-verdict-is-wrong', _replace('| `psci`, then `el1trap` | (2 + 1) + 3 x 2 + 30 + 37 = 76 | yes | no |', '| `psci`, then `el1trap` | (2 + 1) + 3 x 2 + 30 + 37 = 76 | yes | yes |')),
    ('the-qemu-ecv-is-wrong', _replace('ID_AA64MMFR0_EL1=0X2100032310201126 ECV=0X2\nID_AA64PFR0_EL1=0X1301001121110222 EL1=0X2\nOLD CNTHCTL_EL2=0X3 SCTLR_EL1=0XC50838',
                                        'ID_AA64MMFR0_EL1=0X2100032310201126 ECV=0X0\nID_AA64PFR0_EL1=0X1301001121110222 EL1=0X2\nOLD CNTHCTL_EL2=0X3 SCTLR_EL1=0XC50838')),
    ('the-qemu-wait-window-is-wrong', _replace('between 7 and 40 seconds', 'between 7 and 80 seconds')),
    ('the-qemu-variant-count-is-wrong', _replace('ten copies of the source, each edited once', 'nine copies of the source, each edited once')),
    ('the-mutant-count-is-wrong', _replace(f'{len(driver.MUTANTS)} seeded-bug mutants', f'{len(driver.MUTANTS) + 1} seeded-bug mutants')),
    ('the-licence-line-goes', lambda doc: doc.split('\n', 1)[1]),
    ('hardware-is-called-run', _replace('**EXPERIMENTAL; hardware NOT RUN.**', '**EXPERIMENTAL; hardware RUN.**')),
    ('the-unit-is-said-to-have-been-observed', _replace('No value of this payload has been OBSERVED on the unit', 'Its values have been OBSERVED on the unit')),
    ('a-run-is-authorised', _replace('No run is authorised by this document', 'A run is authorised by this document')),
    ('it-is-staged-after-any-answer', _replace('**only after** `cnthctl` printed `BITS13_14_STUCK=YES` with `RESTORED=YES`', '**after** `cnthctl` printed anything')),
    ('an-el3-setting-is-called-known', _replace("the unit's EL3 (UNKNOWN: whether `SCR_EL3.ECVEn`", "the unit's EL3 (known: whether `SCR_EL3.ECVEn`")),
    ('a-link-is-broken', _replace('(SP11-PAYLOAD-CNTHCTL.md) (T-HW1', '(SP11-PAYLOAD-CNTHCTL-X.md) (T-HW1')),
    ('an-anchor-is-broken', _replace('#the-chain-several-payloads-in-one-boot)', '#the-chain-several-payloads-in-one-boots)')),
    ('a-machine-identifier-appears', _replace('# SP11 payload `el1trap`', '# SP11 payload `el1trap` at /Us' + 'ers/x')),
    ('the-document-is-too-big', lambda doc: doc + '\n' + 'x' * 52000),
]


class El1trapDocMutants(unittest.TestCase):
    """The agreement tests above must be able to fail: each seeded mistake in the document is refused by one."""

    @staticmethod
    def outcome(text):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(type('Changed', (El1trapDocAgreement,), {'TEXT': text}))
        result = unittest.TestResult()
        suite.run(result)
        return result

    def test_the_unchanged_document_passes_through_the_same_mechanism(self):
        result = self.outcome(DOC.read_text(encoding='utf-8'))
        self.assertTrue(result.wasSuccessful(), [str(f[1])[-500:] for f in result.failures + result.errors])
        self.assertGreaterEqual(result.testsRun, 18)
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
