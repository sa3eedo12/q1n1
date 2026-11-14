#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The documents of the usbsmmu payload and of the payload runner against the source and each other: docs/SP11-PAYLOAD-USBSMMU.md
(registers, evidence labels, printed lines, numbers, reason names, decision tables), the pointers to it in docs/SP11-PAYLOAD.md
(the stub, the catalogue row, the Tests rows, the stick row, the build line, the allow-list sentence, the order rule) and the
links, anchors, licence lines and sizes of all five payload documents.

    python3 tools/test-q1n1-sp11-payload-usbsmmu-doc.py

  * UsbsmmuDocAgreement: the register table is the source's enums and macros, its offsets and (S0's) evidence; the two printed
    blocks are what the host test of tools/test-q1n1-sp11-payload-usbsmmu.c dumps (`dump hub`, `dump direct`), line for line;
    every number and reason name is the source's; the decision tables answer every outcome the payload can print; the QEMU
    block is the one tools/test-q1n1-sp11-payload-qemu-usbsmmu.py asserts.
  * UsbsmmuDocMutants: seeded mistakes in either document, each of which an agreement test must refuse.
    (The planning table of "The chain" is checked in tools/test-q1n1-sp11-payload-chain.py.)

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
import ast
import functools
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


native = load_module('sp11_payload_native_for_usbsmmu_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload.py')
native.BUILD = ROOT / 'build' / 'sp11-payload-usbsmmu-doc-test'
BUILD = native.BUILD
own = load_module('sp11_payload_usbsmmu_for_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload-usbsmmu.py')
SOURCE = ROOT / 'payloads' / 'usbsmmu.c'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD.md'
DOC_USBSMMU = ROOT / 'docs' / 'SP11-PAYLOAD-USBSMMU.md'
DOCS = {name: ROOT / 'docs' / name for name in ('SP11-PAYLOAD.md', 'SP11-PAYLOAD-STATE.md', 'SP11-PAYLOAD-PSCI.md',
                                                 'SP11-PAYLOAD-TIMER.md', 'SP11-PAYLOAD-USBSMMU.md')}
PAGE_FONT = re.compile(r'^[A-Z0-9 :\-./=?()_]*$')
PREFIX = 'PAYLOAD USBSMMU '
# What the S0 survey read on the unit (OBSERVED, once, 2026-11-14; the survey's own register lists and section 12 of the stick log):
# every other register of the table is VERIFIED by the architecture or a pinned file and was never read there.
OBSERVED_BY_S0 = {'CAP_CAP0', 'CAP_HCSPARAMS1', 'CAP_HCCPARAMS1', 'CAP_RTSOFF', 'OP_USBCMD', 'OP_USBSTS', 'OP_CRCR', 'OP_DCBAAP',
                  'OP_CONFIG', 'OP_PORTSC(n)', 'RT_ERSTBA', 'RT_ERDP', 'DWC3_GCTL', 'DWC3_GSTS', 'DWC3_GSNPSID', 'DWC3_GBUSERRADDR0',
                  'SMMU_SCR0', 'SMMU_ID0', 'SMMU_GFSR', 'SMMU_SMR(n)', 'SMMU_S2CR(n)'}
# Every word the payload prints as a reason or a status, which the document must explain.
REASONS = ['UNREADABLE', 'ALL_ONES', 'ZERO', 'NOT_XHCI', 'U0_NOT_READ', 'NO_XHC', 'NO_STREAMS', 'NO_BANK', 'NO_ERST', 'BAD_SIZE',
           'NO_TRANSLATING_STREAM_BELOW_NCB', 'UNSUPPORTED_EXID', 'S2CR_UNREAD', 'NOMATCH', 'NO_DCBAAP', 'DCBAAP_MISALIGNED',
           'UNREAD', 'NO_SEG0', 'ERDP_NOT_IN_SEG0', 'RESERVED_DESCRIPTOR', 'DEPTH', 'TRANSLATES_NOTHING', 'BYPASS_LIKE', 'ALL_ZERO',
           'SKIPPED_NOT_AT_EL2', 'REFUSED_NO_LOAD32', 'NONE', 'EP', 'ERST']
NUMBER_WORDS = {1: 'one', 2: 'two', 3: 'three', 4: 'four', 5: 'five', 6: 'six', 7: 'seven', 8: 'eight', 9: 'nine', 10: 'ten'}


@functools.lru_cache(maxsize=None)
def measured():
    """What the host test says about the payload: `dump hub`, `dump direct` and the most lines and loads of its suites."""
    done, binary = native.build_program('usbsmmu', native.UEFI, native.PAYLOADS, BUILD / 'native')
    assert done.returncode == 0, done.stderr
    result = {}
    for which in ('hub', 'direct'):
        code, text = native.run_program(binary, 'dump', which)
        assert code == 0, text
        result[which] = text.splitlines()
    code, text = native.run_program(binary, 'lines-report')
    assert code == 0, text
    result['report'] = {key: int(value) for key, value in re.findall(r'^([A-Z_]+)=(\d+)$', text, re.M)}
    return result


def qemu_lines():
    """USBSMMU_UNDER_QEMU of the QEMU test, read without running it."""
    tree = ast.parse((ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu-usbsmmu.py').read_text(encoding='utf-8'))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, 'id', '') == 'USBSMMU_UNDER_QEMU' for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError('USBSMMU_UNDER_QEMU is gone')


class UsbsmmuDocAgreement(unittest.TestCase):
    TEXT = None     # a changed copy of docs/SP11-PAYLOAD-USBSMMU.md, for UsbsmmuDocMutants
    MAIN = None     # a changed copy of docs/SP11-PAYLOAD.md, for UsbsmmuDocMutants

    @classmethod
    def setUpClass(cls):
        if not lib.have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)
        cls.doc = DOC_USBSMMU.read_text(encoding='utf-8') if cls.TEXT is None else cls.TEXT
        cls.main = DOC.read_text(encoding='utf-8') if cls.MAIN is None else cls.MAIN
        cls.source = SOURCE.read_text(encoding='utf-8')
        cls.code = re.sub(r'/\*.*?\*/', '', cls.source, flags=re.S)
        cls.flat = ' '.join(cls.doc.split())            # the paragraphs are wrapped: phrases are looked up with the wraps undone
        cls.measured = measured()

    def mentions(self, phrase, text=None):
        self.assertTrue(phrase in (self.flat if text is None else ' '.join(text.split())), f'the document does not say {phrase!r}')

    def section(self, name):
        start, end = f'<!-- {name} -->', f'<!-- /{name} -->'
        self.assertIn(start, self.doc)
        self.assertIn(end, self.doc)
        return self.doc[self.doc.index(start):self.doc.index(end)]

    def block(self, name):
        found = re.search(rf'<!-- {name} -->\n```\n(.*?)```\n<!-- /{name} -->', self.doc, re.S)
        self.assertIsNotNone(found, f'no <!-- {name} --> block')
        return found.group(1).splitlines()

    def define(self, name):
        return int(re.search(rf'#define {name} (\d+)u', self.code).group(1))

    # -- the registers ------------------------------------------------------------------------------------------------------
    def table(self):
        return re.findall(r'^\| `([A-Z][A-Z0-9_]*(?:\(n\))?)` \| `([^`]+)` \| ([^|]+?) \| (.+) \|$', self.section('usbsmmu-registers'), re.M)

    def test_the_register_table_is_the_sources_enums_and_macros_with_their_offsets(self):
        enums = {name: int(value, 16) for name, value in re.findall(r'\b([A-Z][A-Z0-9]*_[A-Z0-9_]+) = (0x[0-9a-fA-F]+)', self.code)}
        macros = {f'{name}(n)': re.sub(r'\b(0x[0-9a-fA-F]+|\d+)u\b', r'\1', body)
                  for name, body in re.findall(r'^#define ([A-Z][A-Z0-9_]*)\(n\) (.+)$', self.code, re.M)}
        self.assertEqual((len(enums), len(macros)), (35, 5))
        rows = self.table()
        self.assertEqual(len(rows), 40)
        self.assertEqual({name for name, *_ in rows}, set(enums) | set(macros))
        for name, offset, _, _ in rows:
            if name in enums:
                self.assertEqual(int(offset, 16), enums[name], name)
                continue
            formula = re.sub(r'(?<=\d)n\b', '*n', offset)
            for n in (1, 2, 5, 9):
                self.assertEqual(eval(formula, {'__builtins__': {}}, {'n': n}), eval(macros[name], {'__builtins__': {}}, {'n': n}), name)

    def test_only_what_s0_read_is_called_observed_and_everything_else_is_verified(self):
        for name, _, _, evidence in self.table():
            with self.subTest(register=name):
                self.assertIn('VERIFIED', evidence)
                if name in OBSERVED_BY_S0:
                    self.assertIn('S0 OBSERVED', evidence)
                    self.assertNotIn('never read on the unit', evidence)
                else:
                    self.assertIn('never read on the unit', evidence)
                    self.assertNotIn('OBSERVED', evidence)
        evidence = {name: text for name, _, _, text in self.table()}
        self.assertIn('0x1019', evidence['OP_USBSTS'])
        self.assertIn('0x7C017E9A', evidence['SMMU_ID0'])
        self.assertIn('not in the pinned header', evidence['SMMU_GFAR'])

    def test_the_status_bits_the_document_names_are_the_ones_the_payload_decodes(self):
        bits = [int(b) for b in re.search(r'sts_bit\[\d+\] = \{([^}]*)\}', self.code).group(1).split(',')]
        names = re.findall(r'"([A-Z]+)"', re.search(r'sts_name\[\d+\]\[\d+\] = \{([^}]*)\}', self.code).group(1))
        self.assertEqual(len(bits), 9)
        self.assertEqual(names, ['HCH', 'HSE', 'EINT', 'PCD', 'SSS', 'RSS', 'SRE', 'CNR', 'HCE'])
        rows = {name: evidence for name, _, _, evidence in self.table()}
        self.mentions(', '.join(f'{name} {bit}' for name, bit in zip(names, bits)), rows['OP_USBSTS'])
        self.assertEqual(bits[names.index('HCE')], 12)
        for name, bit in zip(names, bits):
            self.assertRegex(self.flat, rf'`{name}` {bit}\b')

    def test_the_windows_and_the_streams_are_the_sources(self):
        table = re.search(r'windows\[WINDOWS\] = \{(.*?)\};', self.code, re.S).group(1)
        windows = re.findall(r'\{(0x[0-9a-f]+)u, (0x[0-9a-f]+)u\}', table)
        self.assertEqual(windows, [('0x0a600000', '0xfc100'), ('0x0a800000', '0xfc100'), ('0x15000000', '0x100000')])
        for base, size in windows:
            self.mentions(f'`{base}`')
            self.mentions(f'`{size}`')
        streams = re.search(r'stream_id\[2\] = \{(0x[0-9a-f]+)u, (0x[0-9a-f]+)u\}', self.code).groups()
        self.assertEqual(streams, ('0x1420', '0x1460'))
        self.mentions(f'S{streams[0][2:]}=')

    # -- what it prints -----------------------------------------------------------------------------------------------------
    def test_the_printed_blocks_are_the_lines_the_host_test_dumps_in_order(self):
        for which in ('direct', 'hub'):
            lines = self.block(f'{which}-lines')
            with self.subTest(block=which):
                self.assertEqual(lines, self.measured[which])
                self.assertLessEqual(len(lines), 24)
                for line in lines:
                    self.assertTrue(line.startswith(PREFIX), line)
                    self.assertLessEqual(len(line), 100)
                    self.assertRegex(line, PAGE_FONT)
        self.assertEqual(len(self.measured['direct']), 24, 'the direct fixture is the worst case: exactly the budget')

    def test_every_next_line_comes_before_the_group_it_names_and_the_groups_are_in_order(self):
        lines = [line[len(PREFIX):] for line in self.block('direct-lines')]
        positions = [lines.index(f'NEXT {name}') for name in ('U0', 'SMMU', 'RINGS', 'CB3', 'WALK')]
        self.assertEqual(positions, sorted(positions))
        first = {'U0': 'U0 CAPL=', 'SMMU': 'SMMU ID0=', 'RINGS': 'RINGS CSZ=', 'CB3': 'CB3 CBAR=', 'WALK': 'WALK IOVA='}
        for name, start in first.items():
            self.assertEqual(next(i for i, line in enumerate(lines) if line.startswith(start)), lines.index(f'NEXT {name}') + 1, name)
        self.assertEqual(lines[-1][:19], 'WALK SUMMARY PROBES')

    def test_the_line_table_names_only_keys_the_payload_prints(self):
        table = self.doc[self.doc.index('| Line | Fields |'):self.doc.index('**The probes**')]
        literals = set(re.findall(r'"([A-Z][A-Z0-9_]*)"', self.code))
        first_column = ' '.join(re.findall(r'^\| (`(?:[^|\\]|\\.)+`) \|', table, re.M))
        keys = set(re.findall(r'\b([A-Z][A-Z0-9_]*)=', first_column))
        self.assertGreaterEqual(len(keys), 40)
        for key in sorted(keys):
            self.assertIn(key, literals | {'REFUSED', 'S1420'}, f'{key}= is in the line table and not in the source')
        for key in ('CAPL', 'STS', 'DCBAAP', 'GCTL', 'BERR', 'LTSSM', 'SMRG', 'NCB', 'CBBASE', 'ERSTSZ', 'SEG0', 'CBAR', 'VA64',
                    'T0SZ', 'TG0', 'EPD0', 'ASID', 'MAIR0', 'FSR', 'IOVA', 'OA', 'LVL', 'ATTR', 'PROBES', 'MAPPED', 'IDENTITY', 'CUTS'):
            self.assertIn(f'{key}=', first_column, key)

    def test_the_probes_the_document_lists_are_the_ones_the_payload_adds_in_that_order(self):
        roles = re.findall(r'add_probe\(list, &n, [^;]*?, "([A-Z]+)", ', self.code)
        self.assertEqual(roles, ['DCBAAP', 'STACK', 'CONVLO', 'CONVHI', 'RAMHI', 'ERDP', 'RAMLO'])
        probes = self.doc[self.doc.index('**The probes**'):self.doc.index('## The line budget')]
        self.assertEqual([probes.index(f'`{role}`') for role in roles], sorted(probes.index(f'`{role}`') for role in roles))
        self.mentions(f'At most {NUMBER_WORDS[self.define("PROBES_MAX")]}, one per 4 KiB page', probes)

    def test_the_reason_names_in_the_document_are_the_sources_and_every_source_reason_is_explained(self):
        why = re.search(r'walk_why\[\d+\]\[\d+\] = \{([^}]*)\}', self.code).group(1)
        reasons = re.findall(r'"([A-Z0-9_]+)"', why)
        self.assertEqual(reasons, ['NOT_READ', 'ALL_ZERO', 'STAGE2_ONLY', 'NESTED', 'M0', 'VA64_0', 'EPD0', 'TG0_RESERVED', 'T0SZ_RANGE',
                                   'TTBR0_MISALIGNED'])
        failures = re.search(r'reason_name\[\d+\]\[\d+\] = \{([^}]*)\}', self.code).group(1)
        refusals = [r for r in re.findall(r'"([A-Z0-9_]+)"', failures)]
        self.assertEqual(refusals, ['RANGE', 'MISALIGNED', 'AFTER_FAULT', 'BUDGET', 'FAULT', 'LOAD32', 'NO_MAP', 'NOT_IN_MAP', 'TYPE_'])
        printed = set(re.findall(r'\bnote\(c, "[A-Z0-9_]+", "[A-Z0-9_]+", "([A-Z0-9_]+)"\)', self.code)) | set(
            re.findall(r'\bkt\(&?o, "[A-Z0-9_]+", "([A-Z0-9_]+)"\)', self.code)) | set(re.findall(r'\bsay\(&?c, "([A-Z0-9_]+)"\)', self.code))
        self.assertLessEqual(printed, set(REASONS), f'a reason the document list does not know: {sorted(printed - set(REASONS))}')
        for name in REASONS + reasons:
            self.assertRegex(self.code, rf'"\.?{re.escape(name)}', name)
            self.assertIn(name, self.doc, f'{name} is printed and the document does not say what it means')
        for name in refusals:
            self.assertIn(name.rstrip('_'), self.doc, name)
        for name in ('STOP=TABLE_', 'TABLE_NOT_IN_MAP', 'TABLE_TYPE_0X', 'TABLE_NO_MAP', 'TABLE_FAULT', 'REFUSED='):
            self.mentions(name)

    def test_the_numbers_in_the_document_are_the_sources(self):
        line_cap, load_cap = self.define('LINE_CAP'), self.define('LOAD_CAP')
        self.assertEqual((line_cap, load_cap), (24, 3000))
        self.mentions(f'At most **{line_cap} lines**')
        self.mentions(f'**{load_cap} loads**')
        self.mentions(f'the host test\'s most is {self.measured["report"]["LOADS_MAX"]} (the ABI allows 4096)')
        self.assertEqual(self.measured['report']['LINES_MAX'], line_cap)
        reserves = [self.define(f'RESERVE_AFTER_{name}') for name in ('U0', 'SMMU', 'RINGS', 'CB')]
        self.assertEqual(reserves, [17, 14, 10, 4])
        self.mentions(f'the reserves are {reserves[0]} lines after the U0 group, {reserves[1]} after the SMMU group, {reserves[2]} after the rings and {reserves[3]} after the first bank')
        self.mentions(f'{self.define("SLOTS_SCANNED")} slots')
        self.mentions(f'at most {self.define("SLOT_LINES_MAX")} lines')
        self.mentions(f'{self.define("SMR_SCANNED_MAX")} stream match registers')
        self.mentions(f'{self.define("MAP_DESCRIPTORS_MAX")} descriptors')
        self.mentions(f'at most {self.define("LOAD_CAP")} (the ABI allows 4096)')
        self.mentions('4 table levels')

    def test_the_chain_arithmetic_is_the_planning_tables_numbers(self):
        found = re.search(r'\(3 \+ 1\) \+ 3 x 3 \+ (\d+) \+ (\d+) \+ (\d+) = (\d+) lines', self.flat)
        self.assertIsNotNone(found, 'the arithmetic of the chain is gone')
        psci, new, timer, total = map(int, found.groups())
        budget = self.main[self.main.index('<!-- chain-budget -->'):self.main.index('<!-- /chain-budget -->')]
        rows = {label: int(value) for label, value in re.findall(r'^\| `(\w+)`, at most \| (\d+) \|$', budget, re.M)}
        self.assertEqual((psci, new, timer), (rows['psci'], rows['usbsmmu'], rows['timer']))
        self.assertEqual(new, self.measured['report']['LINES_MAX'])
        self.assertEqual(total, 4 + 9 + psci + new + timer)
        self.assertTrue(60 < total <= 89)
        self.mentions('six under the unit\'s 89 rows')
        self.assertEqual(89 - total, 6)
        self.mentions('`psci.bin usbsmmu.bin timer.bin`')
        self.mentions('(4 + 1) + 3 x 4 + 22 + 30 + 24 + 16 = 109 lines')

    # -- what the outcomes mean ---------------------------------------------------------------------------------------------
    def rows_of(self, name):
        return [row for row in self.section(name).splitlines() if row.startswith('| ') and not row.startswith(('| Printed', '| Probes', '| ---'))]

    def test_every_bank_the_walk_does_not_model_has_a_row_and_no_row_claims_a_decision_it_cannot_make(self):
        rows = self.rows_of('usbsmmu-outcomes')
        self.assertGreaterEqual(len(rows), 8)
        for reason in ('ALL_ZERO', 'STAGE2_ONLY', 'NESTED', 'M0', 'VA64_0', 'EPD0', 'TG0_RESERVED', 'T0SZ_RANGE', 'TTBR0_MISALIGNED', 'NOT_READ',
                       'NO_TRANSLATING_STREAM_BELOW_NCB', 'UNSUPPORTED_EXID', 'S1_S2BYP', 'S1_S2FLT', 'BYPASS_LIKE', 'TRANSLATES_NOTHING'):
            self.assertTrue(any(reason in row for row in rows), f'no outcome row for {reason}')
        by = lambda word: next(row for row in rows if word in row)  # noqa: E731
        # The walk does not read stage 2 and an all-zero bank says nothing: UNKNOWN, with the way to decide, never SC2 by itself.
        for word in ('STAGE2_ONLY', 'NESTED'):
            for phrase in ('UNKNOWN whether the arena is mapped', 'stage-2 walker payload', 'the S1 No-Op',
                           'SC2 applies only if a later walk shows the arena unmapped or the tables in memory the map does not call usable RAM'):
                self.assertIn(phrase, by(word), word)
            self.assertNotIn('**SC2**', by(word), f'{word}: a decision the payload cannot make')
        for phrase in ('RAZ/WI', 'INFERRED', 'UNKNOWN who programs it although S2CR says TRANSLATE', 'not a statement that the bank translates nothing',
                       'not yet SC2', 'the S1 No-Op'):
            self.assertIn(phrase, by('ALL_ZERO'))
        self.assertNotIn('**SC2**', by('ALL_ZERO'))
        # An unreadable bank shows nothing about the arena either: UNKNOWN, decided by an attempted DMA, never SC2 by itself.
        for phrase in ('what it maps is UNKNOWN', 'UNKNOWN: read-only evidence ends here', 'the S1 No-Op',
                       'SC2 applies only if that shows the DMA refused or redirected'):
            self.assertIn(phrase, by('NOT_READ'))
        self.assertNotIn('**SC2**', by('NOT_READ'))
        self.assertIn('INFERRED', by('BYPASS_LIKE'))
        self.assertIn('UNKNOWN', by('BYPASS_LIKE'))
        self.assertIn('FAULT', by('NO_TRANSLATING_STREAM_BELOW_NCB'))
        self.assertIn('SC2', by('NO_TRANSLATING_STREAM_BELOW_NCB'))
        self.assertIn('no bank is chosen', by('UNSUPPORTED_EXID'))

    def test_the_unsupported_row_lists_the_reasons_in_the_order_the_payload_checks_them(self):
        order = re.findall(r'"([A-Z0-9_]+)"', re.search(r'walk_why\[\d+\]\[\d+\] = \{([^}]*)\}', self.code).group(1))
        enum = [name.strip() for name in re.search(r'enum \{ (WY_OK[^}]*)\};', self.code).group(1).split(',')]
        setup = self.code[self.code.index('int walk_setup('):self.code.index('void field_attr(')]
        self.assertEqual(re.findall(r'return (WY_[A-Z0-9_]+);', setup), enum[1:] + ['WY_OK'], 'the checks are in the order of the enum')
        self.assertEqual(len(order), len(enum) - 1)
        row = next(line for line in self.doc.splitlines() if line.startswith('| `WALK UNSUPPORTED <why>'))
        self.assertEqual([token for token in re.findall(r'`([A-Z0-9_]+)`', row.split(' | ', 1)[1]) if token in order], order)
        self.assertEqual(order[:3], ['NOT_READ', 'ALL_ZERO', 'STAGE2_ONLY'], 'an all-zero bank is told before its zero TYPE reads as stage 2')

    def test_the_group_table_says_what_s0_did_not_read_in_the_register_tables_own_words(self):
        unread = {name for name, _, _, evidence in self.table() if 'never read on the unit' in evidence}
        groups = {name: why for name, why in re.findall(r'^\| (U0|SMMU|RINGS|CB|WALK) \| `NEXT [^`]+` \| .+? \| (.+) \|$', self.doc, re.M)}
        self.assertEqual(sorted(groups), ['CB', 'RINGS', 'SMMU', 'U0', 'WALK'])
        alias = {'CONFIG': 'OP_CONFIG', 'GBUSERRADDR1': 'DWC3_GBUSERRADDR1', 'GDBGLTSSM': 'DWC3_GDBGLTSSM', 'ID1': 'SMMU_ID1', 'ID2': 'SMMU_ID2',
                 'sGFAR': 'SMMU_GFAR', 'sGFSYNR': 'SMMU_GFSYNR0', 'ERSTSZ': 'RT_ERSTSZ'}
        named = lambda text: {alias[token] for token in re.findall(r'`(\w+)`', text)}  # noqa: E731
        self.assertEqual(named(groups['U0'].split(' but ', 1)[1]), {n for n in unread if n.startswith(('CAP_', 'OP_', 'DWC3_'))})
        self.assertEqual(named(groups['SMMU'].split(' but ', 1)[1]), {n for n in unread if n.startswith('SMMU_')})
        self.assertEqual(named(groups['RINGS'].split('new here:', 1)[1].split(';')[0]), {n for n in unread if n.startswith('RT_')})
        self.assertIn('never read on the unit', groups['CB'])
        banks = [name for name, _, _, _ in self.table() if name.startswith(('GR1_', 'CB_'))]
        self.assertTrue(banks and all(name in unread for name in banks), 'S0 read no register of any context bank')

    def test_the_paragraph_on_what_the_blocks_show_labels_s0s_values_as_the_survey_and_the_log_have_them(self):
        text = ' '.join(self.doc[self.doc.index('OBSERVED by S0 in them'):self.doc.index('<!-- direct-lines -->')].split())
        observed, made_up = text.split("Made up by the host test's fixture:")
        for phrase in ('`CAPLENGTH` `0x20`', '`USBCMD` 0', '`USBSTS` `0x1019`', '`CRCR` 0', '`CONFIG` `0x40`', '`PORTSC1`', '`ERSTBA`', '`ERDP`',
                       '`USBSTS` `0x1`', '`CONFIG` 0', 'both ports in RxDetect', '`PRTCAPDIR` 1, `CURMOD` 1', 'no latched bus error', '`ID0`',
                       '`sCR0`', '`sGFSR` (no global fault)', 'configured, addresses 1 to 3, hub flag 0', '`0x01` and `0x82`'):
            self.assertIn(phrase, observed)
        for phrase in ('the words of `GCTL` and `GSTS` (S0 has only the decoded facts)', '`GBUSERRADDR1`', '`LTSSM`', '`ID1`', '`ID2`', '`ERSTSZ`',
                       'the TRBs', 'every context bank register', 'the page tables'):
            self.assertIn(phrase, made_up)
        for name in ('CONFIG', 'CRCR', 'USBSTS', 'ERSTBA', 'ERDP', 'ID0', 'sCR0', 'sGFSR'):
            self.assertNotIn(f'`{name}`', made_up, f'{name} was measured and is not made up')
        for name in ('ID1', 'ID2', 'LTSSM', 'GBUSERRADDR1', 'ERSTSZ', 'GCTL', 'GSTS'):
            self.assertNotIn(f'`{name}`', observed, f'{name} was not measured (as a word) and is not observed')

    def test_the_limits_say_that_stage_2_nested_and_all_zero_banks_are_not_walked(self):
        limits = self.doc[self.doc.index('## Limits'):]
        self.mentions('stage-2 and nested banks are not walked', limits)
        self.mentions('(what they map is UNKNOWN, not SC2)', limits)
        self.mentions('nor is a bank that reads all zero', limits)

    def test_every_walk_result_has_a_row_saying_where_the_arena_may_live_and_when_it_is_sc2(self):
        rows = self.rows_of('usbsmmu-walk-outcomes')
        self.assertEqual(len(rows), 6)
        text = '\n'.join(rows)
        for phrase in ('`IDENTITY` = `PROBES`', '**anywhere in DRAM**', '**inside the firmware\'s xHCI memory**', 'no SMMU write is needed',
                       '`OA` different from `IOVA`', 'every probe `FAULT`', 'TABLE_TYPE_0X', 'TABLE_NOT_IN_MAP', 'RESERVED_DESCRIPTOR'):
            self.assertIn(phrase, text)
        self.assertEqual(text.count('**SC2**'), 2, 'the faulting probes and the tables outside usable RAM; the identity row says SC2 is clear')
        self.assertIn('SC2 is clear', text)

    def test_the_hce_table_names_the_registers_that_could_explain_it_and_labels_them_inferred(self):
        rows = self.rows_of('usbsmmu-hce')
        self.assertGreaterEqual(len(rows), 6)
        text = '\n'.join(rows)
        for phrase in ('HCE', 'BERR=', 'GFSR=', 'FSR=', '`FAR`', '`FSYNR0`', '`GFAR`', '`GFSYNR`', 'type 37', 'UNKNOWN'):
            self.assertIn(phrase, text)
        self.mentions('(all INFERRED: HCE\'s cause is UNKNOWN until they say)')
        self.assertIn('0x1019', self.doc)
        for key in ('BERR', 'GFSR', 'FSR', 'FAR', 'GFAR', 'GFSYNR0'):
            self.assertIn(f'"{key}"', self.code)

    def test_the_doc_says_what_the_status_is_and_what_nothing_here_can_prove(self):
        for word in ('EXPERIMENTAL; hardware NOT RUN', 'VERIFIED', 'OBSERVED', 'INFERRED', 'UNKNOWN', 'UNIMPLEMENTED',
                     'nothing of this payload is OBSERVED on the unit', 'the cause of HCE is UNKNOWN', 'nothing recovers it',
                     'proves nothing about the unit\'s windows', 'NEXT CB<n>', 'SC2'):
            self.mentions(word)
        self.mentions('A hang or reset in a context bank register is not recovered by anything here.')
        self.assertNotRegex(self.flat, r'(?i)hardware (run|qualified|passed)\b(?! NOT)')

    def test_it_goes_between_psci_and_timer_and_says_why(self):
        self.mentions('It goes after `psci` and before `timer`: `psci.bin usbsmmu.bin timer.bin`.')
        self.mentions('so `timer`, which may stall the board too, goes **last**')
        self.assertNotRegex(self.flat, r'timer\.bin usbsmmu\.bin')

    def test_the_qemu_block_is_what_the_qemu_test_asserts_and_the_doc_says_what_it_proves(self):
        self.assertEqual(self.block('qemu-lines'), [PREFIX + line for line in qemu_lines()])
        for phrase in ('OBSERVED, QEMU 11.1.3', '`LOADS=4 FAULTS=2 REFUSED=0`', 'finishes with a normal `PAYLOAD DONE`',
                       'proves nothing about the unit\'s windows'):
            self.mentions(phrase)

    # -- the pointers in docs/SP11-PAYLOAD.md --------------------------------------------------------------------------------
    def test_the_main_document_points_here_from_the_build_the_stick_the_order_the_stub_the_catalogue_and_the_tests(self):
        self.mentions('{state,psci,usbsmmu,timer}.bin', self.main)
        self.mentions('`usbsmmu` `MRS` of CurrentEL, no barrier and no `smc`.', self.main)
        stick = self.main[self.main.index('## On the stick'):self.main.index('## The manifest')]
        self.assertRegex(stick, r'\| `SP11\\USBSMMU\.BIN` \|[^\n]*between `psci` and `timer`')
        self.mentions('`psci.bin usbsmmu.bin timer.bin` (manifest indexes 0, 1, 2;', stick)
        chain = self.main[self.main.index('## The chain'):self.main.index('## Payload ABI v1')]
        self.mentions('so it goes after `psci` and before `timer` (`psci.bin usbsmmu.bin timer.bin`)', chain)
        self.mentions('| `usbsmmu`, at most | 24 |', chain)
        start = self.main.index('## Payload `usbsmmu`')
        stub = self.main[start:self.main.index('\n## ', start)]
        for phrase in ('between `psci` and `timer`', '[SP11-PAYLOAD-USBSMMU.md](SP11-PAYLOAD-USBSMMU.md)', 'EXPERIMENTAL; hardware NOT RUN',
                       'nothing of it is OBSERVED on the unit', 'may hang the board'):
            self.mentions(phrase, stub)
        catalogue = self.main[self.main.index('## Line catalogue'):self.main.index('## Failure modes')]
        self.mentions('| `PAYLOAD USBSMMU ...` | page | the `usbsmmu` payload\'s lines, at most 24 ([SP11-PAYLOAD-USBSMMU.md](SP11-PAYLOAD-USBSMMU.md#what-it-prints)) |', catalogue)
        safety = self.main[self.main.index('## Safety'):self.main.index('## Limits')]
        self.mentions('`usbsmmu` reads device registers of three fixed windows', safety)
        self.mentions('(named by its last `NEXT CB<n>` line)', safety)
        tests = self.main[self.main.index('## Tests'):self.main.index('## Safety')]
        for command in ('test-q1n1-sp11-payload-usbsmmu.py', 'test-q1n1-sp11-payload-usbsmmu-doc.py', 'test-q1n1-sp11-payload-qemu-usbsmmu.py'):
            self.mentions(f'python3 tools/{command}`', tests)
        for claim in (f'{len(own.MUTANTS)} seeded-bug mutants', f'{len(own.BAD_BINARIES)} seeded bad binaries', f'with {len(DOC_MUTANTS)} seeded mistakes in the documents'):
            self.mentions(claim, tests)
        self.mentions('eight native programs', tests)
        self.mentions('the `usbsmmu` payload against scripted MMIO windows, RAM and a memory map', tests)
        self.mentions('`usbsmmu` `MRS` of CurrentEL and no barrier;', tests)

    def test_the_documents_start_with_their_licence_line_stay_within_the_size_limit_and_every_link_resolves(self):
        texts = {name: path.read_text(encoding='utf-8') for name, path in DOCS.items()}
        texts['SP11-PAYLOAD.md'], texts['SP11-PAYLOAD-USBSMMU.md'] = self.main, self.doc
        for name, text in texts.items():
            with self.subTest(document=name):
                self.assertEqual(text.splitlines()[0], '<!-- SPDX-License-Identifier: MIT -->')
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                self.assertLess(len(text.splitlines()), 1500)
        self.assertEqual(lib.link_problems(texts, ROOT / 'docs'), [])
        for name in ('SP11-PAYLOAD-STATE.md', 'SP11-PAYLOAD-PSCI.md', 'SP11-PAYLOAD-TIMER.md', 'SP11-PAYLOAD-USBSMMU.md'):
            self.assertTrue(any(t.startswith(name) for t in lib.LINK.findall(texts['SP11-PAYLOAD.md'])), f'the main document does not link {name}')
            self.assertTrue(any(t.startswith('SP11-PAYLOAD.md') for t in lib.LINK.findall(texts[name])), f'{name} does not link back')

    def test_the_state_and_psci_sections_moved_out_of_the_main_document_and_left_a_stub(self):
        for heading, name, marker in (('## Reference payload `state`', 'SP11-PAYLOAD-STATE.md', '<!-- registers -->'),
                                      ('## Payload `psci`', 'SP11-PAYLOAD-PSCI.md', '<!-- psci-ids -->')):
            with self.subTest(section=heading):
                start = self.main.index(heading)
                stub = self.main[start:self.main.index('\n## ', start)]
                self.assertIn(f'({name})', stub)
                self.assertIn('EXPERIMENTAL; hardware NOT RUN', stub)
                self.assertLess(len(stub), 800, 'a stub, not the section')
                self.assertNotIn(marker, self.main)
                self.assertIn(marker, DOCS[name].read_text(encoding='utf-8'))


def _replace(old, new, count=1):
    def mutate(doc):
        assert old in doc, old
        return doc.replace(old, new, count)
    return mutate


def _swap(first, second):
    def mutate(doc):
        lines = doc.split('\n')
        a = next(i for i, line in enumerate(lines) if line.startswith(first))
        b = next(i for i, line in enumerate(lines) if line.startswith(second))
        lines[a], lines[b] = lines[b], lines[a]
        return '\n'.join(lines)
    return mutate


def _drop(prefix):
    def mutate(doc):
        lines = doc.split('\n')
        at = next(i for i, line in enumerate(lines) if line.startswith(prefix))
        return '\n'.join(lines[:at] + lines[at + 1:])
    return mutate


USBSMMU_DOC_MUTANTS = [
    ('a-register-offset-is-wrong', _replace('| `DWC3_GBUSERRADDR1` | `0xc134` |', '| `DWC3_GBUSERRADDR1` | `0xc138` |')),
    ('a-register-row-is-forgotten', _drop('| `CB_FSYNR0` |')),
    ('a-register-row-is-invented', _replace('<!-- /usbsmmu-registers -->', '| `CB_PAR` | `0x50` | context bank n | VERIFIED |\n<!-- /usbsmmu-registers -->')),
    ('a-formula-is-wrong', _replace('| `SMMU_SMR(n)` | `0x800 + 4n` |', '| `SMMU_SMR(n)` | `0x800 + 8n` |')),
    ('a-register-is-renamed', _replace('| `CB_TTBR1` |', '| `CB_TTBR2` |')),
    ('an-unread-register-is-called-observed', _replace('M bit 0); never read on the unit |', 'M bit 0); S0 OBSERVED |')),
    ('an-observed-register-is-called-unread', _replace('S0 OBSERVED `0x7C017E9A`', 'never read on the unit')),
    ('config-is-called-never-read', _replace('S0 OBSERVED `0x40` on U0 (the firmware\'s), `0x0` on U1', 'never read on the unit')),
    ('a-register-lost-its-evidence-label', _replace('| `OP_CONFIG` | `0x38` | xHC operational | VERIFIED (MaxSlotsEn 7:0; `xhci.c`); S0 OBSERVED',
                                                     '| `OP_CONFIG` | `0x38` | xHC operational | S0 OBSERVED')),
    ('the-group-table-says-s0-did-not-read-config', _replace('S0 read all of them but `GBUSERRADDR1` and `GDBGLTSSM`',
                                                              'S0 read all of them but `CONFIG`, `GBUSERRADDR1` and `GDBGLTSSM`')),
    ('the-group-table-forgets-an-unread-register', _replace('S0 read all of them but `GBUSERRADDR1` and `GDBGLTSSM`', 'S0 read all of them but `GBUSERRADDR1`')),
    ('the-rings-row-forgets-erstsz', _replace('new here: `ERSTSZ`, the segment table entry', 'new here: the segment table entry')),
    ('config-is-forgotten-among-the-observed', _replace('`CRCR` 0, `DCBAAP`, `CONFIG` `0x40`, `PORTSC1`,', '`CRCR` 0, `DCBAAP`, `PORTSC1`,')),
    ('an-unread-register-is-observed-in-the-paragraph', _replace('`ID0`, `sCR0`, `sGFSR` (no global fault)', '`ID0`, `ID1`, `sCR0`, `sGFSR` (no global fault)')),
    ('a-decoded-fact-is-called-a-word', _replace('(S0 has only the decoded facts)', '(S0 has the words)')),
    ('a-status-bit-is-wrong', _replace('HCE 12; `xhci.c` has HCH and CNR', 'HCE 13; `xhci.c` has HCH and CNR')),
    ('the-hub-block-loses-a-line', _replace('PAYLOAD USBSMMU WALK SUMMARY PROBES=4 MAPPED=4 IDENTITY=4 FAULT=0 STOP=0 CUTS=2\n', '')),
    ('the-direct-block-has-a-wrong-address', _replace('IOVA=0XCF610000 OA=0XCF610000', 'IOVA=0XCF610000 OA=0XCF610001')),
    ('a-printed-line-is-over-a-hundred-characters', _replace('PAYLOAD USBSMMU NEXT CB3\n', 'PAYLOAD USBSMMU NEXT CB3 ' + 'X' * 100 + '\n')),
    ('two-next-lines-are-swapped', _swap('PAYLOAD USBSMMU NEXT SMMU', 'PAYLOAD USBSMMU NEXT RINGS')),
    ('a-line-key-is-renamed', _replace('CBBASE=0X15080000', 'CBASE=0X15080000')),
    ('the-qemu-block-is-changed', _replace('PAYLOAD USBSMMU CB SKIPPED=NO_STREAMS', 'PAYLOAD USBSMMU CB SKIPPED=NO_BANK')),
    ('the-line-budget-is-wrong', _replace('At most **24 lines**', 'At most **25 lines**')),
    ('the-load-cap-is-wrong', _replace('**3000 loads**', '**4000 loads**')),
    ('the-most-loads-is-wrong', _replace('the host test\'s most is 405', 'the host test\'s most is 400')),
    ('a-reserve-is-wrong', _replace('17 lines after the U0 group', '16 lines after the U0 group')),
    ('the-probe-count-is-wrong', _replace('At most seven, one per', 'At most eight, one per')),
    ('a-probe-role-is-renamed', _replace('`RAMHI` (the last page', '`RAMTOP` (the last page')),
    ('a-reason-is-renamed', _replace('STAGE2_ONLY', 'STAGE_2_ONLY', count=-1)),
    ('a-reason-is-not-explained', _replace('`TTBR0_MISALIGNED`', '`TTBR0_BAD`', count=-1)),
    ('the-all-zero-reason-is-forgotten-in-the-line-table', _replace('`ALL_ZERO` (`CBAR`, `CBA2R`, `SCTLR`, `TCR` and `TTBR0` all read zero), ', '')),
    ('the-reasons-are-listed-in-another-order', _replace(
        '`NOT_READ` (a register of the bank could not be read), `ALL_ZERO` (`CBAR`, `CBA2R`, `SCTLR`, `TCR` and `TTBR0` all read zero)',
        '`ALL_ZERO` (`CBAR`, `CBA2R`, `SCTLR`, `TCR` and `TTBR0` all read zero), `NOT_READ` (a register of the bank could not be read)')),
    ('stage-2-is-called-sc2-again', _replace('| UNKNOWN: a stage-2 walker payload', '| **SC2**: fixing it needs SMMU writes; stop: a stage-2 walker payload')),
    ('stage-2-decision-is-claimed', _replace('UNKNOWN whether the arena is mapped', 'the arena is not mapped')),
    ('stage-2-sc2-condition-is-dropped', _replace(
        'SC2 applies only if a later walk shows the arena unmapped or the tables in memory the map does not call usable RAM', 'SC2 applies')),
    ('stage-2-has-no-way-to-decide', _replace('a stage-2 walker payload (VTCR-style', 'nothing (VTCR-style')),
    ('all-zero-is-called-sc2', _replace('and not yet SC2', 'and so **SC2**')),
    ('unreadable-bank-is-called-sc2', _replace('| UNKNOWN: read-only evidence ends here;', '| **SC2**: no evidence can be had without writes; stop; read-only evidence ends here;')),
    ('unreadable-bank-is-called-known', _replace('what it maps is UNKNOWN', 'it maps nothing')),
    ('all-zero-is-called-stage-1-off', _replace('This is not a statement that the bank translates nothing', 'The bank translates nothing')),
    ('all-zero-is-called-known', _replace('UNKNOWN who programs it although S2CR says TRANSLATE', 'the secure world programs it')),
    ('all-zero-is-called-measured', _replace('INFERRED RAZ/WI', 'OBSERVED RAZ/WI')),
    ('the-limits-forget-stage-2', _replace('stage-2 and nested banks are not walked either (what they map is UNKNOWN, not SC2)', 'stage-2 and nested banks are walked')),
    ('the-limits-forget-all-zero', _replace('nor is a bank that reads all zero', 'nor is a bank that reads stage 1')),
    ('the-identity-outcome-is-weakened', _replace('**anywhere in DRAM**', '**nowhere**')),
    ('the-partial-mapping-outcome-is-weakened', _replace('**inside the firmware\'s xHCI memory**', '**anywhere**')),
    ('the-hce-cause-is-called-known', _replace('the cause of HCE is UNKNOWN', 'the cause of HCE is known')),
    ('hce-readings-are-called-verified', _replace('(all INFERRED: HCE\'s cause is\nUNKNOWN until they say)', '(all VERIFIED)')),
    ('a-window-is-wrong', _replace('`0x0a600000`', '`0x0a700000`', count=-1)),
    ('the-order-puts-usbsmmu-after-timer', _replace('`psci.bin usbsmmu.bin timer.bin`', '`psci.bin timer.bin usbsmmu.bin`', count=-1)),
    ('the-chain-total-is-wrong', _replace('= 83 lines', '= 84 lines')),
    ('the-four-payload-total-is-wrong', _replace('= 109 lines', '= 108 lines')),
    ('hardware-is-claimed-run', _replace('**EXPERIMENTAL; hardware NOT RUN:**', '**hardware run:**')),
    ('the-recovery-claim-appears', _replace('A hang or reset in a context bank register is not recovered by anything here.', 'A hang is recovered.')),
    ('the-qemu-claim-is-widened', _replace('proves nothing about the unit\'s windows', 'proves the unit\'s windows', count=-1)),
    ('the-licence-line-is-gone', _replace('<!-- SPDX-License-Identifier: MIT -->\n', '')),
    ('a-link-back-does-not-resolve', _replace('SP11-PAYLOAD.md#line-catalogue', 'SP11-PAYLOAD.md#line-catalog')),
    ('the-link-to-the-chain-section-is-renamed', _replace('#the-chain-several-payloads-in-one-boot', '#the-chain', count=-1)),
]
MAIN_DOC_MUTANTS = [
    ('the-stub-lost-its-pointer', _replace('[SP11-PAYLOAD-USBSMMU.md](SP11-PAYLOAD-USBSMMU.md). EXPERIMENTAL', 'SP11-PAYLOAD-USBSMMU.md. EXPERIMENTAL')),
    ('the-stub-claims-the-hardware-ran', _replace('[SP11-PAYLOAD-USBSMMU.md](SP11-PAYLOAD-USBSMMU.md). EXPERIMENTAL; hardware NOT RUN:', '[SP11-PAYLOAD-USBSMMU.md](SP11-PAYLOAD-USBSMMU.md). EXPERIMENTAL; hardware run:')),
    ('the-stub-forgets-the-hang', _replace('It may hang the board at the\nfirst context bank register', 'It reads the\nfirst context bank register')),
    ('the-catalogue-row-is-gone', _replace('| `PAYLOAD USBSMMU ...` |', '| `PAYLOAD USB ...` |')),
    ('the-catalogue-anchor-does-not-resolve', _replace('SP11-PAYLOAD-USBSMMU.md#what-it-prints', 'SP11-PAYLOAD-USBSMMU.md#what-it-says')),
    ('the-stick-row-is-renamed', _replace('| `SP11\\USBSMMU.BIN` |', '| `SP11\\USBSMMU.EXE` |')),
    ('the-stick-chain-note-is-gone', _replace('`psci.bin usbsmmu.bin timer.bin` (manifest indexes 0, 1, 2;', '`psci.bin usbsmmu.bin timer.bin` (')),
    ('the-order-paragraph-puts-usbsmmu-last', _replace('so it goes after `psci` and before `timer` (`psci.bin usbsmmu.bin timer.bin`)', 'so it goes last (`psci.bin timer.bin usbsmmu.bin`)')),
    ('the-planning-row-is-wrong', _replace('| `usbsmmu`, at most | 24 |', '| `usbsmmu`, at most | 23 |')),
    ('the-build-line-forgot-usbsmmu', _replace('{state,psci,usbsmmu,timer}.bin', '{state,psci,timer}.bin')),
    ('the-allow-list-sentence-forgot-usbsmmu', _replace('; `usbsmmu` `MRS` of CurrentEL, no barrier and no `smc`.', '.')),
    ('the-safety-bullet-is-gone', _replace('`usbsmmu` reads device registers of three fixed windows', '`usbsmmu` reads things')),
    ('the-tests-row-forgot-the-eighth-program', _replace('eight native programs', 'seven native programs')),
    ('the-build-row-forgot-the-usbsmmu-allow-list', _replace('`usbsmmu` `MRS` of CurrentEL and no barrier;', '')),
    ('the-mutant-count-is-wrong', _replace(f'{len(own.MUTANTS)} seeded-bug mutants', f'{len(own.MUTANTS) - 1} seeded-bug mutants')),
    ('the-bad-binary-count-is-wrong', _replace(f'{len(own.BAD_BINARIES)} seeded bad binaries', f'{len(own.BAD_BINARIES) - 1} seeded bad binaries')),
    ('the-doc-mistake-count-is-wrong', _replace('seeded mistakes in the documents', 'seeded mistakes in the document')),
    ('the-qemu-row-is-gone', _replace('python3 tools/test-q1n1-sp11-payload-qemu-usbsmmu.py`', 'python3 tools/test-q1n1-sp11-payload-qemu-timer2.py`')),
    ('the-state-stub-is-gone', _replace('[SP11-PAYLOAD-STATE.md](SP11-PAYLOAD-STATE.md).', 'SP11-PAYLOAD-STATE.md.')),
    ('the-licence-line-is-gone-from-the-main-document', _replace('<!-- SPDX-License-Identifier: MIT -->\n', '')),
]
DOC_MUTANTS = [(name, 'usbsmmu', mutate) for name, mutate in USBSMMU_DOC_MUTANTS] + [(name, 'main', mutate) for name, mutate in MAIN_DOC_MUTANTS]


class UsbsmmuDocMutants(unittest.TestCase):
    """The agreement tests above must be able to fail: each seeded mistake in either document is refused by one."""

    @staticmethod
    def outcome(text=None, main_text=None):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(type('Changed', (UsbsmmuDocAgreement,), {'TEXT': text, 'MAIN': main_text}))
        result = unittest.TestResult()
        suite.run(result)
        return result

    def test_the_unchanged_documents_pass_through_the_same_mechanism(self):
        result = self.outcome(DOC_USBSMMU.read_text(encoding='utf-8'), DOC.read_text(encoding='utf-8'))
        self.assertTrue(result.wasSuccessful(), [str(f[1])[-400:] for f in result.failures + result.errors])
        self.assertGreaterEqual(result.testsRun, 20)
        self.assertEqual(result.skipped, [], 'a skipped agreement test proves nothing')

    def test_every_seeded_mistake_in_either_document_is_refused(self):
        originals = {'usbsmmu': DOC_USBSMMU.read_text(encoding='utf-8'), 'main': DOC.read_text(encoding='utf-8')}
        self.assertGreaterEqual(len(DOC_MUTANTS), 30)
        self.assertEqual(len({name for name, _, _ in DOC_MUTANTS}), len(DOC_MUTANTS))
        self.assertEqual({which for _, which, _ in DOC_MUTANTS}, {'usbsmmu', 'main'}, 'both documents have seeded mistakes')
        for name, which, mutate in DOC_MUTANTS:
            with self.subTest(mutant=name):
                changed = mutate(originals[which])
                self.assertNotEqual(changed, originals[which])
                result = self.outcome(*((changed, None) if which == 'usbsmmu' else (None, changed)))
                self.assertFalse(result.wasSuccessful(), 'every agreement test still passed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
