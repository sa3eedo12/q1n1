#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""docs/SP11-PAYLOAD-EL2MEM.md and docs/SP11-PAYLOAD-HASHBIG.md against the sources, the host models, the binaries, the QEMU test and
the manifest tool.

    python3 tools/test-q1n1-sp11-payload-mmu-doc.py

  * MmuDocAgreement: the house rules (licence line, size limit, no machine identifier, evidence labels, hardware NOT RUN) and the links;
    every keyword a payload can print against its document and every keyword of the line catalogue against the source; the page of a
    normal run against what the host program prints; the instruction tables against the built binaries (and, for `hashbig`, the two
    functions that load through any base); the `PAR_EL1` table against the decode; every number a document states (limits, seconds,
    sizes, return values) against the source; the QEMU blocks against the shapes tools/test-q1n1-sp11-payload-qemu-el2mem.py asserts, and
    against the arithmetic of their own values; the chain arithmetic against the runner's planning table and the budgets; the staging
    plan against the manifest tool at the staged size; the counts of the Tests tables against the drivers.
  * MmuDocMutants: seeded mistakes in either document, each of which an agreement test must refuse.
    (The planning table of "The chain" is checked in tools/test-q1n1-sp11-payload-chain.py.)

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
import functools
import hashlib
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_manifest as manifest_tool  # noqa: E402
import sp11_payload_memcheck as memcheck  # noqa: E402
import sp11_payload_mmu_testkit as kit  # noqa: E402
import sp11_payload_testlib as lib  # noqa: E402

el2mem = kit.load_module('sp11_payload_el2mem_for_mmu_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload-el2mem.py')
hashbig = kit.load_module('sp11_payload_hashbig_for_mmu_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload-hashbig.py')
engine = kit.load_module('sp11_payload_memcheck_for_mmu_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload-memcheck.py')
qemu = kit.load_module('sp11_payload_qemu_el2mem_for_mmu_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu-el2mem.py')
native = kit.native_module('mmu-doc')
BUILD = native.BUILD
DOCS = {'el2mem': ROOT / 'docs' / 'SP11-PAYLOAD-EL2MEM.md', 'hashbig': ROOT / 'docs' / 'SP11-PAYLOAD-HASHBIG.md'}
RUNNER_DOC = ROOT / 'docs' / 'SP11-PAYLOAD.md'
LINKED = ('SP11-PAYLOAD.md', 'SP11-PAYLOAD-STATE.md', 'SP11-PAYLOAD-CPUON.md', 'SP11-PAYLOAD-RESULTS.md')
PAYLOADS = ('el2mem', 'hashbig')
SOURCE_FILES = {'el2mem': ('el2mem.c', 'payload-mmu.h'), 'hashbig': ('hashbig.c', 'payload-mmu.h', 'payload-sha256.h')}
LINE_WORD = re.compile(r'\b[A-Z][A-Z0-9_]{2,}\b')
NUMBER_WORDS = {3: 'three', 5: 'five', 8: 'eight', 10: 'ten', 12: 'twelve'}
# The numbers in front of the word "second(s)" a document may state: the eight seconds of el2mem's waits, the 25 of hashbig's box.
SECONDS = {'el2mem': {'eight'}, 'hashbig': {'25'}}
PREFIX = {'el2mem': qemu.EL2MEM_PREFIX, 'hashbig': qemu.HASHBIG_PREFIX}
FOLDED = {'el2mem': qemu.EL2MEM_FOLDED, 'hashbig': qemu.HASHBIG_FOLDED}


def block(text, name):
    return text[text.index(f'<!-- {name} -->') + len(name) + 9:text.index(f'<!-- /{name} -->')]


def rows(section):
    return [[cell.strip() for cell in line.strip().strip('|').split('|')] for line in section.splitlines()
            if line.startswith('|') and not re.match(r'^\|[ \-|]+\|$', line)][1:]


def fenced(text, name):
    """The lines of a fenced block inside the comment pair `name`."""
    return block(text, name).replace('```sh', '').replace('```', '').strip().splitlines()


def const(file, name):
    """The value of `#define name expr` in a source or header of payloads/, evaluated (UINT64_C and the u suffix dropped)."""
    text = (ROOT / 'payloads' / file).read_text(encoding='utf-8')
    found = re.search(rf'^#define {name}\s+(.+?)\s*(?:/\*.*)?$', text, re.M)
    expression = re.sub(r'UINT64_C\(([^)]*)\)', r'\1', found.group(1))
    return eval(re.sub(r'\b(0x[0-9a-fA-F]+|\d+)u\b', r'\1', expression), {'__builtins__': {}})


def flat(text):
    return ' '.join(text.split())


@functools.lru_cache(maxsize=None)
def program(payload):
    """The host program of a payload, built once: its normal page and the most lines it prints over every world it scripts."""
    done, binary = native.build_program(payload, native.UEFI, native.PAYLOADS, BUILD / 'native')
    assert done.returncode == 0, done.stderr
    code, page = native.run_program(binary, 'page')
    assert code == 0, page
    code, report = native.run_program(binary, 'lines-report')
    assert code == 0, report
    return {'page': page.splitlines(), 'most': int(report.strip().split('=')[1])}


@functools.lru_cache(maxsize=None)
def built(payload):
    """The built binary of a payload: facts, its disassembly and what the memory checker finds in it."""
    done, elf, flat_bin = kit.Builder(BUILD / f'binary-{payload}').build(payload, payload, [], check=True)
    assert done.returncode == 0, done.stderr
    dis = lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout
    problems, loads, stores = memcheck.analyse(dis)
    return {'facts': kit.facts(elf, flat_bin), 'dis': dis, 'problems': problems, 'loads': loads, 'stores': stores, 'flat': flat_bin}


@functools.lru_cache(maxsize=None)
def staged():
    """The manifest tool's entries for the staging plan at the staged size: BIG.DAT is a sparse file of exactly 144 MiB."""
    out = BUILD / 'staging'
    out.mkdir(parents=True, exist_ok=True)
    big = out / 'BIG.DAT'
    with open(big, 'wb') as handle:
        handle.truncate(150994944)
    try:
        return manifest_tool.build([built('el2mem')['flat'], built('hashbig')['flat'], big])[1]
    finally:
        big.unlink()


class MmuDocAgreement(unittest.TestCase):
    TEXTS = None    # changed copies of the two documents, for MmuDocMutants

    @classmethod
    def setUpClass(cls):
        if not all(path.exists() for path in DOCS.values()):
            raise unittest.SkipTest('the documents do not exist')
        if not lib.have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)
        cls.text = dict(cls.TEXTS) if cls.TEXTS else {name: path.read_text(encoding='utf-8') for name, path in DOCS.items()}

    # -- the house rules -------------------------------------------------------------------------------------------------------
    def test_the_documents_follow_the_house_rules(self):
        paths = '|'.join(['/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/'])
        pattern = re.compile(paths + r'|\.loc' + r'al\b|\bsae' + r'ed\b|host' + r'name|\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', re.I)
        for name, text in self.text.items():
            with self.subTest(document=name):
                self.assertEqual(text.splitlines()[0], '<!-- SPDX-License-Identifier: MIT -->')
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                for label in ('VERIFIED', 'OBSERVED', 'INFERRED', 'EXPERIMENTAL', 'UNIMPLEMENTED', 'UNKNOWN'):
                    self.assertIn(label, text)
                self.assertIn('**EXPERIMENTAL; hardware NOT RUN.**', text)
                self.assertIn('Hardware NOT RUN.', text.split('## Status')[1])
                self.assertIn('no value of this payload has been observed on the unit', flat(text).lower())
                self.assertIn('(not run)', text)
                for number, line in enumerate(text.splitlines(), 1):
                    self.assertIsNone(pattern.search(line), f'{number}: {line}')

    def test_the_links_resolve(self):
        texts = {path.name: self.text[name] for name, path in DOCS.items()}
        texts.update({name: (ROOT / 'docs' / name).read_text(encoding='utf-8') for name in LINKED})
        problems = lib.link_problems(texts, ROOT / 'docs')
        self.assertEqual([p for p in problems if any(path.name in p for path in DOCS.values())], [])

    # -- the source --------------------------------------------------------------------------------------------------------------
    def printed_words(self, payload):
        literals = ' '.join(re.findall(r'"([^"\n]*)"', ' '.join(kit.code_of(ROOT / 'payloads' / name) for name in SOURCE_FILES[payload])))
        return set(LINE_WORD.findall(literals))

    # The words of the line prefix and of an AT answer, which the prose above the catalogue explains rather than a row.
    EXPLAINED_IN_PROSE = {'PAYLOAD', 'EL2MEM', 'HASHBIG', 'DEVICE', 'OTHER', 'NSH', 'RES', 'ADDR', 'TRANS', 'ACCESS', 'PERM', 'NS1', 'NONIDENT',
                          'FAULT'}

    def test_every_keyword_the_payload_can_print_is_in_its_document_and_the_catalogue_names_only_such_keywords(self):
        for payload in PAYLOADS:
            with self.subTest(payload=payload):
                mine = self.printed_words(payload)
                self.assertGreater(len(mine), 40)
                catalogue_text = block(self.text[payload], f'{payload}-lines')
                for word in sorted(mine):
                    where = self.text['el2mem'] + self.text[payload] if word in self.EXPLAINED_IN_PROSE else catalogue_text
                    self.assertIn(word, where, f'{word} can be printed and is not in the line catalogue (or, for an AT answer, the documents)')
                catalogue = {word for row in rows(catalogue_text) for word in LINE_WORD.findall(row[0])}
                for word in sorted(catalogue - mine):
                    self.fail(f'{word} is in the line catalogue and nothing in the source prints it')

    def test_every_refusal_reason_of_the_source_is_in_the_catalogue(self):
        for payload, reasons in (('el2mem', ('STRIDE_BELOW_40', 'STRIDE_NOT_A_MULTIPLE_OF_8', 'SIZE_NOT_WHOLE_DESCRIPTORS',
                                             'BUFFER_OUT_OF_RANGE', 'TOO_MANY_DESCRIPTORS')),
                                 ('hashbig', ('NO_TABLE', 'BAD_HEADER', 'TABLE_OVERRUNS_ITS_SIZE', 'NO_DATA_FILE', 'BASE_NOT_PAGE_ALIGNED',
                                              'SIZE_ZERO_OR_OVER_256_MIB', 'BEYOND_THE_48_BIT_SPACE', 'NOT_IN_ALLOCATED_DESCRIPTORS',
                                              'A_PAGE_OF_THE_FILE_IS_NOT_MAPPED'))):
            catalogue = block(self.text[payload], f'{payload}-lines')
            for reason in reasons:
                with self.subTest(payload=payload, reason=reason):
                    self.assertIn(reason, self.printed_words(payload))
                    self.assertIn(reason, catalogue)

    # -- the host model and the binary ---------------------------------------------------------------------------------------
    def test_the_page_of_a_normal_run_is_what_the_host_program_prints(self):
        for payload in PAYLOADS:
            with self.subTest(payload=payload):
                printed = [line for line in program(payload)['page'] if line.startswith(PREFIX[payload])]
                documented = fenced(self.text[payload], f'{payload}-page')
                self.assertEqual(documented, printed)
                self.assertIn(f'({len(printed)} lines;', self.text[payload])
                self.assertLessEqual(len(printed), const(f'{payload}.c', 'PL_PAGE_LINES'))

    def test_the_instruction_tables_are_the_binaries(self):
        for payload in PAYLOADS:
            with self.subTest(payload=payload):
                f = built(payload)['facts']
                text = self.text[payload]
                named = set()
                for row in rows(block(text, f'{payload}-instructions')):
                    if row[0] == '`MRS`':
                        named |= {lib.SYSTEM_REGISTER_ALIASES.get(token.lower(), token.lower()) for token in re.findall(r'`(\w+)`', row[1])}
                self.assertEqual(named, lib.POLICIES[payload]['registers'])
                self.assertEqual(sorted(f['mrs']), sorted(named))
                self.assertEqual((f['mnemonics']['at'], f['mnemonics']['isb']), (1, 1))
                self.assertIn('`S1E2R`, one site, **no other form**', block(text, f'{payload}-instructions'))
                self.assertIn(f'**{f["bytes"]:,} bytes**', text)
                self.assertIn(f'{f["instructions"]:,} instructions', text)
                self.assertEqual(built(payload)['problems'], [])
                self.assertEqual({s[5] for s in built(payload)['stores']} - {memcheck.STACK, memcheck.CALLER}, set())

    def test_hashbig_loads_through_any_base_in_the_two_functions_the_document_names_and_el2mem_in_none(self):
        self.assertEqual({item[0] for item in built('el2mem')['loads'] if item[5] not in memcheck.POINTERS}, set())
        arbitrary = {item[0] for item in built('hashbig')['loads'] if item[5] not in memcheck.POINTERS}
        self.assertEqual(arbitrary, {'pl_sha256_blocks', 'copy_tail'})
        text = self.text['hashbig']
        self.assertIn('**exactly two functions**: the compression function and the copy of the tail', flat(text))
        self.assertIn('| loads | **any base** | the compression function and the tail copy only |', block(text, 'hashbig-instructions'))
        self.assertTrue(lib.POLICIES['hashbig']['bulk_reads'])
        self.assertNotIn('bulk_reads', lib.POLICIES['el2mem'])

    def test_the_par_table_is_the_sources_decode(self):
        decode = kit.code_of(ROOT / 'payloads' / 'payload-mmu.h')
        section = block(self.text['el2mem'], 'mmu-par')
        by_field = {row[0].strip('`'): row for row in rows(section)}
        self.assertEqual(set(by_field), {'F', 'FST', 'SH', 'NS', 'output address', 'ATTR'})
        for field, bits, code in (('F', '0', 'par & 1'), ('FST', '6:1, when `F` is 1', 'par >> 1 & 63'), ('SH', '8:7, when `F` is 0', 'par >> 7 & 3'),
                                  ('NS', '9, when `F` is 0', 'par >> 9 & 1'), ('output address', '51:12, when `F` is 0', '0x000ffffffffff000'),
                                  ('ATTR', '63:56, when `F` is 0', 'par >> 56')):
            self.assertEqual(by_field[field][1], bits, field)
            self.assertIn(code, decode, f'the source no longer decodes {field} as {code}')
        for row in by_field.values():
            self.assertRegex(row[3], r'VERIFIED|UNKNOWN|INFERRED')
        self.assertIn('VERIFIED against Linux `arch/arm64/include/asm/sysreg.h`', section)
        self.assertIn('1u << 24', decode)

    def test_the_limits_the_documents_state_are_the_sources(self):
        e, h = flat(self.text['el2mem']), flat(self.text['hashbig'])
        self.assertIn(f'At most **{const("el2mem.c", "PL_PAGE_LINES")} lines**', e)
        self.assertIn(f'(at most {const("el2mem.c", "EXTENTS_MAX")})', e)
        self.assertIn(f'(at most {NUMBER_WORDS[const("el2mem.c", "KEYS_MAX")]})', e)
        self.assertIn(f'(at most {NUMBER_WORDS[const("el2mem.c", "OUTLIERS_MAX")]})', e)
        self.assertIn(f'{const("el2mem.c", "BLOCK_2M") >> 20} MiB boundary', e)
        self.assertIn(f'more than {const("payload-mmu.h", "PL_DESCRIPTORS_MAX")} descriptors', e)
        self.assertIn(f'the stride is below {const("payload-mmu.h", "PL_DESC_BYTES_MIN")}', e)
        self.assertIn(f'`{const("el2mem.c", "BANK_BASE"):#x}` to `{const("el2mem.c", "BANK_END"):#x}`', e)
        for text in (e, h):
            self.assertEqual(set(re.findall(r'`(0x88\w*)`', text)) - {'0x880000000'}, set(), 'the bank starts at 0x880000000')
            self.assertEqual(set(re.findall(r'`(0x1000\w*)`', text)) - {'0x1000000000'}, set(), 'the bank ends at 0x1000000000')
        self.assertIn(f'`NEXT <REG> AFTER {const("el2mem.c", "WAIT_BEFORE_READ_S")} S`', e)
        self.assertEqual(set(re.findall(r'AFTER (\d+) S', e)), {str(const('el2mem.c', 'WAIT_BEFORE_READ_S'))}, 'every NEXT line waits the same')
        self.assertEqual(set(re.findall(r'\(at most (\w+)\)', e)),
                         {str(const('el2mem.c', 'EXTENTS_MAX')), NUMBER_WORDS[const('el2mem.c', 'KEYS_MAX')], NUMBER_WORDS[const('el2mem.c', 'OUTLIERS_MAX')]},
                         'every limit the document states is the source\'s')
        self.assertEqual(const('el2mem.c', 'ESSENTIAL_LINES'), 4)
        self.assertIn('The last four lines the payload may print are reserved for the three `NEXT` lines', e)
        self.assertIn(f'At most **{const("hashbig.c", "PL_PAGE_LINES")} lines**', h)
        self.assertIn(f'**{const("hashbig.c", "TIME_BOX_S")} seconds** of counter time', h)
        self.assertIn(f'`NEXT SHA256 BOX={const("hashbig.c", "TIME_BOX_S")} S`', h)
        self.assertEqual(set(re.findall(r'BOX=(\d+) S', h)), {str(const('hashbig.c', 'TIME_BOX_S'))}, 'every mention of the box is the same')
        self.assertIn(f'**{const("hashbig.c", "STUCK_CHECKS")} looks in a row with the same value**', h)
        steps = const('hashbig.c', 'CHECK_BLOCKS') * 64 // 1024
        self.assertIn(f'in {steps} KiB steps', h)
        self.assertIn(f'(no tick in {const("hashbig.c", "STUCK_CHECKS") * steps // 1024} MiB)', h)
        self.assertIn(f'at most {const("hashbig.c", "FILE_BYTES_MAX") >> 20} MiB (the runner\'s own cap)', h)
        preload_max = int(re.search(r'#define Q1N1_PRELOAD_MAX (\d+)', (ROOT / 'platform' / 'uefi' / 'preload.h').read_text(encoding='utf-8')).group(1))
        self.assertIn(f'a count of at most {preload_max}', h)
        self.assertIn('outside 1 MHz to 1 GHz', h)
        self.assertEqual((const('hashbig.c', 'COUNTER_HZ_MIN'), const('hashbig.c', 'COUNTER_HZ_MAX')), (1000000, 1000000000))
        self.assertIn(f'beyond 2^{const("hashbig.c", "TICKS_SHOWN_MAX").bit_length() - 1}', h)
        self.assertIn(f'{150994944 / (const("hashbig.c", "TIME_BOX_S") * (1 << 20)):.2f} MiB/s', h)
        for payload in PAYLOADS:
            words = re.findall(r'\b(\w+)[ -]seconds?\b', flat(self.text[payload]))
            numbers = {word for word in words if word.isdigit() or word in NUMBER_WORDS.values() or word in ('nine', 'seven', 'six', 'four', 'two', 'one')}
            self.assertLessEqual(numbers, SECONDS[payload], f'{payload}: a number of seconds the source does not have')
        self.assertEqual(const('el2mem.c', 'WAIT_BEFORE_READ_S'), 8)
        self.assertEqual(const('hashbig.c', 'TIME_BOX_S'), 25)

    def test_the_return_table_is_the_sources_enum(self):
        source = kit.code_of(ROOT / 'payloads' / 'hashbig.c')
        enum = dict(re.findall(r'\b(RET_[A-Z0-9_]+) = (\d+)', source))
        self.assertEqual(set(enum.values()), {'0', '2', '3', '4', '5', '6', '7'})
        table = {row[0]: row[1] for row in rows(block(self.text['hashbig'], 'hashbig-returns'))}
        self.assertEqual(set(table), {'0', '1', '2', '3', '4', '5', '6', '7'})
        for name, value in (('RET_OK', '0'), ('RET_NOT_EL2', '2'), ('RET_MAP', '3'), ('RET_NO_FILE', '4'), ('RET_EXTENT', '5'), ('RET_DIFFER', '6'),
                            ('RET_NOT_MAPPED', '7')):
            self.assertEqual(enum[name], value)
        self.assertIn('not at EL2', table['2'])
        self.assertIn('differs', table['6'])
        self.assertIn('not mapped', table['7'])
        self.assertIn('time box', table['0'])
        self.assertIn('Q1N1_PAYLOAD_RET_BAD_ARGS', (ROOT / 'platform' / 'uefi' / 'sp11-payload-abi.h').read_text(encoding='utf-8'))
        self.assertIn('RETURN=0X4', self.text['hashbig'])
        self.assertIn('(return 3)', self.text['el2mem'])
        self.assertIn('returns 2', self.text['el2mem'])

    def test_the_decision_tables_answer_every_outcome(self):
        expected = {'el2mem': ('ALL=MAPPED', 'NOT_CONVENTIONAL_IN_THE_MAP', 'FAULT', 'OUTLIER', 'DEVICE', 'NONIDENT', 'CONTROL', 'ERR<n>',
                               'SKIPPED_NOT_MAPPED', 'PAN', 'OSLK', 'SRE', 'ENABLE', 'NEXT', 'SKIPPED=NO_COUNTER', 'MAP_REFUSED',
                               'SCAN_HAS_FAULTS', 'SUPPRESSED', 'NS=1'),
                    'hashbig': ('TIMEBOX', 'MIBS', 'ATTR', 'DEVICE', 'NONIDENT', 'NOT_IN_ALLOCATED_DESCRIPTORS',
                                'A_PAGE_OF_THE_FILE_IS_NOT_MAPPED', 'DIFFER', 'NO_DATA_FILE', 'BAD_HEADER', 'MAP_REFUSED', 'COUNTER_STUCK',
                                'RATE=UNKNOWN_COUNTER', 'NEXT SHA256', 'SUPPRESSED', 'BASE', 'fault page')}
        # What the first column, the outcome on the page, must name: every refusal and every ending the source can print.
        outcomes = {'el2mem': ('ALL=MAPPED', 'NOT_CONVENTIONAL_IN_THE_MAP', 'FAULT', 'OUTLIER', 'RESULT=DEVICE', 'NONIDENT', 'CONTROL', 'ERR<n>',
                               'SKIPPED_NOT_MAPPED', 'PAN', 'OSLK=1', 'OSLK=0', 'SRE=1', 'the page ends at `NEXT MDSCR_EL1',
                               'the page ends before the first', 'SKIPPED=NO_COUNTER', 'MAP_REFUSED', 'SCAN_HAS_FAULTS', 'SUPPRESSED'),
                    'hashbig': ('MIBS', 'TIMEBOX', 'ATTR FIRST=WB.IS', 'NC', 'NONIDENT', 'BASE=0X', 'NO_TABLE', 'BAD_HEADER', 'TABLE_OVERRUNS_ITS_SIZE',
                                'NO_DATA_FILE', 'BASE_NOT_PAGE_ALIGNED', 'SIZE_ZERO_OR_OVER_256_MIB', 'BEYOND_THE_48_BIT_SPACE',
                                'NOT_IN_ALLOCATED_DESCRIPTORS', 'A_PAGE_OF_THE_FILE_IS_NOT_MAPPED', 'DIFFER', 'MAP_REFUSED', 'COUNTER_STUCK',
                                'RATE=UNKNOWN_COUNTER', 'the page ends at `NEXT SHA256', 'a q1n1 fault page after', 'SUPPRESSED')}
        for payload in PAYLOADS:
            with self.subTest(payload=payload):
                decisions = rows(block(self.text[payload], f'{payload}-decisions'))
                self.assertGreaterEqual(len(decisions), 17)
                for row in decisions:
                    self.assertEqual(len(row), 3)
                    self.assertTrue(all(row), row)
                table = ' '.join(' '.join(row) for row in decisions)
                for word in expected[payload]:
                    self.assertIn(word, table, f'the decision table does not mention {word}')
                first = ' '.join(row[0] for row in decisions)
                for word in outcomes[payload]:
                    self.assertIn(word, first, f'no row of the decision table has {word} as its outcome')
                self.assertIn('INFERRED throughout: nothing below has been observed on the unit.', self.text[payload])

    # -- QEMU ---------------------------------------------------------------------------------------------------------------------
    def test_the_qemu_blocks_have_the_shape_the_qemu_test_asserts_and_agree_with_their_own_arithmetic(self):
        for payload in PAYLOADS:
            with self.subTest(payload=payload):
                lines = fenced(self.text[payload], f'{payload}-qemu')
                for line in lines:
                    self.assertIsNotNone(qemu.qemu.FONT_LINE.fullmatch(line), line)
                    self.assertTrue(line.startswith(PREFIX[payload]), line)
                self.assertEqual(qemu.folded(lines, PREFIX[payload]), FOLDED[payload])
                self.assertLessEqual(len(lines), const(f'{payload}.c', 'PL_PAGE_LINES'))
        lines = fenced(self.text['el2mem'], 'el2mem-qemu')
        ids, oslsr, sre = (qemu.values(lines, PREFIX['el2mem'], label) for label in ('ID', 'OSLSR_EL1', 'ICC_SRE_EL2'))
        mmfr1 = int(ids['MMFR1'], 16)
        self.assertEqual((int(ids['PAN']), int(ids['VH']), int(ids['HAFDBS'])), (mmfr1 >> 20 & 15, mmfr1 >> 8 & 15, mmfr1 & 15))
        self.assertEqual(int(oslsr['OSLK']), int(oslsr['RAW'], 16) >> 1 & 1)
        self.assertEqual((int(sre['SRE']), int(sre['ENABLE'])), (int(sre['RAW'], 16) & 1, int(sre['RAW'], 16) >> 3 & 1))
        scan, key, mapped = (qemu.values(lines, PREFIX['el2mem'], label) for label in ('SCAN', 'KEY', 'MAP'))
        self.assertEqual((scan['PROBES'], scan['EXTENTS']), (key['PROBES'], mapped['CONV_EXTENTS']))
        lines = fenced(self.text['hashbig'], 'hashbig-qemu')
        start, file, rate = (qemu.values(lines, PREFIX['hashbig'], label) for label in ('START', 'FILE', 'HASH'))
        freq, ticks, size = int(start['FREQ']), int(rate['TICKS']), int(rate['BYTES'])
        self.assertEqual(size, len(qemu.DATA))
        self.assertEqual((int(file['BYTES']), file['MIB']), (len(qemu.DATA), str(len(qemu.DATA) >> 20)))
        self.assertEqual((int(rate['MS']), int(rate['MIBS'])), (ticks * 1000 // freq, size * freq // (ticks * (1 << 20))))
        self.assertIn(f'{PREFIX["hashbig"]}DIGEST {hashlib.sha256(qemu.DATA).hexdigest()[:16].upper()} MATCH', lines)
        self.assertIn(f'1 MiB and {len(qemu.DATA) - (1 << 20):,} bytes', flat(self.text['hashbig']))

    # -- the chain, the staging plan, the tests ----------------------------------------------------------------------------------
    def test_the_chain_arithmetic_uses_the_runners_numbers_and_the_budgets(self):
        runner = block(RUNNER_DOC.read_text(encoding='utf-8'), 'chain-budget')
        found = {key: re.search(pattern, runner) for key, pattern in (
            ('psci', r'\| `psci`, at most \| (\d+) \|'), ('unit', r"\| panel region, the unit's 2880 x 1920 panel \| (\d+) \|"),
            ('stock', r'\| panel region, the stock layout: the least it asks for \| (\d+) \|'))}
        if not all(found.values()):
            self.skipTest("the runner's planning table has another shape")
        n = {key: int(match.group(1)) for key, match in found.items()}
        e, h = const('el2mem.c', 'PL_PAGE_LINES'), const('hashbig.c', 'PL_PAGE_LINES')
        self.assertEqual(program('el2mem')['most'], e, 'the worst world reaches the budget and never passes it')
        self.assertLessEqual(program('hashbig')['most'], h)
        expected = {
            'el2mem': {'`el2mem` alone': (2, 3, e), '`el2mem`, `hashbig` and `BIG.DAT`: the staging plan': (4, 6, e, h),
                       '`psci`, `el2mem`, `hashbig` and `BIG.DAT`': (5, 9, n['psci'], e, h)},
            'hashbig': {'`hashbig` and a data file': (3, 3, h), '`el2mem`, `hashbig` and `BIG.DAT`: the staging plan': (4, 6, e, h),
                        '`psci`, `hashbig` and `BIG.DAT`': (4, 6, n['psci'], h)}}
        for payload in PAYLOADS:
            by = {row[0]: row for row in rows(block(self.text[payload], f'{payload}-chain-budget'))}
            self.assertEqual(set(by), set(expected[payload]))
            for chain, (_, formula, unit, stock) in by.items():
                with self.subTest(payload=payload, chain=chain):
                    self.assertRegex(formula, r'^[0-9 +()x]+ = \d+$')
                    left, right = formula.split(' = ')
                    self.assertEqual(eval(left.replace('x', '*')), int(right))
                    self.assertEqual(int(right), sum(expected[payload][chain]))
                    self.assertEqual((unit, stock), ('yes' if int(right) <= n['unit'] else 'no', 'yes' if int(right) <= n['stock'] else 'no'))

    def test_the_staging_plan_is_what_the_manifest_tool_accepts_at_the_staged_size(self):
        for payload in PAYLOADS:
            with self.subTest(payload=payload):
                lines = fenced(self.text[payload], f'{payload}-staging')
                commands = [line for line in lines if line and not line.startswith('#')]
                dd = re.fullmatch(r'dd if=/dev/urandom of=BIG\.DAT bs=(\d+) count=(\d+)', commands[0])
                self.assertEqual(int(dd.group(1)) * int(dd.group(2)), 150994944)
                self.assertEqual(150994944, 144 << 20)
                tool = commands[1].split()
                self.assertEqual(tool[:3], ['python3', 'tools/sp11_payload_manifest.py', '--out-dir'])
                self.assertEqual(tool[3:], ['build/stick', 'build/uefi/payloads/el2mem.bin', 'build/uefi/payloads/hashbig.bin', 'BIG.DAT'])
                self.assertTrue((ROOT / tool[1]).is_file())
                self.assertEqual(commands[2:], ['load SP11\\SLBOUNCE-DEVHE-MARK.EFI', 'SP11\\Q1N1-PAYLOAD.EFI --el2'])
                runner = RUNNER_DOC.read_text(encoding='utf-8')
                for command in commands[2:]:
                    self.assertIn(command, runner)
                text = flat(self.text[payload])
                self.assertIn('150,994,944 bytes', text)
                self.assertIn('144 MiB', text)
        entries = staged()
        self.assertEqual([(e[0], e[4]) for e in entries], [('\\SP11\\EL2MEM.BIN', 'payload'), ('\\SP11\\HASHBIG.BIN', 'payload'), ('\\SP11\\BIG.DAT', 'data')])
        self.assertEqual(entries[2][1], 150994944)
        self.assertEqual((manifest_tool.MAX_FILES, manifest_tool.MAX_FILE_BYTES >> 20), (5, 256))
        self.assertIn('at most 5 files, each at most 256 MiB', flat(self.text['el2mem']))
        self.assertIn('at most 5 files, each at most 256 MiB', flat(self.text['hashbig']))
        self.assertEqual([line for line in fenced(self.text['el2mem'], 'el2mem-staging') if not line.startswith('#')],
                         [line for line in fenced(self.text['hashbig'], 'hashbig-staging') if not line.startswith('#')])

    def test_the_tests_tables_state_the_counts_of_the_drivers(self):
        e, h = flat(self.text['el2mem']), flat(self.text['hashbig'])
        self.assertIn(f'{len(el2mem.MUTANTS)} seeded-bug mutants', e)
        self.assertIn(f'{len(el2mem.BAD_BINARIES)} seeded bad binaries', e)
        self.assertIn(f'({NUMBER_WORDS[len(el2mem.SUITES)]} suites', e)
        self.assertIn(f'{len(hashbig.MUTANTS)} seeded-bug mutants', h)
        self.assertIn(f'{len(hashbig.BAD_BINARIES)} seeded bad binaries', h)
        self.assertIn(f'({NUMBER_WORDS[len(hashbig.SUITES)]} suites', h)
        self.assertIn(f'on {len(engine.CASES)} synthetic disassembly cases, with {len(engine.MUTANTS)} seeded bugs in the checker', e)
        self.assertIn(f'on {len(engine.OLDER) * (len(engine.FORMS) + len(engine.READS))} binaries under the five older policies', e)
        for payload in PAYLOADS:
            tests = self.text[payload].split('\n## Tests\n')[1].split('\n## ')[0]
            for command in (f'test-q1n1-sp11-payload-{payload}.py', 'test-q1n1-sp11-payload-memcheck.py', 'test-q1n1-sp11-payload-qemu-el2mem.py',
                            'test-q1n1-sp11-payload-mmu-doc.py', 'test-q1n1-sp11-payload-build.py'):
                self.assertIn(command, tests)
                self.assertTrue((ROOT / 'tools' / command).is_file(), command)

    def test_the_documents_say_what_the_status_is_and_that_the_restart_control_is_reported_not_recorded(self):
        for payload in PAYLOADS:
            text = flat(self.text[payload])
            self.assertIn('UPTIME` 224 S and 268 S in two boots', text)
            self.assertIn('reported to this work; no page of it is in this tree', text)
            self.assertIn('is not expected to restart the board by itself', text)
            self.assertIn('UNKNOWN: everything else this payload would print on the unit.', text)
        self.assertIn('(`ID_AA64ISAR0_EL1` `0x1221111110212120`, OBSERVED on the unit, has `SHA2` 2 in bits 15:12: INFERRED field position)',
                      flat(self.text['hashbig']))


def _replace(old, new):
    def mutate(doc):
        assert doc.count(old) >= 1, old
        return doc.replace(old, new, 1)
    return mutate


def _drop(prefix):
    def mutate(doc):
        lines = doc.split('\n')
        at = next(i for i, line in enumerate(lines) if line.startswith(prefix))
        return '\n'.join(lines[:at] + lines[at + 1:])
    return mutate


EL2MEM_MISTAKES = [
    ('the-line-budget-is-wrong', _replace('At most **26 lines**', 'At most **27 lines**')),
    ('the-extent-limit-is-wrong', _replace('(at most 64)', '(at most 65)')),
    ('the-key-limit-is-wrong', _replace('(at most\n   three)', '(at most\n   four)')),
    ('the-wait-is-wrong', _replace('and\n   eight seconds of waiting', 'and\n   nine seconds of waiting')),
    ('the-next-line-is-wrong', _replace('| `NEXT MDSCR_EL1 AFTER 8 S` |', '| `NEXT MDSCR_EL1 AFTER 9 S` |')),
    ('the-bank-is-wrong', _replace('30 GiB bank `0x880000000` to', '30 GiB bank `0x88000000` to')),
    ('the-page-line-is-changed', _replace('KEY RESULT=WB.IS PROBES=16051', 'KEY RESULT=WB.IS PROBES=16052')),
    ('the-page-line-is-dropped', _drop('PAYLOAD EL2MEM OSLSR_EL1 RAW=0X8 OSLK=0')),
    ('a-keyword-row-is-forgotten', _drop('| `ICC_SRE_EL2 RAW=0X.. SRE=<n> ENABLE=<n>` |')),
    ('a-keyword-is-invented', _replace('<!-- /el2mem-lines -->', '| `SCAN HOLE=<n>` | invented |\n<!-- /el2mem-lines -->')),
    ('a-refusal-reason-is-forgotten', _replace(' / `TOO_MANY_DESCRIPTORS`', '')),
    ('a-register-is-forgotten-in-the-instruction-table', _replace(', `ID_AA64PFR2_EL1` (`S3_0_C0_C4_2`)', '')),
    ('the-binary-size-is-wrong', _replace('**12,834 bytes**', '**12,835 bytes**')),
    ('a-par-bit-is-wrong', _replace('| `SH` | 8:7, when `F` is 0 |', '| `SH` | 9:8, when `F` is 0 |')),
    ('the-attr-bits-are-wrong', _replace('| 63:56, when `F` is 0 |', '| 62:56, when `F` is 0 |')),
    ('the-decision-table-lost-the-load-error', _drop('| `LOAD ...=ERR<n>` after the AT said mapped |')),
    ('the-qemu-block-loses-a-line', _drop('PAYLOAD EL2MEM MAP DESC=38')),
    ('the-qemu-pan-is-wrong', _replace('PAN=3 VH=1 HAFDBS=2\nPAYLOAD EL2MEM ID PFR2', 'PAN=2 VH=1 HAFDBS=2\nPAYLOAD EL2MEM ID PFR2')),
    ('the-qemu-oslk-is-wrong', _replace('OSLSR_EL1 RAW=0XA OSLK=1', 'OSLSR_EL1 RAW=0XA OSLK=0')),
    ('the-chain-formula-is-wrong', _replace('(3 + 1) + 3 x 2 + 26 + 12 = 48 | yes', '(3 + 1) + 3 x 2 + 26 + 12 = 49 | yes')),
    ('the-chain-fit-is-wrong', _replace('= 82 | yes | no |', '= 82 | yes | yes |')),
    ('the-staging-size-is-wrong', _replace('bs=1048576 count=144', 'bs=1048576 count=145')),
    ('the-staging-order-is-wrong', _replace('el2mem.bin build/uefi/payloads/hashbig.bin BIG.DAT\n# copy', 'hashbig.bin build/uefi/payloads/el2mem.bin BIG.DAT\n# copy')),
    ('the-mutant-count-is-wrong', _replace(f'{len(el2mem.MUTANTS)} seeded-bug mutants', f'{len(el2mem.MUTANTS) - 1} seeded-bug mutants')),
    ('the-bad-binary-count-is-wrong', _replace(f'{len(el2mem.BAD_BINARIES)} seeded bad binaries', f'{len(el2mem.BAD_BINARIES) - 1} seeded bad binaries')),
    ('the-case-count-is-wrong', _replace(f'on {len(engine.CASES)} synthetic', f'on {len(engine.CASES) - 1} synthetic')),
    ('the-licence-line-is-gone', _replace('<!-- SPDX-License-Identifier: MIT -->\n', '')),
    ('the-link-is-broken', _replace('(SP11-PAYLOAD-HASHBIG.md)', '(SP11-PAYLOAD-HASHBIG2.md)')),
    ('the-anchor-is-broken', _replace('(SP11-PAYLOAD.md#the-manifest)', '(SP11-PAYLOAD.md#the-manifests)')),
    ('hardware-is-called-run', _replace('**EXPERIMENTAL; hardware NOT RUN.**', '**EXPERIMENTAL; hardware RUN.**')),
    ('a-value-is-called-observed-on-the-unit', _replace('**No value of this payload has been OBSERVED on the unit.**', '**Every value of this payload has been OBSERVED.**')),
    ('the-restart-control-is-called-recorded', _replace('reported to this work; no page of it is in this tree', 'recorded in this tree')),
]
HASHBIG_MISTAKES = [
    ('the-line-budget-is-wrong', _replace('At most **12 lines**', 'At most **13 lines**')),
    ('the-time-box-is-wrong', _replace('**25 seconds** of counter time', '**26 seconds** of counter time')),
    ('the-next-line-is-wrong', _replace('`NEXT SHA256 BOX=25 S`', '`NEXT SHA256 BOX=26 S`')),
    ('the-stuck-count-is-wrong', _replace('**256 looks in a row', '**255 looks in a row')),
    ('the-step-is-wrong', _replace('in 64 KiB steps', 'in 32 KiB steps')),
    ('the-file-limit-is-wrong', _replace("at most 256 MiB (the runner's own cap)", "at most 128 MiB (the runner's own cap)")),
    ('the-threshold-is-wrong', _replace('5.76 MiB/s', '5.67 MiB/s')),
    ('the-return-row-is-forgotten', _drop('| 7 | a page of the file')),
    ('a-return-value-is-wrong', _replace('| 6 | the digest differs', '| 5 | the digest differs')),
    ('the-page-line-is-changed', _replace('MIBS=1\nPAYLOAD HASHBIG DIGEST D91313D6FDEC24D7', 'MIBS=2\nPAYLOAD HASHBIG DIGEST D91313D6FDEC24D7')),
    ('the-page-line-is-dropped', _drop('PAYLOAD HASHBIG EXTENT ALLOCATED DESCRIPTORS=1')),
    ('a-keyword-row-is-forgotten', _drop('| `TIMEBOX HASHED=<n> OF <n> TICKS=<n>`')),
    ('a-keyword-is-invented', _replace('<!-- /hashbig-lines -->', '| `HASH SPEED=<n>` | invented |\n<!-- /hashbig-lines -->')),
    ('a-register-is-forgotten-in-the-instruction-table', _replace('| `MRS` | `PAR_EL1`, once | `pl_at_s1e2r` | the answer of the `AT` |\n', '')),
    ('the-binary-size-is-wrong', _replace('**9,412 bytes**', '**9,413 bytes**')),
    ('the-two-functions-claim-is-wrong', _replace('| the compression function and the tail copy only |', '| the compression function only |')),
    ('the-decision-table-lost-the-fault-page', _drop('| a q1n1 fault page after `NEXT SHA256 BOX=25 S` |')),
    ('the-qemu-digest-is-wrong', _replace('DIGEST 2E86FE97C8CD65D7 MATCH\nPAYLOAD HASHBIG DONE MATCH', 'DIGEST 2E86FE97C8CD65D8 MATCH\nPAYLOAD HASHBIG DONE MATCH')),
    ('the-qemu-rate-is-wrong', _replace('MS=17 MIBS=57', 'MS=18 MIBS=57')),
    ('the-qemu-size-is-wrong', _replace('BYTES=1052669 MIB=1', 'BYTES=1052670 MIB=1')),
    ('the-chain-formula-is-wrong', _replace('(2 + 1) + 3 + 12 = 18', '(2 + 1) + 3 + 12 = 19')),
    ('the-staging-lost-the-data-file', _replace('hashbig.bin BIG.DAT\nload', 'hashbig.bin\nload')),
    ('the-staging-size-is-wrong', _replace('bs=1048576 count=144', 'bs=1048576 count=143')),
    ('the-mutant-count-is-wrong', _replace(f'{len(hashbig.MUTANTS)} seeded-bug mutants', f'{len(hashbig.MUTANTS) - 1} seeded-bug mutants')),
    ('the-bad-binary-count-is-wrong', _replace(f'{len(hashbig.BAD_BINARIES)} seeded bad binaries', f'{len(hashbig.BAD_BINARIES) - 1} seeded bad binaries')),
    ('the-suite-count-is-wrong', _replace('(twelve suites', '(eleven suites')),
    ('the-licence-line-is-gone', _replace('<!-- SPDX-License-Identifier: MIT -->\n', '')),
    ('the-link-is-broken', _replace('(SP11-PAYLOAD-EL2MEM.md#memory-rules)', '(SP11-PAYLOAD-EL2MEM.md#memory-rule)')),
    ('hardware-is-called-run', _replace('**EXPERIMENTAL; hardware NOT RUN.**', '**EXPERIMENTAL; hardware RUN.**')),
    ('a-value-is-called-observed-on-the-unit', _replace('**No value of this payload has been OBSERVED on the unit.**', '**Every value of this payload has been OBSERVED.**')),
    ('the-isar0-claim-loses-its-label', _replace('bits 15:12: INFERRED field position)', 'bits 15:12: VERIFIED)')),
]
MISTAKES = [(name, 'el2mem', mutate) for name, mutate in EL2MEM_MISTAKES] + [(name, 'hashbig', mutate) for name, mutate in HASHBIG_MISTAKES]


class MmuDocMutants(unittest.TestCase):
    """The agreement tests above must be able to fail: each seeded mistake in either document is refused by one."""

    @staticmethod
    def outcome(texts):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(type('Changed', (MmuDocAgreement,), {'TEXTS': texts}))
        result = unittest.TestResult()
        suite.run(result)
        return result

    def test_the_unchanged_documents_pass_through_the_same_mechanism(self):
        result = self.outcome({name: path.read_text(encoding='utf-8') for name, path in DOCS.items()})
        self.assertTrue(result.wasSuccessful(), [str(f[1])[-500:] for f in result.failures + result.errors])
        self.assertGreaterEqual(result.testsRun, 14)
        self.assertEqual(result.skipped, [], 'a skipped agreement test proves nothing')

    def test_every_seeded_mistake_in_either_document_is_refused(self):
        originals = {name: path.read_text(encoding='utf-8') for name, path in DOCS.items()}
        self.assertGreaterEqual(len(EL2MEM_MISTAKES), 30)
        self.assertGreaterEqual(len(HASHBIG_MISTAKES), 28)
        for payload in PAYLOADS:
            names = [name for name, which, _ in MISTAKES if which == payload]
            self.assertEqual(len(set(names)), len(names))
        for name, which, mutate in MISTAKES:
            with self.subTest(mutant=f'{which}-{name}'):
                texts = dict(originals)
                texts[which] = mutate(originals[which])
                self.assertNotEqual(texts[which], originals[which])
                result = self.outcome(texts)
                self.assertFalse(result.wasSuccessful(), 'every agreement test still passed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
