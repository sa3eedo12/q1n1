#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""docs/SP11-PAYLOAD-RETPROBE.md against the source, the host program, the driver and the runner's document, and the same agreement
tests against seeded mistakes in a copy of the document.

    python3 tools/test-q1n1-sp11-payload-retprobe-doc.py

What it holds the document to: the house rules (the licence line, the size limit, ASCII, no machine identifier, the evidence labels,
hardware NOT RUN, no run authorised); the evidence table against the unit's lines in the results document; the page record and the
configuration against the source (every word of the header, the body formula, the CRC word, the limits); the state rules; the reset paths,
their function ids, their gates and the reset type; every keyword the payload prints against the lines table and the other way round;
the refusal reasons and the return values against the source; the three pages of the host program against the examples in the document
(with the hexadecimal values and the mapping masked); the numbers (the most lines, the loads, the suites, the mutants, the QEMU boots);
the authorisation and the stop rule; the sample configuration against the stick test; the links, and the pointer in the runner's document.
Writes only under build/. Hardware: NOT RUN (this checks a document)."""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_ecv_lib as ecv  # noqa: E402

driver = ecv.load_module('sp11_payload_retprobe_driver_for_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload-retprobe.py')
native = driver.native
DOC, SOURCE = driver.DOC, driver.SOURCE
block, rows = ecv.block, ecv.rows
_PROGRAM_OUTPUT = {}     # the host program's output by arguments: the document mutants would otherwise rebuild it for every copy
WORD = re.compile(r'[A-Z][A-Z0-9_]{2,}')
LABELS = ('VERIFIED', 'OBSERVED', 'INFERRED', 'EXPERIMENTAL', 'UNIMPLEMENTED', 'UNKNOWN')
EVIDENCE = {          # each statement of the evidence table, exactly, and the first word of its label
    '`PSCI_FEATURES(SYSTEM_RESET)` answers 0 on the unit': 'OBSERVED',
    '`PSCI_FEATURES(SYSTEM_RESET2)` answers `NOT_SUPPORTED(-1)` on the unit': 'OBSERVED',
    'a 0 from `PSCI_FEATURES` means the function is implemented': 'INFERRED',
    'the architectural warm reset type 0 is implied by `SYSTEM_RESET2` being implemented': 'INFERRED',
    'after a restart by itself the unit boots its normal order, not the stick': 'OBSERVED',
    'a `SYSTEM_RESET` call restarts the unit, and the call does not return': 'UNKNOWN',
    'DRAM keeps its bytes across that reset': 'UNKNOWN',
    'the point of coherency that `DC CVAC` reaches is DRAM and not a system cache in front of it': 'UNKNOWN',
    'a read of memory never written since power-on does not abort': 'UNKNOWN',
    'firmware does not use or clear the three pages before the next boot reads them': 'UNKNOWN',
}


def read_doc(name):
    return (ROOT / 'docs' / name).read_text(encoding='utf-8')


def masked(line):
    """A page line with every hexadecimal value and the mapping attributes replaced: the model's addresses are its own."""
    return re.sub(r'MAP=\S+', 'MAP=<m>', re.sub(r'0X[0-9A-F]+', '0X', line))


def fenced(text):
    return [line for line in text.strip().splitlines() if line != '```']


def words(spec):
    """The word numbers of a table cell such as '4-5' or '20-30'."""
    low, _, high = spec.partition('-')
    return list(range(int(low), int(high or low) + 1))


class RetprobeDocAgreement(unittest.TestCase):
    TEXT = None     # a changed copy of the document, for RetprobeDocMutants

    @classmethod
    def setUpClass(cls):
        if not DOC.exists():
            raise unittest.SkipTest('docs/SP11-PAYLOAD-RETPROBE.md does not exist')
        cls.text = DOC.read_text(encoding='utf-8') if cls.TEXT is None else cls.TEXT
        cls.flat = ' '.join(cls.text.split())               # the paragraphs are wrapped: phrases are looked up with the wraps undone
        cls.code = ecv.code_of(SOURCE)
        cls.source = SOURCE.read_text(encoding='utf-8')

    def says(self, phrase):
        self.assertIn(' '.join(phrase.split()), self.flat, f'the document does not say {phrase!r}')

    def define(self, name):
        found = re.search(rf'#define {name} (\(?[0-9A-Fa-fxuUL() ]+?\)?)\s*(?:/\*.*)?$', self.code, re.M)
        self.assertIsNotNone(found, name)
        return int(found.group(1).strip('() ').rstrip('uUL'), 0)

    def program(self, *args):
        if not lib.have('clang'):
            self.skipTest('clang not installed')
        if args not in _PROGRAM_OUTPUT:
            done, binary = native.build_program('retprobe', native.UEFI, native.PAYLOADS, driver.BUILD / 'doc')
            self.assertEqual(done.returncode, 0, done.stderr)
            code, output = native.run_program(binary, *args)
            self.assertEqual(code, 0, output)
            _PROGRAM_OUTPUT[args] = output
        return _PROGRAM_OUTPUT[args]

    # -- the house rules ------------------------------------------------------------------------------------------------------
    def test_the_document_follows_the_house_rules(self):
        self.assertEqual(self.text.splitlines()[0], '<!-- SPDX-License-Identifier: MIT -->')
        self.assertLess(len(self.text.splitlines()), 1500)
        self.assertLess(len(self.text.encode('utf-8')), 50 * 1024)
        self.assertTrue(self.text.isascii())
        for label in LABELS:
            self.assertIn(label, self.text)
        self.says('**EXPERIMENTAL; hardware NOT RUN.** No value of this payload is OBSERVED on the unit.')
        self.assertNotIn('TODO', self.text)
        paths = '|'.join(['/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/'])
        pattern = re.compile(paths + r'|\.loc' + r'al\b|\bsae' + r'ed\b|host' + r'name|\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', re.I)
        for number, line in enumerate(self.text.splitlines(), 1):
            self.assertIsNone(pattern.search(line), f'{number}: {line}')

    def test_the_links_and_anchors_resolve(self):
        texts = {DOC.name: self.text}
        for other in ('SP11-PAYLOAD.md', 'SP11-PAYLOAD-PSCI.md', 'SP11-PAYLOAD-RESULTS.md'):
            texts[other] = read_doc(other)
        self.assertEqual([p for p in lib.link_problems(texts, ROOT / 'docs') if p.startswith(DOC.name)], [])

    def test_nothing_is_authorised_and_the_authorisation_and_the_stop_rule_are_stated(self):
        self.says('No run is authorised by this document, by its tests, or by the fact that its files are on a stick')
        self.says("a run needs the operator's written authorisation")
        self.says('It is authorised **by name and SHA-256, for one boot, in writing by the operator**, together with its configuration file, '
                  'the reset path and the three addresses.')
        self.says('The stick carries `retprobe` and its configuration **alone**: no other payload shares the boot.')
        self.says('the Shell\'s stick write, the stop rules, and what is not written: the internal disk, NVRAM and firmware settings')
        self.says('**Stop rule.**')
        self.says('A `REFUSED` line means nothing was stored and nothing was reset.')
        self.says('A `VERIFY FAILED` line means no reset was called.')
        self.says('A line `RESET RETURNED` ends the run: the payload makes no second call, and neither does the operator by another path in the same boot.')
        self.says('is left alone and the run is reported')
        self.says('from the reset call until the extraction is written a power cycle loses the pages, so the power button is only for the end of the run '
                  'and for danger (heat, a fan at full speed, a smell)')

    def test_the_evidence_table_labels_and_the_units_lines_are_in_the_results_document(self):
        table = rows(block(self.text, 'retprobe-evidence'))
        self.assertEqual({statement: label.split()[0] for statement, label, _ in table}, EVIDENCE)
        self.assertEqual(len(table), len(EVIDENCE))
        results = read_doc('SP11-PAYLOAD-RESULTS.md')
        self.assertIn('PAYLOAD PSCI FEATURES SYSTEM_RESET=0X0 PSCI_FEATURES=0X0 SYSTEM_SUSPEND=0X0', results)
        self.assertIn('PAYLOAD PSCI FEATURES SYSTEM_RESET2=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)', results)
        self.assertIn('after boot 4', results)

    # -- the page record and the configuration ---------------------------------------------------------------------------------
    def test_the_page_table_is_the_sources_header_and_body(self):
        table = rows(block(self.text, 'retprobe-page'))
        header_words = {int(n) for n in re.findall(r'^\s*header\[(\d+)\] =', self.code, re.M)}
        self.assertEqual(header_words, set(range(20)))
        documented = {}
        for spec, field, _ in table:
            for word in words(spec):
                self.assertNotIn(word, documented, f'word {word} is described twice')
                documented[word] = field
        self.assertEqual(sorted(documented), list(range(1024)), 'every word of the page is described exactly once')
        self.assertEqual({w for w in range(32) if documented[w] == 'reserved'}, set(range(32)) - header_words - {31},
                         'the reserved words are the ones the header leaves zero')
        self.assertEqual({documented[w] for w in range(20, 31)}, {'reserved'})
        self.assertEqual(documented[31], 'CRC-32')
        self.assertEqual(self.define('CRC_WORD'), 31)
        self.assertEqual((self.define('PAGE_WORDS'), self.define('HEADER_WORDS')), (1024, 32))
        self.assertIn('#define BODY_WORDS (PAGE_WORDS - HEADER_WORDS)', self.source)
        self.assertEqual({documented[w] for w in range(32, 1024)}, {'body'})
        self.says('Layout version 1, little endian, 4096 bytes: a 128-byte header of 32 words and 992 body words.')
        self.assertEqual(self.define('LAYOUT_VERSION'), 1)
        self.assertEqual(table[0][0:2], ['0-1', 'magic'])
        self.assertEqual(table[0][2], '`RETCAN01`')
        low, high = self.define('MAGIC_LO'), self.define('PAGE_MAGIC_HI')
        self.assertEqual((low.to_bytes(4, 'little') + high.to_bytes(4, 'little')).decode(), 'RETCAN01')
        self.assertEqual(table[1][2], '1')
        self.assertEqual(table[2][2], '0 to 2')
        self.assertEqual(self.define('PAGES'), 3)
        self.assertIn('1 to `0xFFFFF`', table[4][2])
        self.assertEqual(self.define('COUNTER_MAX'), 0xfffff)

    def test_each_header_word_is_the_field_the_table_names(self):
        table = {words(spec)[0]: (field, value) for spec, field, value in rows(block(self.text, 'retprobe-page'))}
        facts = {                                    # word: (what the document's row must contain, what the source's assignment must contain)
            3: ('page index', 'header[3] = slot;'), 4: ('physical address', 'header[4] = (uint32_t)address;'),
            6: ('boot counter', 'header[6] = s->counter;'), 7: ('previous counter', 'header[7] = s->previous_counter;'),
            8: ('`CNTPCT_EL0`', 'header[8] = (uint32_t)s->timestamp;'), 10: ('`CNTFRQ_EL0`', 'header[10] = s->frequency;'),
            11: ('`PSCI_FEATURES(SYSTEM_RESET)`', 'header[11] = s->feature_reset;'),
            12: ('`PSCI_FEATURES(SYSTEM_RESET2)`', 'header[12] = s->feature_reset2;'),
            13: ('four bytes', 'header[13] = s->path_requested | s->path_used << 8 | s->previous_state[0] << 16 | s->previous_state[1] << 24;'),
            14: ('four bytes', 'header[14] = s->previous_state[2] | 1u << 8;'), 15: ('descriptor type', 'header[15] = x->type;'),
            16: ('descriptor start', 'header[16] = (uint32_t)x->start;'), 18: ('descriptor size', 'header[18] = (uint32_t)x->bytes;'),
        }
        for word, (field, assignment) in facts.items():
            with self.subTest(word=word):
                self.assertIn(field, table[word][0])
                self.assertIn(assignment, self.code)
        self.assertIn('reset path requested, reset path used (0 none, 1 `SYSTEM_RESET`, 2 `SYSTEM_RESET2`), previous state of page 0, of page 1', table[13][1])
        self.assertIn('previous state of page 2 (0 NONE, 1 PARTIAL, 2 WHOLE, 3 UNREADABLE), flush method 1', table[14][1])
        self.assertEqual(table[15][1].split(',')[0], '7')
        self.assertIn('#define PL_EFI_CONVENTIONAL 7u', (ROOT / 'payloads' / 'payload-mmu.h').read_text(encoding='utf-8'))
        self.assertIn('enum { STATE_NONE = 0, STATE_PARTIAL = 1, STATE_WHOLE = 2, STATE_UNREADABLE = 3 };', self.code)
        self.assertIn('enum { PATH_NONE = 0, PATH_PSCI_RESET = 1, PATH_PSCI_RESET2 = 2, PATH_COUNT = 3 };', self.code)
        self.assertEqual(table[31][1], 'IEEE, the value of `zlib.crc32` over the page with this word taken as zero')
        self.assertIn('return counter << 12 | slot << 10 | i;', self.code)
        self.assertEqual(table[32][1], 'word i (0 to 991) is the bitwise OR of `counter << 12`, `page index << 10` and `i`')
        self.assertEqual(self.define('PAGE_WORDS') - self.define('HEADER_WORDS'), 992)

    def test_the_state_rules_are_the_sources(self):
        self.assertEqual(self.define('MIN_BODY_MATCHES'), 16)
        self.says('at least 16 words of exactly that epoch make the page PARTIAL')
        self.says('ties going to the smallest epoch')
        self.says('the epoch (the bits above ten)')
        self.says('whose low ten bits equal their own index')
        self.assertIn('(page[HEADER_WORDS + i] & 0x3ffu) != i', self.code)
        self.assertIn('same == agreed && key < epoch', self.code)
        self.assertIn('matches >= MIN_BODY_MATCHES ? STATE_PARTIAL : STATE_NONE', self.code)
        self.says('the header names this very page (magic, version 1, index, address, a counter from 1 to `0xFFFFF`), the CRC holds, and not one body word is wrong')
        self.says('The count of wrong words and the CRC verdict are reported.')
        self.says('anything else, an all-zero page, an all-ones page and noise included')

    def test_the_configuration_table_is_the_sources(self):
        table = rows(block(self.text, 'retprobe-config'))
        spec = {words(spec_)[0]: (field, rule) for spec_, field, rule in table}
        self.assertEqual(sorted(w for spec_, _, _ in table for w in words(spec_)), list(range(16)))
        self.assertEqual(spec[0][1], '`RETCFG01`')
        low, high = self.define('MAGIC_LO'), self.define('CONFIG_MAGIC_HI')
        self.assertEqual((low.to_bytes(4, 'little') + high.to_bytes(4, 'little')).decode(), 'RETCFG01')
        self.assertEqual(spec[2][1], '1')
        self.assertEqual(spec[3][1], '0 none, 1 `PSCI_RESET`, 2 `PSCI_RESET2`')
        self.assertIn('v[3] >= PATH_COUNT', self.code)
        self.assertEqual(spec[4][1], f'1 to {self.define("COUNTDOWN_MAX_S")}')
        self.assertIn('v[4] < 1u || v[4] > COUNTDOWN_MAX_S', self.code)
        self.assertEqual(spec[5][1], '3')
        self.assertIn('v[5] != PAGES', self.code)
        self.assertEqual(spec[6][1], '64-bit each, 4 KiB aligned, not zero, distinct, below the address limit')
        self.assertIn('c->page[k] & (PL_PAGE_BYTES - 1u)', self.code)
        self.assertIn('c->page[0] == c->page[1] || c->page[0] == c->page[2] || c->page[1] == c->page[2]', self.code)
        self.assertEqual(spec[12][1], 'zero')
        reserved = re.search(r'if \((v\[\d+\](?: \| v\[\d+\])*)\) return CFG_RESERVED', self.code).group(1)
        self.assertEqual(reserved, 'v[12] | v[13] | v[14]')
        self.assertEqual([words(spec_) for spec_, field, _ in table if field == 'reserved'], [[12, 13, 14]])
        self.assertEqual(spec[15][0], 'CRC-32')
        self.assertEqual(spec[15][1], 'of words 0 to 14, checked before any field is believed')
        self.assertIn('for (unsigned i = 0; i < CONFIG_WORDS - 1u; i++) crc = crc32_word(crc, v[i]);', self.code)
        self.assertEqual((self.define('CONFIG_BYTES'), self.define('CONFIG_WORDS')), (64, 16))
        self.says('one data file of exactly 64 bytes that starts with the magic `RETCFG01`')
        self.says('A stick that has no such file, or two of them, is a PHASE 1 run.')

    # -- the paths, the calls and what the payload executes --------------------------------------------------------------------
    def test_the_paths_table_is_the_sources_ids_gates_and_reset_type(self):
        table = rows(block(self.text, 'retprobe-paths'))
        self.assertEqual([r[0] for r in table], ['`NONE`', '`PSCI_RESET`', '`PSCI_RESET2`'])
        self.assertEqual([r[1] for r in table], ['0', '1', '2'])
        self.assertIn(f'`0x{self.define("FUNCTION_SYSTEM_RESET"):08X}`', table[1][2])
        self.assertIn(f'`0x{self.define("FUNCTION_SYSTEM_RESET2"):08X}`', table[2][2])
        self.assertIn(f'reset type {self.define("RESET_TYPE_ARCH_WARM")} (the architectural warm reset), cookie {self.define("COOKIE_UNUSED")}', table[2][2])
        self.assertIn('`PSCI_FEATURES(SYSTEM_RESET)` is not negative as a 32-bit result, else return 7', table[1][3])
        self.assertIn('`PSCI_FEATURES(SYSTEM_RESET2)` is not negative as a 32-bit result, else return 7', table[2][3])
        self.assertIn('if (cfg.path == PATH_PSCI_RESET && (int32_t)(uint32_t)answer[0] < 0) {', self.code)
        self.assertIn('if (cfg.path == PATH_PSCI_RESET2 && (int32_t)(uint32_t)answer[1] < 0) {', self.code)
        self.assertEqual(re.search(r'RET_NOT_IMPLEMENTED = (\d+)', self.code).group(1), '7')
        self.assertIn('answered 0 once (OBSERVED)', table[1][4])
        self.assertIn('answered `NOT_SUPPORTED(-1)` once (OBSERVED): the payload refuses', table[2][4])
        self.assertIn('the default and the negative control', table[0][4])
        self.says('UNIMPLEMENTED: the UEFI `ResetSystem`')
        self.says('a forced hang left for a watchdog')

    def test_the_calls_table_is_the_three_helpers_and_their_fixed_ids(self):
        table = rows(block(self.text, 'retprobe-calls'))
        self.assertEqual([r[0] for r in table], ['`smc_features`', '`smc_system_reset`', '`smc_system_reset2`'])
        wanted = [self.define('FUNCTION_PSCI_FEATURES'), self.define('FUNCTION_SYSTEM_RESET'), self.define('FUNCTION_SYSTEM_RESET2')]
        self.assertEqual([r[1] for r in table], [f'`0x{value:08X}`' for value in wanted])
        self.assertEqual(table[0][2], '`0x84000009` or `0xC4000012`, by index')
        self.assertEqual(self.define('FUNCTION_SYSTEM_RESET'), 0x84000009)
        self.assertEqual(self.define('FUNCTION_SYSTEM_RESET2'), 0xC4000012)
        self.assertEqual(len(re.findall(r'smc #0', self.code)), 3)
        for name in ('smc_features', 'smc_system_reset', 'smc_system_reset2'):
            self.assertIn(f'uint64_t {name}(', self.code)
        self.says('an index outside the table issues no SMC')
        self.says('It reads `CurrentEL`, `CTR_EL0` (the line size), `CNTFRQ_EL0` and `PAR_EL1`')
        self.assertEqual({r.lower() for r in re.findall(r'SYSREG\((\w+)\)', self.code)} - {'name'}, {'currentel', 'ctr_el0', 'cntfrq_el0'})
        self.assertIn('"at s1e2w, %1\\n\\tisb\\n\\tmrs %0, par_el1"', self.code)
        self.assertEqual(lib.POLICIES['retprobe']['registers'], {'currentel', 'ctr_el0', 'cntfrq_el0', 'par_el1'})
        self.says('`AT S1E2R` and `AT S1E2W`, `DC CVAC` and `DC CIVAC`, one `DSB` form and the `ISB`')

    def test_what_it_writes_reads_and_cannot_tell_is_the_sources_and_is_said_plainly(self):
        """The statements of the review: the one register it writes, the reads nothing guards, the reset that is the cold one, the point of
        coherency, the MMU's limits, and the world's comparison of every buffer the payload is given."""
        self.says('it writes no system register but `PAR_EL1`, which `AT S1E2R` and `AT S1E2W` write as their answer')
        self.says('they write `PAR_EL1`, the one system register the payload writes')
        self.says("They show that EL2's stage 1 maps the page and nothing more: not that TrustZone, an XPU or QHEE leave the physical page alone "
                  "outside UEFI's memory map")
        self.says('a store the hardware rejected would be an external abort, which only a power cycle ends')
        self.assertIn('"at s1e2w, %1\\n\\tisb\\n\\tmrs %0, par_el1"', self.code)
        self.assertNotIn('msr', ' '.join(re.findall(r'__asm__ volatile\("([^"]*)"', self.code)))
        self.says("Every other read is a plain load that nothing guards: of the runner's preload table, of the configuration file the table names, "
                  "of the runner's memory map and, after the stores, of the three pages it wrote")
        for plain in ('const struct q1n1_preload_cache *t = (const struct q1n1_preload_cache *)(uintptr_t)a->preload_table;',
                      'const volatile uint32_t *w = (const volatile uint32_t *)(uintptr_t)base;', 'pl_desc_read(a, i, &d)',
                      'const volatile uint32_t *p = (const volatile uint32_t *)(uintptr_t)pages[k];'):
            self.assertIn(plain, self.code)
        self.says('`DC CVAC` and `DC CIVAC` reach the point of coherency and no further: whether a system cache (LLCC), a buffer of the memory controller, '
                  "DRAM's self-refresh or a scrub of memory at boot keeps or loses a page is not named here")
        self.says('`SYSTEM_RESET` is the architectural cold-reset call and the warm reset is `SYSTEM_RESET2`, which the unit answered `NOT_SUPPORTED` once')
        self.says('A NONE after path `PSCI_RESET` is therefore a likely outcome, and it says nothing is wrong with the probe or the unit.')
        self.says('The host test compares every buffer the payload is given (the preload table, the memory map, the configuration file) and the rest of the '
                  'arena with what they were before, after every run, so a store anywhere else fails it.')
        world = (ROOT / 'tools' / 'test-q1n1-sp11-payload-retprobe-world.h').read_text(encoding='utf-8')
        for compared in ('memcmp(table_snap, table_buf, 2 * PAGE)', 'memcmp(map_snap, map_buf, PAGE)', 'memcmp(config_snap, config_buf, PAGE)',
                         'if (!arena_outside_pages_unchanged()) {'):
            self.assertIn(compared, world)
        self.assertEqual(world.count('snapshot_buffers();'), 1, 'the snapshot is taken by the one function that runs the payload')

    def test_a_counter_that_runs_backwards_is_refused_by_the_source_and_the_document_says_so(self):
        wait = re.search(r'OUT_OF_LINE int wait_seconds\(.*?\n}\n', self.code, re.S).group(0)
        self.assertLess(wait.index('if (now < start) return 0;'), wait.index('if (now - start >= frequency * seconds) return 1;'))
        self.says('when the counter does not advance or runs backwards')
        self.says('the counter did not move or ran backwards: no reset (return 9)')

    def test_the_cache_maintenance_and_the_loads_are_in_the_order_the_document_says(self):
        clean = re.search(r'void clean_pages\(.*?\n}\n', self.code, re.S).group(0)
        verify = re.search(r'unsigned verify_pages\(.*?\n}\n', self.code, re.S).group(0)
        self.assertIn('dc_cvac(', clean)
        self.assertNotIn('dc_civac(', clean)
        self.assertIn('dc_civac(', verify)
        self.assertIn('dsb_sy();', clean)
        self.says('Every cache line is then cleaned with `DC CVAC` and a `DSB SY` follows')
        self.says('`DC CIVAC` over every line, `DSB SY`, then the CRC of each page is recomputed from memory')
        self.assertEqual(self.define('PAGES') * self.define('PAGE_WORDS'), 3072)
        self.says('(3072 loads, below the budget of 4096 per call)')
        self.assertIn('4096 loads already made in this call', read_doc('SP11-PAYLOAD.md'))
        entry = self.code[self.code.index('payload_entry(const struct q1n1_payload_args *a)\n{'):]
        self.assertLess(entry.index('read_previous('), entry.index('page_store('))
        self.assertLess(entry.index('page_store('), entry.index('clean_pages('))
        self.assertLess(entry.index('clean_pages('), entry.index('verify_pages('))
        self.assertLess(entry.index('verify_pages('), entry.index('wait_seconds('))
        self.assertLess(entry.index('wait_seconds('), entry.index('smc_system_reset()'))
        self.says('**It reads the previous boot\'s three pages first**')
        self.says('`page_store` holds the only stores to memory outside the payload\'s own stack.')

    # -- what it prints ----------------------------------------------------------------------------------------------------
    def test_every_keyword_the_payload_prints_is_in_the_lines_table_and_every_keyword_of_it_is_the_payloads(self):
        shapes = [row[0] for row in rows(block(self.text, 'retprobe-lines'))]         # the first column: the line as printed
        table_words = {word for shape in shapes for word in WORD.findall(shape)}
        literals = re.findall(r'"([^"\n]*)"', self.code)
        source_words = {w for literal in literals for w in WORD.findall(literal)}
        printed = set()
        for call in re.findall(r'(?:pl_say|pl_page_open|pl_page_add|add_text|pl_add_dec|pl_add_hex|refuse)\([^;]*', self.code):
            for literal in re.findall(r'"([^"\n]*)"', call):
                printed |= set(WORD.findall(literal))
        self.assertEqual(sorted(printed - table_words), [], 'printed and not in the lines table')
        self.assertEqual(sorted(table_words - source_words), [], 'in the lines table and not printed by the payload')
        self.assertGreaterEqual(len(shapes), 30)
        self.assertIn('Every line is `PAYLOAD RETPROBE <line>`.', self.text)
        self.assertEqual(re.search(r'#define PL_PAGE_PREFIX "([^"]*)"', self.code).group(1), 'PAYLOAD RETPROBE ')

    def test_the_refusal_reasons_are_the_sources_and_the_return_table_is_the_enum(self):
        reasons = {}
        for array in ('config_reason', 'page_reason'):
            found = re.search(rf'static const char {array}\[\d+\]\[\d+\] = \{{(.*?)\}};', self.code, re.S).group(1)
            reasons[array] = [r for r in re.findall(r'"([A-Z_0-9]+)"', found) if r != 'OK']
            for reason in reasons[array]:
                self.assertIn(f'`{reason}`', self.text, reason)
        self.assertEqual((len(reasons['config_reason']), len(reasons['page_reason'])), (9, 8))
        reason_text = self.text[self.text.index('The refusal reasons of the configuration are'):self.text.index('The page of a run on a fresh arena')]
        self.assertEqual(sorted(re.findall(r'`([A-Z_]+)`', reason_text)), sorted(reasons['config_reason'] + reasons['page_reason']))
        table = rows(block(self.text, 'retprobe-returns'))
        enum = dict(re.findall(r'RET_(\w+) = (\d+)', self.code))
        enum['BAD_ARGS'] = '1'                       # the runner's Q1N1_PAYLOAD_RET_BAD_ARGS, not an enumerator of this file
        self.assertIn('#define Q1N1_PAYLOAD_RET_BAD_ARGS UINT64_C(1)', (ROOT / 'platform' / 'uefi' / 'sp11-payload-abi.h').read_text(encoding='utf-8'))
        self.assertEqual(sorted(int(r[0]) for r in table), list(range(12)))
        self.assertEqual({r[1]: r[0] for r in table}, enum)

    def test_the_example_pages_are_what_the_host_program_prints(self):
        none = [masked(line) for line in fenced(block(self.text, 'retprobe-page-none'))]
        self.assertEqual(none, [masked(line) for line in self.program('page-report', '0').splitlines()])
        reset = [masked(line) for line in fenced(block(self.text, 'retprobe-page-reset'))]
        model = [masked(line) for line in self.program('page-report', '1').splitlines()]
        self.assertEqual([none[0].replace('PATH=NONE', 'PATH=PSCI_RESET')] + none[1:-2] + reset, model)
        returned = re.search(r'`(PAYLOAD RETPROBE RESET RETURNED=[^`]+)`', self.text).group(1)
        self.assertEqual(model + [masked(returned)], [masked(line) for line in self.program('page-report', '1', 'returns').splitlines()])
        refusal = re.search(r'with\s+`(PAYLOAD RETPROBE REFUSED RESET_NOT_IMPLEMENTED SYSTEM_RESET2)`', self.text).group(1)
        refused = [masked(line) for line in self.program('page-report', '2').splitlines()]
        self.assertEqual(refused, [none[0].replace('PATH=NONE', 'PATH=PSCI_RESET2')] + none[1:8] + [refusal])
        self.says('With path 2 and the unit\'s answer the page ends after the three `PAGE` lines')
        self.says('With path 1 the last four lines become the following.')

    def test_the_numbers_are_the_sources(self):
        self.assertEqual(self.program('lines-report').strip(), f'LINES_MAX={driver.LINES_MAX}')
        self.says(f'never prints more than {driver.LINES_MAX} lines of its own (a test measures it over random worlds: `LINES_MAX={driver.LINES_MAX}`)')
        self.says("inside its budget of 40 and the runner's page of at least 60 lines")
        self.assertIn('#define PL_PAGE_LINES 40u', self.code)
        self.assertEqual((self.define('COUNTDOWN_MAX_S'), self.define('PAGES')), (60, 3))
        self.says('NEXT RESET AFTER <n> S')
        self.assertEqual(len(driver.SUITES), 10)
        self.assertGreaterEqual(len(driver.MUTANTS), 90)

    # -- the tests table and what the document says about QEMU, the pages and the pointer to it ---------------------------------
    def test_the_tests_table_names_files_that_exist_and_counts_what_the_driver_holds(self):
        table = rows(block(self.text, 'retprobe-tests'))
        self.assertEqual(len(table), 3)
        for command, _ in table:
            name = re.search(r'tools/(\S+\.py)', command).group(1)
            self.assertTrue((ROOT / 'tools' / name).exists(), name)
        self.assertIn('ten native suites under ASan and UBSan', table[0][1])
        self.assertIn('five boots', table[1][1])
        self.assertIn(f'{len(DOC_MUTANTS)} seeded mistakes in a copy of the document', table[2][1])
        qemu = (ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu-retprobe.py').read_text(encoding='utf-8')
        self.assertIn('in four of the five boots', qemu)
        self.says(f'The {len(driver.MUTANTS)} seeded bugs include')
        names = {m[0] for m in driver.MUTANTS}
        for named in ('resets-without-the-feature-check', 'resets2-without-the-feature-check', 'gates-system-reset-on-the-other-answer', 'does-not-wait',
                      'no-fence-after-the-clean', 'does-not-verify', 'reads-after-writing', 'says-whole-without-the-crc', 'stores-one-word-past-the-page',
                      'writes-without-a-config', 'finds-the-config-by-half-its-magic', 'vote-takes-the-rarest-epoch'):
            self.assertIn(f'retprobe-{named}', names)
        self.says("QEMU's RAM, its cache and its PSCI are not the unit's")
        self.says('where RAM survives a reset by construction')

    def test_the_sample_configuration_is_the_stick_tests_and_the_pages_are_the_designs(self):
        self.says('A sample (the stick test\'s; it authorises nothing): path 1, countdown 8 and the pages `0x9C000000`, `0xF8400000` and `0xFFFF00000`')
        text = (ROOT / 'tools' / 'test-q1n1-sp11-payload-retprobe.py').read_text(encoding='utf-8')
        self.assertIn('config_bytes(1, 8, (0x9C000000, 0xF8400000, 0xFFFF00000))', text)
        self.says('the six memory maps of the unit\'s runs')
        self.says('every page must be conventional there, or the whole of PHASE 2 is refused')

    def test_the_runner_document_points_here(self):
        runner = read_doc('SP11-PAYLOAD.md')
        row = [line for line in runner.splitlines() if 'test-q1n1-sp11-payload-retprobe.py' in line]
        self.assertEqual(len(row), 1)
        self.assertIn('(SP11-PAYLOAD-RETPROBE.md#tests)', row[0])
        self.assertIn('## Tests', self.text)
        self.assertEqual(lib.link_problems({'SP11-PAYLOAD.md': runner, DOC.name: self.text}, ROOT / 'docs'), [])


# ---- seeded mistakes in the document --------------------------------------------------------------------------------------------

def _pattern(old):
    """`old` with every run of white space in it matching any run of white space: the document's paragraphs are wrapped."""
    return re.compile(r'\s+'.join(re.escape(part) for part in old.split()))


def _replace(old, new, count=1):
    pattern = _pattern(old)

    def mutate(doc):
        assert pattern.search(doc), old
        return pattern.sub(lambda found: new, doc, count)
    return mutate


def _in(block_name, old, new):
    """A change inside one marked block only."""
    pattern = _pattern(old)

    def mutate(doc):
        start, end = doc.index(f'<!-- {block_name} -->'), doc.index(f'<!-- /{block_name} -->')
        assert pattern.search(doc[start:end]), old
        return doc[:start] + pattern.sub(lambda found: new, doc[start:end], 1) + doc[end:]
    return mutate


def _the_doc_mutant_count_is_wrong(doc):
    count = len(DOC_MUTANTS)
    return _in('retprobe-tests', f'{count} seeded mistakes', f'{count - 1} seeded mistakes')(doc)


DOC_MUTANTS = [
    ('the-licence-line-goes', lambda doc: doc.split('\n', 1)[1]),
    ('hardware-not-run-is-dropped', _replace('**EXPERIMENTAL; hardware NOT RUN.** No value of this payload is OBSERVED on the unit.', '**EXPERIMENTAL.** No value of this payload is OBSERVED on the unit.')),
    ('a-run-is-authorised', _replace('No run is authorised by this document', 'A run is authorised by this document')),
    ('the-authorisation-is-not-for-one-boot', _replace('by name and SHA-256, for one boot, in writing', 'by name and SHA-256, for every boot, in writing')),
    ('the-stick-is-shared', _replace('and its configuration **alone**: no other payload shares the boot', 'and its configuration: another payload may share the boot')),
    ('the-stop-rule-allows-a-second-call', _replace('the payload\nmakes no second call, and neither does the operator by another path in the same boot', 'the payload\nmakes a second call')),
    ('a-refusal-is-said-to-have-stored', _replace('A `REFUSED` line means nothing was stored and nothing was reset.', 'A `REFUSED` line means the pages were stored.')),
    ('a-failed-verify-is-said-to-reset', _replace('A `VERIFY FAILED` line means no reset was called.', 'A `VERIFY FAILED` line means the reset was called.')),
    ('the-unit-answer-is-called-verified', _in('retprobe-evidence', 'OBSERVED once (boot 5, payload `psci`)', 'VERIFIED once (boot 5, payload `psci`)')),
    ('retention-is-called-observed', _in('retprobe-evidence', '| DRAM keeps its bytes across that reset | UNKNOWN |', '| DRAM keeps its bytes across that reset | OBSERVED |')),
    ('the-coherency-point-is-called-inferred', _in('retprobe-evidence', 'DRAM and not a system cache in front of it | UNKNOWN |', 'DRAM and not a system cache in front of it | INFERRED |')),
    ('the-reset-answer-is-wrong', _in('retprobe-evidence', 'answers `NOT_SUPPORTED(-1)` on the unit', 'answers 0 on the unit')),
    ('the-magic-is-wrong', _in('retprobe-page', '`RETCAN01`', '`RETCAN02`')),
    ('the-version-is-wrong', _in('retprobe-page', '| 2 | layout version | 1 |', '| 2 | layout version | 2 |')),
    ('the-index-range-is-wrong', _in('retprobe-page', '| 3 | page index | 0 to 2 |', '| 3 | page index | 0 to 3 |')),
    ('the-counter-limit-is-wrong', _in('retprobe-page', '1 to `0xFFFFF`', '1 to `0xFFFF`')),
    ('the-timestamp-is-the-virtual-counter', _in('retprobe-page', '`CNTPCT_EL0` when written', '`CNTVCT_EL0` when written')),
    ('the-crc-word-moves', _in('retprobe-page', '| 31 | CRC-32 |', '| 30 | CRC-32 |')),
    ('the-body-formula-is-wrong', _in('retprobe-page', 'page index << 10', 'page index << 11')),
    ('the-body-size-is-wrong', _replace('a 128-byte header of 32 words and 992 body words', 'a 128-byte header of 32 words and 1000 body words')),
    ('a-header-row-is-forgotten', _in('retprobe-page', '| 15 | descriptor type | 7, the type of the memory-map descriptor that holds the page |\n', '')),
    ('the-previous-states-are-in-the-wrong-word', _in('retprobe-page', 'previous state of page 2 (0 NONE', 'previous state of page 3 (0 NONE')),
    ('the-partial-threshold-is-wrong', _replace('at least 16 words of exactly that epoch', 'at least 17 words of exactly that epoch')),
    ('the-tie-goes-to-the-largest', _replace('ties going to the smallest epoch', 'ties going to the largest epoch')),
    ('the-countdown-range-is-wrong', _in('retprobe-config', '| 4 | countdown in seconds | 1 to 60 |', '| 4 | countdown in seconds | 1 to 30 |')),
    ('the-config-magic-is-wrong', _in('retprobe-config', '`RETCFG01`', '`RETCFG02`')),
    ('the-page-count-is-wrong', _in('retprobe-config', '| 5 | page count | 3 |', '| 5 | page count | 4 |')),
    ('the-reserved-words-are-wrong', _in('retprobe-config', '| 12-14 | reserved | zero |\n| 15 |', '| 12-13 | reserved | zero |\n| 14 | spare | zero |\n| 15 |')),
    ('the-config-size-is-wrong', _replace('one data file of exactly 64 bytes', 'one data file of exactly 48 bytes')),
    ('a-path-is-renumbered', _in('retprobe-paths', '| `PSCI_RESET2` | 2 |', '| `PSCI_RESET2` | 3 |')),
    ('the-reset-id-is-wrong', _in('retprobe-paths', '`SYSTEM_RESET` (`0x84000009`)', '`SYSTEM_RESET` (`0x84000008`)')),
    ('the-reset2-id-is-wrong', _in('retprobe-calls', '| `smc_system_reset2` | `0xC4000012` |', '| `smc_system_reset2` | `0x84000012` |')),
    ('the-features-id-is-wrong', _in('retprobe-calls', '`0x8400000A`', '`0x8400000B`')),
    ('the-reset-type-is-wrong', _in('retprobe-paths', 'reset type 0 (the architectural warm reset)', 'reset type 1 (the architectural warm reset)')),
    ('the-gate-returns-another-code', _in('retprobe-paths', '`PSCI_FEATURES(SYSTEM_RESET2)` is not negative as a 32-bit result, else return 7', '`PSCI_FEATURES(SYSTEM_RESET2)` is not negative as a 32-bit result, else return 8')),
    ('the-negative-control-is-not-the-default', _in('retprobe-paths', 'the default and the negative control', 'the exception')),
    ('the-unit-is-said-to-accept-reset2', _in('retprobe-paths', 'answered `NOT_SUPPORTED(-1)` once (OBSERVED): the payload refuses', 'answered 0 once (OBSERVED): the payload calls it')),
    ('the-clean-is-an-invalidate', _replace('Every cache line is then cleaned with `DC CVAC` and a `DSB SY` follows', 'Every cache line is then cleaned with `DC CIVAC` and a `DSB SY` follows')),
    ('the-load-count-is-wrong', _replace('(3072 loads, below the budget of 4096 per call)', '(2048 loads, below the budget of 4096 per call)')),
    ('a-line-is-forgotten', _in('retprobe-lines', '| `REFUSED COUNTER_NOT_ADVANCING` | the counter did not move or ran backwards: no reset (return 9) |\n', '')),
    ('a-line-is-invented', _in('retprobe-lines', '| `NEXT FEATURES` |', '| `DONE INDEX=0` | the end |\n| `NEXT FEATURES` |')),
    ('a-reason-is-forgotten', _replace('`NOT_WRITE_BACK`, `NOT_IDENTITY` and', '`NOT_WRITE_BACK` and')),
    ('a-return-value-is-renumbered', _in('retprobe-returns', '| 7 | NOT_IMPLEMENTED |', '| 8 | NOT_IMPLEMENTED |')),
    ('a-return-value-is-forgotten', _in('retprobe-returns', '| 10 | OVERFLOW | the boot counter would overflow |\n', '')),
    ('the-lines-maximum-is-wrong', _replace('`LINES_MAX=21`', '`LINES_MAX=22`')),
    ('the-first-page-changes', _in('retprobe-page-none', 'COUNTER THIS=1 PREVIOUS=0', 'COUNTER THIS=2 PREVIOUS=0')),
    ('a-page-line-is-forgotten', _in('retprobe-page-none', 'PAYLOAD RETPROBE VERIFY OK\n', '')),
    ('the-countdown-of-the-reset-page-is-wrong', _in('retprobe-page-reset', 'NEXT RESET AFTER 8 S', 'NEXT RESET AFTER 5 S')),
    ('the-refusal-line-is-wrong', _replace('`PAYLOAD RETPROBE REFUSED RESET_NOT_IMPLEMENTED SYSTEM_RESET2`', '`PAYLOAD RETPROBE REFUSED RESET_NOT_IMPLEMENTED SYSTEM_RESET`')),
    ('the-returned-line-is-wrong', _replace('RESET RETURNED=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)', 'RESET RETURNED=0X0:IMPLEMENTED')),
    ('the-mutant-count-is-wrong', _replace('The 115 seeded bugs include', 'The 114 seeded bugs include')),
    ('the-at-is-said-to-write-no-register', _replace('they write `PAR_EL1`, the one system register the payload writes', 'they write no register at all')),
    ('the-mmu-is-said-to-prove-the-page-is-free', _replace("They show that EL2's stage 1 maps the page and nothing more", 'They show that the page is free')),
    ('the-reads-are-said-to-be-guarded', _replace('Every other read is a plain load that nothing guards', 'Every other read is a guarded load')),
    ('the-clean-is-said-to-reach-dram', _replace('reach the point of coherency and no further', 'reach DRAM')),
    ('the-reset-is-called-the-warm-one', _replace('`SYSTEM_RESET` is the architectural cold-reset call and the warm reset is `SYSTEM_RESET2`',
                                                 '`SYSTEM_RESET` is the architectural warm-reset call and the cold reset is `SYSTEM_RESET2`')),
    ('none-is-called-a-failure', _replace('it says nothing is wrong with the probe or the unit', 'it says the probe is wrong')),
    ('the-stray-store-check-is-dropped', _replace('so a store anywhere else fails it', 'so a store anywhere else is tolerated')),
    ('the-power-button-is-the-answer-to-a-lost-restart', _replace('is left alone and the run is reported', 'is switched off with the power button, and the run is reported')),
    ('a-backwards-counter-is-not-mentioned', _replace('when the counter does not advance or runs backwards', 'when the counter does not advance')),
    ('the-suite-count-is-wrong', _in('retprobe-tests', 'ten native suites', 'eleven native suites')),
    ('the-qemu-boot-count-is-wrong', _in('retprobe-tests', 'five boots (no configuration', 'six boots (no configuration')),
    ('the-doc-mutant-count-is-wrong', _the_doc_mutant_count_is_wrong),
    ('a-tests-file-is-misnamed', _in('retprobe-tests', 'test-q1n1-sp11-payload-qemu-retprobe.py', 'test-q1n1-sp11-payload-qemu-retprob.py')),
    ('the-sample-page-is-wrong', _replace('`0x9C000000`, `0xF8400000` and `0xFFFF00000`', '`0x9C000001`, `0xF8400000` and `0xFFFF00000`')),
    ('qemu-is-said-to-show-retention', _replace("QEMU's RAM, its cache and its PSCI are not the unit's", "QEMU's RAM, its cache and its PSCI are the unit's")),
    ('a-link-is-broken', _replace('(SP11-PAYLOAD-PSCI.md)', '(SP11-PAYLOAD-PSCIX.md)')),
    ('an-anchor-is-broken', _replace('SP11-PAYLOAD-RESULTS.md#the-restart-probe', 'SP11-PAYLOAD-RESULTS.md#the-restart-probes')),
    ('a-machine-identifier-appears', _replace('# SP11 payload `retprobe`', '# SP11 payload `retprobe` at /Us' + 'ers/x')),
    ('the-document-is-too-big', lambda doc: doc + '\n' + 'x' * 52000),
]


class RetprobeDocMutants(unittest.TestCase):
    """The agreement tests above must be able to fail: each seeded mistake in the document is refused by one."""

    @staticmethod
    def outcome(text):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(type('Changed', (RetprobeDocAgreement,), {'TEXT': text}))
        result = unittest.TestResult()
        suite.run(result)
        return result

    def test_the_unchanged_document_passes_through_the_same_mechanism(self):
        result = self.outcome(DOC.read_text(encoding='utf-8'))
        self.assertTrue(result.wasSuccessful(), [str(f[1])[-500:] for f in result.failures + result.errors])
        self.assertGreaterEqual(result.testsRun, 14)
        self.assertEqual(result.skipped, [], 'a skipped agreement test proves nothing')

    def test_every_seeded_mistake_in_the_document_is_refused(self):
        original = DOC.read_text(encoding='utf-8')
        self.assertGreaterEqual(len(DOC_MUTANTS), 40)
        self.assertEqual(len({name for name, _ in DOC_MUTANTS}), len(DOC_MUTANTS))
        for name, mutate in DOC_MUTANTS:
            with self.subTest(mutant=name):
                changed = mutate(original)
                self.assertNotEqual(changed, original)
                self.assertFalse(self.outcome(changed).wasSuccessful(), 'every agreement test still passed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
