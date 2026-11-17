#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""docs/SP11-PAYLOAD-XHCI.md against the payload's sources: the register table, the numbers (budgets, waits, arena addresses and offsets), the
vocabulary of the page (verdicts, reasons, stages, arena reasons, refusals), the line templates, the parts and the tests it names. Host only; reads
files, writes nothing.

    python3 tools/test-q1n1-sp11-payload-xhci-doc.py

Every check is a function of the text with a faulty text it must refuse. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
import importlib.util
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-XHCI.md'
PAYLOADS = ROOT / 'payloads'
PARTS = ('xhci', 'xhci-io', 'xhci-text', 'xhci-map', 'xhci-ctl', 'xhci-smmu', 'xhci-watch')
MACHINE_IDS = re.compile('|'.join(['/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/']) + r'|\bsae' + r'ed\b|host' + r'name|\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', re.I)
# (the template in the source, how the document writes it)
TEMPLATES = (
    ('NEXT ARENA %d %s %x PAGES %d AFTER 8 S', 'NEXT ARENA <n> <name> <address> PAGES <p> AFTER 8 S'), ('NEXT %s AFTER 8 S', '`NEXT RESET`, `NEXT PROGRAM`, `NEXT RUN`, `NEXT NOOP`'),
    ('WATCH 30 S: CONNECT THE MAC USB-C CABLE TO THE FREE PORT NOW', 'WATCH 30 S: CONNECT THE MAC USB-C CABLE TO THE FREE PORT NOW'),
    ('WATCH 20 S LEFT', 'WATCH 20 S LEFT'), ('WATCH 10 S LEFT', 'WATCH 10 S LEFT'), ('CHG T=%d.%d %s%d FROM %x TO %P', 'CHG T=<s> <port> FROM .. TO ..'),
    ('VERDICT NOOP_OK ARENA=%d', 'VERDICT NOOP_OK ARENA=<n>'), ('VERDICT %s STAGE=%s WHY=%s', 'VERDICT <verdict> STAGE=.. [WHY=..]'),
    ('VERDICT REFUSED=%s %s=%x', 'VERDICT REFUSED=<name> [<key>=<value>]'), ('END HALTED=%s WRITES=%d LOADS=%d%s%s', 'END HALTED=.. WRITES=.. LOADS=..'),
    ('SMMU STREAM=%x SMR=%d %s CB=%d NCB=%x', 'SMMU STREAM=.. SMR=<n>'), (' R%d', 'SMMU1 R<k>'), ('R%d ARENA=%d %s STAGE=%s', 'R<k> ARENA=<n> <verdict> STAGE=<stage>'),
    ('%s ID=%x CAPL=%x VER=%x HCS1=%x HCS2=%x HCC1=%x', 'U<c> ID=.. CAPL=.. VER=.. HCS1=.. HCS2=.. HCC1=..'),
    ('%s SCRATCH=%d PAGESZ=%x AC64=%d CSZ=%d DBOFF=%x RTSOFF=%x', 'U<c> SCRATCH=<n> PAGESZ=.. AC64=.. CSZ=.. DBOFF=.. RTSOFF=..'),
    ('%s CMD=%x STS=%S CRCR=%x DCBAAP=%x CFG=%x', 'U<c> CMD=.. STS=<raw:names> CRCR=.. DCBAAP=.. CFG=..'))
TEST_CLASSES = ('XhciSource', 'XhciBinary', 'XhciNative', 'XhciMutants', 'XhciStick', 'XhciDefaults')
COMPILED_CLASSES = ('XhciProvenance', 'XhciDepth')      # of tools/test-q1n1-sp11-payload-xhci-compiled.py
SNAPINTOSH_FILES = ('sp11_xhci_s1_record.py',)      # named by the document, in the Snapintosh tree


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def flat(text):
    return ' '.join(text.split())


def tables(text):
    """[(header cells, [row cells])] of every pipe table; an escaped pipe inside a cell stays in it."""
    found, block = [], []
    for line in text.splitlines() + ['']:
        if line.startswith('|'):
            block.append(line)
            continue
        if len(block) >= 3 and set(block[1].replace('|', '').replace(' ', '')) <= {'-', ':'}:
            cells = lambda s: [c.strip() for c in re.split(r'(?<!\\)\|', s.strip().strip('|'))]  # noqa: E731
            found.append((cells(block[0]), [cells(row) for row in block[2:]]))
        block = []
    return found


def register_problems(text, header_table):
    """The document's register table against the header's [(name, window, offset, groups)]."""
    windows, bits = {'op': 0, 'ir0': 1, 'db': 2}, {'RESET': 2, 'PROGRAM': 4, 'RUN': 8, 'NOOP': 16}
    for header, rows in tables(text):
        if header == ['Register', 'Block', 'Offset', 'Group']:
            break
    else:
        return ['no register table']
    doc = []
    for names, block, offsets, groups in rows:
        names, offsets = [n.strip() for n in names.split(',')], [o.strip() for o in offsets.split(',')]
        if len(names) != len(offsets):
            return [f'{names}: names and offsets differ in number']
        mask = sum(bit for word, bit in bits.items() if word in groups)
        doc += [(name, windows[block], int(offset, 16), mask) for name, offset in zip(names, offsets)]
    want = [(name, window, offset, 0 if name == 'USBCMD' else groups) for name, window, offset, groups in header_table]
    doc = [(n, w, o, 0 if n == 'USBCMD' else m) for n, w, o, m in doc]
    return [] if sorted(doc) == sorted(want) else [f'the register table differs: {sorted(set(doc) ^ set(want))}']


def header_constants(own, header, abi):
    """Every enum value and every #define of a number (or UINT64_C of one, or a product of them) in the payload's header and the runner's ABI header."""
    constants = dict(own.eval_constants(header))
    for text in (header, abi):
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
        for name, expression in re.findall(r'^#define (\w+) (\(?[0-9xXa-fA-FuU* ()]+\)?|UINT64_C\(0x[0-9A-Fa-f]+\))\s*$', text, re.M):
            expression = re.sub(r'(?<=[0-9a-fA-F])u\b', '', re.sub(r'UINT64_C\((.*?)\)', r'\1', expression))
            constants[name] = eval(expression, {}, {})
    return constants


def number_problems(text, c):
    """Numbers of the document that are the header's, by the constants it defines."""
    body = flat(text)
    stack_pages = (c['Q1N1_PAYLOAD_STACK_BYTES'] - 4096 - c['STACK_KEPT']) // 4096
    checks = {
        '40 lines of 100 characters': c['XHCI_S1_LINE_CAP'] == 40 and c['Q1N1_PAYLOAD_LINES_MAX'] == 40, '3800 of the 4096 loads': c['XHCI_S1_LOAD_CAP'] == 3800 and c['Q1N1_PAYLOAD_LOADS_MAX'] == 4096,
        'AFTER 8 S': c['WAIT_BEFORE_WRITE_S'] == 8, '30 s': c['WATCH_S'] == 30, 'every 250 ms': c['WATCH_STEP_MS'] == 250,
        'halt 50 ms': c['T_HALT_US'] == 50000, 'HCRST clear 1 s': c['T_RESET_US'] == 1000000, 'CNR clear 1 s': c['T_CNR_US'] == 1000000,
        'HCH clear 50 ms': c['T_RUN_US'] == 50000, 'polled every 1 ms for the first 100 ms, every 10 ms after':
        c['POLL_US'] == 1000 and c['POLL_FAST_WINDOW_US'] == 100000 and c['POLL_SLOW_US'] == 10000,
        'attempt keeps six lines': c['ATTEMPT_LINES_MIN'] == 6, 'the closing two': c['CLOSING_LINES'] == 2, 'at or above `0xc100`': c['STORE_LIMIT'] == 0xc100,
        'Completion Event 200 ms': c['T_EVENT_US'] == 200000, '`0xCF412000`, four pages': c['ARENA1_BASE'] == 0xCF412000 and c['ARENA1_PAGES'] == 4,
        '`0x880000000`': c['ARENA4_BASE'] == 0x880000000, 'at most 9 pages': stack_pages == 9, 'the last 24 KiB': c['STACK_KEPT'] == 24 * 1024,
        'DCBAA at `0x000` (up to 71 slots fit': c['OFF_DCBAA'] == 0 and c['SLOTS_FIT'] == 71, 'the scratchpad array at `0x240`': c['OFF_SPARR'] == 0x240,
        'the command ring of 16 TRBs closed by a Link TRB at `0x400`': c['CMD_TRBS'] == 16 and c['OFF_CMD'] == 0x400, 'the one-entry segment table at `0x500`': c['OFF_ERST'] == 0x500,
        'the event ring of 64 TRBs at `0x600`': c['EVENT_TRBS'] == 64 and c['OFF_EVENT'] == 0x600, 'at most four': c['ARENAS'] == 4,
        'more scratchpads than 32': c['SCRATCH_MAX'] == 32, '`0x0a600000`': c['XHCI_S1_U0_BASE'] == 0x0a600000, '`0x0a800000`': c['XHCI_S1_U1_BASE'] == 0x0a800000,
        '`0x33313130`': c['XHCI_S1_DWC3_ID'] == 0x33313130, 'CAPLENGTH `0x20`': c['XHCI_S1_CAPLENGTH'] == 0x20, 'HCIVERSION `0x110`': c['XHCI_S1_HCIVERSION'] == 0x110}
    problems = [f'{phrase!r} is not in the document' for phrase in checks if phrase not in body]
    return problems + [f'{phrase!r} is not what the header says' for phrase, holds in checks.items() if phrase in body and not holds]


def vocabulary_problems(text, verdicts, stages, reasons, arena, refusals):
    body = flat(text)
    problems = []
    for kind, names in (('verdict', verdicts), ('stage', stages), ('reason', reasons), ('arena reason', arena), ('refusal', refusals)):
        problems += [f'{kind} {name} is not in the document' for name in names if not re.search(rf'(?<![A-Z_]){re.escape(name)}(?![A-Z_])', body)]
    return problems


def template_problems(text, source):
    problems = []
    body = flat(text)
    for in_source, in_doc in TEMPLATES:
        if in_source not in source:
            problems.append(f'the source no longer has {in_source!r}')
        if in_doc not in body:
            problems.append(f'the document no longer has {in_doc!r}')
    return problems


def parts_problems(text, makefile):
    listed = re.search(r'^XHCI_S1_PARTS := (.*)$', makefile, re.M)
    if not listed or tuple(listed.group(1).split()) != PARTS:
        return ['the Makefile\'s XHCI_S1_PARTS is not the parts the document lists']
    body = flat(text)
    problems = [f'part {part} is not in the document' for part in PARTS if f'`{part}.c`' not in body and f'`{part}`' not in body]
    return problems + [f'{part}.c does not exist' for part in PARTS if not (PAYLOADS / f'{part}.c').is_file()]


def tests_problems(text, tools_dir, classes_source):
    body = flat(text)
    problems = [f'class {name} is not in the document' for name in TEST_CLASSES if f'`{name}`' not in body]
    problems += [f'class {name} is not in the test module' for name in TEST_CLASSES if f'class {name}(' not in classes_source]
    for path in re.findall(r'tools/([A-Za-z0-9_.{},-]+\.(?:py|c))', text):
        if '{' in path or path in SNAPINTOSH_FILES:
            continue
        if not (tools_dir / path).is_file():
            problems.append(f'tools/{path} does not exist')
    return problems


def compiled_problems(text, compiled_source):
    """The classes of the audit of the compiled code, in the document and in their module."""
    body = flat(text)
    problems = [f'class {name} is not in the document' for name in COMPILED_CLASSES if f'`{name}`' not in body]
    return problems + [f'class {name} is not in the compiled-code test' for name in COMPILED_CLASSES if f'class {name}(' not in compiled_source]


def hygiene_problems(text):
    problems = []
    if not text.isascii():
        problems.append('not ASCII')
    if len(text.encode()) >= 50 * 1024 or len(text.splitlines()) >= 1500:
        problems.append('over the size limits')
    if 'SPDX-License-Identifier: MIT' not in text[:200]:
        problems.append('no SPDX line')
    if MACHINE_IDS.search(text):
        problems.append('machine-identifying text')
    return problems


# What the delta review of 2026-11-17 (N1, N2, N4, N5) had corrected, in the document's words; each phrase has a faulty text without it.
ROUND3_PHRASES = (
    'So only optional lines give way, never the first line of an `R<k>` result, the VERDICT or the END line',
    'So `NOOP_OK` may be followed by an END line with `LINES_CUT` on `XHCI0.BIN`',
    'whose `R<k>` lines (`SMMU=CHANGED`) are still there, and the result is whole', 'The `edges` suite of the native test pins all of it',
    'is the `VERDICT REFUSED=...` line alone, with no `U<c>` line', 'an RTSOFF of `0xc0e0` puts ERSTSZ at `0xc108`: `VALUE=0XC108`',
    'a pointer that is not rooted in the payload\'s own stack, context or line buffers', 'It proves the base of a store and not its offset',
    'The offsets are checked on the paths the host tests run', 'AddressSanitizer and UBSan run with every case', 'a digit buffer that is too small passes it',
    'At the RUN or NOOP stage a silence (`EVENT`), a Host System Error or Host Controller Error (`HSE`, `HCE`), or a controller that does not start (`HCH`)',
    'A failure at the RESET or PROGRAM stage ends the run, an `HSE` or `HCE` that the reset itself ends with included',
    'At the RESET and PROGRAM stages every failure ends the run', 'Completion Event 200 ms, polled every 1 ms throughout',
    'compares the tree with a copy of itself without `payloads/xhci*`', 'the full tree having exactly the two extra binaries',
    'default build plans no file of this payload', 'so it holds at every commit', '`make clean` removes the objects of the directories `xhci0` and `xhci1`',
    # round 4b (the review's rows R2, R3, R6 and R7)
    'A result of 100 characters or more takes a second line (it starts with `R<k>`), which no budget reserves',
    'an attempt that starts with 32 lines on the page, the most with which one starts, loses it', 'a bad completion in the last attempt of `XHCI0.BIN`',
    'whose results are one line each and whose global fault status is 0 before and after every attempt',
    'whatever the number of port changes in the watch (it prints at most four `CHG` lines)',
    'The model overwrites FAR at every fault, so it assumes that every failed attempt changes the SMMU\'s fault registers and the DWC3\'s bus-error address and valid bit',
    'the SMMU records only the first fault of a context bank until its FSR is cleared, which A1 never does',
    'so `SMMU=SAME` does not prove that an attempt did not fault', 'an `SMMU1` FAR or FSYNR0 may belong to an earlier fault',
    'With a global fault status that is not 0 already at the pre-flight (not observed)',
    # round 5 (N-B): what `SMMU=CHANGED` and `SMMU=SAME` compare
    'and says for each what the SMMU\'s fault registers and the DWC3\'s bus-error address and valid bit did',
    'with or without a change of the SMMU\'s fault registers and the DWC3\'s bus-error address and valid bit, goes on to the next arena',
    'when all four arenas are refused with a change of the SMMU\'s fault registers and the DWC3\'s bus-error address and valid bit',
    'when the SMMU\'s fault registers or the DWC3\'s bus-error address or valid bit changed since the end of the one before',
    'SMMU compares the SMMU\'s fault registers and the DWC3\'s bus-error address and valid bit with those at the end of the attempt before')
# Wording that the last review withdrew or corrected: it must not come back (N-A: the claim that the stick may be on neither controller; N-B; N-C).
WITHDRAWN_PHRASES = ('a change of the SMMU\'s registers', 'changes the SMMU\'s registers', 'may be on neither', 'left by firmware')
BUDGET_TABLE = re.compile(r'printed_four_arenas\[6\] = \{([^}]*)\};')
BUDGET_RULE = re.compile(r'b\.cut == \(!T && success > 1 && changes \+ success >= (\d+)\)')


def round3_problems(text):
    body = flat(text)
    return ([f'the document lacks {phrase!r}' for phrase in ROUND3_PHRASES if phrase not in body] +
            [f'the document has the withdrawn {phrase!r}' for phrase in WITHDRAWN_PHRASES if phrase in body])


def budget_problems(text, cases):
    """The numbers of 'The page' against the table and the rule of the `edges` suite (`cases`: tools/test-q1n1-sp11-payload-xhci-cases.c): how many of the
    four SMMU1 reports of the four-arena controller are on the page after 0, 1, 2 and 3 or more CHG lines, and from how many CHG lines on a success at arena
    4, 3 and 2 says LINES_CUT."""
    body = flat(text).replace('`', '')
    problems = []
    table = BUDGET_TABLE.search(cases)
    printed = [int(n) for n in table.group(1).split(',')] if table else []
    if printed != [3, 2, 1, 0, 0, 0]:
        problems.append(f'the model prints {printed} of the four reports after 0, 1, 2, 3, 4 and 8 changes')
    elif '3, 2, 1 or 0 of the four after 0, 1, 2 or 3 or more CHG lines' not in body:
        problems.append('the document does not give the reports that fit')
    rule = BUDGET_RULE.search(cases)
    if not rule:
        return problems + ['the model has no rule for the success that says LINES_CUT']
    words = {1: 'one', 2: 'two', 3: 'three'}
    limit = int(rule.group(1))
    wanted = ('at arena 4 from %s CHG line on, at arena 3 from %s, at arena 2 from %s, never at arena 1' %
              tuple(words.get(limit - arena, str(limit - arena)) for arena in (4, 3, 2)))
    if wanted not in body:
        problems.append(f'the document does not say {wanted!r}')
    return problems


def link_problems(text, base):
    def slug(heading):
        return re.sub(r'\s', '-', re.sub(r'[^\w\- ]', '', heading.strip().lower().replace('`', '')))
    problems = []
    for target, anchor in re.findall(r'\]\(([^)#:]+\.md)(?:#([^)]*))?\)', text):
        path = base / target
        if not path.is_file():
            problems.append(f'{target} does not exist')
        elif anchor and anchor not in {slug(h) for h in re.findall(r'^#{1,6} (.*)$', path.read_text(), re.M)}:
            problems.append(f'{target}#{anchor}')
    return problems


class XhciDocAgreement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOC.read_text(encoding='utf-8')
        cls.header = (PAYLOADS / 'xhci-regs.h').read_text(encoding='utf-8')
        cls.source = ''.join((PAYLOADS / f'{part}.c').read_text(encoding='utf-8') for part in PARTS)
        cls.own_path = ROOT / 'tools' / 'test-q1n1-sp11-payload-xhci.py'
        cls.own = load('sp11_payload_xhci_for_doc', cls.own_path)
        cls.constants = header_constants(cls.own, cls.header, (ROOT / 'platform' / 'uefi' / 'sp11-payload-abi.h').read_text(encoding='utf-8'))

    def table(self, name):
        body = re.search(rf'{name}\[[^\]]*\](?:\[[^\]]*\])? = \{{(.*?)\}};', self.header, re.S).group(1)
        return tuple(re.findall(r'"([A-Z0-9_]*)"', body))

    def names(self):
        return (tuple(n for n in self.table('verdict_name') if n != 'NONE'), tuple(n for n in self.table('stage_name') if n != 'HALT'),
                tuple(n for n in self.table('why_name') if n), tuple(n for n in self.table('arena_why') if n not in ('OK', 'N_A')))

    def test_the_register_table_is_the_headers(self):
        table = self.own.header_registers(self.header)
        self.assertEqual(register_problems(self.text, table), [])
        for label, mutated in (('an offset', self.text.replace('| CONFIG | op | 0x38 |', '| CONFIG | op | 0x3c |')), ('a group', self.text.replace('| IMAN | ir0 | 0x00 | NOOP |', '| IMAN | ir0 | 0x00 | RUN |')),
                               ('a register', self.text.replace('| DB0 | db | 0x00 | NOOP |', '')), ('an extra register', self.text.replace('| DB0 | db | 0x00 | NOOP |', '| DB0 | db | 0x00 | NOOP |\n| USBSTS | op | 0x04 | RUN |')),
                               ('a block', self.text.replace('| ERSTSZ | ir0 | 0x08 |', '| ERSTSZ | op | 0x08 |'))):
            with self.subTest(case=label):
                self.assertTrue(register_problems(mutated, table), label)

    def test_the_numbers_are_the_headers(self):
        self.assertEqual(number_problems(self.text, self.constants), [])
        for name, value in (('XHCI_S1_LINE_CAP', 30), ('XHCI_S1_LOAD_CAP', 1000), ('WAIT_BEFORE_WRITE_S', 4), ('WATCH_S', 20), ('T_EVENT_US', 1), ('ARENA1_BASE', 0xCF000000),
                            ('ARENA4_BASE', 0x800000000), ('OFF_SPARR', 0x200), ('OFF_EVENT', 0x700), ('EVENT_TRBS', 32), ('ARENAS', 3), ('Q1N1_PAYLOAD_STACK_BYTES', 1 << 20)):
            with self.subTest(constant=name):
                self.assertTrue(number_problems(self.text, dict(self.constants, **{name: value})), name)

    def test_the_vocabulary_is_the_headers_and_the_refusals_are_the_sources(self):
        verdicts, stages, reasons, arena = self.names()
        refusals = ('NO_COUNTER', 'NO_LOAD32', 'COUNTER_STUCK', 'READ_FAULT', 'NOT_XHCI', 'CAPLENGTH', 'HCIVERSION', 'DWC3_ID', 'OFFSET', 'HCE', 'HSE', 'CNR', 'RUNNING', 'PAGESIZE',
                    'SMMU_UNREADABLE', 'SCRATCHPADS', 'NO_ARENA', 'SKIPPED_NOT_AT_EL2')
        for name in refusals:
            self.assertIn(f'"{name}"', self.source, name)
        self.assertEqual(vocabulary_problems(self.text, verdicts, stages, reasons, arena, refusals), [])
        for kind, name in (('verdict', 'NOOP_BAD_COMPLETION'), ('stage', 'PROGRAM'), ('reason', 'NOT_HELD'), ('reason', 'LINES'), ('arena', 'SMALL_STACK'), ('refusal', 'SMMU_UNREADABLE')):
            with self.subTest(removed=name):
                mutated = re.sub(rf'(?<![A-Z_]){name}(?![A-Z_])', 'REMOVED', self.text)
                self.assertTrue(vocabulary_problems(mutated, verdicts, stages, reasons, arena, refusals), name)
        self.assertTrue(vocabulary_problems(self.text, verdicts + ('NOOP_NEW',), stages, reasons, arena, refusals), 'a name the payload gained and the document lacks')

    def test_the_line_templates_are_in_the_source_and_in_the_document(self):
        self.assertEqual(template_problems(self.text, self.source), [])
        for in_source, in_doc in TEMPLATES:
            with self.subTest(template=in_source):
                self.assertTrue(template_problems(self.text, self.source.replace(in_source, 'X')), 'a changed source template')
                self.assertTrue(template_problems(self.text.replace(in_doc, 'X'), self.source), 'a changed document line')

    def test_the_parts_and_the_tests_it_names_exist(self):
        makefile = (ROOT / 'platform' / 'uefi' / 'Makefile').read_text(encoding='utf-8')
        self.assertEqual(parts_problems(self.text, makefile), [])
        self.assertTrue(parts_problems(self.text, makefile.replace('xhci-watch', 'xhci-watcher')))
        self.assertTrue(parts_problems(self.text.replace('`xhci-smmu.c`', '`other`').replace('`xhci-smmu`', '`other`'), makefile))
        classes = self.own_path.read_text(encoding='utf-8')
        self.assertEqual(tests_problems(self.text, ROOT / 'tools', classes), [])
        self.assertTrue(tests_problems(self.text, ROOT / 'tools', classes.replace('class XhciBinary(', 'class XhciOther(')))
        self.assertTrue(tests_problems(self.text + '\n`tools/test-q1n1-no-such-file.py`\n', ROOT / 'tools', classes))
        self.assertTrue(tests_problems(self.text.replace('`XhciMutants`', '`X`'), ROOT / 'tools', classes))
        compiled = (ROOT / 'tools' / 'test-q1n1-sp11-payload-xhci-compiled.py').read_text(encoding='utf-8')
        self.assertEqual(compiled_problems(self.text, compiled), [])
        self.assertTrue(compiled_problems(self.text, compiled.replace('class XhciDepth(', 'class XhciOther(')))
        self.assertTrue(compiled_problems(self.text.replace('`XhciProvenance`', '`X`'), compiled))

    def test_the_text_is_ascii_small_and_names_no_machine_and_its_links_resolve(self):
        self.assertEqual(hygiene_problems(self.text), [])
        for label, mutated in (('non-ASCII', self.text + '\u00e9'), ('a path', self.text + '/Us' + 'ers/x'), ('a MAC', self.text + ' aa:bb:cc:dd:' + 'ee:ff'), ('no SPDX', self.text.replace('SPDX-License-Identifier', 'X')),
                               ('too long', self.text + '\n' * 1500)):
            with self.subTest(case=label):
                self.assertTrue(hygiene_problems(mutated))
        self.assertEqual(link_problems(self.text, DOC.parent), [])
        self.assertTrue(link_problems(self.text + '\n[x](SP11-NO-SUCH.md)\n', DOC.parent))
        self.assertTrue(link_problems(self.text + '\n[x](SP11-PAYLOAD.md#no-such-heading)\n', DOC.parent))

    def test_a_table_row_has_the_cells_of_its_header(self):
        for header, rows in tables(self.text):
            for row in rows:
                self.assertEqual(len(row), len(header), row)
        broken = self.text.replace('| ERSTSZ | ir0 | 0x08 | PROGRAM |', '| ERSTSZ | ir0 | 0x08 | PROGRAM | extra |')
        self.assertTrue(any(len(row) != len(header) for header, rows in tables(broken) for row in rows))

    def test_the_corrections_of_the_delta_review_are_in_the_document(self):
        self.assertEqual(round3_problems(self.text), [])
        for phrase in ROUND3_PHRASES:
            with self.subTest(phrase=phrase):
                self.assertTrue(round3_problems(flat(self.text).replace(phrase, 'X' * len(phrase))), phrase)
        for phrase in WITHDRAWN_PHRASES:
            with self.subTest(back=phrase):
                self.assertTrue(round3_problems(flat(self.text) + ' ' + phrase), phrase)

    def test_the_numbers_of_the_line_budget_are_the_host_models(self):
        cases = (ROOT / 'tools' / 'test-q1n1-sp11-payload-xhci-cases.c').read_text(encoding='utf-8')
        self.assertEqual(budget_problems(self.text, cases), [])
        self.assertTrue(budget_problems(self.text, cases.replace('{3, 2, 1, 0, 0, 0}', '{3, 2, 0, 0, 0, 0}')))
        self.assertTrue(budget_problems(self.text, cases.replace('>= 5)', '>= 6)')))
        self.assertTrue(budget_problems(self.text.replace('3, 2, 1 or 0 of the four', '3, 2 or 1 of the four'), cases))


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
