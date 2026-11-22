#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests of the two documents of the payload inpsnap2 (docs/SP11-PAYLOAD-INPSNAP2.md and docs/SP11-PAYLOAD-INPSNAP2-EVIDENCE.md) against the header, the host model and the seeded bugs.

    python3 tools/test-q1n1-sp11-payload-inpsnap2-doc.py

  Doc           the page and the numbers of the document are the ones the host model prints, the windows and the blocks are the header's, the outcome table has a row for every string the
                payload can print and every token a page of the model shows, the chain budget is the runner's arithmetic with the payload's own numbers, the counts of the seeded bugs
                are the module's, the links resolve, no file is oversized
  Evidence      the register table is the header's, every seeded bug is listed exactly once, the excerpts are lines of the model's pages
  DocMistakes   one wrong statement each in a copy of a document: the check that names it must refuse it, and no other

SKIPs, never passes, without clang. Evidence: EXPERIMENTAL (host model only); hardware NOT RUN."""
import functools
from collections import Counter
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_inpsnap2_mutants as mutants  # noqa: E402

DOC = ROOT / 'docs' / 'SP11-PAYLOAD-INPSNAP2.md'
EVIDENCE = ROOT / 'docs' / 'SP11-PAYLOAD-INPSNAP2-EVIDENCE.md'
SOURCE = ROOT / 'payloads' / 'inpsnap2.c'
REGS = ROOT / 'payloads' / 'inpsnap2-regs.h'
HARNESS = ROOT / 'tools' / 'test-q1n1-sp11-payload-inpsnap2.c'
BUILD = ROOT / 'build' / 'sp11-payload-inpsnap2-doc'
ROW = re.compile(r'X\((\w+), "(\w+)", (0x[0-9a-f]+), (WIN_\w+), (B_\w+), ([^,]+), (\d+)\)')
FLAGS = {'F_CBCR': 'CBCR', 'F_HWCG': 'HWCG', 'F_WRAP': 'WRAP'}
# Every string of the payload's code that can reach the page, and the row of the document's outcome table that says what it means; None is structure that is no outcome (the prefix, the
# legend, units, the helpers' digits). A string that is in neither this table nor the payload fails the test: a token cannot be added to the payload without a row saying what it means.
LITERAL_ROWS = {
    'inpsnap2-regs.h': None, 'payload-util.h': None, 'mrs %0, ': None, '=r': None, 'PAYLOAD INPSNAP2 ': None, '0123456789ABCDEF': None, ' ': None, '=': None, '/': None,
    'KEY=VALUE .ON .OFF .HW .ODD=CLOCK FAULT:6=ABORT SKIP=NOT READ K=LINE CRC16': None, 'READ ONLY EL=2 STAGE=I0 CAP=': None,
    'inpsnap2: the legend fits a line': None, 'inpsnap2: a line of four words fits': None, 'inpsnap2: a line of three clock words fits': None, 'inpsnap2: a word record is 8 bytes': None,
    'NEXT ': 'NEXT <block>', ' K=': 'K=', '.ON': '.ON', '.OFF': '.OFF', '.HW': '.HW', '.ODD': '.ODD', 'FAULT:': 'FAULT:6', 'SKIP': 'SKIP', 'BUDGET': 'BUDGET', 'NA': 'NA',
    'END LOADS=': 'END', ' FAULTS=': 'END', ' SKIPS=': 'END', ' BLK=': 'BLK', ' CUTS=': 'CUTS', ' LINES=': 'END', ' STOP=': 'STOP=<key>', 'NONE': 'STOP=<key>',
    'QUP GATED OFF': 'QUP GATED OFF', 'QUP GATED ERR': 'QUP GATED ERR', 'SKIPPED_NOT_AT_EL2': 'SKIPPED_NOT_AT_EL2', 'REFUSED_NO_LOAD32': 'REFUSED_NO_LOAD32',
}
RUN_OUTCOMES = ('no END line', 'q1n1 fault page', 'runner VERIFY refusal', 'KEY=VALUE')
# How the tokens of a page are recognised: (a regular expression over a line of the page without its prefix, the row of the outcome table).
PAGE_TOKENS = (
    (r'\.ON\b', '.ON'), (r'\.OFF\b', '.OFF'), (r'\.HW\b', '.HW'), (r'\.ODD\b', '.ODD'), (r'=FAULT:\d+', 'FAULT:6'), (r'=SKIP\b', 'SKIP'), (r'=BUDGET\b', 'BUDGET'), (r'=NA\b', 'NA'),
    (r'^QUP GATED OFF$', 'QUP GATED OFF'), (r'^QUP GATED ERR$', 'QUP GATED ERR'), (r'^NEXT (GATE|RCG|PLL|LVL|QUP)$', 'NEXT <block>'), (r' K=[0-9A-F]{4}$', 'K='),
    (r'^END LOADS=', 'END'), (r' BLK=', 'BLK'), (r'CUTS=[1-9]', 'CUTS'), (r'STOP=(?!NONE)', 'STOP=<key>'), (r'STOP=NONE', 'STOP=<key>'), (r'^SKIPPED_NOT_AT_EL2$', 'SKIPPED_NOT_AT_EL2'),
    (r'^REFUSED_NO_LOAD32$', 'REFUSED_NO_LOAD32'),
)
SCENARIOS = ('unit', 'gateoff', 'gateerr', 'hwvote', 'stop', 'fault', 'dfs', 'el1', 'noload32')
# Which payloads the chain-budget table names, and their line counts: the two the review of TSNAP v1.1 and GPUSNAP2 gave (their cap, 34), and this payload's own, from the model's numbers.
SEEN_ROWS, COMPUTED_ROWS, OTHER_PAYLOAD_LINES = 73, 89, 34


@functools.lru_cache(maxsize=None)
def model(*options):
    """The output of the host model built over the shipped source (without sanitizers) for `options`."""
    BUILD.mkdir(parents=True, exist_ok=True)
    binary = BUILD / 'harness'
    sources = (HARNESS, HARNESS.with_name('test-q1n1-sp11-payload-inpsnap2-model.h'), HARNESS.with_name('test-q1n1-sp11-payload-inpsnap2-suites.inc'), SOURCE, REGS)
    if not binary.exists() or binary.stat().st_mtime < max(path.stat().st_mtime for path in sources):
        done = lib.run(['clang', '-std=gnu11', '-O1', '-w', '-DQ1N1_PAYLOAD_HOST_TEST=1', '-Iplatform/uefi', '-Ipayloads', '-o', str(binary), str(HARNESS)])
        if done.returncode:
            raise RuntimeError('the host test did not build:\n' + done.stderr[-1500:])
    done = subprocess.run([str(binary), *options], cwd=ROOT, capture_output=True, text=True, timeout=120)
    if done.returncode:
        raise RuntimeError(f'the host test failed: {options}: {done.stderr[-500:]}')
    return done.stdout


def header_rows():
    return [(key, int(off, 16), win[4:], block[2:], flags, int(vbit)) for _, key, off, win, block, flags, vbit in ROW.findall(REGS.read_text(encoding='utf-8'))]


def header_windows():
    text = REGS.read_text(encoding='utf-8')
    found = re.search(r'windows\[WINDOWS\] = \{\{(0x[0-9a-f]+)u, GCC_BYTES, 0\}, \{(0x[0-9a-f]+)u, QUP_BYTES, 0\}\}', text)
    sizes = {name: int(value, 16) for name, value in re.findall(r'#define (GCC|QUP)_BYTES (0x[0-9a-f]+)u', text)}
    return {'GCC': (int(found.group(1), 16), sizes['GCC']), 'QUP': (int(found.group(2), 16), sizes['QUP'])}


def block_of(text, name):
    found = re.search(rf'<!-- {re.escape(name)} -->\n(.*?)<!-- /{re.escape(name)} -->', text, re.S)
    return found.group(1) if found else None


def fenced(text, name):
    body = block_of(text, name)
    found = re.search(r'```\n(.*?)```', body or '', re.S)
    return found.group(1) if found else None


def table_rows(text, header):
    """[[cells]] of the data rows of the Markdown table whose header row starts with `header`."""
    rows, inside = [], False
    for line in text.splitlines():
        if line.startswith(header):
            inside = True
            continue
        if inside and not line.startswith('|'):
            break
        if inside and not set(line) <= set('|- '):
            rows.append([cell.strip() for cell in line.strip().strip('|').split('|')])
    return rows


def source_literals():
    """The string literals of the payload's code (comments left out)."""
    code = re.sub(r'/\*.*?\*/', '', SOURCE.read_text(encoding='utf-8'), flags=re.S)
    return set(re.findall(r'"((?:[^"\\\n]|\\.)*)"', code))


def required_rows():
    return sorted({row for row in LITERAL_ROWS.values() if row} | set(RUN_OUTCOMES))


def outcome_missing(text, wanted):
    have = {token for row in table_rows(text, '| Token | What it says |') for token in re.findall(r'`([^`]+)`', row[0])}
    return sorted(token for token in wanted if token not in have)


def page_tokens_needed():
    """The rows of the outcome table a page of the model needs: every token of every scenario's page."""
    needed = set()
    for scenario in SCENARIOS:
        for line in model('--scenario', scenario).splitlines():
            body = line[len('PAYLOAD INPSNAP2 '):]
            for pattern, row in PAGE_TOKENS:
                if re.search(pattern, body):
                    needed.add(row)
    return needed


def check_page(text):
    shown = fenced(text, 'page')
    return [] if shown == model('--page') else ['the page block is not the model\'s page']


def check_numbers(text):
    shown = block_of(text, 'numbers')
    return [] if shown is not None and shown.strip() == model('--numbers').strip() else ['the numbers block is not the model\'s numbers']


def check_outcomes(text):
    return [f'no row for {token}' for token in outcome_missing(text, sorted(set(required_rows()) | page_tokens_needed()))]


def check_windows(text):
    problems = []
    rows = {row[0]: row for row in table_rows(text, '| Window | Base | Size |')}
    for name, (base, size) in header_windows().items():
        found = next((row for key, row in rows.items() if key.startswith(name)), None)
        if not found or found[1] != f'0x{base:08x}' or found[2] != f'0x{size:x}':
            problems.append(f'the window {name} is not 0x{base:08x} + 0x{size:x} in the document')
    return problems


def check_blocks(text):
    problems = []
    keys = {}
    for key, _, _, block, _, _ in header_rows():
        keys.setdefault(block, []).append(key)
    rows = {re.sub(r'`', '', row[0]): row for row in table_rows(text, '| Block | Rows | What for |')}
    for block, wanted in keys.items():
        row = rows.get(block)
        if not row:
            problems.append(f'no row for the block {block}')
            continue
        listed = re.findall(r'`(\w+?)`(?:-`(\w+)`)?', row[1])
        found = []
        for first, last in listed:
            if last:
                found += [f'{first[:2]}{n}' for n in range(int(first[2:]), int(last[2:]) + 1)]
            else:
                found.append(first)
        if found != wanted:
            problems.append(f'the block {block} lists {found}, the header has {wanted}')
        count = re.search(r'\((\d+)\)', row[1])
        if not count or int(count.group(1)) != len(wanted):
            problems.append(f'the block {block} is not {len(wanted)} rows in the document')
    return problems


def check_chain(text):
    """The chain budget: every row's formula adds up, uses this payload's own numbers and the runner's rows, and its verdict against the rows seen is right."""
    numbers = {name: int(value) for name, value in (line.split() for line in model('--numbers').splitlines())}
    rows = table_rows(block_of(text, 'inpsnap2-chain-budget') or '', '| Chain | Rows (nominal) | Rows (at most) |')
    problems = []
    if len(rows) != 4:
        return ['the chain budget has not four rows']
    for row in rows:
        payloads = row[0].count('`inpsnap2`') + row[0].count('`tsnap`') + row[0].count('`gpusnap2`')
        for cell, own, label in ((row[1], numbers['unit_lines'], 'nominal'), (row[2], numbers['line_cap'], 'at most')):
            left, _, total = cell.partition(' = ')
            found = re.fullmatch(r'\((\d+) \+ 1\) \+ (?:(\d+) x )?3 \+ (.*)', left)
            if not found or not total.isdigit():
                problems.append(f'{row[0]}: {label} cell {cell!r} has no form the checker knows')
                continue
            files, count, rest = int(found.group(1)), int(found.group(2) or 1), [int(n) for n in found.group(3).split(' + ')]
            if files != count or count != payloads:
                problems.append(f'{row[0]}: {label}: {files} files, {count} payload groups, {payloads} payloads named')
            if rest[-1] != own or any(n != OTHER_PAYLOAD_LINES for n in rest[:-1]):
                problems.append(f'{row[0]}: {label}: the payload lines are {rest}, not {OTHER_PAYLOAD_LINES} for the others and {own} for inpsnap2')
            if (files + 1) + 3 * count + sum(rest) != int(total):
                problems.append(f'{row[0]}: {label}: the sum is {(files + 1) + 3 * count + sum(rest)}, not {total}')
        at_most = int(row[2].rpartition(' = ')[2]) if row[2].rpartition(' = ')[2].isdigit() else -1
        verdict = row[3]
        if (at_most <= SEEN_ROWS) != verdict.startswith('fits') or (at_most > COMPUTED_ROWS) != ('more rows than 89' in verdict):
            problems.append(f'{row[0]}: the verdict {verdict!r} is wrong for {at_most} rows against {SEEN_ROWS} seen and {COMPUTED_ROWS} computed')
        spare = re.search(r'(\d+) to spare', verdict)
        if spare and int(spare.group(1)) != SEEN_ROWS - at_most:
            problems.append(f'{row[0]}: {spare.group(1)} to spare, not {SEEN_ROWS - at_most}')
    if str(SEEN_ROWS) not in text or str(COMPUTED_ROWS) not in text:
        problems.append('the rows seen and computed are not stated')
    return problems


def check_counts(text):
    """The sentence of the tests section that counts the seeded bugs against the module."""
    found = re.search(r'(\d+) in all, (\d+) refused by the host test at the shipped caps, (\d+) at smaller caps, (\d+) by the compiler\'s static assertions, (\d+) by the IR audit, '
                      r'(\d+) by the binary policy and (\d+) by the stack check', ' '.join(text.split()))
    if not found:
        return ['the sentence that counts the seeded bugs is missing']
    stages = Counter(m.stage for m in mutants.all_mutants(ROOT))
    stated = [int(n) for n in found.groups()]
    want = [sum(stages.values()), stages['harness'], stages['caps'], stages['build'], stages['audit'], stages['binary'], stages['stack']]
    problems = [] if stated == want else [f'the document counts {stated}, the module {want}']
    if f'the {want[0]} seeded bugs' not in text:
        problems.append('the commands table does not name the number of seeded bugs')
    return problems


def check_links(text, base=DOC.parent):
    problems = []
    for target in re.findall(r'\]\(([^)#]+\.md)(?:#([^)]*))?\)', text):
        path = base / target[0]
        if not path.is_file():
            problems.append(f'{target[0]} does not exist')
        elif target[1]:
            slugs = {re.sub(r'[^a-z0-9 -]', '', heading.lower()).strip().replace(' ', '-') for heading in re.findall(r'^#+ (.*)$', path.read_text(encoding='utf-8'), re.M)}
            if target[1] not in slugs:
                problems.append(f'{target[0]}#{target[1]} has no such heading')
    return problems


def check_register_table(text):
    problems = []
    rows = {row[1].strip('`'): row for row in table_rows(text, '| Block | Key | Window | Offset |')}
    header = header_rows()
    if len(rows) != len(header):
        problems.append(f'the register table has {len(rows)} rows, the header {len(header)}')
    for key, off, win, block, flags, vbit in header:
        row = rows.get(key)
        if not row:
            problems.append(f'no row for {key}')
            continue
        if (row[0], row[2], row[3]) != (block, win, f'`0x{off:x}`'):
            problems.append(f'{key}: the document says {row[0]} {row[2]} {row[3]}, the header {block} {win} `0x{off:x}`')
        listed = {name for name in FLAGS.values() if name in row[4].split(',')[0].split()}
        wanted = {FLAGS[flag] for flag in re.findall(r'F_\w+', flags)}
        if listed != wanted:
            problems.append(f'{key}: the flags are {sorted(listed)} in the document, {sorted(wanted)} in the header')
        found = re.search(r'vote bit (\d+)', row[4])
        if (int(found.group(1)) if found else 0) != vbit:
            problems.append(f'{key}: the vote bit is {found.group(1) if found else 0} in the document, {vbit} in the header')
    return problems


FAMILIES = {
    'row-offset-': 'KEY', 'row-key-': 'KEY', 'row-block-': 'KEY', 'line-end-': 'N', 'line-block-': 'N', 'line-head-': 'N',
}


def listed_mutants(text):
    """The names of the seeded bugs the evidence document lists (section C): the written-out ones once each, the families as `<prefix><KEY or N>` for every key of the table or line of the page."""
    section = text[text.index('\n## C. '):text.index('\n## D. ')]
    names = re.findall(r'`([a-z0-9][A-Za-z0-9<>-]+)`', section)
    keys = [key for key, *_ in header_rows()]
    lines = range(13)
    found = []
    for name in names:
        template = next((prefix for prefix in FAMILIES if name == f'{prefix}<{FAMILIES[prefix]}>'), None)
        if template:
            found += [f'{template}{key}' for key in keys] if FAMILIES[template] == 'KEY' else [f'{template}{n}' for n in lines]
        else:
            found.append(name)
    return found


def check_mutant_list(text):
    problems = []
    listed = listed_mutants(text)
    wanted = [m.name for m in mutants.all_mutants(ROOT)]
    for name, count in Counter(listed).items():
        if count > 1:
            problems.append(f'{name} is listed {count} times')
    problems += [f'{name} is not listed' for name in sorted(set(wanted) - set(listed))]
    problems += [f'{name} is listed and is no seeded bug' for name in sorted(set(listed) - set(wanted))]
    return problems


def check_excerpts(text):
    problems = []
    for block, scenario in (('gateoff-lines', 'gateoff'), ('gateerr-lines', 'gateerr'), ('hwvote-lines', 'hwvote'), ('stop-lines', 'stop'), ('fault-lines', 'fault')):
        shown = (fenced(text, block) or '').splitlines()
        page = model('--scenario', scenario).splitlines()
        at = -1
        for line in shown:
            if line not in page[at + 1:]:
                problems.append(f'{line!r} is not a later line of the page of {scenario}')
                break
            at = page.index(line, at + 1)
        if not shown:
            problems.append(f'the excerpt {block} is missing')
    return problems


class Doc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not lib.have('clang'):
            raise unittest.SkipTest('clang not installed')
        cls.text = DOC.read_text(encoding='utf-8')

    def test_the_page_is_the_one_the_host_model_prints(self):
        self.assertEqual(check_page(self.text), [])

    def test_the_numbers_are_the_ones_the_host_model_measures(self):
        self.assertEqual(check_numbers(self.text), [])

    def test_the_windows_and_the_blocks_are_the_headers(self):
        self.assertEqual(check_windows(self.text), [])
        self.assertEqual(check_blocks(self.text), [])

    def test_the_outcome_table_has_a_row_for_every_outcome_the_page_can_show(self):
        literals = source_literals()
        self.assertEqual(sorted(literals - set(LITERAL_ROWS)), [], 'a string of the payload that no row of the table accounts for')
        self.assertEqual(sorted(set(LITERAL_ROWS) - literals), [], 'a string the table accounts for that the payload no longer has')
        self.assertEqual(check_outcomes(self.text), [])

    def test_the_chain_budget_is_the_arithmetic_of_the_runner_and_the_pages(self):
        self.assertEqual(check_chain(self.text), [])
        runner = (ROOT / 'docs' / 'SP11-PAYLOAD.md').read_text(encoding='utf-8')
        self.assertRegex(runner, r'\| runner, once per boot: `LOADED` for each file \(payload or data\), `READY` \| files \+ 1 \|')
        self.assertRegex(runner, r'\| runner, for each payload: `VERIFY`, `CALL`, `DONE` \| 3 \|')

    def test_the_counts_of_the_seeded_bugs_are_the_modules(self):
        self.assertEqual(check_counts(self.text), [])

    def test_the_links_resolve(self):
        self.assertEqual(check_links(self.text), [])
        self.assertEqual(check_links(EVIDENCE.read_text(encoding='utf-8')), [])

    def test_the_document_says_what_it_is_and_what_it_is_not(self):
        for statement in ('**Status: EXPERIMENTAL; hardware NOT RUN.**', 'UNKNOWN risk', 'stores nothing but to its own stack', 'The first run is **alone**', 'no document of this tree authorises a run',
                          '## 9. What could not be verified', 'It stores nothing'):
            self.assertIn(statement, self.text)

    def test_the_files_are_within_the_limits(self):
        for path in (DOC, EVIDENCE, SOURCE, REGS, HARNESS, ROOT / 'tools' / 'test-q1n1-sp11-payload-inpsnap2-model.h', ROOT / 'tools' / 'test-q1n1-sp11-payload-inpsnap2-suites.inc',
                     ROOT / 'tools' / 'sp11_payload_inpsnap2_mutants.py', ROOT / 'tools' / 'sp11_payload_inpsnap2_mutants_more.py', ROOT / 'tools' / 'sp11_payload_inpsnap2_refs.py',
                     ROOT / 'tools' / 'sp11_payload_inpsnap2_audit.py', ROOT / 'tools' / 'test-q1n1-sp11-payload-inpsnap2.py', ROOT / 'tools' / 'test-q1n1-sp11-payload-inpsnap2-refs.py',
                     ROOT / 'tools' / 'test-q1n1-sp11-payload-inpsnap2-doc.py', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu-inpsnap2.py'):
            with self.subTest(file=path.name):
                self.assertLess(path.stat().st_size, 51200)
                self.assertLess(len(path.read_text(encoding='utf-8').splitlines()), 1500)
                self.assertIn('SPDX-License-Identifier: MIT', path.read_text(encoding='utf-8')[:200])


class Evidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not lib.have('clang'):
            raise unittest.SkipTest('clang not installed')
        cls.text = EVIDENCE.read_text(encoding='utf-8')

    def test_the_register_table_is_the_header(self):
        self.assertEqual(check_register_table(self.text), [])

    def test_every_seeded_bug_is_listed_once_and_only_the_seeded_bugs(self):
        self.assertEqual(check_mutant_list(self.text), [])

    def test_the_excerpts_are_lines_of_the_pages_the_host_model_prints(self):
        self.assertEqual(check_excerpts(self.text), [])


class DocMistakes(unittest.TestCase):
    """One wrong statement each in a copy of a document: the check that names it must refuse it."""

    @classmethod
    def setUpClass(cls):
        if not lib.have('clang'):
            raise unittest.SkipTest('clang not installed')
        cls.doc, cls.evidence = DOC.read_text(encoding='utf-8'), EVIDENCE.read_text(encoding='utf-8')

    def replaced(self, text, old, new, count=1):
        self.assertEqual(text.count(old), count, f'{old!r} must occur {count} times for the mistake to be one change')
        return text.replace(old, new)

    def test_a_changed_check_in_the_page(self):
        problems = check_page(self.replaced(self.doc, 'K=3886', 'K=3887'))
        self.assertEqual(problems, ['the page block is not the model\'s page'])

    def test_a_changed_number(self):
        self.assertEqual(check_numbers(self.replaced(self.doc, 'unit_lines 21', 'unit_lines 22')), ['the numbers block is not the model\'s numbers'])

    def test_a_missing_row_of_the_outcome_table(self):
        rows = [line for line in self.doc.splitlines() if line.startswith('| `.HW` |')]
        self.assertEqual(len(rows), 1)
        self.assertEqual(check_outcomes(self.doc.replace(rows[0] + '\n', '')), ['no row for .HW'])

    def test_a_wrong_window_base(self):
        problems = check_windows(self.replaced(self.doc, '| 0x00bc0000 |', '| 0x00bc1000 |'))
        self.assertEqual(problems, ['the window QUP is not 0x00bc0000 + 0x2000 in the document'])

    def test_a_block_with_a_row_too_many(self):
        problems = check_blocks(self.replaced(self.doc, '`DFS` `DIV` `CMD` `CFG` `M` `N` `D` (7)', '`DFS` `DIV` `CMD` `CFG` `M` `N` `D` `X` (8)'))
        self.assertTrue(problems and all('RCG' in problem for problem in problems), problems)

    def test_a_wrong_total_in_the_chain_budget(self):
        problems = check_chain(self.replaced(self.doc, '(1 + 1) + 3 + 21 = 26', '(1 + 1) + 3 + 21 = 27'))
        self.assertEqual(len(problems), 1)
        self.assertIn('the sum is 26, not 27', problems[0])

    def test_a_wrong_verdict_in_the_chain_budget(self):
        problems = check_chain(self.replaced(self.doc, 'no: more rows than 89', 'fits'))
        self.assertTrue(problems and 'the verdict' in problems[0], problems)

    def test_a_wrong_count_of_seeded_bugs(self):
        total = len(mutants.all_mutants(ROOT))
        problems = check_counts(self.replaced(self.doc, f' {total} in all,', f' {total + 1} in all,'))
        self.assertEqual(len(problems), 1)
        self.assertIn('the document counts', problems[0])

    def test_a_wrong_offset_in_the_register_table(self):
        problems = check_register_table(self.replaced(self.evidence, '| `0x42274` |', '| `0x42278` |'))
        self.assertEqual(len(problems), 1)
        self.assertIn('SE0', problems[0])

    def test_a_seeded_bug_that_is_not_listed(self):
        problems = check_mutant_list(self.replaced(self.evidence, '`prefix-loses-the-version-digit`', '`prefix-loses-the-version-digit-not`'))
        self.assertEqual(sorted(problems), ['prefix-loses-the-version-digit is not listed', 'prefix-loses-the-version-digit-not is listed and is no seeded bug'])

    def test_a_line_that_the_model_does_not_print(self):
        problems = check_excerpts(self.replaced(self.evidence, 'QUP GATED OFF\n', 'QUP GATED ON\n', count=self.evidence.count('QUP GATED OFF\n')))
        self.assertTrue(problems and all('QUP GATED ON' in problem or 'is not a later line' in problem for problem in problems), problems)


if __name__ == '__main__':
    unittest.main()
