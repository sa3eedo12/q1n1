#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The smmuprobe document against its source and its host test (docs/SP11-PAYLOAD-SMMUPROBE.md).

    python3 tools/test-q1n1-sp11-payload-smmuprobe-doc.py

What it holds: the register table is the source's table, in order, with its offsets and widths; the printed page of the document is the page
the host program prints and the one its source holds; every verdict mode and reason of the source is in the decision table; every label the
source prints is in the line catalogue; the numbers of the text (the page budget, the load bound, the most lines, the counts of seeded bugs)
are the source's and the tests'; the chain arithmetic is right; the evidence labels are used as the series uses them; the links and anchors
resolve; no machine identifier is in it; and the pointer to it in docs/SP11-PAYLOAD.md. Each check also fails on a seeded mistake in the
document (a list of them, below), because a check that no mistake can fail checks nothing.

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_mmu_testkit as kit  # noqa: E402

probe = kit.load_module('sp11_smmuprobe_test_for_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload-smmuprobe.py')
native = probe.native
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-SMMUPROBE.md'
RUNNER_DOC = ROOT / 'docs' / 'SP11-PAYLOAD.md'
SOURCE = ROOT / 'payloads' / 'smmuprobe.c'
HOST_TEST = ROOT / 'tools' / 'test-q1n1-sp11-payload-smmuprobe.c'
LABELS = ('VERIFIED', 'OBSERVED', 'INFERRED', 'EXPERIMENTAL', 'UNIMPLEMENTED', 'UNKNOWN')


def block(text, tag):
    start, end = f'<!-- {tag} -->', f'<!-- /{tag} -->'
    if start not in text or end not in text:
        raise KeyError(tag)
    return text[text.index(start) + len(start):text.index(end)]


def rows(table):
    """The cells of every body row of a markdown table (the header and its rule skipped)."""
    out = [[c.strip() for c in re.split(r'(?<!\\)\|', line.strip())[1:-1]] for line in table.strip().splitlines() if line.startswith('|')]
    return out[2:]


def slug(heading):
    heading = re.sub(r'[`*]', '', heading.strip().lower())
    return re.sub(r'[^a-z0-9 _-]', '', heading).replace(' ', '-')


def anchors(path):
    return {slug(m.group(1)) for m in re.finditer(r'^#+ (.+)$', path.read_text(encoding='utf-8'), re.M)}


def source_rows():
    code = SOURCE.read_text(encoding='utf-8')
    return [(name, int(offset, 16), 2 if wide == '1' else 1) for name, offset, wide in re.findall(r'\{"(\w+)", (0x[0-9a-f]+), (\d)\}', code)]


def returned_names(function):
    code = SOURCE.read_text(encoding='utf-8')
    body = code[code.index(function):]
    body = body[:body.index('\n}\n')]
    return re.findall(r'return "(\w+)"', body)


def unit_page_of_the_host_test():
    text = HOST_TEST.read_text(encoding='utf-8')
    body = text[text.index('static const char *const unit_page[] = {'):]
    body = body[:body.index('};')]
    return ['PAYLOAD SMMUPROBE ' + line for line in re.findall(r'P "([^"]*)"', body)]


def page_of_the_host_program(binary):
    code, output = native.run_program(binary, 'page')
    assert code == 0, output
    return output.splitlines()


def evaluate(formula):
    """`(1 + 1) + 3 + 36` or `(3 + 1) + 3 x 3 + 24` as a number."""
    return eval(formula.replace('x', '*'), {'__builtins__': {}})  # noqa: S307: digits, + * and parentheses only (checked by the caller)


def problems(text, page, doc_page):
    """Everything wrong with the document text `text`, as sentences; empty when it is right. `page` is the host program's page."""
    bad = []
    code = SOURCE.read_text(encoding='utf-8')
    # the register table
    try:
        table = [(re.sub('`', '', r[1]), int(re.sub('`', '', r[2]), 16), int(r[3])) for r in rows(block(text, 'smmuprobe-registers'))]
    except (KeyError, ValueError):
        table = None
    if table != source_rows():
        bad.append(f'the register table is not the source\'s: {table} against {source_rows()}')
    # the page
    shown = re.findall(r'^PAYLOAD SMMUPROBE .*$', block(text, 'smmuprobe-page'), re.M) if '<!-- smmuprobe-page -->' in text else None
    if shown != page or page != doc_page:
        bad.append('the printed page of the document is not the host program\'s page, or the host test\'s own')
    # the modes and reasons
    modes = set(returned_names('INLINE_NAME const char *mode_text')) | {'UNKNOWN'}
    reasons = set(returned_names('INLINE_NAME const char *why_text')) | {'NONE'}
    try:
        decisions = block(text, 'smmuprobe-decisions')
    except KeyError:
        decisions = ''
    for name in sorted(modes | reasons):
        if f'`{name}`' not in decisions:
            bad.append(f'the decision table does not name {name}')
    # the labels the source prints
    try:
        lines = block(text, 'smmuprobe-lines')
    except KeyError:
        lines = ''
    printed = set(re.findall(r'(?:pl_page_open\(PG\(c\), |pl_page_open\(PG\(&c\), |pl_say\(a, (?:PG\(&c\)|p), )"([A-Z0-9_.]+)"', code))
    printed |= {'RP', 'EP', 'RP.PCIE', 'EP.PCIE', 'RP.AER', 'EP.AER', 'PCIE_CAPS', 'SMMU_REGISTERS'}
    for label in sorted(printed):
        if f'`{label}`' not in lines:
            bad.append(f'the line catalogue does not name {label}')
    # the numbers
    budget = int(re.search(r'#define PL_PAGE_LINES (\d+)u', code).group(1))
    cap = int(re.search(r'#define LOAD_CAP (\d+)u', code).group(1))
    caps, ext = (int(re.search(rf'#define {n} (\d+)u', code).group(1)) for n in ('CAP_STEPS', 'EXT_STEPS'))
    per_function = 7 + caps + 5 + ext + 5
    bound = 2 * per_function + len(source_rows()) + 1 + 2 + 8
    for claim, value in ((r'[Aa]t most (\d+) lines \(the runner draws', budget), (r'its own cap is (\d+)', cap), (r'at most (\d+) on any page', bound),
                         (r'two functions of at most (\d+) each', per_function), (r'budget of (\d+) \(the host tests', budget)):
        found = re.search(claim.replace('its own cap', 'the payload\'s own cap'), text)
        if not found or int(found.group(1)) != value:
            bad.append(f'the text says {found.group(1) if found else "nothing"} where the source has {value} ({claim})')
    if not re.search(rf'measures at most {probe.MOST_LINES} over', text):
        bad.append('the most lines the host test measures is not in the text')
    loads = int(re.search(r'LOADS=(\d+)', page[-1]).group(1))
    for pattern, value in ((r'(\d+) seeded-bug mutants', len(probe.MUTANTS)), (r'(\d+) seeded page-budget bugs', len(probe.BUDGET_MUTANTS)),
                           (r'(\d+) seeded load-cap bugs', len(probe.CAP_MUTANTS)), (r'(\d+) seeded bad binaries', len(probe.BAD_BINARIES)),
                           (r'and (\d+) loads in order', loads)):
        found = re.search(pattern, text)
        if not found or int(found.group(1)) != value:
            bad.append(f'the text says {found.group(1) if found else "nothing"} where there are {value} ({pattern})')
    # the chain arithmetic
    try:
        chain = rows(block(text, 'smmuprobe-chain-budget'))
    except KeyError:
        chain = []
    if len(chain) < 3:
        bad.append('the chain table has fewer than three rows')
    for name, formula, unit, least in chain:
        cells = re.fullmatch(r'([0-9 +x()]+) = (\d+)', formula)
        if not cells or evaluate(cells.group(1)) != int(cells.group(2)):
            bad.append(f'the chain {name} does not add up: {formula}')
            continue
        total = int(cells.group(2))
        if (unit == 'yes') != (total <= 89) or (least == 'yes') != (total <= 60):
            bad.append(f'the chain {name} fits the wrong panel: {total} against 89 and 60')
        if f'+ {budget}' not in cells.group(1):
            bad.append(f'the chain {name} does not use the payload\'s budget of {budget}')
    # labels
    for found in re.finditer(r'\bVERIFIED\b', text):
        near = text[max(0, found.start() - 60):found.end() + 80]
        if 'Evidence labels as there' not in text[max(0, found.start() - 120):found.start()] and 'Nothing in this document is VERIFIED' not in near:
            bad.append(f'VERIFIED used at: {near!r}')
    if 'hardware NOT RUN' not in text[:2000] or 'EXPERIMENTAL' not in text[:2000]:
        bad.append('the opening does not say EXPERIMENTAL and hardware NOT RUN')
    # nothing that identifies a machine or a person (the paths are built from pieces so that this file does not hold what it looks for)
    for pattern in ('/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/', r'@\w+\.\w+', r'\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b',
                    r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'):
        if re.search(pattern, text):
            bad.append(f'a machine or person identifier matches {pattern}')
    return bad


# Seeded mistakes in the document: each must make problems() say something.
MISTAKES = [
    ('a-register-offset-is-wrong', '| 11 | `GBPA` | `0x44` |', '| 11 | `GBPA` | `0x48` |'),
    ('two-registers-swap', '| 9 | `CR0` | `0x20` |', '| 9 | `CR0ACK` | `0x24` |'),
    ('a-register-is-dropped', '| 8 | `AIDR` | `0x1c` | 1 | the architecture revision, printed raw |\n', ''),
    ('strtab-base-is-one-word', '| 13 | `STRTAB_BASE` | `0x80` | 2 |', '| 13 | `STRTAB_BASE` | `0x80` | 1 |'),
    ('the-page-has-a-wrong-value', 'MODE=S2 WHY=NONE', 'MODE=S1 WHY=NONE'),
    ('the-page-lost-a-line', 'PAYLOAD SMMUPROBE EP BAR1=0X0 CAPPTR=0X40\n', ''),
    ('a-mode-is-not-in-the-table', '`NO_STE` (`SID_BEYOND_TABLE`, `NO_L2_TABLE`, `BEYOND_L2_SPAN`)', '`SID_BEYOND_TABLE`, `NO_L2_TABLE`, `BEYOND_L2_SPAN`'),
    ('a-reason-is-not-in-the-table', '`TABLE_NOT_RAM`, `L1_NOT_READ`, `STE_NOT_READ`', '`L1_NOT_READ`, `STE_NOT_READ`'),
    ('a-label-is-not-in-the-catalogue', '| `S2` | `VMID`', '| `S3` | `VMID`'),
    ('the-budget-is-wrong', 'At most 36 lines (the runner draws 40', 'At most 40 lines (the runner draws 40'),
    ('the-load-bound-is-wrong', 'at most 139 on any page', 'at most 150 on any page'),
    ('the-load-cap-is-wrong', 'the payload\'s own cap is 400', 'the payload\'s own cap is 500'),
    ('the-most-lines-is-wrong', 'measures at most 30 over', 'measures at most 25 over'),
    ('the-mutant-count-is-wrong', '134 seeded-bug mutants', '110 seeded-bug mutants'),
    ('a-page-reason-is-not-in-the-table', '| `UNKNOWN` with `SMMU_PAGE_UNMAPPED`, `SMMU_PAGE_NOT_DEVICE` |', '| `UNKNOWN` with `SMMU_PAGE_UNMAPPED`, `SMMU_PAGE_NOT_DEVICED` |'),
    ('the-acknowledgement-reason-is-not-in-the-table', '| `UNKNOWN` with `CR0_ACK_DISAGREE` |', '| `UNKNOWN` with `CR0_ACK_DISAGREED` |'),
    ('a-table-page-reason-is-not-in-the-table', '`L1_UNMAPPED`, `STE_UNMAPPED` |', '`L1_UNMAPPED` |'),
    ('the-bad-binary-count-is-wrong', '27 seeded bad binaries', '20 seeded bad binaries'),
    ('a-chain-does-not-add-up', '(2 + 1) + 3 x 2 + 26 + 36 = 71', '(2 + 1) + 3 x 2 + 26 + 36 = 70'),
    ('a-chain-fits-the-wrong-panel', '| `usbsmmu`, `el2mem` and `smmuprobe` | (3 + 1) + 3 x 3 + 24 + 26 + 36 = 99 | no | no |',
     '| `usbsmmu`, `el2mem` and `smmuprobe` | (3 + 1) + 3 x 3 + 24 + 26 + 36 = 99 | yes | no |'),
    ('a-chain-ignores-the-budget', '(1 + 1) + 3 + 36 = 41', '(1 + 1) + 3 + 29 = 34'),
    ('hardware-is-called-verified', 'Nothing in this document is VERIFIED for the unit.', 'The SMMU is VERIFIED to be in bypass.'),
    ('a-machine-path-is-in-it', 'tools/sp11_payload_manifest.py', '/Us' + 'ers/someone/q1n1/tools/sp11_payload_manifest.py'),
]


class SmmuprobeDoc(unittest.TestCase):
    text = DOC.read_text(encoding='utf-8')

    @classmethod
    def setUpClass(cls):
        if not native.have('clang'):
            raise unittest.SkipTest('clang not installed')
        native.BUILD.mkdir(parents=True, exist_ok=True)
        done, binary = native.build_program('smmuprobe', native.UEFI, native.PAYLOADS, native.BUILD / 'doc')
        if done.returncode:
            raise RuntimeError(done.stderr)
        cls.page = page_of_the_host_program(binary)
        cls.doc_page = unit_page_of_the_host_test()

    def test_the_document_is_right(self):
        self.assertEqual(problems(self.text, self.page, self.doc_page), [])

    def test_each_seeded_mistake_is_found(self):
        self.assertGreaterEqual(len(MISTAKES), 20)
        for name, old, new in MISTAKES:
            with self.subTest(mistake=name):
                self.assertEqual(self.text.count(old), 1, f'the target of {name} is not in the document exactly once')
                self.assertTrue(problems(self.text.replace(old, new, 1), self.page, self.doc_page), 'the checks passed a wrong document')

    def test_the_page_block_is_the_host_programs_page_to_the_last_line(self):
        shown = re.findall(r'^PAYLOAD SMMUPROBE .*$', block(self.text, 'smmuprobe-page'), re.M)
        self.assertEqual(shown, self.page)
        self.assertEqual(self.page, self.doc_page)
        self.assertEqual(len(self.page), 25)

    def test_the_most_lines_the_host_program_reaches_is_in_the_text(self):
        done, binary = native.build_program('smmuprobe', native.UEFI, native.PAYLOADS, native.BUILD / 'doc')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary, 'lines-report')
        self.assertEqual((code, output.strip()), (0, f'LINES_MAX={probe.MOST_LINES}'))

    def test_the_links_and_anchors_resolve(self):
        for target in re.findall(r'\]\(([^)#\s]*)(?:#([^)\s]*))?\)', self.text):
            path, anchor = target
            with self.subTest(link=f'{path}#{anchor}'):
                if path.startswith('http'):
                    continue
                destination = (DOC.parent / path) if path else DOC
                self.assertTrue(destination.is_file(), f'{path} does not exist')
                if anchor:
                    self.assertIn(anchor, anchors(destination), f'{anchor} is no heading of {path or DOC.name}')

    def test_the_document_is_within_the_size_limits_and_carries_the_licence(self):
        self.assertLess(len(self.text.splitlines()), 1500)
        self.assertLess(len(self.text.encode('utf-8')), 50 * 1024)
        self.assertTrue(self.text.startswith('<!-- SPDX-License-Identifier: MIT -->'))
        self.text.encode('ascii')

    def test_every_evidence_label_used_is_one_of_the_series(self):
        for word in set(re.findall(r'\b[A-Z]{5,}\b', self.text)) & {'VERIFIED', 'OBSERVED', 'INFERRED', 'EXPERIMENTAL', 'UNIMPLEMENTED', 'UNKNOWN'}:
            self.assertIn(word, LABELS)

    def test_the_runner_document_points_here(self):
        runner = RUNNER_DOC.read_text(encoding='utf-8')
        self.assertIn('SP11-PAYLOAD-SMMUPROBE.md', runner, 'the runner document does not point to this one')
        self.assertIn('test-q1n1-sp11-payload-smmuprobe', runner)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
