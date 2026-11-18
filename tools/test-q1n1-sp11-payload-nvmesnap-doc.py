#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The nvmesnap document against its source and its host test (docs/SP11-PAYLOAD-NVMESNAP.md).

    python3 tools/test-q1n1-sp11-payload-nvmesnap-doc.py

What it holds: the register table is the source's table, in order, with its offsets and widths; the printed page of the document is the page
the host program prints and the one its source holds; every state, reason and link word of the source is in the decision table; every label the
source prints is in the line catalogue; the numbers of the text (the page budget, the load bound, the most lines, the counts of seeded bugs)
are the source's and the tests'; the chain arithmetic is right; the evidence labels are used as the series uses them; the links and anchors
resolve; no machine identifier is in it; the sentences the review of v1 asked for are there and the wrong ones are not (the order of the headers and of the
port's link line, the one load that is not `load32`, the rules for a run, the staging names, the legend of the page, the row for a panel that stops at
`MAP` or `RP`), each against the source, the runner or q1n1 file it rests on; and the runner's document (docs/SP11-PAYLOAD.md) points here. Each check
also fails on a seeded mistake in the
document (a list of them, below), because a check that no mistake can fail checks nothing.

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_manifest as manifest  # noqa: E402
import sp11_payload_mmu_testkit as kit  # noqa: E402

probe = kit.load_module('sp11_nvmesnap_test_for_doc', ROOT / 'tools' / 'test-q1n1-sp11-payload-nvmesnap.py')
native = probe.native
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-NVMESNAP.md'
RUNNER_DOC = ROOT / 'docs' / 'SP11-PAYLOAD.md'
SMMUPROBE_DOC = ROOT / 'docs' / 'SP11-PAYLOAD-SMMUPROBE.md'
SOURCE = ROOT / 'payloads' / 'nvmesnap.c'
MMU_HEADER = ROOT / 'payloads' / 'payload-mmu.h'
ENTRY_S = ROOT / 'platform' / 'uefi' / 'entry.S'
RUNNER_C = ROOT / 'platform' / 'uefi' / 'sp11-payload-run.c'
HOST_TEST = ROOT / 'tools' / 'test-q1n1-sp11-payload-nvmesnap.c'
LABELS = ('VERIFIED', 'OBSERVED', 'INFERRED', 'EXPERIMENTAL', 'UNIMPLEMENTED', 'UNKNOWN')
EXTRA_LABELS = {'RP', 'EP', 'RP.LINK', 'EP.LINK', 'CAPS', 'NVME_REGS', 'NVME_AQ', 'NVME', 'NVME.AQ', 'SQ0', 'SQ1', 'CQ0', 'CQ1', 'ASQ', 'ACQ'}
# Every token the payload can print besides the states and reasons of its switches: each must be in the outcome table (and in the source, so that
# this list cannot go stale). `REFUSED:126` and `REFUSED:127` are the page's and the window's refusals of rd().
OUTCOME_TOKENS = ('SKIPPED=NO_COUNTER', 'SKIPPED=COUNTER_UNUSABLE', 'SKIPPED=SPIN_BOUND', 'NOT_ATTEMPTED', 'FAULT', 'REFUSED:126', 'REFUSED:127', 'ABSENT', 'ODD=ALL_ONES',
                  'PCIE=NONE', 'PCIE=NOT_READ', 'PM=NONE', 'PM=NOT_READ', 'NOT_AT_EL2', 'NO_LOAD_OP', 'SUPPRESSED', 'MEMMAP_TYPE', 'NOT_IN_MAP', 'MAP_UNUSABLE',
                  'NVME_GROUP_SKIPPED', 'GROUP_SKIPPED')
# What the outcome table must say about the panel that stops, and about recovery (a hang, a q1n1 fault page, a reset after DONE): nothing was written.
OUTCOME_PHRASES = ('a q1n1 fault page', 'the board resets after `DONE`', 'nothing was written, so there is nothing to undo', 'boot the stick again',
                   '`ODD` on `RP.LINK`', 'the panel ends at `MAP` or `RP`', 'no `NEXT` line', 'report the last line')
# What the review of v1 (F1 to F8) found wrong or missing: sentences the document must say, and wrong ones it must not say again. They are compared with
# the whitespace collapsed, so a line break in the document does not matter.
REVIEW_PHRASES = ("The endpoint's header is read first, with no proof of the link", "the port's before the endpoint's capability list is read",
                  'except the descriptors of the memory map', "plain loads of the memory map's descriptors", "2-entry admin queue (its slots 0 and 1)",
                  'Film the panel continuously from `PAYLOAD CALL 0` until two minutes after `DONE`, or for ten minutes when there is no `DONE`',
                  'Run on AC power or at 50 % battery or more, with one hardware client', 'An asynchronous SError is neither caught nor printed',
                  'q1n1 keeps `DAIF.A` masked', "`POLICIES['nvmesnap']`", 'staged as a copy of the same bytes named `SMMUPRB.BIN`',
                  '`MEMMAP_TYPE` is the raw EFI memory type', '4 boot services data', '7 conventional memory', 'a page of 2^(12 + n) bytes',
                  'a doorbell stride of 2^(2 + n) bytes', 'the MMU did not approve a Device page', 'the device refused nothing',
                  'the table sets them against what this payload reads')
WRONG_PHRASES = ("before the endpoint's page", 'the last two commands', 'of the last commands', 'lists it like any other', 'the shared registry is not extended',
                 'every configuration dword above offset')
# Claims about the unit that are not measurements, each with the label it must carry within 250 characters.
LABELLED_CLAIMS = (('could hang the bus', 'INFERRED'), ('show where its DMA landed', 'INFERRED'), ("Linux's `nvme` driver reads", 'INFERRED'),
                   ('a fifth of the bound', 'INFERRED'), ('all ones is what a root complex returns', 'INFERRED'))


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
    first_block = define(code, 'NR_FIRST_BLOCK')
    return [('NVME_REGS' if i < first_block else 'NVME_AQ', name, int(offset, 16), 2 if wide == '1' else 1)
            for i, (name, offset, wide) in enumerate(re.findall(r'\{"(\w+)", (0x[0-9a-f]+), (\d)\}', code))]


def returned_names(function):
    code = SOURCE.read_text(encoding='utf-8')
    body = code[code.index(function):]
    body = body[:body.index('\n}\n')]
    return re.findall(r'return "(\w+)"', body)


def unit_page_of_the_host_test():
    text = HOST_TEST.read_text(encoding='utf-8')
    body = text[text.index('static const char *const unit_page[] = {'):]
    body = body[:body.index('};')]
    return ['PAYLOAD NVMESNAP ' + line for line in re.findall(r'P "([^"]*)"', body)]


def page_of_the_host_program(binary):
    code, output = native.run_program(binary, 'page')
    assert code == 0, output
    return output.splitlines()


def evaluate(formula):
    """`(1 + 1) + 3 + 34` or `(3 + 1) + 3 x 3 + 26` as a number."""
    return eval(formula.replace('x', '*'), {'__builtins__': {}})  # noqa: S307: digits, + * and parentheses only (checked by the caller)


def define(code, name):
    return int(re.search(rf'#define {name} (\d+)u', code).group(1))


def wrong_claims(text):
    """The claims the review of v1 found wrong that `text` makes again (whitespace collapsed)."""
    flat = ' '.join(text.split())
    return [phrase for phrase in WRONG_PHRASES if phrase in flat]


def order_problems(code):
    """The order the document gives for the headers, the port's link line and the endpoint's capability list, in payload_entry: both headers before the
    first NEXT line, then the port's capabilities and its link line, then the endpoint's capabilities."""
    entry = code[code.index('uint64_t payload_entry(const struct q1n1_payload_args *a)\n{'):]
    marks = ('report_head(a, &c, "RP"', 'report_head(a, &c, "EP"', 'announce(a, PG(&c), freq, "CAPS")', 'read_caps(a, &c, &rp', 'report_link(a, &c, "RP.LINK"',
             'read_caps(a, &c, &ep')
    at = [entry.find(mark) for mark in marks]
    return [] if min(at) >= 0 and at == sorted(at) else [f'payload_entry does not read in the order the document gives: {at} for {marks}']


def platform_problems(text, entry_s, runner_c, mmu_header):
    """The document's claims about the runner and q1n1 against their files: the map's descriptors are read in place, a load is one guarded copy of a synchronous
    access, and q1n1 masks SError (and the rest) at each of its three entries."""
    bad = []
    if 'pl_desc_read' not in mmu_header:
        bad.append("payload-mmu.h has no pl_desc_read, the loads of the map's descriptors the document names")
    if 'Q1N1_PAYLOAD_G_COPY32' not in runner_c or 'static int32_t op_load32(' not in runner_c:
        bad.append('the runner no longer makes a load as one guarded copy in op_load32')
    for quoted in re.findall(r'`(msr daifset, #\d+)`', text):
        if entry_s.count(quoted) < 3:
            bad.append(f'entry.S has {entry_s.count(quoted)} of `{quoted}` where the document says q1n1 masks at its entry points')
    return bad


def other_problems(smmuprobe, runner, name_rule):
    """The staging sentence of smmuprobe's document and the runner document's pointer here, against the manifest tool's rule for names."""
    bad = []
    if 'SP11-PAYLOAD-NVMESNAP.md' not in runner or 'test-q1n1-sp11-payload-nvmesnap' not in runner:
        bad.append('the runner document does not point to this one')
    if 'lists it like any other' in smmuprobe or '`SMMUPRB.BIN`' not in smmuprobe:
        bad.append("smmuprobe's document does not say that its binary is staged as SMMUPRB.BIN")
    for name, fits in (('NVMESNAP.BIN', True), ('SMMUPRB.BIN', True), ('SMMUPROBE.BIN', False)):
        if bool(name_rule.match(name)) != fits:
            bad.append(f'the manifest tool {"refuses" if fits else "takes"} {name}, which the documents say the opposite of')
    return bad


def problems(text, page, doc_page):
    """Everything wrong with the document text `text`, as sentences; empty when it is right. `page` is the host program's page."""
    bad = []
    code = SOURCE.read_text(encoding='utf-8')
    # the register table
    try:
        table = [(re.sub('`', '', r[1]), re.sub('`', '', r[2]), int(re.sub('`', '', r[3]), 16), int(r[4])) for r in rows(block(text, 'nvmesnap-registers'))]
    except (KeyError, ValueError, IndexError):
        table = None
    if table != source_rows():
        bad.append(f'the register table is not the source\'s: {table} against {source_rows()}')
    # the configuration dwords of the header row
    try:
        config = block(text, 'nvmesnap-config')
    except KeyError:
        config = ''
    for offset in ('0x00', '0x04', '0x08', '0x0c', '0x10', '0x14', '0x18', '0x20', '0x34'):
        if f'`{offset}`' not in config:
            bad.append(f'the configuration table does not name {offset}')
    # the page
    shown = re.findall(r'^PAYLOAD NVMESNAP .*$', block(text, 'nvmesnap-page'), re.M) if '<!-- nvmesnap-page -->' in text else None
    if shown != page or page != doc_page:
        bad.append('the printed page of the document is not the host program\'s page, or the host test\'s own')
    # the states and reasons
    names = set()
    for function in ('why', 'link', 'ctrl', 'queues'):
        names |= set(returned_names(f'INLINE_NAME const char *{function}_text'))
    names |= {'NONE', 'UNKNOWN', 'NOT_READ', 'NA'}
    try:
        decisions = block(text, 'nvmesnap-decisions')
    except KeyError:
        decisions = ''
    for name in sorted(names):
        if not re.search(rf'(?<![A-Z_]){name}(?![A-Z_])', decisions):
            bad.append(f'the decision table does not name {name}')
    # every other token the payload can print has a row, and the panel that stops has its row and its recovery
    for token in OUTCOME_TOKENS:
        if token.startswith('REFUSED:'):
            if f'#define {"RC_PAGE 0x7eu" if token.endswith("126") else "RC_OUTSIDE 0x7fu"}' not in code:
                bad.append(f'the source no longer defines the code of {token}')
        elif f'"{token}"' not in code:
            bad.append(f'the source can no longer print {token}: the list of outcome tokens is stale')
        if not re.search(rf'(?<![A-Z_]){re.escape(token)}(?![A-Z_])', decisions):
            bad.append(f'the outcome table has no row for {token}')
    for phrase in OUTCOME_PHRASES:
        if phrase not in decisions:
            bad.append(f'the outcome table does not say {phrase!r}')
    # a claim about the unit that is not a measurement carries its label
    for phrase, label in LABELLED_CLAIMS:
        at = text.find(phrase)
        if at < 0:
            bad.append(f'the text no longer says {phrase!r}')
        elif label not in text[max(0, at - 250):at + 250]:
            bad.append(f'{phrase!r} is not labelled {label}')
    # the labels the source prints
    try:
        lines = block(text, 'nvmesnap-lines')
    except KeyError:
        lines = ''
    printed = set(re.findall(r'(?:pl_page_open\(PG\(c\), |pl_page_open\(PG\(&c\), |pl_say\(a, (?:PG\(&c\)|PG\(c\)|p), )"([A-Z0-9_.]+)"', code)) | EXTRA_LABELS
    for label in sorted(printed):
        if f'`{label}`' not in lines:
            bad.append(f'the line catalogue does not name {label}')
    # the numbers
    budget, cap, steps, peek = (define(code, n) for n in ('PL_PAGE_LINES', 'LOAD_CAP', 'CAP_STEPS', 'PEEK_ENTRIES'))
    words = sum(row[3] for row in source_rows())
    queue_words = peek * (len(re.search(r'sqe_words\[6\] = \{([^}]*)\}', code).group(1).split(',')) + len(re.search(r'cqe_words\[3\] = \{([^}]*)\}', code).group(1).split(',')))
    bound = 2 * 7 + 2 * steps + 5 + words + queue_words
    for claim, value in ((r'[Aa]t most (\d+) lines \(the runner draws', budget), (r'the payload\'s own cap is (\d+)', cap), (r'at most (\d+) on any page', bound),
                         (r'walked at most (\d+) times', steps), (r'walks of at most (\d+) steps', steps), (r'here its budget of (\d+) \(the host tests', budget)):
        found = re.search(claim, text)
        if not found or int(found.group(1)) != value:
            bad.append(f'the text says {found.group(1) if found else "nothing"} where the source has {value} ({claim})')
    if not re.search(rf'measures at most {probe.MOST_LINES} over', text):
        bad.append('the most lines the host test measures is not in the text')
    loads = int(re.search(r'LOADS=(\d+)', page[-1]).group(1))
    for pattern, value in ((r'(\d+) seeded-bug mutants', len(probe.mut.MUTANTS)), (r'(\d+) seeded bad binaries', len(probe.BAD_BINARIES)),
                           (r'and (\d+) loads in order', loads)):
        found = re.search(pattern, text)
        if not found or int(found.group(1)) != value:
            bad.append(f'the text says {found.group(1) if found else "nothing"} where there are {value} ({pattern})')
    # the review of v1: what the document must now say, what it must not say again, and what its claims about the order, the runner and q1n1 rest on
    flat = ' '.join(text.split())
    for phrase in REVIEW_PHRASES:
        if phrase not in flat:
            bad.append(f'the text does not say {phrase!r}')
    bad += [f'the text says {phrase!r}, which the review found wrong' for phrase in wrong_claims(text)]
    bad += order_problems(code)
    bad += platform_problems(text, ENTRY_S.read_text(encoding='utf-8'), RUNNER_C.read_text(encoding='utf-8'), MMU_HEADER.read_text(encoding='utf-8'))
    try:
        x2_rows = rows(block(text, 'nvmesnap-x2'))
    except KeyError:
        x2_rows = []
    if [row[0] for row in x2_rows] != ['root port 00:00.0', 'endpoint 01:00.0'] or any(len(row) != 3 for row in x2_rows):
        bad.append('the table of what the X2 image read and what is new does not have its two rows')
    # the chain arithmetic
    try:
        chain = rows(block(text, 'nvmesnap-chain-budget'))
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
    ('a-register-offset-is-wrong', '| 2 | `NVME_REGS` | `CSTS` | `0x1c` |', '| 2 | `NVME_REGS` | `CSTS` | `0x18` |'),
    ('two-registers-swap', '| 3 | `NVME_REGS` | `CC` | `0x14` |', '| 3 | `NVME_REGS` | `CSTS` | `0x1c` |'),
    ('a-register-is-dropped', '| 4 | `NVME_REGS` | `VS` | `0x08` | 1 | the version, `MJR` 31:16, `MNR` 15:8, `TER` 7:0, printed as `VER=a.b.c` |\n', ''),
    ('the-second-csts-is-dropped', '| 5 | `NVME_AQ` | `CSTS2` | `0x1c` | 1 | `CSTS` read a second time, printed as `CSTS2`: a failed or all-ones read stops the block; a change in bits 3:0 makes the state `TRANSITION` |\n', ''),
    ('a-register-is-in-the-wrong-block', '| 6 | `NVME_AQ` | `AQA` |', '| 6 | `NVME_REGS` | `AQA` |'),
    ('the-queue-registers-come-first', '| 4 | `NVME_REGS` | `VS` | `0x08` |', '| 4 | `NVME_REGS` | `AQA` | `0x24` |'),
    ('asq-is-one-word', '| 7 | `NVME_AQ` | `ASQ` | `0x28` | 2 |', '| 7 | `NVME_AQ` | `ASQ` | `0x28` | 1 |'),
    ('cap-is-one-word', '| 1 | `NVME_REGS` | `CAP` | `0x00` | 2 |', '| 1 | `NVME_REGS` | `CAP` | `0x00` | 1 |'),
    ('a-configuration-offset-is-not-in-the-table', '`0x18` (type 1: bus numbers) and `0x20` (memory window)', '`0x1c` (type 1: bus numbers) and `0x24` (memory window)'),
    ('the-page-has-a-wrong-value', 'VERDICT CTRL=RUNNING QUEUES=READ LINK=UP WHY=NONE', 'VERDICT CTRL=DISABLED QUEUES=READ LINK=UP WHY=NONE'),
    ('the-page-lost-a-line', 'PAYLOAD NVMESNAP AQ ASQE=4 ACQE=4\n', ''),
    ('the-page-has-the-old-register-order', 'PAYLOAD NVMESNAP NVME CAP=0X3100323C0301FF CSTS=0X1 CC=0X460081 VS=0X20100', 'PAYLOAD NVMESNAP NVME CAP=0X3100323C0301FF VS=0X20100 CC=0X460081 CSTS=0X1'),
    ('the-pages-loads-are-wrong', 'NVME_GROUP_RAN LOADS=55 FAULTS=0', 'NVME_GROUP_RAN LOADS=54 FAULTS=0'),
    ('a-controller-state-is-not-in-the-table', '`CTRL=FATAL`, `SHUTDOWN` (`QUEUES=NOT_ENABLED`)', '`CTRL=FATAL` (`QUEUES=NOT_ENABLED`)'),
    ('a-reason-is-not-in-the-table', '(`LINK_DOWN`, `LINK_TRAINING`, `LINK_UNPROVEN`, `NO_LINK_CAPABILITY`)', '(`LINK_DOWN`, `LINK_UNPROVEN`, `NO_LINK_CAPABILITY`)'),
    ('a-bar-reason-is-not-in-the-table', '`BAR0_IN_RAM`, `MEMORY_MAP_UNREADABLE`, `BAR0_PAGE_UNMAPPED`, `BAR0_PAGE_NOT_DEVICE`', '`BAR0_IN_RAM`, `BAR0_PAGE_UNMAPPED`, `BAR0_PAGE_NOT_DEVICE`'),
    ('a-queue-state-is-not-in-the-table', '`QUEUES=NO_QUEUES`, `BAD_ADDRESS`, `NOT_RAM`, `PAGE_UNMAPPED`, `FAULT`', '`QUEUES=NO_QUEUES`, `BAD_ADDRESS`, `NOT_RAM`, `FAULT`'),
    ('the-second-blocks-reason-is-not-in-the-table', '(`AQ_REGISTERS_NOT_READ`)', '(`AQ_REGISTERS`)'),
    ('the-all-ones-reason-is-not-in-the-table', '(`REGISTERS_ALL_ONES`)', '(`REGISTERS_ONES`)'),
    ('the-bridge-memory-reason-is-not-in-the-table', ', `BRIDGE_MEMORY_OFF`', ''),
    ('a-skip-token-has-no-row', '`SKIPPED=NO_COUNTER`, `SKIPPED=COUNTER_UNUSABLE` or `SKIPPED=SPIN_BOUND` on the block\'s line', '`SKIPPED=COUNTER_UNUSABLE` or `SKIPPED=SPIN_BOUND` on the block\'s line'),
    ('the-spin-bound-has-no-row', '`SKIPPED=COUNTER_UNUSABLE` or `SKIPPED=SPIN_BOUND` on the block\'s line | a wait could not be made: there is no counter op, the counter stood still or went back (`COUNTER_UNUSABLE`), or it moved but not enough in 2^32 - 1 reads (`SPIN_BOUND`: a slow counter, not a dead one)',
     '`SKIPPED=COUNTER_UNUSABLE` on the block\'s line | a wait could not be made: there is no counter op, or the counter stood still or went back (`COUNTER_UNUSABLE`)'),
    ('the-budget-row-is-dropped', '`SUPPRESSED=<n>` on the last line; a read `REFUSED` with the budget\'s code', 'a read `REFUSED` with the budget\'s code'),
    ('the-recovery-is-not-said', '**nothing was written, so there is nothing to undo: power-cycle the board and boot the stick again**', '**power-cycle the board**'),
    ('the-fault-page-row-is-dropped', 'or on a q1n1 fault page, or the board resets after `DONE`', 'or the board resets after `DONE`'),
    ('the-odd-mark-has-no-row', ', `ODD` on `RP.LINK`', ''),
    ('a-claim-loses-its-label', 'a read through a link that is not up could hang the bus (INFERRED)', 'a read through a link that is not up could hang the bus'),
    ('a-claim-about-the-driver-loses-its-label', '(INFERRED from memory of the driver: its source is not a file of this tree)', '(from memory of the driver: its source is not a file of this tree)'),
    ('a-label-is-not-in-the-catalogue', '| `AQ` | `ASQE`, `ACQE`, `ODD` (a reserved bit of `AQA` is set) |', '| `AQX` | `ASQE`, `ACQE`, `ODD` (a reserved bit of `AQA` is set) |'),
    ('the-second-block-label-is-not-in-the-catalogue', '| `NVME.AQ` | `CSTS2`, `AQA`, `ASQ`, `ACQ`, raw | after the third `NEXT` |\n', ''),
    ('the-budget-is-wrong', 'At most 34 lines (the runner draws 40', 'At most 40 lines (the runner draws 40'),
    ('the-load-bound-is-wrong', 'at most 80 on any page', 'at most 81 on any page'),
    ('the-load-cap-is-wrong', 'the payload\'s own cap is 400', 'the payload\'s own cap is 500'),
    ('the-walk-bound-is-wrong', 'walked at most 16 times', 'walked at most 32 times'),
    ('the-most-lines-is-wrong', 'measures at most 33 over', 'measures at most 25 over'),
    ('the-mutant-count-is-wrong', f'{len(probe.mut.MUTANTS)} seeded-bug mutants', '110 seeded-bug mutants'),
    ('the-bad-binary-count-is-wrong', f'{len(probe.BAD_BINARIES)} seeded bad binaries', '20 seeded bad binaries'),
    ('a-chain-does-not-add-up', '(2 + 1) + 3 x 2 + 34 + 36 = 79', '(2 + 1) + 3 x 2 + 34 + 36 = 78'),
    ('a-chain-fits-the-wrong-panel', '| `nvmesnap` and `smmuprobe` | (2 + 1) + 3 x 2 + 34 + 36 = 79 | yes | no |', '| `nvmesnap` and `smmuprobe` | (2 + 1) + 3 x 2 + 34 + 36 = 79 | yes | yes |'),
    ('a-chain-ignores-the-budget', '(1 + 1) + 3 + 34 = 39', '(1 + 1) + 3 + 29 = 34'),
    ('hardware-is-called-verified', 'Nothing in this document is VERIFIED for the unit.', 'The link is VERIFIED to be up.'),
    ('a-machine-path-is-in-it', 'tools/sp11_payload_manifest.py', '/Us' + 'ers/someone/q1n1/tools/sp11_payload_manifest.py'),
    # the review of v1 (F1 to F8)
    ('the-endpoint-header-is-said-to-wait-for-the-link', "**The endpoint's header is read first, with no proof of the link:**", "**The endpoint's header is read after the link is proven:**"),
    ('the-link-line-is-said-to-come-before-the-endpoints-page', "the port's before the endpoint's capability list is read", "the port's before the endpoint's page is read"),
    ('every-word-is-said-to-come-from-load32', '`load32`, except the descriptors of the memory map, which are read in place once the map', '`load32`, which are read in place once the map'),
    ('the-descriptor-loads-have-no-row', "| plain loads of the memory map's descriptors |", '| plain loads |'),
    ('the-last-two-commands-are-back', "the two commands of the firmware's 2-entry admin queue (its slots 0 and 1)", 'the last two commands the firmware sent on the admin queue'),
    ('the-filming-rule-is-dropped', 'Film the panel continuously from `PAYLOAD CALL 0` until two minutes after `DONE`, or for ten minutes when there is no `DONE`. ', ''),
    ('the-film-ends-too-soon', 'until two minutes after `DONE`', 'until two seconds after `DONE`'),
    ('the-power-rule-is-dropped', 'Run on AC power or at 50 % battery or more, with one hardware', 'Run with one hardware'),
    ('the-serror-sentence-is-reversed', '**An asynchronous SError is neither caught nor printed:**', '**An asynchronous SError is caught and printed:**'),
    ('the-masking-instruction-is-wrong', '(`msr daifset, #15` at its entry points,', '(`msr daifset, #3` at its entry points,'),
    ('the-manifest-tool-is-said-to-list-everything', "lists `NVMESNAP.BIN` like any other: it takes 8.3 names, and `NVMESNAP` has eight letters.", 'lists it like any other.'),
    ('the-nine-letter-name-is-not-said', 'not fit it (`SMMUPROBE.BIN` has nine), so in a chain it is staged as a copy of the same bytes named `SMMUPRB.BIN`.',
     'fit it, so in a chain it is staged under its own name.'),
    ('the-registry-is-said-not-to-be-extended', "with the policy `POLICIES['nvmesnap']` of that shared registry, which the shared build test",
     'with a policy local to the test (the shared registry is not extended), which the shared build test'),
    ('the-legend-has-the-wrong-memory-type', '4 boot services data', '4 runtime services data'),
    ('the-legend-has-the-wrong-page-exponent', 'a page of 2^(12 + n) bytes', 'a page of 2^(10 + n) bytes'),
    ('the-legend-says-the-device-refused', 'nothing was loaded, and the device refused nothing.', 'the device refused the read.'),
    ('the-header-hang-row-is-dropped', '| the panel ends at `MAP` or `RP`, with no `NEXT` line after it |', '| the panel ends at a line |'),
    ('the-header-hang-row-does-not-ask-for-the-last-line', 'and report the last line on the panel |', 'and nothing else |'),
    ('the-x2-table-loses-its-end', '<!-- /nvmesnap-x2 -->', ''),
    ('the-novelty-list-claims-every-dword-above-0x40', "**New on this unit, and so UNKNOWN until a run:** the endpoint's header dword",
     "**New on this unit, and so UNKNOWN until a run:** every configuration dword above offset `0x40`, the endpoint's header dword"),
]


class NvmesnapDoc(unittest.TestCase):
    text = DOC.read_text(encoding='utf-8')

    @classmethod
    def setUpClass(cls):
        if not native.have('clang'):
            raise unittest.SkipTest('clang not installed')
        native.BUILD.mkdir(parents=True, exist_ok=True)
        done, binary = native.build_program('nvmesnap', native.UEFI, native.PAYLOADS, native.BUILD / 'doc')
        if done.returncode:
            raise RuntimeError(done.stderr)
        cls.binary = binary
        cls.page = page_of_the_host_program(binary)
        cls.doc_page = unit_page_of_the_host_test()

    def test_the_document_is_right(self):
        self.assertEqual(problems(self.text, self.page, self.doc_page), [])

    def test_each_seeded_mistake_is_found(self):
        self.assertGreaterEqual(len(MISTAKES), 35)
        for name, old, new in MISTAKES:
            with self.subTest(mistake=name):
                self.assertEqual(self.text.count(old), 1, f'the target of {name} is not in the document exactly once')
                self.assertTrue(problems(self.text.replace(old, new, 1), self.page, self.doc_page), 'the checks passed a wrong document')

    def test_the_page_block_is_the_host_programs_page_to_the_last_line(self):
        shown = re.findall(r'^PAYLOAD NVMESNAP .*$', block(self.text, 'nvmesnap-page'), re.M)
        self.assertEqual(shown, self.page)
        self.assertEqual(self.page, self.doc_page)
        self.assertEqual(len(self.page), 27)

    def test_the_most_lines_the_host_program_reaches_is_in_the_text(self):
        code, output = native.run_program(self.binary, 'lines-report')
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

    def test_the_other_documents_agree_and_each_of_their_checks_can_fail(self):
        smmuprobe, runner = SMMUPROBE_DOC.read_text(encoding='utf-8'), RUNNER_DOC.read_text(encoding='utf-8')
        self.assertEqual(other_problems(smmuprobe, runner, manifest.NAME), [])
        no_pointer = runner.replace('SP11-PAYLOAD-NVMESNAP.md', 'SP11-PAYLOAD-OTHER.md')
        old_sentence = smmuprobe.replace('takes 8.3 names only and refuses `SMMUPROBE.BIN` (nine letters)', 'lists it like any other')
        self.assertNotEqual(no_pointer, runner)
        self.assertNotEqual(old_sentence, smmuprobe)
        for label, args in (('no pointer from the runner document', (smmuprobe, no_pointer, manifest.NAME)),
                            ("smmuprobe's old staging sentence", (old_sentence, runner, manifest.NAME)),
                            ('a looser rule for names', (smmuprobe, runner, re.compile(r'^[A-Z0-9_-]{1,9}\.[A-Z0-9_-]{1,3}$')))):
            with self.subTest(case=label):
                self.assertTrue(other_problems(*args))

    def test_the_order_the_document_gives_is_the_sources_and_the_check_can_fail(self):
        code = SOURCE.read_text(encoding='utf-8')
        self.assertEqual(order_problems(code), [])
        header_late = code.replace('    report_head(a, &c, "EP", &ep, &snap.ep);\n', '', 1).replace(
            '        read_caps(a, &c, &ep, &snap.ep, 1, &snap.ep_caps);\n',
            '        report_head(a, &c, "EP", &ep, &snap.ep);\n        read_caps(a, &c, &ep, &snap.ep, 1, &snap.ep_caps);\n', 1)
        link_late = code.replace('        report_link(a, &c, "RP.LINK", &rp, &snap.rp_caps, 1);\n', '', 1).replace(
            '        snap.caps_run = 1;\n', '        report_link(a, &c, "RP.LINK", &rp, &snap.rp_caps, 1);\n        snap.caps_run = 1;\n', 1)
        for label, changed in (('the endpoint header after the capability reads', header_late), ("the port's link line after the endpoint's capabilities", link_late)):
            with self.subTest(case=label):
                self.assertNotEqual(changed, code)
                self.assertTrue(order_problems(changed))

    def test_the_claims_about_the_runner_and_q1n1_are_their_files_and_each_check_can_fail(self):
        entry, runner, mmu = (path.read_text(encoding='utf-8') for path in (ENTRY_S, RUNNER_C, MMU_HEADER))
        self.assertEqual(platform_problems(self.text, entry, runner, mmu), [])
        for label, args in (('a masking that is not there', (self.text, entry.replace('msr daifset, #15', 'msr daifset, #3'), runner, mmu)),
                            ('a guard that is not one copy', (self.text, entry, runner.replace('Q1N1_PAYLOAD_G_COPY32', 'OTHER'), mmu)),
                            ('no reader of descriptors', (self.text, entry, runner, mmu.replace('pl_desc_read', 'other_read')))):
            with self.subTest(case=label):
                self.assertTrue(platform_problems(*args))

    def test_the_host_test_does_not_repeat_what_the_review_found_wrong(self):
        text = HOST_TEST.read_text(encoding='utf-8')
        self.assertEqual(wrong_claims(text), [])
        self.assertIn("link line before the endpoint's capability list", ' '.join(text.split()))
        self.assertTrue(wrong_claims(text.replace("before the endpoint's capability list", "before the endpoint's page")), 'the old comment passed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
