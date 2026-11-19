#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The mapping step's document against its source and its host test (docs/SP11-PAYLOAD-SMMUMAP.md).

    python3 tools/test-q1n1-sp11-payload-smmumap-doc.py

What it holds: the constants of the table are the header's; the printed page of the document is the page the host program holds (and prints); every line the
logic begins is in the line table; every reason of the source is a row of the outcome table, with the rows for the stop, the put-back, the hang and the reset; the
numbers of the text (the most lines, the budget, the digests' shape) are the source's and the arithmetic is right; the build recipe is the Makefile's; the evidence
labels are used as the series uses them and the claims about the unit that are not measurements carry one; the hazards and the recovery are said; the links and
anchors resolve; no machine identifier is in it; the runner's document points here and its raised size cap is the least that holds it. Each check also fails on a
seeded mistake in the document (a list of them, below), because a check that no mistake can fail checks nothing.

Writes nothing. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_smmumap_mutants as mutant_module  # noqa: E402
import sp11_payload_testlib as lib  # noqa: E402

DOCS = ROOT / 'docs'
DOC = DOCS / 'SP11-PAYLOAD-SMMUMAP.md'
RUNNER_DOC = DOCS / 'SP11-PAYLOAD.md'
UEFI = ROOT / 'platform' / 'uefi'
HEADER = UEFI / 'sp11-smmumap.h'
LOGIC = UEFI / 'sp11-smmumap.c'
HOST_TEST = ROOT / 'tools' / 'test-q1n1-sp11-payload-smmumap.c'
SCAN_TEST = ROOT / 'tools' / 'test-q1n1-sp11-payload-smmumap-scan.c'
WORLD = ROOT / 'tools' / 'test-q1n1-sp11-payload-smmumap-world.h'
MAKEFILE = UEFI / 'Makefile'
LABELS = ('VERIFIED', 'OBSERVED', 'INFERRED', 'EXPERIMENTAL', 'UNIMPLEMENTED', 'UNKNOWN')
PINNED_RUNNER_SHA256 = 'c20579093ec7b1506faca3c0d33520561716510d7932ac1c9d340f432c88bf6e'
# Rows of the outcome table besides one per reason: the stop, the put-back, the done lines, the hang, the dark panel, the reset, the hash stop, the SError line, and recovery.
OUTCOME_PHRASES = ('PAYLOAD CHAIN STOPPED INDEX=<n> REASON=SMMUMAP', 'DONE MAPPED=0 STORES=<n> UNSAFE', 'REFUSED=CHECK_FAILED UNDONE=1', 'DONE MAPPED=1 STORES=1',
                   'DONE MAPPED=0 STORES=0', 'NEXT STORE AFTER 8 S', 'the panel ends at `START`, `REGS`, `WALK`, `TEMPLATE` or `TABLE`', 'a q1n1 fault page',
                   'boot the stick again', 'FORCE OFF', 'nothing was written to any device', 'the lines of smmuprobe follow', 'REASON=HASH_AT_EL2',
                   'SERROR=NONE PENDING=0 BEFORE=0', 'SERROR=FOUND SYNDROME= PENDING= BEFORE=', 'REFUSED=TABLE_NOT_RAM TABLE= TYPE= LEVEL= ATTR=',
                   'after the last `PAYLOAD DONE`, no `SERROR` line and no ticking uptime for two minutes', 'but there is no `SERROR` line')
# Sentences the document must say: the hazards, what it does not know, the model's disclaimers, and the points the brief names.
REQUIRED_PHRASES = ('q1n1 keeps `DAIF.A` masked', 'neither caught nor printed', 'boots 16, 17 and 19 went dark', 'cause UNKNOWN', 'film continuously from the first',
                    '**`MAIR_EL2` has no Device-nGnRE entry**', 'stricter than the nGnRE that was first asked for', 'The tables are the model\'s, an invention',
                    'the values are not the unit\'s', '**Nothing is written to any device**', 'is **not\nchanged**', 'UNIMPLEMENTED: a put-back exists',
                    '**Retirement condition:**', 'one row** of\n  `q1n1_smmumap_specs`', 'Why a walker of its own', 'the descriptor is gone', 'The descriptor stays for the rest of the boot',
                    'record the hash of the image that is staged', 'hardware NOT RUN', 'EXPERIMENTAL; hardware NOT RUN',
                    '`PTW` is bit 8 and `S` bit 9 of `PAR_EL1`', 'right after the first payload\'s own check passed and before its `PAYLOAD CALL`', 'calls **no** payload',
                    'a payload that is already damaged when the step is about\nto be made', '**The stamp.**', 'its `BUILD` line would read `A9F00F9CCBB5`', 'the stamp of the pinned gate-off\nrunner',
                    'is read once more just before the store', 'no device is read or written by the step\'s own loads and stores, by construction', 'with no margin',
                    'a hang before it leaves the last line of smmuprobe',
                    'The runner catches or clears nothing else', 'a third-party report from another SoC', 'an answer about the step, not about the SMMU',
                    # v3: every load is proven RAM, none skipped, the line after the chain read as it is, the hang rule, and what a record must say
                    '**No path table is skipped**', 'at most 2,047 loads', '1,567 on the unit\'s regime', 'raised by a payload of the chain (nvmesnap or smmuprobe) or later',
                    '`BEFORE=1` separates only the step\'s own past', '**A record must not conclude from `FOUND` alone**', '**It does not mean the read was error-free**',
                    '`SCR_EL3.EA` is UNKNOWN on this unit', '**The poll consumes what it finds**', 'a ticking uptime within seconds', 'neither for two minutes is a hang (the poll can hang)',
                    '**Every refusal means no experiment was made**', '`REFS=0/0/1` on the unit\'s regime', 'is an overflow, or a page that was not mapped, not a hang',
                    'expected near 68 lines', 'follows the first payload\'s `PAYLOAD VERIFY=OK` and precedes its `PAYLOAD CALL`', 'The staged runner is built from the committed tree with its own stamp',
                    'golden SHA-256 of its text', '`stray_reads`, none allowed', 'a refusal here is plausible and benign',
                    # v3.1: what a refusal writes, the scanner, the key ATTR=, and the record's N6 and N7
                    'writes no device and leaves no descriptor in place, except that `CHECK_FAILED` wrote one',
                    'no device was written and no descriptor is left in place, except that `CHECK_FAILED` wrote one and undid it',
                    'the scanner is literal-aware, so a comment marker inside a string hides nothing', 'a review tripwire, not the identity of what runs',
                    'four for `TABLE_NOT_RAM` (`TABLE`, `TYPE`, `LEVEL`, `ATTR`)', '`ATTR=` is the MAIR byte on `TEMPLATE` and its refusals, the EFI attribute word on `TABLE_NOT_RAM`',
                    'the stamp of point 5 as the identity of what runs', 'a review tripwire, not an identity', 'A `TABLE_NOT_RAM` refusal is a likely first outcome',
                    'relaxing the RAM rule is a new review')
# What the document must no longer say: a refusal "writes nothing" is false for CHECK_FAILED (written and undone) and ROLLBACK_FAILED (UNSAFE).
FORBIDDEN_PHRASES = ('A refusal of the step wrote nothing', 'every refusal writes nothing', '(nothing was written; smmuprobe')
# A claim about the unit that is not a measurement must carry one of these labels within 250 characters.
LABELLED_CLAIMS = (('that EL2\'s stage 1 has no entry for it', ('OBSERVED',)), ('is whatever the template', ('INFERRED', 'OBSERVED', 'UNKNOWN')),
                   ('Whether a watchdog resets a hung unit', ('UNKNOWN', 'INFERRED')), ('that this is enough to keep the page out of speculation', ('INFERRED',)),
                   ('Nothing unmaps the page', ('UNIMPLEMENTED',)), ('the level-3 table page is writable and ordinary memory on the unit', ('UNKNOWN',)),
                   ('The Wi-Fi and the SSD\'s stream both go through the same PCIe SMMU', ('INFERRED',)),
                   ('describes the unit\'s RAM truthfully', ('INFERRED',)), ('Which EFI type the unit\'s table pages have', ('UNKNOWN',)),
                   ('Whether the one poll for an SError works', ('UNKNOWN',)), ('a plain read plausible', ('INFERRED', 'VERIFIED')),
                   ('do no harm is INFERRED', ('INFERRED',)), ('EL3 may take an SError itself', ('UNKNOWN',)), ('expected near 68 lines', ('INFERRED',)),
                   ('`REFS=0/0/1` on the unit\'s regime', ('INFERRED',)), ('the buffer is the runner\'s own allocation', ('INFERRED',)))
MACHINE = re.compile('|'.join(['/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/', '/t' + 'mp/']) + r'|\.loc' + r'al\b|\bsae' + r'ed\b|host' + r'name|' +
                     r'\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', re.I)


def squash(text):
    return ' '.join(text.split())


def section(text, start, end):
    a, b = text.find(start), text.find(end)
    return text[a:b] if 0 <= a < b else ''


def slug(heading):
    heading = re.sub(r'[`*_]', '', heading.strip().lower())
    return re.sub(r'\s', '-', re.sub(r'[^\w\s-]', '', heading))


def anchors(path):
    return {slug(m.group(2)) for m in re.finditer(r'^(#+)\s+(.*)$', path.read_text(encoding='utf-8'), re.M)}


def source_facts():
    header = HEADER.read_text(encoding='utf-8')
    logic = LOGIC.read_text(encoding='utf-8')
    host = HOST_TEST.read_text(encoding='utf-8')
    scan = SCAN_TEST.read_text(encoding='utf-8')
    world = WORLD.read_text(encoding='utf-8')
    page = re.search(r'good_page\[\] = \{(.*?)\};', host, re.S).group(1)
    return {
        'constants': dict(re.findall(r'#define Q1N1_SMMUMAP_(PAGE_PA|TEMPLATE_PA|TTBR0_EL2) UINT64_C\((0x[0-9A-Fa-f]+)\)', header)),
        'wait': re.search(r'#define Q1N1_SMMUMAP_WAIT_S (\d+)u', header).group(1),
        'reasons': [n for n in re.findall(r'case Q1N1_SMMUMAP_R_(\w+): return', logic) if n != 'NONE'],
        # The line after the chain is begun with a choice of two literals, so its kind is named from them.
        'kinds': re.findall(r'begin\(&line, "([A-Z ]+)"\)', logic) + re.findall(r'begin\(&line, found \? "(SERROR)=FOUND" : "SERROR=NONE"\)', logic),
        'page': re.findall(r'"(PAYLOAD SMMUMAP [^"]*)"', page),
        'most_lines': int(re.search(r'w->nlines > 1 && w->nlines <= (\d+)', world).group(1)),
        'spec_name': re.search(r'\{"(\w+)", Q1N1_SMMUMAP_PAGE_PA', logic).group(1),
        'fuzz': int(re.search(r'for \(n = 0; n < (\d+); n\+\+\)', host).group(1)),
        'suites': len(re.findall(r'\{"\w+", suite_\w+\}', host)) + len(re.findall(r'\{"\w+", suite_\w+\}', scan)),
        'mutants': len(mutant_module.MUTANTS),
        'world': world,
    }


def problems(doc, runner_doc=None, facts=None):
    """What is wrong with the document, as a list (none: it is the checked one)."""
    facts = facts or source_facts()
    bad = []
    flat = squash(doc)
    if doc.splitlines()[0] != '<!-- SPDX-License-Identifier: MIT -->':
        bad.append('the licence line is not first')
    if len(doc.encode('utf-8')) >= 50 * 1024 or len(doc.splitlines()) >= 1500:
        bad.append('the document is oversized')
    if not all(ord(c) < 128 for c in doc):
        bad.append('a character outside ASCII')
    for number, line in enumerate(doc.splitlines(), 1):
        if MACHINE.search(line):
            bad.append(f'a machine identifier on line {number}')
    # constants
    table = section(doc, '| Constant | Value |', 'The registers of the regime')
    for name, value in facts['constants'].items():
        if not re.search(rf'`Q1N1_SMMUMAP_{name}` \| `{re.escape(value)}`', table):
            bad.append(f'constant {name} is not {value} in the table')
    if f'| `Q1N1_SMMUMAP_WAIT_S` | {facts["wait"]} |' not in table:
        bad.append('the wait is not the header\'s')
    # the printed page, line for line
    block = section(doc, '<!-- smmumap-page -->', '<!-- /smmumap-page -->')
    if re.findall(r'^PAYLOAD SMMUMAP .*$', block, re.M) != facts['page']:
        bad.append('the page block is not the host program\'s good page')
    # the line table: every kind the logic begins, and the refusal row
    lines = section(doc, '<!-- smmumap-lines -->', '<!-- /smmumap-lines -->')
    for kind in facts['kinds']:
        if f'`PAYLOAD SMMUMAP {kind}' not in lines:
            bad.append(f'line {kind} is not in the line table')
    if '`PAYLOAD SMMUMAP REFUSED=<NAME>`' not in lines:
        bad.append('no refusal row in the line table')
    most = {9: 'nine', 10: 'ten'}.get(facts['most_lines'], str(facts['most_lines']))
    if f'at most {most} lines in a run' not in flat or f'`LINES_MAX={facts["most_lines"]}`' not in flat:
        bad.append('the most lines is not the host test\'s')
    # the outcomes: one row per reason, and the rows of the brief
    outcomes = section(doc, '<!-- smmumap-outcomes -->', '<!-- /smmumap-outcomes -->')
    for name in facts['reasons']:
        if f'REFUSED={name}' not in outcomes:
            bad.append(f'reason {name} has no row in the outcome table')
    for phrase in OUTCOME_PHRASES:
        if phrase not in outcomes and phrase not in squash(doc[doc.find('<!-- /smmumap-outcomes -->'):doc.find('## Hazards')]):
            bad.append(f'the outcome table lacks: {phrase}')
    rows = [r for r in outcomes.splitlines() if r.startswith('| ') and 'What is on the page' not in r and not r.startswith('| ---')]
    if len(rows) < len(facts['reasons']) + 4 or any(r.count('|') != 5 for r in rows):
        bad.append('the outcome table is short or has a ragged row')
    # sentences, labels
    for phrase in REQUIRED_PHRASES:
        if phrase not in doc and squash(phrase) not in flat:
            bad.append(f'missing: {phrase}')
    for phrase in FORBIDDEN_PHRASES:
        if squash(phrase) in flat:
            bad.append(f'the document still says: {phrase}')
    for label in LABELS:
        if label not in doc:
            bad.append(f'label {label} is not used')
    for needle, labels in LABELLED_CLAIMS:
        at = flat.find(squash(needle))
        if at < 0:
            bad.append(f'missing claim: {needle}')
        elif not any(label in flat[max(0, at - 250):at + 250 + len(needle)] for label in labels):
            bad.append(f'the claim "{needle}" carries none of {labels}')
    # the numbers of the text are the source's and the tests'
    words = {10: 'ten', 11: 'eleven', 12: 'twelve', 13: 'thirteen', 14: 'fourteen', 15: 'fifteen', 16: 'sixteen', 17: 'seventeen', 18: 'eighteen', 19: 'nineteen', 20: 'twenty'}
    if f'{words.get(facts["suites"], "?")} suites' not in flat:
        bad.append('the number of suites is not the host program\'s')
    if f'{facts["fuzz"]:,} corrupted worlds' not in flat:
        bad.append('the number of fuzz worlds is not the host program\'s')
    if re.findall(r'(\d+) seeded bugs', flat) != [str(facts['mutants'])]:
        bad.append('the number of seeded bugs is not the mutant list\'s')
    # the scan's bound is the arithmetic of its loops, and the host program checks the same total (4 + 4 for the walks, 2,047, 1 for the re-read)
    scan = re.search(r'at most ([\d,]+) loads \(511 \+ 3 x 512; ([\d,]+) on the unit\'s regime: 511 \+ 32 \+ 512 \+ 512\)', flat)
    if not scan or [int(g.replace(',', '')) for g in scan.groups()] != [511 + 3 * 512, 511 + 32 + 512 + 512]:
        bad.append('the scan\'s bound is not the arithmetic of its loops')
    if f'w->reads <= {4 + 4 + 511 + 3 * 512 + 1}u' not in facts['world']:
        bad.append('the host model\'s bound on the loads is not the document\'s')
    if runner_doc is not None and f'{facts["mutants"]} seeded bugs' not in runner_doc:
        bad.append('the runner\'s document has another number of seeded bugs')
    # the chain arithmetic
    budget = section(doc, '<!-- smmumap-chain-budget -->', '<!-- /smmumap-chain-budget -->')
    rows = re.findall(r'\| .*? \| \((\d+) \+ 1\) \+ 3( x (\d+))? \+ ((?:\d+ \+ )*\d+) = (\d+) \| (yes|no) \| (yes|no) \|', budget)
    if len(rows) != 3:
        bad.append('the chain table does not have its three rows')
    for files, _, payloads, rest, total, fits89, fits60 in rows:
        files, payloads = int(files), int(payloads or 1)
        parts = [int(x) for x in rest.split(' + ')]
        want = files + 1 + 3 * payloads + sum(parts)
        if want != int(total) or (int(total) <= 89) != (fits89 == 'yes') or (int(total) <= 60) != (fits60 == 'yes'):
            bad.append(f'the chain row {files} files, {payloads} payloads says {total}, the arithmetic says {want}')
        if facts['most_lines'] not in parts:
            bad.append('a chain row does not carry the step\'s most lines')
    # the build recipe and the digests
    recipe = section(doc, '```\nmake -f', '```\n\n`SMMUMAP=1` without')
    for needle in ('SP11=1', 'PAYLOAD=1', 'SMMUMAP=1', 'payload-runner', 'SP11_BUILD_STAMP=A9F00F9CCBB5', '/Brepro', 'SP11_USB_TABLE_C=', 'SP11_STAGE_TABLE_C='):
        if needle not in recipe:
            bad.append(f'the recipe lacks {needle}')
    digests = section(doc, '<!-- smmumap-digests -->', '<!-- /smmumap-digests -->')
    found = re.findall(r'\| ([\d,]+) B \| `([0-9a-f]{64})` \|', digests)
    if len(found) != 2 or found[0][1] != PINNED_RUNNER_SHA256 or found[0][0] != '776,192' or found[0][1] == found[1][1]:
        bad.append('the digest table is not the pinned runner and the gate-on runner')
    if found and any(int(size.replace(',', '')) % 512 for size, _ in found):
        bad.append('a runner size is not a multiple of the 512-byte PE file alignment')
    # links and anchors, and the commands the tests table names
    for target, anchor in re.findall(r'\]\(([A-Za-z0-9_.-]+\.md)(?:#([\w-]+))?\)', doc) + [('SP11-PAYLOAD-SMMUMAP.md', a) for a in re.findall(r'\]\(#([\w-]+)\)', doc)]:
        path = DOCS / target
        if not path.is_file():
            bad.append(f'link to a missing file {target}')
        elif anchor and anchor not in anchors(path if target != 'SP11-PAYLOAD-SMMUMAP.md' else DOC):
            bad.append(f'anchor #{anchor} is not a heading of {target}')
    for command in re.findall(r'`python3 (tools/[\w.-]+\.py)`', doc):
        if not (ROOT / command).is_file():
            bad.append(f'the tests table names a missing file {command}')
    # the Makefile says what the document says it says
    makefile = MAKEFILE.read_text(encoding='utf-8')
    for needle in ('SMMUMAP ?= 0', 'SMMUMAP=1 needs PAYLOAD=1', '-DQ1N1_SP11_SMMUMAP=1'):
        if needle not in makefile:
            bad.append(f'the Makefile lacks {needle}')
    if runner_doc is not None:
        if 'SP11-PAYLOAD-SMMUMAP.md#tests' not in runner_doc:
            bad.append('the runner\'s document does not point here')
        cap = lib.DOC_SIZE_CAPS.get('SP11-PAYLOAD.md', 50 * 1024)
        if len(runner_doc.encode('utf-8')) > cap or cap % 512:
            bad.append('the runner\'s document is over its raised cap, or the cap is not a multiple of 512')
    return bad


# Mistakes planted in the document: each check above must find its own.
SEEDED = [
    ('a-wrong-page-address', '| `Q1N1_SMMUMAP_PAGE_PA` | `0x15400000` |', '| `Q1N1_SMMUMAP_PAGE_PA` | `0x15410000` |', 'PAGE_PA'),
    ('a-wrong-root', '| `Q1N1_SMMUMAP_TTBR0_EL2` | `0xA7F2E000` |', '| `Q1N1_SMMUMAP_TTBR0_EL2` | `0xA7F2F000` |', 'TTBR0_EL2'),
    ('a-wrong-wait', '| `Q1N1_SMMUMAP_WAIT_S` | 8 |', '| `Q1N1_SMMUMAP_WAIT_S` | 7 |', 'wait'),
    ('a-wrong-page-line', 'DONE MAPPED=1 STORES=1\n```', 'DONE MAPPED=1 STORES=2\n```', 'good page'),
    ('a-missing-reason-row', '| `REFUSED=TABLE_SHARED TABLE= LEVEL=` |', '| `REFUSED=TABLE_SHARD TABLE= LEVEL=` |', 'TABLE_SHARED has no row'),
    ('a-missing-line-kind', '| `PAYLOAD SMMUMAP CHECK` |', '| `PAYLOAD SMMUMAP CHEK` |', 'CHECK is not in the line table'),
    ('no-stop-row', 'then `PAYLOAD CHAIN STOPPED INDEX=<n> REASON=SMMUMAP`', 'then nothing', 'CHAIN STOPPED'),
    ('no-put-back-row', '`REFUSED=CHECK_FAILED UNDONE=1` (after `CHECK`)', '`REFUSED=CHECK_FAILED` (after `CHECK`)', 'UNDONE=1'),
    ('no-recovery', 'FORCE OFF', 'power off', 'FORCE OFF'),
    ('no-daifa-sentence', 'q1n1 keeps `DAIF.A` masked', 'q1n1 masks interrupts', 'q1n1 keeps `DAIF.A` masked'),
    ('no-serror-anywhere', 'caught nor printed', 'seen', 'neither caught nor printed', 'all'),
    ('no-a1-precedent', 'boots 16, 17 and 19 went dark', 'boots went dark', 'boots 16, 17 and 19'),
    ('a-wrong-budget', '(2 + 1) + 3 x 2 + 10 + 34 + 36 = 89', '(2 + 1) + 3 x 2 + 10 + 34 + 36 = 88', 'arithmetic says 89'),
    ('a-wrong-fit', '= 119 | no | no |', '= 119 | yes | no |', 'arithmetic says 119'),
    ('a-wrong-most-lines', 'at most ten lines in a run', 'at most nine lines in a run', 'most lines'),
    ('a-short-digest', '`9e9579e3cbc02b34759c8b5d9651dc0f8a1ff1356e42442dac6e621d2f5ad6db`', '`9e9579e3cbc02b34759c8b5d9651dc0f8a1ff1356e42442dac6e621d2f5ad6d`', 'digest table'),
    ('the-pinned-digest-is-changed', '`c20579093ec7b1506faca3c0d33520561716510d7932ac1c9d340f432c88bf6e`', '`c20579093ec7b1506faca3c0d33520561716510d7932ac1c9d340f432c88bf6f`',
     'digest table'),
    ('an-odd-runner-size', '787,968 B', '787,969 B', 'multiple of the 512'),
    ('a-wrong-mutant-count', '162 seeded bugs, each', '161 seeded bugs, each', 'seeded bugs'),
    ('a-wrong-fuzz-count', '6,000 corrupted worlds', '5,000 corrupted worlds', 'fuzz worlds'),
    ('a-wrong-suite-count', 'eighteen suites', 'seventeen suites', 'number of suites'),
    ('a-recipe-without-the-gate', 'PAYLOAD=1 SMMUMAP=1 SP11_BUILD_STAMP', 'PAYLOAD=1 SP11_BUILD_STAMP', 'recipe lacks SMMUMAP=1'),
    ('a-broken-anchor', '[below](#the-publication)', '[below](#the-publicatio)', 'anchor #the-publicatio'),
    ('a-broken-link', '(SP11-PAYLOAD-SMMUPROBE.md#what-each-outcome-means)', '(SP11-PAYLOAD-SMMUPROBE.md#what-each-outcome-mean)', 'anchor #what-each-outcome-mean'),
    ('a-machine-identifier', 'the same box as', 'the same box at /Us' + 'ers/x as', 'machine identifier'),
    ('a-claim-without-its-label', 'that this is enough to keep the page out of speculation is INFERRED, not checked here', 'that this is enough to keep the page out of speculation, not checked here',
     'carries none of'),
    ('no-unimplemented-label', 'UNIMPLEMENTED', 'UNDONE', 'label UNIMPLEMENTED', 'all'),
    ('the-model-is-the-unit', "The tables are the model's, an invention", 'The tables are the unit\'s', 'an invention'),
    ('no-device-nGnRE-disclosure', '**`MAIR_EL2` has no Device-nGnRE entry**', '`MAIR_EL2` has a Device-nGnRE entry', 'no Device-nGnRE entry'),
    ('hardware-claimed', 'EXPERIMENTAL; hardware NOT RUN', 'EXPERIMENTAL', 'hardware NOT RUN'),
    # what the step added: the memory-map check, the scan, the line after the chain, the hook's place, the PAR bits, the stamp
    ('no-table-line-row', '| `PAYLOAD SMMUMAP TABLE` |', '| `PAYLOAD SMMUMAP TABL` |', 'TABLE is not in the line table'),
    ('no-serror-line-row', '| `PAYLOAD SMMUMAP SERROR=NONE` or `SERROR=FOUND` |', '| `PAYLOAD SMMUMAP SEROR=NONE` or `SEROR=FOUND` |', 'SERROR is not in the line table'),
    ('no-ram-reason-row', '| `REFUSED=TABLE_NOT_RAM TABLE= TYPE= LEVEL= ATTR=` |', '| `REFUSED=TABLE_NOT_RA TABLE= TYPE= LEVEL= ATTR=` |', 'TABLE_NOT_RAM has no row'),
    ('no-scan-fault-row', '| `REFUSED=SCAN_FAULT AT= LEVEL=` |', '| `REFUSED=SCAN_FAUL AT= LEVEL=` |', 'SCAN_FAULT has no row'),
    ('no-hash-stop-row', 'REASON=HASH_AT_EL2', 'REASON=HASH', 'REASON=HASH_AT_EL2', 'all'),
    ('no-serror-found-row', 'SERROR=FOUND SYNDROME= PENDING= BEFORE=', 'SERROR=FOUND SYNDROME= PENDING=', 'SERROR=FOUND SYNDROME= PENDING= BEFORE=', 'all'),
    ('ptw-and-s-are-confused', '`PTW` is bit 8 and `S` bit 9 of `PAR_EL1`', '`S` is bit 8 of `PAR_EL1`', 'PTW'),
    ('no-hook-position', 'right after the first payload\'s own check passed and before its `PAYLOAD CALL`', 'before any payload is checked', 'right after the first payload'),
    ('no-pre-verify-claim', 'calls **no** payload', 'calls the first payload', 'calls **no** payload'),
    ('no-stamp-paragraph', 'its `BUILD` line would read `A9F00F9CCBB5`', 'its `BUILD` line would be the same', 'its `BUILD` line would read'),
    ('the-stamp-claim-is-dropped', '**The stamp.**', 'The stamp.', '**The stamp.**'),
    ('no-reread-sentence', 'is read once more just before the store', 'is read when it is read', 'is read once more just before the store'),
    ('no-structural-ram-claim', 'step\'s own loads and stores, by construction', 'step\'s own loads and stores', 'no device is read or written'),
    ('the-budget-has-a-margin', 'with no margin', 'with a margin', 'with no margin'),
    ('no-serror-scope', 'The runner catches or clears nothing else', 'The runner catches things', 'catches or clears nothing else'),
    ('the-third-party-map-is-called-observed', 'a third-party report from another SoC', 'an observation of this unit', 'third-party report'),
    ('the-poll-claim-is-dropped', 'Whether the one poll for an SError works', 'Whether the SError', 'missing claim'),
    ('a-wrong-page-table-line', 'TABLE VALID=2 REFS=0/0/1\nPAYLOAD SMMUMAP STORE', 'TABLE VALID=3 REFS=0/0/1\nPAYLOAD SMMUMAP STORE', 'good page'),
    # v3: the proof before every load, the scan without a skip, the line after the chain as it is, the hang rule, and what a record says
    ('a-path-table-is-skipped', '**No path table is skipped**', 'A path table that is not RAM is skipped', 'No path table is skipped'),
    ('a-wrong-scan-bound', 'at most 2,047 loads', 'at most 2,100 loads', 'bound is not the arithmetic'),
    ('a-wrong-regime-scan-bound', '1,567 on the unit\'s regime', '1,568 on the unit\'s regime', 'bound is not the arithmetic', 'all'),
    ('found-is-attributed-to-smmuprobe', '**A record must not conclude from `FOUND` alone**', 'A record may conclude from `FOUND`', 'must not conclude from'),
    ('found-is-not-scoped', 'raised by a payload of the chain (nvmesnap or smmuprobe) or later', 'raised by smmuprobe', 'raised by a payload of the chain', 'all'),
    ('before-is-overclaimed', '`BEFORE=1` separates only the step\'s own past', '`BEFORE=1` separates every other cause', 'separates only the step', 'all'),
    ('none-is-error-free', '**It does not mean the read was error-free**', 'It means the read was error-free', 'does not mean the read was error-free'),
    ('ea-is-not-unknown', '`SCR_EL3.EA` is UNKNOWN on this unit', '`SCR_EL3.EA` is set on this unit', 'SCR_EL3.EA'),
    ('the-poll-does-not-consume', '**The poll consumes what it finds**', 'The poll only looks', 'The poll consumes'),
    ('no-hang-rule-after-the-chain', 'neither for two minutes is a hang (the poll can hang)', 'neither is a hang', 'neither for two minutes'),
    ('no-record-refusal-statement', '**Every refusal means no experiment was made**', 'A refusal is an experiment', 'Every refusal means no experiment'),
    ('a-wrong-refs-expectation', '`REFS=0/0/1` on the unit\'s regime', '`REFS=0/0/0` on the unit\'s regime', 'REFS=0/0/1'),
    ('a-missing-serror-line-is-a-hang', 'that was not mapped, not a hang.**', 'that was not mapped, a hang.**', 'not a hang'),
    ('the-budget-guess-has-no-label', 'plus the step\'s ten at most: INFERRED, not measured for this chain', 'plus the step\'s ten at most', 'expected near 68 lines'),
    ('no-block-position', 'follows the first payload\'s `PAYLOAD VERIFY=OK` and precedes its `PAYLOAD CALL`', 'follows nothing', 'follows the first payload'),
    ('the-staged-stamp-is-the-pinned-one', 'The staged runner is built from the committed tree with its own stamp', 'The staged runner is the gate-on row', 'with its own stamp'),
    ('no-glue-digest', 'golden SHA-256 of its text', 'a list of names', 'golden SHA-256'),
    ('no-stray-reads-pin', '`stray_reads`, none allowed', 'a count', 'stray_reads', 'all'),
    ('a-refusal-is-not-benign', 'a refusal here is plausible and benign', 'a refusal here is a failure', 'plausible and benign'),
    ('no-hang-row', 'after the last `PAYLOAD DONE`, no `SERROR` line and no ticking uptime for two minutes', 'after the last `PAYLOAD DONE`, nothing', 'no ticking uptime for two minutes'),
    ('no-overflow-row', 'but there is no `SERROR` line', 'but there is a `SERROR` line', 'but there is no `SERROR` line'),
    # v3.1: what a refusal writes (MINOR 2), the key ATTR= (OPTIONAL 3), N6 and N7, and the scanner claim
    ('a-refusal-writes-nothing-again', 'every refusal writes no device and leaves no descriptor in place', 'every refusal writes nothing', 'still says: every refusal writes nothing'),
    ('where-it-runs-says-nothing-was-written', 'A refusal of the step writes no device and leaves no descriptor in place', 'A refusal of the step wrote nothing', 'still says: A refusal of the step wrote nothing'),
    ('n1-says-nothing-was-written', 'no device was written and no descriptor is left in place, except that', 'nothing was written, except that', 'no device was written and no descriptor is left in place'),
    ('n6-makes-the-digest-the-identity', 'a review tripwire, not an identity', 'the identity', 'a review tripwire, not an identity'),
    ('n6-drops-the-stamp', 'the stamp of point 5 as the identity of', 'nothing as the identity of', 'the stamp of point 5'),
    ('n7-calls-the-refusal-unlikely', 'is a likely first outcome', 'is an unlikely first outcome', 'is a likely first outcome'),
    ('n7-relaxes-the-rule', 'relaxing the RAM rule is a new review, not an edit', 'the RAM rule may be relaxed', 'relaxing the RAM rule is a new review'),
    ('attr-has-one-meaning', '`ATTR=` is the MAIR byte on `TEMPLATE` and its refusals, the EFI attribute word on `TABLE_NOT_RAM`', '`ATTR=` is the MAIR byte', '`ATTR=` is the MAIR byte on `TEMPLATE` and its refusals'),
    ('refused-carries-two-numbers', 'four for `TABLE_NOT_RAM` (`TABLE`, `TYPE`, `LEVEL`, `ATTR`)', 'two for `TABLE_NOT_RAM`', 'four for `TABLE_NOT_RAM`'),
    ('the-scanner-claim-is-dropped', 'the scanner is literal-aware, so a comment marker inside a string hides nothing', 'the scanner strips comments', 'the scanner is literal-aware'),
    ('the-digest-is-the-identity', 'a review tripwire, not the identity of what runs', 'the identity of what runs', 'a review tripwire, not the identity of what runs'),
]


class SmmumapDoc(unittest.TestCase):
    doc = DOC.read_text(encoding='utf-8')
    runner_doc = RUNNER_DOC.read_text(encoding='utf-8')

    def test_the_document_is_right(self):
        self.assertEqual(problems(self.doc, self.runner_doc), [])

    def test_each_seeded_mistake_is_found_by_its_own_check(self):
        facts = source_facts()
        for name, old, new, expected, *every in SEEDED:
            with self.subTest(mistake=name):
                if not every:
                    self.assertEqual(self.doc.count(old), 1, f'the needle of {name} occurs {self.doc.count(old)} times')
                else:
                    self.assertGreaterEqual(self.doc.count(old), 1)
                found = problems(self.doc.replace(old, new), self.runner_doc, facts)
                self.assertTrue(any(expected in p for p in found), f'{name}: wanted a problem with "{expected}", got {found}')

    def test_the_host_models_bound_on_the_loads_is_the_documents(self):
        facts = dict(source_facts())
        self.assertFalse(any('host model' in p for p in problems(self.doc, self.runner_doc, facts)))
        facts['world'] = facts['world'].replace('w->reads <= 2056u', 'w->reads <= 2100u')
        self.assertTrue(any('host model' in p for p in problems(self.doc, self.runner_doc, facts)))

    def test_the_runners_index_row_points_here_and_the_cap_is_a_multiple_of_512_that_holds_the_document(self):
        self.assertIn('SP11-PAYLOAD-SMMUMAP.md#tests', self.runner_doc)
        size, cap = len(self.runner_doc.encode('utf-8')), lib.DOC_SIZE_CAPS['SP11-PAYLOAD.md']
        self.assertLessEqual(size, cap)
        self.assertEqual(cap % 512, 0)
        self.assertLess(cap - size, 512 + 512, 'the cap was raised by more than the row needed')

    def test_the_series_documents_that_this_one_leans_on_say_what_it_says_they_say(self):
        smmuprobe = (DOCS / 'SP11-PAYLOAD-SMMUPROBE.md').read_text(encoding='utf-8')
        self.assertIn('faulted at EL2 in two boots', smmuprobe)
        self.assertIn('## What each outcome means', smmuprobe)
        self.assertIn('SMMU_PAGE_UNMAPPED', smmuprobe)
        entry = (UEFI / 'entry.S').read_text(encoding='utf-8')
        self.assertIn('msr daifset, #15', entry)
        self.assertIn('MAP SMMU=FAULT=0X7:TRANS_L3', HEADER.read_text(encoding='utf-8'))

    def test_the_header_names_the_documents_evidence(self):
        header = HEADER.read_text(encoding='utf-8')
        for needle in ('docs/SP11-PAYLOAD-SMMUMAP.md', 'hamoa.dtsi', 'TTBR0_EL2 0xA7F2E000', 'EXPERIMENTAL',
                       'A refusal leaves no descriptor in place (CHECK_FAILED wrote one and put the zero back, STORES=2; a put-back that'):
            self.assertIn(needle, header)
        self.assertNotIn('Every refusal below writes nothing', header)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
