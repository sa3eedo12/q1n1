#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The citations of the payload tsnap against the pinned reference copies (docs/SP11-PAYLOAD-TSNAP.md).

    TSNAP_REFS_DIR=<directory with the five pinned files> python3 tools/test-q1n1-sp11-payload-tsnap-refs.py

The copies are not in the repository: `hamoa.dtsi` is the one the Snapintosh tree pins (docs/SP11-STICK-LOG.md section 10, under
$SNAPINTOSH_DIR/build/sp11-stick-log/refs/), the four Linux files of tools/sp11_payload_tsnap_refs.py are fetched from the commit that module names. The files are looked
for in $TSNAP_REFS_DIR, then build/tsnap-refs/ of this tree, then the Snapintosh refs directory. The class `Refs` SKIPs, never passes, when one is missing or has another digest;
the class `Ledger` needs no copy.

  Ledger     the document carries the digest, size and path of every pin and the commit; every `file:line` that payloads/tsnap.c, payloads/tsnap-regs.h and
             docs/SP11-PAYLOAD-TSNAP.md cite is in the ledger, and every ledger entry is cited somewhere
  Digests    each copy hashes to the digest and size of tools/sp11_payload_tsnap_refs.py
  Lines      every ledger entry: the cited lines of the copy hold the text the entry says (names and constants only), the lines the generic v2 driver's op set spans hold no
             calibration step, and whole files hold what the document says they never hold (CODE_OR_TEMP in tsens.c, a regmap read of an interrupt status field) or hold only once
             (the TRDY read, the watchdog bit read) or hold only inside given lines (CODE_OR_TEMP in tsens-v2.c: the field table and the ipq5332 init)
  DT facts   the numbers the document states about the device tree, by a parse of the pinned copy: four controllers with sixteen sensors, 50 thermal zones on 13, 11, 11 and
             15 ids of the four, the trips (50 critical at 115 C, 12 hot at 90 C, 8 passive at 95 C), and where the thermal-zones node ends
Seeded mistakes: a copy of every checked text with one citation moved by a line, one name changed or one digest wrong must be refused.
Hardware: NOT RUN. Evidence: EXPERIMENTAL (facts read in public sources)."""
import hashlib
import os
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_tsnap_refs as refs  # noqa: E402

DOC = ROOT / 'docs' / 'SP11-PAYLOAD-TSNAP.md'
CITING = (ROOT / 'payloads' / 'tsnap.c', ROOT / 'payloads' / 'tsnap-regs.h', DOC)


def find(name):
    candidates = []
    if os.environ.get('TSNAP_REFS_DIR'):
        candidates.append(Path(os.environ['TSNAP_REFS_DIR']) / name)
    candidates.append(ROOT / 'build' / 'tsnap-refs' / name)
    if os.environ.get('SNAPINTOSH_DIR'):
        candidates.append(Path(os.environ['SNAPINTOSH_DIR']) / 'build' / 'sp11-stick-log' / 'refs' / name)
    for path in candidates:
        if path.is_file():
            return path
    return None


def lines_of(path):
    return path.read_text(encoding='utf-8').splitlines()


def span_text(lines, span):
    first, last = refs.span_lines(span)
    return '\n'.join(lines[first - 1:last])


def status_fields(lines):
    """{name: (lsb, msb)} of the fields the driver declares for the status word of a sensor (REG_FIELD_FOR_EACH_SENSOR16 on TM_Sn_STATUS_OFF)."""
    found = {}
    for line in lines:
        match = re.search(r'REG_FIELD_FOR_EACH_SENSOR16\((\w+),\s*TM_Sn_STATUS_OFF,\s*(\d+),\s*(\d+)\)', line)
        if match:
            found[match[1]] = (int(match[2]), int(match[3]))
    return found


def header_constant(text, name):
    """The value of a plain `#define NAME <number, shifts and sums>` of the header."""
    found = re.search(rf'^#define {name} (.+?)(?:\s*/\*.*)?$', text, re.M)
    expression = re.sub(r'\b(0x[0-9a-fA-F]+|[0-9]+)u\b', r'\1', found.group(1))
    return eval(expression, {'__builtins__': {}})


def refuse(name, spans, lines):
    """The problems of a ledger ({span: [text]}) against the lines of a copy."""
    problems = []
    for span, texts in spans.items():
        held = span_text(lines, span)
        for text in texts:
            if text not in held:
                problems.append(f'{name}:{span} does not hold {text!r}')
    for (other, span), texts in refs.ABSENT.items():
        if other == name:
            for text in texts:
                if text in span_text(lines, span):
                    problems.append(f'{name}:{span} holds {text!r}')
    whole = '\n'.join(lines)
    for text in refs.ABSENT_IN_FILE.get(name, ()):
        if text in whole:
            problems.append(f'{name} holds {text!r}')
    for (other, text), count in refs.EXACTLY.items():
        if other == name and whole.count(text) != count:
            problems.append(f'{name} holds {text!r} {whole.count(text)} times, not {count}')
    for (other, text), allowed in refs.ONLY_IN.items():
        if other != name:
            continue
        for number, line in enumerate(lines, 1):
            if text in line and not any(refs.span_lines(span)[0] <= number <= refs.span_lines(span)[1] for span in allowed):
                problems.append(f'{name}:{number} holds {text!r} outside {allowed}')
    return problems


class Ledger(unittest.TestCase):
    """What needs no pinned copy: the document, the header and the source against the ledger."""

    def test_the_document_carries_every_pin(self):
        doc = DOC.read_text(encoding='utf-8')
        for name, (tree_path, digest, size) in refs.PINS.items():
            self.assertRegex(digest, r'^[0-9a-f]{64}$', name)
            self.assertIn(digest, doc, f'the document does not carry the digest of {name}')
            self.assertIn(tree_path, doc, f'the document does not name {tree_path}')
            self.assertIn(f'{size:,}', doc, f'the document does not carry the size of {name}')
        self.assertIn(refs.COMMIT, doc)

    def test_every_citation_is_in_the_ledger_and_every_entry_is_cited(self):
        cited = set()
        for path in CITING:
            found = refs.citations(path.read_text(encoding='utf-8'))
            self.assertTrue(found, f'{path.name} cites nothing')
            unchecked = sorted(found - refs.ledger_pairs())
            self.assertEqual(unchecked, [], f'{path.name} cites lines that the ledger does not check')
            cited |= found
        self.assertEqual(sorted(refs.ledger_pairs() - cited), [], 'a ledger entry nothing cites')

    def test_the_ledger_is_well_formed(self):
        self.assertLessEqual(set(refs.LEDGER), set(refs.PINS))
        for name, spans in refs.LEDGER.items():
            for span, texts in spans.items():
                first, last = refs.span_lines(span)
                self.assertTrue(1 <= first <= last, f'{name}:{span}')
                self.assertTrue(texts and all(texts), f'{name}:{span} says nothing')


class Refs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = {name: find(name) for name in refs.PINS}
        missing = [name for name, path in cls.path.items() if path is None]
        if missing:
            raise unittest.SkipTest(f'no pinned copy of {missing} (set TSNAP_REFS_DIR)')
        for name, path in cls.path.items():
            if hashlib.sha256(path.read_bytes()).hexdigest() != refs.PINS[name][1]:
                raise unittest.SkipTest(f'{path} is not the pinned copy of {name}')
        cls.lines = {name: lines_of(path) for name, path in cls.path.items()}

    def test_the_digests_and_sizes_are_the_pinned_ones(self):
        for name, (_, digest, size) in refs.PINS.items():
            data = self.path[name].read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest, name)
            self.assertEqual(len(data), size, name)

    def test_every_ledger_entry_holds_what_it_says(self):
        for name, spans in refs.LEDGER.items():
            self.assertEqual(refuse(name, spans, self.lines[name]), [], name)

    def test_a_citation_moved_by_a_line_is_refused(self):
        for name, spans in refs.LEDGER.items():
            for span in spans:
                first, last = refs.span_lines(span)
                moved = {f'{first + 1}-{last + 1}' if last != first else str(first + 1): spans[span]}
                self.assertTrue(refuse(name, moved, self.lines[name]), f'{name}:{span} moved by one line is still accepted')

    def test_a_changed_name_a_wrong_digest_and_a_calibration_step_are_refused(self):
        self.assertTrue(refuse('tsens-v2.c', {'14-17': ['SROT_HW_VER_OFFSET']}, self.lines['tsens-v2.c']))
        self.assertNotEqual(hashlib.sha256(self.path['tsens.c'].read_bytes() + b'\n').hexdigest(), refs.PINS['tsens.c'][1])
        lines = list(self.lines['tsens-v2.c'])
        lines[264] = '\t.calibrate\t= tsens_v2_calibration,'           # line 265, inside the generic v2 op set
        self.assertTrue(any('calibrate' in problem for problem in refuse('tsens-v2.c', {}, lines)))
        self.assertEqual(refuse('tsens-v2.c', {}, self.lines['tsens-v2.c']), [])

    def test_a_driver_that_names_the_format_bit_or_reads_trdy_twice_is_refused(self):
        lines = list(self.lines['tsens.c'])
        self.assertEqual(refuse('tsens.c', {}, lines), [])
        named = lines[:931] + ['\tregmap_field_write(priv->rf[CODE_OR_TEMP], 1);'] + lines[931:]
        self.assertTrue(any('CODE_OR_TEMP' in problem for problem in refuse('tsens.c', {}, named)))
        read_twice = lines[:835] + [lines[834]] + lines[835:]
        self.assertTrue(any('rf[TRDY]' in problem for problem in refuse('tsens.c', {}, read_twice)))
        status = lines[:931] + ['\tregmap_field_read(priv->rf[UP_INT_STATUS_0], &x);'] + lines[931:]
        self.assertTrue(any('UP_INT_STATUS' in problem for problem in refuse('tsens.c', {}, status)))
        third = self.lines['tsens-v2.c'] + ['\tregmap_field_write(priv->rf[CODE_OR_TEMP], 0);']
        self.assertTrue(any('CODE_OR_TEMP' in problem for problem in refuse('tsens-v2.c', {}, third)))

    def test_the_status_word_fields_are_the_headers_and_none_lies_above_bit_21(self):
        self.assertEqual(status_fields(self.lines['tsens-v2.c']), refs.STATUS_FIELDS)
        self.assertEqual(max(msb for _, msb in refs.STATUS_FIELDS.values()), 21, 'the sensor number of the unit\'s words (bits 26:22) is in no pinned field')
        header = (ROOT / 'payloads' / 'tsnap-regs.h').read_text(encoding='utf-8')
        value = {name: header_constant(header, name) for name in ('ST_TEMP_MASK', 'ST_CRIT_FLAGS', 'ST_VALID', 'ST_ID_SHIFT', 'ST_ID_MASK', 'ST_RESERVED_SHIFT')}
        low, high = refs.STATUS_FIELDS['LAST_TEMP']
        self.assertEqual(value['ST_TEMP_MASK'], (1 << (high + 1)) - (1 << low))
        self.assertEqual(value['ST_VALID'], 1 << refs.STATUS_FIELDS['VALID'][0])
        self.assertEqual(value['ST_CRIT_FLAGS'], 1 << refs.STATUS_FIELDS['CRITICAL_STATUS'][0] | 1 << refs.STATUS_FIELDS['MAX_STATUS'][0])
        # What the header checks beyond the driver's fields starts above them: the sensor number at bit 22, the reserved bits after the five-bit number.
        self.assertEqual(value['ST_ID_SHIFT'], refs.STATUS_FIELDS['VALID'][1] + 1)
        self.assertEqual(value['ST_RESERVED_SHIFT'], value['ST_ID_SHIFT'] + bin(value['ST_ID_MASK']).count('1'))

    def test_a_status_word_field_above_bit_21_in_the_driver_is_refused(self):
        lines = list(self.lines['tsens-v2.c'])
        at = next(i for i, line in enumerate(lines) if 'REG_FIELD_FOR_EACH_SENSOR16(VALID,' in line)
        added = lines[:at + 1] + ['\tREG_FIELD_FOR_EACH_SENSOR16(SENSOR_ID,      TM_Sn_STATUS_OFF, 22,  26),'] + lines[at + 1:]
        self.assertNotEqual(status_fields(added), refs.STATUS_FIELDS)
        moved = [line.replace('TM_Sn_STATUS_OFF, 21,  21', 'TM_Sn_STATUS_OFF, 20,  20') for line in lines]
        self.assertNotEqual(status_fields(moved), refs.STATUS_FIELDS)

    def test_the_board_device_tree_has_no_thermal_text(self):
        folder = Path(os.environ.get('SNAPINTOSH_DIR', '/nonexistent')) / 'build' / 'sp11-stick-log' / 'refs'
        board = [folder / 'x1-microsoft-denali.dtsi', folder / 'x1-el2.dtso']
        if not all(path.is_file() for path in board):
            raise unittest.SkipTest('the pinned board device trees are not under $SNAPINTOSH_DIR/build/sp11-stick-log/refs')
        for path in board:
            self.assertIsNone(re.search(r'(?i)tsens|thermal|sensor', path.read_text(encoding='utf-8')), path.name)

    def test_the_device_tree_facts(self):
        lines = self.lines['hamoa.dtsi']
        text = '\n'.join(lines)
        self.assertEqual(len(re.findall(r'^\t\ttsens\d: thermal-sensor@', text, re.M)), 4)
        self.assertEqual(text.count('#qcom,sensors = <16>;'), 4)
        # The thermal-zones node: its first and last line, by brace depth.
        start = next(i for i, line in enumerate(lines) if line.startswith('\tthermal_zones: thermal-zones {'))
        depth, end = 0, None
        for i in range(start, len(lines)):
            depth += lines[i].count('{') - lines[i].count('}')
            if depth == 0:
                end = i
                break
        self.assertEqual((start + 1, end + 1), (9123, 9915))
        zones, current = [], None
        for line in lines[start:end + 1]:
            node = re.match(r'\t\t(?:\w+: )?([\w-]+-thermal) \{', line)
            if node:
                current = {'name': node.group(1), 'sensor': None, 'trips': []}
                zones.append(current)
            sensor = re.search(r'thermal-sensors = <&tsens(\d) (\d+)>', line)
            if sensor and current:
                current['sensor'] = (int(sensor.group(1)), int(sensor.group(2)))
            temperature = re.search(r'temperature = <(\d+)>', line)
            if temperature and current:
                current['trips'].append([int(temperature.group(1)), None])
            kind = re.search(r'type = "(\w+)"', line)
            if kind and current and current['trips']:
                current['trips'][-1][1] = kind.group(1)
        self.assertEqual(len(zones), 50)
        per_block = {block: sorted(z['sensor'][1] for z in zones if z['sensor'][0] == block) for block in range(4)}
        self.assertEqual({block: (len(ids), ids[0], ids[-1]) for block, ids in per_block.items()}, {0: (13, 0, 12), 1: (11, 0, 10), 2: (11, 0, 10), 3: (15, 0, 14)})
        for ids in per_block.values():
            self.assertEqual(ids, list(range(len(ids))), 'the ids a zone reads are 0 up, with no gap')
        trips = {}
        for zone in zones:
            for temperature, kind in zone['trips']:
                trips[(kind, temperature)] = trips.get((kind, temperature), 0) + 1
        self.assertEqual(trips, {('critical', 115000): 50, ('hot', 90000): 12, ('passive', 95000): 8})
        names = {block: {z['sensor'][1]: z['name'] for z in zones if z['sensor'][0] == block} for block in range(4)}
        self.assertEqual(names[0][1], 'cpu0-0-top-thermal')
        self.assertEqual(names[0][11], 'mem-thermal')
        self.assertEqual(names[0][12], 'video-thermal')
        self.assertEqual([names[3][i] for i in (1, 4, 5, 12, 13, 14)], ['nsp0-thermal', 'nsp3-thermal', 'gpuss-0-thermal', 'gpuss-7-thermal', 'camera0-thermal', 'camera1-thermal'])
        self.assertEqual({z['name'] for z in zones if z['sensor'][0] == 3 and any(kind == 'passive' for _, kind in z['trips'])}, {f'gpuss-{i}-thermal' for i in range(8)})


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
