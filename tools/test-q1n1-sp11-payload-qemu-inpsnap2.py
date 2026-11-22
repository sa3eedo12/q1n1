#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The payload `inpsnap2` behind the runner, under QEMU's EDK2 shell (docs/SP11-PAYLOAD-INPSNAP2.md, docs/SP11-PAYLOAD-INPSNAP2-EVIDENCE.md).

    python3 tools/test-q1n1-sp11-payload-qemu-inpsnap2.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), lays two sticks out as the stick is laid out (`inpsnap2` alone and `state inpsnap2`) and boots QEMU's
EDK2 shell on each, with a real ExitBootServices and a real EL2 (the stick layout, the boot driver and the helpers are those of test-q1n1-sp11-payload-qemu.py).

QEMU has neither window the payload reads. The clock controller (0x00100000) and the QUP wrapper (0x00bc0000) lie in its flash, which reads back the firmware's own bytes where the firmware is and
zeros or ones in the padding after it, so every word the page prints under QEMU is the flash's and not a model of the unit's clocks: a word may be all ones (which ends the page, by design) and the
wrapper's gate opens or not as the flash's bytes say. The test does not pin those words. It reads the words the page printed and decides, by its OWN statement of the rules (written here from the
design note, not from the payload: the page's check is binascii.crc_hqx, the clock verdict and the wrapper's gate are re-derived below), what the page must show: the order of the blocks and lines, the check
of every line, the verdict of every clock word, whether the wrapper's word was read or gated and why, where the page stops after an all-ones word, the counters of the end line and that the runner's
counters agree. What that proves: the binary runs at EL2 behind the runner, uses only its ops, keeps its stores on its own stack (the runner would refuse a load destination outside it), announces every
block before its first load, gates the way the words say, ends at the first all-ones word, prints nothing outside the page font and never more than 24 lines. What it does not prove: anything about the unit's
words or whether the wrapper's window answers on it (UNKNOWN, hardware NOT RUN), an abort (QEMU's flash never aborts a load), or the guard on Oryon.

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image; the one test that hands the page the real binary printed to the host parser
(tools/sp11_inpsnap2_parse.py of the Snapintosh tree) SKIPs without SNAPINTOSH_DIR set to a main checkout that has it.
Evidence: EXPERIMENTAL (QEMU only); hardware NOT RUN. Writes only under build/sp11-payload-qemu-inpsnap2/."""
import binascii
import concurrent.futures
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
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


qemu = load_module('sp11_payload_qemu_base_for_inpsnap2', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-inpsnap2'
sha, script, manifest, Boot = qemu.sha, qemu.script, qemu.manifest, qemu.Boot
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'
PREFIX = 'PAYLOAD INPSNAP2 '
LEGEND = 'KEY=VALUE .ON .OFF .HW .ODD=CLOCK FAULT:6=ABORT SKIP=NOT READ K=LINE CRC16'
# The page by the design note: the blocks in order and the keys of each block's lines.
BLOCKS = (('GATE', (('MA0', 'SA0', 'CR0'), ('SE0', 'VT0', 'GV'))),
          ('RCG', (('DFS', 'DIV', 'CMD', 'CFG'), ('M', 'N', 'D'))),
          ('PLL', (('MODE', 'OP', 'ST'), ('L', 'AL', 'USR'))),
          ('LVL', (('LC0', 'LC1', 'LC2', 'LC3'), ('LC4', 'LC5', 'LC6', 'LC7'), ('LM0', 'LM1', 'LM2', 'LM3'), ('LM4', 'LM5', 'LM6', 'LM7'),
                   ('LN0', 'LN1', 'LN2', 'LN3'), ('LN4', 'LN5', 'LN6', 'LN7'))),
          ('QUP', (('VER',),)))
KEYS = [key for _, lines in BLOCKS for line in lines for key in line]
HWCG = {'MA0': 6, 'SA0': 7}              # the clocks with a hardware gating bit, and their vote bit in VT0
STATE = {'FAULT': 2, 'SKIP': 3, 'BUDGET': 4, 'NA': 0}
TOKEN = re.compile(r'^(?P<key>[A-Z][A-Z0-9]*)=(?P<value>FAULT:\d+|SKIP|BUDGET|NA|0X[0-9A-F]+|\d+)(?:\.(?P<clock>ON|OFF|HW|ODD))?$')


def parse_value(text):
    """(state, value) of a word as the page shows it: 1 a word, 2 an abort (its code), 3 not read (after an abort or an all-ones word), 4 the load cap, 0 `NA`."""
    if text.startswith('FAULT:'):
        return 2, int(text[6:])
    if text in STATE:
        return STATE[text], 0
    return 1, int(text, 16) if text.startswith('0X') else int(text)


def clock_verdict(word, hwcg):
    """The design note's reading of a branch clock word: running when CLK_OFF (bit 31) is clear or the NoC FSM (bits 30:28) says 2; all ones is no clock word; hardware gating only where the clock has the bit."""
    if word == 0xFFFFFFFF:
        return 'ODD'
    if not word >> 31 or (word >> 28) & 7 == 2:
        return 'ON'
    return 'HW' if hwcg and word >> 1 & 1 else 'OFF'


def line_check(words):
    """CRC-16/CCITT-FALSE of five bytes a word in order: the state, then the value least significant byte first."""
    data = b''.join(bytes([state]) + value.to_bytes(4, 'little') for state, value in words)
    return binascii.crc_hqx(data, 0xFFFF)


def wrapper_gate(words):
    """The wrapper's gate from the words of the page: 'OPEN', 'OFF' (a clock word that read says stopped) or 'ERR' (what it needs did not read or cannot be trusted)."""
    vote = words.get('VT0')
    off = unknown = False
    for key in ('MA0', 'SA0', 'CR0'):
        word = words.get(key)
        if word is None or word[0] != 1:
            unknown = True
            continue
        verdict = clock_verdict(word[1], key in HWCG)
        if verdict == 'HW':
            verdict = 'ODD' if vote is None or vote[0] != 1 else 'ON' if vote[1] >> HWCG[key] & 1 else 'OFF'
        off |= verdict == 'OFF'
        unknown |= verdict == 'ODD'
    if vote is None or vote[0] != 1 or vote[1] in (0, 0xFFFFFFFF):
        unknown = True
    return 'OFF' if off else 'ERR' if unknown else 'OPEN'


def chain_stick(entries):
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


class Inpsnap2Qemu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'lld-link', 'ld.lld', 'make', 'qemu-system-aarch64'):
            if not lib.have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        cls.firmware = qemu.helpers.find_firmware()
        if not cls.firmware:
            raise unittest.SkipTest('no EDK2 aarch64 firmware (set Q1N1_EDK2_CODE)')
        qemu.BUILD = BUILD
        shutil.rmtree(BUILD, ignore_errors=True)
        BUILD.mkdir(parents=True)
        out = BUILD / 'out'
        built = subprocess.run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j1', 'PAYLOAD=1']
                               + qemu.SP11_VARS + ['payload-runner', 'payloads'], cwd=ROOT, env=lib.ENV, capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError('PAYLOAD=1 build failed:\n' + built.stdout[-2000:] + built.stderr[-2000:])
        cls.runner = out / 'q1n1-payload.efi'
        cls.bins = {name: (out / 'payloads' / f'{name}.bin').read_bytes() for name in ('state', 'inpsnap2')}
        boots = [
            Boot('alone', chain_stick([('INPSNAP2.BIN', cls.bins['inpsnap2'])]), script(), marker='PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK '),
            Boot('after-state', chain_stick([('STATE.BIN', cls.bins['state']), ('INPSNAP2.BIN', cls.bins['inpsnap2'])]), script(), marker='PAYLOAD DONE INDEX=1 RETURN=0X0 STACK=OK '),
        ]
        # One emulator at a time: two boots in parallel doubled the memory this test needs for no gain.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            cls.runs = {boot.name: boot for boot in pool.map(lambda boot: qemu.run_boot(boot, cls.runner, cls.firmware), boots)}

    def after(self, name):
        text = self.runs[name].text
        self.assertIn(AFTER, text, f'{name}: the bounce was never confirmed; inspect {BUILD / (name + ".log")}')
        return text.split(AFTER, 1)[1]

    def lines(self, name, prefixes=('PAYLOAD ',)):
        return [line for line in self.after(name).split('\n') if line.startswith(prefixes)]

    def printed(self, name):
        return [line[len(PREFIX):] for line in self.lines(name) if line.startswith(PREFIX)]

    def done(self, name, index):
        found = [line for line in self.lines(name) if line.startswith(f'PAYLOAD DONE INDEX={index} ')]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def analyse(self, name):
        """The page of boot `name` against the design note's rules; returns what the end line must say: {loads, faults, skips, stop, words}."""
        page = self.printed(name)
        self.assertEqual(page[0], 'READ ONLY EL=2 STAGE=I0 CAP=44/24')
        self.assertEqual(page[1], LEGEND)
        end = page[-1]
        self.assertTrue(end.startswith('END '), page)
        words, order, stop = {}, [], None
        at = 2
        for block, lines in BLOCKS:
            if stop is not None:
                break
            self.assertEqual(page[at], f'NEXT {block}', f'the blocks are announced in the order of the design: {page[at:at + 2]}')
            at += 1
            if block == 'QUP':
                gate = wrapper_gate(words)
                if gate != 'OPEN':
                    self.assertEqual(page[at], f'QUP GATED {gate}', f'the wrapper must be gated {gate} by the words of the page')
                    at += 1
                    break
            for keys in lines:
                found = re.fullmatch(rf'{block} (.*) K=([0-9A-F]{{4}})', page[at])
                self.assertTrue(found, f'{block} line {page[at]!r}')
                tokens = [TOKEN.fullmatch(token) for token in found.group(1).split(' ')]
                self.assertTrue(all(tokens), page[at])
                self.assertEqual([t.group('key') for t in tokens], list(keys), page[at])
                line_words = []
                for token in tokens:
                    key, (state, value) = token.group('key'), parse_value(token.group('value'))
                    words[key] = (state, value)
                    line_words.append((state, value))
                    order.append(key)
                    if token.group('clock') is not None:
                        self.assertEqual(state, 1)
                        self.assertEqual(token.group('clock'), clock_verdict(value, key in HWCG), f'the verdict of {key}')
                    elif key in ('MA0', 'SA0', 'CR0', 'SE0'):
                        self.assertNotEqual(state, 1, f'a clock word that read carries its verdict: {page[at]}')
                self.assertEqual(int(found.group(2), 16), line_check(line_words), f'the check of {page[at]!r}')
                at += 1
                hit = next((key for key in keys if words[key] == (1, 0xFFFFFFFF)), None)
                if hit is not None:
                    stop = hit
                    self.assertTrue(all(words[key][0] == 3 for key in keys[keys.index(hit) + 1:]), f'after an all-ones word the rest of its line is not read: {page[at - 1]}')
                    break
        stops = [key for key in order if words[key] == (1, 0xFFFFFFFF)]
        self.assertEqual(stop, stops[0] if stops else None, 'the page ends after the first all-ones word and no other')
        self.assertEqual(at, len(page) - 1, f'nothing but the end line is left after the last block: {page[at:]}')
        loads = sum(1 for state, _ in words.values() if state in (1, 2))
        faults = sum(1 for state, _ in words.values() if state == 2)
        skips = sum(1 for state, _ in words.values() if state == 3)
        self.assertEqual(faults, 0, 'QEMU\'s flash never aborts a load')
        found = re.fullmatch(r'END LOADS=(\d+) FAULTS=(\d+) SKIPS=(\d+) BLK=(0X[0-9A-F]+|\d+) CUTS=(\d+) LINES=(\d+) STOP=(\w+)', end)
        self.assertTrue(found, end)
        self.assertEqual((int(found.group(1)), int(found.group(2)), int(found.group(3))), (loads, faults, skips), end)
        self.assertEqual(found.group(7), stop or 'NONE')
        self.assertEqual((int(found.group(5)), int(found.group(6))), (0, len(page)))
        self.assertLessEqual(len(page), 24)
        if stop is None and loads < len(KEYS):
            self.assertIn('QUP GATED', page[-2], 'a complete page without the wrapper word says why')
        return {'loads': loads, 'faults': faults, 'skips': skips, 'stop': stop, 'words': words, 'lines': len(page)}

    def test_it_runs_to_the_end_behind_the_runner_alone_and_after_state(self):
        for name, index in (('alone', 0), ('after-state', 1)):
            with self.subTest(boot=name):
                want = self.analyse(name)
                self.assertRegex(self.done(name, index), rf'^PAYLOAD DONE INDEX={index} RETURN=0X0 STACK=OK LOADS={want["loads"]} FAULTS=0 REFUSED=0 LINES={want["lines"]} DROPPED=0$')
                self.assertNotIn('SYNCHRONOUS EXCEPTION', self.runs[name].text)
        self.assertEqual(self.printed('alone'), self.printed('after-state'), 'the same flash, the same page, whether state ran before it or not')

    def test_the_page_stops_at_an_all_ones_word_or_reads_every_row_once(self):
        want = self.analyse('alone')
        if want['stop'] is None:
            gated = any(line.startswith('QUP GATED') for line in self.printed('alone'))
            self.assertEqual(want['loads'], len(KEYS) - 1 if gated else len(KEYS), 'every row of the table is read once, the wrapper word only behind its gate')
        else:
            self.assertEqual(want['loads'], KEYS.index(want['stop']) + 1, 'the loads end with the first all-ones word: every row before it was read once, none after')

    def test_it_prints_nothing_outside_the_page_font(self):
        for name in self.runs:
            for line in self.lines(name):
                self.assertIsNotNone(qemu.FONT_LINE.fullmatch(line), line)
                self.assertLessEqual(len(line), 100)

    def test_the_host_parser_reads_the_page_the_real_binary_printed(self):
        path = Path(os.environ.get('SNAPINTOSH_DIR', '/nonexistent')) / 'tools' / 'sp11_inpsnap2_parse.py'
        if not path.is_file():
            self.skipTest('no tools/sp11_inpsnap2_parse.py: set SNAPINTOSH_DIR to a main checkout that has it')
        parse = load_module('sp11_inpsnap2_parse_for_qemu', path)
        for name in self.runs:
            with self.subTest(boot=name):
                want = self.analyse(name)
                page = parse.parse_page(''.join(PREFIX + line + '\n' for line in self.printed(name)))
                seen = {key: ({'OK': 1, 'FAULT': 2, 'SKIP': 3}[word.state], word.value) for key, word in page.words.items()}
                self.assertEqual(seen, want['words'], 'the parser and this test read the same words from the same page')
                self.assertEqual(page.stop, want['stop'])

    def test_no_boot_changes_a_file_of_the_stick(self):
        for name, boot in self.runs.items():
            self.assertFalse(boot.changed, f'{name}: a file on the stick changed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
