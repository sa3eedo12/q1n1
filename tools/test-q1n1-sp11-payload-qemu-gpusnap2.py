#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The payload `gpusnap2` behind the runner, under QEMU's EDK2 shell (docs/SP11-PAYLOAD-GPUSNAP2.md, docs/SP11-PAYLOAD-GPUSNAP2-EVIDENCE.md).

    python3 tools/test-q1n1-sp11-payload-qemu-gpusnap2.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), lays two sticks out as the stick is laid out (`gpusnap2` alone and `state gpusnap2`) and boots
QEMU's EDK2 shell on each, with a real ExitBootServices and a real EL2 (the stick layout, the boot driver and the helpers are those of test-q1n1-sp11-payload-qemu.py).

QEMU has none of the seven windows the payload reads, and what each answers is the `virt` machine's: the two TSENS windows (0x0c2xxxxx) lie in its platform bus, where nothing is mapped,
the RSC and QFPROM windows (0x1752xxxx, 0x221cxxxx) in its PCIe MMIO range, GCC and GPUCC (0x001xxxxx, 0x03dxxxxx) in the flash, which reads back the firmware's own bytes where the
firmware is and zeros in the padding after it, and the command database (0x81c6xxxx) lies beyond the RAM the emulator was given, so the runner's memory map does not describe it. The words the
payload prints under QEMU are therefore not a model of the GPU, and whether the CFG AHB gate opens is the firmware's doing. The test does not pin those words. It reads the words the page printed
and decides, by its OWN statement of the rules (written here from the design note, not from the payload), which blocks the page must show as read and which as gated, how many loads the payload
must have made and how many of them aborted, which windows the END line must report as not read, and that the runner's counters agree. What that proves: the binary runs at EL2 behind the
runner, uses only its ops, keeps its stores on its own stack (the runner would refuse a load destination outside it), announces each block before its first load, gates the way the words say,
never reads the command database behind a map that does not describe it as reserved, turns a faulted load into FAULT:6, prints nothing outside the page font and never more than 34 lines. What it
does not prove: anything about the unit's windows (UNKNOWN, hardware NOT RUN), a block that answers (QEMU has none, apart from the flash's GCC word and the GPUCC words behind it), the reads of
the command database and the RSC (QEMU never opens those gates: only the host test does), or the guard on Oryon.

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image.
Evidence: EXPERIMENTAL (QEMU only); hardware NOT RUN. Writes only under build/sp11-payload-qemu-gpusnap2/."""
import concurrent.futures
import importlib.util
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


qemu = load_module('sp11_payload_qemu_base_for_gpusnap2', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-gpusnap2'
sha, script, manifest, Boot = qemu.sha, qemu.script, qemu.manifest, qemu.Boot
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'
PREFIX = 'PAYLOAD GPUSNAP2 '
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-GPUSNAP2-EVIDENCE.md'
LEGEND = 'KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=NOT TRUSTED NA=NOT READ -=NO VOTE TEMP=0.1 C'
BLOCKS = ('TSENS3', 'GCC', 'GPUCC', 'CMDDB', 'RSC2', 'QFPROM')
# What a window that is not there can answer, as the page shows a word: a faulted load, zeros, all ones.
ABSENT = {'FAULT:6', '0', '0XFFFFFFFF'}
GPUCC_LINES = ('AHB=', 'PLL0 ', 'PLL1 ', 'FFC=', 'CRC=', 'MEM=')
GPUCC_LOADS = 21
WORD = re.compile(r'^(?P<value>FAULT:\d+|0X[0-9A-F]+|\d+)(?:\.(?P<clock>ON|OFF|ODD))?$')


def normal(lines):
    """`lines` (without the prefix) as the document shows them: what depends on the flash's bytes or on the memory map of the emulator as a placeholder."""
    shown = []
    for line in lines:
        line = re.sub(r'^GCC CFGA=\S+$', 'GCC CFGA=<W>', line)
        line = re.sub(r'^CMDDB MAP DESC=\d+ HITS=\d+( T=\d+ ATTR=\S+)? (NONE|TYPE|PART|BAD)$', r'CMDDB MAP DESC=<N> HITS=<H>\1 \2', line)
        line = re.sub(r'^END LOADS=\d+ FAULTS=\d+ SKIPS=0 BLK=\S+ CUTS=0 LINES=\d+$', 'END LOADS=<L> FAULTS=<F> SKIPS=0 BLK=<B> CUTS=0 LINES=<N>', line)
        shown.append(line)
    return shown


def token(line, key):
    """The token after `key=` in `line` (a word as the page shows it), or None."""
    found = re.search(rf'(?:^| ){re.escape(key)}=(\S+)', line)
    return found.group(1) if found else None


def chain_stick(entries):
    """The files of a stick: `entries` is [(file name, bytes)] in manifest order."""
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


class Gpusnap2Qemu(unittest.TestCase):
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
        cls.bins = {name: (out / 'payloads' / f'{name}.bin').read_bytes() for name in ('state', 'gpusnap2')}
        boots = [
            Boot('alone', chain_stick([('GPUSNAP2.BIN', cls.bins['gpusnap2'])]), script(), marker='PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK '),
            Boot('after-state', chain_stick([('STATE.BIN', cls.bins['state']), ('GPUSNAP2.BIN', cls.bins['gpusnap2'])]), script(),
                 marker='PAYLOAD DONE INDEX=1 RETURN=0X0 STACK=OK '),
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

    def block_lines(self, page, block):
        """The lines of `block`: `NEXT <block>` and what follows it up to the next NEXT or the end line, or the one `<block> GATED BY <why>` line."""
        head = {'TSENS3': 'T3', 'GCC': 'GCC', 'GPUCC': 'GPUCC', 'CMDDB': 'CMDDB', 'RSC2': 'RSC2', 'QFPROM': 'QFPROM'}[block]
        if f'NEXT {block}' not in page:
            gated = [line for line in page if re.fullmatch(rf'{block} GATED BY \w+', line)]
            self.assertEqual(len(gated), 1, f'{block} is neither announced nor gated: {page}')
            return None
        first = page.index(f'NEXT {block}') + 1
        last = first
        while not page[last].startswith(('NEXT ', 'END ')) and not (re.fullmatch(r'\w+ GATED BY \w+', page[last]) and not page[last].startswith(head + ' ')):
            last += 1
        found = page[first:last]
        self.assertTrue(found and all(line.startswith(head + ' ') for line in found), (block, found))
        return found

    def expected(self, name):
        """What the payload must have done, from the page's own words and this test's rules: {loads, faults, blocks (the END `BLK` mask), read (the blocks it read), why (gate reasons)}.
        The rules (the design note): a block is announced before its first load; TSENS3's first load is the identity of the SROT, a window that answers with anything but a word that is neither
        zero nor all ones is gated at once; GPUCC is read, 21 words, only when the one GCC word says the GPU's CFG AHB clock runs (a clock the page marks .ON: enabled, CLK_OFF clear);
        the database is read only behind a memory map that describes all of it as reserved memory, and QEMU's does not (so the map is read, four words of each descriptor and two of each
        that overlaps the region, and nothing else of the block); the RSC is read behind its identity word, which QEMU's window never gives, and the QFPROM word is the last load."""
        page = self.printed(name)
        want = {'loads': 0, 'faults': 0, 'blocks': 0, 'read': [], 'why': {}}
        tsens = self.block_lines(page, 'TSENS3')
        self.assertEqual(len(tsens), 1, 'the TSROT identity is not a word QEMU gives, so TSENS3 is one gated line')
        ver = token(tsens[0], 'VER')
        self.assertIn(ver, ABSENT, tsens)
        self.assertEqual(tsens[0], f'T3 VER={ver} GATED')
        want['loads'] += 1
        want['faults'] += ver == 'FAULT:6'
        want['blocks'] |= 1
        gcc = self.block_lines(page, 'GCC')
        self.assertEqual(len(gcc), 1, gcc)
        cfga = WORD.match(token(gcc[0], 'CFGA') or '')
        self.assertTrue(cfga, gcc)
        want['loads'] += 1
        want['faults'] += cfga.group('value').startswith('FAULT')
        want['blocks'] |= 4 * cfga.group('value').startswith('FAULT')
        runs = cfga.group('clock') == 'ON'
        gpucc = self.block_lines(page, 'GPUCC')
        if runs:
            self.assertIsNotNone(gpucc, 'the CFG AHB word says the clock runs, yet GPUCC was gated')
            self.assertEqual(len(gpucc), len(GPUCC_LINES), gpucc)
            for line, key in zip(gpucc, GPUCC_LINES):
                self.assertTrue(line[6:].startswith(key), (line, key))
            self.assertNotIn('FAULT', ' '.join(gpucc), 'GPUCC aborted: not a case this test knows')
            want['loads'] += GPUCC_LOADS
            want['read'].append('GPUCC')
        else:
            self.assertIsNone(gpucc)
            word_ok = cfga.group('value') != '0XFFFFFFFF' and not cfga.group('value').startswith('FAULT')
            self.assertIn(f'GPUCC GATED BY {"AHB" if word_ok else "AHBERR"}', page)
            want['blocks'] |= 8
        cmddb = self.block_lines(page, 'CMDDB')
        self.assertIsNotNone(cmddb, 'the map gate is read before it is a gate')
        found = re.fullmatch(r'CMDDB MAP DESC=(\d+) HITS=(\d+)(?: T=\d+ ATTR=\S+)? (NONE|TYPE|PART|BAD)', cmddb[0])
        self.assertTrue(found, f'QEMU reserves no region at the command database: {cmddb}')
        self.assertEqual(cmddb[1:], ['CMDDB GATED BY MAP'], 'a map that does not describe the database as reserved opens nothing of it')
        want['loads'] += 4 * int(found.group(1)) + 2 * int(found.group(2))
        want['blocks'] |= 0x10
        rsc = self.block_lines(page, 'RSC2')
        self.assertEqual(len(rsc), 2, rsc)
        rid = token(rsc[0], 'ID')
        self.assertIn(rid, ABSENT, rsc)
        self.assertEqual(rsc[1], 'RSC2 GATED BY ID')
        want['loads'] += 1
        want['faults'] += rid == 'FAULT:6'
        want['blocks'] |= 0x20
        qf = self.block_lines(page, 'QFPROM')
        self.assertEqual(len(qf), 1, qf)
        word = token(qf[0], 'W118')
        self.assertIn(word, ABSENT, qf)
        want['loads'] += 1
        want['faults'] += word == 'FAULT:6'
        want['blocks'] |= 0x40 * (word == 'FAULT:6')
        if word == 'FAULT:6':
            self.assertEqual(qf[0], 'QFPROM W118=FAULT:6')
        return want

    def test_it_runs_to_the_end_behind_the_runner_alone_and_after_state(self):
        for name, index in (('alone', 0), ('after-state', 1)):
            with self.subTest(boot=name):
                want = self.expected(name)
                self.assertRegex(self.done(name, index),
                                 rf'^PAYLOAD DONE INDEX=\d RETURN=0X0 STACK=OK LOADS={want["loads"]} FAULTS={want["faults"]} REFUSED=0 LINES=\d+ DROPPED=0$')
                self.assertNotIn('SYNCHRONOUS EXCEPTION', self.runs[name].text)
        self.assertEqual(normal(self.printed('alone')), normal(self.printed('after-state')))

    def test_the_page_has_its_structure_under_qemu(self):
        page = self.printed('alone')
        self.assertEqual(page[0], 'READ ONLY EL=2 CAP=2048/34')
        self.assertEqual(page[1], LEGEND)
        want = self.expected('alone')
        nexts = [line[5:] for line in page if line.startswith('NEXT ')]
        order = [page.index(f'NEXT {block}') for block in nexts]
        self.assertEqual(order, sorted(order))
        self.assertEqual(nexts, [block for block in BLOCKS if f'NEXT {block}' in page], 'the blocks are announced in the order of the design')
        for block in nexts:
            self.assertTrue(page[page.index(f'NEXT {block}') + 1].startswith({'TSENS3': 'T3 ', 'GCC': 'GCC ', 'GPUCC': 'GPUCC ', 'CMDDB': 'CMDDB ', 'RSC2': 'RSC2 ', 'QFPROM': 'QFPROM '}[block]),
                            f'a block is printed right after its NEXT line: {block}')
        self.assertEqual('NEXT GPUCC' in page, not any(line.startswith('GPUCC GATED BY ') for line in page), 'GPUCC is read or gated, never both and never neither')
        found = re.fullmatch(rf'END LOADS={want["loads"]} FAULTS={want["faults"]} SKIPS=0 BLK=(0X[0-9A-F]+|\d+) CUTS=0 LINES=(\d+)', page[-1])
        self.assertTrue(found, (page[-1], want))
        self.assertEqual(int(found.group(1), 0), want['blocks'], 'BLK holds the windows that were not read: TSROT, GCC if it aborted, GPUCC, CMDDB, RSC, QFPROM if it aborted')
        self.assertEqual(int(found.group(2)), len(page))
        self.assertLessEqual(len(page), 34)

    def test_the_counters_of_the_runner_agree_with_the_payload(self):
        line = self.done('alone', 0)
        want = self.expected('alone')
        self.assertIn(f'LOADS={want["loads"]} FAULTS={want["faults"]} ', line)
        self.assertIn(f'LINES={len(self.printed("alone"))} ', line)

    def test_it_prints_nothing_outside_the_page_font(self):
        for name in self.runs:
            for line in self.lines(name):
                self.assertIsNotNone(qemu.FONT_LINE.fullmatch(line), line)
                self.assertLessEqual(len(line), 100)

    def test_the_document_gives_the_lines_qemu_showed(self):
        doc = DOC.read_text(encoding='utf-8')
        block = re.search(r'<!-- qemu-lines -->\n```\n(.*?)```\n<!-- /qemu-lines -->', doc, re.S)
        self.assertIsNotNone(block, f'{DOC.name} has no <!-- qemu-lines --> block')
        shown = block.group(1).splitlines()
        page = [PREFIX + line for line in normal(self.printed('alone'))]
        self.assertEqual(shown, page)

    def test_no_boot_changes_a_file_of_the_stick(self):
        for name, boot in self.runs.items():
            self.assertFalse(boot.changed, f'{name}: a file on the stick changed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
