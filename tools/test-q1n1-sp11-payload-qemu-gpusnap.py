#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The payload `gpusnap` behind the runner, under QEMU's EDK2 shell (docs/SP11-PAYLOAD-GPUSNAP.md).

    python3 tools/test-q1n1-sp11-payload-qemu-gpusnap.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), lays two sticks out as the stick is laid out (`gpusnap` alone and
`state gpusnap`) and boots QEMU's EDK2 shell on each, with a real ExitBootServices and a real EL2 (the stick layout, the boot driver and the helpers are
those of test-q1n1-sp11-payload-qemu.py).

QEMU has none of the blocks the payload reads: every window of it lies in the flash of the `virt` machine (below 0x08000000), which reads back the
firmware's own bytes where the firmware is and zeros in the padding after it. The words the payload prints under QEMU are therefore the firmware's, not a
model of the GPU, and whether the CFG AHB gate opens, and what the CX verdict says, is the firmware's doing. The test does not pin those lines. It reads
the words the payload printed and decides, by its OWN statement of the rules (written here from the design note, not from the payload), which blocks the
page must show as read and which as gated, what the R4 line must say, that the late words (the ones no Linux code reads) come after the drift report and
only for the blocks that were read, how many loads the payload must have made and that the runner's counters agree. What
that proves: the binary runs at EL2 behind the runner, uses only its ops, keeps its stores on its own stack (the runner would refuse a load destination
outside it), takes its second snapshot after a real 8 s on the counter, gates the way the words say, and prints nothing outside the page font and never
more than 40 lines. What it does not prove: anything about the unit's windows (UNKNOWN, hardware NOT RUN), the abort path (the flash does not abort), or a
snapshot that moves, which only the host test exercises.

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image.
Evidence: EXPERIMENTAL (QEMU only); hardware NOT RUN. Writes only under build/sp11-payload-qemu-gpusnap/."""
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


qemu = load_module('sp11_payload_qemu_base_for_gpusnap', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-gpusnap'
sha, script, manifest, Boot = qemu.sha, qemu.script, qemu.manifest, qemu.Boot
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'
PREFIX = 'PAYLOAD GPUSNAP '
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-GPUSNAP-EVIDENCE.md'
VALUE = re.compile(r'^(?P<key>[A-Z0-9_]+)=(?:(?P<value>0X[0-9A-F]+|\d+)(?:\.(?:ON|OFF|ODD))?|(?P<unread>FAULT:\d+|SKIP))$')
LEGEND = 'KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=BIT 31 NOT TRUSTED NO GPU-WINDOW REGISTER IS READ'
GATE_INPUTS = ('CXGD', 'CXHW', 'AHB', 'CGMU', 'CXO', 'AXI_NW', 'MNOC', 'HUB', 'DMT')
GPUCC_KEYS = ('CXGD', 'CXHW', 'AHB', 'CGMU', 'CXO', 'HUB', 'DMT', 'HLOS', 'GXGD', 'GXCF', 'CXOA', 'HUBA', 'GXGM', 'GRC', 'GRF', 'HRC', 'HRF', 'XRC', 'XRF')


def normal(lines):
    """`lines` (without the prefix) as the document shows them under "What QEMU shows": the lines that do not depend on what the flash holds, the frequency, the
    counts of the end line, the gap and the line count as placeholders."""
    shown = []
    for line in lines:
        if not (line.startswith(('READ ONLY', 'KEY=', 'NEXT WAIT', 'NEXT S2 GCC', 'NEXT GCC', 'END '))):
            continue
        line = re.sub(r'HZ=0X[0-9A-F]+', 'HZ=<HZ>', line)
        line = re.sub(r'^END LOADS=\d+ FAULTS=\d+ SKIPS=\d+ BLK=\S+ ', 'END LOADS=<L> FAULTS=<F> SKIPS=<S> BLK=<B> ', line)
        line = re.sub(r'GAP_MS=\d+ LINES=\d+', 'GAP_MS=<MS> LINES=<N>', line)
        shown.append(line)
    return shown


def words(page):
    """{key: value} of the `KEY=VALUE` fields of the lines of `page` (a value below 10 is one digit, a larger one is 0X and hex; a clock word carries .ON, .OFF or .ODD); the value
    is None where the field says the word was not read (`FAULT:n`, `SKIP`). The first occurrence of a key is the one of snapshot 1."""
    found = {}
    for line in page:
        for token in line.split()[1:]:
            match = VALUE.match(token)
            if match and match.group('key') not in found:
                found[match.group('key')] = int(match.group('value'), 0) if match.group('value') else None
    return found


def runs(word, hwcg=False, nohalt=False):
    """This test's own statement of when a branch clock word proves that the clock runs (the design note, not the payload): read, not all ones, enabled, and CLK_OFF clear, or
    the halt check skipped, or hardware gating (bit 1) on a clock that has it."""
    if word is None or word == 0xffffffff or not word & 1:
        return False
    return True if nohalt else (not word >> 31 & 1) or (hwcg and bool(word >> 1 & 1))


def verdict(w):
    """(CX verdict, clock mask of the seven, mask of the SMMU's four) from the printed words, by the design note's rules: an input that was not read, or reads all ones,
    is UNK."""
    clocks = [runs(w['AHB']), runs(w['CGMU']), runs(w['CXO']), runs(w['AXI_NW'], True, True), runs(w['MNOC'], True), runs(w['HUB']), runs(w['DMT'])]
    smmu = [runs(w['HLOS']), runs(w['MNOC'], True), runs(w['SNOC']), runs(w['AHB'])]
    mask = sum(c << i for i, c in enumerate(clocks))
    sm = sum(c << i for i, c in enumerate(smmu))
    known = all(w[k] is not None and w[k] != 0xffffffff for k in GATE_INPUTS)
    if not known:
        return 'UNK', mask, sm
    if w['CXGD'] >> 1 & 1:
        return 'HWCTL', mask, sm
    if w['CXGD'] & 1 or not w['CXHW'] >> 31 & 1:
        return 'OFF', mask, sm
    return ('ON' if mask == 0x7f else 'PART'), mask, sm


def chain_stick(entries):
    """The files of a stick: `entries` is [(file name, bytes)] in manifest order."""
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


class GpusnapQemu(unittest.TestCase):
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
        cls.bins = {name: (out / 'payloads' / f'{name}.bin').read_bytes() for name in ('state', 'gpusnap')}
        boots = [
            Boot('alone', chain_stick([('GPUSNAP.BIN', cls.bins['gpusnap'])]), script(), marker='PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK '),
            Boot('after-state', chain_stick([('STATE.BIN', cls.bins['state']), ('GPUSNAP.BIN', cls.bins['gpusnap'])]), script(),
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

    def expected(self, name):
        """What the payload must have done, from the words its page printed and this test's own rules: {loads, faults, skips, blocks (the END `BLK` mask), state (the CX
        verdict, or NA when GPUCC was not read), gpucc (snapshot 2 re-reads it), cmp (the values the drift report compares), sm (the SMMU clock mask)}."""
        w = words(self.printed(name))
        for key in ('CFGA', 'QMIP', 'MNOC', 'SNOC', 'AXI_NW'):
            self.assertIn(key, w, f'the GCC lines of the page do not hold {key}')
        want = {'loads': 14, 'faults': 0, 'skips': 0, 'blocks': 0x3e, 'state': 'NA', 'gpucc': False, 'cmp': 7, 'sm': 0}
        if not runs(w['CFGA']):
            return want
        for key in GPUCC_KEYS:
            self.assertIn(key, w, f'the GPUCC lines of the page do not hold {key}')
        if w['CXGD'] is None:
            # The first load of GPUCC aborted: the other 18 words of the window are skipped, nothing is read behind it, and snapshot 2 has nothing of it to read again.
            want.update(loads=15, faults=1, skips=18, state='UNK')
            return want
        self.assertTrue(all(w[key] is not None for key in GPUCC_KEYS), 'GPUCC aborted after its first word: not a case this test knows')
        state, _, sm = verdict(w)
        want.update(loads=14 + 19 + 19, state=state, gpucc=True, cmp=26, sm=sm, blocks=0x3c)
        if state == 'ON':
            want['loads'] += 1 + 6 + 13 + (6 if sm == 0xf else 0)
            want['blocks'] = 0 if sm == 0xf else 0x20
        return want

    def test_it_runs_to_the_end_behind_the_runner_alone_and_after_state(self):
        for name, index in (('alone', 0), ('after-state', 1)):
            with self.subTest(boot=name):
                want = self.expected(name)
                self.assertRegex(self.done(name, index), rf'^PAYLOAD DONE INDEX=\d RETURN=0X0 STACK=OK LOADS={want["loads"]} FAULTS={want["faults"]} REFUSED=0 LINES=\d+ DROPPED=0$')
                self.assertNotIn('SYNCHRONOUS EXCEPTION', self.runs[name].text)
        self.assertEqual(normal(self.printed('alone')), normal(self.printed('after-state')))

    def test_the_page_has_its_structure_under_qemu(self):
        page = self.printed('alone')
        self.assertRegex(page[0], r'^READ ONLY EL=2 HZ=0X[0-9A-F]+ GAP=8 S$')
        self.assertEqual(page[1], LEGEND)
        w, want = words(page), self.expected('alone')
        nexts = [line for line in page if line.startswith('NEXT ')]
        read = ['GCC'] + (['GPUCC'] if runs(w['CFGA']) else [])
        if want['state'] == 'ON':
            read += ['CXMISC', 'GMU', 'RSCC'] + (['SMMU'] if want['sm'] == 0xf else [])
        # nothing in the flash moves, so snapshot 2 finds the same words (a GPUCC that did not read has nothing to read again) and the late words are read, for the blocks that were read
        late = ['NEXT LATE GMU', 'NEXT LATE RSCC'] if want['state'] == 'ON' else []
        self.assertEqual([n[5:] for n in nexts[:len(read)]], read)
        self.assertEqual(nexts[len(read):], ['NEXT WAIT 8 S', 'NEXT S2 GCC'] + (['NEXT S2 GPUCC GCC=SAME'] if want['gpucc'] else []) + late)
        order = [page.index(line) for line in nexts]
        self.assertEqual(order, sorted(order))
        if late:
            drift, gmu, rscc = page.index(f'DRIFT NONE CMP={want["cmp"]}'), page.index('NEXT LATE GMU'), page.index('NEXT LATE RSCC')
            self.assertLess(drift, gmu, 'the late words come after the drift report')
            self.assertTrue(page[gmu + 1].startswith('LATE GMU RST=') and page[rscc + 1].startswith('LATE RSCC PDCS='), 'each NEXT LATE line is followed by its words')
            self.assertEqual((rscc, page[rscc + 2][:4]), (gmu + 2, 'END '))
        else:
            self.assertFalse([line for line in page if line.startswith(('NEXT LATE', 'LATE '))], 'a block that was not read in snapshot 1 has no late words')
        gated = [line for line in page if ' GATED BY ' in line]
        state = want['state']
        if not runs(w['CFGA']):
            self.assertEqual(gated, [f'{b} GATED BY AHB' for b in ('GPUCC', 'CXMISC', 'GMU', 'RSCC', 'SMMU')])
            self.assertFalse([line for line in page if line.startswith('R4 ')])
        elif state != 'ON':
            self.assertEqual(gated, [f'{b} GATED BY CX={state}' for b in ('CXMISC', 'GMU', 'RSCC', 'SMMU')])
        else:
            self.assertEqual(gated, [] if want['sm'] == 0xf else ['SMMU GATED BY SMCLK'])
        if runs(w['CFGA']):
            self.assertTrue(any(line.startswith(f'R4 CX={state}') for line in page), (state, page))
        self.assertIn(f'DRIFT NONE CMP={want["cmp"]}', page)
        found = re.fullmatch(rf'END LOADS={want["loads"]} FAULTS={want["faults"]} SKIPS={want["skips"]} BLK=(0X[0-9A-F]+|\d+) CUTS=0 GAP_MS=(\d+) LINES=(\d+)', page[-1])
        self.assertTrue(found, (page[-1], want))
        self.assertEqual(int(found.group(1), 0), want['blocks'])
        self.assertGreaterEqual(int(found.group(2)), 8000, 'the gap on the real counter')
        self.assertLess(int(found.group(2)), 12000)
        self.assertEqual(int(found.group(3)), len(page))
        self.assertLessEqual(len(page), 40)

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
        self.assertIsNotNone(block, 'docs/SP11-PAYLOAD-GPUSNAP-EVIDENCE.md has no <!-- qemu-lines --> block')
        shown = block.group(1).splitlines()
        page = [PREFIX + line for line in normal(self.printed('alone'))]
        self.assertEqual(shown, page)

    def test_no_boot_changes_a_file_of_the_stick(self):
        for name, boot in self.runs.items():
            self.assertFalse(boot.changed, f'{name}: a file on the stick changed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
