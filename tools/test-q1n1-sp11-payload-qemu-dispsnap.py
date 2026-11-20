#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The payload `dispsnap` behind the runner, under QEMU's EDK2 shell (docs/SP11-PAYLOAD-DISPSNAP.md).

    python3 tools/test-q1n1-sp11-payload-qemu-dispsnap.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), lays two sticks out as the stick is laid out (`dispsnap` alone and
`state dispsnap`) and boots QEMU's EDK2 shell on each, with a real ExitBootServices and a real EL2 (the stick layout, the boot driver and the helpers are
those of test-q1n1-sp11-payload-qemu.py).

QEMU has none of the blocks the payload reads. GCC's window lies in the flash of the `virt` machine (below 0x08000000), which reads back the firmware's own
bytes where the firmware is and zeros in the padding after it; the display clock controller, the MDSS and the DPU lie in an address range the machine does
not populate. The words the payload prints under QEMU are therefore the firmware's, or the abort of a page the firmware's tables do not map, not a model of the
display, and whether the display register clock gate opens is the firmware's doing. The test does not pin those lines. It reads the words the payload printed
and decides, by its OWN statement of the rules (written here from the design note, not from the payload), which blocks the page must show as read and which as
gated, what the gate line must say, how many loads the payload must have made and that the runner's counters agree. What that proves: the binary runs at EL2
behind the runner, uses only its ops, keeps its stores on its own stack (the runner would refuse a load destination outside it), prints the GOP mode of the
runner's own framebuffer, takes its second snapshot after a real 8 s on the counter when it has anything to read again, gates the way the words say, and prints
nothing outside the page font and never more than 40 lines. What it does not prove: anything about the unit's windows (UNKNOWN, hardware NOT RUN), a display
that runs (the page under QEMU stops at the first gate), or a snapshot that moves, which only the host test exercises. The unit's abort path (the guarded
load's recovery) is not shown here either: the first abort of a window that the page shows under QEMU, if any, is the firmware tables' and not the unit's.

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image.
Evidence: EXPERIMENTAL (QEMU only); hardware NOT RUN. Writes only under build/sp11-payload-qemu-dispsnap/."""
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


qemu = load_module('sp11_payload_qemu_base_for_dispsnap', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-dispsnap'
sha, script, manifest, Boot = qemu.sha, qemu.script, qemu.manifest, qemu.Boot
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'
PREFIX = 'PAYLOAD DISPSNAP '
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-DISPSNAP-EVIDENCE.md'
VALUE = re.compile(r'^(?P<key>[A-Z0-9_]+)=(?:(?P<value>0X[0-9A-F]+|\d+)(?:\.(?:ON|OFF|ODD))?|(?P<unread>FAULT:\d+|SKIP|NOFLC))$')
LEGEND = 'KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=BIT 31 NOT TRUSTED NO STORE NO AUX NO IRQ STATUS'


def normal(lines):
    """`lines` (without the prefix) as the document shows them under "What QEMU shows": the lines that do not depend on what the flash holds, the frequency, the
    framebuffer mode, the counts of the end line, the gap and the line count as placeholders."""
    shown = []
    for line in lines:
        if not (line.startswith(('READ ONLY', 'KEY=', 'GOP ', 'MAP ', 'NEXT WAIT', 'NEXT S2 GCC', 'NEXT GCC', 'END '))):
            continue
        line = re.sub(r'HZ=0X[0-9A-F]+', 'HZ=<HZ>', line)
        line = re.sub(r'^GOP W=\d+ H=\d+ STRIDE=\d+ FMT=\d+$', 'GOP W=<W> H=<H> STRIDE=<S> FMT=<F>', line)
        line = re.sub(r'^END LOADS=\d+ FAULTS=\d+ SKIPS=\d+ BLK=\S+ ', 'END LOADS=<L> FAULTS=<F> SKIPS=<S> BLK=<B> ', line)
        line = re.sub(r'GAP_MS=\d+ LINES=\d+', 'GAP_MS=<MS> LINES=<N>', line)
        shown.append(line)
    return shown


def words(page):
    """{key: value} of the `KEY=VALUE` fields of the lines of `page` (a value below 10 is one digit, a larger one is 0X and hex; a clock word carries .ON, .OFF or .ODD); the value
    is None where the field says the word was not read (`FAULT:n`, `SKIP`, `NOFLC`). The first occurrence of a key is the one of snapshot 1."""
    found = {}
    for line in page:
        if line.startswith(('GOP ', 'MAP ', 'S2 ', 'DG ', 'DD ')):
            continue
        for token in line.split()[1:]:
            match = VALUE.match(token)
            if match and match.group('key') not in found:
                found[match.group('key')] = int(match.group('value'), 0) if match.group('value') else None
    return found


def runs(word):
    """This test's own statement of when a branch clock word proves that the clock runs (the design note, not the payload): read, not all ones, enabled, and CLK_OFF clear."""
    return word is not None and word != 0xffffffff and bool(word & 1) and not word >> 31 & 1


def verdict(w):
    """(display verdict, mask of the two clocks) from the printed words, by the design note's rules: an input that was not read, or reads all ones, is UNK."""
    mask = runs(w['AHBC']) | runs(w['MDPC']) << 1
    if any(w[k] is None or w[k] == 0xffffffff for k in ('GDSC', 'AHBC', 'MDPC')):
        return 'UNK', mask
    if w['GDSC'] >> 1 & 1:
        return 'HWCTL', mask
    if w['GDSC'] & 1 or not w['GDSC'] >> 31 & 1:
        return 'OFF', mask
    return ('ON' if mask == 3 else 'PART'), mask


def chain_stick(entries):
    """The files of a stick: `entries` is [(file name, bytes)] in manifest order."""
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


class DispsnapQemu(unittest.TestCase):
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
        cls.bins = {name: (out / 'payloads' / f'{name}.bin').read_bytes() for name in ('state', 'dispsnap')}
        boots = [
            Boot('alone', chain_stick([('DISPSNAP.BIN', cls.bins['dispsnap'])]), script(), marker='PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK '),
            Boot('after-state', chain_stick([('STATE.BIN', cls.bins['state']), ('DISPSNAP.BIN', cls.bins['dispsnap'])]), script(),
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
        """What the payload must have done, from the words its page printed and this test's own rules: {loads, faults, skips, blocks (the END `BLK` mask), state (the display
        verdict, or NA when DISPCC was not read), s2 (the blocks snapshot 2 reads again), cmp (the values the drift report compares)}. Only the cases QEMU can show: the
        display register clock does not run or aborts, or it runs and DISPCC answers with a verdict that is not ON."""
        w = words(self.printed(name))
        self.assertIn('DAHB', w, 'the GCC line of the page does not hold DAHB')
        raw = {line.split()[1]: line for line in self.printed(name) if line.startswith('GCC DAHB=')}
        faulted = 'DAHB=FAULT' in ' '.join(raw.values())
        if faulted:
            return dict(loads=1, faults=1, skips=0, blocks=0xf, state='NA', s2=[], cmp=0)
        if not runs(w['DAHB']):
            return dict(loads=2, faults=0, skips=0, blocks=0xe, state='NA', s2=['GCC'], cmp=1)
        for key in ('GDSC', 'AHBC', 'MDPC'):
            self.assertIn(key, w, f'the DISPCC lines of the page do not hold {key}')
        if w['GDSC'] is None:
            # the first load of DISPCC aborted: the two other words of the window are skipped and nothing is read behind it
            return dict(loads=1 + 1 + 1, faults=1, skips=2, blocks=0xe, state='UNK', s2=['GCC'], cmp=1)
        self.assertTrue(w['AHBC'] is not None and w['MDPC'] is not None, 'DISPCC aborted after its first word: not a case this test knows')
        state, _ = verdict(w)
        self.assertNotEqual(state, 'ON', 'the display gate is open under QEMU: not a case this test knows')
        return dict(loads=1 + 3 + 1 + 3, faults=0, skips=0, blocks=0xc, state=state, s2=['GCC', 'DISPCC'], cmp=4)

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
        self.assertRegex(page[2], r'^GOP W=\d+ H=\d+ STRIDE=\d+ FMT=\d+$')
        self.assertEqual(page[3], 'MAP GCC=0X100000 DISPCC=0XAF00000 MDSS=0XAE00000 DPU=0XAE01000')
        self.assertEqual(page[4], 'MAP INTF=5 AT=0X39000 CTL=0X15000 STEP=0X1000 REG=0XF4')
        want = self.expected('alone')
        nexts = [line for line in page if line.startswith('NEXT ')]
        read = ['GCC'] + (['DISPCC'] if want['state'] != 'NA' else [])
        self.assertEqual([n[5:] for n in nexts[:len(read)]], read)
        tail = (['NEXT WAIT 8 S', 'NEXT S2 GCC'] if want['s2'] else []) + (['NEXT S2 DISPCC GCC=SAME'] if 'DISPCC' in want['s2'] else [])
        self.assertEqual(nexts[len(read):], tail if want['faults'] == 0 or want['s2'] else nexts[len(read):])
        order = [page.index(line) for line in nexts]
        self.assertEqual(order, sorted(order))
        gated = [line for line in page if ' GATED BY ' in line]
        state = want['state']
        if want['faults'] == 1 and state == 'NA':
            self.assertEqual(gated, [f'{b} GATED BY DAHBERR' for b in ('DISPCC', 'MDSS', 'DPU')])
        elif state == 'NA':
            self.assertEqual(gated, [f'{b} GATED BY DAHB' for b in ('DISPCC', 'MDSS', 'DPU')])
            self.assertFalse([line for line in page if line.startswith('DG ')])
        else:
            self.assertEqual(gated, [f'{b} GATED BY DISP={state}' for b in ('MDSS', 'DPU')])
            self.assertTrue(any(line.startswith(f'DG DISP={state}') for line in page), (state, page))
        self.assertFalse([line for line in page if line.startswith(('INTF ', 'CTL ', 'MDSS ')) and 'GATED' not in line], 'nothing behind a closed gate is printed')
        found = re.fullmatch(rf'END LOADS={want["loads"]} FAULTS={want["faults"]} SKIPS={want["skips"]} BLK=(0X[0-9A-F]+|\d+) CUTS=0 GAP_MS=(\d+) LINES=(\d+)', page[-1])
        self.assertTrue(found, (page[-1], want))
        self.assertEqual(int(found.group(1), 0), want['blocks'])
        if want['s2']:
            self.assertGreaterEqual(int(found.group(2)), 8000, 'the gap on the real counter')
            self.assertLess(int(found.group(2)), 12000)
            self.assertIn(f'DRIFT NONE CMP={want["cmp"]}', page)
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
        self.assertIsNotNone(block, 'docs/SP11-PAYLOAD-DISPSNAP.md has no <!-- qemu-lines --> block')
        shown = block.group(1).splitlines()
        page = [PREFIX + line for line in normal(self.printed('alone'))]
        self.assertEqual(shown, page)

    def test_no_boot_changes_a_file_of_the_stick(self):
        for name, boot in self.runs.items():
            self.assertFalse(boot.changed, f'{name}: a file on the stick changed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
