#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The payload `inputsnap` behind the runner, under QEMU's EDK2 shell (docs/SP11-PAYLOAD-INPUTSNAP.md).

    python3 tools/test-q1n1-sp11-payload-qemu-inputsnap.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), lays two sticks out as the stick is laid out (`inputsnap` alone and
`state inputsnap`) and boots QEMU's EDK2 shell on each, with a real ExitBootServices and a real EL2 (the stick layout, the boot driver and the helpers are those
of test-q1n1-sp11-payload-qemu.py).

OBSERVED when this test was written, QEMU `virt,virtualization=on`, `-cpu max`, `-smp 1`, TCG, EDK2 AArch64 (the document says which version), and asserted
here: QEMU has none of the windows the payload reads except by accident. The clock controller's window and the two engines' windows lie in the flash of the `virt`
machine, which reads back (the firmware's bytes at the clock words, zeros past the image: the values are not pinned, only that they print and that nothing aborts).
The GIC distributor's window lies inside the PCIe MMIO window, where nothing is mapped: its loads answer all ones. The pin controller's window lies in a hole of the
memory map: its first guarded load aborts, the runner reports a faulted load, the payload prints FAULT:6 and reads nothing more from that window. Whether an engine
is read at all is the firmware's doing (the clock words it reads at the engine's gate offsets): the test derives which of the two it must see from the words the
payload printed, by its own reading of them, and holds the page and the runner's counters to that. The payload announces every block, waits its eight seconds on
the real counter, prints a drift report (nothing moves) and the end line, never prints more than 40 lines or a character outside the page font, and the runner
reports a normal DONE whose counters agree with the page. What that proves: the binary runs at EL2 behind the runner, uses only the ops, keeps its stores on its own
stack (the runner would have refused the load destination otherwise), takes its second snapshot after the gap the page announces, decides the gating the way the
words say, and fails closed on the hole. What it does not: anything about the unit's windows (UNKNOWN, hardware NOT RUN), or a snapshot that moves, which only the
host test exercises.

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image.
Evidence: EXPERIMENTAL (QEMU only); hardware NOT RUN. Writes only under build/sp11-payload-qemu-inputsnap/."""
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


qemu = load_module('sp11_payload_qemu_base_for_inputsnap', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-inputsnap'
sha, script, manifest, Boot = qemu.sha, qemu.script, qemu.manifest, qemu.Boot
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'
PREFIX = 'PAYLOAD INPUTSNAP '
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-INPUTSNAP.md'
# The lines of the page that do not depend on what the flash window holds (the clock controller's window reads the firmware's bytes under QEMU, so the GCC line
# values are left out, and so are the lines of the engines' own blocks, early and late, which are read or gated by those bytes, and the S2 lines that follow from them), as
# the document shows them under "What QEMU shows". The number the drift summary compared is the number of clock words that read, which is flash-independent too, but is
# a count of the page's own and is left as a placeholder.
FLASH_LINES = ('GCC ', 'U2 ', 'S10 ', 'X U2 ', 'X S10 ', 'S2 U2 ', 'NEXT S2 U2')
GATE_WORDS = {'U2': ('MA0', 'SA0', 'CR0', 'SE0'), 'S10': ('MA1', 'SA1', 'CR1', 'SE1', 'QS1')}
HWCG = ('MA0', 'SA0', 'MA1', 'SA1')
BLOCKS = ('GCC', 'GIC', 'U2', 'S10', 'TLMM', 'X U2', 'X S10', 'X GIC')      # the bits of BLK, in this order


def normal(lines):
    """`lines` (without the prefix) as the document shows them: no flash-dependent line, the frequency, the compared count, the counts of the end line, the gap and
    the line count as placeholders."""
    shown = []
    for line in lines:
        if line.startswith(FLASH_LINES):
            continue
        line = re.sub(r'HZ=0X[0-9A-F]+', 'HZ=<HZ>', line)
        line = re.sub(r'CMP=\d+', 'CMP=<N>', line)
        line = re.sub(r'^END LOADS=\d+ FAULTS=\d+ SKIPS=\d+ BLK=\S+ CUTS=\d+ ', 'END LOADS=<L> FAULTS=<F> SKIPS=<S> BLK=<B> CUTS=<C> ', line)
        line = re.sub(r'GAP_MS=\d+ LINES=\d+', 'GAP_MS=<MS> LINES=<N>', line)
        shown.append(line)
    return shown


def gcc_words(page):
    """{key: value} of the clock words on the GCC lines of `page` as printed (a value below 10 is one digit, a larger one is 0X and hex; a clock word carries its
    .ON, .OFF, .HW or .ODD), or the string FAULT:6 / SKIP when the word was not read."""
    found = {}
    for line in page:
        if not line.startswith('GCC '):
            continue
        for token in line.split()[1:]:
            match = re.fullmatch(r'(\w+)=(0X[0-9A-F]+|\d+)(?:\.(?:ON|OFF|HW|ODD))?', token)
            if match:
                found[match.group(1)] = int(match.group(2), 0)
            elif '=' in token:
                found[token.split('=')[0]] = token.split('=')[1]
    return found


def clock_stopped(word, hwcg):
    """Whether a branch clock word says the clock is stopped (clk-branch.c: CLK_OFF, bit 31, unless the NoC FSM status is ON, 2 in bits 30:28, or, for a clock that
    declares a hardware gating bit, HW_CTL, bit 1): this test's own statement of the payload's rule, to be checked against the binary. An all-ones word is no clock word
    (what a failed read returns): the payload does not call it stopped but unknown."""
    return word != 0xffffffff and bool(word >> 31 & 1 and not (hwcg and word >> 1 & 1) and (word >> 28 & 7) != 2)


def gate_verdict(words, keys):
    """OFF when a gate word that read says stopped, else ERR when one did not read or read as all ones, else OPEN: the payload's engine_gate(), restated."""
    off = any(isinstance(words[key], int) and clock_stopped(words[key], key in HWCG) for key in keys)
    err = any(not isinstance(words[key], int) or words[key] == 0xffffffff for key in keys)
    return 'OFF' if off else 'ERR' if err else 'OPEN'


def implied_blk(page):
    """The BLK the page implies: a bit for each block with a cell that is FAULT, SKIP or GATED, or whose NEXT line is not on the page."""
    bits = 0
    for bit, head in enumerate(BLOCKS):
        text = ' '.join(line for line in page if line.startswith(head + ' '))
        if f'NEXT {head}' not in page or re.search(r'=FAULT:|=SKIP\b|GATED', text):
            bits |= 1 << bit
    return bits


def chain_stick(entries):
    """The files of a stick: `entries` is [(file name, bytes)] in manifest order."""
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


class InputsnapQemu(unittest.TestCase):
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
        cls.bins = {name: (out / 'payloads' / f'{name}.bin').read_bytes() for name in ('state', 'inputsnap')}
        boots = [
            Boot('alone', chain_stick([('INPUTSNP.BIN', cls.bins['inputsnap'])]), script(), marker='PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK '),
            Boot('after-state', chain_stick([('STATE.BIN', cls.bins['state']), ('INPUTSNP.BIN', cls.bins['inputsnap'])]), script(),
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

    def verdicts(self, name):
        """{engine: OPEN, OFF or ERR}, from the GCC words the page itself printed, by gate_verdict(): this test's own reading of them, to be held against the page's."""
        words = gcc_words(self.printed(name))
        verdicts = {}
        for engine, keys in GATE_WORDS.items():
            self.assertTrue(all(key in words for key in keys), f'the GCC lines of the page do not hold the clock words of {engine}: {words}')
            verdicts[engine] = gate_verdict(words, keys)
        return verdicts

    def test_it_runs_to_the_end_behind_the_runner_alone_and_after_state(self):
        for name, index in (('alone', 0), ('after-state', 1)):
            with self.subTest(boot=name):
                self.assertRegex(self.done(name, index), r'^PAYLOAD DONE INDEX=\d RETURN=0X0 STACK=OK LOADS=\d+ FAULTS=\d+ REFUSED=0 LINES=\d+ DROPPED=0$')
                self.assertNotIn('SYNCHRONOUS EXCEPTION', self.runs[name].text)
        self.assertEqual(normal(self.printed('alone')), normal(self.printed('after-state')))

    def test_the_page_has_its_structure_under_qemu(self):
        page = self.printed('alone')
        self.assertRegex(page[0], r'^READ ONLY EL=2 HZ=0X[0-9A-F]+ GAP=8 S$')
        self.assertEqual(page[1], 'KEY=VALUE FAULT:6=ABORT SKIP=AFTER ONE GATED=NOT READ ODD=DECODE NOT VALID')
        verdicts = self.verdicts('alone')
        raw = [line for line in page if line.startswith('NEXT ')]
        nexts = [re.sub(r' GCC=(?:SAME|CHG:\d+)$', '', line) for line in raw]
        u2_read = any(line.startswith('U2 FW=') and not line.startswith('U2 FW=FAULT') for line in page)
        early = ['NEXT GCC', 'NEXT GIC', 'NEXT U2', 'NEXT S10', 'NEXT TLMM', 'NEXT WAIT 8 S', 'NEXT S2 GCC'] + (['NEXT S2 U2'] if u2_read else [])
        late = [f'NEXT {head}' for head in BLOCKS[5:] if f'NEXT {head}' in nexts]
        self.assertEqual(nexts, early + late, 'snapshot 2 visits no window that aborted (the pin controller does here, in snapshot 1), the flash does not move; the late blocks come last')
        order = [page.index(line) for line in raw]
        self.assertEqual(order, sorted(order))
        drift = next(i for i, line in enumerate(page) if line.startswith('DRIFT '))
        self.assertTrue(page[drift].startswith('DRIFT NONE CMP='), page[drift])
        self.assertTrue(all(page.index(f'NEXT {head}') > drift for head in BLOCKS[5:] if f'NEXT {head}' in page), 'the late blocks follow the drift summary')
        self.assertGreater(len([line for line in page if line.startswith('GIC ')]), 0, 'the GIC block has lines')
        for engine in ('U2', 'S10'):
            first = [line for line in page if line.startswith(engine + ' ')]
            dead = verdicts[engine] == 'OPEN' and first[0].startswith(f'{engine} FW=FAULT:6')
            for head in (engine, f'X {engine}'):
                if head.startswith('X') and f'NEXT {head}' not in page:
                    continue
                own = [line for line in page if line.startswith(head + ' ')]
                if verdicts[engine] != 'OPEN':
                    self.assertEqual(own, [f'{head} GATED {verdicts[engine]}'], 'a gated engine is one line, and the late block gates on the same words')
                    continue
                self.assertFalse(any('GATED' in line for line in own), (head, own))
                if dead:
                    cells = re.findall(r'\b(\w+)=(\S+)', ' '.join(own))
                    self.assertTrue(all(value == 'SKIP' for key, value in cells if (head, key) != (engine, 'FW')), (head, own))
        tlmm = page[page.index('NEXT TLMM') + 1:page.index('NEXT WAIT 8 S')]
        self.assertTrue(tlmm and tlmm[0].startswith('TLMM F8=FAULT:6'), tlmm)
        self.assertIn('SKIP', ' '.join(tlmm))
        found = re.fullmatch(r'END LOADS=(\d+) FAULTS=(\d+) SKIPS=(\d+) BLK=(\S+) CUTS=(\d+) GAP_MS=(\d+) LINES=(\d+)', page[-1])
        self.assertTrue(found, page[-1])
        loads, faults, skips, blk, cuts, gap, lines = found.groups()
        cells = [token for line in page for token in re.findall(r'=(FAULT:\d+|SKIP)\b', line)]
        self.assertEqual(int(faults), sum(token.startswith('FAULT') for token in cells), 'every abort is on the page, once')
        implied = implied_blk(page)
        if int(cuts) == 0:
            self.assertEqual(int(skips), sum(token == 'SKIP' for token in cells))
            self.assertEqual(int(blk, 0), implied, (blk, implied))
        else:
            self.assertEqual(implied & ~int(blk, 0), 0, 'a block the page shows incomplete is in BLK')
        self.assertGreaterEqual(int(gap), 8000, 'the gap on the real counter')
        self.assertLess(int(gap), 12000)
        self.assertEqual(int(lines), len(page))
        self.assertLessEqual(len(page), 34)

    def test_the_counters_of_the_runner_agree_with_the_payload(self):
        line = self.done('alone', 0)
        printed = self.printed('alone')[-1]
        loads, faults = (int(re.search(rf'{name}=(\d+)', printed).group(1)) for name in ('LOADS', 'FAULTS'))
        self.assertIn(f'LOADS={loads} FAULTS={faults} ', line)
        self.assertIn(f'LINES={len(self.printed("alone"))} ', line)

    def test_it_prints_nothing_outside_the_page_font(self):
        for name in self.runs:
            for line in self.lines(name):
                self.assertIsNotNone(qemu.FONT_LINE.fullmatch(line), line)
                self.assertLessEqual(len(line), 100)

    def test_the_document_gives_the_lines_qemu_showed(self):
        doc = DOC.read_text(encoding='utf-8')
        block = re.search(r'<!-- qemu-lines -->\n```\n(.*?)```\n<!-- /qemu-lines -->', doc, re.S)
        self.assertIsNotNone(block, 'docs/SP11-PAYLOAD-INPUTSNAP.md has no <!-- qemu-lines --> block')
        shown = block.group(1).splitlines()
        page = [PREFIX + line for line in normal(self.printed('alone'))]
        self.assertEqual(shown, page)

    def test_no_boot_changes_a_file_of_the_stick(self):
        for name, boot in self.runs.items():
            self.assertFalse(boot.changed, f'{name}: a file on the stick changed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
