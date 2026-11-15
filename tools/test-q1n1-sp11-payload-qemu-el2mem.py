#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The payloads `el2mem` and `hashbig` under QEMU's EDK2 shell (docs/SP11-PAYLOAD-EL2MEM.md, docs/SP11-PAYLOAD-HASHBIG.md).

    python3 tools/test-q1n1-sp11-payload-qemu-el2mem.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), lays three sticks out as the stick is laid out
(`el2mem` alone, `hashbig` with a data file alone, and the proposed chain `el2mem hashbig BIG.DAT`) and boots QEMU's EDK2 shell on
each, with a real ExitBootServices and a real EL2 (the stick layout, the boot driver and the helpers are those of
test-q1n1-sp11-payload-qemu.py). The data file is small (1 MiB and 4093 bytes, so that SHA-256 needs two final blocks), not the 144 MiB
of the staging plan: QEMU reads a FAT directory slowly, and what 144 MiB takes on the unit is the question the unit has to answer.

What it shows (OBSERVED, QEMU 11.1.3, `virt,virtualization=on`, `-cpu max`, `-smp 1`, TCG, EDK2 AArch64; see the QEMU sections of the
two documents): both payloads run at EL2 behind the runner, read only what they are given, print only font characters and stay within
their line budgets, return 0, and leave the stick as it was. `hashbig` finds the data file the runner loaded, checks its extent
against the final memory map, asks the MMU about its pages, hashes it with the digest that Python's hashlib computes for the same
bytes, and says MATCH. `el2mem` walks QEMU's own conventional memory with AT S1E2R, with all pages mapped and the controls readable,
says there is no 30 GiB bank here, reads QEMU's own ID registers and waits its three times eight seconds of counter.
What it does not show: anything about the unit (every value printed here is QEMU's: UNKNOWN on the unit, hardware NOT RUN), the unit's
firmware map, whether the monitor's candidate region is mapped, whether a register read traps to EL3 (QEMU has no EL3 here), how
fast the unit hashes (TCG speed says nothing), or the attributes of a 144 MiB file.

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image.
Evidence: EXPERIMENTAL (QEMU only); hardware NOT RUN. Writes only under build/sp11-payload-qemu-el2mem/."""
import concurrent.futures
import hashlib
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


qemu = load_module('sp11_payload_qemu_base_for_el2mem', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-el2mem'
sha, script, manifest, Boot = qemu.sha, qemu.script, qemu.manifest, qemu.Boot
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'
DATA = hashlib.shake_256(b'sp11 hashbig qemu data file').digest(1024 * 1024 + 4093)
EL2MEM_PREFIX = 'PAYLOAD EL2MEM '
HASHBIG_PREFIX = 'PAYLOAD HASHBIG '
# The page of each payload as (label, entry keys), consecutive lines of one label joined: the page wraps a long group onto a second
# line at a different place for different values, so the wrap is not asserted. An entry's key is its text before `=` and without
# the address of a LOAD entry. docs/SP11-PAYLOAD-EL2MEM.md and docs/SP11-PAYLOAD-HASHBIG.md give the lines QEMU showed in
# `el2mem-qemu` and `hashbig-qemu` blocks, which tools/test-q1n1-sp11-payload-mmu-doc.py holds to these shapes.
EL2MEM_FOLDED = [
    ('START', ['CURRENTEL', 'FREQ']), ('MAP', ['DESC', 'STRIDE', 'CONV_EXTENTS', 'CONV_MIB']), ('KEY', ['RESULT', 'PROBES', 'FIRST', 'LAST']),
    ('SCAN', ['EXTENTS', 'PROBES', 'ALL', 'ATTR', 'SH', 'NS']), ('BANK', ['NOT_CONVENTIONAL_IN_THE_MAP']),
    ('CONTROL', ['T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'CODE', 'STACK']), ('LOAD', ['BANK', 'LOW_FIRST', 'LOW_LAST']),
    ('ID', ['DFR1', 'ISAR2', 'MMFR1', 'PAN', 'VH', 'HAFDBS', 'PFR2', 'AIDR', 'REVIDR', 'MDCR_EL2']),
    ('NEXT', ['MDSCR_EL1', 'AFTER', '8', 'S']), ('MDSCR_EL1', ['RAW']),
    ('NEXT', ['OSLSR_EL1', 'AFTER', '8', 'S']), ('OSLSR_EL1', ['RAW', 'OSLK']),
    ('NEXT', ['ICC_SRE_EL2', 'AFTER', '8', 'S']), ('ICC_SRE_EL2', ['RAW', 'SRE', 'ENABLE']),
    ('DONE', ['SCAN_ALL_MAPPED', 'LOADS_OK', 'OF', 'HAZARD_READS']),
]
HASHBIG_FOLDED = [
    ('START', ['CURRENTEL', 'FREQ']), ('FILE', ['INDEX', 'BASE', 'BYTES', 'MIB']), ('EXTENT', ['ALLOCATED', 'DESCRIPTORS']),
    ('ATTR', ['FIRST', 'MID', 'LAST']), ('NEXT', ['SHA256', 'BOX', 'S']), ('HASH', ['BYTES', 'TICKS', 'MS', 'MIBS']),
    ('DIGEST', ['<DIGEST>', 'MATCH']), ('DONE', ['MATCH']),
]
HASHBIG_NO_FILE_FOLDED = [('START', ['CURRENTEL', 'FREQ']), ('TABLE_REFUSED', ['NO_DATA_FILE'])]


def folded(lines, prefix):
    """[(label, [entry keys])] of the payload's lines: see EL2MEM_FOLDED. A digest (sixteen hex digits) is `<DIGEST>`."""
    out = []
    for line in lines:
        label, *entries = line[len(prefix):].split(' ')
        keys = [re.sub(r'\(.*?\)', '', entry).split('=')[0] for entry in entries]
        keys = ['<DIGEST>' if re.fullmatch(r'[0-9A-F]{16}', key) else key for key in keys]
        if out and out[-1][0] == label and label != 'NEXT':
            out[-1][1].extend(keys)
        else:
            out.append((label, keys))
    return out


def values(lines, prefix, label):
    """{key: value text} of every `KEY=VALUE` entry of the lines with this label (a LOAD entry's address is dropped from its key)."""
    found = {}
    for line in lines:
        words = line[len(prefix):].split(' ')
        if words[0] == label:
            for entry in words[1:]:
                if '=' in entry:
                    key, value = entry.split('=', 1)
                    found[re.sub(r'\(.*?\)', '', key)] = value
    return found


def chain_stick(entries):
    """The files of a stick: `entries` is [(file name, bytes)] in manifest order."""
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


class El2memQemu(unittest.TestCase):
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
        built = subprocess.run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j4', 'PAYLOAD=1']
                               + qemu.SP11_VARS + ['payload-runner', 'payloads'], cwd=ROOT, env=lib.ENV, capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError('PAYLOAD=1 build failed:\n' + built.stdout[-2000:] + built.stderr[-2000:])
        cls.runner = out / 'q1n1-payload.efi'
        cls.bins = {name: (out / 'payloads' / f'{name}.bin').read_bytes() for name in ('el2mem', 'hashbig')}
        cls.runs = cls._boots()

    @classmethod
    def _boots(cls):
        b = cls.bins
        boots = [
            Boot('el2mem-alone', chain_stick([('EL2MEM.BIN', b['el2mem'])]), script(), marker='PAYLOAD DONE INDEX=0 ', timeout=300),
            Boot('hashbig-alone', chain_stick([('HASHBIG.BIN', b['hashbig']), ('BIG.DAT', DATA)]), script(), marker='PAYLOAD DONE INDEX=0 ',
                 timeout=300),
            Boot('hashbig-nofile', chain_stick([('HASHBIG.BIN', b['hashbig'])]), script(), marker='PAYLOAD DONE INDEX=0 ', timeout=300),
            Boot('chain', chain_stick([('EL2MEM.BIN', b['el2mem']), ('HASHBIG.BIN', b['hashbig']), ('BIG.DAT', DATA)]), script(),
                 marker='PAYLOAD DONE INDEX=1 ', timeout=300),
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            return {boot.name: boot for boot in pool.map(lambda boot: qemu.run_boot(boot, cls.runner, cls.firmware), boots)}

    # -- what a boot printed ----------------------------------------------------------------------------------------------
    def before(self, name):
        return self.runs[name].text.split(AFTER, 1)[0]

    def after(self, name):
        text = self.runs[name].text
        self.assertIn(AFTER, text, f'{name}: the bounce was never confirmed; inspect {BUILD / (name + ".log")}')
        return text.split(AFTER, 1)[1]

    def lines(self, name, prefixes=('PAYLOAD ',)):
        return [line for line in self.after(name).split('\n') if line.startswith(prefixes)]

    def printed(self, name, prefix):
        return [line for line in self.lines(name) if line.startswith(prefix)]

    def done(self, name, index):
        found = [line for line in self.lines(name) if line.startswith(f'PAYLOAD DONE INDEX={index} ')]
        self.assertEqual(len(found), 1, found)
        return found[0]

    def runner_state(self, name):
        """CNTFRQ_EL0 and MAIR_EL2 as integers, from the EL2 state the runner printed after the bounce (QEMU's own)."""
        return {key: int(value, 16) for key, value in re.findall(r'^(CNTFRQ_EL0|MAIR_EL2) 0X([0-9A-F]+)$', self.after(name), re.M)}

    # -- el2mem -------------------------------------------------------------------------------------------------------------
    def test_el2mem_prints_the_page_of_the_documents_alone_and_in_the_chain(self):
        for name in ('el2mem-alone', 'chain'):
            with self.subTest(boot=name):
                self.assertEqual(folded(self.printed(name, EL2MEM_PREFIX), EL2MEM_PREFIX), [(label, keys) for label, keys in EL2MEM_FOLDED])

    def test_el2mem_walked_qemus_map_and_every_page_it_asked_about_was_mapped_with_a_mair_attribute_of_the_machine(self):
        for name in ('el2mem-alone', 'chain'):
            with self.subTest(boot=name):
                lines = self.printed(name, EL2MEM_PREFIX)
                start, scan, key = (values(lines, EL2MEM_PREFIX, label) for label in ('START', 'SCAN', 'KEY'))
                mapped = values(lines, EL2MEM_PREFIX, 'MAP')
                state = self.runner_state(name)
                entries = re.search(r'SP11 EBS: map status=0x0 parse=OK entries=(\d+)', self.after(name))
                self.assertEqual(int(mapped['DESC']), int(entries.group(1)), 'the descriptors the payload read in place are the map the runner parsed')
                self.assertEqual(mapped['STRIDE'], '48')
                self.assertEqual(start['CURRENTEL'], '0X8')
                self.assertEqual(int(start['FREQ']), state['CNTFRQ_EL0'], "the payload's counter frequency is CNTFRQ_EL0, as the runner printed it")
                self.assertEqual((scan['ALL'], scan['SH']), ('MAPPED', 'IS'))
                self.assertEqual(scan['PROBES'], key['PROBES'], 'one key, so every probe has it')
                self.assertEqual(scan['EXTENTS'], mapped['CONV_EXTENTS'])
                self.assertEqual(key['RESULT'], 'WB.IS.NS1')
                maired = [state['MAIR_EL2'] >> (8 * i) & 255 for i in range(8)]
                self.assertIn(0xFF, maired, 'PAR_EL1.ATTR is a MAIR_EL2 attribute byte; WB is 0xFF')
                controls = values(lines, EL2MEM_PREFIX, 'CONTROL')
                self.assertEqual(set(controls.values()), {'WB.IS.NS1'}, 'the firmware types, the payload and its stack all read as mapped')
                self.assertIn('NOT_CONVENTIONAL_IN_THE_MAP', ' '.join(lines), 'QEMU has no 30 GiB bank')

    def test_el2mem_loaded_the_two_low_words_through_the_guard_and_skipped_the_bank(self):
        for name in ('el2mem-alone', 'chain'):
            with self.subTest(boot=name):
                loads = [line for line in self.printed(name, EL2MEM_PREFIX) if line.startswith(EL2MEM_PREFIX + 'LOAD ')]
                self.assertEqual(len(loads), 1)
                self.assertRegex(loads[0], r'^PAYLOAD EL2MEM LOAD BANK=SKIPPED_NOT_CONVENTIONAL LOW_FIRST\(0X[0-9A-F]+\)=0X[0-9A-F]+ '
                                           r'LOW_LAST\(0X[0-9A-F]+\)=0X[0-9A-F]+$')
                self.assertRegex(self.done(name, 0), r'^PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK LOADS=2 FAULTS=0 REFUSED=0 LINES=\d+ DROPPED=0$')

    def test_el2mems_register_fields_are_the_decode_of_the_registers_it_printed(self):
        for name in ('el2mem-alone', 'chain'):
            with self.subTest(boot=name):
                lines = self.printed(name, EL2MEM_PREFIX)
                ids = values(lines, EL2MEM_PREFIX, 'ID')
                mmfr1 = int(ids['MMFR1'], 16)
                self.assertEqual((int(ids['PAN']), int(ids['VH']), int(ids['HAFDBS'])), (mmfr1 >> 20 & 15, mmfr1 >> 8 & 15, mmfr1 & 15))
                oslsr = values(lines, EL2MEM_PREFIX, 'OSLSR_EL1')
                self.assertEqual(int(oslsr['OSLK']), int(oslsr['RAW'], 16) >> 1 & 1)
                sre = values(lines, EL2MEM_PREFIX, 'ICC_SRE_EL2')
                self.assertEqual((int(sre['SRE']), int(sre['ENABLE'])), (int(sre['RAW'], 16) & 1, int(sre['RAW'], 16) >> 3 & 1))

    def test_el2mem_announced_each_read_that_may_trap_before_making_it_and_ended_with_its_counts(self):
        for name in ('el2mem-alone', 'chain'):
            with self.subTest(boot=name):
                lines = [line[len(EL2MEM_PREFIX):] for line in self.printed(name, EL2MEM_PREFIX)]
                for register in ('MDSCR_EL1', 'OSLSR_EL1', 'ICC_SRE_EL2'):
                    next_line = lines.index(f'NEXT {register} AFTER 8 S')
                    self.assertTrue(lines[next_line + 1].startswith(f'{register} RAW=0X'), lines[next_line:next_line + 2])
                self.assertEqual(lines[-1], 'DONE SCAN_ALL_MAPPED LOADS_OK=2 OF=2 HAZARD_READS=3')

    # -- hashbig ------------------------------------------------------------------------------------------------------------
    def test_hashbig_prints_the_page_of_the_documents_alone_and_in_the_chain(self):
        for name in ('hashbig-alone', 'chain'):
            with self.subTest(boot=name):
                self.assertEqual(folded(self.printed(name, HASHBIG_PREFIX), HASHBIG_PREFIX), HASHBIG_FOLDED)

    def test_hashbig_hashed_the_file_the_runner_loaded_and_said_match_with_the_digest_hashlib_makes(self):
        want = hashlib.sha256(DATA).hexdigest()[:16].upper()
        for name, index in (('hashbig-alone', 1), ('chain', 2)):
            with self.subTest(boot=name):
                lines = self.printed(name, HASHBIG_PREFIX)
                loaded = re.search(rf'PAYLOAD LOADED INDEX={index} BASE=0X([0-9A-F]+) BYTES=(\d+) SHA=([0-9A-F]{{16}}) TYPE=2', self.before(name))
                self.assertIsNotNone(loaded, 'the runner did not load the data file as data')
                self.assertEqual(loaded.group(3), want, 'the digest the runner made is the one hashlib makes')
                file = values(lines, HASHBIG_PREFIX, 'FILE')
                self.assertEqual((file['INDEX'], int(file['BASE'], 16), int(file['BYTES']), file['MIB']),
                                 (str(index), int(loaded.group(1), 16), len(DATA), '1'), 'where the firmware put it, and how big')
                self.assertIn(f'{HASHBIG_PREFIX}DIGEST {want} MATCH', lines)
                self.assertEqual(lines[-1], f'{HASHBIG_PREFIX}DONE MATCH')
                self.assertIn(f'{HASHBIG_PREFIX}EXTENT ALLOCATED DESCRIPTORS=1', lines)
                self.assertIn(f'{HASHBIG_PREFIX}NEXT SHA256 BOX=25 S', lines)

    def test_hashbigs_rate_is_arithmetic_on_its_own_ticks_and_the_runners_counter_frequency(self):
        for name in ('hashbig-alone', 'chain'):
            with self.subTest(boot=name):
                lines = self.printed(name, HASHBIG_PREFIX)
                freq = int(values(lines, HASHBIG_PREFIX, 'START')['FREQ'])
                self.assertEqual(freq, self.runner_state(name)['CNTFRQ_EL0'])
                rate = values(lines, HASHBIG_PREFIX, 'HASH')
                ticks, size = int(rate['TICKS']), int(rate['BYTES'])
                self.assertEqual(size, len(DATA))
                self.assertGreater(ticks, 0)
                self.assertEqual(int(rate['MS']), ticks * 1000 // freq)
                self.assertEqual(int(rate['MIBS']), size * freq // (ticks * (1 << 20)))
                attr = values(lines, HASHBIG_PREFIX, 'ATTR')
                self.assertEqual(set(attr.values()), {'WB.IS.NS1'}, 'the first, middle and last page of the file are mapped')

    def test_hashbig_without_a_data_file_refuses_and_the_runner_sees_return_4(self):
        lines = self.printed('hashbig-nofile', HASHBIG_PREFIX)
        self.assertEqual(folded(lines, HASHBIG_PREFIX), HASHBIG_NO_FILE_FOLDED)
        self.assertEqual(lines[-1], f'{HASHBIG_PREFIX}TABLE_REFUSED NO_DATA_FILE')
        self.assertRegex(self.done('hashbig-nofile', 0), r'^PAYLOAD DONE INDEX=0 RETURN=0X4 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=2 DROPPED=0$')

    # -- the runner's side ------------------------------------------------------------------------------------------------
    def test_the_chain_runs_el2mem_then_hashbig_in_order_to_the_end(self):
        lines = self.lines('chain')
        self.assertIn('PAYLOAD READY FILES=3 RANGES=6 CODE=2', self.before('chain'))
        calls = [line for line in lines if line.startswith('PAYLOAD CALL ')]
        self.assertEqual([line.split()[2] for line in calls], ['0', '1'])
        self.assertEqual([line.split()[3] for line in calls], [sha(self.bins[name])[:16].upper() for name in ('el2mem', 'hashbig')])
        done = [line for line in lines if line.startswith('PAYLOAD DONE ')]
        self.assertEqual([line.split()[2] for line in done], ['INDEX=0', 'INDEX=1'])
        self.assertTrue(all(' RETURN=0X0 STACK=OK ' in line for line in done))
        order = [i for i, line in enumerate(lines) if line.startswith(('PAYLOAD CALL 0', EL2MEM_PREFIX, 'PAYLOAD CALL 1', HASHBIG_PREFIX))]
        self.assertEqual(order, sorted(order))
        self.assertNotIn('SYNCHRONOUS EXCEPTION', self.runs['chain'].text)

    def test_the_runner_counted_the_lines_the_payloads_printed_and_dropped_none(self):
        for name, index, prefix in (('el2mem-alone', 0, EL2MEM_PREFIX), ('hashbig-alone', 0, HASHBIG_PREFIX), ('chain', 0, EL2MEM_PREFIX),
                                    ('chain', 1, HASHBIG_PREFIX)):
            with self.subTest(boot=name, index=index):
                counted = re.search(r' LINES=(\d+) DROPPED=(\d+)$', self.done(name, index))
                self.assertEqual((int(counted.group(1)), counted.group(2)), (len(self.printed(name, prefix)), '0'))

    def test_the_pages_stay_in_the_font_and_within_the_budgets(self):
        for name in self.runs:
            for line in self.lines(name):
                self.assertIsNotNone(qemu.FONT_LINE.fullmatch(line), line)
        self.assertLessEqual(len(self.printed('el2mem-alone', EL2MEM_PREFIX)), 26)
        self.assertLessEqual(len(self.printed('hashbig-alone', HASHBIG_PREFIX)), 12)

    def test_no_boot_changes_a_file_of_the_stick(self):
        for name, boot in self.runs.items():
            self.assertFalse(boot.changed, f'{name}: a file on the stick changed')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
