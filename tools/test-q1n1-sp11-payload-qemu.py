#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end checks of the Surface Pro 11 stick payload runner under QEMU's EDK2 shell
(docs/SP11-PAYLOAD.md).

    python3 tools/test-q1n1-sp11-payload-qemu.py

Builds the runner (SP11=1 PAYLOAD=1, fixture USB and stage tables as the other SP11 suites do), the
reference payload `state`, five test payloads (tools/testdata/sp11-payload-fixture-*.c, built with the
Makefile's own flags) and two copies of the runner with one edit each, lays each out as the stick is laid out
(SP11\\Q1N1-PAYLOAD.EFI, SP11\\PAYLOAD.MAN, SP11\\STATE.BIN and the data file SP11\\DATA.DAT, which is listed in
the manifest and never called) and boots QEMU's EDK2 shell on it, up to seventeen boots at three at a time.
`virtualization=on` gives the runner a real EL2, so the whole path runs: the loader, the declared ranges, a real
ExitBootServices, the second hash, the cache maintenance, the call on the payload stack, the ops (including a
guarded load that really faults and recovers) and the return. `virtualization=off` gives EL1: the runner must
print PAYLOAD SKIPPED=NOT_AT_EL2 and call nothing. The chain (several payloads in one boot, its stop conditions,
the per-payload budgets and the `psci` payload) is in test-q1n1-sp11-payload-qemu-chain.py, which reuses the
helpers of this file.

What it proves: the full flow for `state`, with every register it prints equal to the one q1n1's own page prints;
every refusal before ExitBootServices -- no manifest, a bad manifest, a hash mismatch, six files, a path outside
\\SP11\\, a manifest that is only on a second volume, and a declared table that does not pass the memory map --
returns EFI_ABORTED to the Shell with a PAYLOAD line and never prints "Leaving firmware now"; that the declared
variable is taken back after a late refusal; that no file of either volume changes; that the budgets, the load32
policy and the stack guard (a payload that overwrites it ends the chain) behave on the real call path; that a
payload that never returns is named by the last line; and that a payload that faults reaches q1n1's fault page.
The panel: QEMU's ramfb is 800x600 at most, the page fills it and the region (which is computed for the unit's
far larger panel) has no rows, so the stock run draws nothing on QEMU; a copy that forces a region onto the screen
shows that the drawing path renders the lines. What QEMU cannot show is the real region on the unit's panel
(hardware NOT RUN).

QEMU and its EDK2 are a model, not the Surface: its firmware, memory map and EL2 entry differ, and slbounce is
absent, so ExitBootServices here is the real one and nothing about the scoped sweep is exercised. Evidence:
EXPERIMENTAL (QEMU only); hardware NOT RUN. SKIPs, never passes, without clang, lld-link, make,
qemu-system-aarch64 or an EDK2 AArch64 firmware image (Q1N1_EDK2_CODE overrides the search). With
SP11_UEFI_SHELL (the pinned UEFI Shell image) the happy path is run once more under that shell. Writes only
under build/sp11-payload-qemu/."""
import concurrent.futures
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import preload  # noqa: E402
import sp11_payload_testlib as lib  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-qemu'
ENV = lib.ENV
GUID = '1A3C9E02-7B6F-4D81-9C2E-535031314552'
SP11_VARS = ['SP11=1', 'SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c',
             'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c']
# The one edit that forces the payload page onto QEMU's 800x600 screen (file, needle, replacement): the region computed
# for the unit's far larger panel has no rows there, so the stock runner draws nothing under QEMU.
DRAW_EDIT = ('platform/uefi/main.c',
             '    q1n1_payload_region_place(fb.width, fb.height, fb.scale, fb.row, &payload_page);\n',
             '    q1n1_payload_region_place(fb.width, fb.height, fb.scale, fb.row, &payload_page);\n'
             '    payload_page.placement = Q1N1_PAYLOAD_REGION_RIGHT;\n    payload_page.scale = fb.scale;\n'
             '    payload_page.col0 = 14;\n    payload_page.row0 = 1;\n    payload_page.rows = 28;\n')
PINNED_SHELL = os.environ.get('SP11_UEFI_SHELL')
FONT_LINE = re.compile(r'[A-Z0-9 :\-./=?()_]{1,100}')
STATE_KEYS = ['CURRENTEL', 'MIDR_EL1', 'MPIDR_EL1', 'ID_AA64MMFR0_EL1', 'ID_AA64MMFR1_EL1', 'ID_AA64MMFR2_EL1',
              'ID_AA64MMFR3_EL1', 'ID_AA64MMFR4_EL1', 'ID_AA64PFR0_EL1', 'ID_AA64PFR1_EL1', 'HCR_EL2', 'SCTLR_EL2', 'TCR_EL2',
              'TTBR0_EL2', 'MAIR_EL2', 'VBAR_EL2', 'CPTR_EL2', 'CNTHCTL_EL2', 'CNTFRQ_EL0', 'DAIF', 'SPSEL']


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helpers = load_module('sp11_qemu_helpers', ROOT / 'tools' / 'test-q1n1-sp11-qemu.py')
SWEPT_TYPES, EFI_MEMORY_WB, ANSI = helpers.SWEPT_TYPES, helpers.EFI_MEMORY_WB, helpers.ANSI


def sha(data):
    return hashlib.sha256(data).hexdigest()


def manifest(entries):
    """A Q1N1PLD1 manifest for [(stick path, bytes)]."""
    return preload.manifest([(path, len(data), sha(data)) for path, data in entries])


def stick(payload, extra=(), tamper=None):
    """The files of a stick: the runner's manifest names the payload and `extra` data files."""
    listed = [('\\SP11\\STATE.BIN', payload)] + [(f'\\SP11\\{name}', data) for name, data in extra]
    files = {'SP11/PAYLOAD.MAN': manifest(listed)}
    for path, data in listed:
        files[path[1:].replace('\\', '/')] = data
    if tamper:
        files['SP11/STATE.BIN'] = tamper
    return files


def script(options='--el2 --uart', before='', after=''):
    # The status is echoed straight after the runner: any later command replaces %lasterror%.
    return f'fs0:\n{before}SP11\\Q1N1-PAYLOAD.EFI {options}\necho Q1N1_STATUS=%lasterror%\n{after}echo Q1N1_SHELL_RETURN_OK\n'


def tree_hashes(directory):
    return {str(p.relative_to(directory)): sha(p.read_bytes()) for p in sorted(Path(directory).rglob('*')) if p.is_file()}


class Boot:
    def __init__(self, name, files, startup, el2=True, marker='Q1N1_SHELL_RETURN_OK', second=None, image=None, pinned=False,
                 shot_after=None, timeout=170):
        self.name, self.files, self.startup, self.el2, self.marker = name, files, startup, el2, marker
        self.second, self.image, self.pinned, self.shot_after, self.timeout = second, image, pinned, shot_after, timeout
        self.text, self.shot, self.changed = '', None, None


def run_boot(boot, runner, firmware):
    esp, esp2 = BUILD / boot.name, BUILD / f'{boot.name}-2'
    for directory in (esp, esp2):
        shutil.rmtree(directory, ignore_errors=True)
    esp.mkdir(parents=True)
    (esp / 'SP11').mkdir()
    shutil.copy(boot.image or runner, esp / 'SP11' / 'Q1N1-PAYLOAD.EFI')
    for relative, data in boot.files.items():
        (esp / relative).parent.mkdir(parents=True, exist_ok=True)
        (esp / relative).write_bytes(data)
    (esp / 'startup.nsh').write_text(boot.startup)
    if boot.pinned:
        (esp / 'EFI' / 'BOOT').mkdir(parents=True)
        shutil.copy(PINNED_SHELL, esp / 'EFI' / 'BOOT' / 'BOOTAA64.EFI')
    if boot.second:
        for relative, data in boot.second.items():
            (esp2 / relative).parent.mkdir(parents=True, exist_ok=True)
            (esp2 / relative).write_bytes(data)
    before = (tree_hashes(esp), tree_hashes(esp2) if boot.second else {})
    serial, qmp = BUILD / f'{boot.name}.log', BUILD / f'{boot.name}.q'
    serial.unlink(missing_ok=True)
    qmp.unlink(missing_ok=True)
    drives = ['-drive', f'format=raw,file=fat:rw:{esp}'] + (['-drive', f'format=raw,file=fat:rw:{esp2}'] if boot.second else [])
    cmd = ['qemu-system-aarch64', '-machine', f'virt,virtualization={"on" if boot.el2 else "off"},gic-version=3',
           '-accel', 'tcg', '-cpu', 'max', '-smp', '1', '-m', '512M', '-bios', firmware] + drives + [
           '-device', 'ramfb', '-display', 'none', '-monitor', 'none', '-nic', 'none', '-serial', f'file:{serial}',
           '-qmp', f'unix:{qmp},server=on,wait=off', '-no-reboot']
    proc = subprocess.Popen(cmd, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    text = ''
    try:
        deadline = time.monotonic() + boot.timeout
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(1)
            if serial.exists():
                text = ANSI.sub('', serial.read_text(errors='replace').replace('\r', ''))
                if boot.marker in text:
                    break
        if boot.shot_after is not None and boot.marker in text:
            time.sleep(boot.shot_after)
            helpers.screendump(qmp, BUILD / f'{boot.name}.ppm')
            boot.shot = helpers.read_ppm(BUILD / f'{boot.name}.ppm')
            text = ANSI.sub('', serial.read_text(errors='replace').replace('\r', ''))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    boot.text = text
    after = (tree_hashes(esp), tree_hashes(esp2) if boot.second else {})
    boot.changed = before != after
    return boot


def bands(first, second):
    """How many separate rows of text differ between two screenshots of the same size, leaving out the
    bottom strip that holds the heartbeat."""
    (width, height, one), (_, _, two) = first, second
    rows = [y for y in range(height - 40) if one[y * width * 3:(y + 1) * width * 3] != two[y * width * 3:(y + 1) * width * 3]]
    return 1 + sum(1 for a, b in zip(rows, rows[1:]) if b - a > 1) if rows else 0


class PayloadQemu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'lld-link', 'ld.lld', 'make', 'qemu-system-aarch64'):
            if not lib.have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        cls.firmware = helpers.find_firmware()
        if not cls.firmware:
            raise unittest.SkipTest('no EDK2 aarch64 firmware (set Q1N1_EDK2_CODE)')
        shutil.rmtree(BUILD, ignore_errors=True)
        BUILD.mkdir(parents=True)
        fixtures = SP11_VARS
        out = BUILD / 'out'
        done = subprocess.run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j4', 'PAYLOAD=1']
                              + fixtures + ['payload-runner', 'payloads'], cwd=ROOT, env=ENV, capture_output=True, text=True)
        if done.returncode:
            raise RuntimeError('PAYLOAD=1 build failed:\n' + done.stdout[-2000:] + done.stderr[-2000:])
        cls.runner = out / 'q1n1-payload.efi'
        cls.state = (out / 'payloads' / 'state.bin').read_bytes()
        cls.stamp = helpers.expected_stamp()
        # Two copies, each with one change that a stock build cannot show under QEMU. (1) Write-back is demanded
        # in attribute bit 4, which no descriptor has: the declared table is refused just before the point of no
        # return. (2) The panel region is forced onto the 800x600 screen: QEMU's ramfb is never larger than that,
        # the page fills it, and the real region (computed for the unit's panel, which is far larger) has no rows.
        cls.variant = cls._variant('refuse', 'platform/uefi/sp11-payload-plan.c', '#define ATTRIBUTE_WB (UINT64_C(1) << 3)',
                                   '#define ATTRIBUTE_WB (UINT64_C(1) << 4)', fixtures)
        cls.drawn = cls._variant('draw', *DRAW_EDIT, fixtures)
        cls.fixture = {}
        for name in ('lines', 'loads', 'overflow', 'hang', 'fault'):
            built, _, flat = lib.build_payload(ROOT / 'tools' / 'testdata' / f'sp11-payload-fixture-{name}.c', BUILD / 'fixtures', name=name)
            if built.returncode:
                raise RuntimeError(f'fixture {name} failed:\n{built.stderr[-1500:]}')
            cls.fixture[name] = flat.read_bytes()
        cls.runs = cls._boots()

    @staticmethod
    def _variant(name, relative, needle, replacement, fixtures):
        """Builds a copy of the tree with one edit and returns its runner image."""
        src = BUILD / f'{name}-src'
        shutil.copytree(ROOT / 'platform' / 'uefi', src / 'platform' / 'uefi')
        for directory in ('data', 'font'):
            shutil.copytree(ROOT / directory, src / directory)
        (src / 'tools' / 'testdata').mkdir(parents=True)
        for fixture in ('sp11-usb-table-fixture.c', 'sp11-stage-table-fixture.c'):
            shutil.copy(ROOT / 'tools' / 'testdata' / fixture, src / 'tools' / 'testdata' / fixture)
        path = src / relative
        text = path.read_text(encoding='utf-8')
        assert text.count(needle) == 1, f'{name}: the edit does not apply'
        path.write_text(text.replace(needle, replacement), encoding='utf-8')
        done = subprocess.run(['make', '-f', 'platform/uefi/Makefile', 'OUT=out', '-j4', 'PAYLOAD=1'] + fixtures + ['payload-runner'],
                              cwd=src, env=ENV, capture_output=True, text=True)
        if done.returncode:
            raise RuntimeError(f'{name} build failed:\n' + done.stdout[-2000:] + done.stderr[-2000:])
        return src / 'out' / 'q1n1-payload.efi'

    @classmethod
    def _boots(cls):
        data = bytes(range(251)) * 20
        good = stick(cls.state, [('DATA.DAT', data)])
        decoy = stick(cls.state)
        boots = [
            Boot('ok', good, script(), shot_after=2, marker='PAYLOAD DONE'),
            Boot('draw', good, script(), shot_after=2, marker='PAYLOAD DONE', image=cls.drawn),
            Boot('el1', good, script(), el2=False, marker='PAYLOAD SKIPPED=NOT_AT_EL2'),
            Boot('preflight', stick(cls.state), script(options=''), el2=False),
            Boot('noman', {}, script()),
            Boot('badman', {'SP11/PAYLOAD.MAN': b'\xff' * 64}, script()),
            Boot('badhash', stick(cls.state, tamper=cls.state[:100] + bytes([cls.state[100] ^ 1]) + cls.state[101:]), script()),
            Boot('six', {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\F{i}.BIN', bytes([i]) * 16) for i in range(6)]),
                         **{f'SP11/F{i}.BIN': bytes([i]) * 16 for i in range(6)}}, script()),
            Boot('badpath', {'SP11/PAYLOAD.MAN': manifest([('\\EFI\\BOOT\\X.BIN', bytes(16))])}, script()),
            Boot('othervol', {}, script(before='ls fs1:\\SP11\\\n'), second=decoy),
            Boot('variant', good, script(before=f'setvar Q1N1Sp11EbsRanges -guid {GUID} -bs =01\necho CONTROL_BEGIN\n'
                                         f'dmpstore -guid {GUID}\necho CONTROL_END\n',
                                         after=f'echo AFTER_BEGIN\ndmpstore -guid {GUID}\necho AFTER_END\n'), image=cls.variant),
            Boot('lines', stick(cls.fixture['lines']), script(), marker='PAYLOAD DONE'),
            Boot('loads', stick(cls.fixture['loads']), script(), marker='PAYLOAD DONE'),
            Boot('overflow', stick(cls.fixture['overflow']), script(), marker='PAYLOAD CHAIN STOPPED'),
            Boot('hang', stick(cls.fixture['hang']), script(), marker='PAYLOAD CALL', shot_after=6),
            Boot('fault', stick(cls.fixture['fault']), script(), marker='PAYLOAD CALL', shot_after=6),
        ]
        if PINNED_SHELL and Path(PINNED_SHELL).is_file():
            boots.append(Boot('pinned', good, script(), pinned=True, marker='PAYLOAD DONE'))
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            done = list(pool.map(lambda b: run_boot(b, cls.runner, cls.firmware), boots))
        return {b.name: b for b in done}

    def text(self, name):
        return self.runs[name].text

    def assert_marker(self, name, marker):
        self.assertIn(marker, self.text(name), f'{name}: "{marker}" never appeared; inspect {BUILD / (name + ".log")}')

    @staticmethod
    def payload_lines(text):
        return [line for line in text.split('\n') if line.startswith('PAYLOAD ')]

    # -- the whole flow ---------------------------------------------------------------------------------------------
    def check_happy_path(self, name):
        text = self.text(name)
        self.assert_marker(name, 'PAYLOAD DONE')
        before, after = text.split('EL2 CONFIRMED AFTER EXITBOOTSERVICES', 1)
        digest = sha(self.state)[:16].upper()
        # Before the bounce, on the firmware console: what was loaded and that the table passed.
        self.assertRegex(before, rf'PAYLOAD LOADED INDEX=0 BASE=0X[0-9A-F]+ BYTES={len(self.state)} SHA={digest} TYPE=1')
        self.assertRegex(before, r'PAYLOAD LOADED INDEX=1 BASE=0X[0-9A-F]+ BYTES=5020 SHA=[0-9A-F]{16} TYPE=2')
        self.assertIn('PAYLOAD READY FILES=2 RANGES=5 CODE=1', before)
        self.assertLess(before.index('PAYLOAD READY'), before.index('Leaving firmware now'))
        self.assertIn('SP11 EBS: set_variable=0x0 ranges=5 chunk=0x100000', before)
        rows = re.findall(r'SP11 EBS: r(\d+) (\w+) base=0x[0-9A-F]+ size=0x[0-9A-F]+ desc=(\d+) type=(\d+) attr=(0x[0-9A-F]+) '
                          r'contained=(yes|NO)', after)
        self.assertEqual([(r[0], r[1]) for r in rows], [(str(i), label) for i, label in
                                                       enumerate(['image', 'map', 'preload', 'payload', 'file1'])], rows)
        for _, label, desc, kind, attribute, contained in rows:
            self.assertEqual((desc, contained), ('1', 'yes'), label)
            self.assertIn(int(kind), SWEPT_TYPES, label)
            self.assertTrue(int(attribute, 16) & EFI_MEMORY_WB, label)
        self.assertEqual([r[3] for r in rows if r[1] == 'payload'], ['1'], 'the payload is in code memory')
        # After it, at EL2: verified again, named, run, answered.
        lines = self.payload_lines(after)
        self.assertEqual([line for line in lines if line.startswith('PAYLOAD LOADED')], [
            line for line in self.payload_lines(before) if line.startswith('PAYLOAD LOADED')], 'the notes are replayed unchanged')
        at = lines.index('PAYLOAD VERIFY=OK')
        self.assertEqual(lines[at + 1], f'PAYLOAD CALL 0 {digest}')
        state = [line for line in lines[at + 2:] if line.startswith('PAYLOAD STATE ')]
        self.assertEqual([line.split('=')[0][len('PAYLOAD STATE '):] for line in state], STATE_KEYS)
        self.assertEqual(lines[-1], 'PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=21 DROPPED=0')
        self.assertEqual(sum(line.startswith('PAYLOAD CALL ') for line in lines), 1, 'the data file is not called')
        for line in lines:
            self.assertRegex(line, FONT_LINE, line)
        self.assertNotIn('SYNCHRONOUS EXCEPTION', text)
        values = {line.split('=')[0][len('PAYLOAD STATE '):]: int(line.split('=')[1], 16) for line in state}
        self.assertEqual(values['CURRENTEL'], 8)
        # Every register the existing EL2 page also prints is the same number there.
        page = after.split('EL2 STATE (READ ONLY)', 1)[1].split('USB PROXY', 1)[0]
        for key, label in (('HCR_EL2', 'HCR_EL2'), ('SCTLR_EL2', 'SCTLR_EL2'), ('TCR_EL2', 'TCR_EL2'), ('TTBR0_EL2', 'TTBR0_EL2'),
                           ('MAIR_EL2', 'MAIR_EL2'), ('VBAR_EL2', 'VBAR_EL2'), ('CPTR_EL2', 'CPTR_EL2'), ('CNTHCTL_EL2', 'CNTHCTL_EL2'),
                           ('CNTFRQ_EL0', 'CNTFRQ_EL0'), ('MPIDR_EL1', 'MPIDR_EL1'), ('DAIF', 'DAIF'), ('SPSEL', 'SPSEL')):
            found = re.search(rf'^{label} 0X([0-9A-F]{{16}})', page, re.M)
            self.assertIsNotNone(found, label)
            self.assertEqual(values[key], int(found.group(1), 16), f'{key}: the payload and the page disagree')
        self.assertEqual(('TTBR1_EL2' in values), bool(values['HCR_EL2'] >> 34 & 1))
        self.assertNotIn('EL2REGS', ''.join(state))

    def test_the_state_payload_runs_at_el2_through_the_whole_flow(self):
        self.check_happy_path('ok')
        self.assertFalse(self.runs['ok'].changed, 'a file on the stick changed')

    @unittest.skipUnless(PINNED_SHELL and Path(PINNED_SHELL or '/nonexistent').is_file(), 'SP11_UEFI_SHELL not set')
    def test_the_same_flow_under_the_pinned_uefi_shell(self):
        self.check_happy_path('pinned')

    def test_the_draw_path_renders_the_lines_where_the_region_has_rows(self):
        # At 800x600 the stock region has no rows (see _variant), so the stock run draws nothing and the copy that
        # forces a region draws what the payload printed: the two screens differ in the rows of its text.
        stock, drawn = self.runs['ok'].shot, self.runs['draw'].shot
        self.assertIsNotNone(stock)
        self.assertIsNotNone(drawn)
        self.assertEqual(stock[:2], drawn[:2])
        self.assertGreaterEqual(bands(drawn, stock), 20, 'fewer rows of text differ than the payload printed')
        self.assertLessEqual(bands(stock, self.runs['hang'].shot), 12, 'the stock page changed more than the lines it prints')
        for name in ('ok', 'draw'):
            self.check_happy_path(name)

    def test_at_el1_the_runner_says_so_and_calls_nothing(self):
        self.assert_marker('el1', 'PAYLOAD SKIPPED=NOT_AT_EL2')
        before, after = self.text('el1').split('EL2 NOT REACHED - STILL IN EL1', 1)
        self.assertIn('PAYLOAD READY FILES=2 RANGES=5 CODE=1', before)
        self.assertNotIn('PAYLOAD CALL', after)
        self.assertNotIn('PAYLOAD STATE', self.text('el1'))
        self.assertNotIn('SYNCHRONOUS EXCEPTION', self.text('el1'))

    def test_the_preflight_without_the_el2_option_prints_nothing_of_the_runner(self):
        self.assert_marker('preflight', 'Preflight only.')
        self.assertEqual(self.payload_lines(self.text('preflight')), [])
        self.assertNotIn('SP11 EBS', self.text('preflight'))

    # -- every refusal before ExitBootServices ---------------------------------------------------------------
    def assert_refused(self, name, line_pattern):
        text = self.text(name)
        self.assert_marker(name, 'Q1N1_SHELL_RETURN_OK')
        self.assertRegex(text, line_pattern)
        self.assertNotIn('Leaving firmware now', text)
        self.assertNotIn('EL2 CONFIRMED', text)
        self.assertNotIn('EXITBOOTSERVICES FAILED', text)
        self.assertNotIn('PAYLOAD CALL', text)
        statuses = re.findall(r'Q1N1_STATUS=(\S+)', text)
        self.assertTrue(statuses, 'the Shell did not report a status')
        # The Shell prints the code without the error bit: 0x15 is EFI_ABORTED, what a refusal returns.
        self.assertEqual(statuses[-1].lower(), '0x15', 'a refusal returns EFI_ABORTED to the Shell')
        self.assertFalse(self.runs[name].changed, 'a file on a volume changed')

    def test_no_manifest_returns_to_the_shell_with_a_failure(self):
        self.assert_refused('noman', r'PAYLOAD REFUSED=NO_MANIFEST EFI=0X800000000000000E\b')

    def test_a_bad_manifest_returns_to_the_shell_with_a_failure(self):
        self.assert_refused('badman', r'PAYLOAD REFUSED=MANIFEST_BAD')

    def test_a_hash_mismatch_returns_to_the_shell_and_names_both_digests(self):
        good = sha(self.state)[:16].upper()
        bad = sha(self.state[:100] + bytes([self.state[100] ^ 1]) + self.state[101:])[:16].upper()
        self.assert_refused('badhash', rf'PAYLOAD REFUSED=HASH INDEX=0 WANT={good} HAVE={bad}')

    def test_six_files_return_to_the_shell(self):
        self.assert_refused('six', r'PAYLOAD REFUSED=TOO_MANY_FILES GOT=6 WANT=5')

    def test_a_path_outside_the_sp11_directory_returns_to_the_shell(self):
        self.assert_refused('badpath', r'PAYLOAD REFUSED=BAD_PATH INDEX=0')

    def test_a_manifest_that_is_only_on_a_second_volume_is_not_found(self):
        text = self.text('othervol')
        self.assertIn('PAYLOAD.MAN', text.split('Q1N1_SHELL_RETURN_OK')[0], 'the decoy is not visible on fs1: the test proves nothing')
        self.assert_refused('othervol', r'PAYLOAD REFUSED=NO_MANIFEST')

    def test_a_declared_table_the_memory_map_refuses_is_refused_before_the_bounce_and_taken_back(self):
        text = self.text('variant')
        self.assert_marker('variant', 'AFTER_END')
        self.assertRegex(text, r'PAYLOAD REFUSED=RANGES REASON=NOT_WRITE_BACK RANGE=0')
        self.assertIn('SP11 EBS: r0 image', text, 'the table was declared and reported first')
        self.assertLess(text.index('SP11 EBS: set_variable=0x0'), text.index('PAYLOAD REFUSED=RANGES'))
        self.assertNotIn('Leaving firmware now', text)
        self.assertNotIn('PAYLOAD READY', text)
        self.assertNotIn('EXITBOOTSERVICES FAILED', text)
        control = text.split('CONTROL_BEGIN', 1)[1].split('CONTROL_END', 1)[0]
        self.assertIn('Q1N1Sp11EbsRanges', control, 'dmpstore does not show a variable that exists: the check proves nothing')
        after = text.split('AFTER_BEGIN', 1)[1].split('AFTER_END', 1)[0]
        self.assertNotIn('Q1N1Sp11EbsRanges', after, 'the declared table was left in place after the refusal')
        self.assertRegex(text, r'Q1N1_STATUS=0x15')

    # -- the call path --------------------------------------------------------------------------------------------------
    def test_the_line_budget_keeps_forty_and_counts_the_rest(self):
        lines = self.payload_lines(self.text('lines'))
        fixture = [line for line in self.text('lines').split('\n') if line.startswith('FIXTURE LINE ')]
        self.assertEqual(fixture, [f'FIXTURE LINE 0X{i:X}' for i in range(40)])
        self.assertEqual(lines[-1], 'PAYLOAD DONE INDEX=0 RETURN=0X1234 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=40 DROPPED=5')

    def test_load32_answers_each_case_on_the_real_call_path_and_survives_a_fault(self):
        text = self.text('loads')
        self.assert_marker('loads', 'PAYLOAD DONE')
        want = ['FIXTURE LOAD OWN=0X0 WORD=0XD503245F', 'FIXTURE LOAD ALIGN=0X2 WORD=0XA5A5A5A5',
                'FIXTURE LOAD RANGE=0X3 WORD=0XA5A5A5A5', 'FIXTURE LOAD OUT=0X4 WORD=0XA5A5A5A5',
                'FIXTURE LOAD FAULT=0X6 WORD=0XA5A5A5A5', 'FIXTURE LOAD AFTER=0X0 WORD=0XD503245F']
        got = [line for line in text.split('\n') if line.startswith('FIXTURE LOAD ')]
        self.assertEqual(got, want)
        self.assertEqual(self.payload_lines(text)[-1],
                         'PAYLOAD DONE INDEX=0 RETURN=0X0 STACK=OK LOADS=3 FAULTS=1 REFUSED=3 LINES=6 DROPPED=0')
        self.assertNotIn('SYNCHRONOUS EXCEPTION', text)

    def test_a_payload_that_writes_the_bottom_of_its_stack_is_told_so_and_stops_the_chain(self):
        text = self.text('overflow')
        self.assert_marker('overflow', 'PAYLOAD CHAIN STOPPED')
        self.assertEqual(self.payload_lines(text)[-2:], [
            'PAYLOAD DONE INDEX=0 RETURN=0X7 STACK=OVERFLOW LOADS=0 FAULTS=0 REFUSED=0 LINES=1 DROPPED=0',
            'PAYLOAD CHAIN STOPPED INDEX=0 REASON=STACK_OVERFLOW'])

    def test_a_payload_that_never_returns_is_named_by_the_last_line(self):
        text = self.text('hang')
        self.assert_marker('hang', 'PAYLOAD CALL')
        lines = self.payload_lines(text.split('EL2 CONFIRMED AFTER EXITBOOTSERVICES', 1)[1])
        self.assertEqual(lines[-1], f'PAYLOAD CALL 0 {sha(self.fixture["hang"])[:16].upper()}')
        self.assertNotIn('PAYLOAD DONE', text)

    def test_a_payload_that_faults_lands_in_q1ns_fault_page(self):
        text = self.text('fault')
        self.assert_marker('fault', 'PAYLOAD CALL')
        self.assertNotIn('PAYLOAD DONE', text)
        width, height, pixels = self.runs['fault'].shot
        quiet = self.runs['hang'].shot
        top = pixels[(2 * width + width // 2) * 3:(2 * width + width // 2) * 3 + 3]
        other = quiet[2][(2 * width + width // 2) * 3:(2 * width + width // 2) * 3 + 3]
        self.assertNotEqual(top, other, 'the top rows are the same as for a payload that is still running')
        self.assertGreater(max(top), 200)
        self.assertLess(sorted(top)[1], 120, 'the fault page paints a red bar across the top')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
