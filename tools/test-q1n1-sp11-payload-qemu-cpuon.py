#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The cpuon payload of the Surface Pro 11 stick payload runner under QEMU's EDK2 shell with twelve CPUs
(docs/SP11-PAYLOAD-CPUON.md).

    python3 tools/test-q1n1-sp11-payload-qemu-cpuon.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables) and boots QEMU's EDK2 shell on
`virt,virtualization=on,gic-version=3 -smp 12` with a stick that carries cpuon.bin alone (the stick layout, the
helpers and the Boot class are those of test-q1n1-sp11-payload-qemu.py; the boot driver here is its own because it needs
twelve CPUs and the time at which each line appeared). QEMU's built-in PSCI answers the SMC from EL2 itself, starts the
secondaries at EL2 and powers them off on CPU_OFF, so the real assembly stub and the real vector table run on eleven
CPUs and the primary's whole logic runs on real answers.

What it proves: (1) the shipped binary, whose table is the unit's (MPIDR affinities 0X100...0X20300), cannot start
anything on QEMU, whose twelve CPUs are 0X0...0XB: every AFFINITY_INFO is refused by name, no CPU_ON is issued, no wait
begins and the payload returns 0 (fail closed). (2) A variant that differs only in that table line (asserted) runs the whole
flow: phase 1 on one core, the 8 s wait seen on the wall clock of the serial log, phase 2 on eleven, every core entered at
EL2 with its own MPIDR_EL1 and the boot CPU's ID registers, MMU and caches off as found, and OFF again. (3) Variants of the
stub with one edit each: a fault after the vectors are installed is reported by those vectors (vector 4, EC 0, the exact
ELR); a stub that takes EL2 for another EL; a stub that never publishes its done flag; a stub whose CPU_OFF is replaced by
a NOP and parks (left running, return value 2). (4) Two ways to ask QEMU's PSCI to start a core twice: a table with one
affinity twice (two back-to-back CPU_ON for a core that is starting) and a parked core that phase 2 starts again (a core that
is running). OBSERVED, QEMU 11.1.3: the first is answered with success both times, because QEMU models neither ON_PENDING nor
a window between the request and the start, and the later request's context wins, so the earlier slot never gets a report and
the payload says so (NO_REPORT STAGE=0); the second is answered ALREADY_ON(-4), by name, and the core is counted as not started.
What it does not prove: QEMU is coherent, so the cache rules (clean the image and the slots to the point of coherency before
a start, invalidate before every read) are NOT validated here (the test says SKIP for them; the host model and the review are
what stands for them); DC IVAC/CIVAC are no-ops in TCG and page permissions are not modelled; the entry EL of the unit, what
the secure monitor checks in the entry address and how long a real core takes are UNKNOWN; the 8 s wait is checked against
QEMU's counter (1 GHz with `-cpu max` in 11.1.3), not the unit's 19.2 MHz. Hardware NOT RUN. Evidence: EXPERIMENTAL (QEMU only).

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image. SP11_CPUON_QEMU_ONLY
(comma-separated boot names) runs a subset for debugging; the assertions of the others then SKIP. Writes only under
build/sp11-payload-qemu-cpuon/ (short names: a QMP socket path may not exceed 104 characters)."""
import concurrent.futures
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
import sp11_payload_testlib as lib  # noqa: E402


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


qemu = load_module('sp11_payload_qemu_base_for_cpuon', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py')
BUILD = ROOT / 'build' / 'sp11-payload-qemu-cpuon'
SOURCE = ROOT / 'payloads' / 'cpuon.c'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-CPUON.md'
Boot, script, manifest, sha = qemu.Boot, qemu.script, qemu.manifest, qemu.sha
AFTER = 'EL2 CONFIRMED AFTER EXITBOOTSERVICES'
PREFIX = 'PAYLOAD CPUON '
FONT_LINE = qemu.FONT_LINE
ONLY = {name for name in os.environ.get('SP11_CPUON_QEMU_ONLY', '').split(',') if name}
# OBSERVED, QEMU 11.1.3 `-cpu max`: the generic counter runs at 1 GHz (the unit's is 19.2 MHz), which the payload's plausibility
# range for CNTFRQ_EL0 (1 MHz to 1 GHz inclusive) still takes as it is.
QEMU_CNTFRQ = '0X3B9ACA00'
UNIT_TABLE = '    0x0, 0x100, 0x200, 0x300, 0x10000, 0x10100, 0x10200, 0x10300, 0x20000, 0x20100, 0x20200, 0x20300,\n'
# QEMU's virt machine numbers its CPUs 0X0 to 0XB in Aff0 whatever the topology; the table is the only thing that differs.
QEMU_TABLE = '    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB,\n'
TWICE_TABLE = '    0x0, 0x1, 0x2, 0x2, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB,\n'
STAGE_TWO = '    "    mov x2, #2\\n"\n    STORE("x2", OFF_STAGE)\n'
PARKED = [('    "    smc #0\\n"\n    /* Reached only if CPU_OFF returned', '    "    nop\\n"\n    /* Reached only if CPU_OFF returned')]
# Phase 1 stops calling a core that never reached OFF abnormal, so that phase 2 asks QEMU to start a core that is running.
IGNORE_NOT_OFF = [('    if (!c->off) why |= WHY_NOT_OFF;\n', '')]
# Stub edits, each of which must apply exactly once (a stale one is an error, not a pass).
STUB_EDITS = {
    'fault': [(STAGE_TWO, STAGE_TWO + '    "    udf #0\\n"\n')],
    'notel2': [('    "    cmp x1, #8\\n"\n', '    "    cmp x1, #4\\n"\n')],
    'noflag': [('    "    orr x2, x2, x1\\n"\n    STORE("x2", OFF_DONE)\n', '    "    orr x2, x2, x1\\n"\n')],
    'parked': PARKED,
}


def chain_stick(entries):
    files = {'SP11/PAYLOAD.MAN': manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


def edit(text, edits):
    for needle, replacement in edits:
        assert text.count(needle) == 1, f'the edit does not apply exactly once: {needle!r}'
        text = text.replace(needle, replacement, 1)
    return text


def build_variant(name, edits):
    """cpuon.c with `edits`, built with the Makefile's flags; returns (flat bytes, elf path)."""
    out = BUILD / 'variants'
    out.mkdir(parents=True, exist_ok=True)
    path = out / f'{name}.c'
    path.write_text(edit(SOURCE.read_text(encoding='utf-8'), edits), encoding='utf-8')
    done, elf, flat = lib.build_payload(path, out, name=name)
    if done.returncode:
        raise RuntimeError(f'variant {name} failed:\n{done.stderr[-1500:]}')
    return flat.read_bytes(), elf


class Boot12(Boot):
    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.stamps = {}


def run_boot(boot, runner, firmware):
    """qemu.run_boot with twelve CPUs, and the first time each PAYLOAD line was seen on the serial log."""
    esp = BUILD / boot.name
    shutil.rmtree(esp, ignore_errors=True)
    (esp / 'SP11').mkdir(parents=True)
    shutil.copy(runner, esp / 'SP11' / 'Q1N1-PAYLOAD.EFI')
    for relative, data in boot.files.items():
        (esp / relative).parent.mkdir(parents=True, exist_ok=True)
        (esp / relative).write_bytes(data)
    (esp / 'startup.nsh').write_text(boot.startup)
    before = qemu.tree_hashes(esp)
    serial, qmp = BUILD / f'{boot.name}.log', BUILD / f'{boot.name}.q'
    serial.unlink(missing_ok=True)
    qmp.unlink(missing_ok=True)
    cmd = ['qemu-system-aarch64', '-machine', 'virt,virtualization=on,gic-version=3', '-accel', 'tcg', '-cpu', 'max', '-smp', '12',
           '-m', '1G', '-bios', firmware, '-drive', f'format=raw,file=fat:rw:{esp}', '-device', 'ramfb', '-display', 'none',
           '-monitor', 'none', '-nic', 'none', '-serial', f'file:{serial}', '-qmp', f'unix:{qmp},server=on,wait=off', '-no-reboot']
    proc = subprocess.Popen(cmd, env=lib.ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    text = ''
    try:
        deadline = time.monotonic() + boot.timeout
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.2)
            if not serial.exists():
                continue
            text = qemu.helpers.ANSI.sub('', serial.read_text(errors='replace').replace('\r', ''))
            now = time.monotonic()
            for line in text.split('\n'):
                if line.startswith('PAYLOAD ') and line not in boot.stamps:
                    boot.stamps[line] = now
            if boot.marker in text:
                break
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    boot.text = text
    boot.changed = before != qemu.tree_hashes(esp)
    return boot


def digest(data):
    return sha(data)[:16].upper()


class CpuonQemu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'lld-link', 'ld.lld', 'make', 'qemu-system-aarch64', 'llvm-objdump'):
            if not lib.have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        cls.firmware = qemu.helpers.find_firmware()
        if not cls.firmware:
            raise unittest.SkipTest('no EDK2 aarch64 firmware (set Q1N1_EDK2_CODE)')
        shutil.rmtree(BUILD, ignore_errors=True)
        BUILD.mkdir(parents=True)
        out = BUILD / 'out'
        built = subprocess.run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j4', 'PAYLOAD=1']
                               + qemu.SP11_VARS + ['payload-runner', 'payloads'], cwd=ROOT, env=lib.ENV, capture_output=True, text=True)
        if built.returncode:
            raise RuntimeError('PAYLOAD=1 build failed:\n' + built.stdout[-2000:] + built.stderr[-2000:])
        cls.runner = out / 'q1n1-payload.efi'
        cls.shipped = (out / 'payloads' / 'cpuon.bin').read_bytes()
        source = SOURCE.read_text(encoding='utf-8')
        cls.table = {'happy': [(UNIT_TABLE, QEMU_TABLE)], 'twice': [(UNIT_TABLE, TWICE_TABLE)],
                     'again': [(UNIT_TABLE, QEMU_TABLE)] + PARKED + IGNORE_NOT_OFF}
        for name, edits in STUB_EDITS.items():
            cls.table[name] = [(UNIT_TABLE, QEMU_TABLE)] + edits
        cls.bins, cls.elfs = {}, {}
        for name, edits in cls.table.items():
            cls.bins[name], cls.elfs[name] = build_variant(name, edits)
        assert source.count(UNIT_TABLE) == 1
        cls.runs = cls._boots()
        cls._write_panel()

    @classmethod
    def _boots(cls):
        def boot(name, data):
            return Boot12(name, chain_stick([('CPUON.BIN', data)]), script(), marker='PAYLOAD DONE INDEX=0 ', timeout=300)
        wanted = {'real': cls.shipped, 'happy': cls.bins['happy'], 'twice': cls.bins['twice'], 'again': cls.bins['again'],
                  'fault': cls.bins['fault'], 'notel2': cls.bins['notel2'], 'noflag': cls.bins['noflag'], 'parked': cls.bins['parked']}
        boots = [boot(name, data) for name, data in wanted.items() if not ONLY or name in ONLY]
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            return {b.name: b for b in pool.map(lambda b: run_boot(b, cls.runner, cls.firmware), boots)}

    @classmethod
    def _write_panel(cls):
        """What the payload printed in each boot, and when the waits ended, for the document and the review (build/ only)."""
        for name, boot in cls.runs.items():
            lines = [line for line in boot.text.split(AFTER)[-1].split('\n') if line.startswith(PREFIX)]
            (BUILD / f'{name}.panel.txt').write_text('\n'.join(line[len(PREFIX):] for line in lines) + '\n')
        happy = cls.runs.get('happy')
        if happy:
            seen = {line[len(PREFIX):]: at for line, at in happy.stamps.items() if line.startswith(PREFIX)}
            pairs = (('NEXT CPU_ON 0X1 AFTER 8 S', 'P1 CPU_ON 0X1 RET=0X0:SUCCESS'),
                     ('NEXT CPU_ON ALL AFTER 8 S', 'P2 CPU_ON ISSUED=11 SUCCESS=11'))
            (BUILD / 'happy.timing.txt').write_text(''.join(
                f'{b} - {a}: {seen[b] - seen[a]:.2f} s\n' for a, b in pairs if a in seen and b in seen))

    # -- what a boot printed ------------------------------------------------------------------------------------------
    def boot(self, name):
        if name not in self.runs:
            self.skipTest(f'boot {name} not run (SP11_CPUON_QEMU_ONLY)')
        return self.runs[name]

    def after(self, name):
        text = self.boot(name).text
        self.assertIn(AFTER, text, f'{name}: the bounce was never confirmed; inspect {BUILD / (name + ".log")}')
        return text.split(AFTER, 1)[1]

    def printed(self, name):
        return [line[len(PREFIX):] for line in self.after(name).split('\n') if line.startswith(PREFIX)]

    def done(self, name):
        found = [line for line in self.after(name).split('\n') if line.startswith('PAYLOAD DONE INDEX=0 ')]
        self.assertEqual(len(found), 1, f'{name}: {found}')
        return found[0]

    def stamp(self, name, text):
        found = [at for line, at in self.boot(name).stamps.items() if line == PREFIX + text]
        self.assertEqual(len(found), 1, f'{name}: {text!r} was seen {len(found)} times')
        return found[0]

    def find(self, name, pattern):
        found = [line for line in self.printed(name) if re.fullmatch(pattern, line)]
        self.assertTrue(found, f'{name}: no line matches {pattern!r} in {self.printed(name)}')
        return found

    @staticmethod
    def fields(line):
        return {k: v for k, v in (field.split('=', 1) for field in line.split() if '=' in field)}

    # -- the shipped binary ---------------------------------------------------------------------------------------------
    def test_the_shipped_table_cannot_start_anything_on_qemu_and_fails_closed(self):
        lines = self.printed('real')
        self.assertEqual(lines[0], f'BOOT_CPU MPIDR_EL1=0X80000000 CNTFRQ_EL0={QEMU_CNTFRQ}', lines)
        self.assertIn('NEXT AFFINITY', lines)
        affinity = ' '.join(line for line in lines if line.startswith('AFFINITY '))
        for target in ('0X100', '0X200', '0X300', '0X10000', '0X10100', '0X10200', '0X10300', '0X20000', '0X20100', '0X20200', '0X20300'):
            self.assertIn(f'{target}=INVALID_PARAMETERS(-2)', affinity)
        self.assertIn('P1 SKIPPED=NOT_OFF', lines)
        self.assertIn('P2 SKIPPED=P1_NOT_NORMAL', lines)
        self.assertIn('CORES STARTED=0 REPORTED=0 OFF=0', lines)
        self.assertFalse([line for line in lines if 'CPU_ON' in line or 'PREPARE' in line], 'something was started or prepared')
        self.assertIn('RETURN=0X0 STACK=OK', self.done('real'))
        self.assertNotIn('SYNCHRONOUS EXCEPTION', self.boot('real').text)

    def test_the_variants_differ_from_the_shipped_source_only_where_they_say(self):
        source = SOURCE.read_text(encoding='utf-8')
        self.assertEqual(source.count(UNIT_TABLE), 1)
        self.assertEqual(edit(source, [(UNIT_TABLE, QEMU_TABLE)]).count('\n'), source.count('\n'))
        for name, edits in STUB_EDITS.items():
            self.assertEqual(len(edits), 1, 'one edit of the stub per variant, besides the table')
        shipped = SOURCE.read_text(encoding='utf-8').splitlines()
        happy = (BUILD / 'variants' / 'happy.c').read_text(encoding='utf-8').splitlines()
        self.assertEqual([(a, b) for a, b in zip(shipped, happy) if a != b],
                         [(UNIT_TABLE.rstrip('\n'), QEMU_TABLE.rstrip('\n'))], 'the happy-path variant is the shipped source but for the table')

    # -- the round trip -----------------------------------------------------------------------------------------------------
    def check_core(self, name, phase, target):
        a = self.find(name, rf'P{phase} 0X{target:X} EL=\d MPIDR=\S+ IDS=\S+ FRQ=\S+ CNTVOFF_EL2=0X[0-9A-F]+ DT_US=-?\d+')[0]
        b = self.find(name, rf'P{phase} 0X{target:X} SCTLR_EL2=0X[0-9A-F]+ HCR_EL2=0X[0-9A-F]+ VBAR_EL2=0X[0-9A-F]+')[0]
        fa, fb = self.fields(a), self.fields(b)
        self.assertEqual((fa['EL'], fa['MPIDR'], fa['IDS'], fa['FRQ']), ('2', 'OK', 'SAME', 'SAME'), a)
        self.assertEqual(fa['CNTVOFF_EL2'], '0X0')
        sctlr = int(fb['SCTLR_EL2'], 16)
        self.assertEqual(sctlr & 0x5, 0, f'{b}: the core was entered with the MMU or the data cache on')
        return fa, fb

    def test_phase_one_runs_the_real_stub_at_el2_and_the_core_goes_off(self):
        lines = self.printed('happy')
        self.assertEqual(lines[0], f'BOOT_CPU MPIDR_EL1=0X80000000 CNTFRQ_EL0={QEMU_CNTFRQ}')
        self.assertEqual(self.find('happy', r'AFFINITY 0X1=OFF .*')[0].split()[1], '0X1=OFF')
        order = [lines.index(x) for x in ('NEXT AFFINITY', 'NEXT PREPARE', 'NEXT CPU_ON 0X1 AFTER 8 S', 'P1 CPU_ON 0X1 RET=0X0:SUCCESS',
                                          'P1 POWER_OFF OFF=1 NOT_OFF=0', 'P1 NORMAL', 'NEXT CPU_ON ALL AFTER 8 S')]
        self.assertEqual(order, sorted(order))
        self.check_core('happy', 1, 1)
        self.assertNotIn('P1 0X1 FAULT', ' '.join(lines))

    def test_the_eight_seconds_between_the_next_line_and_the_start_are_real(self):
        for announce, started in (('NEXT CPU_ON 0X1 AFTER 8 S', 'P1 CPU_ON 0X1 RET=0X0:SUCCESS'), ('NEXT CPU_ON ALL AFTER 8 S', 'P2 CPU_ON ISSUED=11 SUCCESS=11')):
            gap = self.stamp('happy', started) - self.stamp('happy', announce)
            self.assertGreaterEqual(gap, 7.0, f'{announce}: the CPU_ON was reported {gap:.1f} s after its NEXT line')
            self.assertLess(gap, 30, f'{announce}: {gap:.1f} s')
        # The announcement is on the page before the preparation that is risky for the core to be started: the cache work is
        # announced first and is over in well under a second.
        self.assertLessEqual(self.stamp('happy', 'NEXT PREPARE'), self.stamp('happy', 'NEXT CPU_ON 0X1 AFTER 8 S'))

    def test_phase_two_starts_eleven_cores_that_report_and_go_off(self):
        lines = self.printed('happy')
        self.assertIn('P2 CPU_ON ISSUED=11 SUCCESS=11', lines)
        seen = []
        for target in range(1, 12):
            fa, fb = self.check_core('happy', 2, target)
            seen.append(fa['DT_US'])
        self.assertEqual(len(seen), 11)
        self.assertIn('P2 POWER_OFF OFF=11 NOT_OFF=0', lines)
        self.assertIn('CORES STARTED=11 REPORTED=11 OFF=11', lines)
        self.assertEqual(lines[-1], 'NOT_DONE NO_SYSTEM_OFF_RESET_SUSPEND NO_CPU_SUSPEND BOOT_CPU_NO_MSR LEFT_RUNNING=0')
        self.assertEqual(lines[-2], 'CORES STARTED=11 REPORTED=11 OFF=11')
        self.assertIn('RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=38 DROPPED=0', self.done('happy'))
        self.assertNotIn('SYNCHRONOUS EXCEPTION', self.boot('happy').text)

    def test_every_line_is_in_the_page_font_and_at_most_a_hundred_characters(self):
        for name in self.runs:
            for line in self.after(name).split('\n'):
                if line.startswith('PAYLOAD '):
                    self.assertRegex(line, FONT_LINE, f'{name}: {line}')
                    self.assertLessEqual(len(line), 100, f'{name}: {line}')
            self.assertLessEqual(len(self.printed(name)), 40, name)

    def test_the_same_core_is_started_in_both_phases_and_goes_off_between(self):
        lines = self.printed('happy')
        self.assertEqual(sum(line.startswith('P1 0X1 EL=') for line in lines), 1)
        self.assertEqual(sum(line.startswith('P2 0X1 EL=') for line in lines), 1, 'core 0X1 is started again in phase 2')
        self.assertLess(lines.index('P1 POWER_OFF OFF=1 NOT_OFF=0'), lines.index('NEXT CPU_ON ALL AFTER 8 S'))

    # -- the stub with one edit -----------------------------------------------------------------------------------------------
    def udf_address(self):
        dis = lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(self.elfs['fault'])]).stdout
        found = re.findall(r'^\s+([0-9a-f]+):\s+udf\s', dis, re.M)
        self.assertEqual(len(found), 1)
        return int(found[0], 16)

    def test_a_fault_on_a_secondary_is_reported_by_its_own_vectors(self):
        lines = self.printed('fault')
        fault = self.find('fault', r'P1 0X1 FAULT STAGE=2 VECTOR=4 ESR_EL2=0X[0-9A-F]+ ELR_EL2=0X[0-9A-F]+ FAR_EL2=0X[0-9A-F]+')[0]
        values = self.fields(fault)
        self.assertEqual(int(values['ESR_EL2'], 16) >> 26, 0, 'EC 0: an undefined instruction')
        # The image is loaded at the base the runner printed for index 0; the udf is at its offset from there.
        base = int(re.search(r'PAYLOAD LOADED INDEX=0 BASE=0X([0-9A-F]+)', self.boot('fault').text).group(1), 16)
        self.assertEqual(int(values['ELR_EL2'], 16), base + self.udf_address(), 'ELR_EL2 is the udf itself')
        self.assertIn('P1 ABNORMAL=FAULT', lines)
        self.assertIn('P1 POWER_OFF OFF=1 NOT_OFF=0', lines, 'the vector took the core to CPU_OFF')
        self.assertIn('P2 SKIPPED=P1_NOT_NORMAL', lines)
        self.assertFalse([line for line in lines if line.startswith('P1 0X1 SCTLR_EL2')], 'no registers were stored before the fault')

    def test_a_stub_that_takes_el2_for_another_el_stores_only_currentel_and_powers_off(self):
        lines = self.printed('notel2')
        self.assertIn('P1 0X1 ENTERED_AT_EL2 NOT_EL2 CURRENTEL=0X8', lines)
        self.assertIn('P1 ABNORMAL=NOT_EL2', lines)
        self.assertIn('P1 POWER_OFF OFF=1 NOT_OFF=0', lines)
        self.assertIn('P2 SKIPPED=P1_NOT_NORMAL', lines)

    def test_a_stub_that_never_publishes_its_flag_is_no_report_not_success(self):
        lines = self.printed('noflag')
        self.assertIn('P1 0X1 NO_REPORT STAGE=3 CURRENTEL=0X8', lines)
        self.assertIn('P1 ABNORMAL=NO_REPORT', lines)
        self.assertIn('CORES STARTED=1 REPORTED=0 OFF=1', lines)
        # The primary polls for its second before it gives up, and not much longer (the stamps have the poll's 0.2 s granularity).
        waited = self.stamp('noflag', 'P1 0X1 NO_REPORT STAGE=3 CURRENTEL=0X8') - self.stamp('noflag', 'P1 CPU_ON 0X1 RET=0X0:SUCCESS')
        self.assertGreaterEqual(waited, 0.5)
        self.assertLess(waited, 15)

    def test_a_core_whose_cpu_off_returns_is_left_running_and_the_payload_says_so(self):
        lines = self.printed('parked')
        self.assertIn('P1 ABNORMAL=NOT_OFF', lines)
        self.assertEqual(self.find('parked', r'P1 NOT_OFF 0X1=ON')[0], 'P1 NOT_OFF 0X1=ON')
        self.find('parked', r'P1 0X1 STILL_ON LAST=ON KIND=4 CPU_OFF_RET=0X[0-9A-F]+')
        self.assertEqual(lines[-1], 'NOT_DONE NO_SYSTEM_OFF_RESET_SUSPEND NO_CPU_SUSPEND BOOT_CPU_NO_MSR LEFT_RUNNING=1')
        self.assertIn('RETURN=0X2 STACK=OK', self.done('parked'))
        self.assertIn('P2 SKIPPED=P1_NOT_NORMAL', lines)

    def test_two_back_to_back_cpu_on_for_one_core_are_never_taken_for_two_reports(self):
        # QEMU 11.1.3 answers both with success (no ON_PENDING, no window between the request and the start) and the later
        # request wins: its slot gets the report, the earlier one stays empty. A PSCI that answers the second with ALREADY_ON
        # or ON_PENDING (what the unit's is expected to do, UNKNOWN) is the other outcome, and the payload names it.
        lines = self.printed('twice')
        two_reports = sum(line.startswith('P2 0X2 EL=') for line in lines)
        silent = [line for line in lines if line.startswith('P2 0X2 NO_REPORT')]
        if 'P2 CPU_ON ISSUED=11 SUCCESS=11' in lines:
            self.assertEqual((two_reports, len(silent)), (1, 1), lines)
            self.assertEqual(silent[0], 'P2 0X2 NO_REPORT STAGE=0 CURRENTEL=0X0')
            self.assertIn('CORES STARTED=11 REPORTED=10 OFF=11', lines)
        else:
            self.assertIn('P2 CPU_ON ISSUED=11 SUCCESS=10', lines)
            self.find('twice', r'P2 CPU_ON_FAILED 0X2=(ALREADY_ON\(-4\)|ON_PENDING\(-5\))')
            self.assertEqual((two_reports, len(silent)), (1, 0), lines)
            self.assertIn('CORES STARTED=10 REPORTED=10 OFF=10', lines)
        self.assertEqual(lines[-1], 'NOT_DONE NO_SYSTEM_OFF_RESET_SUSPEND NO_CPU_SUSPEND BOOT_CPU_NO_MSR LEFT_RUNNING=0')

    def test_a_cpu_on_for_a_core_that_is_running_is_answered_already_on_by_name_and_not_counted(self):
        lines = self.printed('again')
        self.assertIn('P1 NORMAL', lines, 'the variant ignores a core that never goes OFF, so that phase 2 runs')
        self.assertIn('P1 POWER_OFF OFF=0 NOT_OFF=1', lines)
        self.assertIn('P2 CPU_ON ISSUED=11 SUCCESS=10', lines)
        self.assertIn('P2 CPU_ON_FAILED 0X1=ALREADY_ON(-4)', lines)
        self.assertEqual(sum(line.startswith('P2 0X1 EL=') for line in lines), 0, 'the refused core has no phase 2 report')
        self.assertEqual(sum(line.startswith('P2 0X') and ' EL=' in line for line in lines), 10)
        # The variant parks every stub, so all eleven cores are left running. The page then runs out of lines: the late reads
        # are dropped and counted, and the four NEXT lines, the summary and the last line are all still there.
        self.assertIn('P2 POWER_OFF OFF=0 NOT_OFF=10', lines)
        suppressed = int(self.find('again', r'CORES STARTED=10 REPORTED=10 OFF=0 SUPPRESSED=\d+')[0].rsplit('=', 1)[1])
        self.assertGreater(suppressed, 0)
        for essential in ('NEXT AFFINITY', 'NEXT PREPARE', 'NEXT CPU_ON 0X1 AFTER 8 S', 'NEXT CPU_ON ALL AFTER 8 S'):
            self.assertIn(essential, lines)
        self.assertEqual(lines[-1], 'NOT_DONE NO_SYSTEM_OFF_RESET_SUSPEND NO_CPU_SUSPEND BOOT_CPU_NO_MSR LEFT_RUNNING=11')
        self.assertEqual(len(lines), 40)
        self.assertIn('RETURN=0X2 STACK=OK', self.done('again'))
        self.assertIn(' LINES=40 DROPPED=0', self.done('again'), 'the payload kept to its own budget: the runner dropped nothing')

    def test_the_panel_in_the_document_is_what_qemu_printed(self):
        text = DOC.read_text(encoding='utf-8')
        section = text[text.index('<!-- cpuon-qemu-panel -->'):text.index('<!-- /cpuon-qemu-panel -->')]
        documented = [line for line in section.splitlines() if line and not line.startswith(('<!--', '```'))]
        mask = lambda line: re.sub(r'DT_US=-?\d+', 'DT_US=N', line)  # noqa: E731
        self.assertEqual([mask(line) for line in documented], [mask(line) for line in self.printed('happy')])

    # -- what QEMU cannot show ----------------------------------------------------------------------------------------------------
    @unittest.skip('QEMU is cache coherent: a missing DC CIVAC before a start or a missing DC IVAC before a read cannot show here; '
                   'the host model checks them and the hardware run is NOT RUN')
    def test_the_cache_rules_are_validated(self):
        pass


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
