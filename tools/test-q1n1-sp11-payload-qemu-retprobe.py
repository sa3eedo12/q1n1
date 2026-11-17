#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The retprobe payload of the Surface Pro 11 stick payload runner at EL2 under QEMU's EDK2 shell (docs/SP11-PAYLOAD-RETPROBE.md).

    python3 tools/test-q1n1-sp11-payload-qemu-retprobe.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables) and boots QEMU on `virt,virtualization=on,
gic-version=3` with a stick that carries the real retprobe.bin and, in four of the five boots, its 64-byte configuration file
(RETPATH.DAT, written here by an independent writer):
  * no configuration: PHASE 1 only. PSCI_FEATURES says SYSTEM_RESET is implemented and SYSTEM_RESET2 is not (QEMU's own PSCI), nothing is
    written, nothing is reset, the payload returns 0;
  * path none: three pages are written; the guest's RAM, read through QMP (pmemsave) after the page is up, holds three whole pages
    that an independent oracle of the format accepts byte for byte; the payload returns 0 and calls nothing else;
  * path SYSTEM_RESET with a two-second countdown: the pages are written and cleaned first, the countdown is two real seconds, the
    last line is `RESET CALL SYSTEM_RESET`, QEMU's PSCI takes the call (the virtual machine stops, `-no-reboot -no-shutdown`) and no
    DONE line follows; the pages are still whole;
  * path SYSTEM_RESET2: QEMU's PSCI does not report it, so the payload refuses before any store and returns 7: no page, no reset;
  * a configuration whose first page is not in the memory map: refused, returns 5, nothing stored.
What it proves: the real binary, at a real EL2 with its MMU on and the runner's real guarded loads, reads three RAM pages that were
never written, writes the page format, cleans it, and makes the PSCI call it is configured to make. It does not prove that RAM
survives a reset (the end-to-end test of Snapintosh, tools/test-sp11-retention-qemu.py, does that under QEMU, and the unit is the
question), nor anything about the unit's firmware. Hardware NOT RUN. Evidence: EXPERIMENTAL (QEMU only).

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image. Writes only under
build/sp11-payload-qemu-retprobe/ (short names: a socket path may not exceed 104 characters)."""
import concurrent.futures
import json
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_ecv_lib as ecv  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-qemu-retprobe'
PREFIX = 'PAYLOAD RETPROBE '
PAGES = (0x48000000, 0x50000000, 0x58000000)        # inside the 512 MiB of QEMU's RAM (0x40000000 to 0x60000000), far from the firmware's own use
HEX = r'0X[0-9A-F]+'


def config_bytes(path, countdown, pages):
    body = b'RETCFG01' + struct.pack('<IIII', 1, path, countdown, 3) + b''.join(struct.pack('<Q', page) for page in pages) + bytes(12)
    return body + struct.pack('<I', zlib.crc32(body))


class Qmp:
    def __init__(self, path, timeout=60):
        deadline = time.monotonic() + timeout
        while not Path(path).exists():
            if time.monotonic() > deadline:
                raise RuntimeError('no QMP socket')
            time.sleep(0.1)
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(30)
        self.sock.connect(str(path))
        self.stream = self.sock.makefile('rw')
        self.stream.readline()
        self.call('qmp_capabilities')

    def call(self, command, **arguments):
        self.stream.write(json.dumps({'execute': command, 'arguments': arguments}) + '\n')
        self.stream.flush()
        while True:
            reply = json.loads(self.stream.readline())
            if 'return' in reply or 'error' in reply:
                break
        if 'error' in reply:
            raise RuntimeError(f'QMP {command} failed: {reply}')
        return reply['return']

    def close(self):
        self.stream.close()
        self.sock.close()


class Boot:
    def __init__(self, name, files, until, pages=PAGES):
        self.name, self.files, self.until, self.pages = name, files, until, pages
        self.text, self.stamps, self.dumps, self.status = '', {}, {}, None

    def lines(self):
        return [line[len(PREFIX):] for line in self.text.split('\n') if line.startswith(PREFIX)]


def boot(run, runner, firmware):
    """One boot with a QMP socket and `-no-reboot -no-shutdown`: when the guest resets, QEMU stays up with its RAM and stops. Waits for
    `run.until(text)`, then reads the pages of `run.pages` with pmemsave."""
    esp = BUILD / run.name
    shutil.rmtree(esp, ignore_errors=True)
    (esp / 'SP11').mkdir(parents=True)
    shutil.copy(runner, esp / 'SP11' / 'Q1N1-PAYLOAD.EFI')
    for relative, data in run.files.items():
        (esp / relative).parent.mkdir(parents=True, exist_ok=True)
        (esp / relative).write_bytes(data)
    (esp / 'startup.nsh').write_text(ecv.qemu_base().script())
    serial, qmp_path = BUILD / f'{run.name}.log', BUILD / f'{run.name}.q'
    serial.unlink(missing_ok=True)
    qmp_path.unlink(missing_ok=True)
    cmd = ['qemu-system-aarch64', '-machine', 'virt,virtualization=on,gic-version=3', '-accel', 'tcg', '-cpu', 'max', '-smp', '1', '-m', '512M',
           '-bios', firmware, '-drive', f'format=raw,file=fat:rw:{esp}', '-device', 'ramfb', '-display', 'none', '-monitor', 'none', '-nic', 'none',
           '-serial', f'file:{serial}', '-qmp', f'unix:{qmp_path},server=on,wait=off', '-no-reboot', '-no-shutdown']
    proc = subprocess.Popen(cmd, env=lib.ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    qmp = None
    try:
        qmp = Qmp(qmp_path)
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.2)
            if not serial.exists():
                continue
            run.text = ecv.qemu_base().helpers.ANSI.sub('', serial.read_text(errors='replace').replace('\r', ''))
            now = time.monotonic()
            for line in run.text.split('\n'):
                if line.startswith('PAYLOAD ') and line not in run.stamps:
                    run.stamps[line] = now
            if run.until(run.text):
                break
        time.sleep(1.0)                                   # a call that stops the machine needs a moment to do so
        run.status = qmp.call('query-status')['status']
        run.text = ecv.qemu_base().helpers.ANSI.sub('', serial.read_text(errors='replace').replace('\r', ''))
        for k, address in enumerate(run.pages):
            dump = BUILD / f'{run.name}-page{k}.bin'
            dump.unlink(missing_ok=True)
            qmp.call('pmemsave', val=address, size=4096, filename=str(dump))
            run.dumps[k] = dump.read_bytes()
    finally:
        if qmp:
            qmp.close()
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return run


# ---- An oracle of the page format, with explicit byte offsets: it never touches the payload's or the Snapintosh tool's code -----------

def check_page(page, slot, address, counter, path, features):
    """[] when `page` is exactly the page of boot `counter`, else why not."""
    problems = []
    if page[:8] != b'RETCAN01':
        return ['magic']
    fields = struct.unpack_from('<IIQIIQII', page, 8)
    version, index, where, boot_counter, previous, timestamp, frequency, feature_reset = fields
    feature_reset2 = struct.unpack_from('<I', page, 48)[0]
    requested, used, ps0, ps1, ps2, flush = page[52:58]
    extent_type, extent_start, extent_bytes = struct.unpack_from('<IQQ', page, 60)
    expect = {'version': (version, 1), 'index': (index, slot), 'address': (where, address), 'counter': (boot_counter, counter),
              'previous': (previous, counter - 1), 'features': ((feature_reset, feature_reset2), features), 'requested': (requested, path),
              'used': (used, path), 'flush': (flush, 1), 'extent type': (extent_type, 7)}
    problems += [name for name, (got, want) in expect.items() if got != want]
    if not timestamp or not frequency:
        problems.append('timestamp or frequency is zero')
    if not extent_start <= address < extent_start + extent_bytes:
        problems.append('extent does not hold the page')
    if any(page[80:124]) or page[58:60] != b'\0\0':
        problems.append('reserved bytes')
    for i in range(992):
        if struct.unpack_from('<I', page, 128 + 4 * i)[0] != (counter << 12 | slot << 10 | i):
            problems.append(f'body word {i}')
            break
    crc_field = struct.unpack_from('<I', page, 124)[0]
    if zlib.crc32(page[:124] + bytes(4) + page[128:]) != crc_field:
        problems.append('crc')
    return problems


class RetprobeQemu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'lld-link', 'ld.lld', 'make', 'qemu-system-aarch64', 'llvm-objdump'):
            if not lib.have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        cls.firmware = ecv.find_firmware()
        if not cls.firmware:
            raise unittest.SkipTest('no EDK2 aarch64 firmware (set Q1N1_EDK2_CODE)')
        shutil.rmtree(BUILD, ignore_errors=True)
        BUILD.mkdir(parents=True)
        out = BUILD / 'out'
        cls.runner = ecv.build_runner_and_payloads(out)
        cls.payload = (out / 'payloads' / 'retprobe.bin').read_bytes()

        def stick(config):
            entries = [('RETPROBE.BIN', cls.payload)] + ([('RETPATH.DAT', config)] if config else [])
            return ecv.stick(entries)
        done = lambda text: 'PAYLOAD DONE INDEX=0 ' in text  # noqa: E731
        called = lambda text: 'RESET CALL SYSTEM_RESET' in text  # noqa: E731
        cls.boots = {
            'plain': Boot('plain', stick(None), done),
            'none': Boot('none', stick(config_bytes(0, 8, PAGES)), done),
            'reset': Boot('reset', stick(config_bytes(1, 2, PAGES)), called),
            'reset2': Boot('reset2', stick(config_bytes(2, 2, PAGES)), done),
            'badpage': Boot('badpage', stick(config_bytes(0, 8, (0x100000, PAGES[1], PAGES[2]))), done, pages=(0x100000, PAGES[1], PAGES[2])),
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(lambda b: boot(b, cls.runner, cls.firmware), cls.boots.values()))

    def done_line(self, run):
        found = [line for line in run.text.split('\n') if line.startswith('PAYLOAD DONE INDEX=0 ')]
        self.assertTrue(found, f'{run.name} did not finish:\n{run.text[-1500:]}')
        return found[0]

    def test_without_a_configuration_only_the_features_are_asked(self):
        run = self.boots['plain']
        lines = run.lines()
        self.assertEqual(lines[0], 'CONFIG NONE=NO_FILE')
        self.assertIn('FEATURES SYSTEM_RESET=0X0:IMPLEMENTED', lines)
        self.assertIn('FEATURES SYSTEM_RESET2=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)', lines)
        self.assertEqual(lines[-1], 'SKIPPED PHASE2=NO_CONFIG')
        self.assertRegex(self.done_line(run), r'RETURN=0X0 STACK=OK LOADS=0 FAULTS=0 REFUSED=0 LINES=\d+ DROPPED=0')
        for dump in run.dumps.values():
            self.assertNotEqual(dump[:8], b'RETCAN01')

    def test_with_path_none_three_whole_pages_are_in_ram_and_nothing_is_reset(self):
        run = self.boots['none']
        lines = run.lines()
        self.assertEqual(lines[0], 'CONFIG OK PATH=NONE COUNTDOWN=8 PAGES=3')
        self.assertTrue(all(re.fullmatch(rf'PAGE INDEX={k} BASE={HEX} EXTENT={HEX} BYTES={HEX} MAP=WB\.[A-Z]+(\.NS1)?', lines[5 + k]) for k in range(3)), lines[:10])
        self.assertIn('NEXT READ PREVIOUS PAGES', lines)
        self.assertIn('COUNTER THIS=1 PREVIOUS=0', lines)
        self.assertEqual(lines[-3:], ['VERIFY OK', 'PATH REQUESTED=NONE USED=NONE', 'RESET NONE CANARIES STAY FOR A MANUAL RESET'])
        self.assertEqual(run.status, 'running', 'nothing reset or stopped the machine')
        self.assertRegex(self.done_line(run), r'RETURN=0X0 STACK=OK LOADS=3072 FAULTS=0 REFUSED=0 LINES=\d+ DROPPED=0')
        self.assertNotIn('RESET CALL', run.text)
        for k, address in enumerate(PAGES):
            self.assertEqual(check_page(run.dumps[k], k, address, 1, 0, (0, 0xFFFFFFFF)), [], f'page {k}')
        self.assertEqual(len({struct.unpack_from('<Q', run.dumps[k], 32)[0] for k in range(3)}), 1, 'one timestamp for the three pages')

    def test_the_clean_line_agrees_with_the_line_size_the_unit_would_be_asked(self):
        lines = self.boots['none'].lines()
        clean = [line for line in lines if line.startswith('CLEAN ')][0]
        found = re.fullmatch(r'CLEAN DC_CVAC_DSB LINE=(\d+) LINES=(\d+)', clean)
        self.assertIsNotNone(found, clean)
        line, count = int(found.group(1)), int(found.group(2))
        self.assertIn(line, (16, 32, 64, 128))
        self.assertEqual(count, 3 * 4096 // line)

    def test_with_system_reset_the_call_is_the_last_thing_and_the_countdown_is_real_time(self):
        run = self.boots['reset']
        lines = run.lines()
        self.assertEqual(lines[0], 'CONFIG OK PATH=PSCI_RESET COUNTDOWN=2 PAGES=3')
        self.assertEqual(lines[-4:], ['VERIFY OK', 'PATH REQUESTED=PSCI_RESET USED=PSCI_RESET', 'NEXT RESET AFTER 2 S', 'RESET CALL SYSTEM_RESET'])
        self.assertNotIn('PAYLOAD DONE INDEX=0', run.text)
        seconds = ecv.wait_seconds(run, PREFIX + 'NEXT RESET AFTER 2 S', PREFIX + 'RESET CALL SYSTEM_RESET')
        self.assertTrue(1.5 <= seconds <= 20.0, f'{seconds:.2f} s between the countdown line and the call')
        self.assertEqual(run.status, 'shutdown', 'QEMU took the PSCI call and stopped the machine')
        for k, address in enumerate(PAGES):
            self.assertEqual(check_page(run.dumps[k], k, address, 1, 1, (0, 0xFFFFFFFF)), [], f'page {k} after the reset call')

    def test_system_reset2_is_refused_before_any_store_because_qemu_does_not_report_it(self):
        run = self.boots['reset2']
        lines = run.lines()
        self.assertIn('FEATURES SYSTEM_RESET2=0XFFFFFFFFFFFFFFFF:NOT_SUPPORTED(-1)', lines)
        self.assertEqual(lines[-1], 'REFUSED RESET_NOT_IMPLEMENTED SYSTEM_RESET2')
        self.assertRegex(self.done_line(run), r'RETURN=0X7 STACK=OK LOADS=0 ')
        self.assertNotIn('NEXT WRITE PAGES', lines)
        for dump in run.dumps.values():
            self.assertNotEqual(dump[:8], b'RETCAN01')
        self.assertEqual(run.status, 'running', 'refused, not reset')

    def test_a_page_outside_the_memory_map_is_refused_and_nothing_is_stored(self):
        run = self.boots['badpage']
        lines = run.lines()
        self.assertTrue(any(re.fullmatch(r'REFUSED PAGE=NOT_IN_MAP INDEX=0 BASE=0X100000', line) for line in lines), lines)
        self.assertRegex(self.done_line(run), r'RETURN=0X5 STACK=OK LOADS=0 ')
        for dump in list(run.dumps.values())[1:]:
            self.assertNotEqual(dump[:8], b'RETCAN01')

    def test_every_line_is_in_the_page_font_and_within_the_budget(self):
        for name, run in self.boots.items():
            with self.subTest(boot=name):
                lines = run.lines()
                self.assertLessEqual(len(lines), 40)
                for line in lines:
                    self.assertRegex(PREFIX + line, r'^[A-Z0-9 :\-./=?()_]{1,100}$')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
