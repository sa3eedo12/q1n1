#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end checks of the SP11 q1n1.efi under QEMU's EDK2 shell.

    python3 tools/test-q1n1-sp11-qemu.py

Builds the SP11=1 image (fixture USB and stage tables, as tools/test-q1n1-sp11-entry.py does) and
boots it twice: as the no-argument preflight, and as `--el2 --uart` at EL2, which runs the declared
ranges, the pre-ExitBootServices report, a real ExitBootServices and the post-EBS page whose text the
PL011 serial log carries. These are the flows the host tests cannot reach: the --el2 declaration once
silently declared nothing because it read a global only the --boot path sets, and no pure function
could see that.

QEMU and its EDK2 are a model, not the Surface: its firmware, GOP, memory map and EL2 entry differ,
and slbounce is absent, so ExitBootServices here is the real one and nothing about the scoped sweep
is exercised. Evidence: EXPERIMENTAL (QEMU only); hardware NOT RUN. SKIPs, never passes, without
clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image (Q1N1_EDK2_CODE
overrides the search). Writes only under build/sp11-qemu-test/.
"""
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'build' / 'sp11-qemu-test'
LLVM = ('/opt/homebrew/opt/llvm/bin', '/opt/homebrew/opt/lld/bin', '/opt/homebrew/bin')
ENV = dict(os.environ, PATH=os.pathsep.join(LLVM + (os.environ.get('PATH', ''),)), PYTHONDONTWRITEBYTECODE='1')
# Types the paired slbounce scoped sweep accepts (its src/sp11_scoped_sweep.c) and the WB bit it wants.
SWEPT_TYPES = {1, 2, 3, 4, 5, 6, 9}
EFI_MEMORY_WB = 1 << 3
ANSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')


def have(tool):
    return shutil.which(tool, path=ENV['PATH']) is not None


def expected_stamp():
    """What platform/uefi/Makefile's SP11_BUILD_STAMP evaluates to for this checkout."""
    done = subprocess.run(['git', 'describe', '--always', '--dirty', '--abbrev=12', '--exclude=*'], cwd=ROOT,
                          env=ENV, capture_output=True, text=True)
    raw = done.stdout.strip() if done.returncode == 0 else ''
    return re.sub(r'[^A-Z0-9-]', '-', raw.upper()) or 'UNSTAMPED'


def screendump(qmp_path, out_path):
    """Asks QEMU, over its QMP socket, to write the guest display to a PPM file."""
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(30)
    sock.connect(str(qmp_path))
    stream = sock.makefile('rw')
    stream.readline()
    for message in ({'execute': 'qmp_capabilities'},
                    {'execute': 'screendump', 'arguments': {'filename': str(out_path)}}):
        stream.write(json.dumps(message) + '\n')
        stream.flush()
        reply = stream.readline()
        if 'error' in reply:
            raise RuntimeError(f'QMP {message["execute"]} failed: {reply}')
    sock.close()


def read_ppm(path):
    data = Path(path).read_bytes()
    header = re.match(rb'P6\s+(\d+)\s+(\d+)\s+255\s', data)
    if not header:
        raise RuntimeError(f'{path}: not a binary PPM')
    width, height = int(header.group(1)), int(header.group(2))
    pixels = data[header.end():]
    if len(pixels) != width * height * 3:
        raise RuntimeError(f'{path}: truncated PPM')
    return width, height, pixels


def find_firmware():
    override = os.environ.get('Q1N1_EDK2_CODE')
    if override:
        return override if os.path.isfile(override) else None
    qemu = shutil.which('qemu-system-aarch64', path=ENV['PATH'])
    if not qemu:
        return None
    for prefix in (Path(qemu).parent.parent, Path(os.path.realpath(qemu)).parent.parent):
        candidate = prefix / 'share/qemu/edk2-aarch64-code.fd'
        if candidate.is_file():
            return str(candidate)
    return None


class SP11Qemu(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ('clang', 'lld-link', 'ld.lld', 'make', 'qemu-system-aarch64'):
            if not have(tool):
                raise unittest.SkipTest(f'{tool} not installed')
        cls.firmware = find_firmware()
        if not cls.firmware:
            raise unittest.SkipTest('no EDK2 aarch64 firmware (set Q1N1_EDK2_CODE)')
        out = BUILD / 'out'
        shutil.rmtree(out, ignore_errors=True)
        BUILD.mkdir(parents=True, exist_ok=True)
        done = subprocess.run(
            ['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j4', 'all', 'SP11=1',
             'SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c',
             'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c'],
            cwd=ROOT, env=ENV, capture_output=True, text=True)
        if done.returncode:
            raise RuntimeError('SP11=1 build failed:\n' + done.stdout[-2000:] + done.stderr[-2000:])
        cls.image = out / 'q1n1.efi'
        cls.stamp = expected_stamp()

    def boot(self, name, options, el2, marker, timeout=170, during=None):
        """Runs q1n1.efi with `options` from the EDK2 shell until `marker` appears on the serial log
        (or `timeout` seconds pass), then returns the cleaned log after stopping QEMU. `during`, if given,
        is called with the QMP socket path once the marker has appeared and QEMU is still running."""
        esp = BUILD / name
        shutil.rmtree(esp, ignore_errors=True)
        esp.mkdir(parents=True)
        shutil.copy(self.image, esp / 'Q1N1.EFI')
        (esp / 'startup.nsh').write_text(f'fs0:\nQ1N1.EFI {options}\necho Q1N1_SHELL_RETURN_OK\n')
        serial = BUILD / f'{name}.serial.log'
        qmp = BUILD / f'{name}.qmp'
        serial.unlink(missing_ok=True)
        qmp.unlink(missing_ok=True)
        cmd = ['qemu-system-aarch64', '-machine', f'virt,virtualization={"on" if el2 else "off"},gic-version=3',
               '-accel', 'tcg', '-cpu', 'max', '-smp', '1', '-m', '512M', '-bios', self.firmware,
               '-drive', f'format=raw,file=fat:rw:{esp}', '-device', 'ramfb', '-display', 'none',
               '-monitor', 'none', '-nic', 'none', '-serial', f'file:{serial}',
               '-qmp', f'unix:{qmp},server=on,wait=off', '-no-reboot']
        proc = subprocess.Popen(cmd, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        text = ''
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and proc.poll() is None:
                time.sleep(1)
                if serial.exists():
                    text = ANSI.sub('', serial.read_text(errors='replace').replace('\r', ''))
                    if marker in text:
                        break
            if during and marker in text:
                during(qmp)
                text = ANSI.sub('', serial.read_text(errors='replace').replace('\r', ''))
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        self.assertIn(marker, text, f'{name}: "{marker}" never appeared; inspect {serial}')
        return text

    def test_preflight_finds_the_gop_and_reports_the_facts(self):
        text = self.boot('preflight', '', el2=False, marker='Preflight only.')
        self.assertIn('GOP framebuffer captured.', text)
        self.assertRegex(text, r'SP11 GOP: locate_handle status 0x0, \d+ handles, [1-9]\d* with a mode')
        self.assertRegex(text, r'SP11 GOP: map status 0x0, OK, \d+ bytes, stride 48, [1-9]\d* entries')
        self.assertRegex(text, r'SP11 GOP: #0 base 0x[0-9A-F]+ bytes 0x[0-9A-F]+ -> OK')
        self.assertRegex(text, r'SP11 GOP: select OK, rule (SAME|CONSOLE)')

    def test_el2_declares_its_ranges_reports_them_and_exits_boot_services(self):
        text = self.boot('el2', '--el2 --uart', el2=True, marker='POWER CYCLE TO RETURN TO FIRMWARE')
        # The table was written (a regression here read a global only --boot sets and declared nothing).
        self.assertNotIn('no ranges declared', text)
        self.assertIn('SP11 EBS: set_variable=0x0 ranges=2 chunk=0x100000', text)
        self.assertRegex(text, r'SP11 EBS: map status=0x0 parse=OK entries=[1-9]\d*')
        ranges = re.findall(r'SP11 EBS: r(\d+) (\w+) base=0x[0-9A-F]+ size=0x[0-9A-F]+ desc=(\d+) type=(\d+) '
                            r'attr=(0x[0-9A-F]+) contained=(yes|NO)', text)
        # Printed before the point of no return and again on the post-EBS page: two copies of two ranges.
        self.assertEqual([(r[0], r[1]) for r in ranges], [('0', 'image'), ('1', 'map')] * 2, text)
        for _, label, desc, kind, attribute, contained in ranges:
            self.assertEqual((desc, contained), ('1', 'yes'), label)
            self.assertIn(int(kind), SWEPT_TYPES, f'{label} would be refused by the scoped sweep')
            self.assertTrue(int(attribute, 16) & EFI_MEMORY_WB, f'{label} lacks WB')
        # Exactly image and map: no framebuffer range (it is RESERVED memory on the real unit).
        # The report precedes the point of no return, and the post-EBS page followed it at EL2.
        self.assertLess(text.index('SP11 EBS: set_variable'), text.index('Leaving firmware now'))
        self.assertIn('EL2 CONFIRMED AFTER EXITBOOTSERVICES', text)
        self.assertIn('SP11 EBS: r0 image', text.split('EL2 CONFIRMED AFTER EXITBOOTSERVICES', 1)[1])

    def test_el2_page_names_the_build_and_reads_the_el2_state(self):
        text = self.boot('state', '--el2 --uart', el2=True, marker='POWER CYCLE TO RETURN TO FIRMWARE')
        page = text.split('EL2 CONFIRMED AFTER EXITBOOTSERVICES', 1)[1]
        # The photograph has to say which commit ran; the stamp is the checkout's, dirty marker included.
        self.assertIn(f'BUILD {self.stamp}\n', text)
        self.assertIn('EL2 STATE (READ ONLY)', page)

        def register(label):
            found = re.search(rf'^{label} 0X([0-9A-F]{{16}})(.*)$', page, re.M)
            self.assertIsNotNone(found, f'{label} line missing:\n{page}')
            return int(found.group(1), 16), found.group(2)

        # Every decoded flag must equal the bit of the raw value printed on the same line.
        hcr, flags = register('HCR_EL2')
        decoded = dict(re.findall(r'(\w+)=([01])', flags))
        self.assertEqual({k: int(v) for k, v in decoded.items()},
                         {'E2H': hcr >> 34 & 1, 'TGE': hcr >> 27 & 1, 'VM': hcr & 1, 'RW': hcr >> 31 & 1})
        sctlr, flags = register('SCTLR_EL2')
        decoded = dict(re.findall(r'(\w+)=([01])', flags))
        self.assertEqual({k: int(v) for k, v in decoded.items()},
                         {'M': sctlr & 1, 'C': sctlr >> 2 & 1, 'I': sctlr >> 12 & 1,
                          'WXN': sctlr >> 19 & 1, 'EE': sctlr >> 25 & 1})
        # q1n1_enter masks D, A, I and F before anything else runs; its own vectors are installed.
        self.assertEqual(register('DAIF')[0], 0x3c0)
        vbar = register('VBAR_EL2')[0]
        self.assertTrue(vbar and vbar % 0x800 == 0, f'VBAR_EL2 {vbar:#x} is not q1n1\'s 2 KiB-aligned table')
        self.assertGreater(register('CNTFRQ_EL0')[0], 0)
        for label in ('TCR_EL2', 'TTBR0_EL2', 'MAIR_EL2', 'CPTR_EL2', 'CNTHCTL_EL2', 'MPIDR_EL1', 'SPSEL'):
            register(label)
        # TTBR1_EL2 belongs to the translation regime only with E2H set.
        self.assertEqual('TTBR1_EL2 ' in page, bool(hcr >> 34 & 1))

    def test_el2_page_uptime_advances_and_nothing_else_moves(self):
        dumps = []

        def two_dumps(qmp):
            time.sleep(2)
            screendump(qmp, BUILD / 'uptime-a.ppm')
            time.sleep(5)
            screendump(qmp, BUILD / 'uptime-b.ppm')
            dumps.extend([read_ppm(BUILD / 'uptime-a.ppm'), read_ppm(BUILD / 'uptime-b.ppm')])

        self.boot('uptime', '--el2 --uart', el2=True, marker='POWER CYCLE TO RETURN TO FIRMWARE', during=two_dumps)
        (width, height, first), (_, _, second) = dumps
        # The bottom of the screen holds the heartbeat block, which toggles on its own; everything above
        # must be static except the one uptime line, which is the thing that proves the core is running.
        moved = [y for y in range(height - 40)
                 if first[y * width * 3:(y + 1) * width * 3] != second[y * width * 3:(y + 1) * width * 3]]
        self.assertTrue(moved, 'the uptime line never changed between two screenshots 5 s apart')
        scale = 3 if width >= 1600 else 2
        self.assertLessEqual(moved[-1] - moved[0] + 1, 9 * scale, f'more than one text row changed: {moved}')

    def test_el2_option_at_el1_never_reads_an_el2_register(self):
        # No EL2 in the machine, so no slbounce is needed to land at EL1 after ExitBootServices: the
        # amber page. An unguarded `mrs hcr_el2` here would be UNDEFINED and take q1n1's exception path.
        text = self.boot('el1', '--el2 --uart', el2=False, marker='POWER CYCLE TO RETURN TO FIRMWARE')
        page = text.split('EL2 NOT REACHED - STILL IN EL1', 1)[1]
        self.assertIn('EL2 STATE NOT READ (NOT AT EL2)', page)
        self.assertNotIn('HCR_EL2', page)
        self.assertNotIn('SYNCHRONOUS EXCEPTION', text)
        self.assertIn(f'BUILD {self.stamp}\n', text)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
