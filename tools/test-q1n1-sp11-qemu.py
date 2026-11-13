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

SP11StkSurveyQemu boots the same flows with the stage S0 stick-log survey image (STK_SURVEY=1,
q1n1-stk.efi, placed on the volume as Q1N1-STK.EFI), with the volume also on a USB mass storage device
behind QEMU's xHCI: it re-runs every SP11Qemu test against that image and checks the survey's lines
(docs/SP11-STK-SURVEY.md). Where QEMU lacks the Surface Pro 11's blocks the survey must fail closed:
every EL2 block prints SKIPPED or FAULT and it still reaches its verdict.

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

    stick_name = 'Q1N1.EFI'

    def boot(self, name, options, el2, marker, timeout=170, during=None, usb_stick=False):
        """Runs q1n1.efi with `options` from the EDK2 shell until `marker` appears on the serial log
        (or `timeout` seconds pass), then returns the cleaned log after stopping QEMU. `during`, if given,
        is called with the QMP socket path once the marker has appeared and QEMU is still running.
        `usb_stick` puts the volume on a USB mass storage device behind QEMU's xHCI, the way the real
        stick is attached, instead of on the default disk."""
        esp = BUILD / name
        shutil.rmtree(esp, ignore_errors=True)
        esp.mkdir(parents=True)
        shutil.copy(self.image, esp / self.stick_name)
        (esp / 'startup.nsh').write_text(f'fs0:\n{self.stick_name} {options}\necho Q1N1_SHELL_RETURN_OK\n')
        serial = BUILD / f'{name}.serial.log'
        qmp = BUILD / f'{name}.qmp'
        serial.unlink(missing_ok=True)
        qmp.unlink(missing_ok=True)
        volume = (['-drive', f'format=raw,file=fat:rw:{esp},if=none,id=stick', '-device', 'qemu-xhci',
                   '-device', 'usb-storage,drive=stick'] if usb_stick else
                  ['-drive', f'format=raw,file=fat:rw:{esp}'])
        cmd = ['qemu-system-aarch64', '-machine', f'virt,virtualization={"on" if el2 else "off"},gic-version=3',
               '-accel', 'tcg', '-cpu', 'max', '-smp', '1', '-m', '512M', '-bios', self.firmware] + volume + [
               '-device', 'ramfb', '-display', 'none',
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


STK_FONT_LINE = re.compile(r'[A-Z0-9 :\-./=?()_]{1,100}')


class SP11StkSurveyQemu(SP11Qemu):
    """Stage S0 of the stick-log survey (docs/SP11-STK-SURVEY.md): the image built with STK_SURVEY=1
    (q1n1-stk.efi) run from the volume as Q1N1-STK.EFI with the same `--el2 --uart`. Every test of
    SP11Qemu runs again against it -- the preflight, the EBS report, the EL2 page, the uptime row and
    the EL1 refusal -- which is the check that the survey adds lines and changes none of the page's own.

    QEMU does not have the Surface Pro 11's blocks: the clock controller window is mapped Normal (it is
    flash here), the USB windows are unmapped and the SMMU window answers all ones. So the fail-closed
    behaviour is what these tests look for: every EL2 block prints SKIPPED or FAULT, no controller
    register value is printed, nothing hangs and the survey reaches its verdict. QEMU is a model, not
    the Surface: EXPERIMENTAL, hardware NOT RUN."""
    stick_name = 'Q1N1-STK.EFI'

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        out = BUILD / 'out-stk'
        shutil.rmtree(out, ignore_errors=True)
        done = subprocess.run(
            ['make', '-f', 'platform/uefi/Makefile', f'OUT={out.relative_to(ROOT)}', '-j4', 'stk-survey', 'SP11=1',
             'STK_SURVEY=1', 'SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c',
             'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c'],
            cwd=ROOT, env=ENV, capture_output=True, text=True)
        if done.returncode:
            raise RuntimeError('STK_SURVEY=1 build failed:\n' + done.stdout[-2000:] + done.stderr[-2000:])
        cls.image = out / 'q1n1-stk.efi'

    @staticmethod
    def stk(text):
        return [line for line in text.split('\n') if line.startswith('STK ')]

    def assert_el2_blocks_failed_closed(self, lines):
        """What the EL2 half must look like where the Surface's blocks do not exist."""
        self.assertTrue(lines and lines[-1].startswith('STK P3 VERDICT'), lines[-3:])
        self.assertRegex(lines[-1], r'^STK P3 VERDICT U0=(UNREAD|FAULT|GATED-OFF) U1=(UNREAD|FAULT|GATED-OFF) '
                                    r'SMMU=(UNREAD|FAULT|BYPASS)$')
        order = ['STK NEXT MAP', 'STK P3 MAP', 'STK NEXT GCC', 'STK P3 GCC', 'STK P3 GATE', 'STK NEXT SMMU',
                 'STK P3 SMMU', 'STK P3 VERDICT']
        at = -1
        for prefix in order:
            found = next((i for i, line in enumerate(lines) if i > at and line.startswith(prefix)), None)
            self.assertIsNotNone(found, f'{prefix} missing or out of order in {lines}')
            at = found
        for line in lines:
            self.assertRegex(line, STK_FONT_LINE, line)
            # A block that was not read says why; a value from a controller or the clock controller would
            # mean a read that cannot have happened here.
            if re.match(r'STK P3 (GCC|U[01] )', line):
                self.assertTrue('SKIPPED=' in line or 'FAULT=' in line, line)
        self.assertLessEqual(len(lines), 60, 'more lines than the budget allows')

    def test_the_survey_reaches_its_verdict_with_every_el2_block_failed_closed(self):
        text = self.boot('stk-virtio', '--el2 --uart', el2=True, marker='STK P3 VERDICT')
        before, after = text.split('EL2 CONFIRMED AFTER EXITBOOTSERVICES', 1)
        self.assertNotIn('SYNCHRONOUS EXCEPTION', text)
        lines = self.stk(after)
        self.assert_el2_blocks_failed_closed(lines)
        # P2 ran before ExitBootServices, with the build line and the stick's path, and is repeated.
        p2_before = [line for line in self.stk(before) if line.startswith('STK P2 ')]
        p2_after = [line for line in lines if line.startswith('STK P2 ')]
        self.assertTrue(p2_before and p2_after)
        self.assertEqual(p2_before, p2_after)
        self.assertTrue(p2_before[0].startswith('STK P2 BUILD GATE=1 REV='), p2_before[0])
        self.assertTrue(any(line.startswith('STK P2 SELF PATH=') for line in p2_before))
        self.assertIn('STK P2 USBIO SKIPPED=NO_USB_NODE', p2_before)      # a virtio disk, not a stick
        self.assertIn('STK P2 UX SKIPPED=NOT_USB', p2_before)

    def test_p2_reports_the_usb_stick_it_was_loaded_from_and_no_identifier(self):
        text = self.boot('stk-usb', '--el2 --uart', el2=True, marker='STK P3 VERDICT', usb_stick=True)
        before, after = text.split('EL2 CONFIRMED AFTER EXITBOOTSERVICES', 1)
        self.assert_el2_blocks_failed_closed(self.stk(after))
        for part in (before, after):                      # at P2 time and again on the EL2 page
            lines = [line for line in self.stk(part) if line.startswith('STK P2 ')]
            joined = '\n'.join(lines)
            self.assertTrue(any(re.fullmatch(r'STK P2 SELF PATH=.*/USB\(\d+\.\d+\)/.*', line) for line in lines), lines)
            self.assertRegex(joined, r'STK P2 HUB USBNODES=1 ROOTIDX=\d+ HUBPORTIDX=NONE')
            self.assertRegex(joined, r'STK P2 USBIO BCDUSB=0X[0-9A-F]+ CLASS=0X8 SUB=0X6 PROTO=0X50 '
                                     r'EPIN=0X[0-9A-F]+ EPOUT=0X[0-9A-F]+ MPS=0X[0-9A-F]+')
            self.assertRegex(joined, r'STK P2 BLK LASTLBA=0X[0-9A-F]+ BLKSZ=0X[0-9A-F]+ REMOVABLE=[01] READONLY=[01]')
            self.assertIn('STK P2 HC N=1', lines)
            self.assertRegex(joined, r'STK P2 HC HC0 BAR0=0X[0-9A-F]+ CLASS=0XC0330 LOC=')
            # The baseline is the stick's own controller read through the firmware, and labelled UX
            # because its BAR is not one of the Surface's two windows.
            self.assertRegex(joined, r'STK P2 UX CAPLEN=0X[0-9A-F]+ USBCMD=0X[0-9A-F]+ USBSTS=0X[0-9A-F]+ ')
            # QEMU's stick has a vendor and product id and strings; none of them may appear.
            for line in lines:
                for banned in ('46F4', 'QEMU', 'VID', 'PID', 'SERIAL'):
                    self.assertNotIn(banned, line)

    def test_the_survey_image_prints_nothing_without_the_el2_option(self):
        text = self.boot('stk-preflight', '', el2=False, marker='Preflight only.')
        self.assertNotIn('STK ', text)

    def test_at_el1_the_survey_says_so_and_reads_nothing(self):
        text = self.boot('stk-el1', '--el2 --uart', el2=False, marker='STK P3 SKIPPED=NOT_AT_EL2')
        self.assertNotIn('SYNCHRONOUS EXCEPTION', text)
        before, after = text.split('EL2 NOT REACHED - STILL IN EL1', 1)
        self.assertFalse([line for line in self.stk(after) if line.startswith('STK NEXT')])
        self.assertTrue([line for line in self.stk(before) if line.startswith('STK P2 BUILD')])


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
