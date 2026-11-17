#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The xhci payload of the Surface Pro 11 stick payload runner at EL2 under QEMU's EDK2 shell, against QEMU's own xHC (docs/SP11-PAYLOAD-XHCI.md).

    python3 tools/test-q1n1-sp11-payload-qemu-xhci.py

Builds the runner and the payloads (SP11=1 PAYLOAD=1, fixture USB and stage tables), boots QEMU on `virt,virtualization=on,gic-version=3`
with `-device qemu-xhci` once to read where EDK2 put the controller's BAR (the shell's own `pci` command), then builds the payload for that
controller (the macros of payloads/xhci-regs.h that aim it at a window: no DWC3 core, no SMMU, CAPLENGTH 0x40, HCIVERSION 1.0) and boots the
stick with it:
  * the real sequence, at a real EL2 with its MMU on, against an xHC model that was written independently of it (QEMU's hcd-xhci.c):
    reset, program, run, a No Op Command TRB, its Command Completion Event in the event ring the payload built, the ring handed back,
    the controller halted: VERDICT NOOP_OK, END HALTED=YES WRITES=17;
  * the eight seconds before each group are real wall-clock time on QEMU's counter;
  * the same payload with a seeded bug that the host model also rejects (no doorbell, or the segment table not announced to the xHC, or its size
    not programmed): QEMU's xHC does not complete the No Op and the page says so (NOOP_TIMEOUT or NOOP_HSE). A fourth bug the host model rejects,
    the command ring's cycle state not set in CRCR, is not in this list because QEMU's xHC accepts it (it starts its command ring with cycle
    state 1 whatever CRCR.RCS holds): QEMU's model is more lenient than the specification there, and the host model is not.
What it proves: the programming order and the structures are what a second xHC implementation accepts. What it does not prove: anything
about the unit's DWC3, its SMMU or its clocks (QEMU's xHC is a PCI device with DMA straight into RAM; there is no scratchpad: QEMU's HCSPARAMS2
asks for none), coherence (QEMU's DMA is coherent), or that a USB-C port will ever show a device. Hardware NOT RUN. Evidence: EXPERIMENTAL.

SKIPs, never passes, without clang, lld-link, make, qemu-system-aarch64 or an EDK2 AArch64 firmware image, and when the shell's `pci`
command does not show the controller. Writes only under build/sp11-payload-qemu-xhci/ (short names: a socket path may not exceed 104
characters). A QEMU boot that fails is run once more by the test, and the retry is printed."""
import concurrent.futures
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
import sp11_payload_ecv_lib as ecv  # noqa: E402
import sp11_payload_xhci_lib as xl  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-qemu-xhci'
PREFIX = 'PAYLOAD XHCI '
ONLY = {name for name in os.environ.get('SP11_XHCI_QEMU_ONLY', '').split(',') if name}
# What QEMU's hcd-xhci.c reports (OBSERVED in the probe boot): the capability registers are 0x40 bytes, the version 1.00, the BAR 16 KiB.
QEMU_DEFINES = ['-DXHCI_S1_U0_BASE=0', '-DXHCI_S1_WINDOW=0x4000u', '-DXHCI_S1_SMMU_BASE=0', '-DXHCI_S1_DWC3_ID=0', '-DXHCI_S1_CAPLENGTH=0x40u',
                '-DXHCI_S1_HCIVERSION=0x0100u']
# Seeded bugs, each an edit of the payload (file, needle, replacement) that the host model rejects and that QEMU's xHC must not complete.
VARIANTS = {
    'nobell': ('payloads/xhci-ctl.c', '    if (store(c, G_NOOP, SR_DB0, 0)) return W_STORE;\n', ''),
    'noerst': ('payloads/xhci-ctl.c', '    if (store(c, G_PROGRAM, SR_ERSTBA_LO, (uint32_t)erst) || store(c, G_PROGRAM, SR_ERSTBA_HI, (uint32_t)(erst >> 32))) return W_STORE;\n', ''),
    'noerstsz': ('payloads/xhci-ctl.c', '    if (store(c, G_PROGRAM, SR_ERSTSZ, 1)) return W_STORE;\n', ''),
}
# What QEMU's xHC and the payload's own read-back make of each: the doorbell never rung leaves the No Op unanswered in every arena; a
# segment table or its size not programmed is seen by the read-back of the program stage, before any command.
EXPECTED = {
    'nobell': r'VERDICT NOOP_TIMEOUT STAGE=NOOP WHY=EVENT \| END HALTED=YES WRITES=\d+',
    'noerst': r'VERDICT NOOP_TIMEOUT STAGE=PROGRAM WHY=NOT_HELD \| END HALTED=YES WRITES=\d+',
    'noerstsz': r'VERDICT NOOP_TIMEOUT STAGE=PROGRAM WHY=NOT_HELD \| END HALTED=YES WRITES=\d+',
}


class Boot:
    def __init__(self, name, files, startup, marker, timeout=180):
        self.name, self.files, self.startup, self.marker, self.timeout = name, files, startup, marker, timeout
        self.text, self.stamps = '', {}


def run_boot(boot, runner, firmware):
    """qemu-system-aarch64 on `virt,virtualization=on` with a qemu-xhci, the EDK2 shell on a FAT directory; the serial log is polled every 0.2 s."""
    base = ecv.qemu_base()
    esp = BUILD / boot.name
    shutil.rmtree(esp, ignore_errors=True)
    (esp / 'SP11').mkdir(parents=True)
    shutil.copy(runner, esp / 'SP11' / 'Q1N1-PAYLOAD.EFI')
    for relative, data in boot.files.items():
        (esp / relative).parent.mkdir(parents=True, exist_ok=True)
        (esp / relative).write_bytes(data)
    (esp / 'startup.nsh').write_text(boot.startup)
    serial = BUILD / f'{boot.name}.log'
    serial.unlink(missing_ok=True)
    cmd = ['qemu-system-aarch64', '-machine', 'virt,virtualization=on,gic-version=3', '-accel', 'tcg', '-cpu', 'max', '-smp', '1', '-m', '512M',
           '-bios', firmware, '-drive', f'format=raw,file=fat:rw:{esp}', '-device', 'ramfb', '-device', 'qemu-xhci,id=xhc', '-display', 'none',
           '-monitor', 'none', '-nic', 'none', '-serial', f'file:{serial}', '-no-reboot']
    proc = subprocess.Popen(cmd, env=lib.ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + boot.timeout
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.2)
            if not serial.exists():
                continue
            boot.text = base.helpers.ANSI.sub('', serial.read_text(errors='replace').replace('\r', ''))
            now = time.monotonic()
            for line in boot.text.split('\n'):
                if line.startswith('PAYLOAD ') and line not in boot.stamps:
                    boot.stamps[line] = now
            if boot.marker in boot.text:
                break
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return boot


def probe_startup():
    return 'fs0:\npci\npci 00 01 00 -i\necho PROBE_DONE\n'


def bar0_of(text):
    """(BAR0 address, command register) of the xHC from the shell's `pci 00 01 00 -i` dump: the vendor 1B36, device 000D, a 64-bit BAR."""
    start = text.find('pci 00 01 00 -i')
    dump = {}
    for offset, bytes_ in re.findall(r'^\s*([0-9A-Fa-f]{8}): ((?:[0-9A-Fa-f]{2}[ -]){16})', text[start:] if start >= 0 else '', re.M):
        for index, byte in enumerate(re.findall(r'[0-9A-Fa-f]{2}', bytes_)):
            dump.setdefault(int(offset, 16) + index, int(byte, 16))
    if not all(k in dump for k in range(0x00, 0x18)):
        return None
    u32 = lambda at: sum(dump[at + i] << (8 * i) for i in range(4))  # noqa: E731
    if u32(0) != 0x000D1B36 or u32(0x10) & 1:
        return None
    return (u32(0x10) & ~0xf) | (u32(0x14) << 32 if u32(0x10) >> 1 & 3 == 2 else 0), u32(0x04) & 0xffff


class XhciQemu(unittest.TestCase):
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
        cls.runner = ecv.build_runner_and_payloads(BUILD / 'out')
        cls.probe = cls.boot_once(Boot('probe', {}, probe_startup(), 'PROBE_DONE', timeout=120))
        found = bar0_of(cls.probe.text)
        if not found:
            raise unittest.SkipTest('the shell shows no qemu-xhci at 00:01.0:\n' + cls.probe.text[-1500:])
        cls.bar, cls.command = found
        specs = [('real', None)] + [(name, edit) for name, edit in VARIANTS.items() if not ONLY or name in ONLY]
        cls.binaries = {name: cls.build(name, edit) for name, edit in specs}
        cls.fixture = cls.build_fixture()
        boots = [Boot(name, ecv.stick([('XHCIQ.BIN', cls.fixture), ('XHCI1.BIN', data)]), ecv.qemu_base().script('--el2 --uart'), ecv.PREFIX_DONE + '1 ')
                 for name, data in cls.binaries.items()]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            cls.runs = {boot.name: boot for boot in pool.map(cls.boot_with_retry, boots)}

    @classmethod
    def boot_once(cls, boot):
        return run_boot(boot, cls.runner, cls.firmware)

    @classmethod
    def boot_with_retry(cls, boot):
        """A QEMU boot that did not reach its marker is run once more, and the retry is printed (a loaded machine can lose a boot)."""
        run_boot(boot, cls.runner, cls.firmware)
        if boot.marker not in boot.text:
            print(f'RETRY: {boot.name} did not reach {boot.marker!r}; booting it once more', file=sys.stderr)
            boot.stamps.clear()
            run_boot(boot, cls.runner, cls.firmware)
        return boot

    @classmethod
    def build_fixture(cls):
        """The test-only payload that turns on the controller's memory space and bus master (see its file)."""
        done, _, flat = lib.build_payload(ROOT / 'tools' / 'testdata' / 'sp11-payload-fixture-xhciq.c', BUILD / 'fix', name='xhciq')
        if done.returncode:
            raise RuntimeError(done.stdout[-800:] + done.stderr[-800:])
        return Path(flat).read_bytes()

    @classmethod
    def build(cls, name, edit=None):
        """The payload for the controller of this machine, from the real tree or from a copy with one seeded bug."""
        root = ROOT
        if edit:
            root = xl.copy_tree(BUILD / f'src-{name}')
            path = root / edit[0]
            text = path.read_text(encoding='utf-8')
            assert text.count(edit[1]) == 1, f'{name}: the seeded edit does not apply exactly once'
            path.write_text(text.replace(edit[1], edit[2], 1), encoding='utf-8')
        done, _, flat = xl.build_binary(1, BUILD / f'bin-{name}', root=root, defines=QEMU_DEFINES + [f'-DXHCI_S1_U1_BASE=UINT64_C({cls.bar:#x})'])
        if done.returncode:
            raise RuntimeError(done.stdout[-800:] + done.stderr[-800:])
        return Path(flat).read_bytes()

    def boot_of(self, name):
        if name not in self.runs:
            self.skipTest(f'{name} was not booted (SP11_XHCI_QEMU_ONLY)')
        boot = self.runs[name]
        self.assertIn(boot.marker, boot.text, f'{name} did not finish:\n{boot.text[-2500:]}')
        return boot

    @staticmethod
    def page(boot):
        return [line[len(PREFIX):] for line in boot.text.split('\n') if line.startswith(PREFIX)]

    def test_the_probe_boot_found_the_controller_with_decode_and_bus_master_on(self):
        self.assertEqual(self.bar, 0x8000004000, 'EDK2 puts the first 64-bit BAR at the start of its high window')
        self.assertEqual(self.command & 7, 7, 'I/O, memory space and bus master enabled by the firmware driver')

    def test_the_real_payload_gets_its_no_op_completed_by_qemus_independent_xhc(self):
        boot = self.boot_of('real')
        page = self.page(boot)
        hexa = r'0X[0-9A-F]+'
        patterns = [
            r'U1 CAPL=0X40 VER=0X100 HCS1=' + hexa + ' HCS2=' + hexa + ' HCC1=' + hexa, r'U1 SCRATCH=0 PAGESZ=0X1 AC64=1 CSZ=32 DBOFF=0X2000 RTSOFF=0X1000',
            r'U1 CMD=0X0 STS=0X1:HCH CRCR=' + hexa + ' DCBAAP=' + hexa + ' CFG=' + hexa]
        for line, pattern in zip(page, patterns):
            self.assertRegex(line, f'^{pattern}$')
        self.assertIn('ARENAS 2=OK 3=OK 4=NOT_FREE', ' '.join(page))
        self.assertRegex('\n'.join(page), r'NEXT ARENA 2 STACK 0X[0-9A-F]+ PAGES 1 AFTER 8 S\nNEXT RESET AFTER 8 S\nNEXT PROGRAM AFTER 8 S\nNEXT RUN AFTER 8 S\n'
                                          r'NEXT NOOP AFTER 8 S\nR1 ARENA=2 NOOP_OK STAGE=NOOP CC=1 STS=0X[0-9A-F]+:HCH(\.EINT)? EV=\d+ SMMU=SAME\nVERDICT NOOP_OK ARENA=2\n'
                                          r'END HALTED=YES WRITES=17 LOADS=\d+$')
        done = [line for line in boot.text.split('\n') if line.startswith(ecv.PREFIX_DONE + '1 ')][0]
        self.assertRegex(done, r'RETURN=0X0 STACK=OK .*REFUSED=0 LINES=\d+ DROPPED=0')

    def test_the_watch_and_the_waits_are_wall_clock_time_on_qemus_counter(self):
        boot = self.boot_of('real')
        watch = ecv.wait_seconds(boot, PREFIX + 'WATCH 30 S', PREFIX + 'WATCH DONE')
        self.assertTrue(28.0 <= watch <= 120.0, f'{watch:.1f} s of watch')
        for before, after in (('NEXT ARENA', 'NEXT RESET'), ('NEXT RESET', 'NEXT PROGRAM'), ('NEXT PROGRAM', 'NEXT RUN'), ('NEXT RUN', 'NEXT NOOP'),
                              ('NEXT NOOP', 'R1 ARENA')):
            seconds = ecv.wait_seconds(boot, PREFIX + before, PREFIX + after)
            self.assertTrue(7.0 <= seconds <= 60.0, f'{seconds:.1f} s between {before} and {after}')

    def test_each_seeded_bug_that_the_host_model_rejects_leaves_the_no_op_uncompleted_under_qemu_too(self):
        for name in VARIANTS:
            with self.subTest(variant=name):
                boot = self.boot_of(name)
                page = ' | '.join(self.page(boot))
                self.assertNotIn('VERDICT NOOP_OK', page, 'QEMU\'s xHC accepted a programming that the host model rejects')
                self.assertRegex(page, EXPECTED[name])
                self.assertRegex(page, r'END HALTED=(YES|NO|UNKNOWN) WRITES=\d+')


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
