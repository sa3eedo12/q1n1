# SPDX-License-Identifier: MIT
"""Helpers shared by the host and QEMU tests of the two timer payloads of the Surface Pro 11 stick payload runner, `cnthctl` and
`el1trap` (docs/SP11-PAYLOAD-CNTHCTL.md, docs/SP11-PAYLOAD-EL1TRAP.md): a builder of payload copies with edits, the instruction
inventory of a built binary, and a boot driver that runs the stick under QEMU's EDK2 with a chosen CPU model and stamps the time
each page line first appeared on the serial log. Writes only below the directories it is given. Hardware: NOT RUN."""
import hashlib
import importlib.util
from collections import Counter
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
import sp11_payload_testlib as lib  # noqa: E402

READELF = lambda: shutil.which('llvm-readelf', path=lib.ENV['PATH']) or 'llvm-readelf'  # noqa: E731


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def need_tools():
    for tool in ('clang', 'ld.lld', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy'):
        if not lib.have(tool):
            raise unittest.SkipTest(f'{tool} not installed')


def code_of(path):
    """A source file without its comments."""
    return re.sub(r'//[^\n]*', '', re.sub(r'/\*.*?\*/', '', Path(path).read_text(encoding='utf-8'), flags=re.S))


class Builder:
    """Builds a copy of a payload with edits, below one directory, with the Makefile's own flags."""

    def __init__(self, directory):
        self.out = Path(directory)
        shutil.rmtree(self.out, ignore_errors=True)
        self.out.mkdir(parents=True)

    def build(self, payload, name, edits, check=False):
        text = (ROOT / 'payloads' / f'{payload}.c').read_text(encoding='utf-8')
        for needle, replacement in edits:
            assert text.count(needle) == 1, f'{name}: {needle[:60]!r} is not in {payload}.c exactly once'
            text = text.replace(needle, replacement, 1)
        path = self.out / f'{name}.c'
        path.write_text(text, encoding='utf-8')
        return lib.build_payload(path, self.out, name=name, check=check)


ANCHOR = 'payload_entry(const struct q1n1_payload_args *a)\n{\n'


def asm(text, clobbers='"memory"'):
    """An edit that puts one inline-assembly statement at the top of payload_entry."""
    return [(ANCHOR, ANCHOR + (f'    __asm__ volatile("{text}" ::: {clobbers});\n' if text else ''))]


def read(register):
    return asm(f'mrs x0, {register}', '"x0", "memory"')


def facts(elf, flat):
    """What a payload binary holds, as the documents state it."""
    dis = lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout
    found = (re.match(r'\s+[0-9a-f]+:\s+(\S+)\s*(.*)$', line) for line in dis.splitlines())
    instructions = [(m.group(1).lower(), m.group(2).split('//')[0].strip()) for m in found if m]
    data = Path(flat).read_bytes()
    first = lambda operands: operands.split(',')[0].strip().lower()  # noqa: E731
    last = lambda operands: operands.split(',')[-1].strip().lower()  # noqa: E731
    return {
        'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'instructions': len(instructions),
        'mnemonics': Counter(m for m, _ in instructions),
        'mrs': Counter(lib.SYSTEM_REGISTER_ALIASES.get(last(o), last(o)) for m, o in instructions if m == 'mrs'),
        'msr': Counter(first(o) for m, o in instructions if m == 'msr'), 'dc': Counter(first(o) for m, o in instructions if m == 'dc'),
        'ic': Counter(first(o) for m, o in instructions if m == 'ic'), 'hvc': Counter(first(o) for m, o in instructions if m == 'hvc'),
        'smc': [o for m, o in instructions if m == 'smc'], 'instruction_list': instructions,
    }


def block(text, name):
    return text[text.index(f'<!-- {name} -->') + len(name) + 9:text.index(f'<!-- /{name} -->')]


def rows(section):
    return [[cell.strip() for cell in line.strip().strip('|').split('|')] for line in section.splitlines()
            if line.startswith('|') and not re.match(r'^\|[ \-|]+\|$', line)][1:]


# ---- QEMU ------------------------------------------------------------------------------------------------------------------

_QEMU = []


def qemu_base():
    """The base QEMU test of the runner (its helpers), loaded on first use so that the host tests do not need it."""
    if not _QEMU:
        _QEMU.append(load_module('sp11_payload_qemu_base_for_ecv', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu.py'))
    return _QEMU[0]


PREFIX_DONE = 'PAYLOAD DONE INDEX='


def stick(entries):
    """The files of a stick whose manifest lists [(8.3 name, bytes)] in that order."""
    files = {'SP11/PAYLOAD.MAN': qemu_base().manifest([(f'\\SP11\\{name}', data) for name, data in entries])}
    for name, data in entries:
        files[f'SP11/{name}'] = data
    return files


class Run:
    """One QEMU boot: the serial text, the first time each PAYLOAD line was seen, whether any file of the stick changed."""

    def __init__(self, name, files, cpu='max', marker=PREFIX_DONE + '0 ', timeout=300, grace=0, shot_after=None):
        self.name, self.files, self.cpu, self.marker, self.timeout, self.grace = name, files, cpu, marker, timeout, grace
        self.shot_after = shot_after       # seconds after the marker (and the grace) at which the panel is photographed over QMP
        self.text, self.stamps, self.changed, self.shot = '', {}, None, None

    def lines(self, prefix):
        return [line[len(prefix):] for line in self.text.split('\n') if line.startswith(prefix)]


def run_boot(run, directory, runner, firmware):
    """qemu-system-aarch64 -machine virt,virtualization=on,gic-version=3 with `run.cpu`, one CPU, the EDK2 shell on a FAT directory;
    the serial log is polled every 0.2 s so that the time at which each PAYLOAD line first appeared is known."""
    esp = Path(directory) / run.name
    shutil.rmtree(esp, ignore_errors=True)
    (esp / 'SP11').mkdir(parents=True)
    shutil.copy(runner, esp / 'SP11' / 'Q1N1-PAYLOAD.EFI')
    for relative, data in run.files.items():
        (esp / relative).parent.mkdir(parents=True, exist_ok=True)
        (esp / relative).write_bytes(data)
    (esp / 'startup.nsh').write_text(qemu_base().script())
    before = qemu_base().tree_hashes(esp)
    serial = Path(directory) / f'{run.name}.log'
    qmp = Path(directory) / f'{run.name}.q'
    serial.unlink(missing_ok=True)
    qmp.unlink(missing_ok=True)
    cmd = ['qemu-system-aarch64', '-machine', 'virt,virtualization=on,gic-version=3', '-accel', 'tcg', '-cpu', run.cpu, '-smp', '1',
           '-m', '512M', '-bios', firmware, '-drive', f'format=raw,file=fat:rw:{esp}', '-device', 'ramfb', '-display', 'none',
           '-monitor', 'none', '-nic', 'none', '-serial', f'file:{serial}', '-no-reboot']
    if run.shot_after is not None:
        cmd += ['-qmp', f'unix:{qmp},server=on,wait=off']
    proc = subprocess.Popen(cmd, env=lib.ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    text = ''
    seen = None
    try:
        deadline = time.monotonic() + run.timeout
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.2)
            if not serial.exists():
                continue
            text = qemu_base().helpers.ANSI.sub('', serial.read_text(errors='replace').replace('\r', ''))
            now = time.monotonic()
            for line in text.split('\n'):
                if line.startswith('PAYLOAD ') and line not in run.stamps:
                    run.stamps[line] = now
            if run.marker in text:
                seen = seen or now         # `grace` seconds more, to see that nothing follows a line a payload hung on
                if now - seen >= run.grace:
                    break
        if run.shot_after is not None and run.marker in text:
            time.sleep(run.shot_after)
            qemu_base().helpers.screendump(qmp, Path(directory) / f'{run.name}.ppm')
            run.shot = qemu_base().helpers.read_ppm(Path(directory) / f'{run.name}.ppm')
            text = qemu_base().helpers.ANSI.sub('', serial.read_text(errors='replace').replace('\r', ''))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    run.text = text
    run.changed = before != qemu_base().tree_hashes(esp)
    return run


def find_firmware():
    return qemu_base().helpers.find_firmware()


def build_runner_and_payloads(out):
    """make PAYLOAD=1 payload-runner payloads, the way the other QEMU suites do; returns the runner's path."""
    built = subprocess.run(['make', '-f', 'platform/uefi/Makefile', f'OUT={Path(out).relative_to(ROOT)}', '-j4', 'PAYLOAD=1']
                           + qemu_base().SP11_VARS + ['payload-runner', 'payloads'], cwd=ROOT, env=lib.ENV, capture_output=True,
                           text=True)
    if built.returncode:
        raise RuntimeError('PAYLOAD=1 build failed:\n' + built.stdout[-2000:] + built.stderr[-2000:])
    return Path(out) / 'q1n1-payload.efi'


def wait_seconds(run, before_prefix, after_prefix):
    """Wall-clock seconds between the first appearance of the line starting `before_prefix` and of the one starting `after_prefix`."""
    first = lambda prefix: next(t for line, t in sorted(run.stamps.items(), key=lambda kv: kv[1]) if line.startswith(prefix))  # noqa: E731
    return first(after_prefix) - first(before_prefix)
