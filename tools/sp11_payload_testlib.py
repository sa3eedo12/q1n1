# SPDX-License-Identifier: MIT
"""Shared helpers of the payload runner's host tests (tools/test-q1n1-sp11-payload*.py).

Builds a payload from a C file with the compiler and linker flags the Makefile uses (they are read from
platform/uefi/Makefile, so a test payload can never be built differently from `make payloads`), and runs
the same ELF check. Writes only below the directory it is given. Hardware: NOT RUN."""
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LLVM = ('/opt/homebrew/opt/llvm/bin', '/opt/homebrew/opt/lld/bin', '/opt/homebrew/bin')
ENV = dict(os.environ, PATH=os.pathsep.join(LLVM + (os.environ.get('PATH', ''),)), PYTHONDONTWRITEBYTECODE='1')
MAKEFILE = ROOT / 'platform' / 'uefi' / 'Makefile'


def have(tool):
    return shutil.which(tool, path=ENV['PATH']) is not None


def run(cmd, cwd=ROOT, **kw):
    return subprocess.run(cmd, cwd=cwd, env=ENV, capture_output=True, text=True, **kw)


def makefile_flags(variable, makefile=MAKEFILE):
    """The words of `VARIABLE := ...` (with backslash continuations) in the Makefile."""
    text = Path(makefile).read_text(encoding='utf-8')
    found = re.search(rf'^{variable} :=((?:.*\\\n)*.*)$', text, re.M)
    if not found:
        raise RuntimeError(f'{variable} is not defined in {makefile}')
    return found.group(1).replace('\\\n', ' ').split()


def payload_cflags(makefile=MAKEFILE):
    """PAYLOAD_CFLAGS without the dependency-file options, which a scratch build has no use for."""
    return [flag for flag in makefile_flags('PAYLOAD_CFLAGS', makefile) if flag not in ('-MMD', '-MP')]


def build_payload(source, out_dir, name=None, extra_cflags=(), root=ROOT, check=True):
    """Compiles `source` with the stub and the linker script of the tree `root`, links, runs the ELF check
    and flattens. Returns (CompletedProcess of the first failing step or of the last step, elf, bin)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    name = name or Path(source).stem
    flags = payload_cflags(Path(root) / 'platform' / 'uefi' / 'Makefile') + list(extra_cflags) + ['-Ipayloads']
    start, obj = out_dir / f'{name}-start.o', out_dir / f'{name}.o'
    elf, flat = out_dir / f'{name}.elf', out_dir / f'{name}.bin'
    steps = [
        ['clang'] + flags + ['-c', str(Path(root) / 'payloads' / 'start.S'), '-o', str(start)],
        ['clang'] + flags + ['-c', str(source), '-o', str(obj)],
        ['ld.lld'] + makefile_flags('PAYLOAD_LDFLAGS', Path(root) / 'platform' / 'uefi' / 'Makefile') +
        ['-T', str(Path(root) / 'payloads' / 'payload.ld'), '-o', str(elf), str(start), str(obj)],
    ]
    if check:
        steps.append(['python3', '-B', str(Path(root) / 'tools' / 'sp11_payload_elfcheck.py'), '--readelf',
                      shutil.which('llvm-readelf', path=ENV['PATH']) or 'llvm-readelf', str(elf)])
    steps.append(['llvm-objcopy', '-O', 'binary', str(elf), str(flat)])
    done = None
    for step in steps:
        done = run(step, cwd=root)
        if done.returncode:
            return done, elf, flat
    return done, elf, flat
