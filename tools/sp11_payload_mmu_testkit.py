# SPDX-License-Identifier: MIT
"""Shared machinery of the el2mem and hashbig tests (tools/test-q1n1-sp11-payload-el2mem.py, -hashbig.py, -mmu-doc.py,
-qemu-el2mem.py): the native test machinery of tools/test-q1n1-sp11-payload.py with the two new programs registered in a private copy
of it (nothing of that file changes), the seeded-bug evaluator, a payload builder that applies text edits to a copy of a source, and the
facts a built binary gives (size, digest, instruction inventory). Writes only under build/. Hardware: NOT RUN."""
import concurrent.futures
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402

READELF = lambda: shutil.which('llvm-readelf', path=lib.ENV['PATH']) or 'llvm-readelf'  # noqa: E731

PROGRAMS = {
    'el2mem': ('tools/test-q1n1-sp11-payload-el2mem.c', ['sp11-payload-text.c'], 10, 60000, 'el2mem'),
    'hashbig': ('tools/test-q1n1-sp11-payload-hashbig.c', ['sp11-payload-text.c', 'sha256.c', 'preload.c'], 12, 1500, 'hashbig'),
}
NEW_PAYLOAD_FILES = ['el2mem.c', 'hashbig.c', 'payload-mmu.h', 'payload-page.h', 'payload-sha256.h']


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_module(tag):
    """The native test machinery with its own build directory, el2mem and hashbig registered, and the new payload files in the copies
    the seeded-bug runs build from."""
    native = load_module(f'sp11_payload_native_for_{tag}', ROOT / 'tools' / 'test-q1n1-sp11-payload.py')
    native.BUILD = ROOT / 'build' / f'sp11-payload-{tag}-test'
    native.PROGRAMS.update(PROGRAMS)
    native.HOST_PAYLOADS.update({'el2mem': 'el2mem.c', 'hashbig': 'hashbig.c'})
    native.PAYLOADS_COPIED = list(native.PAYLOADS_COPIED) + [f for f in NEW_PAYLOAD_FILES if f not in native.PAYLOADS_COPIED]
    return native


def code_of(path):
    """A source file without its comments."""
    return re.sub(r'//[^\n]*', '', re.sub(r'/\*.*?\*/', '', Path(path).read_text(encoding='utf-8'), flags=re.S))


def run_mutants(native, mutants, test_case):
    """Every seeded bug through the native machinery, a few at a time; each must be 'caught'. `mutants` are
    (name, file below the copy, [(needle, replacement)], [programs], build error that counts)."""
    workers = max(1, min(4, os.cpu_count() or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {m[0]: pool.submit(native.Mutants._evaluate, test_case, *m) for m in mutants}
        results = {name: future.result() for name, future in futures.items()}
    for name, (status, detail) in results.items():
        with test_case.subTest(mutant=name):
            test_case.assertEqual(status, 'caught', f'{status}: {detail}')


def mutant(program, name, file, old, new):
    return (f'{program}-{name}', file, [(old, new)], [program], None)


class Builder:
    """Builds a payload from a copy of its source with text edits, with the Makefile's flags (tools/sp11_payload_testlib.py)."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def build(self, payload, name, edits, check=False):
        text = (ROOT / 'payloads' / f'{payload}.c').read_text(encoding='utf-8')
        for needle, replacement in edits:
            if text.count(needle) != 1:
                raise AssertionError(f'{name}: {needle[:60]!r} is not in {payload}.c exactly once')
            text = text.replace(needle, replacement, 1)
        path = self.directory / f'{name}.c'
        path.write_text(text, encoding='utf-8')
        return lib.build_payload(path, self.directory, name=name, check=check)


def facts(elf, flat):
    """Size, digest and the instruction inventory of a built payload."""
    dis = lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout
    mnemonics, reads = {}, {}
    for line in dis.splitlines():
        found = re.match(r'\s+[0-9a-f]+:\s+(\S+)\s*(.*)$', line)
        if not found:
            continue
        mnemonic = found.group(1).lower()
        mnemonics[mnemonic] = mnemonics.get(mnemonic, 0) + 1
        if mnemonic == 'mrs':
            register = found.group(2).split(',')[-1].strip().lower()
            register = lib.SYSTEM_REGISTER_ALIASES.get(register, register)
            reads[register] = reads.get(register, 0) + 1
    data = Path(flat).read_bytes()
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'mnemonics': mnemonics, 'mrs': reads,
            'instructions': sum(mnemonics.values())}


def need_tools(test_case):
    import unittest
    for tool in ('clang', 'ld.lld', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy'):
        if not lib.have(tool):
            raise unittest.SkipTest(f'{tool} not installed')
