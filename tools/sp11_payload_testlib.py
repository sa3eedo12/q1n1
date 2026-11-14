# SPDX-License-Identifier: MIT
"""Shared helpers of the payload runner's host tests (tools/test-q1n1-sp11-payload*.py).

Builds a payload from a C file with the compiler and linker flags the Makefile uses (they are read from
platform/uefi/Makefile, so a test payload can never be built differently from `make payloads`), runs the same
ELF check, and holds the allow-list mechanism that says what a payload binary may contain
(binary_violations). Writes only below the directory it is given. Hardware: NOT RUN."""
import os
from pathlib import Path
import re
import shutil
import struct
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


# ---- What a payload binary may contain ----------------------------------------------------------------------------
# One entry per payload: the system registers its MRS may read, how many SMC instructions it holds (each `smc #0`),
# and the most bytes it may take (one range is declared per file whatever its size). The reference payload `state` is
# MRS only; `psci` is MRS of CurrentEL and MPIDR_EL1 plus exactly one SMC, its one helper.
STATE_REGISTERS = {
    'currentel', 'midr_el1', 'mpidr_el1', 'id_aa64mmfr0_el1', 'id_aa64mmfr1_el1', 'id_aa64mmfr2_el1', 's3_0_c0_c7_3',
    's3_0_c0_c7_4', 'id_aa64pfr0_el1', 'id_aa64pfr1_el1', 'hcr_el2', 'sctlr_el2', 'tcr_el2', 'ttbr0_el2', 's3_4_c2_c0_1',
    'mair_el2', 'vbar_el2', 'cptr_el2', 'cnthctl_el2', 'cntfrq_el0', 'daif', 'spsel'}
POLICIES = {
    'state': {'registers': STATE_REGISTERS, 'smc': 0, 'bytes': 4096},
    'psci': {'registers': {'currentel', 'mpidr_el1'}, 'smc': 1, 'bytes': 8192},
}
# Mnemonics no payload has a use for (smc is counted against the policy instead of being forbidden outright).
FORBIDDEN = {'msr', 'sys', 'sysl', 'dc', 'ic', 'tlbi', 'at', 'hvc', 'svc', 'eret', 'eretaa', 'eretab', 'drps', 'wfi',
             'wfe', 'wfit', 'wfet', 'hlt', 'brk', 'dcps1', 'dcps2', 'dcps3'}
EXCLUSIVE = re.compile(r'^(ldx|ldax|stx|stlx)[rp][bh]?$')
ATOMIC = re.compile(r'^(cas|casp|swp|ld(add|clr|eor|set|smax|smin|umax|umin)|st(add|clr|eor|set|smax|smin|umax|umin))[al]{0,2}[bh]?$')
# Never touched by any payload: the timer offsets whose use stalled this board, under both spellings.
TIMER_OFFSETS = ('cntvoff_el2', 'cntpoff_el2', 's3_4_c14_c0_3', 's3_4_c14_c0_6')
# By encoding, independent of the disassembler: (mask, value) of every aligned word of the code that may not occur.
FORBIDDEN_WORDS = {
    'hvc': (0xffe0001f, 0xd4000002), 'svc': (0xffe0001f, 0xd4000001), 'eret': (0xffffffff, 0xd69f03e0),
    'eretaa': (0xffffffff, 0xd69f0bff), 'eretab': (0xffffffff, 0xd69f0fff), 'msr-register': (0xfff00000, 0xd5100000),
    'msr-immediate': (0xfff8f01f, 0xd500401f), 'sys': (0xfff80000, 0xd5080000), 'sysl': (0xfff80000, 0xd5280000),
    'wfi': (0xffffffff, 0xd503207f), 'wfe': (0xffffffff, 0xd503205f)}
SYSTEM_REGISTER_ALIASES = {'id_aa64mmfr3_el1': 's3_0_c0_c7_3', 'id_aa64mmfr4_el1': 's3_0_c0_c7_4', 'ttbr1_el2': 's3_4_c2_c0_1'}


def binary_violations(elf, flat, policy, readelf='llvm-readelf'):
    """Everything in a payload's code that `policy` does not allow, as sentences; an empty list means it is clean.
    Reads the disassembly of the ELF (every mnemonic, every MRS register, every SMC and its immediate, the timer
    offsets) and, independently, every aligned word of the flat binary's code by encoding."""
    problems = []
    dis = run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)])
    if dis.returncode:
        return [f'llvm-objdump failed: {dis.stderr.strip()}']
    text = dis.stdout
    for undecodable in ('<unknown>', '.inst'):
        if undecodable in text:
            problems.append(f'the disassembly holds {undecodable}: a word that is not a known instruction')
    found = (re.match(r'\s+[0-9a-f]+:\s+(\S+)\s*(.*)$', line) for line in text.splitlines())
    instructions = [(m.group(1).lower(), m.group(2)) for m in found if m]
    mnemonics = {m for m, _ in instructions}
    reads = set()
    for mnemonic, operands in instructions:
        if mnemonic == 'mrs':
            register = operands.split(',')[-1].strip().lower()
            reads.add(SYSTEM_REGISTER_ALIASES.get(register, register))
    if reads != policy['registers']:
        problems.append(f'registers read {sorted(reads)}, allowed {sorted(policy["registers"])}')
    for mnemonic in sorted(mnemonics & FORBIDDEN):
        problems.append(f'forbidden instruction {mnemonic}')
    for mnemonic in sorted(m for m in mnemonics if EXCLUSIVE.match(m) or ATOMIC.match(m)):
        problems.append(f'exclusive or atomic instruction {mnemonic}')
    smc = [operands.strip() for mnemonic, operands in instructions if mnemonic == 'smc']
    if len(smc) != policy['smc']:
        problems.append(f'{len(smc)} smc instructions, the policy allows {policy["smc"]}')
    if any(operand != '#0' for operand in smc):
        problems.append(f'an smc with another immediate than #0: {smc}')
    for register in TIMER_OFFSETS:
        if register in text.lower():
            problems.append(f'the code names {register}')
    if len(mnemonics) < 8:
        problems.append('fewer than eight different mnemonics: the disassembly was not read')
    sections = run([readelf, '--wide', '--sections', str(elf)]).stdout
    size_found = re.search(r'\s\.text\s+PROGBITS\s+\w+\s+\w+\s+(\w+)\s', sections)
    data = Path(flat).read_bytes()
    if not size_found:
        return problems + ['no .text section was found in the ELF']
    size = int(size_found.group(1), 16)
    if not 0 < size <= len(data) or size % 4:
        return problems + [f'the .text size {size} does not fit the flat binary']
    words = struct.unpack(f'<{size // 4}I', data[:size])
    for what, (mask, value) in FORBIDDEN_WORDS.items():
        if any(w & mask == value for w in words):
            problems.append(f'a word of the code encodes {what}')
    words_smc = [w for w in words if w & 0xffe0001f == 0xd4000003]
    if len(words_smc) != policy['smc'] or any(w >> 5 & 0xffff for w in words_smc):
        problems.append(f'{len(words_smc)} words of the code encode smc, the policy allows {policy["smc"]} (immediate 0)')
    if len(data) > policy['bytes']:
        problems.append(f'{len(data)} bytes, the policy allows {policy["bytes"]}')
    return problems
