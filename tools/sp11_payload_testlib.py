# SPDX-License-Identifier: MIT
"""Shared helpers of the payload runner's host tests (tools/test-q1n1-sp11-payload*.py).

Builds a payload from a C file with the compiler and linker flags the Makefile uses (they are read from
platform/uefi/Makefile, so a test payload can never be built differently from `make payloads`), runs the same
ELF check, and holds the allow-list mechanism that says what a payload binary may contain
(binary_violations). Writes only below the directory it is given. Hardware: NOT RUN."""
import os
from collections import Counter
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


def newer_payloads(base_commit, root=ROOT):
    """The payloads in the tree that `base_commit` lacks (the stems of payloads/*.c). The gate-off tests compare the tree with the commit their gate was
    built on, and `make all` builds every payload, so a payload added later is not a difference the gate made."""
    listed = run(['git', 'ls-tree', '--name-only', base_commit, 'payloads/'], cwd=root).stdout.split()
    return {path.stem for path in (Path(root) / 'payloads').glob('*.c')} - {Path(name).stem for name in listed if name.endswith('.c')}


def changed_since(base_commit, *paths, root=ROOT):
    """The tracked and untracked files below `paths` that differ from `base_commit`, without the files of the newer payloads."""
    names = set(run(['git', 'diff', '--name-only', base_commit, '--', *paths], cwd=root).stdout.split())
    names |= set(run(['git', 'ls-files', '--others', '--exclude-standard', '--', *paths], cwd=root).stdout.split())
    own = {part for stem in newer_payloads(base_commit, root) for part in (stem, f'{stem}-regs')}
    return {name for name in names if not (name.startswith('payloads/') and Path(name).name.split('.')[0] in own)}


def without_newer_payloads(base_commit, lines, root=ROOT):
    """`make -n` command lines without those that name a newer payload and without the directory creation they cause: `all` makes the directory
    once for each of them, and those lines name no payload. Every other line stays, so a changed flag of an older payload is still a difference."""
    newer = newer_payloads(base_commit, root)
    if not newer:
        return list(lines)
    named = re.compile(r'/(?:%s)(?:[./\s]|$)' % '|'.join(sorted(newer)))
    return [line for line in lines if not named.search(line) and not line.startswith('mkdir -p ')]


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
# One entry per payload: the system registers its MRS may read (the set of registers read must be exactly this one),
# how many SMC instructions it holds (each `smc #0`), the most bytes it may take (one range is declared per file
# whatever its size), and optionally `timer_offsets` (the payload may name CNTVOFF_EL2 and CNTPOFF_EL2, and must read
# each exactly once) and `forbid` (more mnemonics no instruction of it may use). The reference payload `state` is MRS
# only; `psci` is MRS of CurrentEL and MPIDR_EL1 plus exactly one SMC, its one helper; `timer` is MRS of the timer and
# counter registers and the only payload that may read the two timer offsets, with no barrier instruction either;
# `usbsmmu` is MRS of CurrentEL and nothing else (every device access and every RAM access at an address from hardware is a
# call through the runner's load op; only the runner's own memory map is read in place), no SMC, no barrier, and the only
# payload that is allowed to be larger than a page or two.
# Three more optional keys let a payload that changes the machine be described exactly, and a policy without them is
# checked exactly as before:
#   `allow`        {mnemonic: {first operand, ...}}: a mnemonic of FORBIDDEN that this payload may use, but only in the
#                  listed forms (`msr` to VBAR_EL2 and DAIFSet, `dc` civac and ivac, a bare `wfe` is ''). Every other
#                  operand of it is a violation, and so is a word whose encoding is not that of an allowed form (ALLOW_WORDS).
#   `smc_ids`      the function ids its `smc` instructions are called with, one per instruction: each is read from the
#                  straight-line mov/movz/movk run that builds w0 right before the instruction, and an id that cannot be read
#                  that way (a branch target in the run, another write of w0, a call) is a violation, never a pass.
#   `single_reads` registers it reads in addition to `registers`, each exactly once, and may name for that (CNTVOFF_EL2 for
#                  `cpuon`: it is read once, on the core that was just started; CNTPOFF_EL2 can never be one of them, and
#                  stays in `registers` of `timer` alone).
# `cpuon` is the first payload that starts other CPUs: MRS of the fifteen registers its secondary and its primary read,
# MSR of VBAR_EL2 (the secondary's own vector table) and DAIF, DC CIVAC and DC IVAC (the cache rules of a core that starts
# with its caches off), DSB and ISB, one WFE (the park loop of a core whose CPU_OFF returned), and three `smc #0`: CPU_ON and
# AFFINITY_INFO of the primary, CPU_OFF of the secondary.
STATE_REGISTERS = {
    'currentel', 'midr_el1', 'mpidr_el1', 'id_aa64mmfr0_el1', 'id_aa64mmfr1_el1', 'id_aa64mmfr2_el1', 's3_0_c0_c7_3',
    's3_0_c0_c7_4', 'id_aa64pfr0_el1', 'id_aa64pfr1_el1', 'hcr_el2', 'sctlr_el2', 'tcr_el2', 'ttbr0_el2', 's3_4_c2_c0_1',
    'mair_el2', 'vbar_el2', 'cptr_el2', 'cnthctl_el2', 'cntfrq_el0', 'daif', 'spsel'}
# The timer offsets, by encoding: the disassembler prints CNTVOFF_EL2 by name, and CNTPOFF_EL2 by name only when the
# target has FEAT_ECV, so SYSTEM_REGISTER_ALIASES makes every spelling one.
CNTVOFF_EL2, CNTPOFF_EL2 = 's3_4_c14_c0_3', 's3_4_c14_c0_6'
TIMER_REGISTERS = {
    'currentel', 'id_aa64mmfr0_el1', 'hcr_el2', 'cntfrq_el0', 'cnthctl_el2', 'cntp_ctl_el0', 'cntv_ctl_el0',
    'cnthp_ctl_el2', 'cntpct_el0', 'cntvct_el0', CNTVOFF_EL2, CNTPOFF_EL2}
# What `cpuon` reads besides CNTVOFF_EL2 (which its policy lists apart, as a register read exactly once): the primary reads
# CurrentEL, MPIDR_EL1, CNTFRQ_EL0, MIDR_EL1 and the three ID registers it compares; the secondary stub reads those too and
# SCTLR_EL2, HCR_EL2, VBAR_EL2, CNTPCT_EL0 and, in a vector, ESR_EL2, ELR_EL2 and FAR_EL2.
CPUON_REGISTERS = {
    'currentel', 'mpidr_el1', 'midr_el1', 'id_aa64mmfr0_el1', 'id_aa64isar0_el1', 'id_aa64pfr0_el1', 'cntfrq_el0',
    'sctlr_el2', 'hcr_el2', 'vbar_el2', 'cntpct_el0', 'esr_el2', 'elr_el2', 'far_el2'}
CPUON_SMC_IDS = (0x84000002, 0xC4000003, 0xC4000004)      # CPU_OFF, CPU_ON, AFFINITY_INFO (Arm DEN0022, SMC64 for the last two)
# The common size cap of a document or source is 50 KiB. docs/SP11-PAYLOAD.md carries one index row per payload and had 41 bytes of room under it: its cap is
# raised on purpose, each time by the least multiple of 512 that holds the next row. The row of nvmesnap (413 bytes: 51,159 to 51,572 bytes) needed 50 KiB + 512;
# the row of the runner's mapping step (448 bytes: 51,572 to 52,020 bytes) needs 51 KiB (52,224 bytes); the pointers of the big-file gate (its tests row, its refusal's row,
# a sentence and a few words: 52,020 to 52,797 bytes) need 52 KiB (53,248 bytes). The tests that apply the cap to that document (test-q1n1-sp11-payload.py, -timer.py,
# -usbsmmu-doc.py) read it here; the next row needs the next raise.
DOC_SIZE_CAPS = {'SP11-PAYLOAD.md': 52 * 1024}
POLICIES = {
    'state': {'registers': STATE_REGISTERS, 'smc': 0, 'bytes': 4096},
    'psci': {'registers': {'currentel', 'mpidr_el1'}, 'smc': 1, 'bytes': 8192},
    'timer': {'registers': TIMER_REGISTERS, 'smc': 0, 'bytes': 4096, 'timer_offsets': True,
              'forbid': {'isb', 'dsb', 'dmb', 'sb'}},
    'usbsmmu': {'registers': {'currentel'}, 'smc': 0, 'bytes': 20480, 'forbid': {'isb', 'dsb', 'dmb', 'sb'}},
    # `cnthctl` writes one register, CNTHCTL_EL2, and only `msr cnthctl_el2, xN` (docs/SP11-PAYLOAD-CNTHCTL.md): ISB is the only barrier.
    'cnthctl': {'registers': {'currentel', 'hcr_el2', 'id_aa64mmfr0_el1', 'cntfrq_el0', 'cnthctl_el2'}, 'smc': 0, 'bytes': 4096,
                'forbid': {'dsb', 'dmb', 'sb', 'sev', 'sevl'}, 'allow': {'msr': {'cnthctl_el2'}}},
    # `el1trap` runs a five-instruction stub at EL1 (docs/SP11-PAYLOAD-EL1TRAP.md): the four registers of the excursion and the three
    # the exception machinery changes may be written, in those forms only; ERET, three HVC immediates, DC CIVAC and IC IVAU are its
    # own; DSB and ISB are its barriers. The registers read are its context, its handler's and the stub's four.
    'el1trap': {'registers': {'currentel', 'hcr_el2', 'id_aa64mmfr0_el1', 'id_aa64pfr0_el1', 'cntfrq_el0', 'cnthctl_el2', 'daif', 'spsel',
                              'sctlr_el1', 'vbar_el1', 'vbar_el2', 'spsr_el2', 'elr_el2', 'esr_el2', 'far_el2', 'cntpct_el0', 'esr_el1',
                              'elr_el1', 'far_el1', 'cntvct_el0', 'cntv_ctl_el0'}, 'smc': 0, 'bytes': 16384,
                'forbid': {'dmb', 'sb', 'sev', 'sevl'},
                'allow': {'msr': {'hcr_el2', 'cnthctl_el2', 'sctlr_el1', 'vbar_el1', 'vbar_el2', 'spsr_el2', 'elr_el2'},
                          'hvc': {'#0', '#0x1', '#0x2'}, 'eret': {''}, 'dc': {'civac'}, 'ic': {'ivau'}}},
    'cpuon': {'registers': CPUON_REGISTERS, 'single_reads': {CNTVOFF_EL2}, 'smc': 3, 'smc_ids': CPUON_SMC_IDS,
              'bytes': 20480, 'forbid': {'dmb', 'sb', 'sev', 'sevl'},
              'allow': {'msr': {'vbar_el2', 'daifset'}, 'dc': {'civac', 'ivac'}, 'wfe': {''}}},
}
# el2mem and hashbig (the memory-map and hashing payloads): MRS of a few registers, exactly the AT form S1E2R (an AT of any other
# kind is refused), the ISB that must follow it, no other barrier, no SMC. `read_only` adds the memory discipline of
# tools/sp11_payload_memcheck.py: every store through the payload's own stack and every load through the stack, the image, the
# arguments or a pointer they hold; `bulk_reads` (hashbig only) lets loads use any base, for the one file it hashes in place.
EL2MEM_REGISTERS = {
    'currentel', 'cntfrq_el0', 'par_el1', 'id_aa64mmfr1_el1', 's3_0_c0_c5_1', 's3_0_c0_c6_2', 's3_0_c0_c4_2', 'aidr_el1',
    'revidr_el1', 'mdcr_el2', 'mdscr_el1', 'oslsr_el1', 'icc_sre_el2'}
POLICIES['el2mem'] = {'registers': EL2MEM_REGISTERS, 'smc': 0, 'bytes': 16384, 'forbid': {'dsb', 'dmb', 'sb', 'sev', 'sevl'},
                      'allow': {'at': {'s1e2r'}}, 'read_only': True}
POLICIES['hashbig'] = {'registers': {'currentel', 'cntfrq_el0', 'par_el1'}, 'smc': 0, 'bytes': 12288,
                       'forbid': {'dsb', 'dmb', 'sb', 'sev', 'sevl'}, 'allow': {'at': {'s1e2r'}}, 'read_only': True, 'bulk_reads': True}
# retprobe (docs/SP11-PAYLOAD-RETPROBE.md) stores to RAM outside its own stack (the three canary pages) and may call SYSTEM_RESET. MRS of
# CurrentEL, CTR_EL0 (the cache line size), CNTFRQ_EL0 and PAR_EL1 (the answer of its two translation requests, AT S1E2R and AT S1E2W, each
# followed by an ISB); DC CVAC and DC CIVAC by line, DSB SY; and three `smc #0` with the ids PSCI_FEATURES, SYSTEM_RESET and SYSTEM_RESET2.
# No other system instruction: no MSR, no HVC, no ERET, no TLBI, no IC, no CPU_ON or CPU_OFF. It is not `read_only`: its stores are what
# its host test and its seeded bugs pin, and the allow-list says which instructions can make them visible.
RETPROBE_SMC_IDS = (0x8400000A, 0x84000009, 0xC4000012)         # PSCI_FEATURES, SYSTEM_RESET, SYSTEM_RESET2 (Arm DEN0022)
POLICIES['retprobe'] = {'registers': {'currentel', 'ctr_el0', 'cntfrq_el0', 'par_el1'}, 'smc': 3, 'smc_ids': RETPROBE_SMC_IDS,
                        'bytes': 16384, 'forbid': {'dmb', 'sb', 'sev', 'sevl'},
                        'allow': {'at': {'s1e2r', 's1e2w'}, 'dc': {'cvac', 'civac'}}}
# nvmesnap (docs/SP11-PAYLOAD-NVMESNAP.md) is read only like el2mem: MRS of CurrentEL, CNTFRQ_EL0 and PAR_EL1, exactly the AT form S1E2R with its ISB,
# no other barrier, no SMC, and the memory discipline of tools/sp11_payload_memcheck.py (every store through its own stack).
POLICIES['nvmesnap'] = {'registers': {'currentel', 'cntfrq_el0', 'par_el1'}, 'smc': 0, 'bytes': 20480, 'forbid': {'dsb', 'dmb', 'sb', 'sev', 'sevl'},
                        'allow': {'at': {'s1e2r'}}, 'read_only': True}
# tsnap (docs/SP11-PAYLOAD-TSNAP.md) stores nothing outside its own stack and reads every device word through the runner's guarded load: MRS of CurrentEL and CNTFRQ_EL0, no SMC, no
# barrier at all, and `read_only`, which tools/sp11_payload_memcheck.py proves from the disassembly (the compiled-code audit, tools/sp11_payload_tsnap_audit.py, proves it again from the IR).
POLICIES['tsnap'] = {'registers': {'currentel', 'cntfrq_el0'}, 'smc': 0, 'bytes': 12288, 'forbid': {'isb', 'dsb', 'dmb', 'sb', 'sev', 'sevl'},
                     'read_only': True}
# gpusnap (docs/SP11-PAYLOAD-GPUSNAP.md) stores nothing outside its own stack and reads every device word through the runner's guarded load: MRS of
# CurrentEL and CNTFRQ_EL0, no SMC, no barrier at all, and `read_only`, which tools/sp11_payload_memcheck.py proves from the disassembly (the compiled-code
# audit, tools/sp11_payload_gpusnap_audit.py, proves it again from the IR).
POLICIES['gpusnap'] = {'registers': {'currentel', 'cntfrq_el0'}, 'smc': 0, 'bytes': 12288, 'forbid': {'isb', 'dsb', 'dmb', 'sb', 'sev', 'sevl'},
                       'read_only': True}
# dispsnap (docs/SP11-PAYLOAD-DISPSNAP.md) stores nothing outside its own stack and reads every device word through the runner's guarded load: MRS of
# CurrentEL and CNTFRQ_EL0, no SMC, no barrier at all, and `read_only`, which tools/sp11_payload_memcheck.py proves from the disassembly (the compiled-code
# audit, tools/sp11_payload_dispsnap_audit.py, proves it again from the IR). Its loads through the arguments are the GOP mode it prints.
POLICIES['dispsnap'] = {'registers': {'currentel', 'cntfrq_el0'}, 'smc': 0, 'bytes': 12288, 'forbid': {'isb', 'dsb', 'dmb', 'sb', 'sev', 'sevl'},
                        'read_only': True}
# Mnemonics no payload has a use for (smc is counted against the policy instead of being forbidden outright).
FORBIDDEN = {'msr', 'sys', 'sysl', 'dc', 'ic', 'tlbi', 'at', 'hvc', 'svc', 'eret', 'eretaa', 'eretab', 'drps', 'wfi',
             'wfe', 'wfit', 'wfet', 'hlt', 'brk', 'dcps1', 'dcps2', 'dcps3'}
EXCLUSIVE = re.compile(r'^(ldx|ldax|stx|stlx)[rp][bh]?$')
ATOMIC = re.compile(r'^(cas|casp|swp|ld(add|clr|eor|set|smax|smin|umax|umin)|st(add|clr|eor|set|smax|smin|umax|umin))[al]{0,2}[bh]?$')
# Never touched by a payload whose policy does not say `timer_offsets`: the offsets whose use stalled this board,
# under both spellings.
TIMER_OFFSETS = ('cntvoff_el2', 'cntpoff_el2', CNTVOFF_EL2, CNTPOFF_EL2)
# By encoding, independent of the disassembler: (mask, value) of every aligned word of the code that may not occur.
FORBIDDEN_WORDS = {
    'hvc': (0xffe0001f, 0xd4000002), 'svc': (0xffe0001f, 0xd4000001), 'eret': (0xffffffff, 0xd69f03e0),
    'eretaa': (0xffffffff, 0xd69f0bff), 'eretab': (0xffffffff, 0xd69f0fff), 'msr-register': (0xfff00000, 0xd5100000),
    'msr-immediate': (0xfff8f01f, 0xd500401f), 'sys': (0xfff80000, 0xd5080000), 'sysl': (0xfff80000, 0xd5280000),
    'wfi': (0xffffffff, 0xd503207f), 'wfe': (0xffffffff, 0xd503205f)}
# The same for the barriers a policy may forbid with `forbid` (the CRm field is any), and for the event hints no payload has a
# use for (SEV, SEVL: a wake-up for a core parked in WFE is not a thing a payload may send).
BARRIER_WORDS = {'isb': (0xfffff0ff, 0xd50330df), 'dsb': (0xfffff0ff, 0xd503309f), 'dmb': (0xfffff0ff, 0xd50330bf),
                 'sev': (0xffffffff, 0xd503209f), 'sevl': (0xffffffff, 0xd50320bf)}
# By encoding, the forms a policy's `allow` may name: (mnemonic, first operand) -> the FORBIDDEN_WORDS class the word is in,
# and the mask and value of exactly that form (every register of Rt is any). Independent of the disassembler: a word of such a
# class that is not one of these is a violation whatever the disassembler calls it.
ALLOW_WORDS = {
    ('eret', ''): ('eret', 0xffffffff, 0xd69f03e0),
    ('hvc', '#0'): ('hvc', 0xffffffff, 0xd4000002),                     # HVC #imm16: 0xd4000002 | imm16 << 5
    ('hvc', '#0x1'): ('hvc', 0xffffffff, 0xd4000022),
    ('hvc', '#0x2'): ('hvc', 0xffffffff, 0xd4000042),
    ('ic', 'ivau'): ('sys', 0xffffffe0, 0xd50b7520),                    # SYS #3, C7, C5, #1
    ('msr', 'cnthctl_el2'): ('msr-register', 0xffffffe0, 0xd51ce100),   # S3_4_C14_C1_0
    ('msr', 'elr_el2'): ('msr-register', 0xffffffe0, 0xd51c4020),       # S3_4_C4_C0_1
    ('msr', 'hcr_el2'): ('msr-register', 0xffffffe0, 0xd51c1100),       # S3_4_C1_C1_0
    ('msr', 'sctlr_el1'): ('msr-register', 0xffffffe0, 0xd5181000),     # S3_0_C1_C0_0
    ('msr', 'spsr_el2'): ('msr-register', 0xffffffe0, 0xd51c4000),      # S3_4_C4_C0_0
    ('msr', 'vbar_el1'): ('msr-register', 0xffffffe0, 0xd518c000),      # S3_0_C12_C0_0
    ('msr', 'vbar_el2'): ('msr-register', 0xffffffe0, 0xd51cc000),      # S3_4_C12_C0_0
    ('msr', 'daifset'): ('msr-immediate', 0xfffff0ff, 0xd50340df),      # PSTATE.DAIFSet, any 4-bit immediate
    ('dc', 'civac'): ('sys', 0xffffffe0, 0xd50b7e20),                   # SYS #3, C7, C14, #1
    ('dc', 'ivac'): ('sys', 0xffffffe0, 0xd5087620),                    # SYS #0, C7, C6, #1
    ('wfe', ''): ('wfe', 0xffffffff, 0xd503205f),
}
SYSTEM_REGISTER_ALIASES = {'id_aa64mmfr3_el1': 's3_0_c0_c7_3', 'id_aa64mmfr4_el1': 's3_0_c0_c7_4', 'ttbr1_el2': 's3_4_c2_c0_1',
                           'cntvoff_el2': CNTVOFF_EL2, 'cntpoff_el2': CNTPOFF_EL2}
# AT S1E2R for the el2mem and hashbig policies: SYS #4, C7, C8, #0 (every Xt).
ALLOW_WORDS[('at', 's1e2r')] = ('sys', 0xffffffe0, 0xd50c7800)
# retprobe adds the write translation request, AT S1E2W (SYS #4, C7, C8, #1), and the clean to the point of coherency, DC CVAC (SYS #3, C7, C10, #1).
ALLOW_WORDS[('at', 's1e2w')] = ('sys', 0xffffffe0, 0xd50c7820)
ALLOW_WORDS[('dc', 'cvac')] = ('sys', 0xffffffe0, 0xd50b7a20)
# The ID registers el2mem reads by encoding, which a disassembler may print by name.
SYSTEM_REGISTER_ALIASES.update({'id_aa64dfr1_el1': 's3_0_c0_c5_1', 'id_aa64isar2_el1': 's3_0_c0_c6_2', 'id_aa64pfr2_el1': 's3_0_c0_c4_2'})
# Every spelling of a timer offset: a policy that reads one of them once names it too.
OFFSET_NAMES = {CNTVOFF_EL2: ('cntvoff_el2', CNTVOFF_EL2), CNTPOFF_EL2: ('cntpoff_el2', CNTPOFF_EL2)}


def _memcheck():
    """tools/sp11_payload_memcheck.py, imported by its path next to this file: the memory discipline of the policy keys
    `read_only` and `bulk_reads`, which no older policy has."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('sp11_payload_memcheck', Path(__file__).with_name('sp11_payload_memcheck.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def binary_violations(elf, flat, policy, readelf='llvm-readelf'):
    """Everything in a payload's code that `policy` does not allow, as sentences; an empty list means it is clean.
    Reads the disassembly of the ELF (every mnemonic, every MRS register, every SMC and its immediate, the timer
    offsets) and, independently, every aligned word of the flat binary's code by encoding. The optional policy keys
    `allow`, `smc_ids` and `single_reads` (see POLICIES) widen what is allowed in exact forms only, and `read_only` and
    `bulk_reads` add the memory discipline of tools/sp11_payload_memcheck.py; a policy without them is checked as it
    always was."""
    problems = []
    dis = run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)])
    if dis.returncode:
        return [f'llvm-objdump failed: {dis.stderr.strip()}']
    text = dis.stdout
    for undecodable in ('<unknown>', '.inst'):
        if undecodable in text:
            problems.append(f'the disassembly holds {undecodable}: a word that is not a known instruction')
    if policy.get('read_only') or policy.get('bulk_reads'):
        problems += _memcheck().memory_violations(text, policy)
    found = (re.match(r'\s+[0-9a-f]+:\s+(\S+)\s*(.*)$', line) for line in text.splitlines())
    instructions = [(m.group(1).lower(), m.group(2)) for m in found if m]
    mnemonics = {m for m, _ in instructions}
    reads = Counter()
    for mnemonic, operands in instructions:
        if mnemonic == 'mrs':
            register = operands.split(',')[-1].strip().lower()
            reads[SYSTEM_REGISTER_ALIASES.get(register, register)] += 1
    single = set(policy.get('single_reads', ()))
    if CNTPOFF_EL2 in single:
        problems.append(f'the policy allows a read of {CNTPOFF_EL2}, which never returns on this unit')
    if set(reads) != policy['registers'] | single:
        problems.append(f'registers read {sorted(reads)}, allowed {sorted(policy["registers"] | single)}')
    for register in sorted(single):
        if reads[register] != 1:
            problems.append(f'{register} is read {reads[register]} times, the policy allows exactly one read')
    allow = policy.get('allow', {})
    forbid = set(policy.get('forbid', ()))
    for mnemonic in sorted(set(allow) & forbid):
        problems.append(f'the policy both allows and forbids {mnemonic}')
    for mnemonic in sorted(mnemonics & ((FORBIDDEN | forbid) - set(allow))):
        problems.append(f'forbidden instruction {mnemonic}')
    for form in sorted({(mnemonic, operands.split('//')[0].split(',')[0].strip().lower())
                        for mnemonic, operands in instructions if mnemonic in allow}):
        if form[1] not in allow[form[0]]:
            problems.append(f'forbidden instruction {form[0]} {form[1]}'.strip())
    for mnemonic in sorted(m for m in mnemonics if EXCLUSIVE.match(m) or ATOMIC.match(m)):
        problems.append(f'exclusive or atomic instruction {mnemonic}')
    smc = [operands.strip() for mnemonic, operands in instructions if mnemonic == 'smc']
    if len(smc) != policy['smc']:
        problems.append(f'{len(smc)} smc instructions, the policy allows {policy["smc"]}')
    if any(operand != '#0' for operand in smc):
        problems.append(f'an smc with another immediate than #0: {smc}')
    if 'smc_ids' in policy:
        ids, unreadable = smc_function_ids(text)
        for address in unreadable:
            problems.append(f'the function id of the smc at {address:#x} cannot be read from the code before it')
        if sorted(ids) != sorted(policy['smc_ids']):
            problems.append(f'smc function ids {[hex(i) for i in sorted(ids)]}, the policy allows '
                            f'{[hex(i) for i in sorted(policy["smc_ids"])]}')
    if policy.get('timer_offsets'):
        for register in (CNTVOFF_EL2, CNTPOFF_EL2):
            if reads[register] != 1:
                problems.append(f'{register} is read {reads[register]} times, the policy allows exactly one read')
    else:
        named_by_policy = {name for register in single for name in OFFSET_NAMES.get(register, ())}
        for register in TIMER_OFFSETS:
            if register in text.lower() and register not in named_by_policy:
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
    allowed_words = {}
    for form in sorted({(m, first) for m, firsts in allow.items() for first in firsts}):
        if form not in ALLOW_WORDS:
            problems.append(f'no encoding is known for the allowed form {form[0]} {form[1]}'.strip())
            continue
        what, mask, value = ALLOW_WORDS[form]
        allowed_words.setdefault(what, []).append((mask, value))
    for what, (mask, value) in FORBIDDEN_WORDS.items():
        if any(w & mask == value and not any(w & m == v for m, v in allowed_words.get(what, ())) for w in words):
            problems.append(f'a word of the code encodes {what}')
    for what in sorted(forbid & set(BARRIER_WORDS)):
        mask, value = BARRIER_WORDS[what]
        if any(w & mask == value for w in words):
            problems.append(f'a word of the code encodes {what}')
    words_smc = [w for w in words if w & 0xffe0001f == 0xd4000003]
    if len(words_smc) != policy['smc'] or any(w >> 5 & 0xffff for w in words_smc):
        problems.append(f'{len(words_smc)} words of the code encode smc, the policy allows {policy["smc"]} (immediate 0)')
    if len(data) > policy['bytes']:
        problems.append(f'{len(data)} bytes, the policy allows {policy["bytes"]}')
    return problems


_DIRECT_BRANCH = re.compile(r'^(b|bl|b\.[a-z]{2}|cbz|cbnz|tbz|tbnz)$')
_ANY_TRANSFER = re.compile(r'^(b|bl|b\.[a-z]{2}|cbz|cbnz|tbz|tbnz|br|blr|ret|eret|bra[ab]z?|blra[ab]z?|retaa|retab|smc|hvc|svc)$')


def _addressed_instructions(text):
    """[(address, mnemonic, operands)] of a disassembly, comments dropped; a symbol line is (address, '<label>', name)."""
    items = []
    for line in text.splitlines():
        label = re.match(r'([0-9a-f]+) <(.+)>:\s*$', line)
        if label:
            items.append((int(label.group(1), 16), '<label>', label.group(2)))
            continue
        found = re.match(r'\s+([0-9a-f]+):\s+(\S+)\s*(.*)$', line)
        if found:
            items.append((int(found.group(1), 16), found.group(2).lower(), found.group(3).split('//')[0].strip()))
    return items


def _w0_before(items, smc_index, branch_targets):
    """The value w0 holds at items[smc_index] (an smc), or None when it cannot be read with certainty. The only code that may
    set it is a straight-line run of mov/movz/movn and movk into w0 or x0; between that run and the smc nothing else may name
    w0 or x0, nothing may transfer control (calls, returns, branches, other traps), no symbol may begin, and no branch of the
    program may land inside the run (a join where w0 could have another value)."""
    smc_address = items[smc_index][0]
    halfwords = {}
    for j in range(smc_index - 1, -1, -1):
        address, mnemonic, operands = items[j]
        if mnemonic == '<label>' or _ANY_TRANSFER.match(mnemonic):
            return None
        fields = [field.strip() for field in operands.split(',')]
        if fields[0] in ('w0', 'x0') and mnemonic in ('mov', 'movz', 'movn', 'movk') and len(fields) in (2, 3):
            try:
                immediate = int(fields[1].lstrip('#'), 0)
                shift = int(fields[2].replace('lsl', '').strip().lstrip('#'), 0) if len(fields) == 3 else 0
            except ValueError:
                return None
            width = 32 if fields[0] == 'w0' else 64
            if mnemonic == 'movk':
                if shift % 16 or shift >= width or not 0 <= immediate <= 0xffff:
                    return None
                halfwords.setdefault(shift // 16, immediate)
                continue
            mask = (1 << width) - 1
            value = ~(immediate << shift) & mask if mnemonic == 'movn' else (immediate << shift) & mask
            for half, piece in halfwords.items():
                value = value & ~(0xffff << 16 * half) | piece << 16 * half
            if any(address < target <= smc_address for target in branch_targets):
                return None
            return value
        if re.search(r'\b[wx]0\b', operands):
            return None
    return None


def smc_function_ids(text):
    """(ids, unreadable): the function id of every `smc` in a disassembly, and the addresses of those whose id is not
    certain (see _w0_before)."""
    items = _addressed_instructions(text)
    targets = set()
    for _, mnemonic, operands in items:
        if _DIRECT_BRANCH.match(mnemonic):
            found = re.search(r'\b0x([0-9a-f]+)\b', operands)
            if found:
                targets.add(int(found.group(1), 16))
    ids, unreadable = [], []
    for index, (address, mnemonic, _) in enumerate(items):
        if mnemonic != 'smc':
            continue
        value = _w0_before(items, index, targets)
        if value is None:
            unreadable.append(address)
        else:
            ids.append(value)
    return ids, unreadable


def _string_at(data, address):
    end = data.find(b'\0', address)
    return data[address:end].decode('latin-1') if 0 <= address < len(data) and end >= 0 else None


def _string_argument(instructions, call, data):
    """The C string that was in x1 at the call `instructions[call]`, found through the nearest ADRP/ADD or ADR that
    set it (the payload's say() takes its text there), or None."""
    for at in range(call - 1, -1, -1):
        mnemonic, operands = instructions[at]
        fields = [field.strip() for field in operands.split(',')]
        if mnemonic == 'adr' and fields[0] == 'x1':
            return _string_at(data, int(fields[1].split()[0], 0))
        if mnemonic == 'add' and fields[:2] == ['x1', 'x1'] and fields[2].startswith('#'):
            offset = int(fields[2][1:], 0)
            for back in range(at - 1, -1, -1):
                other, other_operands = instructions[back]
                parts = [field.strip() for field in other_operands.split(',')]
                if other == 'adrp' and parts[0] == 'x1':
                    return _string_at(data, int(parts[1].split()[0], 0) + offset)
            return None
        if fields[0] == 'x1' and mnemonic not in ('str', 'stp', 'cmp', 'tst', 'cbz', 'cbnz', 'bl', 'blr'):
            return None             # x1 is set some other way: not a string the check can read
    return None


def hazard_order_violations(elf, flat):
    """The order of the compiled timer payload, from its disassembly. The last two register reads are CNTVOFF_EL2 and then
    CNTPOFF_EL2, so every other read comes before the first hazard; and each of them follows its NEXT line at once: the
    nearest call before the read is the one that printed that line (the string it was given is found in the flat binary),
    and between that call and the read there is no other call and no other register read. The source-level order is
    pinned by the host test; this is what the compiler made of it."""
    dis = run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)])
    if dis.returncode:
        return [f'llvm-objdump failed: {dis.stderr.strip()}']
    instructions = []
    for line in dis.stdout.splitlines():
        found = re.match(r'\s+[0-9a-f]+:\s+(\S+)\s*(.*)$', line)
        if found:
            instructions.append((found.group(1).lower(), found.group(2)))
    reads = [(at, SYSTEM_REGISTER_ALIASES.get(operands.split(',')[-1].strip().lower(), operands.split(',')[-1].strip().lower()))
             for at, (mnemonic, operands) in enumerate(instructions) if mnemonic == 'mrs']
    if [register for _, register in reads[-2:]] != [CNTVOFF_EL2, CNTPOFF_EL2]:
        return [f'the last two register reads are {[register for _, register in reads[-2:]]}, not CNTVOFF_EL2 then CNTPOFF_EL2']
    data = Path(flat).read_bytes()
    problems = []
    for (at, register), wanted in zip(reads[-2:], ('NEXT CNTVOFF_EL2', 'NEXT CNTPOFF_EL2')):
        call = next((i for i in range(at - 1, -1, -1) if instructions[i][0] in ('bl', 'blr')), None)
        if call is None:
            problems.append(f'{register}: no call comes before the read')
            continue
        if any(mnemonic in ('bl', 'blr', 'mrs') for mnemonic, _ in instructions[call + 1:at]):
            problems.append(f'{register}: another call or register read comes between its NEXT line and the read')
        printed = _string_argument(instructions, call, data)
        if printed != wanted:
            problems.append(f'{register}: the call before the read prints {printed!r}, not {wanted!r}')
    return problems


# ---- The documents ------------------------------------------------------------------------------------------------------
# docs/SP11-PAYLOAD.md and one document per payload link each other: the helpers below say which links do not resolve.
LINK = re.compile(r'(?<!!)\[[^\]\n]+\]\(([^)\s]+)\)')


def anchors_of(text):
    """The anchors GitHub gives the headings of a Markdown document: lower case, everything but letters, digits, spaces,
    underscores and hyphens dropped, spaces to hyphens. Headings inside code fences are not headings."""
    outside = re.sub(r'```.*?```', '', text, flags=re.S)
    return {re.sub(r'[^a-z0-9 _-]', '', title.strip().lower()).replace(' ', '-')
            for title in re.findall(r'^#{1,6} +(.+?) *$', outside, re.M)}


def link_problems(texts, directory):
    """Every relative link of the documents in `texts` ({file name: text}) that does not resolve, as sentences: a file that is
    not there, or an anchor that no heading of its target gives. A target named in `texts` is read from there, so that a
    changed copy is judged; any other is read from `directory`. Links to other sites are not this check's business."""
    problems = []
    for name, text in texts.items():
        for target in LINK.findall(text):
            if re.match(r'[a-z][a-z0-9+.-]*:', target):
                continue
            path, _, fragment = target.partition('#')
            other = path or name
            if other in texts:
                body = texts[other]
            elif (Path(directory) / other).is_file():
                body = (Path(directory) / other).read_text(encoding='utf-8')
            else:
                problems.append(f'{name}: {target}: {other} is not a file')
                continue
            if fragment and fragment not in anchors_of(body):
                problems.append(f'{name}: {target}: {other} has no such heading')
    return problems
