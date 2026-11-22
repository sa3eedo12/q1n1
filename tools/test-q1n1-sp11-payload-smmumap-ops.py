#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The mapping step's EL2 operations and its reading of PAR_EL1, run (docs/SP11-PAYLOAD-SMMUMAP.md): two things the shipped suites
(tools/test-q1n1-sp11-payload-smmumap.py) judge by text and by the digest of the image, not by what they do.

    python3 tools/test-q1n1-sp11-payload-smmumap-ops.py

  * Ops: platform/uefi/sp11-smmumap-el2.c is compiled for the unit's target and its object is executed by a small interpreter of exactly the instructions it has (a
    compiler that emits another one fails the test, never passes it): q1n1_smmumap_el2_ops() fills the environment, then the function each field holds is called and the
    machine instructions it executes are logged, so a barrier bound to the wrong field, a TCR_EL2 read into the field of MAIR_EL2, an AT of the wrong kind or a TLBI operand
    that is not VA[55:12] fails for its own reason. The offsets of the fields are the target's own (a host compile of the header). The audits of the shipped suite count the
    instructions; they cannot see where the results and addresses go.
  * Par: tools/test-q1n1-sp11-payload-smmumap-par.c, the step's judgment of PAR_EL1 (a translation that FAILED but echoes the page in its address field is not a hit), as
    called values and as the whole step in the modelled machine, under ASan and UBSan.
  * Mutants: seeded bugs in copies of the two sources, each caught for its own reason (a bug that survives, or fails for another reason, fails the test).

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model and an interpreter of the object, not the unit)."""
from pathlib import Path
import re
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_smmumap_mutants as mut  # noqa: E402
import sp11_payload_testlib as lib  # noqa: E402

UEFI = ROOT / 'platform' / 'uefi'
TOOLS = ROOT / 'tools'
BUILD = ROOT / 'build' / 'smmumap-ops-test'
GATES = ['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1', '-DQ1N1_SP11_SMMUMAP=1']
TARGET = ['--target=aarch64-pc-windows-msvc', '-O2', '-ffreestanding', '-fno-builtin', '-fshort-wchar', '-mgeneral-regs-only', '-Wall', '-Wextra', '-Werror']
SANITIZE = ['-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror']
EL2 = 'sp11-smmumap-el2.c'
LOGIC = 'sp11-smmumap.c'
OWN_FILES = [Path(__file__), TOOLS / 'test-q1n1-sp11-payload-smmumap-par.c']
ENV_FIELDS = ('regs', 'at', 'clean', 'dsb', 'tlbi', 'isb', 'serror_pending')
REG_FIELDS = {'ttbr0': 'TTBR0_EL2', 'tcr': 'TCR_EL2', 'mair': 'MAIR_EL2', 'sctlr': 'SCTLR_EL2', 'hcr': 'HCR_EL2'}
# Distinct in every byte of the top nibble, so that one register read into another's field is told from the value it carries.
SYSREGS = {'TTBR0_EL2': 0x1000000000000001, 'TCR_EL2': 0x2000000000000002, 'MAIR_EL2': 0x3000000000000003, 'SCTLR_EL2': 0x4000000000000004,
           'HCR_EL2': 0x5000000000000005, 'PAR_EL1': 0x6000000000000006, 'TTBR0_EL1': 0x7000000000000007, 'ISR_EL1': 0x100}
ENV_AT, REGS_AT, PAR_AT = 0x10000, 0x20000, 0x30000
MASK = (1 << 64) - 1


class Unmodelled(Exception):
    """An instruction the interpreter does not know: the object is not the one this test was written for."""


def listing(obj):
    """{function: [{'addr', 'op', 'args', 'reloc'}]} from the object's disassembly with its relocations."""
    text = lib.run(['llvm-objdump', '-d', '-r', '--no-show-raw-insn', str(obj)], check=True).stdout
    functions, name = {}, None
    for line in text.splitlines():
        header = re.match(r'^[0-9a-f]+ <(\w+)>:', line)
        if header:
            name = functions.setdefault(header.group(1), [])
        elif name is not None and re.match(r'^\s+[0-9a-f]+:\s+IMAGE_REL', line):
            name[-1]['reloc'] = line.split()[-1]
        elif name is not None and re.match(r'^\s+[0-9a-f]+:\s', line):
            at, op, args = re.match(r'^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$', line).groups()
            name.append({'addr': int(at, 16), 'op': op, 'args': re.sub(r'\s*<[^>]*>\s*$', '', args), 'reloc': None})
    return functions


class Machine:
    """Executes the object's functions on integers (a function's address is ('sym', name)) and logs what the system instructions of the unit's EL2 would be given."""
    def __init__(self, functions, sysregs):
        self.functions, self.sysregs, self.mem, self.log, self.reg = functions, dict(sysregs), {}, [], {}

    def get(self, name):
        if name in ('xzr', 'wzr'):
            return 0
        value = self.reg['x' + name[1:]]
        if isinstance(value, tuple):
            if name[0] == 'w':
                raise Unmodelled('half of a function address')
            return value
        return value & (0xffffffff if name[0] == 'w' else MASK)

    def put(self, name, value):
        if name not in ('xzr', 'wzr'):
            self.reg['x' + name[1:]] = value

    def run(self, target, *args):
        """Calls the function `target` ('sym', name) with `args`; returns x0."""
        if not (isinstance(target, tuple) and target[0] == 'sym' and target[1] in self.functions):
            raise Unmodelled(f'{target!r} is not a function of the object')
        code = self.functions[target[1]]
        where = {ins['addr']: k for k, ins in enumerate(code)}
        self.reg = {f'x{k}': v for k, v in enumerate(args)}
        pc = steps = 0
        while True:
            steps += 1
            if steps > 100 or pc >= len(code):
                raise Unmodelled('a function that does not end')
            ins = code[pc]
            op, a = ins['op'], ins['args']
            pc += 1
            if op == 'ret':
                return self.get('x0') if 'x0' in self.reg else 0
            elif op == 'adrp' and ins['reloc']:
                self.put(a.split(',')[0], ('sym', ins['reloc']))
            elif op == 'add' and (m := re.fullmatch(r'(x\d+), (x\d+), #(0x[0-9a-f]+|\d+)', a)):
                src = self.get(m[2])
                if isinstance(src, tuple):
                    if not (ins['reloc'] and int(m[3], 0) == 0):
                        raise Unmodelled(f'arithmetic on the address of {src[1]}')
                    self.put(m[1], src)
                else:
                    self.put(m[1], (src + int(m[3], 0)) & MASK)
            elif op in ('str', 'stp') and (m := re.fullmatch(r'(\w+), (?:(\w+), )?\[(x\d+)(?:, #(0x[0-9a-f]+|\d+))?\]', a)):
                base = self.get(m[3]) + int(m[4] or '0', 0)
                for k, source in enumerate(x for x in (m[1], m[2]) if x):
                    self.mem[base + 8 * k] = self.get(source)
            elif op == 'mrs' and (m := re.fullmatch(r'(x\d+), (\w+)', a)):
                register = m[2].upper()
                if register not in self.sysregs:
                    raise Unmodelled(f'mrs of {register}')
                self.log.append(('mrs', register))
                self.put(m[1], self.sysregs[register])
            elif op == 'at' and (m := re.fullmatch(r's1e2([rw]), (x\d+)', a)):
                self.log.append(('at s1e2' + m[1], self.get(m[2])))
            elif op in ('dc', 'tlbi') and (m := re.fullmatch(r'(cvac|vale2is), (x\d+)', a)):
                self.log.append((f'{op} {m[1]}', self.get(m[2])))
            elif op == 'dsb' and a == 'ish':
                self.log.append(('dsb ish',))
            elif op == 'isb' and not a:
                self.log.append(('isb',))
            elif op == 'ubfx' and (m := re.fullmatch(r'([wx]\d+), ([wx]\d+), #(\d+), #(\d+)', a)):
                self.put(m[1], (self.get(m[2]) >> int(m[3])) & ((1 << int(m[4])) - 1))
            elif op in ('cbz', 'cbnz') and (m := re.fullmatch(r'([wx]\d+), (0x[0-9a-f]+)', a)):
                if (self.get(m[1]) == 0) == (op == 'cbz'):
                    pc = where[int(m[2], 16)]
            elif op == 'b' and (m := re.fullmatch(r'(0x[0-9a-f]+)', a)):
                pc = where[int(m[1], 16)]
            elif op == 'and' and (m := re.fullmatch(r'([wx]\d+), ([wx]\d+), #(0x[0-9a-f]+)', a)):
                self.put(m[1], self.get(m[2]) & int(m[3], 16))
            elif op == 'mov' and (m := re.fullmatch(r'([wx]\d+), (wzr|xzr|#\d+)', a)):
                self.put(m[1], 0 if m[2][0] != '#' else int(m[2][1:]))
            else:
                raise Unmodelled(f'{op} {a}')


def field_offsets():
    """The target's own offsets (all fields are 64-bit integers and pointers, so the host's layout is the unit's): {'env': {field: offset}, 'regs': {...}}."""
    lines = ''.join(f'printf("env %s %zu\\n", "{f}", offsetof(struct q1n1_smmumap_env, {f}));' for f in ENV_FIELDS)
    lines += ''.join(f'printf("regs %s %zu\\n", "{f}", offsetof(struct q1n1_smmumap_regs, {f}));' for f in REG_FIELDS)
    source = f'#include <stddef.h>\n#include <stdio.h>\n#include "sp11-smmumap.h"\nint main(void) {{ {lines} return 0; }}\n'
    BUILD.mkdir(parents=True, exist_ok=True)
    built = lib.run(['clang', '-x', 'c', '-', '-I', str(UEFI)] + GATES + ['-o', str(BUILD / 'offsets')], input=source)
    if built.returncode:
        raise RuntimeError(built.stderr)
    out = lib.run([str(BUILD / 'offsets')]).stdout.split()
    table = {'env': {}, 'regs': {}}
    for k in range(0, len(out), 3):
        table[out[k]][out[k + 1]] = int(out[k + 2])
    return table


def behaviour_problems(obj, offsets):
    """What the object does, as a list of words for each thing that is not what the unit needs; empty when it is right."""
    problems = []

    def show(value):
        return f'{value:#x}' if isinstance(value, int) else repr(value)

    def show_log(log):
        return '[' + ', '.join('(' + ', '.join(show(x) for x in entry) + ')' for entry in log) + ']'
    try:
        machine = Machine(listing(obj), SYSREGS)
        machine.run(('sym', 'q1n1_smmumap_el2_ops'), ENV_AT)
        held = {f: machine.mem.get(ENV_AT + offsets['env'][f]) for f in ENV_FIELDS}
        stray = sorted(a - ENV_AT for a in machine.mem if a - ENV_AT not in offsets['env'].values())
        if stray:
            problems.append(f'q1n1_smmumap_el2_ops stores outside the fields it binds: {stray}')
        unbound = [f for f, v in held.items() if v is None]
        if unbound:
            return problems + [f'env.{f} is not bound' for f in unbound]

        def call(field, *args):
            machine.log = []
            return machine.run(held[field], *args)

        def executes(what, want):
            if machine.log != want:
                problems.append(f'env.{what} executes {show_log(machine.log)}, wanted {show_log(want)}')
        call('dsb')
        executes('dsb', [('dsb ish',)])
        call('isb')
        executes('isb', [('isb',)])
        va = 0xFF00000015400000
        call('clean', va)
        executes('clean', [('dc cvac', va)])
        call('tlbi', va)
        executes('tlbi', [('tlbi vale2is', (va >> 12) & ((1 << 44) - 1))])
        for write in (0, 1):
            machine.mem[PAR_AT] = 0
            got = call('at', va, write, PAR_AT)
            executes(f'at(va, {write})', [('at s1e2' + 'rw'[write], va), ('isb',), ('mrs', 'PAR_EL1')])
            if machine.mem.get(PAR_AT) != SYSREGS['PAR_EL1'] or got != 0:
                problems.append(f'env.at(va, {write}) leaves {show(machine.mem.get(PAR_AT))} (returns {got}), wanted PAR_EL1 and 0')
        machine.mem = {}
        call('regs', REGS_AT)
        for field, register in REG_FIELDS.items():
            if machine.mem.get(REGS_AT + offsets['regs'][field]) != SYSREGS[register]:
                problems.append(f'regs.{field} holds {show(machine.mem.get(REGS_AT + offsets["regs"][field]))}, wanted {register}')
        if sorted(r for _, r in machine.log) != sorted(REG_FIELDS.values()):
            problems.append(f'env.regs reads {sorted(r for _, r in machine.log)}, wanted {sorted(REG_FIELDS.values())}')
        for isr, want in ((0x100, 1), (0, 0), (MASK & ~0x100, 0), (0x300, 1)):
            machine.sysregs['ISR_EL1'] = isr
            got = call('serror_pending')
            if got != want or machine.log != [('mrs', 'ISR_EL1')]:
                problems.append(f'env.serror_pending with ISR_EL1 {isr:#x} gives {got} after {show_log(machine.log)}, wanted {want}')
    except Unmodelled as error:
        problems.append(f'the object does something this test does not model: {error}')
    return problems


def build_object(uefi, out):
    out.parent.mkdir(parents=True, exist_ok=True)
    return lib.run(['clang'] + TARGET + ['-I', str(uefi)] + GATES + ['-c', str(uefi / EL2), '-o', str(out)])


def build_par(uefi, out):
    out.parent.mkdir(parents=True, exist_ok=True)
    return lib.run(['clang'] + SANITIZE + GATES + ['-I', str(uefi), str(TOOLS / 'test-q1n1-sp11-payload-smmumap-par.c'), str(uefi / 'sp11-payload-text.c'), '-o', str(out)])


# Seeded bugs: (name, file, edits, reason, flags, program); `reason` is a regular expression over the words the failing check prints.
MUTANTS = [
    mut.two('the-dsb-and-the-isb-are-bound-the-wrong-way-round', EL2, [('env->dsb = op_dsb;', 'env->dsb = op_isb;'), ('env->isb = op_isb;', 'env->isb = op_dsb;')],
            r"env\.dsb executes \[\('isb'\)\]|env\.isb executes \[\('dsb ish'\)\]", program='ops'),
    mut.two('tcr-and-mair-are-read-into-each-others-fields', EL2, [('"mrs %0, tcr_el2" : "=r"(r->tcr)', '"mrs %0, tcr_el2" : "=r"(r->mair)'),
                                                                  ('"mrs %0, mair_el2" : "=r"(r->mair)', '"mrs %0, mair_el2" : "=r"(r->tcr)')],
            r'regs\.tcr holds 0x3\w*, wanted TCR_EL2|regs\.mair holds 0x2\w*, wanted MAIR_EL2', program='ops'),
    mut.two('sctlr-and-hcr-are-read-into-each-others-fields', EL2, [('"mrs %0, sctlr_el2" : "=r"(r->sctlr)', '"mrs %0, sctlr_el2" : "=r"(r->hcr)'),
                                                                   ('"mrs %0, hcr_el2" : "=r"(r->hcr)', '"mrs %0, hcr_el2" : "=r"(r->sctlr)')],
            r'regs\.sctlr holds 0x5\w*, wanted SCTLR_EL2', program='ops'),
    mut.sub('ttbr0-is-read-from-the-el1-register', EL2, '"mrs %0, ttbr0_el2"', '"mrs %0, ttbr0_el1"', r'regs\.ttbr0 holds 0x7\w*, wanted TTBR0_EL2', program='ops'),
    mut.two('the-clean-and-the-tlbi-are-bound-the-wrong-way-round', EL2, [('env->clean = op_clean;', 'env->clean = op_tlbi;'), ('env->tlbi = op_tlbi;', 'env->tlbi = op_clean;')],
            r"env\.clean executes \[\('tlbi vale2is'|env\.tlbi executes \[\('dc cvac'", program='ops'),
    mut.sub('the-at-for-a-write-is-the-read-form', EL2, 'if (write) __asm__ volatile("at s1e2w, %0"', 'if (!write) __asm__ volatile("at s1e2w, %0"',
            r'env\.at\(va, [01]\) executes', program='ops'),
    mut.sub('the-tlbi-operand-is-not-shifted', EL2, 'uint64_t operand = (va >> 12) & ((UINT64_C(1) << 44) - 1);', 'uint64_t operand = va & ((UINT64_C(1) << 44) - 1);',
            r"env\.tlbi executes \[\('tlbi vale2is'", program='ops'),
    mut.sub('the-serror-bit-is-bit-9', EL2, 'return (int)((isr >> 8) & 1u);', 'return (int)((isr >> 9) & 1u);', r'env\.serror_pending with ISR_EL1', program='ops'),
    mut.sub('par_page-ignores-the-fault-bit', LOGIC, 'return !(par & 1u) && (par & Q1N1_SMMUMAP_ADDR) == pa;', 'return (par & Q1N1_SMMUMAP_ADDR) == pa;',
            r'a faulting PAR \(FST [^)]*\) whose address field echoes the page is accepted', program='par'),
    mut.sub('par_page-looks-only-at-the-fault-bit', LOGIC, 'return !(par & 1u) && (par & Q1N1_SMMUMAP_ADDR) == pa;', 'return !(par & 1u) || pa == 0;',
            r'another page is accepted', program='par'),
    mut.sub('the-table-page-write-test-ignores-the-fault-bit', LOGIC, 'if (!par_page(par_table, target.table) ||',
            'if ((par_table & Q1N1_SMMUMAP_ADDR) != target.table ||', r'the table page.s write AT faults and echoes its address: faulting PAR', program='par'),
    mut.sub('the-read-check-after-the-store-ignores-the-fault-bit', LOGIC, 'good = par_page(par_r, spec->page_pa) &&',
            'good = (par_r & Q1N1_SMMUMAP_ADDR) == spec->page_pa &&', r'after the store the read AT faults and echoes the page: faulting PAR', program='par'),
    mut.sub('the-write-check-after-the-store-ignores-the-fault-bit', LOGIC, '&& par_page(par_w, spec->page_pa)',
            '&& (par_w & Q1N1_SMMUMAP_ADDR) == spec->page_pa', r'after the store the write AT faults and echoes the page: faulting PAR', program='par'),
]


def evaluate(m, offsets):
    """(status, detail) of one seeded bug: 'caught', 'survived', 'wrong-reason' or 'stale'."""
    name, file, edits, reason, _, program = m
    directory = BUILD / 'mutants' / name
    shutil.rmtree(directory, ignore_errors=True)
    shutil.copytree(UEFI, directory / 'uefi', ignore=shutil.ignore_patterns('*.obj', '*.o', '*.d'))
    text = (directory / 'uefi' / file).read_text(encoding='utf-8')
    for old, new in edits:
        if text.count(old) != 1:
            return 'stale', f'{old[:60]!r} occurs {text.count(old)} times'
        text = text.replace(old, new)
    (directory / 'uefi' / file).write_text(text, encoding='utf-8')
    if program == 'ops':
        built = build_object(directory / 'uefi', directory / 'el2.obj')
        if built.returncode:
            return 'wrong-reason', 'does not build: ' + built.stderr[-300:]
        words = '\n'.join(behaviour_problems(directory / 'el2.obj', offsets))
    else:
        built = build_par(directory / 'uefi', directory / 'par')
        if built.returncode:
            return 'wrong-reason', 'does not build: ' + built.stderr[-300:]
        done = lib.run([str(directory / 'par')], timeout=180)
        words = done.stdout + done.stderr if done.returncode else ''
    shutil.rmtree(directory, ignore_errors=True)
    if not words:
        return 'survived', 'the shipped checks passed'
    if not re.search(reason, words):
        return 'wrong-reason', f'failed for another reason (wanted /{reason}/): {words[:400]}'
    return 'caught', ''


@unittest.skipUnless(lib.have('clang') and lib.have('llvm-objdump'), 'clang or llvm-objdump not installed')
class Ops(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        BUILD.mkdir(parents=True, exist_ok=True)
        cls.offsets = field_offsets()

    def test_the_offsets_are_the_headers_own(self):
        self.assertEqual(sorted(self.offsets['env']), sorted(ENV_FIELDS))
        self.assertEqual(self.offsets['env']['regs'], 0x18)
        self.assertEqual(self.offsets['env']['serror_pending'], 0x78)
        self.assertEqual(self.offsets['regs'], {'ttbr0': 0, 'tcr': 8, 'mair': 16, 'sctlr': 24, 'hcr': 32})

    def test_the_shipped_object_binds_and_executes_what_the_step_needs(self):
        done = build_object(UEFI, BUILD / 'el2.obj')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(behaviour_problems(BUILD / 'el2.obj', self.offsets), [])

    def test_the_shipped_step_judges_par_by_its_fault_bit(self):
        done = build_par(UEFI, BUILD / 'par')
        self.assertEqual(done.returncode, 0, done.stderr)
        run = lib.run([str(BUILD / 'par')], timeout=180)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertRegex(run.stdout, r'\d+ checks, 0 failures')

    def test_the_new_files_follow_the_repository_rules(self):
        # Built from pieces so that this file does not contain what it looks for.
        pattern = re.compile('|'.join(['/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/', '/t' + 'mp/']) + r'|\.loc' + r'al\b|\bsae' + r'ed\b|host' + r'name', re.I)
        for path in OWN_FILES:
            text = path.read_text(encoding='utf-8')
            with self.subTest(file=path.name):
                self.assertIn('SPDX-License-Identifier: MIT', text[:200])
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                self.assertTrue(all(ord(c) < 128 for c in text), 'a character outside ASCII')
                self.assertIsNone(pattern.search(text))

    def test_the_seeded_bugs_are_distinct_and_their_needles_occur_once(self):
        names = [m[0] for m in MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertEqual({m[5] for m in MUTANTS}, {'ops', 'par'})
        self.assertEqual([bad for m in MUTANTS for bad in mut.stale(m, ROOT)], [])
        for m in MUTANTS:
            re.compile(m[3])
            self.assertTrue(all(old != new for old, new in m[2]), f'{m[0]} changes nothing')

    def test_every_seeded_bug_is_caught_for_its_own_reason(self):
        for m in MUTANTS:
            status, detail = evaluate(m, self.offsets)
            with self.subTest(mutant=m[0]):
                self.assertEqual(status, 'caught', detail)
        shutil.rmtree(BUILD / 'mutants', ignore_errors=True)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
