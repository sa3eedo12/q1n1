#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The runner's mapping step (docs/SP11-PAYLOAD-SMMUMAP.md): host tests, source audits, the gate-at-zero proof and the seeded bugs. The document has its own test,
tools/test-q1n1-sp11-payload-smmumap-doc.py.

    python3 tools/test-q1n1-sp11-payload-smmumap.py

  * SmmumapNative: the host programs (-.c with -scan.c and -world.h: eighteen suites over modelled tables, memory map and AT; -run.c: the hook; -walk.c: the proven
    load, the walk and the scan, by including the source) under ASan and UBSan.
  * SmmumapSource: what no host run shows: the instructions of sp11-smmumap-el2.c, the loads and the store of main.c's gated code, the golden digest of the gated
    glue, the one store and the one proven load of the logic, the hook, the size and identity rules of AGENTS.md; each with seeded bad variants.
  * SmmumapGateOff: with the gate at 0 the new files are empty, the runner's files preprocess as at the base commit and the Makefile's lines are the base's.
  * SmmumapBuild: the runner from the base commit and from this tree with the gate off is one byte string; the gate on builds to one.
  * SmmumapMutants: tools/sp11_payload_smmumap_mutants.py, each seeded bug rejected for its own reason.

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
import hashlib
import os
import re
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_smmumap_mutants as mut  # noqa: E402

UEFI = ROOT / 'platform' / 'uefi'
TOOLS = ROOT / 'tools'
BUILD = ROOT / 'build' / 'smmumap-test'
BASE_COMMIT = '241b7ca'
LLVM = ('/opt/homebrew/opt/llvm/bin', '/opt/homebrew/opt/lld/bin', '/opt/homebrew/bin')
ENV = dict(os.environ, PATH=os.pathsep.join(LLVM + (os.environ.get('PATH', ''),)), PYTHONDONTWRITEBYTECODE='1')
SANITIZE = ['-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror']
GATES = ['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1', '-DQ1N1_SP11_SMMUMAP=1']
# A seeded bug may leave a variable, a parameter or a function unused; that is no reason for it not to build.
RELAX = ['-Wno-unused-parameter', '-Wno-unused-variable', '-Wno-unused-but-set-variable', '-Wno-unused-function']
SUITES = ('good', 'pure', 'map', 'template', 'entry', 'walk', 'table', 'at', 'unsafe', 'regs', 'spec', 'store', 'counter', 'publish', 'ram', 'scan', 'serror', 'fuzz')
OWN_FILES = [UEFI / 'sp11-smmumap.h', UEFI / 'sp11-smmumap.c', UEFI / 'sp11-smmumap-el2.c', TOOLS / 'test-q1n1-sp11-payload-smmumap.c',
             TOOLS / 'test-q1n1-sp11-payload-smmumap-scan.c', TOOLS / 'test-q1n1-sp11-payload-smmumap-world.h', TOOLS / 'test-q1n1-sp11-payload-smmumap-run.c',
             TOOLS / 'test-q1n1-sp11-payload-smmumap-walk.c', TOOLS / 'sp11_payload_smmumap_mutants.py', TOOLS / 'test-q1n1-sp11-payload-smmumap-doc.py', Path(__file__)]
# What each host program is built from: the test, and the sources of the tree under test it links (the walk program includes the logic itself).
PROGRAMS = {
    'main': (('test-q1n1-sp11-payload-smmumap.c', 'test-q1n1-sp11-payload-smmumap-scan.c'), ('sp11-smmumap.c',)),
    'hook': (('test-q1n1-sp11-payload-smmumap-run.c',), ('sp11-payload-run.c', 'preload.c', 'sha256.c')),
    'walk': (('test-q1n1-sp11-payload-smmumap-walk.c',), ()),
}
FIXTURES = ['SP11_USB_TABLE_C=tools/testdata/sp11-usb-table-fixture.c', 'SP11_STAGE_TABLE_C=tools/testdata/sp11-stage-table-fixture.c']
RECIPE = ['SP11=1', 'PAYLOAD=1', 'SP11_BUILD_STAMP=A9F00F9CCBB5'] + FIXTURES + ['LD=lld-link /Brepro']


def run(cmd, cwd=ROOT, timeout=900, **kw):
    return subprocess.run(cmd, cwd=cwd, env=ENV, capture_output=True, text=True, timeout=timeout, **kw)


def have(tool):
    return shutil.which(tool, path=ENV['PATH']) is not None


# One pass that cuts C as the compiler's tokenizer does: a quote opens a string or character literal that only a quote of the same kind ends (a backslash escapes the next
# character, a line break included; an unterminated one ends with its line), so a comment marker inside one starts no comment; the <header> of an #include is a literal
# too; GNU mode has no trigraphs. (The regex that cut comments out whole also cut the code between a '/*' in one literal and a '*/' in another.)
C_LEX = re.compile(r'(?P<lit>"(?:\\.|[^"\\\n])*"?|\'(?:\\.|[^\'\\\n])*\'?|^[ \t]*#[ \t]*(?:include|include_next|import)[ \t]*<[^>\n]*>?)'
                   r'|(?P<com>/\*.*?\*/|//(?:\\.|[^\\\n])*)|(?P<nl>\n)|(?P<blank>[ \t\r\f\v]+)', re.S | re.M)


def strip_comments(text):
    """`text` with each comment replaced by one blank, as the compiler sees it."""
    return C_LEX.sub(lambda m: ' ' if m.lastgroup == 'com' else m.group(0), text)


def squeeze(text):
    """The code and the literals of `text`, each run of blanks and comments one blank and each run that holds a line break one line break."""
    cut = C_LEX.sub(lambda m: m.group(0) if m.lastgroup == 'lit' else '\x02' if m.lastgroup == 'nl' else '\x01', text)
    return re.sub('[\x01\x02]+', lambda g: '\n' if '\x02' in g.group(0) else ' ', cut).strip()


def compile_native(uefi, flags, binary, program='main', extra=()):
    tests, sources = PROGRAMS[program]
    binary.parent.mkdir(parents=True, exist_ok=True)
    return run(['clang'] + SANITIZE + GATES + list(flags) + ['-I', str(uefi)] + [str(TOOLS / t) for t in tests] + [str(uefi / s) for s in sources] +
               [str(uefi / 'sp11-payload-text.c')] + list(extra) + ['-o', str(binary)])


def base_tree():
    """The files of platform/uefi at the commit this gate was built on, extracted under build/ (None when git cannot name it)."""
    if run(['git', 'cat-file', '-e', f'{BASE_COMMIT}^{{commit}}']).returncode != 0:
        return None
    target = BUILD / 'base'
    if not (target / 'platform' / 'uefi' / 'main.c').exists():
        shutil.rmtree(target, ignore_errors=True)
        target.mkdir(parents=True)
        archive = subprocess.run(['git', 'archive', BASE_COMMIT], cwd=ROOT, capture_output=True, check=True).stdout
        subprocess.run(['tar', '-x', '-C', str(target)], input=archive, check=True)
    return target


class SmmumapNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)
        cls.binary = BUILD / 'native' / 'test'
        done = compile_native(UEFI, (), cls.binary)
        assert done.returncode == 0, done.stderr

    def test_all_suites_pass(self):
        done = run([str(self.binary), 'all'])
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-500:])
        self.assertRegex(done.stdout, rf'PASS: smmumap all, {len(SUITES)} suites, \d+ checks')

    def test_each_suite_runs_alone(self):
        for suite in SUITES:
            with self.subTest(suite=suite):
                done = run([str(self.binary), suite])
                self.assertEqual(done.returncode, 0, done.stdout[-800:])
                self.assertRegex(done.stdout, r'PASS: smmumap \w+, 1 suites, \d+ checks')

    def test_an_unknown_suite_is_an_error(self):
        self.assertNotEqual(run([str(self.binary), 'nosuchsuite']).returncode, 0)

    def test_the_most_lines_are_ten_of_the_chain_budget(self):
        done = run([str(self.binary), 'lines-report'])
        self.assertEqual((done.returncode, done.stdout.strip()), (0, 'LINES_MAX=10'))

    def test_a_lowered_bound_on_the_reads_of_a_wait_is_told_from_a_dead_counter(self):
        binary = BUILD / 'spin' / 'test'
        done = compile_native(UEFI, mut.SPIN, binary)
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite in mut.SPIN_SUITES:
            with self.subTest(suite=suite):
                done = run([str(binary), suite])
                self.assertEqual(done.returncode, 0, done.stdout[-800:])

    def test_the_hook_in_the_runner(self):
        binary = BUILD / 'hook' / 'test'
        done = compile_native(UEFI, (), binary, program='hook')
        self.assertEqual(done.returncode, 0, done.stderr)
        done = run([str(binary)])
        self.assertEqual(done.returncode, 0, done.stdout[-800:])
        self.assertRegex(done.stdout, r'PASS: smmumap runner hook, \d+ checks')

    def test_the_walk_and_the_table_arithmetic_of_the_scan(self):
        binary = BUILD / 'walk' / 'test'
        done = compile_native(UEFI, (), binary, program='walk')
        self.assertEqual(done.returncode, 0, done.stderr)
        done = run([str(binary)])
        self.assertEqual(done.returncode, 0, done.stdout[-800:])
        self.assertRegex(done.stdout, r'PASS: smmumap walk, \d+ checks')


# ---- what the host cannot run: the instructions and the store ---------------------------------------------------------------------------------

EL2_ASM = ['mrs %0, ttbr0_el2', 'mrs %0, tcr_el2', 'mrs %0, mair_el2', 'mrs %0, sctlr_el2', 'mrs %0, hcr_el2', 'at s1e2w, %0', 'at s1e2r, %0',
           r'isb\n mrs %0, par_el1', 'dc cvac, %0', 'dsb ish', 'tlbi vale2is, %0', 'isb', 'mrs %0, isr_el1']


def audit_el2(text):
    """What is wrong with the source of the EL2 operations, as a list of problems (none: it is the audited one)."""
    code = strip_comments(text)
    problems = []
    asm = re.findall(r'__asm__ volatile\("([^"]*)"', code)
    if sorted(asm) != sorted(EL2_ASM):
        problems.append(f'instructions are not the allowed set: {sorted(set(asm) ^ set(EL2_ASM))}')
    if not re.search(r'if \(write\) __asm__ volatile\("at s1e2w, %0"[^;]*;\s*else __asm__ volatile\("at s1e2r, %0"', code):
        problems.append('the write form is not the one for write')
    if '(va >> 12) & ((UINT64_C(1) << 44) - 1)' not in code or 'tlbi vale2is, %0" : : "r"(operand)' not in code:
        problems.append('the TLBI operand is not VA[55:12] in bits 43:0')
    if re.search(r'\bmsr\b', code):
        problems.append('an msr')
    if re.search(r'\bvolatile\s*\*|\*\s*\(\s*volatile|\bstr\b|\bldr\b', code):
        problems.append('a raw access')
    if code.count('__asm__') != len(EL2_ASM):
        problems.append('the number of asm statements')
    return problems


def split_gate(text, gate='Q1N1_SP11_SMMUMAP', anchors=False):
    """(on, off): the lines only the gate adds (every `#if gate` branch) and the lines the compiler sees with the gate at 0 (that branch dropped, its `#else` kept).
    With `anchors`, each branch of `on` begins with a line `@@ <the code line before it>`, so that a block moved elsewhere is not the same text."""
    on, off, state, depth, last = [], [], 'plain', 0, ''
    for line in text.splitlines(keepends=True):
        word = re.match(r'[ \t]*#[ \t]*(if|ifdef|ifndef|else|elif|endif)\b(.*)', line)
        kind = word.group(1) if word else ''
        if state == 'plain':
            if kind == 'if' and word.group(2).split('/*')[0].strip() == gate:
                state, depth = 'on', 0
                if anchors:
                    on.append('@@ ' + last + '\n')
            else:
                off.append(line)
                last = ' '.join(line.split()) or last
            continue
        if kind in ('if', 'ifdef', 'ifndef'):
            depth += 1
        elif kind == 'endif':
            if not depth:
                state = 'plain'
                continue
            depth -= 1
        elif kind in ('else', 'elif') and not depth:
            state = 'else'
            continue
        if state == 'on':
            on.append(line)
        else:
            off.append(line)
            last = ' '.join(line.split()) or last
    return ''.join(on), ''.join(off)


# The gated glue of the runner, by its digest. GATED_BANNED below is a deny-list and cannot name every way to reach memory, so the code that the gate adds to main.c and
# sp11-payload-run.c (blocks spelled `#if Q1N1_SP11_SMMUMAP`; comments cut by the scanner above, blanks squeezed, each block led by the code line before it) is also pinned
# whole: an edit of it other than comments and blanks fails until the glue is audited again by hand and the digest updated. A tripwire for review, not a proof: a gate
# spelled another way is caught by the audit that the code with the gate at 0 never names the step, and what runs is identified by the staged image's SHA-256.
GATED_GLUE_SHA256 = '983bdb48f04195ca10542b8a8f1fa3f503acc060df867de36b3fc5c71b454734'
GLUE_MESSAGE = ('the gated glue of main.c and sp11-payload-run.c is not the audited text (digest {have}, audited {want}): audit it again by hand, '
                'every load, store, copy and call it makes and where each block sits, then set GATED_GLUE_SHA256 in this file to the new digest')


def gated_glue_digest(main_text, run_text):
    parts = [squeeze(split_gate(strip_comments(text), anchors=True)[0]) for text in (main_text, run_text)]
    return hashlib.sha256('\n'.join(parts).encode('utf-8')).hexdigest()


# What the gated code of main.c may contain that reaches memory: the two guarded copies of the step's two helpers, and nothing of the other kinds of access.
GATED_BANNED = ('volatile', 'memset32', 'memcpy64', 'write32', 'G_SET32', '__asm__')


def audit_main_store(text):
    """The loads and the one store the runner makes for the mapping step in platform/uefi/main.c: one ldr and one str of 8 bytes through the guarded copy, and
    nothing else in the code the gate adds that could reach memory: exactly the two guarded copies of the helpers, no volatile access, no other copy or store
    function, and nothing of the step in the code the compiler sees with the gate at 0."""
    problems = []
    start = text.find('static int smmumap_read64(')
    if start < 0:
        return ['no smmumap_read64']
    block = text[start:text.index('static void sp11_payload_el2_run(void)', start)]
    if not re.search(r'static int smmumap_read64\(uint64_t pa, uint64_t \*value\)\s*\{\s*return live_guarded\(1, \(uintptr_t\)value, pa, 8\);\s*\}', block):
        problems.append('the read is not one guarded 8-byte copy from the address into the value')
    if not re.search(r'static int smmumap_store64\(uint64_t pa, uint64_t value\)\s*\{\s*return live_guarded\(1, pa, \(uintptr_t\)&value, 8\);\s*\}', block):
        problems.append('the store is not one guarded 8-byte copy of the value to the address')
    if text.count('live_guarded(1, pa, (uintptr_t)&value, 8)') != 1 or text.count('smmumap_store64') != 2 or text.count('smmumap_read64') != 2:
        problems.append('the store or the read is used or defined more than once')
    if 'return kind == Q1N1_PAYLOAD_G_COPY32 ? live_guarded(0, dst, src, size) : 1;' not in text:
        problems.append('the payloads got a store kind')
    for needle in ('smmumap_env.emit = payload_emit;', 'smmumap_env.counter = counter;', 'smmumap_env.freq = frequency();', 'smmumap_env.read64 = smmumap_read64;',
                   'smmumap_env.store64 = smmumap_store64;', 'smmumap_env.map = (const uint8_t *)(uintptr_t)info.memory_map;', 'smmumap_env.map_size = info.memory_map_size;',
                   'smmumap_env.map_stride = info.memory_map_stride;', 'smmumap_env.serror_poll = q1n1_platform_serror_poll;', 'q1n1_smmumap_el2_ops(&smmumap_env);',
                   'return q1n1_smmumap_run(&smmumap_env, &smmumap_result);'):
        if needle not in block:
            problems.append(f'missing {needle}')
    run_start = text.find('static void sp11_payload_el2_run(void)')
    run = text[run_start:text.index('\n}\n', run_start)] if run_start >= 0 else ''
    order = [run.find(n) for n in ('smmumap_result.status = Q1N1_SMMUMAP_REFUSED;', 'q1n1_payload_run(&env, &payload_loaded, &platform, &result);',
                                   '#if Q1N1_SP11_SMMUMAP\n    q1n1_smmumap_after_chain(&smmumap_env, &smmumap_result);\n#endif')]
    if min(order) < 0 or order != sorted(order) or text.count('q1n1_smmumap_after_chain(') != 1 or text.count('smmumap_result.status =') != 1:
        problems.append('the status is not set to refused before the chain, or the line after the chain is not the one call after it, under the gate')
    on, off = split_gate(text)
    code = strip_comments(on)
    if len(re.findall(r'\blive_guarded\(', code)) != 2:
        problems.append('the gated code has other than the two guarded copies of the helpers')
    for banned in GATED_BANNED:
        if banned in code:
            problems.append(f'the gated code has {banned}')
    if code.count('q1n1_platform_serror_poll') != 1:
        problems.append('the poll is named other than once, in the one assignment')
    if 'smmumap' in strip_comments(off).lower():
        problems.append('the code with the gate at 0 names the step')
    return problems


EL2_BAD = [
    ('the-at-forms-are-swapped', [('if (write) __asm__ volatile("at s1e2w, %0"', 'if (write) __asm__ volatile("at s1e2r, %0"'),
                                  ('else __asm__ volatile("at s1e2r, %0"', 'else __asm__ volatile("at s1e2w, %0"')], 'allowed set|write form'),
    ('an-at-of-the-wrong-regime', [('at s1e2r, %0', 'at s1e1r, %0')], 'allowed set'),
    ('an-invalidation-of-everything', [('tlbi vale2is, %0', 'tlbi alle2is')], 'allowed set|TLBI operand'),
    ('an-invalidation-of-all-levels', [('tlbi vale2is, %0', 'tlbi vae2is, %0')], 'allowed set'),
    ('an-invalidation-of-one-cpu', [('tlbi vale2is, %0', 'tlbi vale2, %0')], 'allowed set'),
    ('an-operand-that-is-not-shifted', [('(va >> 12) & ((UINT64_C(1) << 44) - 1)', 'va & ((UINT64_C(1) << 44) - 1)')], 'TLBI operand'),
    ('a-clean-and-invalidate', [('dc cvac, %0', 'dc civac, %0')], 'allowed set'),
    ('a-barrier-of-another-scope', [('dsb ish', 'dsb sy')], 'allowed set'),
    ('no-isb-before-the-read-of-par', [(r'isb\n mrs %0, par_el1', 'mrs %0, par_el1')], 'allowed set'),
    ('a-read-of-the-wrong-ttbr', [('mrs %0, ttbr0_el2', 'mrs %0, ttbr0_el1')], 'allowed set'),
    ('an-msr', [('static void op_isb(void)\n{\n', 'static void op_isb(void)\n{\n    __asm__ volatile("msr daifclr, #4" : : : "memory");\n')], 'msr|allowed set|asm statements'),
    ('a-raw-store', [('static void op_dsb(void)\n{\n', 'static void op_dsb(void)\n{\n    *(volatile uint64_t *)0x15400000 = 0;\n')], 'raw access'),
]
MAIN_BAD = [
    ('the-store-is-two-32-bit-stores', [('live_guarded(1, pa, (uintptr_t)&value, 8)', 'live_guarded(0, pa, (uintptr_t)&value, 8)')], '8-byte copy'),
    ('the-store-is-four-bytes', [('live_guarded(1, pa, (uintptr_t)&value, 8)', 'live_guarded(1, pa, (uintptr_t)&value, 4)')], '8-byte copy'),
    ('the-store-is-sixteen-bytes', [('live_guarded(1, pa, (uintptr_t)&value, 8)', 'live_guarded(1, pa, (uintptr_t)&value, 16)')], '8-byte copy'),
    ('the-store-is-a-read', [('live_guarded(1, pa, (uintptr_t)&value, 8)', 'live_guarded(1, (uintptr_t)&value, pa, 8)')], '8-byte copy'),
    ('the-store-is-a-memset', [('live_guarded(1, pa, (uintptr_t)&value, 8)', 'live_guarded(2, pa, value, 8)')], '8-byte copy'),
    ('the-read-is-a-store', [('live_guarded(1, (uintptr_t)value, pa, 8)', 'live_guarded(1, pa, (uintptr_t)value, 8)')], 'read is not'),
    ('the-payloads-get-a-store-kind', [('return kind == Q1N1_PAYLOAD_G_COPY32 ? live_guarded(0, dst, src, size) : 1;', 'return live_guarded(kind, dst, src, size);')], 'store kind'),
    ('the-step-gets-no-counter', [('smmumap_env.counter = counter;', 'smmumap_env.counter = 0;')], 'missing'),
    ('the-step-gets-no-store', [('smmumap_env.store64 = smmumap_store64;', 'smmumap_env.store64 = 0;')], 'missing'),
    ('the-step-gets-no-map', [('smmumap_env.map = (const uint8_t *)(uintptr_t)info.memory_map;', 'smmumap_env.map = 0;')], 'missing'),
    ('the-step-gets-no-map-size', [('smmumap_env.map_size = info.memory_map_size;', 'smmumap_env.map_size = 0;')], 'missing'),
    ('the-step-gets-the-wrong-stride', [('smmumap_env.map_stride = info.memory_map_stride;', 'smmumap_env.map_stride = info.memory_map_size;')], 'missing'),
    ('the-step-gets-no-poll', [('smmumap_env.serror_poll = q1n1_platform_serror_poll;', 'smmumap_env.serror_poll = 0;')], 'missing'),
    ('the-status-is-not-refused-before-the-chain', [('smmumap_result.status = Q1N1_SMMUMAP_REFUSED;', 'smmumap_result.status = Q1N1_SMMUMAP_MAPPED;')], 'status is not set'),
    ('the-line-after-the-chain-is-not-called', [('    q1n1_smmumap_after_chain(&smmumap_env, &smmumap_result);\n', '')], 'status is not set'),
    ('the-line-after-the-chain-is-called-before-it', [('    q1n1_payload_run(&env, &payload_loaded, &platform, &result);\n#if Q1N1_SP11_SMMUMAP\n    q1n1_smmumap_after_chain(&smmumap_env, &smmumap_result);\n#endif',
                                                      '#if Q1N1_SP11_SMMUMAP\n    q1n1_smmumap_after_chain(&smmumap_env, &smmumap_result);\n#endif\n    q1n1_payload_run(&env, &payload_loaded, &platform, &result);')],
     'status is not set'),
    ('the-line-after-the-chain-is-not-under-the-gate', [('#if Q1N1_SP11_SMMUMAP\n    q1n1_smmumap_after_chain(&smmumap_env, &smmumap_result);\n#endif',
                                                       '    q1n1_smmumap_after_chain(&smmumap_env, &smmumap_result);')], 'status is not set|names the step'),
    ('the-poll-is-also-called-by-hand', [('    smmumap_env.emit = payload_emit;\n', '    smmumap_env.emit = payload_emit;\n    q1n1_platform_serror_poll(0, 0);\n')], 'the poll is named'),
    # the review's six ways of adding a store to the gated glue, which the shared pin of the glue (with the gate at 0) cannot see:
    ('a-second-guarded-copy-to-the-smmu-page', [('    smmumap_env.emit = payload_emit;\n', '    smmumap_env.emit = payload_emit;\n    live_guarded(1, 0x15400000, (uintptr_t)&smmumap_env, 8);\n')],
     'other than the two guarded copies'),
    ('a-guarded-fill-of-the-smmu-page', [('    smmumap_env.emit = payload_emit;\n', '    smmumap_env.emit = payload_emit;\n    live_guarded(2, 0x15400000, 0, 8);\n')], 'other than the two guarded copies'),
    ('a-raw-volatile-store-in-the-gated-code', [('    smmumap_env.emit = payload_emit;\n', '    smmumap_env.emit = payload_emit;\n    *(volatile uint64_t *)0x15400000 = 0;\n')], 'gated code has volatile'),
    ('a-memcpy64-in-the-gated-code', [('    smmumap_env.emit = payload_emit;\n', '    smmumap_env.emit = payload_emit;\n    q1n1_memcpy64((void *)0x15400000, &smmumap_env, 8);\n')],
     'gated code has memcpy64'),
    ('a-write32-in-the-gated-code', [('    smmumap_env.emit = payload_emit;\n', '    smmumap_env.emit = payload_emit;\n    live_write32(0x15400000, 0);\n')], 'gated code has write32'),
    ('a-memset32-in-the-gated-code', [('    smmumap_env.emit = payload_emit;\n', '    smmumap_env.emit = payload_emit;\n    memset32((void *)0x15400000, 0, 4);\n')], 'gated code has memset32'),
    ('a-set32-kind-in-the-gated-code', [('    smmumap_env.emit = payload_emit;\n', '    smmumap_env.emit = payload_emit;\n    live_guarded(G_SET32, 0x15400000, 0, 4);\n')], 'gated code has G_SET32|other than the two'),
    ('a-third-call-of-the-store-helper', [('    smmumap_env.emit = payload_emit;\n', '    smmumap_env.emit = payload_emit;\n    smmumap_store64(0x15400000, 0);\n')], 'used or defined more than once'),
    ('a-third-use-of-the-read-helper', [('    smmumap_env.emit = payload_emit;\n', '    smmumap_env.emit = payload_emit;\n    smmumap_read64(0x15400000, 0);\n')], 'used or defined more than once'),
    ('an-asm-store-in-the-gated-code', [('    smmumap_env.emit = payload_emit;\n', '    smmumap_env.emit = payload_emit;\n    __asm__ volatile("str xzr, [%0]" : : "r"(0x15400000) : "memory");\n')],
     'gated code has (volatile|__asm__)'),
]


def apply(text, edits):
    for old, new in edits:
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    return text


_EMIT = '    smmumap_env.emit = payload_emit;\n'


def _after_emit(code):
    return [(_EMIT, _EMIT + code)]


# Ways to add an access of memory to the gated glue that no name of GATED_BANNED lists (the review's nine, and more): only the digest sees them.
MAIN_DIGEST_BAD = [
    ('a-raw-store-without-volatile', _after_emit('    *(uint64_t *)0x15400000 = 0;\n')),
    ('a-memcpy32-in-the-gated-code', _after_emit('    q1n1_memcpy32((void *)0x15400000, &smmumap_env, 4);\n')),
    ('a-memset64-in-the-gated-code', _after_emit('    q1n1_memset64((void *)0x15400000, 0, 8);\n')),
    ('a-byte-copy-in-the-gated-code', _after_emit('    q1n1_copy_bytes((void *)0x15400000, &smmumap_env, 8);\n')),
    ('a-libc-memcpy-in-the-gated-code', _after_emit('    memcpy((void *)0x15400000, &smmumap_env, 8);\n')),
    ('an-array-store-in-the-gated-code', _after_emit('    ((uint64_t *)0x15400000)[0] = 0;\n')),
    ('a-store-through-the-env-in-the-gated-code', _after_emit('    smmumap_env.store64(0x15400000, 0);\n')),
    ('a-store-through-a-pointer-of-the-env', _after_emit('    *(uint64_t *)smmumap_env.map = 0;\n')),
    ('a-store-in-a-new-uncalled-function', [('static int smmumap_read64(uint64_t pa, uint64_t *value)\n{\n',
                                             'static void smmumap_poke(void)\n{\n    *(uint64_t *)0x15400000 = 0;\n}\nstatic int smmumap_read64(uint64_t pa, uint64_t *value)\n{\n')]),
    ('the-step-is-run-twice', [('    return q1n1_smmumap_run(&smmumap_env, &smmumap_result);', '    q1n1_smmumap_run(&smmumap_env, &smmumap_result);\n    return q1n1_smmumap_run(&smmumap_env, &smmumap_result);')]),
    ('the-status-line-moves-after-the-chain', [('#if Q1N1_SP11_SMMUMAP\n    smmumap_result.status = Q1N1_SMMUMAP_REFUSED;      /* zero is MAPPED: a step that never ran must not read as one */\n#endif\n'
                                               '    q1n1_payload_run(&env, &payload_loaded, &platform, &result);\n',
                                               '    q1n1_payload_run(&env, &payload_loaded, &platform, &result);\n#if Q1N1_SP11_SMMUMAP\n    smmumap_result.status = Q1N1_SMMUMAP_REFUSED;\n#endif\n')]),
    ('the-code-before-a-gated-block-changes', [('    payload_next_row = payload_page.row0;\n#if Q1N1_SP11_SMMUMAP\n', '    payload_next_row = payload_page.row0 + 1;\n#if Q1N1_SP11_SMMUMAP\n')]),
    ('a-store-between-two-character-constants', _after_emit("    int hidden = '/*'; *(volatile uint64_t *)0x15400000 = 0; int shown = '*/';\n")),
]
RUN_DIGEST_BAD = [
    ('a-raw-store-in-the-hash-refusal', [('    uint8_t now[32];\n    q1n1_sha256(', '    uint8_t now[32];\n    *(uint64_t *)0x15400000 = 0;\n    q1n1_sha256(')]),
    ('the-hook-is-called-twice', [('            smmumap_done = 1;\n', '            smmumap_done = 1;\n            env->smmumap();\n')]),
    ('the-hook-is-not-guarded-by-the-flag', [('        if (!smmumap_done && env->smmumap) {', '        if (env->smmumap) {')]),
    # the review's evasion of the regex that used to cut comments: a store between a '/*' in one literal and a '*/' in another
    ('a-store-between-two-literals', [('(size_t)file->bytes, now);\n    q1n1_payload_line_begin(&line, "PAYLOAD REFUSED=HASH_AT_EL2");',
                                       '(size_t)file->bytes, now);\n    q1n1_payload_line_begin(&line, "PAYLOAD /*"); *(volatile uint64_t *)0x15400000 = 0; '
                                       'q1n1_payload_line_raw(&line, "*/REFUSED=HASH_AT_EL2");')]),
]


class SmmumapSource(unittest.TestCase):
    el2 = (UEFI / 'sp11-smmumap-el2.c').read_text(encoding='utf-8')
    logic = (UEFI / 'sp11-smmumap.c').read_text(encoding='utf-8')
    header = (UEFI / 'sp11-smmumap.h').read_text(encoding='utf-8')
    main_c = (UEFI / 'main.c').read_text(encoding='utf-8')
    run_c = (UEFI / 'sp11-payload-run.c').read_text(encoding='utf-8')

    def test_the_el2_operations_are_the_audited_ones_and_a_seeded_bad_one_is_not(self):
        self.assertEqual(audit_el2(self.el2), [])
        for name, edits, wanted in EL2_BAD:
            with self.subTest(variant=name):
                problems = audit_el2(apply(self.el2, edits))
                self.assertTrue(problems, 'the audit passed a bad variant')
                self.assertRegex(' | '.join(problems), wanted)

    @unittest.skipUnless(have('clang') and have('llvm-objdump'), 'clang or llvm-objdump not installed')
    def test_the_el2_object_has_exactly_the_instructions_of_the_audit_and_no_system_register_write(self):
        obj = BUILD / 'el2.obj'
        obj.parent.mkdir(parents=True, exist_ok=True)
        done = run(['clang', '--target=aarch64-pc-windows-msvc', '-O2', '-ffreestanding', '-fno-builtin', '-fshort-wchar', '-mgeneral-regs-only', '-Wall', '-Wextra',
                    '-Werror', '-Iplatform/uefi'] + GATES + ['-c', str(UEFI / 'sp11-smmumap-el2.c'), '-o', str(obj)])
        self.assertEqual(done.returncode, 0, done.stderr)
        listing = run(['llvm-objdump', '-d', '--no-show-raw-insn', str(obj)]).stdout
        mnemonics = {m.group(1) for m in re.finditer(r'^\s+[0-9a-f]+:\s+(\w+)', listing, re.M)}
        self.assertEqual(mnemonics, {'add', 'adrp', 'at', 'b', 'cbz', 'dc', 'dsb', 'isb', 'mov', 'mrs', 'ret', 'stp', 'str', 'tlbi', 'ubfx'}, listing)
        self.assertEqual(len(re.findall(r'\btlbi\tvale2is, ', listing)), 1)
        self.assertEqual(sorted(re.findall(r'\bat\t(s1e2[rw]), ', listing)), ['s1e2r', 's1e2w'])
        self.assertEqual(len(re.findall(r'\bubfx\t\w+, \w+, #12, #44', listing)), 1)

    def test_main_c_makes_the_one_store_through_the_guarded_copy_and_a_seeded_bad_one_is_not(self):
        self.assertEqual(audit_main_store(self.main_c), [])
        for name, edits, wanted in MAIN_BAD:
            with self.subTest(variant=name):
                problems = audit_main_store(apply(self.main_c, edits))
                self.assertTrue(problems, 'the audit passed a bad variant')
                self.assertRegex(' | '.join(problems), wanted)

    def test_the_scanner_cuts_c_as_the_compiler_does(self):
        for text, want in (('a /* c */ b // d\ne', 'a   b  \ne'), ('f("/*"); g(); h("*/");', None), ('f("//"); g();', None), ("x = '/*'; y(); z = '*/';", None),
                           ('"a\\"/*" b /* c */', '"a\\"/*" b  '), ('x // c \\\n y\nz', 'x  \nz'), ('#include <a//b>\nx /* c */', '#include <a//b>\nx  '), ("#error don't /* c */\nq", None)):
            self.assertEqual(strip_comments(text), text if want is None else want, text)
        self.assertEqual(squeeze('a  /* c */\n\n  b("x  y")  ;'), 'a\nb("x  y") ;')
        self.assertEqual((squeeze('a  b'), squeeze('a/**/b')), ('a b', 'a b'))
        self.assertNotEqual(squeeze('a\nb'), squeeze('a b'))
        self.assertNotEqual(squeeze('a b'), squeeze('ab'))
        # The review's evasion hid the store from the regex, and the scanner keeps it in the hashed text.
        regex = lambda t: re.sub(r'//[^\n]*', '', re.sub(r'/\*.*?\*/', '', t, flags=re.S))
        evasion = apply(self.run_c, dict(RUN_DIGEST_BAD)['a-store-between-two-literals'])
        self.assertNotIn('0x15400000', split_gate(regex(evasion))[0])
        self.assertIn('0x15400000', split_gate(strip_comments(evasion))[0])

    def test_the_gated_glue_is_the_audited_text_and_every_edit_of_it_is_seen(self):
        have = gated_glue_digest(self.main_c, self.run_c)
        self.assertEqual(have, GATED_GLUE_SHA256, GLUE_MESSAGE.format(have=have, want=GATED_GLUE_SHA256))
        # Dropping the comments must not drop a directive: every gated block is still there.
        gate = re.compile(r'^[ \t]*#[ \t]*if[ \t]+Q1N1_SP11_SMMUMAP\b', re.M)
        for text in (self.main_c, self.run_c):
            self.assertEqual(len(gate.findall(text)), len(gate.findall(strip_comments(text))))
        # A comment or a change of blanks is no edit; an edit of the gated code otherwise, or of the code a gated block follows, is.
        quiet = apply(self.main_c, [('static int smmumap_read64(uint64_t pa, uint64_t *value)\n{\n', '/* a comment */\nstatic int smmumap_read64(uint64_t pa,   uint64_t *value)\n{\n')])
        self.assertEqual(gated_glue_digest(quiet, self.run_c), have)
        for name, edits in MAIN_DIGEST_BAD:
            with self.subTest(variant=name):
                self.assertNotEqual(gated_glue_digest(apply(self.main_c, edits), self.run_c), have)
        for name, edits in RUN_DIGEST_BAD:
            with self.subTest(variant=name):
                self.assertNotEqual(gated_glue_digest(self.main_c, apply(self.run_c, edits)), have)
        # The deny-list's own variants that edit gated text are seen by the digest as well: only the one that edits ungated text is not.
        for name, edits, _ in MAIN_BAD:
            with self.subTest(variant=name):
                if name != 'the-payloads-get-a-store-kind':
                    self.assertNotEqual(gated_glue_digest(apply(self.main_c, edits), self.run_c), have)

    def test_the_logic_stores_only_the_descriptor_and_its_put_back_and_reads_only_through_the_one_proven_load(self):
        code = strip_comments(self.logic)
        self.assertEqual(sorted(re.findall(r'env->store64\(([^()]*)\)', code)), ['slot, 0', 'slot, desc'])
        # Every load of firmware RAM is made by one call in load_ram, after the page was proven RAM: its four callers are the walk, the scan (twice) and the re-read.
        self.assertEqual(re.findall(r'env->read64\(([^()]*)\)', code), ['at, value'])
        self.assertEqual(sorted(re.findall(r'\bload_ram\(env, ([^()]*)\)', code)), ['at, &desc, &w->proof', 'at, &value, &s->bad', 'at, &value, &s->bad', 'slot, &again, &reread'])
        body = code[code.index('static int load_ram('):code.index('enum { WALK_PAGE')]
        self.assertEqual(len(re.findall(r'\bq1n1_smmumap_map_type\(env->map, env->map_size, env->map_stride, page, PAGE_BYTES, &p->attr\)', code)), 1)
        self.assertLess(body.index('q1n1_smmumap_map_type('), body.index('if (!p->ok) return LOAD_NOT_RAM;'))
        self.assertLess(body.index('if (!p->ok) return LOAD_NOT_RAM;'), body.index('env->read64('))
        for banned in ('volatile', '__asm__', 'asm(', 'msr', 'memcpy', 'memset', '*(uint64_t'):
            self.assertNotIn(banned, code)
        self.assertEqual(len(re.findall(r'\benv->(\w+)\(', code)), len(re.findall(r'\benv->(?:emit|regs|read64|store64|at|clean|dsb|tlbi|isb|counter|serror_poll|serror_pending)\(', code)))
        self.assertEqual(len(re.findall(r'env->store64\(', code)), 2)
        self.assertEqual(len(re.findall(r'env->serror_poll\(', code)), 1)
        # Everything the step reads of the memory map it reads byte by byte through the pointer it was given, in one function.
        self.assertEqual(len(re.findall(r'\bmap \+ i \* stride\b', code)), 1)

    def test_the_hook_in_the_runner_is_one_call_after_the_first_payloads_check_and_before_its_call(self):
        code = self.run_c
        verify_loop = 'if (!q1n1_payload_verify_in_place(loaded, index)) {'
        hook = 'if (!smmumap_done && env->smmumap) {'
        self.assertEqual(code.count('env->smmumap'), 2)
        self.assertEqual(code.count('env->smmumap()'), 1)
        self.assertEqual(code.count(verify_loop), 1)
        # The order in the loop: the payload's own hash check and its line, then the others' checks, then the hook, then the payload is made executable and called.
        positions = [code.index(p) for p in (verify_loop, 'q1n1_payload_line_begin(&line, "PAYLOAD VERIFY=OK");', hook, 'refuse_hash(env, loaded, other, result);',
                                             'if (env->smmumap() == Q1N1_SMMUMAP_UNSAFE) {', 'env->sync_code(file->base, file->alloc);', 'env->call(file->base, &args')]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(code.index('Q1N1_PAYLOAD_RUN_NO_PAYLOAD;'), positions[0])
        self.assertIn('emit_chain_stopped(env, index, "SMMUMAP");', code)
        self.assertIn('for (uint32_t other = index + 1; other < loaded->count && other < Q1N1_PAYLOAD_MAX_FILES; other++) {', code)
        self.assertIn('if (q1n1_payload_file_is_code(&loaded->file[other]) && !q1n1_payload_verify_in_place(loaded, other)) {', code)
        self.assertEqual(code.count('smmumap_done = 1;'), 1)
        self.assertEqual(len(re.findall(r'#if Q1N1_SP11_SMMUMAP\n(.*?)#endif', code, re.S)), 4, 'the include, the refusal helper, the flag and the hook are the only gated code')
        self.assertNotIn('smmumap', strip_comments(split_gate(code)[1]).lower())

    def test_the_new_files_follow_the_repository_rules(self):
        # Built from pieces so that this file does not contain what it looks for.
        pattern = re.compile('|'.join(['/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/', '/t' + 'mp/']) + r'|\.loc' + r'al\b|\bsae' + r'ed\b|host' + r'name|' +
                             r'\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', re.I)
        for path in OWN_FILES:
            text = path.read_text(encoding='utf-8')
            with self.subTest(file=path.name):
                self.assertIn('SPDX-License-Identifier: MIT', text[:200])
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                self.assertTrue(all(ord(c) < 128 for c in text), 'a character outside ASCII')
                for number, line in enumerate(text.splitlines(), 1):
                    self.assertIsNone(pattern.search(line), f'line {number}: {line}')

    def test_the_shared_pin_of_the_glue_sees_the_gate_off_code_and_still_fails_on_an_extra_store(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('smmumap_shared', TOOLS / 'test-q1n1-sp11-payload.py')
        shared = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(shared)
        self.assertEqual(shared.with_gate_at_zero('#if Q1N1_SP11_SMMUMAP\nA\n#else\nB\n#endif\nC\n#if Q1N1_SP11_SMMUMAP\nD\n#if X\nE\n#endif\n#endif\nF\n'), 'B\nC\nF\n')
        self.assertEqual(shared.with_gate_at_zero('#if OTHER\nA\n#endif\n'), '#if OTHER\nA\n#endif\n')
        first, last = '/* ---- Stick payload runner (sp11-payload.h): the platform side', '#endif /* Q1N1_SP11_PAYLOAD */'
        glue = shared.with_gate_at_zero(self.main_c[self.main_c.index(first):self.main_c.index(last)])
        self.assertEqual(len(re.findall(r'live_guarded\(', glue)), 1)
        self.assertNotIn('smmumap_store64', glue)
        extra = self.main_c.replace('static void payload_emit(const char *line)\n{\n', 'static void payload_emit(const char *line)\n{\n    live_guarded(1, 0, 0, 8);\n', 1)
        self.assertEqual(len(re.findall(r'live_guarded\(', shared.with_gate_at_zero(extra[extra.index(first):extra.index(last)]))), 2)

    def test_the_constants_name_their_evidence(self):
        for needle in ('hamoa.dtsi', 'pcie_smmu: iommu@15400000', 'MCFG', 'MAP RP=DEVICE.OS.NS1', 'MAP SMMU=FAULT=0X7:TRANS_L3', 'TTBR0_EL2 0xA7F2E000', 'EXPERIMENTAL'):
            self.assertIn(needle, self.header, needle)
        found = dict(re.findall(r'#define Q1N1_SMMUMAP_(\w+) UINT64_C\((0x[0-9A-Fa-f]+)\)', self.header))
        self.assertEqual({k: found[k] for k in ('PAGE_PA', 'TEMPLATE_PA', 'TTBR0_EL2')}, {'PAGE_PA': '0x15400000', 'TEMPLATE_PA': '0x70000000', 'TTBR0_EL2': '0xA7F2E000'})

    def test_every_reason_has_a_name_a_line_and_a_row_of_the_enum(self):
        enum = re.findall(r'Q1N1_SMMUMAP_R_(\w+)(?: = 0)?,', self.header)
        names = re.findall(r'case Q1N1_SMMUMAP_R_(\w+): return "(\w+)";', self.logic)
        self.assertEqual([n for n in enum if n != 'COUNT'], [n for n, _ in names])
        self.assertTrue(all(a == b for a, b in names))


# ---- the gate at zero changes nothing ---------------------------------------------------------------------------------------------------------

class SmmumapGateOff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def preprocess(self, tree, name, *defines):
        done = run(['clang', '-E', '-P', '-Iplatform/uefi'] + list(defines) + [f'platform/uefi/{name}'], cwd=tree)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def test_the_new_files_are_empty_with_the_gate_off(self):
        self.assertTrue(have('llvm-nm'), 'llvm-nm not installed')
        flags = ['--target=aarch64-pc-windows-msvc', '-O2', '-ffreestanding', '-fno-builtin', '-fshort-wchar', '-mgeneral-regs-only', '-Wall', '-Wextra', '-Werror',
                 '-Iplatform/uefi']
        for name in ('sp11-smmumap.c', 'sp11-smmumap-el2.c'):
            for defines in ([], ['-DSNAP_PLATFORM_SP11=1'], ['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1'],
                            ['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1', '-DQ1N1_SP11_SMMUMAP=0']):
                with self.subTest(file=name, defines=defines):
                    obj = BUILD / f'{name}.gate-off.obj'
                    done = run(['clang'] + flags + defines + ['-c', str(UEFI / name), '-o', str(obj)])
                    self.assertEqual(done.returncode, 0, done.stderr)
                    left = [line for line in run(['llvm-nm', str(obj)]).stdout.splitlines() if line.strip() and '@feat.00' not in line]
                    self.assertEqual(left, [])

    def test_the_gate_without_the_runner_is_an_error(self):
        # main.c keeps all of its gated code under the runner's own gate, so it ignores this one without it: the Makefile refuses that case below.
        for name in ('sp11-smmumap.c', 'sp11-smmumap-el2.c', 'sp11-payload-run.c'):
            with self.subTest(file=name):
                done = run(['clang', '-E', '-P', '-Iplatform/uefi', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_SMMUMAP=1', str(UEFI / name)])
                self.assertNotEqual(done.returncode, 0)
                self.assertIn('needs Q1N1_SP11_PAYLOAD=1', done.stderr)

    def test_the_runners_files_preprocess_as_at_the_base_commit_with_the_gate_off(self):
        base = base_tree()
        if base is None:
            self.skipTest(f'git cannot name {BASE_COMMIT}')
        for name in ('main.c', 'sp11-payload-run.c', 'sp11-payload-text.c', 'sp11-payload-plan.c', 'sp11-payload-load.c'):
            for defines in (['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1'], ['-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1', '-DQ1N1_SP11_SMMUMAP=0'],
                            ['-DSNAP_PLATFORM_SP11=1'], []):
                with self.subTest(file=name, defines=defines):
                    self.assertEqual(self.preprocess(ROOT, name, *defines), self.preprocess(base, name, *[d for d in defines if 'SMMUMAP' not in d]))

    def test_only_the_gates_files_differ_from_the_base_commit_in_platform_and_payloads(self):
        if run(['git', 'cat-file', '-e', f'{BASE_COMMIT}^{{commit}}']).returncode != 0:
            self.skipTest(f'git cannot name {BASE_COMMIT}')
        changed = set(run(['git', 'diff', '--name-only', BASE_COMMIT, '--', 'platform', 'payloads']).stdout.split())
        changed |= set(run(['git', 'ls-files', '--others', '--exclude-standard', '--', 'platform', 'payloads']).stdout.split())
        self.assertEqual(changed, {'platform/uefi/Makefile', 'platform/uefi/main.c', 'platform/uefi/sp11-payload-run.c', 'platform/uefi/sp11-payload.h',
                                   'platform/uefi/sp11-smmumap.c', 'platform/uefi/sp11-smmumap.h', 'platform/uefi/sp11-smmumap-el2.c',
                                   'platform/uefi/sp11-payload-load.c', 'platform/uefi/sp11-payload-plan.c'})   # the last two: BIGFILE

    def make_lines(self, tree, *args):
        done = run(['make', '-n', '-f', 'platform/uefi/Makefile', 'OUT=build/dryrun'] + FIXTURES + ['SP11_BUILD_STAMP=PROOF'] + list(args), cwd=tree)
        self.assertEqual(done.returncode, 0, done.stderr)
        return [' '.join(line.split()) for line in done.stdout.replace('\\\n', ' ').splitlines()]

    def test_the_makefiles_command_lines_are_the_base_commits_with_the_gate_off(self):
        base = base_tree()
        if base is None:
            self.skipTest(f'git cannot name {BASE_COMMIT}')
        for args in (['SP11=1', 'all'], ['SP11=1', 'PAYLOAD=1', 'payload-runner'], ['SP11=1', 'PAYLOAD=1', 'SMMUMAP=0', 'payload-runner'], ['SP11=1', 'PAYLOAD=1', 'all']):
            with self.subTest(args=args):
                mine = self.make_lines(ROOT, *args)
                theirs = self.make_lines(base, *[a for a in args if a != 'SMMUMAP=0'])
                self.assertGreater(len(mine), 10)
                self.assertEqual(mine, theirs)
                self.assertNotIn('smmumap', ' '.join(mine).lower())

    def test_the_makefile_refuses_the_gate_without_the_runner(self):
        done = run(['make', '-n', '-f', 'platform/uefi/Makefile', 'OUT=build/dryrun'] + FIXTURES + ['SP11=1', 'SMMUMAP=1', 'all'])
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('SMMUMAP=1 needs PAYLOAD=1', done.stdout + done.stderr)

    def test_with_the_gate_on_its_define_is_on_exactly_the_runners_compile_lines(self):
        lines = self.make_lines(ROOT, 'SP11=1', 'PAYLOAD=1', 'SMMUMAP=1', 'payload-runner')
        compiles = [line for line in lines if ' -c ' in line]
        with_define = {re.search(r'-o (\S+)$', line).group(1) for line in compiles if '-DQ1N1_SP11_SMMUMAP=1' in line}
        self.assertEqual({Path(p).name for p in with_define},
                         {'main-payload.obj', 'sp11-payload-text.obj', 'sp11-payload-plan.obj', 'sp11-payload-load.obj', 'sp11-payload-run.obj', 'sp11-payload-call.obj',
                          'sp11-smmumap.obj', 'sp11-smmumap-el2.obj'})
        link = [line for line in lines if 'lld-link' in line or '/subsystem:efi_application' in line]
        self.assertEqual(len(link), 1)
        self.assertIn('sp11-smmumap.obj', link[0])
        self.assertIn('sp11-smmumap-el2.obj', link[0])
        self.assertTrue(all('SMMUMAP' not in line for line in compiles if 'main-payload.obj' not in line and 'sp11-' not in line))


class SmmumapBuild(unittest.TestCase):
    """The runner as an image: built from the base commit and from this tree with the gate off (one byte string), and with the gate on."""
    @classmethod
    def setUpClass(cls):
        if not (have('clang') and have('lld-link')):
            raise unittest.SkipTest('clang or lld-link not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def image(self, tree, out, *extra):
        shutil.rmtree(tree / out, ignore_errors=True)
        done = run(['make', '-f', 'platform/uefi/Makefile', f'OUT={out}'] + RECIPE[:3] + list(extra) + RECIPE[3:] + ['payload-runner'], cwd=tree)
        self.assertEqual(done.returncode, 0, done.stdout[-1500:] + done.stderr[-1500:])
        return (tree / out / 'q1n1-payload.efi').read_bytes()

    def test_the_runner_with_the_gate_off_is_the_base_commits_runner_and_with_it_on_builds_to_one_image(self):
        base = base_tree()
        if base is None:
            self.skipTest(f'git cannot name {BASE_COMMIT}')
        pinned = self.image(base, 'build/pinned')
        pinned_b = self.image(base, 'build/pinned-b')
        self.assertEqual(pinned, pinned_b, 'the base commit\'s runner is not reproducible')
        off = self.image(ROOT, 'build/smmumap-test/off')
        off_b = self.image(ROOT, 'build/smmumap-test/off-b')
        self.assertEqual(off, off_b, 'the runner with the gate at zero is not reproducible')
        self.assertEqual(hashlib.sha256(off).hexdigest(), hashlib.sha256(pinned).hexdigest(), 'the gate at zero changed the runner')
        on_a = self.image(ROOT, 'build/smmumap-test/on-a', 'SMMUMAP=1')
        on_b = self.image(ROOT, 'build/smmumap-test/on-b', 'SMMUMAP=1')
        self.assertEqual(on_a, on_b, 'the runner with the gate on is not reproducible')
        self.assertNotEqual(on_a, off)
        for text in (b'PAYLOAD SMMUMAP', b'REFUSED=', b'NEXT STORE AFTER', b'TABLE_SHARED', b'CHECK_FAILED', b'ROLLBACK_FAILED', b'TABLE_NOT_RAM', b'SCAN_FAULT', b'SERROR=FOUND',
                     b'SERROR=NONE', b'REFS='):
            self.assertIn(text, on_a)
        self.assertNotIn(b'PAYLOAD SMMUMAP', off)
        self.assertNotIn(b'TABLE_SHARED', off)
        self.assertNotIn(b'SERROR=', off)
        # The digest table of the document is these two images.
        doc = (ROOT / 'docs' / 'SP11-PAYLOAD-SMMUMAP.md').read_text(encoding='utf-8')
        rows = re.findall(r'\| ([\d,]+) B \| `([0-9a-f]{64})` \|', doc[doc.index('<!-- smmumap-digests -->'):doc.index('<!-- /smmumap-digests -->')])
        self.assertEqual([(int(size.replace(',', '')), digest) for size, digest in rows],
                         [(len(off), hashlib.sha256(off).hexdigest()), (len(on_a), hashlib.sha256(on_a).hexdigest())], 'the digest table is not these images')


class SmmumapMutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_there_are_enough_distinct_mutants_over_the_three_files_and_the_three_programs(self):
        names = [m[0] for m in mut.MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertGreaterEqual(len(names), 130)
        self.assertEqual({m[1] for m in mut.MUTANTS}, {mut.LOGIC, mut.HEADER, mut.RUNNER})
        self.assertEqual({m[5] for m in mut.MUTANTS}, set(PROGRAMS))
        # The hook's seeded bugs are in the runner and are run against the hook's program; the walk's are in the logic.
        self.assertTrue(all((m[1] == mut.RUNNER) == (m[5] == 'hook') for m in mut.MUTANTS))

    def test_every_needle_occurs_exactly_once_and_changes_something_and_has_a_reason(self):
        self.assertEqual([bad for m in mut.MUTANTS for bad in mut.stale(m, ROOT)], [])
        for name, _, edits, reason, flags, program in mut.MUTANTS:
            self.assertTrue(all(old != new for old, new in edits), f'{name} changes nothing')
            re.compile(reason)
            self.assertTrue(set(flags) <= set(mut.SPIN), name)
            self.assertIn(program, PROGRAMS)

    def test_the_unmutated_copy_passes_in_all_three_programs(self):
        directory = BUILD / 'control'
        shutil.rmtree(directory, ignore_errors=True)
        shutil.copytree(UEFI, directory / 'uefi', ignore=shutil.ignore_patterns('*.obj', '*.o', '*.d'))
        for program in PROGRAMS:
            with self.subTest(program=program):
                done = compile_native(directory / 'uefi', (), directory / f'test-{program}', program=program)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(run([str(directory / f'test-{program}')] + (['all'] if program == 'main' else [])).returncode, 0)
        shutil.rmtree(directory, ignore_errors=True)

    def test_every_seeded_bug_is_caught_for_its_own_reason(self):
        work = BUILD / 'mutants'
        for m in mut.MUTANTS:
            status, detail = mut.evaluate(m, work, ROOT, lambda uefi, flags, binary, program: compile_native(uefi, flags, binary, program=program, extra=RELAX))
            with self.subTest(mutant=m[0]):
                self.assertEqual(status, 'caught', detail)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
