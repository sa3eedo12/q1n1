#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The el1trap payload of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-EL1TRAP.md): its host test, its seeded bugs, the
allow-list of its binary, the audit of its EL1 stub and vector tables, and its stick. The QEMU run is
tools/test-q1n1-sp11-payload-qemu-el1trap.py, the document's test tools/test-q1n1-sp11-payload-el1trap-doc.py.

    python3 tools/test-q1n1-sp11-payload-el1trap.py          # the suites
    python3 tools/test-q1n1-sp11-payload-el1trap.py facts    # size, digest and instruction inventory of the built binary

  * El1trapNative: tools/test-q1n1-sp11-payload-el1trap.c (nine suites over a modelled machine, a predictor and a checker of the order
    and the page, 6000 random worlds), built and run by the machinery of tools/test-q1n1-sp11-payload.py under ASan and UBSan.
  * El1trapSource: what no run shows -- the ops the source calls, the registers and MSRs it names, the constants the document gives,
    the monitor's own formula (when SNAPINTOSH_DIR names the tree), that ECV is never set, no writable global.
  * El1trapMutants: seeded bugs in el1trap.c, each applied to a copy of the sources and each of which the host program must reject.
  * El1trapBinary: the allow-list applied to el1trap.bin with seeded bad binaries and a flat binary patched so that only the encoding
    layer can see it; the encodings this payload added to the engine; the inventory of the code; the EL1 stub and both vector tables.
  * El1trapStick: the manifest tool and the runner's own validator on a stick that holds el1trap.bin alone, and after `psci`.

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
import concurrent.futures
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_ecv_lib as ecv  # noqa: E402
from sp11_payload_el1trap_mutants import ASM_MUTANTS, FILE, MUTANTS  # noqa: E402  (the seeded bugs, kept in a file of their own)

native = ecv.load_module('sp11_payload_native_for_el1trap', ROOT / 'tools' / 'test-q1n1-sp11-payload.py')
native.BUILD = ROOT / 'build' / 'sp11-payload-el1trap-test'
# The shared machinery knows the older payloads; this payload joins it here, in this copy of the module only.
native.PROGRAMS['el1trap'] = ('tools/test-q1n1-sp11-payload-el1trap.c', ['sp11-payload-text.c'], 9, 100000, 'el1trap')
native.HOST_PAYLOADS['el1trap'] = 'el1trap.c'
native.PAYLOADS_COPIED = native.PAYLOADS_COPIED + ['el1trap.c']
BUILD = native.BUILD
SOURCE = ROOT / 'payloads' / 'el1trap.c'
READELF, run, have = ecv.READELF, lib.run, lib.have
code_of, Builder, asm, read, facts, need_tools = ecv.code_of, ecv.Builder, ecv.asm, ecv.read, ecv.facts, ecv.need_tools
SUITES = ('order', 'accesses', 'ends', 'probe', 'held', 'refuse', 'clock', 'fuzz', 'args')
OWN_FILES = [SOURCE] + [ROOT / 'tools' / name for name in (
    'test-q1n1-sp11-payload-el1trap.c', 'test-q1n1-sp11-payload-el1trap-tail.h', 'test-q1n1-sp11-payload-el1trap.py',
    'test-q1n1-sp11-payload-qemu-el1trap.py', 'test-q1n1-sp11-payload-el1trap-doc.py', 'sp11_payload_ecv_lib.py',
    'sp11_payload_el1trap_mutants.py')]
LINES_MAX = 37
POLICY = lib.POLICIES['el1trap']
OTHERS = ('state', 'psci', 'timer', 'usbsmmu', 'cpuon', 'cnthctl')


class El1trapNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_the_el1trap_suites_pass(self):
        native.Native._check(self, 'el1trap')

    def test_each_suite_runs_alone(self):
        done, binary = native.build_program('el1trap', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite in SUITES:
            with self.subTest(suite=suite):
                code, output = native.run_program(binary, suite)
                self.assertEqual(code, 0, output)
                self.assertRegex(output, r'PASS: 1 payload el1trap suites, \d+ checks')

    def test_the_most_lines_are_measured(self):
        done, binary = native.build_program('el1trap', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary, 'lines-report')
        self.assertEqual(code, 0, output)
        self.assertEqual(output.strip(), f'LINES_MAX={LINES_MAX}')


class El1trapSource(unittest.TestCase):
    code = code_of(SOURCE)

    def test_the_source_calls_only_the_counter_op_and_the_helpers_hex_and_puts(self):
        self.assertEqual(set(re.findall(r'ops\.(\w+)', self.code)), {'counter'}, 'never load32')
        self.assertEqual(set(re.findall(r'ops\.(\w+)', code_of(ROOT / 'payloads' / 'payload-util.h'))), {'hex', 'puts'})

    def test_the_registers_the_source_and_its_assembly_read_are_the_ones_the_policy_lists(self):
        named = {name.lower() for name in re.findall(r'SYSREG\((\w+)\)', self.code)} - {'name'}
        named |= {name.lower() for name in re.findall(r'mrs x\d+, (\w+)', self.code)}
        self.assertEqual(named, POLICY['registers'])

    def test_the_msrs_the_source_and_its_assembly_have_are_the_ones_the_policy_allows(self):
        named = set(re.findall(r'msr (\w+), (?:%0|x\d+)', self.code))
        self.assertEqual(named, POLICY['allow']['msr'])
        self.assertEqual(sorted(re.findall(r'(?<![\w])(hvc) #(\w+)', self.code)), [('hvc', '0'), ('hvc', '1'), ('hvc', '2')])
        for mnemonic in ('smc', 'svc', 'wfi', 'wfe', 'sev', 'dmb', 'tlbi', ' at ', 'ldxr', 'stxr', 'cas ', 'swp'):
            self.assertNotIn(f'"{mnemonic}', self.code)
            self.assertNotIn(f'    {mnemonic}', self.code.replace('\n', '\n ').replace('__asm__', ''))

    def test_the_registers_that_must_not_be_touched_are_not_named_in_code(self):
        for forbidden in ('CNTPOFF', 'S3_4_C14_C0_6', 'CNTVOFF', 'S3_4_C14_C0_3', 'CNTKCTL', 'CNTV_CVAL', 'CNTV_TVAL', 'CNTP_CTL', 'CNTP_CVAL',
                          'CNTP_TVAL', 'CNTHP', 'CNTHV', 'CNTPS', 'SP_EL1', 'SP_EL0', 'TCR_', 'TTBR', 'MAIR', 'CPTR', 'MDCR', 'SCR_EL3'):
            with self.subTest(register=forbidden):
                self.assertNotIn(forbidden, self.code.upper())

    def test_the_values_written_are_the_documents(self):
        for define, value in (('HCR_EXCURSION', '(UINT64_C(1) << 31)'), ('SCTLR_EL1_EXCURSION', 'UINT64_C(0x30500800)'),
                              ('EL1_PHYSICAL_BITS', 'UINT64_C(3)'), ('EL1TVT_BIT', '(UINT64_C(1) << 13)'), ('EL1TVCT_BIT', '(UINT64_C(1) << 14)'),
                              ('ECV_BIT', '(UINT64_C(1) << 12)'), ('WAIT_BEFORE_EXCURSION_S', '8u'), ('DEADLINE_S', '1u'), ('TRAPS_MAX', '8'),
                              ('ENTRIES_BUDGET', '8'), ('ENTRIES_FATAL', '24'), ('STACK_KEPT_BYTES', '(16u * 1024u)'), ('CACHE_STEP', '16u'),
                              ('COUNTER_STUCK_READS', '2000000u'), ('DAIF_MASKED', 'UINT64_C(0x3c0)'), ('SPSR_EL2H_MASKED', '0x3c9'),
                              ('SPSR_KEPT_LOW', '0x1000'), ('SPSR_KEPT_HIGH', '0x3c0'), ('E_CALLER_SPSR', '296')):
            self.assertRegex(self.code, rf'#define {define}\s+{re.escape(value)}')
        self.assertIn('r.wanted[R_CNTHCTL] = (cnthctl & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;', self.code)
        self.assertIn('mov x2, #0x3c5', self.code)
        self.assertIn('mov x14, #" STR(SPSR_EL2H_MASKED)', self.code)
        self.assertNotIn('mov x13, #0x3c9', self.code, 'the end of an excursion no longer returns a constant')
        self.assertEqual(len(re.findall(r'\bECV_BIT\b', self.code)), 3, 'defined, in OLD_REFUSED_BITS, and in the check of the read-back')
        self.assertIn('#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT)', self.code)

    def test_sctlr_el1_is_linuxs_init_value_with_the_mmu_off(self):
        bits = (29, 28, 22, 20, 11)      # LSMAOE, nTLSMD, EIS, TSCXT, EOS: INIT_SCTLR_EL1_MMU_OFF in Linux 7475ea8b5861 (facts only)
        self.assertEqual(sum(1 << b for b in bits), 0x30500800)
        tree = os.environ.get('LINUX_DIR')
        path = Path(tree) / 'arch' / 'arm64' / 'include' / 'asm' / 'sysreg.h' if tree else None
        if not path or not path.is_file():
            self.skipTest('LINUX_DIR does not name a Linux tree: INIT_SCTLR_EL1_MMU_OFF is not compared')
        text = path.read_text(encoding='utf-8', errors='replace')
        found = re.search(r'#define INIT_SCTLR_EL1_MMU_OFF\s*\\?\s*(.*?)\n\n', text, re.S)
        self.assertTrue(found)
        for name in ('LSMAOE', 'nTLSMD', 'EIS', 'TSCXT', 'EOS'):
            self.assertIn(name, found.group(1))

    def test_the_formula_is_the_one_in_the_monitors_source(self):
        tree = os.environ.get('SNAPINTOSH_DIR')
        path = Path(tree) / 'probes' / 'xnuboot' / 'prepare.c' if tree else None
        if not path or not path.is_file():
            self.skipTest('SNAPINTOSH_DIR does not name a Snapintosh tree: the monitor source is not compared')
        self.assertIn('guest_cnthctl = (vcpu_of(c)->save_cnthctl & ~3UL) | (1UL<<14) | (1UL<<13);', path.read_text(encoding='utf-8'))

    def test_no_writable_global_and_every_table_is_constant(self):
        for declaration in re.findall(r'^static\b[^\n(]*;', self.code, re.M):
            self.assertRegex(declaration, r'\bconst\b|\binline\b', declaration)
        self.assertEqual(re.findall(r'^static (?!const|inline|__attribute__)[^\n(]*$', self.code, re.M), [])
        self.assertNotIn('.data', self.code)
        self.assertNotIn('.bss', self.code)

    def test_the_files_are_within_the_size_limits(self):
        for path in OWN_FILES:
            if not path.exists():
                continue
            with self.subTest(file=path.name):
                text = path.read_text(encoding='utf-8')
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                self.assertIn('SPDX-License-Identifier: MIT', text[:200])


class El1trapMutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    _build = staticmethod(native.Mutants._build)

    def _evaluate(self, *mutant):
        return native.Mutants._evaluate(self, *mutant)

    def test_there_are_enough_distinct_mutants_and_they_all_target_the_payload(self):
        names = [m[0] for m in MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertFalse({m[0] for m in native.MUTANTS} & set(names), 'a name the native suite already uses')
        self.assertGreaterEqual(len(names), 100)
        self.assertEqual({m[1] for m in MUTANTS}, {FILE})
        for wanted in ('hcr-also-sets-tge', 'sctlr-sets-the-mmu', 'cnthctl-sets-ecv-as-well', 'hcr-is-written-first', 'never-puts-vbar-el1-back',
                       'never-retries', 'runs-without-checking-the-writes', 'hcr-check-misses-e2h', 'sctlr-check-misses-wxn', 'never-probes',
                       'ignores-a-failed-probe', 'does-not-wait', 'does-not-clean-the-image', 'does-not-invalidate-the-instruction-cache',
                       'runs-at-any-el', 'does-not-refuse-e2h', 'does-not-refuse-an-old-with-bits-set', 'does-not-check-the-stack',
                       'verdict-ignores-the-control', 'does-not-check-the-iss', 'returns-0-when-it-could-not-restore', 'reads-cntpoff-el2'):
            self.assertIn(f'el1trap-{wanted}', names)

    def test_the_unmutated_control_passes_from_a_copy(self):
        directory = BUILD / 'control'
        native.copy_tree(directory)
        done, binary = self._build('el1trap', directory, relaxed=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary)
        self.assertEqual(code, 0, output[-600:])

    def test_every_seeded_bug_is_caught(self):
        workers = max(1, min(4, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {m[0]: pool.submit(self._evaluate, *m) for m in MUTANTS}
            results = {name: future.result() for name, future in futures.items()}
        for name, (status, detail) in results.items():
            with self.subTest(mutant=name):
                self.assertEqual(status, 'caught', f'{status}: {detail}')


# ---- the binary ------------------------------------------------------------------------------------------------------------

BAD_BINARIES = [
    # (name, [(needle, replacement)], what the allow-list check must say)
    ('a-read-of-cntpoff-el2', read('S3_4_C14_C0_6'), 'the code names'),
    ('a-write-to-cntpoff-el2', asm('msr S3_4_C14_C0_6, xzr'), 'the code names'),
    ('a-read-of-cntvoff-el2', read('S3_4_C14_C0_3'), 'the code names'),
    ('a-write-to-cntvoff-el2', asm('msr cntvoff_el2, xzr'), 'forbidden instruction msr cntvoff_el2'),
    ('a-write-to-cntkctl-el1', asm('msr cntkctl_el1, xzr'), 'forbidden instruction msr cntkctl_el1'),
    ('a-write-to-cntv-ctl-el0', asm('msr cntv_ctl_el0, xzr'), 'forbidden instruction msr cntv_ctl_el0'),
    ('a-write-to-cnthp-ctl-el2', asm('msr cnthp_ctl_el2, xzr'), 'forbidden instruction msr cnthp_ctl_el2'),
    ('a-write-to-sctlr-el2', asm('msr sctlr_el2, xzr'), 'forbidden instruction msr sctlr_el2'),
    ('a-write-to-tcr-el2', asm('msr tcr_el2, xzr'), 'forbidden instruction msr tcr_el2'),
    ('a-write-to-ttbr0-el2', asm('msr ttbr0_el2, xzr'), 'forbidden instruction msr ttbr0_el2'),
    ('a-write-to-vttbr-el2', asm('msr vttbr_el2, xzr'), 'forbidden instruction msr vttbr_el2'),
    ('a-write-to-vtcr-el2', asm('msr vtcr_el2, xzr'), 'forbidden instruction msr vtcr_el2'),
    ('a-write-to-scr-el3', asm('msr scr_el3, xzr'), 'forbidden instruction msr scr_el3'),
    ('a-write-to-esr-el2', asm('msr esr_el2, xzr'), 'forbidden instruction msr esr_el2'),
    ('a-write-to-far-el2', asm('msr far_el2, xzr'), 'forbidden instruction msr far_el2'),
    ('a-write-to-elr-el1', asm('msr elr_el1, xzr'), 'forbidden instruction msr elr_el1'),
    ('a-write-to-spsr-el1', asm('msr spsr_el1, xzr'), 'forbidden instruction msr spsr_el1'),
    ('a-write-to-sp-el1', asm('msr sp_el1, xzr'), 'forbidden instruction msr sp_el1'),
    ('a-write-to-daifclr', asm('msr daifclr, #15'), 'forbidden instruction msr daifclr'),
    ('a-write-to-daifset', asm('msr daifset, #15'), 'forbidden instruction msr daifset'),
    ('a-write-to-spsel', asm('msr spsel, #1'), 'forbidden instruction msr spsel'),
    ('a-read-of-an-unlisted-register', read('ttbr0_el2'), 'registers read'),
    ('a-read-of-sctlr-el2', read('sctlr_el2'), 'registers read'),
    ('a-read-of-the-physical-timer-control', read('CNTP_CTL_EL0'), 'registers read'),
    ('an-smc', asm('smc #0'), '1 smc instructions'),
    ('an-hvc-with-another-immediate', asm('hvc #3'), 'forbidden instruction hvc #0x3'),
    ('an-hvc-with-a-large-immediate', asm('hvc #0xffff'), 'forbidden instruction hvc #0xffff'),
    ('an-svc', asm('svc #0'), 'svc'),
    ('a-wfi', asm('wfi'), 'wfi'),
    ('a-wfe', asm('wfe'), 'forbidden instruction wfe'),
    ('an-sev', asm('sev'), 'sev'),
    ('a-dmb', asm('dmb sy'), 'dmb'),
    ('a-tlb-operation', asm('tlbi alle2'), 'tlbi'),
    ('an-instruction-cache-operation-to-the-point-of-unification', asm('ic iallu'), 'forbidden instruction ic iallu'),
    ('a-data-cache-clean', asm('dc cvac, x0'), 'forbidden instruction dc cvac'),
    ('a-data-cache-zero', asm('dc zva, x0'), 'forbidden instruction dc zva'),
    ('an-address-translation', asm('at s1e2r, x0'), 'forbidden instruction at'),
    ('an-exclusive-load', asm('ldxr x9, [sp]'), 'ldxr'),
    ('an-atomic-add', asm('.arch_extension lse\\n ldadd x9, x10, [sp]'), 'ldadd'),
    ('a-word-that-is-no-instruction', asm('.inst 0xffffffff'), 'not a known instruction'),
]


def llvm_mc(text):
    done = run(['llvm-mc', '-triple=aarch64', '-mattr=+v8.4a', '-show-encoding'], input=text)
    found = re.findall(r'encoding: \[((?:0x[0-9a-f]{2},?)+)\]', done.stdout)
    return [struct.unpack('<I', bytes(int(b, 16) for b in encoding.split(',')))[0] for encoding in found]


MACHINE = ('el1trap_run', 'el1trap_probe', 'el1trap_resume', 'el1trap_el2_common', 'el1trap_from_el2', 'el1trap_trapped', 'el1trap_hvc',
           'el1trap_end', 'el1trap_fatal')


def machine_blocks(text):
    """{label: [(mnemonic, operands)]} of the assembly of el1trap_run in an objdump listing, comments cut, case folded, an address
    before a symbol left out."""
    blocks, label = {}, None
    for line in text.splitlines():
        head = re.match(r'^[0-9a-f]+ <(\w+)>:$', line)
        if head:
            label = head.group(1) if head.group(1) in MACHINE else None
            if label:
                blocks[label] = []
            continue
        ins = re.match(r'\s+[0-9a-f]+:\s+(\S+)\s*(.*)$', line)
        if label and ins:
            blocks[label].append((ins.group(1).lower(), re.sub(r'0x[0-9a-f]+ (<\w+>)', r'\1', ins.group(2).split('//')[0].strip().lower())))
    return blocks


def asm_problems(text, source):
    """What the disassembly says against the document's account of the assembly (the order of the saves and the restores, the ISB after
    every write of VBAR_EL2, the class taken from ESR_EL2[31:26], what the stub's registers are reported as, what the last ERET
    returns with); an empty list means it agrees. The offsets are the source's own."""
    blocks, problems = machine_blocks(text), []
    off = lambda name: f'#{int(re.search(rf"#define {name} (\d+)", source).group(1)):#x}'   # noqa: E731
    spsr_slot, frame = off('FRAME_SPSR'), off('FRAME_E')

    def need(label, wanted, why):
        block = blocks.get(label, [])
        if not any(block[i:i + len(wanted)] == wanted for i in range(len(block) - len(wanted) + 1)):
            problems.append(f'{label}: {why}')

    need('el1trap_run', [('mrs', 'x2, spsr_el2'), ('mrs', 'x3, elr_el2'), ('stp', f'x2, x3, [sp, {spsr_slot}]')], 'SPSR_EL2 and ELR_EL2 are not saved in x2, x3')
    need('el1trap_run', [('mrs', 'x27, vbar_el2'), ('str', f'x27, [x0, {off("E_SAVED_VBAR")}]')], 'VBAR_EL2 is not saved')
    need('el1trap_run', [('adr', 'x2, <el1trap_vectors_el2>'), ('msr', 'vbar_el2, x2'), ('isb', '')], 'the EL2 table is not installed and synchronised')
    need('el1trap_run', [('msr', 'elr_el2, x1'), ('mov', 'x2, #0x3c5'), ('msr', 'spsr_el2, x2'), ('eret', '')], 'the ERET to the stub is not EL1h with DAIF masked')
    need('el1trap_resume', [('ldr', f'x0, [sp, {frame}]'), ('ldr', f'x2, [x0, {off("E_SAVED_VBAR")}]'), ('msr', 'vbar_el2, x2'), ('isb', ''),
                            ('ldp', f'x2, x3, [sp, {spsr_slot}]'), ('msr', 'spsr_el2, x2'), ('msr', 'elr_el2, x3'),
                            ('ldr', f'x0, [x0, {off("E_REASON")}]')], 'VBAR_EL2, SPSR_EL2 and ELR_EL2 are not put back from the slots they were saved in')
    need('el1trap_el2_common', [('ubfx', 'x13, x9, #26, #6')], 'the exception class is not ESR_EL2[31:26]')
    if ('lsr', 'x13, x9, #26') in blocks.get('el1trap_el2_common', []):
        problems.append('el1trap_el2_common: the class keeps ESR_EL2[63:32]')
    need('el1trap_from_el2', [('mov', 'x14, #0x1'), ('str', f'x14, [x11, {off("E_PROBE_OK")}]'), ('mrs', 'x14, spsr_el2'),
                              ('str', f'x14, [x11, {off("E_CALLER_SPSR")}]'), ('eret', '')], "the probe does not keep the caller's SPSR_EL2")
    need('el1trap_end', [('stp', f'x0, x1, [x11, {off("E_X0")}]'), ('stp', f'x2, x3, [x11, {off("E_X2")}]'), ('adr', 'x13, <el1trap_resume>'),
                         ('msr', 'elr_el2, x13'), ('ldr', f'x13, [x11, {off("E_CALLER_SPSR")}]'), ('mov', 'x14, #0x1000'),
                         ('movk', 'x14, #0x3c0, lsl #16'), ('and', 'x13, x13, x14'), ('mov', 'x14, #0x3c9'), ('orr', 'x13, x13, x14'),
                         ('msr', 'spsr_el2, x13'), ('eret', '')],
         "the stub's x0 to x3 are not reported as they were, or the last ERET does not return with SSBS, PAN, UAO, DIT and TCO of the caller")
    need('el1trap_fatal', [('msr', 'vbar_el2, x27'), ('isb', ''), ('udf', '#0x0')], 'the fatal path does not put VBAR_EL2 back and fault')
    sites = [(label, i) for label, block in blocks.items() for i, (m, o) in enumerate(block) if m == 'msr' and o.startswith('vbar_el2,')]
    if len(sites) != 3:
        problems.append(f'{len(sites)} writes of VBAR_EL2 in the assembly, the document says three')
    problems += [f'{label}: the write of VBAR_EL2 is not followed by an ISB' for label, i in sites if blocks[label][i + 1:i + 2] != [('isb', '')]]
    return problems


class El1trapBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.out = BUILD / 'bad-binaries'
        cls.builder = Builder(cls.out)
        done, cls.elf, cls.flat = cls.builder.build('el1trap', 'control', [], check=True)
        if done.returncode:
            raise RuntimeError(done.stderr[-1500:])
        cls.text = run(['llvm-objdump', '-d', '--no-show-raw-insn', str(cls.elf)]).stdout
        cls.symbols = {m.group(2): int(m.group(1), 16) for m in re.finditer(r'^([0-9a-f]+) <(\w+)>:$', cls.text, re.M)}

    def test_the_unmodified_payload_is_clean_and_fits_the_policy(self):
        self.assertEqual(lib.binary_violations(self.elf, self.flat, POLICY, READELF()), [])
        self.assertEqual(POLICY['allow'], {'msr': {'hcr_el2', 'cnthctl_el2', 'sctlr_el1', 'vbar_el1', 'vbar_el2', 'spsr_el2', 'elr_el2'},
                                           'hvc': {'#0', '#0x1', '#0x2'}, 'eret': {''}, 'dc': {'civac'}, 'ic': {'ivau'}})
        self.assertEqual(POLICY['smc'], 0)
        self.assertGreaterEqual(POLICY['forbid'], {'dmb', 'sb', 'sev', 'sevl'})
        self.assertFalse({'isb', 'dsb'} & POLICY['forbid'])
        self.assertFalse({'smc_ids', 'single_reads', 'timer_offsets'} & set(POLICY))
        self.assertEqual(len(POLICY['registers']), 21)
        self.assertLessEqual(Path(self.flat).stat().st_size, POLICY['bytes'])

    def test_the_instruction_inventory_is_what_the_document_says(self):
        f = facts(self.elf, self.flat)
        self.assertEqual(set(f['mrs']), POLICY['registers'])
        self.assertEqual(dict(f['msr']), {'vbar_el2': 4, 'elr_el2': 4, 'spsr_el2': 3, 'hcr_el2': 1, 'cnthctl_el2': 1, 'sctlr_el1': 1, 'vbar_el1': 1})
        self.assertEqual((f['mnemonics']['mrs'], f['mnemonics']['msr']), (28, 15))
        self.assertEqual(dict(f['hvc']), {'#0x1': 16, '#0': 1, '#0x2': 1}, 'sixteen EL1 vector entries, the stub, the probe')
        self.assertEqual((f['mnemonics']['eret'], f['mnemonics']['isb'], f['mnemonics']['dsb'], f['mnemonics']['udf']), (4, 4, 1, 1))
        self.assertEqual((dict(f['dc']), dict(f['ic'])), ({'civac': 1}, {'ivau': 1}))
        for mnemonic in ('smc', 'svc', 'wfi', 'wfe', 'sev', 'sevl', 'dmb', 'sb', 'tlbi', 'at', 'sys', 'sysl', 'brk', 'hlt'):
            self.assertEqual(f['mnemonics'][mnemonic], 0, mnemonic)
        self.assertFalse([m for m in f['mnemonics'] if re.match(r'^(ldx|ldax|stx|stlx|cas|swp|ldadd|ldset|ldclr|ldeor)', m)])

    def test_the_el1_stub_is_five_instructions_with_no_branch_and_no_memory_access(self):
        start, end = self.symbols['el1trap_stub'], self.symbols.get('el1trap_stub_end')
        stub = [(a, m, o.split('//')[0].strip().lower()) for a, m, o in self.listing() if start <= a < (end or start + 20)]
        self.assertEqual([(m, o) for _, m, o in stub], [('mrs', 'x0, cntvct_el0'), ('mrs', 'x1, cntv_ctl_el0'), ('mrs', 'x2, cntfrq_el0'),
                                                         ('mrs', 'x3, cntpct_el0'), ('hvc', '#0')])
        self.assertEqual([a for a, _, _ in stub], [start + 4 * i for i in range(5)])
        data = Path(self.flat).read_bytes()
        self.assertEqual(struct.unpack_from('<5I', data, start), (0xd53be040, 0xd53be321, 0xd53be002, 0xd53be023, 0xd4000002),
                         'MRS CNTVCT_EL0, CNTV_CTL_EL0, CNTFRQ_EL0, CNTPCT_EL0 into x0 to x3, and HVC #0')

    def listing(self):
        found = (re.match(r'\s+([0-9a-f]+):\s+(\S+)\s*(.*)$', line) for line in self.text.splitlines())
        return [(int(m.group(1), 16), m.group(2).lower(), m.group(3)) for m in found if m]

    def test_both_vector_tables_are_two_kib_aligned_and_every_entry_is_two_instructions_as_the_document_says(self):
        el2, el1, common = self.symbols['el1trap_vectors_el2'], self.symbols['el1trap_vectors_el1'], self.symbols['el1trap_el2_common']
        self.assertEqual((el2 % 2048, el1 % 2048), (0, 0), 'VBAR_ELx keeps bits 10:0 reserved')
        self.assertEqual(el1 - el2, 2048)
        by_address = {a: (m, o.split('//')[0].strip().lower()) for a, m, o in self.listing()}
        for n in range(16):
            with self.subTest(entry=n):
                self.assertEqual(by_address[el2 + 128 * n][0], 'mov')
                self.assertEqual(int(by_address[el2 + 128 * n][1].split('#')[1], 0), n)
                self.assertTrue(by_address[el2 + 128 * n][1].startswith('x15,'), 'the vector number is in x15')
                branch = by_address[el2 + 128 * n + 4]
                self.assertEqual(branch[0], 'b')
                self.assertEqual(int(branch[1].split()[0], 16), common, 'every EL2 entry goes to the one handler')
                self.assertEqual(by_address[el1 + 128 * n][0], 'mov')
                self.assertTrue(by_address[el1 + 128 * n][1].startswith('x16,'), 'the vector number is in x16')
                self.assertEqual(int(by_address[el1 + 128 * n][1].split('#')[1], 0), n)
                self.assertEqual(by_address[el1 + 128 * n + 4], ('hvc', '#0x1'), 'every EL1 entry reports by HVC #1')
                for offset in (8, 64, 124) if n < 15 else (8,):     # the rest of an entry is padding that is never executed
                    self.assertEqual(by_address[el2 + 128 * n + offset][0], 'nop')
                    self.assertEqual(by_address[el1 + 128 * n + offset][0], 'nop')

    def test_the_assembly_saves_installs_reports_and_returns_as_the_document_says(self):
        self.assertEqual(asm_problems(self.text, SOURCE.read_text(encoding='utf-8')), [])
        self.assertEqual(sorted(machine_blocks(self.text)), sorted(MACHINE))

    def test_every_forbidden_addition_is_named_by_the_allow_list_check(self):
        self.assertGreaterEqual(len(BAD_BINARIES), 40)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            built = list(pool.map(lambda b: (b, self.builder.build('el1trap', b[0], b[1])), BAD_BINARIES))
        for (name, _, expected), (done, elf, flat) in built:
            with self.subTest(binary=name):
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                problems = lib.binary_violations(elf, flat, POLICY, READELF())
                self.assertTrue(problems, 'the check passed a binary it must refuse')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_a_flat_binary_patched_behind_the_disassembly_is_caught_by_the_encoding_layer_alone(self):
        data = bytearray(Path(self.flat).read_bytes())
        words = struct.unpack(f'<{len(data) // 4}I', bytes(data[:len(data) // 4 * 4]))
        self.assertEqual(lib.binary_violations(self.elf, self.flat, POLICY, READELF()), [])
        msr = lambda w: w & 0xffffffe0 == 0xd51ce100                  # noqa: E731  msr cnthctl_el2
        isb = lambda w: w == 0xd5033fdf                               # noqa: E731
        wanted = (
            ('msr cnthctl_el2 to msr cntvoff_el2', msr, lambda w: 0xd51ce060 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr cntkctl_el1', msr, lambda w: 0xd518e100 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr sctlr_el2', msr, lambda w: 0xd51c1000 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr tcr_el2', msr, lambda w: 0xd51c2040 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr elr_el1', msr, lambda w: 0xd5184020 | w & 31, 'msr-register'),
            ('msr cnthctl_el2 to msr daifset', msr, lambda w: 0xd50340df, 'msr-immediate'),
            ('hvc #1 to hvc #3', lambda w: w == 0xd4000022, lambda w: 0xd4000062, 'hvc'),
            ('hvc #1 to svc #1', lambda w: w == 0xd4000022, lambda w: 0xd4000021, 'svc'),
            ('hvc #1 to smc #0', lambda w: w == 0xd4000022, lambda w: 0xd4000003, 'smc'),
            ('isb to dmb', isb, lambda w: 0xd5033fbf, 'dmb'),
            ('isb to wfe', isb, lambda w: 0xd503205f, 'wfe'),
            ('isb to wfi', isb, lambda w: 0xd503207f, 'wfi'),
            ('isb to dc cvac', isb, lambda w: 0xd50b7a20, 'sys'),
            ('isb to ic iallu', isb, lambda w: 0xd508751f, 'sys'),
        )
        for label, is_target, patch, what in wanted:
            with self.subTest(patch=label):
                at = next(i for i, w in enumerate(words) if is_target(w))
                patched = bytearray(data)
                struct.pack_into('<I', patched, at * 4, patch(words[at]))
                path = self.out / 'patched.bin'
                path.write_bytes(patched)
                problems = lib.binary_violations(self.elf, path, POLICY, READELF())
                expected = 'words of the code encode smc' if what == 'smc' else f'a word of the code encodes {what}'
                self.assertTrue(any(expected in p for p in problems), problems)

    @unittest.skipUnless(have('llvm-mc'), 'llvm-mc not installed')
    def test_the_encodings_this_payload_added_to_the_engine_are_what_llvm_mc_says(self):
        for form, text in ((('eret', ''), 'eret'), (('hvc', '#0'), 'hvc #0'), (('hvc', '#0x1'), 'hvc #1'), (('hvc', '#0x2'), 'hvc #2'),
                           (('ic', 'ivau'), 'ic ivau, x0'), (('msr', 'cnthctl_el2'), 'msr cnthctl_el2, x0'), (('msr', 'elr_el2'), 'msr elr_el2, x0'),
                           (('msr', 'hcr_el2'), 'msr hcr_el2, x0'), (('msr', 'sctlr_el1'), 'msr sctlr_el1, x0'), (('msr', 'spsr_el2'), 'msr spsr_el2, x0'),
                           (('msr', 'vbar_el1'), 'msr vbar_el1, x0'), (('msr', 'vbar_el2'), 'msr vbar_el2, x0')):
            with self.subTest(form=form):
                _, mask, value = lib.ALLOW_WORDS[form]
                word = llvm_mc(text + '\n')[0]
                register = text.endswith(', x0') and form[0] in ('msr', 'ic')
                self.assertEqual(word & mask, value, f'{word:#x} {mask:#x} {value:#x}')
                if register:
                    self.assertEqual(mask, 0xffffffe0, 'every Rt is allowed, nothing else')
                    self.assertEqual(llvm_mc(text.replace('x0', 'x17') + '\n')[0] & mask, value)

    def test_the_binary_is_refused_under_every_other_policy_and_the_others_under_its_own(self):
        for other in OTHERS:
            with self.subTest(policy=other):
                self.assertTrue(lib.binary_violations(self.elf, self.flat, lib.POLICIES[other], READELF()))
        out = BUILD / 'others'
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        for other in OTHERS:
            with self.subTest(payload=other):
                done, o_elf, o_flat = lib.build_payload(ROOT / 'payloads' / f'{other}.c', out, name=other, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertTrue(lib.binary_violations(o_elf, o_flat, POLICY, READELF()), f'{other} passes the el1trap policy: the policy is too loose')

    def test_the_forms_are_allowed_to_this_payload_and_to_no_older_one_except_where_the_document_says(self):
        for mnemonic, form, only in (('msr', 'cnthctl_el2', {'cnthctl', 'el1trap'}), ('msr', 'hcr_el2', {'el1trap'}), ('msr', 'sctlr_el1', {'el1trap'}),
                                     ('msr', 'vbar_el1', {'el1trap'}), ('msr', 'spsr_el2', {'el1trap'}), ('msr', 'elr_el2', {'el1trap'}),
                                     ('hvc', '#0x1', {'el1trap'}), ('eret', '', {'el1trap'}), ('ic', 'ivau', {'el1trap'})):
            with self.subTest(form=(mnemonic, form)):
                self.assertEqual({name for name, policy in lib.POLICIES.items() if form in policy.get('allow', {}).get(mnemonic, ())} - {'cpuon', 'el2mem'},
                                 only)

    def test_two_builds_from_the_same_tree_are_byte_identical(self):
        done, _, flat = Builder(BUILD / 'again').build('el1trap', 'control', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(Path(flat).read_bytes(), Path(self.flat).read_bytes())
        self.assertEqual(Path(self.flat).read_bytes()[:4], bytes.fromhex('5f2403d5'), 'BTI c first, as the runner expects')


class El1trapAsmMutants(unittest.TestCase):
    """The audit of the assembly must be able to fail: no host program runs the assembly, so each seeded edit of it is built and the
    audit of its disassembly must name something (the QEMU suite is the run of the real thing)."""

    def test_each_seeded_edit_of_the_assembly_is_named_and_the_control_is_clean(self):
        need_tools()
        source = SOURCE.read_text(encoding='utf-8')
        builder = Builder(BUILD / 'asm-mutants')
        self.assertGreaterEqual(len(ASM_MUTANTS), 10)
        self.assertEqual(len({name for name, _ in ASM_MUTANTS}), len(ASM_MUTANTS))
        for name, edits in [('control', [])] + ASM_MUTANTS:
            with self.subTest(mutant=name):
                done, elf, _ = builder.build('el1trap', name, edits)
                self.assertEqual(done.returncode, 0, done.stderr[-800:])
                problems = asm_problems(run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout, source)
                if name == 'control':
                    self.assertEqual(problems, [])
                else:
                    self.assertTrue(problems, 'the audit passed a binary whose assembly was changed')


class El1trapStick(unittest.TestCase):
    tool = ROOT / 'tools' / 'sp11_payload_manifest.py'

    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.out = BUILD / 'stick-payloads'
        shutil.rmtree(cls.out, ignore_errors=True)
        done = run(['make', '-f', 'platform/uefi/Makefile', f'OUT={cls.out.relative_to(ROOT)}', 'payloads'])
        if done.returncode:
            raise RuntimeError('make payloads failed:\n' + done.stdout[-1500:] + done.stderr[-1500:])
        cls.bins = {name: cls.out / 'payloads' / f'{name}.bin' for name in ('state', 'psci', 'el1trap')}

    def stick(self, order):
        base = BUILD / 'stick' / '-'.join(order)
        shutil.rmtree(base, ignore_errors=True)
        done = run(['python3', '-B', str(self.tool), '--out-dir', str(base)] + [str(self.bins[name]) for name in order])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        return base, done

    def entries(self, base):
        raw = (base / 'SP11' / 'PAYLOAD.MAN').read_bytes()
        magic, version, count, size = struct.unpack_from('<4Q', raw)
        self.assertEqual(magic, int.from_bytes(b'Q1N1PLD1', 'little'))
        return [struct.unpack_from('<Q32s256s', raw, 32 + i * size) for i in range(count)]

    def test_el1trap_alone_is_one_payload_and_the_stick_holds_the_manifest_and_the_file(self):
        base, done = self.stick(('el1trap',))
        entries = self.entries(base)
        self.assertEqual([e[2].rstrip(b'\0').decode() for e in entries], ['\\SP11\\EL1TRAP.BIN'])
        data = self.bins['el1trap'].read_bytes()
        self.assertEqual((entries[0][0], entries[0][1]), (len(data), hashlib.sha256(data).digest()))
        self.assertEqual(sorted(p.name for p in (base / 'SP11').iterdir()), ['EL1TRAP.BIN', 'PAYLOAD.MAN'])
        self.assertEqual((base / 'SP11' / 'EL1TRAP.BIN').read_bytes(), data)
        self.assertIn('(INDEX=0, payload, called in manifest order)', done.stdout)

    def test_the_runners_own_validator_and_loader_take_it_as_a_payload_alone_and_after_psci(self):
        harness = BUILD / 'kinds-harness'
        sources = [ROOT / 'tools' / 'testdata' / 'sp11-payload-kinds-harness.c'] + [
            native.UEFI / name for name in ('sp11-payload-load.c', 'sp11-payload-plan.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c')]
        done = run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1',
                    '-I', str(native.UEFI)] + [str(s) for s in sources] + ['-o', str(harness)])
        self.assertEqual(done.returncode, 0, done.stderr)
        for order, expected in ((('el1trap',), ['\\SP11\\EL1TRAP.BIN code']),
                                (('psci', 'el1trap'), ['\\SP11\\PSCI.BIN code', '\\SP11\\EL1TRAP.BIN code'])):
            with self.subTest(order=order):
                base, _ = self.stick(order)
                ours = run([str(harness), str(base / 'SP11' / 'PAYLOAD.MAN')])
                self.assertEqual(ours.returncode, 0, ours.stdout + ours.stderr)
                self.assertEqual(ours.stdout.splitlines(), expected)

    def test_the_binary_is_a_few_pages_and_inside_its_policy(self):
        self.assertLessEqual(self.bins['el1trap'].stat().st_size, POLICY['bytes'])
        self.assertGreater(self.bins['el1trap'].stat().st_size, 8192, 'the two 2 KiB tables and the code')


def facts_main():
    need_tools()
    done, elf, flat = Builder(BUILD / 'facts').build('el1trap', 'el1trap', [], check=True)
    if done.returncode:
        sys.exit(done.stderr)
    f = facts(elf, flat)
    print(f'el1trap.bin: {f["bytes"]} bytes, sha256 {f["sha256"]}, {f["instructions"]} instructions')
    print('mnemonics:', ', '.join(f'{m} {n}' for m, n in sorted(f['mnemonics'].items())))
    print('registers read:', ', '.join(f'{r} x{n}' for r, n in sorted(f['mrs'].items())))
    print('msr operands:', dict(f['msr']), 'hvc:', dict(f['hvc']), 'dc:', dict(f['dc']), 'ic:', dict(f['ic']))
    print('allow-list violations:', lib.binary_violations(elf, flat, POLICY, READELF()))


if __name__ == '__main__':
    if sys.argv[1:] == ['facts']:
        facts_main()
    else:
        sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
