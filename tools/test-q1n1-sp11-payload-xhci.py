#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The xhci payload of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-XHCI.md): its host test, its seeded bugs, the audits of
the record over every file of the payload, the allow-list of its binary and its stick. The QEMU run is
tools/test-q1n1-sp11-payload-qemu-xhci.py, the document's test tools/test-q1n1-sp11-payload-xhci-doc.py.

    python3 tools/test-q1n1-sp11-payload-xhci.py          # everything
    python3 tools/test-q1n1-sp11-payload-xhci.py facts    # sizes, digests and instruction inventory of the built binaries

  * XhciNative: tools/test-q1n1-sp11-payload-xhci*.c (a model of the controller, the DWC3, the SMMU, the memory map, a non-coherent cache
    and the page, an audit of every access independent of the payload, nine suites, one of which calls the store gates directly with
    every input they must refuse, and 1500 random worlds), built for each controller under ASan and UBSan, and again with shrunken
    line and load budgets.
  * XhciSource: the audits of the record that no run shows, over every file of the payload (xhci*.c, xhci-priv.h, xhci-regs.h): two store
    sinks and one call of each, the registers the stores name, the groups, the cache instructions behind the arena gate, no other asm, no
    writable global, no address outside the header. Each rule is a function of text, and each has a faulty text it must reject.
  * XhciMutants: seeded bugs, each applied to a copy of the tree and each of which the host harness must reject; one per rule of every
    store gate, each of which only the direct tests of the gates may be what rejects.
  * XhciBinary: the allow-list applied to xhci0.bin and xhci1.bin, the store sinks and their call sites in the disassembly, seeded bad
    binaries and a flat binary patched so that only the encoding layer can see it. The compiled code is audited further in
    tools/test-q1n1-sp11-payload-xhci-compiled.py: the root of every pointer a store uses, and the depth of the payload's frames.
  * XhciStick and XhciDefaults: the manifest tool and the runner's validator on the real binaries; and that the xHCI payload leaves the default build,
    every other payload and the shared machinery as they are, by checks that compare the tree with a copy of itself without payloads/xhci* and so hold
    at any commit (tools/sp11_payload_xhci_defaults.py, with its seeded bugs).

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
import concurrent.futures
import hashlib
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_ecv_lib as ecv  # noqa: E402
import sp11_payload_xhci_audit as audit  # noqa: E402
import sp11_payload_xhci_defaults as df  # noqa: E402
import sp11_payload_xhci_lib as xl  # noqa: E402
import sp11_payload_xhci_mutants as seeded  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-xhci-test'
SUITES = ('nominal', 'scratch', 'refuse', 'faults', 'fallback', 'watch', 'edges', 'gates', 'fuzz')
READELF, run = ecv.READELF, lib.run
MAX_BYTES, MAX_LINES = 50 * 1024, 1500
MACHINE_IDS = re.compile('|'.join(['/Us' + 'ers/', '/ho' + 'me/', '/Vol' + 'umes/']) + r'|\bsae' + r'ed\b|host' + r'name|\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b', re.I)
OWN_FILES = (xl.payload_files() + [ROOT / 'tools' / name for name in xl.HARNESS + (xl.HARNESS_HEADER,)] + [
    ROOT / 'tools' / 'sp11_payload_xhci_lib.py', ROOT / 'tools' / 'sp11_payload_xhci_mutants.py', ROOT / 'tools' / 'test-q1n1-sp11-payload-xhci.py',
    ROOT / 'tools' / 'sp11_payload_xhci_audit.py', ROOT / 'tools' / 'sp11_payload_xhci_audit_cases.py', ROOT / 'tools' / 'sp11_payload_xhci_defaults.py',
    ROOT / 'tools' / 'test-q1n1-sp11-payload-xhci-compiled.py',
    ROOT / 'tools' / 'test-q1n1-xhci.c', ROOT / 'tools' / 'test-q1n1-sp11-payload-xhci-doc.py', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu-xhci.py',
    ROOT / 'docs' / 'SP11-PAYLOAD-XHCI.md'])


def sources(root=ROOT):
    return {path.name: ecv.code_of(path) for path in xl.payload_files(root) if path.exists()}


# ---- the header: the one table of registers, groups and budgets -------------------------------------------------------------------

def eval_constants(text):
    """The names of every enum with a value in a header, evaluated (the u suffixes of C dropped; a name of something else is skipped)."""
    constants = {}
    for body in re.findall(r'enum\s*\{([^}]*)\}', re.sub(r'/\*.*?\*/', '', text, flags=re.S)):
        value = -1
        for item in (part.strip() for part in body.split(',')):
            if not item:
                continue
            name, _, expression = item.partition('=')
            try:
                value = eval(re.sub(r'(\d)u\b', r'\1', expression.strip()), {}, constants) if expression else value + 1
            except NameError:
                continue
            constants[name.strip()] = value
    return constants


def header_registers(text):
    """[(name, window, offset, groups)] of the registers the payload may store to, read from payloads/xhci-regs.h: the SR_ enum, reg_map
    and reg_groups. window 0 is the operational registers, 1 interrupter 0, 2 the doorbell array."""
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    constants = eval_constants(text)
    names = re.search(r'enum \{ (SR_USBCMD[^}]*)\}', text).group(1).replace('\n', ' ').split(',')
    names = [n.strip()[3:] for n in names if n.strip() and n.strip() != 'SR_COUNT']
    pairs = re.findall(r'\{(\d), ([A-Z_0-9]+(?: \+ \d+)?)\}', re.search(r'reg_map\[SR_COUNT\] = \{(.*?)\};', text, re.S).group(1))
    groups = re.search(r'reg_groups\[SR_COUNT\] = \{(.*?)\};', text, re.S).group(1).replace('\n', ' ').split(',')
    return [(name, int(window), eval(offset, {}, constants), eval(group.strip(), {}, constants))
            for name, (window, offset), group in zip(names, pairs, groups)]


# ---- the audits of the record, as functions of text ----------------------------------------------------------------------------

ASM_ALLOWED = {'"mrs %0, "', '"dc cvac, %0"', '"dc civac, %0"', '"dsb sy"'}
SINKS = (('mmio_store32', 'xhc_store'), ('ram_store32', 'ram_put'))


def function_body(text, name):
    found = re.search(rf'^[A-Za-z_][^\n;]*\b{name}\([^\n]*\)\n\{{\n(.*?)\n\}}\n', text, re.S | re.M)
    return found.group(1) if found else ''


def function_bodies(text):
    """{name: body} of every function of the text whose braces stand on lines of their own."""
    return {found.group(1): found.group(2) for found in re.finditer(r'^[A-Za-z_][^\n;]*\b(\w+)\([^\n]*\)\n\{\n(.*?)\n\}\n', text, re.S | re.M)}


# Each cache instruction is made by one helper, called from one function only, and that function checks every address against the arena first.
CACHE_OPS = (('dc_cvac', 'clean_range'), ('dc_civac', 'events_take'))


def source_problems(texts, header_registers_table):
    """Everything in the sources of the payload (name -> text without comments) that breaks a rule of the record; empty means clean."""
    problems = []
    joined = '\n'.join(texts.values())
    for sink, caller in SINKS:
        if len(re.findall(rf'\bSINK void {sink}\(', joined)) != 1:
            problems.append(f'{sink} is not defined exactly once')
        calls = [m for m in re.finditer(rf'(?<!void )\b{sink}\(', joined)]
        if len(calls) != 1:
            problems.append(f'{sink} is called {len(calls)} times, the record allows one call, in {caller}')
        elif f'{sink}(' not in function_body(joined, caller):
            problems.append(f'the one call of {sink} is not in {caller}')
    stores = re.findall(r'\*\(volatile uint32_t \*\)\(uintptr_t\)a = v', joined)
    if len(stores) != 2:
        problems.append(f'{len(stores)} pointer stores of a word, the record allows the two sinks')
    rest = re.sub(r'\*\(volatile uint32_t \*\)\(uintptr_t\)a = v|\*\(volatile const uint32_t \*\)\(uintptr_t\)a|\(\(volatile uint8_t \*\)&c\)\[i\] = 0|'
                  r'__asm__ volatile|#define OUT_OF_LINE|__attribute__\(\(noinline\)\)', '', joined)
    if 'volatile' in rest:
        problems.append('a volatile access that is not one of the two sinks, the one load and the clearing of the context')
    asm = set(re.findall(r'__asm__ volatile\(("[^"]*")', joined))
    if asm != ASM_ALLOWED:
        problems.append(f'inline assembly {sorted(asm)}, the record allows {sorted(ASM_ALLOWED)}')
    if len(re.findall(r'__asm__', joined)) != 4 or re.search(r'\basm\b\s*\(', joined):
        problems.append('an inline assembly statement that is not one of the four')
    if len(re.findall(r'->ops\.load32\(', joined)) != 1 or len(re.findall(r'->ops\.(\w+)\(', joined)) < 3:
        problems.append('the device reads do not all go through one call of ops.load32')
    bodies = function_bodies(joined)
    for helper, owner in CACHE_OPS:
        users = sorted(name for name, body in bodies.items() if re.search(rf'(?<!void ){helper}\(', body))
        if users != [owner]:
            problems.append(f'{helper} is called from {users}, the record allows {owner} alone')
        elif 'arena_range(' not in bodies[owner]:
            problems.append(f'{owner} maintains the cache without checking the range against the arena')
    names = [name for name, _, _, _ in header_registers_table]
    used = set()
    for group, register in re.findall(r'\bstore\(c, (G_\w+), (SR_\w+),', joined):
        if register[3:] not in names:
            problems.append(f'store() names {register}, which is not a register of the record')
            continue
        used.add(register[3:])
        allowed = dict((n, g) for n, _, _, g in header_registers_table)[register[3:]]
        value = {'G_STOP': 0, 'G_ARENA': 1, 'G_RESET': 2, 'G_PROGRAM': 4, 'G_RUN': 8, 'G_NOOP': 16}[group]
        if register != 'SR_USBCMD' and not allowed & value:
            problems.append(f'store() writes {register} in {group}, which the table does not allow')
    if used != set(names):
        problems.append(f'registers without a store() or with one too many: {sorted(used ^ set(names))}')
    for physical in ('0x0a600000', '0x0a800000', '0x15000000', '0xa600000', '0xa800000'):
        for name, text in texts.items():
            if name != 'xhci-regs.h' and physical in text.lower():
                problems.append(f'the physical address {physical} is named in {name}, outside xhci-regs.h')
    for declaration in re.findall(r'^static\b[^\n(]*;', joined, re.M):
        if not re.search(r'\bconst\b|\binline\b', declaration) and not declaration.startswith('static struct {'):
            problems.append(f'a writable file-scope variable: {declaration}')
    return problems


def faulty(texts, name, old, new):
    changed = dict(texts)
    assert changed[name].count(old) == 1, (name, old)
    changed[name] = changed[name].replace(old, new, 1)
    return changed


# The payloads whose policy allows DC CVAC, each with its reason: retprobe cleans its three canary pages so that they are in DRAM before the reset it
# makes (docs/SP11-PAYLOAD-RETPROBE.md); the two xHCI files clean what the CPU wrote for the xHC, which a bus master that may not snoop the CPU's caches
# reads from memory. A fourth payload that needs it has to be named here.
CVAC_PAYLOADS = ('retprobe', 'xhci0', 'xhci1')
CVAC_FORM = ('sys', 0xffffffe0, 0xd50b7a20)       # SYS #3, C7, C10, #1


def cvac_problems(policies, allow_words):
    holders = {name for name, policy in policies.items() if 'cvac' in policy.get('allow', {}).get('dc', ())}
    problems = [f'{name} may use DC CVAC and is not named with its reason' for name in sorted(holders - set(CVAC_PAYLOADS))]
    problems += [f'{name} is named for DC CVAC and its policy does not allow it' for name in sorted(set(CVAC_PAYLOADS) - holders)]
    if allow_words.get(('dc', 'cvac')) != CVAC_FORM:
        problems.append('the shared form of DC CVAC is not SYS #3, C7, C10, #1')
    return problems


# ---- native ---------------------------------------------------------------------------------------------------------------------

class XhciNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ecv.need_tools()
        shutil.rmtree(BUILD / 'native', ignore_errors=True)
        (BUILD / 'native').mkdir(parents=True)
        jobs = [(c, None, None) for c in xl.CONTROLLERS] + [(c, cap, None) for c in xl.CONTROLLERS for cap in xl.TIGHT_CAPS] + [
            (c, None, loads) for c in xl.CONTROLLERS for loads in xl.TIGHT_LOAD_CAPS]
        cls.binaries = {job: BUILD / 'native' / ('h-%d-%s-%s' % (job[0], job[1], job[2])) for job in jobs}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(4, os.cpu_count() or 1))) as pool:
            done = list(pool.map(lambda job: xl.build_harness(job[0], cls.binaries[job], cap=job[1], load_cap=job[2]), jobs))
        for job, finished in zip(jobs, done):
            if finished.returncode:
                raise RuntimeError(f'{job}: {finished.stderr[-1500:]}')

    def test_every_suite_passes_alone_for_both_controllers(self):
        for controller in xl.CONTROLLERS:
            for suite in SUITES:
                with self.subTest(controller=controller, suite=suite):
                    code, output = xl.run_harness(self.binaries[(controller, None, None)], suite)
                    self.assertEqual(code, 0, output[-1500:])
                    self.assertRegex(output, rf'PASS: 1 payload xhci suites, \d+ checks, \d+ runs \(controller {controller}\)')

    def test_all_suites_in_one_run_and_the_checks_do_not_shrink(self):
        for controller in xl.CONTROLLERS:
            code, output = xl.run_harness(self.binaries[(controller, None, None)])
            self.assertEqual(code, 0, output[-1500:])
            found = re.search(r'PASS: 9 payload xhci suites, (\d+) checks, (\d+) runs', output)
            self.assertIsNotNone(found, output)
            self.assertGreaterEqual(int(found.group(1)), 2500, 'a suite stopped checking what it used to')
            self.assertGreaterEqual(int(found.group(2)), 1640)

    def test_the_shrunken_budgets_never_cost_a_verdict_an_unannounced_write_or_a_line_over_the_cap(self):
        for job, binary in self.binaries.items():
            if job[1] is None and job[2] is None:
                continue
            with self.subTest(job=job):
                code, output = xl.run_harness(binary)
                self.assertEqual(code, 0, output[-1500:])
                self.assertIn('PASS: 1 payload xhci suites', output)

    def test_an_unknown_suite_is_refused(self):
        code, output = xl.run_harness(self.binaries[(1, None, None)], 'nothing')
        self.assertEqual(code, 2, output)

    def test_the_registers_the_audit_knows_are_the_header_s_table(self):
        table = header_registers((ROOT / 'payloads' / 'xhci-regs.h').read_text(encoding='utf-8'))
        self.assertEqual(len(table), 13)
        for controller in xl.CONTROLLERS:
            code, output = xl.run_harness(self.binaries[(controller, None, None)], 'registers')
            self.assertEqual(code, 0, output)
            oracle = [(name, int(window), int(offset, 16)) for _, name, window, offset in (line.split() for line in output.splitlines())]
            self.assertEqual(oracle, [(name, window, offset) for name, window, offset, _ in table])


# ---- source ---------------------------------------------------------------------------------------------------------------------

class XhciSource(unittest.TestCase):
    texts = sources()
    table = header_registers((ROOT / 'payloads' / 'xhci-regs.h').read_text(encoding='utf-8'))

    def test_the_payload_is_split_by_responsibility_and_every_file_is_covered(self):
        self.assertEqual(sorted(self.texts), sorted([f'{p}.c' for p in xl.PARTS] + list(xl.HEADERS)))
        self.assertEqual(sorted(p.name for p in (ROOT / 'payloads').glob('xhci*')), sorted(self.texts))

    def test_the_sources_obey_every_rule_of_the_record(self):
        self.assertEqual(source_problems(self.texts, self.table), [])

    def test_the_rules_reject_the_faulty_texts(self):
        io, ctl, main = 'xhci-io.c', 'xhci-ctl.c', 'xhci.c'
        cases = (
            ('a second call of the device sink', faulty(self.texts, ctl, '    if (store(c, G_NOOP, SR_IMAN, IMAN_IP)) return W_STORE;\n',
                                                        '    mmio_store32(0, 0);\n'), 'mmio_store32 is called 2 times'),
            ('the device sink called outside the gate', faulty(self.texts, io, '    mmio_store32(windows[TARGET].base + off, value);\n    return STORE_OK;\n',
                                                               '    return STORE_OK;\n'), 'mmio_store32 is called 0 times'),
            ('a third pointer store', faulty(self.texts, main, '    c.a = a;\n', '    c.a = a;\n    *(volatile uint32_t *)(uintptr_t)a = v;\n'), 'pointer stores'),
            ('another volatile access', faulty(self.texts, main, '    c.a = a;\n', '    c.a = a;\n    *(volatile uint64_t *)a = 0;\n'), 'volatile access'),
            ('an isb', faulty(self.texts, main, '    c.a = a;\n', '    c.a = a;\n    __asm__ volatile("isb");\n'), 'inline assembly'),
            ('an msr', faulty(self.texts, main, '    c.a = a;\n', '    c.a = a;\n    __asm__ volatile("msr daifclr, #15");\n'), 'inline assembly'),
            ('a register that is not in the record', faulty(self.texts, ctl, 'SR_DB0, 0)', 'SR_PORTSC1, 0)'), 'not a register of the record'),
            ('a register without a store', faulty(self.texts, ctl, '    if (store(c, G_NOOP, SR_DB0, 0)) return W_STORE;\n', ''), 'without a store()'),
            ('a group the table does not allow', faulty(self.texts, ctl, 'store(c, G_NOOP, SR_IMAN, IMAN_IP)', 'store(c, G_PROGRAM, SR_IMAN, IMAN_IP)'), 'does not allow'),
            ('a second load op', faulty(self.texts, main, '    c.a = a;\n', '    c.a = a;\n    a->ops.load32(0, 0);\n'), 'ops.load32'),
            ('a writable global', faulty(self.texts, main, '#include "xhci-priv.h"\n', '#include "xhci-priv.h"\nstatic unsigned counter_of_runs;\n'), 'writable file-scope'),
            ('a physical address outside the header', faulty(self.texts, main, '    c.a = a;\n', '    c.a = a;\n    c.hz = 0x0a600000;\n'), 'physical address'),
            ('a cache instruction made from another function', faulty(self.texts, main, '    c.a = a;\n', '    c.a = a;\n    dc_civac(0);\n'), 'dc_civac is called from'),
            ('an event slot invalidated without the arena check', faulty(self.texts, ctl, '            if (!arena_range(c, at, CACHE_STEP)) return W_STORE;\n', ''),
             'events_take maintains the cache'),
            ('a clean without the arena check', faulty(self.texts, io, '        if (!arena_range(c, at, CACHE_STEP)) break;\n', ''), 'clean_range maintains the cache'),
        )
        for label, texts, expected in cases:
            with self.subTest(case=label):
                problems = source_problems(texts, self.table)
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not in {problems}')

    def test_the_header_table_is_the_records_thirteen_registers_in_the_order_it_is_written(self):
        self.assertEqual([r[0] for r in self.table], ['USBCMD', 'CRCR_LO', 'CRCR_HI', 'DCBAAP_LO', 'DCBAAP_HI', 'CONFIG', 'ERSTSZ', 'ERSTBA_LO', 'ERSTBA_HI',
                                                      'ERDP_LO', 'ERDP_HI', 'IMAN', 'DB0'])
        self.assertEqual([(r[1], r[2]) for r in self.table], [(0, 0x00), (0, 0x18), (0, 0x1c), (0, 0x30), (0, 0x34), (0, 0x38), (1, 0x08), (1, 0x10), (1, 0x14),
                                                              (1, 0x18), (1, 0x1c), (1, 0x00), (2, 0x00)])
        for forbidden in ('PORTSC', 'DWC3', 'SMMU', 'GCC', 'GDSC'):
            self.assertFalse([r for r in self.table if forbidden in r[0]], forbidden)

    def test_the_budgets_are_below_the_abis(self):
        header = (ROOT / 'payloads' / 'xhci-regs.h').read_text(encoding='utf-8')
        abi = (ROOT / 'platform' / 'uefi' / 'sp11-payload-abi.h').read_text(encoding='utf-8')
        self.assertEqual(int(re.search(r'#define XHCI_S1_LOAD_CAP (\d+)u', header).group(1)), 3800)
        self.assertEqual(int(re.search(r'#define XHCI_S1_LINE_CAP (\d+)u', header).group(1)), int(re.search(r'#define Q1N1_PAYLOAD_LINES_MAX (\d+)u', abi).group(1)))
        self.assertLess(3800, int(re.search(r'#define Q1N1_PAYLOAD_LOADS_MAX (\d+)u', abi).group(1)))
        for bad in (b'#define XHCI_S1_LOAD_CAP 9000u', b'#define XHCI_S1_LOAD_CAP 4096u'):
            self.assertGreaterEqual(int(re.search(rb'(\d+)u', bad).group(1)), 4096, 'a cap at or above the ABI would not be a margin')

    def test_the_write_groups_and_waits_are_the_records(self):
        regs = (ROOT / 'payloads' / 'xhci-regs.h').read_text(encoding='utf-8')
        for define, value in (('WAIT_BEFORE_WRITE_S', '8u'), ('WATCH_S', '30u'), ('CACHE_STEP', '16u'), ('ARENAS', '4u'), ('SCRATCH_MAX', '32u'),
                              ('T_RESET_US', '1000000u'), ('T_CNR_US', '1000000u'), ('POLL_US', '1000u'), ('POLL_SLOW_US', '10000u'),
                              ('POLL_FAST_WINDOW_US', '100000u'), ('STORE_LIMIT', '0xc100u'), ('ATTEMPT_LINES_MIN', '6u'), ('CLOSING_LINES', '2u')):
            self.assertRegex(regs, rf'#define {define} {value}\b')
        ctl = (ROOT / 'payloads' / 'xhci-ctl.c').read_text(encoding='utf-8')
        order = [ctl.index(f'announce(c, {g}') for g in ('G_ARENA', 'G_RESET', 'G_PROGRAM', 'G_RUN', 'G_NOOP')]
        self.assertEqual(order, sorted(order), 'the groups are announced in the order of the sequence')

    def test_the_files_are_within_the_size_limits_and_carry_no_machine_identifier(self):
        for path in OWN_FILES:
            if not path.exists():
                continue
            with self.subTest(file=path.name):
                text = path.read_text(encoding='utf-8')
                self.assertLess(len(text.splitlines()), MAX_LINES)
                self.assertLess(len(text.encode('utf-8')), MAX_BYTES)
                self.assertIn('SPDX-License-Identifier: MIT', text[:200])
                self.assertTrue(text.isascii(), 'ASCII only')
                self.assertIsNone(MACHINE_IDS.search(text))


# ---- seeded bugs -----------------------------------------------------------------------------------------------------------------

class XhciMutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ecv.need_tools()
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_there_are_enough_distinct_mutants_and_every_part_has_one(self):
        names = [m[0] for m in seeded.MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertGreaterEqual(len(names), 100)
        files = {edit[0] for m in seeded.MUTANTS for edit in m[1]}
        self.assertEqual(files, {'payloads/xhci.c', 'payloads/xhci-io.c', 'payloads/xhci-map.c', 'payloads/xhci-ctl.c', 'payloads/xhci-text.c',
                                 'payloads/xhci-watch.c', 'payloads/xhci-smmu.c', 'payloads/xhci-regs.h'})
        for wanted in ('erstba-before-erstsz', 'missing-scratchpad', 'no-wait-before-a-write', 'a-store-to-the-smmu', 'no-bound-on-a-poll',
                       'the-noop-trb-is-not-cleaned', 'arms-without-a-printed-announcement', 'the-verdict-can-be-crowded-out',
                       'a-bad-completion-moves-on-to-the-next-arena', 'a-redirect-is-a-timeout', 'the-smmu-baseline-is-not-refreshed',
                       'the-event-is-invalidated-a-megabyte-above-its-slot', 'the-arena-clean-overruns-by-a-page', 'a-reset-gets-a-tenth-of-a-second',
                       'the-watch-does-not-notice-a-counter-that-stopped', 'the-store-limit-is-checked-nowhere',
                       'a-counter-that-is-set-back-ends-a-wait-at-once', 'the-bus-error-address-and-valid-bit-are-not-compared',
                       'the-bus-error-address-is-not-compared', 'the-bus-error-valid-bit-is-not-compared', 'hse-at-the-reset-is-not-noticed',
                       'hce-at-the-reset-is-not-noticed', 'a-digit-buffer-that-is-too-small'):
            self.assertIn(wanted.replace('missing-scratchpad', 'no-scratchpad-array'), names)

    def test_every_rule_of_every_gate_has_a_mutant_that_only_the_direct_tests_of_the_gates_can_catch(self):
        gate_mutants = [m for m in seeded.MUTANTS if m[3] == 'gates']
        self.assertGreaterEqual(len(gate_mutants), 19)
        io = (ROOT / 'payloads' / 'xhci-io.c').read_text(encoding='utf-8')
        for _, edits, _, _ in gate_mutants:
            self.assertEqual(len(edits), 1, 'a gate mutant removes one rule and nothing else')
            self.assertEqual(edits[0][0], 'payloads/xhci-io.c')
            self.assertEqual(io.count(edits[0][1]), 1, edits[0][1])

    def test_the_unmutated_control_passes_from_a_copy(self):
        directory = xl.copy_tree(BUILD / 'control')
        for controller, cap, load_cap in ((0, None, None), (1, None, None), (1, 16, None), (0, None, 700)):
            done = xl.build_harness(controller, directory / f'h{controller}{cap}{load_cap}', root=directory, cap=cap, load_cap=load_cap)
            self.assertEqual(done.returncode, 0, done.stderr[-1500:])
            code, output = xl.run_harness(directory / f'h{controller}{cap}{load_cap}')
            self.assertEqual(code, 0, output[-800:])

    def test_every_seeded_bug_is_caught(self):
        workers = max(1, min(4, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {m[0]: pool.submit(seeded.evaluate, m, BUILD) for m in seeded.MUTANTS}
            results = {name: future.result() for name, future in futures.items()}
        for name, (status, detail) in results.items():
            with self.subTest(mutant=name):
                self.assertEqual(status, 'caught', f'{status}: {detail}')
        # An offset inside a buffer of the payload is outside what the IR audit proves (it proves bases): the sanitizers of the harness are what catch it
        # (UBSan's bounds check on the array index here, AddressSanitizer for an index it does not know the bound of).
        self.assertIn('Sanitizer', results['a-digit-buffer-that-is-too-small'][1])


# ---- the binary -----------------------------------------------------------------------------------------------------------------

BAD_BINARIES = [
    # (name, edits of the entry, what the allow-list check must say)
    ('an-isb', ecv.asm('isb'), 'isb'),
    ('a-dmb', ecv.asm('dmb sy'), 'dmb'),
    ('an-smc', ecv.asm('smc #0'), '1 smc instructions'),
    ('an-hvc', ecv.asm('hvc #0'), 'hvc'),
    ('an-svc', ecv.asm('svc #0'), 'svc'),
    ('an-eret', ecv.asm('eret'), 'eret'),
    ('a-wfi', ecv.asm('wfi'), 'wfi'),
    ('a-wfe', ecv.asm('wfe'), 'forbidden instruction wfe'),
    ('an-sev', ecv.asm('sev'), 'sev'),
    ('a-tlb-operation', ecv.asm('tlbi alle2'), 'tlbi'),
    ('an-instruction-cache-operation', ecv.asm('ic iallu'), 'forbidden instruction ic'),
    ('a-data-cache-zero', ecv.asm('dc zva, x0'), 'forbidden instruction dc zva'),
    ('a-data-cache-invalidate-without-clean', ecv.asm('dc ivac, x0'), 'forbidden instruction dc ivac'),
    ('a-data-cache-set-way-operation', ecv.asm('dc cisw, x0'), 'forbidden instruction dc cisw'),
    ('an-address-translation', ecv.asm('at s1e2r, x0'), 'forbidden instruction at'),
    ('a-write-to-hcr-el2', ecv.asm('msr hcr_el2, xzr'), 'forbidden instruction msr'),
    ('a-write-to-sctlr-el2', ecv.asm('msr sctlr_el2, xzr'), 'a word of the code encodes msr-register'),
    ('a-write-to-daifclr', ecv.asm('msr daifclr, #15'), 'a word of the code encodes msr-immediate'),
    ('a-write-to-vbar-el2', ecv.asm('msr vbar_el2, xzr'), 'forbidden instruction msr'),
    ('a-write-to-cntvoff-el2', ecv.asm('msr cntvoff_el2, xzr'), 'the code names cntvoff_el2'),
    ('a-read-of-cntpoff-el2', ecv.read('S3_4_C14_C0_6'), 'the code names'),
    ('a-read-of-cntvoff-el2', ecv.read('S3_4_C14_C0_3'), 'the code names'),
    ('a-read-of-the-physical-counter', ecv.read('CNTPCT_EL0'), 'registers read'),
    ('a-read-of-an-unlisted-register', ecv.read('ttbr0_el2'), 'registers read'),
    ('a-read-of-hcr-el2', ecv.read('hcr_el2'), 'registers read'),
    ('an-exclusive-load', ecv.asm('ldxr x9, [sp]'), 'ldxr'),
    ('an-atomic-add', ecv.asm('.arch_extension lse\\n ldadd x9, x10, [sp]'), 'ldadd'),
    ('a-word-that-is-no-instruction', ecv.asm('.inst 0xffffffff'), 'not a known instruction'),
]


class XhciBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ecv.need_tools()
        shutil.rmtree(BUILD / 'binary', ignore_errors=True)
        cls.built = {}
        for controller in xl.CONTROLLERS:
            done, elf, flat = xl.build_binary(controller, BUILD / 'binary' / f'c{controller}')
            if done.returncode:
                raise RuntimeError(done.stdout[-1500:] + done.stderr[-1500:])
            cls.built[controller] = (elf, flat)

    def disassembly(self, controller):
        return lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(self.built[controller][0])]).stdout

    def test_both_binaries_are_clean_under_their_policy(self):
        for controller in xl.CONTROLLERS:
            with self.subTest(controller=controller):
                elf, flat = self.built[controller]
                policy = lib.POLICIES[f'xhci{controller}']
                self.assertEqual(lib.binary_violations(elf, flat, policy, READELF()), [])
                self.assertEqual(policy['registers'], {'currentel', 'cntfrq_el0'})
                self.assertEqual(policy['allow'], {'dc': {'cvac', 'civac'}})
                self.assertEqual(policy['smc'], 0)
                self.assertGreaterEqual(policy['forbid'], {'isb', 'dmb', 'sb', 'sev', 'sevl'})
                self.assertNotIn('dsb', policy['forbid'])
                self.assertLessEqual(Path(flat).stat().st_size, policy['bytes'])

    def test_the_instruction_inventory_is_what_the_document_says(self):
        for controller in xl.CONTROLLERS:
            with self.subTest(controller=controller):
                f = ecv.facts(*self.built[controller])
                self.assertEqual(set(f['mrs']), {'currentel', 'cntfrq_el0'})
                self.assertEqual(dict(f['dc']), {'cvac': 1, 'civac': 1}, 'one site of each: the two helpers')
                self.assertEqual(f['mnemonics']['dsb'], 1, 'one DSB site: the helper')
                for mnemonic in ('msr', 'isb', 'dmb', 'sb', 'smc', 'hvc', 'svc', 'eret', 'wfi', 'wfe', 'sev', 'sevl', 'tlbi', 'ic', 'at', 'sysl', 'brk', 'hlt'):
                    self.assertEqual(f['mnemonics'][mnemonic], 0, mnemonic)
                self.assertFalse([m for m in f['mnemonics'] if re.match(r'^(ldx|ldax|stx|stlx|cas|swp|ldadd|ldset|ldclr|ldeor)', m)])
                self.assertEqual(f['mrs']['currentel'], 1)
                self.assertEqual(f['mrs']['cntfrq_el0'], 1)

    def test_each_store_sink_is_one_instruction_with_one_call_site_in_its_gate(self):
        for controller in xl.CONTROLLERS:
            text = self.disassembly(controller)
            for sink, gate in SINKS:
                with self.subTest(controller=controller, sink=sink):
                    body = re.search(rf'<{sink}>:\n(.*?)\n\n', text, re.S).group(1)
                    stores = [line for line in body.splitlines() if re.search(r'\t(str|stur|stp|strb|strh|stlr|stnp)\b', line)]
                    self.assertEqual(len(stores), 1, body)
                    self.assertRegex(stores[0], r'str\tw1, \[x0\]')
                    callers = []
                    function = None
                    for line in text.splitlines():
                        label = re.match(r'[0-9a-f]+ <([^>]+)>:', line)
                        if label:
                            function = label.group(1)
                        if re.search(rf'\b(bl|b)\t0x[0-9a-f]+ <{sink}>', line):
                            callers.append(function)
                    self.assertEqual(callers, [gate])

    def test_the_gates_and_the_stores_are_reached_only_from_the_functions_the_record_names(self):
        callers = {}
        for controller in xl.CONTROLLERS:
            text = self.disassembly(controller)
            function = None
            for line in text.splitlines():
                label = re.match(r'[0-9a-f]+ <([^>]+)>:', line)
                if label:
                    function = label.group(1)
                found = re.search(r'\b(bl|b)\t0x[0-9a-f]+ <(xhc_store|store|ram_put|ram_put64|arena_range|clean_range|dc_cvac|dc_civac|ram_load32)>', line)
                if found:
                    callers.setdefault((controller, found.group(2)), set()).add(function)
            self.assertEqual(callers[(controller, 'xhc_store')], {'store'})
            self.assertEqual(callers[(controller, 'store')], {'xhc_halt', 'xhc_reset', 'xhc_program', 'xhc_run', 'xhc_noop'})
            self.assertEqual(callers[(controller, 'ram_put')], {'ram_put64', 'arena_build', 'arena_zero', 'xhc_noop'})
            self.assertEqual(callers[(controller, 'ram_put64')], {'arena_build', 'xhc_noop'})
            # every cache instruction is made by clean_range or events_take, each behind the arena gate, and the one RAM load is the event's
            self.assertEqual(callers[(controller, 'dc_cvac')], {'clean_range'})
            self.assertEqual(callers[(controller, 'dc_civac')], {'events_take'})
            self.assertEqual(callers[(controller, 'arena_range')], {'clean_range', 'events_take', 'xhc_noop'})
            self.assertEqual(callers[(controller, 'clean_range')], {'arena_build', 'arena_zero', 'xhc_noop'})
            self.assertEqual(callers[(controller, 'ram_load32')], {'events_take', 'xhc_noop'})

    def test_every_forbidden_addition_is_named_by_the_allow_list_check(self):
        self.assertGreaterEqual(len(BAD_BINARIES), 25)
        directory = BUILD / 'bad'
        shutil.rmtree(directory, ignore_errors=True)

        def build(bad):
            name, edits, _ = bad
            copy = xl.copy_tree(directory / name)
            path = copy / 'payloads' / 'xhci.c'
            text = path.read_text(encoding='utf-8')
            for needle, replacement in edits:
                self.assertEqual(text.count(needle), 1, f'{name}: anchor not found once')
                text = text.replace(needle, replacement, 1)
            path.write_text(text, encoding='utf-8')
            return xl.build_binary(1, copy / 'out', root=copy, check=False)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            built = list(pool.map(lambda b: (b, build(b)), BAD_BINARIES))
        for (name, _, expected), (done, elf, flat) in built:
            with self.subTest(binary=name):
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                problems = lib.binary_violations(elf, flat, lib.POLICIES['xhci1'], READELF())
                self.assertTrue(problems, 'the check passed a binary it must refuse')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_a_flat_binary_patched_behind_the_disassembly_is_caught_by_the_encoding_layer_alone(self):
        elf, flat = self.built[1]
        data = bytearray(Path(flat).read_bytes())
        words = struct.unpack(f'<{len(data) // 4}I', bytes(data[:len(data) // 4 * 4]))
        policy = lib.POLICIES['xhci1']
        self.assertEqual(lib.binary_violations(elf, flat, policy, READELF()), [])
        wanted = (
            ('dsb sy to isb', lambda w: w == 0xd5033f9f, lambda w: 0xd5033fdf, 'isb'),
            ('dsb sy to dmb', lambda w: w == 0xd5033f9f, lambda w: 0xd5033fbf, 'dmb'),
            ('dsb sy to wfe', lambda w: w == 0xd5033f9f, lambda w: 0xd503205f, 'wfe'),
            ('dsb sy to wfi', lambda w: w == 0xd5033f9f, lambda w: 0xd503207f, 'wfi'),
            ('dsb sy to eret', lambda w: w == 0xd5033f9f, lambda w: 0xd69f03e0, 'eret'),
            ('dsb sy to hvc', lambda w: w == 0xd5033f9f, lambda w: 0xd4000002, 'hvc'),
            ('dsb sy to svc', lambda w: w == 0xd5033f9f, lambda w: 0xd4000001, 'svc'),
            ('dsb sy to smc', lambda w: w == 0xd5033f9f, lambda w: 0xd4000003, 'smc'),
            ('dc civac to dc ivac', lambda w: w & 0xffffffe0 == 0xd50b7e20, lambda w: 0xd5087620 | w & 31, 'sys'),
            ('dc cvac to dc zva', lambda w: w & 0xffffffe0 == 0xd50b7a20, lambda w: 0xd50b7420 | w & 31, 'sys'),
            ('mrs CurrentEL to msr', lambda w: w == 0xd5384248, lambda w: 0xd5184248, 'msr-register'),
            ('mrs CurrentEL to msr daifset', lambda w: w == 0xd5384248, lambda w: 0xd50340df, 'msr-immediate'),
        )
        for label, is_target, patch, what in wanted:
            with self.subTest(patch=label):
                at = next((i for i, w in enumerate(words) if is_target(w)), None)
                self.assertIsNotNone(at, f'no word to patch for {label}')
                patched = bytearray(data)
                struct.pack_into('<I', patched, at * 4, patch(words[at]))
                path = BUILD / 'binary' / 'patched.bin'
                path.write_bytes(patched)
                problems = lib.binary_violations(elf, path, policy, READELF())
                expected = 'words of the code encode smc' if what == 'smc' else f'a word of the code encodes {what}'
                self.assertTrue(any(expected in p for p in problems), problems)

    def test_the_binary_is_refused_under_every_other_policy(self):
        for other in ('state', 'psci', 'timer', 'usbsmmu', 'cpuon', 'cnthctl'):
            if other in lib.POLICIES:
                with self.subTest(policy=other):
                    self.assertTrue(lib.binary_violations(*self.built[1], lib.POLICIES[other], READELF()))

    def test_dc_cvac_is_allowed_to_exactly_retprobe_xhci0_and_xhci1(self):
        self.assertEqual(cvac_problems(lib.POLICIES, lib.ALLOW_WORDS), [])
        for controller in xl.CONTROLLERS:
            self.assertEqual(lib.POLICIES[f'xhci{controller}']['allow'], {'dc': {'cvac', 'civac'}})
        self.assertNotIn('ALLOW_WORDS', (ROOT / 'tools' / 'sp11_payload_xhci_lib.py').read_text(encoding='utf-8'), 'the form is the shared one, which retprobe added')

    def test_the_dc_cvac_check_rejects_a_fourth_payload_a_missing_one_and_another_form(self):
        policies = {name: {'allow': dict(policy.get('allow', {}))} for name, policy in lib.POLICIES.items()}
        fourth = dict(policies, cpuon={'allow': {'dc': {'civac', 'ivac', 'cvac'}}})
        missing = dict(policies, xhci0={'allow': {'dc': {'civac'}}})
        gone = {name: policy for name, policy in policies.items() if name != 'retprobe'}
        for label, changed, words in (('a fourth payload', fourth, lib.ALLOW_WORDS), ('a payload without it', missing, lib.ALLOW_WORDS),
                                      ('a payload that is not there', gone, lib.ALLOW_WORDS),
                                      ('another form', policies, {**lib.ALLOW_WORDS, ('dc', 'cvac'): ('sys', 0xffffffe0, 0xd50b7e20)}),
                                      ('no form', policies, {})):
            with self.subTest(case=label):
                self.assertTrue(cvac_problems(changed, words), label)

    def test_two_builds_of_one_tree_are_byte_identical_and_the_controllers_differ(self):
        done, _, flat = xl.build_binary(1, BUILD / 'again' / 'c1')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(Path(flat).read_bytes(), Path(self.built[1][1]).read_bytes())
        self.assertNotEqual(Path(self.built[0][1]).read_bytes(), Path(self.built[1][1]).read_bytes())
        self.assertEqual(Path(self.built[1][1]).read_bytes()[:4], bytes.fromhex('5f2403d5'), 'BTI c first, as the runner expects')


# ---- the stick and the defaults -------------------------------------------------------------------------------------------------

class XhciStick(unittest.TestCase):
    tool = ROOT / 'tools' / 'sp11_payload_manifest.py'

    @classmethod
    def setUpClass(cls):
        ecv.need_tools()
        cls.out = BUILD / 'stick-payloads'
        shutil.rmtree(cls.out, ignore_errors=True)
        done = run(['make', '-f', 'platform/uefi/Makefile', f'OUT={cls.out.relative_to(ROOT)}', 'payloads'])
        if done.returncode:
            raise RuntimeError('make payloads failed:\n' + done.stdout[-1500:] + done.stderr[-1500:])
        cls.bins = {name: cls.out / 'payloads' / f'{name}.bin' for name in ('xhci0', 'xhci1', 'psci')}

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

    def test_the_make_builds_one_binary_per_controller_and_they_are_the_ones_the_test_builds(self):
        self.assertEqual(sorted(p.name for p in (self.out / 'payloads').glob('xhci*.bin')), ['xhci0.bin', 'xhci1.bin'])
        for controller in xl.CONTROLLERS:
            done, _, flat = xl.build_binary(controller, BUILD / 'stick-compare' / f'c{controller}')
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(self.bins[f'xhci{controller}'].read_bytes(), Path(flat).read_bytes(), 'the Makefile and the test build it differently')

    def test_each_binary_alone_is_one_payload_and_the_stick_holds_the_manifest_and_the_file(self):
        for name in ('xhci0', 'xhci1'):
            with self.subTest(binary=name):
                base, done = self.stick((name,))
                entries = self.entries(base)
                self.assertEqual([e[2].rstrip(b'\0').decode() for e in entries], [f'\\SP11\\{name.upper()}.BIN'])
                data = self.bins[name].read_bytes()
                self.assertEqual((entries[0][0], entries[0][1]), (len(data), hashlib.sha256(data).digest()))
                self.assertEqual(sorted(p.name for p in (base / 'SP11').iterdir()), sorted([f'{name.upper()}.BIN', 'PAYLOAD.MAN']))
                self.assertIn('(INDEX=0, payload, called in manifest order)', done.stdout)

    def test_the_runners_own_validator_and_loader_take_each_as_a_payload_and_both_in_either_order(self):
        harness = BUILD / 'kinds-harness'
        sources = [ROOT / 'tools' / 'testdata' / 'sp11-payload-kinds-harness.c'] + [
            ROOT / 'platform' / 'uefi' / name for name in ('sp11-payload-load.c', 'sp11-payload-plan.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c')]
        done = run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1',
                    '-I', str(ROOT / 'platform' / 'uefi')] + [str(s) for s in sources] + ['-o', str(harness)])
        self.assertEqual(done.returncode, 0, done.stderr)
        for order, expected in ((('xhci1',), ['\\SP11\\XHCI1.BIN code']), (('xhci0',), ['\\SP11\\XHCI0.BIN code']),
                                (('xhci1', 'xhci0'), ['\\SP11\\XHCI1.BIN code', '\\SP11\\XHCI0.BIN code']),
                                (('psci', 'xhci1'), ['\\SP11\\PSCI.BIN code', '\\SP11\\XHCI1.BIN code'])):
            with self.subTest(order=order):
                base, _ = self.stick(order)
                ours = run([str(harness), str(base / 'SP11' / 'PAYLOAD.MAN')])
                self.assertEqual(ours.returncode, 0, ours.stdout + ours.stderr)
                self.assertEqual(ours.stdout.splitlines(), expected)

    def test_the_binaries_are_a_few_kilobytes_and_one_range_is_declared_whatever_their_size(self):
        for name in ('xhci0', 'xhci1'):
            size = self.bins[name].stat().st_size
            self.assertLessEqual(size, lib.POLICIES[name]['bytes'])
            self.assertGreater(size, 8192)


class XhciDefaults(unittest.TestCase):
    """The xHCI payload leaves the default build, every other payload and the shared machinery as they are. Every check compares the tree with a copy of
    itself without payloads/xhci* (tools/sp11_payload_xhci_defaults.py) and none with an earlier commit, so that the class passes at any commit: before
    the one that adds the payload, at it, and after it."""

    @classmethod
    def setUpClass(cls):
        ecv.need_tools()
        cls.scratch = BUILD / 'defaults'
        shutil.rmtree(cls.scratch, ignore_errors=True)

    def test_the_default_build_plans_no_file_of_the_xhci_payload(self):
        self.assertEqual(df.default_problems(ROOT), [])

    def test_the_payloads_target_plans_xhci0_and_xhci1_and_no_other_xhci_binary(self):
        self.assertEqual(df.target_problems(ROOT), [])

    def test_without_the_xhci_sources_the_payloads_target_plans_the_same_but_for_the_xhci_lines(self):
        self.assertEqual(df.without_problems(ROOT, self.scratch / 'plan'), [])

    def test_every_other_payload_binary_is_byte_for_byte_the_same_with_and_without_the_xhci_sources(self):
        self.assertEqual(df.binary_problems(ROOT, self.scratch / 'build'), [])

    def test_the_shared_machinery_names_no_xhci(self):
        self.assertEqual(df.shared_problems(df.shared_texts(ROOT)), [])

    def test_make_clean_removes_the_objects_of_the_xhci_payload(self):
        self.assertEqual(df.clean_problems(ROOT), [])

    def test_the_checks_pass_on_a_copy_of_the_tree(self):
        copy = df.copy_build_tree(ROOT, self.scratch / 'control' / 'with')
        self.assertEqual(df.target_problems(copy), [])
        self.assertEqual(df.without_problems(copy, self.scratch / 'control'), [])
        self.assertEqual(df.binary_problems(copy, self.scratch / 'control'), [])
        self.assertEqual(df.clean_problems(copy), [])
        self.assertEqual(df.shared_problems(df.shared_texts(copy)), [])

    def test_every_seeded_bug_of_these_checks_is_caught_for_the_reason_it_is_meant_for(self):
        names = [mutant[0] for mutant in df.MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertEqual({mutant[1] for mutant in df.MUTANTS}, {'default', 'target', 'without', 'binaries', 'shared', 'clean'}, 'a seeded bug for each check')
        self.assertEqual({mutant[2][0][0] for mutant in df.MUTANTS if mutant[1] == 'shared'}, set(df.SHARED), 'one for each shared file')
        for mutant in df.MUTANTS:
            with self.subTest(mutant=mutant[0]):
                status, detail = df.evaluate(mutant, self.scratch / 'mutants')
                self.assertEqual(status, 'caught', f'{status}: {detail}')


def facts_main():
    ecv.need_tools()
    for controller in xl.CONTROLLERS:
        done, elf, flat = xl.build_binary(controller, BUILD / 'facts' / f'c{controller}')
        if done.returncode:
            sys.exit(done.stderr)
        f = ecv.facts(elf, flat)
        print(f'xhci{controller}.bin: {f["bytes"]} bytes, sha256 {f["sha256"]}, {f["instructions"]} instructions')
        print('  mnemonics:', ', '.join(f'{m} {n}' for m, n in sorted(f['mnemonics'].items())))
        print('  registers read:', ', '.join(f'{r} x{n}' for r, n in sorted(f['mrs'].items())), '; dc:', dict(f['dc']))
        print('  allow-list violations:', lib.binary_violations(elf, flat, lib.POLICIES[f'xhci{controller}'], READELF()))
        problems, counts = audit.provenance(audit.build_ir(controller, BUILD / 'facts' / f'ir{controller}'))
        print(f'  stores in the IR: {counts["stores"]} in {counts["functions"]} functions, by root {counts["by_root"]} (S stack, P parameter, I the two sinks); '
              f'problems: {problems}')
        listing = lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(elf)]).stdout
        used, path = audit.depth(audit.call_graph(listing), audit.frame_sizes(controller, BUILD / 'facts' / f'frames{controller}'))
        print(f'  deepest frames: {used} bytes along {" > ".join(path)} (the stack keeps 24 KiB, the ABI leaves {audit.OPS_ALLOWANCE} of it to the runner)')


if __name__ == '__main__':
    if sys.argv[1:] == ['facts']:
        facts_main()
    else:
        sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
