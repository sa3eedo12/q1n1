#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The retprobe payload of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-RETPROBE.md): its host test, its seeded bugs, the
allow-list of its binary, its stick and its document. The QEMU run is tools/test-q1n1-sp11-payload-qemu-retprobe.py.

    python3 tools/test-q1n1-sp11-payload-retprobe.py          # the suites
    python3 tools/test-q1n1-sp11-payload-retprobe.py facts    # size, digest and instruction inventory of the built binary

  * RetprobeNative: tools/test-q1n1-sp11-payload-retprobe.c (ten suites over a modelled machine: the memory map, the MMU's answers, a cache
    that agrees with DRAM only through cache maintenance, PSCI, guarded loads, a counter; an independent oracle of the page format; random
    worlds), built and run by the machinery of tools/test-q1n1-sp11-payload.py under ASan and UBSan.
  * RetprobeSource: what no run shows -- the ops the source calls, the registers it names, the three SMC sites and their ids, that no other
    PSCI function id is in the source, the one function that stores to a page, no writable global, the size limits.
  * RetprobeMutants: seeded bugs in retprobe.c, each applied to a copy of the sources and each of which the host program must reject.
  * RetprobeBinary: the allow-list applied to retprobe.bin (four registers read, AT S1E2R and S1E2W, DC CVAC and CIVAC, DSB, three SMC with
    the ids of PSCI_FEATURES, SYSTEM_RESET and SYSTEM_RESET2 and nothing else) with seeded bad binaries and a flat binary patched behind the
    disassembly, and the build's reproducibility.
  * RetprobeStick: the manifest tool and the runner's own validator on a stick that holds retprobe.bin and its configuration file.

The document is held to the source by tools/test-q1n1-sp11-payload-retprobe-doc.py.

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
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_ecv_lib as ecv  # noqa: E402

native = ecv.load_module('sp11_payload_native_for_retprobe', ROOT / 'tools' / 'test-q1n1-sp11-payload.py')
native.BUILD = ROOT / 'build' / 'sp11-payload-retprobe-test'
# The shared machinery knows the older payloads; this payload joins it here, in this copy of the module only.
native.PROGRAMS['retprobe'] = ('tools/test-q1n1-sp11-payload-retprobe.c', ['sp11-payload-text.c'], 10, 5000, 'retprobe')
native.HOST_PAYLOADS['retprobe'] = 'retprobe.c'
native.PAYLOADS_COPIED = native.PAYLOADS_COPIED + ['retprobe.c', 'payload-page.h', 'payload-mmu.h']
BUILD = native.BUILD
SOURCE = ROOT / 'payloads' / 'retprobe.c'
DOC = ROOT / 'docs' / 'SP11-PAYLOAD-RETPROBE.md'
READELF, run, have = ecv.READELF, lib.run, lib.have
code_of, Builder, asm, read, facts, need_tools = ecv.code_of, ecv.Builder, ecv.asm, ecv.read, ecv.facts, ecv.need_tools
SUITES = ('args', 'phase1', 'config', 'pages', 'previous', 'write', 'cache', 'reset', 'lines', 'fuzz')
OWN_FILES = [SOURCE, DOC, ROOT / 'tools' / 'test-q1n1-sp11-payload-retprobe.c', ROOT / 'tools' / 'test-q1n1-sp11-payload-retprobe-world.h',
             ROOT / 'tools' / 'test-q1n1-sp11-payload-retprobe.py', ROOT / 'tools' / 'test-q1n1-sp11-payload-qemu-retprobe.py',
             ROOT / 'tools' / 'test-q1n1-sp11-payload-retprobe-doc.py']
LINES_MAX = 21


def config_bytes(path, countdown, pages):
    """The configuration file of the payload's header comment, written here and not taken from the payload or the Snapintosh tool."""
    body = b'RETCFG01' + struct.pack('<IIII', 1, path, countdown, 3) + b''.join(struct.pack('<Q', page) for page in pages) + bytes(12)
    return body + struct.pack('<I', zlib.crc32(body))


class RetprobeNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_the_retprobe_suites_pass(self):
        native.Native._check(self, 'retprobe')

    def test_each_suite_runs_alone(self):
        done, binary = native.build_program('retprobe', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite in SUITES:
            with self.subTest(suite=suite):
                code, output = native.run_program(binary, suite)
                self.assertEqual(code, 0, output)
                self.assertRegex(output, r'PASS: 1 payload retprobe suites, \d+ checks')

    def test_the_most_lines_are_measured(self):
        done, binary = native.build_program('retprobe', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary, 'lines-report')
        self.assertEqual(code, 0, output)
        self.assertEqual(output.strip(), f'LINES_MAX={LINES_MAX}')


class RetprobeSource(unittest.TestCase):
    code = code_of(SOURCE)

    def test_the_source_calls_only_the_load_and_counter_ops_and_the_helpers_puts_and_hex(self):
        self.assertEqual(set(re.findall(r'ops\.(\w+)', self.code)), {'load32', 'counter'})
        util = code_of(ROOT / 'payloads' / 'payload-util.h') + code_of(ROOT / 'payloads' / 'payload-page.h')
        self.assertEqual(set(re.findall(r'ops\.(\w+)', util)), {'hex', 'puts'})

    def test_the_registers_the_source_names_are_the_ones_the_policy_lists(self):
        named = {name.lower() for name in re.findall(r'SYSREG\((\w+)\)', self.code)} - {'name'}
        self.assertEqual(named | {'par_el1'}, lib.POLICIES['retprobe']['registers'])
        self.assertIn('par_el1', self.code)

    def test_the_only_instructions_are_the_documented_ones(self):
        statements = re.findall(r'__asm__ volatile\("([^"]*)"', self.code)
        self.assertEqual(sorted(statements), sorted(['smc #0'] * 3 + ['mrs %0, ', 'at s1e2w, %1\\n\\tisb\\n\\tmrs %0, par_el1', 'dc cvac, %0', 'dc civac, %0', 'dsb sy']))
        for forbidden in ('msr', 'hvc', 'svc', 'eret', 'wfi', 'wfe', 'tlbi', 'ic ', 'sev', 'ldxr', 'stxr'):
            self.assertNotIn(forbidden, ' '.join(statements))

    def test_there_are_three_smc_helpers_each_with_one_function_id(self):
        self.assertEqual(re.findall(r'^OUT_OF_LINE uint64_t (smc_\w+)\(', self.code, re.M), ['smc_features', 'smc_system_reset', 'smc_system_reset2'])
        defined = dict(re.findall(r'#define (FUNCTION_\w+) (0x[0-9A-Fa-f]+)u', self.code))
        self.assertEqual(defined, {'FUNCTION_PSCI_FEATURES': '0x8400000A', 'FUNCTION_SYSTEM_RESET': '0x84000009', 'FUNCTION_SYSTEM_RESET2': '0xC4000012'})
        self.assertEqual(sorted(int(v, 16) for v in defined.values()), sorted(lib.POLICIES['retprobe']['smc_ids']))
        self.assertIn('{FUNCTION_SYSTEM_RESET, FUNCTION_SYSTEM_RESET2}', self.code, 'the two arguments of PSCI_FEATURES')

    def test_no_other_psci_function_id_is_in_the_source(self):
        text = self.code.lower()
        for name, ids in (('CPU_SUSPEND', ('84000001', 'c4000001')), ('CPU_OFF', ('84000002',)), ('CPU_ON', ('84000003', 'c4000003')),
                          ('AFFINITY_INFO', ('84000004', 'c4000004')), ('MIGRATE', ('84000005', 'c4000005')), ('SYSTEM_OFF', ('84000008',)),
                          ('SYSTEM_SUSPEND', ('8400000e', 'c400000e')), ('SMCCC_VERSION', ('80000000',))):
            for value in ids:
                with self.subTest(function=name, id=value):
                    self.assertNotIn(value, text)
        self.assertNotIn('0x84000012', text, 'the SMC32 form of SYSTEM_RESET2 is not used')

    def test_one_function_stores_to_a_page_and_the_rest_store_to_the_stack(self):
        self.assertEqual(self.code.count('volatile uint32_t *p = (volatile uint32_t *)(uintptr_t)address;'), 1)
        body = self.code[self.code.index('OUT_OF_LINE void page_store'):self.code.index('OUT_OF_LINE void clean_pages')]
        self.assertEqual(len(re.findall(r'\bp\[[^\]]+\] = ', body)), 2, 'the header and the body')
        self.assertEqual(len(re.findall(r'\bp\[[^\]]+\] = ', self.code)), 2, 'no other store through a page pointer')

    def test_the_reset_is_called_from_one_place_each_and_only_after_the_wait(self):
        self.assertEqual(self.code.count('smc_system_reset()'), 1)
        self.assertEqual(self.code.count('smc_system_reset2()'), 1)
        order = [self.code.index(token) for token in ('page_store(cfg.page[k]', 'clean_pages(cfg.page', 'verify_pages(cfg.page', 'wait_seconds(a, cfg.countdown)',
                                                       'answer[0] = smc_system_reset();')]
        self.assertEqual(order, sorted(order))
        gate = self.code.index('RESET_NOT_IMPLEMENTED SYSTEM_RESET"')
        self.assertLess(gate, self.code.index('read_previous(a, cfg.page[k]'))
        self.assertLess(self.code.index('read_previous(a, cfg.page[k]'), order[0], 'the previous pages are read before the first store')

    def test_no_writable_global_and_every_table_is_constant(self):
        for declaration in re.findall(r'^static\b[^\n(]*;', self.code, re.M):
            self.assertRegex(declaration, r'\bconst\b|\binline\b', declaration)
        self.assertEqual(re.findall(r'^static (?!const|inline|__attribute__)[^\n(]*$', self.code, re.M), [])

    def test_the_files_are_within_the_size_limits(self):
        for path in OWN_FILES:
            if not path.exists():
                continue
            with self.subTest(file=path.name):
                text = path.read_text(encoding='utf-8')
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                self.assertIn('SPDX-License-Identifier: MIT', text[:200])
                self.assertTrue(text.isascii(), 'ASCII only')


# ---- seeded bugs in retprobe.c ----------------------------------------------------------------------------------------------

FILE = 'payloads/retprobe.c'
GATE1 = '    if (cfg.path == PATH_PSCI_RESET && (int32_t)(uint32_t)answer[0] < 0) {\n'
GATE2 = '    if (cfg.path == PATH_PSCI_RESET2 && (int32_t)(uint32_t)answer[1] < 0) {\n'
STORE_LOOP = '    for (unsigned i = 0; i < BODY_WORDS; i++) p[HEADER_WORDS + i] = body_word(counter, slot, i);\n'
CVAC_LOOP = '        for (uint32_t offset = 0; offset < PL_PAGE_BYTES; offset += line) dc_cvac(pages[k] + offset);\n'
CIVAC_LOOP = '        for (uint32_t offset = 0; offset < PL_PAGE_BYTES; offset += line) dc_civac(pages[k] + offset);\n'
WAIT_TEST = '        if (now - start >= frequency * seconds) return 1;\n'
READ_LINE = '        read_previous(a, cfg.page[k], k, page, &previous[k]);\n'
CLASSIFY_WHOLE = '        r->state = r->crc_ok && !bad ? STATE_WHOLE : STATE_PARTIAL;\n'
RESET_BLOCK = '    if (cfg.path == PATH_PSCI_RESET) {\n        pl_say(a, &p, "RESET", "CALL SYSTEM_RESET", 1);\n'
CONFIG_LINE = '        if (w[0] != MAGIC_LO || w[1] != CONFIG_MAGIC_HI) continue;\n'
PAGE_TYPE = '        if (d.type != PL_EFI_CONVENTIONAL || d.start > address || d.end < address + PL_PAGE_BYTES) return PAGE_OVERLAPS_OTHER;\n'
PROTECTED = ('    if (overlaps(address, PL_PAGE_BYTES, a->payload_base, a->payload_size) || overlaps(address, PL_PAGE_BYTES, a->stack_base, a->stack_size) ||\n'
             '        overlaps(address, PL_PAGE_BYTES, a->preload_table, a->preload_size) || overlaps(address, PL_PAGE_BYTES, a->map_base, a->map_size))\n'
             '        return PAGE_PROTECTED;\n')
DIFFER = '    if (w->pa != written.pa || w->attr != written.attr || w->sh != written.sh) return PAGE_READ_WRITE_DIFFER;\n'
STORES = '    /* The stores. */\n'
VERIFIED = '    pl_say(a, &p, "VERIFY", "OK", 0);\n'


def sub(name, old, new):
    return ('retprobe-' + name, FILE, [(old, new)], ['retprobe'], None)


def drop(name, statement):
    return sub(name, statement, '')


def stray(name, address, anchor=STORES):
    """A bug that stores a zero word through a pointer at `address`, right after `anchor`: an address the payload may not store to."""
    return sub('stray-store-' + name, anchor, anchor + f'    *(volatile uint32_t *)(uintptr_t)({address}) = 0;\n')


MUTANTS = [
    # -- the reset is gated by what PSCI_FEATURES said, before any store
    sub('resets-without-the-feature-check', GATE1, '    if (0) {\n'),
    sub('resets2-without-the-feature-check', GATE2, '    if (0) {\n'),
    sub('takes-not-supported-for-implemented', GATE1, '    if (cfg.path == PATH_PSCI_RESET && (int32_t)(uint32_t)answer[0] < -1) {\n'),
    sub('gates-system-reset-on-the-other-answer', GATE1, '    if (cfg.path == PATH_PSCI_RESET && (int32_t)(uint32_t)answer[1] < 0) {\n'),
    sub('gates-system-reset2-on-the-other-answer', GATE2, '    if (cfg.path == PATH_PSCI_RESET2 && (int32_t)(uint32_t)answer[0] < 0) {\n'),
    sub('goes-on-after-saying-the-reset-is-not-implemented',
        '        refuse(a, &p, "RESET_NOT_IMPLEMENTED SYSTEM_RESET");\n        return RET_NOT_IMPLEMENTED;\n',
        '        refuse(a, &p, "RESET_NOT_IMPLEMENTED SYSTEM_RESET");\n'),
    # -- which function, which arguments
    sub('system-reset-is-system-off', '#define FUNCTION_SYSTEM_RESET 0x84000009u', '#define FUNCTION_SYSTEM_RESET 0x84000008u'),
    sub('system-reset2-is-the-smc32-id', '#define FUNCTION_SYSTEM_RESET2 0xC4000012u', '#define FUNCTION_SYSTEM_RESET2 0x84000012u'),
    sub('features-is-another-function', '#define FUNCTION_PSCI_FEATURES 0x8400000Au', '#define FUNCTION_PSCI_FEATURES 0x8400000Bu'),
    sub('reset-type-is-not-the-architectural-warm-reset', '#define RESET_TYPE_ARCH_WARM 0u', '#define RESET_TYPE_ARCH_WARM 1u'),
    sub('cookie-is-set', '#define COOKIE_UNUSED 0u', '#define COOKIE_UNUSED 1u'),
    sub('asks-about-the-functions-in-the-wrong-order',
        'static const uint32_t feature_asked[2] = {FUNCTION_SYSTEM_RESET, FUNCTION_SYSTEM_RESET2};',
        'static const uint32_t feature_asked[2] = {FUNCTION_SYSTEM_RESET2, FUNCTION_SYSTEM_RESET};'),
    sub('calls-the-wrong-reset-for-the-path', RESET_BLOCK, '    if (cfg.path != PATH_PSCI_RESET) {\n        pl_say(a, &p, "RESET", "CALL SYSTEM_RESET", 1);\n'),
    sub('path-none-goes-on-to-a-reset', '        pl_say(a, &p, "RESET", "NONE CANARIES STAY FOR A MANUAL RESET", 1);\n        return RET_OK;\n',
        '        pl_say(a, &p, "RESET", "NONE CANARIES STAY FOR A MANUAL RESET", 1);\n'),
    sub('calls-system-reset-twice', '        answer[0] = smc_system_reset();\n', '        answer[0] = smc_system_reset();\n        answer[0] = smc_system_reset();\n'),
    sub('returns-ok-when-the-reset-returned', '        add_answer(a, &p, "RETURNED", answer[0], 1);\n    }\n    pl_page_flush(a, &p);\n    return RET_RETURNED;',
        '        add_answer(a, &p, "RETURNED", answer[0], 1);\n    }\n    pl_page_flush(a, &p);\n    return RET_OK;'),
    # -- announce, wait, then the reset
    drop('never-announces-the-countdown', '    pl_page_add(a, &p, "RESET AFTER");\n    pl_page_add(a, &p, seconds.buf);\n    pl_page_add(a, &p, "S");\n'),
    sub('does-not-wait', WAIT_TEST, '        return 1;\n'),
    sub('waits-twice-as-long', WAIT_TEST, '        if (now - start >= frequency * seconds * 2) return 1;\n'),
    sub('waits-one-second-too-few', WAIT_TEST, '        if (now - start >= frequency * (seconds - 1)) return 1;\n'),
    sub('waits-at-a-fixed-19-2-mhz', WAIT_TEST, '        if (now - start >= 19200000u * seconds) return 1;\n'),
    sub('does-not-bound-the-frequency', '    if (frequency < COUNTER_HZ_MIN || frequency > COUNTER_HZ_MAX) return 0;\n', ''),
    sub('frequency-upper-bound-excludes-one-ghz', 'frequency > COUNTER_HZ_MAX) return 0;', 'frequency >= COUNTER_HZ_MAX) return 0;'),
    sub('takes-a-stuck-counter-for-elapsed', '            if (++stuck >= STUCK_READS) return 0;\n', '            if (++stuck >= STUCK_READS) return 1;\n'),
    # -- the stores and the cache
    sub('stores-one-word-past-the-page', STORE_LOOP, '    for (unsigned i = 0; i <= BODY_WORDS; i++) p[HEADER_WORDS + i] = body_word(counter, slot, i);\n'),
    sub('cleans-every-other-line', CVAC_LOOP, CVAC_LOOP.replace('offset += line)', 'offset += 2 * line)')),
    sub('cleans-two-pages-only', '    for (unsigned k = 0; k < PAGES; k++)\n        for (uint32_t offset = 0; offset < PL_PAGE_BYTES; offset += line) dc_cvac(',
        '    for (unsigned k = 0; k < PAGES - 1u; k++)\n        for (uint32_t offset = 0; offset < PL_PAGE_BYTES; offset += line) dc_cvac('),
    sub('no-fence-after-the-clean', '    dsb_sy();\n}\n\n/* Cleans and invalidates every line', '}\n\n/* Cleans and invalidates every line'),
    sub('no-fence-after-the-invalidate', '    dsb_sy();\n    for (unsigned k = 0; k < PAGES; k++) {\n        const volatile', '    for (unsigned k = 0; k < PAGES; k++) {\n        const volatile'),
    sub('assumes-64-byte-lines', '    uint32_t line = 4u << (cache_type >> 16 & 15u);\n', '    uint32_t line = 64u;\n'),
    sub('line-size-is-eight-times-the-field', '    uint32_t line = 4u << (cache_type >> 16 & 15u);\n', '    uint32_t line = 8u << (cache_type >> 16 & 15u);\n'),
    sub('accepts-any-line-size', '    if ((cache_type >> 16 & 15u) < 2u || (cache_type >> 16 & 15u) > 9u) {\n', '    if (0) {\n'),
    sub('does-not-verify', '    state = verify_pages(cfg.page, crc, line);\n    if (state) {\n', '    state = 0;\n    if (state) {\n'),
    sub('verifies-without-invalidating', CIVAC_LOOP, CIVAC_LOOP.replace('dc_civac(pages[k] + offset)', 'dc_cvac(pages[k] + offset)')),
    sub('verifies-the-crc-over-its-own-word', '        bad += page_crc(p) != crc[k] || p[CRC_WORD] != crc[k];\n', '        bad += p[CRC_WORD] != crc[k];\n'),
    sub('page-crc-counts-its-own-word', 'for (unsigned i = 0; i < PAGE_WORDS; i++) crc = crc32_word(crc, i == CRC_WORD ? 0u : words[i]);',
        'for (unsigned i = 0; i < PAGE_WORDS; i++) crc = crc32_word(crc, words[i]);'),
    sub('new-page-crc-leaves-out-the-body', '    for (unsigned i = 0; i < BODY_WORDS; i++) crc = crc32_word(crc, body_word(counter, slot, i));\n    return ~crc;\n}\n\n/* The state',
        '    return ~crc;\n}\n\n/* The state'),
    # -- the page
    sub('body-pattern-has-no-page-index', '    return counter << 12 | slot << 10 | i;', '    return counter << 12 | i;'),
    sub('body-pattern-counter-shift-is-11', '    return counter << 12 | slot << 10 | i;', '    return counter << 11 | slot << 10 | i;'),
    sub('magic-is-another-word', '#define PAGE_MAGIC_HI 0x31304e41u', '#define PAGE_MAGIC_HI 0x31304e42u'),
    sub('records-the-path-used-as-none', '    stamp.path_used = cfg.path;\n', '    stamp.path_used = 0;\n'),
    sub('forgets-the-flush-method', '    header[14] = s->previous_state[2] | 1u << 8;\n', '    header[14] = s->previous_state[2];\n'),
    sub('swaps-two-previous-states', 's->previous_state[0] << 16 | s->previous_state[1] << 24;', 's->previous_state[1] << 16 | s->previous_state[0] << 24;'),
    sub('timestamp-is-zero', '    stamp.timestamp = a->ops.counter();\n', '    stamp.timestamp = 0;\n'),
    sub('frequency-is-zero', '    stamp.frequency = (uint32_t)SYSREG(cntfrq_el0);\n', '    stamp.frequency = 0;\n'),
    sub('does-not-record-the-extent', '    header[16] = (uint32_t)x->start;\n', '    header[16] = 0;\n'),
    sub('records-the-wrong-feature-answer', '    stamp.feature_reset2 = (uint32_t)answer[1];\n', '    stamp.feature_reset2 = (uint32_t)answer[0];\n'),
    # -- the previous boot's pages, read first
    sub('reads-after-writing', READ_LINE, '        pl_zero(header, sizeof header);\n        page_store(cfg.page[k], header, 1, k);\n' + READ_LINE),
    sub('counter-does-not-advance', '    stamp.counter = highest + 1u;\n', '    stamp.counter = highest;\n'),
    sub('counter-follows-the-lowest-page', '            if (previous[k].counter > highest) highest = previous[k].counter;\n',
        '            if (previous[k].counter < highest) highest = previous[k].counter;\n'),
    sub('counter-follows-a-damaged-page', '            pl_add_dec(a, &p, "BAD_WORDS", previous[k].bad_words);\n',
        '            pl_add_dec(a, &p, "BAD_WORDS", previous[k].bad_words);\n            if (previous[k].counter > highest) highest = previous[k].counter;\n'),
    sub('counter-overflow-is-not-checked', '    if (highest >= COUNTER_MAX) {\n', '    if (0) {\n'),
    sub('does-not-stop-at-an-unreadable-word', '            r->load_word = i;\n            return;\n', '            r->load_word = i;\n'),
    sub('takes-an-unreadable-page-for-none', '            r->state = STATE_UNREADABLE;\n', '            r->state = STATE_NONE;\n'),
    sub('reads-one-word-too-many', '    for (unsigned i = 0; i < PAGE_WORDS; i++) {\n        int32_t error', '    for (unsigned i = 0; i <= PAGE_WORDS; i++) {\n        int32_t error'),
    sub('says-whole-without-the-crc', CLASSIFY_WHOLE, '        r->state = !bad ? STATE_WHOLE : STATE_PARTIAL;\n'),
    sub('says-whole-without-the-body', CLASSIFY_WHOLE, '        r->state = r->crc_ok ? STATE_WHOLE : STATE_PARTIAL;\n'),
    sub('does-not-compare-the-address', 'page[4] == (uint32_t)address && page[5] == (uint32_t)(address >> 32) && ', ''),
    sub('does-not-compare-the-page-index', ' && page[3] == slot &&', ' &&'),
    sub('does-not-compare-the-version', ' && page[2] == LAYOUT_VERSION &&', ' &&'),
    sub('accepts-a-counter-of-zero', 'counter >= 1u && counter <= COUNTER_MAX', 'counter <= COUNTER_MAX'),
    sub('counter-limit-is-one-low', 'counter >= 1u && counter <= COUNTER_MAX', 'counter >= 1u && counter < COUNTER_MAX'),
    sub('needs-seventeen-words-for-partial', 'matches >= MIN_BODY_MATCHES ?', 'matches > MIN_BODY_MATCHES ?'),
    sub('needs-eight-words-for-partial', '#define MIN_BODY_MATCHES 16u', '#define MIN_BODY_MATCHES 8u'),
    sub('filter-keeps-the-low-eleven-bits', '        if ((page[HEADER_WORDS + i] & 0x3ffu) != i) continue;\n', '        if ((page[HEADER_WORDS + i] & 0x7ffu) != i) continue;\n'),
    sub('vote-takes-the-rarest-epoch', 'if (same > agreed || (same == agreed && key < epoch)) {', 'if (same < agreed || !agreed) {'),
    # -- the pages are checked first, all of them
    sub('does-not-check-the-map', '    state = pl_map_check(a);\n    if (state != PL_MAP_OK) {\n', '    if (0) {\n'),
    sub('checks-two-pages-only', '    for (unsigned k = 0; k < PAGES; k++) {\n        state = page_check(', '    for (unsigned k = 0; k < PAGES - 1u; k++) {\n        state = page_check('),
    sub('accepts-any-memory-type', PAGE_TYPE, '        if (d.start > address || d.end < address + PL_PAGE_BYTES) return PAGE_OVERLAPS_OTHER;\n'),
    sub('does-not-need-a-descriptor', '    if (!inside) return PAGE_NOT_IN_MAP;\n', ''),
    drop('ignores-the-payloads-own-ranges', PROTECTED),
    sub('forgets-the-payload-image', PROTECTED, PROTECTED.replace('overlaps(address, PL_PAGE_BYTES, a->payload_base, a->payload_size) || ', '')),
    sub('forgets-the-stack', PROTECTED, PROTECTED.replace('overlaps(address, PL_PAGE_BYTES, a->stack_base, a->stack_size) ||\n       ', '\n       ')),
    sub('forgets-the-preload-table', PROTECTED, PROTECTED.replace('overlaps(address, PL_PAGE_BYTES, a->preload_table, a->preload_size) || ', '')),
    sub('forgets-the-map-buffer', PROTECTED, PROTECTED.replace(' || overlaps(address, PL_PAGE_BYTES, a->map_base, a->map_size)', '')),
    sub('does-not-ask-for-write-permission', '    pl_walk_decode(at_s1e2w(address), address, &written);\n', '    written = *w;\n'),
    drop('does-not-compare-the-two-translations', DIFFER),
    sub('does-not-compare-shareability', DIFFER, DIFFER.replace(' || w->sh != written.sh', '')),
    sub('does-not-compare-attributes', DIFFER, DIFFER.replace(' || w->attr != written.attr', '')),
    drop('does-not-need-write-back', '    if (pl_attr_class(w->attr) != PL_ATTR_WB) return PAGE_NOT_WRITE_BACK;\n'),
    drop('does-not-need-an-identity-map', '    if (!w->ident) return PAGE_NOT_IDENTITY;\n'),
    # -- the configuration
    drop('does-not-check-the-config-crc', '    if (~crc != v[CONFIG_WORDS - 1u]) return CFG_BAD_CRC;\n'),
    sub('config-crc-misses-a-word', '    for (unsigned i = 0; i < CONFIG_WORDS - 1u; i++) crc = crc32_word(crc, v[i]);\n',
        '    for (unsigned i = 0; i < CONFIG_WORDS - 2u; i++) crc = crc32_word(crc, v[i]);\n'),
    drop('does-not-check-the-config-version', '    if (v[2] != LAYOUT_VERSION) return CFG_BAD_VERSION;\n'),
    sub('accepts-a-fourth-path', '    if (v[3] >= PATH_COUNT) return CFG_BAD_PATH;\n', '    if (v[3] > PATH_COUNT) return CFG_BAD_PATH;\n'),
    sub('accepts-a-countdown-of-zero', '    if (v[4] < 1u || v[4] > COUNTDOWN_MAX_S) return CFG_BAD_COUNTDOWN;\n', '    if (v[4] > COUNTDOWN_MAX_S) return CFG_BAD_COUNTDOWN;\n'),
    sub('refuses-a-countdown-of-sixty', '    if (v[4] < 1u || v[4] > COUNTDOWN_MAX_S) return CFG_BAD_COUNTDOWN;\n', '    if (v[4] < 1u || v[4] >= COUNTDOWN_MAX_S) return CFG_BAD_COUNTDOWN;\n'),
    drop('does-not-check-the-page-count', '    if (v[5] != PAGES) return CFG_BAD_PAGE_COUNT;\n'),
    drop('does-not-check-the-reserved-words', '    if (v[12] | v[13] | v[14]) return CFG_RESERVED;\n'),
    drop('does-not-check-page-alignment', '        if (c->page[k] & (PL_PAGE_BYTES - 1u)) return CFG_PAGE_UNALIGNED;\n'),
    sub('accepts-page-zero', '        if (!c->page[k] || c->page[k] > PL_ADDRESS_LIMIT - PL_PAGE_BYTES) return CFG_PAGE_RANGE;\n',
        '        if (c->page[k] > PL_ADDRESS_LIMIT - PL_PAGE_BYTES) return CFG_PAGE_RANGE;\n'),
    sub('accepts-the-same-page-twice', '    if (c->page[0] == c->page[1] || c->page[0] == c->page[2] || c->page[1] == c->page[2]) return CFG_PAGES_NOT_DISTINCT;\n',
        '    if (c->page[0] == c->page[1] || c->page[0] == c->page[2]) return CFG_PAGES_NOT_DISTINCT;\n'),
    sub('finds-the-config-by-half-its-magic', CONFIG_LINE, '        if (w[0] != MAGIC_LO) continue;\n'),
    sub('takes-a-file-of_any-size-for-the-config', ' || e->file.size != CONFIG_BYTES || !e->base', ' || !e->base'),
    sub('does-not-skip-its-own-entry', 'if (e->base == a->payload_base || e->file.size', 'if (e->file.size'),
    sub('takes-the-first-of-two-configs', '        if (found++) return CONFIG_TWO;\n', '        found++;\n'),
    sub('writes-without-a-config', '    if (found != CONFIG_FOUND || state != CFG_OK) {\n        if (found == CONFIG_FOUND) {', '    if (0) {\n        if (found == CONFIG_FOUND) {'),
    sub('goes-on-after-a-refused-config', '            refuse(a, &p, "CONFIG");\n            return RET_CONFIG;\n', '            refuse(a, &p, "CONFIG");\n'),
    # -- the page, the exception level and the arguments
    sub('runs-at-any-el', '    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {\n', '    if (0) {\n'),
    sub('takes-el3-for-el2', '    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {\n', '    if ((SYSREG(CurrentEL) >> 2 & 3) < 2) {\n'),
    sub('does-not-need-the-load-op', '    if (!pl_args_ok(a) || !a->ops.load32 || !a->ops.counter) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
        '    if (!pl_args_ok(a) || !a->ops.counter) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n'),
    drop('never-announces-the-features-query', '    pl_say(a, &p, "NEXT", "FEATURES", 1);\n'),
    sub('says-every-negative-answer-is-implemented', '        pl_text(&item, (int32_t)(uint32_t)x0 >= 0 ? ":IMPLEMENTED" : ":NEGATIVE");\n',
        '        pl_text(&item, ":IMPLEMENTED");\n'),
    sub('names-eight-error-codes-not-nine', '    if (negated - 1u < 9u) {\n', '    if (negated - 1u < 8u) {\n'),
    sub('says-system-reset2-is-implemented-when-it-is-not', '(int32_t)(uint32_t)answer[1] >= 0 ? "SYSTEM_RESET2=YES" : "SYSTEM_RESET2=NO"',
        '(int32_t)(uint32_t)answer[1] >= 0 ? "SYSTEM_RESET2=NO" : "SYSTEM_RESET2=YES"'),
    # -- a counter that ran backwards would read as an endless wait
    drop('does-not-notice-a-counter-running-backwards', '        if (now < start) return 0;\n'),
    # -- the payload stores to its three pages and nowhere else: the world compares every buffer it is given (the preload table, the map, the
    # configuration file) and the rest of the arena after every run, and anything else is unmapped there
    stray('to-the-configuration-file', 'config_base'),
    stray('to-the-preload-table', 'a->preload_table'),
    stray('to-the-memory-map', 'a->map_base'),
    stray('to-the-rest-of-the-extent', 'extent[0].start + 4096u'),
    stray('one-word-below-the-first-page', 'cfg.page[0] - 4u'),
    stray('one-word-above-the-last-page', 'cfg.page[2] + PL_PAGE_BYTES'),
    stray('to-the-payload-image', 'a->payload_base'),
    stray('to-the-stack-it-was-given', 'a->stack_base'),
    stray('into-a-page-after-it-was-verified', 'cfg.page[1] + 64u', VERIFIED),
]


class RetprobeMutants(unittest.TestCase):
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
        self.assertGreaterEqual(len(names), 90)
        self.assertEqual({m[1] for m in MUTANTS}, {FILE})
        for wanted in ('resets-without-the-feature-check', 'does-not-wait', 'no-fence-after-the-clean', 'does-not-verify', 'reads-after-writing',
                       'says-whole-without-the-crc', 'ignores-the-payloads-own-ranges', 'writes-without-a-config', 'stores-one-word-past-the-page',
                       'does-not-check-the-config-crc', 'path-none-goes-on-to-a-reset', 'runs-at-any-el'):
            self.assertIn(f'retprobe-{wanted}', names)

    def test_the_unmutated_control_passes_from_a_copy(self):
        directory = BUILD / 'control'
        native.copy_tree(directory)
        done, binary = self._build('retprobe', directory, relaxed=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary)
        self.assertEqual(code, 0, output[-600:])

    def test_every_seeded_bug_is_caught(self):
        workers = max(1, min(2, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {m[0]: pool.submit(self._evaluate, *m) for m in MUTANTS}
            results = {name: future.result() for name, future in futures.items()}
        for name, (status, detail) in results.items():
            with self.subTest(mutant=name):
                self.assertEqual(status, 'caught', f'{status}: {detail}')


# ---- the binary ------------------------------------------------------------------------------------------------------------

ID_LINE = 'FUNCTION_SYSTEM_RESET '
FEATURES_SMC = ('    register uint64_t x1 __asm__("x1") = feature_asked[which];\n    register uint64_t x2 __asm__("x2") = 0;\n'
                '    register uint64_t x3 __asm__("x3") = 0;\n    __asm__ volatile("smc #0"')
BAD_BINARIES = [
    # (name, [(needle, replacement)], what the allow-list check must say)
    ('an-smc-with-another-immediate', [(FEATURES_SMC, FEATURES_SMC.replace('smc #0', 'smc #1'))], 'immediate'),
    ('an-hvc-instead-of-an-smc', [(FEATURES_SMC, FEATURES_SMC.replace('smc #0', 'hvc #0'))], 'hvc'),
    ('a-reset-with-another-function-id', [('#define FUNCTION_SYSTEM_RESET 0x84000009u', '#define FUNCTION_SYSTEM_RESET 0x84000008u')], 'smc function ids'),
    ('a-features-call-for-another-function', [('#define FUNCTION_PSCI_FEATURES 0x8400000Au', '#define FUNCTION_PSCI_FEATURES 0xC4000003u')], 'smc function ids'),
    ('a-cpu-on-in-the-reset-helper', [('#define FUNCTION_SYSTEM_RESET2 0xC4000012u', '#define FUNCTION_SYSTEM_RESET2 0xC4000003u')], 'smc function ids'),
    ('a-fourth-smc', [('    pl_zero(&cfg, sizeof cfg);\n', '    pl_zero(&cfg, sizeof cfg);\n    __asm__ volatile("smc #0" ::: "memory");\n')], 'smc'),
    ('a-write-to-a-system-register', ecv.asm('msr daifset, #2'), 'msr'),
    ('a-write-to-vbar-el2', ecv.asm('msr vbar_el2, xzr'), 'msr'),
    ('a-read-of-cntvoff-el2', ecv.read('cntvoff_el2'), 'the code names'),
    ('a-read-of-cntpoff-el2', ecv.read('S3_4_C14_C0_6'), 'the code names'),
    ('a-read-of-another-register', ecv.read('midr_el1'), 'registers read'),
    ('an-eret', ecv.asm('eret'), 'eret'),
    ('a-wfe', ecv.asm('wfe'), 'wfe'),
    ('a-tlb-operation', ecv.asm('tlbi alle2'), 'tlbi'),
    ('an-instruction-cache-operation', ecv.asm('ic iallu'), 'ic'),
    ('a-cache-invalidate-without-clean', ecv.asm('dc ivac, x0'), 'forbidden instruction dc'),
    ('a-cache-zero', ecv.asm('dc zva, x0'), 'forbidden instruction dc'),
    ('a-translation-of-another-kind', ecv.asm('at s1e1r, x0'), 'forbidden instruction at'),
    ('a-dmb', ecv.asm('dmb sy'), 'dmb'),
    ('an-exclusive-load', ecv.asm('ldxr x9, [sp]'), 'ldxr'),
    ('a-word-that-is-no-instruction', ecv.asm('.inst 0xffffffff'), 'not a known instruction'),
]


class RetprobeBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.out = BUILD / 'bad-binaries'
        cls.builder = Builder(cls.out)
        done, cls.elf, cls.flat = cls.builder.build('retprobe', 'control', [], check=True)
        if done.returncode:
            raise RuntimeError(done.stderr[-1500:])

    def test_the_unmodified_payload_is_clean_and_fits_the_policy(self):
        policy = lib.POLICIES['retprobe']
        self.assertEqual(lib.binary_violations(self.elf, self.flat, policy, READELF()), [])
        self.assertEqual(policy['smc'], 3)
        self.assertEqual(policy['allow'], {'at': {'s1e2r', 's1e2w'}, 'dc': {'cvac', 'civac'}})
        self.assertNotIn('dsb', policy['forbid'])
        self.assertNotIn('isb', policy['forbid'])
        self.assertFalse({'read_only', 'bulk_reads', 'single_reads', 'timer_offsets'} & set(policy))
        self.assertLessEqual(Path(self.flat).stat().st_size, policy['bytes'])

    def test_the_instruction_inventory_is_what_the_document_says(self):
        f = facts(self.elf, self.flat)
        self.assertEqual(set(f['mrs']), lib.POLICIES['retprobe']['registers'])
        self.assertEqual(len(f['smc']), 3)
        self.assertEqual(dict(f['dc']), {'cvac': 1, 'civac': 1})
        self.assertEqual((f['mnemonics']['at'], f['mnemonics']['dsb'], f['mnemonics']['isb']), (2, 1, 2))
        for mnemonic in ('msr', 'hvc', 'svc', 'eret', 'wfi', 'wfe', 'sev', 'sevl', 'dmb', 'sb', 'tlbi', 'ic', 'sys', 'sysl', 'brk', 'hlt'):
            self.assertEqual(f['mnemonics'][mnemonic], 0, mnemonic)
        self.assertFalse([m for m in f['mnemonics'] if re.match(r'^(ldx|ldax|stx|stlx|cas|swp|ldadd|ldset|ldclr|ldeor)', m)])
        ids, unreadable = lib.smc_function_ids(lib.run(['llvm-objdump', '-d', '--no-show-raw-insn', str(self.elf)]).stdout)
        self.assertEqual((sorted(ids), unreadable), (sorted(lib.POLICIES['retprobe']['smc_ids']), []))

    def test_every_forbidden_addition_is_named_by_the_allow_list_check(self):
        self.assertGreaterEqual(len(BAD_BINARIES), 20)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            built = list(pool.map(lambda b: (b, self.builder.build('retprobe', b[0], b[1])), BAD_BINARIES))
        for (name, _, expected), (done, elf, flat) in built:
            with self.subTest(binary=name):
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                problems = lib.binary_violations(elf, flat, lib.POLICIES['retprobe'], READELF())
                self.assertTrue(problems, 'the check passed a binary it must refuse')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_a_flat_binary_patched_behind_the_disassembly_is_caught_by_the_encoding_layer_alone(self):
        data = bytearray(Path(self.flat).read_bytes())
        words = struct.unpack(f'<{len(data) // 4}I', bytes(data[:len(data) // 4 * 4]))
        policy = lib.POLICIES['retprobe']
        isb, dsb = 0xd5033fdf, 0xd5033f9f
        wanted = (
            ('dsb to dmb', lambda w: w == dsb, lambda w: 0xd5033fbf, 'dmb'),
            ('isb to wfe', lambda w: w == isb, lambda w: 0xd503205f, 'wfe'),
            ('isb to eret', lambda w: w == isb, lambda w: 0xd69f03e0, 'eret'),
            ('isb to hvc', lambda w: w == isb, lambda w: 0xd4000002, 'hvc'),
            ('isb to svc', lambda w: w == isb, lambda w: 0xd4000001, 'svc'),
            ('dsb to a fourth smc', lambda w: w == dsb, lambda w: 0xd4000003, 'smc'),
            ('dc cvac to dc ivac', lambda w: w & 0xffffffe0 == 0xd50b7a20, lambda w: 0xd5087620 | w & 31, 'sys'),
            ('dc cvac to dc zva', lambda w: w & 0xffffffe0 == 0xd50b7a20, lambda w: 0xd50b7420 | w & 31, 'sys'),
            ('at s1e2w to at s1e1w', lambda w: w & 0xffffffe0 == 0xd50c7820, lambda w: 0xd5087820 | w & 31, 'sys'),
        )
        for label, is_target, patch, what in wanted:
            with self.subTest(patch=label):
                at = next(i for i, w in enumerate(words) if is_target(w))
                patched = bytearray(data)
                struct.pack_into('<I', patched, at * 4, patch(words[at]))
                path = self.out / 'patched.bin'
                path.write_bytes(patched)
                problems = lib.binary_violations(self.elf, path, policy, READELF())
                expected = 'words of the code encode smc' if what == 'smc' else f'a word of the code encodes {what}'
                self.assertTrue(any(expected in p for p in problems), problems)

    def test_the_binary_is_refused_under_every_other_policy_and_the_others_under_its_own(self):
        others = [name for name in lib.POLICIES if name != 'retprobe']
        self.assertGreaterEqual(len(others), 9)
        for other in others:
            with self.subTest(policy=other):
                self.assertTrue(lib.binary_violations(self.elf, self.flat, lib.POLICIES[other], READELF()))
        out = BUILD / 'others'
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        for other in others:
            with self.subTest(payload=other):
                done, o_elf, o_flat = lib.build_payload(ROOT / 'payloads' / f'{other}.c', out, name=other, check=False)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertTrue(lib.binary_violations(o_elf, o_flat, lib.POLICIES['retprobe'], READELF()),
                                f'{other} passes the retprobe policy: the policy is too loose')

    def test_the_new_instruction_forms_are_allowed_to_retprobe_and_the_cache_clean_to_no_other_payload(self):
        self.assertEqual([name for name, policy in lib.POLICIES.items() if 'cvac' in policy.get('allow', {}).get('dc', ())], ['retprobe'])
        self.assertEqual([name for name, policy in lib.POLICIES.items() if 's1e2w' in policy.get('allow', {}).get('at', ())], ['retprobe'])
        self.assertEqual(lib.ALLOW_WORDS[('dc', 'cvac')], ('sys', 0xffffffe0, 0xd50b7a20))
        self.assertEqual(lib.ALLOW_WORDS[('at', 's1e2w')], ('sys', 0xffffffe0, 0xd50c7820))
        self.assertEqual([name for name, policy in lib.POLICIES.items() if 0xC4000012 in policy.get('smc_ids', ())], ['retprobe'])

    def test_two_builds_from_the_same_tree_are_byte_identical(self):
        done, _, flat = Builder(BUILD / 'again').build('retprobe', 'control', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(Path(flat).read_bytes(), Path(self.flat).read_bytes())
        self.assertEqual(Path(self.flat).read_bytes()[:4], bytes.fromhex('5f2403d5'), 'BTI c first, as the runner expects')


class RetprobeStick(unittest.TestCase):
    tool = ROOT / 'tools' / 'sp11_payload_manifest.py'

    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.out = BUILD / 'stick-payloads'
        shutil.rmtree(cls.out, ignore_errors=True)
        done = run(['make', '-f', 'platform/uefi/Makefile', f'OUT={cls.out.relative_to(ROOT)}', 'payloads'])
        if done.returncode:
            raise RuntimeError('make payloads failed:\n' + done.stdout[-1500:] + done.stderr[-1500:])
        cls.bin = cls.out / 'payloads' / 'retprobe.bin'
        cls.psci = cls.out / 'payloads' / 'psci.bin'
        cls.config = BUILD / 'retpath.dat'
        cls.config.write_bytes(config_bytes(1, 8, (0x9C000000, 0xF8400000, 0xFFFF00000)))

    def stick(self, files):
        base = BUILD / 'stick' / '-'.join(Path(f).stem for f in files)
        shutil.rmtree(base, ignore_errors=True)
        done = run(['python3', '-B', str(self.tool), '--out-dir', str(base)] + [str(f) for f in files])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        return base, done

    def entries(self, base):
        raw = (base / 'SP11' / 'PAYLOAD.MAN').read_bytes()
        magic, version, count, size = struct.unpack_from('<4Q', raw)
        self.assertEqual(magic, int.from_bytes(b'Q1N1PLD1', 'little'))
        return [struct.unpack_from('<Q32s256s', raw, 32 + i * size) for i in range(count)]

    def test_the_payload_and_its_configuration_are_a_payload_and_a_data_file_on_the_stick(self):
        base, done = self.stick((self.bin, self.config))
        entries = self.entries(base)
        self.assertEqual([e[2].rstrip(b'\0').decode() for e in entries], ['\\SP11\\RETPROBE.BIN', '\\SP11\\RETPATH.DAT'])
        for entry, path in zip(entries, (self.bin, self.config)):
            data = path.read_bytes()
            self.assertEqual((entry[0], entry[1]), (len(data), hashlib.sha256(data).digest()))
        self.assertEqual(sorted(p.name for p in (base / 'SP11').iterdir()), ['PAYLOAD.MAN', 'RETPATH.DAT', 'RETPROBE.BIN'])
        self.assertEqual(len(self.config.read_bytes()), 64)
        self.assertIn('(INDEX=0, payload, called in manifest order)', done.stdout)

    def test_the_runners_own_validator_and_loader_take_the_pair_and_the_payload_alone(self):
        harness = BUILD / 'kinds-harness'
        sources = [ROOT / 'tools' / 'testdata' / 'sp11-payload-kinds-harness.c'] + [
            native.UEFI / name for name in ('sp11-payload-load.c', 'sp11-payload-plan.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c')]
        done = run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1',
                    '-I', str(native.UEFI)] + [str(s) for s in sources] + ['-o', str(harness)])
        self.assertEqual(done.returncode, 0, done.stderr)
        for files, expected in (((self.bin,), ['\\SP11\\RETPROBE.BIN code']),
                                ((self.bin, self.config), ['\\SP11\\RETPROBE.BIN code', '\\SP11\\RETPATH.DAT data']),
                                ((self.psci, self.bin, self.config), ['\\SP11\\PSCI.BIN code', '\\SP11\\RETPROBE.BIN code', '\\SP11\\RETPATH.DAT data'])):
            with self.subTest(files=[Path(f).name for f in files]):
                base, _ = self.stick(files)
                ours = run([str(harness), str(base / 'SP11' / 'PAYLOAD.MAN')])
                self.assertEqual(ours.returncode, 0, ours.stdout + ours.stderr)
                self.assertEqual(ours.stdout.splitlines(), expected)

    def test_the_binary_is_a_few_kilobytes_and_one_range_is_declared_whatever_its_size(self):
        self.assertLessEqual(self.bin.stat().st_size, lib.POLICIES['retprobe']['bytes'])
        self.assertGreater(self.bin.stat().st_size, 4096)


def facts_main():
    need_tools()
    done, elf, flat = Builder(BUILD / 'facts').build('retprobe', 'retprobe', [], check=True)
    if done.returncode:
        sys.exit(done.stderr)
    f = facts(elf, flat)
    print(f'retprobe.bin: {f["bytes"]} bytes, sha256 {f["sha256"]}, {f["instructions"]} instructions')
    print('mnemonics:', ', '.join(f'{m} {n}' for m, n in sorted(f['mnemonics'].items())))
    print('registers read:', ', '.join(f'{r} x{n}' for r, n in sorted(f['mrs'].items())))
    print('dc operands:', dict(f['dc']), 'smc:', len(f['smc']))
    print('allow-list violations:', lib.binary_violations(elf, flat, lib.POLICIES['retprobe'], READELF()))


if __name__ == '__main__':
    if sys.argv[1:] == ['facts']:
        facts_main()
    else:
        sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
