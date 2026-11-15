#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The hashbig payload of the Surface Pro 11 stick payload runner (docs/SP11-PAYLOAD-HASHBIG.md): its host test, SHA-256 against Python's
hashlib, its seeded bugs and the allow-list of its binary. The documents are checked by tools/test-q1n1-sp11-payload-mmu-doc.py, the QEMU
run is tools/test-q1n1-sp11-payload-qemu-el2mem.py.

    python3 tools/test-q1n1-sp11-payload-hashbig.py

  * HashbigNative: tools/test-q1n1-sp11-payload-hashbig.c (twelve suites: the FIPS 180-4 vectors, every block-boundary size against the
    runner's own sha256.c, the page, which file is picked, every refusal of the table, the extent, the map and the arguments with the
    file's memory made PROT_NONE where nothing may be read, Device and non-cacheable and unmapped pages, a corrupted file, the 25 s time
    box, a counter that stands still or goes back, random worlds), built and run under ASan and UBSan.
  * HashbigSha: the payload's own SHA-256 code against hashlib on random sizes and contents, and at the staged size, 144 MiB.
  * HashbigSource: what no run shows (ops, registers, no libc call, the one function that reads the file in place).
  * HashbigMutants: seeded bugs in hashbig.c and payload-sha256.h, each of which the host program must reject.
  * HashbigBinary: the allow-list on hashbig.bin (MRS of CurrentEL, CNTFRQ_EL0 and PAR_EL1, exactly AT S1E2R, stores only through the stack,
    loads through any base only in two named functions) with seeded bad binaries, and the build's reproducibility.

Writes only under build/. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
import hashlib
import os
import re
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_mmu_testkit as kit  # noqa: E402
import sp11_payload_memcheck as memcheck  # noqa: E402
import sp11_payload_testlib as lib  # noqa: E402

native = kit.native_module('hashbig')
BUILD = native.BUILD
SOURCE = ROOT / 'payloads' / 'hashbig.c'
run, have, READELF = lib.run, lib.have, kit.READELF
SUITES = ('vectors', 'sizes', 'normal', 'choice', 'table', 'extent', 'attr', 'differ', 'clock', 'gates', 'map', 'fuzz')


class HashbigNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_the_hashbig_suites_pass(self):
        native.Native._check(self, 'hashbig')

    def test_each_suite_runs_alone(self):
        done, binary = native.build_program('hashbig', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        for suite in SUITES:
            with self.subTest(suite=suite):
                code, output = native.run_program(binary, suite)
                self.assertEqual(code, 0, output)
                self.assertRegex(output, r'PASS: 1 payload hashbig suites, \d+ checks')

    def test_the_most_lines_are_measured_and_within_the_budget_of_twelve(self):
        done, binary = native.build_program('hashbig', native.UEFI, native.PAYLOADS, BUILD / 'native')
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary, 'lines-report')
        self.assertEqual(code, 0, output)
        self.assertRegex(output, r'^LINES_MAX=[1-9]\d?\n$')
        self.assertLessEqual(int(output.split('=')[1]), 12)


class HashbigSha(unittest.TestCase):
    """The payload's SHA-256 against hashlib: the host program hashes a file through the payload, with the digest hashlib made as the
    runner's, and must say MATCH."""
    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)
        done, cls.binary = native.build_program('hashbig', native.UEFI, native.PAYLOADS, BUILD / 'native')
        if done.returncode:
            raise RuntimeError(done.stderr)
        cls.work = BUILD / 'files'
        cls.work.mkdir(parents=True, exist_ok=True)

    def through_the_payload(self, data, name, digest=None, step=1000000):
        path = self.work / name
        path.write_bytes(data)
        code, output = native.run_program(self.binary, 'sha', str(path), digest or hashlib.sha256(data).hexdigest(), str(step))
        path.unlink()
        return code, output

    def test_random_sizes_and_contents_agree_with_hashlib(self):
        sizes = [1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 4095, 4096, 4097, 65535, 65536, 65537, 1000003]
        generator = hashlib.sha256(b'hashbig').digest()
        for i in range(24):
            generator = hashlib.sha256(generator).digest()
            sizes.append(1 + int.from_bytes(generator[:3], 'little') % 400000)
        for size in sizes:
            with self.subTest(size=size):
                data = hashlib.shake_256(f'{size}'.encode()).digest(size)
                code, output = self.through_the_payload(data, f'r{size}.bin')
                self.assertEqual(code, 0, output)
                self.assertIn('RETURN=0', output)
                self.assertIn(f'PAYLOAD HASHBIG DIGEST {hashlib.sha256(data).hexdigest()[:16].upper()} MATCH', output)

    def test_a_wrong_digest_is_a_difference_and_a_changed_byte_is_too(self):
        data = hashlib.shake_256(b'x').digest(100000)
        code, output = self.through_the_payload(data, 'wrong.bin', digest=hashlib.sha256(data + b'!').hexdigest())
        self.assertNotEqual(code, 0)
        self.assertIn('DIFFER WANT=', output)
        self.assertIn(f'DIGEST {hashlib.sha256(data).hexdigest()[:16].upper()} DIFFER', output)
        changed = bytearray(data)
        changed[50000] ^= 1
        code, output = self.through_the_payload(bytes(changed), 'changed.bin', digest=hashlib.sha256(data).hexdigest())
        self.assertNotEqual(code, 0)
        self.assertIn('DIFFER', output)

    def test_the_staged_size_of_144_mib_matches_hashlib_and_is_reported_as_150994944_bytes(self):
        size = 150994944
        data = os.urandom(size)
        code, output = self.through_the_payload(data, 'big.dat', step=1000)
        self.assertEqual(code, 0, output[-600:])
        self.assertIn('PAYLOAD HASHBIG FILE INDEX=2 BASE=0X', output)
        self.assertIn('BYTES=150994944 MIB=144', output)
        self.assertIn(f'PAYLOAD HASHBIG DIGEST {hashlib.sha256(data).hexdigest()[:16].upper()} MATCH', output)
        self.assertIn('PAYLOAD HASHBIG HASH BYTES=150994944 TICKS=', output)
        self.assertNotIn('TIMEBOX', output)


class HashbigSource(unittest.TestCase):
    code = kit.code_of(SOURCE)
    sha = kit.code_of(ROOT / 'payloads' / 'payload-sha256.h')
    header = kit.code_of(ROOT / 'payloads' / 'payload-mmu.h')

    def test_the_payload_calls_only_the_counter_op_and_the_helpers_puts_and_hex(self):
        self.assertEqual(set(re.findall(r'ops\.(\w+)', self.code)), {'counter'}, 'never load32: the file is read in place')
        helpers = kit.code_of(ROOT / 'payloads' / 'payload-util.h') + kit.code_of(ROOT / 'payloads' / 'payload-page.h')
        self.assertEqual(set(re.findall(r'ops\.(\w+)', helpers + self.header + self.sha)), {'puts', 'hex'})

    def test_the_registers_it_names_are_the_policys(self):
        named = {name.lower() for name in re.findall(r'SYSREG\((\w+)\)', self.code)} - {'name'}
        self.assertEqual(named | {'par_el1'}, lib.POLICIES['hashbig']['registers'])

    def test_no_libc_no_writable_global_and_the_constants_are_integers_in_rodata(self):
        for text in (self.code, self.sha):
            for declaration in re.findall(r'^static\b[^\n(]*;', text, re.M):
                self.assertRegex(declaration, r'\bconst\b|\binline\b|typedef', declaration)
        self.assertNotRegex(self.code + self.sha, r'\b(memcpy|memset|memcmp|strlen|malloc)\b')
        self.assertEqual(len(re.findall(r'0x[0-9a-f]{8}u', self.sha)), 64 + 8, '64 round constants and 8 initial words')
        self.assertIn('static const uint32_t pl_sha256_k[64]', self.sha)

    def test_the_file_is_read_in_two_functions_only_and_never_written(self):
        self.assertEqual(len(re.findall(r'\bpl_sha256_blocks\(', self.code)), 1)
        self.assertEqual(len(re.findall(r'\bcopy_tail\(', self.code)) - 1, 1)
        self.assertEqual(len(re.findall(r'\bvolatile\b', self.code)), 1, 'only the MRS macro')
        self.assertNotIn('volatile', self.sha)
        self.assertIn('base page aligned', SOURCE.read_text(encoding='utf-8'))

    def test_the_files_are_within_the_size_limits_and_carry_the_licence(self):
        for path in (SOURCE, ROOT / 'payloads' / 'payload-sha256.h', ROOT / 'tools' / 'test-q1n1-sp11-payload-hashbig.c', Path(__file__)):
            with self.subTest(file=path.name):
                text = path.read_text(encoding='utf-8')
                self.assertLess(len(text.splitlines()), 1500)
                self.assertLess(len(text.encode('utf-8')), 50 * 1024)
                self.assertIn('SPDX-License-Identifier: MIT', text[:200])

    def test_the_text_it_prints_is_in_the_page_font(self):
        for literal in re.findall(r'"([^"\n]*)"', self.code):
            if literal.endswith('.h') or re.search(r'%|\\n|mrs ', literal) or literal in ('=r', 'r', 'memory') or literal.startswith('\\'):
                continue
            self.assertRegex(literal, r'^[A-Z0-9:\-./=?()_ ]*$', literal)


FILE = 'payloads/hashbig.c'
SHA = 'payloads/payload-sha256.h'


def sub(name, old, new, file=FILE):
    return kit.mutant('hashbig', name, file, old, new)


MUTANTS = [
    # -- SHA-256
    sub('a-round-constant-is-wrong', '0x428a2f98u,', '0x428a2f99u,', SHA),
    sub('the-initial-value-is-wrong', 's->h[0] = 0x6a09e667u;', 's->h[0] = 0x6a09e668u;', SHA),
    sub('a-rotation-is-wrong', 'pl_sha256_ror(e, 6)', 'pl_sha256_ror(e, 7)', SHA),
    sub('the-other-rotation-is-wrong', 'pl_sha256_ror(a, 22)', 'pl_sha256_ror(a, 21)', SHA),
    sub('the-schedule-reads-the-wrong-word', 'w[(i + 14) & 15]', 'w[(i + 13) & 15]', SHA),
    sub('the-length-is-written-wrong', 'block[used - 1 - i] = (uint8_t)(bits >> (8 * i));', 'block[used - 1 - i] = (uint8_t)(bits >> (7 * i));', SHA),
    sub('a-56-byte-tail-gets-one-block', 'unsigned used = tail_len < 56 ? 64 : 128;', 'unsigned used = tail_len <= 56 ? 64 : 128;', SHA),
    sub('the-one-bit-is-missing', 'block[tail_len] = 0x80;', 'block[tail_len] = 0x00;', SHA),
    sub('the-words-are-read-little-endian', 'wi = __builtin_bswap32(((const pl_sha256_word *)p)[i]);', 'wi = ((const pl_sha256_word *)p)[i];', SHA),
    sub('the-digest-is-written-little-endian', 'out[4 * i] = (uint8_t)(s->h[i] >> 24);', 'out[4 * i] = (uint8_t)(s->h[i] >> 16);', SHA),
    sub('the-last-word-adds-the-wrong-register', 's->h[7] += h;', 's->h[7] += g;', SHA),
    sub('a-block-is-63-bytes', '        p += 64;\n', '        p += 63;\n', SHA),
    # -- reading the file
    sub('the-tail-reads-one-byte-too-many', 'for (uint32_t i = 0; i < bytes; i++) block[i] = from[i];', 'for (uint32_t i = 0; i <= bytes; i++) block[i] = from[i];'),
    sub('the-tail-starts-one-byte-late', 'copy_tail(block, p + blocks * 64, (uint32_t)(size % 64));', 'copy_tail(block, p + blocks * 64 + 1, (uint32_t)(size % 64));'),
    sub('the-tail-is-size-mod-63', 'pl_sha256_finish(&state, block, (uint32_t)(size % 64), size, r->digest);', 'pl_sha256_finish(&state, block, (uint32_t)(size % 63), size, r->digest);'),
    sub('a-partial-block-is-hashed-whole', 'uint64_t blocks = size / 64, done = 0, limit = TIME_BOX_S * freq;', 'uint64_t blocks = (size + 63) / 64, done = 0, limit = TIME_BOX_S * freq;'),
    sub('a-step-skips-a-block', 'pl_sha256_blocks(&state, p + done * 64, n);', 'pl_sha256_blocks(&state, p + (done + 1) * 64, n);'),
    # -- the clock
    sub('the-time-box-is-ignored', 'if (now < start || now - start >= limit) {', 'if (now < start) {'),
    sub('the-time-box-is-nothing', '#define TIME_BOX_S 25u', '#define TIME_BOX_S 0u'),
    sub('a-stuck-counter-is-never-noticed', 'if (++same >= STUCK_CHECKS) {', 'if (0) {'),
    sub('a-stuck-counter-is-noticed-at-once', '#define STUCK_CHECKS 256u', '#define STUCK_CHECKS 1u'),
    sub('a-rate-is-made-from-no-ticks', 'if (!r->ticks || r->ticks >= TICKS_SHOWN_MAX) {', 'if (r->ticks >= TICKS_SHOWN_MAX) {'),
    sub('the-rate-forgets-the-megabyte', 'pl_add_dec(a, p, "MIBS", r->hashed * freq / (r->ticks * MIB));', 'pl_add_dec(a, p, "MIBS", r->hashed * freq / r->ticks);'),
    sub('a-frequency-of-zero-is-used', 'if (freq < COUNTER_HZ_MIN || freq > COUNTER_HZ_MAX) freq = COUNTER_HZ_DEFAULT;', ''),
    sub('the-counter-op-is-not-required', 'if (!pl_args_ok(a) || !a->ops.counter) return Q1N1_PAYLOAD_RET_BAD_ARGS;', 'if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;'),
    # -- the verdict
    sub('only-eight-bytes-of-the-digest-are-compared', 'for (unsigned i = 0; i < 32; i++) different |= digest[i] ^ e->file.sha256[i];',
        'for (unsigned i = 0; i < 8; i++) different |= digest[i] ^ e->file.sha256[i];'),
    sub('every-digest-matches', 'return !different;', 'return 1;'),
    sub('a-difference-returns-zero', 'rc = match ? RET_OK : RET_DIFFER;', 'rc = RET_OK;'),
    # -- the extent
    sub('boot-services-data-is-allocated-memory', '(d.type == PL_EFI_LOADER_CODE || d.type == PL_EFI_LOADER_DATA)',
        '(d.type == PL_EFI_LOADER_CODE || d.type == PL_EFI_LOADER_DATA || d.type == 4)'),
    sub('an-unaligned-base-is-accepted', 'if (base & (PL_PAGE_BYTES - 1)) return EXTENT_ALIGN;', ''),
    sub('a-file-over-256-mib-is-accepted', 'if (!size || size > FILE_BYTES_MAX) return EXTENT_SIZE;', 'if (!size) return EXTENT_SIZE;'),
    sub('a-wrapping-extent-is-accepted', 'if (base >= PL_ADDRESS_LIMIT || size > PL_ADDRESS_LIMIT - base) return EXTENT_WRAPS;', ''),
    sub('the-last-page-is-not-checked', 'end = base + size;', 'end = base + size - PL_PAGE_BYTES;'),
    sub('the-descriptors-are-not-counted', '        (*segments)++;\n', ''),
    sub('only-the-first-page-must-be-mapped', '*mapped = first.mapped && middle.mapped && last.mapped;', '*mapped = first.mapped;'),
    sub('the-middle-page-is-a-third-of-the-way', '(last_page - f->base) / 2 &', '(last_page - f->base) / 3 &'),
    # -- the table and the choice
    sub('the-magic-is-not-checked', 't->magic != Q1N1_CACHE_MAGIC || ', ''),
    sub('the-count-is-not-checked-against-the-size', ' || 32u + t->count * sizeof(struct q1n1_cached_file) > a->preload_size', ''),
    sub('the-payload-itself-may-be-hashed', 'e->base == a->payload_base || ', ''),
    sub('a-payload-name-may-be-hashed', ' || path_is_payload(e->file.path)) continue;', ') continue;'),
    sub('the-smallest-file-is-chosen', 'if (!found || e->file.size > f->size) {', 'if (!found || e->file.size < f->size) {'),
    sub('the-last-of-equals-is-chosen', 'if (!found || e->file.size > f->size) {', 'if (!found || e->file.size >= f->size) {'),
    sub('the-suffix-is-case-sensitive', "(path[length - 3] | 32) == 'b'", "path[length - 3] == 'B'"),
    sub('a-bare-dot-bin-is-a-payload', 'if (length - name < 5) return 0;', 'if (length - name < 4) return 0;'),
    sub('it-runs-below-el2', 'if ((current_el >> 2 & 3) != 2) {', 'if (0) {'),
    sub('the-map-is-not-checked', 'code = pl_map_check(a);', 'code = PL_MAP_OK;'),
]


class HashbigMutants(unittest.TestCase):
    _build = staticmethod(native.Mutants._build)

    @classmethod
    def setUpClass(cls):
        if not have('clang'):
            raise unittest.SkipTest('clang not installed')
        BUILD.mkdir(parents=True, exist_ok=True)

    def test_there_are_enough_distinct_mutants_and_every_file_has_one(self):
        names = [m[0] for m in MUTANTS]
        self.assertEqual(len(set(names)), len(names))
        self.assertGreaterEqual(len(names), 40)
        self.assertEqual({m[1] for m in MUTANTS}, {FILE, SHA})

    def test_the_unmutated_control_passes_from_a_copy(self):
        directory = BUILD / 'control'
        native.copy_tree(directory)
        done, binary = native.Mutants._build('hashbig', directory, False)
        self.assertEqual(done.returncode, 0, done.stderr)
        code, output = native.run_program(binary)
        self.assertEqual(code, 0, output[-600:])

    def test_every_seeded_bug_is_caught(self):
        kit.run_mutants(native, MUTANTS, self)


ANCHOR = '    pl_page_open(&p, "START", 0);\n'
TAIL = 'OUT_OF_LINE void copy_tail(uint8_t *block, const uint8_t *from, uint32_t bytes)\n{\n'
TABLE = '    uint64_t found = 0;\n'


def after(anchor, text):
    return [(anchor, anchor + text)]


BAD_BINARIES = [
    ('an-msr', after(ANCHOR, '    __asm__ volatile("msr daifset, #2" ::: "memory");\n'), 'msr'),
    ('a-dc', after(ANCHOR, '    __asm__ volatile("dc civac, %0" :: "r"(a) : "memory");\n'), 'dc'),
    ('a-tlbi', after(ANCHOR, '    __asm__ volatile("tlbi vmalle1" ::: "memory");\n'), 'tlbi'),
    ('at-s1e2w', after(ANCHOR, '    __asm__ volatile("at s1e2w, %0" :: "r"(a) : "memory");\n'), 'forbidden instruction at s1e2w'),
    ('at-s12e1r', after(ANCHOR, '    __asm__ volatile("at s12e1r, %0" :: "r"(a) : "memory");\n'), 'forbidden instruction at s12e1r'),
    ('an-smc', after(ANCHOR, '    __asm__ volatile("smc #0" ::: "memory");\n'), 'smc'),
    ('a-dsb', after(ANCHOR, '    __asm__ volatile("dsb sy" ::: "memory");\n'), 'dsb'),
    ('an-exclusive-load', after(ANCHOR, '    __asm__ volatile("ldxr x9, [sp]" ::: "x9", "memory");\n'), 'ldxr'),
    ('a-read-of-cntpoff-el2', after(ANCHOR, '    (void)SYSREG(S3_4_C14_C0_6);\n'), 'the code names'),
    ('a-read-of-another-register', after(ANCHOR, '    (void)SYSREG(midr_el1);\n'), 'registers read'),
    ('a-store-into-the-file', after(TAIL, '    ((uint8_t *)(uintptr_t)from)[0] = 0;\n'), 'a store in copy_tail'),
    ('a-store-through-the-table', after(TABLE, '    ((struct q1n1_preload_cache *)(uintptr_t)a->preload_table)->count = 0;\n'), 'a store in find_file'),
    ('a-store-through-the-map-pointer', after(ANCHOR, '    *(volatile uint64_t *)(uintptr_t)a->map_base = 0;\n'), 'a store in payload_entry'),
]


class HashbigBinary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        kit.need_tools(cls)
        cls.out = BUILD / 'binary'
        shutil.rmtree(cls.out, ignore_errors=True)
        cls.builder = kit.Builder(cls.out)
        done, cls.elf, cls.flat = cls.builder.build('hashbig', 'hashbig', [], check=True)
        if done.returncode:
            raise RuntimeError('hashbig did not build:\n' + done.stderr[-1500:])
        cls.facts = kit.facts(cls.elf, cls.flat)
        cls.dis = run(['llvm-objdump', '-d', '--no-show-raw-insn', str(cls.elf)]).stdout

    def test_the_binary_holds_only_what_its_policy_allows(self):
        self.assertEqual(lib.binary_violations(self.elf, self.flat, lib.POLICIES['hashbig'], READELF()), [])

    def test_one_at_one_isb_and_one_read_each_of_three_registers(self):
        f = self.facts
        self.assertEqual((f['mnemonics']['at'], f['mnemonics']['isb']), (1, 1))
        self.assertEqual(f['mrs'], {'currentel': 1, 'cntfrq_el0': 1, 'par_el1': 1})
        for banned in ('msr', 'dc', 'ic', 'tlbi', 'smc', 'hvc', 'svc', 'eret', 'wfe', 'wfi', 'sys', 'dsb', 'dmb'):
            self.assertNotIn(banned, f['mnemonics'])
        self.assertLessEqual(f['bytes'], lib.POLICIES['hashbig']['bytes'])

    def test_loads_through_any_base_are_in_two_functions_only_and_nothing_stores_but_through_the_stack(self):
        problems, loads, stores = memcheck.analyse(self.dis)
        self.assertEqual(problems, [])
        self.assertEqual({item[5] for item in stores} - {memcheck.STACK, memcheck.CALLER}, set(), 'a store through something other than the stack')
        self.assertEqual({item[0] for item in loads if item[5] not in memcheck.POINTERS}, {'pl_sha256_blocks', 'copy_tail'})
        refused = memcheck.memory_violations(self.dis, dict(lib.POLICIES['hashbig'], bulk_reads=False))
        self.assertEqual(len(refused), 2, refused)
        self.assertTrue(all('(the policy has no bulk_reads)' in line for line in refused))
        self.assertEqual({re.search(r'a load in (\w+)', line).group(1) for line in refused}, {'pl_sha256_blocks', 'copy_tail'})

    def test_no_library_call_is_left_to_resolve(self):
        self.assertNotRegex(self.dis, r'<(memcpy|memset|memmove|memcmp|strlen)>')

    def test_seeded_bad_binaries_are_each_refused_for_the_right_reason(self):
        for name, edits, expected in BAD_BINARIES:
            with self.subTest(binary=name):
                done, elf, flat = self.builder.build('hashbig', name, edits)
                self.assertEqual(done.returncode, 0, f'{name} did not build: {done.stderr[-500:]}')
                problems = lib.binary_violations(elf, flat, lib.POLICIES['hashbig'], READELF())
                self.assertTrue(problems, 'the check passed a binary it must refuse')
                self.assertTrue(any(expected in p for p in problems), f'{expected!r} not named in {problems}')

    def test_the_other_policies_refuse_it_and_el2mems_binary_is_refused_by_this_policy(self):
        for other in ('state', 'psci', 'timer', 'usbsmmu', 'cpuon', 'el2mem'):
            with self.subTest(policy=other):
                self.assertTrue(lib.binary_violations(self.elf, self.flat, lib.POLICIES[other], READELF()))
        done, elf, flat = kit.Builder(BUILD / 'el2mem-here').build('el2mem', 'el2mem', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(lib.binary_violations(elf, flat, lib.POLICIES['hashbig'], READELF()))

    def test_two_builds_are_byte_identical_and_the_entry_is_at_offset_zero(self):
        done, _, flat = kit.Builder(BUILD / 'again').build('hashbig', 'hashbig', [])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(Path(flat).read_bytes(), Path(self.flat).read_bytes())
        self.assertEqual(Path(self.flat).read_bytes()[:4], bytes.fromhex('5f2403d5'), 'BTI c first, as the runner expects')


def facts_main():
    kit.need_tools(None)
    done, elf, flat = kit.Builder(BUILD / 'facts').build('hashbig', 'hashbig', [], check=True)
    if done.returncode:
        sys.exit(done.stderr)
    f = kit.facts(elf, flat)
    print(f'hashbig.bin: {f["bytes"]} bytes, sha256 {f["sha256"]}, {f["instructions"]} instructions')
    print('registers read:', ', '.join(f'{r} x{n}' for r, n in sorted(f['mrs'].items())))
    print('allow-list violations:', lib.binary_violations(elf, flat, lib.POLICIES['hashbig'], READELF()))


if __name__ == '__main__':
    if sys.argv[1:] == ['facts']:
        facts_main()
    else:
        sys.exit(0 if unittest.main(verbosity=1, exit=False).result.wasSuccessful() else 1)
