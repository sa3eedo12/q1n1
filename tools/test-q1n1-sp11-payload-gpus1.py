#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests of the GPU stage S1 payload and its tables (payloads/gpus1.c, gpus1d.c, gpus1*.wtab.json): the tables, the compiled code against the write-table
policy, the host model and its seeded bugs.

    python3 tools/test-q1n1-sp11-payload-gpus1.py

  Tables    the live table (a DRAFT) and the dry table: the author rules, the one write, the pinned digest of the dry table, the generated headers are what the
            tool makes, a draft has no approval note
  Audit     the payloads built as payloads: the IR audit finds exactly TABLE_DRAFT for gpus1 and nothing for gpus1d, the policies `gpus1` and `gpus1d` of
            tools/sp11_payload_testlib.py say nothing against them, every word they read is in a readable block or a window of the table
  Model     tools/test-q1n1-sp11-payload-gpus1-model.c under ASan and UBSan, live and dry: the real runner loop and the real payload against a model of the CX domain
  Mutants   seeded bugs of the payload, each refused for its own reason: by the audit or by named checks of the model

Writes only under build/sp11-payload-gpus1/. It SKIPs, and never passes, without clang, ld.lld, make, llvm-objdump, llvm-nm, llvm-readelf and llvm-objcopy.
Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model and compiled code only)."""
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_wtab_audit as audit  # noqa: E402
import sp11_payload_wtab_mutants as mutants  # noqa: E402
import sp11_wtab as wtab  # noqa: E402

BUILD = ROOT / 'build' / 'sp11-payload-gpus1'
UEFI = ROOT / 'platform' / 'uefi'
PAYLOADS = ROOT / 'payloads'
MODEL_C = ROOT / 'tools' / 'test-q1n1-sp11-payload-gpus1-model.c'
RUNNER_SOURCES = ('sp11-payload-wtab.c', 'sp11-payload-run.c', 'sp11-payload-text.c', 'preload.c', 'sha256.c')
TOOLS = ('clang', 'ld.lld', 'make', 'llvm-objdump', 'llvm-readelf', 'llvm-objcopy', 'llvm-nm')
LIVE_JSON, DRY_JSON = PAYLOADS / 'gpus1.wtab.json', PAYLOADS / 'gpus1d.wtab.json'
DRY_SHA256 = '2e2a5adf1552aea2eba39f7e1ce4596e9a1158b3b540541adc2a36d3167feee8'
LIVE_DRAFT_SHA256 = 'a962e8cd26cbfe8d8f0cd1d2b739fcd2ab4d603ac7e3c4d9a03e810edc5c9b66'
# What each build of the model is: the flags that say how the runner and the payload treat a draft table.
MODES = {'live': ['-DQ1N1_WTAB_ALLOW_DRAFT=1'], 'dry': ['-DMODEL_DRY=1'], 'draft-runner': ['-DMODEL_DRAFT_RUNNER=1'],
         'draft-payload': ['-DMODEL_DRAFT_PAYLOAD=1', '-DQ1N1_WTAB_ALLOW_DRAFT=1']}


def need_tools():
    for tool in TOOLS:
        if not lib.have(tool):
            raise unittest.SkipTest(f'{tool} not installed')


def load(path, allow_draft=False):
    source = json.loads(Path(path).read_text(encoding='utf-8'))
    return source, wtab.Table(source)


def readable_blocks():
    """The blocks the S1 payload may read whatever the table does: the GCC and GPUCC windows the table allows."""
    return [(base, size) for _, base, size in load(LIVE_JSON)[1].allowed]


def build_model(name, mode, source_dir=None):
    """The host model under ASan and UBSan, in one of MODES; `source_dir` holds a seeded variant of payloads/gpus1.c that is found before the real one."""
    out = BUILD / name
    out.mkdir(parents=True, exist_ok=True)
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-fno-sanitize-recover=undefined',
             '-DQ1N1_PAYLOAD_HOST_TEST=1', '-DSNAP_PLATFORM_SP11=1', '-DQ1N1_SP11_PAYLOAD=1', '-DQ1N1_SP11_WTAB=1', '-I.', *MODES[mode]]
    if source_dir:
        flags.append(f'-I{source_dir}')
    flags += [f'-I{UEFI}', f'-I{PAYLOADS}']
    binary = out / 'model'
    done = lib.run(['clang', *flags, '-o', str(binary), str(MODEL_C), *[str(UEFI / s) for s in RUNNER_SOURCES]])
    if done.returncode:
        raise RuntimeError('the host model did not build:\n' + done.stderr[-2500:])
    return binary


def run_model(binary):
    return subprocess.run([str(binary)], capture_output=True, text=True, timeout=600, cwd=ROOT,
                          env=dict(lib.ENV, ASAN_OPTIONS='detect_stack_use_after_return=0:detect_leaks=0'))


def failed_checks(text):
    return set(re.findall(r'^FAIL (\S+) \(', text, re.M))


class Tables(unittest.TestCase):
    def test_the_live_table_is_a_draft_with_no_window_and_has_the_one_write(self):
        source, table = load(LIVE_JSON)
        self.assertEqual(wtab.problems(table, allow_draft=True), [])
        self.assertTrue(any(p.startswith('DRAFT') for p in wtab.problems(table)), 'without allow_draft the author rules refuse a draft')
        self.assertTrue(table.name.endswith('-DRAFT') and source['draft'], 'the name ends -DRAFT exactly while the draft list is not empty')
        writers = [r.tag for r in table.rows if r.mask]
        self.assertEqual(writers, ['CXGDSC'], 'the first S1 table makes exactly one write')
        self.assertEqual(table.windows, [], 'the first live table has no window: nothing behind the domain is read')
        row = next(r for r in table.rows if r.tag == 'CXGDSC')
        self.assertEqual((row.addr, row.mask, row.value), (0x03d99108, 0x1, 0x0))
        self.assertEqual(row.undo_kind, wtab.UNDO_RESTORE)
        self.assertIn('UNKNOWN on this unit', row.effect)
        self.assertEqual(wtab.validate_blob(table.pack(), allow_draft=True)[0], 'OK')
        self.assertEqual(wtab.validate_blob(table.pack())[0], 'DRAFT', 'the runner as the Makefile builds it refuses the draft at open')
        self.assertEqual(table.sha256(), LIVE_DRAFT_SHA256)
        self.assertEqual(lib.POLICIES['gpus1']['write_table']['table_sha256'], LIVE_DRAFT_SHA256)
        with self.assertRaises(ValueError):
            wtab.render_note(table, 'GPUS1', 'ab' * 32)

    def test_the_dry_table_writes_nothing_is_pinned_and_exercises_the_timed_machinery(self):
        _, table = load(DRY_JSON)
        self.assertEqual(wtab.problems(table), [])
        self.assertEqual([r for r in table.rows if r.mask], [])
        self.assertEqual(table.windows, [])
        self.assertEqual(table.sha256(), DRY_SHA256)
        self.assertEqual(lib.POLICIES['gpus1d']['write_table']['table_sha256'], DRY_SHA256)
        for row in table.rows:
            self.assertEqual((row.settle_us, row.rb_addr, row.rb_timeout_us), (1, row.addr, 200), row.tag)
            self.assertEqual((row.rb_mask, row.rb_value), (row.found_mask, row.found_value), f'{row.tag}: the read-back is the found check of its own word')
        note = wtab.render_note(table, 'GPUS1D', 'ab' * 32)
        self.assertIn(DRY_SHA256, note)
        self.assertIn('WTAB ATTR CXGDSC', note)
        self.assertIn('lines           9 ordinary lines at most', note)
        self.assertIn("reads between two rows (gpus1d: the eight snapshot reads between rows 2 and 3) and not in the next row.", note)
        self.assertIn('This table writes no device word: no store is made, no undo is needed, and by the reviewed bytes of the payload named above nothing else is stored to a device word.', note)

    def test_the_generated_headers_are_what_the_tool_makes(self):
        for json_path, header in ((LIVE_JSON, 'gpus1-table.h'), (DRY_JSON, 'gpus1d-table.h')):
            _, table = load(json_path)
            text = (PAYLOADS / header).read_text(encoding='utf-8')
            self.assertEqual(text, wtab.emit_c(table), f'{header} is stale: rerun tools/sp11_wtab.py emit-c')
            head = text.split('#pragma once')[0]
            if table.draft:
                self.assertIn('is a DRAFT and is NOT to be approved', head)
                self.assertNotIn('operator approves', head)
            else:
                self.assertIn('operator approves', head)
                self.assertNotIn('DRAFT', head)

    def test_the_dry_table_decodes_from_its_own_bytes(self):
        _, table = load(DRY_JSON)
        text = wtab.decode(table.pack())
        self.assertTrue(text.startswith('table GPUS1D rows=4 windows=0 '), text[:60])
        self.assertIn(f'sha256={DRY_SHA256}', text)
        self.assertEqual(text, wtab.decode(table.pack(), allow_draft=False))
        _, live = load(LIVE_JSON)
        self.assertIn('table GPUS1-DRAFT rows=11 windows=0 ', wtab.decode(live.pack()))
        self.assertEqual(wtab.decode(live.pack(), allow_draft=False), 'REFUSED DRAFT')

    def test_the_two_tables_agree_on_what_they_share(self):
        _, live = load(LIVE_JSON)
        _, dry = load(DRY_JSON)
        for tag in ('GCCAHB', 'GMURCG', 'HUBRCG'):
            a = next(r for r in live.rows if r.tag == tag)
            b = next(r for r in dry.rows if r.tag == tag)
            self.assertEqual([getattr(a, f) for f in ('addr', 'found_mask', 'found_value')], [getattr(b, f) for f in ('addr', 'found_mask', 'found_value')], tag)
        a = next(r for r in live.rows if r.tag == 'CXGDSC')
        b = next(r for r in dry.rows if r.tag == 'CXGDSC')
        self.assertEqual((a.addr, a.found_mask, a.found_value), (b.addr, b.found_mask, b.found_value), 'the dry run checks the very word the live row would store to')

    def test_the_policies_name_the_tables(self):
        self.assertTrue(lib.POLICIES['gpus1']['write_table']['allow_draft'])
        self.assertNotIn('allow_draft', lib.POLICIES['gpus1d']['write_table'])
        for name in ('gpus1', 'gpus1d'):
            self.assertTrue(lib.POLICIES[name]['read_only'])
            self.assertEqual(lib.POLICIES[name]['registers'], set())
            self.assertEqual(lib.POLICIES[name]['smc'], 0)
            self.assertEqual(lib.POLICIES[name]['register_offset_stores'], {'field_name': 6, 'head': 2, 'text': 2})


class Audit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.results = {}
        map_ = lib.POLICIES['gpus1']['register_offset_stores']
        for name, extra in (('gpus1', ()), ('gpus1-allow-draft', ('-DGPUS1_ALLOW_DRAFT=1',)), ('gpus1d', ())):
            source = PAYLOADS / f'{name.split("-")[0]}.c'
            cls.results[name] = audit.audit(source, BUILD / 'audit' / name, list(extra), readable=readable_blocks(), approved_sha256=None, register_offset_stores=map_)

    def test_live_payload_has_exactly_the_draft_finding_in_both_builds(self):
        for name in ('gpus1', 'gpus1-allow-draft'):
            findings, facts = self.results[name]
            self.assertEqual(audit.codes_of(findings), {'TABLE_DRAFT'}, (name, findings))
            self.assertEqual((facts['ir']['open_calls'], facts['ir']['row_calls'], facts['ir']['unwind_calls']), (1, 11, 1), name)
            self.assertEqual(facts['ir']['reads'], 3 * 8, name)
            self.assertEqual(facts['ir']['rows_asked'], {i: 1 for i in range(11)}, name)

    def test_the_default_build_keeps_the_code_behind_the_draft_refusal_and_the_model_build_drops_the_refusal(self):
        default, allow = (Path(self.results[name][1]['flat']).stat().st_size for name in ('gpus1', 'gpus1-allow-draft'))
        self.assertGreater(default, allow, 'the refusal reads the name at run time: its code is in the default build and not in the host model\'s')
        self.assertGreater(default, 3000, 'the code behind the refusal must still be in the binary the policy audits')

    def test_dry_payload_has_no_finding(self):
        findings, facts = self.results['gpus1d']
        self.assertEqual(findings, [])
        self.assertEqual((facts['ir']['open_calls'], facts['ir']['row_calls'], facts['ir']['unwind_calls']), (1, 4, 1))
        self.assertEqual(facts['ir']['reads'], 3 * 8)

    def test_the_policies_say_nothing_against_the_binaries(self):
        for name, policy in (('gpus1', 'gpus1'), ('gpus1-allow-draft', 'gpus1'), ('gpus1d', 'gpus1d')):
            _, facts = self.results[name]
            self.assertEqual(lib.binary_violations(facts['elf'], facts['flat'], lib.POLICIES[policy]), [], name)
        _, facts = self.results['gpus1']
        strict = dict(lib.POLICIES['gpus1'], write_table={})
        problems = lib.binary_violations(facts['elf'], facts['flat'], strict)
        self.assertTrue(any(p.startswith('TABLE_DRAFT') for p in problems), 'without allow_draft the policy refuses the draft')
        wrong = dict(lib.POLICIES['gpus1'], write_table={'allow_draft': True, 'table_sha256': '0' * 64})
        self.assertTrue(any(p.startswith('TABLE_SHA') for p in lib.binary_violations(facts['elf'], facts['flat'], wrong)), 'a changed draft fails the policy')

    def test_the_register_offset_map_is_checked(self):
        _, facts = self.results['gpus1d']
        for edit, wording in ((lambda m: {**m, 'head': 3}, 'stores with a register offset'), (lambda m: {k: v for k, v in m.items() if k != 'text'}, 'stores with a register offset'),
                              (lambda m: {**m, 'payload_entry': 1}, 'stores with a register offset')):
            policy = dict(lib.POLICIES['gpus1d'], register_offset_stores=edit(lib.POLICIES['gpus1d']['register_offset_stores']))
            self.assertTrue(any(wording in p for p in lib.binary_violations(facts['elf'], facts['flat'], policy)), edit)

    def test_the_approval_digest_is_checked(self):
        _, facts = self.results['gpus1d']
        problems = lib.binary_violations(facts['elf'], facts['flat'], dict(lib.POLICIES['gpus1d'], write_table={'table_sha256': '0' * 64}))
        self.assertTrue(any(p.startswith('TABLE_SHA') for p in problems), problems)

    def test_the_payload_fits_its_policy(self):
        for name, policy in (('gpus1', 'gpus1'), ('gpus1d', 'gpus1d')):
            size = Path(self.results[name][1]['flat']).stat().st_size
            self.assertLessEqual(size, lib.POLICIES[policy]['bytes'], f'{name} is {size} bytes')

    def test_two_builds_are_byte_for_byte_the_same(self):
        for name in ('gpus1', 'gpus1d'):
            done, _, flat = lib.build_payload(PAYLOADS / f'{name}.c', BUILD / 'audit-again' / name)
            self.assertEqual(done.returncode, 0)
            self.assertEqual(Path(flat).read_bytes(), Path(self.results[name][1]['flat']).read_bytes())


class Model(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()

    def run_mode(self, mode, label):
        done = run_model(build_model(mode, mode))
        self.assertEqual(done.returncode, 0, done.stderr[-2000:] + done.stdout[-500:])
        self.assertRegex(done.stdout, rf'MODEL {label} CHECKS \d+ FAILS 0')

    def test_live(self):
        self.run_mode('live', 'LIVE')

    def test_dry(self):
        self.run_mode('dry', 'DRY')

    def test_a_draft_is_refused_by_the_runner_as_the_makefile_builds_it(self):
        self.run_mode('draft-runner', 'DRAFT_RUNNER')

    def test_a_draft_is_refused_by_the_payload_when_the_runner_takes_it(self):
        self.run_mode('draft-payload', 'DRAFT_PAYLOAD')


# Seeded bugs of payloads/gpus1.c: (name, old, new, codes the audit must report, codes it must not).
AUDIT_MUTANTS = [
    ('a read of a word in no readable block (the GPU SMMU the survey skipped)',
     'X(CXST, 0x03d9953cu)', 'X(CXST, 0x03da0000u)', {'READ_NOT_GATED'}, {'STORE_INTTOPTR', 'ROW_COVERAGE'}),
    ('a read whose address is not a literal',
     'X(CXST, 0x03d9953cu)', 'X(CXST, 0x03d9953cu + (a->size & 0x4u))', {'READ_ADDRESS_NOT_CONSTANT'}, {'READ_NOT_GATED', 'STORE_INTTOPTR'}),
    ('a store of the payload to a device word',
     '    print_snap(a, "BEFORE", &before);\n', '    print_snap(a, "BEFORE", &before);\n    *(volatile uint32_t *)0x03d99108u = 1u;\n', {'STORE_INTTOPTR'}, {'ROW_COVERAGE'}),
    ('a store through the arguments the runner passed',
     '    print_snap(a, "BEFORE", &before);\n', '    print_snap(a, "BEFORE", &before);\n    ((struct q1n1_payload_args *)a)->ops.puts = 0;\n', {'STORE_ARGS'}, {'STORE_INTTOPTR'}),
    ('a row asked for twice and another never', 'wtab->row(WROW_HUBRCG)', 'wtab->row(WROW_GMURCG)', {'ROW_COVERAGE'}, {'ROW_INDEX_NOT_CONSTANT', 'STORE_INTTOPTR'}),
    ('an index that is not a literal', 'wtab->row(WROW_CXGDSC)', 'wtab->row(a->size & 7u)', {'ROW_INDEX_NOT_CONSTANT'}, {'ROW_INDEX_RANGE', 'STORE_INTTOPTR'}),
]

# Seeded bugs the audit cannot see because they are about order or about a refusal, which the runner enforces and the model checks:
# (name, old, new, checks of the model that must fail, the build of the model).
MODEL_MUTANTS = [
    ('GPUCC is read before the register path is proved',
     '    if (wtab->row(WROW_GCCAHB) || wtab->row(WROW_GMURCG) || wtab->row(WROW_HUBRCG)) {\n',
     '    snapshot(a, &before);\n    if (wtab->row(WROW_GCCAHB) || wtab->row(WROW_GMURCG) || wtab->row(WROW_HUBRCG)) {\n',
     {'found/ahb_off.nothing_read_unclocked'}, 'live'),
    ('the answer of the domain row is ignored',
     '    if (wtab->row(WROW_CXGDSC)) {\n        say(a, "STOPPED=STEP1");\n        return 1;\n    }\n', '    (void)wtab->row(WROW_CXGDSC);\n',
     {'stops/never_powers.payload_says_so'}, 'live'),
    ('the payload never unwinds and leaves it to the runner',
     '    if (wtab->unwind()) {\n        say(a, "UNDO FAILED");\n        return 1;\n    }\n', '',
     {'normal/no_auto_unwind'}, 'live'),
    ('the comparison always says restored', 'changed |= (before.v[i] != after.v[i]) ? 1u << i : 0;', 'changed |= 0;', {'drift/changed_word.is_reported'}, 'live'),
    ('the payload does not refuse a table named as a draft',
     '    if (table_is_named_a_draft()) return 5;\n', '    if (table_is_named_a_draft() && 0) return 5;\n',
     {'draft/payload.says_the_table_is_a_draft_and_returns'}, 'draft-payload'),
    ('the payload reads a block behind the domain (the CX_MISC word the first live table does not read)',
     '    print_snap(a, "BEFORE", &before);\n',
     '    print_snap(a, "BEFORE", &before);\n    { uint32_t behind = 0; (void)a->ops.load32(0x03d9e0e4u, &behind); }\n',
     {'normal/no_read_behind_the_domain'}, 'live'),
    ('the payload gives ops.hex a destination just past its stack',
     '    print_snap(a, "BEFORE", &before);\n',
     '    print_snap(a, "BEFORE", &before);\n    (void)a->ops.hex((char *)(uintptr_t)(a->stack_base + a->stack_size), 8u, 1u);\n',
     {'normal/no_op_pointer_of_the_payload_is_refused'}, 'live'),
]

# The review's seeds of the write-table policy tooling, each an edit of gpus1.c built as the DRY payload (payloads/gpus1d.c): (name, old, new, second edit or None, codes the
# audit must report, a phrase the policy `gpus1d` must say or None). Each passed the first version of the tools.
AFTER_BEFORE = '    print_snap(a, "BEFORE", &before);\n'
SAY = 'INLINE void say(const struct q1n1_payload_args *a, const char *message)\n{'
OPEN = 'wtab->open(WTAB_TABLE_ADDRESS)'
REVIEW_SEEDS = [
    ('S02 a store through the stack base plus a run-time offset that lands on a device word', AFTER_BEFORE,
     AFTER_BEFORE + '    {\n        volatile uint64_t target = 0x03d99108u;\n        volatile uint32_t slot[2] = {0, 0};\n'
     '        uint64_t delta = target - (uint64_t)(uintptr_t)&slot[0];\n        *(volatile uint32_t *)((volatile uint8_t *)&slot[0] + delta) = 1u;\n    }\n',
     None, {'STORE_INDEXED'}, None),
    ('S22 the same with the stack address laundered through a volatile', AFTER_BEFORE,
     AFTER_BEFORE + '    {\n        volatile uint64_t keep = 0;\n        volatile uint32_t slot[2] = {0, 0};\n        keep = (uint64_t)(uintptr_t)&slot[0];\n'
     '        volatile uint64_t target = 0x03d99108u;\n        uint64_t delta = target - keep;\n        *(volatile uint32_t *)((volatile uint8_t *)&slot[0] + delta) = 1u;\n    }\n',
     None, {'STORE_INDEXED'}, 'stores with a register offset'),
    ('S18 a stack store with an index the runner passed', AFTER_BEFORE, AFTER_BEFORE + '    before.v[a->fb_width] = 0u;\n',
     None, {'STORE_INDEXED'}, 'stores with a register offset'),
    ('S03 a store through a select of a device literal and a stack address', AFTER_BEFORE,
     AFTER_BEFORE + '    {\n        uint32_t local = 0;\n        volatile uint32_t *p = (a->fb_width & 1u) ? (volatile uint32_t *)0x03d99108u : (volatile uint32_t *)&local;\n        *p = 1u;\n    }\n',
     None, {'STORE_INTTOPTR'}, 'whose base'),
    ('S04 a store through a phi of a stack address and a device literal', AFTER_BEFORE,
     AFTER_BEFORE + '    {\n        uint32_t local = 0;\n        volatile uint32_t *p = &local;\n'
     '        for (unsigned i = 0; i < (a->fb_width & 3u); i++) p = (volatile uint32_t *)0x03d99108u;\n        *p = 1u;\n    }\n',
     None, {'STORE_INTTOPTR'}, 'whose base'),
    ('S09 open of an address inside the approved table, eight bytes from its start', OPEN,
     'wtab->open((const struct q1n1_wtab_header *)((const uint8_t *)WTAB_TABLE_ADDRESS + 8))', None, {'OPEN_ARGUMENT'}, None),
    ('S10 open of a second table that has no wtab_ name, the approved one still in the image', SAY,
     'static const struct q1n1_wtab_header other_table = {.magic = Q1N1_WTAB_TABLE_MAGIC, .version = 1, .bytes = sizeof(struct q1n1_wtab_header)};\n' + SAY,
     (OPEN, '((void)*(const volatile uint32_t *)&WTAB_TABLE_ADDRESS->rows, wtab->open(&other_table))'), {'TABLE_COUNT', 'OPEN_ARGUMENT'}, 'TABLE_COUNT'),
]

# The seeds that move the stack address by a run-time number before the store, in a helper that stores through its pointer parameter (S27, S30) and in a register an empty
# asm hands back (S28): (name, old, new, second edit, the audit's codes exactly, a phrase the policy `gpus1d` says). The policy says it only because of the key
# `register_offset_stores`, and the codes of the audit are the whole of what the IR audit finds (S28's store is through the asm's result, which the IR audit cannot root).
LAUNDERED_SLOT = ('    {\n        volatile uint64_t keep = 0;\n        volatile uint32_t slot[2] = {0, 0};\n        keep = (uint64_t)(uintptr_t)&slot[0];\n'
                  '        volatile uint64_t target = 0x03d99108u;\n        uint64_t delta = target - keep;\n')
MOVED_SEEDS = [
    ('S27 a store in a helper through its pointer parameter, the caller adds a run-time offset to the stack base', SAY,
     'OUT_OF_LINE void poke_word(volatile uint32_t *p)\n{\n    *p = 1u;\n}\n\n' + SAY,
     (AFTER_BEFORE, AFTER_BEFORE + LAUNDERED_SLOT + '        poke_word((volatile uint32_t *)((volatile uint8_t *)&slot[0] + delta));\n    }\n'),
     {'CALL_ARGUMENT_INDEXED'}, 'whose base'),
    ('S30 a four-byte memset in a helper through its pointer parameter, the caller adds a run-time offset to the stack base', SAY,
     'OUT_OF_LINE void zap_word(void *p)\n{\n    __builtin_memset(p, 0, 4u);\n}\n\n' + SAY,
     (AFTER_BEFORE, AFTER_BEFORE + LAUNDERED_SLOT + '        zap_word((void *)((volatile uint8_t *)&slot[0] + delta));\n        (void)*(volatile uint32_t *)&slot[0];\n    }\n'),
     {'CALL_ARGUMENT_INDEXED'}, 'whose base'),
    ('S28 the address folded into one register by an empty asm, so that the store is a plain [xN]', AFTER_BEFORE,
     AFTER_BEFORE + LAUNDERED_SLOT + '        volatile uint8_t *where = (volatile uint8_t *)&slot[0] + delta;\n        __asm__ volatile("" : "+r"(where));\n'
     '        *(volatile uint32_t *)where = 1u;\n    }\n',
     None, {'INLINE_ASM', 'STORE_UNKNOWN'}, 'whose base'),
]


class Mutants(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        need_tools()
        cls.source = (PAYLOADS / 'gpus1.c').read_text(encoding='utf-8')
        cls.wrapper = (PAYLOADS / 'gpus1d.c').read_text(encoding='utf-8')
        cls.map = lib.POLICIES['gpus1']['register_offset_stores']

    def write(self, name, text, wrapper=False):
        out = BUILD / 'mutants' / re.sub(r'\W+', '-', name)[:40]
        out.mkdir(parents=True, exist_ok=True)
        (out / 'gpus1.c').write_text(text, encoding='utf-8')
        if wrapper:
            (out / 'gpus1d.c').write_text(self.wrapper, encoding='utf-8')
        return out

    def test_the_unchanged_control_is_clean_through_the_same_mechanism(self):
        out = self.write('control', self.source)
        findings, _ = audit.audit(out / 'gpus1.c', out / 'build', [f'-I{out}'], readable=readable_blocks(), register_offset_stores=self.map)
        self.assertEqual(audit.codes_of(findings), {'TABLE_DRAFT'}, findings)
        out = self.write('control-dry', self.source, wrapper=True)
        findings, facts = audit.audit(out / 'gpus1d.c', out / 'build', [f'-I{out}'], readable=readable_blocks(), approved_sha256=DRY_SHA256, register_offset_stores=self.map)
        self.assertEqual((findings, lib.binary_violations(facts['elf'], facts['flat'], lib.POLICIES['gpus1d'])), ([], []))

    def test_every_seeded_audit_bug_is_refused_for_its_own_reason(self):
        primary = []
        for name, old, new, wanted, unwanted in AUDIT_MUTANTS:
            with self.subTest(bug=name):
                out = self.write(name, mutants.apply_once(self.source, old, new))
                findings, facts = audit.audit(out / 'gpus1.c', out / 'build', [f'-I{out}'], readable=readable_blocks(), register_offset_stores=self.map)
                got = audit.codes_of(findings) - {'TABLE_DRAFT'}
                self.assertTrue(wanted <= got, f'wanted {sorted(wanted)}, got {sorted(got)}: {findings[:4]}')
                self.assertFalse(unwanted & got, f'{sorted(unwanted & got)} should not be among {sorted(got)}')
                primary.append(sorted(wanted)[0])
        self.assertEqual(len(set(primary)), len(primary), 'each seeded bug has its own reason')

    def test_the_reviews_seeds_are_each_refused_for_their_own_reason_in_the_dry_payload(self):
        """Edits of gpus1.c built as the dry payload and judged twice: by the audit (the IR, the calls, the table) and by the policy `gpus1d` (the binary)."""
        for name, old, new, second, audit_codes, policy_phrase in REVIEW_SEEDS:
            with self.subTest(seed=name):
                text = mutants.apply_once(self.source, old, new)
                if second:
                    text = mutants.apply_once(text, *second)
                out = self.write(name, text, wrapper=True)
                findings, facts = audit.audit(out / 'gpus1d.c', out / 'build', [f'-I{out}'], readable=readable_blocks(), approved_sha256=DRY_SHA256, register_offset_stores=self.map)
                self.assertIn('elf', facts, findings)
                got = audit.codes_of(findings)
                policy = lib.binary_violations(facts['elf'], facts['flat'], lib.POLICIES['gpus1d'])
                self.assertTrue(audit_codes <= got, f'the audit wanted {sorted(audit_codes)}, got {sorted(got)}: {findings[:3]}')
                if policy_phrase:
                    self.assertTrue(any(policy_phrase in p for p in policy), f'the policy wanted {policy_phrase!r}, said {policy[:3]}')
                self.assertTrue(findings or policy, name)

    def test_the_seeds_that_move_the_stack_address_by_a_number_are_each_refused_for_their_own_reason_by_both_judges(self):
        """S27 and S30 by the call argument of the IR audit and by the memcheck class of the callee's base, S28 by its asm and by the memcheck class of the register: the binary
        policy refuses each of them without the audit, and passes each of them without the key `register_offset_stores`."""
        without_key = {k: v for k, v in lib.POLICIES['gpus1d'].items() if k != 'register_offset_stores'}
        for name, old, new, second, audit_codes, policy_phrase in MOVED_SEEDS:
            with self.subTest(seed=name):
                text = mutants.apply_once(self.source, old, new)
                if second:
                    text = mutants.apply_once(text, *second)
                out = self.write(name, text, wrapper=True)
                findings, facts = audit.audit(out / 'gpus1d.c', out / 'build', [f'-I{out}'], readable=readable_blocks(), approved_sha256=DRY_SHA256, register_offset_stores=self.map)
                self.assertIn('elf', facts, findings)
                self.assertEqual(audit.codes_of(findings), audit_codes, findings[:4])
                self.assertTrue(any(policy_phrase in p for p in lib.binary_violations(facts['elf'], facts['flat'], lib.POLICIES['gpus1d'])), name)
                self.assertFalse(any(policy_phrase in p for p in lib.binary_violations(facts['elf'], facts['flat'], without_key)), 'the key is what refuses this seed')

    def test_every_seeded_order_bug_fails_the_checks_that_name_it(self):
        for mode in ('live', 'draft-payload'):
            self.assertEqual(run_model(build_model(f'mutant-control-{mode}', mode)).returncode, 0)
        for name, old, new, checks, mode in MODEL_MUTANTS:
            with self.subTest(bug=name):
                out = self.write(name, mutants.apply_once(self.source, old, new))
                done = run_model(build_model('mutant-' + re.sub(r'\W+', '-', name)[:30], mode, source_dir=out))
                self.assertNotEqual(done.returncode, 0, 'the seeded bug passed the host model')
                failed = failed_checks(done.stderr)
                self.assertTrue(checks <= failed, f'wanted {sorted(checks)} among {sorted(failed)}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
