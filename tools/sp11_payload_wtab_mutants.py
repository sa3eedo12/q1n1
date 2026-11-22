# SPDX-License-Identifier: MIT
"""Seeded bugs of the write-table work (tools/test-q1n1-sp11-payload-wtab.py): each is a small change of one real file, and each must be refused by the
check that was written for it and named by its own reason, not by whichever check happens to trip first. A control (the unchanged file) must pass the same
mechanism, so that a mutant that fails is not a build that was broken before it was seeded.

  payload  mutants of tools/wtab-ref/ref-payload.c, judged by tools/sp11_payload_wtab_audit.py (the IR, the binary) and the `wtabref` policy
  table    mutants of tools/wtab-ref/ref.json, whose packed table is judged by the runner's rules and against the approved digest
  runner   mutants of platform/uefi/sp11-payload-wtab.c, judged by the host harness: the names of the checks that must fail

An `old` text must occur exactly once in its file: a mutant that did not change anything is an error of the test, never a pass. Hardware: NOT RUN."""

# ---- The payload: (name, old, new, codes that must be among the findings, codes that must not) ------------------------------------------
# The stack slot a seed addresses by a number the compiler cannot fold: the distance from the slot to a device word, computed through volatiles.
LAUNDERED_SLOT = ('        volatile uint64_t keep = 0;\n        volatile uint32_t slot[2] = {0, 0};\n        keep = (uint64_t)(uintptr_t)&slot[0];\n'
                  '        volatile uint64_t target = 0x01002000u;\n        uint64_t delta = target - keep;\n')
# The seeds that hand an op of the payload ABI a pointer of the payload's choosing, the stack base plus a run-time offset (S38 ops.hex, S39 ops.puts, S40 ops.load32). The tools
# pass them (an op's pointer argument is only asked to be rooted in the stack or the image, and nothing in the code is a store); the runner's write-table gate refuses them when
# the code runs (tools/test-q1n1-sp11-payload-wtab.py, Mutants). `SEED_TARGET` is a device word in the target build and the harness' own buffer `seed_buffer` in the host build.
SEEDED_SLOT = LAUNDERED_SLOT.replace('0x01002000u', 'SEED_TARGET')
OPS_SEED_PREAMBLE = ('static void say(', '#ifndef SEED_TARGET\n#define SEED_TARGET 0x01002000u\n#endif\n#ifdef SEED_EXTERN\nextern char seed_buffer[64];\n#endif\n\nstatic void say(')
OPS_SEED_AFTER = '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n'
OPS_SEEDS = [
    ('S38 ops.hex into the stack base plus a run-time offset that lands outside the stack', 'hex',
     '        (void)a->ops.hex((char *)((volatile uint8_t *)&slot[0] + delta), 19u, 0x1234u);\n'),
    ('S39 ops.puts of a string at the stack base plus a run-time offset that lands outside the stack and the image', 'puts',
     '        a->ops.puts((const char *)((volatile uint8_t *)&slot[0] + delta));\n'),
    ('S40 ops.load32 into the stack base plus a run-time offset that lands outside the stack', 'load32',
     '        (void)a->ops.load32(BLOCK_WORD, (uint32_t *)((volatile uint8_t *)&slot[0] + delta));\n'),
]
PAYLOAD_MUTANTS = [
    ('a store outside the table: a device word written by the payload itself',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    *(volatile uint32_t *)0x01002000u = 1u;\n',
     {'STORE_INTTOPTR'}, {'ROW_COVERAGE', 'TABLE_REFUSED', 'TABLE_SHA'}),
    ('a store through a pointer: the runner\'s own ops table written through the pointer read from the arguments',
     '    if (wtab->open(WTAB_TABLE_ADDRESS)) {\n',
     '    ((struct q1n1_payload_wtab_ops *)wtab)->reserved[0] = 1;\n    if (wtab->open(WTAB_TABLE_ADDRESS)) {\n',
     {'STORE_LOADED'}, {'INTTOPTR', 'STORE_INTTOPTR'}),
    ('a store through the arguments the runner passed',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    ((uint32_t *)a)[0] = 0;\n',
     {'STORE_ARGS'}, {'INTTOPTR', 'STORE_INTTOPTR', 'STORE_LOADED'}),
    ('an unchecked index: the row asked for comes from a word the runner passed',
     'wtab->row(WROW_CLKA)', 'wtab->row(a->fb_width & 3u)',
     {'ROW_INDEX_NOT_CONSTANT'}, {'ROW_INDEX_RANGE', 'STORE_INTTOPTR'}),
    ('an index past the end of the table',
     'wtab->row(WROW_CLKB)', 'wtab->row(7)',
     {'ROW_INDEX_RANGE'}, {'ROW_INDEX_NOT_CONSTANT', 'STORE_INTTOPTR'}),
    ('a row asked for twice and another never',
     'wtab->row(WROW_CLKA)', 'wtab->row(WROW_DOMAIN)',
     {'ROW_COVERAGE', 'BIN_ROW_COVERAGE'}, {'ROW_INDEX_RANGE', 'ROW_INDEX_NOT_CONSTANT', 'STORE_INTTOPTR'}),
    ('a table that is not the constant: the stack table',
     'wtab->open(WTAB_TABLE_ADDRESS)', 'wtab->open(&spare)',
     {'OPEN_ARGUMENT'}, {'STORE_INTTOPTR', 'ROW_COVERAGE'}),
    ('a store in inline assembly, which the IR audit cannot see',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    __asm__ volatile("str %w0, [%1]" : : "r"(1u), "r"((uint64_t)0x01002000u) : "memory");\n',
     {'INLINE_ASM'}, {'STORE_INTTOPTR', 'INTTOPTR'}),
    ('a call to an address the payload made up, in inline assembly',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    __asm__ volatile("mov x8, #0x1000\\n blr x8" : : : "x8", "x30", "memory");\n',
     {'INLINE_ASM', 'BIN_INDIRECT_CALL'}, {'STORE_INTTOPTR', 'INTTOPTR'}),
    # The review's seeds (S02, S03, S04, S09, S10, S18, S22 of its list), each of which passed the first version of the tools.
    ('S02 a store through the stack base plus a run-time offset that lands on a device word',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    {\n        volatile uint64_t target = 0x01002000u;\n        volatile uint32_t slot[2] = {0, 0};\n'
     '        uint64_t delta = target - (uint64_t)(uintptr_t)&slot[0];\n        *(volatile uint32_t *)((volatile uint8_t *)&slot[0] + delta) = 1u;\n    }\n',
     {'STORE_INDEXED'}, {'INTTOPTR', 'STORE_INTTOPTR', 'OPEN_ARGUMENT', 'TABLE_COUNT'}),
    ('S22 the same with the stack address laundered through a volatile, so that no compiler can fold the sum to the literal',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    {\n        volatile uint64_t keep = 0;\n        volatile uint32_t slot[2] = {0, 0};\n'
     '        keep = (uint64_t)(uintptr_t)&slot[0];\n        volatile uint64_t target = 0x01002000u;\n        uint64_t delta = target - keep;\n'
     '        *(volatile uint32_t *)((volatile uint8_t *)&slot[0] + delta) = 1u;\n    }\n',
     {'STORE_INDEXED'}, {'INTTOPTR', 'STORE_INTTOPTR', 'OPEN_ARGUMENT', 'TABLE_COUNT'}),
    ('S18 a stack store with an index the runner passed',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    volatile uint32_t spare[4] = {0, 0, 0, 0};\n    spare[a->fb_width] = 0u;\n',
     {'STORE_INDEXED'}, {'INTTOPTR', 'STORE_INTTOPTR', 'OPEN_ARGUMENT', 'TABLE_COUNT'}),
    # The three seeds that move the stack address by a run-time number before the store: in a helper that stores through its pointer parameter (S27, S30) and in a
    # register an empty asm hands back (S28). The IR audit and the binary policy refuse each one separately, S28 also by the asm itself.
    ('S27 a store in a helper through its pointer parameter, the caller adds a run-time offset to the stack base',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    {\n' + LAUNDERED_SLOT +
     '        poke_word((volatile uint32_t *)((volatile uint8_t *)&slot[0] + delta));\n    }\n',
     {'CALL_ARGUMENT_INDEXED'}, {'INTTOPTR', 'STORE_INTTOPTR', 'STORE_INDEXED', 'INLINE_ASM', 'OPEN_ARGUMENT', 'TABLE_COUNT'}),
    ('S30 a four-byte memset in a helper through its pointer parameter, the caller adds a run-time offset to the stack base',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    {\n' + LAUNDERED_SLOT +
     '        zap_word((void *)((volatile uint8_t *)&slot[0] + delta));\n        (void)*(volatile uint32_t *)&slot[0];\n    }\n',
     {'CALL_ARGUMENT_INDEXED'}, {'INTTOPTR', 'STORE_INTTOPTR', 'STORE_INDEXED', 'INLINE_ASM', 'OPEN_ARGUMENT', 'TABLE_COUNT'}),
    ('S28 the address folded into one register by an empty asm, so that the store is a plain [xN]',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    {\n' + LAUNDERED_SLOT +
     '        volatile uint8_t *where = (volatile uint8_t *)&slot[0] + delta;\n        __asm__ volatile("" : "+r"(where));\n        *(volatile uint32_t *)where = 1u;\n    }\n',
     {'INLINE_ASM'}, {'CALL_ARGUMENT_INDEXED', 'INTTOPTR', 'STORE_INTTOPTR', 'OPEN_ARGUMENT', 'TABLE_COUNT'}),
    ('S03 a store through a select of a device literal and a stack address',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    {\n        uint32_t local = 0;\n'
     '        volatile uint32_t *p = (a->fb_width & 1u) ? (volatile uint32_t *)0x01002000u : (volatile uint32_t *)&local;\n        *p = 1u;\n    }\n',
     {'STORE_INTTOPTR'}, {'STORE_INDEXED', 'OPEN_ARGUMENT', 'TABLE_COUNT'}),
    ('S04 a store through a phi of a stack address and a device literal',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n',
     '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    {\n        uint32_t local = 0;\n        volatile uint32_t *p = &local;\n'
     '        for (unsigned i = 0; i < (a->fb_width & 3u); i++) p = (volatile uint32_t *)0x01002000u;\n        *p = 1u;\n    }\n',
     {'STORE_INTTOPTR'}, {'STORE_INDEXED', 'OPEN_ARGUMENT', 'TABLE_COUNT'}),
    ('S09 open of an address inside the approved table, eight bytes from its start',
     'wtab->open(WTAB_TABLE_ADDRESS)', 'wtab->open((const struct q1n1_wtab_header *)((const uint8_t *)WTAB_TABLE_ADDRESS + 8))',
     {'OPEN_ARGUMENT'}, {'STORE_INDEXED', 'STORE_INTTOPTR', 'TABLE_COUNT'}),
    ('S10 open of a second table that has no wtab_ name, the approved one still in the image',
     'static void say(',
     'static const struct q1n1_wtab_header other_table = {.magic = Q1N1_WTAB_TABLE_MAGIC, .version = 1, .bytes = sizeof(struct q1n1_wtab_header)};\n\nstatic void say(',
     {'TABLE_COUNT', 'OPEN_ARGUMENT'}, {'STORE_INDEXED', 'STORE_INTTOPTR'}),
]
# What the mutants above need besides their one change: the stack table of the `open` mutant, the helper of the two seeds that store through a pointer parameter, and nothing else.
PAYLOAD_PREAMBLE = {
    'a table that is not the constant: the stack table':
        ('    uint32_t word = 0;\n', '    uint32_t word = 0;\n    struct q1n1_wtab_header spare = {0};\n    if (wtab_wtabref.header.rows != 4) return 4;\n'),
    'S27 a store in a helper through its pointer parameter, the caller adds a run-time offset to the stack base':
        ('static void say(', 'static __attribute__((noinline)) void poke_word(volatile uint32_t *p)\n{\n    *p = 1u;\n}\n\nstatic void say('),
    'S30 a four-byte memset in a helper through its pointer parameter, the caller adds a run-time offset to the stack base':
        ('static void say(', 'static __attribute__((noinline)) void zap_word(void *p)\n{\n    __builtin_memset(p, 0, 4u);\n}\n\nstatic void say('),
}
# The seeds that need a second edit: S10 opens the second table (and keeps the approved one referenced, as a payload that carries both would)
PAYLOAD_SECOND_EDIT = {
    'S10 open of a second table that has no wtab_ name, the approved one still in the image':
        ('wtab->open(WTAB_TABLE_ADDRESS)', '((void)*(const volatile uint32_t *)&WTAB_TABLE_ADDRESS->rows, wtab->open(&other_table))'),
}
# A binary-level finding the policy (tools/sp11_payload_testlib.py, binary_violations) must also make for the mutants that store: `read_only` says so in its own words.
POLICY_PHRASE = {
    'a store outside the table: a device word written by the payload itself': 'whose base',
    'a store through a pointer: the runner\'s own ops table written through the pointer read from the arguments': 'whose base',
    'a store in inline assembly, which the IR audit cannot see': 'whose base',
    'a store through the arguments the runner passed': 'whose base',
    'S02 a store through the stack base plus a run-time offset that lands on a device word': 'whose base',
    'S22 the same with the stack address laundered through a volatile, so that no compiler can fold the sum to the literal': 'stores with a register offset',
    'S18 a stack store with an index the runner passed': 'stores with a register offset',
    'S27 a store in a helper through its pointer parameter, the caller adds a run-time offset to the stack base': 'whose base',
    'S30 a four-byte memset in a helper through its pointer parameter, the caller adds a run-time offset to the stack base': 'whose base',
    'S28 the address folded into one register by an empty asm, so that the store is a plain [xN]': 'whose base',
    'S03 a store through a select of a device literal and a stack address': 'whose base',
    'S04 a store through a phi of a stack address and a device literal': 'whose base',
    'S10 open of a second table that has no wtab_ name, the approved one still in the image': 'TABLE_COUNT',
}
# The seeds that the binary policy passes unless the policy has the key `register_offset_stores`: that key, and nothing else of the policy, is what stops them.
NEEDS_KEY = {name for name in POLICY_PHRASE if name[:3] in ('S18', 'S22', 'S27', 'S28', 'S30')}

# ---- The table: (name, edit of the JSON, codes that must be among the findings, codes that must not) -------------------------------------
TABLE_MUTANTS = [
    ('a wrong value: a bit more written, a table that is valid and is not the approved one',
     lambda t: t['rows'][2].update(mask='0x3', value='0x3', found=['0x3', '0x0']),
     {'TABLE_SHA'}, {'TABLE_REFUSED'}),
    ('a dropped undo: a row that writes and cannot be put back',
     lambda t: t['rows'][2].update(undo={'kind': 'none'}),
     {'TABLE_REFUSED', 'TABLE_SHA'}, set()),
    ('a write without a read-back',
     lambda t: t['rows'][2].pop('readback'),
     {'TABLE_REFUSED', 'TABLE_SHA'}, set()),
    ('a row that reads the window it must open first',
     lambda t: t['windows'][0].update(base='0x01002000', size='0x40'),
     {'TABLE_REFUSED', 'TABLE_SHA'}, set()),
]

# ---- The runner: (name, old, new, checks of the host harness that must fail) -----------------------------------------------------------
RUNNER_MUTANTS = [
    ('the undo runs forward', 'for (uint32_t i = S.hdr->rows; i-- > 0;) {', 'for (uint32_t i = 0; i < S.hdr->rows; i++) {',
     {'run/unwind.reverse_order'}),
    ('the undo skips a row', 'if (S.journal[i].state != J_STORED || S.rows[i].undo_kind == Q1N1_WTAB_UNDO_NONE) continue;',
     'if (S.journal[i].state != J_STORED || S.rows[i].undo_kind == Q1N1_WTAB_UNDO_NONE || i == 1) continue;', {'run/unwind.device_back_to_found'}),
    ('the row index is not bounded', 'if (index >= S.hdr->rows) return stop(Q1N1_WTAB_INDEX, index, 0, index, S.hdr->rows, 0);', '',
     {'stops/index.open'}),
    ('a wrong value is stored', 'uint32_t next = (pre & ~r->mask) | r->value;', 'uint32_t next = (pre & ~r->mask) | (r->value ^ 0x4);',
     {'run/stores.three_before_undo'}),
    ('the store is not announced', 'if (!put(&line, 0)) return stop(Q1N1_WTAB_BUDGET, index, r->addr, S.lines, S.ordinary_limit, 0);',
     '(void)line;', {'run/lines.every_store_announced'}),
    ('a store is not journaled', 'S.journal[index].state = J_STORED;', 'S.journal[index].state = J_CHECKED;', {'run/unwind.reverse_order'}),
    ('the SError after a store is not looked at',
     'if (S.env->store32(r->addr, next)) return stop(Q1N1_WTAB_FAULT, index, r->addr, pre, next, r->mask);\n'
     '        if (S.env->serror_poll && S.env->serror_poll()) return stop(Q1N1_WTAB_SERROR, index, r->addr, pre, next, r->mask);',
     'if (S.env->store32(r->addr, next)) return stop(Q1N1_WTAB_FAULT, index, r->addr, pre, next, r->mask);',
     {'stops/serror.names_the_store'}),
    ('the found value is not checked',
     'if ((pre & r->found_mask) != r->found_value) return stop(Q1N1_WTAB_FOUND, index, r->addr, pre & r->found_mask, r->found_value, r->found_mask);',
     '', {'stops/found.row0_ok_row1_refused'}),
    ('a stopped run goes on', '    if (S.stopped || S.finished) return Q1N1_WTAB_STOPPED;\n    if (index >= S.hdr->rows)', '    if (index >= S.hdr->rows)',
     {'stops/found.nothing_after'}),
    ('the read gate is always open', '    if (open) return 0;\n', '    (void)open;\n    return 0;\n', {'gate/closed.refused'}),
    ('the table accepts a value outside the mask', 'if (r->value & ~r->mask) return Q1N1_WTAB_ROW_MASK_VALUE;', '',
     {'validate/refuses.value outside mask'}),
    ('the run reads the payload\'s image and not its copy', 'S.hdr = (const struct q1n1_wtab_header *)S.blob64;', 'S.hdr = table;',
     {'open/copy.is_private'}),
    ('an SError in the undo is ignored',
     '            undo_failure(index, "FAULT");\n            return;\n        }\n        if (S.env->serror_poll && S.env->serror_poll()) {',
     '            undo_failure(index, "FAULT");\n            return;\n        }\n        if (0) {', {'undo/undo_serror.no_readback_after_the_error_response'}),
    ('the table accepts a write row that says nothing about the bits it writes (F33)',
     '    if (!check && (r->found_mask & r->mask) != r->mask) return Q1N1_WTAB_ROW_NO_FOUND;\n', '',
     {'validate/refuses.write row with no found mask', 'validate/refuses.found mask short of the mask', 'validate/refuses.found mask covering part of the mask'}),
    ('the table accepts a write row whose found mask covers only a part of the bits it writes (F33)',
     '(r->found_mask & r->mask) != r->mask) return Q1N1_WTAB_ROW_NO_FOUND;', '(r->found_mask & r->mask) == 0) return Q1N1_WTAB_ROW_NO_FOUND;',
     {'validate/refuses.found mask covering part of the mask'}),
    ('the table can be opened twice', '    if (S.opened) {\n        refused_line(Q1N1_WTAB_REOPEN, 0);\n        return Q1N1_WTAB_REOPEN;\n    }\n', '',
     {'open/then_open.ok'}),
    ('a row over RAM is accepted', 'if (!q1n1_wtab_map_allows(&S.machine, S.rows[i].addr) && S.rows[i].mask) {', 'if (0) {', {'open/ram.refused'}),
    ('the windowed reads are not bounded', 'S.window_reads < Q1N1_WTAB_WINDOW_READS_MAX &&', '', {'gate/budget.cap'}),
    ('the end of the payload does not undo', 'if (S.hdr->flags & Q1N1_WTAB_F_RESTORE_AT_END) {', 'if (0) {', {'finish/auto.unwinds'}),
    ('an undo is not verified', 'int rc = poll_match(r->addr, r->mask, target, r->undo_timeout_us, &got, &us);', 'int rc = 0;',
     {'undo/ignored.unwind'}),
    ('an irreversible row is undone with a guess', ' || S.rows[i].undo_kind == Q1N1_WTAB_UNDO_NONE) continue;', ') continue;',
     {'undo/irreversible.unwind'}),
    ('the undo restores zero and not what was found', 'S.journal[index].old : r->undo_value', '0 : r->undo_value', {'undo/restore_bits.unwind'}),
    ('the pause of a step is not waited', 'if (wait_us((uint64_t)S.hdr->pause_s * 1000000u)) return stop(Q1N1_WTAB_COUNTER, index, 0, 0, 0, 0);', '',
     {'stops/counter_stuck.stores_made'}),
    # the review's required changes (R1-R6): each of these is the fix applied backwards
    ('R1 the row is journaled after its store (a store that faults after it wrote is never undone)',
     '        S.journal[index].old = pre;\n        S.journal[index].state = J_STORED;\n'
     '        if (S.env->store32(r->addr, next)) return stop(Q1N1_WTAB_FAULT, index, r->addr, pre, next, r->mask);\n',
     '        if (S.env->store32(r->addr, next)) return stop(Q1N1_WTAB_FAULT, index, r->addr, pre, next, r->mask);\n'
     '        S.journal[index].old = pre;\n        S.journal[index].state = J_STORED;\n',
     {'stops/store_fault_applied.word_back_to_found', 'stops/store_fault_applied.undone', 'stops/store_fault_applied.end'}),
    ('R2 no SError poll before the store (a pending error response of an earlier access is taken for the store\'s own)',
     '        if (S.env->serror_poll && S.env->serror_poll()) return stop(Q1N1_WTAB_SERROR, index, r->addr, pre, next, r->mask);\n        row_head(&line, "W", index);',
     '        row_head(&line, "W", index);',
     {'stops/serror_before_store.nothing_stored'}),
    ('R2 no SError poll after the read-back of the undo (an undo is called proven with an error response pending)',
     '    if (S.env->serror_poll && S.env->serror_poll()) {\n        S.serror_seen = 1;\n        *abort_all = 1;\n        undo_failure(index, "SERROR");\n        return;\n    }\n    if (rc) {',
     '    if (rc) {', {'undo/undo_serror_readback.fail_line', 'undo/undo_serror_readback.end'}),
    ('R3 the reserve is not kept back for the stop, the undo and the end (they are ordinary lines)',
     'S.lines >= (critical ? Q1N1_WTAB_LINES_MAX : S.ordinary_limit)', 'S.lines >= (critical ? S.ordinary_limit : S.ordinary_limit)',
     {'lines/worst_case_finish.thirty_two_lines', 'lines/worst_case_finish.end_is_last', 'lines/worst_case_stop.end_is_last'}),
    ('R3 the validator does not count the reserve',
     'return 2u + 2u * writes + (header->windows ? Q1N1_WTAB_REFUSED_LINES : 0u);', 'return 0u * writes + (header->windows ? 0u : 0u);',
     {'validate/refuses.too_many_lines', 'validate/line_cost.exact_table'}),
    ('R3 the platform is not asked for a counter that counts',
     '    if ((writes || timed) && !counter_advances()) return Q1N1_WTAB_PLATFORM;\n', '    (void)counter_advances;\n    (void)timed;\n',
     {'open/platform.stuck_counter_refused'}),
    ('R3 the platform is not asked for a store and an SError poll',
     '    if (writes && (!S.env->store32 || !S.env->serror_poll)) return Q1N1_WTAB_PLATFORM;\n', '',
     {'open/platform.no_store32_refused', 'open/platform.no_serror_poll_refused'}),
    ('R5 a table named as a draft is opened',
     'if (!Q1N1_WTAB_ALLOW_DRAFT && draft_named(h)) return Q1N1_WTAB_DRAFT;', 'if (!Q1N1_WTAB_ALLOW_DRAFT && draft_named(h) && 0) return Q1N1_WTAB_DRAFT;',
     {'validate/draft.suffix_is_the_rule', 'open/draft.open'}),
    ('R6 a write row on a page that is not Device is accepted',
     'if (S.rows[i].mask && attr != Q1N1_WTAB_ATTR_DEVICE && bad_attr == HEADER_INDEX) bad_attr = i;', '',
     {'open/attr.write_row_on_NORMAL.refused', 'open/attr.write_row_on_NONE.refused', 'open/attr.write_row_on_UNKNOWN.refused'}),
    ('R6 a page whose mapping is unknown passes for Device',
     'if (S.rows[i].mask && attr != Q1N1_WTAB_ATTR_DEVICE && bad_attr == HEADER_INDEX) bad_attr = i;',
     'if (S.rows[i].mask && attr == Q1N1_WTAB_ATTR_NORMAL && bad_attr == HEADER_INDEX) bad_attr = i;',
     {'open/attr.write_row_on_NONE.refused', 'open/attr.write_row_on_UNKNOWN.refused', 'open/attr.no_callback_is_unknown'}),
    ('R6 a check row on a page that is not Device is refused too',
     'if (S.rows[i].mask && attr != Q1N1_WTAB_ATTR_DEVICE && bad_attr == HEADER_INDEX) bad_attr = i;',
     'if (attr != Q1N1_WTAB_ATTR_DEVICE && bad_attr == HEADER_INDEX) bad_attr = i;',
     {'open/attr.check_row_on_normal_is_printed_and_opens', 'open/attr.checks_only_table_opens_on_normal_pages'}),
    ('R6 the mapping of a check row is not printed',
     '        put(&attr_line, 0);', '        if (S.rows[i].mask) put(&attr_line, 0);',
     {'run/attr.one_line_for_every_row_before_open', 'open/attr.checks_only_table_opens_on_normal_pages'}),
    # the faults the harness passed before the re-review (R-v3-3): each is the line removed that the check of the `faults` suite is about
    ('RM1 no SError poll after the read-back of a row (an error response of the read-back itself goes unseen)',
     '    if (S.env->serror_poll && S.env->serror_poll()) return stop(Q1N1_WTAB_SERROR, index, r->rb_addr, got, r->rb_value, r->rb_mask);\n', '',
     {'faults/late_serror.stops', 'faults/late_serror.names_the_readback_word'}),
    ('RM2 the undo does not wait before it proves the word',
     '    if (wait_us(r->undo_after_us)) {\n        undo_failure(index, "COUNTER");\n        return;\n    }\n', '',
     {'faults/undo_waits.proven_after_the_wait'}),
    ('RM9 a poll with a timeout does not need a usable counter',
     '    if (timeout_us && !counter_usable()) return Q1N1_WTAB_COUNTER;\n', '',
     {'faults/counter_unusable.no_frequency_stops'}),
    ('RM12 the fault of the store of one undo ends the undo of every row that is left',
     '        if (S.env->store32(r->addr, next)) {\n            undo_failure(index, "FAULT");\n            return;\n        }',
     '        if (S.env->store32(r->addr, next)) {\n            undo_failure(index, "FAULT");\n            *abort_all = 1;\n            return;\n        }',
     {'faults/undo_store_fault.the_others_are_undone_and_proven', 'faults/undo_store_fault.end'}),
    ('RM6d the mapping asked for is that of the read-back address of the row',
     'int attr = S.env->attr ? S.env->attr(S.rows[i].addr) : Q1N1_WTAB_ATTR_UNKNOWN;',
     'int attr = S.env->attr ? S.env->attr(S.rows[i].rb_mask ? S.rows[i].rb_addr : S.rows[i].addr) : Q1N1_WTAB_ATTR_UNKNOWN;',
     {'faults/attr_of_the_row.a_normal_readback_page_opens', 'faults/attr_of_the_row.a_normal_row_page_is_refused'}),
    ('RMn3 the settle time of a row is not waited',
     '    if (wait_us(r->settle_us)) return stop(Q1N1_WTAB_COUNTER, index, r->addr, 0, 0, 0);\n', '',
     {'faults/settle_waits.rows'}),
    ('RMn5 the store is made although its W line could not be printed (the BUDGET stop removed)',
     '        if (!put(&line, 0)) return stop(Q1N1_WTAB_BUDGET, index, r->addr, S.lines, S.ordinary_limit, 0);', '        (void)put(&line, 0);',
     {'faults/no_line_no_store.stops', 'faults/no_line_no_store.nothing_stored'}),
    # the pure checks of the two ops that take a pointer (the run-time answer to S38 and S39)
    ('the destination of ops.hex is only checked at its first byte, not to its end',
     'return where >= stack_base && cap <= stack_size && where - stack_base <= stack_size - cap;', 'return where >= stack_base && where - stack_base < stack_size;',
     {'ops/hex_refused.one_past_the_end', 'ops/hex_refused.longer_than_the_stack'}),
    ('the end of the destination of ops.hex is computed with a sum that wraps',
     'return where >= stack_base && cap <= stack_size && where - stack_base <= stack_size - cap;', 'return where >= stack_base && where + cap <= stack_base + stack_size;',
     {'ops/hex_refused.an_address_that_wraps'}),
    ('ops.puts is allowed to read one byte fewer than the runner reads',
     'for (uint64_t k = 0; k <= Q1N1_PAYLOAD_LINE_MAX; k++) {', 'for (uint64_t k = 0; k < Q1N1_PAYLOAD_LINE_MAX; k++) {',
     {'ops/puts_refused.the_hundred_and_first_byte_is_outside'}),
]

# The runner loop (platform/uefi/sp11-payload-run.c), judged by the same harness: (name, old, new, checks that must fail). S38 and S39 are run against the first two as well.
# The mutants from the ninth on change the window of a check, a count or a line. A window is changed by a macro that calls the same function with another argument, written inside
# the gate in front of the function that uses it, so the entries above still find their text exactly once in such a runner, and the runner without the gate is as it was. The
# mutant that charges a refusal line dropped at a full budget adds a statement inside the text of the two entries for the line budget, which it does not keep.
OP_HEX_FN = 'static uint32_t op_hex(char *dst, uint32_t cap, uint64_t value)\n'
OP_PUTS_FN = 'static void op_puts(const char *line)\n'
HEX_OK_MACRO = '#if Q1N1_SP11_WTAB\n#define q1n1_wtab_hex_ok(d, c, sb, ss) q1n1_wtab_hex_ok(d, c, %s)\n#endif\n'
PUTS_OK_MACRO = '#if Q1N1_SP11_WTAB\n#define q1n1_wtab_puts_ok(l, sb, ss, ib, im) q1n1_wtab_puts_ok(l, %s)\n#endif\n'
OPS_RUNNER_MUTANTS = [
    ('the destination of ops.hex is not checked', 'if (!q1n1_wtab_hex_ok(dst, cap, session.stack_base, session.stack_size)) {', 'if (0) {',
     {'ops/hex_outside_the_stack.nothing_is_written'}),
    ('the string of ops.puts is not checked',
     'if (!q1n1_wtab_puts_ok(line, session.stack_base, session.stack_size, session.image_base, session.image_size)) {', 'if (0) {',
     {'ops/puts_of_a_string_in_neither.is_not_read'}),
    ('a refusal of ops.hex or ops.puts is not counted', '    session.refused++;\n    if (session.op_lines & bit) return;', '    if (session.op_lines & bit) return;',
     {'ops/hex_outside_the_stack.is_counted_and_on_the_page'}),
    ('every refusal is a line of the page, not the first of each op', '    if (session.op_lines & bit) return;\n', '',
     {'ops/hex_refused_three_times.counted_three_times_on_the_page_once'}),
    ('a refusal line is printed past the line budget', '    if (Q1N1_PAYLOAD_LINES_MAX <= session.lines) {\n        session.dropped++;\n        return;\n    }\n    q1n1_payload_line_begin(&line, "PAYLOAD OP REFUSED");',
     '    q1n1_payload_line_begin(&line, "PAYLOAD OP REFUSED");', {'ops/hex_refused_at_the_line_budget.is_counted_and_the_done_line_says_so'}),
    ('the destination of ops.load32 is not checked against the stack (the check that was there before the table)',
     'if (stack_size < 4 || where < stack_base || where - stack_base > stack_size - 4) return Q1N1_PAYLOAD_LOAD_E_OUT;\n', '(void)stack_base;\n    (void)stack_size;\n',
     {'ops/load32_out_of_the_stack.is_still_refused'}),
    ('ops.hex and ops.puts share one bit of "the first refusal of this op was printed"', 'refuse_pointer_op(2u, "PUTS", line, 0);', 'refuse_pointer_op(1u, "PUTS", line, 0);',
     {'ops/hex_and_puts_both_refused.each_op_has_its_own_line'}),
    ('ops.hex may write into the payload\'s image (the destination is the stack only); the check of the stack stays as it was',
     'static uint32_t op_hex(char *dst, uint32_t cap, uint64_t value)\n{\n#if Q1N1_SP11_WTAB\n',
     'static uint32_t op_hex(char *dst, uint32_t cap, uint64_t value)\n{\n#if Q1N1_SP11_WTAB\n'
     '    if (q1n1_wtab_hex_ok(dst, cap, session.image_base, session.image_size)) return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value);\n',
     {'ops/hex_into_the_image.nothing_is_written'}),
    # What follows: one change each at an edge of a window, in a count or in a line (a probe far from an edge passes them all).
    ('a refused ops.hex still writes one byte through its destination when that starts inside the stack and the range leaves it',
     '        refuse_pointer_op(1u, "HEX", dst, cap);\n        return 0;\n',
     '        refuse_pointer_op(1u, "HEX", dst, cap);\n'
     '        if (cap && (uintptr_t)dst >= session.stack_base && (uintptr_t)dst - session.stack_base < session.stack_size) dst[0] = 0;\n        return 0;\n',
     {'ops/hex_leaving_the_stack_from_inside.stack_bytes_untouched'}),
    ('the window of ops.hex is 8 bytes longer at its end (a call-site argument)', OP_HEX_FN, HEX_OK_MACRO % '(sb), (ss) + 8' + OP_HEX_FN,
     {'ops/hex_one_past_the_end_of_the_stack.nothing_is_written'}),
    ('the window of ops.hex starts 8 bytes below the stack (a call-site argument)', OP_HEX_FN, HEX_OK_MACRO % '(sb) - 8, (ss) + 8' + OP_HEX_FN,
     {'ops/hex_one_below_the_stack.nothing_is_written'}),
    ('a refusal line is printed but not charged to the lines of the payload', '    session.lines++;\n    session.env->emit(line.buf);\n}\n#endif',
     '    session.env->emit(line.buf);\n}\n#endif', {'ops/hex_and_puts_both_refused.two_lines_are_charged_to_the_budget'}),
    ('ops.hex may write into the image at its first byte only (a hole of one byte)',
     'static uint32_t op_hex(char *dst, uint32_t cap, uint64_t value)\n{\n#if Q1N1_SP11_WTAB\n',
     'static uint32_t op_hex(char *dst, uint32_t cap, uint64_t value)\n{\n#if Q1N1_SP11_WTAB\n'
     '    if (cap && (uint64_t)(uintptr_t)dst == session.image_base) return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value);\n',
     {'ops/hex_at_the_first_byte_of_the_image.nothing_is_written'}),
    ('a refusal line shows A=0 instead of the pointer', '    q1n1_payload_line_hex(&line, "A", (uint64_t)(uintptr_t)where);\n',
     '    (void)where;\n    q1n1_payload_line_hex(&line, "A", 0);\n', {'ops/hex_outside_the_stack.the_line_names_the_pointer_and_cap'}),
    ('a refusal at a full line budget is tried again at the next call: DROPPED counts every refusal, not the one line of the op',
     '    session.op_lines |= bit;\n    if (Q1N1_PAYLOAD_LINES_MAX <= session.lines) {\n        session.dropped++;\n        return;\n    }\n'
     '    q1n1_payload_line_begin(&line, "PAYLOAD OP REFUSED");\n',
     '    if (Q1N1_PAYLOAD_LINES_MAX <= session.lines) {\n        session.dropped++;\n        return;\n    }\n'
     '    q1n1_payload_line_begin(&line, "PAYLOAD OP REFUSED");\n    session.op_lines |= bit;\n',
     {'ops/hex_and_puts_refused_at_the_line_budget.dropped_once_per_op'}),
    ('the window of ops.hex leaves out the two guard words at the stack base: a write there is refused instead of accepted and reported by the guard',
     OP_HEX_FN, HEX_OK_MACRO % '(sb) + 16, (ss) - 16' + OP_HEX_FN, {'ops/hex_first_byte_of_the_stack.is_written_and_the_guard_reports_it'}),
    ('the stack window of ops.puts is 8 bytes longer at its end (a call-site argument)', OP_PUTS_FN, PUTS_OK_MACRO % 'sb, (ss) + 8, ib, im' + OP_PUTS_FN,
     {'ops/puts_at_the_first_byte_past_the_stack.is_not_read'}),
    ('the stack window of ops.puts starts 8 bytes below the stack (a call-site argument)', OP_PUTS_FN, PUTS_OK_MACRO % '(sb) - 8, (ss) + 8, ib, im' + OP_PUTS_FN,
     {'ops/puts_one_below_the_stack.is_not_read'}),
    # The probes that close the mutants of one byte: a window longer by one byte, a dropped line that is still charged, a hole of one byte at the last byte of the image.
    ('the stack window of ops.puts is longer by one byte at its end (a call-site argument)', OP_PUTS_FN, PUTS_OK_MACRO % 'sb, (ss) + 1, ib, im' + OP_PUTS_FN,
     {'ops/puts_at_the_first_byte_past_the_stack.empty_string_is_not_read'}),
    ('a refusal line dropped at a full line budget is still charged to the lines of the payload',
     '        session.dropped++;\n        return;\n    }\n    q1n1_payload_line_begin(&line, "PAYLOAD OP REFUSED");',
     '        session.dropped++;\n        session.lines++;\n        return;\n    }\n    q1n1_payload_line_begin(&line, "PAYLOAD OP REFUSED");',
     {'ops/hex_and_puts_refused_at_the_line_budget.dropped_once_per_op'}),
    ('ops.hex may write into the image at its last byte only (a hole of one byte)',
     'static uint32_t op_hex(char *dst, uint32_t cap, uint64_t value)\n{\n#if Q1N1_SP11_WTAB\n',
     'static uint32_t op_hex(char *dst, uint32_t cap, uint64_t value)\n{\n#if Q1N1_SP11_WTAB\n'
     '    if (cap && (uint64_t)(uintptr_t)dst == session.image_base + session.image_size - 1) return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value);\n',
     {'ops/hex_at_every_byte_of_the_image.nothing_is_written'}),
]


def apply_once(text, old, new):
    """`text` with `old` replaced by `new`; an error when `old` is not there exactly once (a seeded bug that changed nothing proves nothing)."""
    found = text.count(old)
    if found != 1:
        raise ValueError(f'the seeded text occurs {found} times: {old[:70]!r}')
    return text.replace(old, new)
