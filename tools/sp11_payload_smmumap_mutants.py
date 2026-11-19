# SPDX-License-Identifier: MIT
"""Seeded bugs for the runner's mapping step (docs/SP11-PAYLOAD-SMMUMAP.md, tools/test-q1n1-sp11-payload-smmumap.py).

Each one edits a copy of platform/uefi/sp11-smmumap.c, sp11-smmumap.h or sp11-payload-run.c and builds one of the host programs against the copy (under
ASan and UBSan, as the shipped suites are), then runs it: `main` is tools/test-q1n1-sp11-payload-smmumap.c (the suites over the modelled machine),
`walk` is tools/test-q1n1-sp11-payload-smmumap-walk.c (the proven load, the static walk, the scan and their table arithmetic, by including the source), `hook` is
tools/test-q1n1-sp11-payload-smmumap-run.c (the hook in the runner). A needle that does not occur exactly once is a stale mutant and an error, never a
pass. A mutant is caught only for its own reason: the host program must fail and the FAIL lines it prints (or the sanitizer's report) must match
`reason`, a regular expression over the program's own words; a program that fails for another reason (a crash nobody expected, a hang) is
`wrong-reason`, not a pass. `flags` builds the host program with the lowered bounds on the reads of a wait, where a failure needs them. The
instructions of platform/uefi/sp11-smmumap-el2.c and the store of platform/uefi/main.c cannot be run on the host: their seeded bugs are in
tools/test-q1n1-sp11-payload-smmumap.py, against the source audit. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only); serial on purpose,
one build and one run at a time."""
from pathlib import Path
import re
import shutil
import subprocess

LOGIC = 'sp11-smmumap.c'
HEADER = 'sp11-smmumap.h'
RUNNER = 'sp11-payload-run.c'
SPIN = ('-DSMMUMAP_SPIN_MAX=1000u', '-DSMMUMAP_STUCK_READS=100u', '-DTEST_SPIN_MAX=1000')
SPIN_SUITES = ('counter', 'fuzz')
PUBLISH_DSB = 'env->tlbi(page_va);\n    env->dsb();'
WALK_CHECK = 'if (!(par & 1u) || ((par >> 1) & 0x3fu) != FST_TRANSLATION_L3 || (par & PAR_FAULT_STAGE2))'
SLOT_CHECK = 'if (((slot & UINT64_C(0xfff)) >> 3) != ((spec->page_pa >> 12) & UINT64_C(0x1ff)) || (slot & ~UINT64_C(0xfff)) != target.table)'
REREAD = ('    /* The slot was read as zero in the walk, eight seconds and a few thousand reads ago: read it once more, just before the store (through\n'
          '     * load_ram with a proof of its own, so that the page is asked about again). */\n'
          '    reread.page = reread.attr = 0;\n'
          '    reread.type = reread.ok = 0;\n'
          '    got = load_ram(env, slot, &again, &reread);\n'
          '    if (got == LOAD_NOT_RAM) return refuse_not_ram(env, out, &reread, 3);\n'
          '    if (got == LOAD_ABORT) return refuse(env, out, Q1N1_SMMUMAP_R_WALK_FAULT, "LEVEL", 3, 0, 0);\n'
          '    if (again) return refuse(env, out, Q1N1_SMMUMAP_R_ENTRY_NOT_ZERO, "DESC", again, 0, 0);\n')
HOOK_VERIFY = '        if (!q1n1_payload_verify_in_place(loaded, index)) {\n            uint8_t now[32];'


def sub(name, file, old, new, reason, flags=(), program='main'):
    return (name, file, [(old, new)], reason, tuple(flags), program)


def two(name, file, edits, reason, flags=(), program='main'):
    return (name, file, list(edits), reason, tuple(flags), program)


MUTANTS = [
    # -- the descriptor: the one page, the template's attributes and nothing else
    sub('the-descriptor-copies-the-contiguous-bit', LOGIC, '(template_desc & (Q1N1_SMMUMAP_ATTR_LOW | Q1N1_SMMUMAP_ATTR_HIGH))',
        '(template_desc & (Q1N1_SMMUMAP_ATTR_LOW | Q1N1_SMMUMAP_ATTR_HIGH | (UINT64_C(1) << 52)))', r'not attributes|bits of the template'),
    sub('the-descriptor-leaves-out-execute-never', LOGIC, '(template_desc & (Q1N1_SMMUMAP_ATTR_LOW | Q1N1_SMMUMAP_ATTR_HIGH))',
        '(template_desc & Q1N1_SMMUMAP_ATTR_LOW)', r'descriptor of the template|the first store|the descriptor is'),
    sub('the-descriptor-check-accepts-a-block-type', LOGIC, 'if ((desc & UINT64_C(3)) != UINT64_C(3)) return 0;', '', r'block/reserved type'),
    sub('the-descriptor-check-ignores-the-address', LOGIC, 'if ((desc & Q1N1_SMMUMAP_ADDR) != page_pa) return 0;', '', r'another page.s address|judged wrongly'),
    sub('the-descriptor-check-allows-any-high-bit', LOGIC, 'return !(desc & ~(Q1N1_SMMUMAP_ADDR | UINT64_C(3) | Q1N1_SMMUMAP_ATTR_LOW | Q1N1_SMMUMAP_ATTR_HIGH));',
        'return 1;', r'judged wrongly'),
    # -- the template
    sub('the-template-check-accepts-gre', LOGIC, 'if (attr != 0x00u && attr != 0x04u) return', 'if (attr != 0x00u && attr != 0x04u && attr != 0x0cu) return', r'MAIR byte 0c'),
    sub('the-template-check-refuses-only-the-all-ones-byte', LOGIC, 'if (attr != 0x00u && attr != 0x04u) return', 'if (attr == 0xffu) return', r'MAIR byte|not Device-nGnRnE'),
    sub('the-template-check-ignores-the-access-flag', LOGIC, '!(desc & DESC_AF) || (desc & DESC_AP_RO)', '(desc & DESC_AP_RO)', r'AF clear'),
    sub('the-template-check-ignores-read-only', LOGIC, '(desc & DESC_AP_RO) || !(desc & DESC_XN)', '!(desc & DESC_XN)', r'read-only'),
    sub('the-template-check-ignores-execute-never', LOGIC, '(desc & DESC_AP_RO) || !(desc & DESC_XN)', '(desc & DESC_AP_RO)', r'executable'),
    sub('the-template-attribute-comes-from-the-wrong-index', LOGIC, 'unsigned index = (unsigned)((desc >> 2) & 7u);', 'unsigned index = (unsigned)((desc >> 3) & 7u);',
        r'MAIR byte'),
    sub('the-template-agreement-of-the-at-is-not-asked', LOGIC, 'if ((par_template & 1u) || (par_template >> 56) != mair_byte)', 'if (0)', r'AT of the template'),
    # -- the walk
    sub('the-walk-reads-the-wrong-index', LOGIC, 'at = table + ((va >> shift) & 0x1ffu) * 8u;', 'at = table + ((va >> shift) & 0x1ffu) * 4u;', r'the good world|first store'),
    sub('the-walk-does-not-check-the-table-address', LOGIC, 'if (table >> pa_bits) return WALK_ADDRESS;', '', r'physical address size|PS'),
    sub('the-walk-ignores-an-aborted-read', LOGIC, 'if (got == LOAD_ABORT) return WALK_FAULT;', '', r'a read of the walk aborts'),
    sub('the-walk-forgets-the-control-bits', LOGIC, 'w->upper |= desc & TABLE_UPPER_BITS;', '', r'hierarchical control bit|every control bit'),
    sub('the-control-bits-mask-misses-bit-59', LOGIC, '#define TABLE_UPPER_BITS UINT64_C(0xf800000000000000)', '#define TABLE_UPPER_BITS UINT64_C(0xf000000000000000)',
        r'hierarchical control bit'),
    sub('a-reserved-level-3-form-is-a-hole', LOGIC, 'if (level == 3u) return (desc & 3u) == 3u ? WALK_PAGE : WALK_FORMAT;', 'if (level == 3u) return WALK_PAGE;',
        r'reserved level-3 form|invalid'),
    sub('a-valid-entry-is-not-refused-by-name', LOGIC, 'if (status == WALK_PAGE) return refuse(env, out, Q1N1_SMMUMAP_R_ENTRY_VALID, "DESC", target.desc[3], 0, 0);', '',
        r'ENTRY_VALID'),
    sub('a-non-zero-invalid-entry-is-overwritten', LOGIC, 'if (target.desc[3]) return refuse(env, out, Q1N1_SMMUMAP_R_ENTRY_NOT_ZERO, "DESC", target.desc[3], 0, 0);', '',
        r'ENTRY_NOT_ZERO|tables changed|refused after the walk'),
    sub('a-level-3-table-that-is-a-table-above-is-accepted', LOGIC, 'for (i = 0; i < 3; i++)\n        if (target.base[i] == target.table)', 'for (i = 0; i < 0; i++)\n        if (target.base[i] == target.table)',
        r'TABLE_SHARED|another level of the path'),
    sub('a-level-3-table-that-is-the-templates-is-accepted', LOGIC, 'for (i = 0; i <= tpl.last; i++)', 'for (i = 0; i < 0; i++)', r'TABLE_SHARED|another level of the path'),
    # -- the instruction against the walk, the table page, the check after the store
    sub('the-first-at-only-has-to-fault', LOGIC, WALK_CHECK, 'if (!(par & 1u))', r'not a level-3 translation fault'),
    sub('the-first-at-is-not-asked-at-all', LOGIC, WALK_CHECK, 'if (0)', r'already mapped|not a level-3 translation fault'),
    sub('the-table-page-is-not-asked-for-a-write', LOGIC, 'if (!par_page(par_table, target.table) || !((par_table >> 56) & 0xf0u))', 'if (0)',
        r'table page|TABLE_NOT_WRITABLE'),
    sub('a-device-table-page-is-accepted', LOGIC, ' || !((par_table >> 56) & 0xf0u))', ')', r'table page is Device'),
    sub('the-table-pages-address-is-not-compared', LOGIC, 'if (!par_page(par_table, target.table)', 'if ((par_table & 1u)', r'another page'),
    two('the-slot-index-is-wrong-and-not-checked', LOGIC, [('at = table + ((va >> shift) & 0x1ffu) * 8u;', 'at = table + ((va >> shift) & 0x1ffu) * 8u + (level == 3u ? 8u : 0u);'),
                                                          (SLOT_CHECK, 'if (0)')], r'first store went to|page.s level-3 slot'),
    sub('the-check-after-the-store-ignores-the-write', LOGIC, 'par_page(par_r, spec->page_pa) && par_page(par_w, spec->page_pa) &&', 'par_page(par_r, spec->page_pa) &&',
        r'not writable|write reaches'),
    sub('the-check-after-the-store-ignores-the-attributes', LOGIC, ' && !((par_r ^ par_template) & PAR_ATTR_MASK);', ';', r'attributes are not the template'),
    sub('the-check-after-the-store-ignores-the-address', LOGIC, 'par_page(par_r, spec->page_pa) && par_page(par_w, spec->page_pa)', '!(par_r & 1u) && par_page(par_w, spec->page_pa)',
        r'translates to another page'),
    # -- the publication (the model sees a store only after clean, dsb, tlbi, dsb, isb in that order) and the put-back
    sub('the-slot-is-not-cleaned', LOGIC, 'env->clean(slot);', '', r'good world is not mapped|effects|publication'),
    sub('the-first-barrier-is-missing', LOGIC, 'env->clean(slot);\n    env->dsb();', 'env->clean(slot);', r'good world is not mapped|effects|publication'),
    sub('the-invalidation-is-missing', LOGIC, 'env->tlbi(page_va);\n', '', r'good world is not mapped|effects|publication'),
    sub('the-invalidation-is-of-the-slot', LOGIC, 'env->tlbi(page_va);', 'env->tlbi(slot);', r'effect 14|good world is not mapped|publication'),
    sub('the-second-barrier-is-missing', LOGIC, PUBLISH_DSB, 'env->tlbi(page_va);', r'good world is not mapped|effects|publication'),
    sub('the-isb-is-missing', LOGIC, 'env->dsb();\n    env->isb();', 'env->dsb();', r'good world is not mapped|effects|publication'),
    sub('the-invalidation-comes-before-the-first-barrier', LOGIC, 'env->dsb();\n    env->tlbi(page_va);', 'env->tlbi(page_va);\n    env->dsb();', r'good world is not mapped|effects|publication'),
    sub('a-failed-check-does-not-put-the-descriptor-back', LOGIC, 'if (remove_descriptor(env, out, slot, spec->page_pa)) {', 'if (1) {', r'stores|put back'),
    sub('the-put-back-is-not-verified', LOGIC, 'return (par & 1u) != 0;                 /* it translates no more */', 'return 1;', r'still translates|put-back store aborts'),
    two('an-unsafe-result-is-a-refusal', LOGIC, [('done(env, out, Q1N1_SMMUMAP_UNSAFE, Q1N1_SMMUMAP_R_ROLLBACK_FAILED);\n            return Q1N1_SMMUMAP_UNSAFE;',
                                                  'done(env, out, Q1N1_SMMUMAP_REFUSED, Q1N1_SMMUMAP_R_ROLLBACK_FAILED);\n            return Q1N1_SMMUMAP_REFUSED;')],
        r'status|UNSAFE|put-back'),
    sub('an-aborted-store-is-ignored', LOGIC, 'if (env->store64(slot, desc)) return refuse(env, out, Q1N1_SMMUMAP_R_STORE_FAULT, "SLOT", slot, 0, 0);',
        'env->store64(slot, desc);', r'the store aborts'),
    # -- the regime and the root
    sub('the-root-is-not-pinned', LOGIC, 'if (r->ttbr0 != Q1N1_SMMUMAP_TTBR0_EL2) return Q1N1_SMMUMAP_R_TTBR0_UNPINNED;', '', r'another TTBR0_EL2|CnP'),
    sub('e2h-is-ignored', LOGIC, 'if (r->hcr & HCR_E2H) return Q1N1_SMMUMAP_R_REGIME;', '', r'E2H set'),
    sub('the-mmu-off-is-ignored', LOGIC, 'if (!(r->sctlr & SCTLR_M) || (r->sctlr & SCTLR_EE)) return Q1N1_SMMUMAP_R_REGIME;', 'if (r->sctlr & SCTLR_EE) return Q1N1_SMMUMAP_R_REGIME;', r'MMU off'),
    sub('big-endian-walks-are-ignored', LOGIC, 'if (!(r->sctlr & SCTLR_M) || (r->sctlr & SCTLR_EE)) return Q1N1_SMMUMAP_R_REGIME;', 'if (!(r->sctlr & SCTLR_M)) return Q1N1_SMMUMAP_R_REGIME;',
        r'big-endian'),
    sub('the-granule-is-ignored', LOGIC, 'if ((r->tcr >> 14) & 3u) return Q1N1_SMMUMAP_R_REGIME;', '', r'KiB granule'),
    sub('the-t0sz-range-is-open-above', LOGIC, 'if (t0sz < 16u || t0sz > 39u) return Q1N1_SMMUMAP_R_REGIME;', 'if (t0sz < 16u) return Q1N1_SMMUMAP_R_REGIME;', r'T0SZ'),
    sub('the-regime-is-judged-after-the-walk', LOGIC, '    reason = regime(&regs);\n    if (reason) return refuse(env, out, reason, "TTBR0", regs.ttbr0, "TCR", regs.tcr);\n',
        '', r'before the regime was judged|another TTBR0_EL2|E2H set|MMU off'),
    # -- the wait: NEXT line, bounds, counter (the lowered-bound builds make the bound matter)
    sub('the-wait-is-not-made', LOGIC, 'reason = wait_seconds(env, Q1N1_SMMUMAP_WAIT_S);\n    if (reason) return refuse(env, out, reason, 0, 0, 0, 0);', 'reason = 0;',
        r'ticks from the NEXT line|no counter|counter that'),
    sub('a-missing-counter-counts-as-a-made-wait', LOGIC, 'if (!env->counter) return Q1N1_SMMUMAP_R_NO_COUNTER;', 'if (!env->counter) return Q1N1_SMMUMAP_R_NONE;', r'no counter'),
    sub('a-counter-that-goes-back-is-not-seen', LOGIC, 'if (now < start) return Q1N1_SMMUMAP_R_COUNTER_UNUSABLE;', '', r'counter that goes back'),
    sub('a-frequency-outside-the-window-is-used', LOGIC, 'if (freq < COUNTER_HZ_MIN || freq > COUNTER_HZ_MAX) freq = COUNTER_HZ_DEFAULT;', '', r'frequency'),
    sub('a-stuck-counter-is-not-seen', LOGIC, 'if (++same >= SMMUMAP_STUCK_READS) return Q1N1_SMMUMAP_R_COUNTER_UNUSABLE;', '++same;', r'stuck counter|a stuck counter', SPIN),
    sub('the-spin-bound-is-called-a-dead-counter', LOGIC, 'if (++spins >= SMMUMAP_SPIN_MAX) return Q1N1_SMMUMAP_R_SPIN_BOUND;',
        'if (++spins >= SMMUMAP_SPIN_MAX) return Q1N1_SMMUMAP_R_COUNTER_UNUSABLE;', r'moves too slowly|bound', SPIN),
    sub('the-spin-bound-is-never-hit', LOGIC, 'if (++spins >= SMMUMAP_SPIN_MAX) return Q1N1_SMMUMAP_R_SPIN_BOUND;', '++spins;', r'moves too slowly|bound', SPIN),
    # -- the page, the template, the root: a wrong base, and the likeliest slip, the two swapped
    sub('the-page-address-is-wrong', HEADER, '#define Q1N1_SMMUMAP_PAGE_PA UINT64_C(0x15400000)', '#define Q1N1_SMMUMAP_PAGE_PA UINT64_C(0x15410000)', r'allow-list|PAGE|the good world'),
    sub('the-template-address-is-wrong', HEADER, '#define Q1N1_SMMUMAP_TEMPLATE_PA UINT64_C(0x70000000)', '#define Q1N1_SMMUMAP_TEMPLATE_PA UINT64_C(0x70001000)',
        r'allow-list|TEMPLATE|the good world'),
    sub('the-root-is-wrong', HEADER, '#define Q1N1_SMMUMAP_TTBR0_EL2 UINT64_C(0xA7F2E000)', '#define Q1N1_SMMUMAP_TTBR0_EL2 UINT64_C(0xA7F2F000)', r'pinned root'),
    sub('the-wait-is-seven-seconds', HEADER, '#define Q1N1_SMMUMAP_WAIT_S 8u', '#define Q1N1_SMMUMAP_WAIT_S 7u', r'pinned root or the wait|NEXT STORE AFTER'),
    sub('the-page-and-the-template-are-swapped', LOGIC, '{"PCIE_SMMU0", Q1N1_SMMUMAP_PAGE_PA, Q1N1_SMMUMAP_TEMPLATE_PA},', '{"PCIE_SMMU0", Q1N1_SMMUMAP_TEMPLATE_PA, Q1N1_SMMUMAP_PAGE_PA},',
        r'allow-list|PAGE'),
    sub('a-second-page-is-on-the-list', LOGIC, '{"PCIE_SMMU0", Q1N1_SMMUMAP_PAGE_PA, Q1N1_SMMUMAP_TEMPLATE_PA},',
        '{"PCIE_SMMU0", Q1N1_SMMUMAP_PAGE_PA, Q1N1_SMMUMAP_TEMPLATE_PA},\n    {"OTHER", UINT64_C(0x15410000), Q1N1_SMMUMAP_TEMPLATE_PA},', r'allow-list'),
    sub('the-list-is-not-consulted', LOGIC, 'if (!allowed) {', 'if (0) {', r'was accepted|OTHER_PAGE|SAME|ZERO|SWAPPED|WIDE'),
    # -- the text
    sub('a-refusal-has-no-name', LOGIC, 'case Q1N1_SMMUMAP_R_TABLE_SHARED: return "TABLE_SHARED";', '', r'has no name|TABLE_SHARED'),
    sub('the-done-line-says-mapped-for-a-refusal', LOGIC, 'q1n1_payload_line_dec(&line, "MAPPED", status == Q1N1_SMMUMAP_MAPPED);', 'q1n1_payload_line_dec(&line, "MAPPED", 1);', r'last line'),
    # -- v2, PAR_EL1: bit 8 is PTW and bit 9 is S, so a stage-2 fault is either; and the mask of the attributes holds the type, NS and SH
    sub('the-stage-2-test-is-ptw-only', LOGIC, '#define PAR_FAULT_STAGE2 (UINT64_C(3) << 8)', '#define PAR_FAULT_STAGE2 (UINT64_C(1) << 8)', r'stage-2 bit \(PTW or S\)'),
    sub('the-stage-2-test-is-s-only', LOGIC, '#define PAR_FAULT_STAGE2 (UINT64_C(3) << 8)', '#define PAR_FAULT_STAGE2 (UINT64_C(1) << 9)', r'stage-2 bit \(PTW or S\)'),
    sub('the-attribute-mask-leaves-out-shareability-and-ns', LOGIC, '#define PAR_ATTR_MASK (UINT64_C(0xff00000000000000) | UINT64_C(0x380))',
        '#define PAR_ATTR_MASK UINT64_C(0xff00000000000000)', r'shareability or NS differs'),
    sub('the-attribute-mask-leaves-out-the-memory-type', LOGIC, '#define PAR_ATTR_MASK (UINT64_C(0xff00000000000000) | UINT64_C(0x380))',
        '#define PAR_ATTR_MASK UINT64_C(0x380)', r'attributes are not the template'),
    # -- v2, the walk (the white-box program reaches what a black-box page and template cannot: a level-0 leaf, other regimes)
    sub('a-level-0-block-leaf-is-a-block', LOGIC, 'return level == 0u ? WALK_FORMAT : WALK_BLOCK;', 'return WALK_BLOCK;', r'level-0 block', program='walk'),
    sub('a-level-0-block-leaf-is-a-table', LOGIC, 'if ((desc & 3u) == 1u) return level == 0u ? WALK_FORMAT : WALK_BLOCK;', 'if ((desc & 3u) == 1u && level != 0u) return WALK_BLOCK;', r'level-0 block|bit 0 clear', program='walk'),
    sub('the-start-level-is-one-too-low', LOGIC, 'unsigned level = 4u - (bits - 12u + 8u) / 9u;', 'unsigned level = 4u - (bits - 12u + 9u) / 9u;', r'the walk starts at level|runtime error', program='walk'),
    sub('the-physical-address-size-of-ps-4-is-48-bits', LOGIC, 'static const unsigned bits[] = {32, 36, 40, 42, 44, 48};', 'static const unsigned bits[] = {32, 36, 40, 42, 48, 48};',
        r'PS 4 is|a root beyond PS', program='walk'),
    sub('a-start-table-has-512-entries', LOGIC, 'return top >= 9u ? 512u : 1u << top;', 'return 512u;', r'number of entries of a start table', program='walk'),
    sub('a-start-table-has-one-entry-too-few', LOGIC, 'return top >= 9u ? 512u : 1u << top;', 'return top >= 9u ? 512u : (1u << top) - 1u;', r'number of entries of a start table', program='walk'),
    sub('the-index-of-a-level-is-shifted-wrongly', LOGIC, 'uint32_t shift = 12u + 9u * (3u - level);', 'uint32_t shift = 12u + 9u * (3u - level) + (level == 2u ? 1u : 0u);',
        r'the index into each table', program='walk'),
    sub('an-aborted-read-is-a-hole', LOGIC, 'if (got == LOAD_ABORT) return WALK_FAULT;', 'if (got == LOAD_ABORT) return WALK_INVALID;', r'a read that aborts', program='walk'),
    sub('the-controls-of-a-leaf-are-added-to-those-of-the-tables', LOGIC, 'w->desc[level] = desc;\n', 'w->desc[level] = desc;\n        w->upper |= desc & TABLE_UPPER_BITS;\n',
        r'the control bits of the tables passed', program='walk'),
    two('the-fault-level-is-the-last-that-worked', LOGIC, [('w->base[level] = table;\n        w->last = level;\n        got = load_ram(',
                                                           'w->base[level] = table;\n        got = load_ram('),
                                                          ('w->at[level] = at;\n        if (!(desc & 1u)) return WALK_INVALID;', 'w->at[level] = at;\n        w->last = level;\n        if (!(desc & 1u)) return WALK_INVALID;')],
        r'the abort at level|the line is'),
    # -- v2, the slot is read once more just before the store (a store into a slot that another agent has filled in the eight seconds)
    sub('the-reread-of-the-slot-is-not-made', LOGIC, REREAD, '', r'written while the step waits'),
    sub('the-reread-abort-is-ignored', LOGIC, '    if (got == LOAD_ABORT) return refuse(env, out, Q1N1_SMMUMAP_R_WALK_FAULT, "LEVEL", 3, 0, 0);\n', '', r'read of the slot just before the store aborts'),
    sub('the-reread-value-is-not-judged', LOGIC, 'if (again) return refuse(env, out, Q1N1_SMMUMAP_R_ENTRY_NOT_ZERO, "DESC", again, 0, 0);', '', r'written while the step waits'),
    sub('the-reread-reads-the-next-slot', LOGIC, 'got = load_ram(env, slot, &again, &reread);', 'got = load_ram(env, slot + 8u, &again, &reread);',
        r'written while the step waits|not preceded by a read of the slot|good world is not mapped'),
    two('the-reread-is-made-before-the-wait', LOGIC, [(REREAD, ''),
                                                      ('    q1n1_payload_fmt_dec(seconds, sizeof seconds, Q1N1_SMMUMAP_WAIT_S);\n',
                                                       REREAD + '    q1n1_payload_fmt_dec(seconds, sizeof seconds, Q1N1_SMMUMAP_WAIT_S);\n')], r'written while the step waits'),
    sub('a-non-zero-reread-is-an-abort', LOGIC, 'return refuse(env, out, Q1N1_SMMUMAP_R_ENTRY_NOT_ZERO, "DESC", again, 0, 0);', 'return refuse(env, out, Q1N1_SMMUMAP_R_WALK_FAULT, "LEVEL", 3, 0, 0);',
        r'written while the step waits'),
    # -- v3, every table page of every load is proven RAM by the memory map the runner kept (the same predicate as the payloads') before the load
    sub('the-ram-check-is-not-made', LOGIC, '    if (!p->ok) return LOAD_NOT_RAM;\n', '', r'loads into a page that the memory map does not call RAM'),
    sub('the-load-is-made-before-the-proof-is-judged', LOGIC, '    if (!p->ok) return LOAD_NOT_RAM;\n    return env->read64(at, value) ? LOAD_ABORT : LOAD_OK;',
        '    int aborted = env->read64(at, value);\n    if (!p->ok) return LOAD_NOT_RAM;\n    return aborted ? LOAD_ABORT : LOAD_OK;', r'loads into a page that the memory map does not call RAM'),
    sub('the-proof-of-the-first-page-is-kept-for-every-page', LOGIC, 'if (!p->ok || p->page != page) {', 'if (!p->ok) {', r'loads into a page that the memory map does not call RAM|the proof is of the last page only'),
    sub('a-page-that-is-not-ram-is-remembered-as-ram', LOGIC, 'p->ok = q1n1_smmumap_ram_type(p->type);', 'p->ok = 1;', r'loads into a page that the memory map does not call RAM|the line is'),
    sub('the-proof-is-of-the-next-page', LOGIC, 'env->map_stride, page, PAGE_BYTES, &p->attr);', 'env->map_stride, page + PAGE_BYTES, PAGE_BYTES, &p->attr);', r'the line is|loads into a page that the memory map does not call RAM'),
    sub('the-walk-loads-without-the-proof', LOGIC, '        got = load_ram(env, at, &desc, &w->proof);', '        got = env->read64(at, &desc) ? LOAD_ABORT : LOAD_OK;',
        r'loads into a page that the memory map does not call RAM'),
    sub('the-scan-loads-the-level-3-table-without-the-proof', LOGIC, '        if (at == slot) continue;\n        got = load_ram(env, at, &value, &s->bad);',
        '        if (at == slot) continue;\n        got = env->read64(at, &value) ? LOAD_ABORT : LOAD_OK;', r'at the scan|loads into a page that the memory map does not call RAM'),
    sub('the-scan-loads-the-path-without-the-proof', LOGIC, '            uint64_t at = target->base[level] + 8u * i;\n            got = load_ram(env, at, &value, &s->bad);',
        '            uint64_t at = target->base[level] + 8u * i;\n            got = env->read64(at, &value) ? LOAD_ABORT : LOAD_OK;', r'at the scan|loads into a page that the memory map does not call RAM'),
    sub('the-reread-loads-without-the-proof', LOGIC, 'got = load_ram(env, slot, &again, &reread);', 'got = env->read64(slot, &again) ? LOAD_ABORT : LOAD_OK;',
        r'read once more before the store|loads into a page that the memory map does not call RAM'),
    sub('a-path-table-that-is-not-ram-is-skipped-by-the-scan', LOGIC, '            if (got != LOAD_OK) {\n                s->at = at;\n                s->level = level;\n                return got;\n            }',
        '            if (got == LOAD_NOT_RAM) { s->refs[level] = -1; break; }\n            if (got != LOAD_OK) {\n                s->at = at;\n                s->level = level;\n                return got;\n            }',
        r'at the scan'),
    sub('the-scan-skips-the-start-level-too', LOGIC, 'if (level < first) continue;', 'if (level <= first) continue;', r'REFS|the scan of a regime that starts at level 1|PAYLOAD SMMUMAP TABLE VALID'),
    sub('the-walks-refusal-is-ignored', LOGIC, '    if (status == WALK_NOT_RAM) return refuse_not_ram(env, out, &target.proof, target.last);\n', '', r'the line is|reason'),
    sub('the-templates-refusal-is-ignored', LOGIC, '    if (status == WALK_NOT_RAM) return refuse_not_ram(env, out, &tpl.proof, tpl.last);\n', '', r'the line is|reason'),
    sub('the-scans-refusal-is-ignored', LOGIC, '    if (got == LOAD_NOT_RAM) return refuse_not_ram(env, out, &found.bad, found.level);\n', '', r'at the scan|loads into a page that the memory map does not call RAM'),
    sub('the-rereads-refusal-is-ignored', LOGIC, '    if (got == LOAD_NOT_RAM) return refuse_not_ram(env, out, &reread, 3);\n', '', r'read once more before the store|loads into a page that the memory map does not call RAM'),
    sub('the-walks-refusal-names-the-wrong-level', LOGIC, 'refuse_not_ram(env, out, &target.proof, target.last);', 'refuse_not_ram(env, out, &target.proof, 0);', r'the line is'),
    sub('the-templates-refusal-names-the-wrong-level', LOGIC, 'refuse_not_ram(env, out, &tpl.proof, tpl.last);', 'refuse_not_ram(env, out, &tpl.proof, tpl.last + 1u);', r'the line is'),
    sub('the-scans-refusal-names-the-wrong-level', LOGIC, 'refuse_not_ram(env, out, &found.bad, found.level);', 'refuse_not_ram(env, out, &found.bad, 3);', r'at the scan'),
    sub('the-rereads-refusal-names-the-wrong-level', LOGIC, 'refuse_not_ram(env, out, &reread, 3);', 'refuse_not_ram(env, out, &reread, 0);', r'read once more before the store'),
    sub('the-refusal-names-the-wrong-table', LOGIC, 'q1n1_payload_line_hex(&line, "TABLE", p->page);', 'q1n1_payload_line_hex(&line, "TABLE", p->page + PAGE_BYTES);', r'the line is'),
    sub('the-refusal-prints-the-attribute-of-a-page-in-no-descriptor', LOGIC, 'if (p->type >= 0 && line.len + 6u', 'if (line.len + 6u', r'the line is|a page that is in no descriptor'),
    sub('the-attribute-word-is-cut-not-dropped', LOGIC, 'q1n1_payload_fmt_hex(text, sizeof text, p->attr) <= Q1N1_PAYLOAD_LINE_MAX)', 'q1n1_payload_fmt_hex(text, sizeof text, p->attr) <= Q1N1_PAYLOAD_LINE_MAX + 24u)',
        r'attribute \d: the line is'),
    sub('the-attribute-word-fit-is-one-too-strict', LOGIC, 'q1n1_payload_fmt_hex(text, sizeof text, p->attr) <= Q1N1_PAYLOAD_LINE_MAX)', 'q1n1_payload_fmt_hex(text, sizeof text, p->attr) < Q1N1_PAYLOAD_LINE_MAX)',
        r'attribute \d: the line is|to the last column'),
    sub('the-attribute-word-fit-is-one-too-loose', LOGIC, 'if (p->type >= 0 && line.len + 6u', 'if (p->type >= 0 && line.len + 5u', r'attribute \d: the line is'),
    sub('the-attribute-word-of-the-deciding-descriptor-is-read-from-the-wrong-offset', LOGIC, 'if (attr) *attr = le64(d + 32);\n            return type;', 'if (attr) *attr = le64(d + 24);\n            return type;',
        r'attribute word|the line is'),
    sub('the-attribute-word-of-a-ram-descriptor-is-read-from-the-wrong-offset', LOGIC, 'found_attr = le64(d + 32);', 'found_attr = le64(d + 24);', r'attribute word'),
    sub('a-type-above-the-clamp-is-not-clamped', LOGIC, 'int type = raw > 0xffffu ? 0xffff : (int)raw;', 'int type = (int)raw;', r'type'),
    sub('a-type-above-the-clamp-is-clamped-to-a-ram-type', LOGIC, 'int type = raw > 0xffffu ? 0xffff : (int)raw;', 'int type = raw > 0xffffu ? 7 : (int)raw;', r'type'),
    sub('the-ram-types-include-mmio', LOGIC, 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 1 && type <= 7) || type == 9 || type == 11;', r'EFI type 11 is judged'),
    sub('the-ram-types-include-reserved', LOGIC, 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 0 && type <= 7) || type == 9;', r'EFI type 0 is judged'),
    sub('the-ram-types-include-unusable', LOGIC, 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 1 && type <= 8) || type == 9;', r'EFI type 8 is judged'),
    sub('the-ram-types-leave-out-boot-services-data', LOGIC, 'return (type >= 1 && type <= 7) || type == 9;', 'return (type >= 1 && type <= 7 && type != 4) || type == 9;',
        r'EFI type 4 is judged'),
    sub('the-ram-types-leave-out-acpi-reclaim', LOGIC, 'return (type >= 1 && type <= 7) || type == 9;', 'return type >= 1 && type <= 7;', r'EFI type 9 is judged'),
    sub('a-range-that-leaves-the-extent-is-held', LOGIC, 'if (pa >= start && end - pa >= bytes) {', 'if (pa >= start) {', r'spans two RAM extents'),
    sub('an-overlapping-non-ram-descriptor-does-not-decide', LOGIC, '        if (!q1n1_smmumap_ram_type(type)) {\n            if (attr) *attr = le64(d + 32);\n            return type;\n        }\n',
        '        if (!q1n1_smmumap_ram_type(type)) continue;\n',
        r'unusable descriptor over the page decides|MMIO and reserved descriptors decide|MMIO descriptor over the page'),
    sub('the-first-of-two-ram-descriptors-wins', LOGIC, 'if (pa >= start && end - pa >= bytes) {', 'if (found < 0 && pa >= start && end - pa >= bytes) {',
        r'the later is answered'),
    sub('an-unaligned-descriptor-is-not-skipped', LOGIC, 'if ((start & (PAGE_BYTES - 1)) || !pages ||', 'if (!pages ||', r'malformed descriptor took the page'),
    sub('an-overflowing-descriptor-is-not-skipped', LOGIC, ' || pages > (MAP_ADDRESS_LIMIT - start) / PAGE_BYTES) continue;', ') continue;', r'malformed descriptor took the page'),
    sub('a-stride-of-32-is-read', LOGIC, '#define EFI_DESC_MIN 40u', '#define EFI_DESC_MIN 32u', r'a stride below 40'),
    sub('one-more-descriptor-than-the-limit-is-read', LOGIC, 'size / stride > MAP_DESCRIPTORS_MAX', 'size / stride > MAP_DESCRIPTORS_MAX + 1u', r'1025 descriptors are too many'),
    sub('the-two-unreadable-type-codes-are-swapped', LOGIC, 'p->type == -1 ? Q1N1_SMMUMAP_TYPE_NOT_IN_MAP : p->type == -2 ? Q1N1_SMMUMAP_TYPE_MAP_UNUSABLE : (uint64_t)p->type',
        'p->type == -1 ? Q1N1_SMMUMAP_TYPE_MAP_UNUSABLE : p->type == -2 ? Q1N1_SMMUMAP_TYPE_NOT_IN_MAP : (uint64_t)p->type', r'a page that is in no descriptor|a map that cannot be read|the line is'),
    sub('a-map-that-cannot-be-read-is-a-page-that-is-ram', LOGIC, 'if (!map || stride < EFI_DESC_MIN', 'if (stride < EFI_DESC_MIN', r'no map|SEGV|Sanitizer'),
    # -- v2, the scan of the level-3 table and the tables of the path (evidence, and a refusal only for a pointer from the root or the level-1 table)
    sub('the-scan-reads-the-slot-too', LOGIC, '        if (at == slot) continue;\n', '', r'reads, wanted|effects are|has operand|has second operand'),
    sub('the-scan-counts-every-neighbour', LOGIC, 's->valid += (unsigned)(value & 1u);', 's->valid++;', r'PAYLOAD SMMUMAP TABLE VALID'),
    sub('the-scan-counts-bit-1-as-valid', LOGIC, 's->valid += (unsigned)(value & 1u);', 's->valid += (unsigned)((value >> 1) & 1u);', r'PAYLOAD SMMUMAP TABLE VALID'),
    sub('the-scan-counts-a-block-as-a-reference', LOGIC, 'if ((value & 3u) == 3u && (value & Q1N1_SMMUMAP_ADDR) == target->table) s->refs[level]++;',
        'if ((value & 1u) && (value & Q1N1_SMMUMAP_ADDR) == target->table) s->refs[level]++;', r'PAYLOAD SMMUMAP TABLE VALID'),
    sub('the-scan-counts-any-table-as-a-reference', LOGIC, 'if ((value & 3u) == 3u && (value & Q1N1_SMMUMAP_ADDR) == target->table) s->refs[level]++;',
        'if ((value & 3u) == 3u) s->refs[level]++;', r'PAYLOAD SMMUMAP TABLE VALID|PAYLOAD SMMUMAP REFUSED'),
    sub('the-scan-counts-the-references-to-another-page', LOGIC, 'if ((value & 3u) == 3u && (value & Q1N1_SMMUMAP_ADDR) == target->table) s->refs[level]++;',
        'if ((value & 3u) == 3u && (value & Q1N1_SMMUMAP_ADDR) != target->table) s->refs[level]++;', r'PAYLOAD SMMUMAP TABLE VALID|PAYLOAD SMMUMAP REFUSED'),
    sub('the-scan-reads-the-start-table-in-full', LOGIC, 'unsigned entries = level == first ? start_entries(bits, level) : 512u;', 'unsigned entries = 512u;', r'entry beyond the 32'),
    sub('a-pointer-from-the-root-is-only-printed', LOGIC, 'if (found.refs[0] > 0 || found.refs[1] > 0)', 'if (found.refs[1] > 0)', r'entry of the root points'),
    sub('a-pointer-from-the-level-1-table-is-only-printed', LOGIC, 'if (found.refs[0] > 0 || found.refs[1] > 0)', 'if (found.refs[0] > 0)', r'entry of the level-1 table points'),
    sub('an-alias-in-the-level-2-table-is-refused', LOGIC, 'if (found.refs[0] > 0 || found.refs[1] > 0)', 'if (found.refs[0] > 0 || found.refs[1] > 0 || found.refs[2] > 1)',
        r'alias in the level-2 table'),
    sub('the-level-of-a-pointer-is-wrong', LOGIC, '"LEVEL", found.refs[0] > 0 ? 0u : 1u);', '"LEVEL", found.refs[0] > 0 ? 1u : 0u);', r'entry of the (root|level-1 table) points|both|the root is named first'),
    sub('a-scan-abort-in-the-level-3-table-is-ignored', LOGIC, '            s->at = at;\n            return got;\n        }\n        s->valid', '            s->at = at;\n        }\n        s->valid',
        r'a read of the scan aborts|scan fault'),
    sub('a-scan-abort-in-the-path-is-ignored', LOGIC, '                s->at = at;\n                s->level = level;\n                return got;\n', '                s->at = at;\n                s->level = level;\n',
        r'a read of the scan aborts|scan fault'),
    sub('a-scan-abort-names-the-wrong-level', LOGIC, '                s->level = level;\n', '                s->level = 3;\n', r'scan fault'),
    sub('a-scan-abort-is-a-walk-fault', LOGIC, 'Q1N1_SMMUMAP_R_SCAN_FAULT, "AT"', 'Q1N1_SMMUMAP_R_WALK_FAULT, "AT"', r'a read of the scan aborts'),
    sub('the-table-line-is-not-printed', LOGIC, '    begin(&line, "TABLE");\n    put_scan(&line, &found);\n    env->emit(line.buf);\n', '', r'lines, wanted|line \d+ is|PAYLOAD SMMUMAP TABLE'),
    sub('an-unscanned-level-is-printed-as-zero', LOGIC, 'q1n1_payload_line_raw(line, "-");', 'q1n1_payload_line_raw(line, "0");', r'the scan of a walk that starts at level 1|the scan of a regime that starts at level 1'),
    # -- v2, the SError line after the chain
    sub('the-serror-line-is-also-for-a-refusal', LOGIC, 'if (!result || result->status != Q1N1_SMMUMAP_MAPPED || !env->serror_poll) return;', 'if (!result || !env->serror_poll) return;',
        r'refused page is polled|unsafe page is polled'),
    sub('the-serror-poll-is-not-asked', LOGIC, 'found = env->serror_poll(&syndrome, &still);', 'found = 0;', r'found:|pending:'),
    sub('a-found-serror-is-called-none', LOGIC, 'begin(&line, found ? "SERROR=FOUND" : "SERROR=NONE");', 'begin(&line, "SERROR=NONE");', r'found:|pending:'),
    sub('the-serror-syndrome-is-not-printed', LOGIC, '    if (found) q1n1_payload_line_hex(&line, "SYNDROME", syndrome);\n', '', r'found:|pending:'),
    sub('the-serror-pending-flag-is-not-printed', LOGIC, 'q1n1_payload_line_dec(&line, "PENDING", still != 0);', 'q1n1_payload_line_dec(&line, "PENDING", 0);', r'pending:'),
    sub('the-serror-before-is-not-recorded', LOGIC, 'out->serror_before = env->serror_pending ? env->serror_pending() != 0 : 0;', 'out->serror_before = 0;', r'pending before|pending:'),
    sub('the-serror-before-is-printed-as-the-poll', LOGIC, 'q1n1_payload_line_dec(&line, "BEFORE", result->serror_before != 0);', 'q1n1_payload_line_dec(&line, "BEFORE", still != 0);', r'before only|pending after only'),
    sub('a-runner-with-no-poll-is-polled', LOGIC, 'if (!result || result->status != Q1N1_SMMUMAP_MAPPED || !env->serror_poll) return;', 'if (!result || result->status != Q1N1_SMMUMAP_MAPPED) return;',
        r'SEGV|no poll to ask|AddressSanitizer'),
    # -- v2, the hook in the runner (the hook program): after the first payload's own hash check, once every payload has verified
    two('the-hook-runs-before-the-first-payload-is-verified', RUNNER, [(HOOK_VERIFY, '        if (!smmumap_done && env->smmumap) { smmumap_done = 1; env->smmumap(); }\n' + HOOK_VERIFY)],
        r'payload 0 damaged|payload 1 damaged|payload 2 of 3 damaged|the hook did not follow', program='hook'),
    sub('the-other-payloads-are-not-verified-before-the-hook', RUNNER, 'if (q1n1_payload_file_is_code(&loaded->file[other]) && !q1n1_payload_verify_in_place(loaded, other)) {',
        'if (0) {', r'payload 1 damaged|payload 2 of 3 damaged', program='hook'),
    sub('only-the-next-payload-is-verified-before-the-hook', RUNNER, 'for (uint32_t other = index + 1; other < loaded->count && other < Q1N1_PAYLOAD_MAX_FILES; other++) {',
        'for (uint32_t other = index + 1; other < loaded->count && other < index + 2u && other < Q1N1_PAYLOAD_MAX_FILES; other++) {', r'payload 2 of 3 damaged', program='hook'),
    sub('a-data-file-is-verified-as-a-payload-before-the-hook', RUNNER, 'if (q1n1_payload_file_is_code(&loaded->file[other]) && !q1n1_payload_verify_in_place(loaded, other)) {',
        'if (!q1n1_payload_verify_in_place(loaded, other)) {', r'a damaged data file', program='hook'),
    sub('the-hook-runs-for-every-payload', RUNNER, '            smmumap_done = 1;\n', '', r'two payloads|hook ran', program='hook'),
    sub('an-unsafe-step-does-not-stop-the-chain', RUNNER, 'if (env->smmumap() == Q1N1_SMMUMAP_UNSAFE) {', 'if (env->smmumap() == 12345) {', r'UNSAFE', program='hook'),
    sub('an-unsafe-stop-names-another-reason', RUNNER, 'emit_chain_stopped(env, index, "SMMUMAP");', 'emit_chain_stopped(env, index, "HASH_AT_EL2");', r'UNSAFE', program='hook'),
    sub('an-unsafe-stop-names-another-index', RUNNER, 'emit_chain_stopped(env, index, "SMMUMAP");', 'emit_chain_stopped(env, index + 1u, "SMMUMAP");', r'UNSAFE', program='hook'),
    sub('the-hook-refusal-names-the-wrong-payload', RUNNER, 'q1n1_payload_line_dec(&line, "INDEX", index);\n    q1n1_payload_line_digest(&line, "WANT", file->sha256);',
        'q1n1_payload_line_dec(&line, "INDEX", 0);\n    q1n1_payload_line_digest(&line, "WANT", file->sha256);', r'payload 1 damaged|payload 2 of 3 damaged', program='hook'),
    sub('the-hook-refusal-is-not-a-hash-stop', RUNNER, '    result->status = Q1N1_PAYLOAD_RUN_HASH;\n    result->stopped = index;\n    emit_chain_stopped(env, index, "HASH_AT_EL2");\n}',
        '    result->status = Q1N1_PAYLOAD_RUN_OK;\n    result->stopped = index;\n    emit_chain_stopped(env, index, "HASH_AT_EL2");\n}', r'payload 1 damaged|payload 2 of 3 damaged', program='hook'),
]


def stale(m, root):
    """The edits whose needle does not occur exactly once in the file."""
    name, file, edits, _, _, _ = m
    text = (root / 'platform' / 'uefi' / file).read_text(encoding='utf-8')
    return [f'{name}: {old[:60]!r} occurs {text.count(old)} times' for old, _ in edits if text.count(old) != 1]


def evaluate(m, work, root, compile_cmd, spin_suites=SPIN_SUITES):
    """(status, detail): 'caught', 'survived' or 'wrong-reason'. `compile_cmd(uefi_dir, flags, binary, program)` builds the host program."""
    name, file, edits, reason, flags, program = m
    directory = work / name
    shutil.rmtree(directory, ignore_errors=True)
    uefi = directory / 'uefi'
    shutil.copytree(root / 'platform' / 'uefi', uefi, ignore=shutil.ignore_patterns('*.obj', '*.o', '*.d'))
    path = uefi / file
    text = path.read_text(encoding='utf-8')
    for old, new in edits:
        if text.count(old) != 1:
            return 'stale', f'{old[:60]!r} occurs {text.count(old)} times'
        text = text.replace(old, new)
    path.write_text(text, encoding='utf-8')
    binary = directory / 'test'
    built = compile_cmd(uefi, flags, binary, program)
    if built.returncode != 0:
        return 'wrong-reason', 'does not build: ' + built.stderr[-300:]
    outputs = []
    for suite in (spin_suites if flags else ('all',)) if program == 'main' else (None,):
        try:
            done = subprocess.run([str(binary)] + ([suite] if suite else []), capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            outputs.append('TIMEOUT')
            continue
        outputs.append(done.stdout + done.stderr if done.returncode else '')
    failed = [o for o in outputs if o]
    shutil.rmtree(directory, ignore_errors=True)
    if not failed:
        return 'survived', 'the host program passed'
    text = '\n'.join(failed)
    if 'TIMEOUT' in text and not re.search(reason, text):
        return 'wrong-reason', 'a hang'
    if not re.search(reason, text):
        return 'wrong-reason', f'failed for another reason (wanted /{reason}/): {text[:300]}'
    return 'caught', ''
