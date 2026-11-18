# SPDX-License-Identifier: MIT
"""More seeded bugs for the payload `nvmesnap` (tools/sp11_payload_nvmesnap_mutants.py has the machinery and the first set; its list is extended with
MORE at the end). They are the ones the independent review of the sibling payload `tsnap` asked for, applied to the second block of registers and to
the windows: a wrong base for every window and a swap of two windows or two roles (the likeliest slip of a source), an unguarded read (the guard of rd()
open with a caller's bug), the first load of a block that is a register Linux does not read, a line that is printed after the load it must precede, a
wait bound that is never reached or one read off, a bound that says a dead counter, a dead counter that says the bound, a failed read reported as the
thing it gates on, a decode that does not check the mode bits that make it valid, a dropped NEXT line. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host
model only)."""
from sp11_payload_nvmesnap_mutants import GUARD_OPEN, PAGE14, SPIN, sub, two
from sp11_payload_nvmesnap_reasons import AFTER, PAGE, STRAY


def no_token(token, line):
    """The failure of a check that a line has a token."""
    return rf"no '{token}' token on a 'PAYLOAD NVMESNAP {line}"


def no_line(text):
    """The failure of a check that a line is on the page."""
    return rf"no line 'PAYLOAD NVMESNAP {text}'"


LOADS = r'loads\[i\]\.addr = '
REASONS_MORE = {
    # the two blocks of registers, and what each says when a read does not return
    'a-failed-register-read-does-not-stop-the-block': AFTER,
    'an-all-ones-second-csts-does-not-stop-the-block': r'loads_in\(BAR_GOOD, BAR_GOOD \+ 0x4000\) = 0xb, wanted 0x6',
    'an-unread-cc-is-a-state': no_token('CTRL=UNKNOWN', 'VERDICT'),
    'a-failed-register-in-a-block-is-no-reason': AFTER,
    'the-two-blocks-swap-their-reasons': no_token('WHY=REGISTERS_NOT_READ', 'VERDICT'),
    'a-register-never-tried-is-a-failed-read': no_token('WHY=REGISTERS_ALL_ONES', 'VERDICT'),
    'a-failed-read-says-the-controller-answers-with-ones': no_token('WHY=REGISTERS_NOT_READ', 'VERDICT'),
    'a-fault-in-the-first-block-lets-the-second-run': AFTER,
    # the waits
    'the-wait-before-the-second-block-is-not-made': no_line('NEXT NVME_AQ AFTER 8 S'),
    'a-skipped-second-block-has-no-reason': no_token('WHY=GROUP_SKIPPED', 'VERDICT'),
    'the-wait-is-announced-and-not-made': r'loads\[i\]\.clock - line_clock\[k\] >= 8 \* freq',
    'the-caps-block-has-no-next-line': no_line('NEXT CAPS AFTER 8 S') + '|' + PAGE,
    'the-registers-block-has-no-next-line': PAGE,
    'the-second-block-has-no-next-line': no_line('NEXT NVME_AQ AFTER 8 S') + '|' + PAGE,
    'the-second-next-line-may-be-dropped': no_line('NEXT NVME_AQ AFTER 8 S'),
    'the-spin-bound-is-never-reached': STRAY,
    'the-spin-bound-is-reached-one-read-late': STRAY,
    'the-spin-bound-is-reached-one-read-early': r'line_count == UNIT_LINES = 0, wanted 0x1',
    'the-spin-bound-says-the-counter-is-dead': no_line('CAPS SKIPPED=SPIN_BOUND'),
    'the-spin-token-is-the-dead-counters': no_line('CAPS SKIPPED=SPIN_BOUND'),
    'a-dead-counter-says-the-spin-bound': no_line('CAPS SKIPPED=COUNTER_UNUSABLE'),
    'a-counter-going-back-says-the-spin-bound': no_line('CAPS SKIPPED=COUNTER_UNUSABLE'),
    'the-spin-bound-is-below-the-stuck-count': no_line('CAPS SKIPPED=COUNTER_UNUSABLE'),
    # a wrong base for every window, and the swaps
    'the-root-port-window-starts-after-the-id': PAGE,
    'the-endpoint-window-is-at-the-root-ports-base': PAGE,
    'the-controller-window-starts-after-cap': PAGE,
    'the-ram-window-starts-after-the-first-word': PAGE,
    'the-ram-window-ends-a-word-early': PAGE,
    'the-pages-of-the-two-functions-are-swapped': PAGE,
    'the-root-port-is-asked-about-the-endpoints-page': r'at_log\[0\] = 0x70100000, wanted 0x70000000|' + STRAY,
    'the-controller-is-read-a-page-late': PAGE,
    'the-controller-is-read-a-page-late-and-the-guard-is-open': STRAY,
    'the-queue-addresses-are-swapped': PAGE,
    'the-submission-queue-is-read-a-page-late': PAGE,
    'the-completion-queue-is-read-a-page-late': STRAY,
    'the-asq-and-acq-registers-are-swapped': PAGE,
    'the-queue-words-are-swapped-between-the-queues': PAGE,
    'the-slot-stride-is-not-the-entry-size': PAGE,
    # the first load of a block, and what is printed before the next risky load
    'the-version-is-read-first': PAGE,
    'the-queue-registers-come-before-the-second-csts': PAGE,
    'the-submission-words-are-read-in-the-x2-order': LOADS,
    'the-completion-words-are-read-in-slot-order': LOADS,
    'the-link-line-waits-for-the-endpoint-list': r'loads\[18\]\.lines <= \(unsigned\)rp_link',
    'the-first-block-is-decoded-after-the-second': PAGE,
    # CSTS read twice, and a controller that answers with ones
    'the-second-csts-is-not-compared': no_token('CTRL=TRANSITION', 'VERDICT'),
    'the-second-csts-compares-every-bit': no_token('CTRL=RUNNING', 'VERDICT'),
    'the-second-csts-compares-only-ready': no_token('CTRL=TRANSITION', 'VERDICT'),
    'an-all-ones-second-csts-is-a-state': no_token('CTRL=ALL_ONES', 'VERDICT'),
    'the-second-csts-is-not-settled': no_token('CTRL=TRANSITION', 'VERDICT'),
    'a-failed-second-csts-is-compared': no_token('CTRL=RUNNING', 'VERDICT'),
    'an-all-ones-controller-is-decoded': no_line('CTRL ODD=ALL_ONES'),
    'cc-all-ones-is-not-noticed': no_token('CTRL=ALL_ONES', 'VERDICT'),
    'csts-all-ones-is-not-noticed': no_token('CTRL=ALL_ONES', 'VERDICT') + '|' + no_line('CTRL ODD=ALL_ONES'),
    'cap-all-ones-is-not-noticed': no_token('CTRL=ALL_ONES', 'VERDICT'),
    'an-all-ones-controller-is-shown-decoded': no_line('CTRL ODD=ALL_ONES'),
    'the-second-block-is-read-after-an-all-ones-first': no_token('QUEUES=NOT_READ', 'VERDICT'),
    # the mode bits that make a decode valid
    'a-port-of-any-type-is-accepted': STRAY,
    'a-downstream-port-is-refused': no_token('WHY=NONE', 'VERDICT'),
    'a-root-port-is-refused': no_token('WHY=NONE', 'VERDICT') + '|' + PAGE,
    'a-port-of-the-wrong-type-is-not-odd': no_token('ODD', 'RP.LINK'),
    'a-link-that-is-down-is-not-odd': no_token('ODD', 'RP.LINK'),
    'an-endpoint-of-the-wrong-type-is-not-odd': no_token('ODD', 'EP.LINK'),
    'a-legacy-endpoint-is-odd': r"a 'ODD' token on a 'PAYLOAD NVMESNAP EP.LINK",
    'the-bridge-memory-space-is-not-checked': STRAY,
    'the-bridge-memory-space-bit-is-bit-0': STRAY,
    'the-gate-line-has-no-bridge-memory-space': no_token('RPMEM=1', 'GATE') + '|' + PAGE,
    'a-reserved-aqa-bit-is-not-odd': no_token('ODD', 'AQ '),
    'the-aqa-reserved-mask-misses-the-top-bits': no_token('ODD', 'AQ '),
}

MORE = [
    # -- a wrong base for every window, and swaps of two windows or roles
    sub('the-root-port-window-starts-after-the-id', 'if (addr >= ROOT_PORT_PAGE && addr < ROOT_PORT_PAGE + CFG_PAGE_BYTES) return PAGE_RP;',
        'if (addr >= ROOT_PORT_PAGE + 4u && addr < ROOT_PORT_PAGE + CFG_PAGE_BYTES) return PAGE_RP;', 'unit faults'),
    sub('the-endpoint-window-is-at-the-root-ports-base', 'if (addr >= ENDPOINT_PAGE && addr < ENDPOINT_PAGE + CFG_PAGE_BYTES) return PAGE_EP;',
        'if (addr >= ROOT_PORT_PAGE && addr < ROOT_PORT_PAGE + CFG_PAGE_BYTES) return PAGE_EP;', 'unit faults'),
    sub('the-controller-window-starts-after-cap', 'if (c->bar0 && addr >= c->bar0 && addr < c->bar0 + NVME_READ_END) return PAGE_BAR0;',
        'if (c->bar0 && addr >= c->bar0 + 4u && addr < c->bar0 + NVME_READ_END) return PAGE_BAR0;', 'unit nvfaults'),
    sub('the-ram-window-starts-after-the-first-word', 'if (c->ram_hi && addr >= c->ram_lo && addr < c->ram_hi', 'if (c->ram_hi && addr >= c->ram_lo + 4u && addr < c->ram_hi',
        'unit queues'),
    sub('the-ram-window-ends-a-word-early', 'addr < c->ram_hi && c->ram_hi - addr >= 4u) return WIN_RAM;', 'addr < c->ram_hi - 4u && c->ram_hi - addr >= 4u) return WIN_RAM;',
        'unit queues'),
    two('the-pages-of-the-two-functions-are-swapped', [('    rp.page = ROOT_PORT_PAGE;\n    ep.page = ENDPOINT_PAGE;', '    rp.page = ENDPOINT_PAGE;\n    ep.page = ROOT_PORT_PAGE;')],
        'unit gates'),
    sub('the-root-port-is-asked-about-the-endpoints-page', 'c.approved[PAGE_RP] = (uint8_t)add_walk(a, &c, "RP", ROOT_PORT_PAGE, 1);',
        'c.approved[PAGE_RP] = (uint8_t)add_walk(a, &c, "RP", ENDPOINT_PAGE, 1);', 'unit pages'),
    sub('the-controller-is-read-a-page-late', 'uint64_t at = c->bar0 + nvme_regs[i].offset;', 'uint64_t at = c->bar0 + 0x1000u + nvme_regs[i].offset;', 'unit nvfaults'),
    two('the-controller-is-read-a-page-late-and-the-guard-is-open',
        [('uint64_t at = c->bar0 + nvme_regs[i].offset;', 'uint64_t at = c->bar0 + 0x1000u + nvme_regs[i].offset;'), (GUARD_OPEN, '    } else if (0) {')],
        'unit nvfaults'),
    two('the-queue-addresses-are-swapped',
        [('sq = read_queue(a, c, "ASQ", "SQ", asq, k->sq_entries', 'sq = read_queue(a, c, "ASQ", "SQ", acq, k->sq_entries'),
         ('cq = read_queue(a, c, "ACQ", "CQ", acq, k->cq_entries', 'cq = read_queue(a, c, "ACQ", "CQ", asq, k->cq_entries')], 'unit queues'),
    sub('the-submission-queue-is-read-a-page-late', 'sq = read_queue(a, c, "ASQ", "SQ", asq, k->sq_entries', 'sq = read_queue(a, c, "ASQ", "SQ", asq + 0x1000u, k->sq_entries',
        'unit queues'),
    sub('the-completion-queue-is-read-a-page-late', 'cq = read_queue(a, c, "ACQ", "CQ", acq, k->cq_entries', 'cq = read_queue(a, c, "ACQ", "CQ", acq + 0x1000u, k->cq_entries',
        'unit queues'),
    sub('the-asq-and-acq-registers-are-swapped', '{"ASQ", 0x28, 1}, {"ACQ", 0x30, 1},', '{"ASQ", 0x30, 1}, {"ACQ", 0x28, 1},', 'unit ctrl'),
    two('the-queue-words-are-swapped-between-the-queues',
        [('SQE_BYTES, sqe_words, 6u);', 'SQE_BYTES, cqe_words, 3u);'), ('CQE_BYTES, cqe_words, 3u);', 'CQE_BYTES, sqe_words, 6u);')], 'unit queues'),
    sub('the-slot-stride-is-not-the-entry-size', 'read_slot(a, c, at + (uint64_t)slot * entry_bytes, words, nwords, w);',
        'read_slot(a, c, at + (uint64_t)slot * (entry_bytes + 4u), words, nwords, w);', 'unit queues'),
    # -- the first load of a block is a register Linux reads; what Linux never reads comes last
    two('the-version-is-read-first',
        [('enum { NR_CAP, NR_CSTS, NR_CC, NR_VS, NR_CSTS2, NR_AQA, NR_ASQ, NR_ACQ, NR_COUNT };', 'enum { NR_VS, NR_CC, NR_CSTS, NR_CAP, NR_CSTS2, NR_AQA, NR_ASQ, NR_ACQ, NR_COUNT };'),
         ('{"CAP", 0x00, 1}, {"CSTS", 0x1c, 0}, {"CC", 0x14, 0}, {"VS", 0x08, 0},', '{"VS", 0x08, 0}, {"CC", 0x14, 0}, {"CSTS", 0x1c, 0}, {"CAP", 0x00, 1},')],
        'unit nvfaults'),
    two('the-queue-registers-come-before-the-second-csts',
        [('enum { NR_CAP, NR_CSTS, NR_CC, NR_VS, NR_CSTS2, NR_AQA, NR_ASQ, NR_ACQ, NR_COUNT };', 'enum { NR_CAP, NR_CSTS, NR_CC, NR_VS, NR_AQA, NR_ASQ, NR_ACQ, NR_CSTS2, NR_COUNT };'),
         ('{"CSTS2", 0x1c, 0}, {"AQA", 0x24, 0}, {"ASQ", 0x28, 1}, {"ACQ", 0x30, 1},', '{"AQA", 0x24, 0}, {"ASQ", 0x28, 1}, {"ACQ", 0x30, 1}, {"CSTS2", 0x1c, 0},')],
        'unit nvfaults'),
    two('the-submission-words-are-read-in-the-x2-order',
        [('static const uint8_t sqe_words[6] = {0, 6, 7, 1, 10, 11};', 'static const uint8_t sqe_words[6] = {0, 1, 6, 7, 10, 11};'),
         ('add_reading(a, c, "NSID", w[3]);', 'add_reading(a, c, "NSID", w[1]);'),
         ('if (w[1].state == RS_VALUE && w[2].state == RS_VALUE) pl_add_hex(a, PG(c), "PRP1", w[1].value | w[2].value << 32);\n    else add_reading(a, c, "PRP1", w[1].state != RS_VALUE ? w[1] : w[2]);',
          'if (w[2].state == RS_VALUE && w[3].state == RS_VALUE) pl_add_hex(a, PG(c), "PRP1", w[2].value | w[3].value << 32);\n    else add_reading(a, c, "PRP1", w[2].state != RS_VALUE ? w[2] : w[3]);')],
        'unit queues'),
    two('the-completion-words-are-read-in-slot-order',
        [('static const uint8_t cqe_words[3] = {3, 2, 0};', 'static const uint8_t cqe_words[3] = {0, 2, 3};'),
         ('add_reading(a, c, "DW0", w[2]);\n    add_reading(a, c, "DW3", w[0]);\n    if (w[0].state == RS_VALUE) {\n        pl_add_hex(a, PG(c), "CID", w[0].value & 0xffffu);\n'
          '        pl_add_dec(a, PG(c), "P", w[0].value >> 16 & 1u);\n        pl_add_hex(a, PG(c), "SC", w[0].value >> 17 & 0xffu);\n        pl_add_dec(a, PG(c), "SCT", w[0].value >> 25 & 7u);',
          'add_reading(a, c, "DW0", w[0]);\n    add_reading(a, c, "DW3", w[2]);\n    if (w[2].state == RS_VALUE) {\n        pl_add_hex(a, PG(c), "CID", w[2].value & 0xffffu);\n'
          '        pl_add_dec(a, PG(c), "P", w[2].value >> 16 & 1u);\n        pl_add_hex(a, PG(c), "SC", w[2].value >> 17 & 0xffu);\n        pl_add_dec(a, PG(c), "SCT", w[2].value >> 25 & 7u);')],
        'unit queues'),
    # -- what was read is printed before the next risky load
    two('the-link-line-waits-for-the-endpoint-list',
        [('        report_link(a, &c, "RP.LINK", &rp, &snap.rp_caps, 1);\n', ''),
         ('        snap.caps_run = 1;\n', '        snap.caps_run = 1;\n        report_link(a, &c, "RP.LINK", &rp, &snap.rp_caps, 1);\n')], 'unit'),
    two('the-first-block-is-decoded-after-the-second',
        [('            report_ctrl(a, &c, &view, &ctrl);\n            why = why_block(&view, &ctrl, 0, NR_FIRST_BLOCK);', '            why = why_block(&view, &ctrl, 0, NR_FIRST_BLOCK);'),
         ('            settle_ctrl(&view, &ctrl);', '            report_ctrl(a, &c, &view, &ctrl);\n            settle_ctrl(&view, &ctrl);')], 'unit counter'),
    # -- the state, read twice
    sub('the-second-csts-is-not-compared', '    else if ((csts->value ^ again->value) & 0xfu) k->state = C_TRANSITION;\n', '', 'ctrl'),
    sub('the-second-csts-compares-every-bit', '(csts->value ^ again->value) & 0xfu)', '(csts->value ^ again->value) & 0xffffffffu)', 'ctrl'),
    sub('the-second-csts-compares-only-ready', '(csts->value ^ again->value) & 0xfu)', '(csts->value ^ again->value) & 0x1u)', 'ctrl'),
    sub('an-all-ones-second-csts-is-a-state', '    if (again->value == ALL_ONES32) k->state = C_ALL_ONES;\n    else if ((csts->value ^ again->value) & 0xfu) k->state = C_TRANSITION;',
        '    if ((csts->value ^ again->value) & 0xfu) k->state = C_TRANSITION;', 'ctrl'),
    sub('the-second-csts-is-not-settled', '            settle_ctrl(&view, &ctrl);\n', '', 'ctrl'),
    sub('a-failed-second-csts-is-compared', '    if (again->state != RS_VALUE) return;\n', '', 'nvfaults'),
    # -- a controller that answers with ones is not decoded, and a failed read is not reported as the thing it gates on
    sub('an-all-ones-controller-is-decoded', '    if (cc == ALL_ONES32 || csts == ALL_ONES32 || (v->reg[NR_CAP].state == RS_VALUE && v->reg[NR_CAP].value == ~UINT64_C(0))) return C_ALL_ONES;\n',
        '', 'ctrl'),
    sub('cc-all-ones-is-not-noticed', 'if (cc == ALL_ONES32 || csts == ALL_ONES32 ||', 'if (csts == ALL_ONES32 ||', 'ctrl'),
    sub('csts-all-ones-is-not-noticed', 'if (cc == ALL_ONES32 || csts == ALL_ONES32 ||', 'if (cc == ALL_ONES32 ||', 'ctrl'),
    sub('cap-all-ones-is-not-noticed', ' || (v->reg[NR_CAP].state == RS_VALUE && v->reg[NR_CAP].value == ~UINT64_C(0))) return C_ALL_ONES;', ') return C_ALL_ONES;', 'ctrl'),
    sub('an-all-ones-controller-is-shown-decoded', '    if (out->state == C_ALL_ONES) {\n        pl_say(a, PG(c), "CTRL", "ODD=ALL_ONES", 0);\n        return;\n    }\n', '', 'ctrl'),
    sub('the-second-block-is-read-after-an-all-ones-first', 'return k->state == C_ALL_ONES ? W_ALL_ONES : W_NONE;', 'return W_NONE;', 'ctrl'),
    sub('a-fault-in-the-first-block-lets-the-second-run', 'why = why_block(&view, &ctrl, 0, NR_FIRST_BLOCK);', 'why = W_NONE;', 'nvfaults'),
    # -- the mode bits that make a decode valid
    sub('a-port-of-any-type-is-accepted', '    if (pcie_type(k) != PCIE_TYPE_ROOT_PORT && pcie_type(k) != PCIE_TYPE_DOWNSTREAM_PORT) return L_UNPROVEN;\n', '', 'gates'),
    sub('a-downstream-port-is-refused', ' && pcie_type(k) != PCIE_TYPE_DOWNSTREAM_PORT) return L_UNPROVEN;', ') return L_UNPROVEN;', 'gates'),
    sub('a-root-port-is-refused', 'if (pcie_type(k) != PCIE_TYPE_ROOT_PORT && pcie_type(k) != PCIE_TYPE_DOWNSTREAM_PORT) return L_UNPROVEN;',
        'if (pcie_type(k) != PCIE_TYPE_DOWNSTREAM_PORT) return L_UNPROVEN;', 'unit gates'),
    sub('a-port-of-the-wrong-type-is-not-odd', 'int odd = port ? (type != PCIE_TYPE_ROOT_PORT && type != PCIE_TYPE_DOWNSTREAM_PORT) || (reports', 'int odd = port ? (0) || (reports', 'gates'),
    sub('a-link-that-is-down-is-not-odd', ' || (reports && (!dll_up || training))', '', 'gates'),
    sub('an-endpoint-of-the-wrong-type-is-not-odd', ': (type != PCIE_TYPE_ENDPOINT && type != PCIE_TYPE_LEGACY_ENDPOINT);', ': 0;', 'gates'),
    sub('a-legacy-endpoint-is-odd', ': (type != PCIE_TYPE_ENDPOINT && type != PCIE_TYPE_LEGACY_ENDPOINT);', ': (type != PCIE_TYPE_ENDPOINT);', 'gates'),
    sub('the-bridge-memory-space-is-not-checked', '    if (!(rp->cmd.value >> 1 & 1u)) return W_BRIDGE_MEM_OFF;', '', 'gates'),
    sub('the-bridge-memory-space-bit-is-bit-0', 'if (!(rp->cmd.value >> 1 & 1u)) return W_BRIDGE_MEM_OFF;', 'if (!(rp->cmd.value >> 0 & 1u)) return W_BRIDGE_MEM_OFF;', 'gates'),
    sub('the-gate-line-has-no-bridge-memory-space', '    if (s->rp.cmd.state == RS_VALUE) pl_add_dec(a, PG(c), "RPMEM", s->rp.cmd.value >> 1 & 1u);\n', '', 'unit gates'),
    sub('a-reserved-aqa-bit-is-not-odd', '    if (aqa->value & 0xf000f000u) pl_page_add(a, PG(c), "ODD");\n', '', 'ctrl'),
    sub('the-aqa-reserved-mask-misses-the-top-bits', 'if (aqa->value & 0xf000f000u)', 'if (aqa->value & 0x0000f000u)', 'ctrl'),
    # -- the bound on the reads of a wait, and what a dead counter says
    sub('the-spin-bound-is-never-reached', '        if (++spins >= SPIN_MAX) return WAIT_SPIN;\n', '', 'counter', flags=SPIN),
    sub('the-spin-bound-is-reached-one-read-late', 'if (++spins >= SPIN_MAX) return WAIT_SPIN;', 'if (++spins > SPIN_MAX) return WAIT_SPIN;', 'counter', flags=SPIN),
    sub('the-spin-bound-is-reached-one-read-early', 'if (++spins >= SPIN_MAX) return WAIT_SPIN;', 'if (++spins >= SPIN_MAX - 1u) return WAIT_SPIN;', 'counter', flags=SPIN),
    sub('the-spin-bound-says-the-counter-is-dead', 'if (++spins >= SPIN_MAX) return WAIT_SPIN;', 'if (++spins >= SPIN_MAX) return WAIT_DEAD;', 'counter', flags=SPIN),
    sub('the-spin-token-is-the-dead-counters', 'waited == WAIT_SPIN ? "SKIPPED=SPIN_BOUND" : "SKIPPED=COUNTER_UNUSABLE"', '"SKIPPED=COUNTER_UNUSABLE"', 'counter', flags=SPIN),
    sub('a-dead-counter-says-the-spin-bound', 'if (++same >= COUNTER_STUCK_READS) return WAIT_DEAD;', 'if (++same >= COUNTER_STUCK_READS) return WAIT_SPIN;', 'counter'),
    sub('a-counter-going-back-says-the-spin-bound', 'if (now < start) return WAIT_DEAD;', 'if (now < start) return WAIT_SPIN;', 'counter'),
    sub('the-spin-bound-is-below-the-stuck-count', '#define SPIN_MAX 0xffffffffu', '#define SPIN_MAX 1000000u', 'counter'),
    sub('the-wait-is-announced-and-not-made', 'waited = wait_seconds(a, freq, WAIT_BEFORE_READ_S);', 'waited = WAIT_MADE;', 'unit counter'),
    # -- a dropped NEXT line, a NEXT line that may be dropped (the names are "CAPS", "NVME_REGS", "NVME_AQ": index 5 is read only of the latter two)
    sub('the-caps-block-has-no-next-line', '    pl_say(a, p, "NEXT", text.buf, 1);', '    if (name[0] != \'C\') pl_say(a, p, "NEXT", text.buf, 1);', 'unit counter'),
    sub('the-registers-block-has-no-next-line', '    pl_say(a, p, "NEXT", text.buf, 1);', '    if (!(name[0] == \'N\' && name[5] == \'R\')) pl_say(a, p, "NEXT", text.buf, 1);',
        'unit counter'),
    sub('the-second-block-has-no-next-line', '    pl_say(a, p, "NEXT", text.buf, 1);', '    if (!(name[0] == \'N\' && name[5] == \'A\')) pl_say(a, p, "NEXT", text.buf, 1);',
        'unit counter'),
    sub('the-second-next-line-may-be-dropped', '    pl_say(a, p, "NEXT", text.buf, 1);', '    pl_say(a, p, "NEXT", text.buf, !(name[0] == \'N\' && name[5] == \'A\'));', 'budget',
        flags=PAGE14),
]
