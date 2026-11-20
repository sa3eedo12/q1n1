# SPDX-License-Identifier: MIT
"""Seeded bugs of the payload `tsnap` (payloads/tsnap.c, payloads/tsnap-regs.h) that the host test must refuse, each for its own reason
(tools/test-q1n1-sp11-payload-tsnap.py runs them; docs/SP11-PAYLOAD-TSNAP.md lists them). A mutant is an exact, once-only replacement in one of the two files, and names
the stage that must reject it and what that stage must say:

  harness       the native host test (tools/test-q1n1-sp11-payload-tsnap.c) built over the mutant exits non-zero, the suites in `suites` are among the ones that FAIL, and its
                diagnostics hold `reason` (the text of the failed check)
  slow          the same for the one suite that takes seconds (`--slow`: a counter that needs more reads than 2^28)
  caps          the same, built with `defs` (small caps) and running only the cap suite
  audit         the IR audit (tools/sp11_payload_tsnap_audit.py) reports a problem that holds `reason`
  binary        the mutant links and the `tsnap` policy of tools/sp11_payload_testlib.py reports a violation that holds `reason`, or the link refuses it with a message that
                holds `reason`

The audit and binary mutants are never run natively: some of them store to a device address.
Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model and compiled code only)."""
from collections import namedtuple

Mutant = namedtuple('Mutant', 'name file old new stage suites reason defs')


def m(name, file, old, new, stage='harness', suites=(), reason='', defs=()):
    return Mutant(name, file, old, new, stage, tuple(suites), reason, tuple(defs))


H, C = 'payloads/tsnap-regs.h', 'payloads/tsnap.c'
SMALL = ('-DTSNAP_LINE_CAP=6u',)
SMALL_BOTH = ('-DTSNAP_LINE_CAP=26u', '-DTSNAP_LOAD_CAP=30u')

MUTANTS = [
    # -- Reads that the pinned driver does not list: the model's own list (m_allowed) and its windows refuse them.
    m('ctrl-is-the-measure-period', H, '#define SROT_CTRL 0x04u', '#define SROT_CTRL 0x08u', suites=('unit',), reason='m_allowed(win, off)'),
    m('tm-window-one-block-low', H, '0x0c271000u', '0x0c270000u', suites=('unit',), reason='a load outside the eight windows'),
    m('srot-window-one-block-low', H, '0x0c222000u', '0x0c221000u', suites=('unit',), reason='a load outside the eight windows'),
    m('srot3-window-moved', H, '0x0c225000u', '0x0c226000u', suites=('unit',), reason='a load outside the eight windows'),
    m('tm3-window-moved', H, '0x0c274000u', '0x0c275000u', suites=('unit',), reason='a load outside the eight windows'),
    # The windows are all in the set, but a block reads another block's, or the SROT reads where the TM is (the likeliest slip: the DT lists TM first): the model's list of what each
    # window may be asked and the block each load belongs to refuse them.
    m('two-srot-windows-swapped', H, '{0x0c222000u, 0x0c223000u, 0x0c224000u, 0x0c225000u, 0x0c271000u, 0x0c272000u, 0x0c273000u, 0x0c274000u}',
      '{0x0c222000u, 0x0c224000u, 0x0c223000u, 0x0c225000u, 0x0c271000u, 0x0c272000u, 0x0c273000u, 0x0c274000u}', suites=('unit',), reason='m_ann_block == (int)n'),
    m('srot-and-tm-windows-swapped', H, '{0x0c222000u, 0x0c223000u, 0x0c224000u, 0x0c225000u, 0x0c271000u, 0x0c272000u, 0x0c273000u, 0x0c274000u}',
      '{0x0c271000u, 0x0c272000u, 0x0c273000u, 0x0c274000u, 0x0c222000u, 0x0c223000u, 0x0c224000u, 0x0c225000u}', suites=('unit',), reason='m_allowed(win, off)'),
    m('status-words-one-word-high', H, '#define TM_STATUS 0xa0u', '#define TM_STATUS 0xa4u', suites=('unit',), reason='m_allowed(win, off)'),
    m('conversion-words-one-word-high', H, '#define SROT_CONV 0x60u', '#define SROT_CONV 0x64u', suites=('unit',), reason='m_allowed(win, off)'),
    m('ready-word-moved', H, '#define TM_TRDY 0xe4u', '#define TM_TRDY 0xe8u', suites=('unit',), reason='m_allowed(win, off)'),
    m('critical-status-is-the-clear-register', H, '#define TM_CRIT_STATUS 0x14u', '#define TM_CRIT_STATUS 0x18u', suites=('unit',), reason='m_allowed(win, off)'),
    m('ul-status-is-the-clear-register', H, '#define TM_UL_STATUS 0x08u', '#define TM_UL_STATUS 0x0cu', suites=('unit',), reason='m_allowed(win, off)'),
    # -- Order and gating.
    m('tsens3-first', H, 'block_order[INSTANCES] = {0, 1, 2, 3};', 'block_order[INSTANCES] = {3, 0, 1, 2};', suites=('order', 'unit'), reason='ev_line_n(&k, "NEXT T%u", n)'),
    m('next-line-after-the-first-load', C,
     '    if (!next_line(c, n)) {\n        b->state = BS_SKIPPED;\n        c->gated++;\n        return;\n    }\n    read_word(c, WIN_SROT(n), SROT_HW_VER, &b->ver);\n',
     '    read_word(c, WIN_SROT(n), SROT_HW_VER, &b->ver);\n    if (!next_line(c, n)) {\n        b->state = BS_SKIPPED;\n        c->gated++;\n        return;\n    }\n',
     suites=('order', 'unit'), reason='m_ann_block == (int)n'),
    m('tm-read-before-the-gate', C,
     '    read_word(c, WIN_SROT(n), SROT_HW_VER, &b->ver);\n    if (!ident_ok(&b->ver)) {\n',
     '    read_word(c, WIN_TM(n), TM_TRDY, &b->rdy);\n    read_word(c, WIN_SROT(n), SROT_HW_VER, &b->ver);\n    if (!ident_ok(&b->ver)) {\n',
     suites=('gate', 'order'), reason='m_wloads[M_SROT(1)] == CASES[c].srot && m_wloads[M_TM(1)] == CASES[c].tm'),
    m('no-identity-gate', C, '    if (!ident_ok(&b->ver)) {\n', '    if (0) {\n', suites=('gate',), reason='m_wloads[M_SROT(1)] == CASES[c].srot'),
    m('all-ones-passes-the-identity-gate', C, 'return w->st == V_OK && w->v != 0 && w->v != 0xffffffffu;', 'return w->st == V_OK && w->v != 0;', suites=('gate',),
      reason='m_wloads[M_SROT(1)] == CASES[c].srot'),
    m('zero-passes-the-identity-gate', C, 'return w->st == V_OK && w->v != 0 && w->v != 0xffffffffu;', 'return w->st == V_OK && w->v != 0xffffffffu;', suites=('gate',),
      reason='m_wloads[M_SROT(1)] == CASES[c].srot'),
    m('software-reset-passes-the-enable-gate', C, 'return w->st == V_OK && (w->v & CTRL_EN) && !(w->v & CTRL_SW_RST);', 'return w->st == V_OK && (w->v & CTRL_EN);', suites=('gate',),
      reason='m_wloads[M_SROT(1)] == CASES[c].srot'),
    m('enable-bit-not-required', C, 'return w->st == V_OK && (w->v & CTRL_EN) && !(w->v & CTRL_SW_RST);', 'return w->st == V_OK && !(w->v & CTRL_SW_RST);', suites=('gate',),
      reason='m_wloads[M_SROT(1)] == CASES[c].srot'),
    m('no-enable-gate', C, '    if (!running(&b->ctl)) {\n        b->state = b->ctl.st == V_OK ? BS_OFF : BS_CTLERR;', '    if (0) {\n        b->state = b->ctl.st == V_OK ? BS_OFF : BS_CTLERR;', suites=('gate',),
      reason='m_wloads[M_SROT(1)] == CASES[c].srot'),
    m('software-reset-bit-moved', H, '#define CTRL_SW_RST 0x2u', '#define CTRL_SW_RST 0x4u', suites=('gate',), reason='m_wloads[M_SROT(1)] == CASES[c].srot'),
    m('window-reads-continue-after-an-abort', C, 'if (rc == RD_FAULT) c->dead |= 1u << win;', 'if (rc == RD_FAULT) c->dead |= 0;', suites=('faults',), reason='!(m_dead_windows >> win & 1)'),
    m('dead-tm-window-still-prints-its-lines', C, '        if (!half && c->dead >> WIN_TM(n) & 1 && b->st[0][0].st != V_OK) return;', '        if (0) return;', suites=('faults',),
      reason='m_find("T0 R8", 0) < 0 && m_find("T0 C", 0) < 0'),
    m('second-reading-visits-a-dead-window', C, 'if (c->blk[n].state == BS_OK && !(c->dead >> WIN_TM(n) & 1)) todo[count++] = n;',
      'if (c->blk[n].state == BS_OK) todo[count++] = n;', suites=('faults',), reason='m_find("S2 T0", 0) < 0 && m_find("S2 T1", 0) >= 0'),
    m('conversion-pass-reads-gated-blocks', C, '        if (c->blk[block_order[k]].state == BS_OK) todo[count++] = block_order[k];\n', '        todo[count++] = block_order[k];\n', suites=('gate',),
      reason='m_wloads[M_SROT(1)] == CASES[c].srot'),
    m('conversion-pass-ignores-the-second-readings-verdict', C, '            b->state = BS_OFF;\n            pk_text(c, &line, "OFF");', '            pk_text(c, &line, "OFF");', suites=('drift',),
      reason='m_wloads[M_TM(1)] == 36 - 19 && m_wloads[M_SROT(1)] == 3'),
    m('a-second-reading-ctrl-error-keeps-the-block', C, '            b->state = BS_CTLERR;\n            pk_word(c, &line, "CTL=", &ctl);', '            pk_word(c, &line, "CTL=", &ctl);', suites=('drift',),
      reason='m_wloads[M_TM(2)] == 36 - 19 && m_find("S2 T3", 0) >= 0 && m_find("CONV T2", 0) < 0'),
    m('a-ctrl-error-is-called-off', C, 'b->state = b->ctl.st == V_OK ? BS_OFF : BS_CTLERR;', 'b->state = BS_OFF;', suites=('gate',), reason='T1 VER=0X20040000 CTL=FAULT:6 CTLERR'),
    m('chain-names-the-block-by-index', C, 'block_two(c, todo[k], k + 1 < count ? todo[k + 1] : INSTANCES)', 'block_two(c, todo[k], k + 1 < INSTANCES ? k + 1 : INSTANCES)',
      suites=('gate',), reason='" NEXT T2"'),
    m('conversion-chain-names-the-block-by-index', C, 'conv_block(c, todo[k], k + 1 < count ? todo[k + 1] : INSTANCES)', 'conv_block(c, todo[k], k + 1 < INSTANCES ? k + 1 : INSTANCES)',
      suites=('gate',), reason='"NEXT CONV T") == 2'),
    # -- The decode and the sums.
    m('sign-not-extended-right', C, 'if (t & 0x800) t -= 0x1000;', 'if (t & 0x800) t -= 0x800;', suites=('cells', 'random'), reason='a line differs'),
    m('window-top-moved', H, '#define TEMP_MAX_TENTHS 1200', '#define TEMP_MAX_TENTHS 1300', suites=('cells',), reason='a line differs'),
    m('window-bottom-moved', H, '#define TEMP_MIN_TENTHS (-400)', '#define TEMP_MIN_TENTHS (-500)', suites=('cells',), reason='a line differs'),
    m('only-all-ones-is-odd', C, 'if (raw >> ST_RESERVED_SHIFT) return K_ODD;', 'if (raw == 0xffffffffu) return K_ODD;', suites=('cells', 'random'), reason='a line differs'),
    m('reserved-bits-start-one-bit-high', H, '#define ST_RESERVED_SHIFT 22u', '#define ST_RESERVED_SHIFT 23u', suites=('cells',), reason='a line differs'),
    m('valid-bit-not-checked', C, 'if (!(raw & ST_VALID)) return K_INVALID;', 'if (0) return K_INVALID;', suites=('cells', 'random'), reason='a line differs'),
    m('valid-bit-moved', H, '#define ST_VALID (1u << 21)', '#define ST_VALID (1u << 20)', suites=('cells', 'unit'), reason='m_norm_is(i, GOLDEN[i])'),
    m('critical-flags-one-bit-low', H, '#define ST_CRIT_FLAGS (3u << 19)', '#define ST_CRIT_FLAGS (3u << 18)', suites=('cells',), reason='field CRIT differs'),
    m('critical-counted-for-odd-words', C, 'if (kind != K_ODD && (raw & ST_CRIT_FLAGS)) a->crit++;', 'if (raw & ST_CRIT_FLAGS) a->crit++;', suites=('cells',), reason='field CRIT differs'),
    m('minimum-ties-go-to-the-last', C, 'if (!a->valid || t < a->min) {', 'if (!a->valid || t <= a->min) {', suites=('cells',), reason='MIN=400(T0.0)'),
    m('maximum-ties-go-to-the-last', C, 'if (!a->valid || t > a->max) {', 'if (!a->valid || t >= a->max) {', suites=('cells',), reason='MAX=400(T0.0)'),
    m('block-minimum-ties-go-to-the-last', C, 'if (from->valid && (!to->valid || from->min < to->min)) {', 'if (from->valid && (!to->valid || from->min <= to->min)) {',
      suites=('cells',), reason='MIN=400(T0.0)'),
    m('first-sums-lost', C, '    agg_merge(&c->tot[0], &a);\n', '', suites=('unit', 'cells'), reason='m_norm_is(i, GOLDEN[i])'),
    m('change-needs-two-tenths', C, 'if (d) a.chg++;', 'if (d > 1) a.chg++;', suites=('unit', 'drift'), reason='m_field(line, "CHG") == (long)chg'),
    m('second-reading-shows-the-first-words', C, 'agg_sample(&a, n << 4 | i, w->v, code);', 'agg_sample(&a, n << 4 | i, b->st[0][i].v, code);', suites=('unit', 'drift'),
      reason='a line differs'),
    # -- CODE_OR_TEMP: a block whose CTRL does not say temperature has no temperatures.
    m('code-mode-cells-are-decoded', C, '    if (code) return K_ODD;\n', '', suites=('gate',), reason='T1 C O O O O O O O O O O O ? ? ? ? ? RDY=0X1 V=0'),
    m('code-bit-polarity-reversed', C, 'b->code = !(b->ctl.v & CTRL_CODE_OR_TEMP);', 'b->code = !!(b->ctl.v & CTRL_CODE_OR_TEMP);', suites=('unit',), reason='m_norm_is(i, GOLDEN[i])'),
    m('second-reading-code-bit-is-the-first-readings', C, 'unsigned code = !(ctl.v & CTRL_CODE_OR_TEMP);', 'unsigned code = b->code;', suites=('drift',),
      reason='S2 T1 V=0 MIN=NA MAX=NA CHG=0 D=0 DT=# CODE NEXT T2'),
    m('code-mode-is-not-said', C, '    if (b->state == BS_OK && b->code) pk_text(c, &line, "CODE");\n', '', suites=('gate',), reason='T1 VER=0X20040000 CTL=0X3FF9 SEN=0X7FF CODE'),
    # -- Time, frequency, EL.
    m('the-gap-is-one-second', H, '#define GAP_S 2u', '#define GAP_S 1u', suites=('unit',), reason='m_norm_is(i, GOLDEN[i])'),
    m('the-wait-is-half-as-long', C, 'if (now - start >= ticks) return DELAY_OK;', 'if (now - start >= ticks / 2) return DELAY_OK;', suites=('unit', 'counter'),
      reason='m_counter_value - m_last_load_counter'),
    m('a-frequency-outside-the-range-is-believed', C, 'c.hz_default = hz < COUNTER_HZ_MIN || hz > COUNTER_HZ_MAX;', 'c.hz_default = 0;', suites=('counter',), reason='m_line_is(0, HZ[i].header)'),
    m('a-stuck-counter-is-waited-for', C, 'if (++same >= STUCK_READS) return DELAY_STUCK;', 'if (++same >= STUCK_READS) same = 0;', stage='caps', suites=('caps',),
      reason='m_counter_reads <= STUCK_READS + 16', defs=('-DTSNAP_STUCK_READS=1000u', '-DTSNAP_SPIN_MAX=5000u')),
    m('a-slow-counter-is-waited-for', C, '    for (uint32_t spins = 0; spins < SPIN_MAX; spins++) {', '    for (uint32_t spins = 0; spins < 0xffffffffu; spins++) {', stage='caps', suites=('caps',),
      reason='m_counter_reads <= SPIN_MAX + 16', defs=('-DTSNAP_SPIN_MAX=5000u', '-DTSNAP_STUCK_READS=100000000u')),
    # The wait ends as SPIN only for a counter that moved, and a bound of 2^28 reads would end it early for a counter that needs more.
    m('a-moving-counter-is-called-dead', C, '    return moved ? DELAY_SPIN : DELAY_STUCK;', '    return DELAY_STUCK;', stage='caps', suites=('caps',),
      reason='m_find("S2 SKIPPED SPIN", 0) >= 0', defs=('-DTSNAP_SPIN_MAX=5000u',)),
    m('a-dead-counter-is-called-slow', C, '    return moved ? DELAY_SPIN : DELAY_STUCK;', '    return DELAY_SPIN;', stage='caps', suites=('caps',),
      reason='m_find("S2 SKIPPED NO_COUNTER", 0) >= 0 && m_find("S2 SKIPPED SPIN", 0) < 0', defs=('-DTSNAP_SPIN_MAX=5000u',)),
    m('a-counter-that-stops-is-called-slow', C, 'if (++same >= STUCK_READS) return DELAY_STUCK;', 'if (++same >= STUCK_READS) return DELAY_SPIN;', suites=('counter',),
      reason='m_find("S2 SKIPPED NO_COUNTER", 0) > m_find("NEXT S2 AFTER 2 S", 0) && m_find("S2 SKIPPED SPIN", 0) < 0'),
    m('the-spin-bound-is-the-old-2-to-the-28', C, '    for (uint32_t spins = 0; spins < SPIN_MAX; spins++) {', '    for (uint32_t spins = 0; spins < (1u << 28); spins++) {', stage='slow',
      suites=('slow',), reason='m_find("S2 SKIPPED", 0) < 0 && m_find("S2 T3", 0) >= 0'),
    m('the-spin-bound-in-the-header-is-the-old-2-to-the-28', H, '#define TSNAP_SPIN_MAX 0xffffffffu', '#define TSNAP_SPIN_MAX (1u << 28)', stage='binary',
      reason='the wait is bounded by 2^32 - 1 reads'),
    m('runs-below-el2', C, '    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {', '    if (0) {', suites=('el',), reason='m_nlines == 1 && m_line_is(0, "SKIPPED_NOT_AT_EL2")'),
    m('no-load-op-is-not-refused', C, '    if (!c.load32) {', '    if (0) {', reason='AddressSanitizer: SEGV'),
    # -- The page.
    m('end-line-count-is-short-by-one', C, 'dec(&line, c.lines + 1u);', 'dec(&line, c.lines);', suites=('unit',), reason='m_field(last, "LINES") == (long)m_nlines'),
    m('fields-are-cut-in-half', C, 'if (line->len + 1 + item->len > Q1N1_PAYLOAD_LINE_MAX) {', 'if (line->len + 1 + item->len > Q1N1_PAYLOAD_LINE_MAX + 20) {', suites=('budget',),
      reason='m_field(m_text(m_nlines - 1), "CUTS") == 8'),
    m('ready-word-is-not-on-the-temperature-line', C, '    pk_word(c, &line, "RDY=", &c->blk[n].rdy);\n', '', suites=('unit',), reason='m_norm_is(i, GOLDEN[i])'),
    m('ready-word-is-dropped-before-the-count', C, '    pk_word(c, &line, "RDY=", &c->blk[n].rdy);\n    pk_number(c, &line, "V=", a->valid);\n',
      '    pk_number(c, &line, "V=", a->valid);\n    pk_word(c, &line, "RDY=", &c->blk[n].rdy);\n', suites=('budget',),
      reason='T0 C 1100 1100 1100 1100 1100 1100 300 300 300 300 300 300 300 300 300 300 RDY=0X1'),
    m('raw-words-in-six-digits', C, 'for (unsigned shift = 32; shift;) {', 'for (unsigned shift = 24; shift;) {', suites=('unit', 'cells'), reason='m_norm_is(i, GOLDEN[i])'),
    m('sensor-enable-field-moved', H, '#define CTRL_SENSOR_SHIFT 3u', '#define CTRL_SENSOR_SHIFT 2u', suites=('unit', 'gate'), reason='m_norm_is(i, GOLDEN[i])'),
    m('lower-case-text', C, 'tx(&text, "NEXT T");', 'tx(&text, "next T");', suites=('unit',), reason='strchr(FONT, line[i]) != NULL'),
    m('the-cap-is-ignored', C, 'if (c->lines >= (closing ? LINE_CAP : LINE_CAP - CLOSING_LINES)) {', 'if (0) {', stage='caps', suites=('caps',), reason='m_nlines <= LINE_CAP', defs=SMALL),
    m('closing-lines-are-not-reserved', C, 'if (c->lines >= (closing ? LINE_CAP : LINE_CAP - CLOSING_LINES)) {', 'if (c->lines >= LINE_CAP) {', stage='caps', suites=('caps',),
      reason='END LOADS=', defs=SMALL),
    m('a-block-is-read-without-its-next-line', C, '    if (!next_line(c, n)) {\n        b->state = BS_SKIPPED;\n        c->gated++;\n        return;\n    }\n',
      '    next_line(c, n);\n', stage='caps', suites=('caps',), reason='m_ann_block == (int)n', defs=SMALL),
    m('load-budget-is-not-kept', C, 'if (c->loads >= LOAD_CAP) return RD_BUDGET;', '', stage='caps', suites=('caps',), reason='m_nloads <= LOAD_CAP', defs=SMALL_BOTH),
    # -- The order of the evidence and the announcements: what a hang names depends on them.
    m('trdy-is-read-before-the-status-words', C, '    for (unsigned half = 0; half < 2; half++) {\n        blk_head(&head, "", n);\n        tx(&head, " R");',
      '    read_word(c, WIN_TM(n), TM_TRDY, &b->rdy);\n    for (unsigned half = 0; half < 2; half++) {\n        blk_head(&head, "", n);\n        tx(&head, " R");', suites=('order',),
      reason='ev_load(&k, M_TM(n), 0xa0 + 4 * i)'),
    m('identity-line-is-never-printed-for-a-running-block', C, '    if (!identity_line(c, n)) {\n        b->state = BS_SKIPPED;\n        c->gated++;\n        return;\n    }\n    for (unsigned half',
      '    for (unsigned half', suites=('order',), reason='m_ann_ident == (int)n'),
    m('a-block-is-read-without-its-identity-line', C, '    if (!identity_line(c, n)) {\n        b->state = BS_SKIPPED;\n        c->gated++;\n        return;\n    }\n    for (unsigned half',
      '    identity_line(c, n);\n    for (unsigned half', stage='caps', suites=('caps',), reason='m_ann_ident == (int)n', defs=('-DTSNAP_LINE_CAP=5u',)),
    m('conversion-pass-before-the-second-reading', C, '    snapshot_two(&c);\n    conv_pass(&c);\n', '    conv_pass(&c);\n    snapshot_two(&c);\n', suites=('order',),
      reason='ev_line(&k, "SUM1 ") && ev_line(&k, "NEXT S2 AFTER 2 S")'),
    m('second-reading-is-not-announced', C, '        tx(&text, " S");\n        if (!say(c, text.buf, 0)) return;\n', '        tx(&text, " S");\n', suites=('order',),
      reason='ev_line(&k, "SUM1 ") && ev_line(&k, "NEXT S2 AFTER 2 S")'),
    m('conversion-lines-do-not-name-the-next-block', C, '    if (next < INSTANCES) announced = pk_next(c, &line, 1, next);\n', '    announced = 1;\n', suites=('order', 'unit'),
      reason='m_ann_conv == (int)n'),
    m('last-second-reading-line-does-not-name-the-conversion-pass', C, '        named = pk_next(c, &line, 1, conv);\n', '        named = 0;\n', suites=('unit', 'order'),
      reason='m_announces(line, "NEXT CONV T") == 0'),
    m('a-second-reading-block-is-read-after-its-line-failed', C, '    return printed && announced;\n', '    return 1;\n', stage='caps', suites=('caps',),
      reason='m_ann_s2_block == -1 || m_ann_s2_block == (int)n', defs=('-DTSNAP_LINE_CAP=28u',)),
    m('a-conversion-block-is-read-after-its-line-failed', C, '    return emit(c, &line, 0) && announced;\n', '    emit(c, &line, 0);\n    return 1;\n', stage='caps', suites=('caps',),
      reason='m_ann_conv == (int)n', defs=('-DTSNAP_LINE_CAP=30u',)),
    # -- A load that does not go through the runner's guarded load32 (the only device access the payload may make).
    m('a-device-word-is-read-without-the-guard', C, '    err = c->load32(phys, &c->word);\n', '    err = 0;\n    c->word = *(volatile uint32_t *)(uintptr_t)phys;\n', reason='AddressSanitizer: SEGV'),
    m('an-unguarded-load-is-an-integer-to-pointer', C, '    err = c->load32(phys, &c->word);\n', '    err = 0;\n    c->word = *(volatile uint32_t *)(uintptr_t)phys;\n', stage='audit',
      reason='turns an integer into a pointer'),
    # -- What the compiled code may hold (never run natively).
    m('store-to-a-device-address', C, '    c->loads++;\n', '    c->loads++;\n    *(volatile uint32_t *)(uintptr_t)(window_base[0] + 8u) = 0;\n', stage='audit',
      reason='turns an integer into a pointer'),
    m('store-through-the-arguments', C, '    c.puts = a->ops.puts;\n', '    c.puts = a->ops.puts;\n    ((struct q1n1_payload_args *)a)->reserved[0] = 1;\n', stage='audit',
      reason='stores through the arguments the runner passed'),
    m('store-through-a-pointer-read-back-from-memory', C, '    c->lines++;\n', '    c->lines++;\n    { struct pl_line *volatile keep = (struct pl_line *)line; keep->len = 0; }\n',
      stage='audit', reason="root ['L']"),
    m('explicit-memset-libcall', C, '    for (size_t i = 0; i < sizeof c; i++) ((volatile uint8_t *)&c)[i] = 0;\n',
      '    { extern void *memset(void *, int, unsigned long); memset(&c, 0, sizeof c); }\n', stage='audit', reason='memset, which the module does not define'),
    m('writable-global', C, 'OUT_OF_LINE int load(struct ctx *c, uint64_t phys, uint32_t *value)\n{\n',
      'static uint32_t seen;\nOUT_OF_LINE int load(struct ctx *c, uint64_t phys, uint32_t *value)\n{\n    seen++;\n', stage='audit', reason='is a writable global'),
    m('atomic-counter', C, '    c->loads++;\n', '    __atomic_fetch_add(&c->loads, 1, __ATOMIC_SEQ_CST);\n', stage='audit', reason='atomic or a fence'),
    m('smc-call', C, '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n', '    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;\n    __asm__ volatile("smc #0" ::: "memory");\n',
      stage='binary', reason='1 smc instructions, the policy allows 0'),
    m('data-barrier', C, '    c->loads++;\n', '    c->loads++;\n    __asm__ volatile("dsb sy" ::: "memory");\n', stage='binary', reason='forbidden instruction dsb'),
    m('instruction-barrier', C, '    c->loads++;\n', '    c->loads++;\n    __asm__ volatile("isb" ::: "memory");\n', stage='binary', reason='forbidden instruction isb'),
    m('reads-the-counter-register-itself', C, '    hz = SYSREG(cntfrq_el0);\n', '    hz = SYSREG(cntfrq_el0);\n    hz += SYSREG(cntpct_el0) & 0;\n', stage='binary', reason="registers read ['cntfrq_el0', 'cntpct_el0', 'currentel']"),
    m('writes-a-system-register', C, '    c->loads++;\n', '    c->loads++;\n    __asm__ volatile("msr daifset, #2" ::: "memory");\n', stage='binary', reason='forbidden instruction msr'),
    m('exclusive-store-pair', C, '    c->loads++;\n', '    c->loads++;\n    { uint32_t t_; uint32_t r_; __asm__ volatile("1: ldxr %w0, [%2]\\n stxr %w1, %w0, [%2]\\n cbnz %w1, 1b" : "=&r"(t_), "=&r"(r_) : "r"(&c->loads) : "memory"); }\n',
      stage='binary', reason='exclusive or atomic instruction'),
    m('frame-larger-than-the-stack-allows', C, '    struct pl_line line;\n    uint64_t hz;\n', '    struct pl_line line;\n    uint64_t hz;\n    volatile char big[60000];\n    __asm__ volatile("" :: "r"(&big[0]) : "memory");\n', stage='stack'),
]
