# SPDX-License-Identifier: MIT
"""Seeded bugs for the payload `inputsnap` (docs/SP11-PAYLOAD-INPUTSNAP.md, tools/test-q1n1-sp11-payload-inputsnap.py): each one edits a copy of
payloads/inputsnap.c or payloads/inputsnap-regs.h (the needle must occur exactly once: a needle that does not is a stale mutant and an error, not a pass) and
the suites below must reject the copy:

  harness   the native host test (tools/test-q1n1-sp11-payload-inputsnap.c) built against the copy, at the shipped caps and, for the mutants that need it,
            with a smaller line or load cap or spin bound (`harness-capped`); it fails by exit status (a violation, a check, a signal) and prints its FAIL lines
  ir        the compiled-code audit (tools/sp11_payload_inputsnap_audit.py) of the copy's LLVM IR
  binary    the allow-list and memory check of the linked copy (the `inputsnap` policy of that module, with `read_only`)
  refs      the register table and field positions of the copy against the pinned Linux files (tools/test-q1n1-sp11-payload-inputsnap-refs.py; a SKIP,
            never a pass, in a tree without them)

`expect` is what each mutant must be rejected by; other suites may reject it too. REASONS says in each suite's own words why: a rejection for another
reason (a crash, a build failure, a check that trips by accident) is not a pass. DOC_MUTANTS are the seeded bugs of the document (a table row that is missing),
which the document test must refuse. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_inputsnap_audit as audit  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('inputsnap.c', 'inputsnap-regs.h')
H, I, B, R = 'harness', 'ir', 'binary', 'refs'
SPIN_BUILD = '-DINPUTSNAP_SPIN_MAX=4000000u'

# (name, what it is, [(file, needle, replacement)], expect, capped): `capped` also builds the harness with a smaller cap where a failure needs one to show:
# True is a line cap of 6 (a NEXT line can fail to print), a string is the build flag to use.
MUTANTS = [
    ('store-to-window', 'a store to the device word it just read',
     [('inputsnap.c', "    err = c->load32(phys, &c->word);\n    if (err) {", "    err = c->load32(phys, &c->word);\n    *(volatile uint32_t *)(uintptr_t)phys = 0;\n    if (err) {")],
     {H, I, B}, False),
    ('store-through-args', 'a store through the arguments the runner passed',
     [('inputsnap.c', "    c.puts = a->ops.puts;\n", "    ((struct q1n1_payload_args *)a)->reserved[0] = 1;\n    c.puts = a->ops.puts;\n")],
     {I, B}, False),
    ('writable-global', 'a counter in a writable global',
     [('inputsnap.c', "OUT_OF_LINE int emit(struct ctx *c, const struct pl_line *line, unsigned keep)\n",
       "static volatile uint32_t emitted;\nOUT_OF_LINE int emit(struct ctx *c, const struct pl_line *line, unsigned keep)\n"),
      ('inputsnap.c', "    c->lines++;\n    c->puts(line->buf);\n", "    c->lines++;\n    emitted++;\n    c->puts(line->buf);\n")],
     {I, B}, False),
    ('unguarded-load', 'the device word is loaded through a pointer made from the address, not through the runner\'s load32',
     [('inputsnap.c', "    err = c->load32(phys, &c->word);\n    if (err) {", "    err = 0;\n    c->word = *(volatile uint32_t *)(uintptr_t)phys;\n    if (err) {")],
     {H, I, B}, False),
    ('fifo-window-read', 'the receive watermark is read at 0x784, inside the receive FIFO window (a read pops bytes)',
     [('inputsnap-regs.h', 'X(U_RFW, "RFW", 0x0814,', 'X(U_RFW, "RFW", 0x0784,')], {H, R}, False),
    ('tlmm-reserved-pin', 'gpio43\'s CFG is read at 0x2c000, which is gpio44\'s (the TPM, reserved)',
     [('inputsnap-regs.h', 'X(T_F43, "F43", 0x2b000,', 'X(T_F43, "F43", 0x2c000,')], {H, R}, False),
    ('no-next-line', 'no NEXT line before the SPI engine\'s block',
     [('inputsnap.c', "    if (!say(c, next.buf, b >= B_XU2 ? KEEP_X : KEEP_DATA)) {\n        c->blocks |= 1u << b;\n        return;\n    }\n",
       "    if (b != B_S10 && !say(c, next.buf, b >= B_XU2 ? KEEP_X : KEEP_DATA)) {\n        c->blocks |= 1u << b;\n        return;\n    }\n")], {H}, False),
    ('no-next-late-block', 'no NEXT line before the UART engine\'s late block',
     [('inputsnap.c', "    if (!say(c, next.buf, b >= B_XU2 ? KEEP_X : KEEP_DATA)) {\n        c->blocks |= 1u << b;\n        return;\n    }\n",
       "    if (b != B_XU2 && !say(c, next.buf, b >= B_XU2 ? KEEP_X : KEEP_DATA)) {\n        c->blocks |= 1u << b;\n        return;\n    }\n")], {H}, False),
    ('no-next-wait', 'the wait is made without the `NEXT WAIT 8 S` line that announces it',
     [('inputsnap.c', "    if (!say(c, wait.buf, KEEP_DATA)) return;\n", "")], {H}, False),
    ('no-next-s2', 'snapshot 2 reads its windows without the `NEXT S2 <window>` lines',
     [('inputsnap.c', "        visit = (unsigned)say(c, next.buf, KEEP_DATA) && verdict == GATE_OPEN;\n", "        visit = verdict == GATE_OPEN;\n")], {H}, False),
    ('read-without-next', 'a block is read although its NEXT line could not be printed',
     [('inputsnap.c', "    if (!say(c, next.buf, b >= B_XU2 ? KEEP_X : KEEP_DATA)) {\n        c->blocks |= 1u << b;\n        return;\n    }\n",
       "    say(c, next.buf, b >= B_XU2 ? KEEP_X : KEEP_DATA);\n")], {H}, True),
    ('tlmm-before-gcc', 'the blocks are read last to first: the pin controller before the clock words',
     [('inputsnap.c', "    for (unsigned b = 0; b < S1_BLOCKS; b++) announce_and_read(c, &c->s[0], &c->s[0], b);\n",
       "    for (unsigned b = S1_BLOCKS; b-- > 0;) announce_and_read(c, &c->s[0], &c->s[0], b);\n")], {H}, False),
    ('retry-after-fault', 'a faulting load is tried again',
     [('inputsnap.c', "    if (err) {\n        c->err = (uint32_t)err;\n        return RD_FAULT;", "    if (err && c->load32(phys, &c->word)) {\n        c->err = (uint32_t)err;\n        return RD_FAULT;")],
     {H}, False),
    ('dead-window-ignored', 'a window that aborted is read on',
     [('inputsnap.c', "        if (rc == RD_FAULT) c->dead |= 1u << dead_bit(win, grp);\n", "        if (rc == RD_FAULT) c->dead |= 0;\n")], {H}, False),
    ('gcc-dead-window-wide', 'an abort in one group of GCC ends every later read of GCC',
     [('inputsnap.c', "    return win == WIN_GCC ? grp : 2u + win;\n", "    return 2u + win;\n")], {H}, False),
    ('gate-removed', 'the engines are read whatever their clock words say',
     [('inputsnap.c', "    if (!engine) return GATE_OPEN;\n", "    return GATE_OPEN;\n")], {H}, False),
    ('gate-fails-open', 'a clock word that did not read (an abort, a skip) does not gate the engine',
     [('inputsnap.c', "        if (s->v[id].st != V_OK) {\n            unknown = 1;\n            continue;\n        }\n", "        if (s->v[id].st != V_OK) continue;\n")], {H}, False),
    ('gate-ignores-hwcg-flag', 'a clock word that is OFF with HW_CTL set is called hardware-gated for every clock, not only the four AHB clocks',
     [('inputsnap.c', "    return hwcg && (v->v >> 1 & 1) ? CK_HW : CK_OFF;\n", "    return (v->v >> 1 & 1) ? CK_HW : CK_OFF;\n")], {H}, False),
    ('gate-ignores-all-ones', 'an all-ones clock word, what a failed read returns, is a clock word like another',
     [('inputsnap.c', "    if (v->v == 0xffffffffu) return CK_ODD;\n", "")], {H}, False),
    ('gate-err-says-off', 'a clock word that did not read is reported as a clock that is off',
     [('inputsnap.c', "    return off ? GATE_OFF : unknown ? GATE_ERR : GATE_OPEN;\n", "    return off || unknown ? GATE_OFF : GATE_OPEN;\n")], {H}, False),
    ('gate-roles-swapped', 'the UART engine is gated by the SPI engine\'s clock words and the SPI engine by the UART engine\'s',
     [('inputsnap.c', "    unsigned engine = win == WIN_U2 ? GATE_U2 : win == WIN_S10 ? GATE_S10 : 0, off = 0, unknown = 0;\n",
       "    unsigned engine = win == WIN_U2 ? GATE_S10 : win == WIN_S10 ? GATE_U2 : 0, off = 0, unknown = 0;\n")], {H}, False),
    ('s2-gating-removed', 'snapshot 2 announces an engine whose clocks went off during the wait as visited (`NEXT S2 U2`), not as skipped; the check at the load itself still holds back every read',
     [('inputsnap.c', "        verdict = engine_gate(&c->s[1], &c->s[0], win);\n", "        verdict = GATE_OPEN;\n")], {H}, False),
    ('late-gates-on-snapshot-1', 'the late blocks gate on snapshot 1\'s clock words, not on the freshest ones',
     [('inputsnap.c', "        announce_and_read(c, &c->s[1], gate, b);\n", "        announce_and_read(c, &c->s[1], &c->s[0], b);\n")], {H}, False),
    ('late-read-without-room', 'a late block is read although the page has no room left for what it reads',
     [('inputsnap.c', "        if (room_for(c, b) < 2) {\n            c->blocks |= 1u << b;\n            continue;\n        }\n", "")], {H}, False),
    ('s1-gated-line-lost', 'a gated engine prints a value per row instead of the one line `<engine> GATED OFF`',
     [('inputsnap.c', "    if (verdict != GATE_OPEN) {\n        struct pl_line gated;", "    if (0) {\n        struct pl_line gated;")], {H}, False),
    ('drift-counts-s2-skipped-window', 'the drift report compares the values of an engine that snapshot 2 did not visit',
     [('inputsnap.c', "    if (c->s2_skip >> r->win & 1) return 0;\n", "")], {H}, False),
    ('s2-note-dropped', 'snapshot 2 does not say what it found in GCC on the next NEXT line',
     [('inputsnap.c', '        if (note.len) {\n            tx(&next, " ");\n            tx(&next, note.buf);\n        }\n', "")], {H}, False),
    ('stream-read-then-print', 'a block is read whole and printed afterwards',
     [('inputsnap.c', "        read_row(c, s, gate, id);\n        put_row(c, &o, s, id);\n        if (id + 1 < block_first[b + 1] && (regs[id + 1].flags & F_BREAK)) out_break(c, &o);\n    }\n    out_end(c, &o);\n",
       "        read_row(c, s, gate, id);\n    }\n    for (unsigned id = block_first[b]; id < block_first[b + 1]; id++) {\n        if (regs[id].flags & F_BREAK) out_break(c, &o);\n"
       "        put_row(c, &o, s, id);\n    }\n    out_end(c, &o);\n")], {H}, False),
    ('wide-high-word-first', 'a 64-bit register is read high word first',
     [('inputsnap.c', "    int rc = rd32(c, win, grp, off, &lo);\n    if (!rc) rc = rd32(c, win, grp, off + 4, &hi);\n",
       "    int rc = rd32(c, win, grp, off + 4, &hi);\n    if (!rc) rc = rd32(c, win, grp, off, &lo);\n")], {H}, False),
    ('s2-reads-unlisted', 'snapshot 2 reads the main interrupt enable word again, which no snapshot-2 list names',
     [('inputsnap-regs.h', 'X(U_MIE, "MIE", 0x0614, WIN_U2, 0, 0, F_BREAK,', 'X(U_MIE, "MIE", 0x0614, WIN_U2, 0, 0, F_BREAK | F_S2,')], {H}, False),
    ('late-before-s2', 'the words no Linux driver reads are read before the wait and snapshot 2',
     [('inputsnap.c', "    snapshot_one(&c);\n    snapshot_two(&c);\n    if (c.s2_ran) drift_report(&c);\n    late_blocks(&c);\n",
       "    snapshot_one(&c);\n    late_blocks(&c);\n    snapshot_two(&c);\n    if (c.s2_ran) drift_report(&c);\n")], {H}, False),
    ('drift-after-late', 'the drift summary is printed after the late blocks, so that a hang in them loses it',
     [('inputsnap.c', "    snapshot_one(&c);\n    snapshot_two(&c);\n    if (c.s2_ran) drift_report(&c);\n    late_blocks(&c);\n",
       "    snapshot_one(&c);\n    snapshot_two(&c);\n    late_blocks(&c);\n    if (c.s2_ran) drift_report(&c);\n")], {H}, False),
    ('wait-zero', 'the wait the page announces is not made (the page still says 8 S)',
     [('inputsnap.c', "    waited = delay_ticks(c, (uint64_t)GAP_S * c->hz);\n", "    waited = delay_ticks(c, 0);\n")], {H}, False),
    ('unbounded-wait', 'the wait does not give up on a counter that does not run',
     [('inputsnap-regs.h', "#define COUNTER_STUCK_READS 2000000u", "#define COUNTER_STUCK_READS 0xffffffffu")], {H}, False),
    ('spin-bound-too-small', 'the bound on the wait\'s reads is 2^20, which a slow loop on a slow counter reaches before 8 s',
     [('inputsnap-regs.h', "#define INPUTSNAP_SPIN_MAX 0xffffffffu", "#define INPUTSNAP_SPIN_MAX 0x00100000u")], {H}, False),
    ('spin-bound-says-dead', 'a bound that is reached while the counter runs is reported as a dead counter',
     [('inputsnap.c', "        if (++spins >= SPIN_MAX) return W_SPIN;\n", "        if (++spins >= SPIN_MAX) return W_DEAD;\n")], {H}, SPIN_BUILD),
    ('dead-counter-says-spin', 'a counter that stands still is reported as a bound that was reached',
     [('inputsnap.c', "            if (++same >= COUNTER_STUCK_READS) return W_DEAD;\n", "            if (++same >= COUNTER_STUCK_READS) return W_SPIN;\n")], {H}, False),
    ('line-overflow', 'the line cap, the blocks\' budget and the drift budget are gone',
     [('inputsnap.c', "    if (c->lines + keep >= LINE_CAP) {", "    if (0) {"),
      ('inputsnap.c', "    return LINE_CAP - keep < max ? LINE_CAP - keep : max;\n", "    return max;\n"),
      ('inputsnap.c', "        out_begin(&o, group[g], avail < group_lines[g] ? avail : group_lines[g], KEEP_DATA);", "        out_begin(&o, group[g], group_lines[g], KEEP_DATA);")],
     {H}, True),
    ('closing-crowded-out', 'the drift lines may take the rows the summary and the end line need',
     [('inputsnap-regs.h', "#define CLOSING_LINES 2u", "#define CLOSING_LINES 0u")], {H}, False),
    ('load-cap-ignored', 'a load past the payload\'s own cap is made',
     [('inputsnap.c', "    if (c->loads >= LOAD_CAP) return RD_BUDGET;\n", "")], {H}, '-DINPUTSNAP_LOAD_CAP=60u'),
    ('fault-code-lost', 'an abort is printed without the code load32 returned',
     [('inputsnap.c', '        tx(line, "FAULT:");\n        dec(line, v->code);\n', '        tx(line, "FAULT:");\n')], {H}, False),
    ('cbcr-polarity', 'a set CLK_OFF is called ON',
     [('inputsnap.c', "    if (!(v->v >> 31 & 1) || (v->v >> 28 & 7) == 2) return CK_ON;\n", "    if ((v->v >> 31 & 1) || (v->v >> 28 & 7) == 2) return CK_ON;\n")], {H}, False),
    ('cts-mode-unchecked', 'IO2 is read as CTS whatever protocol the engine runs',
     [('inputsnap.c', '        if (uart_mode(s)) put_field(c, o, "CTS", v, 1, 1, D_NONE);', '        if (1) put_field(c, o, "CTS", v, 1, 1, D_NONE);')], {H}, False),
    ('fifo-mode-unchecked', 'the FIFO counts are decoded whatever the DMA and FIFO interface mode words say',
     [('inputsnap.c', "    return ifd->st == V_OK && dma->st == V_OK && !(ifd->v & 1) && !(dma->v & 1);\n", "    return 1;\n")], {H}, False),
    ('el-check-dropped', 'the payload reads whatever the exception level',
     [('inputsnap.c', "    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {", "    if (0) {")], {H}, False),
    ('first-load-no-precedent', 'the UART engine\'s block starts with the serial clock word, which no Linux driver reads, instead of the firmware revision word',
     [('inputsnap-regs.h', 'X(U_FW, "FW", 0x0068,', 'X(U_FW, "FW", 0x0048,')], {H, R}, False),
    ('gcc-offset-drift', 'the QSPI clock of wrapper 1 is read 4 bytes up',
     [('inputsnap-regs.h', 'X(G_QS1, "QS1", 0x18280,', 'X(G_QS1, "QS1", 0x18284,')], {H, R}, False),
    ('engine-offset-drift', 'the firmware revision word is read at +0x6c',
     [('inputsnap-regs.h', 'X(U_FW, "FW", 0x0068,', 'X(U_FW, "FW", 0x006c,')], {H, R}, False),
    ('gic-offset-drift', 'the routing register of INTID 616 is read 8 bytes up',
     [('inputsnap-regs.h', 'X(I_R616, "R616", 0x7340,', 'X(I_R616, "R616", 0x7348,')], {H, R}, False),
    ('pin-offset-drift', 'the level of gpio91 is read at +8, which is its interrupt configuration word',
     [('inputsnap-regs.h', 'X(T_L91, "L91", 0x5b004,', 'X(T_L91, "L91", 0x5b008,')], {H, R}, False),
    ('window-base-gcc', 'the clock controller\'s window starts 0x1000 up',
     [('inputsnap-regs.h', "{0x00100000u, 0x200000u, 0}", "{0x00101000u, 0x200000u, 0}")], {H, R}, False),
    ('window-base-gic', 'the GIC distributor\'s window starts 0x1000 up',
     [('inputsnap-regs.h', "{0x17000000u, 0x10000u, 0}", "{0x17001000u, 0x10000u, 0}")], {H, R}, False),
    ('window-base-u2', 'the UART engine\'s window starts 0x4000 up',
     [('inputsnap-regs.h', "{0x00b88000u, 0x1000u, 0}", "{0x00b8c000u, 0x1000u, 0}")], {H, R}, False),
    ('window-base-s10', 'the SPI engine\'s window starts 0x4000 up',
     [('inputsnap-regs.h', "{0x00a88000u, 0x1000u, 0}", "{0x00a8c000u, 0x1000u, 0}")], {H, R}, False),
    ('window-base-tlmm', 'the pin controller\'s window starts 0x1000 up',
     [('inputsnap-regs.h', "{0x0f100000u, 0xf00000u, 0}", "{0x0f101000u, 0xf00000u, 0}")], {H, R}, False),
    ('window-swap-engines', 'the UART engine and the SPI engine have each other\'s window',
     [('inputsnap-regs.h', "{0x00b88000u, 0x1000u, 0}, {0x00a88000u, 0x1000u, 0}", "{0x00a88000u, 0x1000u, 0}, {0x00b88000u, 0x1000u, 0}")], {H, R}, False),
    ('block-window-swap', 'the late blocks of the two engines read each other\'s window',
     [('inputsnap-regs.h', "static const uint8_t block_win[BLOCKS] = {WIN_GCC, WIN_GIC, WIN_U2, WIN_S10, WIN_TLMM, WIN_U2, WIN_S10, WIN_GIC};",
       "static const uint8_t block_win[BLOCKS] = {WIN_GCC, WIN_GIC, WIN_U2, WIN_S10, WIN_TLMM, WIN_S10, WIN_U2, WIN_GIC};")], {H}, False),
    ('field-shift-drift', 'the secondary command active bit is taken from bit 11',
     [('inputsnap.c', 'put_field(c, o, "S", v, 12, 1, D_NONE);', 'put_field(c, o, "S", v, 11, 1, D_NONE);')], {H, R}, False),
    ('icfgr-width-drift', 'the configuration field of INTID 616 is three bits wide',
     [('inputsnap-regs.h', 'X(I_C616, "C616", 0x0c98, WIN_GIC, 0, 0, 0, D_FIELD, 16, 2,', 'X(I_C616, "C616", 0x0c98, WIN_GIC, 0, 0, 0, D_FIELD, 16, 3,')], {H, R}, False),
    ('hwcg-flag-drift', 'the first AHB clock of wrapper 0 no longer carries the hardware gating flag',
     [('inputsnap-regs.h', 'X(G_MA0, "MA0", 0x23000, WIN_GCC, G_W0, GATE_U2, F_S2 | F_HWCG,', 'X(G_MA0, "MA0", 0x23000, WIN_GCC, G_W0, GATE_U2, F_S2,')], {H, R}, False),
    # v1.1: the vote evidence a hardware-gated clock and a window of zeros need, and the second lines of defence the page never shows.
    ('hw-gate-needs-no-vote', 'a clock that says only hardware gating counts as running whatever its vote says',
     [('inputsnap.c', "        if (state == CK_HW) {\n            state = CK_ODD;\n", "        if (state == CK_HW) state = CK_ON;\n        if (0) {\n            state = CK_ODD;\n")], {H}, False),
    ('hw-unread-vote-counts-as-a-vote', 'a hardware-gated clock whose vote word did not read counts as running',
     [('inputsnap.c', "            state = CK_ODD;\n            for (unsigned k = 0;", "            state = CK_ON;\n            for (unsigned k = 0;")], {H}, False),
    ('hw-clear-vote-says-unknown', 'a hardware-gated clock whose vote bit is clear is reported as unknown (GATED ERR), not as stopped (GATED OFF)',
     [('inputsnap.c', "state = vote->v >> hw_votes[k].bit & 1 ? CK_ON : CK_OFF;", "state = vote->v >> hw_votes[k].bit & 1 ? CK_ON : CK_ODD;")], {H}, False),
    ('hw-set-vote-says-unknown', 'a hardware-gated clock whose vote bit is set is still unknown: the engine is never read',
     [('inputsnap.c', "state = vote->v >> hw_votes[k].bit & 1 ? CK_ON : CK_OFF;", "state = vote->v >> hw_votes[k].bit & 1 ? CK_ODD : CK_OFF;")], {H}, False),
    ('hw-vote-bit-of-ma0-is-7', 'the vote of wrapper 0\'s m_ahb clock is taken from bit 7, its neighbour\'s',
     [('inputsnap-regs.h', "{{R_G_MA0, R_G_VT0, 6, 0},", "{{R_G_MA0, R_G_VT0, 7, 0},")], {H, R}, False),
    ('hw-vote-bit-of-sa0-is-6', 'the vote of wrapper 0\'s s_ahb clock is taken from bit 6, its neighbour\'s',
     [('inputsnap-regs.h', "{R_G_SA0, R_G_VT0, 7, 0},", "{R_G_SA0, R_G_VT0, 6, 0},")], {H, R}, False),
    ('hw-vote-bit-of-ma1-is-19', 'the vote of wrapper 1\'s m_ahb clock is taken from bit 19',
     [('inputsnap-regs.h', "{R_G_MA1, R_G_VT1, 20, 0},", "{R_G_MA1, R_G_VT1, 19, 0},")], {H, R}, False),
    ('hw-vote-bit-of-sa1-is-22', 'the vote of wrapper 1\'s s_ahb clock is taken from bit 22',
     [('inputsnap-regs.h', "{R_G_SA1, R_G_VT1, 21, 0}};", "{R_G_SA1, R_G_VT1, 22, 0}};")], {H, R}, False),
    ('hw-vote-word-of-ma1-is-vt0', 'the vote of wrapper 1\'s m_ahb clock is looked up in wrapper 0\'s vote word',
     [('inputsnap-regs.h', "{R_G_MA1, R_G_VT1, 20, 0},", "{R_G_MA1, R_G_VT0, 20, 0},")], {H, R}, False),
    ('hw-vote-word-of-sa1-is-vt2', 'the vote of wrapper 1\'s s_ahb clock is looked up in the third vote word',
     [('inputsnap-regs.h', "{R_G_SA1, R_G_VT1, 21, 0}};", "{R_G_SA1, R_G_VT2, 21, 0}};")], {H, R}, False),
    ('zero-votes-open-the-gate', 'three vote words that read zero (a window of zeros) do not gate the engines',
     [('inputsnap.c', "    if (votes->v[R_G_VT0].st == V_OK && votes->v[R_G_VT1].st == V_OK && votes->v[R_G_VT2].st == V_OK && !(votes->v[R_G_VT0].v | votes->v[R_G_VT1].v | votes->v[R_G_VT2].v)) unknown = 1;\n", "")],
     {H}, False),
    ('zero-rule-asks-vt0-only', 'the engines are gated whenever the first vote word reads zero, not when all three do',
     [('inputsnap.c', "    if (votes->v[R_G_VT0].st == V_OK && votes->v[R_G_VT1].st == V_OK && votes->v[R_G_VT2].st == V_OK && !(votes->v[R_G_VT0].v | votes->v[R_G_VT1].v | votes->v[R_G_VT2].v)) unknown = 1;\n",
       "    if (votes->v[R_G_VT0].st == V_OK && !votes->v[R_G_VT0].v) unknown = 1;\n")], {H}, False),
    ('zero-rule-ignores-vt2', 'the third vote word does not count as vote evidence',
     [('inputsnap.c', "!(votes->v[R_G_VT0].v | votes->v[R_G_VT1].v | votes->v[R_G_VT2].v)) unknown = 1;", "!(votes->v[R_G_VT0].v | votes->v[R_G_VT1].v)) unknown = 1;")], {H}, False),
    ('zero-rule-uses-and', 'the vote words are ANDed: the engines are gated when no bit is set in all three',
     [('inputsnap.c', "!(votes->v[R_G_VT0].v | votes->v[R_G_VT1].v | votes->v[R_G_VT2].v)) unknown = 1;", "!(votes->v[R_G_VT0].v & votes->v[R_G_VT1].v & votes->v[R_G_VT2].v)) unknown = 1;")], {H}, False),
    ('zero-rule-counts-unread-votes', 'a vote word that did not read counts as one that read zero',
     [('inputsnap.c', "    if (votes->v[R_G_VT0].st == V_OK && votes->v[R_G_VT1].st == V_OK && votes->v[R_G_VT2].st == V_OK && !(", "    if (!(")], {H}, False),
    ('s2-gate-takes-votes-from-snapshot-2', 'snapshot 2 judges a hardware-gated clock by vote words it did not read',
     [('inputsnap.c', "        verdict = engine_gate(&c->s[1], &c->s[0], win);\n", "        verdict = engine_gate(&c->s[1], &c->s[1], win);\n")], {H}, False),
    ('late-gate-takes-votes-from-the-gate-snapshot', 'the late blocks judge a hardware-gated clock by the vote words of the freshest snapshot, which holds none',
     [('inputsnap.c', "    unsigned verdict = engine_gate(gate, &c->s[0], block_win[b]), keep", "    unsigned verdict = engine_gate(gate, gate, block_win[b]), keep")], {H}, False),
    ('rd32-window-unchecked', 'the read primitive indexes its window table by a window number it has not checked',
     [('inputsnap.c', "    if (win >= WINDOWS) {\n        rc = RD_RANGE;\n    } else if (off & 3) {", "    if (off & 3) {")], {H}, False),
    ('rd32-range-unchecked', 'the read primitive loads an offset past the end of its window',
     [('inputsnap.c', "    } else if (off >= windows[win].size || windows[win].size - off < 4) {", "    } else if (0) {")], {H}, False),
    ('rd32-alignment-unchecked', 'the read primitive loads an unaligned offset',
     [('inputsnap.c', "    } else if (off & 3) {\n        rc = RD_ALIGN;", "    } else if (0) {\n        rc = RD_ALIGN;")], {H}, False),
    ('read-row-gate-removed', 'the check at the load itself does not hold an engine back: only the callers\' checks do',
     [('inputsnap.c', "    if (engine_gate(gate, &c->s[0], r->win) != GATE_OPEN) {", "    if (0) {")], {H}, False),
    ('emit-cap-off-by-one', 'a line may use the last of the lines it must keep free',
     [('inputsnap.c', "    if (c->lines + keep >= LINE_CAP) {", "    if (c->lines + keep > LINE_CAP) {")], {H}, False),
]

# Seeded bugs of the document: (name, what it is, the outcome-table token whose row is taken out). The document test must name the row it misses.
DOC_MUTANTS = [
    ('doc-token-row-missing', 'the outcome table has no row for `S2 SKIPPED SPIN`', 'S2 SKIPPED SPIN'),
]

# What each suite must say about each mutant, a regular expression over the suite's own words: a mutant that is rejected for another reason (a crash, a
# build failure, a different check that happens to trip) is not a pass. `harness-capped` stands for the harness built with the smaller cap `capped` names.
GATE_STOPPED = r'load of U2\+0x[0-9a-f]+ while the clock word GCC\+0x23000 of the engine is stopped \(0x80000000\)'
REASONS = {
    'store-to-window': {H: r'an access reached a device window without load32', I: r'integer-to-pointer', B: r"not provably the payload's own stack"},
    'store-through-args': {I: r'stores through the arguments the runner passed', B: r"not provably the payload's own stack"},
    'writable-global': {I: r'is a writable global', B: r'no writable globals'},
    'unguarded-load': {H: r'an access reached a device window without load32', I: r'integer-to-pointer', B: r'a load in \w+ at 0x[0-9a-f]+ .* is not provably the stack'},
    'fifo-window-read': {H: r'load of U2\+0x784, a register the design forbids', R: r"key='RFW'"},
    'tlmm-reserved-pin': {H: r'load of TLMM\+0x2c000, a register the design forbids', R: r"word='F43'"},
    'no-next-line': {H: r'load of S10\+0x[0-9a-f]+ \(block S10\) without `NEXT S10` as the last line'},
    'no-next-late-block': {H: r'(late-block load of U2\+0x[0-9a-f]+ without `NEXT X U2` as the last line|snapshot-2 load of U2\+0x48, a register the snapshot-2 list does not name)'},
    'no-next-wait': {H: r'\+0x[0-9a-f]+ read twice in one snapshot'},
    'no-next-s2': {H: r'snapshot-2 load of GCC\+0x[0-9a-f]+ without `NEXT S2 GCC` as the last line'},
    'read-without-next': {'harness-capped': r'\(block U2\) without `NEXT U2` as the last line'},
    'tlmm-before-gcc': {H: r'\(block \w+\) after a later block'},
    'retry-after-fault': {H: r'after an abort in that window \(a retry'},
    'dead-window-ignored': {H: r'after an abort in that window \(a retry'},
    'gcc-dead-window-wide': {H: r'm_window_loads\(M_GCC, 1\) == 14 - m_group_after'},
    'gate-removed': {H: GATE_STOPPED},
    'gate-fails-open': {H: r'load of U2\+0x[0-9a-f]+ while the clock word GCC\+0x23000 of the engine aborted'},
    'gate-ignores-hwcg-flag': {H: r'GCC C20 is 0X80000002\.HW, not 0X80000002\.OFF'},
    'gate-ignores-all-ones': {H: r'GCC C20 is 0XFFFFFFFF\.OFF, not 0XFFFFFFFF\.ODD'},
    'gate-err-says-off': {H: r'WORDS\[k\]\.unknown \? err : off'},
    'gate-roles-swapped': {H: GATE_STOPPED},
    's2-gating-removed': {H: r'm_line_starts\("S2 U2 SKIP GATED OFF"\) > 0'},
    'late-gates-on-snapshot-1': {H: GATE_STOPPED},
    'late-read-without-room': {H: r'm_late_blocks_accounted\(\)'},
    's1-gated-line-lost': {H: r'WORDS\[k\]\.unknown \? err : off'},
    'drift-counts-s2-skipped-window': {H: r'DRIFT CHANGED=1 LOST=0 CMP=13'},
    's2-note-dropped': {H: r'm_line_index\("NEXT S2 U2 GCC=SAME", 0\) > 0'},
    'stream-read-then-print': {H: r'event < load'},
    'wide-high-word-first': {H: r'the high word \w+\+0x[0-9a-f]+ of a 64-bit register is not read right after its low word'},
    's2-reads-unlisted': {H: r'snapshot-2 load of U2\+0x614, a register the snapshot-2 list does not name'},
    'late-before-s2': {H: r'last1 < first2 && last2 < first3'},
    'drift-after-late': {H: r'm_line_event\(\(unsigned\)drift\) < first_x'},
    'wait-zero': {H: r'm_end_field\("GAP_MS"\) >= 8000'},
    'unbounded-wait': {H: r'the counter was read \d+ times: an unbounded wait'},
    'spin-bound-too-small': {H: r'SPIN_MAX == 0xffffffffu'},
    'spin-bound-says-dead': {'harness-capped': r'S2 SKIPPED SPIN'},
    'dead-counter-says-spin': {H: r'S2 SKIPPED SPIN'},
    'line-overflow': {H: r"more lines than the payload's cap", 'harness-capped': r"more lines than the payload's cap"},
    'closing-crowded-out': {H: r'the last line is not the end line'},
    'load-cap-ignored': {'harness-capped': r"more loads than the payload's cap"},
    'fault-code-lost': {H: r'U2 IFD is FAULT:, not FAULT:6|named == n'},
    'cbcr-polarity': {H: r'page line 3 is .*MA0=1\.OFF'},
    'cts-mode-unchecked': {H: r'U2 CTS is 1, not ODD'},
    'fifo-mode-unchecked': {H: r'U2 TXN is 7, not ODD'},
    'el-check-dropped': {H: r'm_has\("SKIPPED_NOT_AT_EL2"\)'},
    'first-load-no-precedent': {H: r'snapshot-1 load of U2\+0x48, a register no Linux driver reads', R: r"key='FW'"},
    'gcc-offset-drift': {H: r'load of GCC\+0x18284, a register no list names', R: r"key='QS1'"},
    'engine-offset-drift': {H: r'load of U2\+0x6c, a register no list names', R: r"key='FW'"},
    'gic-offset-drift': {H: r'load of GIC\+0x7348, a register no list names', R: r'test_the_gic_words_are_where_the_interrupts_live'},
    'pin-offset-drift': {H: r'TLMM\+0x5b008 read twice in one snapshot', R: r"word='L91'"},
    'window-base-gcc': {H: r'windows\[w\]\.base == M_BASE\[w\]', R: r"window='GCC'"},
    'window-base-gic': {H: r'windows\[w\]\.base == M_BASE\[w\]', R: r"window='GIC'"},
    'window-base-u2': {H: r'windows\[w\]\.base == M_BASE\[w\]', R: r"window='U2'"},
    'window-base-s10': {H: r'windows\[w\]\.base == M_BASE\[w\]', R: r"window='S10'"},
    'window-base-tlmm': {H: r'windows\[w\]\.base == M_BASE\[w\]', R: r"window='TLMM'"},
    'window-swap-engines': {H: r'windows\[w\]\.base == M_BASE\[w\]', R: r"window='U2'"},
    'block-window-swap': {H: r'block_win\[regs\[id\]\.block\] == win'},
    'field-shift-drift': {H: r'U2 S is 0, not 1', R: r"item='S'"},
    'icfgr-width-drift': {H: r'GIC C616 is 4, not 0', R: r'test_the_gic_words_are_where_the_interrupts_live'},
    'hwcg-flag-drift': {H: r'!!\(regs\[id\]\.flags & F_HWCG\) == !!m_in_hwcg\(regs\[id\]\.off\)', R: r"key='MA0'"},
    'hw-gate-needs-no-vote': {H: r'says hardware gating and bit 6 of its vote word GCC\+0x52020 is clear'},
    'hw-unread-vote-counts-as-a-vote': {H: r'says hardware gating and its vote word GCC\+0x52020 was not read'},
    'hw-clear-vote-says-unknown': {H: r'm_line_index\(off, 0\) >= 0 && m_line_index\(err, 0\) < 0 && m_window_loads\(engine, 1\) == 0'},
    'hw-set-vote-says-unknown': {H: r'm_line_index\(off, 0\) < 0 && m_line_index\(err, 0\) < 0 && m_window_loads\(engine, 1\) > 0 && m_window_loads\(other, 1\) > 0'},
    'hw-vote-bit-of-ma0-is-7': {H: r'hw_votes\[k\]\.bit == M_HWVOTE\[k\]\.bit', R: r"clock='G_MA0'"},
    'hw-vote-bit-of-sa0-is-6': {H: r'hw_votes\[k\]\.bit == M_HWVOTE\[k\]\.bit', R: r"clock='G_SA0'"},
    'hw-vote-bit-of-ma1-is-19': {H: r'hw_votes\[k\]\.bit == M_HWVOTE\[k\]\.bit', R: r"clock='G_MA1'"},
    'hw-vote-bit-of-sa1-is-22': {H: r'hw_votes\[k\]\.bit == M_HWVOTE\[k\]\.bit', R: r"clock='G_SA1'"},
    'hw-vote-word-of-ma1-is-vt0': {H: r'regs\[hw_votes\[k\]\.vote\]\.off == M_HWVOTE\[k\]\.vote', R: r"clock='G_MA1'"},
    'hw-vote-word-of-sa1-is-vt2': {H: r'regs\[hw_votes\[k\]\.vote\]\.off == M_HWVOTE\[k\]\.vote', R: r"clock='G_SA1'"},
    'zero-votes-open-the-gate': {H: r'the three vote words read zero, so nothing backs the clock words'},
    'zero-rule-asks-vt0-only': {H: r'm_line_index\("U2 GATED ERR", 0\) < 0 && m_line_index\("S10 GATED ERR", 0\) < 0 && m_window_loads\(M_U2, 1\) > 0'},
    'zero-rule-ignores-vt2': {H: r'm_line_index\("U2 GATED ERR", 0\) < 0 && m_line_index\("S10 GATED ERR", 0\) < 0 && m_window_loads\(M_U2, 1\) > 0'},
    'zero-rule-uses-and': {H: r'page line \d+ is ".*GATED ERR'},
    'zero-rule-counts-unread-votes': {H: r'm_line_index\("U2 GATED ERR", 0\) < 0 && m_window_loads\(M_U2, 1\) > 0'},
    's2-gate-takes-votes-from-snapshot-2': {H: r'm_line_starts\("NEXT S2 U2"\) > 0 && m_window_loads\(M_U2, 2\) == 6 && m_window_loads\(M_U2, 3\) == LOADS_XU2'},
    'late-gate-takes-votes-from-the-gate-snapshot': {H: r'm_line_starts\("NEXT S2 U2"\) > 0 && m_window_loads\(M_U2, 2\) == 6 && m_window_loads\(M_U2, 3\) == LOADS_XU2'},
    'rd32-window-unchecked': {H: r'rd32\(&c, WINDOWS, 0, 0, &value\) == RD_RANGE'},
    'rd32-range-unchecked': {H: r'rd32\(&c, WIN_U2, 0, windows\[WIN_U2\]\.size, &value\) == RD_RANGE'},
    'rd32-alignment-unchecked': {H: r'rd32\(&c, WIN_GCC, 0, 2, &value\) == RD_ALIGN'},
    'read-row-gate-removed': {H: r'c\.s\[0\]\.v\[R_U_FW\]\.st == V_GATED && c\.loads == 0'},
    'emit-cap-off-by-one': {H: r'emit\(&c, &line, 1\) == 0 && c\.cuts == 1'},
}


def stale(mutant, text_of):
    """The edits whose needle does not occur exactly once in the file they name (empty for a good mutant). An edit that follows another one on the same needle is
    counted on the text as the earlier edits leave it, which is the text the mutant is applied to."""
    name, _, edits, _, _ = mutant
    text = dict(text_of)
    found = []
    for f, needle, replacement in edits:
        if text[f].count(needle) != 1:
            found.append((name, f, needle[:50], text[f].count(needle)))
        text[f] = text[f].replace(needle, replacement, 1)
    return found


def write_copy(mutant, directory, root=ROOT):
    """Copies the sources of `root` into `directory` with the mutant's edits applied (none for mutant None); returns the path of inputsnap.c."""
    directory = Path(directory)
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True)
    text = {f: (Path(root) / 'payloads' / f).read_text(encoding='utf-8') for f in SOURCES}
    if mutant is not None:
        bad = stale(mutant, text)
        if bad:
            raise ValueError(f'stale mutant: {bad}')
        for f, needle, replacement in mutant[2]:
            text[f] = text[f].replace(needle, replacement, 1)
    for f in SOURCES:
        (directory / f).write_text(text[f], encoding='utf-8')
    return directory / 'inputsnap.c'


def harness_rejects(source, out_dir, extra=(), root=ROOT):
    """(rejected, why) of the native host test built against `source`, without sanitizers (the shipped suite builds with them); a build failure is an error.
    `why` is the exit status and every FAIL line the test printed (at most 60), so that a reason can be looked for in all of them."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / ('harness' + ''.join(flag.split('=')[-1].strip('u') for flag in extra))
    built = lib.run(['clang', '-std=gnu11', '-O1', '-w', '-DQ1N1_PAYLOAD_HOST_TEST=1', f'-DINPUTSNAP_SRC="{source}"', '-Iplatform/uefi', '-Ipayloads', *extra,
                     '-o', str(binary), str(Path(root) / 'tools' / 'test-q1n1-sp11-payload-inputsnap.c')], cwd=root)
    if built.returncode:
        raise RuntimeError('the host test did not build against the mutant:\n' + built.stderr[-1500:])
    done = lib.run([str(binary)], cwd=root, timeout=300)
    text = (done.stderr or '') + (done.stdout or '')
    fails = [line for line in text.splitlines() if line.startswith('FAIL')][:60]
    return done.returncode != 0, (f'exit status {done.returncode}: ' + (' | '.join(fails) if fails else '(no FAIL line) ' + text[-200:]))[:12000]


def ir_rejects(source, out_dir, root=ROOT):
    problems, _ = audit.provenance(audit.build_ir(source, out_dir, root, extra=('-Wno-error',)))
    return bool(problems), ' | '.join(problems[:6])


def binary_rejects(source, out_dir, root=ROOT):
    done, elf, flat = lib.build_payload(source, out_dir, name='mutant', extra_cflags=('-Wno-error',), root=root)
    if done.returncode:
        return True, f'does not build or link: {done.stderr[-200:]}'
    problems = lib.binary_violations(elf, flat, lib.POLICIES['inputsnap'], 'llvm-readelf')
    return bool(problems), ' | '.join(problems[:6])


def refs_rejects(source, root=ROOT):
    """(rejected, why) of tools/test-q1n1-sp11-payload-inputsnap-refs.py run against the sources of the copy; rejected is None when this tree has no reference
    copies to run it with, so that the check is a SKIP and never a pass."""
    env = dict(lib.ENV, INPUTSNAP_PAYLOAD_DIR=str(Path(source).parent))
    done = subprocess.run(['python3', '-B', str(Path(root) / 'tools' / 'test-q1n1-sp11-payload-inputsnap-refs.py')], cwd=root, env=env, capture_output=True, text=True,
                          timeout=300)
    text = (done.stderr or '') + (done.stdout or '')
    if 'Ran 0 tests' in text and 'skipped' in text:
        return None, 'SKIP: no reference copies'
    lines = [line for line in text.splitlines() if line.startswith(('FAIL:', 'ERROR:', 'AssertionError'))][:12]
    return done.returncode != 0, (' | '.join(lines) if lines else text[-200:])[:3000]


def run_mutant(mutant, work, root=ROOT):
    """{suite: (rejected, detail)} of one mutant (or of the unedited sources for None), working under `work`; rejected is None for a suite that could not run
    (SKIP). `capped` of the mutant (True: a line cap of 6; a string: that build flag) adds `harness-capped`, the host test built with the smaller cap, where a
    failure that needs a cap to show can show."""
    work = Path(work)
    source = write_copy(mutant, work / 'src', root)
    result = {H: harness_rejects(source, work / 'h', root=root), I: ir_rejects(source, work / 'ir', root), B: binary_rejects(source, work / 'bin', root),
              R: refs_rejects(source, root)}
    if mutant is not None and mutant[4]:
        flag = mutant[4] if isinstance(mutant[4], str) else '-DINPUTSNAP_LINE_CAP=6u'
        result['harness-capped'] = harness_rejects(source, work / 'h', extra=(flag,), root=root)
    return result
