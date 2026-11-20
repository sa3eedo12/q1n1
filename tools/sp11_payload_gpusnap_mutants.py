# SPDX-License-Identifier: MIT
"""Seeded bugs for the payload `gpusnap` (docs/SP11-PAYLOAD-GPUSNAP.md, tools/test-q1n1-sp11-payload-gpusnap.py): each one edits a copy of
payloads/gpusnap.c or payloads/gpusnap-regs.h (the needle must occur exactly once: a needle that does not is a stale mutant and an error, not a pass) and
the suites below must reject the copy:

  harness   the native host test (tools/test-q1n1-sp11-payload-gpusnap.c) built against the copy, at the shipped caps and, for the mutants that need it,
            with a smaller line or load cap (`harness-capped`); it fails by exit status (a violation, a check, a signal) and prints its FAIL lines
  ir        the compiled-code audit (tools/sp11_payload_gpusnap_audit.py) of the copy's LLVM IR
  binary    the allow-list and memory check of the linked copy (`gpusnap` policy of tools/sp11_payload_testlib.py, with `read_only`)
  refs      the register table and field positions of the copy against the pinned Linux files (tools/test-q1n1-sp11-payload-gpusnap-refs.py; a SKIP,
            never a pass, in a tree without them)

`expect` is what each mutant must be rejected by; other suites may reject it too. REASONS says in each suite's own words why: a rejection for another
reason (a crash, a build failure, a check that trips by accident) is not a pass. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_gpusnap_audit as audit  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('gpusnap.c', 'gpusnap-regs.h')
H, I, B, R = 'harness', 'ir', 'binary', 'refs'

# (name, what it is, [(file, needle, replacement)], expect, capped): `capped` also builds the harness with a smaller cap where a failure needs one to show:
# True is a line cap of 6 (a NEXT line can fail to print), a string is the build flag to use.
MUTANTS = [
    # ---- nothing but loads, and only of the table -------------------------------------------------------------------------------------------------
    ('store-to-window', 'a store to the device word it just read',
     [('gpusnap.c', "    err = c->load32(phys, &c->word);\n    if (err) {", "    err = c->load32(phys, &c->word);\n    *(volatile uint32_t *)(uintptr_t)phys = 0;\n    if (err) {")],
     {H, I, B}, False),
    ('unguarded-load', 'a plain load of the device word, next to the load32 that is allowed to make it',
     [('gpusnap.c', "    err = c->load32(phys, &c->word);\n    if (err) {", "    err = c->load32(phys, &c->word);\n    c->word = *(volatile uint32_t *)(uintptr_t)phys;\n    if (err) {")],
     {H, I, B}, False),
    ('window-range-unchecked', 'a window number the table does not have is not refused before the table is indexed',
     [('gpusnap.c', "    if (win >= WINDOWS) {\n        rc = RD_RANGE;\n    } else if (off & 3) {\n", "    if (off & 3) {\n")], {H}, False),
    ('store-through-args', 'a store through the arguments the runner passed',
     [('gpusnap.c', "    c.puts = a->ops.puts;\n", "    ((struct q1n1_payload_args *)a)->reserved[0] = 1;\n    c.puts = a->ops.puts;\n")],
     {I, B}, False),
    ('writable-global', 'a counter in a writable global',
     [('gpusnap.c', "OUT_OF_LINE int emit(struct ctx *c, const struct pl_line *line, unsigned kind)\n", "static volatile uint32_t emitted;\nOUT_OF_LINE int emit(struct ctx *c, const struct pl_line *line, unsigned kind)\n"),
      ('gpusnap.c', "    c->lines++;\n    c->puts(line->buf);\n", "    c->lines++;\n    emitted++;\n    c->puts(line->buf);\n")],
     {I, B}, False),
    ('barrier-inserted', 'a data synchronisation barrier before every load',
     [('gpusnap.c', "    c->loads++;\n    err = c->load32(phys, &c->word);", "    c->loads++;\n    __asm__ volatile(\"dsb sy\");\n    err = c->load32(phys, &c->word);")], {B}, False),
    ('smc-inserted', 'a secure monitor call in the entry',
     [('gpusnap.c', "    c.cx = CX_UNK;\n", "    c.cx = CX_UNK;\n    __asm__ volatile(\"smc #0\");\n")], {B}, False),
    ('msr-inserted', 'a write of a PSTATE field',
     [('gpusnap.c', "    c.cx = CX_UNK;\n", "    c.cx = CX_UNK;\n    __asm__ volatile(\"msr daifset, #2\");\n")], {B}, False),
    ('extra-sysreg', 'a third system register read',
     [('gpusnap.c', "    hz = SYSREG(cntfrq_el0);\n", "    hz = SYSREG(cntfrq_el0);\n    (void)SYSREG(MPIDR_EL1);\n")], {H, B}, False),
    ('gx-register-read', 'CX_MISC is moved into the GPU window and its word becomes RBBM_STATUS',
     [('gpusnap-regs.h', "{0x03d9e000u, 0x01000u, 0}", "{0x03d00000u, 0x40000u, 0}"), ('gpusnap-regs.h', 'ROW(WIN_CXMISC, CXM(0x39), D_NONE, 0, "TCMR")', 'ROW(WIN_CXMISC, CXM(0x210), D_NONE, 0, "TCMR")')],
     {H, R}, False),
    ('unlisted-offset', 'the GMU word GMU_CM3_SYSRESET is read at the next dword',
     [('gpusnap-regs.h', 'ROW(WIN_GMU, GMU(0x1f800), D_NONE, F_LATE, "RST")', 'ROW(WIN_GMU, GMU(0x1f801), D_NONE, F_LATE, "RST")')], {H, R}, False),
    # ---- the gates --------------------------------------------------------------------------------------------------------------------------------
    ('ahb-gate-removed', 'GPUCC is read whatever the CFG AHB clock says',
     [('gpusnap.c', "    why = ahb_reason(s);\n    if (why || win == WIN_GPUCC) return why;\n", "    why = win == WIN_GPUCC ? RS_OPEN : ahb_reason(s);\n    if (why || win == WIN_GPUCC) return why;\n")], {H}, False),
    ('cx-gate-removed', 'the blocks behind the CX domain are read whatever the verdict says',
     [('gpusnap.c', "    if (c->cx != CX_ON) return RS_CX_UNK - CX_UNK + c->cx;\n", "")], {H}, False),
    ('cx-gate-ignores-hwctl', 'a CX GDSC under hardware control does not close the gate',
     [('gpusnap.c', "    if (gdscr->v >> GDSC_HW_CONTROL_BIT & 1) return CX_HWCTL;\n", "")], {H}, False),
    ('cx-gate-ignores-swcollapse', 'a CX GDSC under software collapse does not close the gate',
     [('gpusnap.c', "    if ((gdscr->v >> GDSC_SW_COLLAPSE_BIT & 1) || !(status->v >> GDSC_PWR_ON_BIT & 1)) return CX_OFF;",
       "    if (!(status->v >> GDSC_PWR_ON_BIT & 1)) return CX_OFF;")], {H}, False),
    ('cx-gate-ignores-pwr-on', 'a CX GDSC whose status word says off does not close the gate',
     [('gpusnap.c', "    if ((gdscr->v >> GDSC_SW_COLLAPSE_BIT & 1) || !(status->v >> GDSC_PWR_ON_BIT & 1)) return CX_OFF;",
       "    if (gdscr->v >> GDSC_SW_COLLAPSE_BIT & 1) return CX_OFF;")], {H}, False),
    ('cx-gate-needs-one-clock', 'one of the seven clocks running is enough to open the gate',
     [('gpusnap.c', "    return *clk == (1u << GMU_CLOCKS) - 1u ? CX_ON : CX_PART;", "    return *clk ? CX_ON : CX_PART;")], {H}, False),
    ('cx-gate-unknown-is-known', 'a gate input that did not read, or reads as a failed read, is taken as read',
     [('gpusnap.c', "    if (!known) return CX_UNK;\n", "")], {H}, False),
    ('cx-verdict-zero-is-on', 'the zero value of the CX verdict is ON again (a context nobody initialised is open); the explicit initial UNK of the entry is kept',
     [('gpusnap-regs.h', "enum { CX_UNK, CX_OFF, CX_HWCTL, CX_PART, CX_ON, CX_STATES };", "enum { CX_ON, CX_OFF, CX_HWCTL, CX_PART, CX_UNK, CX_STATES };"),
      ('gpusnap-regs.h', '{"UNK", "OFF", "HWCTL", "PART", "ON"}', '{"ON", "OFF", "HWCTL", "PART", "UNK"}'),
      ('gpusnap-regs.h', "enum { RS_OPEN, RS_CX_UNK, RS_CX_OFF, RS_CX_HWCTL, RS_CX_PART, RS_AHB, RS_SMCLK,", "enum { RS_OPEN, RS_AHB, RS_CX_OFF, RS_CX_HWCTL, RS_CX_PART, RS_CX_UNK, RS_SMCLK,"),
      ('gpusnap-regs.h', '{"", "CX=UNK", "CX=OFF", "CX=HWCTL", "CX=PART", "AHB", "SMCLK",', '{"", "AHB", "CX=OFF", "CX=HWCTL", "CX=PART", "CX=UNK", "SMCLK",')], {H}, False),
    ('word-ok-accepts-all-ones', 'a word of all ones counts as a read',
     [('gpusnap.c', "    return v->st == V_OK && v->v != 0xffffffffu;\n", "    return v->st == V_OK;\n")], {H}, False),
    ('clock-ignores-clk-off', 'CLK_OFF set does not stop a clock from counting as running',
     [('gpusnap.c', "    if (!(v->v >> CBCR_CLK_OFF_BIT & 1)) return 1;\n    return (flags & F_HWCG) && (v->v >> CBCR_HW_CTL_BIT & 1);", "    return 1;")], {H}, False),
    ('clock-ignores-enable', 'a clock whose enable bit is clear counts as running when CLK_OFF is clear',
     [('gpusnap.c', "    if (!word_ok(v) || !(v->v >> CBCR_ENABLE_BIT & 1)) return 0;", "    if (!word_ok(v)) return 0;")], {H}, False),
    ('hwcg-exemption-for-all', 'every clock with HW_CTL set counts as running, not only those that have a hardware gating bit',
     [('gpusnap.c', "    return (flags & F_HWCG) && (v->v >> CBCR_HW_CTL_BIT & 1);", "    return v->v >> CBCR_HW_CTL_BIT & 1;")], {H}, False),
    ('nohalt-ignored', 'the halt check of a clock that skips it is judged like the others',
     [('gpusnap.c', "    if (flags & F_NOHALT) return 1;\n", "")], {H}, False),
    ('smmu-clock-gate-removed', 'the SMMU is read without its own four clocks',
     [('gpusnap.c', "    if (win == WIN_SMMU && c->sm_mask != (1u << SMMU_CLOCKS) - 1u) {\n", "    if (0) {\n")], {H}, False),
    ('gated-reason-swapped', 'the reason a block is gated is named after another verdict',
     [('gpusnap-regs.h', '{"", "CX=UNK", "CX=OFF", "CX=HWCTL", "CX=PART", "AHB", "SMCLK", "AHBERR", "SMERR", "NOS2"}',
       '{"", "CX=UNK", "CX=HWCTL", "CX=OFF", "CX=PART", "AHB", "SMCLK", "AHBERR", "SMERR", "NOS2"}')], {H}, False),
    # ---- the page: NEXT lines, the order of the lines, the caps ------------------------------------------------------------------------------------
    ('no-next-line', 'no NEXT line before the CX_MISC block',
     [('gpusnap.c', "        if (!say(c, next.buf, EM_NORMAL)) {\n            c->blocks |= 1u << win;\n            continue;\n        }\n        c->read_mask |= 1u << win;\n",
       "        if (win != WIN_CXMISC && !say(c, next.buf, EM_NORMAL)) {\n            c->blocks |= 1u << win;\n            continue;\n        }\n        c->read_mask |= 1u << win;\n")], {H}, False),
    ('read-without-next', 'a block is read although its NEXT line could not be printed',
     [('gpusnap.c', "        if (!say(c, next.buf, EM_NORMAL)) {\n            c->blocks |= 1u << win;\n            continue;\n        }\n        c->read_mask |= 1u << win;\n",
       "        say(c, next.buf, EM_NORMAL);\n        c->read_mask |= 1u << win;\n")], {H}, True),
    ('block-read-then-printed', 'a block is read whole before its first line is printed',
     [('gpusnap.c', "        for (unsigned li = 0; li < LINES; li++) {\n            if (lines[li].win == win && !lines[li].late) do_line(c, &c->s[0], li, EM_NORMAL);\n        }\n",
       "        for (unsigned id = 0; id < R_COUNT; id++) {\n            if (regs[id].win == win && !(regs[id].flags & F_LATE)) read_row(c, &c->s[0].v[id], id);\n        }\n"
       "        for (unsigned li = 0; li < LINES; li++) {\n            if (lines[li].win == win && !lines[li].late) do_line(c, &c->s[0], li, EM_NORMAL);\n        }\n")], {H}, False),
    ('r4-printed-late', 'the CX verdict is printed after the rest of GPUCC has been read',
     [('gpusnap-regs.h', '{WIN_GPUCC, R_HUB, R_GXGD, A_R4, "GPUCC", 0}', '{WIN_GPUCC, R_HUB, R_GXGD, A_NONE, "GPUCC", 0}'),
      ('gpusnap-regs.h', '{WIN_GPUCC, R_XRC, R_TCMR, A_NONE, "GPUCC", 0}', '{WIN_GPUCC, R_XRC, R_TCMR, A_R4, "GPUCC", 0}')], {H}, False),
    ('retry-after-fault', 'a faulting load is tried again',
     [('gpusnap.c', "    if (err) {\n        c->err = (uint32_t)err;\n        return RD_FAULT;", "    if (err && c->load32(phys, &c->word)) {\n        c->err = (uint32_t)err;\n        return RD_FAULT;")],
     {H}, False),
    ('dead-window-ignored', 'a window that aborted is read on',
     [('gpusnap.c', "        if (rc == RD_FAULT) c->dead |= 1u << win;\n", "        if (rc == RD_FAULT) c->dead |= 0;\n")], {H}, False),
    ('fault-code-lost', 'an abort is printed without the code load32 returned',
     [('gpusnap.c', '        tx(line, "FAULT:");\n        dec(line, v->code);\n', '        tx(line, "FAULT:");\n')], {H}, False),
    ('line-overflow', 'the line cap and the drift budget are gone',
     [('gpusnap.c', "    if (c->lines >= (kind == EM_CLOSING ? LINE_CAP : kind == EM_LATE ? LINE_CAP - 1u : NORMAL_LIMIT)) {", "    if (0) {"),
      ('gpusnap.c', "        unsigned avail = c->lines < NORMAL_LIMIT ? NORMAL_LIMIT - c->lines : 0;", "        unsigned avail = 60;")], {H}, True),
    ('closing-crowded-out', 'the drift lines may take the rows the summary and the end line need',
     [('gpusnap-regs.h', "#define CLOSING_LINES 2u", "#define CLOSING_LINES 0u")], {H}, False),
    ('load-cap-ignored', 'a load past the payload\'s own cap is made',
     [('gpusnap.c', "    if (c->loads >= LOAD_CAP) return RD_BUDGET;\n", "")], {H}, '-DGPUSNAP_LOAD_CAP=30u'),
    ('wait-zero', 'the wait the page announces is not made (the page still says 8 S)',
     [('gpusnap.c', "    waited = delay_ticks(c, (uint64_t)GAP_S * c->hz);", "    waited = delay_ticks(c, 0);")], {H}, False),
    ('unbounded-wait', 'the wait does not give up on a counter that does not run',
     [('gpusnap-regs.h', "#define COUNTER_STUCK_READS 2000000u", "#define COUNTER_STUCK_READS 0xffffffffu")], {H}, False),
    ('backwards-counter-ignored', 'a counter that runs backwards is not noticed (the unsigned difference looks like a long wait)',
     [('gpusnap.c', "        if (now < start) return 0;\n", "")], {H}, False),
    ('spin-bound-too-small', 'the bound on the reads of a counter that moves is below what a slow counter needs',
     [('gpusnap-regs.h', "#define GPUSNAP_SPIN_MAX 0xffffffffu", "#define GPUSNAP_SPIN_MAX 0x300000u")], {H}, False),
    ('spin-bound-removed', 'the wait has no bound on the reads of a counter that moves and never gets there',
     [('gpusnap.c', "        if (++reads >= SPIN_MAX) return 2;\n", "")], {H}, '-DGPUSNAP_SPIN_MAX=3000000u'),
    ('spin-bound-passed-as-success', 'a wait that hit its bound goes on as if the time had passed',
     [('gpusnap.c', "        if (++reads >= SPIN_MAX) return 2;\n", "        if (++reads >= SPIN_MAX) return 1;\n")], {H}, '-DGPUSNAP_SPIN_MAX=3000000u'),
    ('spin-token-reused', 'a bound hit prints the token of a counter that does not run',
     [('gpusnap.c', 'say(c, waited == 2 ? "S2 SKIPPED SPIN" : "S2 SKIPPED NO_COUNTER", EM_NORMAL);', 'say(c, "S2 SKIPPED NO_COUNTER", EM_NORMAL);')], {H}, '-DGPUSNAP_SPIN_MAX=3000000u'),
    # ---- snapshot 2 ----------------------------------------------------------------------------------------------------------------------------------
    ('no-next-gcc', 'no NEXT line before the first block, GCC',
     [('gpusnap.c', "        if (!say(c, next.buf, EM_NORMAL)) {\n            c->blocks |= 1u << win;\n            continue;\n        }\n        c->read_mask |= 1u << win;\n",
       "        if (win != WIN_GCC && !say(c, next.buf, EM_NORMAL)) {\n            c->blocks |= 1u << win;\n            continue;\n        }\n        c->read_mask |= 1u << win;\n")], {H}, False),
    ('no-next-wait', 'the wait is made without a NEXT WAIT line',
     [('gpusnap.c', "    if (!say(c, wait.buf, EM_NORMAL)) return;\n", "")], {H}, False),
    ('no-next-late', 'the late words are read without a NEXT LATE line of their own',
     [('gpusnap.c', "            if (!say(c, next.buf, EM_LATE)) {\n                c->blocks |= 1u << d->win;\n                continue;\n            }\n", "")], {H}, False),
    ('s2-without-next', 'snapshot 2 reads a window without announcing it',
     [('gpusnap.c', "        if (!say(c, next.buf, 0)) continue;\n        pl_begin(&note);\n", "        pl_begin(&note);\n")], {H}, False),
    ('s2-note-dropped', 'snapshot 2 does not say what it found in GCC on the next NEXT line',
     [('gpusnap.c', '        if (note.len) {\n            tx(&next, " ");\n            tx(&next, note.buf);\n        }\n', "")], {H}, False),
    ('s2-gpucc-gate-removed', 'snapshot 2 reads GPUCC again without looking at its own CFG AHB word',
     [('gpusnap.c', "        gated = win == WIN_GPUCC && !row_runs(&c->s[1], R_CFGA);\n", "        gated = 0;\n")], {H}, False),
    ('s2-dead-window-visited', 'snapshot 2 reads a window that aborted in snapshot 1',
     [('gpusnap.c', "    return !(c->dead_s1 >> win & 1) && !(c->s2_skip >> win & 1);\n", "    return !(c->s2_skip >> win & 1);\n")], {H}, False),
    ('s2-reads-the-cx-blocks', 'snapshot 2 reads the blocks behind the CX gate again',
     [('gpusnap.c', "    if (win != WIN_GCC && win != WIN_GPUCC) return 0;\n", ""),
      ('gpusnap.c', "    for (unsigned win = WIN_GCC; win <= WIN_GPUCC; win++) {\n        struct pl_line next;\n", "    for (unsigned win = WIN_GCC; win < WINDOWS; win++) {\n        struct pl_line next;\n")], {H}, False),
    ('drift-counts-skipped-window', 'the drift report compares the values of a window that snapshot 2 did not visit',
     [('gpusnap.c', "    return !(c->dead_s1 >> win & 1) && !(c->s2_skip >> win & 1);\n", "    return !(c->dead_s1 >> win & 1);\n")], {H}, False),
    # ---- the order of a block, the late words and the gates that fail to read -------------------------------------------------------------------------
    ('late-word-first-in-block', 'the RSC block starts with PDC_SEQ_START_ADDR, a word no Linux code reads, and reads it in snapshot 1',
     [('gpusnap-regs.h', '    {WIN_RSCC, R_BSY, R_PDCS, A_NONE, "RSCC", 0},\n    {WIN_RSCC, R_PDCS, R_ID0, A_NONE, "LATE RSCC", 1},\n',
       '    {WIN_RSCC, R_PDCS, R_ID0, A_NONE, "RSCC", 0},\n    {WIN_RSCC, R_BSY, R_PDCS, A_NONE, "RSCC", 0},\n')], {H}, False),
    ('late-words-read-in-snapshot-one', 'the GMU words no Linux code reads are read in snapshot 1, right after the words Linux reads',
     [('gpusnap-regs.h', '{WIN_GMU, R_RST, R_BSY, A_NONE, "LATE GMU", 1}', '{WIN_GMU, R_RST, R_BSY, A_NONE, "GMU", 0}')], {H}, False),
    ('late-before-the-wait', 'the late words are read before snapshot 2 and the drift report',
     [('gpusnap.c', "    snapshot_one(&c);\n    snapshot_two(&c);\n    late_reads(&c);\n", "    snapshot_one(&c);\n    late_reads(&c);\n    snapshot_two(&c);\n")], {H}, False),
    ('late-gate-uses-snapshot-1', 'the late gate judges snapshot 1\'s words, not the fresh ones of snapshot 2',
     [('gpusnap.c', "    why = ahb_reason(&c->s[1]);\n", "    why = ahb_reason(&c->s[0]);\n"), ('gpusnap.c', "    cx = cx_eval(&c->s[1], &clk, &sm);\n", "    cx = cx_eval(&c->s[0], &clk, &sm);\n")], {H}, False),
    ('late-cx-gate-removed', 'the late words are read whatever the CX verdict of snapshot 2 says',
     [('gpusnap.c', "    return cx == CX_ON ? RS_OPEN : RS_CX_UNK - CX_UNK + cx;\n", "    return RS_OPEN;\n")], {H}, False),
    ('late-ahb-gate-removed', 'the late words are read whatever snapshot 2\'s CFG AHB word says',
     [('gpusnap.c', "    why = ahb_reason(&c->s[1]);\n    if (why) return why;\n", "    why = ahb_reason(&c->s[1]);\n")], {H}, False),
    ('late-without-snapshot-2', 'the late gate does not notice that snapshot 2 never ran',
     [('gpusnap.c', "    if (!c->s2_ran) return RS_NO_S2;\n", "")], {H}, False),
    ('late-reads-unread-block', 'the late words of a block that snapshot 1 did not read are read',
     [('gpusnap.c', "        if (!d->late || !(c->read_mask >> d->win & 1)) continue;\n", "        if (!d->late) continue;\n")], {H}, False),
    ('late-lines-crowded-out', 'the ordinary lines may take the rows kept for the late ones',
     [('gpusnap-regs.h', "#define LATE_LINES 4u", "#define LATE_LINES 0u")], {H}, False),
    ('ahb-failed-read-reported-as-off', 'a CFG AHB word that could not be read is reported as a clock that is off',
     [('gpusnap.c', "    return word_ok(&s->v[R_CFGA]) ? RS_AHB : RS_AHB_ERR;\n", "    return RS_AHB;\n")], {H}, False),
    ('smmu-failed-read-reported-as-clock-off', 'an SMMU clock word that could not be read is reported as a clock that is off',
     [('gpusnap.c', "? RS_SMCLK : RS_SM_ERR;\n", "? RS_SMCLK : RS_SMCLK;\n")], {H}, False),
    ('smmu-decode-printed-late', 'the SMMU decode comes after the sCR0, sGFSR and ID7 words instead of right after the ID words',
     [('gpusnap-regs.h', '{WIN_SMMU, R_ID0, R_SCR0, A_SMMU, "SMMU", 0}', '{WIN_SMMU, R_ID0, R_SCR0, A_NONE, "SMMU", 0}'),
      ('gpusnap-regs.h', '{WIN_SMMU, R_SCR0, R_COUNT, A_NONE, "SMMU", 0}', '{WIN_SMMU, R_SCR0, R_COUNT, A_SMMU, "SMMU", 0}')], {H}, False),
    # ---- the register table and the windows: the pinned files -------------------------------------------------------------------------------------------
    ('gcc-offset-drift', 'QMIP is read at the next word of GCC',
     [('gpusnap-regs.h', 'ROW(WIN_GCC, 0x71008, D_CBCR, F_HWCG, "QMIP")', 'ROW(WIN_GCC, 0x7100c, D_CBCR, F_HWCG, "QMIP")')], {H, R}, False),
    ('gpucc-offset-drift', 'the CX GDSC status word is read at the next word of GPUCC',
     [('gpusnap-regs.h', 'ROW(WIN_GPUCC, 0x953c, D_PWR, 0, "CXHW")', 'ROW(WIN_GPUCC, 0x9540, D_PWR, 0, "CXHW")')], {H, R}, False),
    ('rscc-offset-drift', 'SEQ_BUSY_DRV0 is read at the next dword',
     [('gpusnap-regs.h', 'ROW(WIN_RSCC, RSC(0x0101), D_NONE, 0, "BSY")', 'ROW(WIN_RSCC, RSC(0x0102), D_NONE, 0, "BSY")')], {H, R}, False),
    ('tcs-offset-without-seqmem', 'the TCS status words are read without the four dwords of the a740 family',
     [('gpusnap-regs.h', "#define RSC_TCS_SEQMEM_DWORDS 4u", "#define RSC_TCS_SEQMEM_DWORDS 0u")], {H, R}, False),
    ('smmu-offset-drift', 'ID2 is read at ID3',
     [('gpusnap-regs.h', 'ROW(WIN_SMMU, 0x28, D_NONE, 0, "ID2")', 'ROW(WIN_SMMU, 0x2c, D_NONE, 0, "ID2")')], {H, R}, False),
    ('cxmisc-offset-drift', 'TCM_RET_CNTL is read at the next dword',
     [('gpusnap-regs.h', 'ROW(WIN_CXMISC, CXM(0x39), D_NONE, 0, "TCMR")', 'ROW(WIN_CXMISC, CXM(0x3a), D_NONE, 0, "TCMR")')], {H, R}, False),
    ('gcc-window-base-drift', 'the GCC window starts 0x1000 higher',
     [('gpusnap-regs.h', "{0x00100000u, 0x200000u, 0}", "{0x00101000u, 0x200000u, 0}")], {H, R}, False),
    ('gpucc-window-base-drift', 'the GPUCC window starts 0x1000 higher',
     [('gpusnap-regs.h', "{0x03d90000u, 0x0a000u, 0}", "{0x03d91000u, 0x0a000u, 0}")], {H, R}, False),
    ('cxmisc-window-base-drift', 'the CX_MISC window starts 0x1000 higher',
     [('gpusnap-regs.h', "{0x03d9e000u, 0x01000u, 0}", "{0x03d9f000u, 0x01000u, 0}")], {H, R}, False),
    ('gmu-window-base-drift', 'the GMU window starts 0x1000 higher',
     [('gpusnap-regs.h', "{0x03d6a000u, 0x35000u, 0}", "{0x03d6b000u, 0x35000u, 0}")], {H, R}, False),
    ('rscc-window-base-drift', 'the RSC window starts 0x1000 higher',
     [('gpusnap-regs.h', "{0x03d50000u, 0x10000u, 0}", "{0x03d51000u, 0x10000u, 0}")], {H, R}, False),
    ('smmu-window-base-drift', 'the GPU SMMU window starts 0x1000 higher',
     [('gpusnap-regs.h', "{0x03da0000u, 0x40000u, 0}", "{0x03da1000u, 0x40000u, 0}")], {H, R}, False),
    ('gmu-rscc-windows-swapped', 'the GMU and RSC windows are swapped in the window table',
     [('gpusnap-regs.h', "{0x03d6a000u, 0x35000u, 0}, {0x03d50000u, 0x10000u, 0}", "{0x03d50000u, 0x10000u, 0}, {0x03d6a000u, 0x35000u, 0}")], {H, R}, False),
    ('gpucc-cxmisc-windows-swapped', 'the GPUCC and CX_MISC windows are swapped in the window table',
     [('gpusnap-regs.h', "{0x03d90000u, 0x0a000u, 0}, {0x03d9e000u, 0x01000u, 0}", "{0x03d9e000u, 0x01000u, 0}, {0x03d90000u, 0x0a000u, 0}")], {H, R}, False),
    ('cx-gdscr-status-offsets-swapped', 'the CX GDSCR and its status word are read at each other\'s offsets',
     [('gpusnap-regs.h', 'ROW(WIN_GPUCC, 0x9108, D_GDSCR, 0, "CXGD")', 'ROW(WIN_GPUCC, 0x953c, D_GDSCR, 0, "CXGD")'),
      ('gpusnap-regs.h', 'ROW(WIN_GPUCC, 0x953c, D_PWR, 0, "CXHW")', 'ROW(WIN_GPUCC, 0x9108, D_PWR, 0, "CXHW")')], {H, R}, False),
    ('window-names-swapped', 'the page calls the GMU window RSCC and the RSC window GMU',
     [('gpusnap-regs.h', '{"GCC", "GPUCC", "CXMISC", "GMU", "RSCC", "SMMU"}', '{"GCC", "GPUCC", "CXMISC", "RSCC", "GMU", "SMMU"}')], {H}, False),
    ('ahb-gate-reads-wrong-word', 'the CFG AHB gate looks at the GPUCC AHB clock, which is not read until the gate has opened',
     [('gpusnap.c', "    if (row_runs(s, R_CFGA)) return RS_OPEN;\n    return word_ok(&s->v[R_CFGA]) ? RS_AHB : RS_AHB_ERR;\n",
       "    if (row_runs(s, R_AHB)) return RS_OPEN;\n    return word_ok(&s->v[R_AHB]) ? RS_AHB : RS_AHB_ERR;\n")], {H}, False),
    ('gmu-window-offset-drift', 'the GMU window is taken to start 0x1000 higher above the GPU base',
     [('gpusnap-regs.h', "#define GMU_WINDOW_FROM_GPU_BASE 0x6a000u", "#define GMU_WINDOW_FROM_GPU_BASE 0x6b000u")], {H, R}, False),
    ('window-size-drift', 'the GPU SMMU window is 0x3f000 long',
     [('gpusnap-regs.h', "{0x03da0000u, 0x40000u, 0}", "{0x03da0000u, 0x3f000u, 0}")], {R}, False),
    ('gmu-clock-order', 'the axi and memnoc clocks are swapped in the list of the seven',
     [('gpusnap.c', "{R_AHB, R_CGMU, R_CXO, R_AXI, R_MNOC, R_HUB, R_DMT}", "{R_AHB, R_CGMU, R_CXO, R_MNOC, R_AXI, R_HUB, R_DMT}")], {H, R}, False),
    ('smmu-clock-list', 'the SMMU\'s iface clock is taken to be the QMIP clock',
     [('gpusnap.c', "{R_HLOS, R_MNOC, R_SNOC, R_AHB}", "{R_HLOS, R_MNOC, R_QMIP, R_AHB}")], {H, R}, False),
    ('hwcg-flag-dropped', 'memnoc is not known to have a hardware gating bit',
     [('gpusnap-regs.h', 'ROW(WIN_GCC, 0x71010, D_CBCR, F_HWCG, "MNOC")', 'ROW(WIN_GCC, 0x71010, D_CBCR, 0, "MNOC")')], {H, R}, False),
    ('nohalt-flag-dropped', 'the axi clock is not known to skip its halt check',
     [('gpusnap-regs.h', 'ROW(WIN_GCC, 0x7115c, D_NW, F_HWCG | F_NOHALT, "AXI_NW")', 'ROW(WIN_GCC, 0x7115c, D_NW, F_HWCG, "AXI_NW")')], {H, R}, False),
    ('hwcg-flag-on-gpucc', 'a GPUCC clock is taken to have a hardware gating bit',
     [('gpusnap-regs.h', 'ROW(WIN_GPUCC, 0x911c, D_CBCR, 0, "AHB")', 'ROW(WIN_GPUCC, 0x911c, D_CBCR, F_HWCG, "AHB")')], {H, R}, False),
    # ---- bit positions and decodes ---------------------------------------------------------------------------------------------------------------------
    ('cbcr-polarity', 'a set CLK_OFF is printed as .ON',
     [('gpusnap.c', 'cell_is_odd(v->v, flags) ? ".ODD" : v->v >> CBCR_CLK_OFF_BIT & 1 ? ".OFF" : ".ON");', 'cell_is_odd(v->v, flags) ? ".ODD" : v->v >> CBCR_CLK_OFF_BIT & 1 ? ".ON" : ".OFF");')], {H}, False),
    ('rcg-polarity', 'a set ROOT_OFF of a root clock generator\'s command word is printed as .ON',
     [('gpusnap.c', 'v->v == 0xffffffffu ? ".ODD" : v->v >> CBCR_CLK_OFF_BIT & 1 ? ".OFF" : ".ON");', 'v->v == 0xffffffffu ? ".ODD" : v->v >> CBCR_CLK_OFF_BIT & 1 ? ".ON" : ".OFF");')], {H}, False),
    ('pwr-polarity', 'a set PWR_ON is printed as .OFF',
     [('gpusnap.c', ': v->v >> GDSC_PWR_ON_BIT & 1 ? ".ON" : ".OFF");', ': v->v >> GDSC_PWR_ON_BIT & 1 ? ".OFF" : ".ON");')], {H}, False),
    ('gx-state-polarity', 'the GMU\'s GX status bits set are printed as GX on',
     [('gpusnap.c', 'v->v & GXST_OFF_MASK ? "OFF" : "ON");', 'v->v & GXST_OFF_MASK ? "ON" : "OFF");')], {H}, False),
    ('gx-state-mask', 'only bit 0 of the GMU\'s GX status word is taken',
     [('gpusnap-regs.h', "#define GXST_OFF_MASK 3u", "#define GXST_OFF_MASK 1u")], {H, R}, False),
    ('tcs-polarity', 'a TCS word with bit 0 set is counted as busy',
     [('gpusnap.c', "(t->v & 1u) << i", "(~t->v & 1u) << i")], {H}, False),
    ('tcs-all-ones-idle', 'ten TCS words of all ones (a failed read) print as ten idle TCSs',
     [('gpusnap.c', "        odd |= t->st == V_OK && t->v == 0xffffffffu;\n", "")], {H}, False),
    ('all-ones-clock-decoded', 'a clock word of all ones (a failed read) is decoded as .OFF',
     [('gpusnap.c', "    if (w == 0xffffffffu) return 1;\n    if (!(w >> CBCR_CLK_OFF_BIT & 1)) return !(w >> CBCR_ENABLE_BIT & 1);\n",
       "    if (!(w >> CBCR_CLK_OFF_BIT & 1)) return !(w >> CBCR_ENABLE_BIT & 1);\n")], {H}, False),
    ('enable-clear-decoded-as-on', 'a clock word with CLK_OFF clear and CLK_ENABLE clear (a window of zeros) is decoded as .ON',
     [('gpusnap.c', "    if (!(w >> CBCR_CLK_OFF_BIT & 1)) return !(w >> CBCR_ENABLE_BIT & 1);\n", "    if (!(w >> CBCR_CLK_OFF_BIT & 1)) return 0;\n")], {H}, False),
    ('all-ones-gdsc-decoded', 'a GDSC status word of all ones (a failed read) is decoded as .ON',
     [('gpusnap.c', 'tx(line, v->v == 0xffffffffu ? ".ODD" : v->v >> GDSC_PWR_ON_BIT', 'tx(line, v->v >> GDSC_PWR_ON_BIT')], {H}, False),
    ('hwcg-clk-off-decoded', 'CLK_OFF with HW_CTL set on a hardware gated clock is decoded as .OFF',
     [('gpusnap.c', "    if ((flags & F_HWCG) && (w >> CBCR_HW_CTL_BIT & 1)) return 1;\n", "")], {H}, False),
    ('fsm-on-clk-off-decoded', 'CLK_OFF with an NoC FSM status of ON is decoded as .OFF',
     [('gpusnap.c', "    return (w >> CBCR_FSM_SHIFT & CBCR_FSM_MASK) == CBCR_FSM_ON;\n", "    return 0;\n")], {H}, False),
    ('rcg-command-word-judged-as-a-branch', 'the command word of a root clock generator is judged by the modes of a branch clock (an FSM status field it does not have)',
     [('gpusnap-regs.h', 'ROW(WIN_GPUCC, 0x9318, D_RCGCMD, 0, "GRC")', 'ROW(WIN_GPUCC, 0x9318, D_CBCR, 0, "GRC")')], {H}, False),
    ('all-ones-field-decoded', 'a bit field cut from a word of all ones (a failed read) is printed as a field',
     [('gpusnap.c', '    if (v->st == V_OK && v->v == 0xffffffffu) tx(&item, "ODD");\n    else side(c, &item, &field, D_NONE, 0);\n', '    side(c, &item, &field, D_NONE, 0);\n')], {H}, False),
    ('gx-reserved-bits-trusted', 'a GMU GX status word with bits above 1 set is read as GX on or off',
     [('gpusnap.c', 'tx(&item, v->v & ~GXST_OFF_MASK ? "ODD" : v->v & GXST_OFF_MASK', 'tx(&item, v->v & GXST_OFF_MASK')], {H}, False),
    ('cbcr-clk-off-bit', 'CLK_OFF is taken from bit 30',
     [('gpusnap-regs.h', "#define CBCR_CLK_OFF_BIT 31u", "#define CBCR_CLK_OFF_BIT 30u")], {H, R}, False),
    ('cbcr-enable-bit', 'CLK_ENABLE is taken from bit 1',
     [('gpusnap-regs.h', "#define CBCR_ENABLE_BIT 0u", "#define CBCR_ENABLE_BIT 1u")], {H, R}, False),
    ('gdsc-pwr-on-bit', 'PWR_ON is taken from bit 30',
     [('gpusnap-regs.h', "#define GDSC_PWR_ON_BIT 31u", "#define GDSC_PWR_ON_BIT 30u")], {H, R}, False),
    ('gdsc-sw-collapse-bit', 'SW_COLLAPSE is taken from bit 2',
     [('gpusnap-regs.h', "#define GDSC_SW_COLLAPSE_BIT 0u", "#define GDSC_SW_COLLAPSE_BIT 2u")], {H, R}, False),
    ('gdsc-hw-control-bit', 'HW_CONTROL is taken from bit 2',
     [('gpusnap-regs.h', "#define GDSC_HW_CONTROL_BIT 1u", "#define GDSC_HW_CONTROL_BIT 2u")], {H, R}, False),
    ('vote-bit-drift', 'the CPH vote is taken from bit 14',
     [('gpusnap-regs.h', "#define VOTE_CPH_BIT 15u", "#define VOTE_CPH_BIT 14u")], {H, R}, False),
    ('rcg-source-shift', 'the RCG source select is taken from bit 9',
     [('gpusnap-regs.h', "#define RCG_SRC_SHIFT 8u", "#define RCG_SRC_SHIFT 9u")], {H, R}, False),
    ('smmu-ubs-shift', 'UBS is taken from bit 12 of ID2',
     [('gpusnap-regs.h', "#define SMMU_ID2_UBS_SHIFT 8u", "#define SMMU_ID2_UBS_SHIFT 12u")], {H, R}, False),
]

# What each suite must say about each mutant, a regular expression over the suite's own words: a mutant that is rejected for another reason (a crash, a
# build failure, a different check that happens to trip) is not a pass. `harness-capped` stands for the harness built with the smaller cap `capped` names.
def _own_stack(function):
    return rf"a store in {function} at 0x[0-9a-f]+ \(.*\) whose base x\d+ is not provably the payload.s own stack"


def _offset(key):
    return rf"test_every_offset_of_the_table_is_the_pinned_files .*\(key='{key}'\)"


def _field(name):
    return rf"test_the_bit_positions_of_the_code_are_the_pinned_macros .*\(field='{name}'\)"


def _window(name):
    return rf"test_the_windows_are_those_of_the_device_tree .*\(window='{name}'\)"


def _inside(key, window):
    return rf"test_every_row_lies_inside_its_window_and_in_the_block_it_names .*\(key='{key}', window='{window}'\)"


_NODE_CLOCKS = r'test_the_gate_inputs_are_the_clocks_of_the_two_device_tree_nodes_in_their_order'
_FLAGS = r'test_the_hardware_gating_and_skipped_halt_flags_are_the_pinned_clock_structs .*\(key=\'%s\'\)'
_NOT_PRINTED = 'no page line starts with'

REASONS = {
    # ---- nothing but loads, and only of the table
    'store-to-window': {H: r'an access reached a device window without load32', I: r'integer-to-pointer conversions: this payload turns no number into a pointer',
                        B: _own_stack('load')},
    'unguarded-load': {H: r'an access reached a device window without load32', I: r'load has 1 integer-to-pointer conversions: this payload turns no number into a pointer',
                       B: r'a load in load at 0x[0-9a-f]+ \(ldr w\d+, \[x\d+\]\) whose base x\d+ is not provably the stack'},
    'window-range-unchecked': {H: r'rd32\(&c, BAD\[i\], 1, &w\) == RD_RANGE'},
    'store-through-args': {I: r'stores through the arguments the runner passed', B: _own_stack('payload_entry')},
    'writable-global': {I: r'@emitted is a writable global', B: r'no writable globals'},
    'barrier-inserted': {B: r'forbidden instruction dsb'},
    'smc-inserted': {B: r'1 smc instructions, the policy allows 0'},
    'msr-inserted': {B: r'forbidden instruction msr'},
    'extra-sysreg': {H: r'a system register read: MPIDR_EL1', B: r"registers read \['cntfrq_el0', 'currentel', 'mpidr_el1'\]"},
    'gx-register-read': {H: r'a GX register \(the GPU window: RBBM, CP\)', R: r'test_the_gpu_window_and_the_blocks_the_payload_does_not_name_are_never_read'},
    'unlisted-offset': {H: r'load of 0x3d7e004, a register no list names', R: _offset('RST')},
    # ---- the gates
    'ahb-gate-removed': {H: r'load of GPUCC CXGD behind a closed gate'},
    'cx-gate-removed': {H: r'load of CXMISC TCMR behind a closed gate'},
    'cx-gate-ignores-hwctl': {H: rf'CX GDSCR HW_CONTROL set: {_NOT_PRINTED} "R4 CX=HWCTL"'},
    'cx-gate-ignores-swcollapse': {H: r'CX GDSCR SW_COLLAPSE set under PWR_ON \(on only by another vote\)'},
    'cx-gate-ignores-pwr-on': {H: rf'CX status PWR_ON clear: {_NOT_PRINTED} "R4 CX=OFF PWR=0"'},
    'cx-gate-needs-one-clock': {H: rf'gpucc ahb off: {_NOT_PRINTED} "R4 CX=PART'},
    'cx-gate-unknown-is-known': {H: rf'CX GDSCR a failed read: {_NOT_PRINTED} "R4 CX=UNK"'},
    'cx-verdict-zero-is-on': {H: r'c\.cx == CX_UNK && !strcmp\(cx_name\[c\.cx\], "UNK"\)'},
    'word-ok-accepts-all-ones': {H: rf'failed read: {_NOT_PRINTED} "R4 CX=UNK"'},
    'clock-ignores-clk-off': {H: rf'AHB CLK_OFF set: {_NOT_PRINTED} "GPUCC GATED BY AHB"'},
    'clock-ignores-enable': {H: rf'AHB not enabled: {_NOT_PRINTED} "GPUCC GATED BY AHB"'},
    'hwcg-exemption-for-all': {H: r'AHB CLK_OFF set and HW_CTL set: CFGA has no hardware gating bit in Linux'},
    'nohalt-ignored': {H: r'axi enabled with CLK_OFF set: Linux does not check it \(BRANCH_HALT_SKIP\)'},
    'smmu-clock-gate-removed': {H: r'load of SMMU ID0 behind a closed gate'},
    'gated-reason-swapped': {H: r'CXMISC GATED BY CX=HWCTL", not "PAYLOAD GPUSNAP CXMISC GATED BY CX=OFF"'},
    'no-next-line': {H: r'load of CXMISC TCMR without `NEXT CXMISC` as the last line'},
    'no-next-gcc': {H: r'load of GCC CFGA without `NEXT GCC` as the last line'},
    'no-next-wait': {H: r'the wait starts without `NEXT WAIT` as the last line'},
    'no-next-late': {H: r'load of GMU RST, a word no Linux code reads, outside the late phase'},
    'read-without-next': {'harness-capped': r'load of GCC CFGA without `NEXT GCC` as the last line'},
    'block-read-then-printed': {H: r'load of GCC QMIP \(line 1\) before the line 0 was printed'},
    'r4-printed-late': {H: r'GPUCC GXGD=0X222001 GXCF=0X8000 UP=0 DN=1", not "PAYLOAD GPUSNAP R4 CX=ON'},
    'retry-after-fault': {H: r'load of GCC CFGA after an abort in that window'},
    'dead-window-ignored': {H: r'load of GCC QMIP after an abort in that window'},
    'fault-code-lost': {H: r'm_has\(want\)'},
    'line-overflow': {H: r"more lines than the payload's cap", 'harness-capped': r"more lines than the payload's cap"},
    'closing-crowded-out': {H: r'm_has\("DRIFT CHANGED=16 LOST=0 CMP=26 MORE=12"\) && m_has\("DG SNOC="\)'},
    'load-cap-ignored': {'harness-capped': r"more loads than the payload's cap"},
    'wait-zero': {H: r'GAP_MS=30 LINES=33", not "PAYLOAD GPUSNAP END LOADS=78 .*GAP_MS=8020'},
    'unbounded-wait': {H: r'the counter was read \d+ times: an unbounded wait'},
    'backwards-counter-ignored': {H: r'm_has\("S2 SKIPPED NO_COUNTER"\) && m_loads_in\(2\) == 0'},
    'spin-bound-too-small': {H: r'SPIN_MAX >= 0x40000000u && !m_has\("SKIPPED"\) && m_loads_in\(2\) == LOADS_S2'},
    'spin-bound-removed': {'harness-capped': r'the counter was read \d+ times: an unbounded wait'},
    'spin-bound-passed-as-success': {'harness-capped': r'm_has\("S2 SKIPPED SPIN"\) && !m_has\("S2 SKIPPED NO_COUNTER"\) && m_end_field\("GAP_MS"\) == 0'},
    'spin-token-reused': {'harness-capped': r'SPIN_MAX < 3840000u && m_has\("S2 SKIPPED SPIN"\) && !m_has\("S2 SKIPPED NO_COUNTER"\)'},
    'gcc-offset-drift': {H: r'load of 0x17100c, a register no list names', R: _offset('QMIP')},
    # ---- snapshot 2
    's2-without-next': {H: r'snapshot-2 load of GCC CFGA without `NEXT S2 GCC` as the last line'},
    's2-note-dropped': {H: r'"PAYLOAD GPUSNAP NEXT S2 GPUCC", not "PAYLOAD GPUSNAP NEXT S2 GPUCC GCC=SAME"'},
    's2-gpucc-gate-removed': {H: r'snapshot-2 load of GPUCC CXGD behind a CFG AHB word that does not run'},
    's2-dead-window-visited': {H: r'm_line_starts\(want\) < 0'},
    's2-reads-the-cx-blocks': {H: r'snapshot-2 load of CXMISC TCMR: only GCC and GPUCC are read again'},
    'drift-counts-skipped-window': {H: r'm_has\("S2 GPUCC SKIP GATED GCC=CHG:1"\)'},
    # ---- the order of a block, the late words and the gates that fail to read
    'late-word-first-in-block': {H: r'load of RSCC PDCS, a word no Linux code reads, outside the late phase'},
    'late-words-read-in-snapshot-one': {H: r'load of GMU RST, a word no Linux code reads, outside the late phase'},
    'late-before-the-wait': {H: r'page line 24 is "PAYLOAD GPUSNAP LATE GMU GATED BY NOS2", not "PAYLOAD GPUSNAP NEXT WAIT 8 S"'},
    'late-gate-uses-snapshot-1': {H: r'late load of GMU RST behind a state the harness holds closed'},
    'late-cx-gate-removed': {H: r'late load of GMU RST behind a state the harness holds closed'},
    'late-ahb-gate-removed': {H: r'm_loads_in\(3\) == 0 && m_line_starts\("LATE GMU GATED BY AHB"\) >= 0 && m_line_starts\("LATE RSCC GATED BY AHB"\) >= 0'},
    'late-without-snapshot-2': {H: r'm_has\("S2 SKIPPED NO_COUNTER"\) && m_loads_in\(3\) == 0 && m_line_starts\("LATE GMU GATED BY NOS2"\) >= 0'},
    'late-reads-unread-block': {H: r'page line 22 is "PAYLOAD GPUSNAP LATE GMU GATED BY CX=OFF", not "PAYLOAD GPUSNAP END LOADS=52'},
    'late-lines-crowded-out': {H: r'm_has\("DRIFT CHANGED=16 LOST=0 CMP=26 MORE=12"\) && m_has\("DG SNOC="\)'},
    'ahb-failed-read-reported-as-off': {H: r"AHB a failed read: not 'the clock is off': no page line starts with \"GPUCC GATED BY AHBERR\""},
    'smmu-failed-read-reported-as-clock-off': {H: r"snoc dvm clock a failed read: not 'the clock is off': no page line starts with \"SMMU GATED BY SMERR\""},
    'smmu-decode-printed-late': {H: r'page line 22 is "PAYLOAD GPUSNAP SMMU SCR0=0X230406 GFSR=0 ID7=0X21", not "PAYLOAD GPUSNAP SMMU SMRG=0X9A'},
    # ---- the register table and the windows: the pinned files
    'gpucc-offset-drift': {H: r'load of 0x3d99540, a register no list names', R: _offset('CXHW')},
    'rscc-offset-drift': {H: r'load of 0x3d50408, a register no list names', R: _offset('BSY')},
    'tcs-offset-without-seqmem': {H: r'load of 0x3d50d18, a register no list names', R: _offset('T0')},
    'smmu-offset-drift': {H: r'load of 0x3da002c, a register no list names', R: _offset('ID2')},
    'cxmisc-offset-drift': {H: r'load of 0x3d9e0e8, a register no list names', R: _offset('TCMR')},
    'gmu-window-offset-drift': {H: r'load of 0x3d7d340, a register no list names', R: _offset('RST')},
    'gcc-window-base-drift': {H: r'load of 0x172004, a register no list names', R: _window('GCC')},
    'gpucc-window-base-drift': {H: r'load of 0x3d9a108, a register no list names', R: _window('GPUCC')},
    'cxmisc-window-base-drift': {H: r'load of 0x3d9f0e4, a register no list names', R: _window('CXMISC')},
    'gmu-window-base-drift': {H: r'load of 0x3d7f340, a register no list names', R: _window('GMU')},
    'rscc-window-base-drift': {H: r'load of 0x3d51404, a register no list names', R: _window('RSCC')},
    'smmu-window-base-drift': {H: r'load of 0x3da1020, a register no list names', R: _window('SMMU')},
    'gmu-rscc-windows-swapped': {H: r'load of 0x3d6a404, a register no list names', R: _inside('GXST', 'GMU')},
    'gpucc-cxmisc-windows-swapped': {H: r'page line 6 is "PAYLOAD GPUSNAP GPUCC CXGD=NA SC=NA HW=NA CXHW=NA", not "PAYLOAD GPUSNAP GPUCC CXGD=0X8022F000', R: _inside('CXGD', 'GPUCC')},
    'cx-gdscr-status-offsets-swapped': {H: r'page line 6 is "PAYLOAD GPUSNAP GPUCC CXGD=0X80000000 SC=0 HW=0 CXHW=0X8022F000.ON", not "PAYLOAD GPUSNAP GPUCC CXGD=0X8022F000', R: _offset('CXGD')},
    'window-names-swapped': {H: r'load of GMU GXST without `NEXT GMU` as the last line'},
    'ahb-gate-reads-wrong-word': {H: r'page line 5 is "PAYLOAD GPUSNAP GPUCC GATED BY AHBERR", not "PAYLOAD GPUSNAP NEXT GPUCC"'},
    'window-size-drift': {R: _window('SMMU')},
    'gmu-clock-order': {H: r'axi not enabled \(its CLK_OFF is no witness\): no page line starts with "R4 CX=PART PWR=1 SC=0 HW=0 CLK=0X77"', R: _NODE_CLOCKS},
    'smmu-clock-list': {H: r'snoc dvm clock off \(not one of the seven\)', R: _NODE_CLOCKS},
    'hwcg-flag-dropped': {H: r'memnoc CLK_OFF set under hardware gating \(bit 1\): Linux does not judge it', R: _FLAGS % 'MNOC'},
    'nohalt-flag-dropped': {H: r'axi enabled with CLK_OFF set: Linux does not check it \(BRANCH_HALT_SKIP\)', R: _FLAGS % 'AXI_NW'},
    'hwcg-flag-on-gpucc': {H: r'gpucc ahb enabled, CLK_OFF set, bit 1 set: this clock has no hardware gating bit', R: _FLAGS % 'AHB'},
    # ---- bit positions and decodes
    'cbcr-polarity': {H: r'page line 3 is "PAYLOAD GPUSNAP GCC CFGA=1.OFF MNOC=3.OFF AXI_NW=3 SNOC=1.OFF", not "PAYLOAD GPUSNAP GCC CFGA=1.ON'},
    'rcg-polarity': {H: r'page line 12 is "PAYLOAD GPUSNAP GPUCC GRC=2\.OFF GRF=0 S=0 HRC=0X80000000\.ON HRF=0X100 S=1", not "PAYLOAD GPUSNAP GPUCC GRC=2\.ON'},
    'pwr-polarity': {H: r'CXHW=0X80000000.OFF", not'},
    'gx-state-polarity': {H: r'page line 17 is "PAYLOAD GPUSNAP GMU GXST=3 GX=ON INIT=0 FENS=0", not "PAYLOAD GPUSNAP GMU GXST=3 GX=OFF INIT=0 FENS=0"'},
    'gx-state-mask': {H: r'm_has\(GX\[i\]\.want\):  GX=OFF', R: _field('GXST_OFF_MASK')},
    'gx-reserved-bits-trusted': {H: r'm_has\(GX\[i\]\.want\):  GX=ODD'},
    'tcs-polarity': {H: r'page line 19 is "PAYLOAD GPUSNAP RSCC BSY=0 ST0=0 TCS=0", not "PAYLOAD GPUSNAP RSCC BSY=0 ST0=0 TCS=0X3FF"'},
    'tcs-all-ones-idle': {H: r'm_has\(" TCS=ODD"\) && !m_has\("TCS=0X3FF"\)'},
    'all-ones-clock-decoded': {H: r'm_has\(ODD\[i\]\.want\):  CFGA=0XFFFFFFFF\.ODD'},
    'enable-clear-decoded-as-on': {H: r'm_has\(ODD\[i\]\.want\):  CFGA=0\.ODD'},
    'all-ones-gdsc-decoded': {H: r'm_has\(ODD\[i\]\.want\):  CXHW=0XFFFFFFFF\.ODD'},
    'hwcg-clk-off-decoded': {H: r'm_has\(ODD\[i\]\.want\):  MNOC=0X80000003\.ODD'},
    'fsm-on-clk-off-decoded': {H: r'm_has\(ODD\[i\]\.want\):  AHB=0XA0000001\.ODD'},
    'rcg-command-word-judged-as-a-branch': {H: r'm_has\(ODD\[i\]\.want\):  GRC=0XA0000000\.OFF'},
    'all-ones-field-decoded': {H: r'm_has\(ODD\[i\]\.want\):  CXGD=0XFFFFFFFF SC=ODD HW=ODD'},
    'cbcr-clk-off-bit': {H: r'GXGM=0X80000000.ODD", not', R: _field('CBCR_CLK_OFF_BIT')},
    'cbcr-enable-bit': {H: r'm_nlines == sizeof GOLDEN_ON', R: _field('CBCR_ENABLE_BIT')},
    'gdsc-pwr-on-bit': {H: r'm_nlines == sizeof GOLDEN_ON', R: _field('GDSC_PWR_ON_BIT')},
    'gdsc-sw-collapse-bit': {H: r'CXGD=0X222001 SC=0 HW=0 CXHW=0.OFF", not "PAYLOAD GPUSNAP GPUCC CXGD=0X222001 SC=1', R: _field('GDSC_SW_COLLAPSE_BIT')},
    'gdsc-hw-control-bit': {H: rf'CX GDSCR HW_CONTROL set: {_NOT_PRINTED} "R4 CX=HWCTL"', R: _field('GDSC_HW_CONTROL_BIT')},
    'vote-bit-drift': {H: r'page line 4 is "PAYLOAD GPUSNAP GCC QMIP=3.ON VOTE=0X18001 CPH=0 DIV=1 GP0V=1", not', R: _field('VOTE_CPH_BIT')},
    'rcg-source-shift': {H: r'HRF=0X100 S=0", not', R: _field('RCG_SRC_SHIFT')},
    'smmu-ubs-shift': {H: r'IAS=2 OAS=2 UBS=5", not', R: _field('SMMU_ID2_UBS_SHIFT')},
}


def stale(mutant, text_of):
    """The edits whose needle does not occur exactly once in the file they name (empty for a good mutant)."""
    name, _, edits, _, _ = mutant
    return [(name, f, needle[:50], text_of[f].count(needle)) for f, needle, _ in edits if text_of[f].count(needle) != 1]


def write_copy(mutant, directory, root=ROOT):
    """Copies the sources of `root` into `directory` with the mutant's edits applied (none for mutant None); returns the path of gpusnap.c."""
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
    return directory / 'gpusnap.c'


def harness_rejects(source, out_dir, extra=(), root=ROOT):
    """(rejected, why) of the native host test built against `source`, without sanitizers (the shipped suite builds with them); a build failure is an error.
    `why` is the exit status and every FAIL line the test printed (at most 60), so that a reason can be looked for in all of them."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / ('harness' + ''.join(flag.split('=')[-1].strip('u') for flag in extra))
    built = lib.run(['clang', '-std=gnu11', '-O1', '-w', '-DQ1N1_PAYLOAD_HOST_TEST=1', f'-DGPUSNAP_SRC="{source}"', '-Iplatform/uefi', '-Ipayloads', *extra,
                     '-o', str(binary), str(Path(root) / 'tools' / 'test-q1n1-sp11-payload-gpusnap.c')], cwd=root)
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
    problems = lib.binary_violations(elf, flat, lib.POLICIES['gpusnap'], 'llvm-readelf')
    return bool(problems), ' | '.join(problems[:6])


def refs_rejects(source, root=ROOT):
    """(rejected, why) of tools/test-q1n1-sp11-payload-gpusnap-refs.py run against the sources of the copy; rejected is None when this tree has no reference
    copies to run it with, so that the check is a SKIP and never a pass."""
    env = dict(lib.ENV, GPUSNAP_PAYLOAD_DIR=str(Path(source).parent))
    done = subprocess.run(['python3', '-B', str(Path(root) / 'tools' / 'test-q1n1-sp11-payload-gpusnap-refs.py')], cwd=root, env=env, capture_output=True, text=True,
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
        flag = mutant[4] if isinstance(mutant[4], str) else '-DGPUSNAP_LINE_CAP=6u'
        result['harness-capped'] = harness_rejects(source, work / 'h', extra=(flag,), root=root)
    return result
