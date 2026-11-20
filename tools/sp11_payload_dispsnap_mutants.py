# SPDX-License-Identifier: MIT
"""Seeded bugs for the payload `dispsnap` (docs/SP11-PAYLOAD-DISPSNAP.md, tools/test-q1n1-sp11-payload-dispsnap.py): each one edits a copy of
payloads/dispsnap.c or payloads/dispsnap-regs.h (the needle must occur exactly once: a needle that does not is a stale mutant and an error, not a pass) and
the suites below must reject the copy:

  harness   the native host test (tools/test-q1n1-sp11-payload-dispsnap.c) built against the copy, at the shipped caps and, for the mutants that need it,
            with a smaller line or load cap (`harness-capped`); it fails by exit status (a violation, a check, a signal) and prints its FAIL lines
  ir        the compiled-code audit (tools/sp11_payload_dispsnap_audit.py) of the copy's LLVM IR
  binary    the allow-list and memory check of the linked copy (`dispsnap` policy of tools/sp11_payload_testlib.py, with `read_only`)
  refs      the register table and field positions of the copy against the pinned Linux files (tools/test-q1n1-sp11-payload-dispsnap-refs.py; a SKIP,
            never a pass, in a tree without them)

`expect` is what each mutant must be rejected by; other suites may reject it too. REASONS says in each suite's own words why: a rejection for another
reason (a crash, a build failure, a check that trips by accident) is not a pass. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only)."""
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sp11_payload_testlib as lib  # noqa: E402
import sp11_payload_dispsnap_audit as audit  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('dispsnap.c', 'dispsnap-regs.h')
H, I, B, R = 'harness', 'ir', 'binary', 'refs'
C, G = 'dispsnap.c', 'dispsnap-regs.h'
NEXT_S1 = "        /* No NEXT line, no read: what hangs must be named. */\n        if (!say(c, next.buf, EM_NORMAL)) {"
NEXT_S2 = "        /* No NEXT line, no read, as in snapshot 1. */\n        if (!say(c, next.buf, EM_NORMAL)) {"
SPIN = '-DDISPSNAP_SPIN_MAX=3000000u'

# (name, what it is, [(file, needle, replacement)], expect, capped): `capped` also builds the harness with a smaller cap where a failure needs one to show:
# True is a line cap of 6 (a NEXT line can fail to print), a string is the build flag to use.
MUTANTS = [
    # ---- nothing but loads, and only of the table -------------------------------------------------------------------------------------------------
    ('store-to-window', 'a store to the device word it just read',
     [(C, "    err = c->load32(phys, &c->word);\n    if (err) {", "    err = c->load32(phys, &c->word);\n    *(volatile uint32_t *)(uintptr_t)phys = 0;\n    if (err) {")],
     {H, I, B}, False),
    ('unguarded-load', 'a plain load of the device word, next to the load32 that is allowed to make it',
     [(C, "    err = c->load32(phys, &c->word);\n    if (err) {", "    err = c->load32(phys, &c->word);\n    c->word = *(volatile uint32_t *)(uintptr_t)phys;\n    if (err) {")],
     {H, I, B}, False),
    ('store-to-framebuffer', 'a store to the framebuffer the page is drawn in (the scanout), through the address the arguments carry',
     [(C, "    c.puts = a->ops.puts;\n", "    *(volatile uint32_t *)(uintptr_t)a->fb_base = 0;\n    c.puts = a->ops.puts;\n")], {H, I, B}, False),
    ('framebuffer-read', 'a read of the first word of the framebuffer, through the address the arguments carry',
     [(C, "    c.puts = a->ops.puts;\n", "    c.word = *(volatile uint32_t *)(uintptr_t)a->fb_base;\n    c.puts = a->ops.puts;\n")], {H, I}, False),
    ('window-range-unchecked', 'a window number the table does not have is not refused before the table is indexed',
     [(C, "    if (win >= WINDOWS) {\n        rc = RD_RANGE;\n    } else if (off & 3) {\n", "    if (off & 3) {\n")], {H}, False),
    ('store-through-args', 'a store through the arguments the runner passed',
     [(C, "    c.puts = a->ops.puts;\n", "    ((struct q1n1_payload_args *)a)->reserved[0] = 1;\n    c.puts = a->ops.puts;\n")], {I, B}, False),
    ('writable-global', 'a counter in a writable global',
     [(C, "OUT_OF_LINE int emit(struct ctx *c, const struct pl_line *line, unsigned kind)\n",
       "static volatile uint32_t emitted;\nOUT_OF_LINE int emit(struct ctx *c, const struct pl_line *line, unsigned kind)\n"),
      (C, "    c->lines++;\n    c->puts(line->buf);\n", "    c->lines++;\n    emitted++;\n    c->puts(line->buf);\n")], {I, B}, False),
    ('barrier-inserted', 'a data synchronisation barrier before every load',
     [(C, "    c->loads++;\n    err = c->load32(phys, &c->word);", "    c->loads++;\n    __asm__ volatile(\"dsb sy\");\n    err = c->load32(phys, &c->word);")], {B}, False),
    ('smc-inserted', 'a secure monitor call in the entry', [(C, "    c.disp = DX_UNK;\n", "    c.disp = DX_UNK;\n    __asm__ volatile(\"smc #0\");\n")], {B}, False),
    ('msr-inserted', 'a write of a PSTATE field', [(C, "    c.disp = DX_UNK;\n", "    c.disp = DX_UNK;\n    __asm__ volatile(\"msr daifset, #2\");\n")], {B}, False),
    ('extra-sysreg', 'a third system register read', [(C, "    hz = SYSREG(cntfrq_el0);\n", "    hz = SYSREG(cntfrq_el0);\n    (void)SYSREG(MPIDR_EL1);\n")], {H, B}, False),
    ('far-offset-read', 'the frame counter\'s enable is read 0x500 into the interface\'s page, which is in no list (inside the DPU window, past INTF_5\'s 0x280 bytes)',
     [(G, "#define INTF_FRAME_LINE_COUNT_EN 0x0a8u", "#define INTF_FRAME_LINE_COUNT_EN 0x500u")], {H, R}, False),
    ('line-counter-in-place-of-frame-counter', 'the interface\'s line counter is read in place of the frame counter',
     [(G, "#define INTF_FRAME_COUNT 0x0acu", "#define INTF_FRAME_COUNT 0x0b0u")], {H, R}, False),
    # ---- the gates --------------------------------------------------------------------------------------------------------------------------------
    ('display-register-clock-gate-removed', 'DISPCC is read whatever the display register clock says',
     [(C, "    why = ahb_reason(s);\n    if (why || win == WIN_DISPCC) return why;\n", "    why = 0;\n    if (win == WIN_DISPCC) return why;\n")], {H}, False),
    ('display-gate-removed', 'the MDSS and the DPU are read whatever the display verdict says',
     [(C, "    if (c->disp != DX_ON) return RS_DISP_UNK - DX_UNK + c->disp;\n", "")], {H}, False),
    ('display-gate-ignores-hwctl', 'HW_CONTROL set does not close the gate',
     [(C, "    if (gdsc->v >> GDSC_HW_CONTROL_BIT & 1) return DX_HWCTL;\n", "")], {H}, False),
    ('display-gate-ignores-swcollapse', 'SW_COLLAPSE set under PWR_ON does not close the gate',
     [(C, "(gdsc->v >> GDSC_SW_COLLAPSE_BIT & 1) || !(gdsc->v >> GDSC_PWR_ON_BIT & 1)", "!(gdsc->v >> GDSC_PWR_ON_BIT & 1)")], {H}, False),
    ('display-gate-ignores-pwr-on', 'PWR_ON clear does not close the gate',
     [(C, "(gdsc->v >> GDSC_SW_COLLAPSE_BIT & 1) || !(gdsc->v >> GDSC_PWR_ON_BIT & 1)", "(gdsc->v >> GDSC_SW_COLLAPSE_BIT & 1)")], {H}, False),
    ('display-gate-needs-one-clock', 'one running clock of the two opens the gate',
     [(C, "    return *clk == (1u << GATE_CLOCKS) - 1u ? DX_ON : DX_PART;", "    return *clk ? DX_ON : DX_PART;")], {H}, False),
    ('display-gate-unknown-is-known', 'a gate input that was not read does not make the verdict unknown',
     [(C, "    if (!known) return DX_UNK;\n", "")], {H}, False),
    ('display-verdict-zero-is-on', 'the zero value of the verdict is ON, so that a context nobody initialised is open',
     [(G, "enum { DX_UNK, DX_OFF, DX_HWCTL, DX_PART, DX_ON, DX_STATES };", "enum { DX_UNK = 4, DX_OFF = 5, DX_HWCTL = 6, DX_PART = 7, DX_ON = 0, DX_STATES = 8 };"),
      (G, 'disp_name[DX_STATES][8] = {"UNK", "OFF", "HWCTL", "PART", "ON"};', 'disp_name[DX_STATES][8] = {"ON", "", "", "", "UNK", "OFF", "HWCTL", "PART"};')], {H}, False),
    ('word-ok-accepts-all-ones', 'a word of all ones counts as read',
     [(C, "    return v->st == V_OK && v->v != 0xffffffffu;", "    return v->st == V_OK;")], {H}, False),
    ('clock-ignores-clk-off', 'a clock runs when it is enabled, whatever CLK_OFF says',
     [(C, "(v->v >> CBCR_ENABLE_BIT & 1) && !(v->v >> CBCR_CLK_OFF_BIT & 1);", "(v->v >> CBCR_ENABLE_BIT & 1);")], {H}, False),
    ('clock-ignores-enable', 'a clock runs when CLK_OFF is clear, whatever CLK_ENABLE says',
     [(C, "word_ok(v) && (v->v >> CBCR_ENABLE_BIT & 1) && !(v->v", "word_ok(v) && !(v->v")], {H}, False),
    ('version-gate-removed', 'the DPU is read whatever the hardware version word says',
     [(C, "        if (!word_ok(&s->v[R_VER])) return RS_VER_ERR;\n        if (!s->v[R_VER].v) return RS_VER;\n", "")], {H}, False),
    ('version-zero-accepted', 'a hardware version of zero does not close the DPU',
     [(C, "        if (!s->v[R_VER].v) return RS_VER;\n", "")], {H}, False),
    ('frame-counter-read-without-enable', 'the frame counter is read whatever its enable says',
     [(C, "if ((regs[id].flags & F_NEEDS_FLC) && !counter_claimed(s) && !(c->dead >> d->win & 1)) {", "if (0) {")], {H}, False),
    ('frame-counter-enable-zero-counts', 'an enable of zero counts as claiming the counter',
     [(C, "    return word_ok(&s->v[R_FLC]) && s->v[R_FLC].v;", "    return word_ok(&s->v[R_FLC]);")], {H}, False),
    ('frame-counter-enable-all-ones-counts', 'an enable of all ones counts as claiming the counter',
     [(C, "    return word_ok(&s->v[R_FLC]) && s->v[R_FLC].v;", "    return s->v[R_FLC].st == V_OK && s->v[R_FLC].v;")], {H}, False),
    ('dahb-failed-read-reported-as-off', 'a display register clock word that could not be read is reported as a clock that is off',
     [(C, "    return word_ok(&s->v[R_DAHB]) ? RS_DAHB : RS_DAHB_ERR;", "    return RS_DAHB;")], {H}, False),
    ('ver-failed-read-reported-as-zero', 'a hardware version word that could not be read is reported as a version of zero',
     [(C, "        if (!word_ok(&s->v[R_VER])) return RS_VER_ERR;\n", "        if (!word_ok(&s->v[R_VER])) return RS_VER;\n")], {H}, False),
    ('gated-reason-swapped', 'the reason of a closed gate is the next verdict\'s',
     [(C, "    if (c->disp != DX_ON) return RS_DISP_UNK - DX_UNK + c->disp;\n", "    if (c->disp != DX_ON) return RS_DISP_UNK - DX_UNK + (c->disp == DX_OFF ? DX_HWCTL : c->disp);\n")], {H}, False),
    # ---- the order, the NEXT lines, the lines as they go out -------------------------------------------------------------------------------------
    ('no-next-line', 'no NEXT line is ever printed before a block',
     [(C, NEXT_S1, "        if (!(1 || say(c, next.buf, EM_NORMAL))) {")], {H}, False),
    ('no-next-gcc', 'no NEXT line before GCC',
     [(C, NEXT_S1, "        if (!(win == WIN_GCC || say(c, next.buf, EM_NORMAL))) {")], {H}, False),
    ('no-next-mdss', 'no NEXT line before the MDSS',
     [(C, NEXT_S1, "        if (!(win == WIN_MDSS || say(c, next.buf, EM_NORMAL))) {")], {H}, False),
    ('no-next-dpu', 'no NEXT line before the DPU',
     [(C, NEXT_S1, "        if (!(win == WIN_DPU || say(c, next.buf, EM_NORMAL))) {")], {H}, False),
    ('no-next-wait', 'the wait starts without its NEXT line', [(C, "    if (!say(c, wait.buf, EM_NORMAL)) return;\n", "")], {H}, False),
    ('read-without-next', 'a block is read although its NEXT line could not be printed',
     [(C, "        if (!say(c, next.buf, EM_NORMAL)) {\n            c->blocks |= 1u << win;\n            continue;\n        }\n        for (unsigned li",
       "        if (!say(c, next.buf, EM_NORMAL)) {\n            c->blocks |= 1u << win;\n        }\n        for (unsigned li")], {H}, True),
    ('block-read-then-printed', 'the first two lines of the interface are read before either is printed',
     [(G, '    {WIN_DPU, R_ST, R_HS, A_NONE, "INTF"},\n    {WIN_DPU, R_HS, R_AVS, A_NONE, "INTF"},', '    {WIN_DPU, R_ST, R_AVS, A_NONE, "INTF"},\n    {WIN_DPU, R_AVS, R_AVS, A_NONE, "INTF"},')], {H}, False),
    ('verdict-line-dropped', 'the display verdict is never printed',
     [(C, "        disp_gate(c, s);\n        dg_line(c, s);\n", "        disp_gate(c, s);\n")], {H}, False),
    ('retry-after-fault', 'a window that aborted is read again',
     [(C, "        rc = load(c, windows[win].base + off, value);\n        if (rc == RD_FAULT) c->dead |= 1u << win;\n", "        rc = load(c, windows[win].base + off, value);\n")], {H}, False),
    ('dead-window-ignored', 'the abort is recorded and not obeyed',
     [(C, "    } else if (c->dead >> win & 1) {\n        rc = RD_DEAD;\n", "    } else if (0) {\n        rc = RD_DEAD;\n")], {H}, False),
    ('fault-code-lost', 'the code of an abort is printed as zero',
     [(C, "        tx(line, \"FAULT:\");\n        dec(line, v->code);\n", "        tx(line, \"FAULT:\");\n        dec(line, 0);\n")], {H}, False),
    ('line-overflow', 'the line cap is not enforced', [(C, "    if (c->lines >= (kind == EM_CLOSING ? LINE_CAP : NORMAL_LIMIT)) {", "    if (0) {")], {H}, True),
    ('closing-crowded-out', 'the end line obeys the limit of the ordinary lines',
     [(C, "(kind == EM_CLOSING ? LINE_CAP : NORMAL_LIMIT)", "NORMAL_LIMIT")], {H}, True),
    ('load-cap-ignored', 'the load cap is not enforced', [(C, "    if (c->loads >= LOAD_CAP) return RD_BUDGET;\n", "")], {H}, '-DDISPSNAP_LOAD_CAP=20u'),
    ('wait-zero', 'the wait does not wait', [(C, "    waited = delay_ticks(c, (uint64_t)GAP_S * c->hz);", "    waited = delay_ticks(c, 0);")], {H}, False),
    ('unbounded-wait', 'a counter that stands still is waited on for ever (the bound on its identical reads is gone)',
     [(C, "            if (++same >= COUNTER_STUCK_READS) return 0;\n", "            if (++same >= 0xffffffffu) return 0;\n")], {H}, False),
    ('backwards-counter-ignored', 'a counter that runs backwards is not noticed', [(C, "        if (now < start) return 0;\n", "")], {H}, False),
    ('spin-bound-too-small', 'the bound on the reads of the wait is 2^20',
     [(G, "#define DISPSNAP_SPIN_MAX 0xffffffffu", "#define DISPSNAP_SPIN_MAX 0x100000u")], {H}, False),
    ('spin-bound-removed', 'the spin bound is never reached', [(C, "        if (++reads >= SPIN_MAX) return 2;\n", "")], {H}, SPIN),
    ('spin-bound-passed-as-success', 'a wait that hit its bound goes on to snapshot 2',
     [(C, "    if (waited != 1) {\n        say(c, waited == 2", "    if (waited == 0) {\n        say(c, waited == 2")], {H}, SPIN),
    ('spin-token-reused', 'the bound and a dead counter print the same token',
     [(C, "        say(c, waited == 2 ? \"S2 SKIPPED SPIN\" : \"S2 SKIPPED NO_COUNTER\", EM_NORMAL);", "        say(c, \"S2 SKIPPED NO_COUNTER\", EM_NORMAL);")], {H}, SPIN),
    # ---- snapshot 2 and the frame counter ----------------------------------------------------------------------------------------------------------
    ('s2-without-next', 'snapshot 2 reads a block without announcing it', [(C, NEXT_S2, "        if (!(1 || say(c, next.buf, EM_NORMAL))) {")], {H}, False),
    ('s2-note-dropped', 'the note of the block before is not on the NEXT S2 line',
     [(C, "        if (note.len) {\n            tx(&next, \" \");\n            tx(&next, note.buf);\n        }\n        /* No NEXT line, no read, as in snapshot 1. */", "        /* No NEXT line, no read, as in snapshot 1. */")],
     {H}, False),
    ('s2-dispcc-gate-removed', 'DISPCC is read again whatever snapshot 2\'s own display register clock word says',
     [(C, "        why = win == WIN_DISPCC ? ahb_reason(&c->s[1]) : win == WIN_DPU ? s2_dpu_reason(c) : RS_OPEN;", "        why = win == WIN_DPU ? s2_dpu_reason(c) : RS_OPEN;")], {H}, False),
    ('s2-dpu-gate-removed', 'the interface is read again whatever snapshot 2\'s own gate words say',
     [(C, "        why = win == WIN_DISPCC ? ahb_reason(&c->s[1]) : win == WIN_DPU ? s2_dpu_reason(c) : RS_OPEN;", "        why = win == WIN_DISPCC ? ahb_reason(&c->s[1]) : RS_OPEN;")], {H}, False),
    ('s2-dpu-gate-judged-by-snapshot-1', 'the interface\'s second look is judged by snapshot 1\'s gate words',
     [(C, "    unsigned why = ahb_reason(&c->s[1]), disp;\n", "    unsigned why = ahb_reason(&c->s[0]), disp;\n"), (C, "    disp = disp_eval(&c->s[1], &clk);", "    disp = disp_eval(&c->s[0], &clk);")],
     {H}, False),
    ('s2-dead-window-visited', 'a window that aborted in snapshot 1 is visited again',
     [(C, "    return !(c->dead_s1 >> win & 1) && !(c->s2_skip >> win & 1);", "    return !(c->s2_skip >> win & 1);")], {H}, False),
    ('s2-reads-other-interface-words', 'snapshot 2 reads every word of the interface again',
     [(C, "    if (win == WIN_DPU && id != R_ST && id != R_EN && id != R_FRA) return 0;\n", "")], {H}, False),
    ('drift-counts-the-frame-counter', 'the frame counter, which is meant to move, is reported as drift',
     [(C, "if (id == R_FRA || (g == 0)", "if ((g == 0)")], {H}, False),
    ('dt-missing', 'the counter ticks between the two readings of the frame counter are not printed',
     [(C, "    if (revisit(c, R_FRA) && c->s[1].v[R_FRA].st == V_OK && c->t_frb > c->t_fra && c->t_fra) {", "    if (0) {")], {H}, False),
    ('dt-from-the-wrong-reading', 'DT is measured from the start of the run and not from the first reading of the frame counter',
     [(C, "            else c->t_fra = c->counter();", "            else c->t_fra = c->t_first;")], {H}, False),
    # ---- what the page says about the addresses and the mode -----------------------------------------------------------------------------------------
    ('map-base-lies', 'the MAP line prints a base that is not the one the loads use',
     [(C, "        hx(c, &item, windows[win].base);", "        hx(c, &item, windows[win].base + 0x1000);")], {H}, False),
    ('map-intf-index-wrong', 'the MAP line names INTF_4', [(C, "    dec(&line, INTF_INDEX);", "    dec(&line, INTF_INDEX - 1);")], {H}, False),
    ('map-ctl-step-wrong', 'the MAP line prints twice the CTL step', [(C, "    hx(c, &line, CTL_STEP);", "    hx(c, &line, CTL_STEP * 2);")], {H}, False),
    ('gop-swapped', 'the GOP line prints the height for the width and the width for the height',
     [(C, "    header_lines(&c, a->fb_width, a->fb_height, a->fb_stride, a->fb_format);", "    header_lines(&c, a->fb_height, a->fb_width, a->fb_stride, a->fb_format);")], {H}, False),
    # ---- the register table and the windows: the pinned files ---------------------------------------------------------------------------------------
    ('dahb-offset-next-word', 'the display register clock is read at the next word',
     [(G, "#define GCC_DISP_AHB_CBCR 0x27004u", "#define GCC_DISP_AHB_CBCR 0x27008u")], {H, R}, False),
    ('gdsc-offset-drift', 'the MDSS GDSCR is read at the next word', [(G, "#define DISPCC_MDSS_GDSCR 0x9000u", "#define DISPCC_MDSS_GDSCR 0x9004u")], {H, R}, False),
    ('ahbc-offset-a16', 'the MDSS AHB clock is read at the A16\'s offset, which is not a branch clock here',
     [(G, "#define DISPCC_MDSS_AHB_CBCR 0x80a8u", "#define DISPCC_MDSS_AHB_CBCR 0x80b0u")], {H, R}, False),
    ('mdpc-offset-a16', 'the MDP clock is read at the A16\'s offset, which is not a branch clock here',
     [(G, "#define DISPCC_MDSS_MDP_CBCR 0x800cu", "#define DISPCC_MDSS_MDP_CBCR 0x8010u")], {H, R}, False),
    ('version-offset-drift', 'the hardware version is read at the next word', [(G, "#define MDSS_HW_VERSION 0x000u", "#define MDSS_HW_VERSION 0x004u")], {H, R}, False),
    ('status-reads-avr-control', 'STATUS is read at the offset of AVR_CONTROL', [(G, "#define INTF_STATUS 0x26cu", "#define INTF_STATUS 0x270u")], {H, R}, False),
    ('enable-offset-drift', 'the timing engine enable is read at CONFIG', [(G, "#define INTF_TIMING_ENGINE_EN 0x000u", "#define INTF_TIMING_ENGINE_EN 0x004u")], {H, R}, False),
    ('config2-offset-drift', 'CONFIG2 is read at the next word', [(G, "#define INTF_CONFIG2 0x060u", "#define INTF_CONFIG2 0x064u")], {H, R}, False),
    ('flc-offset-drift', 'the frame counter\'s enable is read at the counter\'s offset', [(G, "#define INTF_FRAME_LINE_COUNT_EN 0x0a8u", "#define INTF_FRAME_LINE_COUNT_EN 0x0acu")], {H, R}, False),
    ('timing-offset-f1', 'the display window start is read from the second field\'s register', [(G, "#define INTF_DISPLAY_V_START_F0 0x01cu", "#define INTF_DISPLAY_V_START_F0 0x020u")],
     {H, R}, False),
    ('ctl-register-offset-drift', 'CTL_INTF_ACTIVE is read at the next word', [(G, "#define CTL_INTF_ACTIVE_OFF 0x0f4u", "#define CTL_INTF_ACTIVE_OFF 0x0f8u")], {H, R}, False),
    ('ctl-first-page-drift', 'the first CTL page is the second one', [(G, "#define CTL_FIRST_OFF 0x15000u", "#define CTL_FIRST_OFF 0x16000u")], {H, R}, False),
    ('ctl-step-drift', 'the CTL pages are 0x2000 apart', [(G, "#define CTL_STEP 0x1000u", "#define CTL_STEP 0x2000u")], {H, R}, False),
    ('intf-page-is-intf-6', 'the interface is INTF_6 and the page still says INTF_5', [(G, "#define INTF_PAGE_OFF 0x39000u", "#define INTF_PAGE_OFF 0x3a000u")], {H, R}, False),
    ('gcc-window-base-drift', 'the GCC window starts 0x1000 higher', [(G, "{0x00100000u, 0x200000u, 0}", "{0x00101000u, 0x200000u, 0}")], {H, R}, False),
    ('dispcc-window-base-drift', 'the DISPCC window starts 0x1000 higher', [(G, "{0x0af00000u, 0x20000u, 0}", "{0x0af01000u, 0x20000u, 0}")], {H, R}, False),
    ('mdss-window-base-drift', 'the MDSS window starts 0x1000 higher', [(G, "{0x0ae00000u, 0x01000u, 0}", "{0x0ae01000u, 0x01000u, 0}")], {H, R}, False),
    ('dpu-window-base-drift', 'the DPU window starts 0x1000 higher', [(G, "{0x0ae01000u, 0x8f000u, 0}", "{0x0ae02000u, 0x8f000u, 0}")], {H, R}, False),
    ('dpu-window-size-drift', 'the DPU window is 0x1000 longer than the device tree says', [(G, "{0x0ae01000u, 0x8f000u, 0}", "{0x0ae01000u, 0x90000u, 0}")], {R}, False),
    ('window-names-swapped', 'the names of the MDSS and the DPU are swapped', [(G, '"GCC", "DISPCC", "MDSS", "DPU"}', '"GCC", "DISPCC", "DPU", "MDSS"}')], {H, R}, False),
    ('mdss-and-dispcc-rows-swapped', 'the MDSS AHB clock is read in the GCC window', [(G, 'ROW(WIN_DISPCC, DISPCC_MDSS_AHB_CBCR, D_CBCR, 0, "AHBC")', 'ROW(WIN_GCC, DISPCC_MDSS_AHB_CBCR, D_CBCR, 0, "AHBC")')],
     {H, R}, False),
    ('frame-counter-flag-dropped', 'the frame counter is not marked as needing its enable', [(G, 'F_NEEDS_FLC, "FRA")', '0, "FRA")')], {H, R}, False),
    ('gate-clock-count-drift', 'the display gate asks for one clock', [(G, "#define GATE_CLOCKS 2u", "#define GATE_CLOCKS 1u")], {H, R}, False),
    # ---- bit positions and decodes -------------------------------------------------------------------------------------------------------------------
    ('cbcr-polarity', 'a branch clock prints .ON for bit 31 set', [(C, "v->v >> CBCR_CLK_OFF_BIT & 1 ? \".OFF\" : \".ON\"", "v->v >> CBCR_CLK_OFF_BIT & 1 ? \".ON\" : \".OFF\"")],
     {H}, False),
    ('gdsc-polarity', 'a GDSC prints .OFF for PWR_ON set', [(C, "v->v >> GDSC_PWR_ON_BIT & 1 ? \".ON\" : \".OFF\"", "v->v >> GDSC_PWR_ON_BIT & 1 ? \".OFF\" : \".ON\"")], {H}, False),
    ('all-ones-clock-decoded', 'a branch clock word of all ones decodes as .OFF', [(C, "    if (w == 0xffffffffu) return 1;\n    if (!(w >> CBCR_CLK_OFF_BIT & 1))", "    if (!(w >> CBCR_CLK_OFF_BIT & 1))")], {H}, False),
    ('enable-clear-decoded-as-on', 'a branch clock with CLK_OFF clear and CLK_ENABLE clear (a window of zeros) decodes as .ON',
     [(C, "    if (!(w >> CBCR_CLK_OFF_BIT & 1)) return !(w >> CBCR_ENABLE_BIT & 1);\n", "    if (!(w >> CBCR_CLK_OFF_BIT & 1)) return 0;\n")], {H}, False),
    ('fsm-on-clk-off-decoded', 'a branch clock with CLK_OFF set and an NoC FSM status of ON decodes as .OFF',
     [(C, "    return (w >> CBCR_FSM_SHIFT & CBCR_FSM_MASK) == CBCR_FSM_ON;", "    return 0;")], {H}, False),
    ('all-ones-gdsc-decoded', 'a GDSC word of all ones decodes as .ON', [(C, "tx(line, v->v == 0xffffffffu ? \".ODD\" : v->v >> GDSC_PWR_ON_BIT", "tx(line, v->v >> GDSC_PWR_ON_BIT")], {H}, False),
    ('all-ones-field-decoded', 'a field cut from a word of all ones is printed as a number', [(C, "    if (v->st == V_OK && v->v == 0xffffffffu) tx(&item, \"ODD\");\n    else side(c, &item, &field, D_NONE);",
                                                                                                "    side(c, &item, &field, D_NONE);")], {H}, False),
    ('cbcr-clk-off-bit', 'CLK_OFF is taken from bit 30', [(G, "#define CBCR_CLK_OFF_BIT 31u", "#define CBCR_CLK_OFF_BIT 30u")], {H, R}, False),
    ('cbcr-enable-bit', 'CLK_ENABLE is taken from bit 1', [(G, "#define CBCR_ENABLE_BIT 0u", "#define CBCR_ENABLE_BIT 1u")], {H, R}, False),
    ('gdsc-pwr-on-bit', 'PWR_ON is taken from bit 30', [(G, "#define GDSC_PWR_ON_BIT 31u", "#define GDSC_PWR_ON_BIT 30u")], {H, R}, False),
    ('gdsc-sw-collapse-bit', 'SW_COLLAPSE is taken from bit 2', [(G, "#define GDSC_SW_COLLAPSE_BIT 0u", "#define GDSC_SW_COLLAPSE_BIT 2u")], {H, R}, False),
    ('gdsc-hw-control-bit', 'HW_CONTROL is taken from bit 2', [(G, "#define GDSC_HW_CONTROL_BIT 1u", "#define GDSC_HW_CONTROL_BIT 2u")], {H, R}, False),
    ('version-major-shift', 'the major version is taken from bit 24', [(G, "#define VER_MAJOR_SHIFT 28u", "#define VER_MAJOR_SHIFT 24u")], {H, R}, False),
    ('version-minor-shift', 'the minor version is taken from bit 12', [(G, "#define VER_MINOR_SHIFT 16u", "#define VER_MINOR_SHIFT 12u")], {H, R}, False),
]


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


def _kind(key):
    return rf"test_the_decode_and_the_window_of_every_row_is_the_documents_kind .*\(key='{key}'\)"


_NODE_CLOCKS = r'test_the_gate_inputs_are_the_clocks_of_the_mdss_node_and_the_gdsc_of_its_power_domain'


# What each suite must say about each mutant, a regular expression over the suite's own words: a mutant that is rejected for another reason (a crash, a
# build failure, a different check that happens to trip) is not a pass. `harness-capped` stands for the harness built with the smaller cap `capped` names.
_NO_LOAD32 = r'an access reached a device window or the framebuffer without load32'
_ODD = r'm_has\(ODD\[i\]\.want\):  '
REASONS = {
    # ---- nothing but loads, and only of the table
    'store-to-window': {H: _NO_LOAD32, I: r'load has 1 integer-to-pointer conversions: this payload turns no number into a pointer', B: _own_stack('load')},
    'unguarded-load': {H: _NO_LOAD32, I: r'load has 1 integer-to-pointer conversions: this payload turns no number into a pointer',
                       B: r'a load in load at 0x[0-9a-f]+ \(ldr w\d+, \[x\d+\]\) whose base x\d+ is not provably the stack'},
    'store-to-framebuffer': {H: _NO_LOAD32, I: r'payload_entry has 1 integer-to-pointer conversions', B: _own_stack('payload_entry')},
    'framebuffer-read': {H: _NO_LOAD32, I: r'payload_entry has 1 integer-to-pointer conversions'},
    'window-range-unchecked': {H: r'rd32\(&c, BAD\[i\], 1, &w\) == RD_RANGE && w == 0'},
    'store-through-args': {I: r'stores through the arguments the runner passed', B: _own_stack('payload_entry')},
    'writable-global': {I: r'@emitted is a writable global', B: r'no writable globals'},
    'barrier-inserted': {B: r'forbidden instruction dsb'},
    'smc-inserted': {B: r'1 smc instructions, the policy allows 0'},
    'msr-inserted': {B: r'forbidden instruction msr'},
    'extra-sysreg': {H: r'a system register read: MPIDR_EL1', B: r"registers read \['cntfrq_el0', 'currentel', 'mpidr_el1'\]"},
    'far-offset-read': {H: r'load of 0xae3a500, a register no list names', R: _offset('FLC')},
    'line-counter-in-place-of-frame-counter': {H: r'load of 0xae3a0b0, a register no list names', R: _offset('FRA')},
    # ---- the gates
    'display-register-clock-gate-removed': {H: r'load of DISPCC GDSC behind a closed gate'},
    'display-gate-removed': {H: r'load of MDSS VER behind a closed gate'},
    'display-gate-ignores-hwctl': {H: r'GDSC HW_CONTROL set: no page line starts with "DG DISP=HWCTL"'},
    'display-gate-ignores-swcollapse': {H: r'GDSC SW_COLLAPSE set under PWR_ON \(on only by another vote\): no page line starts with "DG DISP=OFF PWR=1 SC=1"'},
    'display-gate-ignores-pwr-on': {H: r'GDSC PWR_ON clear: no page line starts with "DG DISP=OFF PWR=0"'},
    'display-gate-needs-one-clock': {H: r'AHBC off: no page line starts with "DG DISP=PART PWR=1 SC=0 HW=0 CLK=0X2"'},
    'display-gate-unknown-is-known': {H: r'GDSC a failed read: no page line starts with "DG DISP=UNK"'},
    'display-verdict-zero-is-on': {H: r'c\.disp == DX_UNK && !strcmp\(disp_name\[c\.disp\], "UNK"\)'},
    'word-ok-accepts-all-ones': {H: r"DAHB a failed read: not 'the clock is off': no page line starts with \"DISPCC GATED BY DAHBERR\""},
    'clock-ignores-clk-off': {H: r'DAHB CLK_OFF set: no page line starts with "DISPCC GATED BY DAHB"'},
    'clock-ignores-enable': {H: r'DAHB not enabled: no page line starts with "DISPCC GATED BY DAHB"'},
    'version-gate-removed': {H: r'VER zero: no page line starts with "DPU GATED BY VER"'},
    'version-zero-accepted': {H: r'VER zero: no page line starts with "DPU GATED BY VER"'},
    'frame-counter-read-without-enable': {H: r'load of DPU FRA, the frame counter, while its enable does not say it counts'},
    'frame-counter-enable-zero-counts': {H: r'FLC zero: the counter is not read: no page line starts with "INTF FLC=0 FRA=NOFLC"'},
    'frame-counter-enable-all-ones-counts': {H: r'FLC all ones: a failed read, the counter is not read: no page line starts with "INTF FLC=0XFFFFFFFF FRA=NOFLC"'},
    'dahb-failed-read-reported-as-off': {H: r"DAHB a failed read: not 'the clock is off': no page line starts with \"DISPCC GATED BY DAHBERR\""},
    'ver-failed-read-reported-as-zero': {H: r"VER all ones: a failed read, not 'zero': no page line starts with \"DPU GATED BY VERERR\""},
    'gated-reason-swapped': {H: r'page line 11 is "PAYLOAD DISPSNAP MDSS GATED BY DISP=HWCTL", not "PAYLOAD DISPSNAP MDSS GATED BY DISP=OFF"'},
    # ---- the order, the NEXT lines, the lines as they go out
    'no-next-line': {H: r'load of GCC DAHB without `NEXT GCC` as the last line'},
    'no-next-gcc': {H: r'load of GCC DAHB without `NEXT GCC` as the last line'},
    'no-next-mdss': {H: r'load of MDSS VER without `NEXT MDSS` as the last line'},
    'no-next-dpu': {H: r'load of DPU ST without `NEXT DPU` as the last line'},
    'no-next-wait': {H: r'the wait starts without `NEXT WAIT` as the last line'},
    'read-without-next': {'harness-capped': r'load of GCC DAHB without `NEXT GCC` as the last line'},
    'block-read-then-printed': {H: r'load of DPU HS \(line 5\) before the line 4 was printed'},
    'verdict-line-dropped': {H: r'page line 10 is "PAYLOAD DISPSNAP NEXT MDSS", not "PAYLOAD DISPSNAP DG DISP=ON PWR=1 SC=0 HW=0 CLK=0X3"'},
    'retry-after-fault': {H: r'load of DISPCC MDPC after an abort in that window'},
    'dead-window-ignored': {H: r'load of DISPCC MDPC after an abort in that window'},
    'fault-code-lost': {H: r'm_has\("DAHB=FAULT:6"\) && m_line_starts\("DISPCC GATED BY DAHBERR"\)'},
    'line-overflow': {'harness-capped': r"more lines than the payload's cap"},
    'closing-crowded-out': {'harness-capped': r'the last line is not the end line'},
    'load-cap-ignored': {'harness-capped': r"more loads than the payload's cap"},
    'wait-zero': {H: r'page line 24 is "PAYLOAD DISPSNAP S2 INTF ST=1 EN=1 FRB=0X5C8 DT=0XBB800", not'},
    'unbounded-wait': {H: r'the counter was read \d+ times: an unbounded wait'},
    'backwards-counter-ignored': {H: r'm_has\("S2 SKIPPED NO_COUNTER"\) && m_loads_in\(2\) == 0'},
    'spin-bound-too-small': {H: r'SPIN_MAX >= 0x40000000u && !m_has\("SKIPPED"\) && m_loads_in\(2\) == LOADS_S2'},
    'spin-bound-removed': {'harness-capped': r'the counter was read \d+ times: an unbounded wait'},
    'spin-bound-passed-as-success': {'harness-capped': r'm_has\("S2 SKIPPED SPIN"\) && !m_has\("S2 SKIPPED NO_COUNTER"\) && m_end_field\("GAP_MS"\) == 0 && m_loads_in\(2\) == 0'},
    'spin-token-reused': {'harness-capped': r'SPIN_MAX < 3840000u && m_has\("S2 SKIPPED SPIN"\) && !m_has\("S2 SKIPPED NO_COUNTER"\)'},
    # ---- snapshot 2 and the frame counter
    's2-without-next': {H: r'snapshot-2 load of GCC DAHB without `NEXT S2 GCC` as the last line'},
    's2-note-dropped': {H: r'page line 22 is "PAYLOAD DISPSNAP NEXT S2 DISPCC", not "PAYLOAD DISPSNAP NEXT S2 DISPCC GCC=SAME"'},
    's2-dispcc-gate-removed': {H: r"snapshot-2 load of DISPCC GDSC behind a gate that snapshot 2's own words do not hold open"},
    's2-dpu-gate-removed': {H: r"snapshot-2 load of DPU ST behind a gate that snapshot 2's own words do not hold open"},
    's2-dpu-gate-judged-by-snapshot-1': {H: r"snapshot-2 load of DPU ST behind a gate that snapshot 2's own words do not hold open"},
    's2-dead-window-visited': {H: r'm_line_starts\(want\) < 0'},
    's2-reads-other-interface-words': {H: r"snapshot-2 load of DPU CFG: only GCC, DISPCC and the interface's STATUS, enable and frame counter are read again"},
    'drift-counts-the-frame-counter': {H: r'page line 25 is "PAYLOAD DISPSNAP DD FRA=0X3E8-0X5C8", not "PAYLOAD DISPSNAP DRIFT NONE CMP=6"'},
    'dt-missing': {H: r'page line 24 is "PAYLOAD DISPSNAP S2 INTF ST=1 EN=1 FRB=0X5C8", not'},
    'dt-from-the-wrong-reading': {H: r'strtoull\(p \+ 4, NULL, 0\) == m_ctr_at_frb - m_ctr_at_fra'},
    # ---- what the page says about the addresses and the mode
    'map-base-lies': {H: r'page line 3 is "PAYLOAD DISPSNAP MAP GCC=0X101000 DISPCC=0XAF01000 MDSS=0XAE01000 DPU=0XAE02000"'},
    'map-intf-index-wrong': {H: r'page line 4 is "PAYLOAD DISPSNAP MAP INTF=4 AT=0X39000'},
    'map-ctl-step-wrong': {H: r'STEP=0X2000 REG=0XF4", not'},
    'gop-swapped': {H: r'page line 2 is "PAYLOAD DISPSNAP GOP W=1920 H=2880 STRIDE=2880 FMT=1"'},
    # ---- the register table and the windows: the pinned files
    'dahb-offset-next-word': {H: r'load of 0x127008, a register no list names', R: _offset('DAHB')},
    'gdsc-offset-drift': {H: r'load of 0xaf09004, a register no list names', R: _offset('GDSC')},
    'ahbc-offset-a16': {H: r'load of 0xaf080b0, a register no list names', R: _offset('AHBC')},
    'mdpc-offset-a16': {H: r'load of 0xaf08010, a register no list names', R: _offset('MDPC')},
    'version-offset-drift': {H: r'load of 0xae00004, a register no list names', R: _offset('VER')},
    'status-reads-avr-control': {H: r'load of 0xae3a270, a register no list names', R: _offset('ST')},
    'enable-offset-drift': {H: r"snapshot-2 load of DPU CFG: only GCC, DISPCC and the interface's STATUS, enable and frame counter are read again", R: _offset('EN')},
    'config2-offset-drift': {H: r'load of 0xae3a064, a register no list names', R: _offset('CFG2')},
    'flc-offset-drift': {H: r'page line 17 is "PAYLOAD DISPSNAP INTF FLC=0X3E8 FRA=0X3E8", not', R: _offset('FLC')},
    'timing-offset-f1': {H: r'load of 0xae3a020, a register no list names', R: _offset('DVS')},
    'ctl-register-offset-drift': {H: r'load of 0xae160f8, a register no list names', R: _offset('C0')},
    'ctl-first-page-drift': {H: r'page line 4 is "PAYLOAD DISPSNAP MAP INTF=5 AT=0X39000 CTL=0X16000', R: _offset('C0')},
    'ctl-step-drift': {H: r'page line 4 is "PAYLOAD DISPSNAP MAP INTF=5 AT=0X39000 CTL=0X15000 STEP=0X2000', R: _offset('C1')},
    'intf-page-is-intf-6': {H: r'load of 0xae3b26c, a register no list names', R: _offset('ST')},
    'gcc-window-base-drift': {H: r'load of 0x128004, a register no list names', R: _window('GCC')},
    'dispcc-window-base-drift': {H: r'load of 0xaf0a000, a register no list names', R: _window('DISPCC')},
    'mdss-window-base-drift': {H: r'load of 0xae01000, a register no list names', R: _window('MDSS')},
    'dpu-window-base-drift': {H: r'load of 0xae3b26c, a register no list names', R: _window('DPU')},
    'dpu-window-size-drift': {R: _window('DPU')},
    'window-names-swapped': {H: r'load of MDSS VER without `NEXT MDSS` as the last line', R: r"test_the_windows_are_those_of_the_device_tree .*Lists differ: \['GCC', 'DISPCC', 'DPU', 'MDSS'\]"},
    'mdss-and-dispcc-rows-swapped': {H: r'load of 0x1080a8, a register no list names', R: _kind('AHBC')},
    'frame-counter-flag-dropped': {H: r'load of DPU FRA, the frame counter, while its enable does not say it counts', R: _kind('FRA')},
    'gate-clock-count-drift': {H: r'page line 10 is "PAYLOAD DISPSNAP DG DISP=PART PWR=1 SC=0 HW=0 CLK=0X3", not', R: _NODE_CLOCKS},
    # ---- bit positions and decodes
    'cbcr-polarity': {H: r'page line 6 is "PAYLOAD DISPSNAP GCC DAHB=1\.OFF", not "PAYLOAD DISPSNAP GCC DAHB=1\.ON"'},
    'gdsc-polarity': {H: r'page line 8 is "PAYLOAD DISPSNAP DISPCC GDSC=0X8022F000\.OFF SC=0 HW=0", not'},
    'all-ones-clock-decoded': {H: _ODD + r'DAHB=0XFFFFFFFF\.ODD'},
    'enable-clear-decoded-as-on': {H: _ODD + r'DAHB=0\.ODD'},
    'fsm-on-clk-off-decoded': {H: _ODD + r'AHBC=0XA0000001\.ODD'},
    'all-ones-gdsc-decoded': {H: _ODD + r'GDSC=0XFFFFFFFF\.ODD SC=ODD HW=ODD'},
    'all-ones-field-decoded': {H: _ODD + r'VER=0XFFFFFFFF MAJ=ODD MIN=ODD'},
    'cbcr-clk-off-bit': {H: r'page line 9 is "PAYLOAD DISPSNAP DISPCC AHBC=0X80000000\.ODD MDPC=0X80000000\.ODD", not', R: _field('CBCR_CLK_OFF_BIT')},
    'cbcr-enable-bit': {H: r'page line 6 is "PAYLOAD DISPSNAP GCC DAHB=1\.ODD", not', R: _field('CBCR_ENABLE_BIT')},
    'gdsc-pwr-on-bit': {H: r'page line 8 is "PAYLOAD DISPSNAP DISPCC GDSC=0X8022F000\.OFF SC=0 HW=0", not', R: _field('GDSC_PWR_ON_BIT')},
    'gdsc-sw-collapse-bit': {H: r'page line 8 is "PAYLOAD DISPSNAP DISPCC GDSC=0X222001\.OFF SC=0 HW=0", not', R: _field('GDSC_SW_COLLAPSE_BIT')},
    'gdsc-hw-control-bit': {H: r'GDSC HW_CONTROL set: no page line starts with "DG DISP=HWCTL"', R: _field('GDSC_HW_CONTROL_BIT')},
    'version-major-shift': {H: r'page line 12 is "PAYLOAD DISPSNAP MDSS VER=0X90020000 MAJ=0 MIN=2", not', R: _field('VER')},
    'version-minor-shift': {H: r'page line 12 is "PAYLOAD DISPSNAP MDSS VER=0X90020000 MAJ=9 MIN=0X20", not', R: _field('VER')},
}


def stale(mutant, text_of):
    """The edits whose needle does not occur exactly once in the file they name (empty for a good mutant)."""
    name, _, edits, _, _ = mutant
    return [(name, f, needle[:50], text_of[f].count(needle)) for f, needle, _ in edits if text_of[f].count(needle) != 1]


def write_copy(mutant, directory, root=ROOT):
    """Copies the sources of `root` into `directory` with the mutant's edits applied (none for mutant None); returns the path of dispsnap.c."""
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
    return directory / 'dispsnap.c'


def harness_rejects(source, out_dir, extra=(), root=ROOT):
    """(rejected, why) of the native host test built against `source`, without sanitizers (the shipped suite builds with them); a build failure is an error.
    `why` is the exit status and every FAIL line the test printed (at most 60), so that a reason can be looked for in all of them."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = out_dir / ('harness' + ''.join(flag.split('=')[-1].strip('u') for flag in extra))
    built = lib.run(['clang', '-std=gnu11', '-O1', '-w', '-DQ1N1_PAYLOAD_HOST_TEST=1', f'-DDISPSNAP_SRC="{source}"', '-Iplatform/uefi', '-Ipayloads', *extra,
                     '-o', str(binary), str(Path(root) / 'tools' / 'test-q1n1-sp11-payload-dispsnap.c')], cwd=root)
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
    problems = lib.binary_violations(elf, flat, lib.POLICIES['dispsnap'], 'llvm-readelf')
    return bool(problems), ' | '.join(problems[:6])


def refs_rejects(source, root=ROOT):
    """(rejected, why) of tools/test-q1n1-sp11-payload-dispsnap-refs.py run against the sources of the copy; rejected is None when this tree has no reference
    copies to run it with, so that the check is a SKIP and never a pass."""
    env = dict(lib.ENV, DISPSNAP_PAYLOAD_DIR=str(Path(source).parent))
    done = subprocess.run(['python3', '-B', str(Path(root) / 'tools' / 'test-q1n1-sp11-payload-dispsnap-refs.py')], cwd=root, env=env, capture_output=True, text=True,
                          timeout=300)
    text = (done.stderr or '') + (done.stdout or '')
    if 'Ran 0 tests' in text and 'skipped' in text:
        return None, 'SKIP: no reference copies'
    if 'skipped' in text and 'FAIL' not in text and 'ERROR' not in text and done.returncode == 0 and 'OK (skipped' in text:
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
        flag = mutant[4] if isinstance(mutant[4], str) else '-DDISPSNAP_LINE_CAP=6u'
        result['harness-capped'] = harness_rejects(source, work / 'h', extra=(flag,), root=root)
    return result
