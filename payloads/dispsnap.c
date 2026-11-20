/* SPDX-License-Identifier: MIT */
/* Payload "dispsnap": a read-only look at the display pipeline of the Surface Pro 11 as the firmware left it, before anything is written (the X2 display dump list, docs/SP11-DISPLAY-STUDY.md
 * section 8 of the Snapintosh tree; docs/SP11-PAYLOAD-DISPSNAP.md has the registers with their file:line and evidence labels, the page, the gates and what each outcome would mean). The page
 * is the console the operator reads: the firmware's own scanout. Nothing of this payload may disturb it, so it issues plain 32-bit loads of registers whose reads have no side effect (the
 * document names the clear-on-read and FIFO registers that were left out), never touches the framebuffer, and writes nothing anywhere. Whether the unit's EL2 stage-1 map reaches the MDSS, the
 * DPU and the display clock controller is UNKNOWN, and a load that hangs the bus (or an SError, which the guard does not catch) is not recovered by anything, so the order of the reads is the
 * safety argument. The GCC word comes first and needs no gate; the display clock controller is read only if the display register clock (GCC_DISP_AHB) reads as running; the MDSS and the DPU
 * (the interface's registers and the six CTL paths) only if the display gate, printed as the DG line, says ON: the MDSS GDSC powered and under software control, the MDSS AHB and the MDP
 * clocks running; the DPU also only if the MDSS hardware version read as a word that is neither all ones nor zero. A word that was not read, faulted, skipped or all ones never opens a gate.
 *
 * Every access is an ops.load32 (a synchronous abort comes back as a code, never as an exception; an SError is neither caught by it nor printed); the only system registers are CurrentEL
 * and CNTFRQ_EL0. The only stores are to this payload's own stack, and that is the only memory it writes through any pointer: no pointer is kept in memory (the four ops are copied into
 * the context as function pointers, every data pointer is an argument or a local), so that the compiled-code audit (tools/sp11_payload_dispsnap_audit.py) and the binary check of
 * tools/sp11_payload_memcheck.py can both prove it. The arguments are read for the GOP mode the runner drew the page in (width, height, stride, format) and for nothing else: the framebuffer
 * itself is never read or written. No tick, no SMC, no HVC, no barrier. Nothing is retried: the first abort in a window ends every later read of it, in the second snapshot too. A block is
 * announced by a `NEXT <block>` line first and is not read at all if the line cannot be printed, so that the last line on the panel names what hung. A line is read whole and printed before the
 * first load of the next one, so that a hang keeps every line before the one it hit.
 *
 * The order inside a block is the safety argument too, because the first abort in a window ends the window. The first load of every block is a word Linux itself reads in that block
 * (GCC_DISP_AHB, the MDSS GDSCR, the hardware version, the interface's STATUS); the study's timing words come next, in the same page as that STATUS. A gate that could not read its input says so
 * (DAHBERR, VERERR, DISP=UNK) and never reports the input as off.
 *
 * Page: a header and a legend, the GOP and the two MAP lines (the bases and the geometry the loads use, from the same tables; no load), then for GCC, DISPCC, MDSS and DPU either `NEXT <block>`
 * and its lines or `<block> GATED BY <why>`; `NEXT WAIT 8 S`; snapshot 2, which reads the GCC word and the three gate words again and, if its own words still say ON, the interface's STATUS and
 * enable and the frame counter a second time (with the counter ticks between the two readings), and prints what moved; the end line. A value below 10 is one digit, a larger one 0X and the fewest
 * upper-case hex digits. At most LINE_CAP lines whatever the hardware says: a field that does not fit is dropped and counted in CUTS, never cut in half. */
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* No MRS can run on a build machine: the host test supplies the register file. */
uint64_t pl_host_sysreg(const char *name);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#include "dispsnap-regs.h"

#define PREFIX "PAYLOAD DISPSNAP "
#define OUT_OF_LINE static __attribute__((noinline))     /* one body per helper: the reviewed binary stays small */

#ifdef DISPSNAP_SHIPPED_CAPS
_Static_assert(HEADER_LINES + NEXT_LINES + TABLE_LINES + EXTRA_LINES + S2_NEXT_LINES + S2_RESULT_LINES + CLOSING_LINES <= LINE_CAP, "dispsnap: the page with every gate open fits the line cap");
_Static_assert(S1_LOADS + S2_LOADS <= LOAD_CAP, "dispsnap: the loads of the two snapshots fit the load cap");
#endif

enum { RD_OK, RD_RANGE, RD_ALIGN, RD_DEAD, RD_BUDGET, RD_FAULT };
/* The state of one value: V_NONE not read, V_NA refused, V_SKIP not read after an abort in its window, V_GATED not read because its block's gate was closed (a gated block prints one line and no
 * value, so this state is never printed), V_NOFLC not read because the frame counter's enable did not say it counts. */
enum { V_NONE, V_OK, V_FAULT, V_SKIP, V_NA, V_BUDGET, V_GATED, V_NOFLC };

struct val {
    uint32_t v, st, code, pad;
};

struct snap {
    struct val v[R_COUNT];
};

struct ctx {
    void (*puts)(const char *line);
    uint32_t (*hex)(char *dst, uint32_t cap, uint64_t value);
    int32_t (*load32)(uint64_t addr, uint32_t *out);
    uint64_t (*counter)(void);
    uint32_t word;                  /* the load32 destination: the runner wants it on the payload stack, and the context is */
    uint32_t err;                   /* what the last failed load32 returned */
    uint32_t loads, lines, cuts, faults, skips, blocks, hz, hz_default;
    uint32_t dead, dead_s1;         /* a bit per window in which a load aborted, now and when snapshot 1 ended */
    uint32_t s2_skip;               /* a bit per window snapshot 2 did not visit because its gate was closed */
    uint32_t disp;                  /* the display gate's verdict of snapshot 1 (DX_*) */
    uint32_t clk_mask;              /* the clocks of the display gate that run, one bit each: AHBC bit 0, MDPC bit 1 */
    uint64_t t_first, t_second;
    uint64_t t_fra, t_frb;          /* the counter right after the frame counter was read, in snapshot 1 and in snapshot 2 (0: not read) */
    struct snap s[2];
};

/* ---- Text ---- */

OUT_OF_LINE void tx(struct pl_line *line, const char *text)
{
    pl_text(line, text);
}

OUT_OF_LINE void hx(const struct ctx *c, struct pl_line *line, uint64_t value)
{
    line->len += c->hex(line->buf + line->len, Q1N1_PAYLOAD_LINE_MAX + 1 - line->len, value);
}

OUT_OF_LINE void dec(struct pl_line *line, uint64_t value)
{
    char digits[20];
    unsigned n = 0;
    do {
        digits[n++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    while (n && line->len < Q1N1_PAYLOAD_LINE_MAX) line->buf[line->len++] = digits[--n];
    line->buf[line->len] = 0;
}

OUT_OF_LINE void num(const struct ctx *c, struct pl_line *line, uint64_t value)
{
    if (value < 10) dec(line, value);
    else hx(c, line, value);
}

/* A line counts against LINE_CAP. Two classes: the ordinary lines keep back what the closing lines need, and the closing lines (the drift summary and the end line) may use what is left, so that
 * the end line is never crowded out by the lines before it. */
enum { EM_NORMAL, EM_CLOSING };
#define NORMAL_LIMIT (LINE_CAP > CLOSING_LINES ? LINE_CAP - CLOSING_LINES : 0u)
OUT_OF_LINE int emit(struct ctx *c, const struct pl_line *line, unsigned kind)
{
    if (c->lines >= (kind == EM_CLOSING ? LINE_CAP : NORMAL_LIMIT)) {
        c->cuts++;
        return 0;
    }
    c->lines++;
    c->puts(line->buf);
    return 1;
}

OUT_OF_LINE int say(struct ctx *c, const char *text, unsigned kind)
{
    struct pl_line line;
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, text);
    return emit(c, &line, kind);
}

/* A field goes on the line only whole: one that does not fit is dropped and counted. */
OUT_OF_LINE void put_item(struct ctx *c, struct pl_line *line, const struct pl_line *item)
{
    if (line->len + 1 + item->len > Q1N1_PAYLOAD_LINE_MAX) {
        c->cuts++;
        return;
    }
    tx(line, " ");
    tx(line, item->buf);
}

OUT_OF_LINE void key(struct pl_line *item, const char *name)
{
    pl_begin(item);
    tx(item, name);
    tx(item, "=");
}

/* The text of one value: number (below 10 one digit) and, for a branch clock or the GDSC word, the decode of its bit 31 (.OFF is bit 31 set; .ON is bit 31 clear with CLK_ENABLE set); or why there
 * is no value. A decode is printed only where it can be taken at its word, and `.ODD` marks the cell where it cannot (read the raw word beside it): a word of all ones is what a failed read returns;
 * CLK_OFF clear with CLK_ENABLE clear is a clock that says it runs without being enabled, which is what a window of zeros reads; a CLK_OFF with an NoC FSM status of ON counts as on for Linux
 * (clk-branch.c:54-58). This is the decode only: whether a clock runs is clock_runs()'s, which does not change with it. */
OUT_OF_LINE int cell_is_odd(uint32_t w)
{
    if (w == 0xffffffffu) return 1;
    if (!(w >> CBCR_CLK_OFF_BIT & 1)) return !(w >> CBCR_ENABLE_BIT & 1);
    return (w >> CBCR_FSM_SHIFT & CBCR_FSM_MASK) == CBCR_FSM_ON;
}

OUT_OF_LINE void side(const struct ctx *c, struct pl_line *line, const struct val *v, unsigned decode)
{
    switch (v->st) {
    case V_OK:
        num(c, line, v->v);
        /* CLK_OFF of a branch clock, with the modes that make it untrustworthy (cell_is_odd) */
        if (decode == D_CBCR) tx(line, cell_is_odd(v->v) ? ".ODD" : v->v >> CBCR_CLK_OFF_BIT & 1 ? ".OFF" : ".ON");
        /* a GDSC's PWR_ON */
        if (decode == D_GDSCR) tx(line, v->v == 0xffffffffu ? ".ODD" : v->v >> GDSC_PWR_ON_BIT & 1 ? ".ON" : ".OFF");
        break;
    case V_FAULT:
        tx(line, "FAULT:");
        dec(line, v->code);
        break;
    case V_SKIP:
        tx(line, "SKIP");
        break;
    case V_BUDGET:
        tx(line, "BUDGET");
        break;
    case V_NOFLC:
        tx(line, "NOFLC");
        break;
    default:
        tx(line, "NA");
        break;
    }
}

/* A field of a value as its own field: shift and mask for a bit field. A value that was not read shows why, as the register does. A field of a word of all ones is no field: all ones is what a failed
 * read returns, so the cell says ODD and the raw word beside it says why. */
OUT_OF_LINE void put_bits(struct ctx *c, struct pl_line *line, const char *name, const struct val *v, unsigned shift, uint32_t mask)
{
    struct pl_line item;
    struct val field;
    field.st = v->st;
    field.code = v->code;
    field.pad = 0;
    field.v = v->v >> shift & mask;
    key(&item, name);
    if (v->st == V_OK && v->v == 0xffffffffu) tx(&item, "ODD");
    else side(c, &item, &field, D_NONE);
    put_item(c, line, &item);
}

OUT_OF_LINE void put_reg(struct ctx *c, struct pl_line *line, const struct snap *s, unsigned id)
{
    const struct reg *r = &regs[id];
    const struct val *v = &s->v[id];
    struct pl_line item;
    key(&item, r->key);
    side(c, &item, v, r->dec);
    put_item(c, line, &item);
    switch (r->dec) {
    case D_GDSCR:
        put_bits(c, line, "SC", v, GDSC_SW_COLLAPSE_BIT, 1);
        put_bits(c, line, "HW", v, GDSC_HW_CONTROL_BIT, 1);
        break;
    case D_VER:
        put_bits(c, line, "MAJ", v, VER_MAJOR_SHIFT, VER_MAJOR_MASK);
        put_bits(c, line, "MIN", v, VER_MINOR_SHIFT, VER_MINOR_MASK);
        break;
    default:
        break;
    }
}

/* ---- Reads: every access this payload makes goes through load() ---- */

OUT_OF_LINE int load(struct ctx *c, uint64_t phys, uint32_t *value)
{
    int32_t err;
    *value = 0;
    if (c->loads >= LOAD_CAP) return RD_BUDGET;
    c->loads++;
    err = c->load32(phys, &c->word);
    if (err) {
        c->err = (uint32_t)err;
        return RD_FAULT;
    }
    *value = c->word;
    return RD_OK;
}

/* The first abort ends all reads of its window: whatever stopped one load would stop the next, and nothing is retried. A window the table does not have is refused before `windows` is indexed
 * (every row names a valid one: this keeps a bad row from reading past the table and from shifting `dead` by more than its width). */
OUT_OF_LINE int rd32(struct ctx *c, unsigned win, uint32_t off, uint32_t *value)
{
    int rc;
    *value = 0;
    if (win >= WINDOWS) {
        rc = RD_RANGE;
    } else if (off & 3) {
        rc = RD_ALIGN;
    } else if (off >= windows[win].size || windows[win].size - off < 4) {
        rc = RD_RANGE;
    } else if (c->dead >> win & 1) {
        rc = RD_DEAD;
    } else {
        rc = load(c, windows[win].base + off, value);
        if (rc == RD_FAULT) c->dead |= 1u << win;
    }
    return rc;
}

/* One value of snapshot `snap`, which the caller points at (`v`: the base of the store is the caller's own value, which the binary check can follow): its load, or the reason there is none. The
 * counter is read right after the frame counter's load, so that the two readings of it are timed from the same place. */
OUT_OF_LINE void read_row(struct ctx *c, struct val *v, unsigned snap, unsigned id)
{
    const struct reg *r = &regs[id];
    uint32_t word;
    int rc = rd32(c, r->win, r->off, &word);
    v->v = 0;
    v->code = 0;
    v->pad = 0;
    v->st = V_NA;
    switch (rc) {
    case RD_OK:
        v->v = word;
        v->st = V_OK;
        if (id == R_FRA && c->counter) {
            if (snap) c->t_frb = c->counter();
            else c->t_fra = c->counter();
        }
        break;
    case RD_FAULT:
        v->st = V_FAULT;
        v->code = c->err;
        c->faults++;
        c->blocks |= 1u << r->win;
        break;
    case RD_DEAD:
        v->st = V_SKIP;
        c->skips++;
        c->blocks |= 1u << r->win;
        break;
    case RD_BUDGET:
        v->st = V_BUDGET;
        c->blocks |= 1u << r->win;
        break;
    default:
        break;
    }
}

/* ---- The gates ---- */

/* A word that was read and is not what a failed read returns. */
OUT_OF_LINE int word_ok(const struct val *v)
{
    return v->st == V_OK && v->v != 0xffffffffu;
}

/* A branch clock runs when its word was read, CLK_ENABLE is set and CLK_OFF is clear: positive proof, as Linux asks for when it enables one (clk-branch.c:54-58) but without its extra
 * readings, which would open a gate on less. No clock on this payload's list has a hardware gating bit or skips its halt check, so there is no exemption; a NoC FSM status of ON with CLK_OFF
 * set is not taken as running. */
OUT_OF_LINE int clock_runs(const struct val *v)
{
    return word_ok(v) && (v->v >> CBCR_ENABLE_BIT & 1) && !(v->v >> CBCR_CLK_OFF_BIT & 1);
}

/* The display gate's verdict from the words of a snapshot: ON only if the MDSS GDSC has PWR_ON set while neither SW_COLLAPSE nor HW_CONTROL is set (under hardware control the hardware may
 * collapse it between two reads) and both clocks run; HWCTL, OFF and PART say which of those failed first; UNK is any input that was not read or reads as a failed read does. It also leaves the
 * mask of the clocks that run for the page. */
OUT_OF_LINE unsigned disp_eval(const struct snap *s, uint32_t *clk)
{
    const struct val *gdsc = &s->v[R_GDSC];
    unsigned known = word_ok(gdsc) && word_ok(&s->v[R_AHBC]) && word_ok(&s->v[R_MDPC]);
    *clk = (uint32_t)clock_runs(&s->v[R_AHBC]) | (uint32_t)clock_runs(&s->v[R_MDPC]) << 1;
    if (!known) return DX_UNK;
    if (gdsc->v >> GDSC_HW_CONTROL_BIT & 1) return DX_HWCTL;
    if ((gdsc->v >> GDSC_SW_COLLAPSE_BIT & 1) || !(gdsc->v >> GDSC_PWR_ON_BIT & 1)) return DX_OFF;
    return *clk == (1u << GATE_CLOCKS) - 1u ? DX_ON : DX_PART;
}

OUT_OF_LINE void disp_gate(struct ctx *c, const struct snap *s)
{
    c->disp = disp_eval(s, &c->clk_mask);
}

/* The display register clock's gate of a snapshot (gcc-x1e80100.c:7447): open when the word reads as running; DAHB when it was read and does not; DAHBERR when it was not read (an abort, a skip,
 * all ones), which is not the same statement: a failed gate read is never reported as the thing it gates on. */
OUT_OF_LINE unsigned ahb_reason(const struct snap *s)
{
    if (clock_runs(&s->v[R_DAHB])) return RS_OPEN;
    return word_ok(&s->v[R_DAHB]) ? RS_DAHB : RS_DAHB_ERR;
}

/* Why a window is not read now, 0 if it may be. GCC is always on. DISPCC needs the display register clock to run. The MDSS needs the display verdict ON; the DPU also the MDSS hardware
 * version to have been read as a word that is neither all ones nor zero (a block that does not answer). */
OUT_OF_LINE unsigned gate_reason(const struct ctx *c, unsigned win)
{
    const struct snap *s = &c->s[0];
    unsigned why;
    if (win == WIN_GCC) return RS_OPEN;
    why = ahb_reason(s);
    if (why || win == WIN_DISPCC) return why;
    if (c->disp != DX_ON) return RS_DISP_UNK - DX_UNK + c->disp;
    if (win == WIN_DPU) {
        if (!word_ok(&s->v[R_VER])) return RS_VER_ERR;
        if (!s->v[R_VER].v) return RS_VER;
    }
    return RS_OPEN;
}

/* Why the interface is not read again after the wait, 0 if it may be: the state that opened it in snapshot 1 must still hold, judged by snapshot 2's own words (its display register clock
 * word, then the display verdict over its gate words). A word snapshot 2 could not read is not a clock that stopped: the reason is DAHBERR or DISP=UNK. */
OUT_OF_LINE unsigned s2_dpu_reason(const struct ctx *c)
{
    uint32_t clk;
    unsigned why = ahb_reason(&c->s[1]), disp;
    if (why) return why;
    disp = disp_eval(&c->s[1], &clk);
    return disp == DX_ON ? RS_OPEN : RS_DISP_UNK - DX_UNK + disp;
}

/* ---- The lines of snapshot 1 ---- */

/* DG: the verdict and the words it was made of, printed as soon as they have gone out and before any MDSS word is read. */
OUT_OF_LINE void dg_line(struct ctx *c, const struct snap *s)
{
    struct pl_line line, item;
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "DG DISP=");
    tx(&line, disp_name[c->disp]);
    if (c->disp != DX_UNK) {
        put_bits(c, &line, "PWR", &s->v[R_GDSC], GDSC_PWR_ON_BIT, 1);
        put_bits(c, &line, "SC", &s->v[R_GDSC], GDSC_SW_COLLAPSE_BIT, 1);
        put_bits(c, &line, "HW", &s->v[R_GDSC], GDSC_HW_CONTROL_BIT, 1);
        key(&item, "CLK");
        hx(c, &item, c->clk_mask);
        put_item(c, &line, &item);
    }
    emit(c, &line, EM_NORMAL);
}

/* Whether the frame counter's enable was read, is not a failed read and is not zero. */
OUT_OF_LINE int counter_claimed(const struct snap *s)
{
    return word_ok(&s->v[R_FLC]) && s->v[R_FLC].v;
}

/* One line: its rows are read, then the line goes out, then whatever the line's `after` asks for. The frame counter is read only when its enable says it counts; a window that has aborted
 * says SKIP for it, as for every other row, and not NOFLC. */
OUT_OF_LINE void do_line(struct ctx *c, unsigned li)
{
    const struct line_def *d = &lines[li];
    struct snap *s = &c->s[0];
    struct pl_line line;
    for (unsigned id = d->first; id < d->end; id++) {
        if ((regs[id].flags & F_NEEDS_FLC) && !counter_claimed(s) && !(c->dead >> d->win & 1)) {
            s->v[id].st = V_NOFLC;
            s->v[id].v = s->v[id].code = s->v[id].pad = 0;
        } else {
            read_row(c, &s->v[id], 0, id);
        }
    }
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, d->head);
    for (unsigned id = d->first; id < d->end; id++) put_reg(c, &line, s, id);
    emit(c, &line, EM_NORMAL);
    if (d->after == A_DG) {
        disp_gate(c, s);
        dg_line(c, s);
    }
}

/* A block that is not read, and why: one line. In snapshot 1 every value of the block is marked as not read; a block that snapshot 2 leaves out (`second`) keeps what snapshot 1 read, and its line
 * starts with `S2`. `note` is what the block before it said. */
OUT_OF_LINE void gated_block(struct ctx *c, unsigned win, unsigned why, unsigned second, const char *note)
{
    struct pl_line line;
    if (!second) {
        for (unsigned id = 0; id < R_COUNT; id++) {
            if (regs[id].win == win) c->s[0].v[id].st = V_GATED;
        }
    }
    c->blocks |= 1u << win;
    pl_begin(&line);
    tx(&line, PREFIX);
    if (second) tx(&line, "S2 ");
    tx(&line, window_name[win]);
    tx(&line, " GATED BY ");
    tx(&line, reason_name[why]);
    if (note[0]) {
        tx(&line, " ");
        tx(&line, note);
    }
    emit(c, &line, EM_NORMAL);
}

OUT_OF_LINE void snapshot_one(struct ctx *c)
{
    for (unsigned win = 0; win < WINDOWS; win++) {
        struct pl_line next;
        unsigned why = gate_reason(c, win);
        if (why) {
            gated_block(c, win, why, 0, "");
            continue;
        }
        pl_begin(&next);
        tx(&next, "NEXT ");
        tx(&next, window_name[win]);
        /* No NEXT line, no read: what hangs must be named. */
        if (!say(c, next.buf, EM_NORMAL)) {
            c->blocks |= 1u << win;
            continue;
        }
        for (unsigned li = 0; li < LINES; li++) {
            if (lines[li].win == win) do_line(c, li);
        }
    }
}

/* ---- Snapshot 2: the GCC word, the gate words and the interface again, then a drift report ---- */

/* A value that snapshot 2 reads again and the drift report compares: a word that snapshot 1 read, in a window that had not aborted by the end of snapshot 1 and that snapshot 2 does not leave
 * out. The MDSS is not visited again: its only word is the hardware version. */
OUT_OF_LINE int revisit(const struct ctx *c, unsigned id)
{
    unsigned win = regs[id].win;
    if (win == WIN_MDSS) return 0;
    if (c->s[0].v[id].st != V_OK) return 0;
    if (win == WIN_DPU && id != R_ST && id != R_EN && id != R_FRA) return 0;
    return !(c->dead_s1 >> win & 1) && !(c->s2_skip >> win & 1);
}

OUT_OF_LINE int window_has_reads(const struct ctx *c, unsigned win)
{
    for (unsigned id = 0; id < R_COUNT; id++) {
        if (regs[id].win == win && revisit(c, id)) return 1;
    }
    return 0;
}

OUT_OF_LINE void read_window(struct ctx *c, unsigned win)
{
    for (unsigned id = 0; id < R_COUNT; id++) {
        if (regs[id].win == win && revisit(c, id)) read_row(c, &c->s[1].v[id], 1, id);
    }
}

/* How many of the values of a window that snapshot 2 read again are not what snapshot 1 read (a value that could not be read again counts). The frame counter is meant to move: it is not drift. */
OUT_OF_LINE unsigned changes_in(const struct ctx *c, unsigned win)
{
    unsigned n = 0;
    for (unsigned id = 0; id < R_COUNT; id++) {
        if (regs[id].win == win && id != R_FRA && revisit(c, id)) n += !(c->s[1].v[id].st == V_OK && c->s[1].v[id].v == c->s[0].v[id].v);
    }
    return n;
}

/* What the second look at the interface said, as the host side needs it: the words as read, the frame counter's second reading as FRB, and the counter ticks between the two readings of the
 * frame counter (DT) when both were made. A frame counter that snapshot 1 did not read says why, as FLC's reading allows. */
OUT_OF_LINE void s2_line(struct ctx *c)
{
    struct pl_line line, item;
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "S2 INTF");
    for (unsigned id = R_ST; id <= R_EN; id++) {
        if (revisit(c, id)) put_reg(c, &line, &c->s[1], id);
    }
    key(&item, "FRB");
    if (revisit(c, R_FRA)) side(c, &item, &c->s[1].v[R_FRA], D_NONE);
    else tx(&item, "NOFLC");
    put_item(c, &line, &item);
    if (revisit(c, R_FRA) && c->s[1].v[R_FRA].st == V_OK && c->t_frb > c->t_fra && c->t_fra) {
        key(&item, "DT");
        num(c, &item, c->t_frb - c->t_fra);
        put_item(c, &line, &item);
    }
    emit(c, &line, EM_NORMAL);
}

/* The drift report packs several items on a line and may use several lines: what does not fit the lines left is dropped and counted. */
struct out {
    struct pl_line line;
    char head[4];
    unsigned lines, max_lines, filled, dropped;
};

OUT_OF_LINE void out_start(struct out *o)
{
    pl_begin(&o->line);
    tx(&o->line, PREFIX);
    tx(&o->line, o->head);
    o->filled = 0;
}

OUT_OF_LINE void out_end(struct ctx *c, struct out *o)
{
    if (o->filled) {
        emit(c, &o->line, EM_NORMAL);
        o->lines++;
    }
    out_start(o);
}

OUT_OF_LINE void out_put(struct ctx *c, struct out *o, const struct pl_line *item)
{
    if (!o->max_lines) {
        o->dropped++;
        c->cuts++;
        return;
    }
    if (o->line.len + 1 + item->len > Q1N1_PAYLOAD_LINE_MAX) {
        if (o->lines + 1 >= o->max_lines) {
            o->dropped++;
            c->cuts++;
            return;
        }
        out_end(c, o);
    }
    tx(&o->line, " ");
    tx(&o->line, item->buf);
    o->filled = 1;
}

/* DG holds what moved in the GCC and DISPCC words and DD what moved in the interface's STATUS and enable: KEY=OLD-NEW, where NEW may be the fault, or the skip after one, that replaced the value.
 * CHANGED counts the values that differ, LOST those snapshot 2 could not read; CMP the values snapshot 1 read in a window that had not aborted by then and that snapshot 2 visited, all compared. */
OUT_OF_LINE void drift_report(struct ctx *c)
{
    static const char group[2][4] = {"DG", "DD"};
    unsigned compared = 0, changed = 0, lost = 0, more = 0;
    struct pl_line sum;
    struct out o;
    for (unsigned g = 0; g < 2; g++) {
        unsigned avail = c->lines < NORMAL_LIMIT ? NORMAL_LIMIT - c->lines : 0;
        o.lines = o.dropped = 0;
        o.max_lines = avail;
        for (unsigned i = 0; i < 4; i++) o.head[i] = group[g][i];
        out_start(&o);
        for (unsigned id = 0; id < R_COUNT; id++) {
            const struct val *old = &c->s[0].v[id], *now = &c->s[1].v[id];
            struct pl_line item;
            if (id == R_FRA || (g == 0) == (regs[id].win == WIN_DPU) || !revisit(c, id)) continue;
            compared++;
            if (now->st == V_OK && now->v == old->v) continue;
            if (now->st == V_OK) changed++;
            else lost++;
            key(&item, regs[id].key);
            side(c, &item, old, D_NONE);
            tx(&item, "-");
            side(c, &item, now, D_NONE);
            out_put(c, &o, &item);
        }
        out_end(c, &o);
        more += o.dropped;
    }
    pl_begin(&sum);
    tx(&sum, PREFIX);
    if (!changed && !lost) {
        tx(&sum, "DRIFT NONE");
    } else {
        tx(&sum, "DRIFT CHANGED=");
        dec(&sum, changed);
        tx(&sum, " LOST=");
        dec(&sum, lost);
    }
    tx(&sum, " CMP=");
    dec(&sum, compared);
    if (more) {
        tx(&sum, " MORE=");
        dec(&sum, more);
    }
    emit(c, &sum, EM_CLOSING);
}

/* ---- Time ---- */

/* Waits `ticks` on the runner's counter: 1 when they have passed; 0 when the counter does not run (it stands still for COUNTER_STUCK_READS reads) or runs backwards; 2 when SPIN_MAX reads did
 * not get there, a counter that moves and still never arrives. The two failures are different statements and print different tokens. */
OUT_OF_LINE int delay_ticks(const struct ctx *c, uint64_t ticks)
{
    uint64_t start = c->counter(), last = start;
    uint32_t same = 0, reads = 0;
    for (;;) {
        uint64_t now = c->counter();
        if (now < start) return 0;
        if (now - start >= ticks) return 1;
        if (now == last) {
            if (++same >= COUNTER_STUCK_READS) return 0;
        } else {
            last = now;
            same = 0;
        }
        if (++reads >= SPIN_MAX) return 2;
    }
}

OUT_OF_LINE void snapshot_two(struct ctx *c)
{
    static const uint8_t s2_windows[3] = {WIN_GCC, WIN_DISPCC, WIN_DPU};
    struct pl_line wait, note;
    int waited;
    if (!c->counter) {
        say(c, "S2 SKIPPED NO_COUNTER", EM_NORMAL);
        return;
    }
    pl_begin(&wait);
    tx(&wait, "NEXT WAIT ");
    dec(&wait, GAP_S);
    tx(&wait, " S");
    if (!say(c, wait.buf, EM_NORMAL)) return;
    waited = delay_ticks(c, (uint64_t)GAP_S * c->hz);
    if (waited != 1) {
        say(c, waited == 2 ? "S2 SKIPPED SPIN" : "S2 SKIPPED NO_COUNTER", EM_NORMAL);
        return;
    }
    c->t_second = c->counter();
    c->dead_s1 = c->dead;
    pl_begin(&note);
    for (unsigned i = 0; i < 3; i++) {
        unsigned win = s2_windows[i], why;
        struct pl_line next;
        if (!window_has_reads(c, win)) continue;
        /* DISPCC is read again only while the display register clock still runs in snapshot 2's own GCC word, the DPU only while snapshot 2's own gate words still say ON. A GCC word is always read. */
        why = win == WIN_DISPCC ? ahb_reason(&c->s[1]) : win == WIN_DPU ? s2_dpu_reason(c) : RS_OPEN;
        if (why) {
            c->s2_skip |= 1u << win;
            gated_block(c, win, why, 1, note.buf);
            pl_begin(&note);
            continue;
        }
        pl_begin(&next);
        tx(&next, "NEXT S2 ");
        tx(&next, window_name[win]);
        if (note.len) {
            tx(&next, " ");
            tx(&next, note.buf);
        }
        /* No NEXT line, no read, as in snapshot 1. */
        if (!say(c, next.buf, EM_NORMAL)) {
            c->blocks |= 1u << win;
            c->s2_skip |= 1u << win;
            continue;
        }
        pl_begin(&note);
        read_window(c, win);
        if (win == WIN_DPU) s2_line(c);
        /* What this block said after the wait rides the next NEXT line, so that it is on the film before the next load, which is the one most likely to hang. */
        if (win != WIN_DPU) {
            unsigned n = changes_in(c, win);
            tx(&note, window_name[win]);
            tx(&note, "=");
            if (n) {
                tx(&note, "CHG:");
                dec(&note, n);
            } else {
                tx(&note, "SAME");
            }
        }
    }
    drift_report(c);
}

OUT_OF_LINE void header_lines(struct ctx *c, uint32_t width, uint32_t height, uint32_t stride, uint32_t format)
{
    struct pl_line line, item;
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "READ ONLY EL=2 HZ=");
    hx(c, &line, c->hz);
    if (c->hz_default) tx(&line, " DEFAULT");
    tx(&line, " GAP=");
    dec(&line, GAP_S);
    tx(&line, " S");
    emit(c, &line, EM_NORMAL);
    say(c, "KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=BIT 31 NOT TRUSTED NO STORE NO AUX NO IRQ STATUS", EM_NORMAL);
    /* The mode the runner drew this page in (the GOP, from the arguments): what the host side compares the interface's active window with. The framebuffer itself is never touched. */
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "GOP W=");
    dec(&line, width);
    tx(&line, " H=");
    dec(&line, height);
    tx(&line, " STRIDE=");
    dec(&line, stride);
    tx(&line, " FMT=");
    dec(&line, format);
    emit(c, &line, EM_NORMAL);
    /* The two MAP lines: the bases the loads use, from the table the loads use, and the geometry of the interface and the CTL pages inside the DPU window. No load. */
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "MAP");
    for (unsigned win = 0; win < WINDOWS; win++) {
        key(&item, window_name[win]);
        hx(c, &item, windows[win].base);
        put_item(c, &line, &item);
    }
    emit(c, &line, EM_NORMAL);
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "MAP INTF=");
    dec(&line, INTF_INDEX);
    tx(&line, " AT=");
    hx(c, &line, INTF_PAGE_OFF);
    tx(&line, " CTL=");
    hx(c, &line, CTL_FIRST_OFF);
    tx(&line, " STEP=");
    hx(c, &line, CTL_STEP);
    tx(&line, " REG=");
    hx(c, &line, CTL_INTF_ACTIVE_OFF);
    emit(c, &line, EM_NORMAL);
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct ctx c;
    struct pl_line line;
    uint64_t hz;
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    for (size_t i = 0; i < sizeof c; i++) ((volatile uint8_t *)&c)[i] = 0;
    c.puts = a->ops.puts;
    c.hex = a->ops.hex;
    c.load32 = a->ops.load32;
    c.counter = a->ops.counter;
    /* DX_UNK is the zero verdict, so the zeroing above already says it; the assignment keeps the closed default from resting on that. */
    c.disp = DX_UNK;
    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {
        say(&c, "SKIPPED_NOT_AT_EL2", EM_CLOSING);
        return 0;
    }
    if (!c.load32) {
        say(&c, "REFUSED_NO_LOAD32", EM_CLOSING);
        return Q1N1_PAYLOAD_RET_BAD_ARGS;
    }
    hz = SYSREG(cntfrq_el0);
    c.hz_default = hz < COUNTER_HZ_MIN || hz > COUNTER_HZ_MAX;
    c.hz = c.hz_default ? COUNTER_HZ_DEFAULT : (uint32_t)hz;

    header_lines(&c, a->fb_width, a->fb_height, a->fb_stride, a->fb_format);

    c.t_first = c.counter ? c.counter() : 0;
    snapshot_one(&c);
    snapshot_two(&c);

    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "END LOADS=");
    dec(&line, c.loads);
    tx(&line, " FAULTS=");
    dec(&line, c.faults);
    tx(&line, " SKIPS=");
    dec(&line, c.skips);
    tx(&line, " BLK=");
    num(&c, &line, c.blocks);
    tx(&line, " CUTS=");
    dec(&line, c.cuts);
    tx(&line, " GAP_MS=");
    dec(&line, c.t_second > c.t_first ? (c.t_second - c.t_first) * 1000u / c.hz : 0);
    tx(&line, " LINES=");
    dec(&line, c.lines + 1u);
    emit(&c, &line, EM_CLOSING);
    return 0;
}
