/* SPDX-License-Identifier: MIT */
/* Payload "gpusnap": a read-only look at the clock and power state of the Adreno X1-85 of the Surface Pro 11, before anything is written (stage S0 of the first-contact plan,
 * docs/SP11-GPU-PORT-PLAN.md section 7.1 of the Snapintosh tree; docs/SP11-PAYLOAD-GPUSNAP.md has the registers with their file:line and evidence labels, the page, the gates and what
 * each outcome would mean). Nothing of the GPU side has ever been read on the unit: whether any of it aborts, hangs or raises an SError is UNKNOWN, and a load that hangs the bus is
 * not recovered by anything, so the order of the reads is the safety argument. The GCC words come first and need no gate; GPUCC is read only if the GPU's CFG AHB branch clock reads
 * as running; what lies behind the CX power domain (CX_MISC, the GMU, the RSC and the GPU SMMU) only if the CX verdict printed as the R4 line is ON, the SMMU also only if its own four
 * clocks run. A word that was not read, faulted, skipped or all ones never opens a gate; the two data-path clocks MNOC and AXI_NW count as running under Linux's own hardware-gating and
 * halt-skip exemptions (MNOC then prints .ODD, AXI_NW has no token), and the register-path gates (CFGA, the GPUCC clocks AHB, CGMU, CXO, HUB, DMT and the CX GDSC) need proof. No register of
 * the GPU window (RBBM, CP: the GX side) is ever read, and nothing is ever written; the GPUCC and GMU words about GX (GXGD, GXCF, GXGM, GXST) are read.
 *
 * Every access is an ops.load32 (a synchronous abort comes back as a code, never as an exception; an SError is neither caught by it nor printed); the only system registers are CurrentEL
 * and CNTFRQ_EL0. The only stores are to this payload's own stack, and that is the only memory it writes through any pointer: no pointer is kept in memory (the four ops are copied into
 * the context as function pointers, every data pointer is an argument or a local), so that the compiled-code audit (tools/sp11_payload_gpusnap_audit.py) and the binary check of
 * tools/sp11_payload_memcheck.py can both prove it. No tick, no SMC, no HVC, no barrier. Nothing is retried: the first abort in a window ends every later read of it, in the second
 * snapshot too. A block is announced by a `NEXT <block>` line first and is not read at all if the line cannot be printed, so that the last line on the panel names what hung. A line is
 * read whole and printed before the first load of the next one, so that a hang keeps every line before the one it hit.
 *
 * The order inside a block is the safety argument too, because the first abort in a window ends the window. The first load of every block is a word Linux itself reads in that block; the
 * data the run exists for comes next; and the four words no Linux code reads (F_LATE: GMU SYSRESET, CM3_CFG and FW_BUSY, RSC PDC_SEQ_START_ADDR) are read last of all, after the wait and
 * the drift report, each block under its own `NEXT LATE <block>` line, and only while snapshot 2's words still say what opened the block. A gate that could not read its input says so
 * (AHBERR, SMERR, CX=UNK) and never reports the input as off.
 *
 * Page: a header and a legend; for each of GCC, GPUCC, CXMISC, GMU, RSCC and SMMU either `NEXT <block>` and its lines or `<block> GATED BY <why>`; `NEXT WAIT 8 S`; snapshot 2, which reads the
 * GCC and GPUCC words again (GPUCC only if its own CFG AHB word, read just before, still runs) and prints what moved; the late words; the end line. A value below 10 is one digit, a larger
 * one 0X and the fewest upper-case hex digits. At most LINE_CAP lines whatever the hardware says: a field that does not fit is dropped and counted in CUTS, never cut in half. */
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* No MRS can run on a build machine: the host test supplies the register file. */
uint64_t pl_host_sysreg(const char *name);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#include "gpusnap-regs.h"

#define PREFIX "PAYLOAD GPUSNAP "
#define OUT_OF_LINE static __attribute__((noinline))     /* one body per helper: the reviewed binary stays small */

#ifdef GPUSNAP_SHIPPED_CAPS
_Static_assert(HEADER_LINES + NEXT_LINES + TABLE_LINES + EXTRA_LINES + S2_NEXT_LINES + LATE_LINES + CLOSING_LINES <= LINE_CAP, "gpusnap: the page with every gate open fits the line cap");
_Static_assert(S1_LOADS + S2_LOADS + LATE_LOADS <= LOAD_CAP, "gpusnap: the loads of the three phases fit the load cap");
#endif

enum { RD_OK, RD_RANGE, RD_ALIGN, RD_DEAD, RD_BUDGET, RD_FAULT };
/* The state of one value: V_NONE not read, V_NA refused, V_SKIP not read after an abort in its window, V_GATED not read because its block's gate was closed (a gated block prints one line and no
 * value, so this state is never printed). */
enum { V_NONE, V_OK, V_FAULT, V_SKIP, V_NA, V_BUDGET, V_GATED };

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
    uint32_t read_mask;             /* a bit per window whose snapshot-1 read was begun (its NEXT line went out): the late phase adds to those and to no others */
    uint32_t s2_ran;                /* snapshot 2 was taken: its words are the state the late phase judges */
    uint32_t cx;                    /* the CX verdict of snapshot 1 (CX_*) */
    uint32_t clk_mask, sm_mask;     /* the clocks of the GMU node and of the SMMU node that run, one bit each in the order of gpusnap-regs.h */
    uint64_t t_first, t_second;
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

/* A line counts against LINE_CAP. Three classes: the ordinary lines keep back what the late phase and the closing lines need; the late lines (a NEXT LATE line and the words under it) may use
 * what is kept for them, and the closing lines (the drift summary and the end line) what is left, so that the end line is never crowded out by the lines before it. */
enum { EM_NORMAL, EM_CLOSING, EM_LATE };
#define NORMAL_LIMIT (LINE_CAP > CLOSING_LINES + LATE_LINES ? LINE_CAP - CLOSING_LINES - LATE_LINES : 0u)
OUT_OF_LINE int emit(struct ctx *c, const struct pl_line *line, unsigned kind)
{
    if (c->lines >= (kind == EM_CLOSING ? LINE_CAP : kind == EM_LATE ? LINE_CAP - 1u : NORMAL_LIMIT)) {
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

/* The text of one value: number (below 10 one digit) and, for a branch clock or a GDSC status word, the decode of its bit 31 (.OFF is bit 31 set; .ON is bit 31 clear with CLK_ENABLE set); or why there
 * is no value. A decode is printed only where it can be taken at its word, and `.ODD` marks the cell where it cannot (read the raw word beside it): a word of all ones is what a failed read returns;
 * CLK_OFF clear with CLK_ENABLE clear is a clock that says it runs without being enabled, which is what a window of zeros reads; a CLK_OFF with HW_CTL set on a clock that has the bit is hardware
 * gating, which Linux does not judge (clk-branch.c:17-27, 72); a CLK_OFF with an NoC FSM status of ON counts as on for Linux (clk-branch.c:54-58). This is the decode only: whether a clock runs
 * is clock_runs()'s, which does not change with it. */
OUT_OF_LINE int cell_is_odd(uint32_t w, unsigned flags)
{
    if (w == 0xffffffffu) return 1;
    if (!(w >> CBCR_CLK_OFF_BIT & 1)) return !(w >> CBCR_ENABLE_BIT & 1);
    if ((flags & F_HWCG) && (w >> CBCR_HW_CTL_BIT & 1)) return 1;
    return (w >> CBCR_FSM_SHIFT & CBCR_FSM_MASK) == CBCR_FSM_ON;
}

OUT_OF_LINE void side(const struct ctx *c, struct pl_line *line, const struct val *v, unsigned decode, unsigned flags)
{
    switch (v->st) {
    case V_OK:
        num(c, line, v->v);
        /* CLK_OFF of a branch clock, with the modes that make it untrustworthy (cell_is_odd) */
        if (decode == D_CBCR) tx(line, cell_is_odd(v->v, flags) ? ".ODD" : v->v >> CBCR_CLK_OFF_BIT & 1 ? ".OFF" : ".ON");
        /* ROOT_OFF of a root clock generator's command word (clk-rcg2.c:33-39): the NoC FSM and hardware gating modes are a branch clock's and do not exist there */
        if (decode == D_RCGCMD) tx(line, v->v == 0xffffffffu ? ".ODD" : v->v >> CBCR_CLK_OFF_BIT & 1 ? ".OFF" : ".ON");
        /* a GDSC's PWR_ON */
        if (decode == D_PWR) tx(line, v->v == 0xffffffffu ? ".ODD" : v->v >> GDSC_PWR_ON_BIT & 1 ? ".ON" : ".OFF");
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
    else side(c, &item, &field, D_NONE, 0);
    put_item(c, line, &item);
}

OUT_OF_LINE void put_reg(struct ctx *c, struct pl_line *line, const struct snap *s, unsigned id)
{
    const struct reg *r = &regs[id];
    const struct val *v = &s->v[id];
    struct pl_line item;
    if (!(r->flags & F_QUIET)) {
        key(&item, r->key);
        side(c, &item, v, r->dec, r->flags);
        put_item(c, line, &item);
    }
    switch (r->dec) {
    case D_GDSCR:
        put_bits(c, line, "SC", v, GDSC_SW_COLLAPSE_BIT, 1);
        put_bits(c, line, "HW", v, GDSC_HW_CONTROL_BIT, 1);
        break;
    case D_GXCFG:
        put_bits(c, line, "UP", v, GXCFG_UP_BIT, 1);
        put_bits(c, line, "DN", v, GXCFG_DOWN_BIT, 1);
        break;
    case D_VOTE:
        put_bits(c, line, "CPH", v, VOTE_CPH_BIT, 1);
        put_bits(c, line, "DIV", v, VOTE_DIV_BIT, 1);
        break;
    case D_RCGCFG:
        put_bits(c, line, "S", v, RCG_SRC_SHIFT, RCG_SRC_MASK);
        break;
    case D_GXST:
        /* The GMU's own word for whether the GX domain is up (a6xx_gmu.c:121-136): both of bits 1:0 clear is on. The A7XX layout defines those two bits only, so a word with others set (or all
         * ones) is not taken at its word: GX=ODD. */
        key(&item, "GX");
        if (v->st == V_OK) tx(&item, v->v & ~GXST_OFF_MASK ? "ODD" : v->v & GXST_OFF_MASK ? "OFF" : "ON");
        else side(c, &item, v, D_NONE, 0);
        put_item(c, line, &item);
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

/* One value: its load, or the reason there is none. */
OUT_OF_LINE void read_row(struct ctx *c, struct val *v, unsigned id)
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

/* A branch clock runs when its word was read, CLK_ENABLE is set and CLK_OFF is clear: positive proof, as Linux asks for when it enables one (clk-branch.c:54-58) but without its
 * extra readings, which would open a gate on less. The exceptions are the ones Linux itself makes: a clock whose halt check is BRANCH_HALT_SKIP has no status bit to look at
 * (F_NOHALT: enabled is all that can be said), and one in hardware gated mode (F_HWCG, bit 1 set) is not judged by CLK_OFF (clk-branch.c:17-27, 72). A NoC FSM status of ON with
 * CLK_OFF set is not taken as running: a gate is opened only on proof. */
OUT_OF_LINE int clock_runs(const struct val *v, unsigned flags)
{
    if (!word_ok(v) || !(v->v >> CBCR_ENABLE_BIT & 1)) return 0;
    if (flags & F_NOHALT) return 1;
    if (!(v->v >> CBCR_CLK_OFF_BIT & 1)) return 1;
    return (flags & F_HWCG) && (v->v >> CBCR_HW_CTL_BIT & 1);
}

OUT_OF_LINE int row_runs(const struct snap *s, unsigned id)
{
    return clock_runs(&s->v[id], regs[id].flags);
}

/* R4. The CX verdict from the words of a snapshot: ON only if the CX GDSC's status word has PWR_ON set (gdsc.c:61-91, gpucc-x1e80100.c:534) while neither SW_COLLAPSE nor HW_CONTROL
 * is set in its GDSCR (under hardware control the GMU or the RSC may collapse it between two reads) and all seven clocks of the GMU node run; HWCTL, OFF and PART say which of those
 * failed first; UNK is any input that was not read or reads as a failed read does. It also leaves the masks of the two nodes' clocks for the page and for the SMMU gate. */
OUT_OF_LINE unsigned cx_eval(const struct snap *s, uint32_t *clk, uint32_t *sm)
{
    static const uint8_t gmu_clocks[GMU_CLOCKS] = {R_AHB, R_CGMU, R_CXO, R_AXI, R_MNOC, R_HUB, R_DMT};
    static const uint8_t smmu_clocks[SMMU_CLOCKS] = {R_HLOS, R_MNOC, R_SNOC, R_AHB};
    const struct val *gdscr = &s->v[R_CXGD], *status = &s->v[R_CXHW];
    unsigned known = word_ok(gdscr) && word_ok(status);
    *clk = *sm = 0;
    for (unsigned i = 0; i < GMU_CLOCKS; i++) {
        known &= (unsigned)word_ok(&s->v[gmu_clocks[i]]);
        *clk |= (uint32_t)row_runs(s, gmu_clocks[i]) << i;
    }
    for (unsigned i = 0; i < SMMU_CLOCKS; i++) *sm |= (uint32_t)row_runs(s, smmu_clocks[i]) << i;
    if (!known) return CX_UNK;
    if (gdscr->v >> GDSC_HW_CONTROL_BIT & 1) return CX_HWCTL;
    if ((gdscr->v >> GDSC_SW_COLLAPSE_BIT & 1) || !(status->v >> GDSC_PWR_ON_BIT & 1)) return CX_OFF;
    return *clk == (1u << GMU_CLOCKS) - 1u ? CX_ON : CX_PART;
}

OUT_OF_LINE void cx_gate(struct ctx *c, const struct snap *s)
{
    c->cx = cx_eval(s, &c->clk_mask, &c->sm_mask);
}

/* The CFG AHB gate of a snapshot (gcc-x1e80100.c:7451): open when the word reads as running; AHB when it was read and does not; AHBERR when it was not read (an abort, a skip, all ones), which is
 * not the same statement: a failed gate read is never reported as the thing it gates on. */
OUT_OF_LINE unsigned ahb_reason(const struct snap *s)
{
    if (row_runs(s, R_CFGA)) return RS_OPEN;
    return word_ok(&s->v[R_CFGA]) ? RS_AHB : RS_AHB_ERR;
}

/* Why a window is not read now, 0 if it may be. GCC is always on. GPUCC needs the CFG AHB branch to run. The three CX blocks need GPUCC to have been read and the verdict ON; the SMMU also needs
 * its own four clocks (hamoa.dtsi:4268-4275), and says SMERR rather than SMCLK when one of them could not be read. */
OUT_OF_LINE unsigned gate_reason(const struct ctx *c, unsigned win)
{
    const struct snap *s = &c->s[0];
    unsigned why;
    if (win == WIN_GCC) return RS_OPEN;
    why = ahb_reason(s);
    if (why || win == WIN_GPUCC) return why;
    if (c->cx != CX_ON) return RS_CX_UNK - CX_UNK + c->cx;
    if (win == WIN_SMMU && c->sm_mask != (1u << SMMU_CLOCKS) - 1u) {
        return word_ok(&s->v[R_HLOS]) && word_ok(&s->v[R_MNOC]) && word_ok(&s->v[R_SNOC]) && word_ok(&s->v[R_AHB]) ? RS_SMCLK : RS_SM_ERR;
    }
    return RS_OPEN;
}

/* Why the late blocks are not read now, 0 if they may be: the state that opened them in snapshot 1 must still hold after the wait, judged by snapshot 2's own words (its CFG AHB word, then the CX
 * verdict over its GCC and GPUCC words). With no snapshot 2 there is no fresh state to judge by, and the late words are not read. A word snapshot 2 could not read is not a clock that stopped: the
 * reason is AHBERR or CX=UNK. */
OUT_OF_LINE unsigned late_reason(const struct ctx *c)
{
    uint32_t clk, sm;
    unsigned why, cx;
    if (!c->s2_ran) return RS_NO_S2;
    why = ahb_reason(&c->s[1]);
    if (why) return why;
    cx = cx_eval(&c->s[1], &clk, &sm);
    return cx == CX_ON ? RS_OPEN : RS_CX_UNK - CX_UNK + cx;
}

/* ---- The lines of snapshot 1 ---- */

/* R4: the verdict and the words it was made of, printed as soon as they have gone out. */
OUT_OF_LINE void r4_line(struct ctx *c, const struct snap *s)
{
    struct pl_line line, item;
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "R4 CX=");
    tx(&line, cx_name[c->cx]);
    if (c->cx != CX_UNK) {
        put_bits(c, &line, "PWR", &s->v[R_CXHW], GDSC_PWR_ON_BIT, 1);
        put_bits(c, &line, "SC", &s->v[R_CXGD], GDSC_SW_COLLAPSE_BIT, 1);
        put_bits(c, &line, "HW", &s->v[R_CXGD], GDSC_HW_CONTROL_BIT, 1);
        key(&item, "CLK");
        hx(c, &item, c->clk_mask);
        put_item(c, &line, &item);
        key(&item, "SM");
        hx(c, &item, c->sm_mask);
        put_item(c, &line, &item);
    }
    emit(c, &line, 0);
}

/* The TCS words' bit 0 is set when no RPMh vote is outstanding (a6xx_gmu.c:1111-1135): one bit each, T0 lowest, so that all idle is 0X3FF. A word of all ones is what a failed read returns, not ten
 * idle TCSs: the mask is then not taken at its word (TCS=ODD), and a word that was not read shows why, as the register does. */
OUT_OF_LINE void put_tcs(struct ctx *c, struct pl_line *line, const struct snap *s)
{
    struct pl_line item;
    struct val mask;
    unsigned odd = 0;
    mask.v = 0;
    mask.st = V_OK;
    mask.code = mask.pad = 0;
    for (unsigned i = 0; i < TCS_WORDS; i++) {
        const struct val *t = &s->v[R_T0 + i];
        if (t->st != V_OK && mask.st == V_OK) {
            mask.st = t->st;
            mask.code = t->code;
        }
        if (mask.st == V_OK) mask.v |= (t->v & 1u) << i;
        odd |= t->st == V_OK && t->v == 0xffffffffu;
    }
    key(&item, "TCS");
    if (odd && mask.st == V_OK) tx(&item, "ODD");
    else side(c, &item, &mask, D_NONE, 0);
    put_item(c, line, &item);
}

/* The ID words of the GPU SMMU as fields (arm-smmu.h:55-72): the number of stream matching groups and of context banks, the page size and how many pages the register space has,
 * the page table formats the SMMU walks (bit 2 64K, bit 1 16K, bit 0 4K) and the size codes of the intermediate, output and upstream bus addresses, printed as the codes they
 * are. Printed only for ID words that read as an SMMU's and not as a failed read. */
OUT_OF_LINE void smmu_line(struct ctx *c, const struct snap *s)
{
    const struct val *id0 = &s->v[R_ID0], *id1 = &s->v[R_ID1], *id2 = &s->v[R_ID2];
    struct pl_line line, item;
    if (!word_ok(id0) || !word_ok(id1) || !word_ok(id2)) return;
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "SMMU");
    put_bits(c, &line, "SMRG", id0, 0, SMMU_ID0_NUMSMRG_MASK);
    put_bits(c, &line, "CB", id1, 0, SMMU_ID1_NUMCB_MASK);
    key(&item, "PG");
    tx(&item, id1->v >> SMMU_ID1_PAGESIZE_BIT & 1 ? "64K" : "4K");
    put_item(c, &line, &item);
    put_bits(c, &line, "NPG", id1, SMMU_ID1_NUMPAGENDXB_SHIFT, 7);
    put_bits(c, &line, "PT", id2, SMMU_ID2_PTFS_SHIFT, 7);
    put_bits(c, &line, "IAS", id2, 0, 15);
    put_bits(c, &line, "OAS", id2, SMMU_ID2_OAS_SHIFT, 15);
    put_bits(c, &line, "UBS", id2, SMMU_ID2_UBS_SHIFT, 15);
    emit(c, &line, 0);
}

/* One line: its rows are read, then the line goes out (as a line of kind `kind`), then whatever the line's `after` asks for. */
OUT_OF_LINE void do_line(struct ctx *c, struct snap *s, unsigned li, unsigned kind)
{
    const struct line_def *d = &lines[li];
    struct pl_line line;
    for (unsigned id = d->first; id < d->end; id++) read_row(c, &s->v[id], id);
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, d->head);
    for (unsigned id = d->first; id < d->end; id++) put_reg(c, &line, s, id);
    if (li == L_RSC) put_tcs(c, &line, s);
    emit(c, &line, kind);
    if (d->after == A_R4) {
        cx_gate(c, s);
        r4_line(c, s);
    } else if (d->after == A_SMMU) {
        smmu_line(c, s);
    }
}

/* A block (or, with `head`, a late group) that is not read, and why: one line, and every value of it is marked as not read for the reasons it was not. */
OUT_OF_LINE void gated_block(struct ctx *c, unsigned win, unsigned why, const char *head, unsigned kind)
{
    struct pl_line line;
    if (kind == EM_NORMAL) {
        for (unsigned id = 0; id < R_COUNT; id++) {
            if (regs[id].win == win) c->s[0].v[id].st = V_GATED;
        }
    }
    c->blocks |= 1u << win;
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, head);
    tx(&line, " GATED BY ");
    tx(&line, reason_name[why]);
    emit(c, &line, kind);
}

OUT_OF_LINE void snapshot_one(struct ctx *c)
{
    for (unsigned win = 0; win < WINDOWS; win++) {
        struct pl_line next;
        unsigned why = gate_reason(c, win);
        if (why) {
            gated_block(c, win, why, window_name[win], EM_NORMAL);
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
        c->read_mask |= 1u << win;
        for (unsigned li = 0; li < LINES; li++) {
            if (lines[li].win == win && !lines[li].late) do_line(c, &c->s[0], li, EM_NORMAL);
        }
    }
}

/* ---- The late phase: the words no Linux code reads ---- */

/* The words that only Linux's writes (or nobody) name are read last: after the wait and the drift report, so that a hang there costs neither, and each block under a `NEXT LATE <block>` line
 * of its own so that the film names it. Only blocks snapshot 1 read are visited, and only while snapshot 2's words still say what opened them. A window that aborted in the meantime has no load
 * to announce: its late words print as SKIP. */
OUT_OF_LINE void late_reads(struct ctx *c)
{
    unsigned why = RS_OPEN;
    for (unsigned li = 0; li < LINES; li++) {
        const struct line_def *d = &lines[li];
        if (!d->late || !(c->read_mask >> d->win & 1)) continue;
        if (!why) why = late_reason(c);
        if (why) {
            gated_block(c, d->win, why, d->head, EM_LATE);
            continue;
        }
        if (!(c->dead >> d->win & 1)) {
            struct pl_line next;
            pl_begin(&next);
            tx(&next, "NEXT ");
            tx(&next, d->head);
            if (!say(c, next.buf, EM_LATE)) {
                c->blocks |= 1u << d->win;
                continue;
            }
        }
        do_line(c, &c->s[0], li, EM_LATE);
    }
}

/* ---- Snapshot 2: the GCC and GPUCC words again, then a drift report ---- */

/* A value that snapshot 2 reads again and the drift report compares: a GCC or GPUCC word that snapshot 1 read, in a window that had not aborted by the end of snapshot 1 and that
 * snapshot 2 does not leave out. */
OUT_OF_LINE int revisit(const struct ctx *c, unsigned id)
{
    unsigned win = regs[id].win;
    if (win != WIN_GCC && win != WIN_GPUCC) return 0;
    if (c->s[0].v[id].st != V_OK) return 0;
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
        if (regs[id].win == win && revisit(c, id)) read_row(c, &c->s[1].v[id], id);
    }
}

/* How many of the values of a window that snapshot 2 read again are not what snapshot 1 read (a value that could not be read again counts). */
OUT_OF_LINE unsigned changes_in(const struct ctx *c, unsigned win)
{
    unsigned n = 0;
    for (unsigned id = 0; id < R_COUNT; id++) {
        if (regs[id].win == win && revisit(c, id)) n += !(c->s[1].v[id].st == V_OK && c->s[1].v[id].v == c->s[0].v[id].v);
    }
    return n;
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
        emit(c, &o->line, 0);
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

/* DG holds what moved in GCC and DC what moved in GPUCC: KEY=OLD-NEW, where NEW may be the fault, or the skip after one, that replaced the value. CHANGED counts the values that
 * differ, LOST those snapshot 2 could not read; CMP the values snapshot 1 read in a window that had not aborted by then and that snapshot 2 visited, all compared. */
OUT_OF_LINE void drift_report(struct ctx *c)
{
    static const char group[2][4] = {"DG", "DC"};
    static const uint8_t group_window[2] = {WIN_GCC, WIN_GPUCC};
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
            if (regs[id].win != group_window[g] || !revisit(c, id)) continue;
            compared++;
            if (now->st == V_OK && now->v == old->v) continue;
            if (now->st == V_OK) changed++;
            else lost++;
            key(&item, regs[id].key);
            side(c, &item, old, D_NONE, 0);
            tx(&item, "-");
            side(c, &item, now, D_NONE, 0);
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
    emit(c, &sum, 1);
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
    c->s2_ran = 1;
    pl_begin(&note);
    for (unsigned win = WIN_GCC; win <= WIN_GPUCC; win++) {
        struct pl_line next;
        unsigned gated;
        if (!window_has_reads(c, win)) continue;
        /* GPUCC is read again only while its own gate still holds: S2's CFG AHB word, read just before, says so. A GCC word is always read. */
        gated = win == WIN_GPUCC && !row_runs(&c->s[1], R_CFGA);
        pl_begin(&next);
        tx(&next, gated ? "S2 " : "NEXT S2 ");
        tx(&next, window_name[win]);
        if (gated) tx(&next, " SKIP GATED");
        if (note.len) {
            tx(&next, " ");
            tx(&next, note.buf);
        }
        if (gated) {
            c->blocks |= 1u << win;
            c->s2_skip |= 1u << win;
        }
        if (!say(c, next.buf, 0)) continue;
        pl_begin(&note);
        if (gated) continue;
        read_window(c, win);
        if (win == WIN_GCC) {
            /* What GCC said after the wait rides the next line, so that it is on the film before the load that is most likely to hang. */
            unsigned n = changes_in(c, win);
            tx(&note, "GCC=");
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
    /* CX_UNK is the zero verdict, so the zeroing above already says it; the assignment keeps the closed default from resting on that. */
    c.cx = CX_UNK;
    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {
        say(&c, "SKIPPED_NOT_AT_EL2", 1);
        return 0;
    }
    if (!c.load32) {
        say(&c, "REFUSED_NO_LOAD32", 1);
        return Q1N1_PAYLOAD_RET_BAD_ARGS;
    }
    hz = SYSREG(cntfrq_el0);
    c.hz_default = hz < COUNTER_HZ_MIN || hz > COUNTER_HZ_MAX;
    c.hz = c.hz_default ? COUNTER_HZ_DEFAULT : (uint32_t)hz;

    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "READ ONLY EL=2 HZ=");
    hx(&c, &line, c.hz);
    if (c.hz_default) tx(&line, " DEFAULT");
    tx(&line, " GAP=");
    dec(&line, GAP_S);
    tx(&line, " S");
    emit(&c, &line, 0);
    say(&c, "KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=BIT 31 NOT TRUSTED NO GPU-WINDOW REGISTER IS READ", 0);

    c.t_first = c.counter ? c.counter() : 0;
    snapshot_one(&c);
    snapshot_two(&c);
    late_reads(&c);

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
    emit(&c, &line, 1);
    return 0;
}
