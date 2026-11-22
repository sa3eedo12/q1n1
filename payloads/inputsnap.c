/* SPDX-License-Identifier: MIT */
/* Payload "inputsnap": a read-only snapshot, before anything is started, of what the Surface Pro 11's two input engines and the pins and interrupts around them
 * look like: QUP wrapper 0 engine 2 (the UART of the Surface Aggregator Module, whose embedded controller is INFERRED to carry the Type Cover's keyboard and touchpad) and
 * QUP wrapper 1 engine 2 (the SPI engine of the touch controller), the clock words that decide whether either may be read at all, the GIC's state for their interrupts and the
 * pin controller's words for their pins (docs/SP11-PAYLOAD-INPUTSNAP.md has the page, what each token means and what it does not answer; its companion
 * docs/SP11-PAYLOAD-INPUTSNAP-REGISTERS.md the registers with their file:line and evidence labels;
 * the stick name of the binary is INPUTSNP.BIN, because the runner's names are 8.3).
 * Nobody has read any of it on this unit: whether firmware left the engines clocked and configured after the hand-off is UNKNOWN, and a read of an engine without its
 * clocks may hang the bus, which no guard recovers. This payload stores nothing at all.
 *
 * Every access is an ops.load32 (a synchronous abort comes back as a code, never as an exception; an SError is neither caught by it nor printed); the only system
 * registers are CurrentEL and CNTFRQ_EL0. The only stores are to this payload's own stack, and that is the only memory it writes through any pointer: no pointer is ever
 * kept in memory (the four ops are copied into the context as function pointers, every data pointer is an argument or a local), so that the compiled-code audit
 * (tools/sp11_payload_inputsnap_audit.py) and the binary check of tools/sp11_payload_memcheck.py can both prove it. No tick, no SMC, no HVC, no barrier. Only the registers
 * of the table are read, each at most once per snapshot, and none of the two FIFO windows of an engine (0x700-0x73f and 0x780-0x7bf: a read of the receive FIFO pops
 * bytes) is in it. Nothing is retried: the first abort in a window (in GCC: in a group of its words) ends every later read of it, for the second snapshot too.
 *
 * Order, which is the order of what one abort or hang costs: snapshot 1 reads only registers a pinned Linux driver reads (the clock words first, then the GIC, then each
 * engine, the pin controller last); the wait, snapshot 2 and its drift report follow; the registers no pinned driver reads (the table's F_FRESH rows) come last of all, in three
 * late blocks (X U2, X S10, X GIC), so that a hang on a word nobody has read through Linux loses nothing the run exists for. Every block is announced by a `NEXT <block>` line
 * before its first load, and is not read at all if the line cannot be printed (a late block also not if no line of values would fit after it), so that the last line on the
 * panel names what hung. The first load of a block is a register Linux reads; the late blocks hold none. An engine is read only if every one of its clock words (the wrapper's
 * two AHB clocks and core clock, the engine's own clock, and for the SPI engine its QSPI clock) has been read and does not say the clock is stopped (an AHB clock in hardware
 * gating mode counts as running only with its vote set, and no clock word counts when the three vote words read zero): otherwise the block is
 * one line, `<engine> GATED OFF`, or `GATED ERR` when a word could not be read (fail closed: an unread word counts as stopped, but is not reported as a clock that says so).
 * Each line goes out as soon as its loads are done, so that a hang keeps what was printed before it; snapshot 2 says what it found in GCC on the next NEXT line and gates the
 * engine on its own clock words again, and the late blocks gate on the freshest clock words there are.
 *
 * Page: two header lines; the five blocks of snapshot 1 after their NEXT lines; `NEXT WAIT 8 S`; snapshot 2 (NEXT S2 GCC, U2, TLMM: only the rows flagged F_S2, and only in a
 * window that has not aborted), printed as a drift report against snapshot 1 (what moved, as KEY=OLD-NEW: the engine's words DU, the pins DT, the clock words DG, in that
 * order) and not as a second page; the three late blocks; the end line. A value below 10 is one digit, a larger one 0X and the fewest upper-case hex digits; a decode that
 * rests on a mode word of the page (a FIFO count, CTS) says ODD when that word does not say it holds. At most LINE_CAP lines whatever the hardware says: a block keeps to what
 * the later ones need (room_for()) and a field that does not fit is dropped and counted in CUTS, never cut in half. */
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* No MRS can run on a build machine: the host test supplies the register file. */
uint64_t pl_host_sysreg(const char *name);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#include "inputsnap-regs.h"

#define PREFIX "PAYLOAD INPUTSNAP "
#define OUT_OF_LINE static __attribute__((noinline))     /* one body per helper: the reviewed binary stays small */

#ifdef INPUTSNAP_SHIPPED_CAPS
_Static_assert(HEADER_LINES + 2u * BLOCKS + S2_NEXT_LINES + DRIFT_LINES + CLOSING_LINES <= LINE_CAP, "inputsnap: the shortest page fits the line cap");
_Static_assert(S1_LOADS_MAX + S2_LOADS_MAX + X_LOADS_MAX <= LOAD_CAP, "inputsnap: the loads of both snapshots and of the late blocks fit the load cap");
#endif
/* The first five blocks are read from the window of their own number; the late blocks are the late half of a window (block_win). */
_Static_assert(B_GCC == WIN_GCC && B_GIC == WIN_GIC && B_U2 == WIN_U2 && B_S10 == WIN_S10 && B_TLMM == WIN_TLMM, "inputsnap: block and window numbers agree");

enum { RD_OK, RD_RANGE, RD_ALIGN, RD_DEAD, RD_BUDGET, RD_FAULT };
/* The state of one value: V_NONE not read (snapshot 2 reads only what snapshot 1 read), V_SKIP not read after an abort, V_GATED not read because the engine's clock words
 * do not all read ON. */
enum { V_NONE, V_OK, V_FAULT, V_SKIP, V_BUDGET, V_GATED };
/* What a branch clock word says (clock_state()), and what the clock words of an engine say together (engine_gate()): OFF is a word that read and says stopped, or says hardware
 * gating with no vote behind it, ERR is a word that did not read, or read as nothing a clock word can be, or the vote evidence it needs did not read or is absent, and no word that
 * says stopped. */
enum { CK_ON, CK_OFF, CK_HW, CK_ODD };
enum { GATE_OPEN, GATE_OFF, GATE_ERR };
/* How the wait ended: the counter reached the gap, it does not run (it stands still or runs backwards), or it runs and SPIN_MAX reads were not enough. */
enum { W_DEAD, W_DONE, W_SPIN };

struct val {
    uint64_t v;
    uint32_t st, code;
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
    uint32_t dead, dead_s1;         /* a bit per (window, group) in which a load aborted, now and when snapshot 1 ended */
    uint32_t s2_skip;               /* a bit per window snapshot 2 did not visit because the engine's clock words went off */
    uint32_t s2_ran;                /* snapshot 2 read its clock words (the wait ended on the counter): the late blocks then gate on those words, else on snapshot 1's */
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

/* A line counts against LINE_CAP, and leaves `keep` lines of it free for the lines that come after it: the lines of the snapshots keep the drift summary and the end line
 * (KEEP_DATA), the lines of the late blocks the end line (KEEP_X), the summary and the end line themselves nothing (KEEP_NONE). */
OUT_OF_LINE int emit(struct ctx *c, const struct pl_line *line, unsigned keep)
{
    if (c->lines + keep >= LINE_CAP) {
        c->cuts++;
        return 0;
    }
    c->lines++;
    c->puts(line->buf);
    return 1;
}

OUT_OF_LINE int say(struct ctx *c, const char *text, unsigned keep)
{
    struct pl_line line;
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, text);
    return emit(c, &line, keep);
}

/* One group's line(s), packed: PREFIX <head> <fields>. A field that does not fit starts the next line while the group has one left (max_lines); otherwise it is dropped
 * and counted, never cut. */
struct out {
    struct pl_line line;
    char head[8];
    unsigned lines, max_lines, filled, dropped, keep;
};

OUT_OF_LINE void out_start(struct out *o)
{
    pl_begin(&o->line);
    tx(&o->line, PREFIX);
    tx(&o->line, o->head);
    o->filled = 0;
}

OUT_OF_LINE void out_begin(struct out *o, const char *head, unsigned max_lines, unsigned keep)
{
    unsigned i = 0;
    while (i < sizeof o->head - 1 && head[i]) {
        o->head[i] = head[i];
        i++;
    }
    o->head[i] = 0;
    o->lines = 0;
    o->max_lines = max_lines;
    o->dropped = 0;
    o->keep = keep;
    out_start(o);
}

/* Prints the line being packed, if it holds a field, and starts the next. */
OUT_OF_LINE void out_end(struct ctx *c, struct out *o)
{
    if (o->filled) {
        emit(c, &o->line, o->keep);
        o->lines++;
    }
    out_start(o);
}

/* A new line before the next field, when the group has one left. */
OUT_OF_LINE void out_break(struct ctx *c, struct out *o)
{
    if (o->filled && o->lines + 1 < o->max_lines) out_end(c, o);
}

OUT_OF_LINE void out_put(struct ctx *c, struct out *o, const struct pl_line *item)
{
    if (!o->max_lines) {
        o->dropped++;
        c->cuts++;
        return;
    }
    if (o->line.len + 1 + item->len > LINE_FILL) {
        if (o->lines + 1 >= o->max_lines) {
            o->dropped++;
            c->cuts++;
            return;
        }
        out_end(c, o);
        if (o->line.len + 1 + item->len > LINE_FILL) {
            o->dropped++;
            c->cuts++;
            return;
        }
    }
    tx(&o->line, " ");
    tx(&o->line, item->buf);
    o->filled = 1;
}

OUT_OF_LINE void key(struct pl_line *item, const char *name)
{
    pl_begin(item);
    tx(item, name);
    tx(item, "=");
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

/* The first abort ends all reads of its window: whatever stopped one load would stop the next, and nothing is retried. GCC is one flat file of registers that do not all
 * answer alike (a protected one aborts, its neighbour does not), so there an abort ends the reads of its group and the other groups go on. */
OUT_OF_LINE unsigned dead_bit(unsigned win, unsigned grp)
{
    return win == WIN_GCC ? grp : 2u + win;
}

/* A register of a window. A window the table does not have, an offset past the window and one that is not aligned are refused before anything is loaded. */
OUT_OF_LINE int rd32(struct ctx *c, unsigned win, unsigned grp, uint64_t off, uint32_t *value)
{
    int rc;
    *value = 0;
    if (win >= WINDOWS) {
        rc = RD_RANGE;
    } else if (off & 3) {
        rc = RD_ALIGN;
    } else if (off >= windows[win].size || windows[win].size - off < 4) {
        rc = RD_RANGE;
    } else if (c->dead >> dead_bit(win, grp) & 1) {
        rc = RD_DEAD;
    } else {
        rc = load(c, windows[win].base + off, value);
        if (rc == RD_FAULT) c->dead |= 1u << dead_bit(win, grp);
    }
    return rc;
}

OUT_OF_LINE int rd64(struct ctx *c, unsigned win, unsigned grp, uint64_t off, uint64_t *value)
{
    uint32_t lo = 0, hi = 0;
    int rc = rd32(c, win, grp, off, &lo);
    if (!rc) rc = rd32(c, win, grp, off + 4, &hi);
    *value = rc ? 0 : (uint64_t)lo | (uint64_t)hi << 32;
    return rc;
}

/* What a branch clock word says. ON: CLK_OFF (bit 31) clear, or the NoC FSM status (bits 30:28) says ON (2), which is how Linux reads a branch that is being enabled
 * (clk-branch.c, clk_branch2_check_halt). HW: CLK_OFF set, no FSM verdict, and the branch declares a hardware clock gating bit (the four AHB clocks: `hwcg`) with HW_CTL
 * (bit 1) set: Linux does not wait for the halt bit of a branch in hardware gating mode (clk_branch_wait, clk_branch_in_hwcg_mode), so the bit is no verdict (engine_gate asks
 * the clock's vote for one). OFF: CLK_OFF set
 * with neither of those. ODD: all ones, what a failed read returns, which no clock word is. Every branch that declares no hardware gating bit is judged by CLK_OFF alone, even
 * with bit 1 set. */
OUT_OF_LINE unsigned clock_state(const struct val *v, unsigned hwcg)
{
    if (v->v == 0xffffffffu) return CK_ODD;
    if (!(v->v >> 31 & 1) || (v->v >> 28 & 7) == 2) return CK_ON;
    return hwcg && (v->v >> 1 & 1) ? CK_HW : CK_OFF;
}

/* What the clock words of an engine say in a snapshot. An engine whose clock words do not ALL read ON is not read: a load from an engine without its bus or engine clock can
 * hang the SoC and no guard recovers that. A word that did not read (an abort, a skip, a window that was never visited) or that read as nothing a clock word can be is not a
 * clock that is off but one that is unknown, and an unknown clock is not read through either: GATE_ERR, which the page does not call OFF. GATE_OFF only when a word that read
 * says stopped. Only the two engine windows are ever gated.
 * Two readings need more than the clock word, because a clock word alone cannot tell them from what a dead window or an idle clock nobody asked for also reads. `.HW` (CLK_OFF
 * set with HW_CTL, which Linux does not wait on) is a healthy idle clock only if its apps vote is set: with the vote word read and the bit set it counts as running, with the bit clear
 * as stopped, and with the word not read as unknown. And a window that reads zero everywhere shows every branch as running (CLK_OFF clear): when all three vote words read zero there is
 * no vote behind any clock word, and the engine is not read. `votes` is the snapshot that read the vote words (snapshot 1: snapshot 2 and the late blocks do not read them again, so
 * they are as old as the first reading; nothing runs between the two). */
OUT_OF_LINE unsigned engine_gate(const struct snap *s, const struct snap *votes, unsigned win)
{
    unsigned engine = win == WIN_U2 ? GATE_U2 : win == WIN_S10 ? GATE_S10 : 0, off = 0, unknown = 0;
    if (!engine) return GATE_OPEN;
    for (unsigned id = block_first[B_GCC]; id < block_first[B_GCC + 1]; id++) {
        unsigned state;
        if (!(regs[id].gate & engine)) continue;
        if (s->v[id].st != V_OK) {
            unknown = 1;
            continue;
        }
        state = clock_state(&s->v[id], regs[id].flags & F_HWCG);
        if (state == CK_HW) {
            state = CK_ODD;
            for (unsigned k = 0; k < sizeof hw_votes / sizeof hw_votes[0]; k++) {
                const struct val *vote = &votes->v[hw_votes[k].vote];
                if (hw_votes[k].clock != id || vote->st != V_OK) continue;
                state = vote->v >> hw_votes[k].bit & 1 ? CK_ON : CK_OFF;
            }
        }
        off |= state == CK_OFF;
        unknown |= state == CK_ODD;
    }
    if (votes->v[R_G_VT0].st == V_OK && votes->v[R_G_VT1].st == V_OK && votes->v[R_G_VT2].st == V_OK && !(votes->v[R_G_VT0].v | votes->v[R_G_VT1].v | votes->v[R_G_VT2].v)) unknown = 1;
    return off ? GATE_OFF : unknown ? GATE_ERR : GATE_OPEN;
}

/* The page's words for a gated engine: on its own line in snapshot 1 and the late blocks, after SKIP in snapshot 2. */
OUT_OF_LINE void tx_gate(struct pl_line *line, unsigned verdict)
{
    tx(line, verdict == GATE_OFF ? "GATED OFF" : "GATED ERR");
}

/* One value of one row: its load(s), or the reason there is none. The values go into `s`, the clock words that gate an engine are read in `gate` (the same snapshot, except in
 * the late blocks, which gate on the freshest clock words there are). */
OUT_OF_LINE void read_row(struct ctx *c, struct snap *s, const struct snap *gate, unsigned id)
{
    const struct reg *r = &regs[id];
    struct val *v = &s->v[id];
    uint64_t value = 0;
    int rc;
    v->v = 0;
    v->code = 0;
    v->st = V_NONE;
    /* stream_block() and snapshot_two() decide first and say so on the page; this is the check at the load itself, so that no path reaches an engine's registers without it. */
    if (engine_gate(gate, &c->s[0], r->win) != GATE_OPEN) {
        v->st = V_GATED;
        c->blocks |= 1u << r->block;
        return;
    }
    if (r->flags & F_WIDE) {
        rc = rd64(c, r->win, r->grp, r->off, &value);
    } else {
        uint32_t word;
        rc = rd32(c, r->win, r->grp, r->off, &word);
        value = word;
    }
    switch (rc) {
    case RD_OK:
        v->v = value;
        v->st = V_OK;
        break;
    case RD_FAULT:
        v->st = V_FAULT;
        v->code = c->err;
        c->faults++;
        c->blocks |= 1u << r->block;
        break;
    case RD_DEAD:
        v->st = V_SKIP;
        c->skips++;
        c->blocks |= 1u << r->block;
        break;
    case RD_BUDGET:
        v->st = V_BUDGET;
        c->blocks |= 1u << r->block;
        break;
    default:
        break;
    }
}

/* ---- The values: text ---- */

/* The text of one value: a number (below 10 one digit), with the branch-clock verdict (clock_state) for the clock words; or why there is none. */
OUT_OF_LINE void side(const struct ctx *c, struct pl_line *line, const struct val *v, unsigned decode)
{
    switch (v->st) {
    case V_OK:
        num(c, line, v->v);
        if (decode == D_CBCR || decode == D_CBCR_HW) {
            switch (clock_state(v, decode == D_CBCR_HW)) {
            case CK_ON:
                tx(line, ".ON");
                break;
            case CK_OFF:
                tx(line, ".OFF");
                break;
            case CK_HW:
                tx(line, ".HW");
                break;
            default:
                tx(line, ".ODD");
                break;
            }
        }
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
    case V_GATED:
        tx(line, "GATED");
        break;
    default:
        tx(line, "NA");
        break;
    }
}

/* KEY=VALUE, the value being a field of the word (shift and mask) when the row is a bit or a field of one. */
OUT_OF_LINE void put_field(struct ctx *c, struct out *o, const char *name, const struct val *a, unsigned shift, uint64_t mask, unsigned decode)
{
    struct pl_line item;
    struct val x;
    x.st = a->st;
    x.code = a->code;
    x.v = a->v >> shift & mask;
    key(&item, name);
    side(c, &item, &x, decode);
    out_put(c, o, &item);
}

/* A derived item whose mode words say it means nothing here: KEY=ODD, the raw word is on the line before it. */
OUT_OF_LINE void put_odd(struct ctx *c, struct out *o, const char *name)
{
    struct pl_line item;
    key(&item, name);
    tx(&item, "ODD");
    out_put(c, o, &item);
}

/* The FIFO word counts mean something in FIFO mode only: the engine's GENI_IF_DISABLE_RO says the FIFO interface is not disabled (FIFO_IF_DISABLE, bit 0) and
 * SE_GENI_DMA_MODE_EN says DMA is not on (bit 0). Both words are read before the counts, and a count whose mode words did not read is not decoded either. The UART driver's
 * interrupt handler reads the mode word first and decodes the FIFO or the DMA registers by it (gser:1237-1241). */
OUT_OF_LINE int fifo_mode(const struct snap *s, unsigned win)
{
    const struct val *ifd = &s->v[win == WIN_U2 ? R_U_IFD : R_S_IFD], *dma = &s->v[win == WIN_U2 ? R_U_DMA : R_S_DMA];
    return ifd->st == V_OK && dma->st == V_OK && !(ifd->v & 1) && !(dma->v & 1);
}

/* IO2 reads as CTS only on an engine whose firmware is the UART's (protocol 2 in bits 15:8 of the revision word, which was read before). */
OUT_OF_LINE int uart_mode(const struct snap *s)
{
    const struct val *fw = &s->v[R_U_FW];
    return fw->st == V_OK && (fw->v >> 8 & 0xff) == 2;
}

OUT_OF_LINE void put_row(struct ctx *c, struct out *o, const struct snap *s, unsigned id)
{
    const struct reg *r = &regs[id];
    const struct val *v = &s->v[id];
    if (r->dec == D_FIELD) {
        put_field(c, o, reg_key[id], v, r->shift, (1u << r->width) - 1u, D_NONE);
        return;
    }
    put_field(c, o, reg_key[id], v, 0, ~(uint64_t)0, r->dec == D_CBCR ? (r->flags & F_HWCG ? D_CBCR_HW : D_CBCR) : D_NONE);
    if (v->st != V_OK) return;
    switch (r->dec) {
    case D_FW:
        put_field(c, o, "PR", v, 8, 0xff, D_NONE);            /* FW_REV_PROTOCOL: 2 UART, 1 SPI, 3 I2C (geni-se.h:180-181, 273-277 of the enum); 255 none */
        break;
    case D_STATUS:
        put_field(c, o, "M", v, 0, 1, D_NONE);                /* M_GENI_CMD_ACTIVE */
        put_field(c, o, "S", v, 12, 1, D_NONE);               /* S_GENI_CMD_ACTIVE: a receive command left running */
        break;
    case D_FIFOT:
        if (fifo_mode(s, r->win)) put_field(c, o, "TXN", v, 0, 0xfffffffu, D_NONE);       /* TX_FIFO_WC */
        else put_odd(c, o, "TXN");
        break;
    case D_FIFOR:
        if (fifo_mode(s, r->win)) put_field(c, o, "RXN", v, 0, 0x1ffffffu, D_NONE);       /* RX_FIFO_WC_MSK: words waiting */
        else put_odd(c, o, "RXN");
        break;
    case D_IOS:
        if (uart_mode(s)) put_field(c, o, "CTS", v, 1, 1, D_NONE);                          /* IO2_DATA_IN: low is asserted */
        else put_odd(c, o, "CTS");
        break;
    default:
        break;
    }
}

/* Lines block b may use now: its own cap, less what the blocks after it (a NEXT line and a line each) keep and, before the second snapshot, what that snapshot, the drift report
 * and the closing lines keep. The late blocks (after the drift summary) keep the end line only, and no later late block's lines: they come in the order of what the first question
 * needs, so the first takes what is left and the last goes without when the page is full. */
OUT_OF_LINE unsigned room_for(const struct ctx *c, unsigned b)
{
    unsigned late = b >= B_XU2, keep = c->lines + (late ? KEEP_X : S2_NEXT_LINES + DRIFT_LINES + CLOSING_LINES), max = block_lines[b];
    for (unsigned j = b + 1; j < S1_BLOCKS; j++) keep += 2u;
    if (keep >= LINE_CAP) return 0;
    return LINE_CAP - keep < max ? LINE_CAP - keep : max;
}

/* ---- Snapshot 1: a block at a time, each line printed as soon as the loads it holds are done ---- */

/* One block: each row is read and packed into the line being built, and a line goes out before the loads of the row that starts the next one, so that a hang loses
 * the line in progress and nothing before. An engine whose clock words do not all read ON is not read: its block is the one line `<head> GATED OFF` (a word that read says the
 * clock is stopped) or `<head> GATED ERR` (a word did not read, or read as no clock word does). The values go into `s`; the clock words that gate come from `gate`. */
OUT_OF_LINE void stream_block(struct ctx *c, struct snap *s, const struct snap *gate, unsigned b)
{
    struct out o;
    unsigned verdict = engine_gate(gate, &c->s[0], block_win[b]), keep = b >= B_XU2 ? KEEP_X : KEEP_DATA;
    if (verdict != GATE_OPEN) {
        struct pl_line gated;
        for (unsigned id = block_first[b]; id < block_first[b + 1]; id++) {
            s->v[id].v = 0;
            s->v[id].code = 0;
            s->v[id].st = V_GATED;
        }
        c->blocks |= 1u << b;
        pl_begin(&gated);
        tx(&gated, block_head[b]);
        tx(&gated, " ");
        tx_gate(&gated, verdict);
        say(c, gated.buf, keep);
        return;
    }
    out_begin(&o, block_head[b], room_for(c, b), keep);
    for (unsigned id = block_first[b]; id < block_first[b + 1]; id++) {
        read_row(c, s, gate, id);
        put_row(c, &o, s, id);
        if (id + 1 < block_first[b + 1] && (regs[id + 1].flags & F_BREAK)) out_break(c, &o);
    }
    out_end(c, &o);
}

/* The NEXT line of a block, then the block; no NEXT line, no read: what hangs must be named. */
OUT_OF_LINE void announce_and_read(struct ctx *c, struct snap *s, const struct snap *gate, unsigned b)
{
    struct pl_line next;
    pl_begin(&next);
    tx(&next, "NEXT ");
    tx(&next, block_head[b]);
    if (!say(c, next.buf, b >= B_XU2 ? KEEP_X : KEEP_DATA)) {
        c->blocks |= 1u << b;
        return;
    }
    stream_block(c, s, gate, b);
}

OUT_OF_LINE void snapshot_one(struct ctx *c)
{
    for (unsigned b = 0; b < S1_BLOCKS; b++) announce_and_read(c, &c->s[0], &c->s[0], b);
}

/* ---- Snapshot 2: the same windows, only the rows flagged F_S2, then a drift report ---- */

/* A value that snapshot 2 reads again and the drift report compares: a flagged one that snapshot 1 read, in a window (in GCC: a group) that had not aborted by the end of
 * snapshot 1 and that snapshot 2 does not leave out. The abort of a window is on the page already, and a second visit would only repeat the one thing nothing here may repeat. */
OUT_OF_LINE int revisit(const struct ctx *c, unsigned id)
{
    const struct reg *r = &regs[id];
    if (!(r->flags & F_S2) || c->s[0].v[id].st != V_OK) return 0;
    if (c->s2_skip >> r->win & 1) return 0;
    return !(c->dead_s1 >> dead_bit(r->win, r->grp) & 1);
}

OUT_OF_LINE void read_window(struct ctx *c, unsigned win)
{
    for (unsigned id = 0; id < R_COUNT; id++) {
        if (regs[id].win == win && revisit(c, id)) read_row(c, &c->s[1], &c->s[1], id);
    }
}

OUT_OF_LINE int window_has_reads(const struct ctx *c, unsigned win)
{
    for (unsigned id = 0; id < R_COUNT; id++) {
        if (regs[id].win == win && revisit(c, id)) return 1;
    }
    return 0;
}

/* How many of the values of a window that snapshot 2 read again are not what snapshot 1 read (a value that could not be read again counts). */
OUT_OF_LINE unsigned changes_in(const struct ctx *c, unsigned win)
{
    unsigned n = 0;
    for (unsigned id = 0; id < R_COUNT; id++) {
        const struct val *old = &c->s[0].v[id], *now = &c->s[1].v[id];
        if (regs[id].win == win && revisit(c, id)) n += !(now->st == V_OK && now->v == old->v);
    }
    return n;
}

/* DU holds what moved in the UART engine's words, DT in the pin levels, DG among the clock words: KEY=OLD-NEW, where NEW may be the fault, or the skip after one, that replaced
 * it. The engine and the pins come first because they are what a run with the cover attached is compared with one without; the clock words' verdict is on the NEXT line too
 * (GCC=SAME or CHG:n), so that a page that has room for two lines of drift never loses it. CHANGED counts the values that differ, LOST those snapshot 2 could not read; CMP
 * the values snapshot 1 read in a window that had not aborted by then and that snapshot 2 visited, all compared. */
OUT_OF_LINE void drift_report(struct ctx *c)
{
    static const unsigned wins[3] = {WIN_U2, WIN_TLMM, WIN_GCC};
    static const char group[3][4] = {"DU", "DT", "DG"};
    static const uint8_t group_lines[3] = {2, 1, 1};     /* at most; the lines the page has left decide, and the reserve (DRIFT_LINES) is what the first two are sure of */
    unsigned compared = 0, changed = 0, lost = 0, more = 0;
    struct pl_line sum;
    struct out o;
    for (unsigned g = 0; g < 3; g++) {
        unsigned avail = c->lines + CLOSING_LINES < LINE_CAP ? LINE_CAP - CLOSING_LINES - c->lines : 0;
        out_begin(&o, group[g], avail < group_lines[g] ? avail : group_lines[g], KEEP_DATA);
        for (unsigned id = 0; id < R_COUNT; id++) {
            const struct val *old = &c->s[0].v[id], *now = &c->s[1].v[id];
            struct pl_line item;
            if (regs[id].win != wins[g] || !revisit(c, id)) continue;
            compared++;
            if (now->st == V_OK && now->v == old->v) continue;
            if (now->st == V_OK) changed++;
            else lost++;
            key(&item, reg_key[id]);
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
    emit(c, &sum, KEEP_NONE);
}

/* ---- Time ---- */

/* Waits `ticks` on the runner's counter. W_DONE when it got there; W_DEAD when the counter does not run (the same value COUNTER_STUCK_READS times in a row, or a value below the
 * start): the wait is then not the one the page announced and there is no gap; W_SPIN when it runs but SPIN_MAX reads did not reach the gap. The two are told apart on the page,
 * because one says nothing about the counter that the other does not. */
OUT_OF_LINE unsigned delay_ticks(const struct ctx *c, uint64_t ticks)
{
    uint64_t start = c->counter(), last = start;
    uint32_t same = 0, spins = 0;
    for (;;) {
        uint64_t now = c->counter();
        if (now < start) return W_DEAD;
        if (now - start >= ticks) return W_DONE;
        if (now == last) {
            if (++same >= COUNTER_STUCK_READS) return W_DEAD;
        } else {
            last = now;
            same = 0;
        }
        if (++spins >= SPIN_MAX) return W_SPIN;
    }
}

/* The wait and snapshot 2's reads. The drift report (drift_report) and the late blocks (late_blocks) follow in payload_entry, so that what snapshot 2 found is on the film
 * before the first load of a word nobody has read through Linux. */
OUT_OF_LINE void snapshot_two(struct ctx *c)
{
    static const unsigned order[3] = {WIN_GCC, WIN_U2, WIN_TLMM};
    struct pl_line wait, note;
    unsigned waited;
    if (!c->counter) {
        say(c, "S2 SKIPPED NO_COUNTER", KEEP_DATA);
        return;
    }
    pl_begin(&wait);
    tx(&wait, "NEXT WAIT ");
    dec(&wait, GAP_S);
    tx(&wait, " S");
    if (!say(c, wait.buf, KEEP_DATA)) return;
    waited = delay_ticks(c, (uint64_t)GAP_S * c->hz);
    if (waited != W_DONE) {
        say(c, waited == W_SPIN ? "S2 SKIPPED SPIN" : "S2 SKIPPED NO_COUNTER", KEEP_DATA);
        return;
    }
    c->t_second = c->counter();
    c->dead_s1 = c->dead;
    c->s2_ran = 1;
    pl_begin(&note);
    for (unsigned i = 0; i < 3; i++) {
        unsigned win = order[i];
        unsigned verdict, visit;
        struct pl_line next;
        if (!window_has_reads(c, win)) continue;
        /* An engine whose clock words went off during the wait, or that S2's own GCC pass could not read, is not visited: S2's own clock words, read just before, decide. */
        verdict = engine_gate(&c->s[1], &c->s[0], win);
        pl_begin(&next);
        tx(&next, verdict != GATE_OPEN ? "S2 " : "NEXT S2 ");
        tx(&next, window_name[win]);
        if (verdict != GATE_OPEN) {
            tx(&next, " SKIP ");
            tx_gate(&next, verdict);
        }
        if (note.len) {
            tx(&next, " ");
            tx(&next, note.buf);
        }
        visit = (unsigned)say(c, next.buf, KEEP_DATA) && verdict == GATE_OPEN;
        pl_begin(&note);
        if (!visit) {
            /* Not read, so not compared either: the drift report skips the window and BLK says it was left out. */
            for (unsigned id = 0; id < R_COUNT; id++) {
                if (regs[id].win == win && revisit(c, id)) c->blocks |= 1u << regs[id].block;
            }
            c->s2_skip |= 1u << win;
            continue;
        }
        read_window(c, win);
        if (win == WIN_GCC) {
            /* The likeliest place of a hang is the engine after it; what GCC said after the wait is on the film before it, on the next line, in no line of its own. */
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
}

/* ---- The late blocks: the words no Linux driver reads, once, after snapshot 2 and its drift report ---- */

/* Each under its own NEXT line, in the order of what the first question needs (the UART engine, the SPI engine, the GIC), gated by the freshest clock words there are: snapshot
 * 2's if it read them, else snapshot 1's. The values go into snapshot 2's array, in rows no snapshot reads twice. */
OUT_OF_LINE void late_blocks(struct ctx *c)
{
    const struct snap *gate = c->s2_ran ? &c->s[1] : &c->s[0];
    for (unsigned b = B_XU2; b < BLOCKS; b++) {
        /* The NEXT line and one line of values: with no room for both, nothing of what would be read could show, and these are the words nobody has read through Linux. */
        if (room_for(c, b) < 2) {
            c->blocks |= 1u << b;
            continue;
        }
        announce_and_read(c, &c->s[1], gate, b);
    }
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
    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {
        say(&c, "SKIPPED_NOT_AT_EL2", KEEP_NONE);
        return 0;
    }
    if (!c.load32) {
        say(&c, "REFUSED_NO_LOAD32", KEEP_NONE);
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
    emit(&c, &line, KEEP_DATA);
    say(&c, "KEY=VALUE FAULT:6=ABORT SKIP=AFTER ONE GATED=NOT READ ODD=DECODE NOT VALID", KEEP_DATA);

    c.t_first = c.counter ? c.counter() : 0;
    snapshot_one(&c);
    snapshot_two(&c);
    if (c.s2_ran) drift_report(&c);
    late_blocks(&c);

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
    emit(&c, &line, KEEP_NONE);
    return 0;
}
