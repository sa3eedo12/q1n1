/* SPDX-License-Identifier: MIT */
/* Payload "inpsnap2": stage I0 of the input plan (docs/SP11-PAYLOAD-INPSNAP2.md has the page, what each token means and what it does not answer; docs/SP11-PAYLOAD-INPSNAP2-EVIDENCE.md the
 * registers with their file:line and evidence labels; the stick name is INPSNAP2.BIN). A read-only survey, before anything is started, of the words that decide how the Type Cover link's
 * UART engine (the Surface Aggregator Module's, QUP wrapper 0 engine 2) could be clocked later: whether its root clock generator is a DFS clock (the flag decides whether any word
 * of it may ever be written), the eight DFS levels' words, GPLL0, the divider below the generator, the engine's own clock word and the votes, and the wrapper's version. Boot 29 (`inputsnap`
 * v1) found the engine clocks off at hand-off; this payload reads what a later, separately approved stage needs to turn one on, and it turns nothing on.
 * Nobody has read these words on this unit, and no word of a QUP wrapper has ever been read on it: a read of a block without its clocks may hang the bus, which no guard recovers. This
 * payload stores nothing at all.
 *
 * Every access is an ops.load32 (a synchronous abort comes back as a code, never as an exception; an SError is neither caught by it nor printed); the only system register is CurrentEL:
 * there is no counter, no wait and no second snapshot. The only stores are to this payload's own stack, and that is the only memory it writes through any pointer: no pointer is kept in
 * memory (the three ops are copied into the context as function pointers, every data pointer is an argument or a local), so that the compiled-code audit
 * (tools/sp11_payload_inpsnap2_audit.py) and the binary check of tools/sp11_payload_memcheck.py can both check the base of every store (neither checks its offset: docs/SP11-PAYLOAD-INPSNAP2.md, 4.1). No tick, no SMC, no HVC, no barrier. Every row of the table is read at
 * most once; nothing is retried.
 *
 * Order, which is the order of what one abort or hang costs: the clock controller's words first (read unconditionally: boots 29 to 31 read other words of it), the wrapper's one word last
 * and only behind proof that the wrapper's clocks run (wrapper_gate()). The first all-ones word ends the page (a bus-fault suspicion: print what was read, read no more). Every block is
 * announced by a `NEXT <block>` line before its first load and is not read at all if the line cannot be printed, so that the last line on the panel names what hung; a line is read whole
 * and printed before the first load of the next, so that a hang keeps every line before it.
 *
 * Page: two header lines; for each block its `NEXT` line and its lines of at most four words, `KEY=VALUE` with a check `K=` of the line; the end line. A value below 10 is one digit, a
 * larger one 0X and the fewest upper-case hex digits; a branch clock word may carry .ON, .OFF, .HW or .ODD. At most LINE_CAP lines whatever the hardware says. */
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* No MRS can run on a build machine: the host test supplies the register file. */
uint64_t pl_host_sysreg(const char *name);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#include "inpsnap2-regs.h"

#define PREFIX "PAYLOAD INPSNAP2 "
#define OUT_OF_LINE static __attribute__((noinline))     /* one body per helper: the binary stays small enough to audit by eye */
#define LEGEND "KEY=VALUE .ON .OFF .HW .ODD=CLOCK FAULT:6=ABORT SKIP=NOT READ K=LINE CRC16"
_Static_assert(sizeof PREFIX - 1 + sizeof LEGEND - 1 <= Q1N1_PAYLOAD_LINE_MAX, "inpsnap2: the legend fits a line");
/* The widest line: four words of the widest form (`KEY=0XFFFFFFFF`) and the check; three words with a clock verdict (`MA0=0XFFFFFFFF.OFF`) and the check. */
_Static_assert(sizeof PREFIX - 1 + 4 + 4 * (1 + 3 + 1 + 10) + 7 <= LINE_FILL, "inpsnap2: a line of four words fits");
_Static_assert(sizeof PREFIX - 1 + 4 + 3 * (1 + 3 + 1 + 10 + 4) + 7 <= LINE_FILL, "inpsnap2: a line of three clock words fits");

/* Why a read did not give a value: RD_RANGE and RD_ALIGN are table defects (nothing is loaded), RD_DEAD an earlier abort in the block, RD_STOP an earlier all-ones word. */
enum { RD_OK, RD_RANGE, RD_ALIGN, RD_DEAD, RD_STOP, RD_BUDGET, RD_FAULT };
/* What a branch clock word says (clock_state()), and what the wrapper's clock words say together (wrapper_gate()): OFF is a word that read and says stopped, or says hardware gating with
 * no vote behind it; ERR is a word that did not read, or read as nothing a clock word can be, or the vote evidence it needs did not read or is implausible, and no word says stopped. */
enum { CK_ON, CK_OFF, CK_HW, CK_ODD };
enum { GATE_OPEN, GATE_OFF, GATE_ERR };

struct val {
    uint32_t v;                     /* the word; for V_FAULT, the code load32 returned */
    uint8_t st, pad[3];
};
_Static_assert(sizeof(struct val) == 8, "inpsnap2: a word record is 8 bytes");

struct ctx {
    void (*puts)(const char *line);
    uint32_t (*hex)(char *dst, uint32_t cap, uint64_t value);
    int32_t (*load32)(uint64_t addr, uint32_t *out);
    uint32_t word;                  /* the load32 destination: the runner wants it on the payload stack, and the context is */
    uint32_t err;                   /* what the last failed load32 returned */
    uint32_t loads, lines, cuts, faults, skips, blocks;
    uint32_t dead;                  /* a bit per block in which a load aborted */
    uint32_t stop;                  /* 0, or the row of the first all-ones word plus one: nothing is read after it */
    struct val v[R_COUNT];
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

/* Four digits whatever the value: the check of a line is read in columns. */
OUT_OF_LINE void hex4(struct pl_line *line, uint32_t value)
{
    for (unsigned shift = 16; shift;) {
        shift -= 4;
        if (line->len < Q1N1_PAYLOAD_LINE_MAX) line->buf[line->len++] = "0123456789ABCDEF"[value >> shift & 15];
    }
    line->buf[line->len] = 0;
}

/* The lines that may still be printed: the end line keeps the last of LINE_CAP. */
OUT_OF_LINE int room(const struct ctx *c)
{
    return c->lines + CLOSING_LINES < LINE_CAP;
}

/* A line counts against LINE_CAP; the end line may use what the others may not. */
OUT_OF_LINE int emit(struct ctx *c, const struct pl_line *line, unsigned closing)
{
    if (closing ? c->lines >= LINE_CAP : !room(c)) {
        c->cuts++;
        return 0;
    }
    c->lines++;
    c->puts(line->buf);
    return 1;
}

OUT_OF_LINE int say(struct ctx *c, const char *text, unsigned closing)
{
    struct pl_line line;
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, text);
    return emit(c, &line, closing);
}

/* `NEXT <block>`: no line, no read, so that what hangs is named. */
OUT_OF_LINE int announce(struct ctx *c, unsigned block)
{
    struct pl_line line;
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "NEXT ");
    tx(&line, block_head[block]);
    return emit(c, &line, 0);
}

/* ---- The check of a line ---- */

OUT_OF_LINE uint32_t crc_byte(uint32_t crc, uint32_t byte)
{
    crc ^= byte << 8;
    for (unsigned bit = 0; bit < 8; bit++) crc = (crc & 0x8000u ? crc << 1 ^ CRC_POLY : crc << 1) & 0xffffu;
    return crc;
}

OUT_OF_LINE uint32_t crc_word(uint32_t crc, const struct val *w)
{
    crc = crc_byte(crc, w->st);
    for (unsigned byte = 0; byte < 4; byte++) crc = crc_byte(crc, w->v >> 8 * byte & 0xffu);
    return crc;
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

/* A register at a place. A window the table does not have, an unaligned offset and an offset past the end of its window are refused before anything is loaded (the window's size is a whole
 * number of words, so an aligned offset inside it has its four bytes); nothing is loaded after an all-ones word; and the first abort in a block ends the reads of the block: whatever
 * stopped one load would stop the next, and nothing is retried. The shipped table never trips the first three: the host test calls this on its own to hold them. */
OUT_OF_LINE int rd_at(struct ctx *c, unsigned block, unsigned win, uint32_t off, uint32_t *value)
{
    int rc;
    *value = 0;
    if (win >= WINDOWS) return RD_RANGE;
    if (off & 3) return RD_ALIGN;
    if (off >= windows[win].size) return RD_RANGE;
    if (c->stop) return RD_STOP;
    if (c->dead >> block & 1) return RD_DEAD;
    rc = load(c, windows[win].base + off, value);
    if (rc == RD_FAULT) c->dead |= 1u << block;
    return rc;
}

/* A register of the table; a row the table does not have is refused. */
OUT_OF_LINE int rd32(struct ctx *c, unsigned id, uint32_t *value)
{
    *value = 0;
    if (id >= R_COUNT) return RD_RANGE;
    return rd_at(c, regs[id].block, regs[id].win, regs[id].off, value);
}

/* One row: its load, or the reason there is none. A word of all ones is what a failed read returns and no register of this table holds: it ends the page, after the line it is in. */
OUT_OF_LINE void read_row(struct ctx *c, unsigned id)
{
    struct val *w = &c->v[id];
    uint32_t word;
    int rc = rd32(c, id, &word);
    w->v = 0;
    w->st = V_NONE;
    w->pad[0] = w->pad[1] = w->pad[2] = 0;
    switch (rc) {
    case RD_OK:
        w->v = word;
        w->st = V_OK;
        if (word == 0xffffffffu) c->stop = id + 1u;
        break;
    case RD_FAULT:
        w->v = c->err;
        w->st = V_FAULT;
        c->faults++;
        c->blocks |= 1u << regs[id].block;
        break;
    case RD_DEAD:
    case RD_STOP:
        w->st = V_SKIP;
        c->skips++;
        c->blocks |= 1u << regs[id].block;
        break;
    case RD_BUDGET:
        w->st = V_BUDGET;
        c->blocks |= 1u << regs[id].block;
        break;
    default:
        break;
    }
}

/* ---- The clock words ---- */

/* What a branch clock word says. ON: CLK_OFF (bit 31) clear, or the NoC FSM status (bits 30:28) says ON (2), which is how Linux reads a branch that is being enabled (clk-branch.c,
 * clk_branch2_check_halt). A voted branch's CLK_ENABLE bit stays clear (its enable is a vote in 0x52020), so a word of 0 is a running clock. HW: CLK_OFF set, no FSM verdict, and the
 * branch declares a hardware clock gating bit (`hwcg`) with HW_CTL (bit 1) set: Linux does not wait for the halt bit of a branch in hardware gating mode (clk_branch_wait,
 * clk_branch_in_hwcg_mode), so the bit is no verdict. OFF: CLK_OFF set with neither of those. ODD: all ones, what a failed read returns, which no clock word is. */
OUT_OF_LINE unsigned clock_state(uint32_t word, unsigned hwcg)
{
    if (word == 0xffffffffu) return CK_ODD;
    if (!(word >> 31 & 1) || (word >> 28 & 7) == 2) return CK_ON;
    return hwcg && (word >> 1 & 1) ? CK_HW : CK_OFF;
}

/* Whether the wrapper's clocks run, for the one read nobody has made. Its AHB clocks and its core clock must all have read and say running (hamoa.dtsi:2141-2146: the wrapper's
 * clocks are m-ahb and s-ahb; the core clock is the plan's third gate word). A word that did not read, or read as all ones, is unknown, never stopped. Two readings need more than the
 * clock word, because a clock word alone cannot tell them from what a dead window or an idle clock nobody asked for also reads (the review of `inputsnap` v1, findings 1 and 4): an AHB
 * clock that says only `.HW` is a healthy idle clock only if its apps vote in VT0 is set (the vote word read and the bit set: running; the bit clear: stopped; the word not read:
 * unknown); and a window of zeros shows every branch as running, so the wrapper's vote word VT0 must have read and be neither zero nor all ones. This payload reads one wrapper's vote
 * word, where `inputsnap` reads three: here VT0 alone is the evidence. */
OUT_OF_LINE unsigned wrapper_gate(const struct ctx *c)
{
    const struct val *vote = &c->v[R_VT0];
    unsigned off = 0, unknown = 0;
    for (unsigned id = 0; id < R_COUNT; id++) {
        unsigned state;
        if (!(regs[id].flags & F_WRAP)) continue;
        if (c->v[id].st != V_OK) {
            unknown = 1;
            continue;
        }
        state = clock_state(c->v[id].v, regs[id].flags & F_HWCG);
        if (state == CK_HW) state = vote->st != V_OK ? CK_ODD : vote->v >> regs[id].vbit & 1 ? CK_ON : CK_OFF;
        off |= state == CK_OFF;
        unknown |= state == CK_ODD;
    }
    if (vote->st != V_OK || !vote->v || vote->v == 0xffffffffu) unknown = 1;
    return off ? GATE_OFF : unknown ? GATE_ERR : GATE_OPEN;
}

/* ---- The page ---- */

/* The text of one word: the runner's 0X form, or why there is none; a clock word's own verdict after it. */
OUT_OF_LINE void put_row(const struct ctx *c, struct pl_line *line, unsigned id)
{
    const struct reg *r = &regs[id];
    const struct val *w = &c->v[id];
    tx(line, " ");
    tx(line, r->key);
    tx(line, "=");
    switch (w->st) {
    case V_OK:
        num(c, line, w->v);
        if (r->flags & F_CBCR) {
            switch (clock_state(w->v, r->flags & F_HWCG)) {
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
        dec(line, w->v);
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

/* One line of the table: its rows are read, then the line goes out with the check of what it shows. A line the page has no room for is not read: nothing is read that cannot be shown. */
OUT_OF_LINE void table_line(struct ctx *c, unsigned li)
{
    const struct line_def *d = &lines[li];
    struct pl_line line;
    uint32_t crc = CRC_INIT;
    if (!room(c)) {
        c->cuts++;
        c->blocks |= 1u << d->block;
        return;
    }
    for (unsigned id = d->first; id < d->end; id++) read_row(c, id);
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, d->head);
    for (unsigned id = d->first; id < d->end; id++) {
        put_row(c, &line, id);
        crc = crc_word(crc, &c->v[id]);
    }
    tx(&line, " K=");
    hex4(&line, crc);
    emit(c, &line, 0);
}

/* A block of the clock controller. Nothing is announced after an all-ones word. */
OUT_OF_LINE void gcc_block(struct ctx *c, unsigned block)
{
    if (c->stop) return;
    if (!announce(c, block)) {
        c->blocks |= 1u << block;
        return;
    }
    for (unsigned li = 0; li < LINES && !c->stop; li++) {
        if (lines[li].block == block) table_line(c, li);
    }
}

/* The wrapper's version, behind the proof that its clocks run: otherwise the block is one line, `QUP GATED OFF` (a clock word that read says stopped) or `QUP GATED ERR` (what it
 * needs did not read or cannot be trusted). */
OUT_OF_LINE void qup_block(struct ctx *c)
{
    unsigned gate;
    if (c->stop) return;
    if (!announce(c, B_QUP)) {
        c->blocks |= 1u << B_QUP;
        return;
    }
    gate = wrapper_gate(c);
    if (gate != GATE_OPEN) {
        c->blocks |= 1u << B_QUP;
        if (gate == GATE_OFF) say(c, "QUP GATED OFF", 0);
        else say(c, "QUP GATED ERR", 0);
        return;
    }
    table_line(c, L_QUP);
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct ctx c;
    struct pl_line line;
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    for (size_t i = 0; i < sizeof c; i++) ((volatile uint8_t *)&c)[i] = 0;
    c.puts = a->ops.puts;
    c.hex = a->ops.hex;
    c.load32 = a->ops.load32;
    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {
        say(&c, "SKIPPED_NOT_AT_EL2", 1);
        return 0;
    }
    if (!c.load32) {
        say(&c, "REFUSED_NO_LOAD32", 1);
        return Q1N1_PAYLOAD_RET_BAD_ARGS;
    }

    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "READ ONLY EL=2 STAGE=I0 CAP=");
    dec(&line, LOAD_CAP);
    tx(&line, "/");
    dec(&line, LINE_CAP);
    emit(&c, &line, 0);
    say(&c, LEGEND, 0);

    for (unsigned block = B_GATE; block < B_QUP; block++) gcc_block(&c, block);
    qup_block(&c);
    if (c.stop) {
        for (unsigned block = regs[c.stop - 1u].block; block < BLOCKS; block++) c.blocks |= 1u << block;
    }

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
    tx(&line, " LINES=");
    dec(&line, c.lines + 1u);
    tx(&line, " STOP=");
    if (c.stop) tx(&line, regs[c.stop - 1u].key);
    else tx(&line, "NONE");
    emit(&c, &line, 1);
    return 0;
}
