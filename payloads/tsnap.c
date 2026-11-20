/* SPDX-License-Identifier: MIT */
/* Payload "tsnap": a read-only snapshot of the four TSENS temperature controllers of the Surface Pro 11's SoC (Snapdragon X Elite X1E80100, "Hamoa"), twice, 2 s apart, printed on
 * the panel as raw words and as decoded temperatures (docs/SP11-PAYLOAD-TSNAP.md has the registers with their file:line and evidence labels, the page, and what it does not answer).
 * Nobody has read a temperature on the unit: the compat/hamoa-thermal model only assumes that these windows are readable at EL2, enabled and calibrated by firmware, and
 * that the status word decodes as tenths of a degree C. This payload is the first reading of all of that, and nothing else: it stores nothing at all.
 *
 * Every device access is an ops.load32 (a synchronous abort comes back as a code, never as an exception; an SError is neither caught by it nor printed); the only system registers
 * are CurrentEL and CNTFRQ_EL0. The only stores are to this payload's own stack, and that is the only memory it writes through any pointer: no pointer is kept in memory (the four
 * ops are copied into the context as function pointers, every data pointer is an argument or a local), so that the compiled-code audit (tools/sp11_payload_tsnap_audit.py) and the
 * binary check of tools/sp11_payload_memcheck.py can both prove it. No tick, no SMC, no HVC, no barrier. Nothing is retried: the first abort in a window (the SROT or the TM of a block)
 * ends every later read of that window, in the second reading too. A block, and each later block of a pass, is announced by a `NEXT` line (or the `NEXT` that ends the line before)
 * before its first load and is not read at all if that line cannot be printed, so that the last line on the panel names what hung. A block is read further only after its own words
 * say it is there and running: its HW_VER must read (not abort, not 0, not all ones) and its CTRL must read and say enabled and out of software reset; otherwise the page says GATED,
 * OFF or CTLERR and the TM window of that block is never touched. Each line goes out as soon as the loads it holds are done, so a hang keeps what was printed before it, and no block's
 * abort silences another block. The words are read in the order of the evidence they carry: HW_VER and CTRL, whose identity line is printed before the first load of the TM window; the
 * sixteen status words, which Linux reads constantly; TRDY (0xe4), which no Linux path reads for a v2 block, last in the block; and, after the second reading, the conversion words and
 * the interrupt status words, which no Linux path reads either.
 *
 * Page (docs/SP11-PAYLOAD-TSNAP.md): two header lines; per block NEXT, an identity line (VER, CTL, SEN), two lines of eight raw status words (eight hex digits each) and a line of tenths of
 * a degree C with RDY= and V=; SUM1; `NEXT S2 AFTER 2 S` and one line per block, each naming the next (the last one the first block of the conversion pass); one CONV line per block, each
 * naming the next; SUM2 and END. A field that does not fit a line is dropped and counted in CUTS, never cut in half. */
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* No MRS can run on a build machine: the host test supplies the register file. */
uint64_t pl_host_sysreg(const char *name);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#include "tsnap-regs.h"

#define PREFIX "PAYLOAD TSNAP "
#define OUT_OF_LINE static __attribute__((noinline))     /* one body per helper: the reviewed binary stays small */

enum { RD_OK, RD_RANGE, RD_ALIGN, RD_DEAD, RD_BUDGET, RD_FAULT };
/* The state of one word: V_NONE not read, V_SKIP not read because an earlier load of its window aborted. */
enum { V_NONE, V_OK, V_FAULT, V_SKIP, V_BUDGET };
/* A block: BS_GATED its HW_VER did not read as a block's, BS_OFF its CTRL read and says it is not running, BS_CTLERR its CTRL did not read, BS_SKIPPED a line that announces it could not
 * be printed. */
enum { BS_NEW, BS_OK, BS_GATED, BS_OFF, BS_CTLERR, BS_SKIPPED };
/* What a status word is: VALID and plausible, VALID clear, reserved bits set (an all-ones word is one) or VALID in a block whose CTRL says ADC codes, or VALID and outside
 * TEMP_MIN_TENTHS..TEMP_MAX_TENTHS. */
enum { K_OK, K_INVALID, K_ODD, K_OUT };
/* How a wait ended: the time passed, the counter does not run (it stands still or goes backwards), or it runs but SPIN_MAX reads did not span the wait. */
enum { DELAY_OK, DELAY_STUCK, DELAY_SPIN };

/* The row sizes below are powers of two, so that indexing them is a shift: the binary check of tools/sp11_payload_memcheck.py proves where a store lands only for a base that
 * is the stack plus a shifted index, never for a product. */
struct val {
    uint32_t v;
    uint16_t code;                  /* what load32 returned, when it failed (the runner's codes are 1 to 6) */
    uint8_t st, pad;
};
_Static_assert(sizeof(struct val) == 8, "tsnap: a word record is 8 bytes");

/* What a set of status words adds up to; min and max carry the sensor they came from (block << 4 | id). */
struct agg {
    uint32_t valid, out, odd, crit, chg, both;
    int32_t min, max, dmax;
    uint32_t min_at, max_at;
};

struct blk {
    uint32_t state;
    uint32_t code;                  /* CTRL bit 21 was clear in the first reading: the status words are not decoded */
    uint64_t t1;                    /* the counter when the sixteen status words of the first reading of this block were read */
    struct val ver, ctl, rdy;
    struct val st[2][SENSORS];      /* the status words of the first and of the second reading */
    uint8_t pad[216];
};
_Static_assert(sizeof(struct blk) == 512, "tsnap: a block record is 512 bytes");

struct ctx {
    void (*puts)(const char *line);
    uint32_t (*hex)(char *dst, uint32_t cap, uint64_t value);
    int32_t (*load32)(uint64_t addr, uint32_t *out);
    uint64_t (*counter)(void);
    uint32_t word;                  /* the load32 destination: the runner wants it on the payload stack, and the context is */
    uint32_t err;                   /* what the last failed load32 returned */
    uint32_t loads, lines, cuts, faults, skips, gated, hz, hz_default;
    uint32_t dead;                  /* a bit per window in which a load aborted */
    uint32_t conv_named;            /* the last line of the second reading already named the first block of the conversion pass */
    uint64_t t_first, t_second;
    struct agg tot[2];
    struct blk blk[INSTANCES];
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

OUT_OF_LINE void sdec(struct pl_line *line, int32_t value)
{
    if (value < 0) {
        tx(line, "-");
        dec(line, (uint64_t)(-(int64_t)value));
    } else {
        dec(line, (uint64_t)value);
    }
}

/* Eight digits whatever the value: a raw status word is read in columns, and an all-ones word must show as such. */
OUT_OF_LINE void hex8(struct pl_line *line, uint32_t value)
{
    for (unsigned shift = 32; shift;) {
        shift -= 4;
        if (line->len < Q1N1_PAYLOAD_LINE_MAX) line->buf[line->len++] = "0123456789ABCDEF"[value >> shift & 15];
    }
    line->buf[line->len] = 0;
}

/* A line counts against LINE_CAP; the closing lines (SUM2 and END) may use what the others may not. */
OUT_OF_LINE int emit(struct ctx *c, const struct pl_line *line, unsigned closing)
{
    if (c->lines >= (closing ? LINE_CAP : LINE_CAP - CLOSING_LINES)) {
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

/* A line being packed: PREFIX, a head, then the fields. A field that does not fit is dropped and counted, never cut. */
OUT_OF_LINE void pk_begin(struct pl_line *line, const char *head)
{
    pl_begin(line);
    tx(line, PREFIX);
    tx(line, head);
}

OUT_OF_LINE int pk_add(struct ctx *c, struct pl_line *line, const struct pl_line *item)
{
    if (line->len + 1 + item->len > Q1N1_PAYLOAD_LINE_MAX) {
        c->cuts++;
        return 0;
    }
    tx(line, " ");
    tx(line, item->buf);
    return 1;
}

OUT_OF_LINE void pk_text(struct ctx *c, struct pl_line *line, const char *text)
{
    struct pl_line item;
    pl_begin(&item);
    tx(&item, text);
    pk_add(c, line, &item);
}

/* `<lead>T<n>`: the head of a block's lines. */
OUT_OF_LINE void blk_head(struct pl_line *head, const char *lead, unsigned n)
{
    pl_begin(head);
    tx(head, lead);
    tx(head, "T");
    dec(head, n);
}

/* The text of one word: the runner's 0X form (or eight digits, for a status word), or why there is none. */
OUT_OF_LINE void word_text(const struct ctx *c, struct pl_line *item, const struct val *w, unsigned fixed)
{
    switch (w->st) {
    case V_OK:
        if (fixed) hex8(item, w->v);
        else hx(c, item, w->v);
        break;
    case V_FAULT:
        tx(item, "FAULT:");
        dec(item, w->code);
        break;
    case V_SKIP:
        tx(item, "SKIP");
        break;
    case V_BUDGET:
        tx(item, "BUDGET");
        break;
    default:
        tx(item, "NA");
        break;
    }
}

OUT_OF_LINE void pk_word(struct ctx *c, struct pl_line *line, const char *key, const struct val *w)
{
    struct pl_line item;
    pl_begin(&item);
    tx(&item, key);
    word_text(c, &item, w, 0);
    pk_add(c, line, &item);
}

OUT_OF_LINE void pk_number(struct ctx *c, struct pl_line *line, const char *key, uint64_t value)
{
    struct pl_line item;
    pl_begin(&item);
    tx(&item, key);
    dec(&item, value);
    pk_add(c, line, &item);
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

/* A register of a window. The first abort ends all reads of its window: whatever stopped one load would stop the next, and nothing is retried. */
OUT_OF_LINE int rd(struct ctx *c, unsigned win, uint32_t off, uint32_t *value)
{
    int rc;
    *value = 0;
    if (win >= WINDOWS) {
        rc = RD_RANGE;
    } else if (off & 3) {
        rc = RD_ALIGN;
    } else if (off > WINDOW_SIZE - 4) {
        rc = RD_RANGE;
    } else if (c->dead >> win & 1) {
        rc = RD_DEAD;
    } else {
        rc = load(c, (uint64_t)window_base[win] + off, value);
        if (rc == RD_FAULT) c->dead |= 1u << win;
    }
    return rc;
}

OUT_OF_LINE void val_copy(struct val *to, const struct val *from)
{
    to->v = from->v;
    to->code = from->code;
    to->st = from->st;
}

OUT_OF_LINE void read_word(struct ctx *c, unsigned win, uint32_t off, struct val *w)
{
    uint32_t value;
    int rc = rd(c, win, off, &value);
    w->v = 0;
    w->code = 0;
    switch (rc) {
    case RD_OK:
        w->v = value;
        w->st = V_OK;
        break;
    case RD_FAULT:
        w->st = V_FAULT;
        w->code = (uint16_t)c->err;
        c->faults++;
        break;
    case RD_DEAD:
        w->st = V_SKIP;
        c->skips++;
        break;
    case RD_BUDGET:
        w->st = V_BUDGET;
        break;
    default:
        w->st = V_NONE;
        break;
    }
}

/* ---- What a word says ---- */

/* A block's own identity: HW_VER read, and neither zero nor all ones, which is what a block that is not there (or a failed read) returns. */
OUT_OF_LINE int ident_ok(const struct val *w)
{
    return w->st == V_OK && w->v != 0 && w->v != 0xffffffffu;
}

/* Enabled and out of software reset, as tsens.c:1018-1031 requires of a block before it trusts it. */
OUT_OF_LINE int running(const struct val *w)
{
    return w->st == V_OK && (w->v & CTRL_EN) && !(w->v & CTRL_SW_RST);
}

/* A reserved bit (31:22) set means the word is not the layout the driver describes, so it is not decoded: an all-ones word is the usual case, a failed read. A VALID word of a block
 * whose CTRL has CODE_OR_TEMP clear is not a temperature either (INFERRED: ADC codes), and is as little decoded. */
OUT_OF_LINE unsigned classify(uint32_t raw, unsigned code, int32_t *tenths)
{
    int32_t t = (int32_t)(raw & ST_TEMP_MASK);
    if (t & 0x800) t -= 0x1000;
    *tenths = t;
    if (raw >> ST_RESERVED_SHIFT) return K_ODD;
    if (!(raw & ST_VALID)) return K_INVALID;
    if (code) return K_ODD;
    if (t < TEMP_MIN_TENTHS || t > TEMP_MAX_TENTHS) return K_OUT;
    return K_OK;
}

OUT_OF_LINE void agg_clear(struct agg *a)
{
    a->valid = a->out = a->odd = a->crit = a->chg = a->both = 0;
    a->min = a->max = a->dmax = 0;
    a->min_at = a->max_at = 0;
}

/* One status word into a set. CRIT counts the CRITICAL and MAX flags of words that are not odd. */
OUT_OF_LINE void agg_sample(struct agg *a, unsigned at, uint32_t raw, unsigned code)
{
    int32_t t;
    unsigned kind = classify(raw, code, &t);
    if (kind != K_ODD && (raw & ST_CRIT_FLAGS)) a->crit++;
    if (kind == K_ODD) {
        a->odd++;
    } else if (kind == K_OUT) {
        a->out++;
    } else if (kind == K_OK) {
        if (!a->valid || t < a->min) {
            a->min = t;
            a->min_at = at;
        }
        if (!a->valid || t > a->max) {
            a->max = t;
            a->max_at = at;
        }
        a->valid++;
    }
}

OUT_OF_LINE void agg_merge(struct agg *to, const struct agg *from)
{
    if (from->valid && (!to->valid || from->min < to->min)) {
        to->min = from->min;
        to->min_at = from->min_at;
    }
    if (from->valid && (!to->valid || from->max > to->max)) {
        to->max = from->max;
        to->max_at = from->max_at;
    }
    to->valid += from->valid;
    to->out += from->out;
    to->odd += from->odd;
    to->crit += from->crit;
    to->chg += from->chg;
    to->both += from->both;
    if (from->dmax > to->dmax) to->dmax = from->dmax;
}

/* The extreme of a set, with the sensor it came from: MIN=213(T0.1), or NA when no word was valid and plausible. */
OUT_OF_LINE void pk_extreme(struct ctx *c, struct pl_line *line, const char *key, const struct agg *a, unsigned maximum, unsigned located)
{
    struct pl_line item;
    pl_begin(&item);
    tx(&item, key);
    if (!a->valid) {
        tx(&item, "NA");
    } else {
        unsigned at = maximum ? a->max_at : a->min_at;
        sdec(&item, maximum ? a->max : a->min);
        if (located) {
            tx(&item, "(T");
            dec(&item, at >> 4);
            tx(&item, ".");
            dec(&item, at & 15);
            tx(&item, ")");
        }
    }
    pk_add(c, line, &item);
}

/* One cell of the temperature line: tenths of a degree, or ? (VALID clear), O (odd, out of range, or any VALID word of a CODE block), X (not read). */
OUT_OF_LINE void cell(struct pl_line *item, const struct val *w, unsigned code)
{
    int32_t t;
    if (w->st != V_OK) {
        tx(item, "X");
        return;
    }
    switch (classify(w->v, code, &t)) {
    case K_OK:
        sdec(item, t);
        break;
    case K_INVALID:
        tx(item, "?");
        break;
    default:
        tx(item, "O");
        break;
    }
}

/* ---- The first reading: a block at a time, each line printed as soon as the loads it holds are done ---- */

OUT_OF_LINE int next_line(struct ctx *c, unsigned n)
{
    struct pl_line text;
    pl_begin(&text);
    tx(&text, "NEXT T");
    dec(&text, n);
    return say(c, text.buf, 0);
}

/* The identity of a block, printed before the first load of its TM window: after it the panel says that the next loads are the status words, and a hang there leaves VER and CTL on
 * the screen. Returns 0 when the line did not go out. */
OUT_OF_LINE int identity_line(struct ctx *c, unsigned n)
{
    const struct blk *b = &c->blk[n];
    struct pl_line head, line;
    blk_head(&head, "", n);
    pk_begin(&line, head.buf);
    pk_word(c, &line, "VER=", &b->ver);
    if (b->ctl.st != V_NONE) pk_word(c, &line, "CTL=", &b->ctl);
    if (b->ctl.st == V_OK) {
        struct pl_line item;
        pl_begin(&item);
        tx(&item, "SEN=");
        hx(c, &item, (b->ctl.v >> CTRL_SENSOR_SHIFT) & CTRL_SENSOR_MASK);
        pk_add(c, &line, &item);
    }
    if (b->state == BS_OK && b->code) pk_text(c, &line, "CODE");
    if (b->state == BS_GATED) pk_text(c, &line, "GATED");
    if (b->state == BS_OFF) pk_text(c, &line, "OFF");
    if (b->state == BS_CTLERR) pk_text(c, &line, "CTLERR");
    return emit(c, &line, 0);
}

/* The temperature line; RDY= comes before V= so that the field with no Linux precedent is the last to be dropped for lack of room. */
OUT_OF_LINE void cells_line(struct ctx *c, unsigned n, const struct agg *a)
{
    struct pl_line head, line, item;
    blk_head(&head, "", n);
    tx(&head, " C");
    pk_begin(&line, head.buf);
    for (unsigned i = 0; i < SENSORS; i++) {
        pl_begin(&item);
        cell(&item, &c->blk[n].st[0][i], c->blk[n].code);
        pk_add(c, &line, &item);
    }
    pk_word(c, &line, "RDY=", &c->blk[n].rdy);
    pk_number(c, &line, "V=", a->valid);
    emit(c, &line, 0);
}

OUT_OF_LINE void block_one(struct ctx *c, unsigned n)
{
    struct blk *b = &c->blk[n];
    struct agg a;
    struct pl_line head, line, item;
    if (!next_line(c, n)) {
        b->state = BS_SKIPPED;
        c->gated++;
        return;
    }
    read_word(c, WIN_SROT(n), SROT_HW_VER, &b->ver);
    if (!ident_ok(&b->ver)) {
        b->state = BS_GATED;
        c->gated++;
        identity_line(c, n);
        return;
    }
    read_word(c, WIN_SROT(n), SROT_CTRL, &b->ctl);
    if (!running(&b->ctl)) {
        b->state = b->ctl.st == V_OK ? BS_OFF : BS_CTLERR;
        c->gated++;
        identity_line(c, n);
        return;
    }
    b->state = BS_OK;
    b->code = !(b->ctl.v & CTRL_CODE_OR_TEMP);
    if (!identity_line(c, n)) {
        b->state = BS_SKIPPED;
        c->gated++;
        return;
    }
    for (unsigned half = 0; half < 2; half++) {
        blk_head(&head, "", n);
        tx(&head, " R");
        dec(&head, half * 8u);
        pk_begin(&line, head.buf);
        for (unsigned i = half * 8u; i < half * 8u + 8u; i++) {
            read_word(c, WIN_TM(n), TM_STATUS + 4u * i, &b->st[0][i]);
            pl_begin(&item);
            word_text(c, &item, &b->st[0][i], 1);
            pk_add(c, &line, &item);
        }
        emit(c, &line, 0);
        if (!half && c->dead >> WIN_TM(n) & 1 && b->st[0][0].st != V_OK) return;      /* the TM window aborted on its first word: no value to print on the next lines */
    }
    b->t1 = c->counter ? c->counter() : 0;
    read_word(c, WIN_TM(n), TM_TRDY, &b->rdy);
    agg_clear(&a);
    for (unsigned i = 0; i < SENSORS; i++) {
        if (b->st[0][i].st == V_OK) agg_sample(&a, n << 4 | i, b->st[0][i].v, b->code);
    }
    cells_line(c, n, &a);
    agg_merge(&c->tot[0], &a);
}

/* SUM1 and SUM2: V of all sensors, the extremes with their sensors, and what was flagged critical, out of range or odd. The order is the order of importance: a field that does not
 * fit the 100 characters is the last one, and only a page of extreme values (four digits everywhere) loses one, which END counts in CUTS. */
OUT_OF_LINE void sum_line(struct ctx *c, const char *name, const struct agg *a, unsigned second)
{
    struct pl_line line, item;
    pk_begin(&line, name);
    pl_begin(&item);
    tx(&item, "V=");
    dec(&item, a->valid);
    tx(&item, "/");
    dec(&item, INSTANCES * SENSORS);
    pk_add(c, &line, &item);
    pk_extreme(c, &line, "MIN=", a, 0, 1);
    pk_extreme(c, &line, "MAX=", a, 1, 1);
    if (second) {
        pl_begin(&item);
        tx(&item, "CHG=");
        dec(&item, a->chg);
        tx(&item, "/");
        dec(&item, a->both);
        pk_add(c, &line, &item);
        pk_number(c, &line, "DMAX=", (uint64_t)a->dmax);
    }
    pk_number(c, &line, "CRIT=", a->crit);
    pk_number(c, &line, "OUT=", a->out);
    pk_number(c, &line, "ODD=", a->odd);
    emit(c, &line, second);
}

/* ---- What a line says about the next read ---- */

/* The announcement that ends a line: ` NEXT T<m>` for the next block of the second reading, ` NEXT CONV T<m>` for the next block of the conversion pass. 0 when it did not fit: the
 * block it names must then not be read. */
OUT_OF_LINE int pk_next(struct ctx *c, struct pl_line *line, unsigned conv, unsigned m)
{
    struct pl_line item;
    pl_begin(&item);
    tx(&item, conv ? "NEXT CONV T" : "NEXT T");
    dec(&item, m);
    return pk_add(c, line, &item);
}

/* The first block, in page order, that the conversion pass reads: one that is still known to run (INSTANCES: none). */
OUT_OF_LINE unsigned first_conv(const struct ctx *c)
{
    for (unsigned k = 0; k < INSTANCES; k++)
        if (c->blk[block_order[k]].state == BS_OK) return block_order[k];
    return INSTANCES;
}

/* ---- Time ---- */

/* Waits `ticks` on the runner's counter: DELAY_OK when they have passed; DELAY_STUCK when the counter does not run (STUCK_READS identical values in a row, or a value below the
 * start); DELAY_SPIN when it runs but SPIN_MAX reads did not span the wait. */
OUT_OF_LINE unsigned delay_ticks(const struct ctx *c, uint64_t ticks)
{
    uint64_t start = c->counter(), last = start;
    uint32_t same = 0;
    unsigned moved = 0;
    for (uint32_t spins = 0; spins < SPIN_MAX; spins++) {
        uint64_t now = c->counter();
        if (now < start) return DELAY_STUCK;
        if (now - start >= ticks) return DELAY_OK;
        if (now == last) {
            if (++same >= STUCK_READS) return DELAY_STUCK;
        } else {
            last = now;
            same = 0;
            moved = 1;
        }
    }
    return moved ? DELAY_SPIN : DELAY_STUCK;
}

/* ---- The second reading: the same status words, one block at a time, each line naming what is read next ---- */

/* The second reading of one block: CTRL, the sixteen status words, TRDY last. Its line ends in the announcement of what is read next: the next block of this pass or, after the last,
 * the first block of the conversion pass. A block whose CTRL no longer says it runs (or does not read) is marked so, and neither this pass nor the conversion pass reads it again.
 * Returns 0 when the line, or the announcement in it, did not go out: nothing further may be read. */
OUT_OF_LINE int block_two(struct ctx *c, unsigned n, unsigned next)
{
    struct blk *b = &c->blk[n];
    struct val ctl, rdy, bad;
    struct agg a;
    struct pl_line head, line, item;
    unsigned announced = 1, named = 0, conv, printed;
    blk_head(&head, "S2 ", n);
    pk_begin(&line, head.buf);
    agg_clear(&a);
    read_word(c, WIN_SROT(n), SROT_CTRL, &ctl);
    if (!running(&ctl)) {
        if (ctl.st == V_OK) {
            b->state = BS_OFF;
            pk_text(c, &line, "OFF");
        } else {
            b->state = BS_CTLERR;
            pk_word(c, &line, "CTL=", &ctl);
            pk_text(c, &line, "CTLERR");
        }
    } else {
        uint64_t now;
        unsigned code = !(ctl.v & CTRL_CODE_OR_TEMP);
        /* The first word that did not read is the one the line shows; the others are in SKIPS and FAULTS. */
        bad.st = V_OK;
        bad.v = bad.code = 0;
        for (unsigned i = 0; i < SENSORS; i++) {
            struct val *w = &b->st[1][i];
            int32_t before, after;
            read_word(c, WIN_TM(n), TM_STATUS + 4u * i, w);
            if (w->st != V_OK) {
                if (bad.st == V_OK) val_copy(&bad, w);
                continue;
            }
            agg_sample(&a, n << 4 | i, w->v, code);
            if (b->st[0][i].st == V_OK && classify(b->st[0][i].v, b->code, &before) == K_OK && classify(w->v, code, &after) == K_OK) {
                int32_t d = after > before ? after - before : before - after;
                a.both++;
                if (d) a.chg++;
                if (d > a.dmax) a.dmax = d;
            }
        }
        now = c->counter();
        read_word(c, WIN_TM(n), TM_TRDY, &rdy);
        if (rdy.st != V_OK && bad.st == V_OK) val_copy(&bad, &rdy);
        pk_number(c, &line, "V=", a.valid);
        pk_extreme(c, &line, "MIN=", &a, 0, 0);
        pk_extreme(c, &line, "MAX=", &a, 1, 0);
        pk_number(c, &line, "CHG=", a.chg);
        pk_number(c, &line, "D=", (uint64_t)a.dmax);
        if (b->t1 && now > b->t1) pk_number(c, &line, "DT=", (now - b->t1) * 1000u / c->hz);
        if (code) pk_text(c, &line, "CODE");
        if (bad.st != V_OK) {
            pl_begin(&item);
            word_text(c, &item, &bad, 0);
            pk_add(c, &line, &item);
        }
    }
    if (next < INSTANCES) {
        announced = pk_next(c, &line, 0, next);
    } else if ((conv = first_conv(c)) < INSTANCES) {
        named = pk_next(c, &line, 1, conv);
    }
    printed = emit(c, &line, 0);
    if (printed && named) c->conv_named = 1;
    agg_merge(&c->tot[1], &a);
    return printed && announced;
}

OUT_OF_LINE void snapshot_two(struct ctx *c)
{
    unsigned todo[INSTANCES], count = 0;
    for (unsigned k = 0; k < INSTANCES; k++) {
        unsigned n = block_order[k];
        /* Only a block whose TM window answered in the first reading is read again. */
        if (c->blk[n].state == BS_OK && !(c->dead >> WIN_TM(n) & 1)) todo[count++] = n;
    }
    if (!count) {
        say(c, "S2 SKIPPED NO_BLOCK", 0);
        return;
    }
    if (!c->counter) {
        say(c, "S2 SKIPPED NO_COUNTER", 0);
        return;
    }
    {
        struct pl_line text;
        pl_begin(&text);
        tx(&text, "NEXT S2 AFTER ");
        dec(&text, GAP_S);
        tx(&text, " S");
        if (!say(c, text.buf, 0)) return;
    }
    switch (delay_ticks(c, (uint64_t)GAP_S * c->hz)) {
    case DELAY_OK:
        break;
    case DELAY_SPIN:
        say(c, "S2 SKIPPED SPIN", 0);
        return;
    default:
        say(c, "S2 SKIPPED NO_COUNTER", 0);
        return;
    }
    c->t_second = c->counter();
    for (unsigned k = 0; k < count; k++)
        if (!block_two(c, todo[k], k + 1 < count ? todo[k + 1] : INSTANCES)) break;
}

/* ---- The conversion words and the interrupt status words: after the second reading, one block at a time ---- */

/* The sixteen conversion words of a block's SROT window and the two interrupt status words of its TM window, on one line that names the next block (INSTANCES: none). Linux reads none of
 * the eighteen offsets but 0x14, and that only as its bit 31, which is why they come after everything else. Returns 0 when the line, or the announcement in it, did not go out. */
OUT_OF_LINE int conv_block(struct ctx *c, unsigned n, unsigned next)
{
    struct val w, ul, cr;
    struct pl_line head, line, item;
    uint32_t nz = 0, lo = 0, hi = 0;
    unsigned seen = 0, all = 1, announced = 1;
    for (unsigned i = 0; i < SENSORS; i++) {
        read_word(c, WIN_SROT(n), SROT_CONV + 4u * i, &w);
        if (w.st != V_OK) {
            all = 0;
            break;
        }
        if (w.v) {
            nz++;
            if (!seen || w.v < lo) lo = w.v;
            if (!seen || w.v > hi) hi = w.v;
            seen = 1;
        }
    }
    read_word(c, WIN_TM(n), TM_UL_STATUS, &ul);
    read_word(c, WIN_TM(n), TM_CRIT_STATUS, &cr);
    blk_head(&head, "CONV ", n);
    pk_begin(&line, head.buf);
    pl_begin(&item);
    tx(&item, "NZ=");
    if (all) dec(&item, nz);
    else tx(&item, "X");
    tx(&item, "/");
    dec(&item, SENSORS);
    pk_add(c, &line, &item);
    pl_begin(&item);
    tx(&item, "LO=");
    if (seen) hx(c, &item, lo);
    else tx(&item, "NA");
    pk_add(c, &line, &item);
    pl_begin(&item);
    tx(&item, "HI=");
    if (seen) hx(c, &item, hi);
    else tx(&item, "NA");
    pk_add(c, &line, &item);
    pk_word(c, &line, "UL=", &ul);
    pk_word(c, &line, "CR=", &cr);
    if (next < INSTANCES) announced = pk_next(c, &line, 1, next);
    return emit(c, &line, 0) && announced;
}

OUT_OF_LINE void conv_pass(struct ctx *c)
{
    unsigned todo[INSTANCES], count = 0;
    for (unsigned k = 0; k < INSTANCES; k++)
        if (c->blk[block_order[k]].state == BS_OK) todo[count++] = block_order[k];
    if (!count) return;
    if (!c->conv_named) {
        struct pl_line text;
        pl_begin(&text);
        tx(&text, "NEXT CONV T");
        dec(&text, todo[0]);
        if (!say(c, text.buf, 0)) return;
    }
    for (unsigned k = 0; k < count; k++)
        if (!conv_block(c, todo[k], k + 1 < count ? todo[k + 1] : INSTANCES)) break;
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
    say(&c, "KEY T0..T3=BLOCK R=RAW STATUS HEX C=TENTHS OF C INFERRED ?=NOT VALID X=NOT READ O=ODD", 0);

    c.t_first = c.counter ? c.counter() : 0;
    for (unsigned k = 0; k < INSTANCES; k++) block_one(&c, block_order[k]);
    sum_line(&c, "SUM1", &c.tot[0], 0);
    snapshot_two(&c);
    conv_pass(&c);
    sum_line(&c, "SUM2", &c.tot[1], 1);

    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "END LOADS=");
    dec(&line, c.loads);
    tx(&line, " FAULTS=");
    dec(&line, c.faults);
    tx(&line, " SKIPS=");
    dec(&line, c.skips);
    tx(&line, " GATED=");
    dec(&line, c.gated);
    tx(&line, " CUTS=");
    dec(&line, c.cuts);
    tx(&line, " GAP_MS=");
    dec(&line, c.t_second > c.t_first ? (c.t_second - c.t_first) * 1000u / c.hz : 0);
    tx(&line, " LINES=");
    dec(&line, c.lines + 1u);
    emit(&c, &line, 1);
    return 0;
}
