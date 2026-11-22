/* SPDX-License-Identifier: MIT */
/* Payload "gpusnap2": experiment E1 of the GPU port plan (docs/SP11-GPU-PORT-PLAN.md of the Snapintosh tree and its v2, section 5), the read-only complement of gpusnap. It asks whether the GPU's
 * power-on stage needs rail votes and PLLs, and gives a thermal and speed-bin baseline: the command database in DRAM (the addresses and level tables of the rails and the bus clock managers the GPU
 * uses), what the apps RSC's wake TCSs hold, the two GPUCC PLLs and the clock words boot 30 did not read, tsens3's sensors 5 to 12, and the speed-bin fuse. docs/SP11-PAYLOAD-GPUSNAP2.md has the
 * registers with their file:line and evidence labels, the page, the gates, why every read is harmless and what each outcome would mean. Reads of the command database, the apps RSC and the QFPROM
 * have never been made on the unit: whether any of them aborts, hangs or raises an SError is UNKNOWN, and a load that hangs the bus is not recovered by anything, so the order of the reads is the
 * safety argument.
 *
 * Every access is an ops.load32 (a synchronous abort comes back as a code, never as an exception; an SError is neither caught by it nor printed): the registers, the DRAM of the command database
 * and the UEFI memory map alike, never through a pointer. The only system register is CurrentEL: there is no counter, no wait and no second snapshot. The only stores are to this payload's own
 * stack, and that is the only memory it writes through any pointer: no pointer is kept in memory (the three ops it uses are copied into the context as function pointers, every data pointer is an
 * argument or a local), so that the compiled-code audit (tools/sp11_payload_gpusnap2_audit.py) and the binary check of tools/sp11_payload_memcheck.py can both prove it. No SMC, no HVC, no barrier.
 * Nothing is retried: the first abort in a window ends every later read of it. A block is announced by a `NEXT <block>` line first and is not read at all if the line cannot be printed, so that the
 * last line on the panel names what hung; a line is read whole and printed before the first load of the next, so that a hang keeps every line before the one it hit.
 *
 * The order of the blocks is the safety argument too. TSENS3 first: its status words were all read in boot 29. Then the one GCC word GPUCC needs, then GPUCC, read only if that word says the GPU's CFG
 * AHB clock runs (boot 30 read both: GPUCC answered; the words behind the GPU's CX domain, CX_MISC, the GMU, the RSC of the GPU and its SMMU, are never read, because CX is off and a read there could
 * hang). Then what has never been read: the command database, only if the final memory map describes all of it as reserved memory and its header carries Linux's magic; the apps RSC, only if its ID is
 * one of the two layouts this payload knows; the QFPROM last. A word that was not read, faulted, skipped or all ones never opens a gate, and what the page does not know it does not say.
 *
 * Page: a header and a legend; for each block either `NEXT <block>` and its lines or `<block> GATED BY <why>`; the end line. A value below 10 is one digit, a larger one 0X and the fewest upper-case
 * hex digits, except the raw status words (eight digits) and the votes and levels (decimal, as RPMh numbers them). At most LINE_CAP lines whatever the hardware says: a field that does not fit is
 * dropped and counted in CUTS, never cut in half. */
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* No MRS can run on a build machine: the host test supplies the register file. */
uint64_t pl_host_sysreg(const char *name);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#include "gpusnap2-regs.h"

#define PREFIX "PAYLOAD GPUSNAP2 "
#define OUT_OF_LINE static __attribute__((noinline))     /* one body per helper: the reviewed binary stays small */
#define LEGEND "KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=NOT TRUSTED NA=NOT READ -=NO VOTE TEMP=0.1 C"
_Static_assert(sizeof PREFIX - 1 + sizeof LEGEND - 1 <= Q1N1_PAYLOAD_LINE_MAX, "gpusnap2: the legend fits a line");

enum { RD_OK, RD_RANGE, RD_ALIGN, RD_DEAD, RD_BUDGET, RD_FAULT };
/* The state of one value: V_NONE not read, V_SKIP not read because an earlier load of its window aborted, V_ABSENT looked for in the whole database and not there, V_PART looked for in a database
 * the scan could not finish (a list longer than the cap, an entry outside the region), V_NOVOTE a TCS none of whose commands is for the rail. */
enum { V_NONE, V_OK, V_FAULT, V_SKIP, V_BUDGET, V_ABSENT, V_PART, V_NOVOTE };
/* A TSENS block: its HW_VER did not read as a block's, its CTRL says it is not running, its CTRL did not read. */
enum { TS_OK, TS_GATED, TS_OFF, TS_CTLERR };
/* What a status word is: VALID and plausible, VALID clear, odd, or VALID and outside TEMP_MIN_TENTHS..TEMP_MAX_TENTHS (as tsnap v1.1). */
enum { K_OK, K_INVALID, K_ODD, K_OUT };

/* The row sizes below are powers of two, so that indexing them is a shift: the binary check of tools/sp11_payload_memcheck.py proves where a store lands only for a base that is the stack plus a
 * shifted index, never for a product. */
struct val {
    uint32_t v;
    uint16_t code;                  /* what load32 returned, when it failed (the runner's codes are 1 to 6) */
    uint8_t st, pad;
};
_Static_assert(sizeof(struct val) == 8, "gpusnap2: a word record is 8 bytes");

/* What the database says of a target: its address (or why there is none), and where its aux data is and how long, in bytes. */
struct tgt {
    struct val addr;
    uint32_t aux, len;
};
_Static_assert(sizeof(struct tgt) == 16, "gpusnap2: a target record is 16 bytes");

struct rhdr {
    uint32_t slv, hoff, doff, cnt;
};
_Static_assert(sizeof(struct rhdr) == 16, "gpusnap2: a resource header record is 16 bytes");

struct mapscan {
    uint32_t state, desc, hits, type, attr, bad, nonres, pad;
    struct val fail;                /* the word whose read failed, when the state is MAP_ERR */
    uint64_t lo[MAP_HITS_MAX], hi[MAP_HITS_MAX];
};

struct ctx {
    void (*puts)(const char *line);
    uint32_t (*hex)(char *dst, uint32_t cap, uint64_t value);
    int32_t (*load32)(uint64_t addr, uint32_t *out);
    uint64_t map_base, map_size, map_stride;
    uint32_t word;                  /* the load32 destination: the runner wants it on the payload stack, and the context is */
    uint32_t err;                   /* what the last failed load32 returned */
    uint32_t loads, lines, cuts, faults, skips, blocks;
    uint32_t dead;                  /* a bit per window in which a load aborted */
    struct tgt tg[TARGETS];
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

OUT_OF_LINE void num(const struct ctx *c, struct pl_line *line, uint64_t value)
{
    if (value < 10) dec(line, value);
    else hx(c, line, value);
}

/* A line counts against LINE_CAP; the end line may use what the others may not. */
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

OUT_OF_LINE void pk_add(struct ctx *c, struct pl_line *line, const struct pl_line *item)
{
    if (line->len + 1 + item->len > Q1N1_PAYLOAD_LINE_MAX) {
        c->cuts++;
        return;
    }
    tx(line, " ");
    tx(line, item->buf);
}

OUT_OF_LINE void pk_text(struct ctx *c, struct pl_line *line, const char *text)
{
    struct pl_line item;
    pl_begin(&item);
    tx(&item, text);
    pk_add(c, line, &item);
}

OUT_OF_LINE void pk_dec(struct ctx *c, struct pl_line *line, const char *key, uint64_t value)
{
    struct pl_line item;
    pl_begin(&item);
    tx(&item, key);
    dec(&item, value);
    pk_add(c, line, &item);
}

/* The text of one value: the runner's 0X form, or why there is none. */
OUT_OF_LINE void word_text(const struct ctx *c, struct pl_line *item, const struct val *w)
{
    switch (w->st) {
    case V_OK:
        num(c, item, w->v);
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
    case V_ABSENT:
        tx(item, "NONE");
        break;
    case V_PART:
        tx(item, "PART");
        break;
    case V_NOVOTE:
        tx(item, "-");
        break;
    default:
        tx(item, "NA");
        break;
    }
}

/* A vote or a level is a number of RPMh's own (16 retention, 64 low SVS, 128 SVS ...) and is printed as one. */
OUT_OF_LINE void vote_text(const struct ctx *c, struct pl_line *item, const struct val *w)
{
    if (w->st == V_OK && w->v < 0x10000u) dec(item, w->v);
    else word_text(c, item, w);
}

OUT_OF_LINE void pk_word(struct ctx *c, struct pl_line *line, const char *key, const struct val *w)
{
    struct pl_line item;
    pl_begin(&item);
    tx(&item, key);
    word_text(c, &item, w);
    pk_add(c, line, &item);
}

/* `NEXT <block>`: no line, no read, so that what hangs is named. */
OUT_OF_LINE int announce(struct ctx *c, const char *block)
{
    struct pl_line text;
    pl_begin(&text);
    tx(&text, "NEXT ");
    tx(&text, block);
    return say(c, text.buf, 0);
}

OUT_OF_LINE void gated_line(struct ctx *c, unsigned win_mask, const char *head, unsigned why)
{
    struct pl_line line;
    c->blocks |= win_mask;
    pk_begin(&line, head);
    tx(&line, " GATED BY ");
    tx(&line, reason_name[why]);
    emit(c, &line, 0);
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

/* A word of a window. The first abort ends all reads of its window: whatever stopped one load would stop the next, and nothing is retried. A window the table does not have, a word outside its
 * window and a word that is not aligned are refused before anything is loaded. */
OUT_OF_LINE int rd32(struct ctx *c, unsigned win, uint32_t off, uint32_t *value)
{
    uint64_t base, size;
    int rc;
    *value = 0;
    if (win >= WINDOWS) return RD_RANGE;
    if (win == WIN_MAP) {
        base = c->map_base;
        size = c->map_size;
    } else {
        base = windows[win].base;
        size = windows[win].size;
    }
    if (off & 3) {
        rc = RD_ALIGN;
    } else if (off >= size || size - off < 4) {
        rc = RD_RANGE;
    } else if (c->dead >> win & 1) {
        rc = RD_DEAD;
    } else {
        rc = load(c, base + off, value);
        if (rc == RD_FAULT) c->dead |= 1u << win;
    }
    return rc;
}

OUT_OF_LINE void read_word(struct ctx *c, unsigned win, uint32_t off, struct val *w)
{
    uint32_t value;
    int rc = rd32(c, win, off, &value);
    w->v = 0;
    w->code = 0;
    w->pad = 0;
    w->st = V_NONE;
    switch (rc) {
    case RD_OK:
        w->v = value;
        w->st = V_OK;
        break;
    case RD_FAULT:
        w->st = V_FAULT;
        w->code = (uint16_t)c->err;
        c->faults++;
        c->blocks |= 1u << win;
        break;
    case RD_DEAD:
        w->st = V_SKIP;
        c->skips++;
        c->blocks |= 1u << win;
        break;
    case RD_BUDGET:
        w->st = V_BUDGET;
        c->blocks |= 1u << win;
        break;
    default:
        break;
    }
}

/* A word that was read and is not what a failed read returns. */
OUT_OF_LINE int word_ok(const struct val *w)
{
    return w->st == V_OK && w->v != 0xffffffffu;
}

/* ---- The sensors: tsens3, sensors 5 to 12 (the registers and the decode of tsnap v1.1) ---- */

/* A block's own identity: HW_VER read, and neither zero nor all ones, which is what a block that is not there (or a failed read) returns. */
OUT_OF_LINE int ident_ok(const struct val *w)
{
    return w->st == V_OK && w->v != 0 && w->v != 0xffffffffu;
}

/* Enabled and out of software reset, as tsens.c:1018-1031 requires of a block before it trusts it (tsens.c of the tsnap pins). */
OUT_OF_LINE int running(const struct val *w)
{
    return w->st == V_OK && (w->v & CTRL_EN) && !(w->v & CTRL_SW_RST);
}

/* A word whose sensor-number field (bits 26:22: INFERRED from the unit's own words in boot 29, docs/SP11-PAYLOAD-TSNAP.md says how) is not the sensor's own index, or with a reserved bit (31:27) set,
 * is not the layout the film describes, so it is not decoded. A VALID word of a block whose CTRL has CODE_OR_TEMP clear is not a temperature either (INFERRED: ADC codes). The field is checked
 * before VALID, so that a sensor that is not enabled and reads its own number alone is `?` and one that reads anything else is `O`. */
OUT_OF_LINE unsigned classify(uint32_t raw, unsigned code, unsigned sensor, int32_t *tenths)
{
    int32_t t = (int32_t)(raw & ST_TEMP_MASK);
    if (t & 0x800) t -= 0x1000;
    *tenths = t;
    if (raw >> ST_RESERVED_SHIFT || (raw >> ST_ID_SHIFT & ST_ID_MASK) != sensor) return K_ODD;
    if (!(raw & ST_VALID)) return K_INVALID;
    if (code) return K_ODD;
    if (t < TEMP_MIN_TENTHS || t > TEMP_MAX_TENTHS) return K_OUT;
    return K_OK;
}

/* One cell of the temperature line: tenths of a degree, or ? (VALID clear), O (odd, or out of range), X (not read). */
OUT_OF_LINE void cell(struct pl_line *item, const struct val *w, unsigned code, unsigned sensor)
{
    int32_t t;
    if (w->st != V_OK) {
        tx(item, "X");
        return;
    }
    switch (classify(w->v, code, sensor, &t)) {
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

/* The identity of the block, printed before the first load of its TM window: after it the panel says that the next loads are the status words, and a hang there leaves VER and CTL on the screen. */
OUT_OF_LINE int ts_identity(struct ctx *c, const struct val *ver, const struct val *ctl, unsigned state, unsigned code)
{
    struct pl_line line, item;
    pk_begin(&line, "T3");
    pk_word(c, &line, "VER=", ver);
    if (ctl->st != V_NONE) pk_word(c, &line, "CTL=", ctl);
    if (ctl->st == V_OK) {
        pl_begin(&item);
        tx(&item, "SEN=");
        hx(c, &item, (ctl->v >> CTRL_SENSOR_SHIFT) & CTRL_SENSOR_MASK);
        pk_add(c, &line, &item);
    }
    if (state == TS_OK && code) pk_text(c, &line, "CODE");
    if (state == TS_GATED) pk_text(c, &line, "GATED");
    if (state == TS_OFF) pk_text(c, &line, "OFF");
    if (state == TS_CTLERR) pk_text(c, &line, "CTLERR");
    return emit(c, &line, 0);
}

/* The temperature line: the cells in sensor order, then how many were valid, the extremes with their sensors, and what was flagged critical, out of range or odd (only when it was: no field
 * means none). */
OUT_OF_LINE void ts_cells(struct ctx *c, const struct val *st, unsigned code)
{
    struct pl_line line, item;
    unsigned valid = 0, odd = 0, out = 0, crit = 0, min_at = 0, max_at = 0;
    int32_t min = 0, max = 0;
    pk_begin(&line, "T3 C5");
    for (unsigned i = 0; i < TS_COUNT; i++) {
        int32_t t;
        unsigned kind;
        pl_begin(&item);
        cell(&item, &st[i], code, TS_FIRST + i);
        pk_add(c, &line, &item);
        if (st[i].st != V_OK) continue;
        kind = classify(st[i].v, code, TS_FIRST + i, &t);
        if (kind != K_ODD && (st[i].v & ST_CRIT_FLAGS)) crit++;
        if (kind == K_ODD) {
            odd++;
        } else if (kind == K_OUT) {
            out++;
        } else if (kind == K_OK) {
            if (!valid || t < min) {
                min = t;
                min_at = TS_FIRST + i;
            }
            if (!valid || t > max) {
                max = t;
                max_at = TS_FIRST + i;
            }
            valid++;
        }
    }
    pk_dec(c, &line, "V=", valid);
    pl_begin(&item);
    tx(&item, "MIN=");
    if (valid) {
        sdec(&item, min);
        tx(&item, "(S");
        dec(&item, min_at);
        tx(&item, ")");
    } else {
        tx(&item, "NA");
    }
    pk_add(c, &line, &item);
    pl_begin(&item);
    tx(&item, "MAX=");
    if (valid) {
        sdec(&item, max);
        tx(&item, "(S");
        dec(&item, max_at);
        tx(&item, ")");
    } else {
        tx(&item, "NA");
    }
    pk_add(c, &line, &item);
    if (crit) pk_dec(c, &line, "CRIT=", crit);
    if (out) pk_dec(c, &line, "OUT=", out);
    if (odd) pk_dec(c, &line, "ODD=", odd);
    emit(c, &line, 0);
}

OUT_OF_LINE void tsens_block(struct ctx *c)
{
    struct val ver, ctl, st[TS_COUNT];
    struct pl_line line, item;
    unsigned code;
    if (!announce(c, "TSENS3")) {
        c->blocks |= 1u << WIN_TSROT | 1u << WIN_TTM;
        return;
    }
    ctl.st = V_NONE;
    ctl.v = 0;
    ctl.code = ctl.pad = 0;
    read_word(c, WIN_TSROT, SROT_HW_VER, &ver);
    if (!ident_ok(&ver)) {
        c->blocks |= 1u << WIN_TSROT;
        ts_identity(c, &ver, &ctl, TS_GATED, 0);
        return;
    }
    read_word(c, WIN_TSROT, SROT_CTRL, &ctl);
    if (!running(&ctl)) {
        c->blocks |= 1u << WIN_TSROT;
        ts_identity(c, &ver, &ctl, ctl.st == V_OK ? TS_OFF : TS_CTLERR, 0);
        return;
    }
    code = !(ctl.v & CTRL_CODE_OR_TEMP);
    if (!ts_identity(c, &ver, &ctl, TS_OK, code)) {
        c->blocks |= 1u << WIN_TTM;
        return;
    }
    pk_begin(&line, "T3 R5");
    for (unsigned i = 0; i < TS_COUNT; i++) {
        read_word(c, WIN_TTM, TM_STATUS + 4u * (TS_FIRST + i), &st[i]);
        pl_begin(&item);
        if (st[i].st == V_OK) hex8(&item, st[i].v);
        else word_text(c, &item, &st[i]);
        pk_add(c, &line, &item);
    }
    emit(c, &line, 0);
    if (st[0].st != V_OK && c->dead >> WIN_TTM & 1) return;      /* the TM window aborted on its first word: no value to print on the next line */
    ts_cells(c, st, code);
}

/* ---- The clock words: GCC and GPUCC ---- */

/* A branch clock's word as a decode: .OFF is bit 31 (CLK_OFF) set, .ON is it clear with CLK_ENABLE set. `.ODD` marks the cell where that cannot be taken at its word: all ones is what a failed read
 * returns; CLK_OFF clear with CLK_ENABLE clear is a clock that says it runs without being enabled, which is what a window of zeros reads; a CLK_OFF with an NoC FSM status of ON counts as on for
 * Linux (clk-branch.c:54-58). This is the decode only: whether a clock runs is clock_runs()'s. */
OUT_OF_LINE int cell_is_odd(uint32_t w)
{
    if (w == 0xffffffffu) return 1;
    if (!(w >> CBCR_CLK_OFF_BIT & 1)) return !(w >> CBCR_ENABLE_BIT & 1);
    return (w >> CBCR_FSM_SHIFT & CBCR_FSM_MASK) == CBCR_FSM_ON;
}

/* A branch clock runs when its word was read, CLK_ENABLE is set and CLK_OFF is clear: positive proof, as Linux asks for when it enables one (clk-branch.c:54-58) but without its extra readings,
 * which would open a gate on less. */
OUT_OF_LINE int clock_runs(const struct val *w)
{
    return word_ok(w) && (w->v >> CBCR_ENABLE_BIT & 1) && !(w->v >> CBCR_CLK_OFF_BIT & 1);
}

/* A field of a value as its own field. A value that was not read shows why, as the register does; a field of a word of all ones is no field: all ones is what a failed read returns, so the cell
 * says ODD and the raw word beside it says why. */
OUT_OF_LINE void put_bits(struct ctx *c, struct pl_line *line, const char *name, const struct val *v, unsigned shift, uint32_t mask)
{
    struct pl_line item;
    struct val field;
    field.st = v->st;
    field.code = v->code;
    field.pad = 0;
    field.v = v->v >> shift & mask;
    pl_begin(&item);
    tx(&item, name);
    tx(&item, "=");
    if (v->st == V_OK && v->v == 0xffffffffu) tx(&item, "ODD");
    else word_text(c, &item, &field);
    pk_add(c, line, &item);
}

OUT_OF_LINE void put_reg(struct ctx *c, struct pl_line *line, unsigned id)
{
    const struct reg *r = &regs[id];
    const struct val *v = &c->v[id];
    struct pl_line item;
    pl_begin(&item);
    tx(&item, r->key);
    tx(&item, "=");
    word_text(c, &item, v);
    if (v->st == V_OK) {
        /* CLK_OFF of a branch clock, with the modes that make it untrustworthy (cell_is_odd) */
        if (r->dec == D_CBCR) tx(&item, cell_is_odd(v->v) ? ".ODD" : v->v >> CBCR_CLK_OFF_BIT & 1 ? ".OFF" : ".ON");
        /* ROOT_OFF of a root clock generator's command word (clk-rcg2.c:33): the NoC FSM of a branch clock does not exist there */
        if (r->dec == D_RCGCMD) tx(&item, v->v == 0xffffffffu ? ".ODD" : v->v >> CBCR_CLK_OFF_BIT & 1 ? ".OFF" : ".ON");
        /* a GDSC's PWR_ON */
        if (r->dec == D_PWR) tx(&item, v->v == 0xffffffffu ? ".ODD" : v->v >> GDSC_PWR_ON_BIT & 1 ? ".ON" : ".OFF");
    }
    pk_add(c, line, &item);
    if (r->dec == D_GDSCR) {
        put_bits(c, line, "SC", v, GDSC_SW_COLLAPSE_BIT, 1);
        put_bits(c, line, "HW", v, GDSC_HW_CONTROL_BIT, 1);
    } else if (r->dec == D_RCGCFG) {
        put_bits(c, line, "S", v, RCG_SRC_SHIFT, RCG_SRC_MASK);
    }
}

/* A PLL's verdict from its MODE and OPMODE words: enabled when OPMODE has RUN and MODE has OUTCTRL, which is what both PLLs' ops call enabled (trion_pll_is_enabled, clk-alpha-pll.c:1078-1090);
 * off when both were read and say otherwise; NA when one was not read; ODD when one is all ones. LK is MODE's LOCK_DET. */
OUT_OF_LINE void put_pll(struct ctx *c, struct pl_line *line, const struct val *mode, const struct val *op)
{
    struct pl_line item;
    pl_begin(&item);
    tx(&item, "EN=");
    if (mode->st != V_OK || op->st != V_OK) tx(&item, "NA");
    else if (mode->v == 0xffffffffu || op->v == 0xffffffffu) tx(&item, "ODD");
    else tx(&item, (op->v >> PLL_RUN_BIT & 1) && (mode->v >> PLL_OUTCTRL_BIT & 1) ? "ON" : "OFF");
    pk_add(c, line, &item);
    put_bits(c, line, "LK", mode, PLL_LOCK_DET_BIT, 1);
}

OUT_OF_LINE void read_row(struct ctx *c, unsigned id)
{
    read_word(c, regs[id].win, regs[id].off, &c->v[id]);
}

/* One line of the table: its rows are read, then the line goes out. */
OUT_OF_LINE void table_line(struct ctx *c, unsigned li)
{
    const struct line_def *d = &lines[li];
    struct pl_line line;
    for (unsigned id = d->first; id < d->end; id++) read_row(c, id);
    pk_begin(&line, d->head);
    for (unsigned id = d->first; id < d->end; id++) put_reg(c, &line, id);
    if (d->pll) put_pll(c, &line, &c->v[d->first], &c->v[d->first + 1u]);
    emit(c, &line, 0);
}

/* The CFG AHB gate (gcc-x1e80100.c:7451): open when the word reads as running; AHB when it was read and does not; AHBERR when it was not read (an abort, a skip, all ones), which is not the same
 * statement: a failed gate read is never reported as the thing it gates on. */
OUT_OF_LINE unsigned ahb_reason(const struct ctx *c)
{
    if (clock_runs(&c->v[R_CFGA])) return RS_OPEN;
    return word_ok(&c->v[R_CFGA]) ? RS_AHB : RS_AHB_ERR;
}

OUT_OF_LINE void gcc_block(struct ctx *c)
{
    if (!announce(c, "GCC")) {
        c->blocks |= 1u << WIN_GCC;
        return;
    }
    for (unsigned li = 0; li < LINES; li++) {
        if (lines[li].win == WIN_GCC) table_line(c, li);
    }
}

OUT_OF_LINE void gpucc_block(struct ctx *c)
{
    unsigned why = ahb_reason(c);
    if (why) {
        gated_line(c, 1u << WIN_GPUCC, "GPUCC", why);
        return;
    }
    if (!announce(c, "GPUCC")) {
        c->blocks |= 1u << WIN_GPUCC;
        return;
    }
    for (unsigned li = 0; li < LINES; li++) {
        if (lines[li].win == WIN_GPUCC) table_line(c, li);
    }
}

/* ---- The command database ---- */

OUT_OF_LINE int in_region(uint32_t off, uint32_t bytes)
{
    return off <= windows[WIN_CMDDB].size && windows[WIN_CMDDB].size - off >= bytes;
}

/* The memory map the runner was given (a->map_*) as usable: aligned, with a descriptor size the UEFI spec allows, a whole number of descriptors and not more than the scan can hold. */
OUT_OF_LINE int map_args_ok(const struct ctx *c)
{
    if (!c->map_base || (c->map_base & 7) || !c->map_size) return 0;
    if (c->map_stride < MAP_STRIDE_MIN || c->map_stride > MAP_STRIDE_MAX || (c->map_stride & 7)) return 0;
    if (c->map_size % c->map_stride || c->map_size / c->map_stride > MAP_DESC_MAX) return 0;
    return c->map_base + c->map_size >= c->map_base && c->map_base + c->map_size <= MAP_ADDR_LIMIT;
}

/* Reads the final memory map and decides whether the whole command database is described as reserved memory: the descriptors that overlap it must all be EfiReservedMemoryType and together cover
 * it (the rule of the A16 flow, tools/a16gpu.py step_cmd_db: a region the map does not describe, or describes as memory the OS or the loader may reuse, is not read). Every descriptor is read: a
 * map is not sorted by contract, and one that overlaps the region may come last. A descriptor that is not page aligned, or whose end is beyond the 48-bit address space, damages the map for this
 * purpose: BAD overrides the rest, ERR (a map word that did not read) overrides everything. */
OUT_OF_LINE void map_scan(struct ctx *c, struct mapscan *m)
{
    static const uint8_t word_at[4] = {MAP_PHYS_OFF, MAP_PHYS_OFF + 4, MAP_PAGES_OFF, MAP_PAGES_OFF + 4};
    const uint64_t reg_lo = windows[WIN_CMDDB].base, reg_hi = windows[WIN_CMDDB].base + windows[WIN_CMDDB].size;
    unsigned n;
    m->state = MAP_BAD;
    m->desc = m->hits = m->type = m->attr = m->bad = m->nonres = m->pad = 0;
    m->fail.v = 0;
    m->fail.code = m->fail.pad = 0;
    m->fail.st = V_NONE;
    if (!map_args_ok(c)) return;
    n = (unsigned)(c->map_size / c->map_stride);
    m->desc = n;
    for (unsigned i = 0; i < n; i++) {
        uint32_t at = (uint32_t)(i * c->map_stride);
        struct val w[4], type, attr;
        uint64_t start, pages, end;
        for (unsigned k = 0; k < 4; k++) {
            read_word(c, WIN_MAP, at + word_at[k], &w[k]);
            if (w[k].st != V_OK) {
                m->fail = w[k];
                m->state = MAP_ERR;
                return;
            }
        }
        start = (uint64_t)w[1].v << 32 | w[0].v;
        pages = (uint64_t)w[3].v << 32 | w[2].v;
        if (!pages) continue;
        if ((start & ((1ull << EFI_PAGE_SHIFT) - 1)) || start >= MAP_ADDR_LIMIT || pages >= MAP_ADDR_LIMIT >> EFI_PAGE_SHIFT ||
            start + (pages << EFI_PAGE_SHIFT) > MAP_ADDR_LIMIT) {
            m->bad = 1;
            continue;
        }
        end = start + (pages << EFI_PAGE_SHIFT);
        if (start >= reg_hi || end <= reg_lo) continue;
        if (m->hits >= MAP_HITS_MAX) {
            m->bad = 1;
            continue;
        }
        read_word(c, WIN_MAP, at + MAP_TYPE_OFF, &type);
        if (type.st == V_OK) read_word(c, WIN_MAP, at + MAP_ATTR_OFF, &attr);
        else attr = type;
        if (attr.st != V_OK) {
            m->fail = type.st != V_OK ? type : attr;
            m->state = MAP_ERR;
            return;
        }
        if (!m->hits) {
            m->type = type.v;
            m->attr = attr.v;
        }
        if (type.v != EFI_RESERVED) m->nonres = 1;
        m->lo[m->hits] = start;
        m->hi[m->hits] = end;
        m->hits++;
    }
    if (m->bad) {
        m->state = MAP_BAD;
    } else if (!m->hits) {
        m->state = MAP_NONE;
    } else if (m->nonres) {
        m->state = MAP_TYPE;
    } else {
        /* Every pass extends the covered run from the region's start by one more overlapping descriptor, if there is one that touches it. */
        uint64_t cover = reg_lo;
        for (unsigned pass = 0; pass < m->hits; pass++) {
            for (unsigned k = 0; k < m->hits; k++) {
                if (m->lo[k] <= cover && m->hi[k] > cover) cover = m->hi[k];
            }
        }
        m->state = cover >= reg_hi ? MAP_OPEN : MAP_PART;
    }
}

OUT_OF_LINE void map_line(struct ctx *c, const struct mapscan *m)
{
    struct pl_line line, item;
    pk_begin(&line, "CMDDB MAP");
    pk_dec(c, &line, "DESC=", m->desc);
    pk_dec(c, &line, "HITS=", m->hits);
    if (m->hits && m->state != MAP_ERR) {
        pk_dec(c, &line, "T=", m->type);
        pl_begin(&item);
        tx(&item, "ATTR=");
        num(c, &item, m->attr);
        pk_add(c, &line, &item);
    }
    if (m->state == MAP_ERR) {
        pl_begin(&item);
        word_text(c, &item, &m->fail);
        pk_add(c, &line, &item);
    }
    pk_text(c, &line, map_name[m->state]);
    emit(c, &line, 0);
}

OUT_OF_LINE int rail_usable(const struct ctx *c, unsigned r)
{
    return c->tg[r].addr.st == V_OK && c->tg[r].addr.v != 0;
}

/* The level table of a rail, `<n>:<first up to eight, decimal, slash separated>`; or why there is none. The aux data is an array of 16-bit levels (a6xx_gmu.c:1823-1838): it may start on the
 * upper half of an aligned word, and then the first half word is skipped; an odd byte offset is not a layout this payload knows. */
OUT_OF_LINE void lvl_item(struct ctx *c, struct pl_line *line, unsigned t)
{
    const struct tgt *g = &c->tg[t];
    struct pl_line item;
    unsigned levels, shown, first, words;
    pl_begin(&item);
    tx(&item, targets[t].key);
    tx(&item, "=");
    if (g->addr.st != V_OK) {
        word_text(c, &item, &g->addr);
    } else if (g->len < 2) {
        tx(&item, "EMPTY");
    } else if (g->aux & 1) {
        tx(&item, "ODD");
    } else {
        levels = g->len / 2;
        shown = levels < LEVELS_MAX ? levels : LEVELS_MAX;
        first = g->aux >> 1 & 1;
        words = (first + shown + 1) / 2;
        if (!in_region(g->aux & ~3u, 4u * words)) {
            tx(&item, "RANGE");
        } else {
            dec(&item, levels);
            tx(&item, ":");
            for (unsigned w = 0; w < words; w++) {
                struct val x;
                read_word(c, WIN_CMDDB, (g->aux & ~3u) + 4u * w, &x);
                if (x.st != V_OK) {
                    if (w) tx(&item, "/");
                    word_text(c, &item, &x);
                    break;
                }
                for (unsigned half = 0; half < 2; half++) {
                    unsigned at = 2u * w + half;
                    if (at < first || at - first >= shown) continue;
                    if (at != first) tx(&item, "/");
                    dec(&item, half ? x.v >> 16 : x.v & 0xffffu);
                }
            }
        }
    }
    pk_add(c, line, &item);
}

/* One target's address, or why it has none. */
OUT_OF_LINE void addr_item(struct ctx *c, struct pl_line *line, unsigned t)
{
    struct pl_line item;
    pl_begin(&item);
    tx(&item, targets[t].key);
    tx(&item, "=");
    word_text(c, &item, &c->tg[t].addr);
    pk_add(c, line, &item);
}

OUT_OF_LINE void addr_line(struct ctx *c, const char *head, unsigned first, unsigned end)
{
    struct pl_line line;
    pk_begin(&line, head);
    for (unsigned t = first; t < end; t++) addr_item(c, &line, t);
    emit(c, &line, 0);
}

OUT_OF_LINE void lvl_line(struct ctx *c, unsigned first, unsigned end)
{
    struct pl_line line;
    pk_begin(&line, "CMDDB LVL");
    for (unsigned t = first; t < end; t++) lvl_item(c, &line, t);
    emit(c, &line, 0);
}

/* The database's own layout (cmd-db.c:36-80, 144-176): a header of a version, a magic, eight resource headers and a checksum; per slave type a list of 24-byte entries whose ids are eight bytes
 * zero padded; per entry its address, and the length and offset of its aux data. Only the ARC and BCM lists are walked: the targets are of those kinds, and the VRM list holds the PMIC rails by the
 * hundred. A list that is longer than the cap is not a proof of absence: the target it leaves unfound is PART, not NONE. The entries of a list cannot run out of the region (see the static
 * assertion), but a list whose offset is not word aligned cannot be read by a 32-bit load, and then that entry word does not read (NA) and ends the walk, like a word that aborts: what the walk
 * left undecided shows that word's own token. */
_Static_assert(CMDDB_HDR_BYTES + 0xffffu + CMDDB_ENTRY_BYTES * CMDDB_ENTRY_MAX <= CMDDB_BYTES, "gpusnap2: no entry of a capped list is outside the database");
OUT_OF_LINE void cmddb_walk(struct ctx *c, const struct rhdr *rh, unsigned nh)
{
    struct val w0, w1, fail;
    unsigned cut = 0, scanned = 0, failed = 0;
    fail.v = 0;
    fail.code = fail.pad = 0;
    fail.st = V_NONE;
    for (unsigned h = 0; h < nh && !failed; h++) {
        unsigned slv = rh[h].slv, limit = rh[h].cnt;
        if (slv != CMDDB_SLV_ARC && slv != CMDDB_SLV_BCM) continue;
        if (limit > CMDDB_ENTRY_MAX) {
            limit = CMDDB_ENTRY_MAX;
            cut |= 1u << slv;
        }
        for (unsigned j = 0; j < limit && !failed; j++) {
            uint32_t at = CMDDB_HDR_BYTES + rh[h].hoff + j * CMDDB_ENTRY_BYTES;
            if (scanned >= CMDDB_SCAN_MAX) {
                cut |= 1u << slv;
                break;
            }
            scanned++;
            read_word(c, WIN_CMDDB, at, &w0);
            if (w0.st != V_OK) {
                fail = w0;
                failed = 1;
                break;
            }
            for (unsigned t = 0; t < TARGETS && !failed; t++) {
                struct val a, lo;
                if (targets[t].slv != slv || c->tg[t].addr.st != V_NONE || targets[t].w0 != w0.v) continue;
                read_word(c, WIN_CMDDB, at + 4, &w1);
                if (w1.st != V_OK) {
                    fail = w1;
                    failed = 1;
                } else if (targets[t].w1 == w1.v) {
                    read_word(c, WIN_CMDDB, at + 16, &a);
                    if (a.st == V_OK) read_word(c, WIN_CMDDB, at + 20, &lo);
                    else lo = a;
                    if (lo.st != V_OK) {
                        fail = a.st != V_OK ? a : lo;
                        failed = 1;
                    } else {
                        c->tg[t].addr = a;
                        c->tg[t].len = lo.v & 0xffffu;
                        c->tg[t].aux = CMDDB_HDR_BYTES + rh[h].doff + (lo.v >> 16);
                    }
                }
            }
        }
    }
    for (unsigned t = 0; t < TARGETS; t++) {
        if (c->tg[t].addr.st != V_NONE) continue;
        if (failed) c->tg[t].addr = fail;
        else c->tg[t].addr.st = cut >> targets[t].slv & 1 ? V_PART : V_ABSENT;
    }
}

OUT_OF_LINE void cmddb_open(struct ctx *c)
{
    struct val ver, magic, w0, w1;
    struct rhdr rh[CMDDB_SLV_MAX];
    struct pl_line line, item;
    unsigned nh = 0, arc = 0, bcm = 0, failed = 0;
    w0.v = w1.v = 0;
    w0.code = w1.code = w0.pad = w1.pad = 0;
    w0.st = w1.st = V_NONE;
    read_word(c, WIN_CMDDB, 0, &ver);
    read_word(c, WIN_CMDDB, 4, &magic);
    pk_begin(&line, "CMDDB HDR");
    pk_word(c, &line, "VER=", &ver);
    pl_begin(&item);
    tx(&item, "MAGIC=");
    if (magic.st != V_OK) word_text(c, &item, &magic);
    else tx(&item, magic.v == CMDDB_MAGIC ? "OK" : "BAD");
    pk_add(c, &line, &item);
    if (magic.st != V_OK || magic.v != CMDDB_MAGIC || ver.st != V_OK) {
        emit(c, &line, 0);
        gated_line(c, 1u << WIN_CMDDB, "CMDDB", RS_MAGIC);
        return;
    }
    for (unsigned i = 0; i < CMDDB_SLV_MAX && !failed; i++) {
        uint32_t at = CMDDB_RSC_HDR_OFF + i * CMDDB_RSC_HDR_BYTES;
        read_word(c, WIN_CMDDB, at, &w0);
        if (w0.st != V_OK) {
            failed = 1;
            break;
        }
        if (!(w0.v & 0xffffu)) break;      /* the end of the list, as Linux takes it (cmd-db.c:158-161) */
        read_word(c, WIN_CMDDB, at + 4, &w1);
        if (w1.st != V_OK) {
            failed = 1;
            break;
        }
        rh[nh].slv = w0.v & 0xffffu;
        rh[nh].hoff = w0.v >> 16;
        rh[nh].doff = w1.v & 0xffffu;
        rh[nh].cnt = w1.v >> 16;
        if (rh[nh].slv == CMDDB_SLV_ARC) arc += rh[nh].cnt;
        if (rh[nh].slv == CMDDB_SLV_BCM) bcm += rh[nh].cnt;
        nh++;
    }
    pk_dec(c, &line, "HDRS=", nh);
    if (failed) pk_word(c, &line, "FAIL=", w0.st != V_OK ? &w0 : &w1);
    pk_dec(c, &line, "ARC=", arc);
    pk_dec(c, &line, "BCM=", bcm);
    emit(c, &line, 0);
    if (failed) {
        for (unsigned t = 0; t < TARGETS; t++) c->tg[t].addr = w0.st != V_OK ? w0 : w1;
    } else {
        cmddb_walk(c, rh, nh);
    }
    addr_line(c, "CMDDB ADDR", T_CX, T_SH0);
    addr_line(c, "CMDDB BCM", T_SH0, TARGETS);
    lvl_line(c, T_CX, T_GFX);
    lvl_line(c, T_GFX, RAILS);
}

OUT_OF_LINE void cmddb_block(struct ctx *c)
{
    struct mapscan m;
    for (unsigned t = 0; t < TARGETS; t++) {
        c->tg[t].addr.v = c->tg[t].aux = c->tg[t].len = 0;
        c->tg[t].addr.code = c->tg[t].addr.pad = 0;
        c->tg[t].addr.st = V_NONE;
    }
    if (!announce(c, "CMDDB")) {
        c->blocks |= 1u << WIN_MAP | 1u << WIN_CMDDB;
        return;
    }
    map_scan(c, &m);
    map_line(c, &m);
    if (m.state != MAP_OPEN) {
        gated_line(c, 1u << WIN_CMDDB, "CMDDB", RS_MAP);
        return;
    }
    cmddb_open(c);
}

/* ---- The apps RSC, drv-2 ---- */

/* The enable mask of a TCS is a 16-bit mask: a word with a bit above 15 (all ones is one) is not one. */
OUT_OF_LINE int tcs_enable_ok(const struct val *en)
{
    return en->st == V_OK && !(en->v >> RSC_CMDS_MAX);
}

/* The enable mask of a TCS, with the decode that it is a 16-bit mask. */
OUT_OF_LINE void put_en(struct ctx *c, struct pl_line *line, const char *key, const struct val *en)
{
    struct pl_line item;
    pl_begin(&item);
    tx(&item, key);
    word_text(c, &item, en);
    if (en->st == V_OK && !tcs_enable_ok(en)) tx(&item, ".ODD");
    pk_add(c, line, &item);
}

/* What the commands of one TCS say about the rails: for every enabled command its address is read, and the data word only of a command whose address is a rail's from the database. The data
 * words have no Linux reader (the driver only writes them) and the TCS may hold anything, so nothing but the rail addresses decides which are read. The last command for a rail wins, as the
 * hardware plays them in order. A rail whose address the database did not give prints NA, one with no command `-`, and a word that did not read its own token. */
OUT_OF_LINE void rsc_wake_line(struct ctx *c, unsigned layout, unsigned t, const struct val *en)
{
    const struct rsc_layout *lay = &rsc_layouts[layout];
    struct val vote[RAILS], fail;
    struct pl_line line, item;
    uint32_t tcs = RSC_TCS_BASE + RSC_TCS_STRIDE * t;
    unsigned n = 0;
    fail.v = 0;
    fail.code = fail.pad = 0;
    fail.st = V_NONE;
    for (unsigned r = 0; r < RAILS; r++) {
        vote[r].v = 0;
        vote[r].code = vote[r].pad = 0;
        vote[r].st = rail_usable(c, r) && tcs_enable_ok(en) ? V_NOVOTE : V_NONE;
    }
    if (tcs_enable_ok(en)) {
        for (unsigned j = 0; j < RSC_CMDS_MAX; j++) n += en->v >> j & 1;
        for (unsigned j = 0; j < RSC_CMDS_MAX && fail.st == V_NONE; j++) {
            struct val a;
            if (!(en->v >> j & 1)) continue;
            read_word(c, WIN_RSC, tcs + lay->addr + lay->cmd_stride * j, &a);
            if (a.st != V_OK) {
                fail = a;
                break;
            }
            for (unsigned r = 0; r < RAILS; r++) {
                if (!rail_usable(c, r) || c->tg[r].addr.v != a.v) continue;
                read_word(c, WIN_RSC, tcs + lay->data + lay->cmd_stride * j, &vote[r]);
                if (vote[r].st != V_OK) fail = vote[r];
            }
        }
    }
    pk_begin(&line, "RSC2 W");
    dec(&line, t);
    pl_begin(&item);
    tx(&item, "N=");
    if (tcs_enable_ok(en)) dec(&item, n);
    else tx(&item, "NA");
    pk_add(c, &line, &item);
    for (unsigned r = 0; r < RAILS; r++) {
        pl_begin(&item);
        tx(&item, targets[r].key);
        tx(&item, "=");
        if (vote[r].st == V_NOVOTE && fail.st != V_NONE) vote_text(c, &item, &fail);
        else vote_text(c, &item, &vote[r]);
        pk_add(c, &line, &item);
    }
    emit(c, &line, 0);
}

OUT_OF_LINE void rsc_block(struct ctx *c)
{
    static const char tcs_key[RSC_TCS_NUM][4] = {"A0=", "A1=", "A2=", "S3=", "S4=", "W5=", "W6="};
    static const uint8_t en_order[RSC_TCS_NUM] = {5, 6, 3, 4, 0, 1, 2};
    struct val id, sol, chld, ie, is, en[RSC_TCS_NUM];
    struct pl_line line, item;
    unsigned why = RS_OPEN, major = 0, layout = 0;
    if (!announce(c, "RSC2")) {
        c->blocks |= 1u << WIN_RSC;
        return;
    }
    read_word(c, WIN_RSC, RSC_DRV_ID, &id);
    pk_begin(&line, "RSC2");
    pk_word(c, &line, "ID=", &id);
    if (!ident_ok(&id)) {
        why = RS_ID;
    } else {
        major = id.v >> RSC_MAJOR_SHIFT & 0xffu;
        pl_begin(&item);
        tx(&item, "VER=");
        dec(&item, major);
        tx(&item, ".");
        dec(&item, id.v >> RSC_MINOR_SHIFT & 0xffu);
        pk_add(c, &line, &item);
        if (major == rsc_layouts[0].major) layout = 0;
        else if (major == rsc_layouts[1].major) layout = 1;
        else why = RS_VER;
    }
    emit(c, &line, 0);
    if (why) {
        gated_line(c, 1u << WIN_RSC, "RSC2", why);
        return;
    }
    read_word(c, WIN_RSC, RSC_DRV_SOLVER, &sol);
    read_word(c, WIN_RSC, RSC_DRV_CHLD, &chld);
    read_word(c, WIN_RSC, RSC_TCS_BASE + RSC_IRQ_ENABLE, &ie);
    read_word(c, WIN_RSC, RSC_TCS_BASE + RSC_IRQ_STATUS, &is);
    pk_begin(&line, "RSC2 CFG");
    pk_word(c, &line, "SOL=", &sol);
    pk_word(c, &line, "CHLD=", &chld);
    if (word_ok(&chld)) pk_dec(c, &line, "NT=", chld.v >> (RSC_NUM_TCS_SHIFT * RSC_DRV_NUMBER) & RSC_NUM_TCS_MASK);
    pk_word(c, &line, "IRQE=", &ie);
    pk_word(c, &line, "IRQS=", &is);
    if (word_ok(&chld)) pk_dec(c, &line, "NCPT=", chld.v >> RSC_NCPT_SHIFT & RSC_NCPT_MASK);
    emit(c, &line, 0);
    if (!word_ok(&chld) || (chld.v >> (RSC_NUM_TCS_SHIFT * RSC_DRV_NUMBER) & RSC_NUM_TCS_MASK) < RSC_TCS_NUM) {
        gated_line(c, 1u << WIN_RSC, "RSC2", RS_TCS);
        return;
    }
    /* The wake TCSs first: when a line is too long for its items it is the last that go, and the wake TCSs are what the page is for. */
    pk_begin(&line, "RSC2 EN");
    for (unsigned i = 0; i < RSC_TCS_NUM; i++) {
        unsigned t = en_order[i];
        read_word(c, WIN_RSC, RSC_TCS_BASE + RSC_TCS_STRIDE * t + rsc_layouts[layout].enable, &en[t]);
        put_en(c, &line, tcs_key[t], &en[t]);
    }
    emit(c, &line, 0);
    for (unsigned w = 0; w < RSC_WAKE_COUNT; w++) rsc_wake_line(c, layout, RSC_TCS_WAKE + w, &en[RSC_TCS_WAKE + w]);
}

/* ---- The speed bin ---- */

OUT_OF_LINE void qfprom_block(struct ctx *c)
{
    struct val w;
    struct pl_line line, item;
    if (!announce(c, "QFPROM")) {
        c->blocks |= 1u << WIN_QFPROM;
        return;
    }
    read_word(c, WIN_QFPROM, QFPROM_WORD, &w);
    pk_begin(&line, "QFPROM");
    pl_begin(&item);
    tx(&item, "W118=");
    word_text(c, &item, &w);
    pk_add(c, &line, &item);
    if (w.st == V_OK) {
        unsigned fuse = w.v >> QFPROM_FUSE_SHIFT & QFPROM_FUSE_MASK, bin = 5;
        for (unsigned i = 0; i < 5; i++) {
            if (speedbins[i].fuse == fuse) bin = speedbins[i].bin;
        }
        pk_dec(c, &line, "FUSE=", fuse);
        pl_begin(&item);
        tx(&item, "SB=");
        if (bin < 5) dec(&item, bin);
        else tx(&item, "?");
        pk_add(c, &line, &item);
    }
    emit(c, &line, 0);
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
    c.map_base = a->map_base;
    c.map_size = a->map_size;
    c.map_stride = a->map_stride;
    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {
        say(&c, "SKIPPED_NOT_AT_EL2", 1);
        return 0;
    }
    if (!c.load32) {
        say(&c, "REFUSED_NO_LOAD32", 1);
        return Q1N1_PAYLOAD_RET_BAD_ARGS;
    }

    pk_begin(&line, "READ ONLY EL=2 CAP=");
    dec(&line, LOAD_CAP);
    tx(&line, "/");
    dec(&line, LINE_CAP);
    emit(&c, &line, 0);
    say(&c, LEGEND, 0);

    tsens_block(&c);
    gcc_block(&c);
    gpucc_block(&c);
    cmddb_block(&c);
    rsc_block(&c);
    qfprom_block(&c);

    pk_begin(&line, "END LOADS=");
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
    emit(&c, &line, 1);
    return 0;
}
