/* SPDX-License-Identifier: MIT */
/* The model of the host test of the payload "gpusnap2" (tools/test-q1n1-sp11-payload-gpusnap2.c holds the suites): the payload built natively with Q1N1_PAYLOAD_HOST_TEST, so that
 * CurrentEL comes from a scripted register file and every load from a fake memory: the registers of six windows, the 128 KiB of the command database, and the UEFI memory map the arguments
 * point at. Built with GPUSNAP2_SRC pointing at a seeded-bug copy of the payload, it is how the mutants are shown to be refused.
 *
 * The model fails the run on anything the payload must never do: a load that is not 4-byte aligned, past the ABI's 4096, at an address the harness's OWN list (below, written from the design
 * note and not from the payload's tables) does not name (so: nothing in the GPU's CX-gated blocks, no GX register, no RSC window but drv-2's, no word of the RSC the design leaves out), in a
 * window after an abort in it (so no retry either), a block's first load whose `NEXT <block>` line is not the last line printed, a load of a lower block after a higher one, a load of a new
 * line of a block before a line has gone out since the last load of the line before it, a load of GPUCC behind a CFG AHB word the harness's OWN rule does not hold running, of the
 * command database behind a memory map or a magic the harness's OWN oracles (a sort-and-sweep of the map, a byte-wise walk of the database) do not hold open, or of a word the walk the
 * oracle makes does not visit, of an RSC word beyond the ID behind an ID, a TCS count or an enable mask the harness does not accept, of a command's data word whose address is not a rail's
 * from the oracle's database, a system register other than CurrentEL, more lines than the ABI or the payload's cap, a line of more than 100 characters or outside the page font, a missing end
 * line, and any access that reaches a device window other than through load32 (the windows are unmapped here, so a payload that dereferences one dies on a signal that the harness turns into
 * that verdict). Nothing here ran on hardware. Evidence: EXPERIMENTAL (host model only). */
#pragma once
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef GPUSNAP2_SRC
#define GPUSNAP2_SRC "../payloads/gpusnap2.c"
#endif
#include GPUSNAP2_SRC

#pragma clang diagnostic ignored "-Wunused-function"     /* a capped build runs only the cap suite, the shipped one all the others */

/* ---- The harness's own list of what may be read ----------------------------------------------------------------------------------------------- */

enum { XW_TSROT, XW_TTM, XW_GCC, XW_GPUCC, XW_CMDDB, XW_RSC, XW_QFP, XW_MAP, XW_COUNT };
enum { B_TSENS, B_GCC, B_GPUCC, B_CMDDB, B_RSC, B_QFPROM, B_COUNT };
static const char B_NAME[B_COUNT][8] = {"TSENS3", "GCC", "GPUCC", "CMDDB", "RSC2", "QFPROM"};
static const struct {
    uint64_t base;
    uint32_t size;
    uint8_t block;
} XW[XW_MAP] = {
    {0x0c225000u, 0x1000u, B_TSENS}, {0x0c274000u, 0x1000u, B_TSENS}, {0x00100000u, 0x200000u, B_GCC}, {0x03d90000u, 0xa000u, B_GPUCC},
    {0x81c60000u, 0x20000u, B_CMDDB}, {0x17520000u, 0x10000u, B_RSC}, {0x221c8000u, 0x1000u, B_QFPROM},
};
#define XDB_BYTES 0x20000u
#define XMAP_BYTES_MAX 40960u
#define XMAP_BASE 0x7e000000ull         /* where the model puts the map it hands over: nothing the payload could confuse with a register */

/* Every register of the fixed windows: window, block, the page line it is printed on (the harness's numbering inside the block), offset, the key it is printed under. */
struct m_reg {
    uint8_t win, block, line;
    uint32_t off;
    char key[8];
};
#define MR(w, b, l, o, k) {w, b, l, o, k}
static const struct m_reg M_REGS[] = {
    MR(XW_TSROT, B_TSENS, 0, 0x00, "VER"), MR(XW_TSROT, B_TSENS, 0, 0x04, "CTL"),
    MR(XW_TTM, B_TSENS, 1, 0xb4, "S5"), MR(XW_TTM, B_TSENS, 1, 0xb8, "S6"), MR(XW_TTM, B_TSENS, 1, 0xbc, "S7"), MR(XW_TTM, B_TSENS, 1, 0xc0, "S8"),
    MR(XW_TTM, B_TSENS, 1, 0xc4, "S9"), MR(XW_TTM, B_TSENS, 1, 0xc8, "S10"), MR(XW_TTM, B_TSENS, 1, 0xcc, "S11"), MR(XW_TTM, B_TSENS, 1, 0xd0, "S12"),
    MR(XW_GCC, B_GCC, 0, 0x71004, "CFGA"),
    MR(XW_GPUCC, B_GPUCC, 1, 0x911c, "AHB"), MR(XW_GPUCC, B_GPUCC, 1, 0x9108, "CXGD"), MR(XW_GPUCC, B_GPUCC, 1, 0x953c, "CXHW"),
    MR(XW_GPUCC, B_GPUCC, 2, 0x0000, "P0MODE"), MR(XW_GPUCC, B_GPUCC, 2, 0x0030, "P0OP"), MR(XW_GPUCC, B_GPUCC, 2, 0x0004, "P0L"), MR(XW_GPUCC, B_GPUCC, 2, 0x0008, "P0AL"),
    MR(XW_GPUCC, B_GPUCC, 3, 0x1000, "P1MODE"), MR(XW_GPUCC, B_GPUCC, 3, 0x1004, "P1OP"), MR(XW_GPUCC, B_GPUCC, 3, 0x1010, "P1L"), MR(XW_GPUCC, B_GPUCC, 3, 0x1014, "P1AL"),
    MR(XW_GPUCC, B_GPUCC, 4, 0x9474, "FFC"), MR(XW_GPUCC, B_GPUCC, 4, 0x9478, "FFF"), MR(XW_GPUCC, B_GPUCC, 4, 0x9050, "XDIV"), MR(XW_GPUCC, B_GPUCC, 4, 0x9054, "DDIV"),
    MR(XW_GPUCC, B_GPUCC, 5, 0x9120, "CRC"), MR(XW_GPUCC, B_GPUCC, 5, 0x914c, "CXFF"), MR(XW_GPUCC, B_GPUCC, 5, 0x9008, "FM"),
    MR(XW_GPUCC, B_GPUCC, 6, 0x9150, "MEM"), MR(XW_GPUCC, B_GPUCC, 6, 0x9134, "SLP"), MR(XW_GPUCC, B_GPUCC, 6, 0x93a4, "CB"),
    MR(XW_QFP, B_QFPROM, 0, 0x118, "W118"),
};
#define M_NREGS (sizeof M_REGS / sizeof M_REGS[0])

/* ---- The state of the model ------------------------------------------------------------------------------------------------------------------- */

static struct {
    uint64_t addr;
    uint32_t value;
    int fault;
} m_fake[1024];
static unsigned m_nfake;
static uint32_t m_fill;                 /* what a register no fixture names reads */
static int m_fill_all;                  /* every register the model is asked about reads m_fill (hostile runs) */
static uint64_t m_rand_seed;            /* non-zero: a register nobody set reads a pseudo-random word */
static uint8_t m_db[XDB_BYTES];
static uint8_t m_map[XMAP_BYTES_MAX];
static uint64_t m_map_base, m_map_size, m_map_stride;       /* the arguments the runner passes (the harness may break them) */
static int m_el, m_have_load32;
static struct {
    uint8_t block, line;
    uint16_t pad;
    uint32_t nlines;                    /* the lines printed when the load was issued */
    uint64_t addr;
} m_loadlog[4200];
static unsigned m_nloadlog;
static char m_lines[128][220];
static unsigned m_nlines, m_nloads, m_violations, m_dead, m_started, m_sysreg_reads, m_checks, m_fails, m_aborted;
static char m_first_violation[260];
static int m_abort_nth, m_hang_nth, m_abort_from_nth;      /* the load (0-based, counting every load) that aborts or hangs, or -1 */
static unsigned m_win_faults;           /* a bit per window every load of which aborts */
static int m_prev_line, m_hung;
static unsigned m_lines_at_prev_load;
static jmp_buf m_hang_jmp;

static void m_violate(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void m_violate(const char *fmt, ...)
{
    va_list ap;
    if (!m_violations++) {
        va_start(ap, fmt);
        vsnprintf(m_first_violation, sizeof m_first_violation, fmt, ap);
        va_end(ap);
    }
}

static void m_dump(FILE *f)
{
    fprintf(f, "  page (%u lines, %u loads):\n", m_nlines, m_nloads);
    for (unsigned i = 0; i < m_nlines; i++) fprintf(f, "  %2u %s\n", i, m_lines[i]);
}

#define CHECK(cond) do { m_checks++; if (!(cond)) { m_fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); m_dump(stderr); } } while (0)
/* The same, with what the case in a table is, so that the FAIL line names it. */
#define CHECKM(cond, what) do { m_checks++; if (!(cond)) { m_fails++; fprintf(stderr, "FAIL %s:%d: %s: %s\n", __FILE__, __LINE__, #cond, what); m_dump(stderr); } } while (0)

static uint32_t m_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void m_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void m_put16(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

/* ---- Where an address is ---------------------------------------------------------------------------------------------------------------------- */

struct m_loc {
    int win;                            /* XW_*, or -1 */
    uint32_t off;
    int known;                          /* the harness's list names the word */
    int block, line;
    char key[12];
};

static int m_rsc_layout(unsigned *en, unsigned *addr, unsigned *data, unsigned *stride);
static int m_find(const char *head, unsigned from);

/* The window of an address and, for a fixed window, the harness's row. The RSC rows depend on the version the fixture's ID word says. */
static void m_locate(uint64_t addr, struct m_loc *l)
{
    memset(l, 0, sizeof *l);
    l->win = -1;
    if (addr >= XMAP_BASE && addr < XMAP_BASE + XMAP_BYTES_MAX && m_map_base == XMAP_BASE) {
        l->win = XW_MAP;
        l->off = (uint32_t)(addr - XMAP_BASE);
        l->block = B_CMDDB;
        l->known = 1;                   /* which words: the oracle's */
        l->line = 0;
        return;
    }
    for (int w = 0; w < XW_MAP; w++) {
        if (addr >= XW[w].base && addr < XW[w].base + XW[w].size) {
            l->win = w;
            l->off = (uint32_t)(addr - XW[w].base);
            l->block = XW[w].block;
        }
    }
    if (l->win < 0) return;
    if (l->win == XW_CMDDB) {
        l->known = 1;                   /* the oracle decides which words, and so which line */
        l->line = 1;
        return;
    }
    if (l->win == XW_RSC) {
        unsigned en, ad, da, st;
        static const struct { uint32_t off; uint8_t line; const char key[6]; } fixed[] = {{0x00, 0, "ID"}, {0x04, 1, "SOL"}, {0x0c, 1, "CHLD"}, {0xd00, 1, "IRQE"}, {0xd04, 1, "IRQS"}};
        for (unsigned i = 0; i < sizeof fixed / sizeof fixed[0]; i++) {
            if (fixed[i].off == l->off) {
                l->known = 1;
                l->line = fixed[i].line;
                snprintf(l->key, sizeof l->key, "%s", fixed[i].key);
                return;
            }
        }
        if (!m_rsc_layout(&en, &ad, &da, &st)) return;
        for (unsigned t = 0; t < 7; t++) {
            uint32_t tcs = 0xd00 + 672 * t;
            if (l->off == tcs + en) {
                l->known = 1;
                l->line = 2;
                snprintf(l->key, sizeof l->key, "EN%u", t);
                return;
            }
            for (unsigned j = 0; j < 16 && t >= 5; j++) {
                if (l->off == tcs + ad + st * j || l->off == tcs + da + st * j) {
                    l->known = 1;
                    l->line = 3 + (int)(t - 5);
                    snprintf(l->key, sizeof l->key, "%c%u.%u", l->off == tcs + ad + st * j ? 'A' : 'D', t, j);
                    return;
                }
            }
        }
        return;
    }
    for (unsigned i = 0; i < M_NREGS; i++) {
        if (M_REGS[i].win == l->win && M_REGS[i].off == l->off) {
            l->known = 1;
            l->line = M_REGS[i].line;
            snprintf(l->key, sizeof l->key, "%s", M_REGS[i].key);
        }
    }
}

/* ---- The value an address reads --------------------------------------------------------------------------------------------------------------- */

static uint32_t m_value(uint64_t addr, int *fault)
{
    struct m_loc l;
    *fault = 0;
    m_locate(addr, &l);
    if (l.win >= 0 && (m_win_faults >> l.win & 1)) {
        *fault = 1;
        return 0;
    }
    for (unsigned i = 0; i < m_nfake && !m_fill_all; i++) {
        if (m_fake[i].addr != addr) continue;
        *fault = m_fake[i].fault;
        return m_fake[i].value;
    }
    if (l.win == XW_CMDDB) return m_le32(m_db + l.off);
    if (l.win == XW_MAP) return l.off + 4 <= XMAP_BYTES_MAX ? m_le32(m_map + l.off) : 0;
    if (m_rand_seed && !m_fill_all) {
        uint64_t x = (addr ^ m_rand_seed) * UINT64_C(0x9E3779B97F4A7C15);
        x ^= x >> 29;
        x *= UINT64_C(0xBF58476D1CE4E5B9);
        return (uint32_t)(x >> 16) & ((x & 1) ? 0xffffffffu : (x & 2) ? 0x00000003u : 0x80000001u);     /* all kinds: ones, small, bit 31 and bit 0 */
    }
    return m_fill;
}

static uint32_t m_reg_value(int win, uint32_t off)
{
    int fault;
    return m_value(XW[win].base + off, &fault);
}

static int m_reg_fault(int win, uint32_t off)
{
    int fault;
    (void)m_value(XW[win].base + off, &fault);
    return fault;
}

/* A word that reads, and is not what a failed read returns. */
static int x_word(int win, uint32_t off, uint32_t *w)
{
    int fault;
    *w = m_value(XW[win].base + off, &fault);
    return !fault && *w != 0xffffffffu;
}

/* ---- What the harness holds a gate to: its own statement of the rules, written from the design note ---------------------------------------------- */

/* The CFG AHB clock proves itself running: enabled (bit 0) and not CLK_OFF (bit 31). */
static int x_ahb_open(void)
{
    uint32_t w;
    return x_word(XW_GCC, 0x71004, &w) && (w & 1) && !(w >> 31);
}

/* The memory map, by a sort and a sweep (the payload covers the region by repeated extension): the verdict on whether the command database is described, all of it, as reserved memory. */
enum { OM_OPEN, OM_NONE, OM_TYPE, OM_PART, OM_BAD };
static const char OM_NAME[5][5] = {"OPEN", "NONE", "TYPE", "PART", "BAD"};
struct o_map {
    int state;
    unsigned desc, hits, type, attr;
    uint8_t read[XMAP_BYTES_MAX / 4];   /* the words of the map the payload must read, one flag each */
};

static int o_map_args(void)
{
    return m_map_base == XMAP_BASE && !(m_map_base & 7) && m_map_size && m_map_stride >= 40 && m_map_stride <= 128 && !(m_map_stride & 7) && m_map_size <= XMAP_BYTES_MAX &&
           m_map_size % m_map_stride == 0 && m_map_size / m_map_stride <= 320;
}

static void o_map(struct o_map *m)
{
    uint64_t lo[320], hi[320], cur, rlo = XW[XW_CMDDB].base, rhi = XW[XW_CMDDB].base + XDB_BYTES;
    unsigned n, bad = 0, nonres = 0;
    memset(m, 0, sizeof *m);
    m->state = OM_BAD;
    if (!o_map_args()) return;
    n = (unsigned)(m_map_size / m_map_stride);
    m->desc = n;
    for (unsigned i = 0; i < n; i++) {
        const uint8_t *d = m_map + i * m_map_stride;
        uint64_t start = (uint64_t)m_le32(d + 12) << 32 | m_le32(d + 8), pages = (uint64_t)m_le32(d + 28) << 32 | m_le32(d + 24);
        unsigned o = (unsigned)(i * m_map_stride) / 4;
        m->read[o + 2] = m->read[o + 3] = m->read[o + 6] = m->read[o + 7] = 1;
        if (!pages) continue;
        if ((start & 0xfff) || start >= (1ull << 48) || pages >= (1ull << 36) || start + (pages << 12) > (1ull << 48)) {
            bad = 1;
            continue;
        }
        if (start >= rhi || start + (pages << 12) <= rlo) continue;
        if (m->hits >= 8) {
            bad = 1;
            continue;
        }
        m->read[o + 0] = m->read[o + 8] = 1;
        if (!m->hits) {
            m->type = m_le32(d);
            m->attr = m_le32(d + 32);
        }
        nonres |= m_le32(d) != 0;
        lo[m->hits] = start;
        hi[m->hits] = start + (pages << 12);
        m->hits++;
    }
    if (bad) return;
    if (!m->hits) {
        m->state = OM_NONE;
        return;
    }
    if (nonres) {
        m->state = OM_TYPE;
        return;
    }
    for (unsigned i = 1; i < m->hits; i++) {            /* insertion sort by start */
        uint64_t a = lo[i], b = hi[i];
        unsigned j = i;
        while (j && lo[j - 1] > a) {
            lo[j] = lo[j - 1];
            hi[j] = hi[j - 1];
            j--;
        }
        lo[j] = a;
        hi[j] = b;
    }
    cur = rlo;
    for (unsigned i = 0; i < m->hits; i++) {
        if (lo[i] > cur) break;
        if (hi[i] > cur) cur = hi[i];
    }
    m->state = cur >= rhi ? OM_OPEN : OM_PART;
}

/* The command database, walked byte-wise: its magic, its resource headers up to the first that has no slave id, the ARC (3) and BCM (5) lists up to 128 entries each and 256 in all, the id
 * of every entry compared with the eight bytes of each target not yet found of that kind, and what each finds. `stage` marks the words of the 128 KiB the payload may read, which is what the
 * walk reads and nothing else, with the page line each belongs to: 1 the header (the HDR line follows), 2 the entries (the ADDR and BCM lines follow), 4 the level tables of the first two
 * rails and 8 those of the other two (a LVL line each). */
enum { OT_UNREAD, OT_FOUND, OT_ABSENT, OT_PART, OT_NA };
static const char O_ID[8][9] = {"cx.lvl", "mx.lvl", "gfx.lvl", "gmxc.lvl", "gbx.lvl", "SH0", "MC0", "ACV"};
static const uint8_t O_SLV[8] = {3, 3, 3, 3, 3, 5, 5, 5};
static const char O_KEY[8][5] = {"CX", "MX", "GFX", "GMXC", "GBX", "SH0", "MC0", "ACV"};
struct o_tgt {
    int state;
    uint32_t addr, aux, len;
    unsigned nlev, shown, lev[8];
    int levels_ok;                      /* the level table was readable (inside the region, an even offset) */
};
struct o_db {
    int magic_ok;
    uint32_t ver;
    unsigned nh, arc, bcm;
    struct o_tgt t[8];
    uint8_t stage[XDB_BYTES / 4];
};

static void o_walk(struct o_db *d)
{
    unsigned scanned = 0, cut = 0, na = 0;
    struct { unsigned slv, hoff, doff, cnt; } rh[8];
    memset(d, 0, sizeof *d);
    d->ver = m_le32(m_db);
    d->stage[0] = d->stage[1] = 1;
    d->magic_ok = m_db[4] == 0xdb && m_db[5] == 0x30 && m_db[6] == 0x03 && m_db[7] == 0x0c;
    if (!d->magic_ok) return;
    for (unsigned i = 0; i < 8; i++) {
        const uint8_t *h = m_db + 8 + 16 * i;
        d->stage[(8 + 16 * i) / 4] = 1;
        if (!(h[0] | h[1])) break;
        d->stage[(8 + 16 * i + 4) / 4] = 1;
        rh[d->nh].slv = h[0] | h[1] << 8;
        rh[d->nh].hoff = h[2] | h[3] << 8;
        rh[d->nh].doff = h[4] | h[5] << 8;
        rh[d->nh].cnt = h[6] | h[7] << 8;
        if (rh[d->nh].slv == 3) d->arc += rh[d->nh].cnt;
        if (rh[d->nh].slv == 5) d->bcm += rh[d->nh].cnt;
        d->nh++;
    }
    for (unsigned h = 0; h < d->nh && !na; h++) {
        unsigned limit = rh[h].cnt;
        if (rh[h].slv != 3 && rh[h].slv != 5) continue;
        if (limit > 128) {
            limit = 128;
            cut |= 1u << rh[h].slv;
        }
        for (unsigned j = 0; j < limit; j++) {
            unsigned at = 0x90 + rh[h].hoff + 24 * j;
            if (scanned >= 256) {
                cut |= 1u << rh[h].slv;
                break;
            }
            scanned++;
            if (at & 3) {                       /* not readable by a 32-bit load: the walk ends here */
                na = 1;
                break;
            }
            d->stage[at / 4] |= 2;
            for (unsigned t = 0; t < 8; t++) {
                char id[8];
                if (O_SLV[t] != rh[h].slv || d->t[t].state != OT_UNREAD) continue;
                memset(id, 0, 8);
                memcpy(id, O_ID[t], strlen(O_ID[t]));
                if (memcmp(m_db + at, id, 4)) continue;
                d->stage[(at + 4) / 4] |= 2;
                if (memcmp(m_db + at + 4, id + 4, 4)) continue;
                d->stage[(at + 16) / 4] |= 2;
                d->stage[(at + 20) / 4] |= 2;
                d->t[t].state = OT_FOUND;
                d->t[t].addr = m_le32(m_db + at + 16);
                d->t[t].len = m_db[at + 20] | m_db[at + 21] << 8;
                d->t[t].aux = 0x90 + rh[h].doff + (m_db[at + 22] | m_db[at + 23] << 8);
            }
        }
    }
    for (unsigned t = 0; t < 8; t++) {
        struct o_tgt *g = &d->t[t];
        if (g->state == OT_UNREAD) g->state = na ? OT_NA : cut >> O_SLV[t] & 1 ? OT_PART : OT_ABSENT;
        if (g->state != OT_FOUND || t >= 4 || g->len < 2 || (g->aux & 1)) continue;
        g->nlev = g->len / 2;
        g->shown = g->nlev < 8 ? g->nlev : 8;
        if (g->aux + 2 * g->shown > XDB_BYTES) continue;
        g->levels_ok = 1;
        for (unsigned i = 0; i < g->shown; i++) {
            g->lev[i] = m_db[g->aux + 2 * i] | m_db[g->aux + 2 * i + 1] << 8;
            d->stage[(g->aux + 2 * i) / 4] |= t < 2 ? 4 : 8;
        }
    }
}

/* The RSC as the fixture's ID word says: the layout of the registers (the version's), or 0 when the ID is not one the design knows. */
static int m_rsc_layout(unsigned *en, unsigned *addr, unsigned *data, unsigned *stride)
{
    int fault;
    uint32_t id = m_value(XW[XW_RSC].base, &fault);
    unsigned major = id >> 16 & 0xff;
    if (fault || !id || id == 0xffffffffu) return 0;
    if (major == 2) {
        *en = 0x1c; *addr = 0x34; *data = 0x38; *stride = 20;
        return 1;
    }
    if (major == 3) {
        *en = 0x2c; *addr = 0x38; *data = 0x3c; *stride = 24;
        return 1;
    }
    return 0;
}

/* A TCS's enable word the design accepts: read, not all ones, and a 16-bit mask. */
static int x_en_ok(unsigned t, uint32_t *mask)
{
    unsigned en, ad, da, st;
    uint32_t w;
    if (!m_rsc_layout(&en, &ad, &da, &st) || !x_word(XW_RSC, 0xd00 + 672 * t + en, &w) || (w >> 16)) return 0;
    *mask = w;
    return 1;
}

/* The harness's own verdicts, computed from the current memory once per run, before the payload runs. */
static struct o_map m_om;
static struct o_db m_od;
static void m_oracles(void)
{
    o_map(&m_om);
    o_walk(&m_od);
}

/* A usable rail address: the database's, found and not zero, and the database was read at all (the map and the magic let it be). */
static int x_rail(unsigned r, uint32_t *addr)
{
    if (m_om.state != OM_OPEN || !m_od.magic_ok || m_od.t[r].state != OT_FOUND || !m_od.t[r].addr) return 0;
    *addr = m_od.t[r].addr;
    return 1;
}

/* ---- The runner's ops ------------------------------------------------------------------------------------------------------------------------- */

static int m_last_line_is(const char *tail)
{
    char want[120];
    snprintf(want, sizeof want, "%s%s", PREFIX, tail);
    return m_nlines && !strcmp(m_lines[m_nlines - 1], want);
}

/* The last line is a line of the block: its NEXT line, or one of the lines that start with its head. */
static int m_last_line_of(int block)
{
    static const char *const heads[B_COUNT][3] = {{"NEXT TSENS3", "T3 ", NULL}, {"NEXT GCC", "GCC ", NULL}, {"NEXT GPUCC", "GPUCC ", NULL},
                                                   {"NEXT CMDDB", "CMDDB ", NULL}, {"NEXT RSC2", "RSC2 ", NULL}, {"NEXT QFPROM", "QFPROM ", NULL}};
    char want[120];
    for (unsigned i = 0; heads[block][i]; i++) {
        snprintf(want, sizeof want, "%s%s", PREFIX, heads[block][i]);
        if (m_nlines && !strncmp(m_lines[m_nlines - 1], want, strlen(want))) return 1;
    }
    return 0;
}

static unsigned m_normal_limit(void)
{
    return LINE_CAP > CLOSING_LINES ? LINE_CAP - CLOSING_LINES : 0u;
}

static void m_check_gate(const struct m_loc *l)
{
    uint32_t mask, addr;
    if (l->block == B_GPUCC && !x_ahb_open()) m_violate("load of GPUCC %s behind a CFG AHB word that does not run", l->key);
    if (l->block == B_TSENS && l->win == XW_TTM) {
        uint32_t ver, ctl;
        if (!x_word(XW_TSROT, 0, &ver) || !ver || !x_word(XW_TSROT, 4, &ctl) || !(ctl & 1) || (ctl & 2)) m_violate("load of a status word behind an identity or a control word the harness does not accept");
    }
    if (l->win == XW_MAP && !o_map_args()) m_violate("load of the memory map behind arguments that do not describe one");
    if (l->win == XW_MAP && !m_om.read[l->off / 4]) m_violate("load of map word +%#x: a word of a descriptor the walk does not need", l->off);
    if (l->win == XW_CMDDB) {
        unsigned s = m_od.stage[l->off / 4];
        const char *need = (s & 1) ? "CMDDB MAP" : (s & 2) ? "CMDDB HDR" : (s & 4) ? "CMDDB BCM" : "CMDDB LVL";
        if (m_om.state != OM_OPEN) m_violate("load of the command database behind a memory map the oracle holds %s", OM_NAME[m_om.state]);
        else if (!s) m_violate("load of command database word +%#x, which the oracle's walk does not visit", l->off);
        else if (l->off >= 8 && !m_od.magic_ok) m_violate("load of command database word +%#x behind a magic that is not Linux's", l->off);
        else if (m_find(need, 0) < 0 && m_nlines < m_normal_limit()) m_violate("load of command database word +%#x before the page has its `%s` line", l->off, need);
    }
    if (l->win == XW_RSC && l->off != 0) {
        unsigned en, ad, da, st;
        int fault;
        uint32_t chld = m_value(XW[XW_RSC].base + 0xc, &fault);
        if (!m_rsc_layout(&en, &ad, &da, &st)) {
            m_violate("load of RSC +%#x behind an ID that is not a layout the design knows", l->off);
        } else if (l->line >= 2 && (fault || chld == 0xffffffffu || (chld >> 12 & 0x3f) < 7)) {
            m_violate("load of RSC %s behind a TCS count the design does not accept", l->key);
        } else if (l->key[0] == 'A' || l->key[0] == 'D') {
            unsigned t = (unsigned)(l->key[1] - '0'), j = (unsigned)atoi(l->key + 3);
            if (!x_en_ok(t, &mask) || !(mask >> j & 1)) m_violate("load of RSC %s: a command that is not enabled in an enable word the harness accepts", l->key);
            if (l->key[0] == 'D') {
                uint32_t a = m_value(XW[XW_RSC].base + 0xd00 + 672 * t + ad + st * j, &fault);
                int match = 0;
                for (unsigned k = 0; k < 4; k++) match |= x_rail(k, &addr) && addr == a;
                if (!match) m_violate("load of RSC %s: the data word of a command whose address is not a rail's from the database", l->key);
            }
        }
    }
}

static int32_t m_load32(uint64_t addr, uint32_t *out)
{
    struct m_loc l;
    int fault;
    unsigned idx = m_nloads;
    *out = 0;
    m_nloads++;
    if (addr & 3) {
        m_violate("load of %#llx is not 4-byte aligned", (unsigned long long)addr);
        return Q1N1_PAYLOAD_LOAD_E_ALIGN;
    }
    if (m_nloads > Q1N1_PAYLOAD_LOADS_MAX) {
        m_violate("load %u is past the ABI's %u", m_nloads, Q1N1_PAYLOAD_LOADS_MAX);
        return Q1N1_PAYLOAD_LOAD_E_BUDGET;
    }
    m_locate(addr, &l);
    if (l.win < 0) {
        m_violate("load of %#llx, an address in no window the design names", (unsigned long long)addr);
        *out = m_fill;
        return Q1N1_PAYLOAD_LOAD_OK;
    }
    if (!l.known) m_violate("load of window %d +%#x, a register no list names", l.win, l.off);
    if (l.win == XW_CMDDB) l.line = 0;           /* the oracle's stages are checked against the page in m_check_gate */
    if (m_dead >> l.win & 1) m_violate("load of window %d +%#x after an abort in that window (a retry or a read the abort should have ended)", l.win, l.off);
    if (m_started >> (l.block + 1)) m_violate("load of %s +%#x after a later block", B_NAME[l.block], l.off);
    if (!(m_started >> l.block & 1)) {
        char tail[24];
        snprintf(tail, sizeof tail, "NEXT %s", B_NAME[l.block]);
        if (!m_last_line_is(tail)) m_violate("first load of %s (+%#x) without `%s` as the last line", B_NAME[l.block], l.off, tail);
        m_started |= 1u << l.block;
    }
    m_check_gate(&l);
    if (m_nloadlog < sizeof m_loadlog / sizeof m_loadlog[0]) {
        m_loadlog[m_nloadlog].block = (uint8_t)l.block;
        m_loadlog[m_nloadlog].line = (uint8_t)(l.line < 0 ? 0 : l.line);
        m_loadlog[m_nloadlog].nlines = m_nlines;
        m_loadlog[m_nloadlog++].addr = addr;
    }
    if (m_hang_nth == (int)idx) {
        m_hung = 1;
        longjmp(m_hang_jmp, 1);
    }
    *out = m_value(addr, &fault);
    if (m_abort_nth == (int)idx || (m_abort_from_nth >= 0 && (int)idx >= m_abort_from_nth)) fault = 1;
    if (fault) {
        m_dead |= 1u << l.win;
        m_aborted++;
        *out = 0;
        return Q1N1_PAYLOAD_LOAD_E_FAULT;
    }
    return Q1N1_PAYLOAD_LOAD_OK;
}

static void m_puts(const char *text)
{
    size_t n = strlen(text);
    if (m_nlines >= sizeof m_lines / sizeof m_lines[0]) {
        m_violate("more than 128 lines");
        return;
    }
    if (m_nlines >= Q1N1_PAYLOAD_LINES_MAX) m_violate("line %u is past the ABI's %u", m_nlines + 1, Q1N1_PAYLOAD_LINES_MAX);
    if (n > Q1N1_PAYLOAD_LINE_MAX) m_violate("a line of %zu characters", n);
    for (size_t i = 0; i < n; i++) {
        char ch = text[i];
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || strchr(" :-./=?()_", ch))) {
            m_violate("character 0x%02x of \"%s\" is not in the page font", (unsigned char)ch, text);
            break;
        }
    }
    if (strncmp(text, PREFIX, strlen(PREFIX))) m_violate("a line without the prefix: \"%s\"", text);
    snprintf(m_lines[m_nlines], sizeof m_lines[0], "%s", text);
    m_nlines++;
}

static uint32_t m_hex(char *dst, uint32_t cap, uint64_t value)
{
    char tmp[24];
    int n = snprintf(tmp, sizeof tmp, "0X%llX", (unsigned long long)value);
    if (cap == 0) return 0;
    if ((uint32_t)n >= cap) n = (int)cap - 1;
    memcpy(dst, tmp, (size_t)n);
    dst[n] = 0;
    return (uint32_t)n;
}

uint64_t pl_host_sysreg(const char *name)
{
    m_sysreg_reads++;
    if (!strcmp(name, "CurrentEL")) return (uint64_t)m_el << 2;
    m_violate("a system register read: %s", name);
    return 0;
}

static struct q1n1_payload_args m_args(void)
{
    struct q1n1_payload_args a;
    memset(&a, 0, sizeof a);
    a.magic = Q1N1_PAYLOAD_ABI_MAGIC;
    a.version = Q1N1_PAYLOAD_ABI_VERSION;
    a.size = sizeof a;
    a.map_base = m_map_base;
    a.map_size = m_map_size;
    a.map_stride = m_map_stride;
    a.ops.puts = m_puts;
    a.ops.hex = m_hex;
    a.ops.load32 = m_have_load32 ? m_load32 : NULL;
    return a;
}

/* The windows are not mapped in this process: a payload that reads or writes a device address through a pointer instead of load32 dies on a signal whose address is in one, and that is
 * reported as what it is. Any other signal keeps its default action (and a sanitized build keeps its own report). */
#if defined(__SANITIZE_ADDRESS__)
#define M_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define M_SANITIZED 1
#endif
#endif
#ifndef M_SANITIZED
static void m_trap(int sig, siginfo_t *info, void *unused)
{
    static const char verdict[] = "FAIL: an access reached a device window without load32\n";
    uint64_t a = (uint64_t)(uintptr_t)info->si_addr;
    (void)unused;
    if ((a >= 0x00100000u && a < 0x00300000u) || (a >= 0x03d90000u && a < 0x03d9a000u) || (a >= 0x81c60000u && a < 0x81c80000u) || (a >= 0x17520000u && a < 0x17530000u) ||
        (a >= 0x221c8000u && a < 0x221c9000u) || (a >= 0x0c225000u && a < 0x0c226000u) || (a >= XMAP_BASE && a < XMAP_BASE + XMAP_BYTES_MAX)) {
        if (write(2, verdict, sizeof verdict - 1) < 0) _exit(2);
        _exit(1);
    }
    signal(sig, SIG_DFL);
}
#endif

static void m_install_trap(void)
{
#ifndef M_SANITIZED
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = m_trap;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
#endif
}

/* ---- Fixtures --------------------------------------------------------------------------------------------------------------------------------- */

static void m_set(uint64_t addr, uint32_t value)
{
    for (unsigned i = 0; i < m_nfake; i++) {
        if (m_fake[i].addr == addr) {
            m_fake[i].value = value;
            m_fake[i].fault = 0;
            return;
        }
    }
    m_fake[m_nfake].addr = addr;
    m_fake[m_nfake].value = value;
    m_fake[m_nfake++].fault = 0;
}

static void m_rset(int win, uint32_t off, uint32_t value)
{
    m_set(XW[win].base + off, value);
}

static void m_fault_at(uint64_t addr)
{
    m_set(addr, 0);
    for (unsigned i = 0; i < m_nfake; i++) if (m_fake[i].addr == addr) m_fake[i].fault = 1;
}

static void m_rfault(int win, uint32_t off)
{
    m_fault_at(XW[win].base + off);
}

/* The offset of a key in the harness's list. */
static uint32_t m_off(const char *key, int *win)
{
    for (unsigned i = 0; i < M_NREGS; i++) {
        if (!strcmp(M_REGS[i].key, key)) {
            *win = M_REGS[i].win;
            return M_REGS[i].off;
        }
    }
    fprintf(stderr, "FAIL: no register %s in the harness's list\n", key);
    exit(2);
}

static void m_setk(const char *key, uint32_t value)
{
    int win;
    uint32_t off = m_off(key, &win);
    m_rset(win, off, value);
}

static void m_faultk(const char *key)
{
    int win;
    uint32_t off = m_off(key, &win);
    m_rfault(win, off);
}

static void m_reset_run(void)
{
    m_nlines = m_nloads = m_violations = m_dead = m_started = m_sysreg_reads = m_nloadlog = m_aborted = 0;
    m_first_violation[0] = 0;
    m_prev_line = -1;
    m_hung = 0;
    m_lines_at_prev_load = 0;
}

static void m_fx_reset(void)
{
    m_nfake = 0;
    m_fill = 0;
    m_fill_all = 0;
    m_win_faults = 0;
    m_rand_seed = 0;
    m_el = 2;
    m_have_load32 = 1;
    m_abort_nth = m_hang_nth = m_abort_from_nth = -1;
    memset(m_db, 0, sizeof m_db);
    memset(m_map, 0, sizeof m_map);
    m_map_base = XMAP_BASE;
    m_map_size = 0;
    m_map_stride = 48;
    m_reset_run();
}

/* One run of the payload against the current model; a hang (a load that never returns) is a longjmp out of the payload. */
static uint64_t m_run(void)
{
    struct q1n1_payload_args a = m_args();
    uint64_t r = 0;
    m_reset_run();
    m_oracles();
    if (!setjmp(m_hang_jmp)) r = payload_entry(&a);
    return r;
}

/* What every run must satisfy whatever the hardware says. The line check is made between loads of different lines: a line goes out, while the cap leaves room, before the next one is read. */
static int m_clean(int at)
{
    const char *why = NULL;
    unsigned loads = 0, lines = 0, faults = 0, skips = 0, cuts = 0;
    char blk[24];
    for (unsigned k = 1; k < m_nloadlog && !m_violations; k++) {
        const typeof(m_loadlog[0]) *prev = &m_loadlog[k - 1], *cur = &m_loadlog[k];
        if (cur->block != prev->block || cur->line == prev->line) continue;
        if (cur->nlines > prev->nlines || cur->nlines >= m_normal_limit()) continue;       /* a line went out in between, or the cap left no room for it */
        m_violate("load %u (%s line %u) before a line was printed since the load before it (line %u): a line is read whole and printed before the next is read", k, B_NAME[cur->block],
                  cur->line, prev->line);
    }
    if (m_violations) why = m_first_violation;
    else if (m_nlines > LINE_CAP) why = "more lines than the payload's cap";
    else if (m_nloads > LOAD_CAP) why = "more loads than the payload's cap";
    else if (!m_nlines) why = "no line at all";
    else if (m_hung) why = NULL;
    else if (m_el == 2 && m_have_load32) {
        if (sscanf(m_lines[m_nlines - 1], PREFIX "END LOADS=%u FAULTS=%u SKIPS=%u BLK=%23s CUTS=%u LINES=%u", &loads, &faults, &skips, blk, &cuts, &lines) != 6) why = "the last line is not the end line";
        else if (loads != m_nloads) why = "the end line's LOADS is not the loads made";
        else if (lines != m_nlines) why = "the end line's LINES is not the lines printed";
        else if (faults != m_aborted) why = "the end line's FAULTS is not the aborts the model gave";
    }
    if (!why) return 1;
    fprintf(stderr, "FAIL line %d: %s (violations %u, lines %u, loads %u)\n", at, why, m_violations, m_nlines, m_nloads);
    m_dump(stderr);
    m_fails++;
    return 0;
}
static unsigned m_max_lines, m_max_loads;
static void m_track(void)
{
    if (m_nlines > m_max_lines) m_max_lines = m_nlines;
    if (m_nloads > m_max_loads) m_max_loads = m_nloads;
}
#define RUN_CLEAN() do { m_checks++; (void)m_run(); (void)m_clean(__LINE__); m_track(); } while (0)

/* ---- The page ---------------------------------------------------------------------------------------------------------------------------------- */

static int m_find(const char *head, unsigned from)
{
    char want[120];
    size_t n;
    snprintf(want, sizeof want, "%s%s", PREFIX, head);
    n = strlen(want);
    for (unsigned i = from; i < m_nlines; i++) {
        if (!strncmp(m_lines[i], want, n) && (m_lines[i][n] == 0 || m_lines[i][n] == ' ')) return (int)i;
    }
    return -1;
}

static const char *m_text(unsigned n)
{
    return m_lines[n] + strlen(PREFIX);
}

static int m_line_is(unsigned n, const char *text, int at)
{
    char want[240];
    snprintf(want, sizeof want, "%s%s", PREFIX, text);
    m_checks++;
    if (n >= m_nlines || strcmp(m_lines[n], want)) {
        m_fails++;
        fprintf(stderr, "FAIL line %d: page line %u is \"%s\", not \"%s\"\n", at, n, n < m_nlines ? m_lines[n] : "(none)", want);
        m_dump(stderr);
        return 0;
    }
    return 1;
}

/* The value of an item of a line, as text: `KEY=<value>` up to the next space. NULL when the line has no such item. */
static const char *m_item(const char *line, const char *key)
{
    static char out[64];
    char pat[32];
    const char *p;
    size_t n = 0;
    snprintf(pat, sizeof pat, " %s=", key);
    p = strstr(line, pat);
    if (!p) return NULL;
    p += strlen(pat);
    while (p[n] && p[n] != ' ' && n < sizeof out - 1) n++;
    memcpy(out, p, n);
    out[n] = 0;
    return out;
}

/* One item of the line with head `head`: a check that names both. */
static int m_item_is(const char *head, const char *key, const char *want, int at)
{
    int n = m_find(head, 0);
    const char *got;
    m_checks++;
    if (n < 0) {
        m_fails++;
        fprintf(stderr, "FAIL line %d: no page line `%s`\n", at, head);
        m_dump(stderr);
        return 0;
    }
    got = m_item(m_text((unsigned)n), key);
    if (!got || strcmp(got, want)) {
        m_fails++;
        fprintf(stderr, "FAIL line %d: item %s of `%s` is \"%s\", not \"%s\"\n", at, key, head, got ? got : "(none)", want);
        m_dump(stderr);
        return 0;
    }
    return 1;
}

static unsigned m_loads_of_block(int block)
{
    unsigned n = 0;
    for (unsigned i = 0; i < m_nloadlog; i++) n += m_loadlog[i].block == block;
    return n;
}

static int m_loaded(int win, uint32_t off)
{
    for (unsigned i = 0; i < m_nloadlog; i++) if (m_loadlog[i].addr == XW[win].base + off) return 1;
    return 0;
}
