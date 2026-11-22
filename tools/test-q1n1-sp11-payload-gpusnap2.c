/* SPDX-License-Identifier: MIT */
/* Host test of the payload "gpusnap2" (payloads/gpusnap2.c, docs/SP11-PAYLOAD-GPUSNAP2.md): the suites. tools/test-q1n1-sp11-payload-gpusnap2-model.h is the model (the fake memory, the runner's
 * ops, the harness's own list of what may be read and its oracles); tools/test-q1n1-sp11-payload-gpusnap2-suites.inc holds the adversarial suites of the memory map, the command database and
 * the RSC. Built by tools/test-q1n1-sp11-payload-gpusnap2.py under ASan and UBSan, at the shipped caps and at smaller ones (-DGPUSNAP2_LINE_CAP, -DGPUSNAP2_LOAD_CAP: only the `caps` suite
 * then), and with GPUSNAP2_SRC pointing at a seeded-bug copy of the payload for the mutants.
 *
 * Everything a fixture holds is MADE UP to show what a page looks like, except what the unit showed: tsens3's identity and control words and sensor numbers (boot 29), the CFG AHB word and
 * the three GPUCC words boot 30 read, and the shape of the memory map (a reserved descriptor of 0x2c0 pages at 0x81a40000, which covers the command database: derived from the unit's own
 * maps). No value of the command database, the RSC, the PLLs or the QFPROM was ever read on the unit (UNKNOWN). Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only).
 *
 *   unit      the nominal world: the whole page, line by line, and every load once; the page the document shows
 *   order     the blocks in their order, each under its NEXT line, every window's loads and the end line
 *   tsens     the status-word decode over every sensor number and every kind of word, and the gates of the block
 *   gpucc     the clock words' decodes, the PLL verdicts and the CFG AHB gate in all its cases
 *   map       the memory-map verdicts against the oracle's and against named cases
 *   cmddb     the database walk: what is found, what is absent, what is cut, what is out of range
 *   rsc       the RSC: both layouts, the version, TCS-count and enable gates, the rail matches and the data reads
 *   qfprom    the speed-bin decode
 *   gates     every gate closed in turn: no load behind it, the reason on the page
 *   faults    an abort at every load of the nominal run, and storms of aborts
 *   hang      a hang at every load of the nominal run: the page so far is a prefix of the clean page and its last line names the block
 *   random    seeded worlds against the page oracle
 *   storm     hostile fills (all ones, zeros, bit 31) in every window
 *   budget    the worst case's loads against the bound the header derives
 *   el        not at EL2, no load32, bad arguments */
#include "test-q1n1-sp11-payload-gpusnap2-model.h"

static uint64_t m_seed = 0x9E3779B97F4A7C15ull;
static uint32_t m_rand(void)
{
    m_seed ^= m_seed << 13;
    m_seed ^= m_seed >> 7;
    m_seed ^= m_seed << 17;
    return (uint32_t)(m_seed >> 11);
}

/* ---- Fixtures ---------------------------------------------------------------------------------------------------------------------------------- */

static uint32_t m_status(int tenths, unsigned sensor)
{
    return sensor << 22 | 1u << 21 | ((uint32_t)tenths & 0xfffu);
}

static void m_db_header(unsigned i, unsigned slv, unsigned hoff, unsigned doff, unsigned cnt)
{
    uint8_t *h = m_db + 8 + 16 * i;
    m_put16(h, slv);
    m_put16(h + 2, hoff);
    m_put16(h + 4, doff);
    m_put16(h + 6, cnt);
}

static void m_db_entry(unsigned at, const char *id, uint32_t addr, unsigned len, unsigned off)
{
    uint8_t *e = m_db + at;
    memset(e, 0, 24);
    memcpy(e, id, strlen(id) > 8 ? 8 : strlen(id));
    m_put32(e + 16, addr);
    m_put16(e + 20, len);
    m_put16(e + 22, off);
}

static void m_db_levels(unsigned at, unsigned n, const unsigned *lev)
{
    for (unsigned i = 0; i < n; i++) m_put16(m_db + at + 2 * i, lev[i]);
}

/* A database of the shape Linux reads (cmd-db.c), with made-up addresses and level tables: an ARC list of eight (the five the GPU needs, three others), a VRM list of four, a BCM list of six. */
#define DB_A 0x90u
static void m_db_unit(void)
{
    static const unsigned cx[] = {16, 48, 64, 128, 192, 256, 320, 384, 416}, mx[] = {16, 48, 64, 128, 192, 256, 384, 416}, gfx[] = {16, 48, 64, 128, 192, 256, 384}, gmxc[] = {16, 64, 128, 256};
    memset(m_db, 0, sizeof m_db);
    m_put32(m_db, 1);
    m_db[4] = 0xdb;
    m_db[5] = 0x30;
    m_db[6] = 0x03;
    m_db[7] = 0x0c;
    m_db_header(0, 3, 0, 0x400, 8);
    m_db_header(1, 4, 24 * 8, 0x500, 4);
    m_db_header(2, 5, 24 * 12, 0x600, 6);
    m_db_entry(DB_A + 0, "cx.lvl", 0x30000, 18, 0x00);
    m_db_entry(DB_A + 24, "mx.lvl", 0x30004, 16, 0x20);
    m_db_entry(DB_A + 48, "lcx.lvl", 0x30008, 0, 0);
    m_db_entry(DB_A + 72, "gfx.lvl", 0x3000c, 14, 0x40);
    m_db_entry(DB_A + 96, "gmxc.lvl", 0x30010, 8, 0x60);
    m_db_entry(DB_A + 120, "gbx.lvl", 0x30014, 0, 0);
    m_db_entry(DB_A + 144, "nsp.lvl", 0x30018, 0, 0);
    m_db_entry(DB_A + 168, "mss.lvl", 0x3001c, 0, 0);
    m_db_entry(DB_A + 192, "ldoa1", 0x40000, 0, 0);
    m_db_entry(DB_A + 216, "ldoa2", 0x40010, 0, 0);
    m_db_entry(DB_A + 240, "smpa1", 0x40020, 0, 0);
    m_db_entry(DB_A + 264, "smpa2", 0x40030, 0, 0);
    m_db_entry(DB_A + 288, "ACV", 0x50000, 0, 0);
    m_db_entry(DB_A + 312, "MC0", 0x50004, 0, 0);
    m_db_entry(DB_A + 336, "SH0", 0x50008, 0, 0);
    m_db_entry(DB_A + 360, "CE0", 0x5000c, 0, 0);
    m_db_entry(DB_A + 384, "MM0", 0x50010, 0, 0);
    m_db_entry(DB_A + 408, "SN0", 0x50014, 0, 0);
    m_db_levels(DB_A + 0x400 + 0x00, 9, cx);
    m_db_levels(DB_A + 0x400 + 0x20, 8, mx);
    m_db_levels(DB_A + 0x400 + 0x40, 7, gfx);
    m_db_levels(DB_A + 0x400 + 0x60, 4, gmxc);
}

static void m_map_desc(unsigned i, uint32_t type, uint64_t start, uint64_t pages, uint32_t attr)
{
    uint8_t *d = m_map + i * m_map_stride;
    memset(d, 0, m_map_stride);
    m_put32(d, type);
    m_put32(d + 8, (uint32_t)start);
    m_put32(d + 12, (uint32_t)(start >> 32));
    m_put32(d + 24, (uint32_t)pages);
    m_put32(d + 28, (uint32_t)(pages >> 32));
    m_put32(d + 32, attr);
}

/* `n` descriptors of stride 48: fillers of types 1 to 7 and 11 below and above, and the reserved one that covers the database at index n / 2. */
static void m_map_unit(unsigned n)
{
    memset(m_map, 0, sizeof m_map);
    m_map_stride = 48;
    m_map_size = (uint64_t)n * m_map_stride;
    for (unsigned i = 0; i < n; i++) {
        uint32_t type = 1 + i % 7 + (i % 11 == 10 ? 4 : 0);
        if (i == n / 2) m_map_desc(i, 0, 0x81a40000ull, 0x2c0, 1);
        else if (i < n / 2) m_map_desc(i, type, 0x80000000ull + 0x4000ull * i, 4, 8);
        else m_map_desc(i, type, 0x82000000ull + 0x4000ull * i, 4, 8);
    }
}

static void m_fx_tsens(void)
{
    m_rset(XW_TSROT, 0, 0x20080000u);
    m_rset(XW_TSROT, 4, 0x9D63FFF9u);
    for (unsigned s = 5; s <= 12; s++) {
        static const int t[8] = {398, 390, 385, 388, 384, 391, 395, 389};
        m_rset(XW_TTM, 0xa0 + 4 * s, m_status(t[s - 5], s));
    }
}

static void m_fx_gpucc(void)
{
    m_rset(XW_GCC, 0x71004, 0x1);
    m_setk("AHB", 0x0); m_setk("CXGD", 0x22F801); m_setk("CXHW", 0xDFF4);
    m_setk("P0MODE", 0x0); m_setk("P0OP", 0x0); m_setk("P0L", 0x29); m_setk("P0AL", 0xA000);
    m_setk("P1MODE", 0x0); m_setk("P1OP", 0x0); m_setk("P1L", 0x16); m_setk("P1AL", 0xEAAA);
    m_setk("FFC", 0x80000000); m_setk("FFF", 0x100); m_setk("XDIV", 0x0); m_setk("DDIV", 0x1);
    m_setk("CRC", 0x80000000); m_setk("CXFF", 0x80000000); m_setk("FM", 0x80000000);
    m_setk("MEM", 0x80000000); m_setk("SLP", 0x80000000); m_setk("CB", 0x80000001);
}

/* The RSC at version 2.7 (`major` 3 for the other layout): drv-2 has seven TCSs; the wake TCSs hold three commands each, the first two for CX and MX (the addresses of the database above). */
static void m_rsc_cmd(unsigned t, unsigned j, uint32_t addr, uint32_t data)
{
    unsigned en, ad, da, st;
    if (!m_rsc_layout(&en, &ad, &da, &st)) return;
    m_rset(XW_RSC, 0xd00 + 672 * t + ad + st * j, addr);
    m_rset(XW_RSC, 0xd00 + 672 * t + da + st * j, data);
}

static void m_fx_rsc(unsigned major)
{
    m_rset(XW_RSC, 0x00, major << 16 | 0x0701u);
    m_rset(XW_RSC, 0x04, 0);
    m_rset(XW_RSC, 0x0c, 3u << 27 | 7u << 12);
    m_rset(XW_RSC, 0xd00, 0x7);
    m_rset(XW_RSC, 0xd04, 0);
    for (unsigned t = 0; t < 7; t++) {
        unsigned en, ad, da, st;
        m_rsc_layout(&en, &ad, &da, &st);
        m_rset(XW_RSC, 0xd00 + 672 * t + en, t == 3 || t == 4 ? 0x3u : t >= 5 ? 0x7u : 0u);
    }
    for (unsigned t = 5; t < 7; t++) {
        m_rsc_cmd(t, 0, 0x30000, t == 5 ? 64 : 128);
        m_rsc_cmd(t, 1, 0x30004, t == 5 ? 64 : 128);
        m_rsc_cmd(t, 2, 0x50000, 1);
    }
}

static void m_fx_unit(void)
{
    m_fx_reset();
    m_fx_tsens();
    m_fx_gpucc();
    m_db_unit();
    m_map_unit(227);
    m_fx_rsc(2);
    m_rset(XW_QFP, 0x118, 59u << 15 | 0x1234u);
}

/* ---- The page, from the memory, by the harness's own arithmetic -------------------------------------------------------------------------------- */

struct o_page {
    char line[48][240];
    unsigned n;
};

/* The payload puts items on a line one at a time and drops, whole and counted, any that would take it past 100 characters with the prefix; later, shorter items may still fit. The oracle's lines
 * are built in full and packed the same way here: the head is the first token, or the first two when the second is not an item (has no `=`), and everything after is an item. */
static void o_pack(char *line)
{
    static const char *const kinds[] = {"T3 ", "GCC ", "GPUCC ", "CMDDB ", "RSC2 ", "QFPROM "};
    char out[240], copy[240];
    char *tok, *save = NULL;
    unsigned n = 0, known = 0;
    for (unsigned i = 0; i < sizeof kinds / sizeof kinds[0]; i++) known |= !strncmp(line, kinds[i], strlen(kinds[i]));
    if (!known || strlen(PREFIX) + strlen(line) <= Q1N1_PAYLOAD_LINE_MAX) return;
    snprintf(copy, sizeof copy, "%s", line);
    out[0] = 0;
    for (tok = strtok_r(copy, " ", &save); tok; tok = strtok_r(NULL, " ", &save), n++) {
        int head = n == 0 || (n == 1 && !strchr(tok, '='));
        if (head || strlen(PREFIX) + strlen(out) + 1 + strlen(tok) <= Q1N1_PAYLOAD_LINE_MAX) snprintf(out + strlen(out), sizeof out - strlen(out), "%s%s", n ? " " : "", tok);
    }
    snprintf(line, 240, "%s", out);
}

static void o_say(struct o_page *p, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void o_say(struct o_page *p, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(p->line[p->n], sizeof p->line[0], fmt, ap);
    va_end(ap);
    o_pack(p->line[p->n++]);
}

/* The runner's own form of a number below ten and above. */
static const char *o_t(uint32_t v)
{
    static char b[16][16];
    static unsigned k;
    char *s = b[k++ & 15];
    if (v < 10) snprintf(s, 16, "%u", v);
    else snprintf(s, 16, "0X%X", v);
    return s;
}

static const char *o_reg(int win, uint32_t off)
{
    return o_t(m_reg_value(win, off));
}

/* The cell of a status word (tsnap v1.1's rules, restated): tenths of a degree, ? (VALID clear), O (odd or out of range). */
static const char *o_cell(uint32_t raw, int code, unsigned sensor, int *kind, int *tenths)
{
    static char b[16][16];
    static unsigned k;
    char *s = b[k++ & 15];
    int t = (int)(raw & 0xfff);
    if (t & 0x800) t -= 0x1000;
    *tenths = t;
    *kind = 2;                                  /* odd */
    if ((raw >> 27) || ((raw >> 22) & 31) != sensor) return "O";
    if (!(raw & 1u << 21)) {
        *kind = 1;
        return "?";
    }
    if (code) return "O";
    if (t < -400 || t > 1200) {
        *kind = 3;
        return "O";
    }
    *kind = 0;
    snprintf(s, 16, "%d", t);
    return s;
}

static void o_tsens(struct o_page *p)
{
    uint32_t ver = m_reg_value(XW_TSROT, 0), ctl = m_reg_value(XW_TSROT, 4);
    char cells[220] = "", raw[220] = "";
    int valid = 0, min = 0, max = 0, min_at = 0, max_at = 0, odd = 0, out = 0, crit = 0, code;
    o_say(p, "NEXT TSENS3");
    if (!ver || ver == 0xffffffffu) {
        o_say(p, "T3 VER=%s GATED", o_t(ver));
        return;
    }
    if (!(ctl & 1) || (ctl & 2)) {
        o_say(p, "T3 VER=%s CTL=%s SEN=0X%X OFF", o_t(ver), o_t(ctl), (ctl >> 3) & 0xffff);
        return;
    }
    code = !(ctl >> 21 & 1);
    o_say(p, "T3 VER=%s CTL=%s SEN=0X%X%s", o_t(ver), o_t(ctl), (ctl >> 3) & 0xffff, code ? " CODE" : "");
    for (unsigned i = 0; i < 8; i++) {
        uint32_t w = m_reg_value(XW_TTM, 0xa0 + 4 * (5 + i));
        int kind, t;
        const char *c = o_cell(w, code, 5 + i, &kind, &t);
        snprintf(raw + strlen(raw), sizeof raw - strlen(raw), " %08X", w);
        snprintf(cells + strlen(cells), sizeof cells - strlen(cells), " %s", c);
        if (kind != 2 && (w & 3u << 19)) crit++;
        if (kind == 2) odd++;
        if (kind == 3) out++;
        if (kind == 0) {
            if (!valid || t < min) {
                min = t;
                min_at = 5 + (int)i;
            }
            if (!valid || t > max) {
                max = t;
                max_at = 5 + (int)i;
            }
            valid++;
        }
    }
    o_say(p, "T3 R5%s", raw);
    {
        char tail[120], lo[24] = "NA", hi[24] = "NA", fl[60] = "";
        if (valid) {
            snprintf(lo, sizeof lo, "%d(S%d)", min, min_at);
            snprintf(hi, sizeof hi, "%d(S%d)", max, max_at);
        }
        if (crit) snprintf(fl + strlen(fl), sizeof fl - strlen(fl), " CRIT=%d", crit);
        if (out) snprintf(fl + strlen(fl), sizeof fl - strlen(fl), " OUT=%d", out);
        if (odd) snprintf(fl + strlen(fl), sizeof fl - strlen(fl), " ODD=%d", odd);
        snprintf(tail, sizeof tail, " V=%d MIN=%s MAX=%s%s", valid, lo, hi, fl);
        o_say(p, "T3 C5%s%s", cells, tail);
    }
}

/* The decodes of a clock word, by the kind of its row. */
static const char *o_dec(char kind, uint32_t w)
{
    int ones = w == 0xffffffffu;
    if (kind == 'C') {
        int odd = ones || (!(w >> 31) && !(w & 1)) || ((w >> 31) && ((w >> 28) & 7) == 2);
        return odd ? ".ODD" : (w >> 31) ? ".OFF" : ".ON";
    }
    if (kind == 'R') return ones ? ".ODD" : (w >> 31) ? ".OFF" : ".ON";
    if (kind == 'P') return ones ? ".ODD" : (w >> 31) ? ".ON" : ".OFF";
    return "";
}

static const char *o_bit(uint32_t w, unsigned shift, uint32_t mask)
{
    static char b[8][16];
    static unsigned k;
    char *s = b[k++ & 7];
    if (w == 0xffffffffu) return "ODD";
    snprintf(s, 16, "%s", o_t(w >> shift & mask));
    return s;
}

static int o_ahb_proves(void)
{
    uint32_t w = m_reg_value(XW_GCC, 0x71004);
    return w != 0xffffffffu && (w & 1) && !(w >> 31);
}

static void o_pll(struct o_page *p, const char *head, uint32_t mo, uint32_t op, uint32_t l, uint32_t al)
{
    const char *en = (mo == 0xffffffffu || op == 0xffffffffu) ? "ODD" : ((op & 1) && (mo & 1)) ? "ON" : "OFF";
    o_say(p, "GPUCC %s MODE=%s OP=%s L=%s AL=%s EN=%s LK=%s", head, o_t(mo), o_t(op), o_t(l), o_t(al), en, o_bit(mo, 31, 1));
}

static void o_gcc_gpucc(struct o_page *p)
{
    uint32_t cfga = m_reg_value(XW_GCC, 0x71004), g[22];
    static const struct { int win; uint32_t off; } rows[] = {
        {XW_GPUCC, 0x911c}, {XW_GPUCC, 0x9108}, {XW_GPUCC, 0x953c}, {XW_GPUCC, 0x0}, {XW_GPUCC, 0x30}, {XW_GPUCC, 0x4}, {XW_GPUCC, 0x8}, {XW_GPUCC, 0x1000}, {XW_GPUCC, 0x1004},
        {XW_GPUCC, 0x1010}, {XW_GPUCC, 0x1014}, {XW_GPUCC, 0x9474}, {XW_GPUCC, 0x9478}, {XW_GPUCC, 0x9050}, {XW_GPUCC, 0x9054}, {XW_GPUCC, 0x9120}, {XW_GPUCC, 0x914c}, {XW_GPUCC, 0x9008},
        {XW_GPUCC, 0x9150}, {XW_GPUCC, 0x9134}, {XW_GPUCC, 0x93a4}};
    o_say(p, "NEXT GCC");
    o_say(p, "GCC CFGA=%s%s", o_t(cfga), o_dec('C', cfga));
    if (!o_ahb_proves()) {
        o_say(p, "GPUCC GATED BY %s", cfga == 0xffffffffu ? "AHBERR" : "AHB");
        return;
    }
    for (unsigned i = 0; i < 21; i++) g[i] = m_reg_value(rows[i].win, rows[i].off);
    o_say(p, "NEXT GPUCC");
    o_say(p, "GPUCC AHB=%s%s CXGD=%s SC=%s HW=%s CXHW=%s%s", o_t(g[0]), o_dec('C', g[0]), o_t(g[1]), o_bit(g[1], 0, 1), o_bit(g[1], 1, 1), o_t(g[2]), o_dec('P', g[2]));
    o_pll(p, "PLL0", g[3], g[4], g[5], g[6]);
    o_pll(p, "PLL1", g[7], g[8], g[9], g[10]);
    o_say(p, "GPUCC FFC=%s%s FFF=%s S=%s XDIV=%s DDIV=%s", o_t(g[11]), o_dec('R', g[11]), o_t(g[12]), o_bit(g[12], 8, 7), o_t(g[13]), o_t(g[14]));
    o_say(p, "GPUCC CRC=%s%s CXFF=%s%s FM=%s%s", o_t(g[15]), o_dec('C', g[15]), o_t(g[16]), o_dec('C', g[16]), o_t(g[17]), o_dec('C', g[17]));
    o_say(p, "GPUCC MEM=%s%s SLP=%s%s CB=%s%s", o_t(g[18]), o_dec('C', g[18]), o_t(g[19]), o_dec('C', g[19]), o_t(g[20]), o_dec('C', g[20]));
}

static const char *o_addr(const struct o_tgt *g)
{
    return g->state == OT_FOUND ? o_t(g->addr) : g->state == OT_PART ? "PART" : g->state == OT_NA ? "NA" : "NONE";
}

static const char *o_lvl(const struct o_tgt *g)
{
    static char b[8][120];
    static unsigned k;
    char *s = b[k++ & 7];
    if (g->state != OT_FOUND) return g->state == OT_PART ? "PART" : g->state == OT_NA ? "NA" : "NONE";
    if (g->len < 2) return "EMPTY";
    if (g->aux & 1) return "ODD";
    if (!g->levels_ok) return "RANGE";
    snprintf(s, 120, "%u:", g->nlev);
    for (unsigned i = 0; i < g->shown; i++) snprintf(s + strlen(s), 120 - strlen(s), "%s%u", i ? "/" : "", g->lev[i]);
    return s;
}

static void o_cmddb(struct o_page *p)
{
    char t[8][160];
    o_say(p, "NEXT CMDDB");
    {
        char tail[100] = "";
        if (m_om.hits && m_om.desc) snprintf(tail, sizeof tail, " T=%u ATTR=%s", m_om.type, o_t(m_om.attr));
        o_say(p, "CMDDB MAP DESC=%u HITS=%u%s %s", m_om.desc, m_om.hits, tail, OM_NAME[m_om.state]);
    }
    if (m_om.state != OM_OPEN) {
        o_say(p, "CMDDB GATED BY MAP");
        return;
    }
    if (!m_od.magic_ok) {
        o_say(p, "CMDDB HDR VER=%s MAGIC=BAD", o_t(m_od.ver));
        o_say(p, "CMDDB GATED BY MAGIC");
        return;
    }
    o_say(p, "CMDDB HDR VER=%s MAGIC=OK HDRS=%u ARC=%u BCM=%u", o_t(m_od.ver), m_od.nh, m_od.arc, m_od.bcm);
    for (unsigned i = 0; i < 8; i++) snprintf(t[i], sizeof t[i], "%s", o_addr(&m_od.t[i]));
    o_say(p, "CMDDB ADDR CX=%s MX=%s GFX=%s GMXC=%s GBX=%s", t[0], t[1], t[2], t[3], t[4]);
    o_say(p, "CMDDB BCM SH0=%s MC0=%s ACV=%s", t[5], t[6], t[7]);
    o_say(p, "CMDDB LVL CX=%s MX=%s", o_lvl(&m_od.t[0]), o_lvl(&m_od.t[1]));
    o_say(p, "CMDDB LVL GFX=%s GMXC=%s", o_lvl(&m_od.t[2]), o_lvl(&m_od.t[3]));
}

static void o_rsc(struct o_page *p)
{
    static const char *const key[7] = {"A0", "A1", "A2", "S3", "S4", "W5", "W6"};
    uint32_t id = m_reg_value(XW_RSC, 0), chld = m_reg_value(XW_RSC, 0xc), en[7], mask;
    unsigned major = id >> 16 & 0xff, enr, ad, da, st;
    char line[240];
    o_say(p, "NEXT RSC2");
    if (!id || id == 0xffffffffu) {
        o_say(p, "RSC2 ID=%s", o_t(id));
        o_say(p, "RSC2 GATED BY ID");
        return;
    }
    o_say(p, "RSC2 ID=%s VER=%u.%u", o_t(id), major, id >> 8 & 0xff);
    if (!m_rsc_layout(&enr, &ad, &da, &st)) {
        o_say(p, "RSC2 GATED BY VER");
        return;
    }
    snprintf(line, sizeof line, "RSC2 CFG SOL=%s CHLD=%s", o_reg(XW_RSC, 4), o_t(chld));
    if (chld != 0xffffffffu) snprintf(line + strlen(line), sizeof line - strlen(line), " NT=%u", chld >> 12 & 0x3f);
    snprintf(line + strlen(line), sizeof line - strlen(line), " IRQE=%s IRQS=%s", o_reg(XW_RSC, 0xd00), o_reg(XW_RSC, 0xd04));
    if (chld != 0xffffffffu) snprintf(line + strlen(line), sizeof line - strlen(line), " NCPT=%u", chld >> 27 & 0x1f);
    o_say(p, "%s", line);
    if (chld == 0xffffffffu || (chld >> 12 & 0x3f) < 7) {
        o_say(p, "RSC2 GATED BY TCS");
        return;
    }
    snprintf(line, sizeof line, "RSC2 EN");
    for (unsigned t = 0; t < 7; t++) en[t] = m_reg_value(XW_RSC, 0xd00 + 672 * t + enr);
    for (unsigned i = 0; i < 7; i++) {
        static const unsigned order[7] = {5, 6, 3, 4, 0, 1, 2};
        unsigned t = order[i];
        snprintf(line + strlen(line), sizeof line - strlen(line), " %s=%s%s", key[t], o_t(en[t]), (en[t] == 0xffffffffu || (en[t] >> 16)) ? ".ODD" : "");
    }
    o_say(p, "%s", line);
    for (unsigned t = 5; t < 7; t++) {
        int ok = en[t] != 0xffffffffu && !(en[t] >> 16);
        const char *vote[4];
        char b[4][16];
        mask = en[t];
        for (unsigned r = 0; r < 4; r++) {
            uint32_t a;
            vote[r] = ok && x_rail(r, &a) ? "-" : "NA";
            for (unsigned j = 0; j < 16 && ok; j++) {
                if (!(mask >> j & 1) || !x_rail(r, &a) || m_reg_value(XW_RSC, 0xd00 + 672 * t + ad + st * j) != a) continue;
                {
                    uint32_t d = m_reg_value(XW_RSC, 0xd00 + 672 * t + da + st * j);
                    if (d < 0x10000) snprintf(b[r], sizeof b[r], "%u", d);
                    else snprintf(b[r], sizeof b[r], "0X%X", d);
                    vote[r] = b[r];
                }
            }
        }
        char nb[16] = "NA";
        if (ok) snprintf(nb, sizeof nb, "%d", __builtin_popcount(mask));
        o_say(p, "RSC2 W%u N=%s CX=%s MX=%s GFX=%s GMXC=%s", t, nb, vote[0], vote[1], vote[2], vote[3]);
    }
}

static void o_qfprom(struct o_page *p)
{
    static const struct { unsigned fuse, bin; } sb[5] = {{0, 0}, {59, 1}, {7, 2}, {232, 3}, {146, 4}};
    uint32_t w = m_reg_value(XW_QFP, 0x118);
    unsigned fuse = w >> 15 & 0xff;
    char bin[8] = "?";
    o_say(p, "NEXT QFPROM");
    for (unsigned i = 0; i < 5; i++) if (sb[i].fuse == fuse) snprintf(bin, sizeof bin, "%u", sb[i].bin);
    o_say(p, "QFPROM W118=%s FUSE=%u SB=%s", o_t(w), fuse, bin);
}

static void o_page(struct o_page *p)
{
    p->n = 0;
    o_say(p, "READ ONLY EL=2 CAP=%u/%u", LOAD_CAP, LINE_CAP);
    o_say(p, "%s", LEGEND);
    o_tsens(p);
    o_gcc_gpucc(p);
    o_cmddb(p);
    o_rsc(p);
    o_qfprom(p);
}

/* The page of the run against the oracle's, every line but the end line, and the end line's own fields against the run. */
static int m_page_is_oracle(int at)
{
    struct o_page p;
    unsigned bad = 0;
    char want[260];
    o_page(&p);
    m_checks++;
    if (m_nlines != p.n + 1) bad = 1;
    for (unsigned i = 0; i < p.n && i + 1 < m_nlines && !bad; i++) {
        snprintf(want, sizeof want, "%s%s", PREFIX, p.line[i]);
        if (strcmp(m_lines[i], want)) {
            fprintf(stderr, "FAIL line %d: page line %u is \"%s\", the oracle's is \"%s\"\n", at, i, m_lines[i], want);
            bad = 1;
        }
    }
    if (bad) {
        m_fails++;
        fprintf(stderr, "FAIL line %d: the page (%u lines) is not the oracle's (%u lines + the end line)\n", at, m_nlines, p.n);
        m_dump(stderr);
        fprintf(stderr, "  the oracle's page:\n");
        for (unsigned i = 0; i < p.n; i++) fprintf(stderr, "  %2u %s\n", i, p.line[i]);
        return 0;
    }
    return 1;
}
#define PAGE_IS_ORACLE() m_page_is_oracle(__LINE__)

/* Every register of the harness's list is loaded exactly once (the windows the nominal world opens), and nothing else of the fixed windows. */
static int m_each_register_once(void)
{
    for (unsigned i = 0; i < M_NREGS; i++) {
        unsigned n = 0;
        for (unsigned k = 0; k < m_nloadlog; k++) n += m_loadlog[k].addr == XW[M_REGS[i].win].base + M_REGS[i].off;
        if (n != 1) return 0;
    }
    return 1;
}

#include "test-q1n1-sp11-payload-gpusnap2-suites.inc"

/* ---- The nominal world ---- */

static int suite_unit(void)
{
    m_fx_unit();
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE());
    CHECK(m_each_register_once());
    CHECK(m_nlines == 31 && m_violations == 0);
    CHECK(m_end_loads() == m_nloads);
    return 0;
}

#define SUITE(name) do { unsigned before_ = m_fails; suite_##name(); printf("suite %-8s %s\n", #name, m_fails == before_ ? "ok" : "FAIL"); } while (0)

/* The page of a scenario, for the document and for a reader: `unit` is the nominal world, `gated` one in which the CFG AHB clock does not run, the map says the database is conventional memory
 * and the RSC's version is not one the payload knows, `aborts` one in which the RSC and the QFPROM abort on their first word. */
static void print_page(const char *scenario)
{
    m_fx_unit();
    if (scenario && !strcmp(scenario, "gated")) {
        m_rset(XW_GCC, 0x71004, 0x80000001u);
        m_map_desc(113, 7, RG, 0x20, 1);
        m_rset(XW_RSC, 0, 4u << 16 | 0x0701u);
    } else if (scenario && !strcmp(scenario, "aborts")) {
        m_rfault(XW_RSC, 0);
        m_rfault(XW_QFP, 0x118);
    }
    (void)m_run();
    for (unsigned i = 0; i < m_nlines; i++) printf("%s\n", m_lines[i]);
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "--page")) {
        print_page(argc > 2 ? argv[2] : NULL);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--numbers")) {
        m_fx_unit();
        (void)m_run();
        printf("LINES %u LOADS %u LINE_CAP %u LOAD_CAP %u PAGE_LINES %u LOADS_MAX %u\n", m_nlines, m_nloads, LINE_CAP, LOAD_CAP, PAGE_LINES, LOADS_MAX);
        return 0;
    }
    m_install_trap();
#ifdef GPUSNAP2_SHIPPED_CAPS
    SUITE(unit);
    SUITE(order);
    SUITE(tsens);
    SUITE(gpucc);
    SUITE(map);
    SUITE(cmddb);
    SUITE(rsc);
    SUITE(qfprom);
    SUITE(gates);
    SUITE(faults);
    SUITE(hang);
    SUITE(random);
    SUITE(storm);
    SUITE(budget);
    SUITE(el);
#else
    SUITE(caps);
#endif
    printf("CHECKS %u FAILS %u MAXLINES %u MAXLOADS %u LINE_CAP %u LOAD_CAP %u\n", m_checks, m_fails, m_max_lines, m_max_loads, LINE_CAP, LOAD_CAP);
    return m_fails ? 1 : 0;
}
