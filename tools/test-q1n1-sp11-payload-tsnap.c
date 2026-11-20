/* SPDX-License-Identifier: MIT */
/* Host test for the payload "tsnap" (payloads/tsnap.c): the suites. tools/test-q1n1-sp11-payload-tsnap-model.h is what they run against (eight register windows with the model's own
 * list of the addresses a read may reach, the runner's ops and page rules, a counter, a CPU's two system registers, and the model's own arithmetic of every line that depends on the
 * words); tools/test-q1n1-sp11-payload-tsnap.py drives the build under ASan
 * and UBSan and builds it again with TSNAP_SRC pointing at a seeded-bug copy of the payload, to show that each mutant is refused. The suites pin what it prints:
 *   unit      the golden page of the made-up fixture (NOT the unit's page: nothing was ever read there), its loads, and that the loads are exactly the model's own list
 *   order     the events in order: each block's NEXT line before its first load, its identity line before the first load of its TM window, TRDY last in the block, the second reading
 *             before the conversion pass, each line right after the loads it holds, tsens3 last, the closing lines last
 *   cells     every kind of status word (VALID, not VALID, all ones, reserved bits, the edges of the plausible window, the critical flags) against the model's own decode, in curated
 *             and in random worlds, down to the raw lines, the temperature lines, SUM1 and the second reading
 *   gate      HW_VER aborting, zero or all ones; CTRL with EN clear, SW_RST set, all ones, aborting, or with CODE_OR_TEMP clear: the block is GATED, OFF, CTLERR or CODE, its TM window
 *             is never read (but for CODE), the other blocks do not change
 *   faults    an abort at every load in turn, the SROT or the TM windows aborting, every window aborting, an abort storm from every load on: one access to a window that aborted, the
 *             token in its place, nothing silenced but the window
 *   hang      a hang at every load in turn: the page up to then is exactly the clean run's page up to that load, so the last line names what hung
 *   drift     what moves during the gap: nothing, everything, a sensor that goes invalid, odd, a jump, a block that goes OFF, a CTRL or TM window that aborts in the second reading
 *   counter   running (the gap is at least 2 s, also for a counter that needs more reads than 2^28), stuck, absent, running backwards, moving and then standing still; the
 *             frequency's range and its default
 *   el        any EL but 2: one line, no load; no load op; bad arguments
 *   budget    the widest page: the cap holds, nothing is cut that a normal page needs
 *   storm     random worlds with random words, aborts and hangs: every invariant, no crash under the sanitizers
 * With TSNAP_LINE_CAP, TSNAP_LOAD_CAP, TSNAP_SPIN_MAX or TSNAP_STUCK_READS set, only the cap suite runs. `--page [scenario]` prints a page, `--numbers` the numbers the document quotes,
 * `--slow` (shipped caps) runs the one suite that takes seconds: a counter that needs more reads than 2^28 still completes the wait.
 * Nothing here ran on hardware. Evidence: EXPERIMENTAL (host model only). */
#include "test-q1n1-sp11-payload-tsnap-model.h"

/* The builds with small caps run only suite_caps, so the other suites and their helpers are unused there. */
#pragma clang diagnostic ignored "-Wunused-function"
/* The page of the fixture, line by line (without the prefix). A made-up page: HW_VER 2.4.0, 30.0 C and up. DT and GAP_MS are the counter's and are matched as `#`. */
static const char *const GOLDEN[] = {
    "READ ONLY EL=2 HZ=0X124F800 GAP=2 S",
    "KEY T0..T3=BLOCK R=RAW STATUS HEX C=TENTHS OF C INFERRED ?=NOT VALID X=NOT READ O=ODD",
    "NEXT T0",
    "T0 VER=0X20040000 CTL=0X20FFF9 SEN=0X1FFF",
    "T0 R0 0020012C 0020012F 00200132 00200135 00200138 0020013B 0020013E 00200141",
    "T0 R8 00200144 00200147 0020014A 0020014D 00200150 00000000 00000000 00000000",
    "T0 C 300 303 306 309 312 315 318 321 324 327 330 333 336 ? ? ? RDY=0X1 V=13",
    "NEXT T1",
    "T1 VER=0X20040000 CTL=0X203FF9 SEN=0X7FF",
    "T1 R0 00200133 00200136 00200139 0020013C 0020013F 00200142 00200145 00200148",
    "T1 R8 0020014B 0020014E 00200151 00000000 00000000 00000000 00000000 00000000",
    "T1 C 307 310 313 316 319 322 325 328 331 334 337 ? ? ? ? ? RDY=0X1 V=11",
    "NEXT T2",
    "T2 VER=0X20040000 CTL=0X203FF9 SEN=0X7FF",
    "T2 R0 0020013A 0020013D 00200140 00200143 00200146 00200149 0020014C 0020014F",
    "T2 R8 00200152 00200155 00200158 00000000 00000000 00000000 00000000 00000000",
    "T2 C 314 317 320 323 326 329 332 335 338 341 344 ? ? ? ? ? RDY=0X1 V=11",
    "NEXT T3",
    "T3 VER=0X20040000 CTL=0X23FFF9 SEN=0X7FFF",
    "T3 R0 00200141 00200144 00200147 0020014A 0020014D 00200150 00200153 00200156",
    "T3 R8 00200159 0020015C 0020015F 00200162 00200165 00200168 0020016B 00000000",
    "T3 C 321 324 327 330 333 336 339 342 345 348 351 354 357 360 363 ? RDY=0X1 V=15",
    "SUM1 V=50/64 MIN=300(T0.0) MAX=363(T3.14) CRIT=0 OUT=0 ODD=0",
    "NEXT S2 AFTER 2 S",
    "S2 T0 V=13 MIN=299 MAX=335 CHG=9 D=1 DT=# NEXT T1",
    "S2 T1 V=11 MIN=307 MAX=338 CHG=7 D=1 DT=# NEXT T2",
    "S2 T2 V=11 MIN=315 MAX=343 CHG=8 D=1 DT=# NEXT T3",
    "S2 T3 V=15 MIN=320 MAX=364 CHG=10 D=1 DT=# NEXT CONV T0",
    "CONV T0 NZ=13/16 LO=0X1B3416A HI=0X1B34176 UL=0X0 CR=0X0 NEXT CONV T1",
    "CONV T1 NZ=11/16 LO=0X1B3416A HI=0X1B34174 UL=0X0 CR=0X0 NEXT CONV T2",
    "CONV T2 NZ=11/16 LO=0X1B3416A HI=0X1B34174 UL=0X0 CR=0X0 NEXT CONV T3",
    "CONV T3 NZ=15/16 LO=0X1B3416A HI=0X1B34178 UL=0X0 CR=0X0",
    "SUM2 V=50/64 MIN=299(T0.0) MAX=364(T3.14) CHG=34/50 DMAX=1 CRIT=0 OUT=0 ODD=0",
    "END LOADS=220 FAULTS=0 SKIPS=0 GATED=0 CUTS=0 GAP_MS=# LINES=34",
};
#define GOLDEN_LINES (sizeof GOLDEN / sizeof GOLDEN[0])

/* A line with the counter's numbers (DT=, GAP_MS=) replaced by `#`; a `#` that is already there stays one. */
static void m_norm(const char *line, char *out)
{
    size_t o = 0;
    for (size_t i = 0; line[i] && o < 126; i++) {
        out[o++] = line[i];
        if ((i >= 2 && !strncmp(line + i - 2, "DT=", 3)) || (i >= 6 && !strncmp(line + i - 6, "GAP_MS=", 7))) {
            if (line[i + 1] >= '0' && line[i + 1] <= '9') {
                while (line[i + 1] >= '0' && line[i + 1] <= '9') i++;
                out[o++] = '#';
            }
        }
    }
    out[o] = 0;
}

static int m_norm_is(unsigned i, const char *tail)
{
    char got[128], want[128];
    if (i >= m_nlines) return 0;
    m_norm(m_text(i), got);
    m_norm(tail, want);
    return !strcmp(got, want);
}

/* ---- Event order ---- */
static int ev_line(unsigned *k, const char *prefix)
{
    char want[128];
    snprintf(want, sizeof want, "%s%s", PREFIX, prefix);
    if (*k >= m_nev || m_ev[*k].kind != 'P') return 0;
    return !strncmp(m_lines[m_ev[(*k)++].line], want, strlen(want));
}

static int ev_load(unsigned *k, unsigned win, uint32_t off)
{
    if (*k >= m_nev || m_ev[*k].kind != 'L') return 0;
    return m_ev[*k].win == win && m_ev[(*k)++].off == off;
}

static int ev_line_n(unsigned *k, const char *format, unsigned n)
{
    char text[64];
    snprintf(text, sizeof text, format, n);
    return ev_line(k, text);
}

static int suite_order(void)
{
    unsigned k = 0;
    m_fx_unit();
    RUN_CLEAN();
    CHECK(m_nev == m_nlines + m_nloads);
    CHECK(ev_line(&k, "READ ONLY EL=2") && ev_line(&k, "KEY "));
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        CHECK(ev_line_n(&k, "NEXT T%u", n));
        CHECK(ev_load(&k, M_SROT(n), 0x00) && ev_load(&k, M_SROT(n), 0x04));
        CHECK(ev_line_n(&k, "T%u VER=", n));                                       /* before the first load of the TM window */
        for (unsigned i = 0; i < 8; i++) CHECK(ev_load(&k, M_TM(n), 0xa0 + 4 * i));
        CHECK(ev_line_n(&k, "T%u R0 ", n));
        for (unsigned i = 8; i < 16; i++) CHECK(ev_load(&k, M_TM(n), 0xa0 + 4 * i));
        CHECK(ev_line_n(&k, "T%u R8 ", n));
        CHECK(ev_load(&k, M_TM(n), 0xe4));                                          /* TRDY, which Linux never reads for a v2 block, last in the block */
        CHECK(ev_line_n(&k, "T%u C ", n));
    }
    CHECK(ev_line(&k, "SUM1 ") && ev_line(&k, "NEXT S2 AFTER 2 S"));
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        CHECK(ev_load(&k, M_SROT(n), 0x04));
        for (unsigned i = 0; i < 16; i++) CHECK(ev_load(&k, M_TM(n), 0xa0 + 4 * i));
        CHECK(ev_load(&k, M_TM(n), 0xe4));
        CHECK(ev_line_n(&k, "S2 T%u ", n));
    }
    for (unsigned n = 0; n < M_BLOCKS; n++) {                                       /* the conversion pass after the second reading, a block at a time */
        for (unsigned i = 0; i < 16; i++) CHECK(ev_load(&k, M_SROT(n), 0x60 + 4 * i));
        CHECK(ev_load(&k, M_TM(n), 0x08) && ev_load(&k, M_TM(n), 0x14));
        CHECK(ev_line_n(&k, "CONV T%u ", n));
    }
    CHECK(ev_line(&k, "SUM2 ") && ev_line(&k, "END LOADS="));
    CHECK(k == m_nev);
    return 0;
}

static int suite_unit(void)
{
    struct m_world w;
    m_fx_unit();
    m_capture(&w);
    RUN_CLEAN();
    CHECK(m_nlines == GOLDEN_LINES && GOLDEN_LINES == PAGE_LINES);
    for (unsigned i = 0; i < GOLDEN_LINES; i++) CHECK(m_norm_is(i, GOLDEN[i]));
    CHECK(m_nloads == LOADS_MAX && m_nloads == 220);
    CHECK(m_sysreg_reads == 2);
    CHECK(m_dead_windows == 0 && m_aborted == 0);
    for (unsigned n = 0; n < M_BLOCKS; n++) CHECK(m_wloads[M_SROT(n)] == 19 && m_wloads[M_TM(n)] == 36);
    CHECK(m_field(m_text(m_nlines - 1), "GAP_MS") >= 2000 && m_field(m_text(m_nlines - 1), "GAP_MS") < 2100);
    m_check_values(&w);
    /* The loads are the model's own list and nothing else, each the number of times the page implies. */
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        unsigned count[2][M_WORDS] = {{0}};
        for (unsigned k = 0; k < m_nloads; k++) {
            if (m_load_win[k] == M_SROT(n)) count[0][m_load_off[k] / 4]++;
            if (m_load_win[k] == M_TM(n)) count[1][m_load_off[k] / 4]++;
        }
        CHECK(count[0][0] == 1 && count[0][1] == 2 && count[1][0xe4 / 4] == 2 && count[1][0x08 / 4] == 1 && count[1][0x14 / 4] == 1);
        for (unsigned i = 0; i < 16; i++) CHECK(count[0][0x60 / 4 + i] == 1 && count[1][0xa0 / 4 + i] == 2);
    }
    return 0;
}

/* ---- The status words ---- */
static const struct {
    uint32_t raw;
    const char *cell;
} CELLS[] = {
    {0x0020012c, "300"}, {0x00200fff, "-1"}, {0x00200000, "0"}, {0x00200001, "1"}, {0x002004b0, "1200"}, {0x002004b1, "O"}, {0x00200e70, "-400"}, {0x00200e6f, "O"},
    {0x00200800, "O"}, {0x002007ff, "O"}, {0x0000012c, "?"}, {0x00000000, "?"}, {0x00000fff, "?"}, {0x0060012c, "O"}, {0x8020012c, "O"}, {0xffffffff, "O"},
    {0x0028012c, "300"}, {0x0030012c, "300"}, {0x0010012c, "?"}, {0x0007012c, "?"}, {0x00e0012c, "O"}, {0x0020b12c, "300"}, {0x00a0012c, "O"}, {0x04200000, "O"},
};

static void m_fx_words(const uint32_t w[M_BLOCKS][16])
{
    m_fx_unit();
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        m_set(M_SROT(n), 0x04, (1u << 21) | (0xffffu << 3) | 1u);
        for (unsigned i = 0; i < 16; i++) {
            m_set(M_TM(n), 0xa0 + 4 * i, w[n][i]);
            m_s2_set[M_TM(n)][(0xa0 + 4 * i) / 4] = 0;
        }
    }
}

static int suite_cells(void)
{
    uint32_t w[M_BLOCKS][16];
    struct m_world world;
    static const uint32_t FLAGS[] = {1u << 16, 1u << 17, 1u << 18, 1u << 19, 1u << 20, 3u << 19, 0x1fu << 16};
    /* Every kind of word, in every slot of a block, in all four blocks. */
    for (unsigned shift = 0; shift < sizeof CELLS / sizeof CELLS[0]; shift++) {
        for (unsigned n = 0; n < M_BLOCKS; n++)
            for (unsigned i = 0; i < 16; i++) w[n][i] = CELLS[(shift + n * 5 + i) % (sizeof CELLS / sizeof CELLS[0])].raw;
        m_fx_words(w);
        m_capture(&world);
        RUN_CLEAN();
        for (unsigned n = 0; n < M_BLOCKS; n++) {
            char head[16];
            int at;
            snprintf(head, sizeof head, "T%u C", n);
            at = m_find(head, 0);
            CHECK(at >= 0);
            for (unsigned i = 0; i < 16; i++) {
                char cell[16];
                m_cell(w[n][i], cell);
                for (unsigned c = 0; c < sizeof CELLS / sizeof CELLS[0]; c++)
                    if (CELLS[c].raw == w[n][i]) CHECK(!strcmp(CELLS[c].cell, cell));
            }
        }
        m_check_values(&world);
    }
    /* The critical flags are counted for any word that is not odd, whether or not it is VALID; MIN, LOWER and UPPER alone are not critical. */
    for (unsigned f = 0; f < sizeof FLAGS / sizeof FLAGS[0]; f++) {
        struct m_sum s;
        memset(w, 0, sizeof w);
        w[2][5] = 0x0020012c | FLAGS[f];
        w[3][0] = 0x0000012c | FLAGS[f];
        w[1][1] = 0x8020012c | FLAGS[f];
        m_fx_words(w);
        m_capture(&world);
        RUN_CLEAN();
        m_oracle(world.w1, &s);
        CHECK(s.crit == (FLAGS[f] >> 19 & 3 ? 2u : 0u));
        CHECK(s.odd == 1 && s.valid == 1);
        m_check_values(&world);
    }
    /* Ties: the first sensor in block order wins both the minimum and the maximum. */
    memset(w, 0, sizeof w);
    for (unsigned n = 0; n < M_BLOCKS; n++)
        for (unsigned i = 0; i < 16; i++) w[n][i] = 0x00200190;
    m_fx_words(w);
    m_capture(&world);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("SUM1", 0), "SUM1 V=64/64 MIN=400(T0.0) MAX=400(T0.0) CRIT=0 OUT=0 ODD=0"));
    /* No valid sensor at all: NA, and the second reading has nothing to compare. */
    memset(w, 0, sizeof w);
    m_fx_words(w);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("SUM1", 0), "SUM1 V=0/64 MIN=NA MAX=NA CRIT=0 OUT=0 ODD=0"));
    CHECK(m_line_is((unsigned)m_find("SUM2", 0), "SUM2 V=0/64 MIN=NA MAX=NA CHG=0/0 DMAX=0 CRIT=0 OUT=0 ODD=0"));
    return 0;
}

static uint32_t m_rng = 0x2545f491u;
static uint32_t m_rand(void)
{
    m_rng ^= m_rng << 13;
    m_rng ^= m_rng >> 17;
    m_rng ^= m_rng << 5;
    return m_rng;
}

static uint32_t m_word(void)
{
    uint32_t kind = m_rand() % 20, flags = (m_rand() & 0x1f) << 16;
    if (m_rand() % 4) flags = 0;
    if (kind < 8) return (1u << 21) | ((uint32_t)((int)(m_rand() % 1601) - 400) & 0xfff) | flags;
    if (kind < 11) return (1u << 21) | (m_rand() & 0xfff) | flags;
    if (kind < 14) return (m_rand() & 0xfff) | flags;
    if (kind < 16) return (m_rand() & 0xffc00000u) | (m_rand() & 0x3fffff);
    if (kind == 16) return 0xffffffffu;
    if (kind == 17) return 0;
    return m_rand();
}

/* Random worlds, healthy blocks: the whole value-dependent page against the oracle, the second reading drifting by random amounts. */
static int suite_random(void)
{
    for (unsigned round = 0; round < 300; round++) {
        uint32_t w[M_BLOCKS][16];
        struct m_world world;
        for (unsigned n = 0; n < M_BLOCKS; n++)
            for (unsigned i = 0; i < 16; i++) w[n][i] = m_word();
        m_fx_words(w);
        for (unsigned n = 0; n < M_BLOCKS; n++)
            for (unsigned i = 0; i < 16; i++)
                if (m_rand() % 3) m_set2(M_TM(n), 0xa0 + 4 * i, (m_rand() % 2 && !(w[n][i] >> 22)) ? ((w[n][i] & ~0xfffu) | (((w[n][i] & 0xfff) + m_rand() % 7 - 3) & 0xfff)) : m_word());
        m_capture(&world);
        RUN_CLEAN();
        m_check_values(&world);
    }
    return 0;
}

/* ---- Gates ---- */
static void m_other_blocks_unchanged(unsigned bad)
{
    /* The identity, raw and temperature lines of the three other blocks are the golden ones. */
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        char head[16];
        int at;
        if (n == bad) continue;
        snprintf(head, sizeof head, "T%u VER=", n);
        at = m_find(head, 0);
        CHECK(at >= 0);
        for (unsigned j = 0; at >= 0 && j < 4; j++) CHECK(m_norm_is((unsigned)at + j, GOLDEN[3 + n * 5 + j]));
    }
}

static int suite_gate(void)
{
    /* What block 1 does when its HW_VER or CTRL reads as given: the identity line, and how many words of its SROT and TM windows are read in the whole run. */
    static const struct {
        uint32_t ver, ctl;
        const char *identity;
        unsigned srot, tm;
    } CASES[] = {
        {0x00000000, 0x203ff9, "T1 VER=0X0 GATED", 1, 0},
        {0xffffffff, 0x203ff9, "T1 VER=0XFFFFFFFF GATED", 1, 0},
        {0x20040000, 0x203ff8, "T1 VER=0X20040000 CTL=0X203FF8 SEN=0X7FF OFF", 2, 0},
        {0x20040000, 0x203ffb, "T1 VER=0X20040000 CTL=0X203FFB SEN=0X7FF OFF", 2, 0},
        {0x20040000, 0x203ffa, "T1 VER=0X20040000 CTL=0X203FFA SEN=0X7FF OFF", 2, 0},
        {0x20040000, 0x203ff0, "T1 VER=0X20040000 CTL=0X203FF0 SEN=0X7FE OFF", 2, 0},
        {0x20040000, 0x00000000, "T1 VER=0X20040000 CTL=0X0 SEN=0X0 OFF", 2, 0},
        {0x20040000, 0xffffffff, "T1 VER=0X20040000 CTL=0XFFFFFFFF SEN=0XFFFF OFF", 2, 0},
        {0x00000001, 0x203ff9, "T1 VER=0X1 CTL=0X203FF9 SEN=0X7FF", 19, 36},      /* a different, plausible HW_VER is no gate */
    };
    for (unsigned c = 0; c < sizeof CASES / sizeof CASES[0]; c++) {
        int at;
        m_fx_unit();
        m_set(M_SROT(1), 0x00, CASES[c].ver);
        m_set(M_SROT(1), 0x04, CASES[c].ctl);
        RUN_CLEAN();
        at = m_find("T1 VER=", 0);
        CHECK(at >= 0 && m_line_is((unsigned)at, CASES[c].identity));
        CHECK(m_wloads[M_SROT(1)] == CASES[c].srot && m_wloads[M_TM(1)] == CASES[c].tm);
        if (CASES[c].tm) {
            CHECK(m_nlines == PAGE_LINES && m_field(m_text(m_nlines - 1), "GATED") == 0);
            continue;
        }
        CHECK(m_find("T1 R0", 0) < 0 && m_find("T1 R8", 0) < 0 && m_find("T1 C", 0) < 0 && m_find("S2 T1", 0) < 0 && m_find("CONV T1", 0) < 0);
        CHECK(m_nlines == PAGE_LINES - 5);                /* its R0, R8, C, S2 and CONV lines */
        CHECK(m_find("NEXT T1", 0) >= 0 && m_find("NEXT T2", 0) > m_find("NEXT T1", 0));
        CHECK(m_field(m_text(m_nlines - 1), "GATED") == 1);
        /* The chains of the second reading and of the conversion pass skip the block. */
        CHECK(m_find("S2 T0", 0) >= 0 && strstr(m_text((unsigned)m_find("S2 T0", 0)), " NEXT T2") != NULL);
        CHECK(m_find("CONV T0", 0) >= 0 && m_announces(m_text((unsigned)m_find("CONV T0", 0)), "NEXT CONV T") == 2);
        CHECK(m_find("CONV T2", 0) >= 0 && m_announces(m_text((unsigned)m_find("CONV T2", 0)), "NEXT CONV T") == 3);
        m_other_blocks_unchanged(1);
    }
    /* HW_VER aborting: the window is dead, the TM window is never touched, the others go on. */
    m_fx_unit();
    m_abort_windows = 1u << M_SROT(1);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("T1 VER=", 0), "T1 VER=FAULT:6 GATED"));
    CHECK(m_wloads[M_SROT(1)] == 1 && m_wloads[M_TM(1)] == 0 && m_aborted == 1);
    CHECK(m_field(m_text(m_nlines - 1), "GATED") == 1 && m_field(m_text(m_nlines - 1), "FAULTS") == 1);
    m_other_blocks_unchanged(1);
    /* CTRL aborting (the load after block 1's HW_VER, which is load 20 of the clean run): CTLERR and not OFF, the TM window untouched, the SROT window dead, no conversion words. */
    m_fx_unit();
    m_abort_nth = 20;
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("T1 VER=", 0), "T1 VER=0X20040000 CTL=FAULT:6 CTLERR"));
    CHECK(m_wloads[M_TM(1)] == 0 && m_find("T1 R0", 0) < 0 && m_wloads[M_SROT(1)] == 2 && m_find("CONV T1", 0) < 0);
    /* A CTRL that reads, says EN set and SW_RST clear, and has CODE_OR_TEMP clear: the words are not temperatures (INFERRED: ADC codes). CODE on the identity line, every VALID cell O,
     * nothing of the block in SUM1 or SUM2 but the count of odd words, the raw words and the loads as ever; the second reading says CODE as well. */
    m_fx_unit();
    m_set(M_SROT(1), 0x04, (0x7ffu << 3) | 1u);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("T1 VER=", 0), "T1 VER=0X20040000 CTL=0X3FF9 SEN=0X7FF CODE"));
    CHECK(m_line_is((unsigned)m_find("T1 C", 0), "T1 C O O O O O O O O O O O ? ? ? ? ? RDY=0X1 V=0"));
    CHECK(m_line_is((unsigned)m_find("T1 R0", 0), GOLDEN[9]) && m_line_is((unsigned)m_find("T1 R8", 0), GOLDEN[10]));
    CHECK(m_line_is((unsigned)m_find("SUM1", 0), "SUM1 V=39/64 MIN=300(T0.0) MAX=363(T3.14) CRIT=0 OUT=0 ODD=11"));
    CHECK(m_norm_is((unsigned)m_find("S2 T1", 0), "S2 T1 V=0 MIN=NA MAX=NA CHG=0 D=0 DT=# CODE NEXT T2"));
    CHECK(m_line_is((unsigned)m_find("SUM2", 0), "SUM2 V=39/64 MIN=299(T0.0) MAX=364(T3.14) CHG=27/39 DMAX=1 CRIT=0 OUT=0 ODD=11"));
    CHECK(m_wloads[M_SROT(1)] == 19 && m_wloads[M_TM(1)] == 36 && m_nlines == PAGE_LINES);
    /* A critical flag in a block that says CODE is not counted: the words are untrusted. */
    m_fx_unit();
    m_set(M_SROT(1), 0x04, (0x7ffu << 3) | 1u);
    m_set(M_TM(1), 0xa0, 0x00300000u | 0x12c);
    RUN_CLEAN();
    CHECK(m_field(m_text((unsigned)m_find("SUM1", 0)), "CRIT") == 0);
    /* A block that is enabled for no sensor at all is running: SEN=0X0 and its words are read. */
    m_fx_unit();
    m_set(M_SROT(2), 0x04, (1u << 21) | 1u);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("T2 VER=", 0), "T2 VER=0X20040000 CTL=0X200001 SEN=0X0") && m_wloads[M_TM(2)] == 36);
    /* All four blocks gated: nothing else is read, the closing lines say so, and there is no conversion pass. */
    m_fx_unit();
    for (unsigned n = 0; n < M_BLOCKS; n++) m_set(M_SROT(n), 0x00, 0);
    RUN_CLEAN();
    CHECK(m_nloads == 4 && m_field(m_text(m_nlines - 1), "GATED") == 4);
    CHECK(m_line_is((unsigned)m_find("SUM1", 0), "SUM1 V=0/64 MIN=NA MAX=NA CRIT=0 OUT=0 ODD=0"));
    CHECK(m_find("S2 SKIPPED NO_BLOCK", 0) >= 0 && m_find("NEXT S2", 0) < 0 && m_counter_reads == 1);
    CHECK(m_find("CONV", 0) < 0 && m_find("NEXT CONV", 0) < 0);
    return 0;
}

/* ---- Faults ---- */
static int suite_faults(void)
{
    unsigned clean;
    m_fx_unit();
    RUN_CLEAN();
    clean = m_nloads;
    CHECK(clean == LOADS_MAX);
    /* An abort at every load in turn. */
    for (unsigned k = 0; k < clean; k++) {
        m_fx_unit();
        m_abort_nth = (int)k;
        RUN_CLEAN();
        CHECK(m_aborted == 1);
        CHECK(m_field(m_text(m_nlines - 1), "FAULTS") == 1);
        CHECK(m_nloads <= clean);
        CHECK(m_nlines <= PAGE_LINES);
        if (k < 19 * 4) CHECK(m_find("NEXT T3", 0) >= 0);           /* no abort in the first reading stops the next block */
    }
    /* The SROT windows aborting, the TM windows aborting, everything aborting. */
    m_fx_unit();
    m_abort_windows = 0x0f;
    RUN_CLEAN();
    CHECK(m_nloads == 4 && m_aborted == 4 && m_field(m_text(m_nlines - 1), "GATED") == 4);
    m_fx_unit();
    m_abort_windows = 0xf0;
    RUN_CLEAN();
    /* Each block: HW_VER and CTRL read, the identity line printed, the first status word aborts, R0 says so and nothing else of the window is read or printed. No block can be read again, the
     * conversion pass reads the SROT words and skips the two TM words. */
    CHECK(m_aborted == 4 && m_wloads[M_TM(0)] == 1 && m_nloads == 4 * 3 + 4 * 16);
    CHECK(m_line_is((unsigned)m_find("T0 VER=", 0), "T0 VER=0X20040000 CTL=0X20FFF9 SEN=0X1FFF"));
    CHECK(m_line_is((unsigned)m_find("T0 R0", 0), "T0 R0 FAULT:6 SKIP SKIP SKIP SKIP SKIP SKIP SKIP"));
    CHECK(m_find("T0 R8", 0) < 0 && m_find("T0 C", 0) < 0 && m_find("S2 SKIPPED NO_BLOCK", 0) >= 0 && m_find("NEXT S2", 0) < 0);
    CHECK(m_find("S2 SKIPPED NO_BLOCK", 0) + 1 == m_find("NEXT CONV T0", 0));
    CHECK(m_line_is((unsigned)m_find("CONV T0", 0), "CONV T0 NZ=13/16 LO=0X1B3416A HI=0X1B34176 UL=SKIP CR=SKIP NEXT CONV T1"));
    CHECK(m_line_is((unsigned)m_find("CONV T3", 0), "CONV T3 NZ=15/16 LO=0X1B3416A HI=0X1B34178 UL=SKIP CR=SKIP"));
    CHECK(m_field(m_text(m_nlines - 1), "FAULTS") == 4 && m_field(m_text(m_nlines - 1), "SKIPS") == 4 * 7 + 4 * 2);
    m_fx_unit();
    m_abort_windows = 0xff;
    RUN_CLEAN();
    CHECK(m_nloads == 4 && m_aborted == 4);
    CHECK(m_find("CONV", 0) < 0 && m_find("NEXT CONV", 0) < 0);
    CHECK(m_line_is((unsigned)m_find("SUM2", 0), "SUM2 V=0/64 MIN=NA MAX=NA CHG=0/0 DMAX=0 CRIT=0 OUT=0 ODD=0"));
    /* A fault in the middle of a status line: FAULT:6 where it happened, SKIP after it, X in the cells, the other lines and blocks intact; TRDY, last in the block, is not read. */
    m_fx_unit();
    m_abort_nth = 2 + 5;                                              /* block 0's sixth status word */
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("T0 R0", 0), "T0 R0 0020012C 0020012F 00200132 00200135 00200138 FAULT:6 SKIP SKIP"));
    CHECK(m_line_is((unsigned)m_find("T0 R8", 0), "T0 R8 SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP"));
    CHECK(m_line_is((unsigned)m_find("T0 C", 0), "T0 C 300 303 306 309 312 X X X X X X X X X X X RDY=SKIP V=5"));
    CHECK(m_find("S2 T0", 0) < 0 && m_find("S2 T1", 0) >= 0);
    CHECK(m_wloads[M_TM(0)] == 6);                                  /* six status words, the sixth of which aborted: nothing more is loaded from the window */
    CHECK(m_field(m_text(m_nlines - 1), "FAULTS") == 1 && m_field(m_text(m_nlines - 1), "SKIPS") == 10 + 1 + 2);   /* ids 6 to 15, TRDY, and UL and CRIT */
    CHECK(m_line_is((unsigned)m_find("CONV T0", 0), "CONV T0 NZ=13/16 LO=0X1B3416A HI=0X1B34176 UL=SKIP CR=SKIP NEXT CONV T1"));
    CHECK(m_line_is((unsigned)m_find("CONV T1", 0), "CONV T1 NZ=11/16 LO=0X1B3416A HI=0X1B34174 UL=0X0 CR=0X0 NEXT CONV T2"));
    /* The first status word aborts: the window is dead with nothing read, R0 says so and the lines of the block end there. */
    m_fx_unit();
    m_abort_nth = 2;
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("T0 R0", 0), "T0 R0 FAULT:6 SKIP SKIP SKIP SKIP SKIP SKIP SKIP"));
    CHECK(m_find("T0 R8", 0) < 0 && m_find("T0 C", 0) < 0 && m_wloads[M_TM(0)] == 1 && m_find("T1 C", 0) >= 0);
    /* TRDY aborts after sixteen good words: the temperatures are all on the page, RDY says FAULT:6, the window is dead for the second reading and the conversion pass's TM words. */
    m_fx_unit();
    m_abort_nth = 18;
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("T0 C", 0), "T0 C 300 303 306 309 312 315 318 321 324 327 330 333 336 ? ? ? RDY=FAULT:6 V=13"));
    CHECK(m_line_is((unsigned)m_find("SUM1", 0), "SUM1 V=50/64 MIN=300(T0.0) MAX=363(T3.14) CRIT=0 OUT=0 ODD=0"));
    CHECK(m_find("S2 T0", 0) < 0 && m_find("S2 T1", 0) >= 0 && m_wloads[M_TM(0)] == 17);
    CHECK(m_line_is((unsigned)m_find("SUM2", 0), "SUM2 V=37/64 MIN=307(T1.0) MAX=364(T3.14) CHG=25/37 DMAX=1 CRIT=0 OUT=0 ODD=0"));
    CHECK(m_line_is((unsigned)m_find("CONV T0", 0), "CONV T0 NZ=13/16 LO=0X1B3416A HI=0X1B34176 UL=SKIP CR=SKIP NEXT CONV T1"));
    /* An abort storm from every load on: still every line, never a load of a window that aborted (the model checks), the closing lines in place. */
    for (unsigned k = 0; k < clean; k += 7) {
        m_fx_unit();
        m_abort_from_nth = (int)k;
        RUN_CLEAN();
        CHECK(m_aborted >= 1 && m_find("SUM1", 0) >= 0 && m_find("SUM2", 0) >= 0);
    }
    return 0;
}

/* ---- Hangs ---- */
static int suite_hang(void)
{
    static char clean_lines[M_EVENTS][128];
    unsigned clean_n, clean_loads, before[256];
    m_fx_unit();
    RUN_CLEAN();
    clean_n = m_nlines;
    clean_loads = m_nloads;
    CHECK(clean_loads <= 256);
    for (unsigned i = 0; i < clean_n; i++) memcpy(clean_lines[i], m_lines[i], 128);
    for (unsigned k = 0; k < clean_loads; k++) before[k] = m_lines_before_load[k];
    for (unsigned k = 0; k < clean_loads; k++) {
        m_fx_unit();
        m_hang_nth = (int)k;
        m_run();
        CHECK(m_hung);
        CHECK(m_nlines == before[k]);
        for (unsigned i = 0; i < m_nlines; i++) CHECK(!strcmp(m_lines[i], clean_lines[i]));
        CHECK(m_nloads == k + 1);
    }
    /* The last line names what hung: the NEXT line of its block or pass, or the line that the loads before it filled. A block's TM window is named by its identity line (the sixteen status words),
     * by R0 (the second eight) and by R8 (TRDY, the offset with no Linux precedent, last); the second reading by the previous S2 line, which names the next block, and the conversion pass by
     * the last S2 line or the previous CONV line. */
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        char next[16], ident[16], raw0[16], raw8[16];
        unsigned first = 19 * n;
        snprintf(next, sizeof next, "NEXT T%u", n);
        snprintf(ident, sizeof ident, "T%u VER=", n);
        snprintf(raw0, sizeof raw0, "T%u R0 ", n);
        snprintf(raw8, sizeof raw8, "T%u R8 ", n);
        for (unsigned k = first; k < first + 2; k++) CHECK(!strcmp(m_lines[before[k] - 1] + strlen(PREFIX), next));
        for (unsigned k = first + 2; k < first + 10; k++) CHECK(!strncmp(m_lines[before[k] - 1] + strlen(PREFIX), ident, strlen(ident)));
        for (unsigned k = first + 10; k < first + 18; k++) CHECK(!strncmp(m_lines[before[k] - 1] + strlen(PREFIX), raw0, strlen(raw0)));
        CHECK(!strncmp(m_lines[before[first + 18] - 1] + strlen(PREFIX), raw8, strlen(raw8)));
    }
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        char want[16];
        snprintf(want, sizeof want, "S2 T%u ", n - 1);
        for (unsigned k = 76 + 18 * n; k < 76 + 18 * (n + 1); k++) {
            if (!n) CHECK(!strcmp(m_lines[before[k] - 1] + strlen(PREFIX), "NEXT S2 AFTER 2 S"));
            else CHECK(!strncmp(m_lines[before[k] - 1] + strlen(PREFIX), want, strlen(want)));
        }
    }
    CHECK(!strncmp(m_lines[before[148] - 1] + strlen(PREFIX), "S2 T3 ", 6) && m_announces(m_lines[before[148] - 1] + strlen(PREFIX), "NEXT CONV T") == 0);
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        char want[16];
        snprintf(want, sizeof want, "CONV T%u ", n - 1);
        for (unsigned k = 148 + 18 * n; k < 148 + 18 * (n + 1); k++) {
            if (!n) CHECK(!strncmp(m_lines[before[k] - 1] + strlen(PREFIX), "S2 T3 ", 6));
            else CHECK(!strncmp(m_lines[before[k] - 1] + strlen(PREFIX), want, strlen(want)) && m_announces(m_lines[before[k] - 1] + strlen(PREFIX), "NEXT CONV T") == (int)n);
        }
    }
    return 0;
}

/* ---- The second reading ---- */
static unsigned m_nth_load_of(unsigned win, uint32_t off, unsigned which)
{
    for (unsigned k = 0; k < m_nloads; k++)
        if (m_load_win[k] == win && m_load_off[k] == off && which-- == 0) return k;
    return 0xffffffffu;
}

static int suite_drift(void)
{
    struct m_world w;
    unsigned second_ctl, word2, rdy2;
    /* Nothing moves. */
    m_fx_unit();
    for (unsigned n = 0; n < M_BLOCKS; n++)
        for (unsigned i = 0; i < 16; i++) m_set2(M_TM(n), 0xa0 + 4 * i, m_reg[M_TM(n)][(0xa0 + 4 * i) / 4]);
    m_capture(&w);
    RUN_CLEAN();
    m_check_values(&w);
    CHECK(m_line_is((unsigned)m_find("SUM2", 0), "SUM2 V=50/64 MIN=300(T0.0) MAX=363(T3.14) CHG=0/50 DMAX=0 CRIT=0 OUT=0 ODD=0"));
    /* Everything moves by 10 (1.0 C). */
    m_fx_unit();
    for (unsigned n = 0; n < M_BLOCKS; n++)
        for (unsigned i = 0; i < M_COUNT[n]; i++) m_set2(M_TM(n), 0xa0 + 4 * i, m_status(m_tenths(n, i) + 10));
    m_capture(&w);
    RUN_CLEAN();
    m_check_values(&w);
    CHECK(m_line_is((unsigned)m_find("SUM2", 0), "SUM2 V=50/64 MIN=310(T0.0) MAX=373(T3.14) CHG=50/50 DMAX=10 CRIT=0 OUT=0 ODD=0"));
    /* A sensor goes invalid, one goes odd, one jumps by 50 C, one leaves the plausible window. */
    m_fx_unit();
    m_set2(M_TM(1), 0xa0 + 4 * 2, 0x0000012c);
    m_set2(M_TM(2), 0xa0 + 4 * 4, 0xffffffffu);
    m_set2(M_TM(3), 0xa0 + 4 * 6, m_status(m_tenths(3, 6) + 500));
    m_set2(M_TM(0), 0xa0 + 4 * 9, m_status(1300));
    m_capture(&w);
    RUN_CLEAN();
    m_check_values(&w);
    CHECK(m_field(m_text((unsigned)m_find("SUM2", 0)), "ODD") == 1 && m_field(m_text((unsigned)m_find("SUM2", 0)), "OUT") == 1);
    CHECK(m_field(m_text((unsigned)m_find("SUM2", 0)), "DMAX") == 500);
    /* A block that goes OFF during the gap (CTRL changes): its S2 line says OFF and none of its TM words is read again, nor are its conversion words; the chains name the block after it. */
    m_fx_unit();
    m_set2(M_SROT(1), 0x04, 0x203ff8);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("S2 T1", 0), "S2 T1 OFF NEXT T2"));
    CHECK(m_wloads[M_TM(1)] == 36 - 19 && m_wloads[M_SROT(1)] == 3);
    CHECK(m_field(m_text((unsigned)m_find("SUM2", 0)), "V") == 39);
    CHECK(m_find("CONV T1", 0) < 0 && m_announces(m_text((unsigned)m_find("CONV T0", 0)), "NEXT CONV T") == 2);
    /* A block whose CTRL no longer says CODE_OR_TEMP in the second reading: its S2 line says CODE and has no value, the block is still read by the conversion pass. */
    m_fx_unit();
    m_set2(M_SROT(1), 0x04, (0x7ffu << 3) | 1u);
    RUN_CLEAN();
    CHECK(m_norm_is((unsigned)m_find("S2 T1", 0), "S2 T1 V=0 MIN=NA MAX=NA CHG=0 D=0 DT=# CODE NEXT T2"));
    CHECK(m_find("CONV T1", 0) >= 0 && m_field(m_text((unsigned)m_find("SUM2", 0)), "V") == 39 && m_field(m_text((unsigned)m_find("SUM2", 0)), "ODD") == 11);
    /* The CTRL read of the second reading aborts: CTLERR, the block is not read again by either pass. */
    m_fx_unit();
    RUN_CLEAN();
    second_ctl = m_nth_load_of(M_SROT(2), 0x04, 1);
    CHECK(second_ctl != 0xffffffffu);
    m_fx_unit();
    m_abort_nth = (int)second_ctl;
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("S2 T2", 0), "S2 T2 CTL=FAULT:6 CTLERR NEXT T3"));
    CHECK(m_wloads[M_TM(2)] == 36 - 19 && m_find("S2 T3", 0) >= 0 && m_find("CONV T2", 0) < 0);
    CHECK(m_announces(m_text((unsigned)m_find("CONV T1", 0)), "NEXT CONV T") == 3);
    /* The TM window aborts at its first load of the second reading (the first status word), and then in the middle of the words (the fourth). */
    m_fx_unit();
    RUN_CLEAN();
    word2 = m_nth_load_of(M_TM(0), 0xa0, 1);
    CHECK(word2 != 0xffffffffu);
    m_fx_unit();
    m_abort_nth = (int)word2;
    RUN_CLEAN();
    CHECK(m_norm_is((unsigned)m_find("S2 T0", 0), "S2 T0 V=0 MIN=NA MAX=NA CHG=0 D=0 DT=# FAULT:6 NEXT T1"));
    CHECK(m_line_is((unsigned)m_find("SUM2", 0), "SUM2 V=37/64 MIN=307(T1.0) MAX=364(T3.14) CHG=25/37 DMAX=1 CRIT=0 OUT=0 ODD=0"));
    CHECK(m_wloads[M_TM(0)] == 17 + 1);
    m_fx_unit();
    m_abort_nth = (int)word2 + 3;
    RUN_CLEAN();
    CHECK(m_norm_is((unsigned)m_find("S2 T0", 0), "S2 T0 V=3 MIN=299 MAX=307 CHG=2 D=1 DT=# FAULT:6 NEXT T1"));
    /* TRDY, the last load of the second reading of a block, aborts: the sixteen words are all in the line and in SUM2, the line shows the fault, the conversion pass skips the TM words. */
    m_fx_unit();
    RUN_CLEAN();
    rdy2 = m_nth_load_of(M_TM(0), 0xe4, 1);
    CHECK(rdy2 != 0xffffffffu);
    m_fx_unit();
    m_abort_nth = (int)rdy2;
    RUN_CLEAN();
    CHECK(m_norm_is((unsigned)m_find("S2 T0", 0), "S2 T0 V=13 MIN=299 MAX=335 CHG=9 D=1 DT=# FAULT:6 NEXT T1"));
    CHECK(m_line_is((unsigned)m_find("SUM2", 0), "SUM2 V=50/64 MIN=299(T0.0) MAX=364(T3.14) CHG=34/50 DMAX=1 CRIT=0 OUT=0 ODD=0"));
    CHECK(m_wloads[M_TM(0)] == 36 - 2);
    CHECK(m_line_is((unsigned)m_find("CONV T0", 0), "CONV T0 NZ=13/16 LO=0X1B3416A HI=0X1B34176 UL=SKIP CR=SKIP NEXT CONV T1"));
    return 0;
}

/* ---- The counter, the frequency, the EL ---- */
static int suite_counter(void)
{
    /* Running. */
    m_fx_unit();
    RUN_CLEAN();
    CHECK(m_field(m_text(m_nlines - 1), "GAP_MS") >= 2000);
    /* Stuck: the wait ends after STUCK_READS reads and the second reading is skipped (NO_COUNTER, never SPIN: the counter never moved); the conversion pass and the page still end. */
    m_fx_unit();
    m_step = 0;
    RUN_CLEAN();
    CHECK(m_find("NEXT S2 AFTER 2 S", 0) >= 0 && m_find("S2 SKIPPED NO_COUNTER", 0) > m_find("NEXT S2 AFTER 2 S", 0) && m_find("S2 T0", 0) < 0 && m_find("S2 SKIPPED SPIN", 0) < 0);
    CHECK(m_counter_reads <= STUCK_READS + 16 && m_field(m_text(m_nlines - 1), "GAP_MS") == 0 && m_nloads == LOADS_MAX - 4 * LOADS_S2_BLOCK);
    CHECK(m_line_is((unsigned)m_find("SUM2", 0), "SUM2 V=0/64 MIN=NA MAX=NA CHG=0/0 DMAX=0 CRIT=0 OUT=0 ODD=0"));
    CHECK(m_find("NEXT CONV T0", 0) == m_find("S2 SKIPPED NO_COUNTER", 0) + 1 && m_find("CONV T3", 0) >= 0);
    /* A counter that moves for a while and then stands still is stuck too, not slow. */
    m_fx_unit();
    m_freeze_after = 10;
    RUN_CLEAN();
    CHECK(m_find("S2 SKIPPED NO_COUNTER", 0) > m_find("NEXT S2 AFTER 2 S", 0) && m_find("S2 SKIPPED SPIN", 0) < 0 && m_find("S2 T0", 0) < 0);
    CHECK(m_counter_reads <= 10 + STUCK_READS + 16 && m_field(m_text(m_nlines - 1), "GAP_MS") == 0);
    /* Absent: no NEXT line, no wait. */
    m_fx_unit();
    m_no_counter = 1;
    RUN_CLEAN();
    CHECK(m_find("NEXT S2", 0) < 0 && m_find("S2 SKIPPED NO_COUNTER", 0) >= 0 && m_counter_reads == 0 && m_field(m_text(m_nlines - 1), "GAP_MS") == 0);
    CHECK(m_find("S2 T0", 0) < 0 && m_nloads == LOADS_MAX - 4 * LOADS_S2_BLOCK);
    /* Running backwards. */
    m_fx_unit();
    m_backwards = 1;
    RUN_CLEAN();
    CHECK(m_find("S2 SKIPPED NO_COUNTER", 0) >= 0 && m_find("S2 T0", 0) < 0 && m_field(m_text(m_nlines - 1), "GAP_MS") == 0);
    /* The frequency: a value outside 1 MHz to 1 GHz is not believed. */
    {
        static const struct {
            uint64_t hz;
            const char *header;
        } HZ[] = {
            {19200000, "READ ONLY EL=2 HZ=0X124F800 GAP=2 S"}, {1000000, "READ ONLY EL=2 HZ=0XF4240 GAP=2 S"}, {1000000000, "READ ONLY EL=2 HZ=0X3B9ACA00 GAP=2 S"},
            {999999, "READ ONLY EL=2 HZ=0X124F800 DEFAULT GAP=2 S"}, {1000000001, "READ ONLY EL=2 HZ=0X124F800 DEFAULT GAP=2 S"},
            {0, "READ ONLY EL=2 HZ=0X124F800 DEFAULT GAP=2 S"}, {UINT64_C(0x100000000) + 19200000, "READ ONLY EL=2 HZ=0X124F800 DEFAULT GAP=2 S"},
        };
        for (unsigned i = 0; i < sizeof HZ / sizeof HZ[0]; i++) {
            m_fx_unit();
            m_cntfrq = HZ[i].hz;
            m_no_counter = 1;
            RUN_CLEAN();
            CHECK(m_line_is(0, HZ[i].header));
        }
    }
    return 0;
}

static int suite_el(void)
{
    for (unsigned el = 0; el < 4; el++) {
        m_fx_unit();
        m_el = el;
        m_run();
        if (el == 2) {
            CHECK(m_nlines == PAGE_LINES && m_nloads == LOADS_MAX && m_sysreg_reads == 2);
        } else {
            CHECK(m_nlines == 1 && m_line_is(0, "SKIPPED_NOT_AT_EL2") && m_nloads == 0 && m_ret == 0 && m_counter_reads == 0 && m_sysreg_reads == 1);
        }
    }
    m_fx_unit();
    m_no_load32 = 1;
    m_run();
    CHECK(m_nlines == 1 && m_line_is(0, "REFUSED_NO_LOAD32") && m_ret == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nloads == 0);
    m_fx_unit();
    m_bad_args = 1;
    m_run();
    CHECK(m_nlines == 0 && m_ret == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nloads == 0 && m_sysreg_reads == 0);
    return 0;
}

/* ---- Budgets ---- */
static int suite_budget(void)
{
    uint32_t w[M_BLOCKS][16];
    /* The widest values that a normal page has: every cell three digits. Nothing is cut and the page is as long as the nominal one. */
    for (unsigned n = 0; n < M_BLOCKS; n++)
        for (unsigned i = 0; i < 16; i++) w[n][i] = 0x00200000u | (900 + n * 16 + i);
    m_fx_words(w);
    RUN_CLEAN();
    CHECK(m_nlines == PAGE_LINES && m_field(m_text(m_nlines - 1), "CUTS") == 0);
    CHECK(m_nlines == LINE_CAP);                                      /* the nominal page is the cap, and the closing lines are still there */
    /* Every cell four characters wide: neither RDY= nor V= of a temperature line fits any more; both are dropped, counted, and nothing else is. */
    for (unsigned n = 0; n < M_BLOCKS; n++)
        for (unsigned i = 0; i < 16; i++) w[n][i] = 0x00200000u | (1100 + n);
    m_fx_words(w);
    RUN_CLEAN();
    CHECK(m_nlines == PAGE_LINES && m_field(m_text(m_nlines - 1), "CUTS") == 8);
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        char head[16];
        int at;
        snprintf(head, sizeof head, "T%u C", n);
        at = m_find(head, 0);
        CHECK(at >= 0 && m_field(m_text((unsigned)at), "V") < 0 && strstr(m_text((unsigned)at), " RDY=") == NULL);
    }
    /* Six cells four characters wide and ten three: RDY= still fits, V= is the one that goes (RDY= comes first because only its absence is a gap in what the run is for). */
    for (unsigned n = 0; n < M_BLOCKS; n++)
        for (unsigned i = 0; i < 16; i++) w[n][i] = 0x00200000u | (i < 6 ? 1100 : 300);
    m_fx_words(w);
    RUN_CLEAN();
    CHECK(m_nlines == PAGE_LINES && m_field(m_text(m_nlines - 1), "CUTS") == 4);
    CHECK(m_line_is((unsigned)m_find("T0 C", 0), "T0 C 1100 1100 1100 1100 1100 1100 300 300 300 300 300 300 300 300 300 300 RDY=0X1"));
    /* All ones everywhere in the status words: eight digits each, still eight to a line, nothing cut. */
    for (unsigned n = 0; n < M_BLOCKS; n++)
        for (unsigned i = 0; i < 16; i++) w[n][i] = 0xffffffffu;
    m_fx_words(w);
    RUN_CLEAN();
    CHECK(m_field(m_text(m_nlines - 1), "CUTS") == 0 && m_nlines == PAGE_LINES);
    CHECK(m_line_is((unsigned)m_find("T0 R0", 0), "T0 R0 FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF"));
    CHECK(m_line_is((unsigned)m_find("T0 C", 0), "T0 C O O O O O O O O O O O O O O O O RDY=0X1 V=0"));
    /* The longest CONV line, every word as wide as it can be, still holds its announcement. */
    m_fx_unit();
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        for (unsigned i = 0; i < 16; i++) m_set(M_SROT(n), 0x60 + 4 * i, 0xfffffff0u + i);
        m_set(M_TM(n), 0x08, 0xffffffffu);
        m_set(M_TM(n), 0x14, 0xffffffffu);
    }
    RUN_CLEAN();
    CHECK(m_field(m_text(m_nlines - 1), "CUTS") == 0 && m_nlines == PAGE_LINES);
    CHECK(m_line_is((unsigned)m_find("CONV T0", 0), "CONV T0 NZ=16/16 LO=0XFFFFFFF0 HI=0XFFFFFFFF UL=0XFFFFFFFF CR=0XFFFFFFFF NEXT CONV T1"));
    return 0;
}

/* ---- Random worlds with everything: values, aborts, hangs, counters ---- */
static int suite_storm(void)
{
    for (unsigned round = 0; round < 1500; round++) {
        m_fx_unit();
        for (unsigned n = 0; n < M_BLOCKS; n++) {
            if (m_rand() % 4 == 0) m_set(M_SROT(n), 0x00, m_word());
            if (m_rand() % 4 == 0) m_set(M_SROT(n), 0x04, m_word());
            if (m_rand() % 4 == 0) m_set(M_TM(n), 0xe4, m_rand());
            for (unsigned i = 0; i < 16; i++) {
                if (m_rand() % 3 == 0) m_set(M_TM(n), 0xa0 + 4 * i, m_word());
                if (m_rand() % 3 == 0) m_set2(M_TM(n), 0xa0 + 4 * i, m_word());
                if (m_rand() % 5 == 0) m_set(M_SROT(n), 0x60 + 4 * i, m_rand());
            }
            if (m_rand() % 6 == 0) m_set2(M_SROT(n), 0x04, m_rand());
        }
        switch (m_rand() % 8) {
        case 0: m_abort_windows = m_rand() & 0xff; break;
        case 1: m_abort_nth = (int)(m_rand() % 230); break;
        case 2: m_abort_from_nth = (int)(m_rand() % 230); break;
        case 3: m_hang_nth = (int)(m_rand() % 230); break;
        case 4: m_step = m_rand() % 3 ? 20000 : 0; break;
        case 5: m_no_counter = 1; break;
        case 6: m_cntfrq = m_rand(); break;
        default: break;
        }
        m_run();
        if (!m_hung) m_check_run_invariants();
        CHECK(m_nlines <= LINE_CAP && m_nloads <= LOAD_CAP && m_dropped == 0);
    }
    return 0;
}

/* ---- Caps (the builds with small caps run only this) ---- */
static int suite_caps(void)
{
    m_fx_unit();
    m_run();
    CHECK(!m_hung && m_nlines <= LINE_CAP && m_nloads <= LOAD_CAP && m_dropped == 0);
    m_check_run_invariants();
    for (unsigned i = 0; i < m_nlines; i++) CHECK(!strncmp(m_lines[i], PREFIX, strlen(PREFIX)));
    CHECK(m_nlines >= 1 && !strncmp(m_text(m_nlines - 1), "END LOADS=", 10));          /* the closing lines are reserved: END is there whatever the cap */
    /* With the load cap reached every later word says BUDGET and nothing more is loaded. */
    if (LOAD_CAP < LOADS_MAX && LINE_CAP >= PAGE_LINES) CHECK(m_nloads == LOAD_CAP);
    /* A stuck or slow counter does not outlast its bound (only checked where the bound is small enough to reach quickly). */
    if (STUCK_READS < 1000000u) {
        m_fx_unit();
        m_step = 0;
        m_run();
        CHECK(!m_hung && m_counter_reads <= STUCK_READS + 16 && m_nlines <= LINE_CAP);
        if (LINE_CAP >= PAGE_LINES) CHECK(m_find("S2 SKIPPED NO_COUNTER", 0) >= 0);
    }
    if (SPIN_MAX < 1000000u) {
        /* A counter that moves one tick a read at 1 MHz needs 2 million reads for 2 s, more than the bound: the wait ends as SPIN (a counter that runs but did not span it), not as a dead
         * counter. */
        m_fx_unit();
        m_step = 1;
        m_cntfrq = 1000000;
        m_run();
        CHECK(!m_hung && m_counter_reads <= SPIN_MAX + 16 && m_nlines <= LINE_CAP);
        if (LINE_CAP >= PAGE_LINES) CHECK(m_find("S2 SKIPPED SPIN", 0) >= 0 && m_find("S2 SKIPPED NO_COUNTER", 0) < 0 && m_find("S2 T0", 0) < 0);
        /* A counter that never moves is a dead one whichever bound comes first. */
        m_fx_unit();
        m_step = 0;
        m_run();
        CHECK(!m_hung && m_counter_reads <= (SPIN_MAX < STUCK_READS ? SPIN_MAX : STUCK_READS) + 16 && m_nlines <= LINE_CAP);
        if (LINE_CAP >= PAGE_LINES) CHECK(m_find("S2 SKIPPED NO_COUNTER", 0) >= 0 && m_find("S2 SKIPPED SPIN", 0) < 0);
    }
    return 0;
}

/* ---- The wait at the shipped bound (slow: `--slow`) ---- */
/* A counter that needs more reads than the old bound of 2^28 completes the wait: 134.3 MHz at one tick a read is 268.6 million reads for 2 s. */
static int suite_slow(void)
{
    m_fx_unit();
    m_step = 1;
    m_cntfrq = 134300000;
    RUN_CLEAN();
    CHECK(m_counter_reads > (1u << 28));
    CHECK(m_find("S2 SKIPPED", 0) < 0 && m_find("S2 T3", 0) >= 0 && m_nlines == PAGE_LINES);
    CHECK(m_field(m_text(m_nlines - 1), "GAP_MS") >= 2000 && m_field(m_text(m_nlines - 1), "GAP_MS") < 2100);
    return 0;
}

#define SUITE(name) do { unsigned before_ = m_fails; suite_##name(); printf("suite %-8s %s\n", #name, m_fails == before_ ? "ok" : "FAIL"); } while (0)

static void print_page(const char *scenario)
{
    m_fx_unit();
    if (scenario && !strcmp(scenario, "gated")) m_set(M_SROT(1), 0x00, 0);
    if (scenario && !strcmp(scenario, "faults")) m_abort_windows = 1u << M_TM(2);
    if (scenario && !strcmp(scenario, "stuck")) m_step = 0;
    if (scenario && !strcmp(scenario, "dead")) m_abort_windows = (1u << (M_BLOCKS * 2)) - 1u;   /* a machine with none of the windows */
    m_run();
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
        m_run();
        printf("LINES %u LOADS %u LINE_CAP %u LOAD_CAP %u PAGE_LINES %u LOADS_MAX %u\n", m_nlines, m_nloads, LINE_CAP, LOAD_CAP, PAGE_LINES, LOADS_MAX);
        return 0;
    }
    m_reset();
#ifdef TSNAP_SHIPPED_CAPS
    if (argc > 1 && !strcmp(argv[1], "--slow")) {
        SUITE(slow);
        printf("CHECKS %u FAILS %u MAXLINES %u MAXLOADS %u LINE_CAP %u LOAD_CAP %u\n", m_checks, m_fails, m_maxlines, m_maxloads, LINE_CAP, LOAD_CAP);
        return m_fails ? 1 : 0;
    }
    SUITE(unit);
    SUITE(order);
    SUITE(cells);
    SUITE(random);
    SUITE(gate);
    SUITE(faults);
    SUITE(hang);
    SUITE(drift);
    SUITE(counter);
    SUITE(el);
    SUITE(budget);
    SUITE(storm);
#else
    SUITE(caps);
#endif
    printf("CHECKS %u FAILS %u MAXLINES %u MAXLOADS %u LINE_CAP %u LOAD_CAP %u\n", m_checks, m_fails, m_maxlines, m_maxloads, LINE_CAP, LOAD_CAP);
    return m_fails ? 1 : 0;
}
