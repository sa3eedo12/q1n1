/* SPDX-License-Identifier: MIT */
/* The suites of the host test of the payload "tsnap" that are about what a status word says (tools/test-q1n1-sp11-payload-tsnap.c includes this file after its fixtures; it is not a
 * translation unit of its own):
 *   cells    every kind of status word in every slot against the model's own decode and against the table of words below, the sensor number of every slot, the reserved bits, the
 *            critical flags, ties and an empty world
 *   boot29   a replay of the unit's own page (boot 29), the words the film gives and the layout it implies, under the old decode and under the new one
 * Nothing here ran on hardware. Evidence: EXPERIMENTAL (host model only). */

/* CHECK with what the case is, so that the FAIL line names it (shown once for each site, as CHECK does). */
#define CHECKM(cond, what) do { m_checks++; if (!(cond)) { static unsigned char shown_; m_fails++; if (!shown_) { shown_ = 1; fprintf(stderr, "FAIL %s:%d: %s: %s\n", __FILE__, __LINE__, #cond, what); } } } while (0)

/* ---- The status words ---- */
/* A word, the sensor slot it is read in, and the cell the decode must make of it. The slot matters: bits 26:22 must be the slot's own number (INFERRED from the unit's own words, boot 29).
 * In slot 0 the number is 0, so the words of the first rows decode as they did before the number was known. */
static const struct {
    uint32_t raw;
    unsigned slot;
    const char *cell;
} CELLS[] = {
    {0x0020012c, 0, "300"}, {0x00200fff, 0, "-1"}, {0x00200000, 0, "0"}, {0x00200001, 0, "1"}, {0x002004b0, 0, "1200"}, {0x002004b1, 0, "O"}, {0x00200e70, 0, "-400"}, {0x00200e6f, 0, "O"},
    {0x00200800, 0, "O"}, {0x002007ff, 0, "O"}, {0x0000012c, 0, "?"}, {0x00000000, 0, "?"}, {0x00000fff, 0, "?"}, {0x0060012c, 0, "O"}, {0x8020012c, 0, "O"}, {0xffffffff, 0, "O"},
    {0x0028012c, 0, "300"}, {0x0030012c, 0, "300"}, {0x0010012c, 0, "?"}, {0x0007012c, 0, "?"}, {0x00e0012c, 0, "O"}, {0x0020b12c, 0, "300"}, {0x00a0012c, 0, "O"}, {0x04200000, 0, "O"},
    /* the right number in the slot: the same decode */
    {0x0060012c, 1, "300"}, {0x00a0012c, 2, "300"}, {0x00e0012c, 3, "300"}, {0x0160012c, 5, "300"}, {0x03e0012c, 15, "300"}, {0x0060b12c, 1, "300"}, {0x00690fff, 1, "-1"}, {0x00e004b1, 3, "O"},
    /* the right number but VALID clear: not valid, not odd */
    {0x0040012c, 1, "?"}, {0x01c0012c, 7, "?"}, {0x03c00000, 15, "?"}, {0x00480000, 1, "?"},
    /* a wrong number in the slot: odd, whatever else the word says (the number of slot 0 in another slot, a neighbour's, the largest, the same number plus the next bit up) */
    {0x0020012c, 1, "O"}, {0x0020012c, 15, "O"}, {0x0060012c, 2, "O"}, {0x00a0012c, 1, "O"}, {0x03e0012c, 14, "O"}, {0x07e0012c, 15, "O"}, {0x0440012c, 1, "O"}, {0x04000000, 0, "O"},
    {0x00400000, 0, "O"}, {0x03c00000, 14, "O"}, {0x00000000, 1, "O"}, {0x00000fff, 15, "O"},
    /* a reserved bit (31:27) set beside the right number */
    {0x0820012c, 0, "O"}, {0x0860012c, 1, "O"}, {0x1020012c, 0, "O"}, {0x2020012c, 0, "O"}, {0x4020012c, 0, "O"}, {0x8020012c, 0, "O"}, {0x8060012c, 1, "O"}, {0x83e0012c, 15, "O"},
    /* all ones in every slot is odd (its number field reads 31) */
    {0xffffffff, 1, "O"}, {0xffffffff, 15, "O"}, {0xffffffff, 7, "O"},
};
#define CELLS_COUNT (sizeof CELLS / sizeof CELLS[0])

/* A world of words that no sensor is enabled to say anything with: each slot reads its own number and nothing else (not VALID). */
static void m_blank_words(uint32_t w[M_BLOCKS][16])
{
    for (unsigned n = 0; n < M_BLOCKS; n++)
        for (unsigned i = 0; i < 16; i++) w[n][i] = m_status_off(i);
}

/* The cell in sensor slot `slot` of the temperature line at page line `line` ("T<n> C c0 c1 ..."), or "" when there is none. */
static void m_cell_token(unsigned line, unsigned slot, char *out)
{
    const char *p = m_text(line);
    out[0] = 0;
    p += 5;                                                    /* "T<n> C" and the space after it */
    for (unsigned i = 0; i < slot && *p; i++) p += strcspn(p, " ") + (p[strcspn(p, " ")] ? 1 : 0);
    if (*p) {
        size_t len = strcspn(p, " ");
        memcpy(out, p, len < 15 ? len : 15);
        out[len < 15 ? len : 15] = 0;
    }
}

static int suite_cells(void)
{
    uint32_t w[M_BLOCKS][16];
    struct m_world world;
    static const uint32_t FLAGS[] = {1u << 16, 1u << 17, 1u << 18, 1u << 19, 1u << 20, 3u << 19, 0x1fu << 16};
    unsigned hit[CELLS_COUNT] = {0};
    /* Every kind of word, in every slot of a block, in all four blocks. */
    for (unsigned shift = 0; shift < CELLS_COUNT; shift++) {
        for (unsigned n = 0; n < M_BLOCKS; n++)
            for (unsigned i = 0; i < 16; i++) w[n][i] = CELLS[(shift + n * 5 + i) % CELLS_COUNT].raw;
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
                char cell[16], shown[16];
                m_cell(w[n][i], i, cell);
                if (at >= 0) {
                    m_cell_token((unsigned)at, i, shown);
                    CHECK(!strcmp(shown, cell));                       /* what the payload printed is the model's cell, slot by slot */
                }
                for (unsigned c = 0; c < CELLS_COUNT; c++) {
                    if (CELLS[c].raw != w[n][i] || CELLS[c].slot != i) continue;
                    CHECKM(!strcmp(CELLS[c].cell, cell), "the model's decode is the table's");
                    hit[c]++;
                }
            }
        }
        m_check_values(&world);
    }
    for (unsigned c = 0; c < CELLS_COUNT; c++) CHECKM(hit[c] > 0, "every word of the table was read in the slot it names");
    /* The sensor number, systematically: every number in every slot on three kinds of word (VALID 30.0 C, not VALID, VALID and out of range), the other slots holding their own right words.
     * Only the right number decodes; every other is odd, whatever else the word says. */
    {
        static const struct {
            uint32_t base;
            const char *cell;
        } KINDS[] = {{0x0020012c, "300"}, {0x0000012c, "?"}, {0x002004b1, "O"}};
        for (unsigned k = 0; k < 3; k++) {
            for (unsigned slot = 0; slot < 16; slot++) {
                for (unsigned id = 0; id < 32; id++) {
                    unsigned n = (slot + id) % M_BLOCKS;
                    char head[16], shown[16];
                    int at;
                    m_fx_unit();
                    m_set(M_TM(n), 0xa0 + 4 * slot, KINDS[k].base | id << 22);
                    m_capture(&world);
                    RUN_CLEAN();
                    snprintf(head, sizeof head, "T%u C", n);
                    at = m_find(head, 0);
                    CHECK(at >= 0);
                    if (at < 0) continue;
                    m_cell_token((unsigned)at, slot, shown);
                    CHECKM(!strcmp(shown, id == slot ? KINDS[k].cell : "O"), "only the sensor's own number decodes");
                    m_check_values(&world);
                }
            }
        }
    }
    /* A reserved bit (31:27) beside the right number, in every slot: odd. Bits 15:12 beside it: not looked at. */
    for (unsigned slot = 0; slot < 16; slot++) {
        for (unsigned bit = 27; bit < 32; bit++) {
            char shown[16];
            m_fx_unit();
            m_set(M_TM(1), 0xa0 + 4 * slot, m_status(300, slot) | 1u << bit);
            RUN_CLEAN();
            m_cell_token((unsigned)m_find("T1 C", 0), slot, shown);
            CHECKM(!strcmp(shown, "O"), "a reserved bit makes the word odd");
        }
        for (unsigned bit = 12; bit < 16; bit++) {
            char shown[16];
            m_fx_unit();
            m_set(M_TM(2), 0xa0 + 4 * slot, m_status(300, slot) | 1u << bit);
            RUN_CLEAN();
            m_cell_token((unsigned)m_find("T2 C", 0), slot, shown);
            CHECKM(!strcmp(shown, "300"), "bits 15:12 are not looked at");
        }
    }
    /* The critical flags are counted for any word that is not odd, whether or not it is VALID; MIN, LOWER and UPPER alone are not critical. */
    for (unsigned f = 0; f < sizeof FLAGS / sizeof FLAGS[0]; f++) {
        struct m_sum s;
        m_blank_words(w);
        w[2][5] = m_status(300, 5) | FLAGS[f];
        w[3][0] = m_status_off(0) | 0x12c | FLAGS[f];
        w[1][1] = m_status(300, 1) | 0x80000000u | FLAGS[f];
        m_fx_words(w);
        m_capture(&world);
        RUN_CLEAN();
        m_oracle(world.w1, &s);
        CHECK(s.crit == (FLAGS[f] >> 19 & 3 ? 2u : 0u));
        CHECK(s.odd == 1 && s.valid == 1);
        m_check_values(&world);
    }
    /* Ties: the first sensor in block order wins both the minimum and the maximum. */
    for (unsigned n = 0; n < M_BLOCKS; n++)
        for (unsigned i = 0; i < 16; i++) w[n][i] = m_status(400, i);
    m_fx_words(w);
    m_capture(&world);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("SUM1", 0), "SUM1 V=64/64 MIN=400(T0.0) MAX=400(T0.0) CRIT=0 OUT=0 ODD=0"));
    /* No valid sensor at all (each slot reads its own number alone): NA, and the second reading has nothing to compare. */
    m_blank_words(w);
    m_fx_words(w);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("SUM1", 0), "SUM1 V=0/64 MIN=NA MAX=NA CRIT=0 OUT=0 ODD=0"));
    CHECK(m_line_is((unsigned)m_find("SUM2", 0), "SUM2 V=0/64 MIN=NA MAX=NA CHG=0/0 DMAX=0 CRIT=0 OUT=0 ODD=0"));
    /* Words of zero everywhere (a window that reads zero): only slot 0 has the right number, so 60 of the 64 are odd, and slot 0 is `?`. */
    memset(w, 0, sizeof w);
    m_fx_words(w);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("SUM1", 0), "SUM1 V=0/64 MIN=NA MAX=NA CRIT=0 OUT=0 ODD=60"));
    CHECK(m_line_is((unsigned)m_find("T0 C", 0), "T0 C ? O O O O O O O O O O O O O O O RDY=0X1 V=0"));
    return 0;
}

/* ---- The unit's own page: a replay of boot 29 ---- */
/* What the page of boot 29 (the first run of tsnap, read from a film: files/result-boot29.md) gives, and what it does not.
 * READ, digits on that page: HW_VER 0X20080000 on all four blocks; CTRL 0X9D60FFF9, 0X9D603FF9, 0X9D603FF9 and 0X9D63FFF9, so SEN 0X1FFF, 0X7FF, 0X7FF and 0X7FFF, 13 + 11 + 11 + 15 = 50
 * sensors enabled; the summary the old decode printed for the first reading, `V=4/64 ... ODD=60`, and for the second `V=4/64 ... CHG=1/4 DMAX=4`; the lowest of the 50 temperatures, 0X17D
 * (38.1 C) on T1, and the highest, 0X1AA (42.6 C) on T0; the four cells the old decode took for clean, which can only be sensor 0 of each block, between 38.5 and 39.8 C, T0.0 being
 * 39.8 C in the first reading and 40.2 C in the second, the other three unchanged.
 * NOT READ, so filler chosen inside those bounds and marked: which sensor of T1 and of T0 holds the extreme, the two clean cells that are not the extremes of the four, every other
 * temperature, TRDY, the conversion words, the interrupt words, and the second reading of every sensor but T0.0.
 * INFERRED (not read): that every word has its own number in bits 26:22, the 14 sensors that are not enabled included, which is what 60 odd words in 64 means for the old decode. */
static const uint32_t B29_CTL[M_BLOCKS] = {0x9d60fff9u, 0x9d603ff9u, 0x9d603ff9u, 0x9d63fff9u};
#define B29_VER 0x20080000u
#define B29_LOW_BLOCK 1u            /* 0X17D is on T1 ... */
#define B29_LOW_SENSOR 4u           /* ... on this sensor: FILLER */
#define B29_HIGH_BLOCK 0u           /* 0X1AA is on T0 ... */
#define B29_HIGH_SENSOR 6u          /* ... on this sensor: FILLER */

static int b29_tenths(unsigned n, unsigned i)
{
    static const int CLEAN[M_BLOCKS] = {398, 391, 385, 388};       /* T0.0 39.8 and T2.0 38.5 are READ as the extremes of the four; T1.0 and T3.0 are FILLER between them */
    if (i == 0) return CLEAN[n];
    if (n == B29_LOW_BLOCK && i == B29_LOW_SENSOR) return 0x17d;
    if (n == B29_HIGH_BLOCK && i == B29_HIGH_SENSOR) return 0x1aa;
    return 384 + (int)((n * 7 + i * 5) % 40);                      /* FILLER strictly between 0X17D and 0X1AA */
}

/* The words boot 29's blocks hold, with the film's digits where there are any and the layout of the unit's words (the sensor's number in bits 26:22) for every sensor. `unenabled_zero`
 * makes the 14 sensors that are not enabled read zero instead of their own number. */
static void m_fx_boot29(unsigned unenabled_zero)
{
    m_reset();
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        m_set(M_SROT(n), 0x00, B29_VER);
        m_set(M_SROT(n), 0x04, B29_CTL[n]);
        m_set(M_TM(n), 0xe4, 1);
        for (unsigned i = 0; i < 16; i++) {
            uint32_t word = unenabled_zero ? 0 : m_status_off(i);
            if (i < M_COUNT[n]) {
                word = m_status(b29_tenths(n, i), i);
                m_set2(M_TM(n), 0xa0 + 4 * i, m_status(n == 0 && i == 0 ? 402 : b29_tenths(n, i), i));
            }
            m_set(M_TM(n), 0xa0 + 4 * i, word);
            m_set(M_SROT(n), 0x60 + 4 * i, 0x01b3416au + i);
        }
    }
}

/* The old decode (the one boot 29 ran), kept only to show that the replay world reproduces what the film's summary said: a word with any bit above 21 is odd, then VALID, then the window. */
static int b29_old_cell(uint32_t raw, int *t)
{
    int v = (int)(raw & 0xfff);
    if (v >= 2048) v -= 4096;
    *t = v;
    if (raw >> 22) return 'O';
    if (!(raw >> 21 & 1)) return '?';
    if (v < -400 || v > 1200) return 'O';
    return 'K';
}

static int suite_boot29(void)
{
    struct m_world w;
    unsigned old_valid = 0, old_odd = 0, old_chg = 0, old_both = 0;
    int old_min = 0, old_max = 0, old_dmax = 0;
    static const char *const IDENT[M_BLOCKS] = {"T0 VER=0X20080000 CTL=0X9D60FFF9 SEN=0X1FFF", "T1 VER=0X20080000 CTL=0X9D603FF9 SEN=0X7FF",
                                                "T2 VER=0X20080000 CTL=0X9D603FF9 SEN=0X7FF", "T3 VER=0X20080000 CTL=0X9D63FFF9 SEN=0X7FFF"};
    m_fx_boot29(0);
    m_capture(&w);
    /* The world is the film's: what the old decode printed on it is the page's summary, `V=4/64 ... ODD=60` and `CHG=1/4 DMAX=4`, and its four clean cells are 38.5 to 39.8 C. */
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        for (unsigned i = 0; i < 16; i++) {
            int t1, t2, k1 = b29_old_cell(w.w1[n][i], &t1), k2 = b29_old_cell(w.w2[n][i], &t2);
            old_odd += k1 == 'O';
            if (k1 == 'K') {
                if (!old_valid || t1 < old_min) old_min = t1;
                if (!old_valid || t1 > old_max) old_max = t1;
                old_valid++;
            }
            if (k1 == 'K' && k2 == 'K') {
                int d = t1 > t2 ? t1 - t2 : t2 - t1;
                old_both++;
                old_chg += d != 0;
                if (d > old_dmax) old_dmax = d;
            }
        }
    }
    CHECK(old_valid == 4 && old_odd == 60);
    CHECK(old_min == 385 && old_max == 398);
    CHECK(old_both == 4 && old_chg == 1 && old_dmax == 4);
    /* The 14 sensors that are not enabled must carry bits above 21 too, or the film's count would have been 46: a world where they read zero is not the film's. */
    {
        struct m_world z;
        unsigned odd = 0;
        m_fx_boot29(1);
        m_capture(&z);
        for (unsigned n = 0; n < M_BLOCKS; n++)
            for (unsigned i = 0; i < 16; i++) odd += b29_old_cell(z.w1[n][i], &(int){0}) == 'O';
        CHECK(odd == 46);
    }
    /* The new decode on the film's words: 50 sensors valid, 38.1 to 42.6 C, nothing odd. */
    m_fx_boot29(0);
    RUN_CLEAN();
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        char head[16];
        int at;
        snprintf(head, sizeof head, "T%u VER=", n);
        at = m_find(head, 0);
        CHECK(at >= 0 && m_line_is((unsigned)at, IDENT[n]));
        snprintf(head, sizeof head, "T%u C", n);
        at = m_find(head, 0);
        CHECK(at >= 0 && m_field(m_text((unsigned)at), "V") == (long)M_COUNT[n]);
        for (unsigned i = 0; at >= 0 && i < 16; i++) {
            char shown[16], want[16];
            m_cell_token((unsigned)at, i, shown);
            if (i < M_COUNT[n]) {
                snprintf(want, sizeof want, "%d", b29_tenths(n, i));
                CHECK(!strcmp(shown, want));
                CHECK(b29_tenths(n, i) >= 0x17d && b29_tenths(n, i) <= 0x1aa);
            } else {
                CHECK(!strcmp(shown, "?"));
            }
        }
    }
    CHECK(m_line_is((unsigned)m_find("T0 R0", 0), "T0 R0 0020018E 00600185 00A0018A 00E0018F 01200194 01600199 01A001AA 01E001A3"));
    CHECK(m_line_is((unsigned)m_find("SUM1", 0), "SUM1 V=50/64 MIN=381(T1.4) MAX=426(T0.6) CRIT=0 OUT=0 ODD=0"));
    CHECK(m_line_is((unsigned)m_find("SUM2", 0), "SUM2 V=50/64 MIN=381(T1.4) MAX=426(T0.6) CHG=1/50 DMAX=4 CRIT=0 OUT=0 ODD=0"));
    m_check_values(&w);
    /* The old decode's second reading said V=4: the same words, now 50. */
    CHECK(m_field(m_text((unsigned)m_find("S2 T0", 0)), "V") == 13 && m_field(m_text((unsigned)m_find("S2 T3", 0)), "V") == 15);
    CHECK(m_field(m_text((unsigned)m_find("S2 T0", 0)), "CHG") == 1 && m_field(m_text((unsigned)m_find("S2 T1", 0)), "CHG") == 0);
    /* The same words with the 14 unenabled sensors reading zero: still 50 valid, and the 14 are odd (their number is not there), the loud answer for a layout that is not the film's. */
    m_fx_boot29(1);
    m_capture(&w);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("SUM1", 0), "SUM1 V=50/64 MIN=381(T1.4) MAX=426(T0.6) CRIT=0 OUT=0 ODD=14"));
    m_check_values(&w);
    return 0;
}
