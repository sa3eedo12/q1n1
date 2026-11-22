/* SPDX-License-Identifier: MIT */
/* The suites of tools/test-q1n1-sp11-payload-gpusnap2.c that set up worlds of their own: the sensors, the clock words, the memory map, the command database, the RSC, the QFPROM, the gates, the
 * faults and hangs, the random and hostile worlds, the budget and the arguments. Included by that file after its fixtures and its page oracle; it is not a unit of its own. */

static unsigned m_end_field(const char *name)
{
    char pat[32];
    const char *p;
    snprintf(pat, sizeof pat, " %s=", name);
    p = m_nlines ? strstr(m_lines[m_nlines - 1], pat) : NULL;
    return p ? (unsigned)strtoul(p + strlen(pat), NULL, 0) : 0xffffffffu;
}

static unsigned m_end_loads(void)
{
    return m_end_field("LOADS");
}

/* Cell `n` of the temperature line of the sensors. */
static const char *m_cell(unsigned n)
{
    static char out[16];
    int line = m_find("T3 C5", 0);
    const char *p;
    if (line < 0) return "(no line)";
    p = m_text((unsigned)line) + strlen("T3 C5");
    for (unsigned i = 0; i <= n; i++) {
        size_t len;
        while (*p == ' ') p++;
        len = strcspn(p, " ");
        if (i == n) {
            snprintf(out, sizeof out, "%.*s", (int)len, p);
            return out;
        }
        p += len;
    }
    return "";
}

static int m_gate_line(const char *block, const char *why)
{
    char text[64];
    snprintf(text, sizeof text, "%s GATED BY %s", block, why);
    return m_find(text, 0) >= 0;
}

static int m_has_text(const char *text)
{
    for (unsigned i = 0; i < m_nlines; i++) if (strstr(m_lines[i], text)) return 1;
    return 0;
}

/* ---- tsens ---- */
static int suite_tsens(void)
{
    static const uint32_t odd_words[] = {0xffffffffu, 0x08000000u | 1u << 21, 0x80000000u | 5u << 22 | 1u << 21 | 0x190, 0x00000000u, 0x00200000u};
    /* Every sensor-number field in every slot: only the slot's own number is a temperature. */
    for (unsigned slot = 0; slot < 8; slot++) {
        for (unsigned id = 0; id < 32; id++) {
            m_fx_unit();
            m_rset(XW_TTM, 0xa0 + 4 * (5 + slot), id << 22 | 1u << 21 | 0x190);
            RUN_CLEAN();
            CHECK(PAGE_IS_ORACLE());
            CHECKM(!strcmp(m_cell(slot), id == 5 + slot ? "400" : "O"), "the sensor number is the slot's own or the word is not decoded");
        }
    }
    /* Reserved bits above the number, the flag bits and the bits the layout leaves alone: each bit of a good word flipped in turn. */
    for (unsigned bit = 0; bit < 32; bit++) {
        m_fx_unit();
        m_rset(XW_TTM, 0xa0 + 4 * 5, m_status(400, 5) ^ 1u << bit);
        RUN_CLEAN();
        CHECK(PAGE_IS_ORACLE());
        if (bit >= 22) CHECKM(!strcmp(m_cell(0), "O"), "the sensor number or a reserved bit above it");
        else if (bit == 21) CHECKM(!strcmp(m_cell(0), "?"), "VALID clear");
        else if (bit >= 19 && bit <= 20) CHECK(m_find("T3 C5", 0) >= 0 && strstr(m_text((unsigned)m_find("T3 C5", 0)), "CRIT=1") && !strcmp(m_cell(0), "400"));
        else if (bit >= 12 && bit <= 18) CHECKM(!strcmp(m_cell(0), "400"), "the bits between the temperature and the flags are ignored");
    }
    for (unsigned i = 0; i < sizeof odd_words / sizeof odd_words[0]; i++) {
        m_fx_unit();
        m_rset(XW_TTM, 0xa0 + 4 * 7, odd_words[i]);
        RUN_CLEAN();
        CHECK(PAGE_IS_ORACLE());
    }
    /* Temperatures at the edges: -400 and 1200 are valid, -401 and 1201 are not, negative values print their sign. */
    {
        static const int t[] = {-400, -401, 1200, 1201, -1, 0, 2047, -2048};
        static const char *const want[] = {"-400", "O", "1200", "O", "-1", "0", "O", "O"};
        for (unsigned i = 0; i < 8; i++) {
            m_fx_unit();
            m_rset(XW_TTM, 0xa0 + 4 * 5, m_status(t[i], 5));
            RUN_CLEAN();
            CHECK(PAGE_IS_ORACLE());
            CHECKM(!strcmp(m_cell(0), want[i]), "the plausible window");
        }
    }
    /* Extremes keep the first sensor on a tie; the flags only count words that are not odd. */
    m_fx_unit();
    for (unsigned s = 5; s <= 12; s++) m_rset(XW_TTM, 0xa0 + 4 * s, m_status(300, s));
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE());
    CHECK(m_item_is("T3 C5", "MIN", "300(S5)", __LINE__) && m_item_is("T3 C5", "MAX", "300(S5)", __LINE__));
    m_fx_unit();
    m_rset(XW_TTM, 0xa0 + 4 * 6, m_status(400, 6) | 3u << 19);
    m_rset(XW_TTM, 0xa0 + 4 * 8, m_status(500, 8) | 1u << 20 | 2u << 27);
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE());
    CHECK(m_item_is("T3 C5", "CRIT", "1", __LINE__) && m_item_is("T3 C5", "ODD", "1", __LINE__));
    /* CTRL with CODE_OR_TEMP clear: ADC codes, nothing decoded. */
    m_fx_unit();
    m_rset(XW_TSROT, 4, 0x9D63FFF9u & ~(1u << 21));
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE());
    CHECK(m_find("T3", 0) >= 0 && strstr(m_text((unsigned)m_find("T3", 0)), " CODE") && !strcmp(m_cell(0), "O"));
    /* The gates of the block: HW_VER zero, all ones, aborting; CTRL with EN clear, SW_RST set, all ones, aborting, and a window that aborts on its first status word. */
    for (unsigned c = 0; c < 8; c++) {
        m_fx_unit();
        switch (c) {
        case 0: m_rset(XW_TSROT, 0, 0); break;
        case 1: m_rset(XW_TSROT, 0, 0xffffffffu); break;
        case 2: m_rfault(XW_TSROT, 0); break;
        case 3: m_rset(XW_TSROT, 4, 0x9D63FFF8u); break;
        case 4: m_rset(XW_TSROT, 4, 0x9D63FFFBu); break;
        case 5: m_rset(XW_TSROT, 4, 0xffffffffu); break;
        case 6: m_rfault(XW_TSROT, 4); break;
        default: m_rfault(XW_TTM, 0xa0 + 4 * 5); break;
        }
        RUN_CLEAN();
        if (c < 7) CHECK(m_loads_of_block(B_TSENS) == (c < 3 ? 1u : 2u) && m_find("T3 R5", 0) < 0);
        else CHECK(m_find("T3 R5", 0) >= 0 && m_find("T3 C5", 0) < 0 && m_loads_of_block(B_TSENS) == 3);
        if (c < 7 && c != 2 && c != 6) CHECK(PAGE_IS_ORACLE());
        CHECK(m_find("GCC", 0) >= 0 && m_find("QFPROM", 0) >= 0);
    }
    return 0;
}

/* ---- gpucc ---- */
static int suite_gpucc(void)
{
    static const char *const cbcr[] = {"AHB", "CRC", "CXFF", "FM", "MEM", "SLP", "CB"};
    static const uint32_t words[] = {0x0, 0x1, 0x80000000u, 0x80000001u, 0xffffffffu, 0x20000001u, 0xA0000001u, 0xA0000000u, 0x80000003u, 0x7ffffffeu, 0x00000002u, 0x30000001u, 0xE0000001u};
    static const uint32_t modes[] = {0, 1, 3, 7, 0x80000000u, 0x80000001u, 0xC0000007u, 0xffffffffu}, ops[] = {0, 1, 2, 3, 0xffffffffu};
    static const uint32_t gd[] = {0, 1, 2, 3, 0xffffffffu, 0x22F801, 0x8022F000u};
    for (unsigned k = 0; k < sizeof cbcr / sizeof cbcr[0]; k++) {
        for (unsigned w = 0; w < sizeof words / sizeof words[0]; w++) {
            m_fx_unit();
            m_setk(cbcr[k], words[w]);
            RUN_CLEAN();
            CHECK(PAGE_IS_ORACLE());
        }
    }
    for (unsigned m = 0; m < sizeof modes / sizeof modes[0]; m++) {
        for (unsigned o = 0; o < sizeof ops / sizeof ops[0]; o++) {
            m_fx_unit();
            m_setk("P0MODE", modes[m]); m_setk("P0OP", ops[o]); m_setk("P1MODE", modes[(m + 3) % 8]); m_setk("P1OP", ops[(o + 1) % 5]);
            RUN_CLEAN();
            CHECK(PAGE_IS_ORACLE());
        }
    }
    for (unsigned i = 0; i < sizeof gd / sizeof gd[0]; i++) {
        m_fx_unit();
        m_setk("CXGD", gd[i]); m_setk("CXHW", gd[(i + 2) % 7]); m_setk("FFC", gd[(i + 3) % 7]); m_setk("FFF", gd[(i + 4) % 7] << 8); m_setk("XDIV", gd[i]); m_setk("DDIV", gd[(i + 1) % 7]);
        RUN_CLEAN();
        CHECK(PAGE_IS_ORACLE());
    }
    /* The golden facts of the nominal page, by hand: PLL0 is configured and off, the CX domain is off as boot 30 read it. */
    m_fx_unit();
    RUN_CLEAN();
    CHECK(m_item_is("GPUCC PLL0", "EN", "OFF", __LINE__) && m_item_is("GPUCC PLL0", "L", "0X29", __LINE__) && m_item_is("GPUCC PLL1", "AL", "0XEAAA", __LINE__));
    CHECK(m_find("GPUCC AHB=0.ODD CXGD=0X22F801 SC=1 HW=0 CXHW=0XDFF4.OFF", 0) >= 0);
    /* The CFG AHB gate: running opens it; everything else closes it, and says whether the word was read. */
    {
        static const struct { uint32_t w; int fault; const char *why; } g[] = {
            {0x1, 0, NULL}, {0x0, 0, "AHB"}, {0x80000000u, 0, "AHB"}, {0x80000001u, 0, "AHB"}, {0x2, 0, "AHB"}, {0x20000001u, 0, NULL}, {0xA0000001u, 0, "AHB"},
            {0xffffffffu, 0, "AHBERR"}, {0, 1, "AHBERR"}, {0x3, 0, NULL}, {0x80000002u, 0, "AHB"}};
        for (unsigned i = 0; i < sizeof g / sizeof g[0]; i++) {
            m_fx_unit();
            m_rset(XW_GCC, 0x71004, g[i].w);
            if (g[i].fault) m_rfault(XW_GCC, 0x71004);
            RUN_CLEAN();
            if (g[i].fault) CHECK(m_find("GCC CFGA=FAULT:6", 0) >= 0);
            else CHECK(PAGE_IS_ORACLE());
            if (g[i].why) CHECK(m_gate_line("GPUCC", g[i].why) && m_loads_of_block(B_GPUCC) == 0 && m_find("NEXT GPUCC", 0) < 0);
            else CHECK(m_loads_of_block(B_GPUCC) == 21 && m_find("NEXT GPUCC", 0) >= 0);
        }
    }
    /* A GPUCC window that aborts at its first word, and in the middle: the rest of its lines say SKIP, and the later blocks are read. */
    m_fx_unit();
    m_rfault(XW_GPUCC, 0x911c);
    RUN_CLEAN();
    CHECK(m_loads_of_block(B_GPUCC) == 1 && m_item_is("GPUCC AHB=FAULT:6", "CXGD", "SKIP", __LINE__) && m_find("QFPROM", 0) >= 0);
    m_fx_unit();
    m_rfault(XW_GPUCC, 0x1000);
    RUN_CLEAN();
    CHECK(m_loads_of_block(B_GPUCC) == 8 && m_item_is("GPUCC PLL1", "MODE", "FAULT:6", __LINE__) && m_item_is("GPUCC PLL1", "EN", "NA", __LINE__) && m_item_is("GPUCC PLL1", "OP", "SKIP", __LINE__));
    return 0;
}

/* ---- qfprom ---- */
static int suite_qfprom(void)
{
    static const struct { unsigned fuse; const char *sb; } known[] = {{0, "0"}, {59, "1"}, {7, "2"}, {232, "3"}, {146, "4"}};
    for (unsigned fuse = 0; fuse < 256; fuse++) {
        const char *want = "?";
        m_fx_unit();
        m_rset(XW_QFP, 0x118, fuse << 15 | (m_rand() & 0x7fff) | (m_rand() & 0xff800000u));
        RUN_CLEAN();
        CHECK(PAGE_IS_ORACLE());
        for (unsigned i = 0; i < 5; i++) if (known[i].fuse == fuse) want = known[i].sb;
        CHECK(m_item_is("QFPROM", "SB", want, __LINE__));
    }
    m_fx_unit();
    m_rset(XW_QFP, 0x118, 0xffffffffu);
    RUN_CLEAN();
    CHECK(m_item_is("QFPROM", "FUSE", "255", __LINE__) && m_item_is("QFPROM", "SB", "?", __LINE__));
    m_fx_unit();
    m_rfault(XW_QFP, 0x118);
    RUN_CLEAN();
    CHECK(m_find("QFPROM W118=FAULT:6", 0) >= 0 && m_find("QFPROM W118=FAULT:6 FUSE", 0) < 0 && m_loads_of_block(B_QFPROM) == 1);
    return 0;
}

/* ---- map ---- */
static void m_map_unit_s(unsigned n, unsigned stride)
{
    m_map_unit(n);
    m_map_stride = stride;
    m_map_size = (uint64_t)n * stride;
    memset(m_map, 0, sizeof m_map);
    for (unsigned i = 0; i < n; i++) {
        uint32_t type = 1 + i % 7;
        if (i == n / 2) m_map_desc(i, 0, 0x81a40000ull, 0x2c0, 1);
        else m_map_desc(i, type, (i < n / 2 ? 0x80000000ull : 0x82000000ull) + 0x4000ull * i, 4, 8);
    }
}

#define RG 0x81c60000ull
static int suite_map(void)
{
    struct { const char *name; int want; } c[64];
    unsigned n = 0;
#define CASE(nm, st) do { c[n].name = nm; c[n].want = st; n++; } while (0)
    CASE("nominal", OM_OPEN); CASE("none: the reserved descriptor is elsewhere", OM_NONE); CASE("first half only", OM_PART); CASE("a superset", OM_OPEN); CASE("exact", OM_OPEN);
    CASE("one page short at the end", OM_PART); CASE("one page late at the start", OM_PART); CASE("two halves in order", OM_OPEN); CASE("two halves reversed", OM_OPEN); CASE("two halves, a gap", OM_PART);
    CASE("two overlapping", OM_OPEN); CASE("a loader descriptor overlaps the first page", OM_TYPE); CASE("covered by MMIO", OM_TYPE); CASE("covered by boot services data", OM_TYPE);
    CASE("covered by conventional memory", OM_TYPE); CASE("a neighbour ends at the region's start", OM_OPEN); CASE("a neighbour starts at the region's end", OM_OPEN);
    CASE("a zero-page descriptor of another type", OM_OPEN); CASE("a start that is not page aligned", OM_BAD); CASE("pages that run past 48 bits", OM_BAD); CASE("a start past 48 bits", OM_BAD);
    CASE("nine overlapping descriptors", OM_BAD); CASE("eight contiguous", OM_OPEN); CASE("the covering one is last", OM_OPEN); CASE("the covering one is first", OM_OPEN);
    CASE("a malformed descriptor elsewhere", OM_BAD); CASE("a covered region and a non-reserved descriptor overlapping it later in the map", OM_TYPE);
    CASE("stride 40", OM_OPEN); CASE("stride 56", OM_OPEN); CASE("stride 64", OM_OPEN); CASE("stride 128", OM_OPEN); CASE("stride 32", OM_BAD); CASE("stride 44", OM_BAD);
    CASE("stride 136", OM_BAD); CASE("stride 0", OM_BAD); CASE("size 0", OM_BAD); CASE("a size that is not a whole number of descriptors", OM_BAD); CASE("321 descriptors", OM_BAD);
    CASE("320 descriptors", OM_OPEN); CASE("a base that is not 8-aligned", OM_BAD); CASE("base 0", OM_BAD); CASE("attribute 8", OM_OPEN);
    CASE("an end that wraps around 2^64", OM_BAD); CASE("a page count that wraps the byte count", OM_BAD);
#undef CASE
    for (unsigned i = 0; i < n; i++) {
        unsigned idx = 113;
        m_fx_unit();
        switch (i) {
        case 0: break;
        case 1: m_map_desc(idx, 0, 0x90000000ull, 0x2c0, 1); break;
        case 2: m_map_desc(idx, 0, RG, 0x10, 1); break;
        case 3: m_map_desc(idx, 0, RG - 0x60000, 0xa0, 1); break;
        case 4: m_map_desc(idx, 0, RG, 0x20, 1); break;
        case 5: m_map_desc(idx, 0, RG, 0x1f, 1); break;
        case 6: m_map_desc(idx, 0, RG + 0x1000, 0x1f, 1); break;
        case 7: m_map_desc(idx, 0, RG, 0x10, 1); m_map_desc(idx + 1, 0, RG + 0x10000, 0x10, 1); break;
        case 8: m_map_desc(idx, 0, RG + 0x10000, 0x10, 1); m_map_desc(idx + 1, 0, RG, 0x10, 1); break;
        case 9: m_map_desc(idx, 0, RG, 0x10, 1); m_map_desc(idx + 1, 0, RG + 0x11000, 0xf, 1); break;
        case 10: m_map_desc(idx, 0, RG, 0x18, 1); m_map_desc(idx + 1, 0, RG + 0x10000, 0x10, 1); break;
        case 11: m_map_desc(idx, 0, RG, 0x20, 1); m_map_desc(idx + 1, 2, RG - 0x1000, 2, 8); break;
        case 12: m_map_desc(idx, 11, RG, 0x20, 1); break;
        case 13: m_map_desc(idx, 4, RG, 0x20, 1); break;
        case 14: m_map_desc(idx, 7, RG, 0x20, 1); break;
        case 15: m_map_desc(idx, 0, RG, 0x20, 1); m_map_desc(idx + 1, 2, RG - 0x4000, 4, 8); break;
        case 16: m_map_desc(idx, 0, RG, 0x20, 1); m_map_desc(idx + 1, 7, RG + 0x20000, 4, 8); break;
        case 17: m_map_desc(idx, 0, RG, 0x20, 1); m_map_desc(idx + 1, 7, RG, 0, 8); m_map_desc(idx + 2, 7, RG + 0x10000, 0, 8); break;
        case 18: m_map_desc(idx, 0, RG + 0x800, 0x20, 1); break;
        case 19: m_map_desc(idx, 0, RG, 1ull << 40, 1); break;
        case 20: m_map_desc(idx, 0, 1ull << 48, 1, 1); break;
        case 21: m_map_desc(idx, 0, RG, 0x20, 1); for (unsigned k = 0; k < 8; k++) m_map_desc(idx + 1 + k, 0, RG + 0x1000ull * k, 1, 1); break;
        case 22: m_map_desc(idx, 0, 0x90000000ull, 1, 1); for (unsigned k = 0; k < 8; k++) m_map_desc(idx + 1 + k, 0, RG + 0x4000ull * k, 4, 1); break;
        case 23: m_map_desc(226, 0, RG, 0x20, 1); m_map_desc(idx, 0, 0x90000000ull, 1, 1); break;
        case 24: m_map_desc(0, 0, RG, 0x20, 1); m_map_desc(idx, 0, 0x90000000ull, 1, 1); break;
        case 25: m_map_desc(5, 1, 0x80000800ull, 4, 8); break;
        case 26: m_map_desc(idx, 0, RG, 0x20, 1); m_map_desc(200, 1, RG + 0x8000, 1, 8); break;
        case 27: m_map_unit_s(227, 40); break;
        case 28: m_map_unit_s(227, 56); break;
        case 29: m_map_unit_s(227, 64); break;
        case 30: m_map_unit_s(227, 128); break;
        case 31: m_map_stride = 32; m_map_size = 227 * 32; break;
        case 32: m_map_stride = 44; m_map_size = 44 * 100; break;
        case 33: m_map_stride = 136; m_map_size = 136 * 100; break;
        case 34: m_map_stride = 0; break;
        case 35: m_map_size = 0; break;
        case 36: m_map_size = 227 * 48 + 8; break;
        case 37: m_map_unit_s(321, 48); break;
        case 38: m_map_unit_s(320, 48); break;
        case 39: m_map_base = XMAP_BASE + 4; break;
        case 40: m_map_base = 0; break;
        case 41: m_map_desc(idx, 0, RG, 0x20, 8); break;
        case 42: m_map_desc(idx, 0, 0xFFFFFFFFFFFFF000ull, 0x2000, 1); break;
        default: m_map_desc(idx, 0, RG, 1ull << 52, 1); break;
        }
        RUN_CLEAN();
        CHECKM(m_om.state == c[i].want, c[i].name);
        CHECKM(m_find("CMDDB MAP", 0) >= 0 && strstr(m_text((unsigned)m_find("CMDDB MAP", 0)), OM_NAME[c[i].want]), c[i].name);
        CHECKM(c[i].want == OM_OPEN ? m_loaded(XW_CMDDB, 0) : !m_loaded(XW_CMDDB, 0), c[i].name);
        CHECKM(c[i].want == OM_OPEN ? m_find("CMDDB HDR", 0) >= 0 : m_gate_line("CMDDB", "MAP"), c[i].name);
        CHECKM(PAGE_IS_ORACLE(), c[i].name);
        /* Arguments that do not describe a map are refused before a word of it is read. */
        if ((i >= 31 && i <= 37) || i == 39 || i == 40) CHECKM(m_loads_of_block(B_CMDDB) == 0, c[i].name);
        if (i == 0) CHECK(m_item_is("CMDDB MAP", "HITS", "1", __LINE__) && m_item_is("CMDDB MAP", "ATTR", "1", __LINE__) && m_item_is("CMDDB MAP", "T", "0", __LINE__));
        if (i == 41) CHECK(m_item_is("CMDDB MAP", "ATTR", "8", __LINE__));
    }
    /* An abort on a map word: ERR, with the word's own token, the block gated and nothing of the database read. */
    for (unsigned w = 0; w < 4; w++) {
        static const unsigned off[4] = {8, 12, 24, 28};
        m_fx_unit();
        m_fault_at(XMAP_BASE + 48 * 100 + off[w]);
        RUN_CLEAN();
        CHECK(m_find("CMDDB MAP", 0) >= 0 && strstr(m_text((unsigned)m_find("CMDDB MAP", 0)), "FAULT:6 ERR") && m_gate_line("CMDDB", "MAP") && !m_loaded(XW_CMDDB, 0));
    }
    return 0;
}

/* ---- cmddb ---- */
static void m_db_fill_list(unsigned hdr, unsigned slv, unsigned hoff, unsigned doff, unsigned cnt, const char *prefix)
{
    char id[16];
    m_db_header(hdr, slv, hoff, doff, cnt);
    for (unsigned j = 0; j < cnt; j++) {
        snprintf(id, sizeof id, "%s%03u", prefix, j);
        m_db_entry(DB_A + hoff + 24 * j, id, 0x60000 + 4 * j, 0, 0);
    }
}

static int suite_cmddb(void)
{
    static const unsigned lv[] = {16, 48, 64, 128, 192, 256, 320, 384, 416, 448, 512, 640};
    /* The nominal database: what the page shows, by hand. */
    m_fx_unit();
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE());
    CHECK(m_line_is((unsigned)m_find("CMDDB HDR", 0), "CMDDB HDR VER=1 MAGIC=OK HDRS=3 ARC=8 BCM=6", __LINE__));
    CHECK(m_line_is((unsigned)m_find("CMDDB ADDR", 0), "CMDDB ADDR CX=0X30000 MX=0X30004 GFX=0X3000C GMXC=0X30010 GBX=0X30014", __LINE__));
    CHECK(m_line_is((unsigned)m_find("CMDDB BCM", 0), "CMDDB BCM SH0=0X50008 MC0=0X50004 ACV=0X50000", __LINE__));
    CHECK(m_line_is((unsigned)m_find("CMDDB LVL", 0), "CMDDB LVL CX=9:16/48/64/128/192/256/320/384 MX=8:16/48/64/128/192/256/384/416", __LINE__));
    CHECK(m_line_is((unsigned)m_find("CMDDB LVL", 0) + 1, "CMDDB LVL GFX=7:16/48/64/128/192/256/384 GMXC=4:16/64/128/256", __LINE__));
    /* A byte of the magic wrong: the header says BAD, nothing but the version and the magic is read. */
    for (unsigned b = 4; b < 8; b++) {
        m_fx_unit();
        m_db[b] ^= 0x10;
        RUN_CLEAN();
        CHECK(PAGE_IS_ORACLE());
        CHECK(m_gate_line("CMDDB", "MAGIC") && m_loads_of_block(B_CMDDB) == 4 * 227 + 2 + 2);
    }
    /* Ids in the wrong kind of list, duplicates, a second word that differs, headers of other kinds, entries that cannot be read: what each leaves found, by hand (two items of the page each). */
    {
        static const struct { const char *h1, *k1, *w1, *h2, *k2, *w2; } x[18] = {
            {"CMDDB BCM", "ACV", "NONE", "CMDDB ADDR", "CX", "0X30000"},          /* 0 cx.lvl in the BCM list in place of ACV: that list is looked at for BCMs only */
            {"CMDDB ADDR", "MX", "NONE", "CMDDB BCM", "SH0", "0X50008"},          /* 1 SH0 in the ARC list in place of mx.lvl */
            {"CMDDB ADDR", "CX", "0X30000", "CMDDB ADDR", "GFX", "0X3000C"},      /* 2 a second cx.lvl later: the first wins */
            {"CMDDB ADDR", "GFX", "NONE", "CMDDB ADDR", "GMXC", "0X30010"},       /* 3 gfx.lvl2: the second word differs */
            {"CMDDB ADDR", "GFX", "NONE", "CMDDB ADDR", "GBX", "0X30014"},        /* 4 gfx.lv: the second word differs */
            {"CMDDB ADDR", "CX", "NONE", "CMDDB BCM", "MC0", "0X50004"},          /* 5 the ARC list declared VRM: not walked */
            {"CMDDB ADDR", "CX", "NONE", "CMDDB BCM", "SH0", "NONE"},             /* 6 the first header has no slave id: the list of headers ends there */
            {"CMDDB HDR", "ARC", "12", "CMDDB ADDR", "CX", "0X30000"},            /* 7 a second ARC list (the four VRM entries) */
            {"CMDDB HDR", "ARC", "16", "CMDDB HDR", "HDRS", "4"},                 /* 8 the same list again as a fourth header */
            {"CMDDB HDR", "ARC", "0", "CMDDB ADDR", "CX", "NONE"},                /* 9 an empty ARC list */
            {"CMDDB HDR", "ARC", "65535", "CMDDB ADDR", "CX", "0X30000"},         /* 10 more entries than the cap: the ones inside it are read */
            {"CMDDB ADDR", "CX", "0", "CMDDB ADDR", "MX", "0X30004"},             /* 11 cx.lvl with address 0 */
            {"CMDDB HDR", "BCM", "65535", "CMDDB BCM", "SH0", "0X50008"},         /* 12 */
            {"CMDDB ADDR", "CX", "NA", "CMDDB ADDR", "GBX", "NA"},                /* 13 a list at an offset that is not word aligned: not readable by a 32-bit load */
            {"CMDDB HDR", "ARC", "14", "CMDDB BCM", "SH0", "NONE"},               /* 14 the BCM list declared ARC */
            {"CMDDB HDR", "BCM", "14", "CMDDB BCM", "SH0", "0X50008"},            /* 15 the ARC list declared BCM: its names are not the BCMs' and the real list is read too */
            {"CMDDB ADDR", "CX", "NA", "CMDDB BCM", "SH0", "NA"},                 /* 16 a list at an offset of 2 */
            {"CMDDB HDR", "HDRS", "8", "CMDDB ADDR", "CX", "0X30000"}};           /* 17 eight headers, four of them ARC lists of the same entries */
        for (unsigned i = 0; i < 18; i++) {
            m_fx_unit();
            switch (i) {
            case 0: m_db_entry(DB_A + 288, "cx.lvl", 0x30000, 18, 0); break;
            case 1: m_db_entry(DB_A + 24, "SH0", 0x50008, 0, 0); break;
            case 2: m_db_entry(DB_A + 48, "cx.lvl", 0x31111, 4, 0x80); break;
            case 3: m_db_entry(DB_A + 72, "gfx.lvl2", 0x3000c, 14, 0x40); break;
            case 4: m_db_entry(DB_A + 72, "gfx.lv", 0x3000c, 14, 0x40); break;
            case 5: m_db_header(0, 4, 0, 0x400, 8); break;
            case 6: m_db_header(0, 0, 0, 0x400, 8); break;
            case 7: m_db_header(1, 3, 24 * 8, 0x500, 4); break;
            case 8: m_db_header(3, 3, 0, 0x400, 8); break;
            case 9: m_db_header(0, 3, 0, 0x400, 0); break;
            case 10: m_db_header(0, 3, 0, 0x400, 0xffff); break;
            case 11: m_put32(m_db + DB_A + 16, 0); break;
            case 12: m_db_header(2, 5, 24 * 12, 0x600, 0xffff); break;
            case 13: m_db_header(0, 3, 0xffff, 0x400, 128); break;
            case 14: m_db_header(2, 3, 24 * 12, 0x600, 6); break;
            case 15: m_db_header(0, 5, 0, 0x400, 8); break;
            case 16: m_db_header(0, 3, 2, 0x400, 8); break;
            default: for (unsigned k = 3; k < 8; k++) m_db_header(k, 3, 0, 0x400, 8); break;
            }
            RUN_CLEAN();
            CHECKM(PAGE_IS_ORACLE(), "a variant of the lists");
            CHECKM(m_item_is(x[i].h1, x[i].k1, x[i].w1, __LINE__) && m_item_is(x[i].h2, x[i].k2, x[i].w2, __LINE__), "what the variant leaves found");
        }
    }
    /* Long lists: the cap of 128 entries in a list, and 256 in all. */
    m_fx_unit();
    m_db_fill_list(0, 3, 0, 0x2000, 300, "f");
    m_db_entry(DB_A + 24 * 0, "cx.lvl", 0x30000, 0, 0);
    m_db_entry(DB_A + 24 * 5, "mx.lvl", 0x30004, 0, 0);
    m_db_entry(DB_A + 24 * 127, "gbx.lvl", 0x30014, 0, 0);
    m_db_entry(DB_A + 24 * 130, "gmxc.lvl", 0x30010, 0, 0);
    m_db_entry(DB_A + 24 * 200, "gfx.lvl", 0x3000c, 0, 0);
    m_db_header(1, 0, 0, 0, 0);
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE());
    CHECK(m_item_is("CMDDB ADDR", "CX", "0X30000", __LINE__) && m_item_is("CMDDB ADDR", "GBX", "0X30014", __LINE__) && m_item_is("CMDDB ADDR", "GFX", "PART", __LINE__) &&
          m_item_is("CMDDB ADDR", "GMXC", "PART", __LINE__) && m_item_is("CMDDB BCM", "SH0", "NONE", __LINE__));
    m_fx_unit();
    m_db_fill_list(0, 3, 0, 0x6000, 100, "a");
    m_db_fill_list(1, 3, 24 * 100, 0x6000, 100, "b");
    m_db_fill_list(2, 3, 24 * 200, 0x6000, 100, "c");
    m_db_entry(DB_A + 24 * 250, "gfx.lvl", 0x3000c, 0, 0);       /* the 251st entry: inside the cap of 256 in all */
    m_db_entry(DB_A + 24 * 260, "gmxc.lvl", 0x30010, 0, 0);      /* the 261st: beyond it */
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE());
    CHECK(m_item_is("CMDDB ADDR", "GFX", "0X3000C", __LINE__) && m_item_is("CMDDB ADDR", "GMXC", "PART", __LINE__) && m_item_is("CMDDB BCM", "SH0", "NONE", __LINE__));
    /* The level tables: lengths, offsets, alignment, the end of the region. `aux` is the table's byte offset in the database; the sequence 16, 48, 64 ... is written at DB_A + 0x400. */
    {
        static const struct { unsigned len, aux; const char *want; } t[] = {
            {0, DB_A + 0x400, "EMPTY"}, {1, DB_A + 0x400, "EMPTY"}, {2, DB_A + 0x400, "1:16"}, {3, DB_A + 0x400, "1:16"}, {4, DB_A + 0x400, "2:16/48"},
            {16, DB_A + 0x400, "8:16/48/64/128/192/256/320/384"}, {18, DB_A + 0x400, "9:16/48/64/128/192/256/320/384"}, {0xffff, DB_A + 0x400, "32767:16/48/64/128/192/256/320/384"},
            {4, DB_A + 0x401, "ODD"}, {4, DB_A + 0x403, "ODD"}, {4, DB_A + 0x402, "2:48/64"}, {6, DB_A + 0x402, "3:48/64/128"}, {16, DB_A + 0x402, "8:48/64/128/192/256/320/384/416"},
            {2, DB_A + 0x402, "1:48"}, {4, 0x1fffc, "2:0/0"}, {2, 0x1fffe, "1:0"}, {6, 0x1fffc, "RANGE"}, {4, 0x1fffe, "RANGE"}, {4, 0x20000, "RANGE"}, {2, 0x20002, "RANGE"},
            {2, 0x1fffc, "1:0"}, {16, 0x1fff0, "8:0/0/0/0/0/0/0/0"}, {18, 0x1fff0, "9:0/0/0/0/0/0/0/0"}, {14, 0x1fff2, "7:0/0/0/0/0/0/0"}, {16, 0x1fff2, "RANGE"}, {18, 0x1fff2, "RANGE"}};
        for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
            unsigned d = t[i].aux - 0x90, doff = d > 0xffff ? 0xffff : d, off = d - doff;
            m_fx_unit();
            m_db_levels(DB_A + 0x400, 12, lv);
            m_db_entry(DB_A + 0, "cx.lvl", 0x30000, t[i].len, off);
            m_put16(m_db + 8 + 4, doff);                       /* the ARC header's data offset */
            RUN_CLEAN();
            CHECKM(PAGE_IS_ORACLE(), "a level table");
            CHECKM(m_item_is("CMDDB LVL", "CX", t[i].want, __LINE__), "a level table");
        }
    }
    /* The VRM list is never walked, whatever it holds. */
    m_fx_unit();
    m_db_fill_list(1, 4, 24 * 8, 0x500, 100, "v");
    m_db_entry(DB_A + 24 * 8 + 24 * 50, "gfx.lvl", 0x3999c, 0, 0);
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE());
    CHECK(m_item_is("CMDDB ADDR", "GFX", "0X3000C", __LINE__));
    /* Addresses of eight digits overflow the ADDR line: the item that does not fit is dropped whole, and counted. */
    m_fx_unit();
    for (unsigned i = 0; i < 6; i++) if (i != 2) m_put32(m_db + DB_A + 24 * i + 16, 0x12345670u + i);
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE() && m_end_field("CUTS") >= 1);
    CHECK(m_line_is((unsigned)m_find("CMDDB ADDR", 0), "CMDDB ADDR CX=0X12345670 MX=0X12345671 GFX=0X12345673 GMXC=0X12345674", __LINE__));
    /* A line of exactly 100 characters keeps its last item; one of 101 drops it whole and counts it. */
    for (unsigned wide = 0; wide < 2; wide++) {
        static const unsigned cxv[] = {100, 101, 102, 103, 104, 105, 106, 107}, mxv[] = {200, 201, 202, 203, 204, 205, 206, 207}, mxw[] = {2000, 201, 202, 203, 204, 205, 206, 207};
        m_fx_unit();
        m_db_levels(DB_A + 0x800, 8, cxv);
        m_db_levels(DB_A + 0x820, 8, wide ? mxw : mxv);
        m_db_entry(DB_A + 0, "cx.lvl", 0x30000, 16, 0);
        m_put16(m_db + 8 + 4, 0x800);                          /* the ARC header's data offset */
        RUN_CLEAN();
        CHECKM(PAGE_IS_ORACLE(), "a level line at the width of the page");
        CHECKM(m_line_is((unsigned)m_find("CMDDB LVL", 0), wide ? "CMDDB LVL CX=8:100/101/102/103/104/105/106/107"
                                                                : "CMDDB LVL CX=8:100/101/102/103/104/105/106/107 MX=8:200/201/202/203/204/205/206/207", __LINE__), "a level line at the width of the page");
        CHECKM(wide ? m_end_field("CUTS") >= 1 : m_end_field("CUTS") == 0, "a level line at the width of the page");
    }
    /* Aborts in the database: the token of the word that did not read is on every item it left undecided. */
    {
        static const struct { unsigned off; const char *hdr, *addr, *bcm, *lvl; } f[] = {
            {0, "CMDDB HDR VER=FAULT:6 MAGIC=SKIP", NULL, NULL, NULL},
            {4, "CMDDB HDR VER=1 MAGIC=FAULT:6", NULL, NULL, NULL},
            {8 + 16, "CMDDB HDR VER=1 MAGIC=OK HDRS=1 FAIL=FAULT:6 ARC=8 BCM=0", "CMDDB ADDR CX=FAULT:6 MX=FAULT:6 GFX=FAULT:6 GMXC=FAULT:6 GBX=FAULT:6",
             "CMDDB BCM SH0=FAULT:6 MC0=FAULT:6 ACV=FAULT:6", "CMDDB LVL CX=FAULT:6 MX=FAULT:6"},
            {DB_A, "CMDDB HDR VER=1 MAGIC=OK HDRS=3 ARC=8 BCM=6", "CMDDB ADDR CX=FAULT:6 MX=FAULT:6 GFX=FAULT:6 GMXC=FAULT:6 GBX=FAULT:6",
             "CMDDB BCM SH0=FAULT:6 MC0=FAULT:6 ACV=FAULT:6", "CMDDB LVL CX=FAULT:6 MX=FAULT:6"},
            {DB_A + 24 * 3, "CMDDB HDR VER=1 MAGIC=OK HDRS=3 ARC=8 BCM=6", "CMDDB ADDR CX=0X30000 MX=0X30004 GFX=FAULT:6 GMXC=FAULT:6 GBX=FAULT:6",
             "CMDDB BCM SH0=FAULT:6 MC0=FAULT:6 ACV=FAULT:6", "CMDDB LVL CX=9:SKIP MX=8:SKIP"},
            {DB_A + 0x400, "CMDDB HDR VER=1 MAGIC=OK HDRS=3 ARC=8 BCM=6", "CMDDB ADDR CX=0X30000 MX=0X30004 GFX=0X3000C GMXC=0X30010 GBX=0X30014",
             "CMDDB BCM SH0=0X50008 MC0=0X50004 ACV=0X50000", "CMDDB LVL CX=9:FAULT:6 MX=8:SKIP"}};
        for (unsigned i = 0; i < sizeof f / sizeof f[0]; i++) {
            m_fx_unit();
            m_rfault(XW_CMDDB, f[i].off);
            RUN_CLEAN();
            CHECKM(m_line_is((unsigned)m_find("CMDDB HDR", 0), f[i].hdr, __LINE__), "the header line of an abort in the database");
            if (f[i].addr) CHECKM(m_line_is((unsigned)m_find("CMDDB ADDR", 0), f[i].addr, __LINE__) && m_line_is((unsigned)m_find("CMDDB BCM", 0), f[i].bcm, __LINE__) &&
                                  m_line_is((unsigned)m_find("CMDDB LVL", 0), f[i].lvl, __LINE__), "the address and level lines of an abort in the database");
            else CHECK(m_gate_line("CMDDB", "MAGIC") && m_find("CMDDB ADDR", 0) < 0);
            CHECK(m_aborted == 1 && m_find("NEXT RSC2", 0) >= 0);
        }
    }
    return 0;
}

/* ---- rsc ---- */
static int suite_rsc(void)
{
    unsigned en, ad, da, st;
    /* The nominal RSC in both layouts. */
    for (unsigned major = 2; major <= 3; major++) {
        m_fx_unit();
        m_fx_rsc(major);
        RUN_CLEAN();
        CHECK(PAGE_IS_ORACLE());
        CHECK(m_item_is("RSC2", "VER", major == 2 ? "2.7" : "3.7", __LINE__));
        CHECK(m_line_is((unsigned)m_find("RSC2 W5", 0), "RSC2 W5 N=3 CX=64 MX=64 GFX=- GMXC=-", __LINE__));
        CHECK(m_line_is((unsigned)m_find("RSC2 W6", 0), "RSC2 W6 N=3 CX=128 MX=128 GFX=- GMXC=-", __LINE__));
        CHECK(m_item_is("RSC2 EN", "W5", "7", __LINE__) && m_item_is("RSC2 EN", "S3", "3", __LINE__) && m_item_is("RSC2 EN", "A0", "0", __LINE__));
        CHECK(m_loads_of_block(B_RSC) == 22);      /* five words, seven masks, three addresses in each wake TCS and the data of two of them */
    }
    /* The ID: not a block's, and a version that is not one of the two layouts. */
    {
        static const uint32_t id[] = {0, 0xffffffffu, 1u << 16, 4u << 16, 0xffu << 16, 0x00020000u, 0x00030000u, 0x000207ffu, 0x0003ff00u, 0x00010701u, 0x00040701u, 0x02020701u, 0x00020701u | 0xff000000u};
        for (unsigned i = 0; i < sizeof id / sizeof id[0]; i++) {
            m_fx_unit();
            m_rset(XW_RSC, 0, id[i]);
            RUN_CLEAN();
            if (!id[i] || id[i] == 0xffffffffu) CHECK(m_gate_line("RSC2", "ID") && m_loads_of_block(B_RSC) == 1);
            else if ((id[i] >> 16 & 0xff) != 2 && (id[i] >> 16 & 0xff) != 3) CHECK(m_gate_line("RSC2", "VER") && m_loads_of_block(B_RSC) == 1);
            else CHECK(m_loads_of_block(B_RSC) > 5);
            CHECK(PAGE_IS_ORACLE());
        }
    }
    m_fx_unit();
    m_rfault(XW_RSC, 0);
    RUN_CLEAN();
    CHECK(m_find("RSC2 ID=FAULT:6", 0) >= 0 && m_gate_line("RSC2", "ID") && m_loads_of_block(B_RSC) == 1 && m_find("QFPROM", 0) >= 0);
    /* The TCS count of drv-2: fewer than seven closes the block after its configuration line; every count is shifted out of the right bits. */
    for (unsigned nt = 0; nt < 64; nt++) {
        m_fx_unit();
        m_rset(XW_RSC, 0x0c, (m_rand() & 0xf8000fffu) | nt << 12 | (m_rand() & 0x3ffu) << 18);
        RUN_CLEAN();
        CHECK(PAGE_IS_ORACLE());
        CHECK(nt < 7 ? m_gate_line("RSC2", "TCS") && m_loads_of_block(B_RSC) == 5 : m_loads_of_block(B_RSC) >= 12);
    }
    m_fx_unit();
    m_rset(XW_RSC, 0x0c, 0xffffffffu);
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE() && m_gate_line("RSC2", "TCS") && m_item_is("RSC2 CFG", "CHLD", "0XFFFFFFFF", __LINE__) && !m_item(m_text((unsigned)m_find("RSC2 CFG", 0)), "NT"));
    /* Enable masks: all ones and a bit above 15 are not masks (.ODD, and no command of that TCS is read); 16 commands, all rails, the last for a rail wins. */
    for (unsigned major = 2; major <= 3; major++) {
        static const uint32_t masks[] = {0, 1, 0x8000, 0xffff, 0x10000, 0xffffffffu, 0x7fff, 0x0005, 0x80000001u};
        for (unsigned i = 0; i < sizeof masks / sizeof masks[0]; i++) {
            m_fx_unit();
            m_fx_rsc(major);
            m_rsc_layout(&en, &ad, &da, &st);
            for (unsigned j = 0; j < 16; j++) {
                static const uint32_t rail[6] = {0x30000, 0x30004, 0x3000c, 0x30010, 0x50000, 0x30000};
                m_rsc_cmd(5, j, rail[j % 6], 100 + j);
                m_rsc_cmd(6, j, rail[(j + 1) % 6], 0x10000 + j);
            }
            m_rset(XW_RSC, 0xd00 + 672 * 5 + en, masks[i]);
            m_rset(XW_RSC, 0xd00 + 672 * 6 + en, masks[(i + 3) % 9]);
            m_rset(XW_RSC, 0xd00 + 672 * 2 + en, masks[(i + 5) % 9]);
            RUN_CLEAN();
            CHECK(PAGE_IS_ORACLE());
        }
    }
    m_fx_unit();
    m_rsc_layout(&en, &ad, &da, &st);
    m_rset(XW_RSC, 0xd00 + 672 * 5 + en, 0xffff);
    for (unsigned j = 0; j < 16; j++) m_rsc_cmd(5, j, j < 8 ? 0x30000 : 0x30010, 200 + j);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("RSC2 W5", 0), "RSC2 W5 N=16 CX=207 MX=- GFX=- GMXC=215", __LINE__));
    m_rset(XW_RSC, 0xd00 + 672 * 5 + en, 0x10000);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("RSC2 W5", 0), "RSC2 W5 N=NA CX=NA MX=NA GFX=NA GMXC=NA", __LINE__) && m_item_is("RSC2 EN", "W5", "0X10000.ODD", __LINE__));
    /* A vote that is not a level number prints in hex; a vote of 0 is a vote. */
    m_fx_unit();
    m_rsc_cmd(5, 0, 0x30000, 0x12345);
    m_rsc_cmd(5, 1, 0x30004, 0);
    m_rsc_cmd(5, 2, 0x3000c, 416);
    RUN_CLEAN();
    CHECK(m_item_is("RSC2 W5", "CX", "0X12345", __LINE__) && m_item_is("RSC2 W5", "MX", "0", __LINE__) && m_item_is("RSC2 W5", "GFX", "416", __LINE__));
    /* What the database gives: no database (the map says TYPE), a rail missing, a rail at address 0. */
    m_fx_unit();
    m_map_desc(113, 7, RG, 0x20, 1);
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE() && m_item_is("RSC2 W5", "CX", "NA", __LINE__) && m_item_is("RSC2 W5", "N", "3", __LINE__) && m_loads_of_block(B_RSC) == 5 + 7 + 6);
    m_fx_unit();
    m_db_entry(DB_A + 72, "xfx.lvl", 0x3000c, 14, 0x40);
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE() && m_item_is("RSC2 W5", "GFX", "NA", __LINE__) && m_item_is("RSC2 W5", "CX", "64", __LINE__));
    m_fx_unit();
    m_put32(m_db + DB_A + 16, 0);
    m_rsc_cmd(5, 0, 0, 77);
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE() && m_item_is("RSC2 W5", "CX", "NA", __LINE__));
    /* Aborts inside a wake line: the words after it say SKIP or the fault, and the rails not yet decided carry the fault's token. */
    m_fx_unit();
    m_rsc_layout(&en, &ad, &da, &st);
    m_rfault(XW_RSC, 0xd00 + 672 * 5 + ad + st * 1);
    RUN_CLEAN();
    CHECK(m_line_is((unsigned)m_find("RSC2 W5", 0), "RSC2 W5 N=3 CX=64 MX=FAULT:6 GFX=FAULT:6 GMXC=FAULT:6", __LINE__) && m_find("RSC2 W6", 0) >= 0);
    m_fx_unit();
    m_rsc_layout(&en, &ad, &da, &st);
    m_rfault(XW_RSC, 0xd00 + 672 * 5 + da);
    RUN_CLEAN();
    CHECK(m_item_is("RSC2 W5", "CX", "FAULT:6", __LINE__) && m_item_is("RSC2 W5", "MX", "FAULT:6", __LINE__));
    return 0;
}

/* ---- the gates, by the loads they keep out ---- */
static int suite_gates(void)
{
    m_fx_unit();
    m_rset(XW_GCC, 0x71004, 0x80000001u);
    RUN_CLEAN();
    CHECK(m_loads_of_block(B_GPUCC) == 0 && m_gate_line("GPUCC", "AHB") && m_loads_of_block(B_CMDDB) > 900 && m_loads_of_block(B_RSC) == 22);
    m_fx_unit();
    m_map_desc(113, 11, RG, 0x20, 1);
    RUN_CLEAN();
    CHECK(m_loads_of_block(B_CMDDB) == 4 * 227 + 2 && m_gate_line("CMDDB", "MAP") && !m_loaded(XW_CMDDB, 0) && m_loads_of_block(B_RSC) > 5);
    m_fx_unit();
    m_db[5] = 0;
    RUN_CLEAN();
    CHECK(m_loads_of_block(B_CMDDB) == 4 * 227 + 2 + 2 && m_gate_line("CMDDB", "MAGIC") && m_item_is("CMDDB HDR", "MAGIC", "BAD", __LINE__));
    m_fx_unit();
    m_rset(XW_RSC, 0x0c, 6u << 12);
    RUN_CLEAN();
    CHECK(m_loads_of_block(B_RSC) == 5 && m_gate_line("RSC2", "TCS") && m_find("RSC2 EN", 0) < 0 && m_find("QFPROM", 0) >= 0);
    m_fx_unit();
    m_rset(XW_TSROT, 0, 0);
    RUN_CLEAN();
    CHECK(m_loads_of_block(B_TSENS) == 1 && m_find("T3 VER=0 GATED", 0) >= 0 && m_loads_of_block(B_GPUCC) == 21);
    /* Nothing behind the CX domain, no GX register and no other RSC driver is ever read, whatever the world. */
    for (unsigned w = 0; w < 40; w++) {
        m_fx_unit();
        if (w & 1) m_rset(XW_GCC, 0x71004, 0x80000001u);
        if (w & 2) m_rset(XW_GPUCC, 0x953c, 0x80000000u);
        if (w & 4) m_rset(XW_RSC, 0, 3u << 16);
        m_rand_seed = w + 1;
        RUN_CLEAN();
        for (unsigned k = 0; k < m_nloadlog; k++) {
            uint64_t a = m_loadlog[k].addr;
            CHECK(!(a >= 0x03d00000u && a < 0x03d90000u) && !(a >= 0x03d9a000u && a < 0x03e00000u) && !(a >= 0x17500000u && a < 0x17520000u) && !(a >= 0x17530000u && a < 0x17600000u));
        }
    }
    return 0;
}

/* ---- aborts ---- */
static int suite_faults(void)
{
    unsigned clean;
    m_fx_unit();
    RUN_CLEAN();
    clean = m_nloads;
    for (unsigned k = 0; k < clean; k++) {
        m_fx_unit();
        m_abort_nth = (int)k;
        RUN_CLEAN();
        CHECK(m_aborted == 1 && m_end_field("FAULTS") == 1 && m_find("QFPROM", 0) >= 0);
    }
    for (unsigned k = 0; k < clean; k += 5) {
        m_fx_unit();
        m_abort_from_nth = (int)k;
        RUN_CLEAN();
        CHECK(m_aborted >= 1 && m_find("QFPROM", 0) >= 0);
    }
    /* Every window aborts on its first load: the five that are read each once, the gates all closed or the blocks dead, every block still printed. */
    m_fx_unit();
    m_win_faults = (1u << XW_COUNT) - 1;
    RUN_CLEAN();
    CHECK(m_aborted == 5 && m_find("T3 VER=FAULT:6 GATED", 0) >= 0 && m_find("GCC CFGA=FAULT:6", 0) >= 0 && m_gate_line("GPUCC", "AHBERR") && m_find("RSC2 ID=FAULT:6", 0) >= 0 &&
          m_find("QFPROM W118=FAULT:6", 0) >= 0 && m_gate_line("CMDDB", "MAP"));
    /* An abort on the first word of each block's window, one at a time, leaves the other blocks as they were. */
    for (unsigned w = 0; w < XW_COUNT; w++) {
        m_fx_unit();
        m_win_faults = 1u << w;
        RUN_CLEAN();
        CHECK(m_aborted == 1);
    }
    return 0;
}

/* ---- hangs ---- */
static int suite_hang(void)
{
    static char clean_lines[64][240];
    static unsigned before[4200];
    static uint8_t block[4200];
    unsigned clean_n, clean_loads;
    m_fx_unit();
    RUN_CLEAN();
    clean_n = m_nlines;
    clean_loads = m_nloads;
    CHECK(clean_loads < 4200);
    for (unsigned i = 0; i < clean_n; i++) memcpy(clean_lines[i], m_lines[i], sizeof clean_lines[i]);
    for (unsigned k = 0; k < clean_loads; k++) {
        before[k] = m_loadlog[k].nlines;
        block[k] = m_loadlog[k].block;
    }
    for (unsigned k = 0; k < clean_loads; k++) {
        m_fx_unit();
        m_hang_nth = (int)k;
        (void)m_run();
        CHECK(m_hung && m_violations == 0);
        CHECK(m_nlines == before[k] && m_nloads == k + 1);
        for (unsigned i = 0; i < m_nlines; i++) CHECK(!strcmp(m_lines[i], clean_lines[i]));
        CHECK(m_last_line_of(block[k]));
    }
    return 0;
}

/* ---- random and hostile worlds ---- */
static uint32_t m_rword(void)
{
    static const uint32_t kind[] = {0, 1, 0x80000000u, 0x80000001u, 0xffffffffu, 0xA0000001u, 0x7ffffffeu, 2, 3, 0x20000001u};
    switch (m_rand() % 4) {
    case 0: return kind[m_rand() % 10];
    case 1: return m_rand() & 0xff;
    default: return m_rand() ^ (uint32_t)(m_rand() << 7);
    }
}

static void m_perturb(void)
{
    unsigned n = 1 + m_rand() % 8;
    for (unsigned i = 0; i < n; i++) {
        switch (m_rand() % 10) {
        case 0: case 1: {
            const struct m_reg *r = &M_REGS[m_rand() % M_NREGS];
            m_rset(r->win, r->off, m_rword());
            break;
        }
        case 2: m_db[m_rand() % 0x90] ^= (uint8_t)(1u << (m_rand() % 8)); break;
        case 3: m_db[0x90 + m_rand() % 0x700] = (uint8_t)m_rand(); break;
        case 4: m_put32(m_db + 4 * (m_rand() % 0x30), m_rword()); break;
        case 5: {
            unsigned d = m_rand() % 227, f = (unsigned[]){0, 8, 12, 24, 28, 32}[m_rand() % 6];
            m_put32(m_map + d * 48 + f, m_rword());
            break;
        }
        case 6: m_put32(m_map + 113 * 48 + (unsigned[]){0, 8, 12, 24, 28}[m_rand() % 5], m_rword()); break;
        case 7: m_rset(XW_RSC, (uint32_t[]){0, 4, 0xc, 0xd00, 0xd04}[m_rand() % 5], m_rword()); break;
        case 8: {
            unsigned en, ad, da, st;
            if (m_rsc_layout(&en, &ad, &da, &st)) m_rset(XW_RSC, 0xd00 + 672 * (m_rand() % 7) + (m_rand() & 1 ? en : (m_rand() & 1 ? ad : da) + st * (m_rand() % 16)), m_rword());
            break;
        }
        default: m_rset(XW_TTM, 0xa0 + 4 * (5 + m_rand() % 8), m_status((int)(m_rand() % 1500) - 200, m_rand() % 32)); break;
        }
    }
}

static int suite_random(void)
{
    for (unsigned i = 0; i < 1500; i++) {
        m_fx_unit();
        if (i & 1) m_fx_rsc(3);
        m_perturb();
        RUN_CLEAN();
        CHECKM(PAGE_IS_ORACLE(), "a random world against the oracle");
    }
    for (unsigned i = 0; i < 600; i++) {
        m_fx_unit();
        m_perturb();
        if (i % 3 == 0) m_abort_nth = (int)(m_rand() % 600);
        if (i % 3 == 1) m_abort_from_nth = (int)(m_rand() % 1200);
        if (i % 3 == 2) m_fault_at(XW[XW_GPUCC].base + 0x9100 + 4 * (m_rand() % 16));
        RUN_CLEAN();
        CHECK(m_nlines >= 5);
    }
    return 0;
}

static int suite_storm(void)
{
    static const uint32_t fills[] = {0, 0xffffffffu, 0x80000000u, 0x7fffffffu, 1, 0x80000001u, 3, 0x20000000u};
    for (unsigned f = 0; f < sizeof fills / sizeof fills[0]; f++) {
        m_fx_unit();
        m_fill_all = 1;
        m_fill = fills[f];
        RUN_CLEAN();
        CHECK(PAGE_IS_ORACLE());
    }
    for (unsigned f = 0; f < sizeof fills / sizeof fills[0]; f++) {
        for (unsigned part = 0; part < 4; part++) {
            m_fx_unit();
            for (unsigned i = 0; i < sizeof m_db; i += 4) if (part & 1) m_put32(m_db + i, fills[f]);
            for (unsigned i = 0; i < 227 * 48; i += 4) if (part & 2) m_put32(m_map + i, fills[(f + 1) % 8]);
            m_fill_all = part == 3;
            m_fill = fills[(f + 2) % 8];
            RUN_CLEAN();
            CHECK(PAGE_IS_ORACLE());
        }
    }
    /* A world where every register reads pseudo-random words, in several seeds. */
    for (unsigned s = 1; s <= 200; s++) {
        m_fx_reset();
        m_rand_seed = s * 0x1234567ull;
        m_db_unit();
        m_map_unit(227);
        RUN_CLEAN();
        CHECK(PAGE_IS_ORACLE());
    }
    return 0;
}

/* ---- the budget ---- */
static unsigned m_stage_words(void)
{
    unsigned n = 0;
    for (unsigned i = 0; i < XDB_BYTES / 4; i++) n += m_od.stage[i] != 0;
    return n;
}

static int suite_budget(void)
{
    /* The nominal run reads every word the oracle names once: the map's and the database's. */
    unsigned map_words = 0;
    m_fx_unit();
    RUN_CLEAN();
    for (unsigned i = 0; i < XMAP_BYTES_MAX / 4; i++) map_words += m_om.read[i];
    CHECK(m_loads_of_block(B_CMDDB) == map_words + m_stage_words() && map_words == 4 * 227 + 2);
    /* The worst world: 320 descriptors with eight that cover the database, two lists of 128 entries whose ids match a target that is never found, and sixteen commands of both wake TCSs
     * for the rails. Its loads reach the bound the header derives, and not past it. */
    m_fx_unit();
    m_map_unit_s(320, 48);
    m_map_desc(160, 0, 0x90000000ull, 1, 1);
    for (unsigned k = 0; k < 8; k++) m_map_desc(10 + k, 0, RG + 0x4000ull * k, 4, 1);
    m_db_unit();
    m_db_fill_list(0, 3, 0, 0x6000, 128, "gbx.lvX");
    m_db_header(1, 5, 24 * 128, 0x6000, 128);
    for (unsigned j = 0; j < 128; j++) {
        m_db_entry(DB_A + 24 * 128 + 24 * j, "MC0", 0x50000 + 4 * j, 0, 0);
        m_db[DB_A + 24 * 128 + 24 * j + 4] = 'x';                  /* the first word is MC0's, which is never found, and the second is not */
    }
    m_db_header(2, 0, 0, 0, 0);
    m_db_entry(DB_A + 0, "cx.lvl", 0x30000, 18, 0);
    m_db_entry(DB_A + 24, "mx.lvl", 0x30004, 16, 0x20);
    m_db_entry(DB_A + 48, "gfx.lvl", 0x3000c, 14, 0x40);
    m_db_entry(DB_A + 72, "gmxc.lvl", 0x30010, 8, 0x60);
    m_db_entry(DB_A + 24 * 128, "SH0", 0x50008, 0, 0);
    m_db_entry(DB_A + 24 * 129, "ACV", 0x50000, 0, 0);
    {
        unsigned en, ad, da, st;
        m_rsc_layout(&en, &ad, &da, &st);
        for (unsigned t = 5; t < 7; t++) {
            m_rset(XW_RSC, 0xd00 + 672 * t + en, 0xffff);
            for (unsigned j = 0; j < 16; j++) m_rsc_cmd(t, j, (uint32_t[]){0x30000, 0x30004, 0x3000c, 0x30010}[j % 4], 10 + j);
        }
    }
    RUN_CLEAN();
    CHECK(PAGE_IS_ORACLE());
    CHECK(m_nloads <= LOADS_MAX && m_nloads + 60 >= LOADS_MAX);
    CHECK(m_item_is("CMDDB MAP", "HITS", "8", __LINE__) && m_find("CMDDB MAP DESC=320 HITS=8 T=0 ATTR=1 OPEN", 0) >= 0);
    CHECK(m_loads_of_block(B_RSC) == 76);
    return 0;
}

/* ---- the arguments ---- */
static int suite_el(void)
{
    for (int el = 0; el < 4; el++) {
        if (el == 2) continue;
        m_fx_unit();
        m_el = el;
        CHECK(m_run() == 0 && m_nloads == 0 && m_nlines == 1 && !strcmp(m_lines[0], PREFIX "SKIPPED_NOT_AT_EL2") && !m_violations);
    }
    m_fx_unit();
    m_have_load32 = 0;
    CHECK(m_run() == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nloads == 0 && m_nlines == 1 && !strcmp(m_lines[0], PREFIX "REFUSED_NO_LOAD32") && !m_violations);
    for (unsigned c = 0; c < 6; c++) {
        struct q1n1_payload_args a;
        m_fx_unit();
        m_reset_run();
        a = m_args();
        switch (c) {
        case 0: a.magic ^= 1; break;
        case 1: a.version++; break;
        case 2: a.size = 100; break;
        case 3: a.ops.puts = NULL; break;
        case 4: a.ops.hex = NULL; break;
        default: break;
        }
        if (c < 5) CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 0 && m_nloads == 0);
        else CHECK(payload_entry(NULL) == Q1N1_PAYLOAD_RET_BAD_ARGS);
    }
    /* The map's arguments are the payload's to check: nothing is dereferenced, whatever they hold. */
    m_fx_unit();
    m_map_base = (1ull << 48) - 8;
    m_map_size = 96;
    RUN_CLEAN();
    CHECK(m_gate_line("CMDDB", "MAP") && m_loads_of_block(B_CMDDB) == 0);
    m_fx_unit();
    m_map_base = ~0ull - 7;
    m_map_size = 48 * 4;
    RUN_CLEAN();
    CHECK(m_gate_line("CMDDB", "MAP") && m_loads_of_block(B_CMDDB) == 0);
    m_fx_unit();
    m_map_size = ~0ull;
    RUN_CLEAN();
    CHECK(m_gate_line("CMDDB", "MAP") && m_loads_of_block(B_CMDDB) == 0);
    return 0;
}

/* ---- the order ---- */
static int suite_order(void)
{
    int at[B_COUNT];
    m_fx_unit();
    RUN_CLEAN();
    for (unsigned b = 0; b < B_COUNT; b++) {
        char next[16];
        snprintf(next, sizeof next, "NEXT %s", B_NAME[b]);
        at[b] = m_find(next, 0);
        CHECK(at[b] >= 0 && (b == 0 || at[b] > at[b - 1]));
    }
    CHECK(at[0] == 2 && m_nlines == 31 && !strncmp(m_lines[m_nlines - 1], PREFIX "END LOADS=", strlen(PREFIX "END LOADS=")));
    for (unsigned k = 1; k < m_nloadlog; k++) CHECK(m_loadlog[k].block >= m_loadlog[k - 1].block);
    CHECK(m_loads_of_block(B_TSENS) == 10 && m_loads_of_block(B_GCC) == 1 && m_loads_of_block(B_GPUCC) == 21 && m_loads_of_block(B_RSC) == 22 && m_loads_of_block(B_QFPROM) == 1);
    CHECK(m_line_is(0, "READ ONLY EL=2 CAP=2048/34", __LINE__) && m_line_is(1, LEGEND, __LINE__));
    /* A block's own lines are between its NEXT line and the next block's, and no other block's. */
    for (unsigned b = 0; b + 1 < B_COUNT; b++) {
        static const char *const head[B_COUNT] = {"T3 ", "GCC ", "GPUCC ", "CMDDB ", "RSC2 ", "QFPROM "};
        if (at[b] < 0 || at[b + 1] < 0) continue;      /* a block that was not announced was already refused above */
        for (unsigned i = (unsigned)at[b] + 1; i < (unsigned)at[b + 1]; i++) CHECKM(!strncmp(m_text(i), head[b], strlen(head[b])), "a line of another block inside a block");
    }
    return 0;
}

/* ---- the caps ---- */
static int suite_caps(void)
{
    m_fx_unit();
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP && m_nloads <= LOAD_CAP);
    CHECK(!strncmp(m_lines[m_nlines - 1], PREFIX "END LOADS=", strlen(PREFIX "END LOADS=")));
    if (LOAD_CAP < 900) CHECK(m_has_text("BUDGET"));
    if (LINE_CAP < 31 && LOAD_CAP >= 1971) CHECK(m_end_field("CUTS") >= 1);
    for (unsigned f = 0; f < 6; f++) {
        m_fx_unit();
        m_fill_all = 1;
        m_fill = (uint32_t[]){0, 0xffffffffu, 0x80000000u, 1, 0x80000001u, 3}[f];
        RUN_CLEAN();
        CHECK(m_nlines <= LINE_CAP && m_nloads <= LOAD_CAP);
    }
    for (unsigned s = 1; s <= 60; s++) {
        m_fx_unit();
        m_perturb();
        m_abort_nth = (int)(m_rand() % 400);
        RUN_CLEAN();
    }
    return 0;
}
