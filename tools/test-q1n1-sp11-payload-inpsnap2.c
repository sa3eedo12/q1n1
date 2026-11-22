/* SPDX-License-Identifier: MIT */
/* Host test for the payload "inpsnap2" (payloads/inpsnap2.c): the suites. tools/test-q1n1-sp11-payload-inpsnap2-model.h is what they run against (a model of the two windows with the
 * harness's own list of rows, a reference interpreter that says what the page and the loads of any fixture must be, and the rules every load and line must keep);
 * tools/test-q1n1-sp11-payload-inpsnap2.py drives the build under ASan and UBSan, and builds it again with INPSNAP2_SRC pointing at a seeded-bug copy of the payload to show that each
 * mutant is refused. Every run of every suite is judged by the reference and the rules (RUN_CLEAN); the suites pin what they say besides:
 *   table     the payload's table and the harness's own list agree row for row (window, offset, key, block, line, flags, vote bit), the lines, the blocks and the budgets
 *   unit      the golden page of the unit-like fixture (the five wrapper-0 words boot 29 read are the unit's, the rest is made up: NOT the unit's page), its loads, the counters of the end line
 *   decode    the number format, the verdict of every branch clock word on every row that has one and on none that has not, the abort token, the check of the line
 *   gate      the wrapper's word is read only behind clock words that run: each AHB clock, its vote bit, the vote word, the core clock; `QUP GATED OFF` and `QUP GATED ERR`
 *   stop      an all-ones word at every row in turn ends the page after its line, reads nothing more and names the row; the same at the wrapper's word
 *   faults    an abort at every row in turn: one access, FAULT:6 under the row's own key, the rest of its block SKIP, the other blocks read; every window aborting
 *   hang      a load that never returns, at every load of several fixtures: the page is exactly the lines the reference prints before that load
 *   random    thousands of fixtures with all-ones, zero, aborting and random words, against the reference and the rules
 *   units     the read primitive, the load budget, the line cap, the clock verdict, the gate and the helpers called directly at their edges
 *   el        any EL but 2, no guarded load, bad arguments
 *   caps      a build with a smaller line or load cap
 * `--page [scenario]` prints a page, `--numbers` the numbers the document quotes, `--table` the table with physical addresses. Nothing here ran on hardware. Evidence: EXPERIMENTAL (host
 * model only). */
#include "test-q1n1-sp11-payload-inpsnap2-model.h"

/* The page of the unit-like fixture, line by line (without the prefix). */
static const char *const GOLDEN[] = {
    "READ ONLY EL=2 STAGE=I0 CAP=44/24",
    "KEY=VALUE .ON .OFF .HW .ODD=CLOCK FAULT:6=ABORT SKIP=NOT READ K=LINE CRC16",
    "NEXT GATE",
    "GATE MA0=0.ON SA0=0.ON CR0=0X4000.ON K=3886",
    "GATE SE0=0X80004000.OFF VT0=0X810223D0 GV=1 K=710E",
    "NEXT RCG",
    "RCG DFS=0 DIV=0 CMD=0 CFG=0X2601 K=EA31",
    "RCG M=0X10 N=0XFFC4 D=0XFFB4 K=FF54",
    "NEXT PLL",
    "PLL MODE=0XC0000005 OP=1 ST=0 K=85B3",
    "PLL L=0X1F AL=0X4000 USR=0X401 K=2415",
    "NEXT LVL",
    "LVL LC0=0X2601 LC1=0X2602 LC2=0X2603 LC3=0X2604 K=FF76",
    "LVL LC4=0X2605 LC5=0X2606 LC6=0X2607 LC7=0X2608 K=9911",
    "LVL LM0=0X10 LM1=0X11 LM2=0X12 LM3=0X13 K=30CA",
    "LVL LM4=0X14 LM5=0X15 LM6=0X16 LM7=0X17 K=D36E",
    "LVL LN0=0XFFC4 LN1=0XFFC3 LN2=0XFFC2 LN3=0XFFC1 K=F5F7",
    "LVL LN4=0XFFC0 LN5=0XFFBF LN6=0XFFBE LN7=0XFFBD K=C82D",
    "NEXT QUP",
    "QUP VER=0X20050000 K=60CA",
    "END LOADS=44 FAULTS=0 SKIPS=0 BLK=0 CUTS=0 LINES=21 STOP=NONE",
};

/* The page's line `n` of the current run is `text` (with the prefix added). */
static void m_line_is(unsigned n, const char *text, int at)
{
    char want[240];
    snprintf(want, sizeof want, "%s%s", PREFIX, text);
    m_checks++;
    if (n >= m_nlines || strcmp(m_lines[n], want)) {
        m_fails++;
        fprintf(stderr, "FAIL line %d: page line %u is \"%s\", not \"%s\"\n", at, n, n < m_nlines ? m_lines[n] : "(none)", want);
        m_dump(stderr);
    }
}

/* The harness's list against the payload's table, row for row. */
static int suite_table(void)
{
    CHECK(R_COUNT == XN && XN == 44 && LOADS_MAX == 44 && BLOCKS == XB_COUNT && LINES == XLINES && WINDOWS == XW_COUNT);
    CHECK(PAGE_LINES == 21 && HEADER_LINES == 2 && CLOSING_LINES == 1);
    for (unsigned w = 0; w < WINDOWS; w++) {
        const char *name = w ? "QUP" : "GCC";
        CHECKM(windows[w].base == XW[w].base, name);
        CHECKM(windows[w].size == XW[w].size, name);
        CHECKM(!windows[w].pad, name);
    }
    CHECK(!strcmp(window_name[0], "GCC") && !strcmp(window_name[1], "QUP"));
    CHECK(!strcmp(PREFIX, "PAYLOAD INPSNAP2 "));
    for (unsigned b = 0; b < BLOCKS; b++) CHECKM(!strcmp(block_head[b], XB_HEAD[b]), XB_HEAD[b]);
    for (unsigned i = 0; i < R_COUNT; i++) {
        const struct x_reg *x = &XR_[i];
        const struct reg *r = &regs[i];
        CHECKM(r->win == x->win, x->key);
        CHECKM(r->off == x->off, x->key);
        CHECKM(!strcmp(r->key, x->key), x->key);
        CHECKM(r->block == x->block, x->key);
        CHECKM(!!(r->flags & F_CBCR) == !!x->kind, x->key);
        CHECKM(!!(r->flags & F_HWCG) == (x->kind == 2), x->key);
        CHECKM(!!(r->flags & F_WRAP) == (i <= XR_CR0), x->key);
        CHECKM(r->vbit == (i < 2 ? X_VOTE_BIT[i] : 0u), x->key);
        CHECKM(!(r->off & 3) && r->off + 4u <= XW[x->win].size, x->key);
        CHECKM(x->block == (i < 6 ? 0u : i < 13 ? 1u : i < 19 ? 2u : i < 43 ? 3u : 4u), x->key);
        CHECKM(XB_FIRST[x->block] <= i && i < XB_FIRST[x->block + 1u], x->key);
        for (unsigned j = i + 1; j < R_COUNT; j++) CHECKM((x->win != XR_[j].win || x->off != XR_[j].off) && strcmp(x->key, XR_[j].key), x->key);
        CHECKM(strlen(x->key) <= 3 || !strcmp(x->key, "MODE"), x->key);
    }
    for (unsigned l = 0; l < LINES; l++) {
        const struct line_def *d = &lines[l];
        char what[24];
        snprintf(what, sizeof what, "line %u", l);
        CHECKM(d->first == XL_FIRST[l], what);
        CHECKM(d->end == XL_FIRST[l] + XL_COUNT[l], what);
        CHECKM(d->block == XR_[XL_FIRST[l]].block, what);
        CHECKM(!d->pad, what);
        CHECKM(!strcmp(d->head, XB_HEAD[XR_[XL_FIRST[l]].block]), what);
        for (unsigned i = d->first; i < d->end && i < XN; i++) CHECKM(XR_[i].line == l, what);
        CHECKM(XL_COUNT[l] <= 4, what);
    }
    CHECK(XB_FIRST[0] == 0 && XB_FIRST[XB_COUNT] == R_COUNT);
    CHECK(L_QUP == XLINES - 1u && lines[L_QUP].first == R_VER && R_VER == XR_VER);
    CHECK(R_MA0 == XR_MA0 && R_SA0 == XR_SA0 && R_CR0 == XR_CR0 && R_SE0 == XR_SE0 && R_VT0 == XR_VT0 && R_GV == XR_GV && R_DFS == XR_DFS);
    CHECK(CRC_INIT == 0xffffu && CRC_POLY == 0x1021u && V_OK == 1 && V_FAULT == 2 && V_SKIP == 3 && V_BUDGET == 4);
    /* The plan's I0 list: 41 words, and the three clock words of the wrapper's gate. */
    CHECK(R_COUNT - 3u == 41u);
    return 0;
}

static int suite_unit(void)
{
    m_fx_unit();
    RUN_CLEAN();
    CHECK(m_nlines == sizeof GOLDEN / sizeof GOLDEN[0]);
    for (unsigned i = 0; i < sizeof GOLDEN / sizeof GOLDEN[0]; i++) m_line_is(i, GOLDEN[i], __LINE__);
    CHECK(m_nloads == 44 && m_nloadlog == 44);
    for (unsigned i = 0; i < 44; i++) CHECK(m_loadlog[i].row == i);              /* the loads are the table, in order, once each */
    CHECK(m_end_field("LOADS") == 44 && m_end_field("FAULTS") == 0 && m_end_field("SKIPS") == 0 && m_end_field("BLK") == 0 && m_end_field("CUTS") == 0);
    CHECK(m_end_field("LINES") == 21 && !strcmp(m_end_stop(), "NONE"));
    CHECK(m_sysreg_reads == 1);                     /* CurrentEL, nothing else */
    return 0;
}

/* One row set to `value`, the page read for the key. */
static void m_with(const char *key, uint32_t value)
{
    m_fx_unit();
    m_set(key, value);
    RUN_CLEAN();
}

static int suite_decode(void)
{
    static const struct {
        uint32_t value;
        const char *text;
    } NUMBERS[] = {{0, "0"}, {9, "9"}, {10, "0XA"}, {0x1f, "0X1F"}, {0x2601, "0X2601"}, {0x80004000u, "0X80004000"}, {0xfffffffeu, "0XFFFFFFFE"}};
    /* A branch clock word: CLK_OFF (bit 31) is stopped unless the NoC FSM (bits 30:28 = 2) says ON; HW_CTL (bit 1) is hardware gating only on a clock that has the bit. */
    static const struct {
        uint32_t value;
        const char *hwcg, *plain;
    } CLOCKS[] = {{0x80000000u, "0X80000000.OFF", "0X80000000.OFF"}, {0x1, "1.ON", "1.ON"}, {0, "0.ON", "0.ON"}, {0x80000002u, "0X80000002.HW", "0X80000002.OFF"},
                  {0xa0000000u, "0XA0000000.ON", "0XA0000000.ON"}, {0xa0000002u, "0XA0000002.ON", "0XA0000002.ON"}, {0x7ffffffeu, "0X7FFFFFFE.ON", "0X7FFFFFFE.ON"},
                  {0x90000000u, "0X90000000.OFF", "0X90000000.OFF"}, {0xf0000000u, "0XF0000000.OFF", "0XF0000000.OFF"}, {0x80004000u, "0X80004000.OFF", "0X80004000.OFF"},
                  {0x4002, "0X4002.ON", "0X4002.ON"}, {0x98000000u, "0X98000000.OFF", "0X98000000.OFF"}, {0xd0000000u, "0XD0000000.OFF", "0XD0000000.OFF"},
                  {0xa8000000u, "0XA8000000.ON", "0XA8000000.ON"}};
    for (unsigned i = 0; i < sizeof NUMBERS / sizeof NUMBERS[0]; i++) {
        m_with("L", NUMBERS[i].value);
        m_word_is("L", NUMBERS[i].text);
    }
    for (unsigned i = 0; i < XN; i++) {
        if (!XR_[i].kind) continue;
        for (unsigned k = 0; k < sizeof CLOCKS / sizeof CLOCKS[0]; k++) {
            m_fx_unit();
            m_set(XR_[i].key, CLOCKS[k].value);
            RUN_CLEAN();
            m_word_is(XR_[i].key, XR_[i].kind == 2 ? CLOCKS[k].hwcg : CLOCKS[k].plain);
        }
    }
    /* All ones is what a failed read returns: no clock word is, it prints .ODD and ends the page. */
    for (unsigned i = 0; i < XN; i++) {
        if (!XR_[i].kind) continue;
        m_fx_unit();
        m_set(XR_[i].key, 0xffffffffu);
        RUN_CLEAN();
        m_word_is(XR_[i].key, "0XFFFFFFFF.ODD");
    }
    /* No other row has a verdict, however its bits read; a vote word or a level is a number. */
    for (unsigned i = 0; i < XN; i++) {
        char want[24];
        if (XR_[i].kind || i == XR_VT0) continue;
        m_fx_unit();
        m_set(XR_[i].key, 0x80000002u);
        RUN_CLEAN();
        snprintf(want, sizeof want, "0X80000002");
        m_word_is(XR_[i].key, want);
    }
    m_with("VT0", 0x80000000u);
    m_word_is("VT0", "0X80000000");
    /* An abort prints its code under the row's key. */
    m_fx_unit();
    m_fault("CFG");
    RUN_CLEAN();
    m_word_is("CFG", "FAULT:6");
    return 0;
}

static unsigned m_crc_of_bytes(const char *text)
{
    uint32_t crc = CRC_INIT;
    for (; *text; text++) crc = crc_byte(crc, (uint8_t)*text);
    return crc;
}

/* The last four characters of a line (the page's check), or the line itself when it is shorter: a page the code under test cut short must fail a check, not read before its buffer. */
static const char *m_last4(const char *text)
{
    size_t n = strlen(text);
    return text + (n > 4 ? n - 4 : 0);
}

static int suite_crc(void)
{
    struct val w;
    struct pl_line line;
    uint8_t bytes[5];
    /* CRC-16/CCITT-FALSE: its published check value, from the payload's own function and from the harness's table-driven one. */
    CHECK(m_crc_of_bytes("123456789") == 0x29b1u);
    CHECK(r_crc(0xffff, (const uint8_t *)"123456789", 9) == 0x29b1u);
    CHECK(crc_byte(CRC_INIT, 0) == r_crc(0xffff, (const uint8_t[]){0}, 1) && crc_byte(0, 0xff) == r_crc(0, (const uint8_t[]){0xff}, 1));
    CHECK(crc_byte(0x1234, 0x56) == r_crc(0x1234, (const uint8_t[]){0x56}, 1) && crc_byte(0xffff, 0x80) == r_crc(0xffff, (const uint8_t[]){0x80}, 1));
    /* A word is five bytes: its state, then its value least significant byte first. */
    w.st = V_OK;
    w.v = 0x12345678u;
    bytes[0] = 1;
    bytes[1] = 0x78;
    bytes[2] = 0x56;
    bytes[3] = 0x34;
    bytes[4] = 0x12;
    CHECK(crc_word(CRC_INIT, &w) == r_crc(0xffff, bytes, 5));
    w.st = V_FAULT;
    w.v = 6;
    bytes[0] = 2;
    bytes[1] = 6;
    bytes[2] = bytes[3] = bytes[4] = 0;
    CHECK(crc_word(CRC_INIT, &w) == r_crc(0xffff, bytes, 5));
    w.st = V_SKIP;
    w.v = 0;
    bytes[0] = 3;
    bytes[1] = 0;
    CHECK(crc_word(CRC_INIT, &w) == r_crc(0xffff, bytes, 5));
    /* Four digits whatever the value, from the low sixteen bits. */
    pl_begin(&line);
    hex4(&line, 0x0a);
    CHECK(!strcmp(line.buf, "000A"));
    pl_begin(&line);
    hex4(&line, 0xffff);
    CHECK(!strcmp(line.buf, "FFFF"));
    pl_begin(&line);
    hex4(&line, 0x12345);
    CHECK(!strcmp(line.buf, "2345"));
    pl_begin(&line);
    hex4(&line, 0);
    CHECK(!strcmp(line.buf, "0000"));
    /* The check on the page is over the words, not the text: a changed word changes it, a swapped pair changes it, and a fault is not the same word as a value. */
    m_fx_unit();
    RUN_CLEAN();
    {
        char first[240], again[240], other[240];
        snprintf(first, sizeof first, "%s", m_lines[6]);
        m_fx_unit();
        m_set("CFG", 0x2602);
        RUN_CLEAN();
        snprintf(other, sizeof other, "%s", m_lines[6]);
        m_fx_unit();
        RUN_CLEAN();
        snprintf(again, sizeof again, "%s", m_lines[6]);
        CHECK(!strcmp(first, again) && strcmp(first, other) && strcmp(m_last4(first), m_last4(other)));
        m_fx_unit();
        m_set("DFS", 5);
        m_set("DIV", 0);
        RUN_CLEAN();
        snprintf(other, sizeof other, "%s", m_lines[6]);
        m_fx_unit();
        m_set("DFS", 0);
        m_set("DIV", 5);
        RUN_CLEAN();
        CHECK(strcmp(m_last4(other), m_last4(m_lines[6])));
        m_fx_unit();
        m_fault("DIV");
        RUN_CLEAN();
        snprintf(other, sizeof other, "%s", m_lines[6]);
        m_fx_unit();
        m_set("DIV", 6);
        RUN_CLEAN();
        CHECK(strcmp(m_last4(other), m_last4(m_lines[6])));
    }
    return 0;
}

/* The wrapper's gate: AHB clock words, vote bits, the vote word, the core clock. */
static int m_ver_read(void) { return m_loads_of_row("VER") == 1; }

static void m_gate_page(const char *want_text, int ver_loaded)
{
    CHECK(m_ver_read() == ver_loaded);
    if (want_text) CHECK(m_line_index(want_text) >= 0);
    CHECK(m_has("NEXT QUP"));
}

static int suite_gate(void)
{
    static const char *const AHB[2] = {"MA0", "SA0"};
    /* The unit-like fixture: every clock reads running, VT0 has bits 6 and 7 set: the wrapper is read. */
    m_fx_unit();
    RUN_CLEAN();
    m_gate_page(NULL, 1);
    CHECK(m_word_is("VER", "0X20050000"));
    for (unsigned k = 0; k < 2; k++) {
        uint32_t vote_all = 0x810223d0u;
        m_fx_unit();
        m_set(AHB[k], 0x80000002u);                                     /* hardware gating, its vote set */
        RUN_CLEAN();
        m_gate_page(NULL, 1);
        m_fx_unit();
        m_set(AHB[k], 0x80000002u);
        m_set("VT0", vote_all & ~(1u << X_VOTE_BIT[k]));                /* its vote clear: stopped */
        RUN_CLEAN();
        m_gate_page("QUP GATED OFF", 0);
        CHECK(m_line_index("QUP GATED ERR") < 0 && m_end_field("BLK") == 0x10 && m_end_field("LOADS") == 43);
        m_fx_unit();
        m_set(AHB[k], 0x80000002u);
        m_set("VT0", 1u << X_VOTE_BIT[k]);                              /* only its own bit: running */
        RUN_CLEAN();
        m_gate_page(NULL, 1);
        m_fx_unit();
        m_set(AHB[k], 0x80000002u);
        m_set("VT0", vote_all & ~(1u << X_VOTE_BIT[1 - k]));            /* only the neighbour's bit clear: its own set, running */
        RUN_CLEAN();
        m_gate_page(NULL, 1);
        m_fx_unit();
        m_set("VT0", vote_all & ~(1u << X_VOTE_BIT[k]));                /* a clock that reads running needs no vote */
        RUN_CLEAN();
        m_gate_page(NULL, 1);
        m_fx_unit();
        m_set(AHB[k], 0x80000002u);
        m_fault("VT0");                                                 /* its vote word did not read: unknown */
        RUN_CLEAN();
        m_gate_page("QUP GATED ERR", 0);
        CHECK(m_line_index("QUP GATED OFF") < 0 && m_word_is("GV", "SKIP"));
        m_fx_unit();
        m_set(AHB[k], 0x80000000u);                                     /* stopped, no hardware gating */
        RUN_CLEAN();
        m_gate_page("QUP GATED OFF", 0);
        m_fx_unit();
        m_set(AHB[k], 0x80000000u);
        m_fault("VT0");                                                 /* a word that says stopped outranks an unread vote */
        RUN_CLEAN();
        m_gate_page("QUP GATED OFF", 0);
        m_fx_unit();
        m_fault(AHB[k]);                                                /* an abort: unknown, and the rest of the block is not read */
        RUN_CLEAN();
        m_gate_page("QUP GATED ERR", 0);
        CHECK(m_word_is(AHB[k], "FAULT:6") && m_word_is("VT0", "SKIP"));
    }
    /* The core clock has no hardware gating bit: HW_CTL means nothing, CLK_OFF decides; its vote is not asked. */
    m_fx_unit();
    m_set("CR0", 0x80000002u);
    RUN_CLEAN();
    m_gate_page("QUP GATED OFF", 0);
    m_fx_unit();
    m_set("CR0", 0xa0000000u);
    RUN_CLEAN();
    m_gate_page(NULL, 1);
    m_fx_unit();
    m_set("CR0", 0);
    m_set("VT0", 0x40);
    RUN_CLEAN();
    m_gate_page(NULL, 1);
    /* The engine's own clock word, the second vote word and the RCG words are not the wrapper's gate. */
    m_fx_unit();
    m_set("SE0", 0x80000000u);
    m_set("GV", 0);
    m_set("DFS", 1);
    RUN_CLEAN();
    m_gate_page(NULL, 1);
    /* The vote word: zero is a window of zeros (every branch reads running), all ones a failed read, an abort no reading. */
    m_fx_unit();
    m_set("VT0", 0);
    RUN_CLEAN();
    m_gate_page("QUP GATED ERR", 0);
    m_fx_unit();
    m_fault("VT0");
    RUN_CLEAN();
    m_gate_page("QUP GATED ERR", 0);
    m_fx_unit();
    m_fx_all(0);
    RUN_CLEAN();
    m_gate_page("QUP GATED ERR", 0);
    CHECK(m_end_field("LOADS") == 43 && m_end_field("FAULTS") == 0);
    /* OFF outranks ERR, in either order the words were read in. */
    m_fx_unit();
    m_set("MA0", 0x80000000u);
    m_set("VT0", 0);
    RUN_CLEAN();
    m_gate_page("QUP GATED OFF", 0);
    /* An open gate with a fixture that has other things wrong: a DFS clock, a PLL that reads unlocked and a faulted level word do not close it. */
    m_fx_unit();
    m_set("DFS", 3);
    m_set("MODE", 0);
    m_fault("LN6");
    RUN_CLEAN();
    m_gate_page(NULL, 1);
    return 0;
}

static int suite_stop(void)
{
    /* An all-ones word at each row in turn: the page ends after its line, the rest of the line is SKIP, no load follows, the end line names the row. */
    for (unsigned i = 0; i < XN; i++) {
        unsigned l = XR_[i].line, loads_expected = i + 1u, skips = XL_FIRST[l] + XL_COUNT[l] - i - 1u;
        char tail[24];
        m_fx_unit();
        m_set(XR_[i].key, 0xffffffffu);
        RUN_CLEAN();
        CHECKM(m_nloads == loads_expected && m_loads_of_row(XR_[i].key) == 1, XR_[i].key);
        CHECKM(!strcmp(m_end_stop(), XR_[i].key) && m_end_field("SKIPS") == skips, XR_[i].key);
        snprintf(tail, sizeof tail, "0XFFFFFFFF%s", XR_[i].kind ? ".ODD" : "");
        CHECKM(m_word(XR_[i].key) && !strcmp(m_word(XR_[i].key), tail), XR_[i].key);
        if (i < XR_VER) CHECKM(!m_has("NEXT QUP") && !m_has("QUP "), XR_[i].key);
        CHECKM(m_end_field("BLK") == (0x1fu & ~((1u << XR_[i].block) - 1u)), XR_[i].key);
        /* nothing is printed after the line of the row but the end line, and that line went out after every load */
        CHECKM(m_nlines == 2u + (XR_[i].block + 1u) + (l + 1u) + 1u, XR_[i].key);
        CHECKM(m_line_loads[m_nlines - 2] == m_nloads, XR_[i].key);
    }
    /* Two all-ones words: the first ends the page. */
    m_fx_unit();
    m_set("DIV", 0xffffffffu);
    m_set("LC3", 0xffffffffu);
    RUN_CLEAN();
    CHECK(!strcmp(m_end_stop(), "DIV") && !m_has("LVL") && m_loads_of_row("LC3") == 0);
    /* An all-ones word of a hostile window: the first row alone, one line, the end. */
    m_fx_unit();
    m_fx_all(0xffffffffu);
    RUN_CLEAN();
    CHECK(m_nloads == 1 && !strcmp(m_end_stop(), "MA0") && m_has("MA0=0XFFFFFFFF.ODD SA0=SKIP CR0=SKIP"));
    return 0;
}

static unsigned m_block_loads(unsigned b)
{
    unsigned n = 0;
    for (unsigned e = 0; e < m_nloadlog; e++) n += XR_[m_loadlog[e].row].block == b;
    return n;
}

static int suite_faults(void)
{
    /* An abort at each row in turn. */
    for (unsigned i = 0; i < XN; i++) {
        unsigned b = XR_[i].block, in_block_before = i - XB_FIRST[b];
        m_fx_unit();
        m_flt[i] = 1;
        RUN_CLEAN();
        CHECKM(m_loads_of_row(XR_[i].key) == 1, XR_[i].key);
        CHECKM(m_word(XR_[i].key) && !strcmp(m_word(XR_[i].key), "FAULT:6"), XR_[i].key);
        CHECKM(m_end_field("FAULTS") == 1 && m_nfaults == 1, XR_[i].key);
        CHECKM(m_block_loads(b) == in_block_before + 1u, XR_[i].key);                 /* the words of its block after it are not read */
        if (i + 1u < XB_FIRST[b + 1u]) CHECKM(m_word(XR_[i + 1u].key) && !strcmp(m_word(XR_[i + 1u].key), "SKIP"), XR_[i].key);
        if (b < XB_QUP) {
            for (unsigned later = b + 1u; later < XB_COUNT; later++) {
                if (later == XB_QUP) continue;
                CHECKM(m_block_loads(later) == XB_FIRST[later + 1u] - XB_FIRST[later], XR_[i].key);        /* the other blocks are read */
            }
            CHECKM(m_end_field("BLK") & (1u << b), XR_[i].key);
        }
    }
    /* The wrapper behind an abort: a gate word or the vote word that did not read gates it; any other abort leaves it read. */
    for (unsigned i = 0; i < XR_VER; i++) {
        m_fx_unit();
        m_flt[i] = 1;
        RUN_CLEAN();
        CHECKM(m_loads_of_row("VER") == (i <= XR_VT0 ? 0u : 1u), XR_[i].key);
        CHECKM(!!m_has("QUP GATED ERR") == (i <= XR_VT0), XR_[i].key);
    }
    /* Windows that abort. */
    m_fx_unit();
    m_win_faults = 1u << XW_GCC;
    RUN_CLEAN();
    CHECK(m_nloads == 4 && m_end_field("FAULTS") == 4 && m_has("QUP GATED ERR") && m_end_field("BLK") == 0x1f);
    m_fx_unit();
    m_win_faults = 1u << XW_QUP;
    RUN_CLEAN();
    CHECK(m_nloads == 44 && m_end_field("FAULTS") == 1 && m_word_is("VER", "FAULT:6"));
    m_fx_unit();
    m_win_faults = 3;
    RUN_CLEAN();
    CHECK(m_nloads == 4 && m_end_field("FAULTS") == 4);
    /* Several aborts: one in each block. */
    m_fx_unit();
    m_fault("CMD");
    m_fault("OP");
    m_fault("LM5");
    m_fault("VER");
    RUN_CLEAN();
    CHECK(m_end_field("FAULTS") == 4 && m_nfaults == 4 && m_nloads == 26);       /* 6 + 3 + 2 + 14 + 1: each block read up to its abort */
    return 0;
}

static int suite_hang(void)
{
    /* A load that never returns, at every load of a run: the lines printed are exactly the reference's up to it, and the last is the NEXT line of the block or the line before. */
    for (unsigned scenario = 0; scenario < 5; scenario++) {
        unsigned total;
        m_fx_unit();
        if (scenario == 1) m_set("MA0", 0x80000000u);
        if (scenario == 2) m_set("L", 0xffffffffu);
        if (scenario == 3) m_fault("CFG");
        if (scenario == 4) m_set("MA0", 0x80000002u);
        RUN_CLEAN();
        r_build();
        total = R.norder;
        CHECK(total == m_nloads);
        for (unsigned n = 0; n < total; n++) {
            unsigned expect = 0, row = R.order[n], l = XR_[row].line;
            char tail[16];
            m_hang_nth = (int)n;
            (void)m_go();
            m_hang_nth = -1;
            CHECKM(m_hung == 1 && m_violations == 0, m_first_violation);
            while (expect < R.n && R.after[expect] <= n) expect++;
            CHECKM(m_nlines == expect, "the lines printed before the hung load are the reference's");
            for (unsigned i = 0; i < m_nlines && i < expect; i++) CHECKM(!strcmp(m_lines[i], R.line[i]), m_lines[i]);
            /* The last line names what hung: the NEXT line of a block (its first load), the line before the one the row is in (its first row), or nothing printed since the row before. */
            snprintf(tail, sizeof tail, "NEXT %s", XB_HEAD[XR_[row].block]);
            if (row == XB_FIRST[XR_[row].block]) CHECKM(m_last_line_is(tail), XR_[row].key);
            else if (row == XL_FIRST[l]) CHECKM(m_last_line_is_data(l - 1u), XR_[row].key);
            else CHECKM(m_nloadlog && m_loadlog[m_nloadlog - 1].nlines == m_nlines, XR_[row].key);
        }
    }
    return 0;
}

/* A pseudo-random fixture: every row is all ones, zero, a small number, a random word or aborts, and a window may abort. */
static uint64_t m_next(uint64_t *state)
{
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    return *state;
}

static void m_fx_random(uint64_t *state)
{
    m_fx_unit();
    for (unsigned i = 0; i < XN; i++) {
        uint64_t x = m_next(state);
        switch (x % 16) {
        case 0:
            m_val[i] = 0xffffffffu;
            break;
        case 1:
        case 2:
            m_val[i] = 0;
            break;
        case 3:
            m_flt[i] = 1;
            break;
        case 4:
        case 5:
            m_val[i] = (uint32_t)(x >> 8) & 0xff;
            break;
        case 6:
            m_val[i] = 0x80000000u | (uint32_t)(x >> 8) % 4u;
            break;
        case 7:
            m_val[i] = 0xa0000000u | (uint32_t)(x >> 8) % 4u;
            break;
        case 8:
            m_val[i] = (uint32_t)(x >> 8);
            break;
        default:
            break;
        }
    }
    /* Keep most runs long enough to reach the later blocks: an all-ones word ends a page. */
    if (m_next(state) % 4 != 0) for (unsigned i = 0; i < XN; i++) if (m_val[i] == 0xffffffffu) m_val[i] = 0x1234;
    if (m_next(state) % 3 == 0) m_val[XR_VT0] = (uint32_t)m_next(state) | 1u;
    if (m_next(state) % 3 == 0) m_val[XR_VT0] &= ~((m_next(state) & 1u) ? 0x40u : 0x80u);
    if (m_next(state) % 5 == 0) m_win_faults = (unsigned)(m_next(state) % 4);
}

static int suite_random(void)
{
    uint64_t state = UINT64_C(0x2545F4914F6CDD1D);
    for (unsigned n = 0; n < 6000; n++) {
        m_fx_random(&state);
        RUN_CLEAN();
        CHECK(m_nlines >= 4);
    }
    /* Windows of one word: every row zero, all ones, one bit, with and without aborting windows. */
    for (unsigned n = 0; n < 40; n++) {
        static const uint32_t FILL[] = {0, 0xffffffffu, 1, 0x80000000u, 0x80000002u, 0x40, 0xa0000000u, 0x7fffffffu};
        m_fx_unit();
        m_fx_all(FILL[n % 8]);
        m_win_faults = n / 8 % 4u;
        RUN_CLEAN();
    }
    return 0;
}

/* The suites from the primitives on are in tools/test-q1n1-sp11-payload-inpsnap2-suites.inc, part of this translation unit. */
#include "test-q1n1-sp11-payload-inpsnap2-suites.inc"

static void m_run_suite(const char *name, int (*suite)(void))
{
    unsigned fails = m_fails, checks = m_checks;
    (void)suite();
    printf("suite %-8s %s (%u checks)\n", name, m_fails == fails ? "ok" : "FAILED", m_checks - checks);
}

static void m_print_table(void)
{
    for (unsigned i = 0; i < R_COUNT; i++)
        printf("%s %s %#llx %u\n", regs[i].key, window_name[regs[i].win], (unsigned long long)(windows[regs[i].win].base + regs[i].off), (unsigned)regs[i].block);
}

static void m_scenario(const char *name)
{
    m_fx_unit();
    if (!strcmp(name, "gateoff")) m_set("MA0", 0x80000000u);
    if (!strcmp(name, "gateerr")) m_set("VT0", 0);
    if (!strcmp(name, "hwvote")) {
        m_set("MA0", 0x80000002u);
        m_set("VT0", 0x810223d0u & ~0x40u);
    }
    if (!strcmp(name, "stop")) m_set("DIV", 0xffffffffu);
    if (!strcmp(name, "fault")) m_fault("LC2");
    if (!strcmp(name, "dfs")) {
        m_set("DFS", 0x7);
        m_set("CFG", 0x2601);
    }
    if (!strcmp(name, "el1")) m_el = 1;
    if (!strcmp(name, "noload32")) m_have_load32 = 0;
    if (!strcmp(name, "badargs")) m_bad_args = 1;
}

static void m_numbers(void)
{
    m_fx_unit();
    RUN_CLEAN();
    printf("rows %u\nloads_max %u\npage_lines_max %u\nline_cap %u\nload_cap %u\nunit_lines %u\nunit_loads %u\n", (unsigned)R_COUNT, (unsigned)LOADS_MAX, (unsigned)PAGE_LINES,
           (unsigned)LINE_CAP, (unsigned)LOAD_CAP, m_nlines, m_nloads);
    m_scenario("gateoff");
    RUN_CLEAN();
    printf("gateoff_lines %u\ngateoff_loads %u\n", m_nlines, m_nloads);
    m_scenario("stop");
    RUN_CLEAN();
    printf("stop_lines %u\nstop_loads %u\n", m_nlines, m_nloads);
    m_fx_unit();
    m_fx_all(0xffffffffu);
    RUN_CLEAN();
    printf("ones_lines %u\nones_loads %u\n", m_nlines, m_nloads);
}

int main(int argc, char **argv)
{
    m_install_trap();
    if (argc > 1 && (!strcmp(argv[1], "--page") || !strcmp(argv[1], "--scenario"))) {
        m_scenario(argc > 2 ? argv[2] : "unit");
        RUN_CLEAN();
        for (unsigned i = 0; i < m_nlines; i++) printf("%s\n", m_lines[i]);
        return m_fails != 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--numbers")) {
        m_numbers();
        return m_fails != 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--table")) {
        m_print_table();
        return 0;
    }
#if defined(INPSNAP2_SHIPPED_CAPS)
    m_run_suite("table", suite_table);
    m_run_suite("unit", suite_unit);
    m_run_suite("decode", suite_decode);
    m_run_suite("crc", suite_crc);
    m_run_suite("gate", suite_gate);
    m_run_suite("stop", suite_stop);
    m_run_suite("faults", suite_faults);
    m_run_suite("hang", suite_hang);
    m_run_suite("random", suite_random);
    m_run_suite("units", suite_units);
    m_run_suite("el", suite_el);
    CHECK(m_max_loads <= LOADS_MAX && m_max_lines <= LINE_CAP && m_max_lines == PAGE_LINES);
#else
    m_run_suite("caps", suite_caps);
#endif
    printf("CHECKS %u FAILS %u MAXLINES %u MAXLOADS %u LINE_CAP %u LOAD_CAP %u\n", m_checks, m_fails, m_max_lines, m_max_loads, LINE_CAP, LOAD_CAP);
    return m_fails ? 1 : 0;
}
