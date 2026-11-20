/* SPDX-License-Identifier: MIT */
/* Host test for the payload "inputsnap" (payloads/inputsnap.c): the suites. tools/test-q1n1-sp11-payload-inputsnap-model.h is what they run against (a model of the five
 * windows with the harness's own list of registers, the order, NEXT and gate rules, the counter and the runner's page); tools/test-q1n1-sp11-payload-inputsnap.py drives
 * the build under ASan and UBSan, and builds it again with INPUTSNAP_SRC pointing at a seeded-bug copy of the payload to show that each mutant is refused. The suites
 * pin what it prints:
 *   table     the payload's table and the harness's own list agree row for row (window, offset, key, 64-bit, snapshot 2, gate, late), and neither holds a FIFO window or a
 *             pin the design excludes; the first row of every block is the register the design starts it with
 *   unit      the golden page of the unit-like fixture (made-up values except GICD_CTLR: NOT the unit's page), its loads, and that the loads are exactly the harness's list
 *   decode    every derived item and every bit and field of the table, read from words that set only that bit or field, then only its neighbours; the mode words a decode
 *             depends on (hardware gating, FIFO mode, the UART's firmware) and the ODD it prints when they say it means nothing
 *   gate      an engine whose clock words are not ALL read ON is not read, in snapshot 1 (`<engine> GATED OFF` or `GATED ERR`), snapshot 2 (`S2 U2 SKIP GATED OFF`) and the late
 *             blocks, and the other readings of those words (hardware gating, an NoC FSM status of ON, clocks that gate nothing) do not gate it
 *   drift     what moves during the gap: an engine word, a pin level, a clock word; a fault in snapshot 2; a window that aborted in snapshot 1; more than the page holds
 *   note      snapshot 2 says what it found in GCC on the next NEXT line, SAME or CHG:<n>
 *   stream    each line of snapshot 1 goes out before the loads of the row that starts the next one, so that a hang keeps what was read before it
 *   order     what a single abort or hang costs: the words no Linux driver reads come after snapshot 2 and its drift report, each late block under its own NEXT line, and a
 *             page too full for them leaves them unread with the closing lines intact
 *   faults    an abort at every address snapshot 1 reads, in turn: one access, FAULT:6 under the register's own name, the window (in GCC the group) silent afterwards
 *   faults2   an abort at every address snapshot 2 reads again, in turn
 *   faults3   an abort at every address of the late blocks, in turn
 *   wide      the 64-bit registers: low word then high word, an abort in either, the value
 *   storm     every window aborting; all-ones and zero windows; hostile random values
 *   counter   running (the gap is at least 8 s), stuck, absent, running backwards, other frequencies
 *   spin      a counter that runs but slowly: the wait is not given up while the counter moves, a spin bound that is reached prints SPIN and not NO_COUNTER
 *   el        any EL but 2: one line, no load; arguments
 *   budget    the widest values: every NEXT line of the snapshots is there, the cap holds
 * With INPUTSNAP_LINE_CAP or INPUTSNAP_LOAD_CAP set, only the cap suite runs, with INPUTSNAP_SPIN_MAX only the spin suite. `--page [scenario]` prints a page, `--numbers` the
 * numbers the document quotes. The suites from `faults2` on (and the cap suite) are in tools/test-q1n1-sp11-payload-inputsnap-limits.inc, part of this translation unit.
 * Nothing here ran on hardware. Evidence: EXPERIMENTAL (host model only). */
#include "test-q1n1-sp11-payload-inputsnap-model.h"

/* The page of the unit-like fixture, line by line (without the prefix). A made-up page: the values are the fixture's (see m_fx_unit in the model). */
static const char *const GOLDEN[] = {
    "READ ONLY EL=2 HZ=0X124F800 GAP=8 S",
    "KEY=VALUE FAULT:6=ABORT SKIP=AFTER ONE GATED=NOT READ ODD=DECODE NOT VALID",
    "NEXT GCC",
    "GCC MA0=1.ON SA0=1.ON CR0=1.ON SE0=1.ON C20=1.ON",
    "GCC MA1=1.ON SA1=1.ON CR1=1.ON SE1=1.ON QS1=1.ON C21=0X80000000.OFF",
    "GCC VT0=0X10C0 VT1=0X1380000 VT2=0X10",
    "NEXT GIC",
    "GIC CTL=0X10 TYP=0X7790F1F",
    "GIC E616=0 P616=1 C616=2 E834=0 P834=0 C834=2 E240=1 P240=0 C240=2",
    "NEXT U2",
    "U2 FW=0X230 PR=2 IFD=0 ST=0 M=0 S=0 DMA=0",
    "U2 TXF=0 TXN=0 RXF=0 RXN=0 MIS=0 SIS=0 IOS=2 CTS=1",
    "U2 MIE=0 SIE=0 IOM=0X1FF TCF=7 RCF=7 TPA=0 RPA=0 HW0=0XA80E0D4 HW1=0XB02",
    "NEXT S10",
    "S10 FW=0X930 PR=9 IFD=0 ST=0 M=0 S=0 DMA=0 TXF=0 TXN=0 RXF=0 RXN=0 MIS=0",
    "S10 SIS=0 IOS=2 MIE=0 SIE=0 HW0=0XA80E0D4 HW1=0XB02",
    "NEXT TLMM",
    "TLMM F8=4 L8=0 F9=4 L9=1 F10=4 L10=0 F11=4 L11=1 F91=1 L91=0 N91=5 S91=0",
    "TLMM F40=8 L40=0 F41=8 L41=1 F42=8 L42=0 F43=8 L43=1 F51=1 L51=0 N51=5 S51=0",
    "TLMM F48=1 L48=1 F64=1 L64=1 F2=1 L2=0",
    "NEXT WAIT 8 S",
    "NEXT S2 GCC",
    "NEXT S2 U2 GCC=SAME",
    "NEXT S2 TLMM",
    "DRIFT NONE CMP=19",
    "NEXT X U2",
    "X U2 CM=0X10 CS=0 CK=0 CC=3 TWL=8 TSB=0X20 RWL=8 STL=0X18 MRF=0 TWM=4",
    "X U2 RWM=0X20 RFW=0X20 DIF=1",
    "NEXT X S10",
    "X S10 CM=0X10 CS=0 CK=0 CC=3 DIF=1",
    "NEXT X GIC",
    "X GIC G616=1 R616=0X100 G834=1 R834=0X80000000 G240=1 R240=0",
    "END LOADS=132 FAULTS=0 SKIPS=0 BLK=0 CUTS=0 GAP_MS=8020 LINES=33",
};

#define LOADS_S1 86u
#define LOADS_S2 19u
#define LOADS_X 27u
#define LOADS_XU2 13u                       /* the late blocks' loads, by block: the UART engine's words, the SPI engine's, the GIC's (three words and three 64-bit ones) */
#define LOADS_XS10 5u
#define LOADS_XGIC 9u

static int m_line_starts(const char *tail)
{
    char want[100];
    size_t n;
    snprintf(want, sizeof want, "%s%s", PREFIX, tail);
    n = strlen(want);
    for (unsigned i = 0; i < m_nlines; i++) if (!strncmp(m_lines[i], want, n) && (m_lines[i][n] == 0 || m_lines[i][n] == ' ')) return (int)i;
    return -1;
}

/* The value text of KEY in the lines of one block of snapshot 1 (from its NEXT line to the next one), or NULL. */
static const char *m_value_in(const char *block, const char *key)
{
    static char out[64];
    char head[64], pat[24];
    int in = 0;
    snprintf(head, sizeof head, PREFIX "NEXT %s", block);
    snprintf(pat, sizeof pat, " %s=", key);
    for (unsigned i = 0; i < m_nlines; i++) {
        const char *p;
        if (!strcmp(m_lines[i], head)) {
            in = 1;
            continue;
        }
        if (!in) continue;
        if (!strncmp(m_lines[i], PREFIX "NEXT ", strlen(PREFIX "NEXT "))) break;
        p = strstr(m_lines[i], pat);
        if (p) {
            size_t n = strcspn(p + strlen(pat), " ");
            snprintf(out, sizeof out, "%.*s", (int)n, p + strlen(pat));
            return out;
        }
    }
    return NULL;
}

static int m_val_is(const char *block, const char *key, const char *want)
{
    const char *got = m_value_in(block, key);
    m_checks++;
    if (got && !strcmp(got, want)) return 1;
    m_fails++;
    fprintf(stderr, "FAIL: %s %s is %s, not %s\n", block, key, got ? got : "(absent)", want);
    m_dump(stderr);
    return 0;
}

static int m_absent_in(const char *block, const char *key)
{
    m_checks++;
    if (!m_value_in(block, key)) return 1;
    m_fails++;
    fprintf(stderr, "FAIL: %s %s is on the page\n", block, key);
    m_dump(stderr);
    return 0;
}

static const char *m_key_of(unsigned w, uint32_t off)
{
    unsigned hi;
    const struct m_reg *r = m_reg_of(w, off, &hi);
    return r ? r->key : NULL;
}

static int m_fault_under(const char *key)
{
    char pat[24];
    snprintf(pat, sizeof pat, " %s=", key);
    for (unsigned i = 0; i < m_nlines; i++) {
        for (const char *p = strstr(m_lines[i], pat); p; p = strstr(p + 1, pat)) {
            const char *end = strchr(p + 1, ' ');
            size_t n = end ? (size_t)(end - p) : strlen(p);
            char token[128];
            snprintf(token, sizeof token, "%.*s", (int)n, p);
            if (strstr(token, "FAULT:6")) return 1;
        }
    }
    return 0;
}

static unsigned m_loads_in(unsigned phase)
{
    unsigned n = 0;
    for (unsigned i = 0; i < m_nevents; i++) n += m_events[i].kind == M_LOAD && m_events[i].phase == phase;
    return n;
}

static int m_line_event(unsigned n)
{
    for (unsigned e = 0; e < m_nevents; e++) if (m_events[e].kind == M_LINE && m_events[e].addr == n) return (int)e;
    return -1;
}

static int m_first_load_of(unsigned w, const char *key)
{
    for (unsigned e = 0; e < m_nevents; e++) {
        const char *k;
        if (m_events[e].kind != M_LOAD || m_events[e].win != w) continue;
        k = m_key_of(w, (uint32_t)(m_events[e].addr - M_BASE[w]));
        if (k && !strcmp(k, key)) return (int)e;
    }
    return -1;
}

/* The first line of snapshot 1 after the NEXT line of `block` that holds KEY. */
static int m_line_holding(const char *block, const char *key)
{
    char head[64], pat[24];
    int in = 0;
    snprintf(head, sizeof head, PREFIX "NEXT %s", block);
    snprintf(pat, sizeof pat, " %s=", key);
    for (unsigned i = 0; i < m_nlines; i++) {
        if (!strcmp(m_lines[i], head)) in = 1;
        else if (in && !strncmp(m_lines[i], PREFIX "NEXT ", strlen(PREFIX "NEXT "))) in = 0;
        else if (in && strstr(m_lines[i], pat)) return (int)i;
    }
    return -1;
}

/* The suite of a build whose caps are the shipped ones only. */
static void m_gcc_all(uint32_t value)
{
    static const uint32_t words[] = {0x23000, 0x23004, 0x23008, 0x23018, 0x42274, 0x23150, 0x23154, 0x23158, 0x23168, 0x18274, 0x18280};
    for (unsigned i = 0; i < sizeof words / sizeof words[0]; i++) m_fset(M_GCC, words[i], value);
}

/* The harness's list against the payload's table, row for row. */
static int suite_table(void)
{
    unsigned total = 0, last_s2 = 0;
    CHECK(R_COUNT == 110 && BLOCKS == 8 && S1_BLOCKS == 5 && WINDOWS == M_WINDOWS);
    for (unsigned w = 0; w < WINDOWS; w++) CHECK(windows[w].base == M_BASE[w] && windows[w].size == M_SIZE[w] && !strcmp(window_name[w], M_NAME[w]));
    for (unsigned id = 0; id < R_COUNT; id++) {
        unsigned hi, win = regs[id].win;
        const struct m_reg *r = m_reg_of(win, regs[id].off, &hi);
        CHECK(r && !hi);
        if (!r) continue;
        CHECK(!strcmp(r->key, reg_key[id]));
        CHECK(!!r->wide == !!(regs[id].flags & F_WIDE));
        CHECK(!!m_in_s2(win, r) == !!(regs[id].flags & F_S2));
        CHECK(!m_forbidden(win, regs[id].off));
        CHECK(block_win[regs[id].block] == win && !(regs[id].off & 3) && regs[id].off + (r->wide ? 8u : 4u) <= M_SIZE[win]);
        /* A row is in a late block exactly when no Linux driver reads it (the harness's own list), and a word no driver reads is not part of snapshot 2. */
        CHECK(!!m_fresh(r) == !!(regs[id].flags & F_FRESH) && !!m_fresh(r) == (regs[id].block >= B_XU2) && !(m_fresh(r) && (regs[id].flags & F_S2)));
        if (win == M_GCC) {
            unsigned in_u2 = 0, in_s10 = 0;
            for (unsigned i = 0; i < 4; i++) in_u2 |= M_GATE_U2[i] == regs[id].off;
            for (unsigned i = 0; i < 5; i++) in_s10 |= M_GATE_S10[i] == regs[id].off;
            CHECK(!!(regs[id].gate & GATE_U2) == !!in_u2 && !!(regs[id].gate & GATE_S10) == !!in_s10 && regs[id].grp == r->group);
            CHECK(!!(regs[id].flags & F_HWCG) == !!m_in_hwcg(regs[id].off));
            /* What a single abort costs: in a group of clock words, the words that gate an engine come before the clock that gates nothing. */
            if (id + 1 < R_COUNT && regs[id + 1].win == M_GCC && regs[id + 1].grp == regs[id].grp) CHECK(!(!regs[id].gate && regs[id + 1].gate));
        } else {
            CHECK(!regs[id].gate);
        }
        if (regs[id].block == B_U2 && (regs[id].flags & F_S2)) last_s2 = id;
        total++;
    }
    CHECK(last_s2 < R_U_MIE);                       /* the words of the UART engine that move come before its configuration */
    for (unsigned i = 0; i < M_NREGS; i++) {
        for (unsigned w = 0; w < M_WINDOWS; w++) {
            unsigned n = 0;
            if (!(M_REGS[i].wins & W(w))) continue;
            for (unsigned id = 0; id < R_COUNT; id++) n += regs[id].win == w && regs[id].off == M_REGS[i].off;
            CHECK(n == 1);
        }
    }
    {
        unsigned listed = 0;
        for (unsigned i = 0; i < M_NREGS; i++) listed += (unsigned)__builtin_popcount(M_REGS[i].wins);
        CHECK(listed == R_COUNT && total == R_COUNT);
    }
    CHECK(S1_LOADS_MAX == LOADS_S1 && S2_LOADS_MAX == LOADS_S2 && X_LOADS_MAX == LOADS_X);
    for (unsigned b = 0; b < BLOCKS; b++) {
        char head[16];
        CHECK(block_first[b] < block_first[b + 1] && regs[block_first[b]].block == b && regs[block_first[b + 1] - 1].block == b);
        if (b < S1_BLOCKS) {
            CHECK(!strcmp(block_head[b], M_NAME[b]) && block_win[b] == b);
            CHECK(regs[block_first[b]].off == M_START[b] && !(regs[block_first[b]].flags & F_FRESH));       /* the first load of a block is one Linux makes */
        } else {
            snprintf(head, sizeof head, "X %s", M_NAME[block_win[b]]);
            CHECK(!strcmp(block_head[b], head) && (regs[block_first[b]].flags & F_FRESH));
        }
    }
    return 0;
}

static void m_check_reads_are_the_list(void)
{
    unsigned s1 = 0, s2 = 0, x = 0;
    for (unsigned i = 0; i < M_NREGS; i++) {
        for (unsigned w = 0; w < M_WINDOWS; w++) {
            const struct m_reg *r = &M_REGS[i];
            unsigned late = (unsigned)m_fresh(r);
            if (!(r->wins & W(w))) continue;
            CHECK(m_loads_of(w, r->off, 1) == (late ? 0u : 1u) && m_loads_of(w, r->off, 3) == (late ? 1u : 0u));
            if (r->wide) CHECK(m_loads_of(w, r->off + 4, 3) == 1);
            CHECK(m_loads_of(w, r->off, 2) == (m_in_s2(w, r) ? 1u : 0u));
            s1 += late ? 0u : 1u;
            x += late ? 1u + r->wide : 0u;
            s2 += m_in_s2(w, r) ? 1u : 0u;
        }
    }
    CHECK(s1 == m_loads_in(1) && s2 == m_loads_in(2) && x == m_loads_in(3));
}

static int suite_unit(void)
{
    m_fx_unit();
    RUN_CLEAN();
    CHECK(m_nlines == sizeof GOLDEN / sizeof GOLDEN[0]);
    for (unsigned i = 0; i < sizeof GOLDEN / sizeof GOLDEN[0]; i++) m_line_is(i, GOLDEN[i], __LINE__);
    CHECK(m_nloads == LOADS_S1 + LOADS_S2 + LOADS_X && m_loads_in(1) == LOADS_S1 && m_loads_in(2) == LOADS_S2 && m_loads_in(3) == LOADS_X);
    m_check_reads_are_the_list();
    CHECK(m_end_field("FAULTS") == 0 && m_end_field("SKIPS") == 0 && m_end_field("CUTS") == 0 && m_end_field("BLK") == 0);
    CHECK(m_has("DRIFT NONE CMP=19"));
    CHECK(m_end_field("GAP_MS") >= 8000 && m_end_field("GAP_MS") < 8100);
    CHECK(m_sysreg_reads == 2);                     /* CurrentEL and CNTFRQ_EL0, nothing else */
    return 0;
}

/* One word of the unit fixture set to `value`, the page read for the key of `block`. */
static void m_with(unsigned w, uint64_t off, uint32_t value)
{
    m_fx_unit();
    m_fset(w, off, value);
    RUN_CLEAN();
}

static int suite_decode(void)
{
    static const struct {
        const char *block, *key;
        uint32_t off;
        unsigned shift, width;
    } GIC[] = {{"GIC", "E240", 0x11c, 16, 1}, {"GIC", "P240", 0x21c, 16, 1}, {"X GIC", "G240", 0x09c, 16, 1}, {"GIC", "C240", 0xc3c, 0, 2}, {"GIC", "E616", 0x14c, 8, 1},
               {"GIC", "P616", 0x24c, 8, 1}, {"X GIC", "G616", 0x0cc, 8, 1}, {"GIC", "C616", 0xc98, 16, 2}, {"GIC", "E834", 0x168, 2, 1}, {"GIC", "P834", 0x268, 2, 1},
               {"X GIC", "G834", 0x0e8, 2, 1}, {"GIC", "C834", 0xcd0, 4, 2}};
    static const char *const ENGINES[] = {"U2", "S10"};
    static const unsigned EW[] = {M_U2, M_S10};
    for (unsigned i = 0; i < sizeof GIC / sizeof GIC[0]; i++) {
        uint32_t mask = (1u << GIC[i].width) - 1u, field = mask << GIC[i].shift;
        char one[4], two[4], all[4];
        snprintf(all, sizeof all, "%u", mask);
        snprintf(one, sizeof one, "1");
        snprintf(two, sizeof two, "2");
        m_with(M_GIC, GIC[i].off, field);
        m_val_is(GIC[i].block, GIC[i].key, all);
        m_with(M_GIC, GIC[i].off, ~field);                      /* every neighbour set, the field clear */
        m_val_is(GIC[i].block, GIC[i].key, "0");
        m_with(M_GIC, GIC[i].off, 1u << GIC[i].shift);
        m_val_is(GIC[i].block, GIC[i].key, one);
        if (GIC[i].width == 2) {
            m_with(M_GIC, GIC[i].off, 2u << GIC[i].shift);
            m_val_is(GIC[i].block, GIC[i].key, two);
        }
    }
    /* Values below 10 are one digit, the others 0X and the fewest upper-case hex digits. */
    m_with(M_GIC, 0x4, 9);
    m_val_is("GIC", "TYP", "9");
    m_with(M_GIC, 0x4, 10);
    m_val_is("GIC", "TYP", "0XA");
    m_with(M_GIC, 0x4, 0xdeadbeefu);
    m_val_is("GIC", "TYP", "0XDEADBEEF");
    /* Branch clock words: bit 31 is CLK_OFF, unless the NoC FSM (bits 30:28 = 2) says ON; a clock that declares a hardware gating bit (the AHB clocks) with HW_CTL (bit 1) set has no
     * verdict in CLK_OFF (.HW); all ones is a failed read, not a clock word (.ODD). */
    m_with(M_GCC, 0x23018, 0x80000000u);
    m_val_is("GCC", "C20", "0X80000000.OFF");
    m_with(M_GCC, 0x23018, 0x1);
    m_val_is("GCC", "C20", "1.ON");
    m_with(M_GCC, 0x23018, 0x7fffffffu);
    m_val_is("GCC", "C20", "0X7FFFFFFF.ON");
    m_with(M_GCC, 0x23018, 0x80000002u);
    m_val_is("GCC", "C20", "0X80000002.OFF");                   /* a clock without a hardware gating bit: HW_CTL means nothing */
    m_with(M_GCC, 0x23018, 0xa0000000u);
    m_val_is("GCC", "C20", "0XA0000000.ON");                    /* CLK_OFF set but the FSM says ON */
    m_with(M_GCC, 0x23018, 0xffffffffu);
    m_val_is("GCC", "C20", "0XFFFFFFFF.ODD");
    m_with(M_GCC, 0x23000, 0x80000002u);
    m_val_is("GCC", "MA0", "0X80000002.HW");
    m_with(M_GCC, 0x23000, 0x80000000u);
    m_val_is("GCC", "MA0", "0X80000000.OFF");
    m_with(M_GCC, 0x23000, 0x1);
    m_val_is("GCC", "MA0", "1.ON");
    m_with(M_GCC, 0x23000, 0xa0000002u);
    m_val_is("GCC", "MA0", "0XA0000002.ON");
    m_with(M_GCC, 0x23000, 0xffffffffu);
    m_val_is("GCC", "MA0", "0XFFFFFFFF.ODD");
    m_with(M_GCC, 0x52020, 0x80000000u);
    m_val_is("GCC", "VT0", "0X80000000");                       /* a vote word is not a branch clock */
    /* The engine words, in both engines (the UART engine's own words in U2 only). */
    for (unsigned e = 0; e < 2; e++) {
        const char *b = ENGINES[e];
        unsigned w = EW[e];
        m_with(w, 0x068, 0x00000230);
        m_val_is(b, "FW", "0X230");
        m_val_is(b, "PR", "2");
        m_with(w, 0x068, 0x0000ff00u);
        m_val_is(b, "PR", "0XFF");
        m_with(w, 0x068, 0xffff00ffu);
        m_val_is(b, "PR", "0");
        m_with(w, 0x040, 0x1);
        m_val_is(b, "M", "1");
        m_val_is(b, "S", "0");
        m_with(w, 0x040, 0x1000);
        m_val_is(b, "M", "0");
        m_val_is(b, "S", "1");
        m_with(w, 0x040, 0xffffefffu);
        m_val_is(b, "M", "1");
        m_val_is(b, "S", "0");
        m_with(w, 0x800, 0xf0000007u);
        m_val_is(b, "TXN", "7");
        m_with(w, 0x800, 0x0fffffffu);
        m_val_is(b, "TXN", "0XFFFFFFF");
        m_with(w, 0x804, 0xfe000005u);
        m_val_is(b, "RXN", "5");
        m_with(w, 0x804, 0x01ffffffu);
        m_val_is(b, "RXN", "0X1FFFFFF");
        /* The FIFO counts mean something in FIFO mode only: DMA mode on, or the FIFO interface disabled, marks them ODD (the raw word is printed), and so does a mode word that did
         * not read; the other mode bits change nothing. */
        m_fx_unit();
        m_fset(w, 0x800, 7);
        m_fset(w, 0x804, 5);
        m_fset(w, 0x258, 0x1);
        RUN_CLEAN();
        m_val_is(b, "TXF", "7");
        m_val_is(b, "TXN", "ODD");
        m_val_is(b, "RXN", "ODD");
        m_fx_unit();
        m_fset(w, 0x800, 7);
        m_fset(w, 0x064, 0x1);
        RUN_CLEAN();
        m_val_is(b, "TXN", "ODD");
        m_val_is(b, "RXN", "ODD");
        m_fx_unit();
        m_fset(w, 0x800, 7);
        m_fset(w, 0x258, 0xfffffffeu);
        m_fset(w, 0x064, 0xfffffffeu);
        RUN_CLEAN();
        m_val_is(b, "TXN", "7");                                /* bit 0 of each is the mode, the neighbours are not */
        m_fx_unit();
        m_ffault(w, 0x064);                                     /* IFD aborts: the window is dead, the rest is SKIP, nothing is decoded from it */
        RUN_CLEAN();
        m_val_is(b, "IFD", "FAULT:6");
        m_val_is(b, "TXF", "SKIP");
        m_absent_in(b, "TXN");
    }
    m_with(M_U2, 0x908, 0x2);
    m_val_is("U2", "CTS", "1");
    m_with(M_U2, 0x908, 0xfffffffdu);
    m_val_is("U2", "CTS", "0");
    /* IO2 reads as CTS only on an engine that runs the UART's firmware: another protocol, or a revision word that did not read, marks it ODD. */
    m_fx_unit();
    m_fset(M_U2, 0x068, 0x00000130);
    RUN_CLEAN();
    m_val_is("U2", "PR", "1");
    m_val_is("U2", "IOS", "2");
    m_val_is("U2", "CTS", "ODD");
    m_fx_unit();
    m_fset(M_U2, 0x068, 0x0000ff30);
    RUN_CLEAN();
    m_val_is("U2", "CTS", "ODD");
    m_fx_unit();
    m_ffault(M_U2, 0x068);
    RUN_CLEAN();
    m_val_is("U2", "FW", "FAULT:6");
    m_val_is("U2", "IOS", "SKIP");
    m_absent_in("U2", "CTS");                                   /* an engine whose first load aborted prints no decode at all */
    m_with(M_S10, 0x908, 0x2);
    m_absent_in("S10", "CTS");                                  /* the CTS reading of IO2 is the UART's: the SPI engine's IOS is printed raw */
    m_val_is("S10", "IOS", "2");
    return 0;
}

static uint32_t m_gate_off(unsigned engine, unsigned i)
{
    static const uint32_t U2[] = {0x23000, 0x23004, 0x23008, 0x42274};
    static const uint32_t S10[] = {0x23150, 0x23154, 0x23158, 0x18274, 0x18280};
    return (engine == M_U2 ? U2 : S10)[i];
}

static void m_gate_word(unsigned engine, unsigned i, uint32_t value)
{
    m_fx_unit();
    m_fset(M_GCC, m_gate_off(engine, i), value);
}

static unsigned m_gate_n(unsigned engine) { return engine == M_U2 ? 4u : 5u; }

static void m_wait_ma0_off(void) { m_fset(M_GCC, 0x23000, 0x80000000u); }
static void m_wait_ma0_on(void) { m_fset(M_GCC, 0x23000, 0x1u); }
static void m_wait_qs1_off(void) { m_fset(M_GCC, 0x18280, 0x80000000u); }
static void m_wait_se0_fault(void) { m_ffault(M_GCC, 0x42274); }
static void m_wait_c20_off(void) { m_fset(M_GCC, 0x23018, 0x80000000u); }

static int suite_gate(void)
{
    /* The four AHB clocks declare a hardware gating bit, so CLK_OFF with HW_CTL set is not stopped for them; the other clock words are judged by CLK_OFF alone. A word that reads
     * as all ones is a failed read: the engine is gated, and the page says ERR (unknown), not OFF. */
    static const struct {
        uint32_t value;
        int stopped_hwcg, stopped_plain, unknown;
    } WORDS[] = {{0x80000000u, 1, 1, 0}, {0xffffffffu, 1, 1, 1}, {0x90000000u, 1, 1, 0}, {0xf0000000u, 1, 1, 0}, {0x80000002u, 0, 1, 0}, {0xa0000000u, 0, 0, 0},
                 {0xa0000002u, 0, 0, 0}, {0x0u, 0, 0, 0}, {0x1u, 0, 0, 0}, {0x7ffffffeu, 0, 0, 0}};
    for (unsigned engine = M_U2; engine <= M_S10; engine++) {
        const char *name = M_NAME[engine];
        unsigned other = engine == M_U2 ? M_S10 : M_U2;
        char off[24], err[24];
        snprintf(off, sizeof off, "%s GATED OFF", name);
        snprintf(err, sizeof err, "%s GATED ERR", name);
        for (unsigned i = 0; i < m_gate_n(engine); i++) {
            for (unsigned k = 0; k < sizeof WORDS / sizeof WORDS[0]; k++) {
                int stopped = m_in_hwcg(m_gate_off(engine, i)) ? WORDS[k].stopped_hwcg : WORDS[k].stopped_plain;
                m_gate_word(engine, i, WORDS[k].value);
                RUN_CLEAN();
                if (stopped) {
                    /* One line, no load of the engine in any snapshot; OFF when a word that read says stopped, ERR when the word is no clock word. */
                    CHECK(m_line_index(WORDS[k].unknown ? err : off, 0) >= 0 && m_line_index(WORDS[k].unknown ? off : err, 0) < 0 && m_wloads[engine] == 0);
                    CHECK(m_wloads[other] > 0);
                    CHECK(m_end_field("BLK") != 0);
                } else {
                    CHECK(m_line_index(off, 0) < 0 && m_line_index(err, 0) < 0 && m_window_loads(engine, 1) > 0);
                }
            }
        }
    }
    /* A word that aborts, and the words after it in its group, are not a reading: the engine is gated (fail closed), and the page says ERR, never OFF. */
    m_fx_unit();
    m_ffault(M_GCC, 0x23000);
    RUN_CLEAN();
    CHECK(m_line_index("U2 GATED ERR", 0) >= 0 && m_line_index("U2 GATED OFF", 0) < 0 && m_wloads[M_U2] == 0 && m_wloads[M_S10] > 0);
    CHECK(m_value_in("GCC", "MA0") && !strcmp(m_value_in("GCC", "MA0"), "FAULT:6") && !strcmp(m_value_in("GCC", "SA0"), "SKIP"));
    m_fx_unit();
    m_ffault(M_GCC, 0x42274);
    RUN_CLEAN();
    CHECK(m_line_index("U2 GATED ERR", 0) >= 0 && m_wloads[M_U2] == 0);
    m_fx_unit();
    m_ffault(M_GCC, 0x18280);
    RUN_CLEAN();
    CHECK(m_line_index("S10 GATED ERR", 0) >= 0 && m_wloads[M_S10] == 0 && m_wloads[M_U2] > 0);
    /* A word that read and says stopped decides OFF even when another word of the engine aborted. */
    m_fx_unit();
    m_fset(M_GCC, 0x23000, 0x80000000u);
    m_ffault(M_GCC, 0x42274);
    RUN_CLEAN();
    CHECK(m_line_index("U2 GATED OFF", 0) >= 0 && m_line_index("U2 GATED ERR", 0) < 0);
    /* Clocks that gate nothing: the core 2x clocks, the votes. */
    m_fx_unit();
    m_fset(M_GCC, 0x23018, 0x80000000u);
    m_fset(M_GCC, 0x23168, 0x80000000u);
    m_fset(M_GCC, 0x52020, 0xffffffffu);
    RUN_CLEAN();
    CHECK(m_has("U2 GATED") == 0 && m_has("S10 GATED") == 0 && m_nloads == LOADS_S1 + LOADS_S2 + LOADS_X);
    /* Both engines at once; and the whole of GCC aborting, which gates both. The late blocks gate the same way, on snapshot 2's own words. */
    m_fx_unit();
    m_gcc_all(0x80000000u);
    RUN_CLEAN();
    CHECK(m_line_index("U2 GATED OFF", 0) >= 0 && m_line_index("S10 GATED OFF", 0) >= 0 && m_wloads[M_U2] == 0 && m_wloads[M_S10] == 0);
    CHECK(m_wloads[M_GIC] > 0 && m_wloads[M_TLMM] > 0);
    CHECK(m_has("NEXT S2 TLMM") && !m_has("NEXT S2 U2"));
    CHECK(m_line_index("X U2 GATED OFF", 0) >= 0 && m_line_index("X S10 GATED OFF", 0) >= 0 && m_window_loads(M_GIC, 3) == LOADS_XGIC);
    m_fx_unit();
    m_win_faults = W(M_GCC);
    RUN_CLEAN();
    CHECK(m_line_index("U2 GATED ERR", 0) >= 0 && m_line_index("S10 GATED ERR", 0) >= 0 && m_wloads[M_U2] == 0 && m_wloads[M_S10] == 0);
    CHECK(m_line_index("X U2 GATED ERR", 0) >= 0 && m_line_index("X S10 GATED ERR", 0) >= 0);
    /* Snapshot 2 decides on its own words: a gate word that went off, or aborts, after snapshot 1 read it. The late blocks follow it. */
    m_fx_unit();
    m_at_wait = m_wait_ma0_off;
    RUN_CLEAN();
    CHECK(m_line_index("U2 SKIP GATED", 0) < 0 && m_line_starts("S2 U2 SKIP GATED OFF") > 0 && m_window_loads(M_U2, 2) == 0 && m_window_loads(M_U2, 1) > 0);
    CHECK(m_has("DRIFT CHANGED=1 LOST=0 CMP=13"));              /* the engine that was not visited is not compared either */
    CHECK(m_line_starts("NEXT S2 TLMM") > 0 && m_window_loads(M_TLMM, 2) == 2);
    CHECK(m_line_index("X U2 GATED OFF", 0) > 0 && m_window_loads(M_U2, 3) == 0 && m_window_loads(M_S10, 3) == LOADS_XS10);
    m_fx_unit();
    m_at_wait = m_wait_se0_fault;
    RUN_CLEAN();
    CHECK(m_line_starts("S2 U2 SKIP GATED ERR") > 0 && m_window_loads(M_U2, 2) == 0 && m_end_field("FAULTS") == 1);
    CHECK(m_line_index("X U2 GATED ERR", 0) > 0 && m_window_loads(M_U2, 3) == 0);
    m_fx_unit();
    m_at_wait = m_wait_qs1_off;                                 /* S10 has no snapshot-2 reads: nothing to skip, nothing read */
    RUN_CLEAN();
    CHECK(m_window_loads(M_S10, 2) == 0 && m_window_loads(M_U2, 2) == 6);
    CHECK(m_line_index("X S10 GATED OFF", 0) > 0 && m_window_loads(M_S10, 3) == 0 && m_window_loads(M_U2, 3) == LOADS_XU2);
    m_fx_unit();
    m_at_wait = m_wait_c20_off;                                 /* a core 2x clock going off does not gate the engine */
    RUN_CLEAN();
    CHECK(m_window_loads(M_U2, 2) == 6 && m_has("DG C20=1-0X80000000") && m_window_loads(M_U2, 3) == LOADS_XU2);
    /* Gated in snapshot 1: no snapshot-2 line for it, even when the words come back; a late block gates on the freshest words, so it reads an engine whose clock came on in the
     * gap (the engine has no snapshot-1 values, so there is nothing to compare, and nothing is claimed about it). */
    m_gate_word(M_U2, 0, 0x80000000u);
    m_at_wait = NULL;
    RUN_CLEAN();
    CHECK(m_line_starts("NEXT S2 U2") < 0 && m_line_starts("S2 U2") < 0 && m_window_loads(M_U2, 3) == 0);
    m_gate_word(M_U2, 0, 0x80000000u);
    m_at_wait = m_wait_ma0_on;
    RUN_CLEAN();
    CHECK(m_line_index("U2 GATED OFF", 0) >= 0 && m_line_starts("S2 U2") < 0 && m_window_loads(M_U2, 1) == 0 && m_window_loads(M_U2, 3) == LOADS_XU2);
    return 0;
}

static void m_wait_c21(void) { m_fset(M_GCC, 0x23168, 0x1); }
static void m_wait_rx5(void) { m_fset(M_U2, 0x804, 5); }
static void m_wait_l91(void) { m_fset(M_TLMM, 0x5b004, 1); }
static void m_wait_u2_fault(void) { m_ffault(M_U2, 0x908); }
static void m_wait_three(void)
{
    m_fset(M_GCC, 0x23018, 0x3);
    m_fset(M_U2, 0x040, 0x1);
    m_fset(M_TLMM, 0x33004, 0x1);
}

static void m_wait_flip_all(void)
{
    for (unsigned i = 0; i < m_nfake; i++) {
        unsigned w = m_win_of(m_fake[i].addr);
        unsigned hi;
        uint32_t hash = (uint32_t)(m_fake[i].addr * 2654435761u >> 4 & 0x0ffffff0u);
        const struct m_reg *r = m_reg_of(w, (uint32_t)(m_fake[i].addr - M_BASE[w]), &hi);
        /* The clock words get an NoC FSM status of ON (bits 30:28 = 2), so that a flip changes every word and gates no engine. */
        if (r && m_in_s2(w, r)) m_fake[i].value = w == M_GCC ? 0xa0000000u | hash : 0x80000002u | hash;
    }
}

static int suite_drift(void)
{
    m_fx_unit();
    m_at_wait = m_wait_rx5;
    RUN_CLEAN();
    CHECK(m_has("DU RXF=0-5") && m_has("DRIFT CHANGED=1 LOST=0 CMP=19") && !m_has("DG ") && !m_has("DT "));
    m_fx_unit();
    m_at_wait = m_wait_l91;
    RUN_CLEAN();
    CHECK(m_has("DT L91=0-1") && m_has("DRIFT CHANGED=1 LOST=0 CMP=19") && !m_has("DU ") && !m_has("DG "));
    m_fx_unit();
    m_at_wait = m_wait_c21;
    RUN_CLEAN();
    CHECK(m_has("DG C21=0X80000000-1") && m_has("DRIFT CHANGED=1 LOST=0 CMP=19"));
    /* Three groups: the order is the engine, the pins, the clock words. */
    m_fx_unit();
    m_at_wait = m_wait_three;
    RUN_CLEAN();
    {
        int u = m_line_starts("DU"), t = m_line_starts("DT"), g = m_line_starts("DG");
        CHECK(u > 0 && t > u && g > t && m_has("DRIFT CHANGED=3 LOST=0 CMP=19"));
        CHECK(m_has("DU ST=0-1") && m_has("DT L51=0-1") && m_has("DG C20=1-3"));
    }
    /* A fault in snapshot 2 is printed in place of the new value and counted as lost; the window is read no more. */
    m_fx_unit();
    m_at_wait = m_wait_u2_fault;
    RUN_CLEAN();
    CHECK(m_has("DU IOS=2-FAULT:6") && m_has("DRIFT CHANGED=0 LOST=1 CMP=19") && m_end_field("FAULTS") == 1);
    /* A window that aborted in snapshot 1 is neither visited nor compared. */
    m_fx_unit();
    m_ffault(M_U2, 0x908);
    RUN_CLEAN();
    CHECK(m_line_starts("NEXT S2 U2") < 0 && m_has("DRIFT NONE CMP=13") && m_window_loads(M_U2, 2) == 0);
    m_fx_unit();
    m_ffault(M_TLMM, 0x5b00c);                                  /* a word in the middle of the pin controller: the window is dead for snapshot 2, and the words after it were never read */
    RUN_CLEAN();
    CHECK(m_line_starts("NEXT S2 TLMM") < 0 && m_has("DRIFT NONE CMP=17"));
    /* More than the page holds: the engine's words and the pins keep their lines, the clock words' items that do not fit are counted in MORE, and the cap holds. */
    m_fx_unit();
    m_at_wait = m_wait_flip_all;
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP && m_has("DRIFT CHANGED=") && m_has("CMP=19") && m_has("MORE=") && m_has("DU ") && m_has("DT "));
    return 0;
}

static void m_wait_two(void)
{
    m_fset(M_GCC, 0x23018, 0x3);
    m_fset(M_GCC, 0x23168, 0x1);
}

static int suite_note(void)
{
    /* Nothing moved: the verdict rides the NEXT line of the engine's snapshot-2 visit, and the GCC line itself carries none. */
    m_fx_unit();
    RUN_CLEAN();
    CHECK(m_line_index("NEXT S2 GCC", 0) > 0 && m_line_index("NEXT S2 U2 GCC=SAME", 0) > 0 && m_line_index("NEXT S2 TLMM", 0) > 0);
    /* One word, two words. */
    m_fx_unit();
    m_at_wait = m_wait_c21;
    RUN_CLEAN();
    CHECK(m_line_index("NEXT S2 U2 GCC=CHG:1", 0) > 0 && m_line_index("NEXT S2 TLMM", 0) > 0);
    m_fx_unit();
    m_at_wait = m_wait_two;
    RUN_CLEAN();
    CHECK(m_line_index("NEXT S2 U2 GCC=CHG:2", 0) > 0);
    /* When the engine has no snapshot-2 line, the next window's NEXT line carries it. */
    m_gate_word(M_U2, 0, 0x80000000u);
    RUN_CLEAN();
    CHECK(m_line_index("NEXT S2 TLMM GCC=SAME", 0) > 0 && m_line_starts("NEXT S2 U2") < 0);
    /* An engine skipped in snapshot 2 says so on that line, with the note and the verdict of its clock words. A word that aborts counts as changed, and is ERR, not OFF. */
    m_fx_unit();
    m_at_wait = m_wait_ma0_off;
    RUN_CLEAN();
    CHECK(m_line_index("S2 U2 SKIP GATED OFF GCC=CHG:1", 0) > 0 && m_line_index("NEXT S2 TLMM", 0) > 0);
    m_fx_unit();
    m_at_wait = m_wait_se0_fault;
    RUN_CLEAN();
    CHECK(m_line_index("S2 U2 SKIP GATED ERR GCC=CHG:2", 0) > 0);          /* the word that aborted and the core 2x clock after it, which was not read again */
    return 0;
}

/* The loads of a key's row: one, or two for a 64-bit register. */
static unsigned m_row_loads(unsigned w, const char *key)
{
    for (unsigned i = 0; i < M_NREGS; i++) if ((M_REGS[i].wins & W(w)) && !strcmp(M_REGS[i].key, key)) return 1u + M_REGS[i].wide;
    return 0;
}

/* Every line of snapshot 1 and of the late blocks has gone out with at most one row of loads after the rows it holds (the row that did not fit on it): a hang loses the line
 * being built and that row, and nothing before. With fields dropped there is no exact count, so the bound is the lower one. */
static int m_stream_ok(void)
{
    unsigned running = 0, base = 0, in_x = 0;
    int wait = m_line_index("NEXT WAIT 8 S", 0);
    for (unsigned i = 0; i < m_nlines; i++) {
        const char *text = m_lines[i] + strlen(PREFIX), *p;
        unsigned w = M_WINDOWS;
        char head[8];
        size_t n = strcspn(text, " ");
        if (!in_x && !strncmp(text, "NEXT X ", 7)) {
            in_x = 1;                                   /* the late blocks count their loads from here */
            base = m_line_loads[i];
            running = 0;
        }
        if (wait >= 0 && (int)i >= wait && !in_x) continue;
        snprintf(head, sizeof head, "%.*s", (int)(n < 7 ? n : 7), text);
        p = text + n;
        if (!strcmp(head, "X") && in_x) {
            size_t k = strspn(p, " ");
            n = strcspn(p + k, " ");
            snprintf(head, sizeof head, "%.*s", (int)(n < 7 ? n : 7), p + k);
            p += k + n;
        }
        for (unsigned k = 0; k < M_WINDOWS; k++) if (!strcmp(head, M_NAME[k])) w = k;
        if (w == M_WINDOWS) continue;
        while (*p) {
            char key[8];
            size_t len;
            while (*p == ' ') p++;
            len = strcspn(p, "= ");
            if (p[len] == '=' && len < sizeof key) {
                const char *value = p + len + 1;
                snprintf(key, sizeof key, "%.*s", (int)len, p);
                /* A row that was not read (SKIP, GATED, BUDGET, NA) made no load, one that aborted made one, the others as many as the register has words. */
                if (strncmp(value, "SKIP", 4) && strncmp(value, "GATED", 5) && strncmp(value, "BUDGET", 6) && strncmp(value, "NA", 2))
                    running += !strncmp(value, "FAULT", 5) ? (m_row_loads(w, key) ? 1u : 0u) : m_row_loads(w, key);
            }
            p += strcspn(p, " ");
        }
        if (m_line_loads[i] - (in_x ? base : 0u) < running || (!m_end_field("CUTS") && m_line_loads[i] - (in_x ? base : 0u) > running + 2)) return 0;
    }
    return 1;
}

/* Where a row starts a new line, the line before it has gone out before that row's loads. */
static int suite_stream(void)
{
    static const struct {
        const char *block, *first;
        unsigned w;
        const char *second;
    } PAIRS[] = {{"GCC", "MA0", M_GCC, "MA1"}, {"GCC", "MA1", M_GCC, "VT0"}, {"GIC", "CTL", M_GIC, "E616"}, {"U2", "FW", M_U2, "TXF"}, {"U2", "TXF", M_U2, "MIE"}};
    m_fx_unit();
    RUN_CLEAN();
    for (unsigned i = 0; i < sizeof PAIRS / sizeof PAIRS[0]; i++) {
        int line = m_line_holding(PAIRS[i].block, PAIRS[i].first), event = line < 0 ? -1 : m_line_event((unsigned)line), load = m_first_load_of(PAIRS[i].w, PAIRS[i].second);
        CHECK(event >= 0 && load >= 0 && event < load);
    }
    CHECK(m_stream_ok());
    m_fx_unit();
    m_at_wait = m_wait_flip_all;
    RUN_CLEAN();
    CHECK(m_stream_ok());
    m_fx_unit();
    m_ffault(M_U2, 0x258);
    RUN_CLEAN();
    CHECK(m_stream_ok());
    return 0;
}

static int in_list(const uint32_t *list, unsigned n, uint32_t off)
{
    for (unsigned i = 0; i < n; i++) if (list[i] == off) return 1;
    return 0;
}

/* The harness's own group of a GCC word, and how many words of that group the list names after it (the loads an abort in it leaves unread). */
static unsigned m_group_of(uint32_t off)
{
    unsigned hi;
    const struct m_reg *r = m_reg_of(M_GCC, off, &hi);
    return r ? r->group : 3u;
}

static unsigned m_group_after(uint32_t off)
{
    unsigned n = 0, seen = 0;
    for (unsigned i = 0; i < M_NREGS; i++) {
        if (!(M_REGS[i].wins & W(M_GCC)) || M_REGS[i].group != m_group_of(off)) continue;
        if (seen) n++;
        if (M_REGS[i].off == off) seen = 1;
    }
    return n;
}

/* An abort at every address snapshot 1 reads, in turn. In GCC an abort ends the rest of its group of words, and the gate words are in the groups: the engine of the group
 * is then not read (wrapper 0 gates the UART engine, wrapper 1 the SPI engine) if the abort is at one of its gate words, which come before the clock that gates nothing;
 * snapshot 2 and the late blocks do not read the words of a group that aborted, so they do not read the engine either (an unknown clock is not read through). */
static int suite_faults(void)
{
    uint64_t addrs[256];
    unsigned n = 0, named = 0, base[M_WINDOWS], base1[M_WINDOWS];
    m_fx_unit();
    RUN_CLEAN();
    for (unsigned w = 0; w < M_WINDOWS; w++) {
        base[w] = m_wloads[w];
        base1[w] = m_window_loads(w, 1);
    }
    for (unsigned i = 0; i < m_nevents && n < 256; i++) {
        if (m_events[i].kind != M_LOAD || m_events[i].phase != 1) continue;
        addrs[n++] = m_events[i].addr;
    }
    CHECK(n == LOADS_S1);
    for (unsigned i = 0; i < n; i++) {
        unsigned w = m_win_of(addrs[i]), hits = 0, grp;
        uint32_t off = (uint32_t)(addrs[i] - M_BASE[w]);
        const char *key = m_key_of(w, off);
        unsigned u2_total = base[M_U2], s10_total = base[M_S10], gate_u2, gate_s10;
        m_fx_unit();
        m_ffault(w, off);
        RUN_CLEAN();
        for (unsigned j = 0; j < m_nfake; j++) if (m_fake[j].addr == addrs[i]) hits = m_fake[j].hits;
        CHECK(hits == 1);                                   /* one access: no retry, and snapshot 2 does not read it again */
        CHECK(key != NULL && m_end_field("FAULTS") == 1 && m_end_field("BLK") != 0);
        named += key && m_fault_under(key);                 /* the abort is printed under the register's own name */
        grp = w == M_GCC ? m_group_of(off) : 3u;
        gate_u2 = grp == 0 && off != 0x23018;               /* the core 2x clock gates nothing and is the last word of its group */
        gate_s10 = grp == 1 && off != 0x23168;
        if (grp == 0) u2_total = gate_u2 ? 0 : base1[M_U2];
        if (grp == 1) s10_total = gate_s10 ? 0 : base1[M_S10];
        if (gate_u2) CHECK(m_line_index("U2 GATED ERR", 0) >= 0 && m_wloads[M_U2] == 0);
        else if (grp == 0) CHECK(m_line_index("U2 GATED ERR", 0) < 0 && m_window_loads(M_U2, 1) == base1[M_U2] && m_line_starts("S2 U2 SKIP GATED ERR") > 0);
        if (gate_s10) CHECK(m_line_index("S10 GATED ERR", 0) >= 0 && m_wloads[M_S10] == 0);
        else if (grp == 1) CHECK(m_line_index("S10 GATED ERR", 0) < 0 && m_window_loads(M_S10, 1) == base1[M_S10]);
        if (w != M_U2) CHECK(m_wloads[M_U2] == u2_total);
        if (w != M_S10) CHECK(m_wloads[M_S10] == s10_total);
        if (w != M_GIC) CHECK(m_wloads[M_GIC] == base[M_GIC]);
        if (w != M_TLMM) CHECK(m_wloads[M_TLMM] == base[M_TLMM]);
        if (w != M_GCC) CHECK(m_wloads[M_GCC] == base[M_GCC]);
        if (w == M_GCC) CHECK(m_window_loads(M_GCC, 1) == 14 - m_group_after(off));      /* the group's later words are not read, the other groups are */
        if (w == M_U2) CHECK(m_line_starts("NEXT S2 U2") < 0 && m_window_loads(M_U2, 3) == 0);        /* a window that aborted is not announced for snapshot 2, nor read late */
        if (w == M_S10) CHECK(m_window_loads(M_S10, 3) == 0);
        if (w == M_GIC) CHECK(m_window_loads(M_GIC, 3) == 0);
        if (w == M_TLMM) CHECK(m_line_starts("NEXT S2 TLMM") < 0);
        if (w == M_GCC) CHECK(m_line_starts("NEXT S2 GCC") > 0);      /* the other groups of GCC still are */
        CHECK(m_stream_ok());
    }
    CHECK(named == n);
    return 0;
}

/* An abort at every address of the late blocks, in turn: one access, FAULT:6 under the row's own name, and nothing else of that window read afterwards; the pages before it
 * are what they were, and so is every other window. */
static int suite_faults3(void)
{
    uint64_t addrs[64];
    unsigned n = 0, base[M_WINDOWS], seen[M_WINDOWS] = {0};
    m_fx_unit();
    RUN_CLEAN();
    for (unsigned w = 0; w < M_WINDOWS; w++) base[w] = m_window_loads(w, 3);
    for (unsigned i = 0; i < m_nevents && n < 64; i++) {
        if (m_events[i].kind != M_LOAD || m_events[i].phase != 3) continue;
        addrs[n++] = m_events[i].addr;
    }
    CHECK(n == LOADS_X);
    for (unsigned i = 0; i < n; i++) {
        unsigned w = m_win_of(addrs[i]), hits = 0;
        uint32_t off = (uint32_t)(addrs[i] - M_BASE[w]);
        const char *key = m_key_of(w, off);
        m_fx_unit();
        m_ffault(w, off);
        RUN_CLEAN();
        seen[w]++;
        for (unsigned j = 0; j < m_nfake; j++) if (m_fake[j].addr == addrs[i]) hits = m_fake[j].hits;
        CHECK(hits == 1 && key != NULL && m_fault_under(key) && m_end_field("FAULTS") == 1 && m_end_field("BLK") != 0);
        CHECK(m_window_loads(w, 3) == seen[w]);             /* the loads of that window's late block up to the abort, and none after it */
        for (unsigned k = 0; k < M_WINDOWS; k++) if (k != w) CHECK(m_window_loads(k, 3) == base[k]);
        CHECK(m_loads_in(1) == LOADS_S1 && m_loads_in(2) == LOADS_S2);
        CHECK(m_stream_ok());
    }
    return 0;
}

/* The suites that push the payload to its limits (aborts in snapshot 2, the 64-bit registers, hostile values, the counter, the order and the budgets of the page): their own
 * file, part of this translation unit. */
#include "test-q1n1-sp11-payload-inputsnap-limits.inc"
static void m_run_suite(const char *name, int (*suite)(void))
{
    unsigned fails = m_fails, checks = m_checks;
    (void)suite();
    printf("suite %-8s %s (%u checks)\n", name, m_fails == fails ? "ok" : "FAILED", m_checks - checks);
}

static void m_scenario(const char *name)
{
    m_fx_unit();
    if (!strcmp(name, "wide") || !strcmp(name, "wideflip")) m_fx_wide();
    if (!strcmp(name, "flip") || !strcmp(name, "wideflip")) m_at_wait = m_wait_flip_all;
    if (!strcmp(name, "rx")) m_at_wait = m_wait_rx5;
    if (!strcmp(name, "three")) m_at_wait = m_wait_three;
    if (!strcmp(name, "twogroups")) m_at_wait = m_wait_two_groups;
    if (!strcmp(name, "nocounter")) m_have_counter = 0;
    if (!strcmp(name, "hzdefault")) m_hz = 0;                      /* a frequency outside 1 to 1000 MHz: the page says DEFAULT */
    if (!strcmp(name, "el1")) m_el = 1;
    if (!strcmp(name, "noload32")) m_have_load32 = 0;
    if (!strcmp(name, "stuck")) m_ctr_mode = C_STUCK;
    if (!strcmp(name, "back")) m_ctr_mode = C_BACK;
    if (!strcmp(name, "slow")) {                    /* 8 million reads of the counter: SKIPPED SPIN in a build with a smaller bound */
        m_hz = 1000000u;
        m_ctr_step = 1;
    }
    if (!strcmp(name, "gated")) m_gcc_all(0x80000000u);
    if (!strcmp(name, "u2gated")) m_fset(M_GCC, 0x23000, 0x80000000u);
    if (!strcmp(name, "u2err")) m_ffault(M_GCC, 0x23000);
    if (!strcmp(name, "s2gated")) m_at_wait = m_wait_ma0_off;
    if (!strcmp(name, "s2err")) m_at_wait = m_wait_se0_fault;
    if (!strcmp(name, "u2abort")) m_ffault(M_U2, 0x040);
    if (!strcmp(name, "xabort")) m_ffault(M_U2, 0x4c);
    if (!strcmp(name, "gccabort")) m_ffault(M_GCC, 0x23008);
    if (!strcmp(name, "s2abort")) m_at_wait = m_wait_u2_fault;
    if (!strcmp(name, "odd")) {                     /* every decode that depends on a mode word has its mode word say it means nothing */
        m_fset(M_GCC, 0x23000, 0x80000002u);
        m_fset(M_GCC, 0x23018, 0xffffffffu);
        m_fset(M_U2, 0x068, 0x00000930);
        m_fset(M_U2, 0x258, 0x1);
    }
}

/* The numbers the document quotes, measured on runs of the model and nothing else: docs/SP11-PAYLOAD-INPUTSNAP.md carries them in one block that the document test
 * compares with this output. */
static void m_numbers(void)
{
    printf("registers %u\nblocks %u\nwindows %u\n", (unsigned)R_COUNT, (unsigned)BLOCKS, (unsigned)WINDOWS);
    printf("line_cap %u\nload_cap %u\nabi_lines %u\nabi_loads %u\n", LINE_CAP, LOAD_CAP, Q1N1_PAYLOAD_LINES_MAX, Q1N1_PAYLOAD_LOADS_MAX);
    printf("snapshot1_loads_max %u\nsnapshot2_loads_max %u\nlate_loads_max %u\n", (unsigned)S1_LOADS_MAX, (unsigned)S2_LOADS_MAX, (unsigned)X_LOADS_MAX);
    m_scenario("unit");
    RUN_CLEAN();
    printf("unit_lines %u\nunit_loads %u\nunit_snapshot1_loads %u\nunit_snapshot2_loads %u\nunit_late_loads %u\n", m_nlines, m_nloads, m_loads_in(1), m_loads_in(2), m_loads_in(3));
    m_scenario("wide");
    RUN_CLEAN();
    printf("wide_lines %u\nwide_cuts %u\n", m_nlines, m_end_field("CUTS"));
    m_scenario("wideflip");
    RUN_CLEAN();
    printf("wideflip_lines %u\nwideflip_cuts %u\n", m_nlines, m_end_field("CUTS"));
    m_scenario("gated");
    RUN_CLEAN();
    printf("gated_lines %u\ngated_loads %u\n", m_nlines, m_nloads);
}

int main(int argc, char **argv)
{
    m_install_trap();
    if (argc > 1 && (!strcmp(argv[1], "--page") || !strcmp(argv[1], "--scenario"))) {
        /* The page of a scenario, for the document and for a reader: --page is the unit-like fixture. */
        m_scenario(argc > 2 ? argv[2] : "unit");
        RUN_CLEAN();
        for (unsigned i = 0; i < m_nlines; i++) printf("%s\n", m_lines[i]);
        return m_fails != 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--numbers")) {
        m_numbers();
        return m_fails != 0;
    }
#if defined(INPUTSNAP_SHIPPED_CAPS)
    m_run_suite("table", suite_table);
    m_run_suite("unit", suite_unit);
    m_run_suite("decode", suite_decode);
    m_run_suite("gate", suite_gate);
    m_run_suite("drift", suite_drift);
    m_run_suite("note", suite_note);
    m_run_suite("stream", suite_stream);
    m_run_suite("order", suite_order);
    m_run_suite("faults", suite_faults);
    m_run_suite("faults2", suite_faults2);
    m_run_suite("faults3", suite_faults3);
    m_run_suite("wide", suite_wide);
    m_run_suite("storm", suite_storm);
    m_run_suite("counter", suite_counter);
    m_run_suite("spin", suite_spin);
    m_run_suite("el", suite_el);
    m_run_suite("budget", suite_budget);
    CHECK(m_max_loads <= LOADS_S1 + LOADS_S2 + LOADS_X && m_max_lines <= LINE_CAP);
#elif INPUTSNAP_SPIN_MAX != 0xffffffffu
    m_run_suite("spin", suite_spin);
#else
    m_run_suite("caps", suite_caps);
#endif
    printf("CHECKS %u FAILS %u MAXLINES %u MAXLOADS %u LINE_CAP %u LOAD_CAP %u\n", m_checks, m_fails, m_max_lines, m_max_loads, LINE_CAP, LOAD_CAP);
    return m_fails ? 1 : 0;
}
