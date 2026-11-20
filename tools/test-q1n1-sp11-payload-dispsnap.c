/* SPDX-License-Identifier: MIT */
/* Host test for the payload "dispsnap" (payloads/dispsnap.c): the suites. tools/test-q1n1-sp11-payload-dispsnap-model.h is what they run against (a fake register file of the four blocks with the
 * harness's own list of registers, its own statement of the gates, the order and NEXT rules, the counter and the runner's page); tools/test-q1n1-sp11-payload-dispsnap.py drives the build under
 * ASan and UBSan, and builds it again with DISPSNAP_SRC pointing at a seeded-bug copy of the payload to show that each mutant is refused. The suites pin what it prints:
 *   unit      the golden page of the open fixture (every gate open: made-up values, NOT the unit's page), its loads, that the loads are exactly the addresses of the harness's own list, the GOP and
 *             MAP lines against the harness's constants, the counter ticks between the two frame-counter readings; a window the table does not have is refused before the table is indexed
 *   cold      the MDSS GDSC off: the gate words are read, the DG line says OFF and nothing behind the gate is read or announced, only gated
 *   gate      the display register clock gate, the display verdict (PWR_ON, SW_COLLAPSE, HW_CONTROL, each of the two clocks, words that are all ones or aborted), the version gate of the DPU and the
 *             frame counter's enable: each in both directions, so that a closed gate is not too strict and an open one is not too loose; the `.ODD` cells; a context nobody initialised opens
 *             nothing behind DISPCC
 *   faults    an abort at every address in turn: one access, FAULT:6 under the register's own name, the window silent afterwards, not visited by snapshot 2, the gates closed that depend on it
 *   storm     every window aborting; all-ones and zero memory; hostile random words
 *   drift     what moves during the gap: the interface's words, the GCC word, the gate words (the interface is not read again), a fault in snapshot 2, more than the page holds
 *   stream    each line goes out before the first load of the next one, a NEXT line before every block, the verdict before the first MDSS load
 *   frames    the frame counter: read only after its enable says it counts, the second reading, the ticks between the two, a counter that did not move
 *   counter   running (the gap is at least 8 s), stuck, absent, running backwards, slow (a long wait is not a dead counter, and the bound on the reads is wide); `spin` (only a build with a small
 *             DISPSNAP_SPIN_MAX): a counter that moves and never gets there says SPIN, not NO_COUNTER
 *   el        any EL but 2: one line, no load; arguments; the framebuffer is neither read nor printed
 *   budget    the widest values: no field is cut and the cap holds
 * With DISPSNAP_LINE_CAP or DISPSNAP_LOAD_CAP set, only the cap suite runs. `--page [scenario]` prints a page, `--numbers` the numbers the document quotes.
 * Nothing here ran on hardware. Evidence: EXPERIMENTAL (host model only). */
/* Whether the build chose its own bound on the reads of the wait: the payload's header defines the default only after this point. */
#ifdef DISPSNAP_SPIN_MAX
#define M_SPIN_OVERRIDE 1
#else
#define M_SPIN_OVERRIDE 0
#endif
#include "test-q1n1-sp11-payload-dispsnap-model.h"

/* The pages of the two fixtures, line by line (without the prefix). Made-up pages: see the fixtures in the model. */
static const char *const GOLDEN_ON[] = {
    "READ ONLY EL=2 HZ=0X124F800 GAP=8 S",
    "KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=BIT 31 NOT TRUSTED NO STORE NO AUX NO IRQ STATUS",
    "GOP W=2880 H=1920 STRIDE=2880 FMT=1",
    "MAP GCC=0X100000 DISPCC=0XAF00000 MDSS=0XAE00000 DPU=0XAE01000",
    "MAP INTF=5 AT=0X39000 CTL=0X15000 STEP=0X1000 REG=0XF4",
    "NEXT GCC",
    "GCC DAHB=1.ON",
    "NEXT DISPCC",
    "DISPCC GDSC=0X8022F000.ON SC=0 HW=0",
    "DISPCC AHBC=1.ON MDPC=1.ON",
    "DG DISP=ON PWR=1 SC=0 HW=0 CLK=0X3",
    "NEXT MDSS",
    "MDSS VER=0X90020000 MAJ=9 MIN=2",
    "NEXT DPU",
    "INTF ST=1 EN=1 CFG=0X60000000 CFG2=0X10",
    "INTF HS=0XBE00020 VP=0X5C4F40 DVS=0X19FF0 DVE=0X5AAF4F",
    "INTF AVS=0X19FF0 AVE=0X5AAFEF DHC=0XB8F0050 AHC=0XB8F0050",
    "INTF FLC=3 FRA=0X3E8",
    "CTL C0=0X20 C1=0 C2=0",
    "CTL C3=0 C4=0 C5=0",
    "NEXT WAIT 8 S",
    "NEXT S2 GCC",
    "NEXT S2 DISPCC GCC=SAME",
    "NEXT S2 DPU DISPCC=SAME",
    "S2 INTF ST=1 EN=1 FRB=0X5C8 DT=0X9308A00",
    "DRIFT NONE CMP=6",
    "END LOADS=32 FAULTS=0 SKIPS=0 BLK=0 CUTS=0 GAP_MS=8030 LINES=27",
};
#define LOADS_ON 32u                    /* 25 in snapshot 1, 7 in snapshot 2 */
#define LOADS_S1_ON 25u
#define LOADS_S2 7u

static const char *const GOLDEN_COLD[] = {
    "READ ONLY EL=2 HZ=0X124F800 GAP=8 S",
    "KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=BIT 31 NOT TRUSTED NO STORE NO AUX NO IRQ STATUS",
    "GOP W=2880 H=1920 STRIDE=2880 FMT=1",
    "MAP GCC=0X100000 DISPCC=0XAF00000 MDSS=0XAE00000 DPU=0XAE01000",
    "MAP INTF=5 AT=0X39000 CTL=0X15000 STEP=0X1000 REG=0XF4",
    "NEXT GCC",
    "GCC DAHB=1.ON",
    "NEXT DISPCC",
    "DISPCC GDSC=0X222001.OFF SC=1 HW=0",
    "DISPCC AHBC=0X80000000.OFF MDPC=0X80000000.OFF",
    "DG DISP=OFF PWR=0 SC=1 HW=0 CLK=0X0",
    "MDSS GATED BY DISP=OFF",
    "DPU GATED BY DISP=OFF",
    "NEXT WAIT 8 S",
    "NEXT S2 GCC",
    "NEXT S2 DISPCC GCC=SAME",
    "DRIFT NONE CMP=4",
    "END LOADS=8 FAULTS=0 SKIPS=0 BLK=0XC CUTS=0 GAP_MS=8020 LINES=18",
};
#define LOADS_COLD 8u                   /* 4 in snapshot 1, 4 in snapshot 2 */

static int m_line_starts(const char *tail)
{
    char want[100];
    size_t n;
    snprintf(want, sizeof want, "%s%s", PREFIX, tail);
    n = strlen(want);
    for (unsigned i = 0; i < m_nlines; i++) if (!strncmp(m_lines[i], want, n) && (m_lines[i][n] == 0 || m_lines[i][n] == ' ')) return (int)i;
    return -1;
}

/* The loads of a run are the harness's own list for the blocks that are open and nothing else: m_load32 already refuses a load outside it, this refuses a list that is wider than what the
 * payload reads (a seeded extra read of a listed-but-unread register would pass otherwise). `blocks` is a bit per block that must be read in snapshot 1; snapshot 2 reads the GCC word, the three
 * gate words and the interface's STATUS, enable and frame counter, in those of the blocks that are read in snapshot 1 and, since the memory does not change, still open after the wait. */
static void m_check_reads_are_the_list(unsigned blocks)
{
    for (unsigned i = 0; i < M_NREGS; i++) {
        unsigned read = (blocks >> M_REGS[i].block & 1) ? 1u : 0u;
        unsigned in_s1 = read ? 1u : 0u;
        unsigned in_s2 = in_s1 && (M_REGS[i].block == M_GCC || M_REGS[i].block == M_DISPCC || M_DPU_S2(&M_REGS[i])) ? 1u : 0u;
        CHECK(m_loads_of(M_REGS[i].addr, 0) == in_s1);
        CHECK(m_loads_of(M_REGS[i].addr, 2) == in_s2);
    }
}

static int suite_unit(void)
{
    static const char *const NEXT[] = {"NEXT GCC", "NEXT DISPCC", "NEXT MDSS", "NEXT DPU", "NEXT WAIT 8 S", "NEXT S2 GCC", "NEXT S2 DISPCC GCC=SAME", "NEXT S2 DPU DISPCC=SAME"};
    int at = -1;
    m_fx_on();
    RUN_CLEAN();
    CHECK(m_nlines == sizeof GOLDEN_ON / sizeof GOLDEN_ON[0]);
    for (unsigned i = 0; i < sizeof GOLDEN_ON / sizeof GOLDEN_ON[0]; i++) m_line_is(i, GOLDEN_ON[i], __LINE__);
    CHECK(m_nloads == LOADS_ON && m_loads_in(0) == LOADS_S1_ON && m_loads_in(2) == LOADS_S2);
    CHECK(m_sysreg_reads == 2);
    CHECK(m_bloads[M_GCC] == 2 && m_bloads[M_DISPCC] == 6 && m_bloads[M_MDSS] == 1 && m_bloads[M_DPU] == 23);
    m_check_reads_are_the_list(0xf);
    for (unsigned i = 0; i < sizeof NEXT / sizeof NEXT[0]; i++) {
        int found = m_line_index(NEXT[i], (unsigned)(at + 1));
        CHECK(found > at);
        at = found;
    }
    CHECK(m_end_field("FAULTS") == 0 && m_end_field("SKIPS") == 0 && m_end_field("CUTS") == 0 && m_end_field("BLK") == 0);
    CHECK(m_end_field("GAP_MS") >= 8000 && m_end_field("GAP_MS") < 8100);
    CHECK(m_gap_ticks >= 8u * m_hz);
    /* the first load of every block is a word Linux reads in that block: the display register clock (read-modify-write at probe), the GDSCR, the hardware version, STATUS */
    {
        static const char *const FIRST[M_BLOCKS] = {"DAHB", "GDSC", "VER", "ST"};
        for (unsigned b = 0; b < M_BLOCKS; b++) {
            for (unsigned i = 0; i < m_nevents; i++) {
                const struct m_reg *r = m_events[i].kind == M_LOAD ? m_find(m_events[i].addr) : NULL;
                if (!r || r->block != b) continue;
                CHECKM(!strcmp(r->key, FIRST[b]), FIRST[b]);
                break;
            }
        }
    }
    /* the GOP line is the arguments' mode and nothing else, and the MAP lines are the harness's constants: the host side computes every address from them */
    {
        char want[100];
        snprintf(want, sizeof want, "GOP W=%u H=%u STRIDE=%u FMT=%u", m_gop_w, m_gop_h, m_gop_stride, m_gop_fmt);
        CHECK(m_line_index(want, 0) == 2);
        snprintf(want, sizeof want, "MAP GCC=%#llX DISPCC=%#llX MDSS=%#llX DPU=%#llX", (unsigned long long)X_GCC, (unsigned long long)X_DISPCC, (unsigned long long)X_MDSS,
                 (unsigned long long)X_DPU);
        for (char *p = want; *p; p++) if (*p == 'x') *p = 'X';
        CHECK(m_line_index(want, 0) == 3);
        snprintf(want, sizeof want, "MAP INTF=%u AT=%#X CTL=%#X STEP=%#X REG=%#X", 5u, 0x39000u, 0x15000u, 0x1000u, 0xf4u);
        for (char *p = want; *p; p++) if (*p == 'x') *p = 'X';
        CHECK(m_line_index(want, 0) == 4);
    }
    /* DT is the counter ticks between the two readings of the frame counter, measured from the same place in both snapshots */
    CHECK(m_ctr_at_fra && m_ctr_at_frb > m_ctr_at_fra);
    {
        const char *p = strstr(m_lines[24], " DT=");
        CHECK(p && strtoull(p + 4, NULL, 0) == m_ctr_at_frb - m_ctr_at_fra && m_ctr_at_frb - m_ctr_at_fra >= 8u * m_hz);
    }
    /* a window the table does not have is refused before `windows` is indexed, whatever the offset: no load, no state change. With a misaligned offset an unchecked rd32 answers RD_ALIGN, so the
     * first calls show that the window comes first; the aligned calls (which an unchecked build would index past the table with) run only if those held */
    {
        struct ctx c;
        uint32_t w;
        unsigned before;
        static const unsigned BAD[] = {WINDOWS, WINDOWS + 1, 32, 255, 0x80000000u, 0xffffffffu};
        m_fx_on();
        memset(&c, 0, sizeof c);
        c.load32 = m_load32;
        before = m_fails;
        for (unsigned i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
            w = 0x5a5a5a5a;
            CHECKM(rd32(&c, BAD[i], 1, &w) == RD_RANGE && w == 0, "misaligned offset, window the table does not have");
        }
        if (m_fails == before) {
            for (unsigned i = 0; i < sizeof BAD / sizeof BAD[0]; i++) {
                w = 0x5a5a5a5a;
                CHECKM(rd32(&c, BAD[i], 0x20, &w) == RD_RANGE && w == 0, "aligned offset, window the table does not have");
            }
        }
        CHECK(m_nloads == 0 && m_violations == 0 && c.dead == 0 && c.loads == 0);
    }
    return 0;
}

static int suite_cold(void)
{
    m_fx_cold();
    RUN_CLEAN();
    CHECK(m_nlines == sizeof GOLDEN_COLD / sizeof GOLDEN_COLD[0]);
    for (unsigned i = 0; i < sizeof GOLDEN_COLD / sizeof GOLDEN_COLD[0]; i++) m_line_is(i, GOLDEN_COLD[i], __LINE__);
    CHECK(m_nloads == LOADS_COLD);
    CHECK(m_bloads[M_GCC] == 2 && m_bloads[M_DISPCC] == 6 && !m_bloads[M_MDSS] && !m_bloads[M_DPU]);
    m_check_reads_are_the_list(0x3);
    CHECK(!m_has("NEXT MDSS") && !m_has("NEXT DPU") && !m_has("NEXT S2 DPU") && !m_has("S2 INTF"));
    CHECK(m_end_field("BLK") == 0xc);
    return 0;
}

/* One variation of the open fixture: `set` changes the memory, the page and the reads are then held to the harness's own gates (in m_load32) and to what `expect` says here. */
struct gate_case {
    const char *what;
    const char *key;
    uint32_t value;
    const char *line;               /* a page line (a prefix of a line) that must be there */
    unsigned blocks;                /* the blocks that must be read in snapshot 1 */
};

static void m_run_case(const struct gate_case *g, int at)
{
    m_fx_on();
    m_set(m_addr(g->key), g->value);
    RUN_CLEAN();
    m_checks++;
    if (g->line && m_line_starts(g->line) < 0) {
        m_fails++;
        fprintf(stderr, "FAIL line %d: %s: no page line starts with \"%s\"\n", at, g->what, g->line);
        m_dump(stderr);
    }
    m_checks++;
    for (unsigned b = 0; b < M_BLOCKS; b++) {
        if (!!m_bloads[b] != !!(g->blocks >> b & 1)) {
            m_fails++;
            fprintf(stderr, "FAIL line %d: %s: block %s was %s\n", at, g->what, M_NAME[b], m_bloads[b] ? "read" : "not read");
            m_dump(stderr);
            break;
        }
    }
}

#define B_ALL 0xfu
#define B_NODPU 0x7u            /* everything but the DPU */
#define B_DISPCC 0x3u
#define B_GCC_ONLY 0x1u
static int suite_gate(void)
{
    static const struct gate_case CASES[] = {
        /* the display register clock gate: positive proof only */
        {"DAHB enabled, CLK_OFF clear", "DAHB", 0x1, "DG DISP=ON", B_ALL},
        {"DAHB enabled, CLK_OFF clear, other bits set", "DAHB", 0x7fffffff, "DG DISP=ON", B_ALL},
        {"DAHB not enabled", "DAHB", 0x0, "DISPCC GATED BY DAHB", B_GCC_ONLY},
        {"DAHB CLK_OFF set", "DAHB", 0x80000001, "DISPCC GATED BY DAHB", B_GCC_ONLY},
        {"DAHB CLK_OFF set and bit 1 set: it has no hardware gating bit in Linux", "DAHB", 0x80000003, "DISPCC GATED BY DAHB", B_GCC_ONLY},
        {"DAHB a failed read: not 'the clock is off'", "DAHB", 0xffffffff, "DISPCC GATED BY DAHBERR", B_GCC_ONLY},
        {"DAHB NoC FSM status ON but CLK_OFF set: no proof", "DAHB", 0xa0000001, "DISPCC GATED BY DAHB", B_GCC_ONLY},
        /* the display verdict: the GDSC */
        {"GDSC PWR_ON clear", "GDSC", 0x0022f000, "DG DISP=OFF PWR=0", B_DISPCC},
        {"GDSC bit 31 clear, bits 30:0 set", "GDSC", 0x7ffffffc, "DG DISP=OFF PWR=0", B_DISPCC},
        {"GDSC SW_COLLAPSE set under PWR_ON (on only by another vote)", "GDSC", 0x8022f001, "DG DISP=OFF PWR=1 SC=1", B_DISPCC},
        {"GDSC HW_CONTROL set", "GDSC", 0x8022f002, "DG DISP=HWCTL", B_DISPCC},
        {"GDSC HW_CONTROL and SW_COLLAPSE set", "GDSC", 0x8022f003, "DG DISP=HWCTL", B_DISPCC},
        {"GDSC a failed read", "GDSC", 0xffffffff, "DG DISP=UNK", B_DISPCC},
        /* the display verdict: the two clocks */
        {"AHBC off", "AHBC", 0x80000000, "DG DISP=PART PWR=1 SC=0 HW=0 CLK=0X2", B_DISPCC},
        {"AHBC enabled, CLK_OFF set", "AHBC", 0x80000001, "DG DISP=PART PWR=1 SC=0 HW=0 CLK=0X2", B_DISPCC},
        {"AHBC enabled, CLK_OFF set, bit 1 set: this clock has no hardware gating bit", "AHBC", 0x80000003, "DG DISP=PART PWR=1 SC=0 HW=0 CLK=0X2", B_DISPCC},
        {"AHBC not enabled", "AHBC", 0x0, "DG DISP=PART PWR=1 SC=0 HW=0 CLK=0X2", B_DISPCC},
        {"MDPC off", "MDPC", 0x80000001, "DG DISP=PART PWR=1 SC=0 HW=0 CLK=0X1", B_DISPCC},
        {"MDPC not enabled", "MDPC", 0x0, "DG DISP=PART PWR=1 SC=0 HW=0 CLK=0X1", B_DISPCC},
        {"MDPC NoC FSM status ON but CLK_OFF set: no proof", "MDPC", 0xa0000001, "DG DISP=PART PWR=1 SC=0 HW=0 CLK=0X1", B_DISPCC},
        {"a clock word reads as a failed read", "MDPC", 0xffffffff, "DG DISP=UNK", B_DISPCC},
        {"the other clock word reads as a failed read", "AHBC", 0xffffffff, "DG DISP=UNK", B_DISPCC},
        /* the version gate of the DPU: the MDSS is read, the DPU is not behind a word that does not look like a version */
        {"VER zero", "VER", 0x0, "DPU GATED BY VER", 0x7u},
        {"VER all ones: a failed read, not 'zero'", "VER", 0xffffffff, "DPU GATED BY VERERR", 0x7u},
        {"VER another DPU version: read, decoded, the DPU is still read", "VER", 12u << 28 | 2u << 16, "MDSS VER=0XC0020000 MAJ=0XC MIN=2", B_ALL},
        {"VER with only the step set", "VER", 0x1, "MDSS VER=1 MAJ=0 MIN=0", B_ALL},
        /* the frame counter's enable: the counter is read only when it says it counts */
        {"FLC zero: the counter is not read", "FLC", 0x0, "INTF FLC=0 FRA=NOFLC", B_ALL},
        {"FLC all ones: a failed read, the counter is not read", "FLC", 0xffffffff, "INTF FLC=0XFFFFFFFF FRA=NOFLC", B_ALL},
        {"FLC bit 0 only: the counter is read", "FLC", 0x1, "INTF FLC=1 FRA=0X3E8", B_ALL},
    };
    for (unsigned i = 0; i < sizeof CASES / sizeof CASES[0]; i++) m_run_case(&CASES[i], __LINE__);
    /* both clocks off at once, the GDSC on: PART, not OFF */
    m_fx_on();
    m_set(m_addr("AHBC"), 0x80000000); m_set(m_addr("MDPC"), 0x80000000);
    RUN_CLEAN();
    CHECK(m_has("DG DISP=PART PWR=1 SC=0 HW=0 CLK=0") && m_has("MDSS GATED BY DISP=PART") && m_has("DPU GATED BY DISP=PART"));
    /* a GCC clock that does not run takes DISPCC and everything behind it with it, and says why */
    m_fx_on();
    m_set(m_addr("DAHB"), 0x80000000);
    RUN_CLEAN();
    CHECK(m_has("DISPCC GATED BY DAHB") && m_has("MDSS GATED BY DAHB") && m_has("DPU GATED BY DAHB") && !m_has("DG ") && !m_has("NEXT DISPCC"));
    CHECK(m_loads_in(2) == 1 && !m_has("S2 DISPCC"));
    /* a gate input that could not be read is reported as that, never as the thing it gates on */
    m_fx_on();
    m_fault_at(m_addr("DAHB"));
    RUN_CLEAN();
    CHECK(m_has("DAHB=FAULT:6") && m_line_starts("DISPCC GATED BY DAHBERR") >= 0 && m_line_starts("MDSS GATED BY DAHBERR") >= 0 && m_line_starts("DISPCC GATED BY DAHB ") < 0);
    m_fx_on();
    m_fault_at(m_addr("AHBC"));
    RUN_CLEAN();
    CHECK(m_has("AHBC=FAULT:6") && m_has("DG DISP=UNK") && m_line_starts("MDSS GATED BY DISP=UNK") >= 0 && m_line_starts("MDSS GATED BY DISP=PART") < 0 && m_line_starts("MDSS GATED BY DISP=OFF") < 0);
    m_fx_on();
    m_fault_at(m_addr("VER"));
    RUN_CLEAN();
    CHECK(m_has("VER=FAULT:6") && m_line_starts("DPU GATED BY VERERR") >= 0 && m_line_starts("DPU GATED BY VER ") < 0 && !m_bloads[M_DPU]);
    /* a cell whose bit 31 cannot be taken at its word says so (.ODD): all ones; CLK_OFF clear with CLK_ENABLE clear; CLK_OFF with an NoC FSM status of ON. The same bits on a GDSC word are a
     * plain PWR_ON, and a bit field cut from a word of all ones is no field. */
    {
        static const struct {
            const char *key;
            uint32_t word;
            const char *want;
        } ODD[] = {
            {"DAHB", 0xffffffff, " DAHB=0XFFFFFFFF.ODD"},     {"AHBC", 0xa0000001, " AHBC=0XA0000001.ODD"},     {"AHBC", 0x90000001, " AHBC=0X90000001.OFF"},
            {"AHBC", 0x20000001, " AHBC=0X20000001.ON"},      {"MDPC", 0x80000003, " MDPC=0X80000003.OFF"},     {"GDSC", 0xffffffff, " GDSC=0XFFFFFFFF.ODD SC=ODD HW=ODD"},
            {"GDSC", 0x7fffffff, " GDSC=0X7FFFFFFF.OFF"},     {"GDSC", 0x80000000, " GDSC=0X80000000.ON SC=0 HW=0"},
            /* CLK_OFF clear with CLK_ENABLE clear is a clock that says it runs without being enabled, which is what a window of zeros reads: no .ON for it (the gate needs the enable and is unchanged) */
            {"DAHB", 0x0, " DAHB=0.ODD"}, {"AHBC", 0x30000000, " AHBC=0X30000000.ODD"}, {"MDPC", 0x2, " MDPC=2.ODD"},
            /* a bit field cut from a word of all ones is no field */
            {"VER", 0xffffffff, " VER=0XFFFFFFFF MAJ=ODD MIN=ODD"},
        };
        for (unsigned i = 0; i < sizeof ODD / sizeof ODD[0]; i++) {
            m_fx_on();
            m_set(m_addr(ODD[i].key), ODD[i].word);
            RUN_CLEAN();
            CHECKM(m_has(ODD[i].want), ODD[i].want);
        }
    }
    /* an odd cell moves no gate: a clock that says it runs without being enabled does not open DISPCC */
    m_fx_on();
    m_set(m_addr("DAHB"), 0x0);
    RUN_CLEAN();
    CHECK(m_has(" DAHB=0.ODD") && m_has("DISPCC GATED BY DAHB") && !m_has("NEXT DISPCC"));
    /* a context nobody initialised is closed: DX_UNK is the zero verdict, so with the display register clock running (the only other thing a block's gate asks of the context) nothing behind
     * DISPCC is open and the reason says why; only an explicit DX_ON opens the MDSS, and the DPU also needs its version word */
    {
        struct ctx c;
        memset(&c, 0, sizeof c);
        c.s[0].v[R_DAHB].v = 1;
        c.s[0].v[R_DAHB].st = V_OK;
        CHECK(c.disp == DX_UNK && !strcmp(disp_name[c.disp], "UNK"));
        CHECK(gate_reason(&c, WIN_GCC) == RS_OPEN && gate_reason(&c, WIN_DISPCC) == RS_OPEN);
        for (unsigned win = WIN_MDSS; win < WINDOWS; win++) CHECKM(!strcmp(reason_name[gate_reason(&c, win)], "DISP=UNK"), window_name[win]);
        c.disp = DX_ON;
        CHECK(gate_reason(&c, WIN_MDSS) == RS_OPEN);
        CHECK(!strcmp(reason_name[gate_reason(&c, WIN_DPU)], "VERERR"));
        c.s[0].v[R_VER].v = 0x90020000u;
        c.s[0].v[R_VER].st = V_OK;
        CHECK(gate_reason(&c, WIN_DPU) == RS_OPEN);
    }
    return 0;
}

/* An abort at every address of the list in turn, in the open fixture. */
static int suite_faults(void)
{
    for (unsigned i = 0; i < M_NREGS; i++) {
        const struct m_reg *r = &M_REGS[i];
        char want[40];
        m_fx_on();
        m_fault_at(r->addr);
        RUN_CLEAN();
        CHECK(m_loads_of(r->addr, 0) == 1 && m_loads_of(r->addr, 2) == 0);
        snprintf(want, sizeof want, " %s=FAULT:6", r->key);
        CHECK(m_has(want));
        CHECK(m_end_field("FAULTS") >= 1);
        /* the window is read no more, in either snapshot, and snapshot 2 does not announce it */
        if (r->block == M_GCC || r->block == M_DISPCC || r->block == M_DPU) {
            snprintf(want, sizeof want, "NEXT S2 %s", M_NAME[r->block]);
            CHECK(m_line_starts(want) < 0);
        }
        CHECK((m_end_field("BLK") >> r->block & 1) == 1);
        /* every word of the window after the one that aborted prints SKIP and is not loaded */
        for (unsigned j = i + 1; j < M_NREGS && M_REGS[j].block == r->block; j++) {
            snprintf(want, sizeof want, " %s=SKIP", M_REGS[j].key);
            CHECK(m_loads_of(M_REGS[j].addr, 0) == 0 && m_has(want));
        }
    }
    /* a fault in the first word of DISPCC that matters: the verdict is unknown and nothing behind it is read */
    m_fx_on();
    m_fault_at(m_addr("GDSC"));
    RUN_CLEAN();
    CHECK(m_has("DG DISP=UNK") && m_has("MDSS GATED BY DISP=UNK") && !m_bloads[M_MDSS] && !m_bloads[M_DPU]);
    /* an abort at the frame counter's enable: the counter is skipped as every word after an abort is, not called absent, and the first CTL page is not read */
    m_fx_on();
    m_fault_at(m_addr("FLC"));
    RUN_CLEAN();
    CHECK(m_has("INTF FLC=FAULT:6 FRA=SKIP") && m_has("CTL C0=SKIP C1=SKIP C2=SKIP") && !m_has("NOFLC"));
    return 0;
}

static void m_wait_flip_all(void)
{
    for (unsigned i = 0; i < M_NREGS; i++) {
        int fault;
        if (M_REGS[i].block == M_MDSS) continue;
        m_set(M_REGS[i].addr, ~m_value(M_REGS[i].addr, &fault) & 0x7fffffffu);
    }
}

/* Every word the second look reads moves, but the ones the gates are made of, so that the interface is still read again and the drift list is as long as it can be. */
static void m_wait_flip_non_gate(void)
{
    m_set(m_addr("ST"), 0x3);
    m_set(m_addr("EN"), 0x2);
}

static int suite_storm(void)
{
    m_fx_on();
    m_win_faults = 0xf;                  /* every window aborts on its first load */
    RUN_CLEAN();
    CHECK(m_loads_in(0) == 1);          /* GCC aborts: DAHB is unknown, DISPCC and the rest are gated */
    CHECK(m_has("DAHB=FAULT:6") && m_has("DISPCC GATED BY DAHBERR") && m_line_starts("DISPCC GATED BY DAHB ") < 0);
    m_fx_on();
    m_win_faults = 0xe;                  /* GCC reads, DISPCC aborts on its first load */
    RUN_CLEAN();
    CHECK(m_bloads[M_GCC] == 2 && m_bloads[M_DISPCC] == 1 && m_has("DG DISP=UNK") && m_has("MDSS GATED BY DISP=UNK"));
    m_fx_on();
    m_win_faults = 0xc;                  /* the MDSS and the DPU abort: they are not read, so they cannot */
    RUN_CLEAN();
    CHECK(m_bloads[M_MDSS] == 1 && m_has("VER=FAULT:6") && m_has("DPU GATED BY VERERR") && m_bloads[M_DPU] == 0);
    m_fx_on();
    m_win_faults = 0x8;                  /* only the DPU aborts: on its first load, STATUS */
    RUN_CLEAN();
    CHECK(m_bloads[M_DPU] == 1 && m_has("ST=FAULT:6 EN=SKIP CFG=SKIP CFG2=SKIP") && m_has("FRA=SKIP") && m_has("C5=SKIP"));
    m_fx_on();
    m_fill_all = 1;
    m_fill = 0xffffffffu;               /* a dead bus reads all ones */
    RUN_CLEAN();
    CHECK(m_bloads[M_DISPCC] == 0 && m_has("DISPCC GATED BY DAHB"));
    m_fx_on();
    m_fill_all = 1;
    m_fill = 0;
    RUN_CLEAN();
    CHECK(m_bloads[M_DISPCC] == 0);     /* ENABLE clear: closed */
    for (uint64_t seed = 1; seed <= 300; seed++) {
        m_fx_on();
        m_rand_seed = seed * UINT64_C(0x2545F4914F6CDD1D);
        m_nfake = 0;
        RUN_CLEAN();
    }
    return 0;
}

/* What moves during the wait. */
static void m_wait_st(void) { m_set(m_addr("ST"), 0x0); }
static void m_wait_en_off(void) { m_set(m_addr("EN"), 0x0); }
static void m_wait_ahb_off(void) { m_set(m_addr("DAHB"), 0x80000000); }
static void m_wait_gdsc_off(void) { m_set(m_addr("GDSC"), 0x00222001); }
static void m_wait_hwctl(void) { m_set(m_addr("GDSC"), 0x8022f002); }
static void m_wait_clock_part(void) { m_set(m_addr("MDPC"), 0x80000001); }
static void m_wait_gdsc_fault(void) { m_fault_at(m_addr("GDSC")); }
static void m_wait_dahb_fault(void) { m_fault_at(m_addr("DAHB")); }
static void m_wait_ahbc_fault(void) { m_fault_at(m_addr("AHBC")); }
static void m_wait_en_fault(void) { m_fault_at(m_addr("EN")); }
static void m_wait_fra_fault(void) { m_fault_at(m_addr("FRA")); }
static void m_wait_ver(void) { m_set(m_addr("VER"), 0); }

static int suite_drift(void)
{
    m_fx_on();
    RUN_CLEAN();
    CHECK(m_has("DRIFT NONE CMP=6") && m_has("S2 INTF ST=1 EN=1 FRB=0X5C8 DT="));
    m_fx_on();
    m_at_wait = m_wait_st;
    RUN_CLEAN();
    CHECK(m_has("NEXT S2 DPU DISPCC=SAME") && m_has("DD ST=1-0") && m_has("DRIFT CHANGED=1 LOST=0 CMP=6") && m_has("S2 INTF ST=0 EN=1 FRB=0X5C8"));
    m_fx_on();
    m_at_wait = m_wait_en_off;
    RUN_CLEAN();
    CHECK(m_has("DD EN=1-0") && m_has("DRIFT CHANGED=1 LOST=0 CMP=6") && m_has("S2 INTF ST=1 EN=0 FRB=0X5C8"));
    /* the display register clock goes off during the wait: DISPCC and the interface are not read again, and say why; the first snapshot's values are not compared */
    m_fx_on();
    m_at_wait = m_wait_ahb_off;
    RUN_CLEAN();
    CHECK(m_has("S2 DISPCC GATED BY DAHB GCC=CHG:1") && m_has("S2 DPU GATED BY DAHB") && m_loads_in(2) == 1 && m_has("DG DAHB=1-0X80000000") && m_has("DRIFT CHANGED=1 LOST=0 CMP=1"));
    CHECK(m_line_starts("NEXT S2 DISPCC") < 0 && m_line_starts("NEXT S2 DPU") < 0 && !m_has("S2 INTF"));
    CHECK((m_end_field("BLK") >> M_DISPCC & 1) == 1 && (m_end_field("BLK") >> M_DPU & 1) == 1);
    /* the display went off, or under hardware control, or lost a clock, during the wait: the interface is not read again (not "the pipeline stopped": the page says which gate) */
    m_fx_on();
    m_at_wait = m_wait_gdsc_off;
    RUN_CLEAN();
    CHECK(m_has("NEXT S2 DISPCC GCC=SAME") && m_has("S2 DPU GATED BY DISP=OFF DISPCC=CHG:1") && m_has("DG GDSC=0X8022F000-0X222001") && m_loads_in(2) == 4 && !m_has("S2 INTF"));
    m_fx_on();
    m_at_wait = m_wait_hwctl;
    RUN_CLEAN();
    CHECK(m_has("S2 DPU GATED BY DISP=HWCTL") && m_loads_in(2) == 4);
    m_fx_on();
    m_at_wait = m_wait_clock_part;
    RUN_CLEAN();
    CHECK(m_has("S2 DPU GATED BY DISP=PART") && m_loads_in(2) == 4);
    /* a fault in snapshot 2: the abort replaces the value, the window is read no more, and the interface cannot be judged (DISP=UNK, not "off") */
    m_fx_on();
    m_at_wait = m_wait_gdsc_fault;
    RUN_CLEAN();
    CHECK(m_has("DG GDSC=0X8022F000-FAULT:6") && m_has("S2 DPU GATED BY DISP=UNK DISPCC=CHG:3") && m_end_field("FAULTS") == 1 && m_has("DRIFT CHANGED=0 LOST=3 CMP=4"));
    m_fx_on();
    m_at_wait = m_wait_ahbc_fault;
    RUN_CLEAN();
    CHECK(m_has("AHBC=1-FAULT:6") && m_has("MDPC=1-SKIP") && m_has("S2 DPU GATED BY DISP=UNK"));
    m_fx_on();
    m_at_wait = m_wait_dahb_fault;
    RUN_CLEAN();
    CHECK(m_has("DG DAHB=1-FAULT:6") && m_has("S2 DISPCC GATED BY DAHBERR") && m_has("S2 DPU GATED BY DAHBERR") && m_line_starts("S2 DISPCC GATED BY DAHB ") < 0);
    /* the interface aborts in snapshot 2, at the enable: the counter is lost with the window, and the second line says so under its own names */
    m_fx_on();
    m_at_wait = m_wait_en_fault;
    RUN_CLEAN();
    CHECK(m_has("DD EN=1-FAULT:6") && m_has("S2 INTF ST=1 EN=FAULT:6 FRB=SKIP") && m_has("DRIFT CHANGED=0 LOST=1 CMP=6"));
    m_fx_on();
    m_at_wait = m_wait_fra_fault;
    RUN_CLEAN();
    CHECK(m_has("S2 INTF ST=1 EN=1 FRB=FAULT:6") && !m_has(" DT=") && m_end_field("FAULTS") == 1);
    /* the MDSS is never read again, so a version that changed during the wait is not seen and not judged */
    m_fx_on();
    m_at_wait = m_wait_ver;
    RUN_CLEAN();
    CHECK(m_loads_of(m_addr("VER"), 2) == 0 && m_has("DRIFT NONE CMP=6"));
    /* every word that can move moves: the list keeps to the cap and the summary counts what it dropped */
    m_fx_on();
    m_at_wait = m_wait_flip_all;
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP && m_has("S2 DISPCC GATED BY DAHB") && m_has("DRIFT CHANGED=1 LOST=0 CMP=1") && m_end_field("LINES") == m_nlines);
    m_fx_on();
    m_at_wait = m_wait_flip_non_gate;
    RUN_CLEAN();
    CHECK(m_has("DD ST=1-3 EN=1-2") && m_has("DRIFT CHANGED=2 LOST=0 CMP=6") && m_end_field("LINES") == m_nlines);
    /* a window that aborted in snapshot 1 is not visited or compared in snapshot 2 */
    m_fx_on();
    m_fault_at(m_addr("AHC"));
    RUN_CLEAN();
    CHECK(m_loads_in(2) == 4 && !m_has("NEXT S2 DPU") && m_has("DRIFT NONE CMP=4"));
    return 0;
}

static int suite_stream(void)
{
    /* In the open fixture a line is printed between the last load of every line and the first load of the next one (m_load32 holds every run to it), and every block has its NEXT line
     * before its first load. Here the order of the events is read back: the first load of each block comes after its NEXT line and after the line before it. */
    m_fx_on();
    RUN_CLEAN();
    for (unsigned b = 0; b < M_BLOCKS; b++) {
        char tail[24];
        int next = -1, first_load = -1;
        snprintf(tail, sizeof tail, "NEXT %s", M_NAME[b]);
        next = m_line_index(tail, 0);
        CHECK(next >= 0);
        for (unsigned i = 0; i < m_nevents && first_load < 0; i++) {
            const struct m_reg *r = m_events[i].kind == M_LOAD ? m_find(m_events[i].addr) : NULL;
            if (r && r->block == b) first_load = (int)i;
        }
        CHECK(first_load >= 0);
        /* the NEXT line is the last LINE event before the first load of the block */
        for (int i = first_load - 1; i >= 0; i--) {
            if (m_events[i].kind != M_LINE) continue;
            CHECK((int)m_events[i].addr == next);
            break;
        }
    }
    /* the verdict goes out before the first load of the MDSS, so that a hang there keeps it */
    {
        int dg_event = -1, ver_event = -1;
        for (unsigned i = 0; i < m_nevents; i++) {
            if (m_events[i].kind == M_LINE && dg_event < 0 && !strncmp(m_lines[m_events[i].addr], PREFIX "DG ", strlen(PREFIX) + 3)) dg_event = (int)i;
            if (m_events[i].kind == M_LOAD && ver_event < 0 && m_events[i].addr == m_addr("VER")) ver_event = (int)i;
        }
        CHECK(dg_event >= 0 && ver_event >= 0 && dg_event < ver_event);
    }
    /* the longest run of loads without a line in snapshot 1 is a line of the table: four words */
    {
        unsigned loads_since_line = 0, max_run = 0;
        for (unsigned i = 0; i < m_nevents; i++) {
            if (m_events[i].phase == 2) break;
            if (m_events[i].kind == M_LINE) loads_since_line = 0;
            else if (++loads_since_line > max_run) max_run = loads_since_line;
        }
        CHECK(max_run <= 4);
    }
    return 0;
}

static int suite_frames(void)
{
    m_fx_on();
    RUN_CLEAN();
    CHECK(m_loads_of(m_addr("FRA"), 0) == 1 && m_loads_of(m_addr("FRA"), 2) == 1 && m_loads_of(m_addr("FLC"), 0) == 1 && m_loads_of(m_addr("FLC"), 2) == 0);
    /* the enable is read before the counter, in the same line, and the counter is not read at all when the enable does not say it counts: the model refuses the load, the page says why */
    m_fx_on();
    m_set(m_addr("FLC"), 0);
    RUN_CLEAN();
    CHECK(m_loads_of(m_addr("FRA"), 0) == 0 && m_loads_of(m_addr("FRA"), 2) == 0 && m_has("S2 INTF ST=1 EN=1 FRB=NOFLC") && !m_has(" DT="));
    /* the counter is free to wrap: 16 below the top and 480 later is a small number, and the page prints both as read */
    m_fx_on();
    m_set(m_addr("FRA"), 0xfffffff0u);
    RUN_CLEAN();
    CHECK(m_has("INTF FLC=3 FRA=0XFFFFFFF0") && m_has("FRB=0X1D0"));
    /* a counter that did not move is printed as it is: the verdict is the host side's */
    m_fx_on();
    m_frames_per_wait = 0;
    RUN_CLEAN();
    CHECK(m_has("INTF FLC=3 FRA=0X3E8") && m_has("FRB=0X3E8 DT="));
    /* no counter op: no wait, no snapshot 2, no second reading, no DT */
    m_fx_on();
    m_have_counter = 0;
    RUN_CLEAN();
    CHECK(m_has("INTF FLC=3 FRA=0X3E8") && m_has("S2 SKIPPED NO_COUNTER") && !m_has("FRB") && !m_has(" DT="));
    return 0;
}

static int suite_counter(void)
{
    m_fx_on();
    RUN_CLEAN();
    CHECK(m_gap_ticks >= 8u * m_hz && m_end_field("GAP_MS") >= 8000);
    m_fx_on();
    m_ctr_mode = C_STUCK;
    RUN_CLEAN();
    CHECK(m_has("S2 SKIPPED NO_COUNTER") && m_end_field("GAP_MS") == 0 && m_loads_in(2) == 0 && !m_has("DRIFT"));
    m_fx_on();
    m_have_counter = 0;
    RUN_CLEAN();
    CHECK(m_has("S2 SKIPPED NO_COUNTER") && m_end_field("GAP_MS") == 0 && !m_has("NEXT WAIT"));
    m_fx_on();
    m_ctr_mode = C_BACK;
    RUN_CLEAN();
    CHECK(m_has("S2 SKIPPED NO_COUNTER") && m_loads_in(2) == 0);
    /* A counter that moves slowly is a long wait, not a dead one, and a bound on the reads must not cut it short: 40 ticks per read need 3.84 million reads for the 8 s at 19.2 MHz, more than a
     * counter that stands still gets (2 million) and fewer than the model tolerates (5 million). The bound the payload ships is at least 2^30 reads, seven times what one tick per read needs at that
     * frequency; a build that chose a bound of its own (the spin build) says SPIN instead of waiting that long. */
    m_fx_on();
    m_ctr_step = 40;
    RUN_CLEAN();
    if (!M_SPIN_OVERRIDE) CHECK(SPIN_MAX >= 0x40000000u && !m_has("SKIPPED") && m_loads_in(2) == LOADS_S2 && m_end_field("GAP_MS") >= 8000);
    else CHECK(SPIN_MAX < 3840000u && m_has("S2 SKIPPED SPIN") && !m_has("S2 SKIPPED NO_COUNTER"));
    m_fx_on();
    m_hz = 100;                          /* a frequency outside 1 to 1000 MHz: the default is used and the page says so */
    RUN_CLEAN();
    CHECK(m_has("HZ=0X124F800 DEFAULT"));
    return 0;
}

#if M_SPIN_OVERRIDE && DISPSNAP_SPIN_MAX < 4000000u
/* A counter that moves and never gets there: the wait gives up after SPIN_MAX reads with a token of its own (S2 SKIPPED SPIN), which is not the dead counter's (S2 SKIPPED NO_COUNTER), and a counter
 * that runs at the model's usual pace never meets the bound. Only the build with a small SPIN_MAX (larger than the 2 million reads of a counter that stands still) runs it: the shipped bound is
 * 2^32-1 reads, minutes of the real loop, which no model run can reach. */
static int suite_spin(void)
{
    m_fx_on();
    m_ctr_step = 1;                      /* one tick per read: 8 s would take 153.6 million reads */
    RUN_CLEAN();
    CHECK(m_has("S2 SKIPPED SPIN") && !m_has("S2 SKIPPED NO_COUNTER") && m_end_field("GAP_MS") == 0 && m_loads_in(2) == 0 && !m_has("DRIFT"));
    m_fx_on();                           /* the usual step: 8 s in 800 reads */
    RUN_CLEAN();
    CHECK(!m_has("SKIPPED") && m_loads_in(2) == LOADS_S2);
    m_fx_on();
    m_ctr_mode = C_STUCK;                /* a counter that stands still is a dead counter, not a bound hit */
    RUN_CLEAN();
    CHECK(m_has("S2 SKIPPED NO_COUNTER") && !m_has("S2 SKIPPED SPIN"));
    m_fx_on();
    m_ctr_mode = C_BACK;
    RUN_CLEAN();
    CHECK(m_has("S2 SKIPPED NO_COUNTER") && !m_has("S2 SKIPPED SPIN"));
    return 0;
}
#endif

static int suite_el(void)
{
    uint64_t r;
    m_fx_on();
    m_el = 1;
    r = m_go();
    CHECK(r == 0 && m_nlines == 1 && !strcmp(m_lines[0], PREFIX "SKIPPED_NOT_AT_EL2") && m_nloads == 0 && !m_violations);
    m_fx_on();
    m_have_load32 = 0;
    r = m_go();
    CHECK(r == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 1 && !strcmp(m_lines[0], PREFIX "REFUSED_NO_LOAD32") && m_nloads == 0 && !m_violations);
    m_fx_on();
    {
        struct q1n1_payload_args a = m_args();
        a.magic = 0;
        m_reset_run();
        r = payload_entry(&a);
        CHECK(r == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 0 && m_nloads == 0);
        a = m_args();
        a.ops.puts = NULL;
        m_reset_run();
        r = payload_entry(&a);
        CHECK(r == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 0);
    }
    /* the framebuffer is the console the page is drawn in: its address is never printed, its pages are never touched (the model maps nothing there, so a dereference ends the run), and a
     * mode of any size is printed as it is (a GOP that is not the panel's size is the host side's verdict) */
    m_fx_on();
    m_gop_w = 1920;
    m_gop_h = 1080;
    m_gop_stride = 2048;
    m_gop_fmt = 0;
    RUN_CLEAN();
    CHECK(m_has("GOP W=1920 H=1080 STRIDE=2048 FMT=0") && !m_has("7E0000") && !m_has("7E00000000"));
    m_fx_on();
    m_gop_w = m_gop_h = m_gop_stride = m_gop_fmt = 0;
    RUN_CLEAN();
    CHECK(m_has("GOP W=0 H=0 STRIDE=0 FMT=0"));
    return 0;
}

/* The widest values: every word that is not a gate input has bit 31 set and eight hex digits; the gate inputs keep their gate open. */
static void m_fx_wide(void)
{
    m_fx_on();
    m_set(m_addr("DAHB"), 0x7ffffffd); m_set(m_addr("GDSC"), 0x8ffffffc); m_set(m_addr("AHBC"), 0x7ffffffd); m_set(m_addr("MDPC"), 0x7ffffffd);
    m_set(m_addr("VER"), 0xffffffe0);
    m_set(m_addr("ST"), 0xfffffffe); m_set(m_addr("EN"), 0xfffffffe); m_set(m_addr("CFG"), 0xfffffffe); m_set(m_addr("CFG2"), 0xfffffffe);
    m_set(m_addr("HS"), 0xfffffffe); m_set(m_addr("VP"), 0xfffffffe); m_set(m_addr("DVS"), 0xfffffffe); m_set(m_addr("DVE"), 0xfffffffe);
    m_set(m_addr("AVS"), 0xfffffffe); m_set(m_addr("AVE"), 0xfffffffe); m_set(m_addr("DHC"), 0xfffffffe); m_set(m_addr("AHC"), 0xfffffffe);
    m_set(m_addr("FLC"), 0xfffffffe); m_set(m_addr("FRA"), 0xfffffffe);
    for (unsigned i = 0; i < CTL_COUNT; i++) {
        char key[4];
        snprintf(key, sizeof key, "C%u", i);
        m_set(m_addr(key), 0xfffffffe);
    }
}

static int suite_budget(void)
{
    m_fx_wide();
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP && m_end_field("CUTS") == 0);
    for (unsigned i = 0; i < m_nlines; i++) CHECK(strlen(m_lines[i]) <= Q1N1_PAYLOAD_LINE_MAX);
    CHECK(m_bloads[M_DPU] == 23);
    m_fx_wide();
    m_at_wait = m_wait_flip_all;
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP);
    m_fx_on();
    m_at_wait = m_wait_flip_non_gate;
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP);
    return 0;
}

/* With a smaller line or load cap: the page keeps to it, says what it dropped and still ends. */
static int suite_caps(void)
{
    m_fx_on();
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP && m_nloads <= LOAD_CAP);
    if (LINE_CAP < 30) CHECK(m_end_field("CUTS") > 0);
    if (LOAD_CAP < LOADS_ON) CHECK(m_has("BUDGET"));
    m_fx_cold();
    RUN_CLEAN();
    m_fx_on();
    m_at_wait = m_wait_flip_all;
    RUN_CLEAN();
    m_at_wait = NULL;
    m_fx_wide();
    RUN_CLEAN();
    m_fx_on();
    m_win_faults = 0xf;
    RUN_CLEAN();
    for (uint64_t seed = 1; seed <= 60; seed++) {
        m_fx_on();
        m_rand_seed = seed * UINT64_C(0x2545F4914F6CDD1D);
        m_nfake = 0;
        RUN_CLEAN();
    }
    return 0;
}

static void m_run_suite(const char *name, int (*suite)(void))
{
    unsigned fails = m_fails, checks = m_checks;
    (void)suite();
    printf("suite %-8s %s (%u checks)\n", name, m_fails == fails ? "ok" : "FAILED", m_checks - checks);
}

/* The scenarios the document shows pages of, and the host parser's tests read: one name, one memory. */
static void m_scenario(const char *name)
{
    m_fx_on();
    if (!strcmp(name, "cold")) m_fx_cold();
    if (!strcmp(name, "wide") || !strcmp(name, "wideflip")) m_fx_wide();
    if (!strcmp(name, "flip") || !strcmp(name, "wideflip")) m_at_wait = m_wait_flip_all;
    if (!strcmp(name, "drift")) m_at_wait = m_wait_st;
    if (!strcmp(name, "dahboff")) m_set(m_addr("DAHB"), 0x80000000);
    if (!strcmp(name, "s2gated")) m_at_wait = m_wait_gdsc_off;
    if (!strcmp(name, "hwctl")) m_set(m_addr("GDSC"), 0x8022f002);
    if (!strcmp(name, "part")) m_set(m_addr("MDPC"), 0x80000000);
    if (!strcmp(name, "dispccabort")) m_fault_at(m_addr("GDSC"));
    if (!strcmp(name, "mdssabort")) m_fault_at(m_addr("VER"));
    if (!strcmp(name, "dpuabort")) m_fault_at(m_addr("ST"));
    if (!strcmp(name, "nocounter")) m_have_counter = 0;
    if (!strcmp(name, "noflc")) m_set(m_addr("FLC"), 0);
    if (!strcmp(name, "wrongmode")) m_fx_intf(2880, 1800);
    if (!strcmp(name, "idle")) { m_set(m_addr("EN"), 0); m_set(m_addr("ST"), 0); m_set(m_addr("C0"), 0); }
    if (!strcmp(name, "stalled")) m_frames_per_wait = 0;
}

static unsigned m_snapshot1_lines(void)
{
    int wait = m_line_index("NEXT WAIT 8 S", 0);
    return wait < 0 ? m_nlines : (unsigned)wait;
}

/* The MORE= of the drift summary, 0 if it has none. */
static unsigned m_more(void)
{
    for (unsigned i = 0; i < m_nlines; i++) {
        if (!strncmp(m_lines[i], PREFIX "DRIFT ", strlen(PREFIX) + 6)) {
            const char *p = strstr(m_lines[i], "MORE=");
            return p ? (unsigned)strtoul(p + 5, NULL, 10) : 0;
        }
    }
    return 0;
}

/* The numbers the document quotes, measured on runs of the model and nothing else: docs/SP11-PAYLOAD-DISPSNAP.md carries them in one block that the document test compares with this
 * output. */
static void m_numbers(void)
{
    printf("registers %u\n", (unsigned)R_COUNT);
    printf("line_cap %u\nload_cap %u\nabi_lines %u\nabi_loads %u\n", LINE_CAP, LOAD_CAP, Q1N1_PAYLOAD_LINES_MAX, Q1N1_PAYLOAD_LOADS_MAX);
    m_scenario("unit");
    RUN_CLEAN();
    printf("open_lines %u\nopen_snapshot1_lines %u\nopen_loads %u\nopen_snapshot1_loads %u\nopen_snapshot2_loads %u\n", m_nlines, m_snapshot1_lines(), m_nloads, m_loads_in(0),
           m_loads_in(2));
    m_scenario("cold");
    RUN_CLEAN();
    printf("cold_lines %u\ncold_loads %u\n", m_nlines, m_nloads);
    m_scenario("dahboff");
    RUN_CLEAN();
    printf("dahboff_lines %u\ndahboff_loads %u\n", m_nlines, m_nloads);
    m_scenario("wide");
    RUN_CLEAN();
    printf("wide_lines %u\nwide_cuts %u\n", m_nlines, m_end_field("CUTS"));
    m_scenario("wideflip");
    RUN_CLEAN();
    printf("wideflip_lines %u\nwideflip_cuts %u\nwideflip_more %u\n", m_nlines, m_end_field("CUTS"), m_more());
}

int main(int argc, char **argv)
{
    m_install_trap();
    if (argc > 1 && (!strcmp(argv[1], "--page") || !strcmp(argv[1], "--scenario"))) {
        /* The page of a scenario, for the document and for a reader: --page is the open fixture. */
        m_scenario(argc > 2 ? argv[2] : "unit");
        RUN_CLEAN();
        for (unsigned i = 0; i < m_nlines; i++) printf("%s\n", m_lines[i]);
        return m_fails != 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--numbers")) {
        m_numbers();
        return m_fails != 0;
    }
#ifdef DISPSNAP_SHIPPED_CAPS
    m_run_suite("unit", suite_unit);
    m_run_suite("cold", suite_cold);
    m_run_suite("gate", suite_gate);
    m_run_suite("faults", suite_faults);
    m_run_suite("storm", suite_storm);
    m_run_suite("drift", suite_drift);
    m_run_suite("stream", suite_stream);
    m_run_suite("frames", suite_frames);
    m_run_suite("counter", suite_counter);
#endif
#if M_SPIN_OVERRIDE && DISPSNAP_SPIN_MAX < 4000000u
    m_run_suite("spin", suite_spin);
#endif
#ifdef DISPSNAP_SHIPPED_CAPS
    m_run_suite("el", suite_el);
    m_run_suite("budget", suite_budget);
#else
    m_run_suite("caps", suite_caps);
#endif
    printf("CHECKS %u FAILS %u MAXLINES %u MAXLOADS %u LINE_CAP %u LOAD_CAP %u\n", m_checks, m_fails, m_max_lines, m_max_loads, LINE_CAP, LOAD_CAP);
    return m_fails != 0;
}
