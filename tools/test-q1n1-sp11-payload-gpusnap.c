/* SPDX-License-Identifier: MIT */
/* Host test for the payload "gpusnap" (payloads/gpusnap.c): the suites. tools/test-q1n1-sp11-payload-gpusnap-model.h is what they run against (a fake register file of the six blocks with the
 * harness's own list of registers, its own statement of the gates, the order and NEXT rules, the counter and the runner's page); tools/test-q1n1-sp11-payload-gpusnap.py drives the build under
 * ASan and UBSan, and builds it again with GPUSNAP_SRC pointing at a seeded-bug copy of the payload to show that each mutant is refused. The suites pin what it prints:
 *   unit      the golden page of the open fixture (every gate open: made-up values, NOT the unit's page), its loads, and that the loads are exactly the addresses of the harness's own list; a
 *             window the table does not have is refused before the table is indexed
 *   cold      the CX domain off: GPUCC is read, the R4 line says OFF and nothing behind the gate is read or announced, only gated
 *   gate      the CFG AHB gate, the CX verdict (PWR_ON, SW_COLLAPSE, HW_CONTROL, each of the seven clocks, the exceptions for a skipped halt check and a hardware gated clock, words that are
 *             all ones or aborted) and the SMMU's four clocks: each in both directions, so that a closed gate is not too strict and an open one is not too loose; the `.ODD` cells (all ones, CLK_OFF
 *             clear with CLK_ENABLE clear, hardware gating, FSM ON) and that an odd cell moves no gate beyond Linux's own exemptions; a context nobody initialised opens no CX block
 *   faults    an abort at every address in turn: one access, FAULT:6 under the register's own name, the window silent afterwards, not visited by snapshot 2, the gates closed that depend on it
 *   storm     every window aborting; all-ones and zero memory; hostile random words
 *   drift     what moves during the gap: a GCC word, a GPUCC word, the CFG AHB clock going off (GPUCC not read again), a fault in snapshot 2, more than the page holds
 *   stream    each line goes out before the first load of the next one, a NEXT line before every block
 *   smmu      the ID decode line: formats, a 64K page, words that read as ones
 *   counter   running (the gap is at least 8 s), stuck, absent, running backwards, slow (a long wait is not a dead counter, and the bound on the reads is wide); `spin` (only a build with a small
 *             GPUSNAP_SPIN_MAX): a counter that moves and never gets there says SPIN, not NO_COUNTER
 *   late      the words no Linux code reads: only after the wait and the drift report, only on a state that still holds, each block under its own NEXT LATE line
 *   el        any EL but 2: one line, no load; arguments
 *   budget    the widest values: no field is cut and the cap holds
 * With GPUSNAP_LINE_CAP or GPUSNAP_LOAD_CAP set, only the cap suite runs. `--page [scenario]` prints a page, `--numbers` the numbers the document quotes.
 * Nothing here ran on hardware. Evidence: EXPERIMENTAL (host model only). */
/* Whether the build chose its own bound on the reads of the wait: the payload's header defines the default only after this point. */
#ifdef GPUSNAP_SPIN_MAX
#define M_SPIN_OVERRIDE 1
#else
#define M_SPIN_OVERRIDE 0
#endif
#include "test-q1n1-sp11-payload-gpusnap-model.h"

/* The pages of the two fixtures, line by line (without the prefix). Made-up pages: see m_fx_gcc and the comment above the fixtures in the model. */
static const char *const GOLDEN_ON[] = {
    "READ ONLY EL=2 HZ=0X124F800 GAP=8 S",
    "KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=BIT 31 NOT TRUSTED NO GPU-WINDOW REGISTER IS READ",
    "NEXT GCC",
    "GCC CFGA=1.ON MNOC=3.ON AXI_NW=3 SNOC=1.ON",
    "GCC QMIP=3.ON VOTE=0X18001 CPH=1 DIV=1 GP0V=1",
    "NEXT GPUCC",
    "GPUCC CXGD=0X8022F000 SC=0 HW=0 CXHW=0X80000000.ON",
    "GPUCC AHB=1.ON CGMU=1.ON CXO=1.ON",
    "GPUCC HUB=1.ON DMT=1.ON HLOS=1.ON",
    "R4 CX=ON PWR=1 SC=0 HW=0 CLK=0X7F SM=0XF",
    "GPUCC GXGD=0X222001 GXCF=0X8000 UP=0 DN=1",
    "GPUCC CXOA=1.ON HUBA=1.ON GXGM=0X80000000.OFF",
    "GPUCC GRC=2.ON GRF=0 S=0 HRC=0X80000000.OFF HRF=0X100 S=1",
    "GPUCC XRC=0X80000000.OFF XRF=0 S=0",
    "NEXT CXMISC",
    "CXMISC TCMR=0",
    "NEXT GMU",
    "GMU GXST=3 GX=OFF INIT=0 FENS=0",
    "NEXT RSCC",
    "RSCC BSY=0 ST0=0 TCS=0X3FF",
    "NEXT SMMU",
    "SMMU ID0=0X7C017E9A ID1=0X6000005F ID2=0X5222",
    "SMMU SMRG=0X9A CB=0X5F PG=4K NPG=6 PT=5 IAS=2 OAS=2 UBS=2",
    "SMMU SCR0=0X230406 GFSR=0 ID7=0X21",
    "NEXT WAIT 8 S",
    "NEXT S2 GCC",
    "NEXT S2 GPUCC GCC=SAME",
    "DRIFT NONE CMP=26",
    "NEXT LATE GMU",
    "LATE GMU RST=1 CFG=0 BUSY=0",
    "NEXT LATE RSCC",
    "LATE RSCC PDCS=0",
    "END LOADS=78 FAULTS=0 SKIPS=0 BLK=0 CUTS=0 GAP_MS=8020 LINES=33",
};
#define LOADS_ON 78u                    /* 48 in snapshot 1, 26 in snapshot 2, 4 late */
#define LOADS_S1_ON 48u
#define LOADS_S2 26u
#define LOADS_LATE 4u

static const char *const GOLDEN_COLD[] = {
    "READ ONLY EL=2 HZ=0X124F800 GAP=8 S",
    "KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=BIT 31 NOT TRUSTED NO GPU-WINDOW REGISTER IS READ",
    "NEXT GCC",
    "GCC CFGA=1.ON MNOC=3.ON AXI_NW=3 SNOC=1.ON",
    "GCC QMIP=3.ON VOTE=0X18001 CPH=1 DIV=1 GP0V=1",
    "NEXT GPUCC",
    "GPUCC CXGD=0X222001 SC=1 HW=0 CXHW=0.OFF",
    "GPUCC AHB=0X80000000.OFF CGMU=0X80000000.OFF CXO=0X80000000.OFF",
    "GPUCC HUB=0X80000000.OFF DMT=0X80000000.OFF HLOS=0X80000000.OFF",
    "R4 CX=OFF PWR=0 SC=1 HW=0 CLK=0X18 SM=0X6",
    "GPUCC GXGD=0X222001 GXCF=0X8000 UP=0 DN=1",
    "GPUCC CXOA=0X80000000.OFF HUBA=0X80000000.OFF GXGM=0X80000000.OFF",
    "GPUCC GRC=0X80000000.OFF GRF=0 S=0 HRC=0X80000000.OFF HRF=0X100 S=1",
    "GPUCC XRC=0X80000000.OFF XRF=0 S=0",
    "CXMISC GATED BY CX=OFF",
    "GMU GATED BY CX=OFF",
    "RSCC GATED BY CX=OFF",
    "SMMU GATED BY CX=OFF",
    "NEXT WAIT 8 S",
    "NEXT S2 GCC",
    "NEXT S2 GPUCC GCC=SAME",
    "DRIFT NONE CMP=26",
    "END LOADS=52 FAULTS=0 SKIPS=0 BLK=0X3C CUTS=0 GAP_MS=8020 LINES=23",
};
#define LOADS_COLD 52u                  /* 26 in snapshot 1, 26 in snapshot 2 */

static int m_line_starts(const char *tail)
{
    char want[100];
    size_t n;
    snprintf(want, sizeof want, "%s%s", PREFIX, tail);
    n = strlen(want);
    for (unsigned i = 0; i < m_nlines; i++) if (!strncmp(m_lines[i], want, n) && (m_lines[i][n] == 0 || m_lines[i][n] == ' ')) return (int)i;
    return -1;
}

/* The loads of a run are the harness's own list for the blocks that are open and nothing else: m_load32 already refuses a load outside it, this refuses a list that is wider than what
 * the payload reads (a seeded extra read of a listed-but-unread register would pass otherwise). `blocks` is a bit per block that must be read in snapshot 1; the words Linux never reads
 * are read once, in the late phase, in those of the blocks that are read in snapshot 1 and, since the memory does not change, still open after the wait. */
static void m_check_reads_are_the_list(unsigned blocks)
{
    for (unsigned i = 0; i < M_NREGS; i++) {
        unsigned read = (blocks >> M_REGS[i].block & 1) ? 1u : 0u;
        unsigned in_s1 = read && !M_REGS[i].late ? 1u : 0u;
        unsigned in_s2 = in_s1 && (M_REGS[i].block == M_GCC || M_REGS[i].block == M_GPUCC) ? 1u : 0u;
        unsigned in_late = read && M_REGS[i].late ? 1u : 0u;
        CHECK(m_loads_of(M_REGS[i].addr, 0) == in_s1);
        CHECK(m_loads_of(M_REGS[i].addr, 2) == in_s2);
        CHECK(m_loads_of(M_REGS[i].addr, 3) == in_late);
    }
}

static int suite_unit(void)
{
    static const char *const NEXT[] = {"NEXT GCC", "NEXT GPUCC", "NEXT CXMISC", "NEXT GMU", "NEXT RSCC", "NEXT SMMU", "NEXT WAIT 8 S", "NEXT S2 GCC", "NEXT S2 GPUCC GCC=SAME",
                                       "NEXT LATE GMU", "NEXT LATE RSCC"};
    int at = -1;
    m_fx_on();
    RUN_CLEAN();
    CHECK(m_nlines == sizeof GOLDEN_ON / sizeof GOLDEN_ON[0]);
    for (unsigned i = 0; i < sizeof GOLDEN_ON / sizeof GOLDEN_ON[0]; i++) m_line_is(i, GOLDEN_ON[i], __LINE__);
    CHECK(m_nloads == LOADS_ON && m_loads_in(0) == LOADS_S1_ON && m_loads_in(2) == LOADS_S2 && m_loads_in(3) == LOADS_LATE);
    CHECK(m_sysreg_reads == 2);
    CHECK(m_bloads[M_GCC] == 14 && m_bloads[M_GPUCC] == 38 && m_bloads[M_CXMISC] == 1 && m_bloads[M_GMU] == 6 && m_bloads[M_RSCC] == 13 && m_bloads[M_SMMU] == 6);
    m_check_reads_are_the_list(0x3f);
    for (unsigned i = 0; i < sizeof NEXT / sizeof NEXT[0]; i++) {
        int found = m_line_index(NEXT[i], (unsigned)(at + 1));
        CHECK(found > at);
        at = found;
    }
    CHECK(m_end_field("FAULTS") == 0 && m_end_field("SKIPS") == 0 && m_end_field("CUTS") == 0 && m_end_field("BLK") == 0);
    CHECK(m_end_field("GAP_MS") >= 8000 && m_end_field("GAP_MS") < 8100);
    CHECK(m_gap_ticks >= 8u * m_hz);
    /* the first load of every block is a word Linux reads, and no word Linux never reads is loaded before the late phase: the model refuses both, and here the order is read back */
    for (unsigned b = 0; b < M_BLOCKS; b++) {
        for (unsigned i = 0; i < m_nevents; i++) {
            const struct m_reg *r = m_events[i].kind == M_LOAD ? m_find(m_events[i].addr) : NULL;
            if (!r || r->block != b) continue;
            CHECK(!r->late);
            break;
        }
    }
    {
        int drift_line = m_line_index("DRIFT NONE CMP=26", 0), drift_event = -1;
        for (unsigned i = 0; i < m_nevents; i++) if (m_events[i].kind == M_LINE && (int)m_events[i].addr == drift_line) drift_event = (int)i;
        CHECK(drift_line >= 0 && drift_event >= 0);
        for (unsigned i = 0; i < m_nevents; i++) {
            if (m_events[i].kind == M_LOAD && m_events[i].phase == 3) CHECK((int)i > drift_event);
        }
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
    CHECK(m_bloads[M_GCC] == 14 && m_bloads[M_GPUCC] == 38 && !m_bloads[M_CXMISC] && !m_bloads[M_GMU] && !m_bloads[M_RSCC] && !m_bloads[M_SMMU]);
    m_check_reads_are_the_list(0x03);
    CHECK(!m_has("NEXT CXMISC") && !m_has("NEXT GMU") && !m_has("NEXT RSCC") && !m_has("NEXT SMMU") && !m_has("LATE"));
    CHECK(m_end_field("BLK") == 0x3c);
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

#define B_ALL 0x3fu
#define B_NOSM 0x1fu            /* everything but the SMMU */
#define B_GPUCC_ONLY 0x03u
#define B_GCC_ONLY 0x01u
static int suite_gate(void)
{
    static const struct gate_case CASES[] = {
        /* the CFG AHB gate: positive proof only */
        {"AHB enabled, CLK_OFF clear", "CFGA", 0x1, "R4 CX=ON", B_ALL},
        {"AHB enabled, CLK_OFF clear, other bits set", "CFGA", 0x7fffffff, "R4 CX=ON", B_ALL},
        {"AHB not enabled", "CFGA", 0x0, "GPUCC GATED BY AHB", B_GCC_ONLY},
        {"AHB CLK_OFF set", "CFGA", 0x80000001, "GPUCC GATED BY AHB", B_GCC_ONLY},
        {"AHB CLK_OFF set and HW_CTL set: CFGA has no hardware gating bit in Linux", "CFGA", 0x80000003, "GPUCC GATED BY AHB", B_GCC_ONLY},
        {"AHB a failed read: not 'the clock is off'", "CFGA", 0xffffffff, "GPUCC GATED BY AHBERR", B_GCC_ONLY},
        {"AHB NoC FSM status ON but CLK_OFF set: no proof", "CFGA", 0xa0000001, "GPUCC GATED BY AHB", B_GCC_ONLY},
        /* the CX verdict: the GDSC */
        {"CX status PWR_ON clear", "CXHW", 0x0, "R4 CX=OFF PWR=0", B_GPUCC_ONLY},
        {"CX status bit 31 clear, bits 30:0 set", "CXHW", 0x7fffffff, "R4 CX=OFF PWR=0", B_GPUCC_ONLY},
        {"CX GDSCR SW_COLLAPSE set under PWR_ON (on only by another vote)", "CXGD", 0x8022f001, "R4 CX=OFF PWR=1 SC=1", B_GPUCC_ONLY},
        {"CX GDSCR HW_CONTROL set", "CXGD", 0x8022f002, "R4 CX=HWCTL", B_GPUCC_ONLY},
        {"CX GDSCR HW_CONTROL and SW_COLLAPSE set", "CXGD", 0x8022f003, "R4 CX=HWCTL", B_GPUCC_ONLY},
        {"CX GDSCR a failed read", "CXGD", 0xffffffff, "R4 CX=UNK", B_GPUCC_ONLY},
        {"CX status a failed read", "CXHW", 0xffffffff, "R4 CX=UNK", B_GPUCC_ONLY},
        /* the CX verdict: the seven clocks of the GMU node (ahb, gmu, cxo, axi, memnoc, hub, demet) */
        {"gpucc ahb off", "AHB", 0x80000000, "R4 CX=PART PWR=1 SC=0 HW=0 CLK=0X7E SM=0X7", B_GPUCC_ONLY},
        {"gpucc ahb enabled, CLK_OFF set", "AHB", 0x80000001, "R4 CX=PART PWR=1 SC=0 HW=0 CLK=0X7E SM=0X7", B_GPUCC_ONLY},
        {"gpucc ahb enabled, CLK_OFF set, bit 1 set: this clock has no hardware gating bit", "AHB", 0x80000003, "R4 CX=PART PWR=1 SC=0 HW=0 CLK=0X7E SM=0X7", B_GPUCC_ONLY},
        {"cx_gmu off", "CGMU", 0x80000001, "R4 CX=PART PWR=1 SC=0 HW=0 CLK=0X7D", B_GPUCC_ONLY},
        {"cxo not enabled", "CXO", 0x0, "R4 CX=PART PWR=1 SC=0 HW=0 CLK=0X7B", B_GPUCC_ONLY},
        {"axi not enabled (its CLK_OFF is no witness)", "AXI_NW", 0x0, "R4 CX=PART PWR=1 SC=0 HW=0 CLK=0X77", B_GPUCC_ONLY},
        {"axi enabled with CLK_OFF set: Linux does not check it (BRANCH_HALT_SKIP)", "AXI_NW", 0x80000001, "R4 CX=ON", B_ALL},
        {"memnoc CLK_OFF set, no hardware gating", "MNOC", 0x80000001, "R4 CX=PART PWR=1 SC=0 HW=0 CLK=0X6F SM=0XD", B_GPUCC_ONLY},
        {"memnoc CLK_OFF set under hardware gating (bit 1): Linux does not judge it", "MNOC", 0x80000003, "R4 CX=ON", B_ALL},
        {"hub_cx_int off", "HUB", 0x80000001, "R4 CX=PART PWR=1 SC=0 HW=0 CLK=0X5F", B_GPUCC_ONLY},
        {"demet off", "DMT", 0x80000001, "R4 CX=PART PWR=1 SC=0 HW=0 CLK=0X3F", B_GPUCC_ONLY},
        {"a clock word of the seven reads as a failed read", "CXO", 0xffffffff, "R4 CX=UNK", B_GPUCC_ONLY},
        /* the SMMU's four clocks (hlos, memnoc, snoc dvm, ahb) in addition */
        {"hlos vote clock off", "HLOS", 0x80000000, "SMMU GATED BY SMCLK", 0x1fu},
        {"snoc dvm clock off (not one of the seven)", "SNOC", 0x80000001, "SMMU GATED BY SMCLK", 0x1fu},
        {"snoc dvm clock a failed read: not 'the clock is off'", "SNOC", 0xffffffff, "SMMU GATED BY SMERR", 0x1fu},
        {"hlos clock enabled with CLK_OFF clear and bit 1 set", "HLOS", 0x3, "R4 CX=ON", B_ALL},
        /* a window whose clocks run but whose GDSC is off, and the other way round */
        {"clocks run, GDSC off", "CXHW", 0x0, "GMU GATED BY CX=OFF", B_GPUCC_ONLY},
    };
    for (unsigned i = 0; i < sizeof CASES / sizeof CASES[0]; i++) m_run_case(&CASES[i], __LINE__);
    /* every clock of the GMU node off at once, the GDSC on: PART, not OFF */
    m_fx_on();
    m_set(m_addr("AHB"), 0x80000000); m_set(m_addr("CGMU"), 0x80000000); m_set(m_addr("CXO"), 0x80000000); m_set(m_addr("AXI_NW"), 0x0);
    m_set(m_addr("MNOC"), 0x80000000); m_set(m_addr("HUB"), 0x80000000); m_set(m_addr("DMT"), 0x80000000);
    RUN_CLEAN();
    CHECK(m_has("R4 CX=PART PWR=1 SC=0 HW=0 CLK=0X0 SM=0X5"));
    CHECK(m_has("CXMISC GATED BY CX=PART") && m_has("SMMU GATED BY CX=PART"));
    /* the GX words are read whatever the CX verdict says, and are never a gate */
    m_fx_cold();
    RUN_CLEAN();
    CHECK(m_seen(m_addr("GXGD")) && m_seen(m_addr("GXCF")));
    /* a GPUCC that is not read because of the AHB gate takes the CX blocks with it, and says why */
    m_fx_on();
    m_set(m_addr("CFGA"), 0x80000000);
    RUN_CLEAN();
    CHECK(m_has("CXMISC GATED BY AHB") && m_has("GMU GATED BY AHB") && m_has("RSCC GATED BY AHB") && m_has("SMMU GATED BY AHB"));
    CHECK(!m_has("R4 ") && !m_has("NEXT GPUCC"));
    CHECK(m_loads_in(2) == 7 && !m_has("S2 GPUCC"));
    /* the GMU's own word for GX: both of its two low bits clear is on, either one set is off, and a word with other bits set (or all ones) is not taken at its word */
    {
        static const struct {
            uint32_t word;
            const char *want;
        } GX[] = {{0x0, " GX=ON"}, {0x1, " GX=OFF"}, {0x2, " GX=OFF"}, {0x3, " GX=OFF"}, {0x4, " GX=ODD"}, {0xfffffffc, " GX=ODD"}, {0xffffffff, " GX=ODD"}};
        for (unsigned i = 0; i < sizeof GX / sizeof GX[0]; i++) {
            m_fx_on();
            m_set(m_addr("GXST"), GX[i].word);
            RUN_CLEAN();
            CHECKM(m_has(GX[i].want), GX[i].want);
        }
    }
    /* a gate input that could not be read is reported as that, never as the thing it gates on: an abort at CFGA is AHBERR (not AHB), at SNOC or HLOS SMERR (not SMCLK), at a clock of the
     * seven CX=UNK (not PART or OFF) */
    m_fx_on();
    m_fault_at(m_addr("CFGA"));
    RUN_CLEAN();
    CHECK(m_has("CFGA=FAULT:6") && m_line_starts("GPUCC GATED BY AHBERR") >= 0 && m_line_starts("GMU GATED BY AHBERR") >= 0 && m_line_starts("GPUCC GATED BY AHB") < 0);
    m_fx_on();
    m_fault_at(m_addr("SNOC"));
    RUN_CLEAN();
    CHECK(m_has("R4 CX=ON") && m_line_starts("SMMU GATED BY SMERR") >= 0 && m_line_starts("SMMU GATED BY SMCLK") < 0 && m_bloads[M_GMU] == 3);
    /* GCC's window died in snapshot 1, so snapshot 2 could not read the CFG AHB word again: the late words have no fresh state to be judged by, and the page says AHBERR */
    CHECK(m_loads_in(3) == 0 && m_line_starts("LATE GMU GATED BY AHBERR") >= 0);
    m_fx_on();
    m_fault_at(m_addr("HLOS"));
    RUN_CLEAN();
    CHECK(m_has("R4 CX=ON") && m_line_starts("SMMU GATED BY SMERR") >= 0 && m_has("HLOS=FAULT:6"));
    m_fx_on();
    m_fault_at(m_addr("CGMU"));
    RUN_CLEAN();
    CHECK(m_has("R4 CX=UNK") && m_line_starts("GMU GATED BY CX=UNK") >= 0 && m_line_starts("GMU GATED BY CX=PART") < 0 && m_line_starts("GMU GATED BY CX=OFF") < 0);
    /* a cell whose bit 31 cannot be taken at its word says so (.ODD): all ones; CLK_OFF clear with CLK_ENABLE clear; CLK_OFF under hardware gating on a clock that has the bit; CLK_OFF with an
     * NoC FSM status of ON. The same bits on a clock that has no such mode are an ordinary .OFF. */
    {
        static const struct {
            const char *key;
            uint32_t word;
            const char *want;
        } ODD[] = {
            {"CFGA", 0xffffffff, " CFGA=0XFFFFFFFF.ODD"},     {"MNOC", 0x80000003, " MNOC=0X80000003.ODD"},    {"QMIP", 0x80000003, " QMIP=0X80000003.ODD"},
            {"SNOC", 0x80000003, " SNOC=0X80000003.OFF"},     {"AHB", 0xa0000001, " AHB=0XA0000001.ODD"},     {"AHB", 0x90000001, " AHB=0X90000001.OFF"},
            {"AHB", 0x20000001, " AHB=0X20000001.ON"},        {"CXHW", 0xffffffff, " CXHW=0XFFFFFFFF.ODD"},   {"GRC", 0xffffffff, " GRC=0XFFFFFFFF.ODD"},
            {"CXHW", 0x7fffffff, " CXHW=0X7FFFFFFF.OFF"},     {"CXHW", 0x80000000, " CXHW=0X80000000.ON"},
            /* a root clock generator's command word has no NoC FSM mode: bit 31 alone says ROOT_OFF */
            {"GRC", 0xa0000000, " GRC=0XA0000000.OFF"},
            /* CLK_OFF clear with CLK_ENABLE clear is a clock that says it runs without being enabled, which is what a window of zeros reads: no .ON for it (the gate needs the enable and is unchanged) */
            {"CFGA", 0x0, " CFGA=0.ODD"}, {"CXO", 0x0, " CXO=0.ODD"}, {"SNOC", 0x30000000, " SNOC=0X30000000.ODD"}, {"MNOC", 0x2, " MNOC=2.ODD"},
            /* a bit field cut from a word of all ones is no field */
            {"CXGD", 0xffffffff, " CXGD=0XFFFFFFFF SC=ODD HW=ODD"}, {"VOTE", 0xffffffff, " VOTE=0XFFFFFFFF CPH=ODD DIV=ODD"},
            {"GXCF", 0xffffffff, " GXCF=0XFFFFFFFF UP=ODD DN=ODD"}, {"GRF", 0xffffffff, " GRF=0XFFFFFFFF S=ODD"},
        };
        for (unsigned i = 0; i < sizeof ODD / sizeof ODD[0]; i++) {
            m_fx_on();
            m_set(m_addr(ODD[i].key), ODD[i].word);
            RUN_CLEAN();
            CHECKM(m_has(ODD[i].want), ODD[i].want);
        }
    }
    /* the TCS mask: a TCS word of all ones is not an idle TCS */
    m_fx_on();
    m_set(m_addr("T3"), 0xffffffff);
    RUN_CLEAN();
    CHECK(m_has(" TCS=ODD") && !m_has("TCS=0X3FF"));
    m_fx_on();
    m_set(m_addr("T3"), 0xfffffffe);
    RUN_CLEAN();
    CHECK(m_has(" TCS=0X3F7"));
    /* the odd cell does not move a gate: the two data-path clocks pass under Linux's own exemptions and print .ODD (MNOC; AXI_NW has no token), the register-path ones need the proof */
    m_fx_on();
    m_set(m_addr("MNOC"), 0x80000003);
    m_set(m_addr("AXI_NW"), 0x80000001);
    RUN_CLEAN();
    CHECK(m_has("R4 CX=ON PWR=1 SC=0 HW=0 CLK=0X7F SM=0XF") && m_has(" MNOC=0X80000003.ODD") && m_has(" AXI_NW=0X80000001"));
    m_fx_on();
    m_set(m_addr("CFGA"), 0x0);
    RUN_CLEAN();
    CHECK(m_has(" CFGA=0.ODD") && m_has("GPUCC GATED BY AHB") && !m_has("NEXT GPUCC"));
    /* a context nobody initialised is closed: CX_UNK is the zero verdict, so with the CFG AHB word running (the only other thing a CX block's gate asks of the context) no CX block is open and
     * the reason says why; only an explicit CX_ON opens them, the SMMU also with its four clocks */
    {
        struct ctx c;
        memset(&c, 0, sizeof c);
        c.s[0].v[R_CFGA].v = 1;
        c.s[0].v[R_CFGA].st = V_OK;
        CHECK(c.cx == CX_UNK && !strcmp(cx_name[c.cx], "UNK"));
        CHECK(gate_reason(&c, WIN_GCC) == RS_OPEN && gate_reason(&c, WIN_GPUCC) == RS_OPEN);
        for (unsigned win = WIN_CXMISC; win < WINDOWS; win++) CHECKM(!strcmp(reason_name[gate_reason(&c, win)], "CX=UNK"), window_name[win]);
        c.cx = CX_ON;
        c.sm_mask = (1u << SMMU_CLOCKS) - 1u;
        for (unsigned win = WIN_CXMISC; win < WINDOWS; win++) CHECKM(gate_reason(&c, win) == RS_OPEN, window_name[win]);
    }
    return 0;
}

/* An abort at every address of the list in turn, in the open fixture. */
static int suite_faults(void)
{
    for (unsigned i = 0; i < M_NREGS; i++) {
        const struct m_reg *r = &M_REGS[i];
        char want[40];
        unsigned phase = r->late ? 3u : 0u;
        m_fx_on();
        m_fault_at(r->addr);
        RUN_CLEAN();
        CHECK(m_loads_of(r->addr, phase) == 1 && m_loads_of(r->addr, 2) == 0);
        /* a TCS word is printed only as the bit of the TCS mask, which shows the abort under its own name */
        if (r->key[0] == 'T' && r->key[1] >= '0' && r->key[1] <= '9') snprintf(want, sizeof want, " TCS=FAULT:6");
        else snprintf(want, sizeof want, " %s=FAULT:6", r->key);
        CHECK(m_has(want));
        CHECK(m_end_field("FAULTS") >= 1);
        /* the window is read no more, in either snapshot, and snapshot 2 does not announce it */
        if (r->block == M_GCC || r->block == M_GPUCC) {
            snprintf(want, sizeof want, "NEXT S2 %s", M_NAME[r->block]);
            CHECK(m_line_starts(want) < 0);
        }
        CHECK((m_end_field("BLK") >> r->block & 1) == 1);
        /* a late word is read after everything else, so an abort at one costs nothing before it; an abort at any word before it ends the window, and the late words print as SKIP without a load */
        for (unsigned j = 0; j < M_NREGS; j++) {
            if (M_REGS[j].block != r->block || !M_REGS[j].late || M_REGS[j].addr == r->addr) continue;
            if (!r->late) {
                snprintf(want, sizeof want, " %s=SKIP", M_REGS[j].key);
                CHECK(m_loads_of(M_REGS[j].addr, 3) == 0 && m_has(want));
            }
        }
    }
    /* a fault in the first word of GPUCC that matters: the CX verdict is unknown and nothing behind it is read */
    m_fx_on();
    m_fault_at(m_addr("CXGD"));
    RUN_CLEAN();
    CHECK(m_has("R4 CX=UNK") && m_has("GMU GATED BY CX=UNK") && !m_bloads[M_GMU]);
    return 0;
}

static void m_wait_flip_all(void)
{
    for (unsigned i = 0; i < M_NREGS; i++) {
        int fault;
        if (M_REGS[i].block != M_GCC && M_REGS[i].block != M_GPUCC) continue;
        m_set(M_REGS[i].addr, ~m_value(M_REGS[i].addr, &fault) & 0x7fffffffu);
    }
}

/* Everything but the CFG AHB word moves, so that GPUCC is still read again and the drift list is as long as it can be. */
static void m_wait_flip_most(void)
{
    uint32_t keep = m_addr("CFGA");
    for (unsigned i = 0; i < M_NREGS; i++) {
        int fault;
        if ((M_REGS[i].block != M_GCC && M_REGS[i].block != M_GPUCC) || M_REGS[i].addr == keep) continue;
        m_set(M_REGS[i].addr, ~m_value(M_REGS[i].addr, &fault) & 0xfffffffeu);
    }
}

/* Every word of GCC and GPUCC moves except the ten that the CFG AHB gate and the CX verdict are made of: the drift list is as long as it can be and the late phase still opens. */
static void m_wait_flip_non_gate(void)
{
    static const char *const inputs[] = {"CFGA", "CXGD", "CXHW", "AHB", "CGMU", "CXO", "AXI_NW", "MNOC", "HUB", "DMT"};
    for (unsigned i = 0; i < M_NREGS; i++) {
        int fault, gate = 0;
        if (M_REGS[i].block != M_GCC && M_REGS[i].block != M_GPUCC) continue;
        for (unsigned k = 0; k < sizeof inputs / sizeof inputs[0]; k++) gate |= !strcmp(M_REGS[i].key, inputs[k]);
        if (!gate) m_set(M_REGS[i].addr, ~m_value(M_REGS[i].addr, &fault) & 0xfffffffeu);
    }
}

static int suite_storm(void)
{
    m_fx_on();
    m_win_faults = 0x3f;                 /* every window aborts on its first load */
    RUN_CLEAN();
    CHECK(m_loads_in(0) == 1);          /* GCC aborts: CFGA is unknown, GPUCC and the rest are gated */
    CHECK(m_has("CFGA=FAULT:6") && m_has("GPUCC GATED BY AHBERR") && !m_has("GPUCC GATED BY AHB ") && m_line_starts("GPUCC GATED BY AHB") < 0);
    m_fx_on();
    m_win_faults = 0x3e;                 /* GCC reads, GPUCC aborts on its first load */
    RUN_CLEAN();
    CHECK(m_bloads[M_GCC] == 14 && m_bloads[M_GPUCC] == 1 && m_has("R4 CX=UNK") && m_has("GMU GATED BY CX=UNK"));
    m_fx_on();
    m_fill_all = 1;
    m_fill = 0xffffffffu;               /* a dead bus reads all ones */
    RUN_CLEAN();
    CHECK(m_bloads[M_GPUCC] == 0 && m_has("GPUCC GATED BY AHB"));
    m_fx_on();
    m_fill_all = 1;
    m_fill = 0;
    RUN_CLEAN();
    CHECK(m_bloads[M_GPUCC] == 0);      /* ENABLE clear: closed */
    m_fx_on();
    m_rand_seed = 0;
    for (uint64_t seed = 1; seed <= 300; seed++) {
        m_fx_on();
        m_rand_seed = seed * UINT64_C(0x2545F4914F6CDD1D);
        m_nfake = 0;
        RUN_CLEAN();
    }
    return 0;
}

/* What moves during the wait. */
static void m_wait_qmip(void) { m_set(m_addr("QMIP"), 0x1); }
static void m_wait_cxhw(void) { m_set(m_addr("CXHW"), 0x0); }
static void m_wait_ahb_off(void) { m_set(m_addr("CFGA"), 0x80000000); }
static void m_wait_cxo_fault(void) { m_fault_at(m_addr("CXO")); }
static void m_wait_gcc_fault(void) { m_fault_at(m_addr("SNOC")); }
static void m_wait_cfga_fault(void) { m_fault_at(m_addr("CFGA")); }
static void m_wait_hwctl(void) { m_set(m_addr("CXGD"), 0x8022f002); }

static int suite_drift(void)
{
    m_fx_on();
    m_at_wait = m_wait_qmip;
    RUN_CLEAN();
    CHECK(m_has("NEXT S2 GPUCC GCC=CHG:1") && m_has("DG QMIP=3-1") && m_has("DRIFT CHANGED=1 LOST=0 CMP=26"));
    CHECK(m_loads_in(3) == LOADS_LATE);     /* a word that moves and is no gate input does not close the late phase */
    m_fx_on();
    m_at_wait = m_wait_cxhw;
    RUN_CLEAN();
    CHECK(m_has("NEXT S2 GPUCC GCC=SAME") && m_has("DC CXHW=0X80000000-0") && m_has("DRIFT CHANGED=1 LOST=0 CMP=26"));
    CHECK(m_loads_in(2) == LOADS_S2);       /* the CX blocks are not read again, whatever GPUCC says now */
    /* the CX domain went off during the wait: the late words are not read, and the page says why */
    CHECK(m_loads_in(3) == 0 && m_line_starts("LATE GMU GATED BY CX=OFF") >= 0 && m_line_starts("LATE RSCC GATED BY CX=OFF") >= 0 && !m_has("NEXT LATE"));
    CHECK((m_end_field("BLK") >> M_GMU & 1) == 1 && (m_end_field("BLK") >> M_RSCC & 1) == 1);
    m_fx_on();
    m_at_wait = m_wait_hwctl;
    RUN_CLEAN();
    CHECK(m_loads_in(3) == 0 && m_line_starts("LATE GMU GATED BY CX=HWCTL") >= 0);
    /* the CFG AHB clock goes off during the wait: GPUCC is not read again, and its values are not compared */
    m_fx_on();
    m_at_wait = m_wait_ahb_off;
    RUN_CLEAN();
    CHECK(m_has("S2 GPUCC SKIP GATED GCC=CHG:1") && m_loads_in(2) == 7 && m_has("DG CFGA=1-0X80000000") && m_has("DRIFT CHANGED=1 LOST=0 CMP=7"));
    CHECK(m_line_starts("NEXT S2 GPUCC") < 0 && !m_has("DC "));
    CHECK((m_end_field("BLK") >> M_GPUCC & 1) == 1);
    CHECK(m_loads_in(3) == 0 && m_line_starts("LATE GMU GATED BY AHB") >= 0 && m_line_starts("LATE RSCC GATED BY AHB") >= 0);
    /* a fault in snapshot 2: the abort replaces the value, the window is read no more, and the late phase cannot judge the state (CX=UNK, not "off") */
    m_fx_on();
    m_at_wait = m_wait_cxo_fault;
    RUN_CLEAN();
    CHECK(m_has("DC CXO=1-FAULT:6") && m_has("LOST=") && m_end_field("FAULTS") == 1);
    CHECK(m_loads_in(3) == 0 && m_line_starts("LATE GMU GATED BY CX=UNK") >= 0);
    m_fx_on();
    m_at_wait = m_wait_cfga_fault;
    RUN_CLEAN();
    CHECK(m_has("DG CFGA=1-FAULT:6") && m_loads_in(3) == 0 && m_line_starts("LATE GMU GATED BY AHBERR") >= 0 && m_line_starts("LATE GMU GATED BY AHB") < 0);
    m_fx_on();
    m_at_wait = m_wait_gcc_fault;
    RUN_CLEAN();
    /* SNOC aborts in snapshot 2: GCC is read no more, so QMIP, VOTE and GP0V are lost with it; GPUCC's gate is its own CFG AHB word, read just before and fine, so it is read again; SNOC is no
     * input of the CX verdict, so the late words are still read */
    CHECK(m_has("DG SNOC=1-FAULT:6 QMIP=3-SKIP VOTE=0X18001-SKIP GP0V=1-SKIP") && m_has("NEXT S2 GPUCC GCC=CHG:4") && m_loads_in(2) == 4 + 19);
    CHECK(m_loads_in(3) == LOADS_LATE);
    /* every word moves: the list keeps to the cap and the summary counts what it dropped */
    m_fx_on();
    m_at_wait = m_wait_flip_all;
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP && m_has("S2 GPUCC SKIP GATED") && m_has("DRIFT CHANGED=7 LOST=0 CMP=7") && m_end_field("LINES") == m_nlines);
    m_fx_on();
    m_at_wait = m_wait_flip_most;
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP && m_has("DRIFT CHANGED=25 LOST=0 CMP=26 MORE=") && m_has("DG ") && m_end_field("LINES") == m_nlines);
    CHECK(m_end_field("CUTS") > 0);
    /* every word that is no gate input moves: the drift list takes the lines the page has room for (one), the gates still hold, so every late line is printed and the end line is the last that fits */
    m_fx_on();
    m_at_wait = m_wait_flip_non_gate;
    RUN_CLEAN();
    CHECK(m_has("DRIFT CHANGED=16 LOST=0 CMP=26 MORE=12") && m_has("DG SNOC=") && !m_has("DC ") && m_loads_in(3) == LOADS_LATE);
    CHECK(m_nlines == LINE_CAP && m_end_field("LINES") == LINE_CAP && m_end_field("CUTS") == 12);
    /* a window that aborted in snapshot 1 is not visited or compared in snapshot 2 */
    m_fx_on();
    m_fault_at(m_addr("MNOC"));
    RUN_CLEAN();
    CHECK(m_loads_in(2) == 0 && !m_has("NEXT S2") && m_has("DRIFT NONE CMP=0"));
    /* the late words come after the drift report */
    m_fx_on();
    m_at_wait = m_wait_qmip;
    RUN_CLEAN();
    CHECK(m_line_index("DRIFT CHANGED=1 LOST=0 CMP=26", 0) < m_line_index("NEXT LATE GMU", 0) && m_line_index("NEXT LATE GMU", 0) < m_line_index("NEXT LATE RSCC", 0));
    return 0;
}

/* The late phase: the words no Linux code reads, read last of all and only on a state that still holds. */
static int suite_late(void)
{
    unsigned rst = 0;
    /* open fixture: both late blocks are announced and read in order, after the drift report and before the end line */
    m_fx_on();
    RUN_CLEAN();
    CHECK(m_loads_in(3) == LOADS_LATE && m_has("NEXT LATE GMU") && m_has("NEXT LATE RSCC"));
    CHECK(m_line_index("NEXT LATE GMU", 0) < m_line_index("LATE GMU RST=1 CFG=0 BUSY=0", 0) && m_line_index("LATE GMU RST=1 CFG=0 BUSY=0", 0) < m_line_index("NEXT LATE RSCC", 0));
    /* cold: nothing was read behind the CX gate in snapshot 1, so there is nothing to add and no late line at all */
    m_fx_cold();
    RUN_CLEAN();
    CHECK(!m_has("LATE") && m_loads_in(3) == 0);
    /* no counter: no wait, no snapshot 2, no fresh state: the late words are not read and the page says so */
    m_fx_on();
    m_have_counter = 0;
    RUN_CLEAN();
    CHECK(m_has("S2 SKIPPED NO_COUNTER") && m_loads_in(3) == 0 && m_line_starts("LATE GMU GATED BY NOS2") >= 0 && m_line_starts("LATE RSCC GATED BY NOS2") >= 0);
    /* a window that aborted in snapshot 1 has no load to announce: the late words print as SKIP and the other block is still read */
    m_fx_on();
    m_fault_at(m_addr("INIT"));
    RUN_CLEAN();
    CHECK(m_has("LATE GMU RST=SKIP CFG=SKIP BUSY=SKIP") && !m_has("NEXT LATE GMU") && m_has("NEXT LATE RSCC") && m_loads_in(3) == 1);
    /* an abort at the first late word ends the window: the others are not loaded, the other block is */
    for (unsigned i = 0; i < M_NREGS; i++) if (!strcmp(M_REGS[i].key, "RST")) rst = i;
    m_fx_on();
    m_fault_at(M_REGS[rst].addr);
    RUN_CLEAN();
    CHECK(m_has("LATE GMU RST=FAULT:6 CFG=SKIP BUSY=SKIP") && m_loads_in(3) == 2 && m_has("LATE RSCC PDCS=0"));
    /* an abort at the last word of the page costs the end line nothing */
    m_fx_on();
    m_fault_at(m_addr("PDCS"));
    RUN_CLEAN();
    CHECK(m_has("LATE RSCC PDCS=FAULT:6") && m_end_field("FAULTS") == 1 && m_end_field("LINES") == m_nlines);
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
    /* the verdict goes out before the first load of a word that does not feed it, so that a hang in the rest of GPUCC keeps it */
    {
        int r4_event = -1, gx_event = -1;
        for (unsigned i = 0; i < m_nevents; i++) {
            if (m_events[i].kind == M_LINE && r4_event < 0 && !strncmp(m_lines[m_events[i].addr], PREFIX "R4 ", strlen(PREFIX) + 3)) r4_event = (int)i;
            if (m_events[i].kind == M_LOAD && gx_event < 0 && m_events[i].addr == m_addr("GXGD")) gx_event = (int)i;
        }
        CHECK(r4_event >= 0 && gx_event >= 0 && r4_event < gx_event);
    }
    /* every table line is a LINE event between its first load and the first load of the next table line */
    unsigned loads_since_line = 0, max_run = 0;
    for (unsigned i = 0; i < m_nevents; i++) {
        if (m_events[i].phase == 2) break;
        if (m_events[i].kind == M_LINE) {
            loads_since_line = 0;
        } else if (++loads_since_line > max_run) {
            max_run = loads_since_line;
        }
    }
    CHECK(max_run <= 13);                /* the longest line of the table is the RSCC line: two words and ten TCS words */
    return 0;
}

static int suite_smmu(void)
{
    m_fx_on();
    m_set(m_addr("ID1"), 0xe000005f);    /* PAGESIZE (64K), NUMPAGENDXB 6 */
    m_set(m_addr("ID2"), 0x7452);
    RUN_CLEAN();
    CHECK(m_has("SMMU SMRG=0X9A CB=0X5F PG=64K NPG=6 PT=7 IAS=2 OAS=5 UBS=4"));
    m_fx_on();
    m_set(m_addr("ID1"), 0xffffffff);    /* a word that reads as a failed read is printed raw and not decoded */
    RUN_CLEAN();
    CHECK(m_has("ID1=0XFFFFFFFF") && !m_has("SMRG="));
    m_fx_on();
    m_fault_at(m_addr("ID2"));
    RUN_CLEAN();
    CHECK(m_has("ID2=FAULT:6") && !m_has("SMRG="));
    m_fx_on();
    m_set(m_addr("GFSR"), 0x2);          /* a global fault is printed raw */
    RUN_CLEAN();
    CHECK(m_has("GFSR=2"));
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

#if M_SPIN_OVERRIDE && SPIN_MAX < 4000000u
/* A counter that moves and never gets there: the wait gives up after SPIN_MAX reads with a token of its own (S2 SKIPPED SPIN), which is not the dead counter's (S2 SKIPPED NO_COUNTER), and a counter
 * that runs at the model's usual pace never meets the bound. Only the build with a small SPIN_MAX (larger than the 2 million reads of a counter that stands still) runs it: the shipped bound is
 * 2^32-1 reads, minutes of the real loop, which no model run can reach. */
static int suite_spin(void)
{
    m_fx_on();
    m_ctr_step = 1;                      /* one tick per read: 8 s would take 153.6 million reads */
    RUN_CLEAN();
    CHECK(m_has("S2 SKIPPED SPIN") && !m_has("S2 SKIPPED NO_COUNTER") && m_end_field("GAP_MS") == 0 && m_loads_in(2) == 0 && !m_has("DRIFT"));
    CHECK(m_loads_in(3) == 0 && m_line_starts("LATE GMU GATED BY NOS2") >= 0);
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
    return 0;
}

/* The widest values: every word that is not a gate input has bit 31 set and eight hex digits; the gate inputs keep their gate open. */
static void m_fx_wide(void)
{
    m_fx_on();
    m_set(m_addr("QMIP"), 0x7fffffff); m_set(m_addr("MNOC"), 0x7ffffffb); m_set(m_addr("SNOC"), 0x7ffffffd); m_set(m_addr("CFGA"), 0x7ffffffd);
    m_set(m_addr("AXI_NW"), 0xfffffffd); m_set(m_addr("VOTE"), 0xffffffff & ~0x2u); m_set(m_addr("GP0V"), 0xfffffffe);
    m_set(m_addr("CXGD"), 0x8fffffe0); m_set(m_addr("CXHW"), 0xfffffffe);
    m_set(m_addr("AHB"), 0x7ffffffd); m_set(m_addr("CGMU"), 0x7ffffffd); m_set(m_addr("CXO"), 0x7ffffffd);
    m_set(m_addr("HUB"), 0x7ffffffd); m_set(m_addr("DMT"), 0x7ffffffd); m_set(m_addr("HLOS"), 0x7ffffffd);
    m_set(m_addr("GXGD"), 0xfffffffe); m_set(m_addr("GXCF"), 0xfffffffe);
    m_set(m_addr("CXOA"), 0xfffffffe); m_set(m_addr("HUBA"), 0xfffffffe); m_set(m_addr("GXGM"), 0xfffffffe);
    m_set(m_addr("GRC"), 0xfffffffe); m_set(m_addr("GRF"), 0xfffffffe); m_set(m_addr("HRC"), 0xfffffffe); m_set(m_addr("HRF"), 0xfffffffe);
    m_set(m_addr("XRC"), 0xfffffffe); m_set(m_addr("XRF"), 0xfffffffe);
    m_set(m_addr("TCMR"), 0xfffffffe); m_set(m_addr("RST"), 0xfffffffe); m_set(m_addr("BUSY"), 0xfffffffe); m_set(m_addr("INIT"), 0xfffffffe); m_set(m_addr("CFG"), 0xfffffffe);
    m_set(m_addr("GXST"), 0xfffffffe); m_set(m_addr("FENS"), 0xfffffffe);
    m_set(m_addr("ST0"), 0xfffffffe); m_set(m_addr("PDCS"), 0xfffffffe); m_set(m_addr("BSY"), 0xfffffffe);
    m_set(m_addr("SCR0"), 0xfffffffe); m_set(m_addr("GFSR"), 0xfffffffe); m_set(m_addr("ID7"), 0xfffffffe);
    m_set(m_addr("ID0"), 0xfffffffe); m_set(m_addr("ID1"), 0xfffffffe); m_set(m_addr("ID2"), 0xfffffffe);
}

static int suite_budget(void)
{
    m_fx_wide();
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP && m_end_field("CUTS") == 0);
    for (unsigned i = 0; i < m_nlines; i++) CHECK(strlen(m_lines[i]) <= Q1N1_PAYLOAD_LINE_MAX);
    CHECK(m_bloads[M_SMMU] == 6);
    m_fx_wide();
    m_at_wait = m_wait_flip_most;
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP && m_has("DRIFT CHANGED=") && m_end_field("CUTS") > 0);
    m_fx_on();
    m_at_wait = m_wait_flip_all;
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
    m_win_faults = 0x3f;
    RUN_CLEAN();
    m_fx_on();
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

static void m_scenario(const char *name)
{
    m_fx_on();
    if (!strcmp(name, "cold")) m_fx_cold();
    if (!strcmp(name, "wide") || !strcmp(name, "wideflip") || !strcmp(name, "wideflipmost")) m_fx_wide();
    if (!strcmp(name, "flip") || !strcmp(name, "wideflip")) m_at_wait = m_wait_flip_all;
    if (!strcmp(name, "flipmost") || !strcmp(name, "wideflipmost")) m_at_wait = m_wait_flip_most;
    if (!strcmp(name, "drift")) m_at_wait = m_wait_qmip;
    if (!strcmp(name, "ahboff")) m_set(m_addr("CFGA"), 0x80000000);
    if (!strcmp(name, "s2gated")) m_at_wait = m_wait_ahb_off;
    if (!strcmp(name, "hwctl")) m_set(m_addr("CXGD"), 0x8022f002);
    if (!strcmp(name, "part")) m_set(m_addr("CGMU"), 0x80000000);
    if (!strcmp(name, "smmuclk")) m_set(m_addr("HLOS"), 0x80000000);
    if (!strcmp(name, "gpuccabort")) m_fault_at(m_addr("CXGD"));
    if (!strcmp(name, "gccabort")) m_fault_at(m_addr("QMIP"));
    if (!strcmp(name, "nocounter")) m_have_counter = 0;
}

static unsigned m_snapshot1_lines(void)
{
    int wait = m_line_index("NEXT WAIT 8 S", 0);
    return wait < 0 ? m_nlines : (unsigned)wait;
}

/* The lines of the late phase: those between the drift summary and the end line. */
static unsigned m_late_lines(void)
{
    unsigned n = 0, after_drift = 0;
    for (unsigned i = 0; i + 1 < m_nlines; i++) {
        if (after_drift) n++;
        if (!strncmp(m_lines[i], PREFIX "DRIFT ", strlen(PREFIX) + 6)) after_drift = 1;
    }
    return n;
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

/* The numbers the document quotes, measured on runs of the model and nothing else: docs/SP11-PAYLOAD-GPUSNAP.md carries them in one block that the document test compares with this
 * output. */
static void m_numbers(void)
{
    printf("registers %u\n", (unsigned)R_COUNT);
    printf("line_cap %u\nload_cap %u\nabi_lines %u\nabi_loads %u\n", LINE_CAP, LOAD_CAP, Q1N1_PAYLOAD_LINES_MAX, Q1N1_PAYLOAD_LOADS_MAX);
    m_scenario("unit");
    RUN_CLEAN();
    printf("open_lines %u\nopen_snapshot1_lines %u\nopen_late_lines %u\nopen_loads %u\nopen_snapshot1_loads %u\nopen_snapshot2_loads %u\nopen_late_loads %u\n", m_nlines,
           m_snapshot1_lines(), m_late_lines(), m_nloads, m_loads_in(0), m_loads_in(2), m_loads_in(3));
    m_scenario("cold");
    RUN_CLEAN();
    printf("cold_lines %u\ncold_loads %u\n", m_nlines, m_nloads);
    m_scenario("ahboff");
    RUN_CLEAN();
    printf("ahboff_lines %u\nahboff_loads %u\n", m_nlines, m_nloads);
    m_scenario("wide");
    RUN_CLEAN();
    printf("wide_lines %u\nwide_cuts %u\n", m_nlines, m_end_field("CUTS"));
    m_scenario("wideflipmost");
    RUN_CLEAN();
    printf("wideflipmost_lines %u\nwideflipmost_cuts %u\nwideflipmost_more %u\n", m_nlines, m_end_field("CUTS"), m_more());
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
#ifdef GPUSNAP_SHIPPED_CAPS
    m_run_suite("unit", suite_unit);
    m_run_suite("cold", suite_cold);
    m_run_suite("gate", suite_gate);
    m_run_suite("faults", suite_faults);
    m_run_suite("storm", suite_storm);
    m_run_suite("drift", suite_drift);
    m_run_suite("late", suite_late);
    m_run_suite("stream", suite_stream);
    m_run_suite("smmu", suite_smmu);
    m_run_suite("counter", suite_counter);
#if M_SPIN_OVERRIDE && SPIN_MAX < 4000000u
    m_run_suite("spin", suite_spin);
#endif
    m_run_suite("el", suite_el);
    m_run_suite("budget", suite_budget);
    CHECK(m_max_loads <= LOADS_ON && m_max_lines <= LINE_CAP);
#else
    m_run_suite("caps", suite_caps);
#endif
    printf("CHECKS %u FAILS %u MAXLINES %u MAXLOADS %u LINE_CAP %u LOAD_CAP %u\n", m_checks, m_fails, m_max_lines, m_max_loads, LINE_CAP, LOAD_CAP);
    return m_fails ? 1 : 0;
}
