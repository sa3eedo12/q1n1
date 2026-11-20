/* SPDX-License-Identifier: MIT */
/* The suites of the host test of the payload "inputsnap" that push it to its limits (tools/test-q1n1-sp11-payload-inputsnap.c includes this file after its own helpers
 * and first suites, as one translation unit: the model's state is static): aborts in snapshot 2, the 64-bit registers, windows that all abort and hostile values, the counter
 * and the bound on the wait, exception levels and arguments, the order of the page and the page's budgets. Nothing here ran on hardware. Evidence: EXPERIMENTAL (host
 * model only). */

static unsigned m_target_w;
static uint32_t m_target_off;
static void m_wait_fault_target(void) { m_ffault(m_target_w, m_target_off); }

/* An abort at every address snapshot 2 reads again, in turn. */
static int suite_faults2(void)
{
    uint64_t addrs[64];
    unsigned n = 0;
    m_fx_unit();
    RUN_CLEAN();
    for (unsigned i = 0; i < m_nevents && n < 64; i++) {
        if (m_events[i].kind != M_LOAD || m_events[i].phase != 2) continue;
        addrs[n++] = m_events[i].addr;
    }
    CHECK(n == LOADS_S2);
    for (unsigned i = 0; i < n; i++) {
        unsigned w = m_win_of(addrs[i]);
        uint32_t off = (uint32_t)(addrs[i] - M_BASE[w]);
        const char *key = m_key_of(w, off);
        m_fx_unit();
        m_target_w = w;
        m_target_off = off;
        m_at_wait = m_wait_fault_target;
        RUN_CLEAN();
        CHECK(key != NULL && m_fault_under(key) && m_end_field("FAULTS") == 1 && !m_has("LOST=0"));
        CHECK(m_loads_of(w, off, 2) == 1);                  /* one access in snapshot 2, never retried */
        /* The words of a group after an abort are not read, so an engine whose gate words come after it in its group is not visited (S2) nor read late (X): an unknown clock is not
         * read through. The core 2x clock is the last word of its group and gates nothing. */
        if (w == M_GCC && m_group_of(off) == 0 && off != 0x23018) CHECK(m_line_starts("S2 U2 SKIP GATED ERR") > 0 && m_window_loads(M_U2, 2) == 0 && m_window_loads(M_U2, 3) == 0);
        else CHECK((m_window_loads(M_U2, 2) > 0 && m_window_loads(M_U2, 3) == LOADS_XU2) || w == M_U2);
        if (w == M_GCC && m_group_of(off) == 1 && off != 0x23168) CHECK(m_window_loads(M_S10, 3) == 0 && m_line_index("X S10 GATED ERR", 0) > 0);
        else CHECK(m_window_loads(M_S10, 3) == LOADS_XS10);
    }
    return 0;
}

static int suite_wide(void)
{
    m_fx_unit();
    m_fset64(M_GIC, 0x7340, UINT64_C(0x0000000100000002));
    RUN_CLEAN();
    m_val_is("X GIC", "R616", "0X100000002");
    m_fx_unit();
    m_fset64(M_GIC, 0x7340, UINT64_C(0x80000000));
    RUN_CLEAN();
    m_val_is("X GIC", "R616", "0X80000000");
    m_fx_unit();
    m_fset64(M_GIC, 0x7a10, UINT64_C(0xffffffff00000000));
    RUN_CLEAN();
    m_val_is("X GIC", "R834", "0XFFFFFFFF00000000");
    m_fx_unit();
    m_fset64(M_GIC, 0x6780, UINT64_C(0x5));
    RUN_CLEAN();
    m_val_is("X GIC", "R240", "5");
    /* An abort in the low word: the high word is not read, the window is silent after it. */
    m_fx_unit();
    m_ffault(M_GIC, 0x7340);
    RUN_CLEAN();
    CHECK(m_loads_of(M_GIC, 0x7344, 3) == 0 && m_fault_under("R616"));
    m_val_is("X GIC", "G834", "SKIP");
    m_val_is("X GIC", "R834", "SKIP");
    /* An abort in the high word: the row says FAULT:6, not half a value. */
    m_fx_unit();
    m_fset64(M_GIC, 0x7340, UINT64_C(0x1234));
    m_ffault(M_GIC, 0x7344);
    RUN_CLEAN();
    CHECK(m_loads_of(M_GIC, 0x7344, 3) == 1);
    m_val_is("X GIC", "R616", "FAULT:6");
    m_val_is("X GIC", "R834", "SKIP");
    return 0;
}

static int suite_storm(void)
{
    m_fx_unit();
    m_win_faults = 0x1f;
    RUN_CLEAN();
    CHECK(m_nloads == 5 && m_end_field("FAULTS") == 5);          /* one load aborts in each of GCC's three groups and in GIC and TLMM; the engines are gated */
    CHECK(m_has("DRIFT NONE CMP=0") && !m_has("NEXT S2") && m_has("U2 GATED ERR") && m_has("S10 GATED ERR"));
    for (unsigned w = 0; w < M_WINDOWS; w++) {
        m_fx_unit();
        m_win_faults = 1u << w;
        RUN_CLEAN();
        CHECK(m_wloads[w] == (w == M_GCC ? 3u : 1u) && m_end_field("FAULTS") >= 1);
    }
    /* Words that are all ones, all zero, or random. */
    m_fx_unit();
    m_fill_all = 1;
    m_fill = 0xffffffffu;
    RUN_CLEAN();
    CHECK(m_has("U2 GATED ERR") && m_has("S10 GATED ERR"));      /* an all-ones clock word is a failed read: the engine is gated, and the clock is not called off */
    m_fill = 0;
    RUN_CLEAN();
    CHECK(!m_has("U2 GATED") && !m_has("S10 GATED"));
    m_fill_all = 0;
    m_fx_unit();
    for (uint64_t seed = 1; seed <= 400; seed++) {
        m_rand_seed = seed * UINT64_C(0x2545F4914F6CDD1D);
        RUN_CLEAN();
        CHECK(m_stream_ok() || m_end_field("CUTS") > 0);
    }
    /* Random words in a fixture with a flip: the second snapshot's own gate decides. */
    m_fx_unit();
    m_at_wait = m_wait_flip_all;
    for (uint64_t seed = 1; seed <= 100; seed++) {
        m_rand_seed = seed * UINT64_C(0x9E3779B97F4A7C15);
        RUN_CLEAN();
    }
    return 0;
}

static int suite_counter(void)
{
    m_fx_unit();
    RUN_CLEAN();
    CHECK(m_ctr_calls > 100 && m_ctr_calls < 20000);
    /* QEMU's counter is 62.5 MHz: the wait is in ticks of the frequency the register says. */
    m_fx_unit();
    m_hz = 62500000u;
    m_ctr_step = 625000;
    RUN_CLEAN();
    CHECK(m_has("HZ=0X3B9ACA0") && m_end_field("GAP_MS") >= 8000);
    /* A frequency outside 1 to 1000 MHz is the default, and the page says so. */
    m_fx_unit();
    m_hz = 0;
    RUN_CLEAN();
    CHECK(m_has("HZ=0X124F800 DEFAULT"));
    m_fx_unit();
    m_hz = UINT64_C(5000000000);
    RUN_CLEAN();
    CHECK(m_has("HZ=0X124F800 DEFAULT"));
    /* A counter that does not run, runs backwards or is absent: no snapshot 2, and the wait is bounded. */
    for (int mode = 0; mode < 3; mode++) {
        m_fx_unit();
        if (mode == 0) m_ctr_mode = C_STUCK;
        if (mode == 1) m_ctr_mode = C_BACK;
        if (mode == 2) m_have_counter = 0;
        RUN_CLEAN();
        CHECK(m_has("S2 SKIPPED NO_COUNTER") && !m_has("S2 SKIPPED SPIN") && !m_has("NEXT S2") && m_nloads == LOADS_S1 + LOADS_X && m_end_field("GAP_MS") == 0);
        CHECK(!m_has("DRIFT") && m_has("NEXT X U2") && m_window_loads(M_U2, 3) == LOADS_XU2);        /* the late blocks go on, gated on snapshot 1's words */
        CHECK(mode == 2 ? !m_has("NEXT WAIT 8 S") : m_has("NEXT WAIT 8 S"));
        CHECK(m_ctr_calls <= COUNTER_STUCK_READS + 10);
    }
    return 0;
}

/* A counter that runs, but slowly. The wait is for 8 s on the counter and ends on it; the bound on the reads it may make (SPIN_MAX) is far above what it needs, so that a slow
 * loop on slow hardware does not lose snapshot 2, and a counter that stands still or runs backwards ends the wait first, as NO_COUNTER. A bound that is reached while the counter
 * runs is SPIN. With the shipped bound a counter that advances once per read at 1 MHz (8 million reads for 8 s) gets there; with the bound the build was given (4 million) it does
 * not, and the page says SPIN, not NO_COUNTER. */
static int suite_spin(void)
{
#ifdef INPUTSNAP_SHIPPED_CAPS
    const int shipped = 1;
    CHECK(SPIN_MAX == 0xffffffffu);                         /* the shipped bound is the largest the counter of reads holds, not a guess at how fast the loop runs */
#else
    const int shipped = 0;
#endif
    m_fx_unit();
    RUN_CLEAN();                                            /* 800 reads of the counter: far inside either bound */
    CHECK(m_has("NEXT S2 GCC") && !m_has("S2 SKIPPED") && m_loads_in(2) == LOADS_S2);
    m_fx_unit();
    m_hz = 1000000u;
    m_ctr_step = 1;
    RUN_CLEAN();
    if (shipped) {
        CHECK(m_has("NEXT S2 GCC") && !m_has("S2 SKIPPED") && m_end_field("GAP_MS") >= 8000 && m_end_field("GAP_MS") < 8100 && m_ctr_calls > 7000000u);
    } else {
        CHECK(m_has("S2 SKIPPED SPIN") && !m_has("NO_COUNTER") && !m_has("NEXT S2") && m_loads_in(2) == 0 && m_end_field("GAP_MS") == 0);
        CHECK(m_ctr_calls >= SPIN_MAX && m_ctr_calls <= SPIN_MAX + 10u);
        CHECK(!m_has("DRIFT") && m_has("NEXT X U2") && m_loads_in(3) == LOADS_X);          /* what a skipped snapshot 2 leaves is still printed, and read */
    }
    /* A counter that advances once in a thousand reads, a thousand ticks at a time: the same rate, the same verdict. */
    m_fx_unit();
    m_hz = 1000000u;
    m_ctr_step = 1000;
    m_ctr_every = 1000;
    RUN_CLEAN();
    CHECK(shipped ? !m_has("S2 SKIPPED") : (m_has("S2 SKIPPED SPIN") && !m_has("NO_COUNTER")));
    /* A counter that does not run is NO_COUNTER, in either build: its bound (COUNTER_STUCK_READS) is the smaller one. */
    for (int mode = 0; mode < 2; mode++) {
        m_fx_unit();
        m_ctr_mode = mode ? C_BACK : C_STUCK;
        RUN_CLEAN();
        CHECK(m_has("S2 SKIPPED NO_COUNTER") && !m_has("S2 SKIPPED SPIN") && m_ctr_calls <= COUNTER_STUCK_READS + 10u);
    }
    return 0;
}

static int suite_el(void)
{
    for (int el = 0; el < 4; el++) {
        if (el == 2) continue;
        m_fx_unit();
        m_el = el;
        RUN_CLEAN();
        CHECK(m_nlines == 1 && m_nloads == 0 && m_has("SKIPPED_NOT_AT_EL2") && m_sysreg_reads == 1);
    }
    m_fx_unit();
    {
        struct q1n1_payload_args a = m_args();
        a.magic ^= 1;
        m_reset_run();
        CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 0 && m_nloads == 0 && m_sysreg_reads == 0);
        a = m_args();
        a.ops.hex = NULL;
        CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 0);
        a = m_args();
        a.version = 2;
        CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 0);
    }
    m_fx_unit();
    m_have_load32 = 0;
    CHECK(m_go() == Q1N1_PAYLOAD_RET_BAD_ARGS && m_nlines == 1 && m_has("REFUSED_NO_LOAD32") && m_violations == 0);
    return 0;
}

/* Eight-digit values that differ everywhere, and a second snapshot that differs again: the widest page. The clock words keep HW_CTL set, so that the engines are read. */
static void m_fx_wide(void)
{
    m_fx_unit();
    for (unsigned i = 0; i < m_nfake; i++) {
        uint32_t x = (uint32_t)(m_fake[i].addr * 2654435761u);
        m_fake[i].value = 0x80000000u | (x >> 1);
    }
    for (unsigned i = 0; i < 4; i++) m_fset(M_GCC, M_GATE_U2[i], 0xa0000000u | (uint32_t)((M_GATE_U2[i] * 2654435761u) >> 1 & 0x0ffffff0u));
    for (unsigned i = 0; i < 5; i++) m_fset(M_GCC, M_GATE_S10[i], 0xa0000000u | (uint32_t)((M_GATE_S10[i] * 2654435761u) >> 1 & 0x0ffffff0u));
}

/* The late blocks, by the harness's own names, and the bit of each in the end line's BLK (the blocks are numbered in page order: GCC 0 ... TLMM 4, then these). */
static const char *const M_XNAME[3] = {"X U2", "X S10", "X GIC"};

/* Two groups of drift lines instead of the three of m_wait_three: one clock word and the UART engine's STATUS. The page then has exactly one line to spare after the second late
 * block: the NEXT line of the third would fit, a line of values after it would not. */
static void m_wait_two_groups(void)
{
    m_fset(M_GCC, 0x23018, 0x3);
    m_fset(M_U2, 0x040, 0x1);
}

/* Each late block is either announced by its own NEXT line, with a line of its own after it, or left out: then its bit of BLK is set and nothing of its window was read late
 * (a word that has no room on the page is not read: these are the words nobody has read through Linux). */
static int m_late_blocks_accounted(void)
{
    static const unsigned WIN[3] = {M_U2, M_S10, M_GIC};
    int ok = 1;
    for (unsigned b = 0; b < 3; b++) {
        char next[16];
        int at;
        snprintf(next, sizeof next, "NEXT %s", M_XNAME[b]);
        at = m_line_index(next, 0);
        if (at >= 0) ok &= (unsigned)at + 1 < m_nlines && !strncmp(m_lines[at + 1] + strlen(PREFIX), M_XNAME[b], strlen(M_XNAME[b]));
        else ok &= (m_end_field("BLK") >> (5 + b) & 1u) && m_window_loads(WIN[b], 3) == 0;
    }
    return ok;
}

/* The page is at most LINE_CAP lines whatever the values: every NEXT line of the snapshots is there, and so is the closing pair; the late blocks, which come last, are announced
 * or counted as left out. */
static int suite_budget(void)
{
    m_fx_wide();
    for (int drift = 0; drift < 2; drift++) {
        m_at_wait = drift ? m_wait_flip_all : NULL;
        RUN_CLEAN();
        CHECK(m_has("NEXT GCC") && m_has("NEXT GIC") && m_has("NEXT U2") && m_has("NEXT S10") && m_has("NEXT TLMM"));
        CHECK(m_has("NEXT WAIT 8 S") && m_has("NEXT S2 TLMM") && m_nlines <= LINE_CAP);
        CHECK(m_has("DRIFT ") && m_has("END LOADS="));
        CHECK(m_end_field("CUTS") > 0);                     /* what the cap keeps off the page is counted */
        CHECK(m_late_blocks_accounted());
        CHECK(m_stream_ok());
    }
    return 0;
}

/* What a single abort or hang costs, by the order of the page: everything the run exists for is on it before the first load of a word no Linux driver reads, and a page too
 * full for the late blocks leaves them unread with the closing lines intact. */
static int suite_order(void)
{
    int drift, next_event, first_x = -1, end_event;
    m_fx_unit();
    RUN_CLEAN();
    drift = m_line_index("DRIFT NONE CMP=19", 0);
    for (unsigned e = 0; e < m_nevents; e++) if (m_events[e].kind == M_LOAD && m_events[e].phase == 3) { first_x = (int)e; break; }
    CHECK(drift > 0 && first_x > 0 && m_line_event((unsigned)drift) < first_x);        /* the drift summary is out before the first late load */
    next_event = m_line_event((unsigned)m_line_index("NEXT X U2", 0));
    CHECK(next_event >= 0 && next_event < first_x);         /* the late block's own NEXT line is out before it (the model: and is the last line printed then) */
    end_event = m_line_event(m_nlines - 1u);
    CHECK(end_event > first_x);
    for (unsigned b = 0; b < 3; b++) {
        char next[16];
        snprintf(next, sizeof next, "NEXT %s", M_XNAME[b]);
        CHECK(m_line_index(next, 0) > drift);
    }
    CHECK(m_line_index("NEXT X U2", 0) < m_line_index("NEXT X S10", 0) && m_line_index("NEXT X S10", 0) < m_line_index("NEXT X GIC", 0));
    /* Every S1 load comes before every S2 load and every S2 load before every late load. */
    {
        unsigned last1 = 0, first2 = m_nevents, last2 = 0, first3 = m_nevents;
        for (unsigned e = 0; e < m_nevents; e++) {
            if (m_events[e].kind != M_LOAD) continue;
            if (m_events[e].phase == 1) last1 = e;
            if (m_events[e].phase == 2 && first2 == m_nevents) first2 = e;
            if (m_events[e].phase == 2) last2 = e;
            if (m_events[e].phase == 3 && first3 == m_nevents) first3 = e;
        }
        CHECK(last1 < first2 && last2 < first3);
    }
    /* A page that has no room: the late blocks are not read, the end line is there, and nothing else is lost. */
    m_fx_wide();
    m_at_wait = m_wait_flip_all;
    RUN_CLEAN();
    CHECK(m_late_blocks_accounted() && m_has("DRIFT ") && m_has("END LOADS=") && m_nlines <= LINE_CAP);
    CHECK(m_loads_in(1) == LOADS_S1 && m_loads_in(2) == LOADS_S2 && m_loads_in(3) <= LOADS_X);
    /* Some room, not enough for all: the late blocks come in the order of what matters (the UART engine, the SPI engine, the GIC), the first takes what it needs and the last is not
     * read, not announced, and counted. */
    m_fx_unit();
    m_at_wait = m_wait_three;
    RUN_CLEAN();
    CHECK(m_late_blocks_accounted() && m_line_index("NEXT X U2", 0) >= 0 && m_line_index("NEXT X S10", 0) >= 0 && m_line_index("NEXT X GIC", 0) < 0);
    CHECK(m_window_loads(M_GIC, 3) == 0 && (m_end_field("BLK") & 0x80u));
    /* One line to spare: the third late block's NEXT line would fit and its values would not, so it is neither announced nor read (and nothing is cut: nothing was read). */
    m_fx_unit();
    m_at_wait = m_wait_two_groups;
    RUN_CLEAN();
    CHECK(m_late_blocks_accounted() && m_line_index("NEXT X S10", 0) >= 0 && m_line_index("NEXT X GIC", 0) < 0);
    CHECK(m_nlines == LINE_CAP - 1u && m_window_loads(M_GIC, 3) == 0 && (m_end_field("BLK") & 0x80u) && m_end_field("CUTS") == 0);
    CHECK(m_has("DRIFT CHANGED=2 LOST=0 CMP=19") && m_has("X S10 CM="));
    /* No counter, so no snapshot 2 and no drift summary: the late blocks still come last. */
    m_fx_unit();
    m_have_counter = 0;
    RUN_CLEAN();
    CHECK(m_line_index("NEXT X U2", 0) > m_line_index("NEXT TLMM", 0) && m_loads_in(3) == LOADS_X);
    return 0;
}

/* A build with a smaller line or load cap than the shipped one: the cap holds, the closing lines are there, and nothing is read that was not announced. */
static int suite_caps(void)
{
    m_fx_unit();
    RUN_CLEAN();
    CHECK(m_nlines <= LINE_CAP && m_nloads <= LOAD_CAP);
    if (LINE_CAP < 30) CHECK(m_end_field("CUTS") > 0);
    if (LOAD_CAP < LOADS_S1 + LOADS_S2 + LOADS_X) CHECK(m_has("BUDGET"));
    m_at_wait = m_wait_flip_all;
    RUN_CLEAN();
    m_at_wait = NULL;
    m_fx_unit();
    m_win_faults = 0x1f;
    RUN_CLEAN();
    m_fx_wide();
    RUN_CLEAN();
    m_fx_unit();
    for (uint64_t seed = 1; seed <= 60; seed++) {
        m_rand_seed = seed * UINT64_C(0x2545F4914F6CDD1D);
        RUN_CLEAN();
    }
    return 0;
}
