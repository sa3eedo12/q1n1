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
    CHECK(m_has("U2 GATED ERR") && m_has("S10 GATED ERR") && !m_has("GATED OFF"));       /* a window of zeros reads every branch as running, and every vote as clear: nothing backs them */
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

/* What an engine's gate needs besides its clock words, and the second lines of defence the page never shows: a clock that says only hardware gating needs its own vote bit in the
 * vote word snapshot 1 read; three vote words that read zero gate every engine (a window of zeros reads every branch as running); the read primitive refuses a window the table does not
 * have, an offset past its window and an unaligned one before it loads; the load-level gate holds an engine back by itself; the line cap holds at its boundary. */
static void m_ctx_init(struct ctx *c)
{
    memset(c, 0, sizeof *c);
    c->puts = m_puts;
    c->hex = m_hex;
    c->load32 = m_load32;
    c->counter = m_counter;
}

static void m_wait_ma0_hw(void) { m_fset(M_GCC, 0x23000, 0x80000002u); }
static void m_wait_votes_zero(void)
{
    m_fset(M_GCC, 0x52020, 0);
    m_fset(M_GCC, 0x52008, 0);
    m_fset(M_GCC, 0x52028, 0);
}

static int suite_gate2(void)
{
    static const uint32_t VOTE_OFF[] = {0x52020, 0x52008, 0x52028};
    struct ctx c;
    struct pl_line line;
    uint32_t value = 0;
    CHECK(sizeof hw_votes / sizeof hw_votes[0] == sizeof M_HWVOTE / sizeof M_HWVOTE[0]);
    for (unsigned k = 0; k < sizeof M_HWVOTE / sizeof M_HWVOTE[0]; k++) {
        unsigned engine = M_HWVOTE[k].clock < 0x23100 ? M_U2 : M_S10, other = engine == M_U2 ? M_S10 : M_U2;
        char off[24], err[24];
        snprintf(off, sizeof off, "%s GATED OFF", M_NAME[engine]);
        snprintf(err, sizeof err, "%s GATED ERR", M_NAME[engine]);
        CHECK(regs[hw_votes[k].clock].off == M_HWVOTE[k].clock);
        CHECK(regs[hw_votes[k].vote].off == M_HWVOTE[k].vote);
        CHECK(hw_votes[k].bit == M_HWVOTE[k].bit);
        CHECK(regs[hw_votes[k].clock].win == WIN_GCC && regs[hw_votes[k].vote].win == WIN_GCC && (regs[hw_votes[k].clock].flags & F_HWCG) && !hw_votes[k].pad);
        /* The clock says only hardware gating and its vote is set (the unit-like fixture's): the engine is read. */
        m_fx_unit();
        m_fset(M_GCC, M_HWVOTE[k].clock, 0x80000002u);
        RUN_CLEAN();
        CHECK(m_line_index(off, 0) < 0 && m_line_index(err, 0) < 0 && m_window_loads(engine, 1) > 0 && m_window_loads(other, 1) > 0);
        /* Its own vote bit clear, every other bit of the word set: stopped, `GATED OFF`, in every snapshot, and the other engine is not touched. */
        m_fx_unit();
        m_fset(M_GCC, M_HWVOTE[k].clock, 0x80000002u);
        m_fset(M_GCC, M_HWVOTE[k].vote, 0xffffffffu & ~(1u << M_HWVOTE[k].bit));
        RUN_CLEAN();
        CHECK(m_line_index(off, 0) >= 0 && m_line_index(err, 0) < 0 && m_window_loads(engine, 1) == 0 && m_window_loads(engine, 3) == 0 && m_window_loads(other, 1) > 0);
        /* Only its own bit clear, the word otherwise as the fixture has it: the same; and the neighbour's bit clear with its own set: read. */
        m_fx_unit();
        m_fset(M_GCC, M_HWVOTE[k].clock, 0x80000002u);
        m_fset(M_GCC, M_HWVOTE[k].vote, M_HWVOTE[k].vote == 0x52020 ? 0x10c0u & ~(1u << M_HWVOTE[k].bit) : 0x1380000u & ~(1u << M_HWVOTE[k].bit));
        RUN_CLEAN();
        CHECK(m_line_index(off, 0) >= 0 && m_window_loads(engine, 1) == 0);
        m_fx_unit();
        m_fset(M_GCC, M_HWVOTE[k].clock, 0x80000002u);
        m_fset(M_GCC, M_HWVOTE[k].vote, 1u << M_HWVOTE[k].bit);
        RUN_CLEAN();
        CHECK(m_line_index(off, 0) < 0 && m_line_index(err, 0) < 0 && m_window_loads(engine, 1) > 0);
        /* The vote bit is asked of a hardware-gated clock only: a clock that reads ON with its bit clear is read (an other master's vote may run it). */
        m_fx_unit();
        m_fset(M_GCC, M_HWVOTE[k].vote, 0xffffffffu & ~(1u << M_HWVOTE[k].bit));
        RUN_CLEAN();
        CHECK(m_line_index(off, 0) < 0 && m_line_index(err, 0) < 0 && m_window_loads(engine, 1) > 0);
        /* The vote word did not read: a hardware-gated clock is unknown, never stopped (the group of vote words is silent after the abort). */
        m_fx_unit();
        m_fset(M_GCC, M_HWVOTE[k].clock, 0x80000002u);
        m_ffault(M_GCC, M_HWVOTE[k].vote);
        RUN_CLEAN();
        CHECK(m_line_index(err, 0) >= 0 && m_line_index(off, 0) < 0 && m_window_loads(engine, 1) == 0 && m_window_loads(other, 1) > 0);
        /* The same abort with the clock reading ON gates nothing, as before: no vote evidence is asked of it. */
        m_fx_unit();
        m_ffault(M_GCC, M_HWVOTE[k].vote);
        RUN_CLEAN();
        CHECK(m_line_index(err, 0) < 0 && m_line_index(off, 0) < 0 && m_window_loads(engine, 1) > 0);
        /* A word that says stopped outranks a vote word that did not read. */
        m_fx_unit();
        m_fset(M_GCC, M_HWVOTE[k].clock, 0x80000000u);
        m_ffault(M_GCC, M_HWVOTE[k].vote);
        RUN_CLEAN();
        CHECK(m_line_index(off, 0) >= 0 && m_line_index(err, 0) < 0);
    }
    /* Snapshot 2 and the late blocks use the votes snapshot 1 read: a clock that turns hardware-gated during the wait keeps the engine visited while the vote was set then, and the
     * vote words going to zero during the wait change nothing (they are not read again). */
    m_fx_unit();
    m_at_wait = m_wait_ma0_hw;
    RUN_CLEAN();
    CHECK(m_line_starts("NEXT S2 U2") > 0 && m_window_loads(M_U2, 2) == 6 && m_window_loads(M_U2, 3) == LOADS_XU2);
    m_fx_unit();
    m_at_wait = m_wait_votes_zero;
    RUN_CLEAN();
    CHECK(m_line_starts("NEXT S2 U2") > 0 && m_window_loads(M_U2, 2) == 6 && m_window_loads(M_S10, 3) == LOADS_XS10);
    /* A hardware-gated clock whose vote is clear in snapshot 1 is stopped in snapshot 1, and stays so for the late blocks even if the clock word goes ON in the wait. */
    m_fx_unit();
    m_fset(M_GCC, 0x23000, 0x80000002u);
    m_fset(M_GCC, 0x52020, 0x1000);
    m_at_wait = m_wait_ma0_on;
    RUN_CLEAN();
    CHECK(m_line_index("U2 GATED OFF", 0) >= 0 && m_window_loads(M_U2, 1) == 0 && m_line_starts("S2 U2") < 0 && m_window_loads(M_U2, 3) == LOADS_XU2);
    /* Three vote words that read zero gate both engines: `GATED ERR` (nothing is known of the clocks), in snapshot 1, snapshot 2 and the late blocks. */
    m_fx_unit();
    m_wait_votes_zero();
    RUN_CLEAN();
    CHECK(m_line_index("U2 GATED ERR", 0) >= 0 && m_line_index("S10 GATED ERR", 0) >= 0 && m_line_index("U2 GATED OFF", 0) < 0 && m_wloads[M_U2] == 0 && m_wloads[M_S10] == 0);
    CHECK(m_line_index("X U2 GATED ERR", 0) >= 0 && m_line_index("X S10 GATED ERR", 0) >= 0 && m_wloads[M_GIC] > 0 && m_wloads[M_TLMM] > 0 && m_end_field("BLK") != 0);
    m_fx_unit();
    m_gcc_all(0);
    m_wait_votes_zero();
    RUN_CLEAN();
    CHECK(m_line_index("U2 GATED ERR", 0) >= 0 && m_line_index("S10 GATED ERR", 0) >= 0 && m_wloads[M_U2] == 0 && m_wloads[M_S10] == 0);
    /* Not every vote word: any one of the three that reads non-zero is vote evidence enough. */
    for (unsigned keep = 0; keep < 3; keep++) {
        m_fx_unit();
        m_wait_votes_zero();
        m_fset(M_GCC, VOTE_OFF[keep], 0x10);
        RUN_CLEAN();
        CHECK(m_line_index("U2 GATED ERR", 0) < 0 && m_line_index("S10 GATED ERR", 0) < 0 && m_window_loads(M_U2, 1) > 0 && m_window_loads(M_S10, 1) > 0);
    }
    /* A vote word that did not read is not a word that read zero: the others at zero do not gate the engines of clocks that read ON. */
    m_fx_unit();
    m_wait_votes_zero();
    m_ffault(M_GCC, 0x52028);
    RUN_CLEAN();
    CHECK(m_line_index("U2 GATED ERR", 0) < 0 && m_window_loads(M_U2, 1) > 0);
    /* The read primitive refuses before it loads: a window the table does not have (any number from WINDOWS up), an offset at or past the end of its window, an unaligned one. */
    m_fx_unit();
    m_reset_run();
    m_ctx_init(&c);
    CHECK(rd32(&c, WINDOWS, 0, 0, &value) == RD_RANGE && rd32(&c, WINDOWS + 3u, 0, 0x100, &value) == RD_RANGE && rd32(&c, 0xffffu, 0, 0, &value) == RD_RANGE);
    CHECK(rd32(&c, WIN_U2, 0, windows[WIN_U2].size, &value) == RD_RANGE && rd32(&c, WIN_U2, 0, windows[WIN_U2].size - 2u, &value) == RD_ALIGN);
    CHECK(rd32(&c, WIN_GCC, 0, 2, &value) == RD_ALIGN && value == 0);
    CHECK(c.loads == 0 && m_nloads == 0 && c.dead == 0);
    /* The load-level gate: a row of an engine is not loaded when the clock words it is handed say stopped, whoever calls; and it is loaded when they say running. */
    m_fx_unit();
    m_reset_run();
    m_ctx_init(&c);
    for (unsigned id = R_G_MA0; id <= R_G_VT2; id++) {
        c.s[0].v[id].st = V_OK;
        c.s[0].v[id].v = regs[id].off >= 0x52000 ? 0x10 : 0x1;
    }
    c.s[0].v[R_G_MA0].v = 0x80000000u;
    read_row(&c, &c.s[0], &c.s[0], R_U_FW);
    CHECK(c.s[0].v[R_U_FW].st == V_GATED && c.loads == 0 && m_nloads == 0 && (c.blocks >> B_U2 & 1));
    c.s[0].v[R_G_MA0].v = 0x1;
    read_row(&c, &c.s[0], &c.s[0], R_U_FW);
    CHECK(c.s[0].v[R_U_FW].st == V_OK && c.loads == 1 && m_nloads == 1);
    /* The line cap holds at its boundary: a line that would leave fewer lines free than it must keep is cut and counted, one that leaves exactly that many is printed. */
    m_reset_run();
    m_ctx_init(&c);
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, "T");
    c.lines = LINE_CAP - 1u;
    CHECK(emit(&c, &line, 1) == 0 && c.cuts == 1 && c.lines == LINE_CAP - 1u && m_nlines == 0);
    c.lines = LINE_CAP - 2u;
    CHECK(emit(&c, &line, 1) == 1 && c.cuts == 1 && c.lines == LINE_CAP - 1u && m_nlines == 1);
    CHECK(emit(&c, &line, 0) == 1 && c.lines == LINE_CAP && emit(&c, &line, 0) == 0 && c.cuts == 2 && m_nlines == 2);
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
