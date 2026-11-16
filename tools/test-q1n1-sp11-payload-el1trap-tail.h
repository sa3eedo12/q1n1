/* SPDX-License-Identifier: MIT */
/* The tail of tools/test-q1n1-sp11-payload-el1trap.c, kept in a file of its own so that neither passes the 50 KiB limit: the random
 * worlds (suite_fuzz), the checks of the arguments (suite_args) and the two reports the documents quote (`page`, `lines-report`).
 * It is included once, between the suites and main, and uses everything the program defines before that point. */

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}
/* `usual`, except one time in `n`: `rare`. */
#define RARELY(n, usual, rare) (rnd() % (n) ? (usual) : (rare))

static int suite_fuzz(void)
{
    static const unsigned fewest[T_COUNT] = {100, 20, 100, 100, 100, 100, 100};
    unsigned seen[T_COUNT];
    memcpy(seen, tally, sizeof seen);
    for (unsigned round = 0; round < 6000; round++) {
        uint64_t ret;
        unit_like();
        w.el_raw = RARELY(8, 2 << 2, (rnd() & 3) << 2);
        w.reg[R_HCR] = RARELY(8, 0x88000010, rnd());
        w.mmfr0 = rnd();
        w.pfr0 = RARELY(16, w.pfr0, rnd());
        w.cntfrq = RARELY(4, 1000000u + rnd() % 999000000u, RARELY(3, 0, rnd()));
        w.daif = RARELY(8, 0x3c0, rnd() & 0x3c0);
        w.spsel = RARELY(12, 1, rnd() & 1);
        w.reg[R_CNTHCTL] = RARELY(4, rnd() & 0xFFF, rnd());
        w.reg[R_SCTLR] = rnd();
        w.reg[R_VBAR1] = rnd() & ~UINT64_C(0x7ff);
        w.reg[R_VBAR2] = (rnd() & ~UINT64_C(0x7ff)) | 0x1000;
        for (unsigned r = 0; r < R_COUNT; r++) {
            w.writable[r] = RARELY(3, ~UINT64_C(0), rnd());
            w.forced[r] = RARELY(12, 0, BIT(rnd() % 64));
            w.restore[r] = (int)(rnd() % 3);
        }
        /* The vector bases hold host addresses, whose bits 11 to 39 depend on where the host loaded the image: a forced bit there
         * would make the world, and so the count of checks, differ from one run to the next. */
        w.forced[R_VBAR1] &= ~((BIT(40) - 1) & ~UINT64_C(0x7ff));
        w.forced[R_VBAR2] &= ~((BIT(40) - 1) & ~UINT64_C(0x7ff));
        w.writable[R_CNTHCTL] &= RARELY(2, 0x7FFF, ~UINT64_C(0));
        w.sp = RARELY(8, w.sp, w.stack_base + rnd() % (w.stack_size * 2));
        w.every = RARELY(200, (plausible_hz(w.cntfrq) ? w.cntfrq : 19200000u) / 40 + rnd() % 2000000, 0);
        w.start = rnd();
        w.stall = RARELY(100, RARELY(10, 0, rnd() % 100), STUCK_READS + 1);
        w.no_counter_op = rnd() % 40 == 0;
        w.ecv_effective = (int)(rnd() & 1);
        w.control_traps = rnd() % 8 != 0;
        w.cntfrq_traps = rnd() % 8 == 0;
        w.iss_noise = RARELY(4, 0, BIT(rnd() % 31) & ~BIT(25));
        w.caller_spsr = rnd();
        w.scenario = RARELY(3, SC_NORMAL, (int)(rnd() % SC_COUNT));
        w.k = rnd() % 5;
        w.probe = RARELY(8, PROBE_OK, PROBE_FAILS);
        w.vbar2 = RARELY(10, VBAR2_BACK, (int)(1 + rnd() % 2));
        switch (rnd() % 24) {
        case 0: w.base = IMG_EL2 + 1 + rnd() % 8192; break;                                 /* the vectors are below the image */
        case 1: w.size = rnd() % 20000; break;
        case 2: w.base = IMG_EL2 - 16 * (1 + rnd() % 64); w.size = IMG_BYTES + (IMG_EL2 - w.base) + rnd() % 100; break;
        case 3: w.base = IMG_EL2 - (1 + rnd() % 15); w.size = IMG_BYTES + (IMG_EL2 - w.base) + rnd() % 100; break;    /* an unaligned start */
        default: break;
        }
        if (run_checked(&ret)) { fprintf(stderr, "fuzz round %u\n", round); return 1; }
    }
    for (unsigned i = 0; i < T_COUNT; i++) CHECK(tally[i] - seen[i] >= fewest[i]);    /* every path was taken often enough to mean something */
    return 0;
}

static int suite_args(void)
{
    struct q1n1_payload_args a;
    unit_like();
    for (unsigned i = 0; i < 5; i++) {
        a = args();
        switch (i) {
        case 0: a.magic ^= 1; break;
        case 1: a.version = 2; break;
        case 2: a.size = sizeof a - 1; break;
        case 3: a.ops.puts = NULL; break;
        default: a.ops.hex = NULL; break;
        }
        CHECK(go(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    }
    CHECK(payload_entry(NULL) == Q1N1_PAYLOAD_RET_BAD_ARGS);
    a = args();
    a.size = sizeof a + 64;                  /* a larger table than the payload knows is fine, and load32 is never used */
    a.ops.load32 = NULL;
    CHECK(go(&a) == 0 && runs == 1);
    return 0;
}

/* The pages of the worlds the host test scripts, as docs/SP11-PAYLOAD-EL1TRAP.md shows them. Run as `page`. */
static void page_of(const char *title)
{
    struct q1n1_payload_args a = args();
    go(&a);
    printf("# %s\n", title);
    for (unsigned i = 0; i < lines_n(); i++) printf("%s\n", line_n(i));
}
#define PAGE(title, edit) do { unit_like(); edit; page_of(title); } while (0)
static int report_page(void)
{
    PAGE("traps effective", (void)0);
    PAGE("bits do not stick", w.writable[R_CNTHCTL] = 0x1FFF);
    PAGE("stuck but inert", w.ecv_effective = 0);
    PAGE("only bit 14 sticks", w.writable[R_CNTHCTL] = 0x1FFF | BIT(14));
    PAGE("control not trapped", w.control_traps = 0);
    PAGE("hvc undefined at el2", (w.probe = PROBE_FAILS, w.end_esr = 0));
    PAGE("write not held", w.forced[R_HCR] = BIT(34));
    PAGE("restore fails", w.restore[R_HCR] = RESTORE_NEVER);
    return 0;
}

/* The most lines this payload prints, for the chain's page budget in docs/SP11-PAYLOAD.md: over every scripted end, both probe
 * results, the traps effective or inert, and no register, four or all five not put back (VBAR_EL2 too). Run as `lines-report`. */
static int report_lines(void)
{
    unsigned most = 0;
    for (unsigned i = 0; i < SC_COUNT * 2 * 3 * 2; i++) {
        struct q1n1_payload_args a;
        unsigned fail = i / SC_COUNT / 2 % 3;       /* 0: none, 1: four registers, 2: five */
        unit_like();
        w.scenario = (int)(i % SC_COUNT);
        w.k = 2;
        w.probe = (int)(i / SC_COUNT % 2);
        w.ecv_effective = (int)(i / SC_COUNT / 6 % 2);
        w.vbar2 = fail == 2 ? VBAR2_LATE : VBAR2_BACK;
        for (unsigned r = 0; fail && r < R_VBAR2 + (fail == 2); r++) w.restore[r] = RESTORE_NEVER;
        a = args();
        go(&a);
        if (lines_n() > most) most = lines_n();
    }
    printf("LINES_MAX=%u\n", most);
    return 0;
}
