/* SPDX-License-Identifier: MIT */
/* Host test for the payload "cpuon" (payloads/cpuon.c), built natively with Q1N1_PAYLOAD_HOST_TEST so that its MRS, SMC, cache
 * maintenance and stack pointer come from the model in test-q1n1-sp11-payload-cpuon-world.h (read its comment first: the model,
 * the rules every run is held to, and the oracle of what the page says). The suites below drive that model; the driver is
 * tools/test-q1n1-sp11-payload-cpuon.py and the machinery of tools/test-q1n1-sp11-payload.py, under ASan and UBSan.
 * The stub itself is assembly this test never runs: the QEMU test runs it and the build test disassembles it.
 * Evidence: EXPERIMENTAL (host model only). */
#include "test-q1n1-sp11-payload-cpuon-world.h"

static unsigned checks;
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)
#define RUN(label) do { world_reset(); a = args(); ret = payload_entry(&a); CHECK(common(label)); } while (0)
#define EXPECT(label) do { RUN(label); CHECK(page_is_oracle(label)); } while (0)

/* ---- ids ------------------------------------------------------------------------------------------------------------- */

static int suite_ids(void)
{
    struct q1n1_payload_args a;
    uint64_t ret;
    unsigned first_all = 0, on_calls = 0;
    script_default();
    EXPECT("ids");
    CHECK(ret == 0);
    for (unsigned i = 0; i < W.nsmc; i++) {
        CHECK(W.smc[i].id == ID_AFFINITY_INFO || W.smc[i].id == ID_CPU_ON);         /* no CPU_OFF, no other function at all */
        if (W.smc[i].id == ID_AFFINITY_INFO) CHECK(W.smc[i].x2 == 0 && W.smc[i].x3 == 0);
        else CHECK(W.smc[i].x2 == (uint64_t)(uintptr_t)cpuon_entry && slot_ok(W.smc[i].x3));
        if (W.smc[i].id == ID_CPU_ON && !on_calls++) CHECK(i == 11 && W.smc[i].x1 == 0x100);
        else if (W.smc[i].id == ID_CPU_ON && !first_all && on_calls > 1) first_all = i;
        if (i < 11) CHECK(W.smc[i].id == ID_AFFINITY_INFO && W.smc[i].x1 == table[i + 1]);   /* phase 0: the eleven, in order, first */
    }
    CHECK(on_calls == 12 && first_all > 11);
    for (unsigned k = 0; k < 11; k++) {         /* phase 2: back to back in table order, slot index = table index */
        CHECK(W.smc[first_all + k].id == ID_CPU_ON && W.smc[first_all + k].x1 == table[k + 1]);
        CHECK(W.smc[first_all + k].x3 == (uint64_t)(uintptr_t)arena + SLOT_BASE + (k + 1) * SLOT);
    }
    CHECK(W.smc[11].x3 == (uint64_t)(uintptr_t)arena + SLOT_BASE);                      /* phase 1 uses slot 0 */
    static const char *const documented[] = {"CurrentEL", "mpidr_el1", "CNTFRQ_EL0", "midr_el1", "id_aa64mmfr0_el1", "id_aa64isar0_el1", "id_aa64pfr0_el1"};
    CHECK(W.nsys == 7);
    for (unsigned i = 0; i < 7; i++) CHECK(!strcmp(W.sysregs[i], documented[i]));
    return 0;
}

static int suite_el(void)
{
    struct q1n1_payload_args a;
    uint64_t ret;
    for (uint64_t el = 0; el <= 3; el++) {
        if (el == 2) continue;
        script_default();
        sc.el = el;
        EXPECT("el");
        CHECK(ret == 0 && W.nsmc == 0 && W.ncache == 0 && W.reads == 0 && W.nlines == 1 && W.nsys == 1);
        CHECK(has("PAYLOAD CPUON SKIPPED_NOT_AT_EL2") && !strcmp(W.sysregs[0], "CurrentEL"));
    }
    return 0;
}

/* ---- the normal run, pinned by literal lines ------------------------------------------------------------------------- */

static int suite_normal(void)
{
    struct q1n1_payload_args a;
    uint64_t ret;
    script_default();
    EXPECT("normal");
    CHECK(ret == 0 && W.nlines == 38);
    CHECK(!strcmp(W.line[0].text, "PAYLOAD CPUON BOOT_CPU MPIDR_EL1=0X80000000 CNTFRQ_EL0=0X124F800"));
    CHECK(!strcmp(W.line[1].text, "PAYLOAD CPUON NEXT AFFINITY"));
    CHECK(!strcmp(W.line[2].text, "PAYLOAD CPUON AFFINITY 0X100=OFF 0X200=OFF 0X300=OFF 0X10000=OFF 0X10100=OFF 0X10200=OFF 0X10300=OFF"));
    CHECK(!strcmp(W.line[3].text, "PAYLOAD CPUON AFFINITY 0X20000=OFF 0X20100=OFF 0X20200=OFF 0X20300=OFF"));
    CHECK(!strcmp(W.line[4].text, "PAYLOAD CPUON NEXT PREPARE"));
    CHECK(!strcmp(W.line[5].text, "PAYLOAD CPUON NEXT CPU_ON 0X100 AFTER 8 S"));
    CHECK(!strcmp(W.line[6].text, "PAYLOAD CPUON P1 CPU_ON 0X100 RET=0X0:SUCCESS"));
    CHECK(!strcmp(W.line[7].text, "PAYLOAD CPUON P1 0X100 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500"));
    CHECK(!strcmp(W.line[8].text, "PAYLOAD CPUON P1 0X100 SCTLR_EL2=0X30C50830 HCR_EL2=0X80000000 VBAR_EL2=0X0"));
    CHECK(!strcmp(W.line[9].text, "PAYLOAD CPUON P1 POWER_OFF OFF=1 NOT_OFF=0"));
    CHECK(!strcmp(W.line[10].text, "PAYLOAD CPUON P1 NORMAL"));
    CHECK(!strcmp(W.line[11].text, "PAYLOAD CPUON NEXT CPU_ON ALL AFTER 8 S"));
    CHECK(!strcmp(W.line[12].text, "PAYLOAD CPUON P2 CPU_ON ISSUED=11 SUCCESS=11"));
    CHECK(!strcmp(W.line[35].text, "PAYLOAD CPUON P2 POWER_OFF OFF=11 NOT_OFF=0"));
    CHECK(!strcmp(W.line[36].text, "PAYLOAD CPUON CORES STARTED=11 REPORTED=11 OFF=11"));
    CHECK(!strcmp(W.line[37].text, "PAYLOAD CPUON NOT_DONE NO_SYSTEM_OFF_RESET_SUSPEND NO_CPU_SUSPEND BOOT_CPU_NO_MSR LEFT_RUNNING=0"));
    /* Order and time: eleven AFFINITY_INFO calls after their NEXT line; the maintenance after NEXT PREPARE and before the first
     * CPU_ON; each CPU_ON eight seconds (and no more than a few reads) after its NEXT line. */
    CHECK(W.line[1].smc == 0 && W.line[2].smc == 11 && W.line[4].cache == 0 && W.line[5].cache > 0 && W.line[5].smc == 11);
    CHECK(W.smc[11].at - W.line[5].at >= 8 * 19200000ull && W.smc[11].at - W.line[5].at < 8 * 19200000ull + 20 * 1920);
    for (unsigned i = 12, batch = 0; i < W.nsmc; i++) {
        if (W.smc[i].id != ID_CPU_ON || batch++) continue;
        CHECK(W.smc[i].at - W.line[11].at >= 8 * 19200000ull && W.smc[i].at - W.line[11].at < 8 * 19200000ull + 20 * 1920);
    }
    for (unsigned at = 0; at < image_bytes; at += LINE) CHECK(image_clean[at / LINE]);
    return 0;
}

/* ---- AFFINITY_INFO answers ---------------------------------------------------------------------------------------------- */

static int suite_affinity(void)
{
    struct q1n1_payload_args a;
    uint64_t ret;
    script_default();
    sc.core[3].probe = 0; sc.core[5].probe = 2; sc.core[7].probe = ~UINT64_C(1); sc.core[9].probe = 0xfffffffe; sc.core[10].probe = 7;
    EXPECT("affinity");
    CHECK(contains("0X300=ON ") && contains("0X10100=ON_PENDING") && contains("0X10300=INVALID_PARAMETERS(-2)") && contains("0X20200=0X7"));
    CHECK(has("PAYLOAD CPUON SKIP_NOT_OFF 0X300 0X10100 0X10300 0X20100 0X20200"));
    CHECK(has("PAYLOAD CPUON CORES STARTED=6 REPORTED=6 OFF=6"));
    for (unsigned i = 1; i < CPUS; i++) CHECK(W.on_ok[i] == (i != 3 && i != 5 && i != 7 && i != 9 && i != 10));
    /* Only exactly 1 is OFF: the upper half of the answer is not ignored for the gate. */
    script_default();
    sc.core[2].probe = 0x100000001ull;
    EXPECT("affinity-upper");
    CHECK(W.on_ok[2] == 0 && contains("0X200=0X100000001"));
    /* Core 0X100 not OFF, whatever it says: no phase 1, no phase 2, no CPU_ON, and none of the preparation either. */
    for (uint64_t answer = 0; answer <= 9; answer++) {
        script_default();
        sc.core[1].probe = answer == 1 ? ~UINT64_C(0) : answer == 9 ? 0xdead00000001ull : answer;
        EXPECT("affinity-first");
        for (unsigned i = 1; i < CPUS; i++) CHECK(W.on_count[i] == 0);
        CHECK(has("PAYLOAD CPUON P1 SKIPPED=NOT_OFF") && has("PAYLOAD CPUON P2 SKIPPED=P1_NOT_NORMAL") && W.ncache == 0);
        CHECK(has("PAYLOAD CPUON CORES STARTED=0 REPORTED=0 OFF=0") && count_with("PAYLOAD CPUON NEXT CPU_ON") == 0 && ret == 0);
    }
    /* The boot CPU is never started and never asked about: its MPIDR is that of a target, with other bits set as well. */
    for (unsigned i = 1; i < CPUS; i++) {
        script_default();
        sc.boot_mpidr = (i % 2 ? 0xC0000000 : 0x80000000) | table[i];
        EXPECT("boot");
        CHECK(W.on_count[i] == 0 && contains("=BOOT_CPU"));
        for (unsigned k = 0; k < W.nsmc; k++) CHECK(W.smc[k].x1 != table[i]);
        CHECK(has(i == 1 ? "PAYLOAD CPUON P1 SKIPPED=NOT_OFF" : "PAYLOAD CPUON P2 CPU_ON ISSUED=10 SUCCESS=10"));
    }
    return 0;
}

/* ---- CPU_ON answers ------------------------------------------------------------------------------------------------------ */

static int suite_cpu_on(void)
{
    struct q1n1_payload_args a;
    uint64_t ret;
    static const uint64_t raw[] = {~UINT64_C(0), ~UINT64_C(1), ~UINT64_C(2), ~UINT64_C(3), ~UINT64_C(4), ~UINT64_C(5), ~UINT64_C(6),
                                   ~UINT64_C(7), ~UINT64_C(8), 0xfffffffe, 0xfffffffd, 0x12345, 0xfffffff6, 1, 0x100000001ull};
    for (unsigned k = 0; k < sizeof raw / sizeof raw[0]; k++) {
        script_default();                       /* phase 1: the answer by name, not started, phase 2 never begins */
        sc.core[1].on_ret = raw[k];
        EXPECT("cpu_on-p1");
        CHECK(W.on_count[1] == 1 && W.on_ok[1] == 0 && has("PAYLOAD CPUON P1 ABNORMAL=NOT_STARTED") && ret == 0);
        for (unsigned i = 2; i < CPUS; i++) CHECK(W.on_count[i] == 0);       /* never retried, no other core started */
        script_default();                       /* phase 2: two cores answer it, the other nine start */
        sc.core[3].on_ret = sc.core[9].on_ret = raw[k];
        EXPECT("cpu_on-p2");
        CHECK(W.on_ok[3] == 0 && W.on_ok[9] == 0 && W.on_ok[2] == 1 && has("PAYLOAD CPUON P2 CPU_ON ISSUED=11 SUCCESS=9"));
        CHECK(has("PAYLOAD CPUON CORES STARTED=9 REPORTED=9 OFF=9"));
    }
    script_default();                           /* the named ones, literally */
    sc.core[1].on_ret = ~UINT64_C(1);
    EXPECT("cpu_on-named");
    CHECK(has("PAYLOAD CPUON P1 CPU_ON 0X100 RET=0XFFFFFFFFFFFFFFFE:INVALID_PARAMETERS(-2)"));
    for (unsigned k = 2; k <= 5; k++) {
        static const char *const names[] = {"", "", "INVALID_PARAMETERS(-2)", "DENIED(-3)", "ALREADY_ON(-4)", "ON_PENDING(-5)"};
        char line[160];
        script_default();
        sc.core[4].on_ret = ~UINT64_C(0) - (k - 1);
        EXPECT("cpu_on-listed");
        snprintf(line, sizeof line, "PAYLOAD CPUON P2 CPU_ON_FAILED 0X10000=%s", names[k]);
        CHECK(has(line));
    }
    script_default();                           /* the upper half of a success is not looked at */
    sc.core[1].on_ret = 0xdead00000000ull;
    EXPECT("cpu_on-upper");
    CHECK(has("PAYLOAD CPUON P1 CPU_ON 0X100 RET=0XDEAD00000000:SUCCESS") && has("PAYLOAD CPUON P1 NORMAL"));
    script_default();                           /* all eleven refusing but the first */
    for (unsigned i = 2; i < CPUS; i++) sc.core[i].on_ret = ~UINT64_C(2);
    EXPECT("cpu_on-all");
    CHECK(has("PAYLOAD CPUON P2 CPU_ON ISSUED=11 SUCCESS=1") && has("PAYLOAD CPUON CORES STARTED=1 REPORTED=1 OFF=1"));
    return 0;
}

/* ---- what a started core can do wrong -------------------------------------------------------------------------------- */

static int suite_cores(void)
{
    struct q1n1_payload_args a;
    uint64_t ret;
    script_default();                           /* phase 1 never reports: how far the stub got, and the core goes OFF on its own */
    sc.core[1].report_ms = NEVER; sc.core[1].stage = 2;
    EXPECT("p1-no-report");
    CHECK(has("PAYLOAD CPUON P1 0X100 NO_REPORT STAGE=2 CURRENTEL=0X8") && has("PAYLOAD CPUON CORES STARTED=1 REPORTED=0 OFF=1") && ret == 0);
    script_default();
    sc.core[1].report_ms = NEVER;
    EXPECT("p1-no-stage");
    CHECK(has("PAYLOAD CPUON P1 0X100 NO_REPORT STAGE=0 CURRENTEL=0X0"));
    /* The deadlines, exactly: a report at 900 ms is seen, one at 1100 ms is not; OFF at 2900 ms after the report is seen, at 3100 not. */
    script_default(); sc.core[1].report_ms = 900; sc.core[1].off_ms = 950;
    RUN("p1-900"); CHECK(has("PAYLOAD CPUON P1 NORMAL"));
    script_default(); sc.core[1].report_ms = 1100; sc.core[1].off_ms = 1150;
    RUN("p1-1100"); CHECK(has("PAYLOAD CPUON P1 ABNORMAL=NO_REPORT"));
    script_default(); sc.core[1].report_ms = 800; sc.core[1].off_ms = 2700;
    RUN("p1-off-in-time"); CHECK(has("PAYLOAD CPUON P1 NORMAL"));
    script_default(); sc.core[1].report_ms = 800; sc.core[1].off_ms = 2950;
    RUN("p1-off-late"); CHECK(has("PAYLOAD CPUON P1 ABNORMAL=NOT_OFF") && ret == 2);
    script_default();                           /* reports, never reaches OFF: left running, and said so */
    sc.core[1].off_ms = NEVER;
    EXPECT("p1-not-off");
    CHECK(has("PAYLOAD CPUON P1 NOT_OFF 0X100=ON") && has("PAYLOAD CPUON P1 0X100 STILL_ON LAST=ON KIND=1") && ret == 2);
    CHECK(has("PAYLOAD CPUON NOT_DONE NO_SYSTEM_OFF_RESET_SUSPEND NO_CPU_SUSPEND BOOT_CPU_NO_MSR LEFT_RUNNING=1") && count_with("PAYLOAD CPUON NEXT CPU_ON") == 1);
    script_default();                           /* CPU_OFF came back: its answer is read from the slot afterwards */
    sc.core[1].kind = K_OFF_RETURNED; sc.core[1].off_ms = NEVER; sc.core[1].off_ret = ~UINT64_C(2);
    EXPECT("p1-off-returned");
    CHECK(has("PAYLOAD CPUON P1 0X100 STILL_ON LAST=ON KIND=4 CPU_OFF_RET=0XFFFFFFFFFFFFFFFD:DENIED(-3)"));
    script_default();                           /* another EL, a fault early and late, a different MPIDR, IDs, counter frequency */
    sc.core[1].kind = K_OTHER_EL; sc.core[1].el = 4;
    EXPECT("p1-el1");
    CHECK(has("PAYLOAD CPUON P1 0X100 ENTERED_AT_EL1 NOT_EL2 CURRENTEL=0X4") && has("PAYLOAD CPUON P1 ABNORMAL=NOT_EL2"));
    script_default();
    sc.core[1].kind = K_FAULT; sc.core[1].esr = 0x96000045; sc.core[1].elr = 0x1234; sc.core[1].far = 0xDEAD0000; sc.core[1].vector = 4; sc.core[1].stage = 3;
    EXPECT("p1-fault");
    CHECK(has("PAYLOAD CPUON P1 0X100 FAULT STAGE=3 VECTOR=4 ESR_EL2=0X96000045 ELR_EL2=0X1234 FAR_EL2=0XDEAD0000"));
    CHECK(has("PAYLOAD CPUON P1 ABNORMAL=FAULT") && has("PAYLOAD CPUON P2 SKIPPED=P1_NOT_NORMAL"));
    script_default();
    sc.core[1].kind = K_FAULT; sc.core[1].stage = 1; sc.core[1].vector = 5;
    EXPECT("p1-fault-early");
    CHECK(contains("P1 0X100 FAULT STAGE=1 VECTOR=5") && count_with("PAYLOAD CPUON P1 0X100 SCTLR_EL2=") == 0);
    script_default(); sc.core[1].mpidr_xor = 0x100;
    EXPECT("p1-mpidr"); CHECK(has("PAYLOAD CPUON P1 0X100 EL=2 MPIDR=0X80000000 IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500") && has("PAYLOAD CPUON P1 ABNORMAL=MPIDR"));
    script_default(); sc.core[1].mpidr_xor = 0x80000000;       /* bits outside the affinity are not the target's business */
    EXPECT("p1-mpidr-bits"); CHECK(has("PAYLOAD CPUON P1 NORMAL"));
    script_default(); sc.core[1].id_differ = 2 | 8;
    EXPECT("p1-ids");
    CHECK(has("PAYLOAD CPUON P1 0X100 EL=2 MPIDR=OK IDS=MMFR0/PFR0 FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500"));
    CHECK(has("PAYLOAD CPUON P1 0X100 MMFR0=0X1102/BOOT=0X1122 PFR0=0X55E6/BOOT=0X5566") && has("PAYLOAD CPUON P1 ABNORMAL=IDS"));
    script_default(); sc.core[1].frq = 24000000;
    EXPECT("p1-frq"); CHECK(has("PAYLOAD CPUON P1 0X100 EL=2 MPIDR=OK IDS=SAME FRQ=0X16E3600 CNTVOFF_EL2=0X0 DT_US=500") && has("PAYLOAD CPUON P1 ABNORMAL=FRQ"));
    script_default(); sc.core[1].mpidr_xor = 1; sc.core[1].id_differ = 5; sc.core[1].frq = 5; sc.core[1].off_ms = NEVER; sc.core[1].el = 4;
    EXPECT("p1-many"); CHECK(has("PAYLOAD CPUON P1 ABNORMAL=NOT_EL2/MPIDR/IDS/FRQ/NOT_OFF"));
    script_default(); sc.core[1].start_delay = -3840;           /* the counter distance has a sign and a size */
    EXPECT("p1-negative"); CHECK(contains("P1 0X100 EL=2 MPIDR=OK IDS=SAME FRQ=SAME CNTVOFF_EL2=0X0 DT_US=-200"));
    script_default(); sc.core[1].start_delay = (int64_t)19200 * 1234567;
    EXPECT("p1-far"); CHECK(contains("DT_US=1234567000"));
    script_default();                           /* phase 2: silent cores, a core that never goes OFF, another EL, another ID */
    sc.core[2].report_ms = NEVER; sc.core[4].off_ms = NEVER; sc.core[6].kind = K_OTHER_EL; sc.core[6].el = 4; sc.core[8].id_differ = 1;
    EXPECT("p2-mixed");
    CHECK(has("PAYLOAD CPUON P2 0X200 NO_REPORT STAGE=0 CURRENTEL=0X0") && has("PAYLOAD CPUON P2 0X10200 ENTERED_AT_EL1 NOT_EL2 CURRENTEL=0X4"));
    CHECK(has("PAYLOAD CPUON P2 0X20000 EL=2 MPIDR=OK IDS=MIDR FRQ=SAME CNTVOFF_EL2=0X0 DT_US=500") && has("PAYLOAD CPUON P2 NOT_OFF 0X10000=ON"));
    CHECK(has("PAYLOAD CPUON CORES STARTED=11 REPORTED=10 OFF=10") && ret == 2);
    script_default();
    for (unsigned i = 2; i < CPUS; i++) { sc.core[i].report_ms = NEVER; sc.core[i].off_ms = NEVER; }
    EXPECT("p2-silent");
    CHECK(has("PAYLOAD CPUON CORES STARTED=11 REPORTED=1 OFF=1") && contains("LEFT_RUNNING=10") && ret == 2);
    return 0;
}

/* ---- the counter ---------------------------------------------------------------------------------------------------------- */

static int suite_counter(void)
{
    struct q1n1_payload_args a;
    uint64_t ret;
    script_default();                           /* no counter op: refused before anything */
    sc.no_counter = 1;
    RUN("no-counter");
    CHECK(W.nlines == 1 && has("PAYLOAD CPUON REFUSED=NO_COUNTER") && W.nsmc == 0 && W.ncache == 0);
    script_default();                           /* a counter that stops before the first wait: the NEXT line, never the CPU_ON */
    sc.stuck_from = 5;
    RUN("stuck");
    CHECK(has("PAYLOAD CPUON NEXT CPU_ON 0X100 AFTER 8 S") && has("PAYLOAD CPUON P1 SKIPPED=COUNTER_STUCK") && has("PAYLOAD CPUON P2 SKIPPED=P1_NOT_NORMAL"));
    for (unsigned i = 1; i < CPUS; i++) CHECK(W.on_count[i] == 0);
    CHECK(has("PAYLOAD CPUON CORES STARTED=0 REPORTED=0 OFF=0") && ret == 0);
    script_default();                           /* one that stops during phase 2's wait: phase 1 stands, no phase 2 CPU_ON */
    sc.stuck_from = 120000;
    RUN("stuck-p2");
    CHECK(has("PAYLOAD CPUON P1 NORMAL") && has("PAYLOAD CPUON P2 SKIPPED=COUNTER_STUCK") && W.on_count[2] == 0 && W.on_count[1] == 1);
    static const uint64_t bad[] = {0, 1, 999999, 1000000001, ~UINT64_C(0)};
    for (unsigned k = 0; k < sizeof bad / sizeof bad[0]; k++) {
        char line[160];
        script_default();
        sc.cntfrq = bad[k];
        EXPECT("freq-bad");
        snprintf(line, sizeof line, "PAYLOAD CPUON BOOT_CPU MPIDR_EL1=0X80000000 CNTFRQ_EL0=0X%" PRIX64 " FREQ=DEFAULT", bad[k]);
        CHECK(has(line));
    }
    script_default();                           /* a 24 MHz counter: eight seconds is 192 million ticks, not 153.6 million */
    sc.cntfrq = 24000000; sc.step = 2400;
    EXPECT("freq-24");
    CHECK(W.smc[11].at - W.line[5].at >= 8 * 24000000ull && W.smc[11].at - W.line[5].at < 8 * 24000000ull + 20 * 2400);
    CHECK(has("PAYLOAD CPUON BOOT_CPU MPIDR_EL1=0X80000000 CNTFRQ_EL0=0X16E3600"));
    return 0;
}

/* ---- where it runs ------------------------------------------------------------------------------------------------------- */

static int suite_refuse(void)
{
    struct q1n1_payload_args a;
    uint64_t ret, stub = (uint64_t)(uintptr_t)cpuon_entry, table = (uint64_t)(uintptr_t)cpuon_vectors;
    uint64_t low = stub < table ? stub : table, high = stub < table ? table : stub;
    for (unsigned k = 0; k < 11; k++) {
        const char *reason = k < 5 ? "STACK" : "ENTRY";
        char line[64];
        script_default();
        world_reset();
        a = args();
        switch (k) {
        case 0: a.stack_base += 64; break;                          /* not 128-byte aligned */
        case 1: a.stack_size = 24000; break;                        /* too small for the slots and the kept stack */
        case 2: W.sp = a.stack_base + 8192; break;                  /* running so low that the slots would be on the live stack */
        case 3: W.sp = a.stack_base + a.stack_size + 16; break;     /* not on this stack at all */
        case 4: W.sp = a.stack_base - 16; break;
        case 5: a.payload_base = table; a.payload_size = 2048; break;                               /* only the vectors are in the image */
        case 6: a.payload_base = stub; a.payload_size = 64; break;                                  /* only the stub is */
        case 7: a.payload_size = UINT64_C(1) << 32; break;
        case 8: a.payload_base = ~UINT64_C(0) - 4095; a.payload_size = 8192; break;                 /* wraps */
        case 9: a.payload_base = low + 1; a.payload_size = high + 2048 - a.payload_base; break;     /* the lower of the two is below it */
        case 10: a.payload_base = low - 4096; a.payload_size = high - a.payload_base; break;        /* the higher is at its end */
        }
        snprintf(line, sizeof line, "PAYLOAD CPUON REFUSED=%s", reason);
        ret = payload_entry(&a);
        CHECK(ret == 0 && W.nlines == 1 && has(line) && W.nsmc == 0 && W.ncache == 0 && W.reads == 0 && common("refuse"));
        CHECK(!memcmp(arena, memory, ARENA));
    }
    script_default();                           /* a larger stack than the arena the test has: only the low part is ever touched */
    world_reset();
    a = args();
    a.stack_size = 2 * ARENA;
    W.sp = a.stack_base + ARENA - 256;
    CHECK(payload_entry(&a) == 0 && has("PAYLOAD CPUON P1 NORMAL"));
    return 0;
}

static int suite_args(void)
{
    struct q1n1_payload_args a;
    script_default();
    world_reset();
    CHECK(payload_entry(NULL) == Q1N1_PAYLOAD_RET_BAD_ARGS && W.nsys == 0 && W.nlines == 0 && W.nsmc == 0);
    a = args(); a.magic ^= 1;
    CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && W.nsys == 0 && W.nsmc == 0);
    a = args(); a.version = 2;
    CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && W.nsmc == 0);
    a = args(); a.size = sizeof a - 1;
    CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && W.nsmc == 0);
    a = args(); a.ops.puts = NULL;
    CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && W.nsmc == 0);
    a = args(); a.ops.hex = NULL;
    CHECK(payload_entry(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && W.nsmc == 0);
    world_reset();                              /* a newer runner hands a bigger block: accepted */
    a = args(); a.size = sizeof a + 64;
    CHECK(payload_entry(&a) == 0 && W.nlines == 38);
    return 0;
}

/* ---- random worlds ---------------------------------------------------------------------------------------------------- */

/* Delays are drawn from the sets that cannot be misread at the deadlines: a report well under 1 s, between 1.3 and 1.7 s (seen
 * by phase 2 only), or later than 2.3 s; OFF well under 1.4 s or later than 5.2 s. */
static uint64_t pick_report(void)
{
    uint64_t r = next_random() % 10;
    return r < 6 ? next_random() % 700 : r < 8 ? 1300 + next_random() % 400 : r < 9 ? 2300 + next_random() % 500 : NEVER;
}
static uint64_t pick_garbage(void)
{
    static const uint64_t garbage[] = {0, 2, 3, 7, ~UINT64_C(0), ~UINT64_C(1), 0xfffffffe, 0x100000001ull, 0x8000000000000000ull, ~UINT64_C(4)};
    return garbage[next_random() % (sizeof garbage / sizeof garbage[0])];
}
static void random_world(unsigned round)
{
    script_default();
    sc.step = 96000;                            /* 5 ms per read: the worlds are cheap */
    sc.cntfrq = round % 17 == 0 ? next_random() : (round % 7 == 0 ? 24000000 : 19200000);
    for (unsigned i = 1; i < CPUS; i++) {
        struct core_script *c = &sc.core[i];
        if (next_random() % 9 == 0) c->probe = pick_garbage();
        if (next_random() % 11 == 0) c->on_ret = pick_garbage();
        c->report_ms = pick_report();
        c->off_ms = next_random() % 5 == 0 ? NEVER : next_random() % 4 == 0 ? 5200 + next_random() % 800 : next_random() % 1400;
        c->kind = (unsigned)(1 + next_random() % 4);
        c->stage = (unsigned)(next_random() % 4);
        if (c->kind == K_FAULT && !c->stage) c->stage = 1;
        if (c->kind == K_OTHER_EL) c->el = 4;
        c->off_ret = next_random(); c->esr = next_random(); c->elr = next_random(); c->far = next_random(); c->vector = next_random() % 16;
        c->start_delay = next_random() % 7 == 0 ? (int64_t)(next_random() >> (next_random() % 64)) : (int64_t)(next_random() % 200000) - 100000;
        c->mpidr_xor = next_random() % 17 == 0 ? next_random() : 0;
        c->id_differ = next_random() % 6 == 0 ? (unsigned)(next_random() & 15) : 0;
        c->frq = next_random() % 19 == 0 ? next_random() : 0;
        c->sctlr = next_random() >> (next_random() % 64); c->hcr = next_random() >> (next_random() % 64);
        c->vbar = next_random() >> (next_random() % 64); c->vo = next_random() >> (next_random() % 64);
        c->after_off = next_random() % 23 == 0 ? next_random() : 1;
    }
    if (round % 3 == 0) {                       /* most worlds get a normal phase 1, so that phase 2 is exercised */
        struct core_script *c = &sc.core[1];
        c->probe = 1; c->on_ret = 0; c->report_ms = 3; c->off_ms = 7; c->kind = K_REPORT; c->mpidr_xor = 0; c->id_differ = 0;
        c->frq = 0; c->el = 8; c->after_off = 1;
    }
    if (round % 29 == 0) sc.boot_mpidr = 0x80000000 | table[1 + next_random() % 11];
}

static unsigned most_lines;
static int run_fuzz(unsigned rounds, int compare)
{
    struct q1n1_payload_args a;
    uint64_t ret;
    for (unsigned round = 0; round < rounds; round++) {
        random_world(round);
        RUN("fuzz");
        if (compare) CHECK(page_is_oracle("fuzz"));
        if (W.nlines > most_lines) most_lines = W.nlines;
        /* Whatever the world did: the last two lines are the summary and what was not done, every NEXT line is there, a
         * core was started only after its NEXT line (common), and the return value says whether a core was left running. */
        CHECK(W.nlines >= 3 && W.nlines <= Q1N1_PAYLOAD_LINES_MAX);
        CHECK(!strncmp(W.line[W.nlines - 2].text, "PAYLOAD CPUON CORES STARTED=", 28));
        CHECK(!strncmp(W.line[W.nlines - 1].text, "PAYLOAD CPUON NOT_DONE NO_SYSTEM_OFF_RESET_SUSPEND", 50));
        CHECK(has("PAYLOAD CPUON NEXT AFFINITY"));
        CHECK(ret == (strstr(W.line[W.nlines - 1].text, "LEFT_RUNNING=0") ? 0u : 2u));
        if (W.on_count[1]) CHECK(has("PAYLOAD CPUON NEXT PREPARE") && count_with("PAYLOAD CPUON NEXT CPU_ON") >= 1);
        if (W.on_count[2]) CHECK(has("PAYLOAD CPUON NEXT CPU_ON ALL AFTER 8 S"));
    }
    return 0;
}
static int suite_fuzz(void) { return run_fuzz(2500, 1); }

/* The number docs/SP11-PAYLOAD-CPUON.md plans a chain's page with, measured: the most lines over the worlds above and the widest
 * one (every register of every core different and long). Run as `lines-report`. */
static int report_lines(void)
{
    struct q1n1_payload_args a;
    most_lines = 0;
    script_default();
    for (unsigned i = 2; i < CPUS; i++) {
        struct core_script *c = &sc.core[i];
        c->id_differ = 15; c->mpidr_xor = 0x1234; c->frq = 0x7fffffffffff; c->sctlr = c->hcr = c->vbar = c->vo = ~UINT64_C(0);
        c->start_delay = -(int64_t)(UINT64_C(1) << 50);
    }
    world_reset(); a = args(); payload_entry(&a);
    if (W.nlines > most_lines) most_lines = W.nlines;
    run_fuzz(2500, 0);
    printf("LINES_MAX=%u\n", most_lines);
    return 0;
}

/* The page of the default script, one line each as the runner would print it: the block docs/SP11-PAYLOAD-CPUON.md shows. Run as
 * `page`. The numbers are the model's, not a unit's. */
static int print_page(void)
{
    struct q1n1_payload_args a;
    uint64_t ret;
    script_default();
    RUN("page");
    (void)ret;
    for (unsigned i = 0; i < W.nlines; i++) puts(W.line[i].text);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"ids", suite_ids}, {"el", suite_el}, {"normal", suite_normal}, {"affinity", suite_affinity}, {"cpu_on", suite_cpu_on},
        {"cores", suite_cores}, {"counter", suite_counter}, {"refuse", suite_refuse}, {"args", suite_args}, {"fuzz", suite_fuzz},
    };
    unsigned ran = 0;
    if (argc > 1 && !strcmp(argv[1], "lines-report")) return report_lines();
    if (argc > 1 && !strcmp(argv[1], "page")) return print_page();
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) { fprintf(stderr, "FAIL: suite %s\n", suites[i].name); return 1; }
        ran++;
    }
    printf("PASS: %u payload cpuon suites, %u checks\n", ran, checks);
    return 0;
}
