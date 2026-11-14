/* SPDX-License-Identifier: MIT */
/* Payload "timer": a read-only probe of the generic timer and counter at EL2, built to isolate the accesses that
 * stalled this board five times in the X2 test image's timer test (T03: the footer showed "RUNNING T03 TIMER" for
 * about 12 s, no exception page, then the board reset). T03 read CNTFRQ_EL0, CNTHCTL_EL2, CNTVOFF_EL2, CNTPCT_EL0 and
 * CNTVCT_EL0, polled CNTPCT_EL0, and then, because ID_AA64MMFR0_EL1.ECV is 2 on this core (OBSERVED), read
 * CNTPOFF_EL2. Here every hazardous read is announced by a line printed BEFORE it, so the last line on the panel
 * names the access that hung; a fault page whose ELR lies inside timer.bin names an instruction that faulted.
 *
 * It goes LAST in a manifest chain (docs/SP11-PAYLOAD-TIMER.md): it may stall the whole board, and a stall costs only the
 * lines after it. READ ONLY: MRS and nothing that writes a system register, a cache, a TLB or a device, no HVC,
 * SMC or SVC, no ERET, WFI or WFE, no exclusive. The tests disassemble the binary against an allow-list that lets
 * this payload, and no other, name CNTVOFF_EL2 and CNTPOFF_EL2. Nothing is enabled, masked or programmed: the timer
 * control registers are only read. It touches no memory but its own stack and uses neither load32 nor counter.
 *
 * Order. CurrentEL first: at any other EL it prints one line and does nothing else. Then the context (the ECV field
 * of ID_AA64MMFR0_EL1; E2H and TGE of HCR_EL2, printed and never depended on), then the SAFE group, each line
 * printed as soon as its register is read, then HAZARD 1 (CNTVOFF_EL2), then HAZARD 2 (CNTPOFF_EL2), the very last
 * access, read only when ECV >= 2. At most 16 lines (the ABI allows 40), KEY=VALUE with 0X hex, in the page font.
 *
 * The registers and the evidence for each (docs/SP11-PAYLOAD-TIMER.md has the same table):
 *
 *   CurrentEL                 VERIFIED (architecture). Read first.
 *   ID_AA64MMFR0_EL1          VERIFIED. ECV is bits 63:60: 0 none, 1 FEAT_ECV, 2 FEAT_ECV and CNTPOFF_EL2. The unit
 *                             reads 2 (OBSERVED, per the Snapintosh docs/SURFACE-PRO-11.md).
 *   HCR_EL2                   VERIFIED. Unit 0x88000010, E2H clear (OBSERVED on q1n1's own page).
 *   CNTFRQ_EL0, CNTHCTL_EL2   VERIFIED; q1n1's own EL2 page reads both. CNTHCTL_EL2.ECV is bit 12. The unit's
 *                             CNTFRQ_EL0 is UNKNOWN until read (19.2 MHz is the monitor's INFERRED expectation).
 *   CNTP_CTL_EL0, CNTV_CTL_EL0, CNTHP_CTL_EL2
 *                             VERIFIED registers, read only. INFERRED safe (no EL3 trap control is known for a read
 *                             at EL2); none was read on the unit before.
 *   CNTPCT_EL0, CNTVCT_EL0    VERIFIED. Read in a bounded poll and never used as a clock.
 *   CNTVOFF_EL2 (S3_4_C14_C0_3)
 *                             VERIFIED register; HAZARD 1, a weak suspect: INFERRED, because it has no EL3 trap
 *                             control. Linux treats it as broken on Oryon X1 (docs/SURFACE-PRO-11.md E17, VERIFIED
 *                             there from Linux's source), and the unit's MIDR is that part (OBSERVED).
 *   CNTPOFF_EL2 (S3_4_C14_C0_6)
 *                             VERIFIED register, present when ECV >= 2; HAZARD 2, the leading suspect: INFERRED and
 *                             untested, that with SCR_EL3.ECVEn = 0 the access traps to EL3 and the firmware's monitor
 *                             hangs or crashes, so the board resets after a watchdog interval.
 *
 * What each outcome would mean for the monitor design (INFERRED; nothing is measured, hardware NOT RUN):
 *
 *   CNTVOFF_EL2: usable at EL2, or not
 *     value, WITHIN=1         readable, and CNTVCT = CNTPCT - CNTVOFF_EL2 holds. With a value of 0 that shows only that
 *                             no offset is in effect: nothing here writes, so it cannot show that a write would work.
 *     value, WITHIN=0         readable, but CNTVCT does not follow it. HELD of OF tells noise (the three reads of a
 *                             round may execute out of order: no ISB) from a real difference, and OFFSET, the first
 *                             round's CNTVCT + CNTVOFF - CNTPCT, how far off: OFFSET equal to CNTVOFF_EL2 means the
 *                             offset is not applied at all, which is what Linux's Oryon X1 workaround assumes.
 *     last line NEXT CNTVOFF_EL2
 *                             even a read stalls: the monitor must not touch CNTVOFF_EL2 at all.
 *     fault page, ELR in timer.bin
 *                             the access raised an exception at EL2: UNDEFINED, or trapped to EL2, in this state.
 *   CNTPOFF_EL2: readable, or an EL3 stall
 *     value                   readable: SCR_EL3.ECVEn is 1 or the firmware does not gate it, so the EL3-trap
 *                             explanation of T03 is wrong for a read; a write is still untested.
 *     last line NEXT CNTPOFF_EL2
 *                             the access stalls, as the EL3-trap explanation predicts: the monitor must never access
 *                             CNTPOFF_EL2 nor set CNTHCTL_EL2.ECV.
 *     CNTPOFF_EL2 N/A         ECV is below 2, the register does not exist, nothing was read.
 *   CNTFRQ_EL0              the counter frequency in Hz as the firmware programmed it: 0X124F800 is 19.2 MHz,
 *                           0X16E3600 24 MHz, 0X3B9ACA00 1 GHz; 0 means nothing programmed it.
 *   POLL_ADVANCED=0         the physical counter did not change in 200000 reads: it is not running, or not readable.
 *
 * CNTPOFF_EL2 is spelled by encoding because an assembler accepts its name only with FEAT_ECV in the target;
 * CNTVOFF_EL2 is spelled the same way, so that a grep for the two encodings finds exactly the two hazardous reads.
 * The page font has no "<", so the ECV < 2 line says BELOW. */
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* The host test replaces the register file: no MRS can run at EL0 on a build machine. */
uint64_t pl_host_sysreg(const char *name);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#define PREFIX "PAYLOAD TIMER "
/* The hard bound of the poll, in reads of CNTPCT_EL0: the counter's frequency is what is being measured, so no
 * delay may be derived from it, and a counter that never changes must not hang the payload. */
#define POLL_READS_MAX 200000u
/* Rounds of (CNTPCT, CNTVCT, CNTPCT) behind the one verdict on CNTVCT + CNTVOFF_EL2. */
#define ROUNDS 8u
#define ECV_HAS_CNTPOFF 2u

static __attribute__((noinline)) void row(struct pl_line *line)
{
    pl_begin(line);
    pl_text(line, PREFIX);
}

static __attribute__((noinline)) void field(const struct q1n1_payload_args *a, struct pl_line *line, const char *key, uint64_t value)
{
    if (line->len > sizeof PREFIX - 1) pl_text(line, " ");
    pl_text(line, key);
    pl_text(line, "=");
    pl_hex(a, line, value);
}

/* PAYLOAD TIMER <text> */
static __attribute__((noinline)) void say(const struct q1n1_payload_args *a, const char *text)
{
    struct pl_line line;
    row(&line);
    pl_text(&line, text);
    pl_emit(a, &line);
}

/* PAYLOAD TIMER KEY=0XVALUE, and the same with two, three or four fields on one line. */
static __attribute__((noinline)) void show(const struct q1n1_payload_args *a, const char *key, uint64_t value)
{
    struct pl_line line;
    row(&line);
    field(a, &line, key, value);
    pl_emit(a, &line);
}

static __attribute__((noinline)) void show2(const struct q1n1_payload_args *a, const char *k1, uint64_t v1, const char *k2, uint64_t v2)
{
    struct pl_line line;
    row(&line);
    field(a, &line, k1, v1);
    field(a, &line, k2, v2);
    pl_emit(a, &line);
}

static __attribute__((noinline)) void show3(const struct q1n1_payload_args *a, const char *k1, uint64_t v1, const char *k2,
                                            uint64_t v2, const char *k3, uint64_t v3)
{
    struct pl_line line;
    row(&line);
    field(a, &line, k1, v1);
    field(a, &line, k2, v2);
    field(a, &line, k3, v3);
    pl_emit(a, &line);
}

static __attribute__((noinline)) void show4(const struct q1n1_payload_args *a, const char *k1, uint64_t v1, const char *k2,
                                            uint64_t v2, const char *k3, uint64_t v3, const char *k4, uint64_t v4)
{
    struct pl_line line;
    row(&line);
    field(a, &line, k1, v1);
    field(a, &line, k2, v2);
    field(a, &line, k3, v3);
    field(a, &line, k4, v4);
    pl_emit(a, &line);
}

#define SHOW(key, reg) show(a, key, SYSREG(reg))

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {
        say(a, "SKIPPED_NOT_AT_EL2");
        return 0;
    }

    /* Context. */
    uint64_t mmfr0 = SYSREG(ID_AA64MMFR0_EL1);
    uint64_t ecv = mmfr0 >> 60 & 15;
    show2(a, "ID_AA64MMFR0_EL1", mmfr0, "ECV", ecv);
    uint64_t hcr = SYSREG(HCR_EL2);
    show3(a, "HCR_EL2", hcr, "E2H", hcr >> 34 & 1, "TGE", hcr >> 27 & 1);

    /* The SAFE group: each line as soon as its register is read. */
    SHOW("CNTFRQ_EL0", CNTFRQ_EL0);
    uint64_t hctl = SYSREG(CNTHCTL_EL2);
    show2(a, "CNTHCTL_EL2", hctl, "ECV", hctl >> 12 & 1);
    SHOW("CNTP_CTL_EL0", CNTP_CTL_EL0);
    SHOW("CNTV_CTL_EL0", CNTV_CTL_EL0);
    SHOW("CNTHP_CTL_EL2", CNTHP_CTL_EL2);
    uint64_t first = SYSREG(CNTPCT_EL0);
    show(a, "CNTPCT_EL0", first);
    uint64_t latest = first;
    uint32_t reads = 0;
    while (reads < POLL_READS_MAX && latest == first) {
        latest = SYSREG(CNTPCT_EL0);
        reads++;
    }
    show3(a, "POLL_ADVANCED", latest != first, "POLL_READS", reads, "POLL_DELTA", latest - first);
    /* The reads CNTVCT_EL0 is checked against once CNTVOFF_EL2 is known. The first round is printed as soon as its
     * three reads are done, so that the SAFE group is complete before the first hazard. */
    uint64_t before[ROUNDS], virtual_count[ROUNDS], after[ROUNDS];
    for (unsigned i = 0; i < ROUNDS; i++) {
        before[i] = SYSREG(CNTPCT_EL0);
        virtual_count[i] = SYSREG(CNTVCT_EL0);
        after[i] = SYSREG(CNTPCT_EL0);
        if (i == 0) show(a, "CNTVCT_EL0", virtual_count[0]);
    }

    /* HAZARD 1. */
    say(a, "NEXT CNTVOFF_EL2");
    uint64_t voff = SYSREG(S3_4_C14_C0_3);
    show(a, "CNTVOFF_EL2", voff);
    /* CNTVCT = CNTPCT - CNTVOFF_EL2, so CNTVCT + CNTVOFF_EL2 lies between the two CNTPCT reads that bracket it.
     * Modular arithmetic: the offset may be larger than the count. */
    unsigned held = 0;
    for (unsigned i = 0; i < ROUNDS; i++) held += virtual_count[i] + voff - before[i] <= after[i] - before[i];
    show4(a, "VCT_PLUS_VOFF_WITHIN_PCT", held == ROUNDS, "HELD", held, "OF", ROUNDS, "OFFSET", virtual_count[0] + voff - before[0]);

    /* HAZARD 2, the very last access. */
    if (ecv >= ECV_HAS_CNTPOFF) {
        say(a, "NEXT CNTPOFF_EL2");
        uint64_t poff = SYSREG(S3_4_C14_C0_6);
        show(a, "CNTPOFF_EL2", poff);
    } else {
        say(a, "CNTPOFF_EL2 N/A (ECV BELOW 2)");
    }
    say(a, "DONE");
    return 0;
}
