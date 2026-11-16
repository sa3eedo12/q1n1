/* SPDX-License-Identifier: MIT */
/* Payload "cnthctl" (T-HW1 of the Surface Pro 11 monitor port, docs/SP11-PAYLOAD-CNTHCTL.md): can CNTHCTL_EL2 be written with
 * exactly the value the A16 monitor writes, do bits 14 (EL1TVCT) and 13 (EL1TVT) read back as written, and can the old value
 * be put back? A write-and-restore of one EL2 register, and the only register it writes. EXPERIMENTAL; hardware NOT RUN.
 *
 * What it writes. CNTHCTL_EL2 = V, with V = (OLD & ~3) | (1 << 14) | (1 << 13), the monitor's own formula (probes/xnuboot/
 * prepare.c: `(old & ~3) | (1UL<<14) | (1UL<<13)`, VERIFIED there, and the same 0x6000 in compat/el2-entry-model.h): bits 1:0 are
 * EL1PCEN and EL1PCTEN of the E2H = 0 layout, so the monitor withholds the EL1 physical counter and timer, and 14 and 13 are the
 * FEAT_ECV traps of the EL1 virtual counter and virtual timer. Then ISB, a read of the register (R), OLD back, ISB, a read (R2).
 * If R2 is not OLD it writes OLD once more and reads again (R3); that one retry is the only one, and a register that still does not
 * hold OLD is reported loudly (NOT_RESTORED, RESTORED=NO) and the payload returns 2. The writes are `msr cnthctl_el2, xN` and
 * nothing else: no other register is written, CNTHCTL_EL2.ECV (bit 12) is never set, CNTPOFF_EL2 (a read of it never returns on
 * this unit) and CNTVOFF_EL2 are never touched, and neither is CNTKCTL_EL1.
 *
 * Why the temporary value changes nothing else. The runner calls a payload at EL2 with D, A, I and F masked (DAIF 0x3C0, OBSERVED on
 * q1n1's page), so no interrupt can arrive while the register holds V; no EL1 or EL0 code runs on this core (the payload and the
 * runner are EL2 code, the secondaries are off); and CNTHCTL_EL2 controls accesses made at EL0 and EL1 (and the event stream,
 * whose bits 11:2 V keeps as found): an EL2 access to a counter or a timer is never trapped by it when HCR_EL2.E2H is 0. The
 * register is per core, so no other core sees it. Between the first write and the last read nothing is printed and nothing is read
 * but CNTHCTL_EL2 itself. (INFERRED from the architecture, which was not re-read here; nothing is measured: hardware NOT RUN.)
 *
 * Order. CurrentEL first: not at EL2 the payload prints one line and does nothing else. At EL2 it refuses, with one REFUSED= line and
 * no write, a runner that gives it no counter, HCR_EL2.E2H set (the register then has the VHE layout and V would mean another
 * thing), and an OLD that already has bit 12, 13 or 14 set (then the write could not show whether it makes a bit stick, and ECV
 * would not be left as found by a payload that never sets it). It prints CurrentEL, HCR_EL2, ID_AA64MMFR0_EL1.ECV, CNTFRQ_EL0 and OLD, then
 * the line NEXT CNTHCTL_EL2 WRITE AFTER 8 S and waits eight seconds on the runner's counter, so that a hang or a reset at the write
 * leaves a page that was already photographed. A counter that does not run, or runs backwards, stops the payload before the write:
 * the wait cannot be made (REFUSED=COUNTER_STUCK). The write sequence follows with nothing printed inside it.
 *
 * What the answer means (INFERRED; the Arm ARM text for the ECV-gated fields was not re-read, and no section is quoted): where
 * SCR_EL3.ECVEn is clear the fields EL1TVT and EL1TVCT are expected to be RES0 for what they DO, while a direct read of the
 * register may still show the written bits. So a read-back of 13 and 14 as written says only that the register holds them; whether
 * they trap is the question of the next payload, el1trap. A read-back of zero says the bits are not implemented or are gated.
 *
 * Lines: at most 11 (the ABI allows 40; the host test measures it), each at most 100 characters in the page font, never cut, all
 * PAYLOAD CNTHCTL .... */
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* The host test replaces what a build machine cannot run: MRS, the one MSR and ISB. */
uint64_t pl_host_sysreg(const char *name);
void pl_host_write_cnthctl(uint64_t value);
void pl_host_isb(void);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#define PREFIX "PAYLOAD CNTHCTL "
/* Every helper is out of line: the reviewed binary stays small and each instruction that matters sits in one helper. */
#define OUT_OF_LINE static __attribute__((noinline))

/* CNTHCTL_EL2 with HCR_EL2.E2H clear. Bits 13 and 14 are the monitor's (EL1TVT, EL1TVCT: FEAT_ECV level 1), bit 12 is ECV. */
#define EL1_PHYSICAL_BITS UINT64_C(3)
#define ECV_BIT (UINT64_C(1) << 12)
#define EL1TVT_BIT (UINT64_C(1) << 13)
#define EL1TVCT_BIT (UINT64_C(1) << 14)
#define OLD_REFUSED_BITS (ECV_BIT | EL1TVT_BIT | EL1TVCT_BIT)
#define WAIT_BEFORE_WRITE_S 8u
#define COUNTER_HZ_DEFAULT 19200000u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u
/* A running counter changes within a few dozen reads at any plausible frequency: this many equal reads in a row mean it is not
 * running and no time can be measured. */
#define COUNTER_STUCK_READS 2000000u
#define RET_NOT_RESTORED 2u

/* ---- The instructions, one helper each ------------------------------------------------------------------------------- */

/* The only MSR of the binary. */
OUT_OF_LINE void write_cnthctl_el2(uint64_t value)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_write_cnthctl(value);
#else
    __asm__ volatile("msr cnthctl_el2, %0" : : "r"(value) : "memory");
#endif
}

/* The write has taken effect before any later instruction runs. */
OUT_OF_LINE void isb(void)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_isb();
#else
    __asm__ volatile("isb" : : : "memory");
#endif
}

OUT_OF_LINE uint64_t read_cnthctl_el2(void)
{
    return SYSREG(cnthctl_el2);
}

/* ---- Output ---------------------------------------------------------------------------------------------------------- */

/* PAYLOAD CNTHCTL <text> */
OUT_OF_LINE void say(const struct q1n1_payload_args *a, const char *text)
{
    struct pl_line line;
    pl_begin(&line);
    pl_text(&line, PREFIX);
    pl_text(&line, text);
    pl_emit(a, &line);
}

/* ` KEY=0XVALUE` appended to a line, the first one without the space. */
OUT_OF_LINE void field(const struct q1n1_payload_args *a, struct pl_line *line, const char *key, uint64_t value)
{
    if (line->len > sizeof PREFIX - 1) pl_text(line, " ");
    pl_text(line, key);
    pl_text(line, "=");
    pl_hex(a, line, value);
}

OUT_OF_LINE void row(struct pl_line *line)
{
    pl_begin(line);
    pl_text(line, PREFIX);
}

/* ---- The wait -------------------------------------------------------------------------------------------------------- */

/* Waits `seconds` on the runner's counter at `hz` ticks a second; 0 if the counter does not run or runs backwards (a read below the
 * first would make now - start huge and end the wait at once: the photograph window is not given up for a counter that lies). */
OUT_OF_LINE int wait_seconds(const struct q1n1_payload_args *a, uint64_t hz, unsigned seconds)
{
    uint64_t start = a->ops.counter(), last = start;
    uint32_t same = 0;
    for (;;) {
        uint64_t now = a->ops.counter();
        if (now < start) return 0;
        if (now - start >= hz * seconds) return 1;
        if (now == last) {
            if (++same >= COUNTER_STUCK_READS) return 0;
        } else {
            last = now;
            same = 0;
        }
    }
}

/* ---- The write and the restore ------------------------------------------------------------------------------------- */

struct probe {
    uint64_t old, wanted, read_back, restored, after_retry;
    uint32_t retried;
};

/* The whole window in which CNTHCTL_EL2 holds something else than OLD: nothing is printed inside it. */
OUT_OF_LINE void write_and_restore(struct probe *p)
{
    write_cnthctl_el2(p->wanted);
    isb();
    p->read_back = read_cnthctl_el2();
    write_cnthctl_el2(p->old);
    isb();
    p->restored = read_cnthctl_el2();
    p->after_retry = p->restored;
    if (p->restored != p->old) {
        write_cnthctl_el2(p->old);
        isb();
        p->after_retry = read_cnthctl_el2();
        p->retried = 1;
    }
}

OUT_OF_LINE void report(const struct q1n1_payload_args *a, const struct probe *p)
{
    struct pl_line line;
    unsigned stuck = (unsigned)(p->read_back >> 13 & 1) + (unsigned)(p->read_back >> 14 & 1);
    /* Two values a line: four 64-bit values would not fit the 100 characters of a line, and a line is never cut. */
    row(&line);
    field(a, &line, "OLD", p->old);
    field(a, &line, "V", p->wanted);
    pl_emit(a, &line);
    row(&line);
    field(a, &line, "R", p->read_back);
    field(a, &line, "R2", p->restored);
    pl_emit(a, &line);

    row(&line);
    pl_text(&line, stuck == 2 ? "BITS13_14_STUCK=YES" : stuck == 0 ? "BITS13_14_STUCK=NO" : "BITS13_14_STUCK=PARTIAL");
    pl_text(&line, p->read_back == p->wanted ? " R_EQ_V=YES" : " R_EQ_V=NO");
    pl_emit(a, &line);

    if (p->retried) {
        row(&line);
        field(a, &line, "RESTORE_RETRY R3", p->after_retry);
        pl_emit(a, &line);
    }
    if (p->after_retry == p->old) {
        say(a, "RESTORED=YES");
        return;
    }
    say(a, "RESTORED=NO");
    row(&line);
    pl_text(&line, "NOT_RESTORED");
    field(a, &line, "OLD", p->old);
    field(a, &line, "NOW", p->after_retry);
    pl_emit(a, &line);
    say(a, "POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD");
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct pl_line line;
    struct probe p = {0, 0, 0, 0, 0, 0};
    uint64_t hcr, mmfr0, cntfrq, hz;
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    uint64_t current_el = SYSREG(CurrentEL);
    if ((current_el >> 2 & 3) != 2) {
        say(a, "SKIPPED_NOT_AT_EL2");
        return 0;
    }
    if (!a->ops.counter) {
        say(a, "REFUSED=NO_COUNTER");
        return 0;
    }

    hcr = SYSREG(hcr_el2);
    mmfr0 = SYSREG(id_aa64mmfr0_el1);
    cntfrq = SYSREG(cntfrq_el0);
    p.old = read_cnthctl_el2();
    hz = cntfrq >= COUNTER_HZ_MIN && cntfrq <= COUNTER_HZ_MAX ? cntfrq : COUNTER_HZ_DEFAULT;

    row(&line);
    field(a, &line, "CURRENTEL", current_el);
    field(a, &line, "HCR_EL2", hcr);
    field(a, &line, "E2H", hcr >> 34 & 1);
    pl_emit(a, &line);
    row(&line);
    field(a, &line, "ID_AA64MMFR0_EL1", mmfr0);
    field(a, &line, "ECV", mmfr0 >> 60 & 15);
    pl_emit(a, &line);
    row(&line);
    field(a, &line, "CNTHCTL_EL2 OLD", p.old);
    field(a, &line, "CNTFRQ_EL0", cntfrq);
    if (hz != cntfrq) pl_text(&line, " FREQ=DEFAULT");
    pl_emit(a, &line);

    if (hcr >> 34 & 1) {
        say(a, "REFUSED=E2H");
        return 0;
    }
    if (p.old & OLD_REFUSED_BITS) {
        say(a, "REFUSED=OLD_HAS_BITS_12_TO_14");
        return 0;
    }

    p.wanted = (p.old & ~EL1_PHYSICAL_BITS) | EL1TVCT_BIT | EL1TVT_BIT;
    say(a, "NEXT CNTHCTL_EL2 WRITE AFTER 8 S");
    if (!wait_seconds(a, hz, WAIT_BEFORE_WRITE_S)) {
        say(a, "REFUSED=COUNTER_STUCK");
        return 0;
    }
    write_and_restore(&p);
    report(a, &p);
    return p.after_retry == p.old ? 0 : RET_NOT_RESTORED;
}
