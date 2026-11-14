/* SPDX-License-Identifier: MIT */
/* Host test for the payload "timer" (payloads/timer.c), built natively with Q1N1_PAYLOAD_HOST_TEST so that its register
 * reads come from a scripted register file instead of MRS. Driven by tools/test-q1n1-sp11-payload-timer.py (and the
 * native suite's own machinery) under ASan and UBSan.
 *
 * Everything is pinned against one event log, in which the register reads and the printed lines are in the order they
 * happened, and against a second, independent copy of the register list the payload documents:
 *   order     the exact reads and lines for the unit as far as it is known (ECV 2, HCR_EL2 0x88000010): every SAFE
 *             register printed as soon as it is read; the line NEXT CNTVOFF_EL2 immediately before its read; CNTPOFF_EL2
 *             the very last read, immediately after its NEXT line, then only DONE; the hazards after every SAFE line
 *   ecv       for every value of the ECV field: CNTPOFF_EL2 is read exactly when ECV >= 2, never before the end, and
 *             otherwise the N/A line takes its place and nothing is read
 *   el        at any EL but 2 one line and nothing else (CurrentEL is the only register read)
 *   poll      the poll of CNTPCT_EL0 stops at the first change or after exactly 200000 reads, whichever comes first,
 *             whatever the counter does (changes at once, at the very last permitted read, one read too late, never,
 *             wraps), and prints whether it advanced, the reads and the delta
 *   bracket   CNTVCT + CNTVOFF within the two CNTPCT reads around it in modular arithmetic: an offset larger than the
 *             count, a counter that wraps inside a round, a counter that never moves, an offset that is not applied,
 *             and a read that is off by a few ticks (HELD below OF)
 *   hostile   every register all ones, zero, a huge value or random, with a counter that never moves or that moves at
 *             random, never prints a character outside the page font, a line over 100 characters, more than 16 lines,
 *             or reads a register that is not documented
 *   budget    the lines of the three-payload chain `state`, `psci`, `timer` against the panel region of the unit
 *   args      bad arguments read and print nothing
 * The test cannot show what the binary does on a core: tools/test-q1n1-sp11-payload-build.py disassembles the real
 * binary. Nothing here runs at EL2 or on hardware. Evidence: EXPERIMENTAL (host model only). */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#include "sp11-payload.h"

uint64_t payload_entry(const struct q1n1_payload_args *a);

static unsigned checks;
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)

#define POLL_BOUND 200000u
#define ROUNDS 8u
#define VOFF "S3_4_C14_C0_3"
#define POFF "S3_4_C14_C0_6"
#define PFX "PAYLOAD TIMER "
/* The registers the payload is documented to read (header of timer.c, docs/SP11-PAYLOAD-TIMER.md), and nothing else. */
static const char *const documented[] = {
    "CurrentEL", "ID_AA64MMFR0_EL1", "HCR_EL2", "CNTFRQ_EL0", "CNTHCTL_EL2", "CNTP_CTL_EL0", "CNTV_CTL_EL0", "CNTHP_CTL_EL2",
    "CNTPCT_EL0", "CNTVCT_EL0", VOFF, POFF,
};
#define DOCUMENTED (sizeof documented / sizeof documented[0])

/* ---- The scripted register file --------------------------------------------------------------------------------- */

enum { MODE_SCRIPT, MODE_FILL, MODE_RANDOM };
struct scenario {
    int mode;
    uint64_t fill, el_raw;
    uint64_t mmfr0, hcr, frq, hctl, pctl, vctl, hpctl, voff, poff;
    uint64_t start, applied;    /* the count at time 0, and the offset the virtual count really subtracts */
    unsigned every;             /* the count moves by one every `every` counter reads; 0 never */
    int down;                   /* ... downwards, as a broken counter might */
    int64_t skew;               /* added to the virtual count of read number `skew_read` (from 0): a read out of order */
    unsigned skew_read;
};
static struct scenario sc;
static uint64_t ticks, vct_reads, rng_state = 0x9e3779b97f4a7c15ull;

static uint64_t next_random(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}
static uint64_t count_now(void)
{
    uint64_t moved = sc.every ? ticks / sc.every : 0;
    return sc.down ? sc.start - moved : sc.start + moved;
}

enum { EV_READ, EV_LINE };
struct event { int kind; char text[104]; uint64_t value; };
#define LOG_MAX 230000u
static struct event log_[LOG_MAX];
static unsigned log_n, bad_lines, line_total;
static char first_bad[160];
static void record(int kind, const char *text, uint64_t value)
{
    if (log_n >= LOG_MAX) { fprintf(stderr, "FAIL: the event log is full\n"); exit(2); }
    log_[log_n].kind = kind;
    snprintf(log_[log_n].text, sizeof log_[0].text, "%s", text);
    log_[log_n].value = value;
    log_n++;
}

uint64_t pl_host_sysreg(const char *name);
uint64_t pl_host_sysreg(const char *name)
{
    unsigned known = 0;
    uint64_t v = 0;
    for (unsigned i = 0; i < DOCUMENTED; i++) known |= !strcasecmp(documented[i], name);
    if (!known) {
        fprintf(stderr, "FAIL: the payload read a register that is not documented: %s\n", name);
        exit(3);
    }
    if (!strcasecmp(name, "CurrentEL")) {
        v = sc.el_raw;
    } else if (sc.mode == MODE_FILL) {
        v = sc.fill;
    } else if (sc.mode == MODE_RANDOM) {
        v = next_random();
    } else if (!strcasecmp(name, "ID_AA64MMFR0_EL1")) v = sc.mmfr0;
    else if (!strcasecmp(name, "HCR_EL2")) v = sc.hcr;
    else if (!strcasecmp(name, "CNTFRQ_EL0")) v = sc.frq;
    else if (!strcasecmp(name, "CNTHCTL_EL2")) v = sc.hctl;
    else if (!strcasecmp(name, "CNTP_CTL_EL0")) v = sc.pctl;
    else if (!strcasecmp(name, "CNTV_CTL_EL0")) v = sc.vctl;
    else if (!strcasecmp(name, "CNTHP_CTL_EL2")) v = sc.hpctl;
    else if (!strcasecmp(name, VOFF)) v = sc.voff;
    else if (!strcasecmp(name, POFF)) v = sc.poff;
    else if (!strcasecmp(name, "CNTPCT_EL0")) { v = count_now(); ticks++; }
    else if (!strcasecmp(name, "CNTVCT_EL0")) {
        v = count_now() - sc.applied + (vct_reads == sc.skew_read ? (uint64_t)sc.skew : 0);
        vct_reads++;
        ticks++;
    }
    record(EV_READ, name, v);
    return v;
}

static int in_font(const char *text)
{
    for (; *text; text++)
        if (!((*text >= 'A' && *text <= 'Z') || (*text >= '0' && *text <= '9') || strchr(" :-./=?()_", *text))) return 0;
    return 1;
}
static void fake_puts(const char *line)
{
    if (strlen(line) > Q1N1_PAYLOAD_LINE_MAX || !in_font(line)) {
        bad_lines++;
        if (!first_bad[0]) snprintf(first_bad, sizeof first_bad, "%.159s", line);
    }
    line_total++;
    record(EV_LINE, line, 0);
}
static uint32_t fake_hex(char *dst, uint32_t cap, uint64_t value) { return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value); }
static int32_t fake_load32(uint64_t addr, uint32_t *out) { (void)addr; (void)out; fprintf(stderr, "FAIL: timer used load32\n"); exit(3); }
static uint64_t fake_counter(void) { fprintf(stderr, "FAIL: timer used counter\n"); exit(3); }

static struct q1n1_payload_args args(void)
{
    struct q1n1_payload_args a;
    memset(&a, 0, sizeof a);
    a.magic = Q1N1_PAYLOAD_ABI_MAGIC;
    a.version = Q1N1_PAYLOAD_ABI_VERSION;
    a.size = sizeof a;
    a.ops.puts = fake_puts; a.ops.hex = fake_hex; a.ops.load32 = fake_load32; a.ops.counter = fake_counter;
    return a;
}

/* The unit as far as it is known: ECV 2 (OBSERVED), HCR_EL2 0x88000010 (OBSERVED: E2H clear, TGE set), a 19.2 MHz counter
 * frequency (INFERRED: the monitor's expectation); the other ID_AA64MMFR0_EL1 fields are QEMU's, the unit's are not in
 * this tree. The values of the control and offset registers are made up and different from each other, so that a
 * payload that prints one under another's name shows. */
static void unit_like(void)
{
    memset(&sc, 0, sizeof sc);
    sc.mode = MODE_SCRIPT;
    sc.el_raw = 2 << 2;
    sc.mmfr0 = UINT64_C(0x2100032310201126);
    sc.hcr = 0x88000010;
    sc.frq = 0x124F800;
    sc.hctl = 3;
    sc.pctl = 1; sc.vctl = 2; sc.hpctl = 5;
    sc.voff = sc.applied = 0x5000;
    sc.poff = 0x777;
    sc.start = 0x10000;
    sc.every = 2;
    sc.skew_read = ~0u;
}
static uint64_t go(const struct q1n1_payload_args *a)
{
    log_n = bad_lines = line_total = 0;
    ticks = vct_reads = 0;
    first_bad[0] = 0;
    return payload_entry(a);
}

/* ---- Reading the log ---------------------------------------------------------------------------------------------- */

static unsigned lines_n(void) { unsigned n = 0; for (unsigned i = 0; i < log_n; i++) n += log_[i].kind == EV_LINE; return n; }
static unsigned reads_of(const char *name)
{
    unsigned n = 0;
    for (unsigned i = 0; i < log_n; i++) n += log_[i].kind == EV_READ && !strcasecmp(log_[i].text, name);
    return n;
}
static int first_read(const char *name)
{
    for (unsigned i = 0; i < log_n; i++) if (log_[i].kind == EV_READ && !strcasecmp(log_[i].text, name)) return (int)i;
    return -1;
}
static int last_read(void)
{
    for (int i = (int)log_n - 1; i >= 0; i--) if (log_[i].kind == EV_READ) return i;
    return -1;
}
static int line_at(const char *text)
{
    for (unsigned i = 0; i < log_n; i++) if (log_[i].kind == EV_LINE && !strcmp(log_[i].text, text)) return (int)i;
    return -1;
}
static int line_starting(const char *prefix)
{
    for (unsigned i = 0; i < log_n; i++) if (log_[i].kind == EV_LINE && !strncmp(log_[i].text, prefix, strlen(prefix))) return (int)i;
    return -1;
}
/* Does event `i` match "R NAME" (a read, case-insensitive) or "L TEXT" (a line, exact)? */
static int event_is(unsigned i, const char *want)
{
    if (i >= log_n) return 0;
    if (want[0] == 'R') return log_[i].kind == EV_READ && !strcasecmp(log_[i].text, want + 2);
    return log_[i].kind == EV_LINE && !strcmp(log_[i].text, want + 2);
}

/* A line of KEY=0XVALUE fields separated by single spaces, after the prefix. */
static int keyed_line(const char *text)
{
    if (strncmp(text, PFX, strlen(PFX))) return 0;
    const char *p = text + strlen(PFX);
    do {
        size_t key = strspn(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_");
        if (!key || p[key] != '=' || strncmp(p + key + 1, "0X", 2)) return 0;
        p += key + 3;
        size_t digits = strspn(p, "0123456789ABCDEF");
        if (!digits || digits > 16 || (digits > 1 && p[0] == '0')) return 0;
        p += digits;
    } while (*p++ == ' ');
    return p[-1] == 0;
}

/* ---- order ------------------------------------------------------------------------------------------------------- */

static int suite_order(void)
{
    struct q1n1_payload_args a = args();
    unit_like();
    CHECK(go(&a) == 0);
    const char *expect[160];
    unsigned n = 0;
#define E(s) (expect[n++] = (s))
    E("R CurrentEL");
    E("R ID_AA64MMFR0_EL1"); E("L " PFX "ID_AA64MMFR0_EL1=0X2100032310201126 ECV=0X2");
    E("R HCR_EL2"); E("L " PFX "HCR_EL2=0X88000010 E2H=0X0 TGE=0X1");
    E("R CNTFRQ_EL0"); E("L " PFX "CNTFRQ_EL0=0X124F800");
    E("R CNTHCTL_EL2"); E("L " PFX "CNTHCTL_EL2=0X3 ECV=0X0");
    E("R CNTP_CTL_EL0"); E("L " PFX "CNTP_CTL_EL0=0X1");
    E("R CNTV_CTL_EL0"); E("L " PFX "CNTV_CTL_EL0=0X2");
    E("R CNTHP_CTL_EL2"); E("L " PFX "CNTHP_CTL_EL2=0X5");
    E("R CNTPCT_EL0"); E("L " PFX "CNTPCT_EL0=0X10000");
    E("R CNTPCT_EL0"); E("R CNTPCT_EL0"); E("L " PFX "POLL_ADVANCED=0X1 POLL_READS=0X2 POLL_DELTA=0X1");
    E("R CNTPCT_EL0"); E("R CNTVCT_EL0"); E("R CNTPCT_EL0"); E("L " PFX "CNTVCT_EL0=0XB002");
    for (unsigned i = 1; i < ROUNDS; i++) { E("R CNTPCT_EL0"); E("R CNTVCT_EL0"); E("R CNTPCT_EL0"); }
    E("L " PFX "NEXT CNTVOFF_EL2"); E("R " VOFF); E("L " PFX "CNTVOFF_EL2=0X5000");
    E("L " PFX "VCT_PLUS_VOFF_WITHIN_PCT=0X1 HELD=0X8 OF=0X8 OFFSET=0X1");
    E("L " PFX "NEXT CNTPOFF_EL2"); E("R " POFF); E("L " PFX "CNTPOFF_EL2=0X777");
    E("L " PFX "DONE");
#undef E
    CHECK(log_n == n);
    for (unsigned i = 0; i < n; i++) {
        if (!event_is(i, expect[i])) fprintf(stderr, "event %u: %s %s, wanted %s\n", i, log_[i].kind == EV_READ ? "R" : "L", log_[i].text, expect[i]);
        CHECK(event_is(i, expect[i]));
    }
    CHECK(bad_lines == 0 && lines_n() == 16);

    /* The properties the exact sequence stands for, stated on their own: hazards after every other read and every SAFE
     * line, each NEXT line immediately before its read, CNTPOFF_EL2 the last read, and only DONE after it. */
    int next_v = line_at(PFX "NEXT CNTVOFF_EL2"), next_p = line_at(PFX "NEXT CNTPOFF_EL2");
    int read_v = first_read(VOFF), read_p = first_read(POFF);
    CHECK(next_v >= 0 && read_v == next_v + 1 && next_p >= 0 && read_p == next_p + 1);
    CHECK(read_p == last_read() && read_v < read_p);
    for (int i = 0; i < next_v; i++) CHECK(!(log_[i].kind == EV_READ && (!strcasecmp(log_[i].text, VOFF) || !strcasecmp(log_[i].text, POFF))));
    CHECK(line_at(PFX "CNTVCT_EL0=0XB002") < next_v);
    CHECK(line_at(PFX "DONE") == (int)log_n - 1 && line_at(PFX "CNTPOFF_EL2=0X777") == (int)log_n - 2);

    /* Each documented register, how often it is read: the hazards exactly once. */
    CHECK(reads_of("CurrentEL") == 1 && reads_of("ID_AA64MMFR0_EL1") == 1 && reads_of("HCR_EL2") == 1);
    CHECK(reads_of("CNTFRQ_EL0") == 1 && reads_of("CNTHCTL_EL2") == 1 && reads_of("CNTP_CTL_EL0") == 1);
    CHECK(reads_of("CNTV_CTL_EL0") == 1 && reads_of("CNTHP_CTL_EL2") == 1);
    CHECK(reads_of("CNTPCT_EL0") == 1 + 2 + 2 * ROUNDS && reads_of("CNTVCT_EL0") == ROUNDS);
    CHECK(reads_of(VOFF) == 1 && reads_of(POFF) == 1);
    for (unsigned i = 0; i < log_n; i++) {
        if (log_[i].kind != EV_LINE) continue;
        const char *t = log_[i].text;
        CHECK(keyed_line(t) || !strcmp(t, PFX "NEXT CNTVOFF_EL2") || !strcmp(t, PFX "NEXT CNTPOFF_EL2") || !strcmp(t, PFX "DONE"));
    }
    return 0;
}

/* ---- ecv, el ----------------------------------------------------------------------------------------------------- */

static int suite_ecv(void)
{
    struct q1n1_payload_args a = args();
    char want[160];
    for (uint64_t ecv = 0; ecv < 16; ecv++) {
        unit_like();
        sc.mmfr0 = (sc.mmfr0 & ~(UINT64_C(15) << 60)) | ecv << 60;
        CHECK(go(&a) == 0);
        snprintf(want, sizeof want, "ECV=0X%" PRIX64, ecv);
        CHECK(strstr(log_[2].text, want) && !strncmp(log_[2].text, PFX "ID_AA64MMFR0_EL1=0X", 33));
        CHECK(reads_of(VOFF) == 1 && bad_lines == 0);
        if (ecv >= 2) {
            int next_p = line_at(PFX "NEXT CNTPOFF_EL2");
            CHECK(reads_of(POFF) == 1 && next_p >= 0 && first_read(POFF) == next_p + 1 && first_read(POFF) == last_read());
            CHECK(line_at(PFX "CNTPOFF_EL2 N/A (ECV BELOW 2)") < 0 && lines_n() == 16);
        } else {
            CHECK(reads_of(POFF) == 0 && line_at(PFX "NEXT CNTPOFF_EL2") < 0 && line_starting(PFX "CNTPOFF_EL2=") < 0);
            CHECK(last_read() == first_read(VOFF));              /* with nothing to read after it, CNTVOFF_EL2 is the last */
            CHECK(line_at(PFX "CNTPOFF_EL2 N/A (ECV BELOW 2)") == (int)log_n - 2 && lines_n() == 15);
        }
        CHECK(line_at(PFX "DONE") == (int)log_n - 1);
    }
    /* ECV is bits 63:60 and nothing else: the neighbouring fields do not make CNTPOFF_EL2 appear or vanish. */
    unit_like();
    sc.mmfr0 = UINT64_C(0x0FFFFFFFFFFFFFFF);
    CHECK(go(&a) == 0 && reads_of(POFF) == 0);
    sc.mmfr0 = UINT64_C(0x2FFFFFFFFFFFFFFF);
    CHECK(go(&a) == 0 && reads_of(POFF) == 1);
    sc.mmfr0 = UINT64_C(0x1FFFFFFFFFFFFFFF);
    CHECK(go(&a) == 0 && reads_of(POFF) == 0);
    /* CNTHCTL_EL2.ECV is bit 12 of CNTHCTL_EL2, not of anything else. */
    unit_like();
    sc.hctl = UINT64_C(1) << 12;
    CHECK(go(&a) == 0 && line_at(PFX "CNTHCTL_EL2=0X1000 ECV=0X1") >= 0);
    sc.hctl = ~(UINT64_C(1) << 12);
    CHECK(go(&a) == 0 && line_at(PFX "CNTHCTL_EL2=0XFFFFFFFFFFFFEFFF ECV=0X0") >= 0);
    /* E2H is bit 34 and TGE bit 27 of HCR_EL2. */
    sc.hcr = UINT64_C(1) << 34;
    CHECK(go(&a) == 0 && line_at(PFX "HCR_EL2=0X400000000 E2H=0X1 TGE=0X0") >= 0);
    sc.hcr = UINT64_C(1) << 27;
    CHECK(go(&a) == 0 && line_at(PFX "HCR_EL2=0X8000000 E2H=0X0 TGE=0X1") >= 0);
    return 0;
}

static int suite_el(void)
{
    struct q1n1_payload_args a = args();
    static const uint64_t raw[] = {0, 4, 12, 16, 0x1c, 0x3c0, ~UINT64_C(0), ~UINT64_C(0) & ~UINT64_C(12), UINT64_C(1) << 63};
    for (unsigned i = 0; i < sizeof raw / sizeof raw[0]; i++) {
        unit_like();
        sc.el_raw = raw[i];
        CHECK((raw[i] >> 2 & 3) != 2);
        CHECK(go(&a) == 0);
        CHECK(log_n == 2 && event_is(0, "R CurrentEL") && event_is(1, "L " PFX "SKIPPED_NOT_AT_EL2"));
        CHECK(bad_lines == 0 && ticks == 0);
    }
    /* Bits of CurrentEL that are RES0 do not turn EL2 into something else. */
    unit_like();
    sc.el_raw = 8 | UINT64_C(0xF0000000000000F0);
    CHECK((sc.el_raw >> 2 & 3) == 2 && go(&a) == 0 && lines_n() == 16);
    return 0;
}

/* ---- poll -------------------------------------------------------------------------------------------------------- */

static int suite_poll(void)
{
    struct q1n1_payload_args a = args();
    static const struct { uint64_t start; unsigned every; unsigned advanced; unsigned reads; uint64_t delta; } cases[] = {
        {0x10000, 1, 1, 1, 1}, {0x10000, 2, 1, 2, 1}, {0x10000, 3, 1, 3, 1}, {0x10000, 100, 1, 100, 1},
        {0x10000, POLL_BOUND - 1, 1, POLL_BOUND - 1, 1}, {0x10000, POLL_BOUND, 1, POLL_BOUND, 1},
        {0x10000, POLL_BOUND + 1, 0, POLL_BOUND, 0}, {0x10000, 0, 0, POLL_BOUND, 0},
        {~UINT64_C(0), 1, 1, 1, 1}, {~UINT64_C(0), 5, 1, 5, 1}, {0, 1, 1, 1, 1},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        unit_like();
        sc.start = cases[i].start;
        sc.every = cases[i].every;
        CHECK(go(&a) == 0);
        char want[120];
        snprintf(want, sizeof want, PFX "POLL_ADVANCED=0X%u POLL_READS=0X%X POLL_DELTA=0X%" PRIX64, cases[i].advanced, cases[i].reads,
                 cases[i].delta);
        if (line_at(want) < 0) fprintf(stderr, "case %u: wanted %s\n", i, want);
        CHECK(line_at(want) >= 0);
        /* One read for the first value, the poll's own, and the sixteen of the rounds: never more than the bound. */
        CHECK(reads_of("CNTPCT_EL0") == 1 + cases[i].reads + 2 * ROUNDS);
        CHECK(cases[i].reads <= POLL_BOUND && bad_lines == 0 && lines_n() == 16);
    }
    /* A counter that moves backwards is a counter that changed: the poll asks for "different" and nothing else. */
    unit_like();
    sc.every = 1;
    sc.down = 1;
    CHECK(go(&a) == 0 && line_at(PFX "POLL_ADVANCED=0X1 POLL_READS=0X1 POLL_DELTA=0XFFFFFFFFFFFFFFFF") >= 0);
    return 0;
}

/* ---- bracket ----------------------------------------------------------------------------------------------------- */

static int bracket(const struct q1n1_payload_args *a, unsigned held, unsigned within)
{
    char want[100];
    CHECK(go(a) == 0);
    snprintf(want, sizeof want, PFX "VCT_PLUS_VOFF_WITHIN_PCT=0X%u HELD=0X%X OF=0X8 OFFSET=0X", within, held);
    CHECK(line_starting(want) >= 0 && bad_lines == 0);
    return 0;
}

static int suite_bracket(void)
{
    struct q1n1_payload_args a = args();
    unit_like();
    sc.voff = sc.applied = 0;
    if (bracket(&a, 8, 1)) return 1;                             /* no offset */
    unit_like();
    if (bracket(&a, 8, 1)) return 1;                             /* an offset in effect */
    unit_like();
    sc.voff = sc.applied = UINT64_C(0xFFFFFFFFFFFF0000);        /* larger than the count: CNTVCT wraps below zero */
    if (bracket(&a, 8, 1)) return 1;
    unit_like();
    sc.start = ~UINT64_C(2);
    sc.every = 1;                                                /* the count wraps inside round 0: FF.., then 0, then 1 */
    if (bracket(&a, 8, 1)) return 1;
    unit_like();
    sc.every = 0;                                                /* a counter that does not move: a bracket of width 0 */
    if (bracket(&a, 8, 1)) return 1;
    unit_like();
    sc.applied = 0;                                              /* the offset is not applied: CNTVCT = CNTPCT */
    if (bracket(&a, 0, 0)) return 1;
    CHECK(line_starting(PFX "VCT_PLUS_VOFF_WITHIN_PCT=0X0 HELD=0X0 OF=0X8 OFFSET=0X5001") >= 0);
    unit_like();
    sc.skew = -1000;                                             /* one read out of order: noise, not a verdict */
    sc.skew_read = 3;
    if (bracket(&a, 7, 0)) return 1;
    unit_like();
    sc.skew = 2;
    sc.skew_read = 0;
    CHECK(go(&a) == 0 && line_starting(PFX "VCT_PLUS_VOFF_WITHIN_PCT=0X0 HELD=0X7 OF=0X8 OFFSET=0X3") >= 0);
    return 0;
}

/* ---- hostile ----------------------------------------------------------------------------------------------------- */

static int hostile_run(const struct q1n1_payload_args *a)
{
    CHECK(go(a) == 0);
    if (bad_lines) fprintf(stderr, "bad line: %s\n", first_bad);
    CHECK(bad_lines == 0 && lines_n() <= 16 && lines_n() >= 15);
    CHECK(line_at(PFX "DONE") == (int)log_n - 1 && reads_of(VOFF) == 1 && reads_of(POFF) <= 1);
    CHECK(reads_of("CNTPCT_EL0") <= 1 + POLL_BOUND + 2 * ROUNDS && reads_of("CNTVCT_EL0") == ROUNDS);
    for (unsigned i = 0; i < log_n; i++) if (log_[i].kind == EV_LINE) CHECK(strlen(log_[i].text) <= Q1N1_PAYLOAD_LINE_MAX);
    return 0;
}

static int suite_hostile(void)
{
    struct q1n1_payload_args a = args();
    static const uint64_t fills[] = {0, ~UINT64_C(0), UINT64_C(1) << 63, ~UINT64_C(0) >> 1, 0xFFFFFFFF, 1, 0x00F0000000000000,
                                     UINT64_C(0x2000000000000000), UINT64_C(0xFEDCBA9876543210)};
    for (unsigned i = 0; i < sizeof fills / sizeof fills[0]; i++) {
        unit_like();
        sc.mode = MODE_FILL;
        sc.fill = fills[i];
        sc.el_raw = 8;
        if (hostile_run(&a)) return 1;
        /* A counter that does not change makes the poll read to its bound and not a read more. */
        CHECK(reads_of("CNTPCT_EL0") == 1 + POLL_BOUND + 2 * ROUNDS);
    }
    for (unsigned i = 0; i < 400; i++) {
        unit_like();
        sc.mode = MODE_RANDOM;
        sc.el_raw = 8;
        rng_state = 0x1234567 + 0x9e3779b97f4a7c15ull * i;
        if (hostile_run(&a)) return 1;
    }
    /* Scripted registers with hostile values of one register at a time, the others as the unit's. */
    for (unsigned i = 0; i < sizeof fills / sizeof fills[0]; i++) {
        unit_like();
        sc.mmfr0 = fills[i]; sc.hcr = fills[i]; sc.frq = fills[i]; sc.hctl = fills[i];
        sc.pctl = fills[i]; sc.vctl = fills[i]; sc.hpctl = fills[i]; sc.voff = fills[i]; sc.poff = fills[i];
        sc.start = fills[i];
        if (hostile_run(&a)) return 1;
    }
    return 0;
}

/* ---- budget ------------------------------------------------------------------------------------------------------ */

/* The three-payload chain `state psci timer` on the panel region of the unit. The line counts of the other two payloads
 * are pinned by their own host tests: `state` prints 21 lines, 22 with E2H set (test-q1n1-sp11-payload-state.c), and
 * `psci` at most 30 for any answers (test-q1n1-sp11-payload-psci.c; 22 under QEMU). The runner prints the notes (one
 * LOADED per file and READY) and three lines per payload (VERIFY, CALL, DONE). */
static int suite_budget(void)
{
    struct q1n1_payload_args a = args();
    unit_like();
    CHECK(go(&a) == 0);
    unsigned timer_most = lines_n();
    unit_like();
    sc.mmfr0 &= ~(UINT64_C(15) << 60);
    CHECK(go(&a) == 0 && lines_n() == timer_most - 1);
    CHECK(timer_most == 16 && timer_most <= Q1N1_PAYLOAD_LINES_MAX / 2);
    const unsigned state_most = 22, psci_most = 30, psci_qemu = 22, state_usual = 21;
#define RUNNER(files, payloads) ((files) + 1 + 3 * (payloads))
    const unsigned worst = RUNNER(3, 3) + state_most + psci_most + timer_most;
    const unsigned qemu = RUNNER(3, 3) + state_usual + psci_qemu + timer_most;
    CHECK(RUNNER(3, 3) == 13 && worst == 81 && qemu == 72);
    struct q1n1_payload_region unit;
    q1n1_payload_region_place(2880, 1920, 3, 20, &unit);     /* the unit's panel, as the planner's own test places it */
    CHECK(unit.placement == Q1N1_PAYLOAD_REGION_RIGHT && unit.rows == 89 && unit.rows >= worst);
    /* The stock layout's 60 rows (the least the layout accepts) do not hold the three-payload chain: lines past a
     * region's last row are not drawn, and the timer's NEXT lines are the last ones. `state` and `timer` alone fit. */
    CHECK(qemu > Q1N1_PAYLOAD_REGION_LINES);
    CHECK(RUNNER(2, 2) + state_most + timer_most == 47 && RUNNER(2, 2) + state_most + timer_most <= Q1N1_PAYLOAD_REGION_LINES);
#undef RUNNER
    return 0;
}

static int suite_args(void)
{
    struct q1n1_payload_args a;
    unit_like();
    CHECK(go(NULL) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    a = args(); a.magic ^= 1;
    CHECK(go(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    a = args(); a.version = 2;
    CHECK(go(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    a = args(); a.size = sizeof a - 1;
    CHECK(go(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    a = args(); a.ops.puts = NULL;
    CHECK(go(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    a = args(); a.ops.hex = NULL;
    CHECK(go(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    /* A newer runner hands a bigger block: accepted. load32 and counter are not needed and not used. */
    a = args(); a.size = sizeof a + 64; a.ops.load32 = NULL; a.ops.counter = NULL;
    CHECK(go(&a) == 0 && lines_n() == 16);
    return 0;
}

/* The number docs/SP11-PAYLOAD.md plans a chain's page with, measured rather than copied: the most lines this payload
 * prints, over every EL and every value of the ID_AA64MMFR0_EL1.ECV field. Run as `lines-report`;
 * tools/test-q1n1-sp11-payload-chain.py compares the planning table of the document with its output. */
static int report_lines(void)
{
    struct q1n1_payload_args a = args();
    unsigned most = 0;
    for (uint64_t el = 0; el <= 3; el++)
        for (uint64_t ecv = 0; ecv <= 15; ecv++) {
            unit_like();
            sc.el_raw = el << 2;
            sc.mmfr0 = (sc.mmfr0 & ~(UINT64_C(15) << 60)) | ecv << 60;
            go(&a);
            if (lines_n() > most) most = lines_n();
        }
    printf("LINES_MAX=%u\n", most);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"order", suite_order}, {"ecv", suite_ecv}, {"el", suite_el}, {"poll", suite_poll}, {"bracket", suite_bracket},
        {"hostile", suite_hostile}, {"budget", suite_budget}, {"args", suite_args},
    };
    if (argc > 1 && !strcmp(argv[1], "lines-report")) return report_lines();
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) { fprintf(stderr, "FAIL: suite %s\n", suites[i].name); return 1; }
        ran++;
    }
    printf("PASS: %u payload timer suites, %u checks\n", ran, checks);
    return 0;
}
