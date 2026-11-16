/* SPDX-License-Identifier: MIT */
/* Host test for the payload "cnthctl" (payloads/cnthctl.c), built natively with Q1N1_PAYLOAD_HOST_TEST so that its register reads,
 * its one MSR and its ISB go to a modelled machine instead of the core. Driven by tools/test-q1n1-sp11-payload-cnthctl.py (and the
 * native suite's own machinery) under ASan and UBSan.
 *
 * The machine is one CNTHCTL_EL2 that a write changes only in the bits in `writable`, the other registers the payload reads, a
 * counter that runs `every` ticks per read (or stalls, or never moves) and an event log in which the reads, the writes, the ISBs
 * and the printed lines are in the order they happened, each stamped with the counter. Worlds: the bits stick; they are RES0 and
 * do not (what an unimplemented or gated field would read back as); only one of the two sticks; a stuck-but-inert register is the
 * same machine as the first, because this payload cannot tell them apart (the traps are el1trap's question) -- a suite asserts
 * that; and the write that puts OLD back is ignored for ever, or only the first time. An independent oracle computes the whole
 * page, the writes and the return value from the world; the payload is held to it.
 *   order     the unit as far as it is known (EL2, HCR_EL2 0x88000010, ECV 2, 19.2 MHz, OLD 0x3): the exact events, the NEXT line
 *             before the write, the write exactly eight seconds of counter after the wait began and not one read later, the first
 *             write V = (OLD & ~3) | (1 << 14) | (1 << 13), the second OLD, an ISB after each, nothing printed and no counter read
 *             inside the window, CNTHCTL_EL2 left as found, the page the document shows
 *   worlds    every machine above against the oracle: R, R2, BITS13_14_STUCK, R_EQ_V, RESTORED, the retry (one, and only when
 *             needed), the return value (2 only when the register does not hold OLD at the end)
 *   refuse    not at EL2, no counter op, E2H set, OLD with bit 12, 13 or 14 set, a counter that does not run: one REFUSED or SKIPPED
 *             line and not a single write
 *   clock     the wait is eight seconds at CNTFRQ_EL0 for 1 MHz to 1 GHz and at 19.2 MHz for any other value, to the read; a
 *             counter that stalls for a million reads still ends the wait, one that never moves ends it in a refusal
 *   fuzz      thousands of random worlds against the oracle, the invariants checked on each (the writes, the font, the lines)
 *   args      bad arguments read and print nothing; a missing counter op is a refusal, not a call through a null pointer
 * The test cannot show what the binary does on a core: tools/test-q1n1-sp11-payload-build.py and -cnthctl.py disassemble the real
 * binary, and tools/test-q1n1-sp11-payload-qemu-cnthctl.py runs it at EL2 under QEMU. Nothing here runs on hardware. Evidence:
 * EXPERIMENTAL (host model only). */
#include <inttypes.h>
#include <stdarg.h>
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

#define PFX "PAYLOAD CNTHCTL "
#define BIT(n) (UINT64_C(1) << (n))
#define ECV_BIT BIT(12)
#define EL1TVT BIT(13)
#define EL1TVCT BIT(14)
#define SECONDS 8u
#define UNIT_HZ 0x124F800u
#define STUCK_READS 2000000u
/* The registers the payload is documented to read (header of cnthctl.c, docs/SP11-PAYLOAD-CNTHCTL.md), and nothing else. */
static const char *const documented[] = {"CurrentEL", "HCR_EL2", "ID_AA64MMFR0_EL1", "CNTFRQ_EL0", "CNTHCTL_EL2"};
#define DOCUMENTED (sizeof documented / sizeof documented[0])

/* ---- The modelled machine ----------------------------------------------------------------------------------------- */

enum { RESTORE_WORKS, RESTORE_NEVER, RESTORE_SECOND };
struct world {
    uint64_t el_raw, hcr, mmfr0, cntfrq;
    uint64_t hctl;              /* CNTHCTL_EL2 as the machine holds it; OLD at the start */
    uint64_t writable;          /* the bits a write changes; the others keep what they hold */
    int restore;                /* what the writes after the first do */
    uint64_t start;             /* the counter's first value */
    uint64_t every;             /* ticks per read of the counter; 0: it never moves */
    uint64_t stall;             /* reads that return the first value before it starts moving */
    int no_counter_op;          /* the runner gives no counter */
    int inert;                  /* the bits stick but trap nothing: no register of this file shows it */
};
static struct world w;
static uint64_t counter_reads, write_count, old_value;

enum { EV_READ, EV_WRITE, EV_ISB, EV_LINE };
struct event { int kind; char text[112]; uint64_t value, reads; };
#define LOG_MAX 64u
static struct event log_[LOG_MAX];
static unsigned log_n, bad_lines, line_total;
static char first_bad[160];

static void record(int kind, const char *text, uint64_t value)
{
    if (log_n >= LOG_MAX) { fprintf(stderr, "FAIL: the event log is full\n"); exit(2); }
    log_[log_n].kind = kind;
    snprintf(log_[log_n].text, sizeof log_[0].text, "%s", text);
    log_[log_n].value = value;
    log_[log_n].reads = counter_reads;
    log_n++;
}

static uint64_t counter_value(uint64_t reads)
{
    uint64_t moved = reads > w.stall ? reads - w.stall : 0;
    return w.start + moved * w.every;
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
    if (!strcasecmp(name, "CurrentEL")) v = w.el_raw;
    else if (!strcasecmp(name, "HCR_EL2")) v = w.hcr;
    else if (!strcasecmp(name, "ID_AA64MMFR0_EL1")) v = w.mmfr0;
    else if (!strcasecmp(name, "CNTFRQ_EL0")) v = w.cntfrq;
    else v = w.hctl;
    record(EV_READ, name, v);
    return v;
}

void pl_host_write_cnthctl(uint64_t value);
void pl_host_write_cnthctl(uint64_t value)
{
    int applies = w.restore == RESTORE_WORKS || write_count == 0 || (w.restore == RESTORE_SECOND && write_count >= 2);
    if (applies) w.hctl = (w.hctl & ~w.writable) | (value & w.writable);
    write_count++;
    record(EV_WRITE, "CNTHCTL_EL2", value);
}

void pl_host_isb(void);
void pl_host_isb(void) { record(EV_ISB, "ISB", 0); }

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
static int32_t fake_load32(uint64_t addr, uint32_t *out) { (void)addr; (void)out; fprintf(stderr, "FAIL: cnthctl used load32\n"); exit(3); }
static uint64_t fake_counter(void)
{
    counter_reads++;
    return counter_value(counter_reads);
}

static struct q1n1_payload_args args(void)
{
    struct q1n1_payload_args a;
    memset(&a, 0, sizeof a);
    a.magic = Q1N1_PAYLOAD_ABI_MAGIC;
    a.version = Q1N1_PAYLOAD_ABI_VERSION;
    a.size = sizeof a;
    a.ops.puts = fake_puts; a.ops.hex = fake_hex; a.ops.load32 = fake_load32;
    a.ops.counter = w.no_counter_op ? NULL : fake_counter;
    return a;
}

/* The unit as far as it is known: EL2, HCR_EL2 0x88000010 (OBSERVED: E2H clear, TGE set), ECV 2 (OBSERVED), CNTFRQ_EL0 19.2 MHz,
 * CNTHCTL_EL2 0x3 (OBSERVED at handoff). The bits of the register that can change are the first fifteen: the machine in which the
 * bits stick. The other ID_AA64MMFR0_EL1 fields are QEMU's; the unit's are not in this tree. */
static void unit_like(void)
{
    memset(&w, 0, sizeof w);
    w.el_raw = 2 << 2;
    w.hcr = 0x88000010;
    w.mmfr0 = UINT64_C(0x2100032310201126);
    w.cntfrq = UNIT_HZ;
    w.hctl = 3;
    w.writable = 0x7FFF & ~ECV_BIT;
    w.restore = RESTORE_WORKS;
    w.start = 0x10000;
    w.every = 1000000;      /* 52 ms of the unit's counter per read: a wait of eight seconds is a few hundred reads */
}

static uint64_t go(const struct q1n1_payload_args *a)
{
    log_n = bad_lines = line_total = 0;
    counter_reads = write_count = 0;
    first_bad[0] = 0;
    old_value = w.hctl;
    return payload_entry(a);
}

/* ---- The oracle: the page, the writes and the return value the payload must produce from a world ------------------- */

struct expect {
    char line[16][112];
    unsigned n;
    uint64_t ret, writes[4];
    unsigned nwrites;
    uint64_t final_hctl;
};

static void hex(char *dst, uint64_t value) { snprintf(dst, 24, "0X%" PRIX64, value); }
static void add(struct expect *e, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void add(struct expect *e, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char text[112];
    vsnprintf(text, sizeof text, fmt, ap);
    va_end(ap);
    snprintf(e->line[e->n++], sizeof e->line[0], PFX "%s", text);
}

static uint64_t apply(const struct world *m, uint64_t stored, unsigned nth, uint64_t value)
{
    int applies = m->restore == RESTORE_WORKS || nth == 0 || (m->restore == RESTORE_SECOND && nth >= 2);
    return applies ? (stored & ~m->writable) | (value & m->writable) : stored;
}

static int plausible_hz(uint64_t f) { return f >= 1000000u && f <= 1000000000u; }

/* Whether the wait reads a value below its first: the model's counter is start + moved * every modulo 2^64 (moved: the reads after the
 * stall), so it goes back when a step is negative and does not wrap below zero at the first, or when a forward counter wraps past 2^64
 * between the first read and the last read of the wait. */
static int counter_back(const struct world *m)
{
    typedef __int128 wide;
    wide two64 = (wide)1 << 64, step = m->every >> 63 ? (wide)m->every - two64 : (wide)m->every;
    wide limit = (wide)SECONDS * (plausible_hz(m->cntfrq) ? m->cntfrq : 19200000u), first = (wide)m->start + (m->stall ? 0 : step);
    if (step > 0) return (first + (limit + step - 1) / step * step) / two64 != first / two64;
    return step < 0 && (first % two64 + two64) % two64 >= -step;
}

static void oracle(const struct world *m, struct expect *e)
{
    char a[24], b[24], c[24], d[24];
    memset(e, 0, sizeof *e);
    e->final_hctl = m->hctl;
    if ((m->el_raw >> 2 & 3) != 2) { add(e, "SKIPPED_NOT_AT_EL2"); return; }
    if (m->no_counter_op) { add(e, "REFUSED=NO_COUNTER"); return; }
    hex(a, m->el_raw); hex(b, m->hcr); hex(c, m->hcr >> 34 & 1);
    add(e, "CURRENTEL=%s HCR_EL2=%s E2H=%s", a, b, c);
    hex(a, m->mmfr0); hex(b, m->mmfr0 >> 60 & 15);
    add(e, "ID_AA64MMFR0_EL1=%s ECV=%s", a, b);
    hex(a, m->hctl); hex(c, m->cntfrq);
    add(e, "CNTHCTL_EL2 OLD=%s CNTFRQ_EL0=%s%s", a, c, plausible_hz(m->cntfrq) ? "" : " FREQ=DEFAULT");
    if (m->hcr >> 34 & 1) { add(e, "REFUSED=E2H"); return; }
    if (m->hctl & (ECV_BIT | EL1TVT | EL1TVCT)) { add(e, "REFUSED=OLD_HAS_BITS_12_TO_14"); return; }
    uint64_t old = m->hctl, v = (old & ~UINT64_C(3)) | EL1TVCT | EL1TVT;
    add(e, "NEXT CNTHCTL_EL2 WRITE AFTER 8 S");
    if (m->every == 0 || m->stall >= STUCK_READS + 1 || counter_back(m)) { add(e, "REFUSED=COUNTER_STUCK"); return; }
    uint64_t r = apply(m, old, 0, v), r2 = apply(m, r, 1, old), r3 = r2;
    e->writes[e->nwrites++] = v;
    e->writes[e->nwrites++] = old;
    if (r2 != old) {
        r3 = apply(m, r2, 2, old);
        e->writes[e->nwrites++] = old;
    }
    unsigned stuck = (unsigned)(r >> 13 & 1) + (unsigned)(r >> 14 & 1);
    hex(a, old); hex(b, v); hex(c, r); hex(d, r2);
    add(e, "OLD=%s V=%s", a, b);
    add(e, "R=%s R2=%s", c, d);
    add(e, "BITS13_14_STUCK=%s R_EQ_V=%s", stuck == 2 ? "YES" : stuck == 0 ? "NO" : "PARTIAL", r == v ? "YES" : "NO");
    if (r2 != old) { hex(a, r3); add(e, "RESTORE_RETRY R3=%s", a); }
    e->final_hctl = r3;
    if (r3 == old) { add(e, "RESTORED=YES"); return; }
    hex(a, old); hex(b, r3);
    add(e, "RESTORED=NO");
    add(e, "NOT_RESTORED OLD=%s NOW=%s", a, b);
    add(e, "POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD");
    e->ret = 2;
}

/* Does the log say what the oracle says? Returns 0, or the number of the first thing that differs (never 0 for a mismatch). */
static unsigned lines_n(void) { unsigned n = 0; for (unsigned i = 0; i < log_n; i++) n += log_[i].kind == EV_LINE; return n; }
static const char *line_n(unsigned k)
{
    for (unsigned i = 0; i < log_n; i++)
        if (log_[i].kind == EV_LINE && k-- == 0) return log_[i].text;
    return NULL;
}
static unsigned writes_n(void) { unsigned n = 0; for (unsigned i = 0; i < log_n; i++) n += log_[i].kind == EV_WRITE; return n; }
static uint64_t write_n(unsigned k)
{
    for (unsigned i = 0; i < log_n; i++)
        if (log_[i].kind == EV_WRITE && k-- == 0) return log_[i].value;
    return ~UINT64_C(0);
}

static int matches_oracle(const struct expect *e, uint64_t ret)
{
    if (ret != e->ret || lines_n() != e->n || writes_n() != e->nwrites || w.hctl != e->final_hctl) return 0;
    for (unsigned i = 0; i < e->n; i++)
        if (strcmp(line_n(i), e->line[i])) { fprintf(stderr, "line %u: %s\n   want: %s\n", i, line_n(i), e->line[i]); return 0; }
    for (unsigned i = 0; i < e->nwrites; i++)
        if (write_n(i) != e->writes[i]) return 0;
    return !bad_lines;
}

/* The properties of every run, whatever the world: what may be read, written and printed, and in which order. Returns 0 if they hold. */
static int invariants(const struct expect *e)
{
    int first_write = -1, last_cnthctl_read = -1, next_line = -1;
    for (unsigned i = 0; i < log_n; i++) {
        if (log_[i].kind == EV_WRITE) {
            if (first_write < 0) first_write = (int)i;
            if (strcmp(log_[i].text, "CNTHCTL_EL2")) return 1;
            if (log_[i].value & ECV_BIT) return 2;
            if (i + 1 >= log_n || log_[i + 1].kind != EV_ISB) return 3;
            if (i + 2 >= log_n || log_[i + 2].kind != EV_READ || strcasecmp(log_[i + 2].text, "CNTHCTL_EL2")) return 4;
        }
        if (log_[i].kind == EV_READ && !strcasecmp(log_[i].text, "CNTHCTL_EL2")) last_cnthctl_read = (int)i;
        if (log_[i].kind == EV_LINE && !strncmp(log_[i].text, PFX "NEXT ", strlen(PFX) + 5)) next_line = (int)i;
    }
    if (e->nwrites == 0) return first_write < 0 && write_count == 0 ? 0 : 5;
    if (next_line < 0 || first_write < next_line) return 6;
    for (int i = first_write; i <= last_cnthctl_read; i++) {
        if (log_[i].kind == EV_LINE) return 7;
        if (log_[i].kind == EV_READ && strcasecmp(log_[i].text, "CNTHCTL_EL2")) return 8;
    }
    if (log_[first_write].reads != log_[last_cnthctl_read].reads) return 9;     /* no counter read inside the window */
    if (log_[(unsigned)last_cnthctl_read].kind != EV_READ) return 10;
    for (unsigned i = (unsigned)last_cnthctl_read + 1; i < log_n; i++)
        if (log_[i].kind != EV_LINE) return 11;                                  /* after the window only lines */
    return 0;
}

static int seconds_waited(const struct expect *e, uint64_t hz)
{
    if (!e->nwrites) return 0;
    int next_line = -1, first_write = -1;
    for (unsigned i = 0; i < log_n; i++) {
        if (log_[i].kind == EV_LINE && next_line < 0 && !strncmp(log_[i].text, PFX "NEXT ", strlen(PFX) + 5)) next_line = (int)i;
        if (log_[i].kind == EV_WRITE && first_write < 0) first_write = (int)i;
    }
    uint64_t began = counter_value(log_[next_line].reads + 1), at = counter_value(log_[first_write].reads);
    uint64_t before = counter_value(log_[first_write].reads - 1);
    /* the write follows the first read at which SECONDS * hz ticks have passed since the first read, and no later one */
    return at - began >= SECONDS * hz && before - began < SECONDS * hz;
}

/* ---- Suites ---------------------------------------------------------------------------------------------------------- */

static int run_checked(uint64_t *ret)
{
    struct expect e;
    struct q1n1_payload_args a = args();
    oracle(&w, &e);
    *ret = go(&a);
    CHECK(matches_oracle(&e, *ret));
    CHECK(invariants(&e) == 0);
    CHECK(lines_n() <= 11);
    if (e.nwrites) {
        CHECK(seconds_waited(&e, plausible_hz(w.cntfrq) ? w.cntfrq : 19200000u));
    }
    CHECK((w.hctl == old_value) == (e.ret == 0));
    return 0;
}

static int suite_order(void)
{
    static const char *const want[] = {
        "R CurrentEL", "R HCR_EL2", "R ID_AA64MMFR0_EL1", "R CNTFRQ_EL0", "R CNTHCTL_EL2",
        "L " PFX "CURRENTEL=0X8 HCR_EL2=0X88000010 E2H=0X0",
        "L " PFX "ID_AA64MMFR0_EL1=0X2100032310201126 ECV=0X2",
        "L " PFX "CNTHCTL_EL2 OLD=0X3 CNTFRQ_EL0=0X124F800",
        "L " PFX "NEXT CNTHCTL_EL2 WRITE AFTER 8 S",
        "W 0X6000", "I", "R CNTHCTL_EL2", "W 0X3", "I", "R CNTHCTL_EL2",
        "L " PFX "OLD=0X3 V=0X6000",
        "L " PFX "R=0X6000 R2=0X3",
        "L " PFX "BITS13_14_STUCK=YES R_EQ_V=YES",
        "L " PFX "RESTORED=YES",
    };
    unit_like();
    uint64_t ret;
    if (run_checked(&ret)) return 1;
    CHECK(ret == 0);
    CHECK(log_n == sizeof want / sizeof want[0]);
    for (unsigned i = 0; i < log_n; i++) {
        char text[160];
        if (log_[i].kind == EV_READ) snprintf(text, sizeof text, "R %s", log_[i].text);
        else if (log_[i].kind == EV_LINE) snprintf(text, sizeof text, "L %s", log_[i].text);
        else if (log_[i].kind == EV_WRITE) snprintf(text, sizeof text, "W 0X%" PRIX64, log_[i].value);
        else snprintf(text, sizeof text, "I");
        if (strcasecmp(text, want[i])) { fprintf(stderr, "event %u: %s, want %s\n", i, text, want[i]); return 1; }
        checks++;
    }
    CHECK(w.hctl == 3);
    CHECK(write_count == 2);
    /* The same machine with the bits stuck but their traps inert: nothing this payload can read or write shows it, so the
     * events are the same, byte for byte. Telling the two apart is el1trap's job. */
    char first[LOG_MAX][112];
    unsigned first_n = log_n;
    for (unsigned i = 0; i < log_n; i++) snprintf(first[i], sizeof first[0], "%d %s %" PRIx64, log_[i].kind, log_[i].text, log_[i].value);
    unit_like();
    w.inert = 1;
    CHECK(!run_checked(&ret) && log_n == first_n);
    for (unsigned i = 0; i < log_n; i++) {
        char text[112];
        snprintf(text, sizeof text, "%d %s %" PRIx64, log_[i].kind, log_[i].text, log_[i].value);
        CHECK(!strcmp(text, first[i]));
    }
    return 0;
}

static int suite_worlds(void)
{
    static const struct { uint64_t writable; const char *what; } masks[] = {
        {0x7FFF & ~ECV_BIT, "stick"}, {0x1FFF, "res0"}, {0x1FFF | EL1TVT, "only 13"}, {0x1FFF | EL1TVCT, "only 14"},
        {0x3, "only the EL1 physical bits"}, {0, "read only"}, {0xFFFFFFFFFFFFFFFFull & ~ECV_BIT, "everything but ECV"},
    };
    static const uint64_t olds[] = {0x0, 0x3, 0x1, 0x2, 0x4, 0xFFC, 0x3 | 0xF0, 0x7FF};
    for (unsigned m = 0; m < sizeof masks / sizeof masks[0]; m++)
        for (int restore = RESTORE_WORKS; restore <= RESTORE_SECOND; restore++)
            for (unsigned o = 0; o < sizeof olds / sizeof olds[0]; o++) {
                unit_like();
                w.writable = masks[m].writable;
                w.restore = restore;
                w.hctl = olds[o];
                uint64_t ret;
                if (run_checked(&ret)) { fprintf(stderr, "world %s restore %d old %#llx\n", masks[m].what, restore, (unsigned long long)olds[o]); return 1; }
            }
    /* Named worlds, one by one. */
    unit_like();
    uint64_t ret;
    w.writable = 0x1FFF;
    CHECK(!run_checked(&ret) && ret == 0 && strstr(line_n(6), "BITS13_14_STUCK=NO R_EQ_V=NO"));
    unit_like();
    w.writable = 0x1FFF | EL1TVT;
    CHECK(!run_checked(&ret) && ret == 0 && strstr(line_n(6), "BITS13_14_STUCK=PARTIAL R_EQ_V=NO"));
    unit_like();
    w.restore = RESTORE_NEVER;
    CHECK(!run_checked(&ret) && ret == 2 && write_count == 3 && w.hctl == 0x6000);
    CHECK(strstr(line_n(lines_n() - 1), "POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD") && strstr(line_n(lines_n() - 2), "NOT_RESTORED OLD=0X3 NOW=0X6000"));
    CHECK(strstr(line_n(lines_n() - 3), "RESTORED=NO"));
    unit_like();
    w.restore = RESTORE_SECOND;
    CHECK(!run_checked(&ret) && ret == 0 && write_count == 3 && w.hctl == 3 && strstr(line_n(7), "RESTORE_RETRY R3=0X3"));
    unit_like();
    CHECK(!run_checked(&ret) && write_count == 2);
    return 0;
}

static int suite_refuse(void)
{
    uint64_t ret;
    for (uint64_t el = 0; el <= 3; el++) {
        unit_like();
        w.el_raw = el << 2;
        CHECK(!run_checked(&ret) && ret == 0);
        if (el != 2) CHECK(write_count == 0 && lines_n() == 1 && log_n == 2);      /* CurrentEL, one line */
        else CHECK(write_count == 2);
    }
    unit_like();
    w.no_counter_op = 1;
    CHECK(!run_checked(&ret) && ret == 0 && write_count == 0 && lines_n() == 1);
    unit_like();
    w.hcr |= BIT(34);
    CHECK(!run_checked(&ret) && ret == 0 && write_count == 0 && strstr(line_n(lines_n() - 1), "REFUSED=E2H"));
    for (unsigned bit = 12; bit <= 14; bit++) {
        unit_like();
        w.hctl = 3 | BIT(bit);
        CHECK(!run_checked(&ret) && ret == 0 && write_count == 0 && strstr(line_n(lines_n() - 1), "REFUSED=OLD_HAS_BITS_12_TO_14"));
        CHECK(!strstr(line_n(lines_n() - 1), "NEXT"));
    }
    unit_like();
    w.every = 0;
    CHECK(!run_checked(&ret) && ret == 0 && write_count == 0 && strstr(line_n(lines_n() - 1), "REFUSED=COUNTER_STUCK"));
    CHECK(strstr(line_n(lines_n() - 2), "NEXT CNTHCTL_EL2 WRITE AFTER 8 S"));
    unit_like();
    w.stall = STUCK_READS + 1000;
    CHECK(!run_checked(&ret) && write_count == 0 && strstr(line_n(lines_n() - 1), "REFUSED=COUNTER_STUCK"));
    /* The boundary, to the read: the first read and 1999999 equal ones after it are a counter that is slow, the next one is not. */
    unit_like();
    w.stall = STUCK_READS;
    CHECK(!run_checked(&ret) && write_count == 2);
    unit_like();
    w.stall = STUCK_READS + 1;
    CHECK(!run_checked(&ret) && write_count == 0);
    /* Bits bit 15 and above of OLD are carried into V unchanged, and bits 11:2 too. */
    unit_like();
    w.hctl = 0xFFC | BIT(20);
    w.writable = ~UINT64_C(0) & ~ECV_BIT;
    CHECK(!run_checked(&ret) && write_n(0) == (0xFFC | BIT(20) | EL1TVT | EL1TVCT));
    return 0;
}

static int suite_clock(void)
{
    static const uint64_t hz[] = {1000000u, 19200000u, 24000000u, 1000000000u, 0, 1, 999999u, 1000000001u, 0xFFFFFFFFFFFFFFFFull, 0x124F800u};
    for (unsigned i = 0; i < sizeof hz / sizeof hz[0]; i++) {
        uint64_t ret;
        unit_like();
        w.cntfrq = hz[i];
        w.every = 9973;
        if (hz[i] >= 1000000000u && hz[i] != 0xFFFFFFFFFFFFFFFFull) w.every = 99991;
        CHECK(!run_checked(&ret) && ret == 0 && write_count == 2);
        CHECK(strstr(line_n(2), plausible_hz(hz[i]) ? "CNTFRQ_EL0=" : "FREQ=DEFAULT"));
        CHECK(!!strstr(line_n(2), "FREQ=DEFAULT") == !plausible_hz(hz[i]));
    }
    uint64_t ret;
    unit_like();
    w.cntfrq = 1000000;                     /* the counter lands exactly on the eight seconds at some read: that read ends the wait */
    w.every = 1000000;
    CHECK(!run_checked(&ret) && ret == 0 && write_count == 2);
    unit_like();
    w.stall = 1000000;                      /* a million reads on one value, then it runs: not stuck */
    CHECK(!run_checked(&ret) && ret == 0 && write_count == 2);
    /* A counter that goes back (or wraps) in the wait is refused where it stands: a read below the first would end the wait at once. */
    for (unsigned i = 0; i < 4; i++) {
        unit_like();
        w.every = i < 2 ? -UINT64_C(1000003) : w.every;             /* counts down ... */
        w.start = i < 2 ? UINT64_C(1) << 40 : ~UINT64_C(0) - 100 * w.every;     /* ... or up, past 2^64 in the middle of the wait */
        w.stall = i & 1 ? 10 : 0;
        CHECK(!run_checked(&ret) && ret == 0 && write_count == 0 && strstr(line_n(lines_n() - 1), "REFUSED=COUNTER_STUCK"));
    }
    return 0;
}

static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

static int suite_fuzz(void)
{
    for (unsigned i = 0; i < 6000; i++) {
        uint64_t ret;
        unit_like();
        w.el_raw = rnd() % 8 ? 2 << 2 : (rnd() & 3) << 2;
        w.hcr = rnd() % 16 ? 0x88000010 : rnd();
        w.mmfr0 = rnd();
        w.cntfrq = rnd() % 4 ? (1000000u + rnd() % 999000000u) : rnd() % 3 ? 0 : rnd();
        w.hctl = rnd() % 4 ? (rnd() & 0xFFF) : rnd();
        w.writable = rnd() % 3 ? (rnd() & 0x7FFF) : rnd();
        w.restore = (int)(rnd() % 3);
        w.every = 100000 + rnd() % 2000000;
        w.start = rnd();
        w.stall = rnd() % 10 ? 0 : rnd() % 100;
        w.no_counter_op = rnd() % 40 == 0;
        if (run_checked(&ret)) { fprintf(stderr, "fuzz round %u\n", i); return 1; }
    }
    return 0;
}

static int suite_args(void)
{
    struct q1n1_payload_args a;
    unit_like();
    a = args();
    a.magic ^= 1;
    CHECK(go(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    a = args();
    a.version = 2;
    CHECK(go(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    a = args();
    a.size = sizeof a - 1;
    CHECK(go(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    a = args();
    a.ops.puts = NULL;
    CHECK(go(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    a = args();
    a.ops.hex = NULL;
    CHECK(go(&a) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    CHECK(payload_entry(NULL) == Q1N1_PAYLOAD_RET_BAD_ARGS && log_n == 0);
    a = args();
    a.size = sizeof a + 64;                  /* a larger table than the payload knows is fine */
    CHECK(go(&a) == 0 && write_count == 2);
    a = args();
    a.ops.load32 = NULL;                     /* the payload never uses load32 */
    CHECK(go(&a) == 0 && write_count == 2);
    return 0;
}

/* The page of the unit-like machines, as docs/SP11-PAYLOAD-CNTHCTL.md shows them. Run as `page`. */
static void print_page(const char *title)
{
    printf("# %s\n", title);
    for (unsigned i = 0; i < log_n; i++)
        if (log_[i].kind == EV_LINE) printf("%s\n", log_[i].text);
}
static int report_page(void)
{
    struct q1n1_payload_args a;
    unit_like();
    a = args();
    go(&a);
    print_page("bits stick");
    unit_like();
    w.writable = 0x1FFF;
    a = args();
    go(&a);
    print_page("bits do not stick");
    unit_like();
    w.writable = 0x1FFF | EL1TVCT;
    a = args();
    go(&a);
    print_page("only bit 14 sticks");
    unit_like();
    w.restore = RESTORE_NEVER;
    a = args();
    go(&a);
    print_page("restore fails");
    unit_like();
    w.restore = RESTORE_SECOND;
    a = args();
    go(&a);
    print_page("restore needs the retry");
    return 0;
}

/* The number docs/SP11-PAYLOAD.md plans a chain's page with, measured: the most lines this payload prints over every EL and
 * every machine above. Run as `lines-report`. */
static int report_lines(void)
{
    unsigned most = 0;
    for (uint64_t el = 0; el <= 3; el++)
        for (uint64_t writable = 0; writable <= 0x7FFF; writable += 0x2000 / 2)
            for (int restore = RESTORE_WORKS; restore <= RESTORE_SECOND; restore++)
                for (unsigned bad = 0; bad < 2; bad++) {
                    struct q1n1_payload_args a;
                    unit_like();
                    w.el_raw = el << 2;
                    w.writable = writable;
                    w.restore = restore;
                    if (bad) w.hctl = 0x4003;
                    a = args();
                    go(&a);
                    if (lines_n() > most) most = lines_n();
                }
    printf("LINES_MAX=%u\n", most);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"order", suite_order}, {"worlds", suite_worlds}, {"refuse", suite_refuse}, {"clock", suite_clock},
        {"fuzz", suite_fuzz}, {"args", suite_args},
    };
    if (argc > 1 && !strcmp(argv[1], "lines-report")) return report_lines();
    if (argc > 1 && !strcmp(argv[1], "page")) return report_page();
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) { fprintf(stderr, "FAIL: suite %s\n", suites[i].name); return 1; }
        ran++;
    }
    printf("PASS: %u payload cnthctl suites, %u checks\n", ran, checks);
    return 0;
}
