/* SPDX-License-Identifier: MIT */
/* Host test for the payload "el1trap" (payloads/el1trap.c), built natively with Q1N1_PAYLOAD_HOST_TEST so that its register reads, its
 * MSRs, its cache maintenance and the whole of its assembly (el1trap_run: the EL2 handler, the EL1 stub, the vector tables) go to a
 * modelled machine; driven by tools/test-q1n1-sp11-payload-el1trap.py under ASan and UBSan.
 *
 * The machine has the five registers the payload changes (the bits a write changes, bits that come up set on the first write, what
 * later writes do), the registers it reads, a counter, and an EL1 that runs the stub: a read traps (ESR_EL2 class 0x18, that register's
 * ISS, the ELR of the instruction) when CNTHCTL_EL2 says so and otherwise returns a value; scripted ends replace the stub's HVC. A
 * predictor says, from the world alone, the refusal or the registers left, whether the excursion ran and what the payload returns; a
 * checker holds every run to the order and the page the document gives: in the suites and in 6000 random worlds.
 * The assembly on a core is not shown here: tools/test-q1n1-sp11-payload-el1trap.py disassembles the real binary and
 * tools/test-q1n1-sp11-payload-qemu-el1trap.py runs it at EL2 under QEMU. Nothing runs on hardware. Evidence: EXPERIMENTAL. */
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
static void dump_page(void);
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); dump_page(); return 1; } \
        checks++; \
    } while (0)
#define NEED(x) do { checks++; if (!(x)) return #x; } while (0)
#define U(x) ((unsigned long long)(x))

#define PFX "PAYLOAD EL1TRAP "
#define BIT(n) (UINT64_C(1) << (n))
#define UNIT_HZ 0x124F800u
#define STUCK_READS 2000000u
#define SECONDS 8u
#define TRAPS_MAX 8
#define EXCURSION_MAGIC UINT64_C(0x31454c5450415250)
#define EXPECTED_HCR BIT(31)
#define EXPECTED_SCTLR UINT64_C(0x30500800)
#define ECV BIT(12)
/* The bits that decide whether EL1 can be entered and left: RW, E2H, TGE, HCD, VM, FMO, IMO, AMO of HCR_EL2; M, A, C, I, WXN, E0E and
 * EE of SCTLR_EL1. */
#define BITS_HCR (BIT(31) | BIT(34) | BIT(27) | BIT(29) | BIT(0) | (UINT64_C(7) << 3))
#define BITS_SCTLR (BIT(0) | BIT(1) | BIT(2) | BIT(12) | BIT(19) | BIT(24) | BIT(25))
/* What a scripted end reports besides its reason: the exception registers of EL2, and of EL1 for an exception an EL1 vector caught. */
#define END_ELR UINT64_C(0x5CB55123)
#define END_FAR UINT64_C(0xDEAD0000)
#define END_SPSR UINT64_C(0x3C9)
#define EL1_ESR UINT64_C(0x02000000)
#define EL1_ELR UINT64_C(0x5CB55200)
#define EL1_FAR UINT64_C(0x1122)
enum { END_NONE, END_HVC, END_BUDGET, END_DEADLINE, END_VECTOR, END_CLASS, END_HVC_IMM, END_EL1_EXCEPTION, END_EL2_EXCEPTION };
enum { MODE_EXCURSION, MODE_PROBE };

/* The record the assembly fills: its layout is the payload's, pinned there by assertion. */
struct trap_record { uint64_t esr, elr; };
struct excursion {
    uint64_t magic, mode, deadline, entries, traps, reason, vector;
    uint64_t end_esr, end_elr, end_far, end_spsr;
    uint64_t x[4];
    uint64_t el1_esr, el1_elr, el1_far, el1_vector;
    uint64_t probe_ok, saved_vbar;
    struct trap_record trap[TRAPS_MAX];
};
_Static_assert(sizeof(struct excursion) == 296, "the record is 296 bytes");

extern char el1trap_host_image[];
#define IMG_EL2 ((uint64_t)(uintptr_t)el1trap_host_image)
#define IMG_EL1 (IMG_EL2 + 2048)
#define IMG_STUB (IMG_EL2 + 4096)
#define IMG_BYTES 4128u

enum { R_HCR, R_CNTHCTL, R_SCTLR, R_VBAR1, R_VBAR2, R_COUNT };
static const char *const reg_name[R_COUNT] = {"HCR_EL2", "CNTHCTL_EL2", "SCTLR_EL1", "VBAR_EL1", "VBAR_EL2"};

/* ---- The modelled machine ---- */

enum { RESTORE_WORKS, RESTORE_NEVER, RESTORE_SECOND };
enum { PROBE_OK, PROBE_FAILS };
enum { SC_NORMAL, SC_EL1_EXC, SC_EL2_EXC, SC_CLASS, SC_VECTOR, SC_HVC_IMM, SC_BUDGET, SC_DEADLINE, SC_NO_REASON, SC_COUNT };
enum { VBAR2_BACK, VBAR2_LATE, VBAR2_NEVER };   /* el1trap_run leaves VBAR_EL2 as found / at its own table, a write puts back / never */
struct world {
    uint64_t el_raw, mmfr0, pfr0, cntfrq, daif, spsel;
    uint64_t reg[R_COUNT], writable[R_COUNT], forced[R_COUNT];  /* forced: bits that read back set after the first write */
    int restore[R_COUNT];       /* what the writes after the first do */
    uint64_t sp, stack_base, stack_size, base, size;            /* the stack the runner gave, the image it loaded */
    uint64_t start, every, stall;                               /* the counter: first value, ticks a read, reads on the first value */
    uint64_t no_counter_op;
    int ecv_effective, control_traps, cntfrq_traps;
    uint64_t value[4];          /* what the stub's reads return when they do not trap */
    uint64_t iss_noise;         /* XORed into the ISS of the first trap record */
    int scenario, probe, vbar2;
    uint64_t k, end_esr;        /* accesses done before an EL1 or EL2 exception; the ESR_EL2 an end reports */
};
static struct world w, before;
static uint64_t counter_reads, write_count[R_COUNT], writes_total, runs, probes, trap_mask;

enum { EV_READ, EV_WRITE, EV_CACHE, EV_RUN, EV_LINE };
struct event { int kind; char text[112]; uint64_t value, from, reads, count; };
#define LOG_MAX 160u
static struct event log_[LOG_MAX];
static unsigned log_n, bad_lines;
static char first_bad[160];

static void record(int kind, const char *text, uint64_t value)
{
    if (log_n >= LOG_MAX) { fprintf(stderr, "FAIL: the event log is full\n"); exit(2); }
    log_[log_n].kind = kind;
    snprintf(log_[log_n].text, sizeof log_[0].text, "%s", text);
    log_[log_n].value = log_[log_n].from = value;
    log_[log_n].reads = counter_reads;
    log_[log_n].count = 1;
    log_n++;
}

static uint64_t counter_value(uint64_t reads)
{
    uint64_t moved = reads > w.stall ? reads - w.stall : 0;
    return w.start + moved * w.every;
}

static unsigned reg_of(const char *name)
{
    for (unsigned i = 0; i < R_COUNT; i++) if (!strcasecmp(reg_name[i], name)) return i;
    return R_COUNT;
}

/* The registers the payload is documented to read, and nothing else. */
uint64_t pl_host_sysreg(const char *name);
uint64_t pl_host_sysreg(const char *name)
{
    const struct { const char *name; const uint64_t *value; } fixed[] = {
        {"CurrentEL", &w.el_raw}, {"daif", &w.daif}, {"SPSel", &w.spsel}, {"cntfrq_el0", &w.cntfrq},
        {"id_aa64mmfr0_el1", &w.mmfr0}, {"id_aa64pfr0_el1", &w.pfr0},
    };
    const uint64_t *v = reg_of(name) < R_COUNT ? &w.reg[reg_of(name)] : NULL;
    for (unsigned i = 0; i < sizeof fixed / sizeof fixed[0]; i++) if (!strcasecmp(fixed[i].name, name)) v = fixed[i].value;
    if (!v) { fprintf(stderr, "FAIL: the payload read a register that is not documented: %s\n", name); exit(3); }
    record(EV_READ, name, *v);
    return *v;
}

/* What a write does, `nth` writes of that register having come before it. */
static uint64_t after_write(const struct world *m, unsigned which, uint64_t held, uint64_t value, uint64_t nth)
{
    int applies = m->restore[which] == RESTORE_WORKS || nth == 0 || (m->restore[which] == RESTORE_SECOND && nth >= 2);
    uint64_t now = applies ? (held & ~m->writable[which]) | (value & m->writable[which]) : held;
    return nth == 0 ? now | m->forced[which] : now;
}

void pl_host_write(const char *name, uint64_t value);
void pl_host_write(const char *name, uint64_t value)
{
    unsigned which = reg_of(name);
    if (which >= R_COUNT) { fprintf(stderr, "FAIL: the payload wrote a register that is not documented: %s\n", name); exit(3); }
    w.reg[which] = after_write(&w, which, w.reg[which], value, write_count[which]);
    write_count[which]++;
    writes_total++;
    record(EV_WRITE, name, value);
}

void pl_host_cache(const char *operation, uint64_t address);
void pl_host_cache(const char *operation, uint64_t address)
{
    struct event *last = log_n ? &log_[log_n - 1] : NULL;
    if ((!strcmp(operation, "civac") || !strcmp(operation, "ivau")) && last && last->kind == EV_CACHE && !strcmp(last->text, operation) &&
        address == last->value + 16) {
        last->value = address;       /* a run of lines 16 bytes apart is one event: first and last address, and the count */
        last->count++;
        return;
    }
    record(EV_CACHE, operation, address);
}

uint64_t pl_host_stack_pointer(void);
uint64_t pl_host_stack_pointer(void) { return w.sp; }

/* The ISS of a trapped MRS of access i into x<rt>: Op0, Op2, Op1, CRn, Rt, CRm and Direction 1 (a read). */
static uint64_t iss_of(unsigned i, unsigned rt)
{
    static const unsigned enc[4][5] = {{3, 3, 14, 0, 2}, {3, 3, 14, 3, 1}, {3, 3, 14, 0, 0}, {3, 3, 14, 0, 1}};   /* op0 op1 CRn CRm op2 */
    return (enc[i][0] << 20) | (enc[i][4] << 17) | (enc[i][1] << 14) | (enc[i][2] << 10) | (rt << 5) | (enc[i][3] << 1) | 1u;
}
static uint64_t trap_esr(unsigned i) { return UINT64_C(0x18) << 26 | BIT(25) | iss_of(i, i); }

/* Whether access i (CNTVCT_EL0, CNTV_CTL_EL0, CNTFRQ_EL0, CNTPCT_EL0) traps with the CNTHCTL_EL2 the machine holds. */
static int trapped_access(unsigned i)
{
    switch (i) {
    case 0: return w.ecv_effective && (w.reg[R_CNTHCTL] >> 14 & 1);
    case 1: return w.ecv_effective && (w.reg[R_CNTHCTL] >> 13 & 1);
    case 2: return w.cntfrq_traps;
    default: return w.control_traps && !(w.reg[R_CNTHCTL] & 1);
    }
}

static int plausible_hz(uint64_t f) { return f >= 1000000u && f <= 1000000000u; }

/* The assembly of el1trap_run: the probe, or the stub run to its end. Fills the record as the handler does and checks what the
 * payload must have set up before the first ERET. */
uint64_t pl_host_run(struct excursion *e, uint64_t stub);
uint64_t pl_host_run(struct excursion *e, uint64_t stub)
{
    static const struct { uint64_t reason, vector; } ends[SC_COUNT] = {
        [SC_NORMAL] = {END_HVC, 8}, [SC_EL1_EXC] = {END_EL1_EXCEPTION, 8}, [SC_EL2_EXC] = {END_EL2_EXCEPTION, 4}, [SC_CLASS] = {END_CLASS, 8},
        [SC_VECTOR] = {END_VECTOR, 9}, [SC_HVC_IMM] = {END_HVC_IMM, 8}, [SC_BUDGET] = {END_BUDGET, 8}, [SC_DEADLINE] = {END_DEADLINE, 8},
    };
    record(EV_RUN, e->mode == MODE_PROBE ? "PROBE" : "EXCURSION", e->mode);
    if (e->magic != EXCURSION_MAGIC || stub != IMG_STUB || (e->mode != MODE_PROBE && e->mode != MODE_EXCURSION) || e->reason || e->entries ||
        e->traps || e->deadline - counter_value(counter_reads) != (plausible_hz(w.cntfrq) ? w.cntfrq : 19200000u) /* one second */ ||
        (e->mode == MODE_PROBE && (writes_total || probes)) || (e->mode == MODE_EXCURSION && !probes)) {
        fprintf(stderr, "FAIL: the record or the stub address handed to el1trap_run is not as the assembly needs it\n");
        exit(3);
    }
    e->saved_vbar = w.reg[R_VBAR2];
    if (e->mode == MODE_PROBE) {
        probes++;
        e->entries = 1;
        e->vector = 4;
        if (w.probe == PROBE_OK) e->probe_ok = 1;
        else e->reason = END_EL2_EXCEPTION;
    } else {
        uint64_t done = w.scenario == SC_EL1_EXC || w.scenario == SC_EL2_EXC ? w.k : 4;      /* accesses before the end */
        runs++;
        if ((w.reg[R_HCR] & BITS_HCR) != EXPECTED_HCR || (w.reg[R_SCTLR] & BITS_SCTLR) != 0 || w.reg[R_VBAR1] != IMG_EL1 ||
            (w.daif & 0x3c0) != 0x3c0 || (w.el_raw >> 2 & 3) != 2 || (w.reg[R_CNTHCTL] & ECV)) {
            fprintf(stderr, "FAIL: the stub was entered in a state the document does not allow\n");
            exit(3);
        }
        for (unsigned i = 0; i < 4 && i < done; i++) {
            if (trapped_access(i)) {
                e->trap[e->traps].esr = trap_esr(i) ^ (e->traps == 0 ? w.iss_noise : 0);
                e->trap[e->traps].elr = stub + 4 * i;
                e->traps++;
                e->entries++;
                trap_mask |= 1u << i;
            } else {
                e->x[i] = w.value[i];
            }
        }
        e->entries++;
        e->reason = ends[w.scenario].reason;
        e->vector = ends[w.scenario].vector;
        for (; w.scenario == SC_BUDGET && e->traps < TRAPS_MAX; e->traps++) {
            e->trap[e->traps].esr = trap_esr(3);
            e->trap[e->traps].elr = stub + 12;
            e->entries = 9;
        }
        if (w.scenario == SC_EL1_EXC) {
            e->el1_esr = EL1_ESR;
            e->el1_elr = EL1_ELR;
            e->el1_far = EL1_FAR;
            e->el1_vector = 4;
        }
    }
    if (e->reason != END_NONE && e->reason != END_HVC) {
        e->end_esr = w.end_esr;
        e->end_elr = END_ELR;
        e->end_far = END_FAR;
        e->end_spsr = END_SPSR;
    }
    if (w.vbar2 != VBAR2_BACK) w.reg[R_VBAR2] = IMG_EL2;
    return e->reason;
}

/* ---- The runner's side ---- */

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
    record(EV_LINE, line, 0);
}
static uint32_t fake_hex(char *dst, uint32_t cap, uint64_t value) { return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value); }
static int32_t fake_load32(uint64_t addr, uint32_t *out) { (void)addr; (void)out; fprintf(stderr, "FAIL: el1trap used load32\n"); exit(3); }
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
    a.ops.puts = fake_puts;
    a.ops.hex = fake_hex;
    a.ops.load32 = fake_load32;
    a.ops.counter = w.no_counter_op ? NULL : fake_counter;
    a.payload_base = w.base;
    a.payload_size = w.size;
    a.stack_base = w.stack_base;
    a.stack_size = w.stack_size;
    return a;
}

/* The unit as far as it is known (EL2, HCR_EL2 0x88000010, ECV 2, 19.2 MHz, CNTHCTL_EL2 0x3, DAIF masked, SP_EL2 selected), with the
 * traps effective as under QEMU's -cpu max. Made up, because the unit's are not in this tree: ID_AA64MMFR0_EL1 and ID_AA64PFR0_EL1
 * apart from ECV and EL1, SCTLR_EL1, VBAR_EL2, what the stub's reads return. */
static void unit_like(void)
{
    memset(&w, 0, sizeof w);
    w.el_raw = 2 << 2;
    w.mmfr0 = UINT64_C(0x2100032310201126);
    w.pfr0 = UINT64_C(0x1301001121110222);
    w.cntfrq = UNIT_HZ;
    w.daif = 0x3c0;
    w.spsel = 1;
    w.reg[R_HCR] = 0x88000010;
    w.reg[R_CNTHCTL] = 3;
    w.reg[R_SCTLR] = 0x30C50838;
    w.reg[R_VBAR2] = 0x5C155000;
    for (unsigned i = 0; i < R_COUNT; i++) w.writable[i] = ~UINT64_C(0);
    w.writable[R_CNTHCTL] = 0x7FFF & ~ECV;
    w.stack_base = 0x80000000;
    w.stack_size = 64 * 1024;
    w.sp = w.stack_base + w.stack_size - 256;
    w.base = IMG_EL2;
    w.size = IMG_BYTES;
    w.start = 0x10000;
    w.every = 1000000;
    w.ecv_effective = w.control_traps = 1;
    w.value[0] = 0x123456789ull;
    w.value[2] = UNIT_HZ;
    w.value[3] = 0x123456000ull;
    w.end_esr = UINT64_C(0x96000045);
}

static uint64_t go(const struct q1n1_payload_args *a)
{
    log_n = bad_lines = 0;
    counter_reads = writes_total = runs = probes = trap_mask = 0;
    memset(write_count, 0, sizeof write_count);
    first_bad[0] = 0;
    if (w.vbar2 == VBAR2_NEVER) w.writable[R_VBAR2] = 0;
    before = w;
    return payload_entry(a);
}

/* ---- Reading the log ---- */

static unsigned lines_n(void) { unsigned n = 0; for (unsigned i = 0; i < log_n; i++) n += log_[i].kind == EV_LINE; return n; }
static const char *line_n(unsigned k)
{
    for (unsigned i = 0; i < log_n; i++)
        if (log_[i].kind == EV_LINE && k-- == 0) return log_[i].text;
    return "";
}
static void dump_page(void)
{
    for (unsigned i = 0; i < lines_n(); i++) fprintf(stderr, "  %2u %s\n", i, line_n(i));
}
static int event_of_line(const char *text)
{
    for (unsigned i = 0; i < log_n; i++) if (log_[i].kind == EV_LINE && !strcmp(log_[i].text, text)) return (int)i;
    return -1;
}
static int has_line(const char *text) { return event_of_line(text) >= 0; }
static int has_prefix(const char *prefix)
{
    for (unsigned i = 0; i < log_n; i++)
        if (log_[i].kind == EV_LINE && !strncmp(log_[i].text, prefix, strlen(prefix))) return 1;
    return 0;
}

/* Whether line n of the page is the formatted text. */
static int line_is(unsigned n, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int line_is(unsigned n, const char *fmt, ...)
{
    char want[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(want, sizeof want, fmt, ap);
    va_end(ap);
    return !strcmp(line_n(n), want);
}

/* Holds the page from line `from` to the list `want` (lines without the prefix), and nothing after it. */
static int page_is(unsigned from, const char *const *want, unsigned n)
{
    if (lines_n() != from + n) { fprintf(stderr, "%u lines, want %u\n", lines_n(), from + n); return 0; }
    for (unsigned i = 0; i < n; i++)
        if (!line_is(from + i, PFX "%s", want[i])) { fprintf(stderr, "line %u: %s\n   want: %s\n", from + i, line_n(from + i), want[i]); return 0; }
    return 1;
}

/* ---- The predictor: what the world must leave, from the world alone ---- */

struct prediction {
    const char *refusal;        /* the line that ends a refused run, NULL if none */
    int waited, probe_failed, held, ran;
    uint64_t final[R_COUNT], ret;
};

static void predict(const struct world *m, struct prediction *p)
{
    uint64_t end = m->base + m->size, saved[R_COUNT], cur[R_COUNT], writes[R_COUNT] = {0, 0, 0, 0, 0}, wanted[4];
    unsigned bad = 0;
    int layout = m->size < (UINT64_C(1) << 32) && end >= m->base && IMG_EL2 >= m->base && IMG_EL2 + 2048 <= end && IMG_EL1 >= m->base &&
                 IMG_EL1 + 2048 <= end && IMG_STUB >= m->base && IMG_STUB + 20 <= end;
    memset(p, 0, sizeof *p);
    for (unsigned i = 0; i < R_COUNT; i++) p->final[i] = saved[i] = cur[i] = m->reg[i];
    if ((m->el_raw >> 2 & 3) != 2) p->refusal = "SKIPPED_NOT_AT_EL2";
    else if (m->no_counter_op) p->refusal = "REFUSED=NO_COUNTER";
    else if (!layout) p->refusal = "REFUSED=ENTRY";
    else if (saved[R_HCR] >> 34 & 1) p->refusal = "REFUSED=E2H";
    else if ((m->pfr0 >> 4 & 15) == 0) p->refusal = "REFUSED=NO_EL1_AARCH64";
    else if ((m->daif & 0x3c0) != 0x3c0) p->refusal = "REFUSED=DAIF_NOT_MASKED";
    else if (!(m->spsel & 1)) p->refusal = "REFUSED=SPSEL_NOT_EL2H";
    else if (saved[R_CNTHCTL] & (ECV | BIT(13) | BIT(14))) p->refusal = "REFUSED=OLD_HAS_BITS_12_TO_14";
    else if (m->sp < m->stack_base + 16384 || m->sp > m->stack_base + m->stack_size) p->refusal = "REFUSED=STACK";
    if (p->refusal) return;
    p->waited = 1;
    if (m->every == 0 || m->stall > STUCK_READS) { p->refusal = "REFUSED=COUNTER_STUCK"; return; }
    /* The probe leaves VBAR_EL2 at the payload's table on this machine; the payload's one write puts it back, if writes work. */
    if (m->vbar2 != VBAR2_BACK) cur[R_VBAR2] = after_write(m, R_VBAR2, IMG_EL2, saved[R_VBAR2], writes[R_VBAR2]++);
    p->probe_failed = m->probe != PROBE_OK || cur[R_VBAR2] != saved[R_VBAR2];
    if (p->probe_failed) {
        p->final[R_VBAR2] = cur[R_VBAR2];
        p->ret = cur[R_VBAR2] != saved[R_VBAR2] ? 3 : 2;
        return;
    }
    wanted[R_HCR] = EXPECTED_HCR;
    wanted[R_CNTHCTL] = (saved[R_CNTHCTL] & ~UINT64_C(3)) | BIT(14) | BIT(13);
    wanted[R_SCTLR] = EXPECTED_SCTLR;
    wanted[R_VBAR1] = IMG_EL1;
    for (unsigned i = 0; i < 4; i++) cur[i] = after_write(m, i, cur[i], wanted[i], writes[i]++);
    p->held = (cur[R_HCR] & BITS_HCR) == (wanted[R_HCR] & BITS_HCR) && (cur[R_SCTLR] & BITS_SCTLR) == (wanted[R_SCTLR] & BITS_SCTLR) &&
              cur[R_VBAR1] == wanted[R_VBAR1] && !(cur[R_CNTHCTL] & ECV);
    if (p->held) {
        p->ran = 1;
        if (m->vbar2 != VBAR2_BACK) cur[R_VBAR2] = IMG_EL2;
    }
    for (unsigned i = 0; i < 4; i++) cur[i] = after_write(m, i, cur[i], saved[i], writes[i]++);
    for (unsigned i = 0; i < R_COUNT; i++)      /* the one retry */
        if (cur[i] != saved[i]) cur[i] = after_write(m, i, cur[i], saved[i], writes[i]++);
    for (unsigned i = 0; i < R_COUNT; i++) { p->final[i] = cur[i]; bad += cur[i] != saved[i]; }
    p->ret = bad ? 3 : (p->ran && m->scenario == SC_NORMAL) ? 0 : 2;
}

/* ---- The rules every run keeps, and its page ---- */

static int ev_is(unsigned i, int kind, const char *text) { return i < log_n && log_[i].kind == kind && !strcasecmp(log_[i].text, text); }
static int ev_write(unsigned i, const char *name, uint64_t value) { return ev_is(i, EV_WRITE, name) && log_[i].value == value; }
/* The retry of one register: the write of what was found, an ISB, a read. */
static int retry_ok(unsigned at, unsigned reg)
{
    return ev_write(at, reg_name[reg], before.reg[reg]) && ev_is(at + 1, EV_CACHE, "isb") && ev_is(at + 2, EV_READ, reg_name[reg]);
}

static int context_ok(const struct world *m, int with_offsets)
{
    return line_is(0, PFX "CURRENTEL=0X%llX HCR_EL2=0X%llX E2H=0X%llX", U(m->el_raw), U(m->reg[R_HCR]), U(m->reg[R_HCR] >> 34 & 1)) &&
           line_is(1, PFX "DAIF=0X%llX SPSEL=0X%llX CNTFRQ_EL0=0X%llX%s", U(m->daif), U(m->spsel), U(m->cntfrq), plausible_hz(m->cntfrq) ? "" : " FREQ=DEFAULT") &&
           line_is(2, PFX "ID_AA64MMFR0_EL1=0X%llX ECV=0X%llX", U(m->mmfr0), U(m->mmfr0 >> 60 & 15)) &&
           line_is(3, PFX "ID_AA64PFR0_EL1=0X%llX EL1=0X%llX", U(m->pfr0), U(m->pfr0 >> 4 & 15)) &&
           line_is(4, PFX "OLD CNTHCTL_EL2=0X%llX SCTLR_EL1=0X%llX", U(m->reg[R_CNTHCTL]), U(m->reg[R_SCTLR])) &&
           line_is(5, PFX "OLD VBAR_EL1=0X%llX VBAR_EL2=0X%llX", U(m->reg[R_VBAR1]), U(m->reg[R_VBAR2])) &&
           (!with_offsets || line_is(6, PFX "STUB_OFFSET=0X%llX EL1_VECTORS_OFFSET=0X%llX EL2_VECTORS_OFFSET=0X%llX",
                                     U(IMG_STUB - m->base), U(IMG_EL1 - m->base), U(IMG_EL2 - m->base)));
}

/* The page of a normal excursion, lines 13 to 18: the four accesses, the verdict, the end. */
static int access_page_ok(const struct world *m, uint64_t readback_cnthctl)
{
    static const char *const names[4] = {"CNTVCT_EL0", "CNTV_CTL_EL0", "CNTFRQ_EL0", "CNTPCT_EL0 CONTROL"};
    unsigned first = 4, n = 0, bits = (unsigned)(readback_cnthctl >> 13 & 1) + (unsigned)(readback_cnthctl >> 14 & 1);
    const char *verdict = !(trap_mask & 8) ? "CONTROL_NOT_TRAPPED" : (trap_mask & 3) == 3 ? "TRAPS_EFFECTIVE" : !(trap_mask & 3) ? "TRAPS_INERT" : "TRAPS_PARTIAL";
    for (unsigned i = 0; i < 4; i++)
        if (trap_mask >> i & 1) { n++; if (first == 4) first = i; }
    for (unsigned i = 0; i < 4; i++) {
        uint64_t esr = trap_esr(i) ^ (i == first ? m->iss_noise : 0);      /* the noise changes the class or the ISS, not the IL bit */
        if (trap_mask >> i & 1 ? !line_is(13 + i, PFX "%s TRAPPED EC=0X%llX ISS=0X%llX ISS_OK=%s", names[i], U(esr >> 26 & 63), U(esr & 0x1ffffff),
                                          esr == trap_esr(i) ? "YES" : "NO")
                               : !line_is(13 + i, PFX "%s NOT_TRAPPED VALUE=0X%llX", names[i], U(m->value[i]))) return 0;
    }
    return line_is(17, PFX "VERDICT=%s BITS13_14_IN_READBACK=%s%s", verdict, bits == 2 ? "YES" : bits == 0 ? "NO" : "PARTIAL",
                   trap_mask & 4 ? " CNTFRQ_EL0_TRAPPED" : "") && line_is(18, PFX "EXCURSION OK ENTRIES=0X%X TRAPS=0X%X", n + 1, n);
}

/* The end of the page: a RESTORE_RETRY for each retried register, then RESTORED=YES, or what differs. Returns the number of lines, 0 if wrong. */
static unsigned restore_block(const struct world *m, unsigned retried, const uint64_t now[R_COUNT], const uint64_t final[R_COUNT])
{
    unsigned n = 0, bad = 0, at;
    for (unsigned i = 0; i < R_COUNT; i++) { n += retried >> i & 1; bad += final[i] != m->reg[i]; }
    n += 1 + (bad ? bad + 1 : 0);
    if (lines_n() < n) return 0;
    at = lines_n() - n;
    for (unsigned i = 0; i < R_COUNT; i++)
        if (retried >> i & 1 && !line_is(at++, PFX "RESTORE_RETRY %s NOW=0X%llX", reg_name[i], U(now[i]))) return 0;
    if (!bad) return line_is(at, PFX "RESTORED=YES") ? n : 0;
    if (!line_is(at++, PFX "RESTORED=NO")) return 0;
    for (unsigned i = 0; i < R_COUNT; i++)
        if (final[i] != m->reg[i] && !line_is(at++, PFX "NOT_RESTORED %s WANT=0X%llX NOW=0X%llX", reg_name[i], U(m->reg[i]), U(final[i]))) return 0;
    return line_is(at, PFX "POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD") ? n : 0;
}

/* NULL if the run kept every rule, else the rule it broke. */
static const char *rules(uint64_t ret, const struct prediction *p)
{
    const struct world *m = &before;
    uint64_t now[R_COUNT] = {0, 0, 0, 0, 0}, rb[4], first = m->base & ~UINT64_C(15), count = (m->base + m->size - first + 15) / 16;
    uint64_t cnthctl = (m->reg[R_CNTHCTL] & ~UINT64_C(3)) | BIT(14) | BIT(13);
    unsigned c = 0, e, fw, at, retried = 0, block;
    NEED(!bad_lines && lines_n() <= 40 && ret == p->ret);
    for (unsigned i = 0; i < R_COUNT; i++) NEED(w.reg[i] == p->final[i]);
    NEED(has_line(PFX "NEXT EL1 EXCURSION AFTER 8 S") == p->waited);
    if (p->refusal) {
        const char *r = p->refusal;
        unsigned n = !strcmp(r, "SKIPPED_NOT_AT_EL2") || !strcmp(r, "REFUSED=NO_COUNTER") ? 1 : !strcmp(r, "REFUSED=ENTRY") ? 7 : !strcmp(r, "REFUSED=COUNTER_STUCK") ? 9 : 8;
        NEED(line_is(n - 1, PFX "%s", r) && lines_n() == n && !writes_total && !probes && !runs);
        for (unsigned i = 0; i < log_n; i++) NEED(log_[i].kind != EV_CACHE);
        NEED(n == 1 || context_ok(m, n > 7));
        return NULL;
    }
    NEED(context_ok(m, 1));
    /* The cache work covers the whole image before the probe: DC CIVAC, DSB, IC IVAU, DSB, ISB; then the probe, then VBAR_EL2. */
    while (c < log_n && log_[c].kind != EV_CACHE) c++;
    NEED((int)c > event_of_line(PFX "NEXT EL1 EXCURSION AFTER 8 S"));
    NEED(ev_is(c, EV_CACHE, "civac") && log_[c].from == first && log_[c].count == count && log_[c].value == first + (count - 1) * 16);
    NEED(ev_is(c + 1, EV_CACHE, "dsb") && ev_is(c + 2, EV_CACHE, "ivau") && log_[c + 2].from == first && log_[c + 2].count == count &&
         log_[c + 2].value == log_[c].value && ev_is(c + 3, EV_CACHE, "dsb") && ev_is(c + 4, EV_CACHE, "isb"));
    NEED(ev_is(c + 5, EV_RUN, "PROBE") && probes == 1 && ev_is(c + 6, EV_READ, "VBAR_EL2"));
    e = c + 7;
    now[R_VBAR2] = log_[c + 6].value;
    if (log_[c + 6].value != m->reg[R_VBAR2]) {
        NEED(retry_ok(e, R_VBAR2));
        now[R_VBAR2] = log_[e + 2].value;
        retried = 1u << R_VBAR2;
        e += 3;
    }
    if (p->probe_failed) {
        int ok = m->probe == PROBE_OK;
        NEED(!runs && !has_line(PFX "NEXT EL1 EXCURSION") && !has_prefix(PFX "WRITES"));
        for (unsigned i = e; i < log_n; i++) NEED(log_[i].kind == EV_LINE);
        NEED(line_is(8, PFX "HVC_AT_EL2=FAILED %s ENTRIES=0X1 VECTOR=0X4", ok ? "NONE" : "EL2_EXCEPTION"));
        NEED(line_is(9, PFX "HVC_AT_EL2 ESR_EL2=0X%llX ELR_EL2=0X%llX", U(ok ? 0 : m->end_esr), U(ok ? 0 : END_ELR)) && line_is(10, PFX "REFUSED=HVC_AT_EL2"));
        block = restore_block(m, retried, now, p->final);
        NEED(block && lines_n() == 11 + block);
        return NULL;
    }
    /* After the probe: three lines, four writes in the order they are set, an ISB, the read-back, the run, the put-back in the reverse
     * order, an ISB, five reads, one retry for what is not as found; no line from the first write to the last read. */
    NEED(log_[e].kind == EV_LINE && log_[e + 1].kind == EV_LINE && log_[e + 2].kind == EV_LINE);
    NEED(line_is(8, PFX "HVC_AT_EL2=OK") && line_is(10, PFX "NEXT EL1 EXCURSION"));
    NEED(line_is(9, PFX "WRITES HCR_EL2=0X%llX CNTHCTL_EL2=0X%llX SCTLR_EL1=0X%llX", U(EXPECTED_HCR), U(cnthctl), U(EXPECTED_SCTLR)));
    fw = e + 3;
    NEED(ev_write(fw, "VBAR_EL1", IMG_EL1) && ev_write(fw + 1, "SCTLR_EL1", EXPECTED_SCTLR) && ev_write(fw + 2, "CNTHCTL_EL2", cnthctl));
    NEED(ev_write(fw + 3, "HCR_EL2", EXPECTED_HCR) && ev_is(fw + 4, EV_CACHE, "isb"));
    for (unsigned k = 0; k < 4; k++) { NEED(ev_is(fw + 5 + k, EV_READ, reg_name[k])); rb[k] = log_[fw + 5 + k].value; }
    at = fw + 9;
    NEED(p->ran == ev_is(at, EV_RUN, "EXCURSION") && runs == (uint64_t)p->ran);
    at += (unsigned)p->ran;
    for (unsigned k = 0; k < 4; k++) NEED(ev_write(at + k, reg_name[k], m->reg[k]));
    NEED(ev_is(at + 4, EV_CACHE, "isb"));
    for (unsigned k = 0; k < R_COUNT; k++) NEED(ev_is(at + 5 + k, EV_READ, reg_name[k]));
    e = at + 5 + R_COUNT;
    for (unsigned k = 0; k < R_COUNT; k++) {
        now[k] = log_[at + 5 + k].value;
        if (now[k] == m->reg[k]) continue;
        NEED(retry_ok(e, k));
        now[k] = log_[e + 2].value;
        retried |= 1u << k;
        e += 3;
    }
    for (unsigned i = e; i < log_n; i++) NEED(log_[i].kind == EV_LINE);
    NEED(line_is(11, PFX "READBACK HCR_EL2=0X%llX CNTHCTL_EL2=0X%llX", U(rb[0]), U(rb[1])));
    NEED(line_is(12, PFX "READBACK SCTLR_EL1=0X%llX VBAR_EL1_OFFSET=0X%llX", U(rb[2]), U(rb[3] - m->base)));
    block = restore_block(m, retried, now, p->final);
    NEED(block);
    if (!p->held) NEED(line_is(13, PFX "REFUSED=WRITE_NOT_HELD") && lines_n() == 14 + block);
    else if (m->scenario == SC_NORMAL) NEED(access_page_ok(m, rb[R_CNTHCTL]) && lines_n() == 19 + block);
    else NEED(!strncmp(line_n(13), PFX "EXCURSION ", strlen(PFX) + 10) && !has_prefix(PFX "VERDICT") && has_line(PFX "ACCESSES_NOT_CLASSIFIED"));
    return NULL;
}

/* The wait: eight seconds of the counter after the NEXT line began it, to the read that ended it and not one read later. */
static int waited_ok(const struct world *m)
{
    uint64_t hz = plausible_hz(m->cntfrq) ? m->cntfrq : 19200000u, began, last, prev;
    int next = event_of_line(PFX "NEXT EL1 EXCURSION AFTER 8 S"), cache = -1;
    for (unsigned i = 0; i < log_n && cache < 0; i++) if (log_[i].kind == EV_CACHE) cache = (int)i;
    if (next < 0 || cache < 0) return 0;
    began = counter_value(log_[next].reads + 1);
    last = counter_value(log_[cache].reads);
    prev = counter_value(log_[cache].reads - 1);
    return last - began >= SECONDS * hz && prev - began < SECONDS * hz;
}

enum { T_REFUSED, T_STUCK, T_PROBE_FAILED, T_NOT_HELD, T_RAN_NORMAL, T_RAN_END, T_NOT_RESTORED, T_COUNT };
static unsigned tally[T_COUNT];

static int run_checked(uint64_t *ret)
{
    struct prediction p;
    struct q1n1_payload_args a = args();
    const char *broken;
    *ret = go(&a);
    predict(&before, &p);
    tally[p.refusal ? (p.waited ? T_STUCK : T_REFUSED) : p.probe_failed ? T_PROBE_FAILED : !p.held ? T_NOT_HELD :
          before.scenario == SC_NORMAL ? T_RAN_NORMAL : T_RAN_END]++;
    tally[T_NOT_RESTORED] += p.ret == 3;
    broken = rules(*ret, &p);
    if (!broken && p.waited && !p.refusal && !waited_ok(&before)) broken = "the wait is not eight seconds to the read";
    if (broken) {
        fprintf(stderr, "RULE BROKEN: %s (return %#llx, predicted %#llx)\n", broken, U(*ret), U(p.ret));
        dump_page();
        if (bad_lines) fprintf(stderr, "  bad line: %s\n", first_bad);
    }
    return broken != NULL;
}

/* ---- Suites ---- */

#define CONTEXT_LINES \
    "CURRENTEL=0X8 HCR_EL2=0X88000010 E2H=0X0", "DAIF=0X3C0 SPSEL=0X1 CNTFRQ_EL0=0X124F800", \
    "ID_AA64MMFR0_EL1=0X2100032310201126 ECV=0X2", "ID_AA64PFR0_EL1=0X1301001121110222 EL1=0X2", \
    "OLD CNTHCTL_EL2=0X3 SCTLR_EL1=0X30C50838", "OLD VBAR_EL1=0X0 VBAR_EL2=0X5C155000", \
    "STUB_OFFSET=0X1000 EL1_VECTORS_OFFSET=0X800 EL2_VECTORS_OFFSET=0X0", "NEXT EL1 EXCURSION AFTER 8 S"
#define WRITES_LINES "HVC_AT_EL2=OK", "WRITES HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000 SCTLR_EL1=0X30500800", "NEXT EL1 EXCURSION", \
    "READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=0X6000", "READBACK SCTLR_EL1=0X30500800 VBAR_EL1_OFFSET=0X800"
#define EFFECTIVE_LINES \
    "CNTVCT_EL0 TRAPPED EC=0X18 ISS=0X34F801 ISS_OK=YES", "CNTV_CTL_EL0 TRAPPED EC=0X18 ISS=0X32F827 ISS_OK=YES", \
    "CNTFRQ_EL0 NOT_TRAPPED VALUE=0X124F800", "CNTPCT_EL0 CONTROL TRAPPED EC=0X18 ISS=0X32F861 ISS_OK=YES", \
    "VERDICT=TRAPS_EFFECTIVE BITS13_14_IN_READBACK=YES", "EXCURSION OK ENTRIES=0X4 TRAPS=0X3", "RESTORED=YES"

static int suite_order(void)
{
    static const char *const page[] = {CONTEXT_LINES, WRITES_LINES, EFFECTIVE_LINES};
    uint64_t ret;
    unit_like();
    CHECK(!run_checked(&ret) && ret == 0);
    CHECK(page_is(0, page, sizeof page / sizeof page[0]));
    CHECK(probes == 1 && runs == 1 && trap_mask == 11);
    return 0;
}

static int suite_accesses(void)
{
    /* writable CNTHCTL_EL2 bits, ECV traps effective, control trapped: the verdict, and the read-back that goes with it */
    static const struct { uint64_t writable; int ecv, control; const char *verdict, *readback; } worlds[] = {
        {0x1FFF, 1, 1, "TRAPS_INERT BITS13_14_IN_READBACK=NO", "0X0"},                          /* the bits do not stick */
        {0x6FFF, 0, 1, "TRAPS_INERT BITS13_14_IN_READBACK=YES", "0X6000"},                      /* they stick and trap nothing */
        {0x1FFF | BIT(14), 1, 1, "TRAPS_PARTIAL BITS13_14_IN_READBACK=PARTIAL", "0X4000"},      /* only bit 14 sticks */
        {0x6FFF, 1, 0, "CONTROL_NOT_TRAPPED BITS13_14_IN_READBACK=YES", "0X6000"},              /* the experiment is void */
    };
    uint64_t ret;
    for (unsigned mask = 0; mask < 16; mask++) {
        unsigned t[4], n = 0;
        unit_like();
        w.ecv_effective = mask & 1;
        w.control_traps = mask >> 1 & 1;
        w.cntfrq_traps = mask >> 2 & 1;
        w.iss_noise = mask >> 3 & 1 ? BIT(7 + 19 * (mask >> 2 & 1)) : 0;      /* Rt, or the class */
        CHECK(!run_checked(&ret) && ret == 0);
        t[0] = t[1] = (unsigned)w.ecv_effective;
        t[2] = (unsigned)w.cntfrq_traps;
        t[3] = (unsigned)w.control_traps;
        for (unsigned i = 0; i < 4; i++) n += t[i];
        CHECK(trap_mask == (t[0] | t[1] << 1 | t[2] << 2 | t[3] << 3));
        CHECK(line_is(17, PFX "VERDICT=%s BITS13_14_IN_READBACK=YES%s", !t[3] ? "CONTROL_NOT_TRAPPED" : t[0] && t[1] ? "TRAPS_EFFECTIVE" :
                      !t[0] && !t[1] ? "TRAPS_INERT" : "TRAPS_PARTIAL", t[2] ? " CNTFRQ_EL0_TRAPPED" : ""));
        CHECK(line_is(18, PFX "EXCURSION OK ENTRIES=0X%X TRAPS=0X%X", n + 1, n));
    }
    for (unsigned i = 0; i < sizeof worlds / sizeof worlds[0]; i++) {
        unit_like();
        w.writable[R_CNTHCTL] = worlds[i].writable;
        w.ecv_effective = worlds[i].ecv;
        w.control_traps = worlds[i].control;
        CHECK(!run_checked(&ret) && ret == 0);
        CHECK(line_is(17, PFX "VERDICT=%s", worlds[i].verdict) && line_is(11, PFX "READBACK HCR_EL2=0X80000000 CNTHCTL_EL2=%s", worlds[i].readback));
    }
    /* The control traps because EL1PCTEN is clear in what the payload writes, not because of what CNTHCTL_EL2 held. */
    unit_like();
    w.reg[R_CNTHCTL] = 1;
    CHECK(!run_checked(&ret) && line_is(17, PFX "VERDICT=TRAPS_EFFECTIVE BITS13_14_IN_READBACK=YES") && w.reg[R_CNTHCTL] == 1);
    return 0;
}

static int suite_ends(void)
{
    static const struct { int scenario; uint64_t k; unsigned entries, traps, vector; const char *name; } ends[] = {
        {SC_EL1_EXC, 1, 2, 1, 8, "EL1_EXCEPTION"}, {SC_EL2_EXC, 2, 3, 2, 4, "EL2_EXCEPTION"}, {SC_CLASS, 4, 4, 3, 8, "UNEXPECTED_CLASS"},
        {SC_VECTOR, 4, 4, 3, 9, "UNEXPECTED_VECTOR"}, {SC_HVC_IMM, 4, 4, 3, 8, "UNEXPECTED_HVC_IMM"}, {SC_BUDGET, 4, 9, 8, 8, "BUDGET"},
        {SC_DEADLINE, 4, 4, 3, 8, "DEADLINE"}, {SC_NO_REASON, 4, 4, 3, 0, "NONE"},
    };
    uint64_t ret;
    for (unsigned i = 0; i < sizeof ends / sizeof ends[0]; i++) {
        unsigned at = ends[i].scenario == SC_EL1_EXC ? 18 : 16, none = ends[i].scenario == SC_NO_REASON;     /* none: nothing was recorded */
        unit_like();
        w.scenario = ends[i].scenario;
        w.k = ends[i].k;
        CHECK(!run_checked(&ret) && ret == 2);
        CHECK(line_is(13, PFX "EXCURSION %s ENTRIES=0X%X TRAPS=0X%X VECTOR=0X%X", ends[i].name, ends[i].entries, ends[i].traps, ends[i].vector));
        CHECK(line_is(14, PFX "ESR_EL2=0X%X ELR_EL2=0X%llX", none ? 0 : 0x96000045, U(none ? 0 : END_ELR)));
        CHECK(line_is(15, PFX "FAR_EL2=0X%llX SPSR_EL2=0X%llX", U(none ? 0 : END_FAR), U(none ? 0 : END_SPSR)));
        if (ends[i].scenario == SC_EL1_EXC) CHECK(line_is(16, PFX "ESR_EL1=0X2000000 ELR_EL1=0X5CB55200") && line_is(17, PFX "FAR_EL1=0X1122 EL1_VECTOR=0X4"));
        for (unsigned j = 0; j < ends[i].traps; j++) CHECK(!strncmp(line_n(at + j), PFX "TRAP ESR_EL2=0X", strlen(PFX) + 15));
        CHECK(line_is(at + ends[i].traps, PFX "ACCESSES_NOT_CLASSIFIED") && line_is(at + ends[i].traps + 1, PFX "RESTORED=YES") && lines_n() == at + ends[i].traps + 2);
        CHECK(!has_prefix(PFX "VERDICT") && !has_prefix(PFX "CNTVCT_EL0"));
    }
    /* A trap record is the ESR and the ELR of the instruction. */
    unit_like();
    w.scenario = SC_EL1_EXC;
    w.k = 1;
    CHECK(!run_checked(&ret) && line_is(18, PFX "TRAP ESR_EL2=0X6234F801 ELR_EL2=0X%llX", U(IMG_STUB)));
    /* The longest page of an end: eight trap records, and every register not put back. */
    unit_like();
    w.scenario = SC_BUDGET;
    for (unsigned r = 0; r < R_VBAR2; r++) w.restore[r] = RESTORE_NEVER;
    CHECK(!run_checked(&ret) && ret == 3 && lines_n() <= 40);
    return 0;
}

static int suite_probe(void)
{
    uint64_t ret;
    unit_like();                    /* UNDEFINED: nothing but VBAR_EL2 was written, and no EL1 code ran */
    w.probe = PROBE_FAILS;
    w.end_esr = 0;
    CHECK(!run_checked(&ret) && ret == 2 && writes_total == 0 && runs == 0 && probes == 1);
    CHECK(line_is(8, PFX "HVC_AT_EL2=FAILED EL2_EXCEPTION ENTRIES=0X1 VECTOR=0X4") && line_is(9, PFX "HVC_AT_EL2 ESR_EL2=0X0 ELR_EL2=0X5CB55123"));
    CHECK(line_is(10, PFX "REFUSED=HVC_AT_EL2") && line_is(11, PFX "RESTORED=YES") && lines_n() == 12);
    /* VBAR_EL2 left at the payload's table after each run: one write puts it back, after each. */
    unit_like();
    w.vbar2 = VBAR2_LATE;
    CHECK(!run_checked(&ret) && ret == 0 && write_count[R_VBAR2] == 2 && w.reg[R_VBAR2] == 0x5C155000);
    CHECK(has_line(PFX "RESTORE_RETRY VBAR_EL2 NOW=0X5C155000") && line_is(lines_n() - 1, PFX "RESTORED=YES"));
    unit_like();
    w.vbar2 = VBAR2_NEVER;
    CHECK(!run_checked(&ret) && ret == 3 && runs == 0 && writes_total == 1);
    CHECK(line_is(8, PFX "HVC_AT_EL2=FAILED NONE ENTRIES=0X1 VECTOR=0X4") && line_is(9, PFX "HVC_AT_EL2 ESR_EL2=0X0 ELR_EL2=0X0"));
    CHECK(line_is(11, PFX "RESTORE_RETRY VBAR_EL2 NOW=0X%llX", U(IMG_EL2)) && line_is(12, PFX "RESTORED=NO"));
    CHECK(line_is(13, PFX "NOT_RESTORED VBAR_EL2 WANT=0X5C155000 NOW=0X%llX", U(IMG_EL2)) && line_is(14, PFX "POWER_CYCLE_BEFORE_ANY_OTHER_PAYLOAD"));
    return 0;
}

static int suite_held(void)
{
    /* Each bit of HCR_EL2 and SCTLR_EL1 that decides whether EL1 can be entered, stuck at the value it must not have (not held) and at
     * the value it must have (held): RW must be set and the others clear. */
    static const unsigned hcr_bits[] = {0, 3, 4, 5, 27, 29, 31}, sctlr_bits[] = {0, 1, 2, 12, 19, 24, 25};
    /* Other failures: nothing writable, bits that come up set (E2H, a bit of VBAR_EL1, ECV), RES0 bits of VBAR_EL1, and bits 13 and 14
     * of CNTHCTL_EL2 that may not stick, which does not stop the run. */
    static const struct { unsigned reg; uint64_t writable, forced; int held; } rest[] = {
        {R_HCR, 0, 0, 0}, {R_HCR, ~UINT64_C(0), BIT(34), 0}, {R_SCTLR, 0, 0, 1}, {R_VBAR1, 0, 0, 0}, {R_VBAR1, ~UINT64_C(0), BIT(60), 0},
        {R_VBAR1, ~UINT64_C(0x7FF), 0, 1}, {R_CNTHCTL, ~UINT64_C(0), ECV, 0}, {R_CNTHCTL, 0x1FFF, 0, 1}, {R_CNTHCTL, 0x2000, 0, 1},
    };
    uint64_t ret;
    for (unsigned reg = R_HCR; reg <= R_SCTLR; reg += 2)
        for (unsigned i = 0; i < 7; i++)
            for (unsigned right = 0; right < 2; right++) {
                unsigned bit = reg == R_HCR ? hcr_bits[i] : sctlr_bits[i], wanted = reg == R_HCR && bit == 31;
                unit_like();
                w.reg[reg] = (w.reg[reg] & ~BIT(bit)) | (uint64_t)(right ? wanted : !wanted) << bit;
                w.writable[reg] = ~BIT(bit);
                if (run_checked(&ret)) { fprintf(stderr, "%s bit %u stuck %s\n", reg_name[reg], bit, right ? "right" : "wrong"); return 1; }
                CHECK(right ? runs == 1 && ret == 0 : runs == 0 && ret == 2 && has_line(PFX "REFUSED=WRITE_NOT_HELD") && line_is(lines_n() - 1, PFX "RESTORED=YES"));
            }
    for (unsigned i = 0; i < sizeof rest / sizeof rest[0]; i++) {
        unit_like();
        w.writable[rest[i].reg] = rest[i].writable;
        w.forced[rest[i].reg] = rest[i].forced;
        if (run_checked(&ret)) { fprintf(stderr, "held case %u\n", i); return 1; }
        CHECK(rest[i].held ? runs == 1 && ret == 0 : runs == 0 && ret == 2 && has_line(PFX "REFUSED=WRITE_NOT_HELD"));
    }
    return 0;
}

static int suite_refuse(void)
{
#define AT(field) offsetof(struct world, field)
    /* One edit of the unit's world each, and the line that ends the page. */
    static const struct { size_t at; uint64_t value; const char *line; } worlds[] = {
        {AT(el_raw), 3 << 2, "SKIPPED_NOT_AT_EL2"}, {AT(no_counter_op), 1, "REFUSED=NO_COUNTER"}, {AT(size), 4096 + 16, "REFUSED=ENTRY"},
        {AT(size), UINT64_C(1) << 32, "REFUSED=ENTRY"}, {AT(reg[R_HCR]), 0x88000010 | BIT(34), "REFUSED=E2H"},
        {AT(pfr0), UINT64_C(0x1301001121110202), "REFUSED=NO_EL1_AARCH64"}, {AT(daif), 0x340, "REFUSED=DAIF_NOT_MASKED"},
        {AT(spsel), 0, "REFUSED=SPSEL_NOT_EL2H"}, {AT(reg[R_CNTHCTL]), 0x1003, "REFUSED=OLD_HAS_BITS_12_TO_14"},
        {AT(reg[R_CNTHCTL]), 0x2003, "REFUSED=OLD_HAS_BITS_12_TO_14"}, {AT(reg[R_CNTHCTL]), 0x4003, "REFUSED=OLD_HAS_BITS_12_TO_14"},
        {AT(sp), 0x80000000 + 16384 - 16, "REFUSED=STACK"}, {AT(sp), 0x80000000 + 0x10000 + 16, "REFUSED=STACK"},
        {AT(every), 0, "REFUSED=COUNTER_STUCK"}, {AT(stall), STUCK_READS + 1, "REFUSED=COUNTER_STUCK"},
    };
    uint64_t ret;
    for (unsigned i = 0; i < sizeof worlds / sizeof worlds[0]; i++) {
        unit_like();
        memcpy((char *)&w + worlds[i].at, &worlds[i].value, sizeof(uint64_t));
        CHECK(!run_checked(&ret) && ret == 0 && writes_total == 0 && line_is(lines_n() - 1, PFX "%s", worlds[i].line));
    }
    unit_like();                    /* the EL2 vectors are below the image */
    w.base = IMG_EL2 + 2048;
    w.size = IMG_BYTES - 2048;
    CHECK(!run_checked(&ret) && line_is(lines_n() - 1, PFX "REFUSED=ENTRY"));
    unit_like();                    /* several at once: the first in the order */
    w.reg[R_HCR] |= BIT(34);
    w.daif = 0;
    w.spsel = 0;
    CHECK(!run_checked(&ret) && line_is(lines_n() - 1, PFX "REFUSED=E2H") && lines_n() == 8);
    /* The edges that are not refused: the least stack, the most, an image that ends with the stub, a counter that stalls a little less. */
    for (unsigned i = 0; i < 4; i++) {
        unit_like();
        w.sp = i == 0 ? w.stack_base + 16384 : i == 1 ? w.stack_base + w.stack_size : w.sp;
        w.size = i == 2 ? IMG_BYTES - 12 : w.size;
        w.stall = i == 3 ? STUCK_READS : 0;
        CHECK(!run_checked(&ret) && ret == 0 && runs == 1);
    }
    return 0;
}

static int suite_clock(void)
{
    static const uint64_t hz[] = {1000000u, 19200000u, 24000000u, 1000000000u, 0, 1, 999999u, 1000000001u, 0xFFFFFFFFFFFFFFFFull, UNIT_HZ};
    uint64_t ret;
    for (unsigned i = 0; i < sizeof hz / sizeof hz[0]; i++) {
        unit_like();
        w.cntfrq = hz[i];
        w.every = plausible_hz(hz[i]) ? hz[i] / 19 + 1 : 1000003;
        CHECK(!run_checked(&ret) && ret == 0 && runs == 1);
    }
    for (unsigned i = 0; i < 3; i++) {
        unit_like();
        w.cntfrq = i == 0 ? 1000000 : UNIT_HZ;
        w.every = i == 0 ? 1000000 : w.every;                       /* the counter lands exactly on eight seconds at a read */
        w.stall = i == 1 ? 1000000 : 0;                             /* a million reads on one value, then it runs: not stuck */
        w.start = i == 2 ? ~UINT64_C(0) - 100 * w.every : w.start;  /* the counter wraps in the middle of the wait */
        CHECK(!run_checked(&ret) && ret == 0);
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

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"order", suite_order}, {"accesses", suite_accesses}, {"ends", suite_ends}, {"probe", suite_probe}, {"held", suite_held},
        {"refuse", suite_refuse}, {"clock", suite_clock}, {"fuzz", suite_fuzz}, {"args", suite_args},
    };
    unsigned ran = 0;
    if (argc > 1 && !strcmp(argv[1], "lines-report")) return report_lines();
    if (argc > 1 && !strcmp(argv[1], "page")) return report_page();
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) { fprintf(stderr, "FAIL: suite %s\n", suites[i].name); return 1; }
        ran++;
    }
    printf("PASS: %u payload el1trap suites, %u checks\n", ran, checks);
    return 0;
}
