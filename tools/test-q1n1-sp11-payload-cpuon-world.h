/* SPDX-License-Identifier: MIT */
/* The world the cpuon host test (tools/test-q1n1-sp11-payload-cpuon.c) runs the payload in: a model of the machine, the rules
 * every run is held to, and an oracle of what the page must say. Header only, included once.
 *
 * The model. The counter advances a fixed step at every read, so waits are counted in reads and cost nothing. PSCI is scripted
 * per core (AFFINITY_INFO and CPU_ON only: any other function id is a tripwire). Memory has two copies: `memory` is what a core
 * with its caches off sees, `arena` is what the primary reads and writes, its cache. They agree only through cache operations:
 * DC CIVAC copies a line to memory, DC IVAC followed by a DSB brings memory back, and a started stub writes `memory` at its
 * scripted time. A payload that reads a slot without invalidating it, or invalidates without a DSB, or starts a core before its
 * slot and the image are clean in memory, or stores into a slot after the clean, fails here.
 *
 * `common` holds every run to: the page (font, 100 characters, 40 lines); only the two function ids; only table affinities,
 * never the boot CPU; a target only when it answered exactly OFF; the stub's address as the entry and a distinct slot of the stack
 * region as the context; a NEXT line and eight seconds of counter before every CPU_ON; nothing printed between the calls of a
 * batch; no dirty line invalidated; the image and the slots clean and fenced before the first start; no store into a slot
 * afterwards; a started core asked about at most once a millisecond. The `oracle` says what the documentation promises the page
 * says for a script, written here independently of the payload. Timing is the one thing it does not predict, so scripts keep
 * their delays away from the deadlines (1 s and 2 s to report, 2 s more to reach OFF). Evidence: EXPERIMENTAL (host model only). */
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#include "sp11-payload.h"

uint64_t payload_entry(const struct q1n1_payload_args *a);
extern char cpuon_entry[64];
extern char cpuon_vectors[2048];

#define CPUS 12u
#define ARENA 65536u
#define LINE 64u
#define SLOT 256u
#define SLOT_BASE 4096u
#define NEVER (~UINT64_C(0))
#define ID_CPU_ON 0xC4000003u
#define ID_AFFINITY_INFO 0xC4000004u
#define PFX "PAYLOAD CPUON "
/* The table and the names the payload is documented to use: the second, independent copy. */
static const uint64_t table[CPUS] = {0x0, 0x100, 0x200, 0x300, 0x10000, 0x10100, 0x10200, 0x10300, 0x20000, 0x20100, 0x20200, 0x20300};
static const char *const error_names[9] = {"NOT_SUPPORTED", "INVALID_PARAMETERS", "DENIED", "ALREADY_ON", "ON_PENDING",
                                           "INTERNAL_FAILURE", "NOT_PRESENT", "DISABLED", "INVALID_ADDRESS"};
static const char *const id_names[4] = {"MIDR", "MMFR0", "ISAR0", "PFR0"};
static const char *const why_names[8] = {"NOT_STARTED", "NO_REPORT", "NOT_EL2", "FAULT", "MPIDR", "IDS", "FRQ", "NOT_OFF"};
enum { WHY_NO_REPORT = 2, WHY_NOT_EL2 = 4, WHY_FAULT = 8, WHY_MPIDR = 16, WHY_IDS = 32, WHY_FRQ = 64, WHY_NOT_OFF = 128 };
/* The slot as the stub stores it: the word numbers of the contract in docs/SP11-PAYLOAD-CPUON.md. */
enum { W_DONE, W_EL, W_MPIDR, W_MIDR, W_SCTLR, W_HCR, W_VBAR, W_VOFF, W_FRQ, W_PCT, W_MMFR0, W_ISAR0, W_PFR0, W_ESR, W_ELR, W_FAR,
       W_VECTOR, W_STAGE, W_OFFRET, W_COUNT };
#define DONE_MAGIC UINT64_C(0x444F4E45)
enum { K_NONE, K_REPORT, K_OTHER_EL, K_FAULT, K_OFF_RETURNED };

/* ---- The script: what the machine does ------------------------------------------------------------------------------ */

struct core_script {
    uint64_t probe;             /* AFFINITY_INFO before any start */
    uint64_t on_ret;            /* x0 of CPU_ON */
    int64_t start_delay;        /* ticks from the CPU_ON call to the stub's CNTPCT read; may be negative */
    uint64_t report_ms;         /* when the done flag reaches memory, from the CPU_ON call; NEVER for no report */
    uint64_t off_ms;            /* when AFFINITY_INFO starts to say OFF; NEVER for never */
    unsigned kind, stage;       /* K_* the stub finishes with; the stage word of a stub that stops early */
    uint64_t el, mpidr_xor, frq, sctlr, hcr, vbar, vo, esr, elr, far, vector, off_ret, after_off;
    unsigned id_differ;         /* mask of MIDR, MMFR0, ISAR0, PFR0 that differ from the boot CPU's */
};
struct scenario {
    uint64_t boot_mpidr, cntfrq, id[4], step, stuck_from, el;
    int no_counter;
    struct core_script core[CPUS];
};
static struct scenario sc;
static uint64_t rng = 0x9e3779b97f4a7c15ull;
static uint64_t next_random(void)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}
static uint64_t model_freq(void) { return sc.cntfrq >= 1000000 && sc.cntfrq <= 1000000000 ? sc.cntfrq : 19200000; }
static uint64_t ms_ticks(uint64_t ms) { return model_freq() / 1000 * ms; }

static void script_default(void)
{
    memset(&sc, 0, sizeof sc);
    sc.boot_mpidr = 0x80000000;
    sc.cntfrq = 19200000;
    sc.id[0] = 0x512F0011; sc.id[1] = 0x1122; sc.id[2] = 0x3344; sc.id[3] = 0x5566;
    sc.step = 1920;                 /* 100 microseconds at 19.2 MHz */
    sc.stuck_from = NEVER;
    sc.el = 2;
    for (unsigned i = 0; i < CPUS; i++) {
        struct core_script *c = &sc.core[i];
        c->probe = 1; c->start_delay = 9600; c->report_ms = 3; c->off_ms = 7; c->kind = K_REPORT; c->el = 8;
        c->sctlr = 0x30C50830; c->hcr = 0x80000000; c->after_off = 1;
    }
    sc.core[0].probe = 0;
}

/* ---- The model ---------------------------------------------------------------------------------------------------- */

static uint8_t arena[ARENA] __attribute__((aligned(16384)));    /* the primary's view of its stack */
static uint8_t memory[ARENA], synced[ARENA];                    /* the truth, and what the view last agreed with it on */
static unsigned pending[64], n_pending;                         /* lines with DC IVAC issued and no DSB yet */
#define IMAGE_LINES 1024u
static uint64_t image_base, image_bytes;
static uint8_t image_clean[IMAGE_LINES];
#define MAX_LINES 96
#define MAX_SMC 32768
static struct {
    uint64_t now, reads, sp, next_at, on_at[CPUS], on_slot[CPUS], last_ai[CPUS];
    unsigned unfenced, nlines, bad_lines, nsmc, ncache, nsys, bad_smc, bad_start, early_start, between, dirty_lost, unclean_image,
        unclean_slot, unfenced_start, next_line, next_calls, lines_since_call, fast_poll;
    int on_ok[CPUS], on_count[CPUS], reported[CPUS], late[CPUS], next_valid;
    struct { char text[200]; uint64_t at; unsigned smc, cache; } line[MAX_LINES];
    struct { uint64_t id, x1, x2, x3, at; } smc[MAX_SMC];
    char sysregs[16][24];
} W;

static unsigned core_of(uint64_t affinity)
{
    for (unsigned i = 0; i < CPUS; i++) if (table[i] == affinity) return i;
    return CPUS;
}
/* From the first CPU_ON on, the first 16 KiB of the arena (one page here; the slots are in it and nothing else the payload may
 * touch) is read-only for the primary: a store into a slot after that point, even
 * of the value already there (a dirty line the secondary's own store could later be overwritten by), ends the run with a fault.
 * The model lifts it for an instant to apply an invalidate that completed. */
static int slots_locked;
static void slots_protect(int locked)
{
    if (mprotect(arena, 16384, locked ? PROT_READ : PROT_READ | PROT_WRITE)) {
        perror("mprotect");
        exit(3);
    }
}

static uint8_t *slot_memory(unsigned i) { return memory + (W.on_slot[i] - (uint64_t)(uintptr_t)arena); }

/* What the stub of core `i` stores into its slot: the report words, then the done flag last. */
static void stub_writes(unsigned i)
{
    const struct core_script *c = &sc.core[i];
    uint64_t w[W_COUNT] = {0};
    w[W_EL] = c->el;
    w[W_STAGE] = c->kind == K_OTHER_EL ? 1 : 3;
    if (c->kind == K_FAULT) {
        w[W_STAGE] = c->stage;
        w[W_ESR] = c->esr; w[W_ELR] = c->elr; w[W_FAR] = c->far; w[W_VECTOR] = c->vector;
    }
    if (c->kind == K_REPORT || c->kind == K_OFF_RETURNED || (c->kind == K_FAULT && c->stage >= 3)) {
        w[W_MPIDR] = (0x80000000 | table[i]) ^ c->mpidr_xor;
        w[W_MIDR] = sc.id[0] ^ ((c->id_differ & 1) ? 0x10 : 0);
        w[W_MMFR0] = sc.id[1] ^ ((c->id_differ & 2) ? 0x20 : 0);
        w[W_ISAR0] = sc.id[2] ^ ((c->id_differ & 4) ? 0x40 : 0);
        w[W_PFR0] = sc.id[3] ^ ((c->id_differ & 8) ? 0x80 : 0);
        w[W_SCTLR] = c->sctlr; w[W_HCR] = c->hcr; w[W_VBAR] = c->vbar; w[W_VOFF] = c->vo;
        w[W_FRQ] = c->frq ? c->frq : sc.cntfrq;
        w[W_PCT] = W.on_at[i] + (uint64_t)c->start_delay;
    }
    w[W_DONE] = (DONE_MAGIC << 32) | (c->kind == K_OFF_RETURNED ? K_REPORT : c->kind);
    for (unsigned k = W_COUNT; k-- > 0;) memcpy(slot_memory(i) + 8 * k, &w[k], 8);
}

/* Applies what the started cores have done by `now` to memory. */
static void world_tick(void)
{
    for (unsigned i = 1; i < CPUS; i++) {
        const struct core_script *c = &sc.core[i];
        if (!W.on_ok[i] || c->report_ms == NEVER) continue;
        if (!W.reported[i] && W.now >= W.on_at[i] + ms_ticks(c->report_ms)) {
            W.reported[i] = 1;
            stub_writes(i);
        }
        if (c->kind == K_OFF_RETURNED && W.reported[i] && !W.late[i] && W.now >= W.on_at[i] + ms_ticks(c->report_ms + 1)) {
            uint64_t done = (DONE_MAGIC << 32) | K_OFF_RETURNED;
            W.late[i] = 1;
            memcpy(slot_memory(i) + 8 * W_OFFRET, &c->off_ret, 8);
            memcpy(slot_memory(i), &done, 8);
        }
    }
}

static uint64_t state_of(unsigned i)
{
    const struct core_script *c = &sc.core[i];
    if (!W.on_ok[i]) return c->probe;
    return c->off_ms != NEVER && W.now >= W.on_at[i] + ms_ticks(c->off_ms) ? c->after_off : 0;
}

uint64_t pl_host_sysreg(const char *name);
uint64_t pl_host_sysreg(const char *name)
{
    if (W.nsys < 16) snprintf(W.sysregs[W.nsys], sizeof W.sysregs[0], "%s", name);
    W.nsys++;
    if (!strcmp(name, "CurrentEL")) return sc.el << 2;
    if (!strcmp(name, "mpidr_el1")) return sc.boot_mpidr;
    if (!strcmp(name, "CNTFRQ_EL0")) return sc.cntfrq;
    if (!strcmp(name, "midr_el1")) return sc.id[0];
    if (!strcmp(name, "id_aa64mmfr0_el1")) return sc.id[1];
    if (!strcmp(name, "id_aa64isar0_el1")) return sc.id[2];
    if (!strcmp(name, "id_aa64pfr0_el1")) return sc.id[3];
    fprintf(stderr, "FAIL: the payload read a register the test does not know: %s\n", name);
    exit(3);
}

uint64_t pl_host_stack_pointer(void);
uint64_t pl_host_stack_pointer(void) { return W.sp; }

void pl_host_cache(const char *operation, uint64_t address);
void pl_host_cache(const char *operation, uint64_t address)
{
    uint64_t base = (uint64_t)(uintptr_t)arena, line = (address - base) & ~(uint64_t)(LINE - 1);
    int in_arena = address >= base && address < base + ARENA;
    world_tick();
    W.ncache++;
    if (!strcmp(operation, "civac") && in_arena) {
        memcpy(memory + line, arena + line, LINE);
        memcpy(synced + line, arena + line, LINE);
        W.unfenced = 1;
    } else if (!strcmp(operation, "civac") && address >= image_base && address < image_base + image_bytes) {
        image_clean[(address - image_base) / LINE] = 1;
        W.unfenced = 1;
    } else if (!strcmp(operation, "ivac") && in_arena) {
        if (memcmp(arena + line, synced + line, LINE)) W.dirty_lost++;
        if (n_pending < 64) pending[n_pending++] = (unsigned)line;
    } else if (!strcmp(operation, "dsb")) {
        int lifted = 0;
        W.unfenced = 0;
        for (unsigned k = 0; k < n_pending; k++) {
            if (memcmp(arena + pending[k], memory + pending[k], LINE)) {
                if (slots_locked && !lifted) slots_protect(0), lifted = 1;
                memcpy(arena + pending[k], memory + pending[k], LINE);
            }
            memcpy(synced + pending[k], memory + pending[k], LINE);
        }
        if (lifted) slots_protect(1);
        n_pending = 0;
    } else {
        fprintf(stderr, "FAIL: cache operation %s at 0x%" PRIx64 " outside what the payload may touch\n", operation, address);
        exit(3);
    }
}

static uint64_t fake_counter(void)
{
    uint64_t value;
    world_tick();
    value = W.now;
    if (W.reads < sc.stuck_from) W.now += sc.step;
    W.reads++;
    return value;
}

static int in_font(const char *text)
{
    for (; *text; text++)
        if (!((*text >= 'A' && *text <= 'Z') || (*text >= '0' && *text <= '9') || strchr(" :-./=?()_", *text))) return 0;
    return 1;
}
static void fake_puts(const char *line)
{
    world_tick();
    if (W.nlines < MAX_LINES) {
        snprintf(W.line[W.nlines].text, sizeof W.line[0].text, "%.199s", line);
        W.line[W.nlines].at = W.now;
        W.line[W.nlines].smc = W.nsmc;
        W.line[W.nlines].cache = W.ncache;
    }
    if (strlen(line) > Q1N1_PAYLOAD_LINE_MAX || !in_font(line)) W.bad_lines++;
    if (!strncmp(line, PFX "NEXT CPU_ON", 25)) {
        W.next_valid = 1; W.next_at = W.now; W.next_line = W.nlines; W.next_calls = 0;
    }
    W.nlines++;
    W.lines_since_call = 1;
}
static uint32_t fake_hex(char *dst, uint32_t cap, uint64_t value) { return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value); }
static int32_t fake_load32(uint64_t addr, uint32_t *out) { (void)addr; (void)out; fprintf(stderr, "FAIL: cpuon used load32\n"); exit(3); }

static int slot_ok(uint64_t context)
{
    uint64_t base = (uint64_t)(uintptr_t)arena + SLOT_BASE;
    return context >= base && context < base + CPUS * SLOT && !((context - base) % SLOT);
}

/* The scripted SMC. A function id the test does not know, an affinity that is not in the table, and every rule of starting a
 * core are checked at the moment of the call. */
void pl_host_smc(uint64_t regs[4]);
void pl_host_smc(uint64_t regs[4])
{
    uint64_t reply = ~UINT64_C(0), boot = sc.boot_mpidr & UINT64_C(0xff00ffffff), base = (uint64_t)(uintptr_t)arena;
    unsigned i = core_of(regs[1]);
    world_tick();
    if (W.nsmc < MAX_SMC) {
        W.smc[W.nsmc].id = regs[0]; W.smc[W.nsmc].x1 = regs[1]; W.smc[W.nsmc].x2 = regs[2]; W.smc[W.nsmc].x3 = regs[3];
        W.smc[W.nsmc].at = W.now;
    }
    W.nsmc++;
    if (regs[0] == ID_AFFINITY_INFO) {
        if (i == CPUS || i == 0 || regs[2] || regs[3] || regs[1] == boot) W.bad_smc++;
        else reply = state_of(i);
        /* A started core is asked at most once a millisecond: the secure world is not polled as fast as a loop can go. */
        if (i < CPUS && W.on_ok[i]) {
            if (W.last_ai[i] && W.now - W.last_ai[i] < ms_ticks(1) / 10 * 9) W.fast_poll++;
            W.last_ai[i] = W.now;
        }
    } else if (regs[0] == ID_CPU_ON && i != CPUS && i != 0 && regs[1] != boot) {
        W.on_count[i]++;
        if (!slots_locked) {
            slots_locked = 1;
            slots_protect(1);
        }
        if (state_of(i) != 1) W.bad_start++;                                    /* only a core that answers exactly OFF */
        if (regs[2] != (uint64_t)(uintptr_t)cpuon_entry || !slot_ok(regs[3])) W.bad_start++;
        for (unsigned k = 1; k < CPUS; k++) if (k != i && W.on_count[k] && W.on_slot[k] == regs[3]) W.bad_start++;
        /* The wait: a NEXT line for this call, eight seconds of counter after it (the line for a single core names it, the line
         * for all allows the whole batch), and nothing printed between the calls of a batch. */
        if (!W.next_valid || W.now - W.next_at < 8 * model_freq()) W.early_start++;
        else if (strstr(W.line[W.next_line].text, " ALL ")) W.next_calls++;
        else if (W.next_calls++ || regs[1] != 0x100) W.early_start++;
        if (W.nsmc >= 2 && W.smc[W.nsmc - 2].id == ID_CPU_ON && W.lines_since_call) W.between++;
        W.lines_since_call = 0;
        /* What the secondary will fetch and write must be in memory, and fenced. */
        for (uint64_t at = 0; at < image_bytes; at += LINE) if (!image_clean[at / LINE]) { W.unclean_image++; break; }
        if (slot_ok(regs[3]))
            for (unsigned b = 0; b < SLOT; b++)
                if (memory[regs[3] - base + b] || arena[regs[3] - base + b]) { W.unclean_slot++; break; }
        if (W.unfenced) W.unfenced_start++;
        reply = sc.core[i].on_ret;
        if ((uint32_t)reply == 0) {
            W.on_ok[i] = 1; W.on_at[i] = W.now; W.on_slot[i] = regs[3]; W.reported[i] = W.late[i] = 0;
            /* A stub that stops early has stored its stage and CurrentEL by now, whatever else it does. */
            if (sc.core[i].report_ms == NEVER && sc.core[i].stage) {
                uint64_t stage = sc.core[i].stage, el = sc.core[i].el;
                memcpy(slot_memory(i) + 8 * W_STAGE, &stage, 8);
                memcpy(slot_memory(i) + 8 * W_EL, &el, 8);
            }
        }
    } else {
        W.bad_smc++;
        if (regs[0] == ID_CPU_ON) W.bad_start++;                                /* a target that is not one, or the boot CPU */
    }
    regs[0] = reply;
    regs[1] = regs[2] = regs[3] = 0xdeadbeef;
}

static struct q1n1_payload_args args(void)
{
    struct q1n1_payload_args a;
    memset(&a, 0, sizeof a);
    a.magic = Q1N1_PAYLOAD_ABI_MAGIC; a.version = Q1N1_PAYLOAD_ABI_VERSION; a.size = sizeof a;
    a.payload_base = image_base; a.payload_size = image_bytes;
    a.stack_base = (uint64_t)(uintptr_t)arena; a.stack_size = ARENA;
    a.ops.puts = fake_puts; a.ops.hex = fake_hex; a.ops.load32 = fake_load32;
    a.ops.counter = sc.no_counter ? NULL : fake_counter;
    return a;
}

static void world_reset(void)
{
    uint64_t a = (uint64_t)(uintptr_t)cpuon_entry, b = (uint64_t)(uintptr_t)cpuon_vectors;
    uint64_t lo = (a < b ? a : b) & ~UINT64_C(4095), hi = ((a > b ? a + 64 : b + 2048) + 4095) & ~UINT64_C(4095);
    image_base = lo - 8192;                     /* an image larger than the stub: the payload must clean all of it */
    image_bytes = hi - lo + 16384;
    if (slots_locked) slots_protect(0);
    slots_locked = 0;
    memset(&W, 0, sizeof W);
    memset(image_clean, 0, sizeof image_clean);
    n_pending = 0;
    /* A used stack: junk in memory and in the view, so that the payload has to clear the slots and carry the zeros out. */
    for (unsigned i = 0; i < ARENA; i++) memory[i] = (uint8_t)(0xC3 ^ i);
    memcpy(arena, memory, ARENA);
    memcpy(synced, memory, ARENA);
    W.sp = (uint64_t)(uintptr_t)arena + ARENA - 512;
    W.now = 1000;
}

/* ---- What the page must say: the oracle ----------------------------------------------------------------------------- */

static char want[MAX_LINES][200];
static unsigned n_want;
static char items[32][96];
static unsigned n_items;
static void ex(const char *format, ...)
{
    va_list ap;
    int n = snprintf(want[n_want], sizeof want[0], PFX);
    va_start(ap, format);
    vsnprintf(want[n_want] + n, sizeof want[0] - (size_t)n, format, ap);
    va_end(ap);
    n_want++;
}
static void it(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vsnprintf(items[n_items++], sizeof items[0], format, ap);
    va_end(ap);
}
/* The entries, packed into lines of at most 100 characters under one label, an entry never cut. */
static void flush(const char *label)
{
    char text[200] = "";
    for (unsigned i = 0; i < n_items; i++) {
        if (text[0] && 14 + strlen(label) + strlen(text) + 1 + strlen(items[i]) > 100) { ex("%s%s", label, text); text[0] = 0; }
        strcat(text, " ");
        strcat(text, items[i]);
    }
    if (text[0]) ex("%s%s", label, text);
    n_items = 0;
}
static const char *state_text(uint64_t raw, char *out)
{
    uint32_t negated = 0u - (uint32_t)raw;
    if (raw <= 2) return raw == 0 ? "ON" : raw == 1 ? "OFF" : "ON_PENDING";
    if (negated >= 1 && negated <= 9) snprintf(out, 64, "%s(-%u)", error_names[negated - 1], negated);
    else snprintf(out, 64, "0X%" PRIX64, raw);
    return out;
}
static const char *suffix_of(uint64_t raw, char *out)
{
    uint32_t negated = 0u - (uint32_t)raw;
    out[0] = 0;
    if ((uint32_t)raw == 0) snprintf(out, 64, ":SUCCESS");
    else if (negated >= 1 && negated <= 9) snprintf(out, 64, ":%s(-%u)", error_names[negated - 1], negated);
    return out;
}
static int64_t us_of(int64_t ticks)
{
    uint64_t m = ticks < 0 ? UINT64_C(0) - (uint64_t)ticks : (uint64_t)ticks;
    if (m > UINT64_C(1) << 43) m = UINT64_C(1) << 43;
    return ticks < 0 ? -(int64_t)(m * 1000000u / model_freq()) : (int64_t)(m * 1000000u / model_freq());
}
static int seen_off(const struct core_script *c) { return c->off_ms != NEVER && c->off_ms < 3000; }
static int off_ok(const struct core_script *c) { return seen_off(c) && c->after_off == 1; }
static int mpidr_bad(const struct core_script *c) { return (c->mpidr_xor & UINT64_C(0xff00ffffff)) != 0; }
static int frq_bad(const struct core_script *c) { return c->frq && c->frq != sc.cntfrq; }

/* The lines of one core that reported; returns why it is not a normal one, as the bits of why_names. */
static unsigned ex_core(unsigned phase, unsigned i)
{
    const struct core_script *c = &sc.core[i];
    char label[64];
    unsigned why = 0;
    snprintf(label, sizeof label, "P%u 0X%" PRIX64, phase, table[i]);
    if ((c->el >> 2 & 3) != 2 || c->kind == K_OTHER_EL) why |= WHY_NOT_EL2;
    if (c->kind == K_OTHER_EL) {
        ex("%s ENTERED_AT_EL%" PRIu64 " NOT_EL2 CURRENTEL=0X%" PRIX64, label, c->el >> 2 & 3, c->el);
        return why;
    }
    if (c->kind == K_FAULT) {
        it("FAULT"); it("STAGE=%u", c->stage); it("VECTOR=%" PRIu64, c->vector); it("ESR_EL2=0X%" PRIX64, c->esr);
        it("ELR_EL2=0X%" PRIX64, c->elr); it("FAR_EL2=0X%" PRIX64, c->far);
        flush(label);
        why |= WHY_FAULT;
        if (c->stage < 3) return why;
    } else {
        why |= (mpidr_bad(c) ? WHY_MPIDR : 0) | (c->id_differ ? WHY_IDS : 0) | (frq_bad(c) ? WHY_FRQ : 0);
    }
    it("EL=%" PRIu64, c->el >> 2 & 3);
    if (mpidr_bad(c)) it("MPIDR=0X%" PRIX64, (0x80000000 | table[i]) ^ c->mpidr_xor); else it("MPIDR=OK");
    if (!c->id_differ) it("IDS=SAME");
    else {
        char joined[64] = "IDS=";
        for (unsigned k = 0, n = 0; k < 4; k++) if (c->id_differ >> k & 1) { if (n++) strcat(joined, "/"); strcat(joined, id_names[k]); }
        it("%s", joined);
    }
    if (frq_bad(c)) it("FRQ=0X%" PRIX64, c->frq); else it("FRQ=SAME");
    it("CNTVOFF_EL2=0X%" PRIX64, c->vo);
    it("DT_US=%" PRId64, us_of(c->start_delay));
    flush(label);
    it("SCTLR_EL2=0X%" PRIX64, c->sctlr); it("HCR_EL2=0X%" PRIX64, c->hcr); it("VBAR_EL2=0X%" PRIX64, c->vbar);
    flush(label);
    if (c->id_differ) {
        static const uint64_t delta[4] = {0x10, 0x20, 0x40, 0x80};
        for (unsigned k = 0; k < 4; k++)
            if (c->id_differ >> k & 1) it("%s=0X%" PRIX64 "/BOOT=0X%" PRIX64, id_names[k], sc.id[k] ^ delta[k], sc.id[k]);
        flush(label);
    }
    return why;
}

/* The lines of a started core that did not reach OFF: what it last answered, and what its slot says. */
static void ex_still_on(unsigned phase, unsigned i, unsigned reported)
{
    const struct core_script *c = &sc.core[i];
    char label[64], buf[64], suffix[64];
    snprintf(label, sizeof label, "P%u 0X%" PRIX64, phase, table[i]);
    it("STILL_ON LAST=%s", state_text(seen_off(c) ? c->after_off : 0, buf));
    if (reported) {
        it("KIND=%u", c->kind);
        if (c->kind == K_OFF_RETURNED) it("CPU_OFF_RET=0X%" PRIX64 "%s", c->off_ret, suffix_of(c->off_ret, suffix));
        if (c->kind == K_FAULT) { it("ESR_EL2=0X%" PRIX64, c->esr); it("ELR_EL2=0X%" PRIX64, c->elr); }
    }
    flush(label);
}

static unsigned oracle_started, oracle_reported, oracle_off, oracle_left;

/* The payload keeps room for its six essential lines (the four NEXT lines, the summary, what was not done): any other line that
 * would leave less is dropped and counted, and the count goes on the summary line. */
static void apply_budget(void)
{
    unsigned used = 0, left = 6, suppressed = 0, kept = 0;
    for (unsigned i = 0; i < n_want; i++) {
        const char *text = want[i] + 14;
        int essential = !strncmp(text, "NEXT ", 5) || !strncmp(text, "CORES ", 6) || !strncmp(text, "NOT_DONE ", 9);
        if (essential) { if (left) left--; }
        else if (used + left >= Q1N1_PAYLOAD_LINES_MAX) { suppressed++; continue; }
        used++;
        if (kept != i) memcpy(want[kept], want[i], sizeof want[0]);
        kept++;
    }
    n_want = kept;
    if (suppressed) {
        size_t n = strlen(want[n_want - 2]);
        snprintf(want[n_want - 2] + n, sizeof want[0] - n, " SUPPRESSED=%u", suppressed);
    }
}

static void ex_reasons(const char *label, unsigned why)
{
    char text[128] = "ABNORMAL=";
    if (!why) { ex("%s NORMAL", label); return; }
    for (unsigned k = 0, n = 0; k < 8; k++) if (why >> k & 1) { if (n++) strcat(text, "/"); strcat(text, why_names[k]); }
    ex("%s %s", label, text);
}

static void oracle(void)
{
    unsigned eligible[CPUS] = {0}, normal = 0, why = 0;
    uint64_t boot = sc.boot_mpidr & UINT64_C(0xff00ffffff);
    char buf[64], suffix[64];
    n_want = n_items = 0;
    oracle_started = oracle_reported = oracle_off = oracle_left = 0;
    if (sc.el != 2) { ex("SKIPPED_NOT_AT_EL2"); return; }
    ex("BOOT_CPU MPIDR_EL1=0X%" PRIX64 " CNTFRQ_EL0=0X%" PRIX64 "%s", sc.boot_mpidr, sc.cntfrq, model_freq() == sc.cntfrq ? "" : " FREQ=DEFAULT");
    ex("NEXT AFFINITY");
    for (unsigned i = 1; i < CPUS; i++) {
        eligible[i] = table[i] != boot && sc.core[i].probe == 1;
        if (table[i] == boot) it("0X%" PRIX64 "=BOOT_CPU", table[i]);
        else it("0X%" PRIX64 "=%s", table[i], state_text(sc.core[i].probe, buf));
    }
    flush("AFFINITY");
    for (unsigned i = 1; i < CPUS; i++) if (!eligible[i]) it("0X%" PRIX64, table[i]);
    flush("SKIP_NOT_OFF");
    if (!eligible[1]) {
        ex("P1 SKIPPED=NOT_OFF");
    } else {
        const struct core_script *c = &sc.core[1];
        unsigned seen = c->report_ms != NEVER && c->report_ms < 1000, off = off_ok(c);
        ex("NEXT PREPARE");
        ex("NEXT CPU_ON 0X100 AFTER 8 S");
        ex("P1 CPU_ON 0X100 RET=0X%" PRIX64 "%s", c->on_ret, suffix_of(c->on_ret, suffix));
        if ((uint32_t)c->on_ret != 0) {
            ex("P1 ABNORMAL=NOT_STARTED");
        } else {
            if (seen) why |= ex_core(1, 1);
            else { unsigned stage = c->report_ms == NEVER ? c->stage : 0; ex("P1 0X100 NO_REPORT STAGE=%u CURRENTEL=0X%" PRIX64, stage, stage ? c->el : 0); why |= WHY_NO_REPORT; }
            ex("P1 POWER_OFF OFF=%u NOT_OFF=%u", off, !off);
            if (!off) {
                it("0X100=%s", state_text(seen_off(c) ? c->after_off : 0, buf));
                flush("P1 NOT_OFF");
                ex_still_on(1, 1, seen);
                why |= WHY_NOT_OFF;
            }
            ex_reasons("P1", why);
            normal = !why;
            oracle_started = 1; oracle_reported = seen; oracle_off = off;
        }
    }
    if (!normal) {
        ex("P2 SKIPPED=P1_NOT_NORMAL");
    } else {
        unsigned issued = 0, ok = 0, list[CPUS], n = 0, reported = 0, off = 0;
        ex("NEXT CPU_ON ALL AFTER 8 S");
        for (unsigned i = 1; i < CPUS; i++) if (eligible[i]) { issued++; ok += (uint32_t)sc.core[i].on_ret == 0; }
        it("ISSUED=%u", issued); it("SUCCESS=%u", ok);
        flush("P2 CPU_ON");
        for (unsigned i = 1; i < CPUS; i++) {
            uint32_t negated = 0u - (uint32_t)sc.core[i].on_ret;
            if (!eligible[i] || (uint32_t)sc.core[i].on_ret == 0) continue;
            if (negated >= 1 && negated <= 9) it("0X%" PRIX64 "=%s(-%u)", table[i], error_names[negated - 1], negated);
            else it("0X%" PRIX64 "=0X%" PRIX64, table[i], sc.core[i].on_ret);
        }
        flush("P2 CPU_ON_FAILED");
        for (unsigned i = 1; i < CPUS; i++) if (eligible[i] && (uint32_t)sc.core[i].on_ret == 0) list[n++] = i;
        for (unsigned k = 0; k < n; k++) {
            const struct core_script *c = &sc.core[list[k]];
            if (c->report_ms != NEVER && c->report_ms < 2000) {
                reported++;
                ex_core(2, list[k]);
            } else {
                unsigned stage = c->report_ms == NEVER ? c->stage : 0;
                ex("P2 0X%" PRIX64 " NO_REPORT STAGE=%u CURRENTEL=0X%" PRIX64, table[list[k]], stage, stage ? c->el : 0);
            }
        }
        for (unsigned k = 0; k < n; k++) off += off_ok(&sc.core[list[k]]);
        ex("P2 POWER_OFF OFF=%u NOT_OFF=%u", off, n - off);
        for (unsigned k = 0; k < n; k++)
            if (!off_ok(&sc.core[list[k]])) it("0X%" PRIX64 "=%s", table[list[k]], state_text(seen_off(&sc.core[list[k]]) ? sc.core[list[k]].after_off : 0, buf));
        flush("P2 NOT_OFF");
        for (unsigned k = 0; k < n; k++)
            if (!off_ok(&sc.core[list[k]])) ex_still_on(2, list[k], sc.core[list[k]].report_ms != NEVER && sc.core[list[k]].report_ms < 2000);
        oracle_started = n; oracle_reported = reported; oracle_off = off;
    }
    /* A core left running counts from either phase. */
    if (eligible[1] && (uint32_t)sc.core[1].on_ret == 0 && !off_ok(&sc.core[1])) oracle_left++;
    if (normal)
        for (unsigned i = 1; i < CPUS; i++) oracle_left += eligible[i] && (uint32_t)sc.core[i].on_ret == 0 && !off_ok(&sc.core[i]);
    ex("CORES STARTED=%u REPORTED=%u OFF=%u", oracle_started, oracle_reported, oracle_off);
    ex("NOT_DONE NO_SYSTEM_OFF_RESET_SUSPEND NO_CPU_SUSPEND BOOT_CPU_NO_MSR LEFT_RUNNING=%u", oracle_left);
    apply_budget();
}

/* ---- Checking a run ------------------------------------------------------------------------------------------------- */

static int has(const char *text)
{
    for (unsigned i = 0; i < W.nlines && i < MAX_LINES; i++) if (!strcmp(W.line[i].text, text)) return 1;
    return 0;
}
static int contains(const char *needle)
{
    for (unsigned i = 0; i < W.nlines && i < MAX_LINES; i++) if (strstr(W.line[i].text, needle)) return 1;
    return 0;
}
static unsigned count_with(const char *prefix)
{
    unsigned n = 0;
    for (unsigned i = 0; i < W.nlines && i < MAX_LINES; i++) n += !strncmp(W.line[i].text, prefix, strlen(prefix));
    return n;
}

static int page_is_oracle(const char *what)
{
    oracle();
    for (unsigned i = 0; i < n_want || i < W.nlines; i++) {
        if (i >= n_want || i >= W.nlines || strcmp(want[i], W.line[i].text)) {
            fprintf(stderr, "%s: line %u: got '%s', wanted '%s'\n", what, i, i < W.nlines ? W.line[i].text : "(nothing)", i < n_want ? want[i] : "(nothing)");
            return 0;
        }
    }
    return 1;
}

/* The rules that hold in every run, whatever the script. */
static int common(const char *what)
{
    int ok = 1;
#define RULE(count, text) do { if (count) { fprintf(stderr, "%s: %u times: %s\n", what, (unsigned)(count), text); ok = 0; } } while (0)
    RULE(W.bad_lines, "a line outside the page font or over 100 characters");
    RULE(W.nlines > Q1N1_PAYLOAD_LINES_MAX, "more lines than the ABI allows");
    RULE(W.bad_smc, "an SMC that is not AFFINITY_INFO of a target");
    RULE(W.bad_start, "a CPU_ON that breaks a rule of the target, the entry or the slot");
    RULE(W.early_start, "a CPU_ON without its NEXT line and eight seconds");
    RULE(W.between, "a line printed between the calls of a batch");
    RULE(W.dirty_lost, "a dirty line invalidated");
    RULE(W.unclean_image, "a core started with the image not clean in memory");
    RULE(W.unclean_slot, "a core started with its slot not zero in memory");
    RULE(W.unfenced_start, "a core started with the cache maintenance not fenced");
    RULE(W.fast_poll, "AFFINITY_INFO of a started core less than a millisecond after the last");
    for (unsigned i = 1; i < CPUS; i++) RULE(W.on_count[i] > (i == 1 ? 2 : 1), "a core started more often than once a phase");
    /* The primary never stores into a slot after it was cleaned: no slot line differs from what it last agreed with memory on. */
    for (unsigned b = 0; b < CPUS * SLOT; b++) RULE(arena[SLOT_BASE + b] != synced[SLOT_BASE + b] && (b = CPUS * SLOT), "a store into a slot after the clean");
    return ok;
}
