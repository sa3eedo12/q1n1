/* SPDX-License-Identifier: MIT */
/* Payload "cpuon": starts the Surface Pro 11's eleven secondary CPUs through PSCI CPU_ON, has each one report the state it was
 * entered in and power itself off with CPU_OFF, and prints what happened (docs/SP11-PAYLOAD-CPUON.md). The first payload that
 * changes the machine: a core that starts and never reports is left running, and a core that locks up may reset the board.
 * EXPERIMENTAL; ran three times on the unit (2026-11-15: boot 7 and steps 2 and 3 of the restart probe; one unit;
 * docs/SP11-PAYLOAD-CPUON.md, "What the unit showed").
 *
 * Order. CurrentEL first: not at EL2 it prints one line and does nothing else. Phase 0 asks AFFINITY_INFO about the eleven
 * targets and only ever starts one that answers OFF. Phase 1 is one round trip, core 0X100 alone: a NEXT line, a wait of eight
 * seconds, then the CPU_ON, so that a stall or a reset leaves a page that was already photographed. Phase 2 starts every
 * target that answered OFF, back to back, only after a normal phase 1 and again after a NEXT line and eight seconds.
 *
 * PSCI ids (SMCCC fast calls, Arm DEN0022 and DEN0028; the numbers are Linux's include/uapi/linux/psci.h, VERIFIED against it;
 * on the unit AFFINITY_INFO was answered and PSCI_FEATURES said CPU_ON is implemented: OBSERVED, the `psci` payload; this
 * payload's own runs then had CPU_ON answered 0 twelve times and CPU_OFF take every started core OFF: OBSERVED twice, on the two
 * finished pages, boot 7 and restart-probe step 3):
 *   CPU_ON         0xC4000003   x1 = MPIDR affinity of the target, x2 = entry address, x3 = context id = its report slot
 *   AFFINITY_INFO  0xC4000004   x1 = MPIDR affinity, x2 = 0 (the CPU itself): 0 ON, 1 OFF, 2 ON_PENDING
 *   CPU_OFF        0x84000002   only in the stub of a secondary below
 * No other id is issued. Each id is a literal in the one helper that holds its `smc`, so the build test counts the three `smc`
 * sites and reads the three ids.
 *
 * Memory. A secondary starts with its MMU and caches off (PSCI DEN0022; OBSERVED twice, boot 7 and step 3): its fetches and
 * stores go to memory and nothing snoops for it, the rule the A16 probe psci-roundtrip.S states ("scratch and report must be
 * clean to PoC before entry on a cache-off CPU"). So before the first CPU_ON the slots are zeroed (the only store the primary
 * ever makes into a slot) and the whole payload image and every slot are cleaned and invalidated to the PoC (DC CIVAC) behind a
 * DSB SY; a slot is read only after DC IVAC and DSB SY, and after the done flag was seen the whole slot is invalidated again,
 * because a prefetch may have refilled its other lines from before the stub stored. A slot owns whole cache lines (128-byte
 * aligned, 256 bytes): DC IVAC drops dirty data. The stub's stores are Device-nGnRnE with the MMU off, so they are ordered and
 * uncached; it ends the report with DSB, the done flag, DSB, and its DC CIVAC over the slot is free in that state and makes the
 * report visible if the core was entered with caches on after all. QEMU is coherent and shows none of this; the host test
 * models it. The slots live in the stack the runner gives the payload, 4 KiB in (the runner's guard words are at the bottom)
 * and far below the top 16 KiB that q1n1's ops need: the page attributes of the payload image are UNKNOWN, so it is never
 * stored into.
 *
 * The stub has no stack and never reads memory. x0 = the slot. It masks DAIF and reads CurrentEL; not at EL2 it stores CurrentEL and
 * goes to CPU_OFF. At EL2 it reads VBAR_EL2 as found and installs its own vector table before its first store (each entry records
 * ESR_EL2, ELR_EL2 and FAR_EL2 and goes to CPU_OFF, so a fault on that core is reported instead of hanging), then stores CurrentEL,
 * VBAR_EL2 as found and the rest, the done flag, and calls CPU_OFF. The brief lists the table last; it goes first so that a fault
 * in any later read or store is reported too. If CPU_OFF returns, the stub stores the answer and parks in WFE.
 *
 * Registers read: CurrentEL, MPIDR_EL1, MIDR_EL1, ID_AA64MMFR0_EL1, ID_AA64ISAR0_EL1, ID_AA64PFR0_EL1, CNTFRQ_EL0 (primary and
 * stub); SCTLR_EL2, HCR_EL2, VBAR_EL2, CNTVOFF_EL2, CNTPCT_EL0, ESR_EL2, ELR_EL2, FAR_EL2 (stub). CNTVOFF_EL2 is spelled by
 * encoding, as in timer.c, and read once (OBSERVED readable on the boot CPU, the X2 test T03, and on the secondaries, boot 7 and
 * step 3);
 * CNTPOFF_EL2 is never touched (a read of it never returns on this unit) and CNTHCTL_EL2.ECV is never set. Written: VBAR_EL2
 * and DAIF, by a stub.
 *
 * Fail closed. Every refusal comes before any CPU_ON; a CPU_ON that does not answer 0 leaves the core counted as not started;
 * a timeout is "NO_REPORT" or "NOT_OFF", never success; no CPU_ON is retried; the boot CPU is never a target; a counter that
 * does not run stops the payload before the CPU_ON, because the wait cannot be made.
 *
 * The unit's runs (2026-11-15; docs/SP11-PAYLOAD-CPUON.md): boot 7 (photographed at an angle, partly blurred), step 2 of the restart
 * probe (its finished page was not photographed) and step 3 (filmed, crisp). OBSERVED twice, on the two finished pages: CPU_ON of
 * one entry address (EfiLoaderCode memory below 4 GiB) was answered 0 for core 0X100 alone and for all eleven back to back; the
 * ten secondaries whose reports reached the page started at EL2, and the nine whose register line did had SCTLR_EL2 0x30000000
 * (MMU and caches off); CNTVOFF_EL2 read 0 on them; a core's first counter read came 45 us to about 2 ms after CPU_ON returned;
 * every core was seen OFF after its CPU_OFF. The page reached the 40-line budget and dropped six lines (SUPPRESSED=6).
 * Still UNKNOWN: what the secure monitor checks in an entry address beyond that kind of address, whether another unit behaves
 * the same, anything with a core kept running or with a guest, and why the board restarted by itself, reported after boot 7 and
 * in step 2 (times UNKNOWN; step 3 was seen alive through UPTIME 36 S).
 *
 * Lines: at most 40 (the ABI's limit), each at most 100 characters in the page font. The last six are reserved for the four
 * NEXT lines, the summary and the line saying what was not done, so a long report can never push them out. */
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* The host test replaces what a build machine cannot run: MRS, SMC, cache maintenance and the stack pointer. */
uint64_t pl_host_sysreg(const char *name);
void pl_host_smc(uint64_t regs[4]);
void pl_host_cache(const char *operation, uint64_t address);
uint64_t pl_host_stack_pointer(void);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#define PREFIX "PAYLOAD CPUON "
/* Every helper is out of line: the reviewed binary stays small and each instruction kind that matters sits in one helper. */
#define OUT_OF_LINE static __attribute__((noinline))

#define FUNCTION_CPU_ON 0xC4000003u
#define FUNCTION_AFFINITY_INFO 0xC4000004u

/* The MADT's GICC MPIDR affinities in CPU order (OBSERVED on the unit). Entry 0 is the boot CPU and no target. Integers, not
 * pointers: an absolute pointer table would depend on the load address. */
#define CORE_COUNT 12u
static const uint64_t core_affinity[CORE_COUNT] = {
    0x0, 0x100, 0x200, 0x300, 0x10000, 0x10100, 0x10200, 0x10300, 0x20000, 0x20100, 0x20200, 0x20300,
};
#define AFFINITY_MASK UINT64_C(0xff00ffffff)    /* Aff3 and Aff2:0 of MPIDR_EL1; bits 31:24 are RES1, MT and U */
#define PHASE1_TARGET 1u                         /* core 0X100 */

/* PSCI return codes -1 to -9, the AFFINITY_INFO states, the ID registers compared with the boot CPU's. */
static const char error_name[9][19] = {
    "NOT_SUPPORTED", "INVALID_PARAMETERS", "DENIED", "ALREADY_ON", "ON_PENDING",
    "INTERNAL_FAILURE", "NOT_PRESENT", "DISABLED", "INVALID_ADDRESS",
};
static const char state_name[3][11] = {"ON", "OFF", "ON_PENDING"};
static const char id_name[4][6] = {"MIDR", "MMFR0", "ISAR0", "PFR0"};

#define WAIT_BEFORE_CPU_ON_S 8u
#define REPORT_TIMEOUT_ONE_MS 1000u
#define REPORT_TIMEOUT_ALL_MS 2000u
#define OFF_TIMEOUT_MS 2000u
#define OFF_POLL_SPACING_MS 1u      /* each CPU is asked at most once a millisecond while the payload waits for OFF */
#define COUNTER_HZ_DEFAULT 19200000u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u
/* A running counter changes within a few dozen reads at any plausible frequency: this many equal reads in a row mean it is not
 * running and no time can be measured. */
#define COUNTER_STUCK_READS 2000000u
/* A larger distance in ticks is not shown as a number: this keeps ticks * 1000000 inside 63 bits. */
#define TICKS_SHOWN_MAX (UINT64_C(1) << 43)

/* The report slot: the stub stores at exactly these byte offsets, one 64-bit store each. */
#define OFF_DONE 0
#define OFF_CURRENTEL 8
#define OFF_MPIDR 16
#define OFF_MIDR 24
#define OFF_SCTLR 32
#define OFF_HCR 40
#define OFF_VBAR 48
#define OFF_CNTVOFF 56
#define OFF_CNTFRQ 64
#define OFF_CNTPCT 72
#define OFF_MMFR0 80
#define OFF_ISAR0 88
#define OFF_PFR0 96
#define OFF_ESR 104
#define OFF_ELR 112
#define OFF_FAR 120
#define OFF_VECTOR 128
#define OFF_STAGE 136
#define OFF_OFF_RETURN 144
#define SLOT_WORDS 19u
#define SLOT_BYTES 256u
_Static_assert(OFF_OFF_RETURN / 8 + 1 == SLOT_WORDS && SLOT_WORDS * 8 <= SLOT_BYTES, "the slot holds every word of the report");
/* One slot for phase 1 and one per target for phase 2: a slot holding a finished report must never be taken for the next. */
#define SLOT_COUNT 12u
#define SLOT_REGION_OFFSET 4096u        /* into the payload stack, past the runner's guard words */
#define SLOT_REGION_BYTES (SLOT_COUNT * SLOT_BYTES)
#define STACK_KEPT_BYTES (16u * 1024u)  /* what q1n1's ops and one fault frame need above the slots */

/* The done flag: DONE_MAGIC in its upper half, how the stub finished in its lower. */
#define DONE_MAGIC UINT64_C(0x444F4E45)
#define KIND_NONE 0
#define KIND_REPORT 1           /* a full report from EL2 */
#define KIND_OTHER_EL 2         /* entered at another EL: CurrentEL only */
#define KIND_FAULT 3            /* a vector was taken: ESR_EL2, ELR_EL2, FAR_EL2 */
#define KIND_OFF_RETURNED 4     /* CPU_OFF came back: its answer is in the slot */
#define STAGE_ALL_STORED 3

#ifdef Q1N1_PAYLOAD_HOST_TEST
char cpuon_entry[64] __attribute__((aligned(64)));
char cpuon_vectors[2048] __attribute__((aligned(2048)));
#else
extern const char cpuon_entry[];
extern const char cpuon_vectors[];
#endif

/* ---- The stub ------------------------------------------------------------------------------------------------------- */
#ifndef Q1N1_PAYLOAD_HOST_TEST
#define STR_(x) #x
#define STR(x) STR_(x)
#define STORE(source, offset) "    str " source ", [x19, #" STR(offset) "]\n"
#define READ_STORE(name, offset) "    mrs x2, " name "\n" STORE("x2", offset)
/* One vector entry, 128 bytes apart, each saying which one it was. */
#define VECTOR(n) "    .balign 128\n    mov w1, #" #n "\n    b cpuon_fault\n"

__asm__(
    ".pushsection .text.cpuon_secondary,\"ax\",%progbits\n"
    /* VBAR_EL2 keeps bits 10:0 reserved, so the table has to be 2 KiB aligned. */
    "    .balign 2048\n"
    "    .globl cpuon_vectors\n"
    "    .hidden cpuon_vectors\n"
    "cpuon_vectors:\n"
    VECTOR(0) VECTOR(1) VECTOR(2) VECTOR(3) VECTOR(4) VECTOR(5) VECTOR(6) VECTOR(7)
    VECTOR(8) VECTOR(9) VECTOR(10) VECTOR(11) VECTOR(12) VECTOR(13) VECTOR(14) VECTOR(15)
    "    .balign 128\n"
    "    .globl cpuon_entry\n"
    "    .hidden cpuon_entry\n"
    "cpuon_entry:\n"
    "    mov x19, x0\n"                              /* the slot: the one register the stub relies on */
    "    mov x20, xzr\n"                             /* set by the first fault: a fault while reporting one parks the core */
    "    msr daifset, #15\n"
    "    mrs x1, CurrentEL\n"
    "    cmp x1, #8\n"
    "    b.ne cpuon_other_el\n"
    /* The vectors go in before the first store, so that a fault in any later instruction, the stores included, is taken by them. */
    "    mrs x4, vbar_el2\n"                         /* as found, kept in a register until it can be stored */
    "    adr x3, cpuon_vectors\n"
    "    msr vbar_el2, x3\n"
    "    isb\n"
    STORE("x1", OFF_CURRENTEL)
    "    mov x2, #1\n"
    STORE("x2", OFF_STAGE)
    STORE("x4", OFF_VBAR)
    "    mov x2, #2\n"
    STORE("x2", OFF_STAGE)
    READ_STORE("mpidr_el1", OFF_MPIDR)
    READ_STORE("midr_el1", OFF_MIDR)
    READ_STORE("sctlr_el2", OFF_SCTLR)
    READ_STORE("hcr_el2", OFF_HCR)
    READ_STORE("S3_4_C14_C0_3", OFF_CNTVOFF)         /* CNTVOFF_EL2, by encoding */
    READ_STORE("CNTFRQ_EL0", OFF_CNTFRQ)
    READ_STORE("CNTPCT_EL0", OFF_CNTPCT)
    READ_STORE("id_aa64mmfr0_el1", OFF_MMFR0)
    READ_STORE("id_aa64isar0_el1", OFF_ISAR0)
    READ_STORE("id_aa64pfr0_el1", OFF_PFR0)
    "    mov x2, #" STR(STAGE_ALL_STORED) "\n"
    STORE("x2", OFF_STAGE)
    "    mov x1, #" STR(KIND_REPORT) "\n"
    "    b cpuon_finish\n"
    "cpuon_other_el:\n"                              /* x1 = CurrentEL; nothing of EL2 is touched */
    STORE("x1", OFF_CURRENTEL)
    "    mov x2, #1\n"
    STORE("x2", OFF_STAGE)
    "    mov x1, #" STR(KIND_OTHER_EL) "\n"
    "    b cpuon_finish\n"
    "cpuon_fault:\n"                                 /* w1 = which of the 16 vectors */
    "    cbnz x20, cpuon_park\n"
    "    mov x20, #1\n"
    READ_STORE("esr_el2", OFF_ESR)
    READ_STORE("elr_el2", OFF_ELR)
    READ_STORE("far_el2", OFF_FAR)
    STORE("x1", OFF_VECTOR)
    "    mov x1, #" STR(KIND_FAULT) "\n"
    "cpuon_finish:\n"                                /* x1 = KIND_*: clean the slot, publish the done flag, power off */
    "    dsb sy\n"
    "    mov x2, x19\n"
    "    add x3, x19, #" STR(SLOT_BYTES) "\n"
    "1:  dc civac, x2\n"
    "    add x2, x2, #16\n"
    "    cmp x2, x3\n"
    "    b.lo 1b\n"
    "    dsb sy\n"
    "    movz x2, #0x4E45, lsl #32\n"                /* DONE_MAGIC << 32 */
    "    movk x2, #0x444F, lsl #48\n"
    "    orr x2, x2, x1\n"
    STORE("x2", OFF_DONE)
    "    dsb sy\n"
    "    dc civac, x19\n"
    "    dsb sy\n"
    "    mov w0, #2\n"                               /* CPU_OFF, 0x84000002 */
    "    movk w0, #0x8400, lsl #16\n"
    "    mov x1, xzr\n"
    "    mov x2, xzr\n"
    "    mov x3, xzr\n"
    "    smc #0\n"
    /* Reached only if CPU_OFF returned: keep the answer and park instead of running random code. */
    STORE("x0", OFF_OFF_RETURN)
    "    movz x2, #0x4E45, lsl #32\n"
    "    movk x2, #0x444F, lsl #48\n"
    "    orr x2, x2, #" STR(KIND_OFF_RETURNED) "\n"
    STORE("x2", OFF_DONE)
    "    dsb sy\n"
    "    dc civac, x19\n"
    "    dsb sy\n"
    "cpuon_park:\n"
    "    wfe\n"
    "    b cpuon_park\n"
    ".popsection\n");
#endif /* !Q1N1_PAYLOAD_HOST_TEST */

/* ---- Instructions, one helper each ------------------------------------------------------------------------------- */

/* The only CPU_ON: its id is the literal here and nowhere else. */
OUT_OF_LINE uint64_t smc_cpu_on(uint64_t target, uint64_t entry, uint64_t context)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    uint64_t regs[4] = {FUNCTION_CPU_ON, target, entry, context};
    pl_host_smc(regs);
    return regs[0];
#else
    register uint64_t x0 __asm__("x0") = FUNCTION_CPU_ON;
    register uint64_t x1 __asm__("x1") = target;
    register uint64_t x2 __asm__("x2") = entry;
    register uint64_t x3 __asm__("x3") = context;
    __asm__ volatile("smc #0" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     :
                     : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
                       "memory");
    return x0;
#endif
}

/* The only AFFINITY_INFO, at the lowest affinity level (the CPU itself). */
OUT_OF_LINE uint64_t smc_affinity_info(uint64_t affinity)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    uint64_t regs[4] = {FUNCTION_AFFINITY_INFO, affinity, 0, 0};
    pl_host_smc(regs);
    return regs[0];
#else
    register uint64_t x0 __asm__("x0") = FUNCTION_AFFINITY_INFO;
    register uint64_t x1 __asm__("x1") = affinity;
    register uint64_t x2 __asm__("x2") = 0;
    register uint64_t x3 __asm__("x3") = 0;
    __asm__ volatile("smc #0" : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
                     :
                     : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
                       "memory");
    return x0;
#endif
}

OUT_OF_LINE void dc_civac(uint64_t address)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_cache("civac", address);
#else
    __asm__ volatile("dc civac, %0" : : "r"(address) : "memory");
#endif
}

OUT_OF_LINE void dc_ivac(uint64_t address)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_cache("ivac", address);
#else
    __asm__ volatile("dc ivac, %0" : : "r"(address) : "memory");
#endif
}

OUT_OF_LINE void dsb_sy(void)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    pl_host_cache("dsb", 0);
#else
    __asm__ volatile("dsb sy" : : : "memory");
#endif
}

OUT_OF_LINE uint64_t stack_pointer(void)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    return pl_host_stack_pointer();
#else
    uint64_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    return sp;
#endif
}

/* 16 bytes is the smallest cache line the architecture allows, so a step of 16 reaches every line whatever the unit's line size
 * is, and CTR_EL0 need not be read. */
#define CACHE_STEP 16u

OUT_OF_LINE void clean_invalidate_range(uint64_t start, uint64_t bytes)
{
    for (uint64_t at = start & ~(uint64_t)(CACHE_STEP - 1); at < start + bytes; at += CACHE_STEP) dc_civac(at);
}

OUT_OF_LINE void invalidate_range(uint64_t start, uint64_t bytes)
{
    for (uint64_t at = start; at < start + bytes; at += CACHE_STEP) dc_ivac(at);
}

static inline uint64_t load64(uint64_t address)
{
    return *(volatile const uint64_t *)(uintptr_t)address;
}

/* ---- Output --------------------------------------------------------------------------------------------------------- */

#define LINES_RESERVED 6u       /* the four NEXT lines, the summary, the line saying what was not done */

struct out {
    const struct q1n1_payload_args *a;
    unsigned used, suppressed, essential_left;
};

/* A line that is not essential is dropped, and counted, once it would leave no room for the essential lines still to come. */
OUT_OF_LINE void out_line(struct out *o, const struct pl_line *line, int essential)
{
    if (essential) {
        if (o->essential_left) o->essential_left--;
    } else if (o->used + o->essential_left >= Q1N1_PAYLOAD_LINES_MAX) {
        o->suppressed++;
        return;
    }
    o->used++;
    pl_emit(o->a, line);
}

/* Entries packed into lines of at most 100 characters under one label: an entry is never cut, and a long group goes on to
 * another line instead of being truncated. */
struct group {
    struct out *o;
    struct pl_line line;
    uint32_t base;
    unsigned items;
    int essential;
};

OUT_OF_LINE void group_start(struct group *g, struct out *o, const char *label)
{
    g->o = o;
    pl_begin(&g->line);
    pl_text(&g->line, PREFIX);
    pl_text(&g->line, label);
    g->base = g->line.len;
    g->items = 0;
    g->essential = 0;
}

OUT_OF_LINE void add(struct group *g, const char *text)
{
    uint32_t length = 0;
    while (text[length]) length++;
    if (g->items && g->line.len + 1 + length > Q1N1_PAYLOAD_LINE_MAX) {
        out_line(g->o, &g->line, g->essential);
        g->line.len = g->base;
        g->line.buf[g->base] = 0;
        g->items = 0;
    }
    pl_text(&g->line, " ");
    pl_text(&g->line, text);
    g->items++;
}

OUT_OF_LINE void group_end(struct group *g)
{
    if (g->items) out_line(g->o, &g->line, g->essential);
    g->items = 0;
}

/* One whole line: PAYLOAD CPUON <label> <text>. */
OUT_OF_LINE void say(struct out *o, const char *label, const char *text, int essential)
{
    struct pl_line line;
    pl_begin(&line);
    pl_text(&line, PREFIX);
    pl_text(&line, label);
    if (*text) {
        pl_text(&line, " ");
        pl_text(&line, text);
    }
    out_line(o, &line, essential);
}

OUT_OF_LINE void put_dec(struct pl_line *line, uint64_t value)
{
    char digits[20];
    unsigned n = 0;
    do {
        digits[n++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    while (n && line->len < Q1N1_PAYLOAD_LINE_MAX) line->buf[line->len++] = digits[--n];
    line->buf[line->len] = 0;
}

OUT_OF_LINE void put_signed(struct pl_line *line, int64_t value)
{
    uint64_t magnitude = (uint64_t)value;
    if (value < 0) {
        pl_text(line, "-");
        magnitude = UINT64_C(0) - magnitude;
    }
    put_dec(line, magnitude);
}

/* KEY=0XVALUE and KEY=DECIMAL as one entry of a group. */
OUT_OF_LINE void add_hex(struct group *g, const char *key, uint64_t value)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, key);
    pl_text(&item, "=");
    pl_hex(g->o->a, &item, value);
    add(g, item.buf);
}

OUT_OF_LINE void add_dec(struct group *g, const char *key, uint64_t value)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, key);
    pl_text(&item, "=");
    put_dec(&item, value);
    add(g, item.buf);
}

/* NAME(-N) for a PSCI error in the low 32 bits of x0 (a firmware may or may not sign-extend a 32-bit answer); 0, and nothing
 * written, for any other value. */
OUT_OF_LINE int put_error_name(struct pl_line *item, uint64_t raw)
{
    uint32_t negated = 0u - (uint32_t)raw;
    if (negated - 1u >= 9u) return 0;
    pl_text(item, error_name[negated - 1]);
    pl_text(item, "(-");
    put_dec(item, negated);
    pl_text(item, ")");
    return 1;
}

/* A CPU_ON answer: the raw x0, then SUCCESS or the error's name when it is certain. */
OUT_OF_LINE void put_on_answer(const struct q1n1_payload_args *a, struct pl_line *item, uint64_t raw)
{
    pl_hex(a, item, raw);
    if ((uint32_t)raw == 0) {
        pl_text(item, ":SUCCESS");
    } else {
        struct pl_line name;
        pl_begin(&name);
        if (put_error_name(&name, raw)) {
            pl_text(item, ":");
            pl_text(item, name.buf);
        }
    }
}

/* An AFFINITY_INFO answer: ON, OFF or ON_PENDING, a PSCI error by name, anything else as the raw value. */
OUT_OF_LINE void put_state(const struct q1n1_payload_args *a, struct pl_line *item, uint64_t raw)
{
    if (raw <= 2) pl_text(item, state_name[raw]);
    else if (!put_error_name(item, raw)) pl_hex(a, item, raw);
}

/* ---- State of the run ---------------------------------------------------------------------------------------------- */

struct core {
    uint64_t affinity;
    uint64_t probe;             /* x0 of the phase 0 AFFINITY_INFO */
    uint64_t on_raw;            /* x0 of its CPU_ON */
    uint64_t t_return;          /* the counter right after that CPU_ON returned */
    uint64_t last_state;        /* the latest AFFINITY_INFO answer while waiting for OFF */
    uint64_t slot;
    uint8_t boot;               /* the CPU the payload runs on: no AFFINITY_INFO, no CPU_ON */
    uint8_t eligible;           /* phase 0 said exactly OFF */
    uint8_t called;             /* CPU_ON was issued */
    uint8_t started;            /* ... and answered 0 */
    uint8_t kind;               /* KIND_* of the done flag once it was seen */
    uint8_t off;                /* AFFINITY_INFO said OFF after the start */
};

struct run {
    const struct q1n1_payload_args *a;
    struct out out;
    uint64_t freq;              /* counter ticks per second */
    uint64_t cntfrq;            /* the boot CPU's CNTFRQ_EL0 as read */
    uint64_t mpidr, boot_affinity;
    uint64_t entry, slot_base;
    uint64_t id[4];             /* the boot CPU's MIDR_EL1, ID_AA64MMFR0_EL1, ID_AA64ISAR0_EL1, ID_AA64PFR0_EL1 */
    struct core core[CORE_COUNT];   /* indexed like core_affinity: phase 0 and phase 2 */
    struct core first;          /* phase 1's core 0X100, apart from phase 2's, which starts it again */
};

/* A loop's two clocks: the deadline, and the check that the counter moves at all. */
struct watch {
    uint64_t start, last, limit;
    uint32_t same;
    uint8_t stuck;
};

OUT_OF_LINE void watch_begin(const struct run *r, struct watch *w, uint64_t limit_ticks)
{
    w->start = w->last = r->a->ops.counter();
    w->limit = limit_ticks;
    w->same = 0;
    w->stuck = 0;
}

/* True once the limit has passed, or the counter has stood still for COUNTER_STUCK_READS reads (`stuck` then says so). */
OUT_OF_LINE int watch_expired(const struct run *r, struct watch *w)
{
    uint64_t now = r->a->ops.counter();
    if (now - w->start >= w->limit) return 1;
    if (now == w->last) {
        if (++w->same >= COUNTER_STUCK_READS) {
            w->stuck = 1;
            return 1;
        }
    } else {
        w->last = now;
        w->same = 0;
    }
    return 0;
}

OUT_OF_LINE uint64_t ticks_ms(const struct run *r, uint64_t ms)
{
    return r->freq / 1000u * ms;
}

/* Waits `ms` milliseconds by the counter; 0 if the counter does not run. */
OUT_OF_LINE int wait_ms(const struct run *r, uint64_t ms)
{
    struct watch w;
    watch_begin(r, &w, ticks_ms(r, ms));
    while (!watch_expired(r, &w)) {
    }
    return !w.stuck;
}

/* The one place a CPU_ON is issued: only a core phase 0 found OFF, and each once. Returns 1 when the answer was 0. */
OUT_OF_LINE int start_core(const struct run *r, struct core *c, unsigned slot_index)
{
    if (!c->eligible || c->called) return 0;
    c->slot = r->slot_base + (uint64_t)slot_index * SLOT_BYTES;
    c->called = 1;
    c->on_raw = smc_cpu_on(c->affinity, r->entry, c->slot);
    c->t_return = r->a->ops.counter();
    c->started = (uint32_t)c->on_raw == 0;
    return c->started;
}

/* Zeroes the slots, then makes them and the image visible in memory: the clean-and-invalidate carries the zeros, the stub and
 * its vectors to the point of coherency before a core that fetches without caches starts. */
OUT_OF_LINE void prepare_memory(const struct run *r)
{
    volatile uint64_t *word = (volatile uint64_t *)(uintptr_t)r->slot_base;
    for (unsigned i = 0; i < SLOT_REGION_BYTES / 8; i++) word[i] = 0;
    clean_invalidate_range(r->a->payload_base, r->a->payload_size);
    clean_invalidate_range(r->slot_base, SLOT_REGION_BYTES);
    dsb_sy();
}

/* How a done flag reads: KIND_*, or KIND_NONE for anything that is not the magic and a known kind. */
OUT_OF_LINE unsigned kind_of(uint64_t done)
{
    uint64_t low = done - (DONE_MAGIC << 32);
    return (done >> 32) == DONE_MAGIC && low >= KIND_REPORT && low <= KIND_OFF_RETURNED ? (unsigned)low : KIND_NONE;
}

/* The done flag of a slot: invalidate its first line, DSB, load. */
OUT_OF_LINE unsigned slot_kind(uint64_t slot)
{
    dc_ivac(slot);
    dsb_sy();
    return kind_of(load64(slot + OFF_DONE));
}

struct report {
    uint64_t w[SLOT_WORDS];
};

/* The whole slot, once the done flag was seen: its other lines may hold a copy fetched before the stub stored, so they are
 * invalidated now. Afterwards the primary does nothing to the slot but, for a core that never reaches OFF, one more read. */
OUT_OF_LINE void slot_read(uint64_t slot, struct report *rep)
{
    invalidate_range(slot, SLOT_BYTES);
    dsb_sy();
    for (unsigned i = 0; i < SLOT_WORDS; i++) rep->w[i] = load64(slot + (uint64_t)i * 8);
}

/* Waits until the done flag of every started core was seen or the time is up. */
OUT_OF_LINE void wait_for_reports(const struct run *r, struct core *list[], unsigned n, uint64_t timeout_ms)
{
    struct watch w;
    watch_begin(r, &w, ticks_ms(r, timeout_ms));
    for (;;) {
        unsigned pending = 0;
        for (unsigned i = 0; i < n; i++) {
            if (list[i]->kind == KIND_NONE) list[i]->kind = (uint8_t)slot_kind(list[i]->slot);
            pending += list[i]->kind == KIND_NONE;
        }
        if (!pending || watch_expired(r, &w)) return;
    }
}

/* Polls AFFINITY_INFO of the started cores until each said OFF or the time is up, spaced so that the secure world is not asked as
 * fast as the loop can go. Only the exact answer 1 counts as OFF. */
OUT_OF_LINE void wait_for_off(const struct run *r, struct core *list[], unsigned n)
{
    struct watch w;
    watch_begin(r, &w, ticks_ms(r, OFF_TIMEOUT_MS));
    for (;;) {
        unsigned pending = 0;
        for (unsigned i = 0; i < n; i++) {
            if (list[i]->off) continue;
            list[i]->last_state = smc_affinity_info(list[i]->affinity);
            if (list[i]->last_state == 1) list[i]->off = 1;
            else pending++;
        }
        if (!pending || watch_expired(r, &w) || !wait_ms(r, OFF_POLL_SPACING_MS)) return;
    }
}

/* ---- Reporting ----------------------------------------------------------------------------------------------------- */

/* A group whose label names the phase and the core: "P1 0X100". */
OUT_OF_LINE void group_core(struct group *g, struct run *r, unsigned phase, const struct core *c)
{
    char label[24] = {'P', (char)('0' + phase), ' ', 0};
    r->a->ops.hex(label + 3, sizeof label - 3, c->affinity);
    group_start(g, &r->out, label);
}

/* Microseconds from the primary's read right after CPU_ON returned to the stub's own read: negative when the core ran before
 * CPU_ON returned. */
OUT_OF_LINE int64_t distance_us(const struct run *r, uint64_t secondary, uint64_t primary)
{
    int64_t ticks = (int64_t)(secondary - primary);
    uint64_t magnitude = ticks < 0 ? UINT64_C(0) - (uint64_t)ticks : (uint64_t)ticks;
    if (magnitude > TICKS_SHOWN_MAX) magnitude = TICKS_SHOWN_MAX;
    int64_t us = (int64_t)(magnitude * 1000000u / r->freq);
    return ticks < 0 ? -us : us;
}

/* The ID registers that differ from the boot CPU's, as a mask: bit 0 MIDR_EL1, 1 ID_AA64MMFR0_EL1, 2 ID_AA64ISAR0_EL1,
 * 3 ID_AA64PFR0_EL1. */
OUT_OF_LINE unsigned id_differences(const struct run *r, const struct report *rep)
{
    static const uint8_t where[4] = {OFF_MIDR, OFF_MMFR0, OFF_ISAR0, OFF_PFR0};
    unsigned mask = 0;
    for (unsigned i = 0; i < 4; i++) mask |= (unsigned)(rep->w[where[i] / 8] != r->id[i]) << i;
    return mask;
}

OUT_OF_LINE int mpidr_matches(const struct core *c, const struct report *rep)
{
    return (rep->w[OFF_MPIDR / 8] & AFFINITY_MASK) == c->affinity;
}

/* A core that reported: line A is the entry EL, whether MPIDR_EL1 is the target's, whether the four ID registers and CNTFRQ_EL0
 * are the boot CPU's, CNTVOFF_EL2 and the counter distance; line B is SCTLR_EL2, HCR_EL2 and VBAR_EL2 as found. */
OUT_OF_LINE void report_registers(struct run *r, const struct core *c, unsigned phase, const struct report *rep)
{
    static const uint8_t where[4] = {OFF_MIDR, OFF_MMFR0, OFF_ISAR0, OFF_PFR0};
    struct group g;
    struct pl_line text;
    unsigned differ = id_differences(r, rep);
    group_core(&g, r, phase, c);
    add_dec(&g, "EL", rep->w[OFF_CURRENTEL / 8] >> 2 & 3);
    if (mpidr_matches(c, rep)) add(&g, "MPIDR=OK");
    else add_hex(&g, "MPIDR", rep->w[OFF_MPIDR / 8]);
    pl_begin(&text);
    pl_text(&text, "IDS=");
    if (!differ) pl_text(&text, "SAME");
    for (unsigned i = 0, first = 1; i < 4; i++) {
        if (!(differ >> i & 1)) continue;
        if (!first) pl_text(&text, "/");
        pl_text(&text, id_name[i]);
        first = 0;
    }
    add(&g, text.buf);
    if (rep->w[OFF_CNTFRQ / 8] == r->cntfrq) add(&g, "FRQ=SAME");
    else add_hex(&g, "FRQ", rep->w[OFF_CNTFRQ / 8]);
    add_hex(&g, "CNTVOFF_EL2", rep->w[OFF_CNTVOFF / 8]);
    pl_begin(&text);
    pl_text(&text, "DT_US=");
    put_signed(&text, distance_us(r, rep->w[OFF_CNTPCT / 8], c->t_return));
    add(&g, text.buf);
    group_end(&g);

    group_core(&g, r, phase, c);
    add_hex(&g, "SCTLR_EL2", rep->w[OFF_SCTLR / 8]);
    add_hex(&g, "HCR_EL2", rep->w[OFF_HCR / 8]);
    add_hex(&g, "VBAR_EL2", rep->w[OFF_VBAR / 8]);
    group_end(&g);

    if (!differ) return;
    /* The raw values, so that a different core is not only named. */
    group_core(&g, r, phase, c);
    for (unsigned i = 0; i < 4; i++) {
        if (!(differ >> i & 1)) continue;
        pl_begin(&text);
        pl_text(&text, id_name[i]);
        pl_text(&text, "=");
        pl_hex(r->a, &text, rep->w[where[i] / 8]);
        pl_text(&text, "/BOOT=");
        pl_hex(r->a, &text, r->id[i]);
        add(&g, text.buf);
    }
    group_end(&g);
}

/* What one core that finished its run through the stub says. */
OUT_OF_LINE void report_core(struct run *r, const struct core *c, unsigned phase, const struct report *rep, unsigned kind)
{
    struct group g;
    struct pl_line text;
    if (kind == KIND_OTHER_EL) {
        group_core(&g, r, phase, c);
        pl_begin(&text);
        pl_text(&text, "ENTERED_AT_EL");
        put_dec(&text, rep->w[OFF_CURRENTEL / 8] >> 2 & 3);
        add(&g, text.buf);
        add(&g, "NOT_EL2");
        add_hex(&g, "CURRENTEL", rep->w[OFF_CURRENTEL / 8]);
        group_end(&g);
        return;
    }
    if (kind == KIND_FAULT) {
        group_core(&g, r, phase, c);
        add(&g, "FAULT");
        add_dec(&g, "STAGE", rep->w[OFF_STAGE / 8]);
        add_dec(&g, "VECTOR", rep->w[OFF_VECTOR / 8]);
        add_hex(&g, "ESR_EL2", rep->w[OFF_ESR / 8]);
        add_hex(&g, "ELR_EL2", rep->w[OFF_ELR / 8]);
        add_hex(&g, "FAR_EL2", rep->w[OFF_FAR / 8]);
        group_end(&g);
        if (rep->w[OFF_STAGE / 8] < STAGE_ALL_STORED) return;
    }
    report_registers(r, c, phase, rep);
}

/* A started core that never reached OFF: what it last answered and what its slot says now (CPU_OFF may have returned, or the
 * stub may have faulted after its report). One more read of the slot, never a write. */
OUT_OF_LINE void report_late(struct run *r, const struct core *c, unsigned phase)
{
    struct group g;
    struct pl_line text;
    struct report rep;
    group_core(&g, r, phase, c);
    pl_begin(&text);
    pl_text(&text, "STILL_ON LAST=");
    put_state(r->a, &text, c->last_state);
    add(&g, text.buf);
    if (c->kind != KIND_NONE) {
        slot_read(c->slot, &rep);
        unsigned kind = kind_of(rep.w[OFF_DONE / 8]);
        add_dec(&g, "KIND", kind);
        if (kind == KIND_OFF_RETURNED) {
            pl_begin(&text);
            pl_text(&text, "CPU_OFF_RET=");
            put_on_answer(r->a, &text, rep.w[OFF_OFF_RETURN / 8]);
            add(&g, text.buf);
        } else if (kind == KIND_FAULT) {
            add_hex(&g, "ESR_EL2", rep.w[OFF_ESR / 8]);
            add_hex(&g, "ELR_EL2", rep.w[OFF_ELR / 8]);
        }
    }
    group_end(&g);
}

/* A started core whose done flag never came: how far the stub got, from one more read of its slot. Stage 0 says it never ran. */
OUT_OF_LINE void report_no_report(struct run *r, const struct core *c, unsigned phase)
{
    struct group g;
    struct report rep;
    slot_read(c->slot, &rep);
    group_core(&g, r, phase, c);
    add(&g, "NO_REPORT");
    add_dec(&g, "STAGE", rep.w[OFF_STAGE / 8]);
    add_hex(&g, "CURRENTEL", rep.w[OFF_CURRENTEL / 8]);
    group_end(&g);
}

struct tally {
    unsigned started, reported, off;
};

OUT_OF_LINE struct tally tally_of(struct core *list[], unsigned n)
{
    struct tally t = {0, 0, 0};
    for (unsigned i = 0; i < n; i++) {
        t.started += list[i]->started;
        t.reported += list[i]->started && list[i]->kind != KIND_NONE;
        t.off += list[i]->started && list[i]->off;
    }
    return t;
}

/* The CPU_ON answers of phase 2: how many were issued and answered 0, and each other answer by name. */
OUT_OF_LINE void report_calls(struct run *r, struct core *list[], unsigned n)
{
    struct group g;
    struct pl_line text;
    unsigned issued = 0, ok = 0;
    for (unsigned i = 0; i < n; i++) {
        issued += list[i]->called;
        ok += list[i]->started;
    }
    group_start(&g, &r->out, "P2 CPU_ON");
    add_dec(&g, "ISSUED", issued);
    add_dec(&g, "SUCCESS", ok);
    group_end(&g);
    if (ok == issued) return;
    group_start(&g, &r->out, "P2 CPU_ON_FAILED");
    for (unsigned i = 0; i < n; i++) {
        if (!list[i]->called || list[i]->started) continue;
        pl_begin(&text);
        pl_hex(r->a, &text, list[i]->affinity);
        pl_text(&text, "=");
        if (!put_error_name(&text, list[i]->on_raw)) pl_hex(r->a, &text, list[i]->on_raw);
        add(&g, text.buf);
    }
    group_end(&g);
}

/* How the wait for OFF ended: the counts, then the cores that did not make it. */
OUT_OF_LINE void report_off(struct run *r, struct core *list[], unsigned n, unsigned phase)
{
    struct group g;
    struct pl_line text;
    struct tally t = tally_of(list, n);
    group_start(&g, &r->out, phase == 1 ? "P1 POWER_OFF" : "P2 POWER_OFF");
    add_dec(&g, "OFF", t.off);
    add_dec(&g, "NOT_OFF", t.started - t.off);
    group_end(&g);
    if (t.off == t.started) return;
    group_start(&g, &r->out, phase == 1 ? "P1 NOT_OFF" : "P2 NOT_OFF");
    for (unsigned i = 0; i < n; i++) {
        if (!list[i]->started || list[i]->off) continue;
        pl_begin(&text);
        pl_hex(r->a, &text, list[i]->affinity);
        pl_text(&text, "=");
        put_state(r->a, &text, list[i]->last_state);
        add(&g, text.buf);
    }
    group_end(&g);
    for (unsigned i = 0; i < n; i++)
        if (list[i]->started && !list[i]->off) report_late(r, list[i], phase);
}

/* ---- The phases ----------------------------------------------------------------------------------------------------- */

/* AFFINITY_INFO of the eleven targets; only a core that answers exactly OFF becomes eligible. */
OUT_OF_LINE void phase_zero(struct run *r)
{
    struct group g;
    struct pl_line text;
    say(&r->out, "NEXT", "AFFINITY", 1);
    for (unsigned i = 1; i < CORE_COUNT; i++) {
        struct core *c = &r->core[i];
        c->boot = c->affinity == r->boot_affinity;
        if (c->boot) continue;
        c->probe = smc_affinity_info(c->affinity);
        c->eligible = c->probe == 1;
    }
    group_start(&g, &r->out, "AFFINITY");
    for (unsigned i = 1; i < CORE_COUNT; i++) {
        pl_begin(&text);
        pl_hex(r->a, &text, r->core[i].affinity);
        pl_text(&text, "=");
        if (r->core[i].boot) pl_text(&text, "BOOT_CPU");
        else put_state(r->a, &text, r->core[i].probe);
        add(&g, text.buf);
    }
    group_end(&g);
    group_start(&g, &r->out, "SKIP_NOT_OFF");
    for (unsigned i = 1; i < CORE_COUNT; i++) {
        if (r->core[i].eligible) continue;
        pl_begin(&text);
        pl_hex(r->a, &text, r->core[i].affinity);
        add(&g, text.buf);
    }
    group_end(&g);
}

/* Why a phase 1 was not a normal round trip, as bits. */
enum {
    WHY_NOT_STARTED = 1u << 0, WHY_NO_REPORT = 1u << 1, WHY_NOT_EL2 = 1u << 2, WHY_FAULT = 1u << 3,
    WHY_MPIDR = 1u << 4, WHY_IDS = 1u << 5, WHY_FRQ = 1u << 6, WHY_NOT_OFF = 1u << 7,
};

OUT_OF_LINE void say_verdict(struct run *r, const char *label, unsigned why)
{
    static const char name[8][12] = {"NOT_STARTED", "NO_REPORT", "NOT_EL2", "FAULT", "MPIDR", "IDS", "FRQ", "NOT_OFF"};
    struct pl_line text;
    pl_begin(&text);
    if (!why) pl_text(&text, "NORMAL");
    else pl_text(&text, "ABNORMAL=");
    for (unsigned i = 0, first = 1; i < 8; i++) {
        if (!(why >> i & 1)) continue;
        if (!first) pl_text(&text, "/");
        pl_text(&text, name[i]);
        first = 0;
    }
    say(&r->out, label, text.buf, 0);
}

/* "CPU_ON <what> AFTER 8 S": the NEXT line that precedes a wait and a CPU_ON. */
OUT_OF_LINE void say_next_cpu_on(struct run *r, const char *what)
{
    struct pl_line text;
    pl_begin(&text);
    pl_text(&text, "CPU_ON ");
    pl_text(&text, what);
    pl_text(&text, " AFTER ");
    put_dec(&text, WAIT_BEFORE_CPU_ON_S);
    pl_text(&text, " S");
    say(&r->out, "NEXT", text.buf, 1);
}

/* Phase 1: core 0X100 alone. Returns 1 for a normal round trip: started, EL2 entry, its own MPIDR, the boot CPU's ID registers
 * and counter frequency, and OFF again. */
OUT_OF_LINE int phase_one(struct run *r)
{
    struct core *c = &r->first;
    struct core *list[1] = {c};
    struct report rep;
    struct pl_line text;
    unsigned why = 0;
    *c = r->core[PHASE1_TARGET];

    say(&r->out, "NEXT", "PREPARE", 1);
    prepare_memory(r);
    pl_begin(&text);
    pl_hex(r->a, &text, c->affinity);
    say_next_cpu_on(r, text.buf);
    if (!wait_ms(r, WAIT_BEFORE_CPU_ON_S * 1000u)) {
        say(&r->out, "P1", "SKIPPED=COUNTER_STUCK", 0);
        return 0;
    }

    start_core(r, c, 0);
    pl_begin(&text);
    pl_hex(r->a, &text, c->affinity);
    pl_text(&text, " RET=");
    put_on_answer(r->a, &text, c->on_raw);
    say(&r->out, "P1 CPU_ON", text.buf, 0);
    if (!c->started) {
        say_verdict(r, "P1", WHY_NOT_STARTED);
        return 0;
    }

    wait_for_reports(r, list, 1, REPORT_TIMEOUT_ONE_MS);
    if (c->kind == KIND_NONE) {
        why |= WHY_NO_REPORT;
        report_no_report(r, c, 1);
    } else {
        slot_read(c->slot, &rep);
        unsigned kind = kind_of(rep.w[OFF_DONE / 8]);
        if (kind == KIND_NONE) kind = c->kind;
        report_core(r, c, 1, &rep, kind);
        if (kind == KIND_OTHER_EL || (rep.w[OFF_CURRENTEL / 8] >> 2 & 3) != 2) why |= WHY_NOT_EL2;
        if (kind == KIND_FAULT) why |= WHY_FAULT;
        if (kind == KIND_REPORT || kind == KIND_OFF_RETURNED) {
            if (!mpidr_matches(c, &rep)) why |= WHY_MPIDR;
            if (id_differences(r, &rep)) why |= WHY_IDS;
            if (rep.w[OFF_CNTFRQ / 8] != r->cntfrq) why |= WHY_FRQ;
        }
    }
    wait_for_off(r, list, 1);
    if (!c->off) why |= WHY_NOT_OFF;
    report_off(r, list, 1, 1);
    say_verdict(r, "P1", why);
    return !why;
}

/* Phase 2: every eligible target, back to back. */
OUT_OF_LINE void phase_two(struct run *r, struct core *list[], unsigned n)
{
    struct core *started[CORE_COUNT];
    struct report rep;
    unsigned count = 0;
    say_next_cpu_on(r, "ALL");
    if (!wait_ms(r, WAIT_BEFORE_CPU_ON_S * 1000u)) {
        say(&r->out, "P2", "SKIPPED=COUNTER_STUCK", 0);
        return;
    }
    /* Nothing is printed and nothing is polled between the calls. */
    for (unsigned i = 0; i < n; i++) start_core(r, list[i], (unsigned)(list[i] - r->core));
    report_calls(r, list, n);
    for (unsigned i = 0; i < n; i++)
        if (list[i]->started) started[count++] = list[i];
    wait_for_reports(r, started, count, REPORT_TIMEOUT_ALL_MS);
    for (unsigned i = 0; i < count; i++) {
        struct core *c = started[i];
        if (c->kind == KIND_NONE) {
            report_no_report(r, c, 2);
            continue;
        }
        slot_read(c->slot, &rep);
        unsigned kind = kind_of(rep.w[OFF_DONE / 8]);
        report_core(r, c, 2, &rep, kind ? kind : c->kind);
    }
    wait_for_off(r, started, count);
    report_off(r, started, count, 2);
}

/* Everything the payload checks about where it is before it touches anything; NULL, or the reason it refuses. */
OUT_OF_LINE const char *refusal_of(struct run *r)
{
    const struct q1n1_payload_args *a = r->a;
    uint64_t slots_end, sp = stack_pointer(), vectors = (uint64_t)(uintptr_t)cpuon_vectors, image_end;
    r->slot_base = a->stack_base + SLOT_REGION_OFFSET;
    slots_end = r->slot_base + SLOT_REGION_BYTES;
    r->entry = (uint64_t)(uintptr_t)cpuon_entry;
    if (!a->ops.counter) return "NO_COUNTER";
    if ((a->stack_base & 127) || a->stack_size < SLOT_REGION_OFFSET + SLOT_REGION_BYTES + STACK_KEPT_BYTES ||
        sp < slots_end + STACK_KEPT_BYTES || sp > a->stack_base + a->stack_size)
        return "STACK";
    image_end = a->payload_base + a->payload_size;
    if (a->payload_size >= (UINT64_C(1) << 32) || image_end < a->payload_base || (r->entry & 3) || (vectors & 2047) ||
        r->entry < a->payload_base || r->entry >= image_end || vectors < a->payload_base || vectors >= image_end)
        return "ENTRY";
    return 0;
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct run r;
    struct core *targets[CORE_COUNT];
    struct pl_line text;
    struct group g;
    unsigned count = 0, normal = 0, left = 0;
    const char *refusal;
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    r.a = r.out.a = a;
    r.out.used = r.out.suppressed = 0;
    r.out.essential_left = LINES_RESERVED;
    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {
        say(&r.out, "SKIPPED_NOT_AT_EL2", "", 0);
        return 0;
    }
    if ((refusal = refusal_of(&r))) {
        pl_begin(&text);
        pl_text(&text, "REFUSED=");
        pl_text(&text, refusal);
        say(&r.out, text.buf, "", 0);
        return 0;
    }
    r.mpidr = SYSREG(mpidr_el1);
    r.boot_affinity = r.mpidr & AFFINITY_MASK;
    r.cntfrq = SYSREG(CNTFRQ_EL0);
    r.freq = r.cntfrq >= COUNTER_HZ_MIN && r.cntfrq <= COUNTER_HZ_MAX ? r.cntfrq : COUNTER_HZ_DEFAULT;
    r.id[0] = SYSREG(midr_el1);
    r.id[1] = SYSREG(id_aa64mmfr0_el1);
    r.id[2] = SYSREG(id_aa64isar0_el1);
    r.id[3] = SYSREG(id_aa64pfr0_el1);
    for (unsigned i = 0; i < sizeof r.core; i++) ((volatile uint8_t *)r.core)[i] = 0;
    for (unsigned i = 0; i < sizeof r.first; i++) ((volatile uint8_t *)&r.first)[i] = 0;
    for (unsigned i = 0; i < CORE_COUNT; i++) r.core[i].affinity = core_affinity[i];

    group_start(&g, &r.out, "BOOT_CPU");
    add_hex(&g, "MPIDR_EL1", r.mpidr);
    add_hex(&g, "CNTFRQ_EL0", r.cntfrq);
    if (r.freq != r.cntfrq) add(&g, "FREQ=DEFAULT");
    group_end(&g);

    phase_zero(&r);
    for (unsigned i = 1; i < CORE_COUNT; i++)
        if (r.core[i].eligible) targets[count++] = &r.core[i];
    if (r.core[PHASE1_TARGET].eligible) normal = phase_one(&r);
    else say(&r.out, "P1", "SKIPPED=NOT_OFF", 0);
    if (normal) phase_two(&r, targets, count);
    else say(&r.out, "P2", "SKIPPED=P1_NOT_NORMAL", 0);

    /* The summary is the last phase that ran; a core left running counts from either. */
    struct core *last_phase[CORE_COUNT];
    unsigned last_count = 0;
    if (normal) {
        for (unsigned i = 0; i < count; i++) last_phase[last_count++] = targets[i];
    } else if (r.first.called) {
        last_phase[last_count++] = &r.first;
    }
    struct tally t = tally_of(last_phase, last_count);
    for (unsigned i = 0; i < CORE_COUNT; i++) left += r.core[i].started && !r.core[i].off;
    left += r.first.started && !r.first.off;
    group_start(&g, &r.out, "CORES");
    g.essential = 1;
    add_dec(&g, "STARTED", t.started);
    add_dec(&g, "REPORTED", t.reported);
    add_dec(&g, "OFF", t.off);
    if (r.out.suppressed) add_dec(&g, "SUPPRESSED", r.out.suppressed);
    group_end(&g);
    pl_begin(&text);
    pl_text(&text, "NO_SYSTEM_OFF_RESET_SUSPEND NO_CPU_SUSPEND BOOT_CPU_NO_MSR LEFT_RUNNING=");
    put_dec(&text, left);
    say(&r.out, "NOT_DONE", text.buf, 1);
    return left ? 2 : 0;
}
