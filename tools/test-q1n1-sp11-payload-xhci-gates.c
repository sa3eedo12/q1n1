/* SPDX-License-Identifier: MIT */
/* The gates of the payload "xhci" called directly (payloads/xhci-io.c: store, ram_put, arena_range, clean_range). The other suites show that every
 * store the payload makes is a legal one; this one shows that each rule of a gate refuses what it exists to refuse, with no help from a caller:
 * every input below breaks exactly one rule and the gate must answer with that rule's code, leave a refusal word naming the register, and let nothing
 * through to the model (no store, no cache instruction outside the arena, no violation of the model's own audit). Two legal calls at the start show
 * that the context here is one the gates accept and that the model counts what reaches it, so that "nothing reached it" means something.
 * tools/sp11_payload_xhci_mutants.py removes one rule at a time from the gates and requires this suite to fail. Nothing here runs on hardware.
 * Evidence: EXPERIMENTAL (host model only). */
#include "test-q1n1-sp11-payload-xhci.h"
#include "xhci-priv.h"

static struct ctx ctx;
static const uint64_t TOP = UINT64_C(0xffffffffffffe000);

/* A context the way the pre-flight leaves it with every group open and no refusal: each case breaks one rule of it. */
static struct ctx *fresh(void)
{
    struct xhc *x;
    world_default();
    world_apply();
    memset(&ctx, 0, sizeof ctx);
    ctx.a = &args;
    x = &ctx.x[TARGET];
    x->op = CAPLENGTH;
    x->ir0 = RTSOFF + 0x20;
    x->db = DBOFF;
    ctx.armed = G_ARENA | G_RESET | G_PROGRAM | G_RUN | G_NOOP;
    ctx.arena.base = regions[R_STACK].base + 0x1000;
    ctx.arena.pages = 3;
    ctx.arena.id = 2;
    arena_base = ctx.arena.base;
    arena_bytes = 3 * 4096;
    return &ctx;
}

static int nothing_reached_the_model(const char *what)
{
    if (nstores || ram_stores || model_violation_mask()) {
        fprintf(stderr, "FAIL: %s reached the model (%u stores, %u RAM stores, violations 0x%x %s)\n", what, nstores, ram_stores, model_violation_mask(),
                model_first_violation());
        fail_count++;
        return 1;
    }
    checks_count++;
    return 0;
}

/* One refused store: its code, the refusal word (code, then the register plus one), and nothing at the model. */
static int store_refused(struct ctx *c, unsigned group, unsigned reg, uint32_t value, int code)
{
    char what[80];
    int rc = store(c, group, reg, value);
    snprintf(what, sizeof what, "store(group %u, reg %u, 0x%x)", group, reg, value);
    if (rc != code || (c->store_refusal & 0xffu) != (unsigned)code || c->store_refusal >> 8 != reg + 1u) {
        fprintf(stderr, "FAIL: %s returned %d with refusal word 0x%x, wanted %d\n", what, rc, c->store_refusal, code);
        fail_count++;
        return 1;
    }
    return nothing_reached_the_model(what);
}

static int ram_refused(struct ctx *c, uint64_t address, const char *why)
{
    char what[96];
    ram_put(c, address, 0x1234u);
    snprintf(what, sizeof what, "ram_put(0x%" PRIx64 ") %s", address, why);
    if (!c->ram_refusal) {
        fprintf(stderr, "FAIL: %s was not refused\n", what);
        fail_count++;
        return 1;
    }
    return nothing_reached_the_model(what);
}

static int range_refused(struct ctx *c, uint64_t start, uint64_t bytes, const char *why)
{
    char what[96];
    int rc = arena_range(c, start, bytes);
    snprintf(what, sizeof what, "arena_range(0x%" PRIx64 ", 0x%" PRIx64 ") %s", start, bytes, why);
    if (rc || !c->ram_refusal) {
        fprintf(stderr, "FAIL: %s was not refused\n", what);
        fail_count++;
        return 1;
    }
    return nothing_reached_the_model(what);
}

/* The two legal calls: the gates accept what the record allows, and the model counts it. The ARENA and PROGRAM lines go through the model's own
 * page hook, so that its audit sees them and eight seconds of its counter pass before the stores. */
static int legal_controls(void)
{
    struct ctx *c = fresh();
    char line[100];
    snprintf(line, sizeof line, "PAYLOAD XHCI NEXT ARENA 2 STACK 0X%llX PAGES 3 AFTER 8 S", (unsigned long long)c->arena.base);
    args.ops.puts(line);
    args.ops.puts("PAYLOAD XHCI NEXT PROGRAM AFTER 8 S");
    for (unsigned i = 0; i < 9000; i++) args.ops.counter();
    CHECK(store(c, G_PROGRAM, SR_CONFIG, 64) == STORE_OK && !c->store_refusal);
    CHECK(nstores == 1 && !strcmp(stores[0].name, "CONFIG") && !ram_stores);
    ram_put(c, c->arena.base + 0x400, 0x5a5a5a5au);
    CHECK(!c->ram_refusal && ram_stores == 1 && !model_violation_mask());
    CHECK(arena_range(c, c->arena.base, 3 * 4096) && arena_range(c, c->arena.base + 3 * 4096 - 16, 16) && !c->ram_refusal);
    return 0;
}

static int usbcmd_rules(void)
{
    /* Another bit than RS and HCRST changed from what was last read (a bit of the firmware's setting is kept, one that is not set stays clear). */
    static const struct { unsigned group; uint32_t seen, value; } other_bits[] = {
        {G_RUN, 0, CMD_RS | 4u}, {G_RESET, 0, CMD_HCRST | 4u}, {G_STOP, 4u, 0}, {G_RUN, 4u, CMD_RS}, {G_RESET, 0, CMD_HCRST | 0x80000000u}, {G_STOP, 0, 8u}};
    /* The group of the value: HCRST in RESET, RS in RUN, a halt in STOP, and nowhere else. A value with both bits has the reset's group, so that only the rule
     * against both can refuse it (below). */
    static const struct { unsigned group; uint32_t value; } wrong_group[] = {
        {G_RUN, CMD_HCRST}, {G_PROGRAM, CMD_HCRST}, {G_STOP, CMD_HCRST}, {G_ARENA, CMD_HCRST}, {G_NOOP, CMD_HCRST}, {G_RESET, CMD_RS}, {G_PROGRAM, CMD_RS},
        {G_STOP, CMD_RS}, {G_NOOP, CMD_RS}, {G_RESET, 0}, {G_RUN, 0}, {G_PROGRAM, 0}, {G_NOOP, 0}, {G_ARENA, 0}};
    struct ctx *c;
    for (unsigned i = 0; i < sizeof other_bits / sizeof other_bits[0]; i++) {
        c = fresh();
        c->cmd_seen = other_bits[i].seen;
        CHECK(!store_refused(c, other_bits[i].group, SR_USBCMD, other_bits[i].value, STORE_BITS));
    }
    c = fresh();
    CHECK(!store_refused(c, G_RESET, SR_USBCMD, CMD_RS | CMD_HCRST, STORE_BITS));
    c = fresh();
    CHECK(!store_refused(c, G_RUN, SR_USBCMD, CMD_RS | CMD_HCRST, STORE_BITS));
    for (unsigned i = 0; i < sizeof wrong_group / sizeof wrong_group[0]; i++) {
        c = fresh();
        CHECK(!store_refused(c, wrong_group[i].group, SR_USBCMD, wrong_group[i].value, STORE_BITS));
    }
    return 0;
}

static int register_groups(void)
{
    /* The groups each register of the record may be stored in, from the record and not from the payload's table. USBCMD is the rules above. */
    static const struct { unsigned reg, allowed; } matrix[] = {
        {SR_CRCR_LO, G_PROGRAM}, {SR_CRCR_HI, G_PROGRAM}, {SR_DCBAAP_LO, G_PROGRAM}, {SR_DCBAAP_HI, G_PROGRAM}, {SR_CONFIG, G_PROGRAM}, {SR_ERSTSZ, G_PROGRAM},
        {SR_ERSTBA_LO, G_PROGRAM}, {SR_ERSTBA_HI, G_PROGRAM}, {SR_ERDP_LO, G_PROGRAM | G_NOOP}, {SR_ERDP_HI, G_PROGRAM | G_NOOP}, {SR_IMAN, G_NOOP}, {SR_DB0, G_NOOP}};
    static const unsigned groups[] = {G_STOP, G_ARENA, G_RESET, G_PROGRAM, G_RUN, G_NOOP};
    CHECK(sizeof matrix / sizeof matrix[0] == SR_COUNT - 1);
    for (unsigned i = 0; i < sizeof matrix / sizeof matrix[0]; i++)
        for (unsigned g = 0; g < sizeof groups / sizeof groups[0]; g++) {
            struct ctx *c = fresh();
            uint32_t legal_value = matrix[i].reg == SR_IMAN ? IMAN_IP : matrix[i].reg == SR_DB0 ? 0 : 0x1000u;
            if (matrix[i].allowed & groups[g]) continue;
            CHECK(!store_refused(c, groups[g], matrix[i].reg, legal_value, STORE_BITS));
        }
    return 0;
}

static int value_rules(void)
{
    static const uint32_t iman[] = {0, 2, 3, 0x80000001u, 0xffffffffu}, doorbell[] = {1, 0x100, 0x10000, 0xffffffffu};
    for (unsigned i = 0; i < sizeof iman / sizeof iman[0]; i++) {
        struct ctx *c = fresh();
        CHECK(!store_refused(c, G_NOOP, SR_IMAN, iman[i], STORE_BITS));
    }
    for (unsigned i = 0; i < sizeof doorbell / sizeof doorbell[0]; i++) {
        struct ctx *c = fresh();
        CHECK(!store_refused(c, G_NOOP, SR_DB0, doorbell[i], STORE_BITS));
    }
    return 0;
}

static int arming_and_window(void)
{
    struct ctx *c = fresh();
    /* Not armed: no group, another group, or a halt before any group opened. */
    c->armed = 0;
    CHECK(!store_refused(c, G_PROGRAM, SR_CONFIG, 64, STORE_NOT_ARMED));
    c = fresh();
    c->armed = G_RESET | G_RUN | G_NOOP | G_ARENA;
    CHECK(!store_refused(c, G_PROGRAM, SR_CONFIG, 64, STORE_NOT_ARMED));
    c = fresh();
    c->armed = 0;
    CHECK(!store_refused(c, G_STOP, SR_USBCMD, 0, STORE_NOT_ARMED));
    c = fresh();
    c->armed = G_PROGRAM;
    CHECK(!store_refused(c, G_NOOP, SR_DB0, 0, STORE_NOT_ARMED));
    /* A window that already faulted on a load. */
    c = fresh();
    c->dead = 1u << TARGET;
    CHECK(!store_refused(c, G_PROGRAM, SR_CONFIG, 64, STORE_DEAD));
    /* A register that is not one of the thirteen. */
    c = fresh();
    CHECK(!store_refused(c, G_PROGRAM, SR_COUNT, 0, STORE_BAD_REG));
    c = fresh();
    CHECK(!store_refused(c, G_PROGRAM, SR_COUNT + 40u, 0, STORE_BAD_REG));
    return 0;
}

static int store_range(void)
{
    /* Where the offsets the controller gave put a register: at or past the DWC3 global registers (0xc100), not word aligned, or far outside. */
    static const uint64_t doorbells[] = {0xc100, 0xc110, 0xc0fe, 0x2002, 0x2001, 0xfc0fc, 0x1000000, UINT64_C(0xffffffff), UINT64_C(0xfffffffffffffffc)};
    struct ctx *c;
    for (unsigned i = 0; i < sizeof doorbells / sizeof doorbells[0]; i++) {
        c = fresh();
        c->x[TARGET].db = doorbells[i];
        CHECK(!store_refused(c, G_NOOP, SR_DB0, 0, STORE_RANGE));
    }
    c = fresh();
    c->x[TARGET].ir0 = 0xc0f0;                              /* ERDP high word at 0xc10c */
    CHECK(!store_refused(c, G_NOOP, SR_ERDP_HI, 0, STORE_RANGE));
    c = fresh();
    c->x[TARGET].ir0 = 0xc0e1;                              /* IMAN, misaligned */
    CHECK(!store_refused(c, G_NOOP, SR_IMAN, IMAN_IP, STORE_RANGE));
    c = fresh();
    c->x[TARGET].op = 0xc0f0;                               /* CONFIG at 0xc128 */
    CHECK(!store_refused(c, G_PROGRAM, SR_CONFIG, 64, STORE_RANGE));
    c = fresh();
    c->x[TARGET].op = 0xc0fd;                               /* USBCMD, misaligned */
    CHECK(!store_refused(c, G_STOP, SR_USBCMD, 0, STORE_RANGE));
    return 0;
}

static int ram_rules(void)
{
    struct ctx *c = fresh();
    const uint64_t base = c->arena.base, size = 3 * 4096;
    c->armed &= ~(unsigned)G_ARENA;
    CHECK(!ram_refused(c, base + 0x400, "with the ARENA group closed"));
    c = fresh();
    CHECK(!ram_refused(c, base + 2, "unaligned"));
    c = fresh();
    CHECK(!ram_refused(c, base + 0x401, "unaligned by one"));
    c = fresh();
    CHECK(!ram_refused(c, base - 4, "just below the arena"));
    c = fresh();
    CHECK(!ram_refused(c, base - 4096, "a page below the arena"));
    c = fresh();
    CHECK(!ram_refused(c, 0, "at address 0"));
    c = fresh();
    CHECK(!ram_refused(c, base + size, "at the end of the arena"));
    c = fresh();
    CHECK(!ram_refused(c, base + size + 4, "past the end of the arena"));
    c = fresh();
    CHECK(!ram_refused(c, base + 0x100000, "a megabyte above the arena"));
    c = fresh();
    CHECK(!ram_refused(c, base + size - 2, "unaligned at the end"));
    /* An arena at the top of the address space: the word at the very top is not inside it, and an address that a sum would wrap is not either. */
    c = fresh();
    c->arena.base = TOP;
    c->arena.pages = 1;
    CHECK(!ram_refused(c, UINT64_C(0xfffffffffffffffc), "at the top of the address space, past an arena below it"));
    c = fresh();
    c->arena.base = TOP;
    c->arena.pages = 1;
    CHECK(!ram_refused(c, 0, "at address 0 with an arena at the top"));
    /* An arena of no pages admits nothing. */
    c = fresh();
    c->arena.pages = 0;
    CHECK(!ram_refused(c, base, "in an arena of no pages"));
    c = fresh();
    c->arena.pages = 0;
    CHECK(!ram_refused(c, base + 0x100, "inside where an arena of no pages was"));
    return 0;
}

static int range_rules(void)
{
    struct ctx *c = fresh();
    const uint64_t base = c->arena.base, size = 3 * 4096;
    CHECK(!range_refused(c, base - 16, 16, "below the arena"));
    c = fresh();
    CHECK(!range_refused(c, base + size, 16, "at the end"));
    c = fresh();
    CHECK(!range_refused(c, base + size - 16, 32, "across the end"));
    c = fresh();
    CHECK(!range_refused(c, base, 0, "of no bytes"));
    c = fresh();
    CHECK(!range_refused(c, base, size + 16, "longer than the arena"));
    c = fresh();
    c->arena.base = TOP;
    c->arena.pages = 1;
    CHECK(!range_refused(c, UINT64_C(0xfffffffffffffff0), 16, "at the top, past an arena below it"));
    c = fresh();
    c->arena.pages = 0;
    CHECK(!range_refused(c, base, 16, "in an arena of no pages"));
    return 0;
}

/* A clean that overruns the arena stops at the arena's end, and one that starts below it does not start: no cache instruction reaches memory of anyone else
 * (the model's audit flags one), and the refusal is named. */
static int clean_rules(void)
{
    struct ctx *c = fresh();
    const uint64_t base = c->arena.base, size = 3 * 4096;
    clean_range(c, base, size + 4096);
    CHECK(c->ram_refusal && !model_violation_mask());
    c = fresh();
    clean_range(c, base - 4096, 8192);
    CHECK(c->ram_refusal && !model_violation_mask());
    c = fresh();
    clean_range(c, base + size - 16, 64);
    CHECK(c->ram_refusal && !model_violation_mask());
    c = fresh();
    clean_range(c, base + 0x400, 16);
    CHECK(!c->ram_refusal && !model_violation_mask());
    c = fresh();
    clean_range(c, base, size);
    CHECK(!c->ram_refusal && !model_violation_mask());
    return 0;
}

int suite_gates(void)
{
    if (legal_controls() || usbcmd_rules() || register_groups() || value_rules() || arming_and_window() || store_range() || ram_rules() || range_rules() ||
        clean_rules())
        return 1;
    return 0;
}
