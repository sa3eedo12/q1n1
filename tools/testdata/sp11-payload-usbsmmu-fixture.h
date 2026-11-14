/* SPDX-License-Identifier: MIT */
/* The fixtures of tools/test-q1n1-sp11-payload-usbsmmu.c, on top of the model in sp11-payload-usbsmmu-model.h.
 *
 * "Unit-like" means the values the S0 survey OBSERVED on the unit (docs/SP11-STICK-LOG.md section 12 of the Snapintosh tree)
 * where it read them: U0 halted after ExitBootServices with USBCMD 0, USBSTS 0x1019, CRCR 0 and CONFIG 0x40, xHCI 1.10,
 * CAPLENGTH 0x20, 64-byte contexts, 64 slots, 2 ports; PORTSC 0xE03 and 0x81203; the firmware's DCBAAP, event ring segment table
 * and event dequeue pointer at the addresses the survey printed, three slots (a hub topology); U1 idle (USBSTS 0x1, DCBAAP 0,
 * CONFIG 0, both ports in RxDetect); the DWC3 ID 0x33313130 in host mode (PRTCAPDIR 1, CURMOD 1) with no latched bus error;
 * apps_smmu with ID0 0x7C017E9A, sCR0 0x230406, no global fault, streams 0x1420 and 0x1460 matching stream match registers 3
 * and 4, both S2CR TYPE translate into context bank 3.
 *
 * Everything S0 did NOT read is made up here, and so are the words of what it read but the log only decodes, and all of it is
 * different from everything else so that a payload that prints one register under another's name shows: ID1, ID2, ERSTSZ,
 * GBUSERRADDR1 and the DWC3 debug register, the words of GCTL and GSTS (S0 has PRTCAPDIR and CURMOD, not the words), U1's
 * USBCMD and port words (S0 has RxDetect), the contents of the event ring, the context bank registers, the page tables. Those
 * values prove the payload decodes and prints what it reads; they say nothing about the unit. */
#pragma once
#include "sp11-payload-usbsmmu-model.h"

#define DCBAA UINT64_C(0xcf412000)
#define RING UINT64_C(0xcf414000)
#define ERST UINT64_C(0xcf415240)
#define ERDP_VALUE UINT64_C(0xcf414cb8)     /* bit 3, Event Handler Busy, is set */
#define CTX1 UINT64_C(0xcf416ac0)
#define CTX2 UINT64_C(0xcf419b00)
#define CTX3 UINT64_C(0xcf41cb40)
#define FW_BASE UINT64_C(0xcf400000)        /* the firmware's xHCI memory: one boot services data descriptor */
#define TBL_BASE UINT64_C(0xa0000000)       /* the page tables: inside the low conventional descriptor */
#define TBL_END (TBL_BASE + 0x400000)
#define CB_BANK 3u
#define CB_PAGE(n) (SMMU_BASE + (uint64_t)(128 + (n)) * 4096u)      /* NUMPAGENDXB 6: 128 global pages */
#define ATTR_DEFAULT (UINT64_C(0x744))                              /* AttrIndx 1, inner shareable, user, AF */
#define MASK48 ((UINT64_C(1) << 48) - 1)

/* ---- xHCI -------------------------------------------------------------------------------------------------------------- */

static unsigned fx_csz = 1;                 /* HCCPARAMS1.CSZ: 1 is 64-byte contexts (what the unit has), 0 is 32-byte */

static void fx_xhci(uint64_t base, uint32_t cmd, uint32_t sts, uint64_t dcbaap, uint32_t p1, uint32_t p2)
{
    uint64_t op = base + 0x20, rt = base + 0x1000;
    rset(base, 0x01100020);                 /* HCIVERSION 1.10, CAPLENGTH 0x20 */
    rset(base + 4, 0x02000840);             /* 64 slots, 8 interrupters, 2 ports */
    rset(base + 0x10, 0x0110ffc1 | fx_csz << 2);
    rset(base + 0x18, 0x1000);              /* RTSOFF */
    rset(op, cmd);
    rset(op + 4, sts);
    rset64(op + 0x18, 0);                   /* CRCR reads 0 on a halted controller */
    rset64(op + 0x30, dcbaap);
    rset(op + 0x38, 0x40);
    rset(op + 0x400, p1);
    rset(op + 0x410, p2);
    rset(rt + 0x28, 0);
    rset64(rt + 0x30, 0);
    rset64(rt + 0x38, 0);
}

static void fx_rings(uint64_t base)
{
    uint64_t rt = base + 0x1000;
    rset(rt + 0x28, 1);
    rset64(rt + 0x30, ERST);
    rset64(rt + 0x38, ERDP_VALUE);
}

/* One TRB: type, completion code, slot, cycle bit and the port id of a port status change event. */
static void fx_trb(uint64_t at, unsigned type, unsigned cc, unsigned slot, unsigned cycle, unsigned port)
{
    ram_w32(at, port << 24);
    ram_w32(at + 4, 0);
    ram_w32(at + 8, cc << 24);
    ram_w32(at + 12, slot << 24 | type << 10 | cycle);
}

/* A device context: slot context (route, speed, root port, state, address, last valid context index) and endpoints
 * ep[i] = {dci, state, type, max packet size} ended by dci 0. */
struct fx_ep { unsigned dci, state, type, mps; };
static void fx_slot(uint64_t ctx, unsigned route, unsigned speed, unsigned port, unsigned addr, unsigned hub, const struct fx_ep *ep)
{
    unsigned last = 0;
    memset(ram_at(ctx, 32 * 64), 0, 32 * 64);       /* the whole device context: 31 endpoints and the slot */
    for (const struct fx_ep *e = ep; e->dci; e++) if (e->dci > last) last = e->dci;
    ram_w32(ctx, route | speed << 20 | hub << 26 | last << 27);
    ram_w32(ctx + 4, port << 16);
    ram_w32(ctx + 8, 0);
    ram_w32(ctx + 12, addr | 3u << 27);
    for (const struct fx_ep *e = ep; e->dci; e++) {
        ram_w32(ctx + e->dci * (fx_csz ? 64u : 32u), e->state);
        ram_w32(ctx + e->dci * (fx_csz ? 64u : 32u) + 4, e->type << 3 | e->mps << 16);
    }
}

/* ---- The memory map ------------------------------------------------------------------------------------------------------- */

static void fx_map(void)
{
    map_clear();
    map_add(4, UINT64_C(0xcf400000), 0x100);                    /* boot services data: the firmware's xHCI memory */
    map_add(10, UINT64_C(0xcf500000), 0x10);                    /* ACPI NVS */
    map_add(0, UINT64_C(0xcf510000), 0x10);                     /* reserved */
    map_add(1, UINT64_C(0xcf600000), 4);                        /* loader code: the payload */
    map_add(2, UINT64_C(0xcf610000), 16);                       /* loader data: its stack */
    map_add(6, UINT64_C(0xcf700000), 0x10);                     /* runtime data */
    map_add(9, UINT64_C(0xcf800000), 8);                        /* ACPI reclaim */
    map_add(7, UINT64_C(0x80000000), 0x40000);                  /* conventional, low bank (1 GiB) */
    map_add(7, UINT64_C(0x880000000), 0x100000);                /* conventional, high bank (4 GiB): the largest */
    map_add(11, UINT64_C(0xf0000000), 0x100);                   /* MMIO */
}

static void fx_ram(void)
{
    for (unsigned i = 0; i < nram; i++) free(ram[i].mem);
    nram = 0;
    ram_add(FW_BASE, 0x100000);
    ram_add(UINT64_C(0xcf500000), 0x10000);                     /* the NVS and reserved descriptors have memory behind them: */
    ram_add(UINT64_C(0xcf510000), 0x10000);                     /* a pointer into them must be refused, not faulted */
    ram_add(UINT64_C(0xcf600000), 0x20000);
    ram_add(TBL_BASE, 0x400000);
    ram_add(UINT64_C(0x880000000), 0x1000);
}

/* ---- SMMU ---------------------------------------------------------------------------------------------------------------- */

static void fx_smmu(void)
{
    rset(SMMU_BASE, 0x230406);
    rset(SMMU_BASE + 0x20, 0x7C017E9A);
    rset(SMMU_BASE + 0x24, 0x60800080);     /* 4 KiB pages, NUMPAGENDXB 6, 128 context banks */
    rset(SMMU_BASE + 0x28, 0x7555);
    rset(SMMU_BASE + 0x48, 0);
    for (unsigned n = 0; n < 154; n++) {
        rset(SMMU_BASE + 0x800 + 4 * n, n % 7 ? 0x80000000u | (0x2000u + n * 0x20) : 0);
        rset(SMMU_BASE + 0xc00 + 4 * n, n % 2 ? 0x00010000 : 0x00020000);       /* bypass or fault */
    }
    rset(SMMU_BASE + 0x800 + 4 * 3, 0x80001420);
    rset(SMMU_BASE + 0x800 + 4 * 4, 0x80001460);
    rset(SMMU_BASE + 0x800 + 4 * 9, 0x800f1400);      /* mask 0xF over 0x1400: 0x1400 to 0x140F, not 0x1420 */
    rset(SMMU_BASE + 0x800 + 4 * 10, 0x00001420);     /* the right id with the valid bit clear: no match */
    rset(SMMU_BASE + 0x800 + 4 * 11, 0x80001400);
    rset(SMMU_BASE + 0xc00 + 4 * 3, 3);
    rset(SMMU_BASE + 0xc00 + 4 * 4, 3);
}

static void fx_bank(unsigned n, uint32_t cbar, uint32_t cba2r, uint32_t sctlr, uint32_t tcr, uint32_t tcr2, uint64_t ttbr0, uint32_t mair0)
{
    rset(SMMU_BASE + 0x1000 + 4 * n, cbar);
    rset(SMMU_BASE + 0x1800 + 4 * n, cba2r);
    rset(CB_PAGE(n), sctlr);
    rset(CB_PAGE(n) + 0x10, tcr2);
    rset64(CB_PAGE(n) + 0x20, ttbr0);
    rset64(CB_PAGE(n) + 0x28, 0);
    rset(CB_PAGE(n) + 0x30, tcr);
    rset(CB_PAGE(n) + 0x38, mair0);
    rset(CB_PAGE(n) + 0x3c, 0);
    rset(CB_PAGE(n) + 0x58, 0);
    rset64(CB_PAGE(n) + 0x60, 0);
    rset(CB_PAGE(n) + 0x68, 0);
}

/* ---- Page tables, built the plain way: from the architecture's own description, not from the payload ---------------------------- */

static struct { unsigned pg, ias, start; uint64_t root, next, end; } pt;
static uint64_t ram_r64(uint64_t addr)
{
    uint8_t *p = ram_at(addr, 8);
    uint64_t v = 0;
    if (!p) { fprintf(stderr, "FAIL: fixture reads outside its RAM\n"); exit(2); }
    for (unsigned i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}
static unsigned pt_shift(unsigned level) { return pt.pg + (pt.pg - 3) * (3 - level); }
static uint64_t pt_alloc(void)
{
    uint64_t t = pt.next;
    pt.next += UINT64_C(1) << pt.pg;
    if (pt.next > pt.end) { fprintf(stderr, "FAIL: the page-table region is full\n"); exit(2); }
    return t;
}
/* Granule 12, 14 or 16 (4, 16 or 64 KiB); the input size is 64 - t0sz bits; levels as many as the bits need. */
static void pt_init(unsigned pg, unsigned t0sz, uint64_t base)
{
    unsigned bpl = pg - 3;
    pt.pg = pg;
    pt.ias = 64 - t0sz;
    pt.start = 4 - (pt.ias - pg + bpl - 1) / bpl;
    pt.next = base;
    pt.end = TBL_END;
    memset(ram_at(base, pt.end - base), 0, pt.end - base);
    pt.root = pt_alloc();
}
static uint64_t pt_slot(uint64_t iova, unsigned leaf)
{
    uint64_t table = pt.root;
    for (unsigned level = pt.start;; level++) {
        unsigned shift = pt_shift(level), bits = level == pt.start ? pt.ias - shift : pt.pg - 3;
        uint64_t slot = table + (iova >> shift & ((UINT64_C(1) << bits) - 1)) * 8, d = ram_r64(slot);
        if (level == leaf) return slot;
        if (!(d & 1)) {
            uint64_t t = pt_alloc();
            ram_w64(slot, t | 3);
            d = t | 3;
        }
        table = d & MASK48 & ~((UINT64_C(1) << pt.pg) - 1);
    }
}
/* A leaf at `leaf`: a page at level 3, a block above. */
static void pt_map(uint64_t iova, uint64_t oa, unsigned leaf, uint64_t attr)
{
    unsigned shift = pt_shift(leaf);
    ram_w64(pt_slot(iova, leaf), (oa & MASK48 & ~((UINT64_C(1) << shift) - 1)) | attr | (leaf == 3 ? 3 : 1));
}

/* Context bank 3 as Linux's io-pgtable would leave it for a stage-1 bank: 48 bit, 4 KiB, TTBR0 only, ASID 4. */
static void fx_walkable(unsigned pg, unsigned t0sz)
{
    uint32_t tg0 = pg == 12 ? 0 : pg == 16 ? 1 : 2;
    uint32_t tcr = t0sz | 1u << 23 | tg0 << 14 | 3u << 12 | 3u << 10 | 3u << 8;
    pt_init(pg, t0sz, TBL_BASE);
    fx_bank(CB_BANK, 0x00010003, 1, 0x000205f7, tcr, 5, UINT64_C(4) << 48 | pt.root, 0x0004ff44);
}
/* The unit-like tables: identity blocks over every region the payload probes. */
static void fx_identity(void)
{
    static const uint64_t blocks[] = {UINT64_C(0xcf400000), UINT64_C(0xcf600000), UINT64_C(0x880000000), UINT64_C(0x97fe00000),
                                      UINT64_C(0x80000000)};
    fx_walkable(12, 16);
    for (unsigned i = 0; i < sizeof blocks / sizeof blocks[0]; i++) pt_map(blocks[i], blocks[i], 2, ATTR_DEFAULT);
}

/* ---- The whole unit ---------------------------------------------------------------------------------------------------------- */

static void fx_reset(void)
{
    nregs = 0;
    mode = MODE_SCRIPT;
    fill_value = 0;
    rng_seed = 0;
    fault_index = 0;
    fault_lo = fault_hi = 0;
    expected_banks[0] = CB_BANK;                /* the only bank the streams select; a test that moves them says so */
    expected_banks_n = 1;
    el_raw = 2 << 2;
    fx_map();
    fx_ram();
}

static void fx_topology_hub(void)
{
    static const struct fx_ep hub_hs[] = {{1, 1, 4, 0x40}, {3, 1, 7, 1}, {0, 0, 0, 0}};
    static const struct fx_ep hub_ss[] = {{1, 1, 4, 0x200}, {3, 1, 7, 2}, {0, 0, 0, 0}};
    static const struct fx_ep stick[] = {{1, 1, 4, 0x200}, {2, 1, 2, 0x400}, {5, 1, 6, 0x400}, {0, 0, 0, 0}};
    ram_w64(DCBAA + 8, CTX1);
    ram_w64(DCBAA + 16, CTX2);
    ram_w64(DCBAA + 24, CTX3);
    fx_slot(CTX1, 0, 3, 1, 1, 0, hub_hs);
    fx_slot(CTX2, 0, 4, 2, 2, 0, hub_ss);
    fx_slot(CTX3, 3, 4, 2, 3, 0, stick);
}

/* The stick plugged in directly: one slot, route string 0, on the SuperSpeed port. */
static void fx_topology_direct(void)
{
    static const struct fx_ep stick[] = {{1, 1, 4, 0x200}, {2, 1, 2, 0x400}, {5, 1, 6, 0x400}, {0, 0, 0, 0}};
    memset(ram_at(DCBAA, 0x100), 0, 0x100);
    ram_w64(DCBAA + 8, CTX1);
    fx_slot(CTX1, 0, 4, 2, 1, 0, stick);
}

/* S0's values where it read them (the header above), made-up ones elsewhere, the hub topology, tables that map the probed
 * regions identity. */
static void fx_unit_like(void)
{
    fx_reset();
    fx_xhci(U0_BASE, 0, 0x1019, DCBAA, 0xe03, 0x81203);
    fx_rings(U0_BASE);
    fx_xhci(U1_BASE, 0, 1, 0, 0x2a0, 0x2a0);
    rset(U1_BASE + 0x20 + 0x38, 0);         /* S0: the idle controller's CONFIG is 0; U0's 0x40 is the firmware's */
    rset(U0_BASE + 0xc110, 0x30c11004);     /* the word is made up; S0 has PRTCAPDIR 1 (host mode) */
    rset(U0_BASE + 0xc118, 1);              /* the word is made up; S0 has CURMOD 1 (host) */
    rset(U0_BASE + 0xc120, 0x33313130);
    rset(U0_BASE + 0xc130, 0);              /* S0: no latched bus error */
    rset(U0_BASE + 0xc134, 0);              /* made up: S0 did not read the high half */
    rset(U0_BASE + 0xc164, 0x4009);         /* made up */
    ram_w64(ERST, RING);
    ram_w32(ERST + 8, 0x100);
    fx_trb(RING + 202 * 16, 34, 1, 0, 1, 2);        /* M1: a port status change event for port 2 */
    fx_trb(RING + 201 * 16, 33, 1, 3, 1, 0);        /* M2: a command completion for slot 3 */
    fx_trb(RING + 200 * 16, 32, 1, 3, 1, 0);        /* M3: a transfer event for slot 3 */
    ram_w32(RING + 203 * 16 + 12, 0);               /* AT: nothing new */
    fx_topology_hub();
    fx_smmu();
    fx_identity();
}

/* What the operator's next boot should show: the same unit, the stick in directly, one slot. */
static void fx_direct(void)
{
    fx_unit_like();
    fx_topology_direct();
}

/* ---- Text and hostile values for the suites --------------------------------------------------------------------------------- */

/* The text of the probe line that ends in `role`, after "WALK ": IOVA=.. OA=.. and so on. */
static const char *walk_of(const char *role)
{
    size_t n = strlen(role);
    for (unsigned i = 0; i < nevents; i++) {
        if (events[i].kind != EV_LINE) continue;
        const char *t = events[i].text + 16;
        size_t len = strlen(t);
        if (!strncmp(t, "WALK IOVA=", 10) && len > n + 1 && t[len - n - 1] == ' ' && !strcmp(t + len - n, role)) return t + 5;
    }
    return NULL;
}

/* The loads that came after the line starting `from` and before the next line (the reads one group did between two prints). */
static unsigned loads_after(const char *from)
{
    unsigned n = 0;
    int on = 0;
    for (unsigned i = 0; i < nevents; i++) {
        if (events[i].kind == EV_LINE) {
            if (on) break;
            on = !strncmp(events[i].text + 16, from, strlen(from));
        } else if (events[i].kind == EV_LOAD && on) {
            n++;
        }
    }
    return n;
}

static uint32_t hostile_value(uint64_t r)
{
    static const uint32_t pool[] = {0, 0xffffffffu, 1, 0x80000000u, 0x7fffffffu, 0xffff0000u, 0xffffu, 0x10000u, 0xfffffff0u,
                                    0x3f, 0x40, 0x1000, 0xdeadbeefu, 0x0a600000u, 0x15000000u, 0x00ffffffu};
    return (r & 3) ? pool[(r >> 8) % (sizeof pool / sizeof pool[0])] : (uint32_t)(r >> 16);
}

/* A unit with `count` hostile words: scripted registers, the firmware's structures, the page tables, the memory map. */
static void fx_perturb(uint64_t seed, unsigned count)
{
    static const struct { uint64_t base, size; } spots[] = {
        {DCBAA, 0x80}, {ERST, 16}, {RING + 196 * 16, 12 * 16}, {CTX1, 0x300}, {CTX2, 0x200}, {CTX3, 0x300}, {TBL_BASE, 0x6000}};
    for (unsigned k = 0; k < count; k++) {
        uint64_t r = mix(seed * 7919 + k);
        unsigned pick = (unsigned)(r >> 4) % 10;
        if (pick < 5 && nregs) {
            regs[(r >> 12) % nregs].value = hostile_value(r >> 20);
        } else if (pick < 9) {
            unsigned s = (unsigned)(r >> 12) % (sizeof spots / sizeof spots[0]);
            ram_w32(spots[s].base + ((r >> 24) % (spots[s].size / 4)) * 4, hostile_value(r >> 28));
        } else if (map_n) {
            uint8_t *d = map_buf + ((r >> 12) % map_n) * MAP_STRIDE;
            uint64_t v = (r >> 5) & 1 ? (uint64_t)hostile_value(r >> 20) << ((r >> 40) & 32) : (r >> 22);
            memcpy(d + (((r >> 10) & 1) ? 8 : 24), &v, 8);
            if (r >> 63) memcpy(d, &(uint32_t){(uint32_t)(r >> 33) & 15}, 4);
        }
    }
}
