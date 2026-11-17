/* SPDX-License-Identifier: MIT */
/* Payload "xhci", the memory map and the arenas (docs/SP11-PAYLOAD-XHCI.md; xhci-priv.h lists the parts): which RAM the runner's own UEFI
 * memory map calls free, where the up to four arenas the attempts use are, and what an arena holds. Every store to an arena goes through
 * ram_put (xhci-io.c). */
#include "xhci-priv.h"

/* ---- The UEFI memory map ------------------------------------------------------------------------------------------------------------ */

static inline uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static inline uint64_t le64(const uint8_t *p)
{
    return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32;
}

/* EFI_MEMORY_DESCRIPTOR: Type u32 at 0, PhysicalStart u64 at 8, NumberOfPages u64 at 24. The map is the runner's own memory (what
 * ExitBootServices was given), read in place. */
static inline const uint8_t *descriptor(const struct ctx *c, uint32_t i)
{
    return (const uint8_t *)(uintptr_t)(c->map.base + (uint64_t)i * c->map.stride);
}

enum { MT_BOOT_DATA = 4, MT_CONVENTIONAL = 7 };

/* A map whose size, stride or entries make no sense is no map, and then every arena that needs it is skipped by name. */
void map_init(struct ctx *c)
{
    const struct q1n1_payload_args *a = c->a;
    uint64_t entries;
    c->map.ok = c->map.count = 0;
    if (!a->map_base || (a->map_base & 7) || a->map_stride < 40 || a->map_stride > MAP_STRIDE_MAX || (a->map_stride & 7) || !a->map_size ||
        a->map_size % a->map_stride || a->map_base + a->map_size < a->map_base)
        return;
    entries = a->map_size / a->map_stride;
    if (entries > MAP_DESCRIPTORS_MAX) return;
    c->map.base = a->map_base;
    c->map.stride = a->map_stride;
    c->map.count = (uint32_t)entries;
    for (uint32_t i = 0; i < c->map.count; i++) {
        const uint8_t *d = descriptor(c, i);
        uint64_t pages = le64(d + 24), start = le64(d + 8);
        if (pages >= (UINT64_C(1) << 40) || start + pages * PAGE < start) return;     /* the map contradicts itself */
    }
    c->map.ok = 1;
}

/* True when every byte of [lo, hi) lies in descriptors whose type is in `types` (a bit per type). The walk follows adjacent descriptors
 * and is bounded by the descriptor count. */
OUT_OF_LINE int map_range_in(const struct ctx *c, uint64_t lo, uint64_t hi, uint32_t types)
{
    uint64_t at = lo;
    if (!c->map.ok || hi <= lo) return 0;
    for (uint32_t step = 0; step <= c->map.count && at < hi; step++) {
        uint64_t reach = at;
        for (uint32_t i = 0; i < c->map.count; i++) {
            const uint8_t *d = descriptor(c, i);
            uint64_t start = le64(d + 8), end = start + le64(d + 24) * PAGE;
            if (at < start || at >= end) continue;
            if (le32(d) > 31u || !(types >> le32(d) & 1u)) return 0;
            if (end > reach) reach = end;
        }
        if (reach == at) return 0;
        at = reach;
    }
    return at >= hi;
}

/* The highest descriptor of conventional memory that ends at or below 4 GiB and holds `bytes`: the top of the low extent where the runner
 * put its big files (they sat at 0xC3E65000 on the unit, OBSERVED, boots 8 and 9). The arena is its last pages. */
OUT_OF_LINE int map_top_low(const struct ctx *c, uint64_t bytes, uint64_t *base)
{
    uint64_t best = 0;
    if (!c->map.ok) return 0;
    for (uint32_t i = 0; i < c->map.count; i++) {
        const uint8_t *d = descriptor(c, i);
        uint64_t start = le64(d + 8), end = start + le64(d + 24) * PAGE;
        if (le32(d) != MT_CONVENTIONAL || end > (UINT64_C(1) << 32) || end - start < bytes || end <= best) continue;
        best = end;
    }
    if (!best) return 0;
    *base = best - bytes;
    return 1;
}

/* ---- The arenas --------------------------------------------------------------------------------------------------------------------- */

/* Arena `id` of `pages` pages (one for the structures, one per scratchpad buffer), or why not. 1: the firmware's own xHCI memory, for
 * usb_1_ss0 only. 2: inside the runner's payload stack, above the guard words in its first page and below the STACK_KEPT bytes the payload
 * and the runner's ops keep; not the payload image, whose loader-code pages may be mapped read-only. 3: the top of the low extent.
 * 4: in the 30 GiB bank, for a controller that takes 64-bit addresses. Only arena 2 is RAM the runner owns and declared to the payload; arenas 1, 3 and
 * 4 are RAM the memory map calls free, and they are the fallbacks after an attempt whose DMA may have gone astray (hazard (c) of the record). */
int arena_for(const struct ctx *c, unsigned id, uint32_t pages, struct arena *out)
{
    const struct q1n1_payload_args *a = c->a;
    uint64_t base = 0, bytes = (uint64_t)pages * PAGE;
    out->id = id;
    out->pages = pages;
    out->base = 0;
    if (pages > 1u + SCRATCH_MAX) return AR_TOO_BIG;
    if (id == 1) {
        if (XHCI_S1_CONTROLLER != 0) return AR_NOT_APPLICABLE;
        if (pages > ARENA1_PAGES) return AR_TOO_BIG;
        base = ARENA1_BASE;
        if (!c->map.ok) return AR_NO_MAP;
        if (!map_range_in(c, base, base + bytes, 1u << MT_BOOT_DATA | 1u << MT_CONVENTIONAL)) return AR_NOT_FREE;
    } else if (id == 2) {
        if ((a->stack_base & (PAGE - 1)) || a->stack_size < Q1N1_PAYLOAD_STACK_BYTES || a->stack_base + a->stack_size < a->stack_base)
            return AR_SMALL_STACK;
        if (bytes > a->stack_size - PAGE - STACK_KEPT) return AR_TOO_BIG;
        base = a->stack_base + PAGE;
    } else if (id == 3) {
        if (!c->map.ok) return AR_NO_MAP;
        if (!map_top_low(c, bytes, &base)) return AR_NOT_FREE;
    } else if (id == 4) {
        if (!c->x[TARGET].ac64) return AR_NO_AC64;
        base = ARENA4_BASE;
        if (!c->map.ok) return AR_NO_MAP;
        if (!map_range_in(c, base, base + bytes, 1u << MT_CONVENTIONAL)) return AR_NOT_FREE;
    } else {
        return AR_NOT_APPLICABLE;
    }
    out->base = base;
    return AR_OK;
}

/* Zero the arena, then lay out what the xHC will read: the scratchpad buffer array (in DCBAA[0] when there are buffers), the command ring
 * closed by a Link TRB, the one-entry segment table. The No Op TRB is written later, right before the doorbell. */
void arena_build(struct ctx *c, uint32_t scratch)
{
    const struct arena *ar = &c->arena;
    for (uint64_t at = ar->base; at < ar->base + (uint64_t)ar->pages * PAGE; at += 4) ram_put(c, at, 0);
    if (scratch) {
        ram_put64(c, ar->base + OFF_DCBAA, ar->base + OFF_SPARR);
        for (uint32_t i = 0; i < scratch; i++) ram_put64(c, ar->base + OFF_SPARR + 8u * i, ar->base + (uint64_t)(1u + i) * PAGE);
    }
    ram_put64(c, ar->base + OFF_CMD + (CMD_TRBS - 1) * TRB_BYTES, ar->base + OFF_CMD);
    ram_put(c, ar->base + OFF_CMD + (CMD_TRBS - 1) * TRB_BYTES + 12, TRB_LINK << 10 | 2u | 1u);   /* toggle cycle; cycle bit 1 */
    ram_put64(c, ar->base + OFF_ERST, ar->base + OFF_EVENT);
    ram_put(c, ar->base + OFF_ERST + 8, EVENT_TRBS);
    clean_range(c, ar->base, (uint64_t)ar->pages * PAGE);
}

/* After the halt: nothing of the attempt is left in RAM. */
void arena_zero(struct ctx *c)
{
    for (uint64_t at = c->arena.base; at < c->arena.base + (uint64_t)c->arena.pages * PAGE; at += 4) ram_put(c, at, 0);
    clean_range(c, c->arena.base, (uint64_t)c->arena.pages * PAGE);
}
