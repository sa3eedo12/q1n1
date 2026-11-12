/* SPDX-License-Identifier: MIT */
/* See sp11-fbgop.h. Ported from probes/uefi/fbtext.c's probe_gop_check/probe_gop_select
 * (Snapintosh repository); tools/test-q1n1-sp11-fbgop.{c,py} here cross-check the status/rule
 * names and the selection outcome against that project's own test fixtures where practical. */
#include "sp11-fbgop.h"

#if SNAP_PLATFORM_SP11

const char *q1n1_sp11_gop_status_name(int status)
{
    switch (status) {
    case Q1N1_SP11_GOP_OK: return "OK";
    case Q1N1_SP11_GOP_ABSENT: return "NO GOP";
    case Q1N1_SP11_GOP_NOT_CONSOLE: return "NOT CONSOLE GOP";
    case Q1N1_SP11_GOP_BAD_MODE: return "BAD MODE";
    case Q1N1_SP11_GOP_NOT_IN_MAP: return "NOT IN MEMORY MAP";
    case Q1N1_SP11_GOP_AMBIGUOUS: return "AMBIGUOUS GOP";
    default: return "UNKNOWN";
    }
}

const char *q1n1_sp11_gop_rule_name(int rule)
{
    switch (rule) {
    case Q1N1_SP11_GOP_RULE_NONE: return "NONE";
    case Q1N1_SP11_GOP_RULE_CONSOLE: return "CONSOLE";
    case Q1N1_SP11_GOP_RULE_SAME: return "SAME";
    default: return "UNKNOWN";
    }
}

/* type >= 32 cannot be tested against a 32-bit mask at all; treating it as "disallowed" (never
 * matching any bit) is correct here, not merely convenient -- masking the shift amount instead
 * (`type & 31`) would alias e.g. type 32 onto bit 0 (EfiReservedMemoryType, which IS allowed),
 * silently trusting a descriptor of a type this code has never heard of. Matches
 * probes/uefi/logic.c probe_memmap_overlaps_other/probe_memmap_covers's own `type < 32 &&` guard
 * exactly (Snapintosh repository), not independently chosen. */
static int type_is_allowed(uint32_t type)
{
    return type < 32 && ((Q1N1_SP11_GOP_TYPES_MASK >> type) & 1u);
}

/* Whether any descriptor of a type outside the mask overlaps [base, base+size) at all -- checked
 * before the covering walk below, and refusing if so even when another, allowed-type descriptor
 * also claims the same bytes. UEFI descriptors are not supposed to overlap, but a map that does is
 * not trusted to say which side is right (probes/uefi/logic.c probe_memmap_overlaps_other, ported
 * verbatim in logic, Snapintosh repository): this is deliberate defense-in-depth for a production
 * console, not a corner case the upstream probe happened to need and q1n1 can skip. */
static int map_overlaps_other(const struct q1n1_sp11_gop_map_entry *map, uint32_t map_count, uint64_t base,
                              uint64_t size)
{
    uint64_t end = base + size;
    if (end < base) end = ~UINT64_C(0); /* a wrapping range reaches the top: see probe_memmap_overlaps_other */
    for (uint32_t i = 0; i < map_count; i++) {
        const struct q1n1_sp11_gop_map_entry *d = &map[i];
        if (type_is_allowed(d->type)) continue;
        uint64_t d_end = d->base + d->pages * 4096u;
        if (d->base < end && d_end > base) return 1;
    }
    return 0;
}

static int map_covers(const struct q1n1_sp11_gop_map_entry *map, uint32_t map_count, uint64_t base,
                      uint64_t size)
{
    if (!map_count || !size) return 0;
    uint64_t at = base, end = base + size;
    if (end < base) return 0; /* overflow */
    if (map_overlaps_other(map, map_count, base, size)) return 0;
    /* Every byte of [base, end) must fall in exactly one descriptor of an allowed type; a single
     * descriptor need not cover the whole range (two adjacent allowed descriptors may), but a gap
     * or a disallowed type anywhere in the range refuses the whole candidate. */
    while (at < end) {
        uint32_t i;
        for (i = 0; i < map_count; i++) {
            const struct q1n1_sp11_gop_map_entry *d = &map[i];
            uint64_t d_end = d->base + d->pages * 4096u;
            if (d->base <= at && at < d_end) {
                if (!type_is_allowed(d->type)) return 0;
                at = d_end < end ? d_end : end;
                break;
            }
        }
        if (i == map_count) return 0; /* no descriptor covers this byte at all */
    }
    return 1;
}

int q1n1_sp11_gop_check(const struct q1n1_sp11_gop_map_entry *map, uint32_t map_count,
                        const struct q1n1_sp11_gop_candidate *c)
{
    if (c->pixel_format > 1) return Q1N1_SP11_GOP_BAD_MODE;
    if (!c->base || !c->width || !c->height || c->width > 16384u || c->height > 16384u)
        return Q1N1_SP11_GOP_BAD_MODE;
    if (c->pixels_per_scanline < c->width || c->pixels_per_scanline > 65536u) return Q1N1_SP11_GOP_BAD_MODE;
    uint64_t stride = (uint64_t)c->pixels_per_scanline * 4u;
    uint64_t needed = (uint64_t)(c->height - 1) * stride + (uint64_t)c->width * 4u;
    if (c->size_bytes < needed) return Q1N1_SP11_GOP_BAD_MODE;
    if (c->base & 3u) return Q1N1_SP11_GOP_BAD_MODE;
    if (c->base > ~UINT64_C(0) - needed) return Q1N1_SP11_GOP_BAD_MODE; /* overflow */
    if (!map_covers(map, map_count, c->base, needed)) return Q1N1_SP11_GOP_NOT_IN_MAP;
    return Q1N1_SP11_GOP_OK;
}

static int same_framebuffer(const struct q1n1_sp11_gop_candidate *a, const struct q1n1_sp11_gop_candidate *b)
{
    return a->base == b->base && a->size_bytes == b->size_bytes && a->width == b->width &&
           a->height == b->height && a->pixels_per_scanline == b->pixels_per_scanline &&
           a->pixel_format == b->pixel_format;
}

void q1n1_sp11_gop_select(const struct q1n1_sp11_gop_map_entry *map, uint32_t map_count,
                         const struct q1n1_sp11_gop_candidate *cand, uint32_t count,
                         struct q1n1_sp11_gop_result *out)
{
    out->status = Q1N1_SP11_GOP_ABSENT;
    out->rule = Q1N1_SP11_GOP_RULE_NONE;
    out->index = 0;
    out->examined = count;

    int console_seen = 0;
    int status = Q1N1_SP11_GOP_ABSENT;
    for (uint32_t i = 0; i < count; i++) {
        if (cand[i].is_console) {
            console_seen = 1;
            int s = q1n1_sp11_gop_check(map, map_count, &cand[i]);
            if (s == Q1N1_SP11_GOP_OK) {
                out->status = Q1N1_SP11_GOP_OK;
                out->rule = Q1N1_SP11_GOP_RULE_CONSOLE;
                out->index = i;
                out->examined = i + 1;
                return;
            }
            if (s > status) status = s;
        }
    }
    if (console_seen) {
        out->status = status;
        return;
    }

    /* Rule 2: no candidate was ever flagged as the console. Judge every one as if it were. */
    status = Q1N1_SP11_GOP_ABSENT;
    uint32_t first = 0, qualifying = 0;
    int differ = 0;
    for (uint32_t i = 0; i < count; i++) {
        int s = q1n1_sp11_gop_check(map, map_count, &cand[i]);
        if (s != Q1N1_SP11_GOP_OK) {
            if (s > status) status = s;
            continue;
        }
        if (qualifying++ == 0) first = i;
        else if (!same_framebuffer(&cand[first], &cand[i])) differ = 1;
    }
    if (qualifying == 0) {
        out->status = status;
    } else if (differ) {
        out->status = Q1N1_SP11_GOP_AMBIGUOUS;
    } else {
        out->status = Q1N1_SP11_GOP_OK;
        out->rule = Q1N1_SP11_GOP_RULE_SAME;
        out->index = first;
    }
}

#endif /* SNAP_PLATFORM_SP11 */
