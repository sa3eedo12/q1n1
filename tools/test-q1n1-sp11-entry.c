/* SPDX-License-Identifier: MIT */
/* Host tests for q1n1's SP11 entry/chainload/console flow (docs/SP11-Q1N1-BOOT-STUDY.md, sections
 * 5.3-5.5, 8, 9): the fail-closed post-EBS EL2 check and its ordering relative to any EL2-only
 * call (section 5.3/9.2), the GOP two-tier selection and the memory-map parser that feeds it
 * (sp11-fbgop.c, section 8), the chainload candidate table (sp11-stage-table.c, section 9.1), and
 * the declared-ranges contract shared with
 * the paired slbounce patch (sp11-ebs-ranges.h, section 4.4/7.2). Driven by
 * tools/test-q1n1-sp11-entry.py, in the same style as tools/test-q1n1-sp11-table.c.
 *
 *   gop      hand-written GOP candidate/memory-map fixtures and the verdicts they must get
 *   stage    hand-written stage-table fixtures and the verdicts they must get
 *   ranges   hand-written declared-ranges tables and the verdicts they must get
 *   entry    the fail-closed EL2 check + dispatch model: every (mode, current_el) combination
 *
 * None of this runs on EFI, EL2 or real hardware: current_el(), proxy_main() and q1n1_gic_init()
 * cannot be invoked here. "entry" checks a model of main.c's own q1n1_main() dispatch (quoted
 * inline below and grepped for literally by tools/test-q1n1-sp11-entry.py's ModelMatchesSource
 * check, so the two cannot silently drift), not the real function. Evidence: EXPERIMENTAL (host
 * model only), UNIMPLEMENTED/NOT RUN with respect to real EL2/hardware behaviour. */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define SNAP_PLATFORM_SP11 1
#include "sp11-fbgop.h"
#include "sp11-stage-table.h"
#include "sp11-ebs-ranges.h"

static unsigned checks;
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)

/* ---- gop: sp11-fbgop.c (q1n1_sp11_gop_check / q1n1_sp11_gop_select) -------------------------- */

static struct q1n1_sp11_gop_candidate cand(int is_console, uint64_t base, uint64_t size, uint32_t w, uint32_t h,
                                           uint32_t stride, uint32_t fmt)
{
    struct q1n1_sp11_gop_candidate c;
    c.is_console = is_console; c.base = base; c.size_bytes = size;
    c.width = w; c.height = h; c.pixels_per_scanline = stride; c.pixel_format = fmt;
    return c;
}

/* A plausible 1920x1080x4 BGRX framebuffer inside one EfiBootServicesData descriptor. */
#define FB_BASE UINT64_C(0x90000000)
#define FB_W 1920u
#define FB_H 1080u
#define FB_STRIDE 1920u
#define FB_BYTES ((uint64_t)FB_STRIDE * FB_H * 4u)

/* One EFI_MEMORY_DESCRIPTOR as firmware lays it out: type at +0, physical start at +8, virtual start
 * at +16, page count at +24, attribute at +32, then whatever padding `stride` adds. Every byte the
 * parser must not read holds 0xa5 junk. */
static void put_desc(uint8_t *p, uint64_t stride, uint32_t type, uint64_t base, uint64_t pages,
                     uint64_t attribute)
{
    memset(p, 0xa5, stride);
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(type >> (8 * i));
    for (unsigned i = 0; i < 8; i++) {
        p[8 + i] = (uint8_t)(base >> (8 * i));
        p[24 + i] = (uint8_t)(pages >> (8 * i));
        p[32 + i] = (uint8_t)(attribute >> (8 * i));
    }
}

static int gop_tests(void)
{
    struct q1n1_sp11_gop_map_entry map_ok[] = {{4 /* BootServicesData */, FB_BASE, (FB_BYTES + 0xfff) / 4096, 0xf}};
    struct q1n1_sp11_gop_map_entry map_disallowed[] = {{2 /* LoaderData: not in the mask */, FB_BASE,
                                                        (FB_BYTES + 0xfff) / 4096, 0xf}};

    /* Tier 1 (CONSOLE): the console's own GOP passes -> chosen immediately, never reaching tier 2. */
    {
        struct q1n1_sp11_gop_candidate c[] = {
            cand(1, FB_BASE, FB_BYTES, FB_W, FB_H, FB_STRIDE, 1),
            cand(0, FB_BASE + 0x1000000, FB_BYTES, FB_W, FB_H, FB_STRIDE, 1), /* a decoy, never examined */
        };
        struct q1n1_sp11_gop_result r;
        q1n1_sp11_gop_select(map_ok, 1, c, 2, &r);
        CHECK(r.status == Q1N1_SP11_GOP_OK && r.rule == Q1N1_SP11_GOP_RULE_CONSOLE && r.index == 0);
        CHECK(r.examined == 1); /* stops at the first passing console candidate, per its own doc comment */
    }
    /* Tier 1 present but fails its check (not in the map): falls through to its own failure status,
     * not silently to tier 2 (rule 1 only fires when a console candidate was never even seen). */
    {
        struct q1n1_sp11_gop_candidate c[] = {cand(1, FB_BASE, FB_BYTES, FB_W, FB_H, FB_STRIDE, 1)};
        struct q1n1_sp11_gop_result r;
        q1n1_sp11_gop_select(map_disallowed, 1, c, 1, &r);
        CHECK(r.status == Q1N1_SP11_GOP_NOT_IN_MAP && r.rule == Q1N1_SP11_GOP_RULE_NONE);
    }
    /* Tier 2 (SAME): no candidate ever flagged console; every candidate agrees -> accepted. */
    {
        struct q1n1_sp11_gop_candidate c[] = {
            cand(0, FB_BASE, FB_BYTES, FB_W, FB_H, FB_STRIDE, 1),
            cand(0, FB_BASE, FB_BYTES, FB_W, FB_H, FB_STRIDE, 1),
        };
        struct q1n1_sp11_gop_result r;
        q1n1_sp11_gop_select(map_ok, 1, c, 2, &r);
        CHECK(r.status == Q1N1_SP11_GOP_OK && r.rule == Q1N1_SP11_GOP_RULE_SAME && r.index == 0);
    }
    /* Tier 2, disagreeing candidates: AMBIGUOUS, nothing drawn (not a guess at either one). */
    {
        struct q1n1_sp11_gop_map_entry map2[] = {{4, FB_BASE, (FB_BYTES + 0xfff) / 4096, 0xf},
                                                  {4, FB_BASE + 0x10000000, (FB_BYTES + 0xfff) / 4096, 0xf}};
        struct q1n1_sp11_gop_candidate c[] = {
            cand(0, FB_BASE, FB_BYTES, FB_W, FB_H, FB_STRIDE, 1),
            cand(0, FB_BASE + 0x10000000, FB_BYTES, FB_W, FB_H, FB_STRIDE, 1),
        };
        struct q1n1_sp11_gop_result r;
        q1n1_sp11_gop_select(map2, 2, c, 2, &r);
        CHECK(r.status == Q1N1_SP11_GOP_AMBIGUOUS && r.rule == Q1N1_SP11_GOP_RULE_NONE);
    }
    /* No candidates at all, and no memory map at all: ABSENT, never a crash, never a false OK. */
    {
        struct q1n1_sp11_gop_result r;
        q1n1_sp11_gop_select(0, 0, 0, 0, &r);
        CHECK(r.status == Q1N1_SP11_GOP_ABSENT && r.rule == Q1N1_SP11_GOP_RULE_NONE);
    }
    /* Bad geometry/format refused as BAD_MODE, independent of the memory map. */
    {
        CHECK(q1n1_sp11_gop_check(map_ok, 1, &(struct q1n1_sp11_gop_candidate){
            .base = 0, .width = FB_W, .height = FB_H, .pixels_per_scanline = FB_STRIDE, .pixel_format = 1}) ==
            Q1N1_SP11_GOP_BAD_MODE); /* base == 0 */
        CHECK(q1n1_sp11_gop_check(map_ok, 1, &(struct q1n1_sp11_gop_candidate){
            .base = FB_BASE, .width = FB_W, .height = FB_H, .pixels_per_scanline = FB_STRIDE, .pixel_format = 2}) ==
            Q1N1_SP11_GOP_BAD_MODE); /* pixel_format > 1 */
        CHECK(q1n1_sp11_gop_check(map_ok, 1, &(struct q1n1_sp11_gop_candidate){
            .base = FB_BASE, .width = FB_W, .height = FB_H, .pixels_per_scanline = FB_W - 1, .pixel_format = 1}) ==
            Q1N1_SP11_GOP_BAD_MODE); /* stride < width */
    }
    /* A descriptor overlapping the framebuffer range with a disallowed type refuses it, even
     * though another descriptor of an allowed type also claims the same bytes (defense-in-depth;
     * ported from probes/uefi/logic.c probe_memmap_overlaps_other). */
    {
        struct q1n1_sp11_gop_map_entry map_both[] = {
            {4 /* BootServicesData: allowed */, FB_BASE, (FB_BYTES + 0xfff) / 4096, 0xf},
            {2 /* LoaderData: not allowed, overlapping the same range */, FB_BASE, (FB_BYTES + 0xfff) / 4096, 0xf},
        };
        struct q1n1_sp11_gop_result r;
        struct q1n1_sp11_gop_candidate c[] = {cand(1, FB_BASE, FB_BYTES, FB_W, FB_H, FB_STRIDE, 1)};
        q1n1_sp11_gop_select(map_both, 2, c, 1, &r);
        CHECK(r.status == Q1N1_SP11_GOP_NOT_IN_MAP);
    }
    /* ---- q1n1_sp11_gop_map_parse: raw GetMemoryMap bytes -> entries ---- */
    {
        static uint8_t raw[1100 * 64];
        static struct q1n1_sp11_gop_map_entry out[1100];
        uint32_t n = 99;

        /* Only type (+0), physical start (+8), page count (+24) and attribute (+32) are read, for any
         * descriptor size UEFI allows (40 defined bytes; firmware may pad to more). put_desc fills
         * every other byte with junk, so a read from the wrong offset or the wrong width cannot
         * pass by luck, and a base above 4 GiB and an attribute with bit 63 set prove the upper
         * half of the 64-bit fields is decoded too. */
        const uint64_t strides[] = {40, 48, 64};
        for (unsigned s = 0; s < 3; s++) {
            uint64_t sz = strides[s];
            put_desc(raw, sz, 7, UINT64_C(0x80000000), 0x100, UINT64_C(0xf));
            put_desc(raw + sz, sz, 0, UINT64_C(0x123456000), 0x21c0, UINT64_C(0x100f));
            put_desc(raw + 2 * sz, sz, 11, UINT64_C(0xfffff000), 1, UINT64_C(0x8000000000000001));
            CHECK(q1n1_sp11_gop_map_parse(raw, 3 * sz, sz, out, 3, &n) == Q1N1_SP11_MAP_OK && n == 3);
            CHECK(out[0].type == 7 && out[0].base == UINT64_C(0x80000000) && out[0].pages == 0x100 &&
                  out[0].attribute == 0xf);
            CHECK(out[1].type == 0 && out[1].base == UINT64_C(0x123456000) && out[1].pages == 0x21c0 &&
                  out[1].attribute == 0x100f);
            CHECK(out[2].type == 11 && out[2].base == UINT64_C(0xfffff000) && out[2].pages == 1 &&
                  out[2].attribute == UINT64_C(0x8000000000000001));
        }

        /* Every refusal reports zero entries and never divides by a bad stride. */
        n = 99; CHECK(q1n1_sp11_gop_map_parse(raw, 0, 48, out, 8, &n) == Q1N1_SP11_MAP_EMPTY && n == 0);
        n = 99; CHECK(q1n1_sp11_gop_map_parse(raw, 96, 0, out, 8, &n) == Q1N1_SP11_MAP_BAD_STRIDE && n == 0);
        n = 99; CHECK(q1n1_sp11_gop_map_parse(raw, 96, 39, out, 8, &n) == Q1N1_SP11_MAP_BAD_STRIDE && n == 0);
        n = 99; CHECK(q1n1_sp11_gop_map_parse(raw, 97, 48, out, 8, &n) == Q1N1_SP11_MAP_BAD_SIZE && n == 0);

        /* A map that does not fit is refused with the output untouched, never cut short: the exact
         * fit is accepted and one entry fewer is not. */
        for (unsigned i = 0; i < 3; i++) put_desc(raw + i * 48, 48, 7, UINT64_C(0x80000000) + i * 0x10000, 1, 0xf);
        memset(out, 0x5a, sizeof out);
        n = 99; CHECK(q1n1_sp11_gop_map_parse(raw, 3 * 48, 48, out, 2, &n) == Q1N1_SP11_MAP_TOO_MANY && n == 0);
        CHECK(out[0].type == 0x5a5a5a5au && out[0].base == UINT64_C(0x5a5a5a5a5a5a5a5a));
        n = 99; CHECK(q1n1_sp11_gop_map_parse(raw, 3 * 48, 48, out, 3, &n) == Q1N1_SP11_MAP_OK && n == 3);

        /* The observed failure shape (hardware attempt 3, 2026-11-12): a map longer than the 512
         * entries an earlier copy kept, with the framebuffer's RESERVED descriptor near the end of
         * the array. Cutting the copy at 512 dropped it and the only GOP read "NOT IN MEMORY MAP". */
        struct q1n1_sp11_gop_candidate unit_gop = cand(0, FB_BASE, UINT64_C(0x1518000), 2880, 1920, 2880, 1);
        for (unsigned i = 0; i < 599; i++)
            put_desc(raw + i * 48, 48, 7, UINT64_C(0x40000000) + (uint64_t)i * 0x10000, 1, 0xf);
        put_desc(raw + 599 * 48, 48, 0, FB_BASE, 0x21c0, 0x100f); /* larger than the framebuffer, as on the unit */
        {
            struct q1n1_sp11_gop_result r;
            CHECK(q1n1_sp11_gop_map_parse(raw, 600 * 48, 48, out, 1024, &n) == Q1N1_SP11_MAP_OK && n == 600);
            q1n1_sp11_gop_select(out, n, &unit_gop, 1, &r);
            CHECK(r.status == Q1N1_SP11_GOP_OK && r.rule == Q1N1_SP11_GOP_RULE_SAME);
            n = 99; CHECK(q1n1_sp11_gop_map_parse(raw, 600 * 48, 48, out, 512, &n) == Q1N1_SP11_MAP_TOO_MANY && n == 0);
            q1n1_sp11_gop_select(out, n, &unit_gop, 1, &r); /* what a refused map leaves behind */
            CHECK(r.status == Q1N1_SP11_GOP_NOT_IN_MAP);
        }

        /* The unit's own map is two ascending runs, not one: nothing may assume address order. The
         * framebuffer's descriptor comes after a lower-addressed MMIO one and a higher RAM one. */
        put_desc(raw, 48, 7, UINT64_C(0x880000000), 0x100, 0xf);
        put_desc(raw + 48, 48, 7, UINT64_C(0xcea57000), 0x100, 0xf);
        put_desc(raw + 2 * 48, 48, 11, UINT64_C(0x0c264000), 1, UINT64_C(0x8000000000000001));
        put_desc(raw + 3 * 48, 48, 0, FB_BASE, 0x21c0, 0x100f);
        put_desc(raw + 4 * 48, 48, 0, UINT64_C(0xff800000), 0x800, 0x1);
        {
            struct q1n1_sp11_gop_result r;
            CHECK(q1n1_sp11_gop_map_parse(raw, 5 * 48, 48, out, 8, &n) == Q1N1_SP11_MAP_OK && n == 5);
            unit_gop.is_console = 1;
            q1n1_sp11_gop_select(out, n, &unit_gop, 1, &r);
            CHECK(r.status == Q1N1_SP11_GOP_OK && r.rule == Q1N1_SP11_GOP_RULE_CONSOLE);

            /* range_facts on that same map. The framebuffer is wholly inside one descriptor whose
             * type is 0 (EfiReservedMemoryType): the scoped sweep in the paired slbounce fork
             * accepts only types 1-6 and 9, so declaring the framebuffer to it would be refused
             * (WRONG_TYPE) on a map shaped like this unit's. The facts report the type; the
             * consumer judges it. */
            struct q1n1_sp11_range_facts f;
            q1n1_sp11_range_facts(out, n, FB_BASE, UINT64_C(0x1518000), &f);
            CHECK(f.overlapping == 1 && f.contained && f.type == 0 && f.attribute == 0x100f);
            q1n1_sp11_range_facts(out, n, FB_BASE + 0x21c0 * 4096 - 0x1000, 0x1000, &f); /* the last page */
            CHECK(f.overlapping == 1 && f.contained);
            q1n1_sp11_range_facts(out, n, FB_BASE + 0x21c0 * 4096 - 0x1000, 0x2000, &f); /* runs past the end */
            CHECK(f.overlapping == 1 && !f.contained && f.type == 0);
            q1n1_sp11_range_facts(out, n, UINT64_C(0x880000000) - 0x1000, 0x2000, &f); /* starts in a hole */
            CHECK(f.overlapping == 1 && !f.contained && f.type == 7);
            q1n1_sp11_range_facts(out, n, UINT64_C(0x300000000), 0x1000, &f); /* nowhere in the map */
            CHECK(f.overlapping == 0 && !f.contained && f.type == 0 && f.attribute == 0);
            q1n1_sp11_range_facts(out, n, FB_BASE, 0, &f); /* zero size overlaps nothing */
            CHECK(f.overlapping == 0 && !f.contained);
            q1n1_sp11_range_facts(out, 0, FB_BASE, 0x1000, &f); /* empty map */
            CHECK(f.overlapping == 0 && !f.contained);
            q1n1_sp11_range_facts(out, n, ~UINT64_C(0) - 0xfff, 0x2000, &f); /* wraps the address space */
            CHECK(f.overlapping == 0 && !f.contained);
        }
        {
            /* Two descriptors both overlapping the range: reported as 2, never "contained", and the
             * type/attribute are the first one's in array order. */
            struct q1n1_sp11_gop_map_entry split[] = {{4, 0x1000, 1, 0xf}, {2, 0x2000, 1, 0x7}};
            struct q1n1_sp11_range_facts f;
            q1n1_sp11_range_facts(split, 2, 0x1800, 0x1000, &f);
            CHECK(f.overlapping == 2 && !f.contained && f.type == 4 && f.attribute == 0xf);
            /* The first descriptor holds the whole range but a second overlaps it too (a hostile
             * map): "exactly one descriptor" is the sweep's own rule, so this is not contained. */
            struct q1n1_sp11_gop_map_entry overlap[] = {{4, 0x1000, 4, 0xf}, {2, 0x2000, 1, 0x7}};
            q1n1_sp11_range_facts(overlap, 2, 0x2000, 0x1000, &f);
            CHECK(f.overlapping == 2 && !f.contained && f.type == 4);
            /* An absurd page count saturates at the top of the address space instead of wrapping to
             * an apparently empty descriptor. */
            struct q1n1_sp11_gop_map_entry huge[] = {{4, 0x1000, ~UINT64_C(0), 0xf}};
            q1n1_sp11_range_facts(huge, 1, 0x2000, 0x1000, &f);
            CHECK(f.overlapping == 1 && f.contained);
        }
        CHECK(!strcmp(q1n1_sp11_map_status_name(Q1N1_SP11_MAP_TOO_MANY), "TOO MANY ENTRIES"));
        CHECK(!strcmp(q1n1_sp11_map_status_name(99), "UNKNOWN"));
    }
    CHECK(!strcmp(q1n1_sp11_gop_status_name(Q1N1_SP11_GOP_AMBIGUOUS), "AMBIGUOUS GOP"));
    CHECK(!strcmp(q1n1_sp11_gop_rule_name(Q1N1_SP11_GOP_RULE_SAME), "SAME"));
    CHECK(!strcmp(q1n1_sp11_gop_status_name(99), "UNKNOWN"));
    printf("PASS %u GOP checks\n", checks);
    return 0;
}

/* ---- stage: sp11-stage-table.c (q1n1_sp11_stage_table_validate) ------------------------------ */

static struct q1n1_sp11_stage_table stage_good(void)
{
    struct q1n1_sp11_stage_table t = {0};
    t.magic = Q1N1_SP11_STAGE_MAGIC; t.version = Q1N1_SP11_STAGE_VERSION; t.count = 2;
    t.candidate[0] = UINT64_C(0x90000000); t.candidate[1] = UINT64_C(0x94000000);
    return t;
}

static int stage_tests(void)
{
    struct q1n1_sp11_stage_table t;
    checks = 0;
    CHECK(q1n1_sp11_stage_table_validate(0) == Q1N1_SP11_STAGE_ERR_NULL);
    t = stage_good(); CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_OK);
    t = stage_good(); t.magic ^= 1; CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_ERR_MAGIC);
    t = stage_good(); t.version = 2; CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_ERR_VERSION);
    t = stage_good(); t.count = 0; CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_ERR_COUNT);
    t = stage_good(); t.count = 5; CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_ERR_COUNT);
    t = stage_good(); t.count = 1; CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_ERR_RESERVED);
    t = stage_good(); t.count = 1; t.candidate[1] = 0; CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_OK);
    t = stage_good(); t.candidate[0] = 0; CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_ERR_ALIGN);
    t = stage_good(); t.candidate[0] += 1; CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_ERR_ALIGN);
    /* F02/section 9.1: the exact A16 stage_candidates[] (main.c) must never be accepted, for any
     * candidate slot, with no "listed independently" escape hatch (unlike the USB table's
     * A16_BASE_LISTED flag: the study names no equivalent carve-out for stage addresses). */
    t = stage_good(); t.candidate[0] = UINT64_C(0xb0000000); CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_ERR_A16_BASE);
    t = stage_good(); t.candidate[1] = UINT64_C(0x4c000000); CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_ERR_A16_BASE);
    t = stage_good(); t.candidate[0] = UINT64_C(0xa0000000); CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_ERR_A16_BASE);
    t = stage_good(); t.candidate[1] = t.candidate[0] + Q1N1_SP11_STAGE_BYTES - 0x1000;
    CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_ERR_OVERLAP);
    t = stage_good(); t.candidate[1] = t.candidate[0];
    CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_ERR_OVERLAP);
    t = stage_good(); t.candidate[1] = t.candidate[0] + Q1N1_SP11_STAGE_BYTES; /* exactly adjacent: no overlap */
    CHECK(q1n1_sp11_stage_table_validate(&t) == Q1N1_SP11_STAGE_OK);
    CHECK(!strcmp(q1n1_sp11_stage_error_name(Q1N1_SP11_STAGE_ERR_COUNT_ALL), "UNKNOWN"));
    printf("PASS %u stage-table checks\n", checks);
    return 0;
}

/* ---- ranges: sp11-ebs-ranges.h (sp11_ebs_ranges_valid), shared with the slbounce fork --------- */

static struct sp11_ebs_ranges_table ranges_with(void (*fill)(struct sp11_ebs_ranges_table *))
{
    struct sp11_ebs_ranges_table t = {0};
    t.magic = SP11_EBS_RANGES_MAGIC; t.version = SP11_EBS_RANGES_VERSION; t.chunk_cap = 1u << 20;
    t.count = 2;
    t.range[0] = (struct sp11_ebs_range){0x90000000, 0x1000};
    t.range[1] = (struct sp11_ebs_range){0xA0000000, 0x2000};
    if (fill) fill(&t);
    t.checksum = sp11_ebs_ranges_fnv((const uint8_t *)&t, offsetof(struct sp11_ebs_ranges_table, checksum));
    return t;
}

static int ranges_tests(void)
{
    checks = 0;
    CHECK(!sp11_ebs_ranges_valid(0));
    struct sp11_ebs_ranges_table t = ranges_with(0);
    CHECK(sp11_ebs_ranges_valid(&t));
    t = ranges_with(0); t.magic ^= 1; CHECK(!sp11_ebs_ranges_valid(&t)); /* stale checksum covers this too */
    t = ranges_with(0); t.checksum ^= 1; CHECK(!sp11_ebs_ranges_valid(&t));
    t = ranges_with(0); t.version = 2; t.checksum = sp11_ebs_ranges_fnv((const uint8_t *)&t, offsetof(struct sp11_ebs_ranges_table, checksum));
    CHECK(!sp11_ebs_ranges_valid(&t));
    t = ranges_with(0); t.count = 0; t.checksum = sp11_ebs_ranges_fnv((const uint8_t *)&t, offsetof(struct sp11_ebs_ranges_table, checksum));
    CHECK(!sp11_ebs_ranges_valid(&t));
    t = ranges_with(0); t.count = SP11_EBS_MAX_RANGES + 1;
    t.checksum = sp11_ebs_ranges_fnv((const uint8_t *)&t, offsetof(struct sp11_ebs_ranges_table, checksum));
    CHECK(!sp11_ebs_ranges_valid(&t));
    t = ranges_with(0); t.chunk_cap = 0; t.checksum = sp11_ebs_ranges_fnv((const uint8_t *)&t, offsetof(struct sp11_ebs_ranges_table, checksum));
    CHECK(!sp11_ebs_ranges_valid(&t));
    t = ranges_with(0); t.reserved = 1; t.checksum = sp11_ebs_ranges_fnv((const uint8_t *)&t, offsetof(struct sp11_ebs_ranges_table, checksum));
    CHECK(!sp11_ebs_ranges_valid(&t));
    t = ranges_with(0); t.range[2].base = 1; /* a nonzero slot at/after count */
    t.checksum = sp11_ebs_ranges_fnv((const uint8_t *)&t, offsetof(struct sp11_ebs_ranges_table, checksum));
    CHECK(!sp11_ebs_ranges_valid(&t));
    t = ranges_with(0); t.range[0].size = 0; t.checksum = sp11_ebs_ranges_fnv((const uint8_t *)&t, offsetof(struct sp11_ebs_ranges_table, checksum));
    CHECK(!sp11_ebs_ranges_valid(&t));
    _Static_assert(sizeof(struct sp11_ebs_range) == 16, "see sp11-ebs-ranges.h");
    _Static_assert(sizeof(struct sp11_ebs_ranges_table) == 160, "see sp11-ebs-ranges.h");
    printf("PASS %u declared-ranges checks\n", checks);
    return 0;
}

/* ---- entry: the fail-closed EL2 check + dispatch model (section 5.3/5.4, 9.2) ----------------- */

enum { MODEL_MODE_FOOTHOLD = 0, MODEL_MODE_USB_PROXY = 1, MODEL_MODE_UART_PROXY = 2 };
enum entry_event { EV_NONE, EV_HALT, EV_PROXY_MAIN };

/* Mirrors main.c's q1n1_main(), exactly (quoted here for traceability; tools/test-q1n1-sp11-
 * entry.py's ModelMatchesSource grep-checks that this literal conditional, "mode != MODE_FOOTHOLD
 * && current_el() != 2", still appears in the real file, so the two cannot silently drift):
 *
 *   if (mode != MODE_FOOTHOLD && current_el() != 2) { ...halt, no return... }
 *   if (mode != MODE_FOOTHOLD) proxy_main();
 *
 * current_el() cannot be read on a host; this takes it as a parameter instead. EV_PROXY_MAIN
 * stands for the only point q1n1_gic_init's EL2-only register writes (ICC_SRE_EL2, CNTHP_*_EL2,
 * F09) are ever reached under the gate -- the test asserts EV_HALT is returned whenever current_el
 * != 2 and mode != MODE_FOOTHOLD, i.e. strictly before that point is ever reached, for every value
 * tried, not merely the ones a real CurrentEL read could produce. */
static enum entry_event model_q1n1_main(int mode, int current_el)
{
    if (mode != MODEL_MODE_FOOTHOLD && current_el != 2)
        return EV_HALT;
    if (mode != MODEL_MODE_FOOTHOLD)
        return EV_PROXY_MAIN;
    return EV_NONE;
}

static int entry_tests(void)
{
    checks = 0;
    static const int modes[] = {MODEL_MODE_FOOTHOLD, MODEL_MODE_USB_PROXY, MODEL_MODE_UART_PROXY};
    /* Every CurrentEL encoding bar 2 (0-3 cover every architecturally valid value; a handful of
     * out-of-range values are included too, since a host model need not restrict itself to what a
     * real `mrs CurrentEL` could produce -- the check must refuse those just as readily). */
    static const int els[] = {0, 1, 2, 3, -1, 7, 255};
    for (unsigned m = 0; m < sizeof modes / sizeof modes[0]; m++) {
        for (unsigned e = 0; e < sizeof els / sizeof els[0]; e++) {
            enum entry_event ev = model_q1n1_main(modes[m], els[e]);
            if (modes[m] == MODEL_MODE_FOOTHOLD) {
                CHECK(ev == EV_NONE); /* never refused, never runs proxy_main either */
            } else if (els[e] != 2) {
                CHECK(ev == EV_HALT); /* refused before any EL2-only call, for every non-2 value */
            } else {
                CHECK(ev == EV_PROXY_MAIN); /* the only state in which an EL2-only call ever runs */
            }
        }
    }
    /* The converse control: an unguarded dispatch (no fail-closed check at all) would reach
     * EV_PROXY_MAIN for every mode != MODE_FOOTHOLD regardless of current_el -- proving this test
     * would not pass trivially if the check were absent (today's F09 behaviour on the A16 path,
     * which this patch does not and must not change there). */
    CHECK(model_q1n1_main(MODEL_MODE_USB_PROXY, 1) == EV_HALT);
    {
        enum entry_event unguarded = (MODEL_MODE_USB_PROXY != MODEL_MODE_FOOTHOLD) ? EV_PROXY_MAIN : EV_NONE;
        CHECK(unguarded == EV_PROXY_MAIN && unguarded != model_q1n1_main(MODEL_MODE_USB_PROXY, 1));
    }
    printf("PASS %u entry-model checks\n", checks);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "gop")) return gop_tests();
    if (argc == 2 && !strcmp(argv[1], "stage")) return stage_tests();
    if (argc == 2 && !strcmp(argv[1], "ranges")) return ranges_tests();
    if (argc == 2 && !strcmp(argv[1], "entry")) return entry_tests();
    if (argc == 1) return gop_tests() || stage_tests() || ranges_tests() || entry_tests();
    fprintf(stderr, "usage: test-q1n1-sp11-entry [gop|stage|ranges|entry]\n");
    return 2;
}
