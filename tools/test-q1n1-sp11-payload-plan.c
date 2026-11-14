/* SPDX-License-Identifier: MIT */
/* Host tests for the payload runner's declared ranges, text layer and ABI (platform/uefi/sp11-payload-plan.c,
 * sp11-payload-text.c, sp11-payload-abi.h). Driven by tools/test-q1n1-sp11-payload.py under ASan and UBSan.
 *
 *   plan       ranges appended to the table the --el2 flow already declares: the capacity of 8, the order,
 *              the labels, the framebuffer kept out, overlaps, wrap, the sweep's chunk budget, and that a
 *              refusal leaves the table exactly as it was
 *   map        the same table against synthetic memory maps shaped like the unit's (two ascending runs, 227
 *              descriptors, a high bank, the framebuffer in RESERVED memory): every reason slbounce
 *              refuses a range, in its order
 *   precheck   the refusal the runner makes just before the point of no return, and which of several
 *              simultaneous causes it names
 *   slbounce   the verdicts compared with slbounce's own sp11_sweep_range over random maps (built only
 *              when the driver passes HAVE_SLBOUNCE_SWEEP and slbounce's source; SKIP otherwise)
 *   text       numbers, the font, the line builder, and the panel region against the survey's own layout
 *              (HAVE_SURVEY_LAYOUT; SKIP otherwise)
 *   abi        the layout of the payload ABI and the constants the documentation states
 *
 * None of this runs on EFI or hardware. Evidence: EXPERIMENTAL (host model only). */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#include "sp11-payload.h"
#ifdef HAVE_SLBOUNCE_SWEEP
#include "sp11_scoped_sweep.h"
#endif
#ifdef HAVE_SURVEY_LAYOUT
struct stk_layout_mirror { int placement; uint32_t scale, col0, row0, rows; };
void stk_layout(uint32_t width, uint32_t height, uint32_t page_scale, uint32_t page_rows,
                struct stk_layout_mirror *out);
#endif

static unsigned checks, skipped;
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)

/* ---- A memory map shaped like the unit's -------------------------------------------------------------- */

#define WB_ALL UINT64_C(0x100f)             /* what the firmware reports for RAM: UC WC WT WB and WP */
#define RUNTIME UINT64_C(0x8000000000000000)
static struct q1n1_sp11_gop_map_entry map[512];
static uint32_t map_n;
static const uint64_t fb_base = UINT64_C(0xe4800000), fb_bytes = UINT64_C(0x1518000);   /* 2880x1920x4 */

static void add(uint32_t type, uint64_t base, uint64_t pages, uint64_t attr)
{
    map[map_n++] = (struct q1n1_sp11_gop_map_entry){type, base, pages, attr};
}

/* 227 descriptors in two ascending runs, as the unit's firmware lists them: the first run is DRAM below
 * 4 GiB with boot services code and data interleaved, a little loader, runtime and ACPI memory, then
 * conventional memory and the 30 GiB high bank; the second is the reserved descriptors, among them the
 * one that holds the framebuffer. Synthetic: the shape, not the addresses, is the unit's. */
static void build_unit_map(void)
{
    map_n = 0;
    uint64_t at = UINT64_C(0x80800000);
    for (unsigned i = 0; i < 8; i++) {
        add(0, at, 0x40, WB_ALL); at += 0x40 * 4096;
        add(7, at, 0x100 + i, WB_ALL); at += (0x100 + i) * 4096 + 0x10000;
    }
    at = UINT64_C(0xa6800000);
    for (unsigned i = 0; i < 90; i++) {
        add(4, at, 0x30 + i, WB_ALL); at += (0x30 + i) * 4096;
        add(3, at, 0x10 + i % 7, WB_ALL); at += (0x10 + i % 7) * 4096;
    }
    add(1, at, 0x10e, WB_ALL); at += 0x10e * 4096 + 0x8000;
    add(2, at, 0x226, WB_ALL); at += 0x226 * 4096 + 0x8000;
    add(1, at, 0x161, WB_ALL); at += 0x161 * 4096 + 0x8000;
    add(5, at, 0x190, RUNTIME | WB_ALL); at += 0x190 * 4096;
    add(6, at, 0x2bc, RUNTIME | WB_ALL); at += 0x2bc * 4096;
    add(6, at, 0x8, RUNTIME | WB_ALL); at += 0x8 * 4096 + 0x4000;
    add(10, at, 0x50, WB_ALL); at += 0x50 * 4096;
    add(9, at, 0x359, WB_ALL); at += 0x359 * 4096;
    add(7, at, 0x6250, WB_ALL); at += 0x6250 * 4096 + 0x100000;
    add(7, at, 0x11b40, WB_ALL);
    add(7, UINT64_C(0x880000000), 0x780000, WB_ALL);                    /* the high bank, 30 GiB */
    add(11, UINT64_C(0x0c264000), 1, RUNTIME | 1);                      /* MMIO */
    for (unsigned i = 0; i < 16; i++) add(0, UINT64_C(0x81a40000) + i * UINT64_C(0x100000), 0x40 + i, i & 1 ? 1 : WB_ALL);
    add(0, fb_base & ~UINT64_C(0xfff), 0x21c0, WB_ALL);                 /* the framebuffer is inside this */
}

/* Takes pages out of the conventional descriptor that holds them and gives them a type: what an
 * AllocatePages does to the map. */
static int carve(uint32_t type, uint64_t base, uint64_t pages)
{
    for (uint32_t i = 0; i < map_n; i++) {
        uint64_t end = map[i].base + map[i].pages * 4096;
        if (map[i].type != 7 || map[i].base > base || end < base + pages * 4096) continue;
        uint64_t head = (base - map[i].base) / 4096, tail = (end - base) / 4096 - pages;
        uint64_t attr = map[i].attribute;
        if (head) {
            map[i].pages = head;
            add(type, base, pages, attr);
        } else {
            map[i] = (struct q1n1_sp11_gop_map_entry){type, base, pages, attr};
        }
        if (tail) add(7, base + pages * 4096, tail, attr);
        return 1;
    }
    return 0;
}

/* The ranges a run declares, then the descriptors EDK2 would list for them: adjacent descriptors of one
 * type and attribute are one. */
struct run_ranges { uint64_t image, map, table, payload, data[4], stack; };
static struct run_ranges ranges = {
    UINT64_C(0xfffe00000), UINT64_C(0xfffd00000), UINT64_C(0xfffcfe000), UINT64_C(0xfffcf8000),
    {UINT64_C(0xfffcf0000), UINT64_C(0xfffcec000), UINT64_C(0xfffce8000), UINT64_C(0xfffce4000)},
    UINT64_C(0xfffcc0000),
};
static void coalesce(void)
{
    int merged;
    do {
        merged = 0;
        for (uint32_t i = 0; i < map_n && !merged; i++) {
            for (uint32_t j = 0; j < map_n; j++) {
                if (i == j || map[i].type != map[j].type || map[i].attribute != map[j].attribute ||
                    map[i].base + map[i].pages * 4096 != map[j].base) continue;
                map[i].pages += map[j].pages;
                map[j] = map[--map_n];
                merged = 1;
                break;
            }
        }
    } while (merged);
}
static void build_run_map(unsigned files)
{
    build_unit_map();
    carve(1, ranges.image, 0x164);
    carve(2, ranges.map, 0x40);
    carve(2, ranges.table, 2);
    carve(1, ranges.payload, 1);
    for (unsigned i = 0; i < files && i < 4; i++) carve(2, ranges.data[i], 2);
    carve(2, ranges.stack, 16);
    coalesce();
}

static struct sp11_ebs_ranges_table base_table(void)
{
    struct sp11_ebs_ranges_table t;
    memset(&t, 0, sizeof t);
    t.magic = SP11_EBS_RANGES_MAGIC; t.version = SP11_EBS_RANGES_VERSION; t.chunk_cap = 1u << 20;
    t.range[0] = (struct sp11_ebs_range){ranges.image, 0x164 * 4096};
    t.range[1] = (struct sp11_ebs_range){ranges.map, 0x40 * 4096};
    t.range[2] = (struct sp11_ebs_range){ranges.table, 0x13a0};      /* the table: its bytes, not its pages */
    t.count = 3;
    return t;
}
static struct q1n1_payload_loaded loaded_files(unsigned count)
{
    struct q1n1_payload_loaded l;
    memset(&l, 0, sizeof l);
    l.count = count;
    for (unsigned i = 0; i < count; i++) {
        l.file[i].base = i ? ranges.data[i - 1] : ranges.payload;
        l.file[i].alloc = i ? 2 * 4096 : 4096;
        l.file[i].bytes = l.file[i].alloc - 5;
    }
    return l;
}

/* ---- plan ---------------------------------------------------------------------------------------------- */

static int suite_plan(void)
{
    const char *labels[SP11_EBS_MAX_RANGES] = {"image", "map", "preload"};
    for (unsigned files = 1; files <= Q1N1_PAYLOAD_MAX_FILES; files++) {
        struct sp11_ebs_ranges_table t = base_table();
        struct q1n1_payload_loaded l = loaded_files(files);
        CHECK(q1n1_payload_plan_append(&t, labels, &l, fb_base, fb_bytes) == Q1N1_PLAN_OK);
        CHECK(t.count == 3 + files && t.count <= SP11_EBS_MAX_RANGES);
        CHECK(!strcmp(labels[3], "payload") && t.range[3].base == ranges.payload && t.range[3].size == 4096);
        for (unsigned i = 1; i < files; i++) {
            char want[8];
            snprintf(want, sizeof want, "file%u", i);
            CHECK(!strcmp(labels[3 + i], want) && t.range[3 + i].base == ranges.data[i - 1]);
        }
        CHECK(!strcmp(labels[0], "image") && !strcmp(labels[2], "preload"));
        CHECK(t.chunk_cap == (1u << 20) && t.magic == SP11_EBS_RANGES_MAGIC);
        for (uint32_t i = t.count; i < SP11_EBS_MAX_RANGES; i++) CHECK(!t.range[i].base && !t.range[i].size);
        CHECK(q1n1_payload_table_check(&t, fb_base, fb_bytes) == Q1N1_PLAN_OK);
    }
    CHECK(Q1N1_PAYLOAD_MAX_FILES == 5 && Q1N1_PAYLOAD_BASE_RANGES + Q1N1_PAYLOAD_MAX_FILES == SP11_EBS_MAX_RANGES);

    /* One file too many for the table: refused, and the table and the labels are as they were. */
    {
        struct sp11_ebs_ranges_table t = base_table(), before;
        const char *name_before[SP11_EBS_MAX_RANGES];
        for (unsigned i = 0; i < 4; i++) t.range[t.count++] = (struct sp11_ebs_range){0x1000000 * (i + 1), 0x1000};
        memcpy(&before, &t, sizeof t);
        memcpy(name_before, labels, sizeof labels);
        struct q1n1_payload_loaded l = loaded_files(5);
        CHECK(q1n1_payload_plan_append(&t, labels, &l, fb_base, fb_bytes) == Q1N1_PLAN_TOO_MANY);
        CHECK(!memcmp(&t, &before, sizeof t) && !memcmp(labels, name_before, sizeof labels));
    }
    /* The edge of the capacity: eight in all is the table's size, nine is one too many. */
    for (unsigned base_extra = 0; base_extra <= 5; base_extra++) {
        for (unsigned files = 1; files <= Q1N1_PAYLOAD_MAX_FILES; files++) {
            struct sp11_ebs_ranges_table t = base_table(), before;
            const char *name_before[SP11_EBS_MAX_RANGES];
            for (unsigned i = 0; i < base_extra; i++) t.range[t.count++] = (struct sp11_ebs_range){0x1000000 * (i + 1), 0x1000};
            memcpy(&before, &t, sizeof t);
            memcpy(name_before, labels, sizeof labels);
            struct q1n1_payload_loaded l = loaded_files(files);
            int status = q1n1_payload_plan_append(&t, labels, &l, fb_base, fb_bytes);
            if (3 + base_extra + files <= SP11_EBS_MAX_RANGES) {
                CHECK(status == Q1N1_PLAN_OK && t.count == 3 + base_extra + files);
            } else {
                CHECK(status == Q1N1_PLAN_TOO_MANY && !memcmp(&t, &before, sizeof t) && !memcmp(labels, name_before, sizeof labels));
            }
        }
    }
    /* A refusal of any kind leaves the table and labels untouched. */
    struct { const char *what; int expect; uint64_t base, size; } bad[] = {
        {"framebuffer start", Q1N1_PLAN_FRAMEBUFFER, fb_base, 0x1000},
        {"framebuffer inside", Q1N1_PLAN_FRAMEBUFFER, fb_base + 0x100000, 0x2000},
        {"framebuffer last byte", Q1N1_PLAN_FRAMEBUFFER, fb_base + fb_bytes - 1, 0x1000},
        {"straddles the framebuffer start", Q1N1_PLAN_FRAMEBUFFER, fb_base - 0x800, 0x1000},
        {"covers the framebuffer", Q1N1_PLAN_FRAMEBUFFER, fb_base - 0x1000, fb_bytes + 0x2000},
        {"overlaps the image", Q1N1_PLAN_OVERLAP, ranges.image + 0x1000, 0x1000},
        {"is the image", Q1N1_PLAN_OVERLAP, ranges.image, 0x164 * 4096},
        {"overlaps the table by one byte", Q1N1_PLAN_OVERLAP, ranges.table + 0x139f, 0x1000},
        {"empty", Q1N1_PLAN_EMPTY, 0x1000000, 0},
        {"wraps", Q1N1_PLAN_WRAP, ~UINT64_C(0) - 0xfff, 0x2000},
        {"one chunk over the sweep's budget", Q1N1_PLAN_TOO_LARGE, UINT64_C(0x10000000000), (UINT64_C(256) << 20) + 1},
    };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        struct sp11_ebs_ranges_table t = base_table(), before;
        const char *name_before[SP11_EBS_MAX_RANGES], *names[SP11_EBS_MAX_RANGES] = {"image", "map", "preload"};
        struct q1n1_payload_loaded l = loaded_files(1);
        l.file[0].base = bad[i].base;
        l.file[0].alloc = bad[i].size;
        memcpy(&before, &t, sizeof t);
        memcpy(name_before, names, sizeof names);
        int status = q1n1_payload_plan_append(&t, names, &l, fb_base, fb_bytes);
        if (status != bad[i].expect) fprintf(stderr, "case: %s got %s\n", bad[i].what, q1n1_payload_plan_name(status));
        CHECK(status == bad[i].expect);
        CHECK(!memcmp(&t, &before, sizeof t) && !memcmp(names, name_before, sizeof names));
    }
    /* Just inside the limits: adjacent to the framebuffer on either side, exactly 256 chunks, a range that
     * ends where the image begins. */
    struct { uint64_t base, size; } good[] = {
        {fb_base - 0x1000, 0x1000}, {fb_base + fb_bytes, 0x1000}, {UINT64_C(0x10000000000), UINT64_C(256) << 20},
        {ranges.image - 0x1000, 0x1000}, {ranges.image + 0x164 * 4096, 0x1000},
    };
    for (unsigned i = 0; i < sizeof good / sizeof good[0]; i++) {
        struct sp11_ebs_ranges_table t = base_table();
        const char *names[SP11_EBS_MAX_RANGES] = {"image", "map", "preload"};
        struct q1n1_payload_loaded l = loaded_files(1);
        l.file[0].base = good[i].base;
        l.file[0].alloc = good[i].size;
        CHECK(q1n1_payload_plan_append(&t, names, &l, fb_base, fb_bytes) == Q1N1_PLAN_OK && t.count == 4);
    }
    /* No framebuffer known: nothing to keep out. A framebuffer that wraps the address space: not checked. */
    {
        struct sp11_ebs_ranges_table t = base_table();
        const char *names[SP11_EBS_MAX_RANGES] = {"image", "map", "preload"};
        struct q1n1_payload_loaded l = loaded_files(1);
        l.file[0].base = fb_base;
        CHECK(q1n1_payload_plan_append(&t, names, &l, fb_base, 0) == Q1N1_PLAN_OK);
    }
    /* The table check's own statuses, in the documented order: with every fault present the first wins. */
    {
        struct sp11_ebs_ranges_table t = base_table();
        t.chunk_cap = 0;
        CHECK(q1n1_payload_table_check(&t, fb_base, fb_bytes) == Q1N1_PLAN_CHUNK_CAP);
        t = base_table();
        t.count = 0;
        CHECK(q1n1_payload_table_check(&t, fb_base, fb_bytes) == Q1N1_PLAN_NO_TABLE);
        CHECK(q1n1_payload_table_check(NULL, fb_base, fb_bytes) == Q1N1_PLAN_NO_TABLE);
        t.count = SP11_EBS_MAX_RANGES + 1;
        CHECK(q1n1_payload_table_check(&t, fb_base, fb_bytes) == Q1N1_PLAN_TOO_MANY);
        t = base_table();
        t.range[0].size = 0;
        t.range[1].base = ~UINT64_C(0);
        t.range[2].base = fb_base;
        CHECK(q1n1_payload_table_check(&t, fb_base, fb_bytes) == Q1N1_PLAN_EMPTY);
        t.range[0].size = 0x1000;
        CHECK(q1n1_payload_table_check(&t, fb_base, fb_bytes) == Q1N1_PLAN_WRAP);
        t.range[1].base = 0x1000000;
        CHECK(q1n1_payload_table_check(&t, fb_base, fb_bytes) == Q1N1_PLAN_FRAMEBUFFER);
        t.range[2].base = ranges.image;
        CHECK(q1n1_payload_table_check(&t, fb_base, fb_bytes) == Q1N1_PLAN_OVERLAP);
    }
    /* A smaller chunk cap shrinks the biggest range: 16 MiB at 64 KiB chunks is exactly 256. */
    {
        struct sp11_ebs_ranges_table t = base_table();
        t.chunk_cap = 1u << 16;
        t.range[0].size = UINT64_C(16) << 20;
        CHECK(q1n1_payload_table_check(&t, 0, 0) == Q1N1_PLAN_OK);
        t.range[0].size++;
        CHECK(q1n1_payload_table_check(&t, 0, 0) == Q1N1_PLAN_TOO_LARGE);
    }
    for (int s = Q1N1_PLAN_OK; s <= Q1N1_PLAN_NOT_WB; s++) CHECK(strcmp(q1n1_payload_plan_name(s), "UNKNOWN") != 0);
    CHECK(!strcmp(q1n1_payload_plan_name(99), "UNKNOWN"));
    return 0;
}

/* ---- map ----------------------------------------------------------------------------------------------- */

static struct sp11_ebs_ranges_table full_table(unsigned files)
{
    struct sp11_ebs_ranges_table t = base_table();
    const char *labels[SP11_EBS_MAX_RANGES] = {"image", "map", "preload"};
    struct q1n1_payload_loaded l = loaded_files(files);
    if (q1n1_payload_plan_append(&t, labels, &l, fb_base, fb_bytes)) abort();
    return t;
}

static int suite_map(void)
{
    build_unit_map();
    CHECK(map_n >= 100 && map_n < 300);
    uint32_t failing = 99;
    for (unsigned files = 1; files <= 5; files++) {
        build_run_map(files - 1);
        struct sp11_ebs_ranges_table t = full_table(files);
        CHECK(q1n1_payload_map_check(&t, map, map_n, &failing) == Q1N1_PLAN_OK && failing == 0);
    }
    build_run_map(0);
    struct sp11_ebs_ranges_table t = full_table(1);
    /* The framebuffer is RESERVED memory: even if it were declared, the map would refuse it. */
    {
        struct sp11_ebs_ranges_table fbt = t;
        fbt.range[fbt.count++] = (struct sp11_ebs_range){fb_base, 0x10000};
        CHECK(q1n1_payload_map_check(&fbt, map, map_n, &failing) == Q1N1_PLAN_WRONG_TYPE && failing == t.count);
    }
    /* Each type, one at a time, for the payload's own descriptor: 1-6 and 9 are swept, the rest are not. */
    for (uint32_t type = 0; type <= 14; type++) {
        build_run_map(0);
        for (uint32_t i = 0; i < map_n; i++)
            if (map[i].base <= ranges.payload && ranges.payload < map[i].base + map[i].pages * 4096) map[i].type = type;
        int want = (type >= 1 && type <= 6) || type == 9 ? Q1N1_PLAN_OK : Q1N1_PLAN_WRONG_TYPE;
        CHECK(q1n1_payload_map_check(&t, map, map_n, &failing) == want);
        CHECK(want == Q1N1_PLAN_OK ? failing == 0 : failing == 3);
    }
    /* No WB in the descriptor's attribute, with every other bit set. */
    build_run_map(0);
    for (uint32_t i = 0; i < map_n; i++)
        if (map[i].base <= ranges.image && ranges.image < map[i].base + map[i].pages * 4096) map[i].attribute = ~UINT64_C(8);
    CHECK(q1n1_payload_map_check(&t, map, map_n, &failing) == Q1N1_PLAN_NOT_WB && failing == 0);
    /* The first refused range is the one reported, whatever follows. The map buffer and the table are
     * adjacent LoaderData, so the firmware lists one descriptor for both: spoil it and the map (range 1)
     * is the first refused, the table (range 2) is not reported. */
    build_run_map(0);
    for (uint32_t i = 0; i < map_n; i++)
        if (map[i].base <= ranges.table && ranges.table < map[i].base + map[i].pages * 4096) map[i].type = 7;
    CHECK(q1n1_payload_map_check(&t, map, map_n, &failing) == Q1N1_PLAN_WRONG_TYPE && failing == 1);
    /* A range in no descriptor, across two, one byte past the end of its descriptor, or in two (an overlapping map). */
    build_run_map(0);
    struct sp11_ebs_ranges_table moved = t;
    moved.range[3].base = UINT64_C(0x2000000000);
    CHECK(q1n1_payload_map_check(&moved, map, map_n, &failing) == Q1N1_PLAN_NOT_CONTAINED && failing == 3);
    moved = t;
    moved.range[3].base = ranges.payload - 0x1000;               /* the conventional page before the payload, then the payload */
    moved.range[3].size = 0x2000;
    CHECK(q1n1_payload_map_check(&moved, map, map_n, &failing) == Q1N1_PLAN_NOT_CONTAINED);
    uint64_t end = 0;
    for (uint32_t i = 0; i < map_n; i++)
        if (map[i].base <= ranges.payload && ranges.payload < map[i].base + map[i].pages * 4096) end = map[i].base + map[i].pages * 4096;
    moved = t;
    moved.range[3].base = end - 0x1000;
    moved.range[3].size = 0x1000;
    CHECK(q1n1_payload_map_check(&moved, map, map_n, &failing) == Q1N1_PLAN_OK);
    moved.range[3].size = 0x1001;
    CHECK(q1n1_payload_map_check(&moved, map, map_n, &failing) == Q1N1_PLAN_NOT_CONTAINED);
    struct q1n1_sp11_gop_map_entry dup = map[0];
    for (uint32_t i = 0; i < map_n; i++)
        if (map[i].base <= ranges.payload && ranges.payload < map[i].base + map[i].pages * 4096) dup = map[i];
    map[map_n++] = dup;
    CHECK(q1n1_payload_map_check(&t, map, map_n, &failing) == Q1N1_PLAN_NOT_CONTAINED && failing == 3);
    /* Zero chunk cap, an empty range, and the chunk budget at its edge, in slbounce's order. */
    build_run_map(0);
    struct sp11_ebs_ranges_table odd = t;
    odd.chunk_cap = 0;
    CHECK(q1n1_payload_map_check(&odd, map, map_n, &failing) == Q1N1_PLAN_CHUNK_CAP && failing == 0);
    odd = t;
    odd.range[1].size = 0;
    CHECK(q1n1_payload_map_check(&odd, map, map_n, &failing) == Q1N1_PLAN_EMPTY && failing == 1);
    /* The chunk budget at its edge, in a descriptor of a swept type: 256 MiB is 256 chunks, one byte more
     * is 257. */
    build_run_map(0);
    CHECK(carve(2, UINT64_C(0x900000000), 0x10100));            /* 257 MiB of loader data in the high bank */
    odd = t;
    odd.range[3] = (struct sp11_ebs_range){UINT64_C(0x900000000), UINT64_C(256) << 20};
    CHECK(q1n1_payload_map_check(&odd, map, map_n, &failing) == Q1N1_PLAN_OK);
    odd.range[3].size++;
    CHECK(q1n1_payload_map_check(&odd, map, map_n, &failing) == Q1N1_PLAN_TOO_LARGE && failing == 3);
    return 0;
}

/* ---- precheck ------------------------------------------------------------------------------------------- */

/* What main.c hands q1n1_payload_precheck, and which refusal comes back first when several are true at once:
 * the plan, then the table's existence, then its write, then the map, then slbounce's rules. */
static int suite_precheck(void)
{
    build_unit_map();
    build_run_map(0);
    struct sp11_ebs_ranges_table t = full_table(1);
    struct q1n1_payload_diag diag;
    uint64_t efi_error = UINT64_C(0x8000000000000009);

    memset(&diag, 0xee, sizeof diag);
    CHECK(q1n1_payload_precheck(Q1N1_PLAN_OK, 0, 0, 1, &t, map, map_n, &diag) == Q1N1_PAYLOAD_OK);

    memset(&diag, 0, sizeof diag);
    CHECK(q1n1_payload_precheck(Q1N1_PLAN_TOO_MANY, 0, 0, 1, &t, map, map_n, &diag) == Q1N1_PAYLOAD_E_RANGES);
    CHECK(diag.plan == Q1N1_PLAN_TOO_MANY && diag.efi == 0);

    /* The plan's refusal wins over a failed write, a bad map and a table slbounce would refuse. */
    memset(&diag, 0, sizeof diag);
    CHECK(q1n1_payload_precheck(Q1N1_PLAN_FRAMEBUFFER, efi_error, efi_error, 0, &t, map, 0, &diag) == Q1N1_PAYLOAD_E_RANGES);
    CHECK(diag.plan == Q1N1_PLAN_FRAMEBUFFER);

    /* No table written: refused as a table that does not exist, and never dereferenced. */
    memset(&diag, 0, sizeof diag);
    CHECK(q1n1_payload_precheck(Q1N1_PLAN_OK, 0, 0, 1, NULL, map, map_n, &diag) == Q1N1_PAYLOAD_E_RANGES);
    CHECK(diag.plan == Q1N1_PLAN_NO_TABLE);
    struct sp11_ebs_ranges_table empty = t;
    empty.count = 0;
    memset(&diag, 0, sizeof diag);
    CHECK(q1n1_payload_precheck(Q1N1_PLAN_OK, 0, 0, 1, &empty, map, map_n, &diag) == Q1N1_PAYLOAD_E_RANGES);
    CHECK(diag.plan == Q1N1_PLAN_NO_TABLE);

    /* SetVariable failed: the firmware's status is kept, and that refusal comes before the map's. */
    memset(&diag, 0, sizeof diag);
    CHECK(q1n1_payload_precheck(Q1N1_PLAN_OK, efi_error, efi_error + 1, 0, &t, map, map_n, &diag) == Q1N1_PAYLOAD_E_DECLARE);
    CHECK(diag.efi == efi_error && diag.plan == 0);

    /* The map could not be read or parsed: its status is kept. */
    memset(&diag, 0, sizeof diag);
    CHECK(q1n1_payload_precheck(Q1N1_PLAN_OK, 0, efi_error + 2, 0, &t, map, map_n, &diag) == Q1N1_PAYLOAD_E_MAP);
    CHECK(diag.efi == efi_error + 2);
    memset(&diag, 0, sizeof diag);
    CHECK(q1n1_payload_precheck(Q1N1_PLAN_OK, 0, 0, 0, &t, map, map_n, &diag) == Q1N1_PAYLOAD_E_MAP);
    CHECK(diag.efi == 0);

    /* The map refuses a range: the table, slbounce's reason and the range come back. */
    for (uint32_t i = 0; i < map_n; i++)
        if (map[i].base <= ranges.payload && ranges.payload < map[i].base + map[i].pages * 4096) map[i].type = 0;
    memset(&diag, 0, sizeof diag);
    CHECK(q1n1_payload_precheck(Q1N1_PLAN_OK, 0, 0, 1, &t, map, map_n, &diag) == Q1N1_PAYLOAD_E_RANGES);
    CHECK(diag.plan == Q1N1_PLAN_WRONG_TYPE && diag.range == 3);
    return 0;
}

/* ---- slbounce ------------------------------------------------------------------------------------------- */

#ifdef HAVE_SLBOUNCE_SWEEP
static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);
static uint64_t rnd(void)
{
    rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
    return rng_state;
}
static int mapped_status(int sweep)
{
    switch (sweep) {
    case SP11_SWEEP_OK: return Q1N1_PLAN_OK;
    case SP11_SWEEP_ERR_BAD_RANGE: return Q1N1_PLAN_EMPTY;
    case SP11_SWEEP_ERR_NOT_CONTAINED: return Q1N1_PLAN_NOT_CONTAINED;
    case SP11_SWEEP_ERR_WRONG_TYPE: return Q1N1_PLAN_WRONG_TYPE;
    case SP11_SWEEP_ERR_NOT_WRITEBACK: return Q1N1_PLAN_NOT_WB;
    case SP11_SWEEP_ERR_CHUNK_CAP: return Q1N1_PLAN_CHUNK_CAP;
    case SP11_SWEEP_ERR_TOO_MANY_OPS: return Q1N1_PLAN_TOO_LARGE;
    default: return -1;
    }
}
#endif

static int suite_slbounce(void)
{
#ifdef HAVE_SLBOUNCE_SWEEP
    static struct sp11_sweep_descriptor descs[512];
    static const uint64_t attrs[] = {0x8, 0x100f, 0x1000, 0, 0x8000000000000008ull, 0x7, ~UINT64_C(0)};
    static const uint32_t caps[] = {1u << 20, 1u << 16, 4096, 1u << 30, 0, 3};
    unsigned refused = 0, accepted = 0;
    for (unsigned trial = 0; trial < 30000; trial++) {
        /* Odd trials are friendly (swept types, write-back, disjoint descriptors, ranges inside them) so
         * that the accepting side is exercised as much as the refusing side; even ones are hostile. */
        int friendly = trial & 1;
        uint32_t n = 1 + rnd() % 12;
        for (uint32_t i = 0; i < n; i++) {
            /* Mostly neighbours, so that ranges straddle, duplicate and overlap descriptors. */
            uint64_t base = (rnd() % 6) * 0x100000 + (rnd() % 4) * 0x1000;
            map[i] = (struct q1n1_sp11_gop_map_entry){(uint32_t)(rnd() % 15), base, 1 + rnd() % 0x500, attrs[rnd() % 7]};
            if (rnd() % 8 == 0) map[i].pages = rnd();             /* a page count that overflows */
            if (friendly) {
                static const uint32_t swept[] = {1, 2, 3, 4, 5, 6, 9};
                map[i] = (struct q1n1_sp11_gop_map_entry){swept[rnd() % 7], (uint64_t)(i + 1) * 0x10000000,
                                                          0x1000 + rnd() % 0x4000, 0x100f};
            }
            descs[i] = (struct sp11_sweep_descriptor){map[i].type, map[i].attribute, map[i].base, map[i].pages};
        }
        struct sp11_ebs_ranges_table t;
        memset(&t, 0, sizeof t);
        t.chunk_cap = caps[rnd() % 6];
        t.count = 1 + rnd() % SP11_EBS_MAX_RANGES;
        if (friendly) t.chunk_cap = 1u << 20;
        for (uint32_t r = 0; r < t.count; r++) {
            uint32_t d = rnd() % n;
            uint64_t base = map[d].base + (rnd() % 3 ? (rnd() % 8) * 0x1000 : 0), size = (rnd() % 5 + 1) * 0x1000;
            if (friendly) {
                t.range[r] = (struct sp11_ebs_range){map[d].base + (rnd() % 8) * 0x1000, (rnd() % 8 + 1) * 0x1000};
                if (rnd() % 10 == 0) t.range[r].size = map[d].pages * 4096;   /* the whole descriptor, exactly */
                continue;
            }
            if (rnd() % 5 == 0) size = (rnd() % 300) << 20;
            if (rnd() % 11 == 0) size = 0;
            if (rnd() % 13 == 0) base = ~UINT64_C(0) - rnd() % 0x3000;
            t.range[r] = (struct sp11_ebs_range){base, size};
        }
        /* slbounce's loop (bounce_main.c sp11_run_scoped_sweep): the first range it refuses ends it. */
        int want = Q1N1_PLAN_OK;
        uint32_t want_at = 0;
        for (uint32_t r = 0; r < t.count; r++) {
            struct sp11_sweep_op ops[256];
            uint32_t n_ops = 0;
            int rc = sp11_sweep_range(descs, n, t.range[r].base, t.range[r].size, t.chunk_cap, ops, 256, &n_ops);
            if (rc != SP11_SWEEP_OK) { want = mapped_status(rc); want_at = r; break; }
        }
        uint32_t at = 77;
        int got = q1n1_payload_map_check(&t, map, n, &at);
        if (got != want || at != want_at)
            fprintf(stderr, "trial %u: slbounce %d at %u, runner %d at %u\n", trial, want, want_at, got, at);
        CHECK(got == want && at == want_at);
        if (want == Q1N1_PLAN_OK) accepted++; else refused++;
    }
    CHECK(accepted > 300 && refused > 300);                          /* the trials exercised both outcomes */
    /* The constants the two sides share. */
    CHECK(SP11_SWEEP_PAGE_BYTES == 4096 && SP11_SWEEP_ATTRIBUTE_WB == 8);
    return 0;
#else
    printf("SKIP: slbounce comparison (no slbounce source given)\n");
    skipped++;
    return 0;
#endif
}

/* ---- text ----------------------------------------------------------------------------------------------- */

static int suite_text(void)
{
    char text[40];
    struct { uint64_t v; const char *hex, *dec; } numbers[] = {
        {0, "0X0", "0"}, {1, "0X1", "1"}, {9, "0X9", "9"}, {10, "0XA", "10"}, {255, "0XFF", "255"}, {256, "0X100", "256"},
        {0xdeadbeef, "0XDEADBEEF", "3735928559"}, {UINT64_C(0x880000000), "0X880000000", "36507222016"},
        {~UINT64_C(0), "0XFFFFFFFFFFFFFFFF", "18446744073709551615"},
    };
    for (unsigned i = 0; i < sizeof numbers / sizeof numbers[0]; i++) {
        CHECK(q1n1_payload_fmt_hex(text, sizeof text, numbers[i].v) == strlen(numbers[i].hex) && !strcmp(text, numbers[i].hex));
        CHECK(q1n1_payload_fmt_dec(text, sizeof text, numbers[i].v) == strlen(numbers[i].dec) && !strcmp(text, numbers[i].dec));
    }
    /* Cut, never overrun, whatever the capacity. */
    for (size_t cap = 0; cap < 24; cap++) {
        char guard[40];
        memset(guard, 0x55, sizeof guard);
        size_t n = q1n1_payload_fmt_hex(guard, cap, ~UINT64_C(0));
        CHECK(n == (cap ? (cap - 1 < 18 ? cap - 1 : 18) : 0));
        if (cap) CHECK(guard[n] == 0);
        CHECK((unsigned char)guard[cap] == 0x55 || cap >= sizeof guard);
        memset(guard, 0x55, sizeof guard);
        n = q1n1_payload_fmt_dec(guard, cap, ~UINT64_C(0));
        CHECK(n == (cap ? (cap - 1 < 20 ? cap - 1 : 20) : 0));
        CHECK((unsigned char)guard[cap] == 0x55 || cap >= sizeof guard);
    }
    /* The font. */
    char line[] = "Payload: a_b-c.d/e=f?(g) \t\x7f\xc3\xa9 ~`!@#$%^&*[]{}\\|;'\",<>+";
    q1n1_payload_sanitize(line);
    for (const char *p = line; *p; p++)
        CHECK((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || strchr(" :-./=?()_", *p));
    CHECK(!strncmp(line, "PAYLOAD: A_B-C.D/E=F?(G) ", 25) && strchr(line, '_') != NULL);
    char same[] = "STATE 0X1: A-B.C/D=E?(F)_G";
    q1n1_payload_sanitize(same);
    CHECK(!strcmp(same, "STATE 0X1: A-B.C/D=E?(F)_G"));
    /* The line builder: every field after a space, cut at the cap, no overrun. */
    struct q1n1_payload_line l;
    q1n1_payload_line_begin(&l, "PAYLOAD X");
    q1n1_payload_line_hex(&l, "A", 255);
    q1n1_payload_line_dec(&l, "B", 7);
    q1n1_payload_line_word(&l, "WORD");
    uint8_t digest[32];
    for (unsigned i = 0; i < 32; i++) digest[i] = (uint8_t)(0x10 * (i & 15) + i);
    q1n1_payload_line_digest(&l, "SHA", digest);
    q1n1_payload_line_digest(&l, NULL, digest);
    q1n1_payload_line_raw(&l, "!");
    CHECK(!strcmp(l.buf, "PAYLOAD X A=0XFF B=7 WORD SHA=0011223344556677 0011223344556677!"));
    for (unsigned i = 0; i < 40; i++) q1n1_payload_line_dec(&l, "LONGKEY", 123456789);
    CHECK(strlen(l.buf) == Q1N1_PAYLOAD_LINE_MAX && l.len == Q1N1_PAYLOAD_LINE_MAX);
    q1n1_payload_line_begin(&l, "");
    CHECK(l.len == 0 && l.buf[0] == 0);

    /* The region: the survey's own layout over a grid of panel sizes, and its invariants whatever the
     * survey is. */
    static const uint32_t widths[] = {0, 100, 640, 800, 1024, 1280, 1366, 1600, 1920, 2560, 2880, 3840};
    static const uint32_t heights[] = {0, 40, 300, 480, 600, 768, 900, 1080, 1200, 1920, 2160};
    static const uint32_t scales[] = {0, 1, 2, 3, 4, 5};
    unsigned grid = 0;
    for (unsigned w = 0; w < sizeof widths / sizeof widths[0]; w++)
        for (unsigned h = 0; h < sizeof heights / sizeof heights[0]; h++)
            for (unsigned s = 0; s < sizeof scales / sizeof scales[0]; s++)
                for (uint32_t rows = 0; rows < 60; rows += 7) {
                    struct q1n1_payload_region r;
                    q1n1_payload_region_place(widths[w], heights[h], scales[s], rows, &r);
                    CHECK(r.scale >= 1 && r.row0 + r.rows >= r.row0);
                    CHECK(r.placement == Q1N1_PAYLOAD_REGION_RIGHT || r.placement == Q1N1_PAYLOAD_REGION_BELOW);
                    if (r.placement == Q1N1_PAYLOAD_REGION_BELOW) CHECK(r.col0 == 0 && r.row0 == rows);
                    grid++;
#ifdef HAVE_SURVEY_LAYOUT
                    struct stk_layout_mirror m;
                    stk_layout(widths[w], heights[h], scales[s], rows, &m);
                    CHECK(m.placement == r.placement && m.scale == r.scale && m.col0 == r.col0 &&
                          m.row0 == r.row0 && m.rows == r.rows);
#endif
                }
    CHECK(grid == 12 * 11 * 6 * 9);
    /* The panel the unit has: 2880 wide at scale 3 puts the region right of the page, under the emblem. */
    struct q1n1_payload_region unit;
    q1n1_payload_region_place(2880, 1920, 3, 20, &unit);
    CHECK(unit.placement == Q1N1_PAYLOAD_REGION_RIGHT && unit.rows >= Q1N1_PAYLOAD_REGION_LINES + 2);
#ifndef HAVE_SURVEY_LAYOUT
    printf("SKIP: survey layout comparison (no survey object given)\n");
    skipped++;
#endif
    return 0;
}

/* ---- abi ------------------------------------------------------------------------------------------------ */

static int suite_abi(void)
{
    CHECK(sizeof(struct q1n1_payload_args) == 192 && sizeof(struct q1n1_payload_ops) == 32);
    CHECK(sizeof(void *) == 8 && sizeof(uint64_t) == 8);
    const uint8_t bytes[8] = {'Q', '1', 'N', '1', 'P', 'A', 'Y', '1'};
    uint64_t magic;
    memcpy(&magic, bytes, 8);
    CHECK(Q1N1_PAYLOAD_ABI_MAGIC == magic);                          /* little endian host: byte 0 is the low byte */
    CHECK(Q1N1_PAYLOAD_ABI_VERSION == 1);
    CHECK(Q1N1_PAYLOAD_LINE_MAX == 100 && Q1N1_PAYLOAD_LINES_MAX == 40 && Q1N1_PAYLOAD_LOADS_MAX == 4096);
    CHECK(Q1N1_PAYLOAD_STACK_BYTES == 65536 && Q1N1_PAYLOAD_REGION_LINES == 60);
    CHECK(Q1N1_PAYLOAD_LINES_MAX + Q1N1_PAYLOAD_NOTES + 6 <= Q1N1_PAYLOAD_REGION_LINES);   /* the runner's lines fit too */
    CHECK(Q1N1_PAYLOAD_SWEEP_MAX_OPS == 256 && Q1N1_PAYLOAD_MAX_FILE_BYTES == (UINT64_C(256) << 20));
    CHECK(Q1N1_PAYLOAD_MAX_FILES == 5 && Q1N1_PAYLOAD_NOTES >= Q1N1_PAYLOAD_MAX_FILES + 1);
    CHECK(Q1N1_PAYLOAD_LOAD_OK == 0 && Q1N1_PAYLOAD_LOAD_E_FAULT == 6 && Q1N1_PAYLOAD_RET_BAD_ARGS == 1);
    CHECK(!strcmp(Q1N1_PAYLOAD_MANIFEST_PATH, "\\SP11\\PAYLOAD.MAN") && !strcmp(Q1N1_PAYLOAD_DIR, "\\SP11\\"));
    CHECK(Q1N1_PAYLOAD_STATUS_REFUSED == EFI_ERROR(21));
    return 0;
}

static void print_abi_table(void)
{
#define OFF(type, field) printf("%s.%s %zu\n", #type, #field, offsetof(struct type, field))
    OFF(q1n1_payload_args, magic); OFF(q1n1_payload_args, version); OFF(q1n1_payload_args, size);
    OFF(q1n1_payload_args, payload_base); OFF(q1n1_payload_args, payload_size); OFF(q1n1_payload_args, fb_base);
    OFF(q1n1_payload_args, fb_bytes); OFF(q1n1_payload_args, fb_width); OFF(q1n1_payload_args, fb_height);
    OFF(q1n1_payload_args, fb_stride); OFF(q1n1_payload_args, fb_format); OFF(q1n1_payload_args, map_base);
    OFF(q1n1_payload_args, map_size); OFF(q1n1_payload_args, map_stride); OFF(q1n1_payload_args, preload_table);
    OFF(q1n1_payload_args, preload_size); OFF(q1n1_payload_args, stack_base); OFF(q1n1_payload_args, stack_size);
    OFF(q1n1_payload_args, ops); OFF(q1n1_payload_args, reserved);
    OFF(q1n1_payload_ops, puts); OFF(q1n1_payload_ops, hex); OFF(q1n1_payload_ops, load32);
    OFF(q1n1_payload_ops, counter);
    printf("q1n1_payload_args %zu\nq1n1_payload_ops %zu\n", sizeof(struct q1n1_payload_args), sizeof(struct q1n1_payload_ops));
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"plan", suite_plan}, {"map", suite_map}, {"precheck", suite_precheck}, {"slbounce", suite_slbounce},
        {"text", suite_text}, {"abi", suite_abi},
    };
    if (argc > 1 && !strcmp(argv[1], "abi-table")) { print_abi_table(); return 0; }
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) { fprintf(stderr, "FAIL: suite %s\n", suites[i].name); return 1; }
        ran++;
    }
    printf("PASS: %u payload plan suites, %u checks%s\n", ran, checks, skipped ? " (some comparisons SKIPPED)" : "");
    return 0;
}
