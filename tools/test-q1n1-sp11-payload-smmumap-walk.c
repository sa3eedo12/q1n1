/* SPDX-License-Identifier: MIT */
/* White-box host test for the loads, the software walk and the scan of the runner's mapping step (platform/uefi/sp11-smmumap.c,
 * docs/SP11-PAYLOAD-SMMUMAP.md). The step's black-box suites (tools/test-q1n1-sp11-payload-smmumap.c) reach the walk only through a page
 * and its template, which share the level-0 entry of the unit's regime; so a level-0 block-form leaf, the start level of other regimes, the
 * address size of a table, the number of entries of a start table and the proof of each table page cannot be built there. They are tested
 * here by including the source: the static functions load_ram(), walk(), scan_tables(), physical_bits() and start_entries() are called
 * directly. Driven by tools/test-q1n1-sp11-payload-smmumap.py under ASan and UBSan. Evidence: EXPERIMENTAL (host model only). */
#include <stdio.h>
#include <string.h>

#include "sp11-smmumap.c"

static unsigned checks, failures;
#define CHECK(x, ...) do { checks++; if (!(x)) { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static struct { uint64_t at, value; } memory[32];
static unsigned memory_n, reads;
static uint64_t fault_at;

static int fake_read64(uint64_t at, uint64_t *value)
{
    reads++;
    if (fault_at && at == fault_at) return 1;
    *value = 0;
    for (unsigned i = 0; i < memory_n; i++)
        if (memory[i].at == at) *value = memory[i].value;
    return 0;
}
static void put(uint64_t at, uint64_t value)
{
    memory[memory_n].at = at;
    memory[memory_n].value = value;
    memory_n++;
}

#define ROOT UINT64_C(0x01000000)
#define TABLE1 UINT64_C(0x02000000)
#define TABLE2 UINT64_C(0x03000000)
#define TABLE3 UINT64_C(0x04000000)
#define RAM_END UINT64_C(0x05000000)
#define FAR_ROOT (UINT64_C(1) << 44)
#define TABLE_DESC(next) ((next) | 3u)
#define MMIO_ATTR UINT64_C(0x8000000000000001)

/* The memory map of the model: descriptor 0 is boot services data over the four tables, 1 is one conventional page at the root that a 48-bit PS
 * allows, and 2 and 3 are free for a case. A test sets a descriptor with map_set (type, start, pages, attribute word); 0 pages is no descriptor. */
#define MAP_STRIDE 48u
static uint8_t map_bytes[MAP_STRIDE * 4];
static struct q1n1_smmumap_env env = {.read64 = fake_read64, .map = map_bytes, .map_size = sizeof map_bytes, .map_stride = MAP_STRIDE};

static void map_set(unsigned i, unsigned type, uint64_t start, uint64_t pages, uint64_t attr)
{
    uint8_t *d = map_bytes + MAP_STRIDE * i;
    memset(d, 0, MAP_STRIDE);
    for (unsigned b = 0; b < 4; b++) d[b] = (uint8_t)(type >> (8 * b));
    for (unsigned b = 0; b < 8; b++) {
        d[8 + b] = (uint8_t)(start >> (8 * b));
        d[24 + b] = (uint8_t)(pages >> (8 * b));
        d[32 + b] = (uint8_t)(attr >> (8 * b));
    }
}
static void clear(void)
{
    memory_n = reads = 0;
    fault_at = 0;
    env.map = map_bytes;
    env.map_size = sizeof map_bytes;
    env.map_stride = MAP_STRIDE;
    map_set(0, 4, ROOT, (RAM_END - ROOT) / 4096u, 0);
    map_set(1, 7, FAR_ROOT, 1, 0);
    map_set(2, 0, 0, 0, 0);
    map_set(3, 0, 0, 0, 0);
}
/* The RAM descriptor with a one-page hole at `page`: no descriptor holds that page. */
static void map_hole(uint64_t page)
{
    map_set(0, 4, ROOT, (page - ROOT) / 4096u, 0);
    map_set(2, 4, page + 4096u, (RAM_END - page - 4096u) / 4096u, 0);
}

static struct q1n1_smmumap_regs regs_of(uint64_t tcr)
{
    struct q1n1_smmumap_regs regs = {.ttbr0 = ROOT | 1u, .tcr = tcr};     /* bit 0 of TTBR0 is CnP, not an address bit */
    return regs;
}

static int walk_va(uint64_t tcr, uint64_t va, struct walk *w)
{
    struct q1n1_smmumap_regs regs = regs_of(tcr);
    return walk(&env, &regs, va, w);
}

/* The unit's regime: T0SZ 20 (a 44-bit VA, start level 0) and PS 4 (44 bits). */
#define TCR_UNIT (UINT64_C(20) | (UINT64_C(4) << 16))

static void start_levels(void)
{
    static const struct { unsigned t0sz, level; } want[] = {{16, 0}, {20, 0}, {24, 0}, {25, 1}, {28, 1}, {33, 1}, {34, 2}, {38, 2}, {42, 2}};
    for (unsigned i = 0; i < sizeof want / sizeof want[0]; i++) {
        struct walk w;
        clear();
        CHECK(walk_va(want[i].t0sz | (UINT64_C(5) << 16), 0, &w) == WALK_INVALID && w.last == want[i].level && reads == 1 && w.base[want[i].level] == ROOT,
              "T0SZ %u: the walk starts at level %u, not %u", want[i].t0sz, want[i].level, w.last);
    }
    CHECK(start_entries(44, 0) == 32 && start_entries(48, 0) == 512 && start_entries(39, 1) == 512 && start_entries(25, 2) == 16 && start_entries(30, 2) == 512 &&
          start_entries(31, 1) == 2 && start_entries(40, 0) == 2, "the number of entries of a start table");
    for (unsigned ps = 0; ps < 8; ps++) {
        static const unsigned bits[] = {32, 36, 40, 42, 44, 48, 48, 48};
        CHECK(physical_bits((uint64_t)ps << 16) == bits[ps], "PS %u is %u bits, not %u", ps, bits[ps], physical_bits((uint64_t)ps << 16));
    }
    CHECK(physical_bits(((uint64_t)4 << 16) | UINT64_C(0xffffffffff00ffc0)) == 44, "only TCR_EL2.PS (bits 18:16) is the address size");
}

static void leaf_forms(void)
{
    struct walk w;
    /* Level 0 holds no block: bits 1:0 of 01 there are not a leaf this walk may take. */
    clear();
    put(ROOT, UINT64_C(0x40000000) | 1u);
    CHECK(walk_va(TCR_UNIT, 0, &w) == WALK_FORMAT && w.last == 0 && w.desc[0] == (UINT64_C(0x40000000) | 1u), "a level-0 block is a format error, not a block");
    clear();
    put(ROOT, UINT64_C(0x40000000) | 2u);
    CHECK(walk_va(TCR_UNIT, 0, &w) == WALK_INVALID && w.last == 0, "bit 0 clear is invalid at level 0 whatever bit 1 says");
    clear();
    CHECK(walk_va(TCR_UNIT, 0, &w) == WALK_INVALID && w.last == 0 && reads == 1, "an empty root is invalid at level 0");

    /* Levels 1 and 2 hold blocks. */
    for (unsigned level = 1; level <= 2; level++) {
        clear();
        put(ROOT, TABLE_DESC(TABLE1));
        if (level == 1) put(TABLE1, UINT64_C(0x80000000) | 1u);
        else { put(TABLE1, TABLE_DESC(TABLE2)); put(TABLE2, UINT64_C(0x80200000) | 1u); }
        CHECK(walk_va(TCR_UNIT, 0, &w) == WALK_BLOCK && w.last == level && w.base[level] == (level == 1 ? TABLE1 : TABLE2), "a block at level %u: last %u", level, w.last);
        clear();
        put(ROOT, TABLE_DESC(TABLE1));
        if (level == 2) put(TABLE1, TABLE_DESC(TABLE2));
        CHECK(walk_va(TCR_UNIT, 0, &w) == WALK_INVALID && w.last == level, "an empty entry at level %u: last %u", level, w.last);
    }

    /* Level 3: 11 is a page, 01 is reserved, anything with bit 0 clear is invalid. */
    static const struct { uint64_t desc; int result; } leaf[] = {{UINT64_C(0x15400000) | 3u, WALK_PAGE}, {UINT64_C(0x15400000) | 1u, WALK_FORMAT},
                                                              {UINT64_C(0x15400000) | 2u, WALK_INVALID}, {0, WALK_INVALID}};
    for (unsigned i = 0; i < 4; i++) {
        clear();
        put(ROOT, TABLE_DESC(TABLE1)); put(TABLE1, TABLE_DESC(TABLE2)); put(TABLE2, TABLE_DESC(TABLE3)); put(TABLE3, leaf[i].desc);
        CHECK(walk_va(TCR_UNIT, 0, &w) == leaf[i].result && w.last == 3 && w.desc[3] == leaf[i].desc && w.at[3] == TABLE3 && w.table == TABLE3,
              "a level-3 descriptor %llx", (unsigned long long)leaf[i].desc);
        CHECK(w.base[0] == ROOT && w.base[1] == TABLE1 && w.base[2] == TABLE2 && w.base[3] == TABLE3 && w.at[0] == ROOT && reads == 4, "the tables of the path are recorded");
    }
}

static void indexes_and_limits(void)
{
    struct walk w;
    /* The index into each table is the VA's own: 9 bits per level from bit 39 (level 0, here only 5 bits of them) down to bit 12. */
    clear();
    put(ROOT + 8u * 3u, TABLE_DESC(TABLE1));
    put(TABLE1 + 8u * 5u, TABLE_DESC(TABLE2));
    put(TABLE2 + 8u * 7u, TABLE_DESC(TABLE3));
    put(TABLE3 + 8u * 9u, UINT64_C(0x15400000) | 3u);
    CHECK(walk_va(TCR_UNIT, (UINT64_C(3) << 39) | (UINT64_C(5) << 30) | (UINT64_C(7) << 21) | (UINT64_C(9) << 12) | 0x123, &w) == WALK_PAGE &&
          w.at[0] == ROOT + 24u && w.at[1] == TABLE1 + 40u && w.at[2] == TABLE2 + 56u && w.at[3] == TABLE3 + 72u, "the index into each table");

    /* A VA beyond the range of T0SZ is not walked: no read at all. */
    clear();
    CHECK(walk_va(TCR_UNIT, UINT64_C(1) << 44, &w) == WALK_FORMAT && reads == 0, "a VA beyond 44 bits is a format error with no read");
    clear();
    CHECK(walk_va(TCR_UNIT, (UINT64_C(1) << 44) - 1, &w) == WALK_INVALID && reads == 1, "the last VA of the range is walked");

    /* A table beyond the physical address size is not read: the root, and an entry that points at one. */
    clear();
    {
        struct q1n1_smmumap_regs regs = {.ttbr0 = UINT64_C(1) << 44, .tcr = TCR_UNIT};
        CHECK(walk(&env, &regs, 0, &w) == WALK_ADDRESS && reads == 0, "a root beyond PS");
        regs.tcr = 20u | (UINT64_C(5) << 16);
        CHECK(walk(&env, &regs, 0, &w) == WALK_INVALID && reads == 1, "the same root under a 48-bit PS is read");
        regs.ttbr0 = UINT64_C(1) << 32;
        regs.tcr = 20u | (UINT64_C(0) << 16);
        reads = 0;
        CHECK(walk(&env, &regs, 0, &w) == WALK_ADDRESS && reads == 0, "a root beyond a 32-bit PS");
    }
    clear();
    put(ROOT, TABLE_DESC(UINT64_C(1) << 44));
    CHECK(walk_va(TCR_UNIT, 0, &w) == WALK_ADDRESS && w.last == 0 && reads == 1, "an entry that points beyond PS: the next table is not read");

    /* A read that aborts ends the walk at that level. */
    for (unsigned level = 0; level < 4; level++) {
        static const uint64_t tables[] = {ROOT, TABLE1, TABLE2, TABLE3};
        clear();
        put(ROOT, TABLE_DESC(TABLE1)); put(TABLE1, TABLE_DESC(TABLE2)); put(TABLE2, TABLE_DESC(TABLE3)); put(TABLE3, UINT64_C(0x15400000) | 3u);
        fault_at = tables[level];
        CHECK(walk_va(TCR_UNIT, 0, &w) == WALK_FAULT && w.last == level && reads == level + 1 && w.desc[level] == 0, "a read that aborts at level %u: last %u, %u reads", level, w.last, reads);
    }

    /* The hierarchical controls of the table descriptors passed add up; those of a leaf do not. */
    clear();
    put(ROOT, TABLE_DESC(TABLE1) | (UINT64_C(1) << 63));
    put(TABLE1, TABLE_DESC(TABLE2) | (UINT64_C(1) << 61));
    put(TABLE2, TABLE_DESC(TABLE3) | (UINT64_C(1) << 59));
    put(TABLE3, (UINT64_C(0x15400000) | 3u) | (UINT64_C(1) << 60));
    CHECK(walk_va(TCR_UNIT, 0, &w) == WALK_PAGE && w.upper == ((UINT64_C(1) << 63) | (UINT64_C(1) << 61) | (UINT64_C(1) << 59)), "the control bits of the tables passed: %llx", (unsigned long long)w.upper);
    /* Bits 58:52 of a table descriptor are neither controls nor address: the next table is where bits 47:12 say. */
    clear();
    put(ROOT, TABLE_DESC(TABLE1) | (UINT64_C(0x7f) << 52));
    CHECK(walk_va(TCR_UNIT, 0, &w) == WALK_INVALID && w.last == 1 && w.base[1] == TABLE1 && w.upper == 0, "only bits 47:12 of a table descriptor address the next table");
}

/* The page of the model's walks: the VA with index 9 in the level-3 table, so that the slot is not the first word of the table. */
#define PAGE_VA (UINT64_C(9) << 12)
static const uint64_t TABLES[] = {ROOT, TABLE1, TABLE2, TABLE3};

static void unit_path(void)
{
    put(ROOT, TABLE_DESC(TABLE1));
    put(TABLE1, TABLE_DESC(TABLE2));
    put(TABLE2, TABLE_DESC(TABLE3));
    put(TABLE3 + 8u * 9u, UINT64_C(0x15400000) | 3u);
}

static void tables_are_proven_ram(void)
{
    struct walk w;
    /* Each table of the path in turn is no RAM of the map: the walk ends before the load from it (the level-3 table before the slot), and
     * says which page and which descriptor decided, whether none holds the page or a descriptor that is no RAM overlaps it. */
    for (unsigned level = 0; level < 4; level++) {
        clear();
        unit_path();
        map_hole(TABLES[level]);
        CHECK(walk_va(TCR_UNIT, PAGE_VA, &w) == WALK_NOT_RAM && w.last == level && reads == level && w.proof.page == TABLES[level] && w.proof.type == -1 &&
              !w.proof.ok && w.proof.attr == 0 && w.desc[level] == 0 && w.at[level] == 0 && w.base[level] == TABLES[level],
              "level %u, no descriptor holds the table: last %u, %u loads, type %d", level, w.last, reads, w.proof.type);
        clear();
        unit_path();
        map_set(2, 11, TABLES[level], 1, MMIO_ATTR);
        CHECK(walk_va(TCR_UNIT, PAGE_VA, &w) == WALK_NOT_RAM && w.last == level && reads == level && w.proof.page == TABLES[level] && w.proof.type == 11 &&
              w.proof.attr == MMIO_ATTR && !w.proof.ok && w.desc[level] == 0,
              "level %u, a descriptor of MMIO overlaps the table: last %u, %u loads, type %d, attribute %llx", level, w.last, reads, w.proof.type,
              (unsigned long long)w.proof.attr);
    }
    /* A map the logic cannot read proves nothing: no load, not even of the root. */
    for (unsigned why = 0; why < 4; why++) {
        clear();
        unit_path();
        if (why == 0) env.map = NULL;
        if (why == 1) env.map_size = 0;
        if (why == 2) env.map_stride = 32;
        if (why == 3) env.map_size = MAP_STRIDE * 4u - 8u;
        CHECK(walk_va(TCR_UNIT, PAGE_VA, &w) == WALK_NOT_RAM && w.last == 0 && reads == 0 && w.proof.type == -2 && w.proof.page == ROOT,
              "an unusable map (%u): last %u, %u loads, type %d", why, w.last, reads, w.proof.type);
    }
    /* The address check comes first and loads nothing, as before: with no map at all, a root beyond the PS is an address error, not a refusal. */
    {
        struct q1n1_smmumap_regs far = {.ttbr0 = FAR_ROOT, .tcr = TCR_UNIT};
        clear();
        env.map = NULL;
        CHECK(walk(&env, &far, 0, &w) == WALK_ADDRESS && reads == 0 && w.proof.page == 0 && w.proof.type == 0, "a root beyond the PS is an address error before any proof");
    }
}

static void load_ram_asks_about_pages(void)
{
    struct ram_proof p;
    uint64_t value = 0;
    clear();
    memset(&p, 0, sizeof p);
    CHECK(load_ram(&env, ROOT + 8u, &value, &p) == LOAD_OK && p.ok && p.page == ROOT && p.type == 4 && reads == 1, "a load in RAM is made");
    map_set(0, 4, ROOT, 0, 0);                                           /* the map changes under the proof; the step's own cannot */
    map_set(2, 4, TABLE1, 1, 0);
    CHECK(load_ram(&env, ROOT + 16u, &value, &p) == LOAD_OK && reads == 2, "a page just proven is not asked about again");
    CHECK(load_ram(&env, TABLE1, &value, &p) == LOAD_OK && p.page == TABLE1 && p.ok && reads == 3, "another page is asked about");
    CHECK(load_ram(&env, ROOT, &value, &p) == LOAD_NOT_RAM && !p.ok && p.page == ROOT && p.type == -1 && reads == 3,
          "the proof is of the last page only: the first page again is asked about, and holds no RAM now");
    CHECK(load_ram(&env, ROOT + 8u, &value, &p) == LOAD_NOT_RAM && reads == 3, "a page that is not RAM is asked about each time");
    map_set(0, 4, ROOT, 1, 0);
    CHECK(load_ram(&env, ROOT + 8u, &value, &p) == LOAD_OK && p.ok && reads == 4, "and is loaded from once the map calls it RAM");
    map_set(3, 11, ROOT, 1, MMIO_ATTR);
    memset(&p, 0, sizeof p);
    CHECK(load_ram(&env, ROOT + 8u, &value, &p) == LOAD_NOT_RAM && p.type == 11 && p.attr == MMIO_ATTR && reads == 4,
          "a descriptor that is no RAM and overlaps the page decides, whatever else holds it");
    map_set(3, 0, 0, 0, 0);
    fault_at = ROOT + 24u;
    CHECK(load_ram(&env, ROOT + 24u, &value, &p) == LOAD_ABORT && p.ok, "a load that aborts in RAM is an abort, not a refusal");
    CHECK(load_ram(&env, ROOT + 4096u - 8u, &value, &p) == LOAD_OK && p.page == ROOT, "the last word of a page is in that page");
    CHECK(load_ram(&env, ROOT + 4096u, &value, &p) == LOAD_NOT_RAM && p.page == ROOT + 4096u && p.type == -1,
          "the first word of the next page: that page is asked about, and no descriptor holds it");
}

static void scan_asks_about_every_page(void)
{
    struct walk w;
    struct scan s;
    struct q1n1_smmumap_regs regs = regs_of(TCR_UNIT);
    clear();
    unit_path();
    put(TABLE3 + 8u, TABLE_DESC(UINT64_C(0x10000000)));
    put(TABLE3 + 8u * 200u, UINT64_C(0x20000000) | 1u);
    put(ROOT + 8u * 5u, TABLE_DESC(TABLE3));                              /* the root points at the level-3 table as well */
    CHECK(walk_va(TCR_UNIT, PAGE_VA, &w) == WALK_PAGE, "the path of the scan");
    reads = 0;
    CHECK(scan_tables(&env, &regs, &w, w.at[3], &s) == LOAD_OK && s.valid == 2 && s.refs[0] == 1 && s.refs[1] == 0 && s.refs[2] == 1 && reads == 1567,
          "the scan of the unit's regime: %u valid, refs %d/%d/%d, %u loads", s.valid, s.refs[0], s.refs[1], s.refs[2], reads);

    /* Each table in turn is no RAM of the map when the scan comes to it: no table is skipped, the scan refuses there with nothing loaded from it. */
    static const unsigned before[] = {511, 511 + 32, 511 + 32 + 512};
    for (unsigned level = 0; level < 4; level++) {
        uint64_t page = TABLES[level];
        clear();
        unit_path();
        put(ROOT + 8u * 5u, TABLE_DESC(TABLE3));
        CHECK(walk_va(TCR_UNIT, PAGE_VA, &w) == WALK_PAGE, "the path of the scan, level %u", level);
        reads = 0;
        if (level == 2) map_set(2, 0, page, 1, MMIO_ATTR); else map_hole(page);
        CHECK(scan_tables(&env, &regs, &w, w.at[3], &s) == LOAD_NOT_RAM && s.level == (level == 3 ? 3u : level) && s.at == page && s.bad.page == page &&
              s.bad.type == (level == 2 ? 0 : -1) && s.bad.attr == (level == 2 ? MMIO_ATTR : 0) && !s.bad.ok && reads == (level == 3 ? 0u : before[level]),
              "level %u: refused at %llx in level %u after %u loads, type %d", level, (unsigned long long)s.at, s.level, reads, s.bad.type);
    }
    clear();
    unit_path();
    CHECK(walk_va(TCR_UNIT, PAGE_VA, &w) == WALK_PAGE, "the path of the scan, for an abort");
    reads = 0;
    fault_at = TABLE2 + 8u * 100u;
    CHECK(scan_tables(&env, &regs, &w, w.at[3], &s) == LOAD_ABORT && s.level == 2 && s.at == fault_at && reads == 511 + 32 + 512 + 101,
          "an abort in the level-2 table: level %u, %u loads", s.level, reads);

    /* A regime that starts at level 1 has no level-0 table: that, and only that, is not scanned (REFS -), the rest in full. */
    clear();
    put(ROOT, TABLE_DESC(TABLE2));
    put(TABLE2, TABLE_DESC(TABLE3));
    put(TABLE3 + 8u * 9u, UINT64_C(0x15400000) | 3u);
    regs = regs_of(UINT64_C(28) | (UINT64_C(4) << 16));
    CHECK(walk(&env, &regs, PAGE_VA, &w) == WALK_PAGE && w.base[1] == ROOT && w.base[2] == TABLE2, "the walk of a regime that starts at level 1");
    reads = 0;
    CHECK(scan_tables(&env, &regs, &w, w.at[3], &s) == LOAD_OK && s.refs[0] == -1 && s.refs[1] == 0 && s.refs[2] == 1 && reads == 511 + 64 + 512,
          "the scan of a regime that starts at level 1: refs %d/%d/%d, %u loads", s.refs[0], s.refs[1], s.refs[2], reads);
}

int main(void)
{
    start_levels();
    leaf_forms();
    indexes_and_limits();
    tables_are_proven_ram();
    load_ram_asks_about_pages();
    scan_asks_about_every_page();
    if (failures) {
        printf("FAILED: %u of %u checks\n", failures, checks);
        return 1;
    }
    printf("PASS: smmumap walk, %u checks\n", checks);
    return 0;
}
