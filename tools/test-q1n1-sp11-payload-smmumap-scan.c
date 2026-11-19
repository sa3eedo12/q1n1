/* SPDX-License-Identifier: MIT */
/* The second file of the host test for the runner's mapping step (platform/uefi/sp11-smmumap.c, docs/SP11-PAYLOAD-SMMUMAP.md): the suites about
 * the memory map and the evidence the step reads and prints, linked into the one program of tools/test-q1n1-sp11-payload-smmumap.c (whose main
 * runs them through smmumap_scan_suites) against the same modelled machine (tools/test-q1n1-sp11-payload-smmumap-world.h). Driven by
 * tools/test-q1n1-sp11-payload-smmumap.py under ASan and UBSan.
 *
 * Suites: map (the pure lookup: which descriptor holds a range, what decides when they disagree, its attribute word, malformed descriptors, the
 * maps it will not read), ram (every table page the step loads from, in either walk, is proven RAM by the map BEFORE the load: each level
 * refused in turn with the loads made so far, every EFI type, extent edges, an MMIO overlap, a map that cannot be read, the line with its
 * level and attribute word and the field that does not fit), scan (what is read and printed about the other 511 slots of the level-3 table and
 * about the tables of the path, and the two pointers that refuse: from the root and from the level-1 table), serror (the one line after the
 * chain: only for a mapped page, once, with what the poll found and what was pending before any payload ran).
 *
 * What it cannot show: what the unit's tables hold, whether the unit's memory map is as the model's, or what a read of the SMMU's page does.
 * Evidence: EXPERIMENTAL (host model only); hardware NOT RUN. */
#include "test-q1n1-sp11-payload-smmumap-world.h"

static int type_of(const struct world *w, uint64_t pa, uint64_t bytes)
{
    return q1n1_smmumap_map_type(w->mapbuf, w->map_size, w->map_stride, pa, bytes, NULL);
}

static uint64_t attr_of(const struct world *w, uint64_t pa, uint64_t bytes)
{
    uint64_t attr = ~UINT64_C(0);
    q1n1_smmumap_map_type(w->mapbuf, w->map_size, w->map_stride, pa, bytes, &attr);
    return attr;
}

/* The pure lookup in the memory map: which descriptor holds a range, what decides when descriptors disagree, its attribute word, and every map it will not read. */
static void suite_map(void)
{
    static uint8_t big[1025 * MAP_STRIDE];
    struct world w;
    int type;
    for (type = -2; type <= 17; type++)
        CHECK(q1n1_smmumap_ram_type(type) == ((type >= 1 && type <= 7) || type == 9), "EFI type %d is judged %d", type, q1n1_smmumap_ram_type(type));
    world_good(&w);
    CHECK(type_of(&w, T_L3A, 4096) == 4 && type_of(&w, UINT64_C(0xA7F19000), 4096) == 4 && type_of(&w, UINT64_C(0xA7FFF000), 4096) == 4,
          "a page inside the boot services extent, at its start and at its last page");
    CHECK(type_of(&w, UINT64_C(0xA7F18000), 4096) == 7 && type_of(&w, UINT64_C(0xA8000000), 4096) == 7, "the neighbours of that extent are conventional memory");
    CHECK(type_of(&w, UINT64_C(0xB0000000), 4096) == -1, "a page that no descriptor holds");
    CHECK(type_of(&w, PAGE, 4096) == 11 && type_of(&w, TEMPLATE, 4096) == 11 && type_of(&w, 0, 4096) == 0, "MMIO and reserved descriptors decide for their pages");
    CHECK(type_of(&w, UINT64_C(0xA7FFF000), 0x2000) == -1, "a range that spans two RAM extents is held by neither");
    CHECK(type_of(&w, T_L3A, 0) == -2 && type_of(&w, ~UINT64_C(0xfff), 0x2000) == -2, "an empty range or one that wraps is not a question");
    /* The attribute word is the deciding descriptor's own (offset 32), and 0 when none decided. */
    CHECK(attr_of(&w, T_L3A, 4096) == 0xf && attr_of(&w, PAGE, 4096) == UINT64_C(0x8000000000000001) && attr_of(&w, UINT64_C(0xB0000000), 4096) == 0 && attr_of(&w, T_L3A, 0) == 0,
          "the attribute word of the descriptor that decided: %llx %llx", LL(attr_of(&w, T_L3A, 4096)), LL(attr_of(&w, PAGE, 4096)));
    /* Descriptors that disagree: a non-RAM one that overlaps decides, even if a RAM one holds the whole page; of two that hold it, the later. */
    add_extent(&w, UINT64_C(0xA7F21000), 1u, 8u);
    add_extent(&w, UINT64_C(0xA7F20000), 0x20u, 7u);
    w.ext[w.extents - 2].attr = UINT64_C(0x1234);
    w.ext[w.extents - 1].attr = UINT64_C(0x5678);
    build_map(&w);
    CHECK(type_of(&w, UINT64_C(0xA7F21000), 4096) == 8, "an unusable descriptor over the page decides: %d", type_of(&w, UINT64_C(0xA7F21000), 4096));
    CHECK(attr_of(&w, UINT64_C(0xA7F21000), 4096) == 0x1234, "the attribute word of the unusable descriptor that decided");
    CHECK(type_of(&w, UINT64_C(0xA7F22000), 4096) == 7, "of two RAM descriptors that hold the page the later is answered: %d", type_of(&w, UINT64_C(0xA7F22000), 4096));
    CHECK(attr_of(&w, UINT64_C(0xA7F22000), 4096) == 0x5678, "the attribute word of the later of two RAM descriptors");
    CHECK(type_of(&w, UINT64_C(0xA7F20000), 4096) == 7, "a page that an unusable descriptor does not touch is still RAM");
    /* Malformed descriptors are skipped, as the payloads skip them: they cannot take a page away. */
    world_good(&w);
    add_extent(&w, T_L3A + 1u, 1u, 11u);            /* an unaligned start */
    add_extent(&w, T_L3A, 0u, 11u);                 /* no pages */
    add_extent(&w, UINT64_C(1) << 48, 1u, 11u);     /* beyond the address limit */
    add_extent(&w, T_L3A, UINT64_C(1) << 50, 11u);  /* a size that overflows */
    build_map(&w);
    CHECK(type_of(&w, T_L3A, 4096) == 4, "a malformed descriptor took the page: %d", type_of(&w, T_L3A, 4096));
    /* A type that no EFI type is (above 0xFFFF) is answered as 0xFFFF and is not RAM: never -1 or -2, which mean other things. */
    world_good(&w);
    w.ext[4].type = 0xFFFFFFFFu;
    build_map(&w);
    CHECK(type_of(&w, T_L3A, 4096) == 0xFFFF && !q1n1_smmumap_ram_type(type_of(&w, T_L3A, 4096)), "a type of 0xFFFFFFFF is answered %d", type_of(&w, T_L3A, 4096));
    w.ext[4].type = 0x10000u;
    build_map(&w);
    CHECK(type_of(&w, T_L3A, 4096) == 0xFFFF, "a type of 0x10000 is answered %d", type_of(&w, T_L3A, 4096));
    w.ext[4].type = 0xFFFFu;
    build_map(&w);
    CHECK(type_of(&w, T_L3A, 4096) == 0xFFFF, "a type of 0xFFFF is answered as it is");
    /* A map it will not read. */
    CHECK(q1n1_smmumap_map_type(NULL, w.map_size, MAP_STRIDE, T_L3A, 4096, NULL) == -2, "no map");
    CHECK(q1n1_smmumap_map_type(w.mapbuf, w.map_size, 32, T_L3A, 4096, NULL) == -2, "a stride below 40");
    CHECK(q1n1_smmumap_map_type(w.mapbuf, w.map_size, 44, T_L3A, 4096, NULL) == -2, "a stride that is not a multiple of 8");
    CHECK(q1n1_smmumap_map_type(w.mapbuf, 0, MAP_STRIDE, T_L3A, 4096, NULL) == -2, "a map of no bytes");
    CHECK(q1n1_smmumap_map_type(w.mapbuf, 100, MAP_STRIDE, T_L3A, 4096, NULL) == -2, "a size that is not whole descriptors");
    {
        static const uint8_t one40[40];                   /* one descriptor of the least stride that is read: all zero, so malformed and skipped */
        uint64_t attr = 7;
        CHECK(q1n1_smmumap_map_type(one40, 40, 40, T_L3A, 4096, &attr) == -1 && attr == 0, "a stride of 40 is the least that is read");
    }
    CHECK(q1n1_smmumap_map_type(big, 1024u * MAP_STRIDE, MAP_STRIDE, T_L3A, 4096, NULL) == -1, "1024 descriptors are read");
    CHECK(q1n1_smmumap_map_type(big, 1025u * MAP_STRIDE, MAP_STRIDE, T_L3A, 4096, NULL) == -2, "1025 descriptors are too many");
}

/* Every table page the step loads from is proven RAM by the memory map BEFORE the load, in the walk to the page and in the walk to the template,
 * at each level: each refused in turn with the loads made so far counted, every EFI type, the edges of an extent, a descriptor over a page
 * alone, a map that cannot be read, the attribute word and the level on the line, and a field that does not fit the line. */
static void suite_ram(void)
{
    static const struct { uint64_t page; unsigned level; const char *what; } pages[] = {
        {T_L0, 0, "the root"}, {T_L1, 1, "the level-1 table"}, {T_L2A, 2, "the level-2 table"}, {T_L3A, 3, "the level-3 table before its slot"},
    };
    unsigned type, i;
    char want[160];
    for (i = 0; i < 4; i++) {
        NEWWORLD(w);
        add_extent(&w, pages[i].page, 1u, 11u);             /* MMIO over this one page, inside the RAM extent */
        build_map(&w);
        GO(w, REFUSED, R(TABLE_NOT_RAM), 0, pages[i].what);
        snprintf(want, sizeof want, "PAYLOAD SMMUMAP REFUSED=TABLE_NOT_RAM TABLE=0X%llX TYPE=0XB LEVEL=0X%u ATTR=0X8000000000000001", LL(pages[i].page), pages[i].level);
        CHECK(!strcmp(find_line(&w, "PAYLOAD SMMUMAP REFUSED"), want), "%s: the line is '%s'", pages[i].what, find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
        /* The loads made are those of the levels above, none from the page that is not RAM, and no AT and no store came first. */
        CHECK(w.reads == pages[i].level && !strchr(w.seq, 'A') && !strchr(w.seq, 'S'), "%s: %u loads before the refusal, effects %s", pages[i].what, w.reads, w.seq);
    }
    for (type = 0; type < 16; type++) {
        NEWWORLD(w);
        w.ext[4].type = type;
        build_map(&w);
        if ((type >= 1 && type <= 7) || type == 9) {
            GO(w, MAPPED, R(NONE), 1, "the tables are in RAM of that EFI type");
        } else {
            GO(w, REFUSED, R(TABLE_NOT_RAM), 0, "the tables are in memory that is not RAM");
            snprintf(want, sizeof want, "PAYLOAD SMMUMAP REFUSED=TABLE_NOT_RAM TABLE=0XA7F2E000 TYPE=0X%X LEVEL=0X0 ATTR=0XF", type);     /* the extent's own attribute word */
            CHECK(!strcmp(find_line(&w, "PAYLOAD SMMUMAP REFUSED"), want), "type %u: the line is '%s'", type, find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
            CHECK(w.reads == 0 && !strchr(w.seq, 'A'), "type %u: a load or an AT was made before the root was proven: %s", type, w.seq);
        }
        CHECK(model_ram(&w, T_L3A) == (w.applied == 1), "type %u: the model's own answer differs", type);
    }
    {
        NEWWORLD(w);
        add_extent(&w, T_L2B, 1u, 11u);                     /* the template's own level-2 table: refused by the walk to the template */
        build_map(&w);
        GO(w, REFUSED, R(TABLE_NOT_RAM), 0, "the template's level-2 table is not RAM");
        CHECK(!strcmp(find_line(&w, "PAYLOAD SMMUMAP REFUSED"), "PAYLOAD SMMUMAP REFUSED=TABLE_NOT_RAM TABLE=0XA7F32000 TYPE=0XB LEVEL=0X2 ATTR=0X8000000000000001"),
              "the line is '%s'", find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
        CHECK(w.reads == 6 && !has_line(&w, "PAYLOAD SMMUMAP TEMPLATE"), "the walk to the page (4) and two of the template (the root, the level-1 table): %u", w.reads);
    }
    {
        NEWWORLD(w);
        w.ext[4].pages = 24;                                /* the extent ends where the level-3 page begins */
        build_map(&w);
        GO(w, REFUSED, R(TABLE_NOT_RAM), 0, "no descriptor holds the level-3 table's page");
        CHECK(!strcmp(find_line(&w, "PAYLOAD SMMUMAP REFUSED"), "PAYLOAD SMMUMAP REFUSED=TABLE_NOT_RAM TABLE=0XA7F31000 TYPE=0XFF LEVEL=0X3"),
              "a page that is in no descriptor has no attribute word: '%s'", find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
        CHECK(w.reads == 3, "three loads, none from the level-3 table: %u", w.reads);
    }
    {
        NEWWORLD(w);
        w.ext[4].pages = 25;                                /* the extent ends where the template's level-2 table begins */
        build_map(&w);
        GO(w, REFUSED, R(TABLE_NOT_RAM), 0, "no descriptor holds the template's table");
        CHECK(!strcmp(find_line(&w, "PAYLOAD SMMUMAP REFUSED"), "PAYLOAD SMMUMAP REFUSED=TABLE_NOT_RAM TABLE=0XA7F32000 TYPE=0XFF LEVEL=0X2"),
              "the line is '%s'", find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
    }
    {
        NEWWORLD(w);
        w.ext[4].pages = 26;                                /* the template's level-2 table is the last page of the extent */
        build_map(&w);
        GO(w, MAPPED, R(NONE), 1, "the last table is the last page of its extent");
    }
    {
        NEWWORLD(w);
        add_extent(&w, T_L3A + 1u, 1u, 11u);                /* malformed: it cannot take the page away */
        build_map(&w);
        GO(w, MAPPED, R(NONE), 1, "a malformed descriptor over the page");
    }
    {
        NEWWORLD(w);
        w.ext[4].type = 0xFFFFFFFEu;                        /* no EFI type: answered as 0xFFFF, not as the -2 of a map that cannot be read */
        build_map(&w);
        GO(w, REFUSED, R(TABLE_NOT_RAM), 0, "a type that no EFI type is");
        CHECK(!strcmp(find_line(&w, "PAYLOAD SMMUMAP REFUSED"), "PAYLOAD SMMUMAP REFUSED=TABLE_NOT_RAM TABLE=0XA7F2E000 TYPE=0XFFFF LEVEL=0X0 ATTR=0XF"),
              "the line is '%s'", find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
    }
    {
        NEWWORLD(w);
        w.map_mode = MAP_NULL;
        GO(w, REFUSED, R(TABLE_NOT_RAM), 0, "no map");
        CHECK(!strcmp(find_line(&w, "PAYLOAD SMMUMAP REFUSED"), "PAYLOAD SMMUMAP REFUSED=TABLE_NOT_RAM TABLE=0XA7F2E000 TYPE=0XFE LEVEL=0X0"),
              "a map that cannot be read: '%s'", find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
        CHECK(w.reads == 0, "a load was made without a map");
    }
    {
        NEWWORLD(w);
        w.map_mode = MAP_STRIDE_SHORT;
        build_map(&w);
        GO(w, REFUSED, R(TABLE_NOT_RAM), 0, "a map with a short stride");
        CHECK(!strcmp(find_line(&w, "PAYLOAD SMMUMAP REFUSED"), "PAYLOAD SMMUMAP REFUSED=TABLE_NOT_RAM TABLE=0XA7F2E000 TYPE=0XFE LEVEL=0X0") && w.reads == 0,
              "a map that cannot be read: '%s'", find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
    }
    {
        /* A 48-bit physical space and a level-2 table at the top of it: the attribute word is the line's longest and last field and is left out whole
         * when it does not fit the 100 columns (never cut), and printed when it does, even to the hundredth column. */
        static const struct { uint64_t attr; const char *field; } cases[] = {
            {UINT64_C(0x8000000000000001), ""},                          /* 101 columns with the field */
            {UINT64_C(0x800000000000001), " ATTR=0X800000000000001"},    /* exactly 100 */
            {0xf, " ATTR=0XF"},
        };
        for (i = 0; i < 3; i++) {
            NEWWORLD(w);
            w.regs.tcr = (w.regs.tcr & ~(UINT64_C(7) << 16)) | (UINT64_C(5) << 16);
            W(w, L1E0) = UINT64_C(0xFFFFFFFFF000) | 3u;
            add_extent(&w, UINT64_C(0xFFFFFFFFF000), 1u, 11u);
            w.ext[w.extents - 1].attr = cases[i].attr;
            build_map(&w);
            GO(w, REFUSED, R(TABLE_NOT_RAM), 0, "a table at the top of a 48-bit space");
            snprintf(want, sizeof want, "PAYLOAD SMMUMAP REFUSED=TABLE_NOT_RAM TABLE=0XFFFFFFFFF000 TYPE=0XB LEVEL=0X2%s", cases[i].field);
            CHECK(!strcmp(find_line(&w, "PAYLOAD SMMUMAP REFUSED"), want), "attribute %u: the line is '%s'", i, find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
            CHECK(i != 1 || strlen(find_line(&w, "PAYLOAD SMMUMAP REFUSED")) == 100, "the line that fits to the last column is %zu columns", strlen(find_line(&w, "PAYLOAD SMMUMAP REFUSED")));
        }
    }
    {
        /* A proof is made at each load, not once for the run: with a map that changes under the step (which the real one cannot do) the scan's first
         * load in each table and the slot read once more before the store are refused when the map no longer calls their page RAM. */
        /* Loads made before the scan: the walk to the page (4) and the walk to the template (3: its leaf is a level-2 block). */
        static const struct { const char *line; uint64_t page; unsigned level, reads; const char *what; } later[] = {
            {"PAYLOAD SMMUMAP TEMPLATE", T_L3A, 3, 7, "the level-3 table, at the scan"},
            {"PAYLOAD SMMUMAP TEMPLATE", T_L0, 0, 7 + 511, "the root, at the scan"},
            {"PAYLOAD SMMUMAP TEMPLATE", T_L1, 1, 7 + 511 + 32, "the level-1 table, at the scan"},
            {"PAYLOAD SMMUMAP TEMPLATE", T_L2A, 2, 7 + 511 + 32 + 512, "the level-2 table, at the scan"},
            {"PAYLOAD SMMUMAP NEXT STORE AFTER", T_L3A, 3, 7 + 1567, "the slot, read once more before the store"},
        };
        for (i = 0; i < 5; i++) {
            NEWWORLD(w);
            w.poke_map_line = later[i].line;
            w.poke_map_start = later[i].page;
            w.poke_map_type = 11u;
            GO(w, REFUSED, R(TABLE_NOT_RAM), 0, later[i].what);
            snprintf(want, sizeof want, "PAYLOAD SMMUMAP REFUSED=TABLE_NOT_RAM TABLE=0X%llX TYPE=0XB LEVEL=0X%u ATTR=0X8000000000000001", LL(later[i].page), later[i].level);
            CHECK(!strcmp(find_line(&w, "PAYLOAD SMMUMAP REFUSED"), want), "%s: the line is '%s'", later[i].what, find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
            CHECK(w.reads == later[i].reads && !strchr(w.seq, 'S'), "%s: %u loads (wanted %u), effects %s", later[i].what, w.reads, later[i].reads, w.seq);
        }
    }
}

/* What the step reads and prints about the level-3 table and the tables of the path, and what it refuses because of them. */
static void suite_scan(void)
{
    unsigned i;
    {
        NEWWORLD(w);
        W(w, SLOT0 + 8) = 0;
        W(w, SLOT0 + 8 * 511u) = 0;
        GO(w, MAPPED, R(NONE), 1, "no valid neighbour");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP TABLE VALID=0 REFS=0/0/1"), "%s", find_line(&w, "PAYLOAD SMMUMAP TABLE"));
    }
    {
        NEWWORLD(w);
        for (i = 1; i < 512; i++) W(w, SLOT0 + 8 * i) = UINT64_C(0x0040000015400643) + UINT64_C(0x1000) * i;
        GO(w, MAPPED, R(NONE), 1, "every neighbour valid");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP TABLE VALID=511 REFS=0/0/1"), "%s", find_line(&w, "PAYLOAD SMMUMAP TABLE"));
    }
    {
        NEWWORLD(w);
        W(w, SLOT0 + 8) = 2;                                /* bit 0 clear: not valid, whatever else is set */
        W(w, SLOT0 + 16) = 2;
        W(w, SLOT0 + 24) = 1;                               /* bit 0 set: valid */
        W(w, SLOT0 + 8 * 511u) = 0;
        GO(w, MAPPED, R(NONE), 1, "valid means bit 0");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP TABLE VALID=1 REFS=0/0/1"), "%s", find_line(&w, "PAYLOAD SMMUMAP TABLE"));
    }
    {
        NEWWORLD(w);
        W(w, T_L2A + 8 * 5u) = T_L3A | 3u;                  /* a second entry of the level-2 table points at the table: the same page at another address */
        GO(w, MAPPED, R(NONE), 1, "an alias in the level-2 table is evidence, not a refusal");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP TABLE VALID=2 REFS=0/0/2"), "%s", find_line(&w, "PAYLOAD SMMUMAP TABLE"));
    }
    {
        NEWWORLD(w);
        W(w, T_L2A + 8 * 5u) = T_L3A | 1u;                  /* a block descriptor is not a table descriptor */
        GO(w, MAPPED, R(NONE), 1, "a block form is no reference");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP TABLE VALID=2 REFS=0/0/1"), "%s", find_line(&w, "PAYLOAD SMMUMAP TABLE"));
    }
    {
        NEWWORLD(w);
        W(w, T_L1 + 8 * 7u) = T_L3A | 3u;                   /* the page would be a level-2 table for another 1 GiB */
        GO(w, REFUSED, R(TABLE_SHARED), 0, "an entry of the level-1 table points at the level-3 table");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP TABLE VALID=2 REFS=0/1/1") && has_line(&w, "PAYLOAD SMMUMAP REFUSED=TABLE_SHARED TABLE=0XA7F31000 LEVEL=0X1"),
              "%s", find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
    }
    {
        NEWWORLD(w);
        W(w, T_L0 + 8 * 3u) = T_L3A | 3u;                   /* the page would be a level-1 table for another 512 GiB */
        GO(w, REFUSED, R(TABLE_SHARED), 0, "an entry of the root points at the level-3 table");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP TABLE VALID=2 REFS=1/0/1") && has_line(&w, "PAYLOAD SMMUMAP REFUSED=TABLE_SHARED TABLE=0XA7F31000 LEVEL=0X0"),
              "%s", find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
    }
    {
        NEWWORLD(w);
        W(w, T_L0 + 8 * 3u) = T_L3A | 3u;
        W(w, T_L1 + 8 * 7u) = T_L3A | 3u;
        GO(w, REFUSED, R(TABLE_SHARED), 0, "both");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP REFUSED=TABLE_SHARED TABLE=0XA7F31000 LEVEL=0X0"), "the root is named first");
    }
    {
        NEWWORLD(w);
        W(w, T_L0 + 8 * 40u) = T_L3A | 3u;                  /* the root of a 44-bit VA has 32 entries: what lies beyond them is not a table entry */
        GO(w, MAPPED, R(NONE), 1, "an entry beyond the 32 of the root");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP TABLE VALID=2 REFS=0/0/1"), "%s", find_line(&w, "PAYLOAD SMMUMAP TABLE"));
    }
    {
        static const struct { uint64_t at; const char *line; } faults[] = {
            {SLOT0 + 16u, "PAYLOAD SMMUMAP REFUSED=SCAN_FAULT AT=0XA7F31010 LEVEL=0X3"},
            {T_L0 + 8u, "PAYLOAD SMMUMAP REFUSED=SCAN_FAULT AT=0XA7F2E008 LEVEL=0X0"},
            {T_L1 + 16u, "PAYLOAD SMMUMAP REFUSED=SCAN_FAULT AT=0XA7F2F010 LEVEL=0X1"},
            {T_L2A + 8u, "PAYLOAD SMMUMAP REFUSED=SCAN_FAULT AT=0XA7F30008 LEVEL=0X2"},
        };
        for (i = 0; i < sizeof faults / sizeof faults[0]; i++) {
            NEWWORLD(w);
            w.read_fault[w.read_faults++] = faults[i].at;
            GO(w, REFUSED, R(SCAN_FAULT), 0, "a read of the scan aborts");
            CHECK(has_line(&w, faults[i].line) && !has_line(&w, "PAYLOAD SMMUMAP TABLE VALID"), "scan fault %u: %s", i, find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
        }
    }
    {
        /* No table of the path is ever skipped: one whose page is not RAM is refused by the walk (suite ram), and a regime that starts at a later level has
         * no table at the levels above its start, printed as `-` (suite regs). Here every level of the unit's regime is read and counted. */
        NEWWORLD(w);
        W(w, T_L0 + 8 * 9u) = T_L3A | 3u;                   /* the root's ninth entry points at the table too: a pointer the root's scan finds */
        GO(w, REFUSED, R(TABLE_SHARED), 0, "a pointer in the root, in a world whose every path table is RAM");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP TABLE VALID=2 REFS=1/0/1"), "%s", find_line(&w, "PAYLOAD SMMUMAP TABLE"));
        CHECK(w.reads == 1574u, "all four levels were read in full, and the slot not again: %u loads", w.reads);
    }
}

/* The line after the chain: only for a page that was mapped, once, with what the poll found and what was pending before any payload ran. */
static void suite_serror(void)
{
    struct q1n1_smmumap_env env;
    struct q1n1_smmumap_result r;
    unsigned before;
    {
        NEWWORLD(w);
        w.poll_found = 1;
        w.poll_syndrome = UINT64_C(0xBF000002);
        CHECK(run_world(&w, &r) == MAPPED && r.serror_before == 0, "the page is mapped, nothing was pending");
        before = w.nlines;
        make_env(&w, &env);
        q1n1_smmumap_after_chain(&env, &r);
        CHECK(w.polls == 1 && w.nlines == before + 1 && !strcmp(w.lines[before], "PAYLOAD SMMUMAP SERROR=FOUND SYNDROME=0XBF000002 PENDING=0 BEFORE=0"),
              "found: %u polls, '%s'", w.polls, w.nlines > before ? w.lines[before] : "");
    }
    {
        NEWWORLD(w);
        CHECK(run_world(&w, &r) == MAPPED, "mapped");
        before = w.nlines;
        make_env(&w, &env);
        q1n1_smmumap_after_chain(&env, &r);
        CHECK(w.polls == 1 && w.nlines == before + 1 && !strcmp(w.lines[before], "PAYLOAD SMMUMAP SERROR=NONE PENDING=0 BEFORE=0"),
              "none: '%s'", w.nlines > before ? w.lines[before] : "");
    }
    {
        NEWWORLD(w);
        w.poll_found = 1;
        w.poll_still = 1;
        w.poll_syndrome = ~UINT64_C(0);
        w.isr_pending = 1;                                  /* an SError was already pending when the step ended */
        CHECK(run_world(&w, &r) == MAPPED && r.serror_before == 1, "pending before: %d", r.serror_before);
        before = w.nlines;
        make_env(&w, &env);
        q1n1_smmumap_after_chain(&env, &r);
        CHECK(w.nlines == before + 1 && !strcmp(w.lines[before], "PAYLOAD SMMUMAP SERROR=FOUND SYNDROME=0XFFFFFFFFFFFFFFFF PENDING=1 BEFORE=1") &&
              strlen(w.lines[before]) <= 100, "pending: '%s'", w.nlines > before ? w.lines[before] : "");
    }
    {
        NEWWORLD(w);
        w.poll_found = 1;
        w.poll_still = 0;
        w.poll_syndrome = UINT64_C(0x1234);
        w.isr_pending = 1;                                  /* pending before any payload ran, and not pending after the poll: the two are told apart */
        CHECK(run_world(&w, &r) == MAPPED && r.serror_before == 1, "pending before, not after: %d", r.serror_before);
        before = w.nlines;
        make_env(&w, &env);
        q1n1_smmumap_after_chain(&env, &r);
        CHECK(w.nlines == before + 1 && !strcmp(w.lines[before], "PAYLOAD SMMUMAP SERROR=FOUND SYNDROME=0X1234 PENDING=0 BEFORE=1"), "before only: '%s'",
              w.nlines > before ? w.lines[before] : "");
    }
    {
        NEWWORLD(w);
        w.poll_found = 1;
        w.poll_still = 1;
        w.poll_syndrome = UINT64_C(0x1234);
        CHECK(run_world(&w, &r) == MAPPED && r.serror_before == 0, "nothing pending before");
        before = w.nlines;
        make_env(&w, &env);
        q1n1_smmumap_after_chain(&env, &r);
        CHECK(w.nlines == before + 1 && !strcmp(w.lines[before], "PAYLOAD SMMUMAP SERROR=FOUND SYNDROME=0X1234 PENDING=1 BEFORE=0"), "pending after only: '%s'",
              w.nlines > before ? w.lines[before] : "");
    }
    {
        NEWWORLD(w);
        w.regs.ttbr0 += 0x1000;                             /* refused: no page was mapped, so nothing is polled */
        CHECK(run_world(&w, &r) == REFUSED && r.serror_before == 0, "refused");
        before = w.nlines;
        make_env(&w, &env);
        q1n1_smmumap_after_chain(&env, &r);
        CHECK(w.polls == 0 && w.nlines == before, "a refused page is polled for an SError");
        q1n1_smmumap_after_chain(&env, NULL);
        CHECK(w.polls == 0 && w.nlines == before, "no result is polled for an SError");
    }
    {
        NEWWORLD(w);
        force_at(&w, PAGE, 0, 2, UINT64_C(0x15401B00));     /* the page is mapped, the check fails, and the put-back cannot be proven: UNSAFE */
        force_at(&w, PAGE, 0, 3, UINT64_C(0x15400B00));
        CHECK(run_world(&w, &r) == Q1N1_SMMUMAP_UNSAFE, "unsafe");
        before = w.nlines;
        make_env(&w, &env);
        q1n1_smmumap_after_chain(&env, &r);
        CHECK(w.polls == 0 && w.nlines == before, "an unsafe page is polled for an SError");
    }
    {
        NEWWORLD(w);
        w.no_poll = 1;
        CHECK(run_world(&w, &r) == MAPPED, "mapped, and the runner has no poll");
        before = w.nlines;
        make_env(&w, &env);
        q1n1_smmumap_after_chain(&env, &r);
        CHECK(w.polls == 0 && w.nlines == before, "a line was printed with no poll to ask");
    }
}

static const struct { const char *name; void (*run)(void); } suites[] = {{"map", suite_map}, {"ram", suite_ram}, {"scan", suite_scan}, {"serror", suite_serror}};

unsigned smmumap_scan_suites(const char *want, unsigned *checks, unsigned *fails, unsigned *lines_max)
{
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (strcmp(want, "all") && strcmp(want, "lines-report") && strcmp(want, suites[i].name)) continue;
        g_suite = suites[i].name;
        suites[i].run();
        ran++;
    }
    *checks = g_checks;
    *fails = g_fail;
    *lines_max = g_lines_max;
    return ran;
}
