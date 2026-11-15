/* SPDX-License-Identifier: MIT */
/* Host test for the el2mem payload (payloads/el2mem.c), built natively with Q1N1_PAYLOAD_HOST_TEST so that its register reads, its AT
 * S1E2R and its guarded loads come from the modelled machine of tools/test-q1n1-sp11-payload-mmu-world.h. Driven by
 * tools/test-q1n1-sp11-payload-el2mem.py under ASan and UBSan.
 *
 * Suites: unit (a map shaped like boot 6's: the exact page, the probes against an independent oracle, the four loads, the order and the
 * eight seconds of the reads that may trap), scan (extents, merging, unsorted and unusable descriptors, a straddle of 4 GiB, more
 * extents than it scans), faulty (a hole in the bank, a bank not mapped, a Device mapping, a non-identity mapping, an attribute that is
 * none of the named ones, a faulting load, no conventional memory), map (every refusal, and never one byte read outside the map: the
 * map sits against PROT_NONE pages), counter (a counter that stands still, goes back, is missing, an absurd CNTFRQ_EL0), el and args,
 * budget (the 26 lines and the lines that may not be dropped), fuzz (random worlds against the invariants).
 *
 * What it cannot show: what the unit's firmware maps, what an EL3 does with the reads that may trap, or what the binary does: the Python
 * driver disassembles the built binary for that. Evidence: EXPERIMENTAL (host model only); hardware NOT RUN. */
#include "test-q1n1-sp11-payload-mmu-world.h"

#define FREQ 19200000u
#define BANK_BASE_ UINT64_C(0x880000000)
#define BANK_END_ UINT64_C(0x1000000000)

struct d {
    uint32_t type;
    uint64_t start, pages;
};

/* A synthetic map in the shape of the one boot 6 showed (OBSERVED shape: seven low conventional extents of 590, 339, 283, 98, 21, 19 and 11 MiB and
 * the 30 GiB bank); the addresses of everything but the bank are made up. */
static const struct d unit_descs[] = {
    {7, 0x80000000, 590 * 256}, {4, 0xa4e00000, 4 * 256}, {7, 0xa5200000, 339 * 256}, {3, 0xba500000, 2 * 256},
    {7, 0xba700000, 283 * 256}, {1, 0xcc200000, 1 * 256}, {2, 0xcc300000, 3 * 256}, {7, 0xcc600000, 98 * 256},
    {6, 0xd2800000, 8 * 256}, {7, 0xd3000000, 21 * 256}, {5, 0xd4500000, 4 * 256}, {7, 0xd4900000, 19 * 256},
    {9, 0xd5c00000, 3 * 256}, {7, 0xd5f00000, 11 * 256}, {0, 0xff800000, 8 * 256}, {7, 0x880000000, 30720 * 256},
};
#define UNIT_COUNT (sizeof unit_descs / sizeof unit_descs[0])

static struct world_map build_map(const struct d *list, unsigned count, uint64_t stride)
{
    struct world_map m = map_new(stride, count);
    for (unsigned i = 0; i < count; i++) map_put(&m, i, list[i].type, list[i].start, list[i].pages, 0xf);
    return m;
}

static void set_registers(uint64_t el)
{
    reg_reset();
    reg_set("CurrentEL", el << 2);
    reg_set("CNTFRQ_EL0", FREQ);
    reg_set("id_aa64mmfr1_el1", 0x311122);
    reg_set("S3_0_C0_C5_1", 0x0);
    reg_set("S3_0_C0_C6_2", 0x21);
    reg_set("S3_0_C0_C4_2", 0x0);
    reg_set("aidr_el1", 0);
    reg_set("revidr_el1", 0);
    reg_set("mdcr_el2", 0);
    reg_set("mdscr_el1", 0);
    reg_set("oslsr_el1", 8);
    reg_set("icc_sre_el2", 9);
}

/* Identity write-back inner-shareable for every descriptor of the list that is memory (not type 0). */
static void map_identity(const struct d *list, unsigned count)
{
    for (unsigned i = 0; i < count; i++)
        if (list[i].type) tr_map(list[i].start, list[i].start + list[i].pages * PAGE_, ATTR_WB, SH_INNER);
}

static uint64_t go(struct q1n1_payload_args *a)
{
    page_clear();
    read_count = 0;
    load_count = load_budget_calls = 0;
    load_unmapped_calls = 0;
    at_count = 0;
    return payload_entry(a);
}

/* ---- The oracle: the probes the scan must make, from the descriptor list alone, written another way --------------------------------- */

/* Every address of every merged conventional extent that must be asked about: its first page, its 2 MiB multiples strictly inside, its
 * last page. Merging is done on page boundaries by marking: a list sorted by start, extents grown while the next one starts at or
 * before the end. Returns the count, fills `out` (sorted). */
static unsigned oracle_probes(const struct d *list, unsigned count, uint64_t *out, unsigned cap, unsigned *extents)
{
    struct d sorted[256];
    unsigned n = 0, total = 0;
    for (unsigned i = 0; i < count; i++)
        if (list[i].type == 7 && list[i].pages) sorted[n++] = list[i];
    for (unsigned i = 1; i < n; i++)
        for (unsigned j = i; j > 0 && sorted[j].start < sorted[j - 1].start; j--) {
            struct d t = sorted[j];
            sorted[j] = sorted[j - 1];
            sorted[j - 1] = t;
        }
    *extents = 0;
    for (unsigned i = 0; i < n;) {
        uint64_t start = sorted[i].start, end = start + sorted[i].pages * PAGE_;
        for (i++; i < n && sorted[i].start <= end; i++)
            if (sorted[i].start + sorted[i].pages * PAGE_ > end) end = sorted[i].start + sorted[i].pages * PAGE_;
        (*extents)++;
        if (*extents > 64) continue;                       /* only the first 64 are scanned */
        if (total < cap) out[total++] = start;
        for (uint64_t x = (start & ~(2 * MIB_ - 1)) + 2 * MIB_; x < end - PAGE_; x += 2 * MIB_)
            if (x > start && total < cap) out[total++] = x;
        if (end - PAGE_ > start && total < cap) out[total++] = end - PAGE_;
    }
    return total;
}

/* The unit page, as the model prints it (docs/SP11-PAYLOAD-EL2MEM.md, "What the host model prints"). */
static const char *const unit_page[] = {
    "PAYLOAD EL2MEM START CURRENTEL=0X8 FREQ=19200000",
    "PAYLOAD EL2MEM MAP DESC=16 STRIDE=48 CONV_EXTENTS=8 CONV_MIB=32081",
    "PAYLOAD EL2MEM KEY RESULT=WB.IS PROBES=16051 FIRST=0X80000000 LAST=0XFFFFFF000",
    "PAYLOAD EL2MEM SCAN EXTENTS=8 PROBES=16051 ALL=MAPPED ATTR=WB SH=IS",
    "PAYLOAD EL2MEM BANK CONV_MIB=30720 PROBES=15361 ALL=MAPPED RESULT=WB.IS",
    "PAYLOAD EL2MEM CONTROL T1=WB.IS T2=WB.IS T3=WB.IS T4=WB.IS T5=WB.IS T6=WB.IS CODE=WB.IS STACK=WB.IS",
    "PAYLOAD EL2MEM LOAD BANK_FIRST(0X880000000)=0X25A50008 BANK_LAST(0XFFFFFFFFC)=0X5A5AFFF3",
    "PAYLOAD EL2MEM LOAD LOW_FIRST(0X80000000)=0X25A50000 LOW_LAST(0XA4DFFFFC)=0X17AFFFC",
    "PAYLOAD EL2MEM ID DFR1=0X0 ISAR2=0X21 MMFR1=0X311122 PAN=3 VH=1 HAFDBS=2 PFR2=0X0 AIDR=0X0",
    "PAYLOAD EL2MEM ID REVIDR=0X0 MDCR_EL2=0X0",
    "PAYLOAD EL2MEM NEXT MDSCR_EL1 AFTER 8 S",
    "PAYLOAD EL2MEM MDSCR_EL1 RAW=0X0",
    "PAYLOAD EL2MEM NEXT OSLSR_EL1 AFTER 8 S",
    "PAYLOAD EL2MEM OSLSR_EL1 RAW=0X8 OSLK=0",
    "PAYLOAD EL2MEM NEXT ICC_SRE_EL2 AFTER 8 S",
    "PAYLOAD EL2MEM ICC_SRE_EL2 RAW=0X9 SRE=1 ENABLE=1",
    "PAYLOAD EL2MEM DONE SCAN_ALL_MAPPED LOADS_OK=4 OF=4 HAZARD_READS=3",
};
#define UNIT_PAGE_LINES (sizeof unit_page / sizeof unit_page[0])

/* The documented register reads, in the order the payload makes them. */
static const char *const documented_reads[] = {
    "CurrentEL", "CNTFRQ_EL0", "id_aa64mmfr1_el1", "S3_0_C0_C5_1", "S3_0_C0_C6_2", "S3_0_C0_C4_2", "aidr_el1", "revidr_el1",
    "mdcr_el2", "mdscr_el1", "oslsr_el1", "icc_sre_el2",
};

static int suite_unit(void)
{
    struct q1n1_payload_args a = args_new();
    struct world_map m = build_map(unit_descs, UNIT_COUNT, 48);
    static uint64_t expect[20000];
    unsigned extents, n;
    world_reset();
    set_registers(2);
    map_identity(unit_descs, UNIT_COUNT);
    args_map(&a, &m);
    CHECK_EQ(go(&a), 0);
    CHECK(font_violations == 0 && long_lines == 0);
    CHECK_EQ(line_count, UNIT_PAGE_LINES);
    for (unsigned i = 0; i < line_count && i < UNIT_PAGE_LINES; i++) {
        if (strcmp(lines[i], unit_page[i])) fprintf(stderr, "line %u:\n  %s\n  %s\n", i, lines[i], unit_page[i]);
        CHECK(!strcmp(lines[i], unit_page[i]));
    }
    /* The AT calls: the oracle's probes in address order, then the six control types, the payload's page, its stack, then the pages of
     * the four loads. Nothing else is ever asked. */
    n = oracle_probes(unit_descs, UNIT_COUNT, expect, 20000, &extents);
    CHECK_EQ(extents, 8);
    CHECK_EQ(n, 16051);
    CHECK_EQ(at_count, n + 6 + 2 + 4);
    for (unsigned i = 0; i < n; i++) CHECK_EQ(at_log[i], expect[i]);
    static const uint64_t controls[] = {0xcc200000, 0xcc300000, 0xba500000, 0xa4e00000, 0xd4500000, 0xd2800000, 0xcc200000, 0xcc300000};
    for (unsigned i = 0; i < 8; i++) CHECK_EQ(at_log[n + i], controls[i]);
    static const uint64_t loaded[] = {BANK_BASE_, BANK_END_ - 4, 0x80000000, 0xa4e00000 - 4};
    for (unsigned i = 0; i < 4; i++) {
        CHECK_EQ(at_log[n + 8 + i], loaded[i]);
        CHECK_EQ(load_log[i], loaded[i]);
    }
    CHECK_EQ(load_count, 4);
    CHECK_EQ(load_unmapped_calls, 0);
    /* The registers: exactly the documented ones, each once, in order; the three that may trap are last, each behind its NEXT line,
     * which was the last thing printed, and eight seconds of the counter before the read. */
    CHECK_EQ(read_count, sizeof documented_reads / sizeof documented_reads[0]);
    for (unsigned i = 0; i < read_count; i++) CHECK(!strcmp(read_log[i], documented_reads[i]));
    static const char *const hazard[] = {"mdscr_el1", "oslsr_el1", "icc_sre_el2"};
    static const char *const next[] = {"PAYLOAD EL2MEM NEXT MDSCR_EL1 AFTER 8 S", "PAYLOAD EL2MEM NEXT OSLSR_EL1 AFTER 8 S",
                                       "PAYLOAD EL2MEM NEXT ICC_SRE_EL2 AFTER 8 S"};
    for (unsigned i = 0; i < 3; i++) {
        int r = read_index(hazard[i]), l = find_line(next[i]);
        CHECK(r >= 9 && l >= 0);
        CHECK_EQ(read_lines[r], l + 1);                                   /* the NEXT line is the last line printed before the read */
        CHECK(read_clock[r] - line_clock[l] >= 8ull * FREQ);              /* and the read comes at least eight seconds later */
        CHECK(read_clock[r] - line_clock[l] < 9ull * FREQ);
    }
    CHECK(!was_read("cntpoff_el2") && !was_read("S3_4_C14_C0_6") && !was_read("cntvoff_el2") && !was_read("S3_4_C14_C0_3"));
    guarded_free(&m.mem);
    return 0;
}

/* ---- The scan ------------------------------------------------------------------------------------------------------------------ */

/* Runs `list` as the map with identity write-back mappings, checks the probes against the oracle and returns the payload's value. */
static int run_oracle(const struct d *list, unsigned count, uint64_t stride, unsigned expect_extents, const char *map_line)
{
    struct q1n1_payload_args a = args_new();
    struct world_map m = build_map(list, count, stride);
    static uint64_t expect[20000];
    unsigned extents, n;
    world_reset();
    set_registers(2);
    map_identity(list, count);
    tr_map(0xcc200000, 0xcc201000, ATTR_WB, SH_INNER);
    tr_map(0xcc300000, 0xcc301000, ATTR_WB, SH_INNER);
    args_map(&a, &m);
    CHECK_EQ(go(&a), 0);
    n = oracle_probes(list, count, expect, 20000, &extents);
    CHECK_EQ(extents, expect_extents);
    CHECK(at_count >= n);
    for (unsigned i = 0; i < n; i++) CHECK_EQ(at_log[i], expect[i]);
    if (map_line) CHECK(!strcmp(lines[find_line("PAYLOAD EL2MEM MAP ")], map_line));
    CHECK(font_violations == 0 && long_lines == 0 && line_count <= 26);
    guarded_free(&m.mem);
    return 0;
}

static int suite_scan(void)
{
    /* Adjacent conventional descriptors are one extent; the map need not be in address order; an overlap merges. */
    static const struct d merged[] = {{7, 0x90000000, 512}, {7, 0x90200000, 512}, {7, 0x90400000, 3}, {1, 0xcc200000, 1}, {2, 0xcc300000, 1}};
    CHECK(!run_oracle(merged, 5, 48, 1, "PAYLOAD EL2MEM MAP DESC=5 STRIDE=48 CONV_EXTENTS=1 CONV_MIB=4"));
    static const struct d unsorted[] = {{7, 0x90400000, 512}, {7, 0x90000000, 512}, {7, 0x90200000, 512}, {7, 0x70000000, 100}, {1, 0xcc200000, 1}, {2, 0xcc300000, 1}};
    CHECK(!run_oracle(unsorted, 6, 56, 2, 0));
    static const struct d overlap[] = {{7, 0x90000000, 1024}, {7, 0x90100000, 4096}, {7, 0x90200000, 16}, {1, 0xcc200000, 1}, {2, 0xcc300000, 1}};
    CHECK(!run_oracle(overlap, 5, 48, 1, 0));
    /* A one-page extent, a two-page extent, an extent that starts mid-block, one that ends on a block boundary. */
    static const struct d small[] = {{7, 0x90000000, 1}, {7, 0x91000000, 2}, {7, 0x92001000, 511}, {7, 0x93000000, 512}, {1, 0xcc200000, 1}, {2, 0xcc300000, 1}};
    CHECK(!run_oracle(small, 6, 48, 4, 0));
    /* Unusable descriptors are counted and ignored: unaligned start, zero pages, beyond 48 bits, pages that overflow. */
    static const struct d bad[] = {{7, 0x90000800, 16}, {7, 0x91000000, 0}, {7, UINT64_C(1) << 48, 16}, {7, 0x92000000, UINT64_C(1) << 60},
                                   {7, 0x93000000, 256}, {1, 0xcc200000, 1}, {2, 0xcc300000, 1}};
    {
        struct q1n1_payload_args a = args_new();
        struct world_map m = build_map(bad, 7, 48);
        world_reset();
        set_registers(2);
        map_identity(bad + 4, 3);
        args_map(&a, &m);
        CHECK_EQ(go(&a), 0);
        CHECK(!strcmp(lines[find_line("PAYLOAD EL2MEM MAP ")], "PAYLOAD EL2MEM MAP DESC=7 STRIDE=48 CONV_EXTENTS=1 CONV_MIB=1 IGNORED=4"));
        CHECK_EQ(at_log[0], 0x93000000);
        guarded_free(&m.mem);
    }
    /* An extent that straddles 4 GiB: the low extent is clipped there, so its last word is below it. */
    {
        static const struct d straddle[] = {{7, 0xfff00000, 512}, {1, 0xcc200000, 1}, {2, 0xcc300000, 1}};
        struct q1n1_payload_args a = args_new();
        struct world_map m = build_map(straddle, 3, 48);
        world_reset();
        set_registers(2);
        map_identity(straddle, 3);
        args_map(&a, &m);
        CHECK_EQ(go(&a), 0);
        CHECK_ANY("PAYLOAD EL2MEM LOAD ", "BANK=SKIPPED_NOT_CONVENTIONAL");
        CHECK_ANY("PAYLOAD EL2MEM LOAD ", "LOW_FIRST(0XFFF00000)=0X");
        CHECK_ANY("PAYLOAD EL2MEM LOAD ", "LOW_LAST(0XFFFFFFFC)=0X");
        CHECK_EQ(load_count, 2);
        CHECK_EQ(load_log[0], 0xfff00000);
        CHECK_EQ(load_log[1], 0xfffffffc);
        guarded_free(&m.mem);
    }
    /* More extents than the 64 it scans: the rest are counted and said. */
    {
        static struct d many[100];
        struct q1n1_payload_args a = args_new();
        struct world_map m;
        for (unsigned i = 0; i < 70; i++) many[i] = (struct d){7, 0x10000000 + (uint64_t)i * 0x400000, 256};
        many[70] = (struct d){1, 0xcc200000, 1};
        many[71] = (struct d){2, 0xcc300000, 1};
        m = build_map(many, 72, 48);
        world_reset();
        set_registers(2);
        map_identity(many, 72);
        args_map(&a, &m);
        CHECK_EQ(go(&a), 0);
        CHECK(!strcmp(lines[find_line("PAYLOAD EL2MEM MAP ")], "PAYLOAD EL2MEM MAP DESC=72 STRIDE=48 CONV_EXTENTS=70 CONV_MIB=70 NOT_SCANNED=6"));
        CHECK(strstr(lines[find_line("PAYLOAD EL2MEM SCAN ")], "EXTENTS=64 PROBES=128") != 0);
        guarded_free(&m.mem);
    }
    return 0;
}

/* ---- Faulty worlds -------------------------------------------------------------------------------------------------------------- */

static void unit_setup(struct q1n1_payload_args *a, struct world_map *m)
{
    *a = args_new();
    world_reset();
    set_registers(2);
    map_identity(unit_descs, UNIT_COUNT);
    args_map(a, m);
}

static int suite_faulty(void)
{
    struct q1n1_payload_args a;
    struct world_map m = build_map(unit_descs, UNIT_COUNT, 48);
    const char *load;

    /* A hole in the middle of the bank: a fault key, one outlier run, the bank line says where the first fault is, and no load goes near it. */
    unit_setup(&a, &m);
    tr_fault(0x900000000, 0x900400000, 0x07);
    CHECK_EQ(go(&a), 0);
    CHECK(has_line("PAYLOAD EL2MEM KEY RESULT=FAULT=0X7:TRANS_L3 PROBES=2 FIRST=0X900000000 LAST=0X900200000"));
    CHECK(has_line("PAYLOAD EL2MEM OUTLIER RESULT=FAULT=0X7:TRANS_L3 FROM=0X900000000 TO=0X900200000 PROBES=2"));
    CHECK(has_line("PAYLOAD EL2MEM SCAN EXTENTS=8 PROBES=16051 MAPPED=16049 FAULT=2 KEYS=2 RUNS=3"));
    CHECK_HAS("PAYLOAD EL2MEM BANK ", "CONV_MIB=30720 PROBES=15361 FAULT=2 SAME_AS_FIRST=15359 FIRST_FAULT=0X900000000");
    CHECK_ANY("PAYLOAD EL2MEM BANK ", "AT=FAULT=0X7:TRANS_L3");
    CHECK(has_line("PAYLOAD EL2MEM DONE SCAN_HAS_FAULTS LOADS_OK=4 OF=4 HAZARD_READS=3"));
    CHECK_EQ(load_count, 4);
    CHECK_EQ(load_unmapped_calls, 0);

    /* The first page of the bank unmapped: that load is skipped by name and never made; the others are made. */
    unit_setup(&a, &m);
    tr_fault(BANK_BASE_, BANK_BASE_ + 0x200000, 0x05);
    CHECK_EQ(go(&a), 0);
    load = lines[find_line("PAYLOAD EL2MEM LOAD ")];
    CHECK(strstr(load, "BANK_FIRST(0X880000000)=SKIPPED_NOT_MAPPED") != 0);
    CHECK_EQ(load_count, 3);
    CHECK_EQ(load_log[0], BANK_END_ - 4);
    CHECK_EQ(load_unmapped_calls, 0);
    CHECK(has_line("PAYLOAD EL2MEM DONE SCAN_HAS_FAULTS LOADS_OK=3 OF=4 HAZARD_READS=3"));

    /* The bank not mapped at all: both bank loads skipped, the bank line says every probe faulted. */
    unit_setup(&a, &m);
    tr_fault(BANK_BASE_, BANK_END_, 0x04);
    CHECK_EQ(go(&a), 0);
    CHECK_ANY("PAYLOAD EL2MEM BANK ", "CONV_MIB=30720 PROBES=15361 FAULT=15361 SAME_AS_FIRST=15361");
    CHECK_ANY("PAYLOAD EL2MEM BANK ", "FIRST_FAULT=0X880000000");
    CHECK_ANY("PAYLOAD EL2MEM BANK ", "AT=FAULT=0X4:TRANS_L0");
    CHECK_EQ(load_count, 2);
    CHECK_EQ(load_log[0], 0x80000000);
    CHECK_ANY("PAYLOAD EL2MEM LOAD ", "BANK_FIRST(0X880000000)=SKIPPED_NOT_MAPPED");
    CHECK_ANY("PAYLOAD EL2MEM LOAD ", "BANK_LAST(0XFFFFFFFFC)=SKIPPED_NOT_MAPPED");

    /* Memory that is not write-back: Device, non-cacheable, write-through and an attribute byte that is none of them, each its own outlier. */
    static const struct { uint8_t attr, sh; const char *name; } kinds[] = {
        {ATTR_DEVICE, SH_OUTER, "DEVICE.OS"}, {ATTR_NC, SH_OUTER, "NC.OS"}, {ATTR_WT, SH_INNER, "WT.IS"}, {0x4f, SH_INNER, "OTHER=0X4F.IS"},
        {ATTR_WB, SH_NONE, "WB.NSH"},
    };
    for (unsigned i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        char want[160];
        unit_setup(&a, &m);
        tr_map(0x910000000, 0x910400000, kinds[i].attr, kinds[i].sh);
        CHECK_EQ(go(&a), 0);
        snprintf(want, sizeof want, "PAYLOAD EL2MEM OUTLIER RESULT=%s FROM=0X910000000 TO=0X910200000 PROBES=2", kinds[i].name);
        CHECK(has_line(want));
        CHECK(strstr(lines[find_line("PAYLOAD EL2MEM SCAN ")], "MAPPED=16051 FAULT=0 KEYS=2 RUNS=3") != 0);
    }

    /* An output address that is not the input address, and a set NS bit. */
    unit_setup(&a, &m);
    tr_map(0x910000000, 0x910400000, ATTR_WB, SH_INNER);
    tr_table[tr_count - 1].delta = 0x200000;
    tr_map(0x920000000, 0x920400000, ATTR_WB, SH_INNER);
    tr_table[tr_count - 1].ns = 1;
    CHECK_EQ(go(&a), 0);
    CHECK(has_line("PAYLOAD EL2MEM OUTLIER RESULT=WB.IS.NONIDENT FROM=0X910000000 TO=0X910200000 PROBES=2"));
    CHECK(has_line("PAYLOAD EL2MEM OUTLIER RESULT=WB.IS.NS1 FROM=0X920000000 TO=0X920200000 PROBES=2"));

    /* A mapped page whose load aborts: the error code is shown, the other loads go on, the payload returns normally. */
    unit_setup(&a, &m);
    load_abort_at = BANK_END_ - 4;
    CHECK_EQ(go(&a), 0);
    CHECK(strstr(lines[find_line("PAYLOAD EL2MEM LOAD ")], "BANK_LAST(0XFFFFFFFFC)=ERR6") != 0);
    CHECK(has_line("PAYLOAD EL2MEM DONE SCAN_ALL_MAPPED LOADS_OK=3 OF=4 HAZARD_READS=3"));
    CHECK_EQ(load_count, 4);

    /* The payload's own page not mapped: the control says so (the method is doubtful), and everything else still runs. */
    unit_setup(&a, &m);
    tr_fault(0xcc200000, 0xcc201000, 0x04);
    CHECK_EQ(go(&a), 0);
    CHECK_ANY("PAYLOAD EL2MEM CONTROL ", "CODE=FAULT=0X4:TRANS_L0");

    /* No conventional memory at all, and a map that lacks a firmware type: nothing is scanned or loaded; T3 reads ABSENT. */
    {
        static const struct d bare[] = {{1, 0xcc200000, 1}, {2, 0xcc300000, 1}};
        struct world_map b = build_map(bare, 2, 48);
        a = args_new();
        world_reset();
        set_registers(2);
        map_identity(bare, 2);
        args_map(&a, &b);
        CHECK_EQ(go(&a), 0);
        CHECK(has_line("PAYLOAD EL2MEM SCAN SKIPPED_NO_CONVENTIONAL_EXTENT"));
        CHECK_EQ(at_count, 0);
        CHECK_EQ(load_count, 0);
        CHECK(has_line("PAYLOAD EL2MEM DONE SCAN_NOT_RUN LOADS_OK=0 OF=0 HAZARD_READS=3"));
        guarded_free(&b.mem);
        static const struct d no3[] = {{7, 0x90000000, 256}, {1, 0xcc200000, 1}, {2, 0xcc300000, 1}};
        b = build_map(no3, 3, 48);
        a = args_new();
        world_reset();
        set_registers(2);
        map_identity(no3, 3);
        args_map(&a, &b);
        CHECK_EQ(go(&a), 0);
        CHECK_ANY("PAYLOAD EL2MEM CONTROL ", "T3=ABSENT T4=ABSENT");
        guarded_free(&b.mem);
    }
    guarded_free(&m.mem);
    return 0;
}

/* ---- Maps that must be refused ------------------------------------------------------------------------------------------------- */

/* A map of `size` bytes at `base` (a real buffer pressed against a guard page when base is 0 here: then the buffer is made for `size`). */
static int refused(uint64_t base, uint64_t size, uint64_t stride, const char *reason)
{
    struct q1n1_payload_args a = args_new();
    struct guarded g = guarded_alloc(size ? size : 8, 1);
    char want[96];
    world_reset();
    set_registers(2);
    a.map_base = base ? base : (uint64_t)(uintptr_t)g.data;
    a.map_size = size;
    a.map_stride = stride;
    CHECK_EQ(go(&a), 3);
    snprintf(want, sizeof want, "PAYLOAD EL2MEM MAP_REFUSED %s", reason);
    CHECK(has_line(want));
    CHECK_EQ(at_count, 0);
    CHECK_EQ(load_count, 0);
    CHECK_EQ(read_count, 12);
    CHECK(has_line("PAYLOAD EL2MEM DONE MAP_REFUSED LOADS_OK=0 OF=0 HAZARD_READS=3"));
    guarded_free(&g);
    return 0;
}

static int suite_map(void)
{
    CHECK(!refused(0, 96, 0, "STRIDE_BELOW_40"));
    CHECK(!refused(0, 78, 39, "STRIDE_BELOW_40"));
    CHECK(!refused(0, 88, 44, "STRIDE_NOT_A_MULTIPLE_OF_8"));
    CHECK(!refused(0, 100, 48, "SIZE_NOT_WHOLE_DESCRIPTORS"));      /* the third descriptor would end beyond the buffer */
    CHECK(!refused(0, 47, 48, "SIZE_NOT_WHOLE_DESCRIPTORS"));
    CHECK(!refused(0, 0, 48, "SIZE_NOT_WHOLE_DESCRIPTORS"));
    CHECK(!refused(UINT64_C(0x10004), 96, 48, "BUFFER_OUT_OF_RANGE"));                   /* not 8-byte aligned: nothing is read */
    CHECK(!refused(UINT64_C(1) << 48, 96, 48, "BUFFER_OUT_OF_RANGE"));
    CHECK(!refused((UINT64_C(1) << 48) - 48, 96, 48, "BUFFER_OUT_OF_RANGE"));
    CHECK(!refused(0, 48 * 1025, 48, "TOO_MANY_DESCRIPTORS"));
    return 0;
}

/* ---- Counter, EL, arguments, budget -------------------------------------------------------------------------------------------- */

static int suite_counter(void)
{
    struct q1n1_payload_args a;
    struct world_map m = build_map(unit_descs, UNIT_COUNT, 48);
    /* A counter that stands still or goes back: the first wait cannot be made, so no register that may trap is ever read; only one NEXT
     * line is printed, because nothing after it is attempted. */
    for (int mode = 1; mode <= 2; mode++) {
        unit_setup(&a, &m);
        clock_set(UINT64_C(1) << 40, mode == 1 ? 0 : 1000, mode);
        CHECK_EQ(go(&a), 0);
        CHECK(has_line("PAYLOAD EL2MEM NEXT MDSCR_EL1 AFTER 8 S"));
        CHECK(has_line("PAYLOAD EL2MEM MDSCR_EL1 SKIPPED=COUNTER_STUCK"));
        CHECK_EQ(count_prefix("PAYLOAD EL2MEM NEXT "), 1);
        CHECK(!was_read("mdscr_el1") && !was_read("oslsr_el1") && !was_read("icc_sre_el2"));
        CHECK(has_line("PAYLOAD EL2MEM DONE SCAN_ALL_MAPPED LOADS_OK=4 OF=4 HAZARD_READS=0"));
        CHECK(clock_calls < 2000100);
    }
    /* No counter op at all. */
    unit_setup(&a, &m);
    a.ops.counter = 0;
    CHECK_EQ(go(&a), 0);
    CHECK(has_line("PAYLOAD EL2MEM MDSCR_EL1 SKIPPED=NO_COUNTER"));
    CHECK(!was_read("mdscr_el1") && !was_read("oslsr_el1") && !was_read("icc_sre_el2"));
    /* CNTFRQ_EL0 that cannot be a counter frequency falls back to 19.2 MHz; a small valid one is used, and the wait follows it. */
    static const struct { uint64_t value, shown; } freqs[] = {{0, 19200000}, {999999, 19200000}, {1000000001, 19200000}, {1000000, 1000000}, {1000000000, 1000000000}};
    for (unsigned i = 0; i < sizeof freqs / sizeof freqs[0]; i++) {
        char want[96];
        unit_setup(&a, &m);
        reg_set("CNTFRQ_EL0", freqs[i].value);
        clock_set(0, freqs[i].shown / 40, 0);
        CHECK_EQ(go(&a), 0);
        snprintf(want, sizeof want, "PAYLOAD EL2MEM START CURRENTEL=0X8 FREQ=%llu", (unsigned long long)freqs[i].shown);
        CHECK(has_line(want));
        int r = read_index("mdscr_el1"), l = find_line("PAYLOAD EL2MEM NEXT MDSCR_EL1 AFTER 8 S");
        CHECK(r >= 0 && l >= 0);
        CHECK(read_clock[r] - line_clock[l] >= 8 * freqs[i].shown);
    }
    guarded_free(&m.mem);
    return 0;
}

static int suite_el(void)
{
    struct q1n1_payload_args a;
    struct world_map m = build_map(unit_descs, UNIT_COUNT, 48);
    for (uint64_t el = 0; el <= 3; el++) {
        char want[96];
        if (el == 2) continue;
        unit_setup(&a, &m);
        reg_set("CurrentEL", el << 2);
        CHECK_EQ(go(&a), 2);
        CHECK_EQ(line_count, 2);
        snprintf(want, sizeof want, "PAYLOAD EL2MEM START CURRENTEL=%s FREQ=19200000", el ? (el == 1 ? "0X4" : "0XC") : "0X0");
        CHECK(!strcmp(lines[0], want));
        CHECK(!strcmp(lines[1], "PAYLOAD EL2MEM REFUSED NOT_AT_EL2"));
        CHECK_EQ(read_count, 2);                                  /* CurrentEL and CNTFRQ_EL0, nothing that is UNDEFINED below EL2 */
        CHECK_EQ(at_count, 0);
        CHECK_EQ(load_count, 0);
        CHECK_EQ(clock_calls, 0);
    }
    guarded_free(&m.mem);
    return 0;
}

static int suite_args(void)
{
    struct q1n1_payload_args a;
    struct world_map m = build_map(unit_descs, UNIT_COUNT, 48);
    CHECK_EQ(payload_entry(0), Q1N1_PAYLOAD_RET_BAD_ARGS);
    for (int variant = 0; variant < 6; variant++) {
        unit_setup(&a, &m);
        switch (variant) {
        case 0: a.magic ^= 1; break;
        case 1: a.version = 2; break;
        case 2: a.size = sizeof a - 8; break;
        case 3: a.ops.puts = 0; break;
        case 4: a.ops.hex = 0; break;
        default: a.version = 0; break;
        }
        CHECK_EQ(go(&a), Q1N1_PAYLOAD_RET_BAD_ARGS);
        CHECK_EQ(line_total, 0);
        CHECK_EQ(read_count, 0);
        CHECK_EQ(at_count, 0);
    }
    guarded_free(&m.mem);
    return 0;
}

#ifndef TEST_BUDGET
#define TEST_BUDGET 26
#endif

static int suite_budget(void)
{
    struct q1n1_payload_args a;
    struct world_map m = build_map(unit_descs, UNIT_COUNT, 48);
    unit_setup(&a, &m);
    CHECK_EQ(go(&a), 0);
    /* The unit page is 16 lines. With a smaller budget lines are dropped and counted, never the NEXT lines or the DONE line. */
    CHECK(line_count <= TEST_BUDGET);
    CHECK_EQ(count_prefix("PAYLOAD EL2MEM NEXT "), 3);
    CHECK(find_line("PAYLOAD EL2MEM DONE ") == (int)line_count - 1);
    if (TEST_BUDGET >= UNIT_PAGE_LINES) {
        CHECK_EQ(line_count, UNIT_PAGE_LINES);
        CHECK(strstr(lines[line_count - 1], "SUPPRESSED") == 0);
    } else {
        const char *done = lines[line_count - 1];
        char want[32];
        CHECK_EQ(line_count, TEST_BUDGET);
        snprintf(want, sizeof want, "SUPPRESSED=%u", (unsigned)(UNIT_PAGE_LINES - TEST_BUDGET));
        CHECK(strstr(done, want) != 0);
    }
    guarded_free(&m.mem);
    return 0;
}

/* The most lines the payload prints over the worlds above and a world built to print as many as it can: five outlier runs, three keys,
 * a long control line, loads that wrap. */
static unsigned most_lines;
static int suite_worst(void)
{
    struct q1n1_payload_args a;
    struct world_map m = build_map(unit_descs, UNIT_COUNT, 48);
    unit_setup(&a, &m);
    for (unsigned i = 0; i < 8; i++) {
        uint64_t at = 0x900000000 + (uint64_t)i * 0x10000000;
        if (i & 1) tr_map(at, at + 0x400000, i & 2 ? ATTR_DEVICE : ATTR_NC, SH_OUTER);
        else tr_fault(at, at + 0x400000, (uint8_t)(0x04 + (i >> 1)));
    }
    tr_table[tr_count - 1].delta = 0x1000;
    tr_fault(0xcc200000, 0xcc201000, 0x0f);
    load_abort_at = BANK_BASE_;
    CHECK_EQ(go(&a), 0);
    CHECK(line_count <= TEST_BUDGET);
    CHECK_EQ(count_prefix("PAYLOAD EL2MEM NEXT "), 3);
    CHECK(find_line("PAYLOAD EL2MEM DONE ") == (int)line_count - 1);
    if (TEST_BUDGET >= 26) {
        CHECK_EQ(count_prefix("PAYLOAD EL2MEM OUTLIER "), 5);
        CHECK_HAS("PAYLOAD EL2MEM SCAN ", "OUTLIERS_NOT_LISTED=");
    }
    if (line_count > most_lines) most_lines = line_count;
    guarded_free(&m.mem);
    return 0;
}

/* ---- Random worlds ------------------------------------------------------------------------------------------------------------- */

static uint64_t rng_state;
static uint64_t rnd(void)
{
    rng_state = rng_state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
    return rng_state >> 33;
}

static int usable_descriptor(const struct d *x)
{
    return !(x->start & (PAGE_ - 1)) && x->pages && x->start < (UINT64_C(1) << 48) && x->pages <= ((UINT64_C(1) << 48) - x->start) / PAGE_;
}

static int suite_fuzz(void)
{
    static struct d list[48], good[48];
    static uint64_t expect[20000];
    for (unsigned world = 0; world < 400; world++) {
        struct q1n1_payload_args a = args_new();
        unsigned count = 2 + (unsigned)(rnd() % 40), usable = 0, extents;
        uint64_t stride = 48 + 8 * (rnd() % 3);
        rng_state = rng_state ^ world;
        for (unsigned i = 0; i < count; i++) {
            static const uint32_t types[] = {7, 7, 7, 7, 1, 2, 3, 4, 5, 6, 9, 0, 11};
            list[i].type = types[rnd() % 13];
            list[i].start = (rnd() % (UINT64_C(1) << 22)) * PAGE_ * 8;
            list[i].pages = 1 + rnd() % 20000;
            if (rnd() % 20 == 0) list[i].start += 0x800;
            else if (rnd() % 30 == 0) list[i].pages = 0;
            else if (rnd() % 40 == 0) list[i].start = (UINT64_C(1) << 48) + PAGE_ * (rnd() % 8);
        }
        list[0].type = 1;
        list[1].type = 2;
        for (unsigned i = 0; i < count; i++)
            if (usable_descriptor(&list[i])) good[usable++] = list[i];
        struct world_map m = build_map(list, count, stride);
        world_reset();
        set_registers(2);
        clock_set(1000, 1000000 + rnd() % 5000000, 0);
        for (unsigned i = 0; i < count; i++) {
            if (!usable_descriptor(&list[i]) || !list[i].type || rnd() % 6 == 0) continue;
            static const uint8_t attrs[] = {ATTR_WB, ATTR_WB, ATTR_WB, ATTR_WT, ATTR_NC, ATTR_DEVICE, 0x4f, 0xf0};
            tr_map(list[i].start, list[i].start + list[i].pages * PAGE_, attrs[rnd() % 8], (uint8_t)(rnd() % 4));
            if (rnd() % 5 == 0) tr_fault(list[i].start, list[i].start + PAGE_ * (1 + rnd() % 600), (uint8_t)(rnd() % 64));
        }
        args_map(&a, &m);
        if (rnd() % 4 == 0) load_abort_at = list[2].start;
        CHECK_EQ(go(&a), 0);
        CHECK(font_violations == 0 && long_lines == 0);
        CHECK(line_count <= TEST_BUDGET && line_count >= 4);
        CHECK(find_line("PAYLOAD EL2MEM DONE ") == (int)line_count - 1);
        CHECK_EQ(count_prefix("PAYLOAD EL2MEM NEXT "), 3);
        CHECK_EQ(load_unmapped_calls, 0);
        CHECK(load_count <= 4);
        unsigned n = oracle_probes(good, usable, expect, 20000, &extents);
        CHECK(at_count >= n && at_count <= n + 12);
        for (unsigned i = 0; i < n && i < AT_LOG_MAX; i++) CHECK_EQ(at_log[i], expect[i]);
        for (unsigned i = 0; i < read_count; i++) {
            if (strcmp(read_log[i], "mdscr_el1") && strcmp(read_log[i], "oslsr_el1") && strcmp(read_log[i], "icc_sre_el2")) continue;
            CHECK(read_lines[i] >= 2 && !strncmp(lines[read_lines[i] - 1], "PAYLOAD EL2MEM NEXT ", 20));
            CHECK(read_clock[i] - line_clock[read_lines[i] - 1] >= 8ull * FREQ);
        }
        if (line_count > most_lines) most_lines = line_count;
        guarded_free(&m.mem);
    }
    return 0;
}

static int report_lines(void)
{
    suite_worst();
    suite_fuzz();
    printf("LINES_MAX=%u\n", most_lines);
    return 0;
}

static int dump_page(void)
{
    struct q1n1_payload_args a;
    struct world_map m = build_map(unit_descs, UNIT_COUNT, 48);
    unit_setup(&a, &m);
    go(&a);
    for (unsigned i = 0; i < line_count; i++) printf("%s\n", lines[i]);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"unit", suite_unit}, {"scan", suite_scan}, {"faulty", suite_faulty}, {"map", suite_map}, {"counter", suite_counter},
        {"el", suite_el}, {"args", suite_args}, {"budget", suite_budget}, {"worst", suite_worst}, {"fuzz", suite_fuzz},
    };
    if (argc > 1 && !strcmp(argv[1], "lines-report")) return report_lines();
    if (argc > 1 && !strcmp(argv[1], "page")) return dump_page();
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) {
            fprintf(stderr, "FAIL: suite %s\n", suites[i].name);
            return 1;
        }
        ran++;
    }
    printf("PASS: %u payload el2mem suites, %u checks\n", ran, checks);
    return 0;
}
