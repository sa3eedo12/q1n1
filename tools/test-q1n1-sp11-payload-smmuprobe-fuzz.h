/* SPDX-License-Identifier: MIT */
/* The fuzz suite of the smmuprobe host test (tools/test-q1n1-sp11-payload-smmuprobe.c): random worlds (a random memory map, hostile
 * capability lists, faults in the configuration pages and in the SMMU registers and tables, random stream tables) judged by an oracle
 * written another way: the stream table lookup of StreamID 0x60100 from the SMMUv3 description, the capability lists walked with a step
 * count, the memory map read for any overlap with a type that must not be read. Every world must also pass the discipline checks of
 * the other suites. Included by the test after the suites it shares helpers with. Evidence: EXPERIMENTAL (host model only). */
#pragma once

static uint64_t rng_state = UINT64_C(20241117);
static uint64_t rnd(void)
{
    rng_state = rng_state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
    return rng_state >> 33;
}
#define ADDR_BITS UINT64_C(0x000fffffffffffc0)

static int descriptor_ok(const struct d *x)
{
    return !(x->start & (PAGE_ - 1)) && x->pages && x->start < (UINT64_C(1) << 48) && x->pages <= ((UINT64_C(1) << 48) - x->start) / PAGE_;
}
/* 1 when [addr, addr + bytes) is inside a descriptor of a type that may be read and no descriptor of another type overlaps it. */
static int oracle_usable(const struct d *list, unsigned count, int map_ok, uint64_t addr, uint64_t bytes)
{
    int inside = 0;
    if (!map_ok) return 0;
    for (unsigned i = 0; i < count; i++) {
        uint64_t s = list[i].start, e = s + list[i].pages * PAGE_;
        if (!descriptor_ok(&list[i]) || addr + bytes <= s || addr >= e) continue;
        if (!((list[i].type >= 1 && list[i].type <= 7) || list[i].type == 9)) return 0;
        if (addr >= s && addr + bytes <= e) inside = 1;
    }
    return inside;
}

struct oracle {
    const char *mode, *why;
    uint64_t l1_at, ste_at;
    unsigned l1_words, ste_words, ste_walk;
};
static int reg_value(unsigned i, uint64_t *v)
{
    uint32_t lo;
    if (i == 12) return peek64(SMMU_PAGE + 0x80, v);
    if (!peek(SMMU_PAGE + smmu_offsets[i], &lo)) return 0;
    *v = lo;
    return 1;
}
/* What the payload must conclude, and read, in the world as scripted: the architecture's lookup of StreamID 0x60100, written from the
 * SMMUv3 description of the stream table, not from the payload. */
static void oracle_run(const struct d *list, unsigned count, int map_ok, struct oracle *o)
{
    uint64_t reg[14] = {0}, base, l1, ste, dw0 = 0, index;
    uint32_t fmt, split, lg, lo, hi, span;
    int ok[14] = {0};
    memset(o, 0, sizeof *o);
    o->mode = "UNKNOWN";
    o->why = "NONE";
    for (unsigned i = 0; i < 14; i++) {
        ok[i] = reg_value(i, &reg[i]);
        if (!ok[i]) break;
    }
    if (!ok[8]) {
        o->why = "CR0_NOT_READ";
        return;
    }
    if (!ok[9]) {
        o->why = "CR0ACK_NOT_READ";
        return;
    }
    if (reg[8] != reg[9]) {
        o->why = "CR0_ACK_DISAGREE";
        return;
    }
    if (!(reg[9] & 1)) {
        if (!ok[10]) {
            o->why = "GBPA_NOT_READ";
            return;
        }
        o->mode = reg[10] >> 20 & 1 ? "ABORT_GLOBAL" : "BYPASS_GLOBAL";
        o->why = "SMMU_DISABLED";
        return;
    }
    if (!ok[12] || !ok[13]) {
        o->why = "STRTAB_NOT_READ";
        return;
    }
    fmt = reg[13] >> 16 & 3;
    split = reg[13] >> 6 & 31;
    lg = reg[13] & 63;
    base = reg[12] & ADDR_BITS;
    if (fmt > 1) {
        o->why = "STRTAB_FORMAT";
        return;
    }
    if ((uint64_t)SID >> lg) {
        o->mode = "NO_STE";
        o->why = "SID_BEYOND_TABLE";
        return;
    }
    if (!fmt) {
        ste = base + SID * UINT64_C(64);
    } else {
        if (split != 6 && split != 8 && split != 10) {
            o->why = "STRTAB_SPLIT";
            return;
        }
        o->l1_at = base + (uint64_t)(SID >> split) * 8;
        if (!oracle_usable(list, count, map_ok, o->l1_at, 8)) {
            o->why = "TABLE_NOT_RAM";
            return;
        }
        if (!tr_is_mapped(o->l1_at)) {
            o->why = "L1_UNMAPPED";
            return;
        }
        o->l1_words = peek(o->l1_at, &lo) ? 2 : 1;
        if (o->l1_words == 1 || !peek(o->l1_at + 4, &hi)) {
            o->why = "L1_NOT_READ";
            return;
        }
        l1 = lo | (uint64_t)hi << 32;
        span = l1 & 31;
        index = SID & ((UINT64_C(1) << split) - 1);
        if (!span || index >= UINT64_C(1) << (span - 1)) {
            o->mode = "NO_STE";
            o->why = span ? "BEYOND_L2_SPAN" : "NO_L2_TABLE";
            return;
        }
        ste = (l1 & ADDR_BITS) + index * 64;
    }
    o->ste_at = ste;
    if (!oracle_usable(list, count, map_ok, ste, 64)) {
        o->why = "TABLE_NOT_RAM";
        return;
    }
    o->ste_walk = 1;
    if (!tr_is_mapped(ste)) {
        o->why = "STE_UNMAPPED";
        return;
    }
    for (unsigned i = 0; i < 4; i++) {
        uint32_t a, b;
        if (!peek(ste + 8 * i, &a) || !peek(ste + 8 * i + 4, &b)) {
            o->ste_words = 2 * i + (peek(ste + 8 * i, &a) ? 2 : 1);
            o->why = "STE_NOT_READ";
            return;
        }
        if (!i) dw0 = a | (uint64_t)b << 32;
    }
    o->ste_words = 8;
    if (!(dw0 & 1)) o->mode = "INVALID";
    else o->mode = (const char *[]){"ABORT", "RESERVED", "RESERVED", "RESERVED", "BYPASS", "S1", "S2", "S1S2"}[dw0 >> 1 & 7];
}

/* The PCI Express capability's offset, and the AER capability's, in a page with no fault: the lists walked with a step count. */
static uint32_t oracle_cap(unsigned fn)
{
    const uint32_t *pg = cfg_value[fn];
    uint32_t ptr = pg[0x34 / 4] & 0xfc;
    if (!(pg[1] >> 20 & 1)) return 0;
    for (unsigned step = 0; step < 16 && ptr >= 0x40 && ptr < 0x100; step++) {
        if ((pg[ptr / 4] & 0xff) == 0x10) return ptr;
        ptr = pg[ptr / 4] >> 8 & 0xfc;
    }
    return 0;
}
static uint32_t oracle_aer(unsigned fn)
{
    const uint32_t *pg = cfg_value[fn];
    uint32_t ptr = 0x100;
    for (unsigned step = 0; step < 24 && ptr >= 0x100 && ptr < 0x1000; step++) {
        uint32_t dw = pg[ptr / 4];
        if (!dw || dw == 0xffffffff) return 0;
        if ((dw & 0xffff) == 1) return ptr;
        ptr = dw >> 20 & 0xffc;
    }
    return 0;
}

static const uint16_t fuzz_offsets[] = {0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x34, 0x40, 0x50, 0x70, 0x78, 0x7c, 0x80, 0x88, 0x8c, 0x90,
                                        0x9c, 0xa0, 0xac, 0xb0, 0xfc, 0x100, 0x104, 0x108, 0x110, 0x114, 0x130, 0x140, 0x144, 0x148, 0x150,
                                        0x154, 0x170, 0xffc};
#define FUZZ_OFFSETS (sizeof fuzz_offsets / sizeof fuzz_offsets[0])
static uint32_t fuzz_word(void)
{
    switch (rnd() % 6) {
    case 0: return 0;
    case 1: return 0xffffffff;
    case 2: return (uint32_t)(rnd() << 1 ^ rnd());
    case 3: return 0x10 | (uint32_t)(0x40 + 4 * (rnd() % 48)) << 8 | (uint32_t)(rnd() % 16) << 16;
    case 4: return 0x1 | (uint32_t)(rnd() % 4) << 16 | (uint32_t)(0x100 + 4 * (rnd() % 960)) << 20;
    default: return (uint32_t)(rnd() % 0x20) | (uint32_t)(0x40 + 4 * (rnd() % 48)) << 8;
    }
}
static uint64_t fuzz_pick(const uint64_t *v, unsigned n)
{
    return v[rnd() % n];
}
#define PICK(...) fuzz_pick((const uint64_t[]){__VA_ARGS__}, sizeof((const uint64_t[]){__VA_ARGS__}) / 8)

/* Every outcome the fuzz must reach, each at least three times, or it proves nothing about the deep paths. */
static const struct { const char *mode, *why; } fuzz_reach[] = {
    {"S2", "NONE"}, {"S1", "NONE"}, {"S1S2", "NONE"}, {"BYPASS", "NONE"}, {"ABORT", "NONE"}, {"INVALID", "NONE"}, {"RESERVED", "NONE"},
    {"BYPASS_GLOBAL", "SMMU_DISABLED"}, {"ABORT_GLOBAL", "SMMU_DISABLED"}, {"NO_STE", "SID_BEYOND_TABLE"}, {"NO_STE", "NO_L2_TABLE"},
    {"NO_STE", "BEYOND_L2_SPAN"}, {"UNKNOWN", "CR0_NOT_READ"}, {"UNKNOWN", "GBPA_NOT_READ"}, {"UNKNOWN", "STRTAB_NOT_READ"},
    {"UNKNOWN", "STRTAB_FORMAT"}, {"UNKNOWN", "STRTAB_SPLIT"}, {"UNKNOWN", "TABLE_NOT_RAM"}, {"UNKNOWN", "L1_NOT_READ"},
    {"UNKNOWN", "STE_NOT_READ"}, {"UNKNOWN", "CR0ACK_NOT_READ"}, {"UNKNOWN", "CR0_ACK_DISAGREE"}, {"UNKNOWN", "L1_UNMAPPED"},
    {"UNKNOWN", "STE_UNMAPPED"},
};
static unsigned fuzz_hits[sizeof fuzz_reach / sizeof fuzz_reach[0]];

static int fuzz_world(void)
{
    struct world w;
    struct d list[16];
    struct oracle o;
    struct smmu_cfg s;
    unsigned count = 0, config_faults = rnd() % 2, used_hz, rp, ep, sm;
    uint64_t cntfrq;
    int map_ok = rnd() % 8 != 0, structured = rnd() % 10 < 7, k1, k2, i;
    char want[128];
        static const uint32_t types[] = {7, 7, 4, 2, 9, 0, 8, 10, 11, 5, 1, 3, 6, 12, 13, 14};
    if (rnd() % 10 < 8) list[count++] = (struct d){7, LB, 0x20000};
    for (unsigned extra = (unsigned)(rnd() % 6); extra--;) {
        list[count].type = types[rnd() % 16];
        list[count].start = PICK(0x8a000000, 0x8a400000, 0x8a404000, 0x81804000, 0x8a003000, 0x8a00c000, 0x8a200000, 0x8a300000,
                                 0xa0000000, 0xb0000000) + (rnd() % 8 == 0 ? 0x800 : 0);
        list[count].pages = rnd() % 12 == 0 ? 0 : 1 + rnd() % 3;
        count++;
    }
    if (!count) list[count++] = (struct d){7, LB, 0x20000};
    world_new(&w, list, count);
    if (!map_ok) {
        unsigned v = (unsigned)(rnd() % 4);
        if (v == 0) w.a.map_base = 0;
        if (v == 1) w.a.map_stride = 36;
        if (v == 2) w.a.map_size += 8;
        if (v == 3) w.a.map_size = 0;
    }
    /* the configuration pages: every dword is scripted, so the oracle can follow the lists; faults only in half of the worlds */
    for (unsigned f = 0; f < 2; f++)
        for (unsigned j = 0; j < 1024; j++) bus_set((f ? EP_PAGE : RP_PAGE) + 4 * j, 0);
    put_rp();
    put_ep();
    for (unsigned f = 0; f < 2; f++) {
        uint64_t page = f ? EP_PAGE : RP_PAGE;
        for (unsigned m = (unsigned)(rnd() % 5); m--;) bus_set(page + fuzz_offsets[rnd() % FUZZ_OFFSETS], fuzz_word());
        if (rnd() % 10 == 0) bus_set(page, rnd() % 2 ? 0xffffffff : 0x1234ffff);
        if (config_faults)
            for (unsigned m = (unsigned)(rnd() % 3); m--;) bus_fault(page + fuzz_offsets[rnd() % FUZZ_OFFSETS]);
    }
    /* the SMMU: registers first (seven worlds in ten with a consistent table), then, where the oracle says the payload will look, the
     * descriptor and the entry */
    s.cr0 = rnd() % 5 ? (uint32_t)rnd() | 1 : (uint32_t)rnd() & ~1u;
    s.gbpa = (uint32_t)rnd();
    s.gerror = (uint32_t)rnd();
    if (structured) {
        s.base = PICK(TB, TB, LB, 0x400000008a000000);
        s.cfg = (uint32_t)(PICK(0, 1, 1, 1) << 16 | PICK(6, 8, 10) << 6 | PICK(19, 20, 21, 24));
    } else {
        s.base = PICK(0x400000008a000000, 0x8a000000, 0x80000000, 0x80000fc0, 0xa0000000, 0xb0000000, 0, ~UINT64_C(0), rnd() & ADDR_BITS);
        s.cfg = (uint32_t)(PICK(0, 1, 1, 1, 1, 1, 2, 3) << 16 | PICK(6, 8, 10, 6, 8, 10, 5, 7, 9, 11, 0, 31) << 6 |
                           PICK(20, 20, 19, 18, 24, 0, 63, 21));
        if (rnd() % 3 == 0) s.cfg |= (uint32_t)rnd() & 0xfffc0000u;
    }
    put_smmu(&s);
    if (rnd() % 10 == 0) bus_set(SMMU_PAGE + 0x24, rnd() % 2 ? (uint32_t)rnd() : s.cr0 ^ (1u << (rnd() % 32)));   /* an acknowledgement that differs */
    if (rnd() % 14 == 0) {
        unsigned r = (unsigned)(rnd() % 14);
        bus_fault(SMMU_PAGE + smmu_offsets[r] + (r == 12 && rnd() % 2 ? 4 : 0));
    }
    if (!(s.cr0 & 1) && rnd() % 3 == 0) bus_fault(SMMU_PAGE + (rnd() % 2 ? 0x24 : 0x44));      /* a disabled SMMU whose GBPA is not read */
    oracle_run(list, count, map_ok, &o);
    if (o.l1_at && rnd() % 9 == 0) tr_fault(o.l1_at & ~UINT64_C(0xfff), (o.l1_at & ~UINT64_C(0xfff)) + 0x1000, 0x05);      /* a page the MMU does not map */
    if (o.l1_at && oracle_usable(list, count, map_ok, o.l1_at, 8)) {
        uint64_t l2 = structured ? PICK(0x8a400000, 0x8a200000, 0x8a300000, 0x8a000000)
                                 : PICK(0x8a400000, 0x8a000000, 0x8a200000, 0x8a300000, 0xa0000000, 0xb0000000, ADDR_BITS, rnd() << 6);
        uint64_t span = structured ? PICK(10, 11, 11, 12, 31, 9, 0, 1, 1, 1) : PICK(0, 1, 9, 10, 11, 12, 31, rnd() % 32);
        bus_set64(o.l1_at, l2 | span | (!structured && rnd() % 3 == 0 ? UINT64_C(0xfff0000000000000) : 0));
        if (rnd() % 12 == 0) bus_fault(o.l1_at + 4 * (rnd() % 2));
    }
    oracle_run(list, count, map_ok, &o);
    if (o.ste_at && oracle_usable(list, count, map_ok, o.ste_at, 64)) {
        for (unsigned j = 0; j < 4; j++)
            bus_set64(o.ste_at + 8 * j, j ? ((uint64_t)rnd() << 32 | rnd()) : (uint64_t)(rnd() % 8) << 1 | (rnd() % 5 != 0));
        if (rnd() % 12 == 0) bus_fault(o.ste_at + 4 * (rnd() % 8));
    }
    oracle_run(list, count, map_ok, &o);
    if (o.ste_at && rnd() % 9 == 0) tr_fault(o.ste_at & ~UINT64_C(0xfff), (o.ste_at & ~UINT64_C(0xfff)) + 0x1000, 0x05);
    oracle_run(list, count, map_ok, &o);
    if (o.l1_words) allow_ram(o.l1_at, o.l1_at + 8);
    if (o.ste_words) allow_ram(o.ste_at, o.ste_at + 32);
    cntfrq = PICK(19200000, 19200000, 24000000, 0, 1000000, 1000000000, 999);
    reg_set("CNTFRQ_EL0", cntfrq);
    used_hz = (unsigned)(cntfrq >= 1000000 && cntfrq <= 1000000000 ? cntfrq : 19200000);
    clock_set(1000, 100000 + rnd() % 2000000, 0);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    snprintf(want, sizeof want, P "VERDICT STREAM=0X60100 MODE=%s WHY=%s", o.mode, o.why);
    CHECK_LINE(want);
    for (unsigned j = 0; j < sizeof fuzz_reach / sizeof fuzz_reach[0]; j++)
        fuzz_hits[j] += !strcmp(o.mode, fuzz_reach[j].mode) && !strcmp(o.why, fuzz_reach[j].why);
    rp = loads_in(RP_PAGE, RP_PAGE + 0x1000);
    ep = loads_in(EP_PAGE, EP_PAGE + 0x1000);
    sm = loads_in(SMMU_PAGE, SMMU_PAGE + 0x90);
    CHECK(rp <= 64 && ep <= 64 && sm <= 15);
    CHECK_EQ(load_n - rp - ep - sm, o.l1_words + o.ste_words);
    CHECK_EQ(at_count, 3 + !!o.l1_at + o.ste_walk);
    CHECK(find_line(P "DONE ") == (int)line_count - 1);
    CHECK_EQ(count_prefix(P "VERDICT "), 1);
    CHECK_EQ(count_prefix(P "NEXT "), 2);
    k1 = find_line(P "NEXT PCIE_CAPS");
    k2 = find_line(P "NEXT SMMU_REGISTERS");
    CHECK(k1 >= 0 && k2 > k1);
    for (int k = k1; k <= k2; k += k2 - k1) {              /* the wait is before every load that follows a NEXT line, whatever it is */
        i = first_load_after((unsigned)k);
        if (i >= 0) CHECK(loads[i].clock - line_clock[k] >= 8 * (uint64_t)used_hz);
    }
    i = first_load_after((unsigned)k2);
    CHECK(i >= 0 && loads[i].lines == (unsigned)k2 + 1 && loads[i].addr == SMMU_PAGE);
    if (TEST_BUDGET >= 36) CHECK_NO_TOKEN(P "DONE ", "SUPPRESSED=");
    if (!config_faults && TEST_BUDGET >= 36)
        for (unsigned f = 0; f < 2; f++) {
            const char *name = f ? "EP" : "RP";
            uint32_t cap = 0, aer = 0, id = cfg_value[f][0];
            int absent = (id & 0xffff) == 0xffff;
            char label[40], token[24];
            if (!absent) cap = oracle_cap(f);
            if (cap) aer = oracle_aer(f);
            snprintf(label, sizeof label, P "%s.PCIE ", name);
            if (cap) {
                snprintf(token, sizeof token, "AT=0X%X", cap);
                CHECK_TOKEN(label, token);
            } else {
                snprintf(want, sizeof want, P "%s.PCIE PCIE=%s", name, absent ? "NOT_READ" : "NONE");
                CHECK_LINE(want);
            }
            snprintf(label, sizeof label, P "%s.AER ", name);
            if (aer) {
                snprintf(token, sizeof token, "AT=0X%X", aer);
                CHECK_TOKEN(label, token);
            } else {
                snprintf(want, sizeof want, P "%s.AER AER=%s", name, cap ? "NONE" : "NO_PCIE_CAP");
                CHECK_LINE(want);
            }
        }
    if (line_count > most_lines) most_lines = line_count;
    world_free(&w);
    return 0;
}

static int suite_fuzz(void)
{
    for (unsigned n = 0; n < 1500; n++)
        if (fuzz_world()) {
            fprintf(stderr, "  in fuzz world %u\n", n);
            return 1;
        }
    for (unsigned i = 0; i < sizeof fuzz_reach / sizeof fuzz_reach[0]; i++)
        if (fuzz_hits[i] < 3) {
            fprintf(stderr, "FAIL: the fuzz reached %s / %s only %u times\n", fuzz_reach[i].mode, fuzz_reach[i].why, fuzz_hits[i]);
            return 1;
        }
    return 0;
}
