/* SPDX-License-Identifier: MIT */
/* Host test for the runner's mapping step (platform/uefi/sp11-smmumap.c, docs/SP11-PAYLOAD-SMMUMAP.md), built natively with the gate on
 * against the machine modelled in tools/test-q1n1-sp11-payload-smmumap-world.h. Driven by tools/test-q1n1-sp11-payload-smmumap.py under ASan
 * and UBSan. Eighteen suites in two files: the four about the memory map and the evidence the step reads and prints (map, ram, scan,
 * serror) are in tools/test-q1n1-sp11-payload-smmumap-scan.c and run from this file's main.
 *
 * Suites here: good (the page of the good world line by line, every effect in order with its operand, the eight seconds, the publication, a
 * second call), pure (the descriptor, its validity check, the template check, the names, the allow-list), template (every way the Device
 * entry the attributes come from can be wrong or odd, and the bits that are not copied), entry (the page's entry is valid, is not zero,
 * has a reserved form), walk (a hole, a block, a read that aborts and its level, a table beyond the physical address size, the control bits
 * of a table descriptor, at each level), table (the table page must take a store), at (the instruction disagrees with the walk before the
 * store, a stage-2 bit of PAR_EL1 either way, and the check after it: put back, or UNSAFE, including a shareability or NS that differs),
 * unsafe, regs (the pinned root, the regime, a table address checked against PS), spec (any page but the one), store (the store aborts,
 * the slot is written by another agent during the wait or its read just before the store aborts), counter (a missing, stuck, backward,
 * odd-frequency and slow counter: the eight seconds are made or nothing is written; with a lowered bound SPIN_BOUND, which a dead counter
 * does not give), publish (each barrier left out), fuzz (random worlds against properties: nothing is written but the one slot, what is
 * written is the one page's descriptor, written only into a table page that is RAM by the map, after a read of that very slot, with no
 * pointer to the table in the root or the level-1 table; no load of any world, refused or not, touches a page the map does not call RAM;
 * a put-back restores the tables, a mapped page is Device).
 *
 * What it cannot show: what the unit does at these addresses, whether the table page is writable on the unit, or what the SMMU does with
 * a read. Evidence: EXPERIMENTAL (host model only); hardware NOT RUN. */
#include "test-q1n1-sp11-payload-smmumap-world.h"

static void reset_log(struct world *w)
{
    memset(w->seq, 0, sizeof w->seq);
    w->events = w->nlines = w->applied = w->attempts = w->stray = w->stray_reads = w->reads = w->polls = 0;
    memset(w->store_pa, 0, sizeof w->store_pa);
    memset(w->store_val, 0, sizeof w->store_val);
    w->next_seen = w->store_before_next = 0;
    w->next_at = w->store_at = 0;
}

/* ---- good ---------------------------------------------------------------------------------------------------------------------- */

static const char *const good_page[] = {
    "PAYLOAD SMMUMAP START PCIE_SMMU0 PAGE=0X15400000 TEMPLATE=0X70000000 TTBR0=0XA7F2E000",
    "PAYLOAD SMMUMAP REGS TCR=0X80843514 MAIR=0XFFBB4400 SCTLR=0X100030C5183D HCR=0X88000010",
    "PAYLOAD SMMUMAP WALK L0=0XA7F2F003 L1=0XA7F30003 L2=0XA7F31003 SLOT=0XA7F31000 OLD=0X0",
    "PAYLOAD SMMUMAP TEMPLATE LEVEL=0X2 DESC=0X40000070000641 ATTR=0X0 PAR=0X70000B00",
    "PAYLOAD SMMUMAP TABLE VALID=2 REFS=0/0/1",
    "PAYLOAD SMMUMAP STORE SLOT=0XA7F31000 DESC=0X40000015400643 TABLEW=OK",
    "PAYLOAD SMMUMAP NEXT STORE AFTER 8 S",
    "PAYLOAD SMMUMAP CHECK PARR=0X15400B00 PARW=0X15400B00 ATTR=SAME",
    "PAYLOAD SMMUMAP DONE MAPPED=1 STORES=1",
};

static void suite_good(void)
{
    NEWWORLD(w);
    struct world after;
    struct q1n1_smmumap_result r;
    uint64_t span;
    unsigned i;
    w_before = w;
    CHECK(run_world(&w, &r) == MAPPED, "the good world is not mapped: %s", last_line(&w));
    common_checks(&w, &w_before, &r, MAPPED);
    CHECK(w.nlines == sizeof good_page / sizeof good_page[0], "%u lines, wanted %zu", w.nlines, sizeof good_page / sizeof good_page[0]);
    for (i = 0; i < w.nlines && i < sizeof good_page / sizeof good_page[0]; i++)
        CHECK(!strcmp(w.lines[i], good_page[i]), "line %u is '%s', wanted '%s'", i, w.lines[i], good_page[i]);
    CHECK(r.status == MAPPED && r.reason == R(NONE) && r.stores == 1 && r.desc == EXPECT_DESC && r.slot == SLOT0,
          "result %d %d %u %llx %llx", r.status, r.reason, r.stores, LL(r.desc), LL(r.slot));
    CHECK(W(w, SLOT0) == EXPECT_DESC, "the slot holds %llx", LL(W(w, SLOT0)));
    CHECK(W(w, SLOT0 + 8) == UINT64_C(0x0040000015401643) && W(w, SLOT0 + 8 * 511u) == UINT64_C(0x00400000155FF643), "a neighbour of the slot changed");
    /* Every effect, in order: the registers, the walk to the page's slot (four words), the AT of the page, the walk to the template (three words,
     * a block), the AT of the template, the AT of the table page for a write, the scan (the other 511 slots of the level-3 table, then the whole
     * root of 32 entries, the level-1 table and the level-2 table), the slot read once more, then the store and its publication, then the AT
     * check. A run of consecutive words of one page is one event whose second operand is its length. */
    CHECK(!strcmp(w.seq, "GRRRRARRRAARRRRRSCDTDIAA"), "the effects are '%s'", w.seq);
    if (!strcmp(w.seq, "GRRRRARRRAARRRRRSCDTDIAA")) {
        static const uint64_t operand[] = {0, L0E, L1E0, L2E, L3E, PAGE, L0E, L1E1, TPLE, TEMPLATE, T_L3A, SLOT0 + 8u, T_L0, T_L1, T_L2A, SLOT0, SLOT0,
                                           SLOT0, 0, PAGE, 0, 0, PAGE, PAGE};
        static const uint64_t second[] = {0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 511, 32, 512, 512, 1, EXPECT_DESC, 0, 0, 0, 0, 0, 0, 1};
        for (i = 0; i < 24; i++) {
            CHECK(w.arg[i] == operand[i], "effect %u (%c) has operand %llx, wanted %llx", i, w.seq[i], LL(w.arg[i]), LL(operand[i]));
            CHECK(w.arg2[i] == second[i], "effect %u (%c) has second operand %llx, wanted %llx", i, w.seq[i], LL(w.arg2[i]), LL(second[i]));
        }
    }
    CHECK(w.reads == 1575u, "%u reads, wanted 4 + 3 + 511 + 32 + 512 + 512 + 1", w.reads);
    CHECK(w.pend_stage == 6, "the publication was not whole (stage %d)", w.pend_stage);
    span = w.store_at - w.next_at;
    CHECK(span >= 8u * GOOD_FREQ && span < 8u * GOOD_FREQ + 3u * w.step, "%llu ticks from the NEXT line to the store, eight seconds are %llu",
          LL(span), LL(8u * GOOD_FREQ));
    /* The page is mapped for good: the model's own walk, seen whole, says Device, readable and writable, that page. */
    CHECK(model_at(&w, PAGE, 0, 0) == (UINT64_C(0x15400B00)) && model_at(&w, PAGE, 1, 0) == UINT64_C(0x15400B00), "the mapped page does not translate to itself");
    /* A second call does not write again and does not call the page unmapped. */
    after = w;
    reset_log(&w);
    CHECK(run_world(&w, &r) == REFUSED && r.reason == R(ENTRY_VALID) && w.applied == 0 && same_tables(&w, &after), "a second call: %s", last_line(&w));
    CHECK(has_line(&w, "PAYLOAD SMMUMAP REFUSED=ENTRY_VALID DESC=0X40000015400643"), "the second call names the descriptor it found");
}

/* ---- pure ---------------------------------------------------------------------------------------------------------------------- */

static void suite_pure(void)
{
    uint64_t t = TEMPLATE_BLOCK, d;
    unsigned i, index;
    CHECK(q1n1_smmumap_descriptor(PAGE, t) == EXPECT_DESC, "descriptor of the template: %llx", LL(q1n1_smmumap_descriptor(PAGE, t)));
    /* What is not copied: contiguous (52), DBM (51), software (58:55), and everything of the template's address. */
    d = q1n1_smmumap_descriptor(PAGE, t | (UINT64_C(1) << 52) | (UINT64_C(1) << 51) | (UINT64_C(15) << 55) | (UINT64_C(1) << 63) | UINT64_C(0xffff00000000));
    CHECK(d == EXPECT_DESC, "bits that are not attributes were copied: %llx", LL(d));
    CHECK(q1n1_smmumap_descriptor_ok(EXPECT_DESC, PAGE), "the good descriptor is refused");
    CHECK(!q1n1_smmumap_descriptor_ok(EXPECT_DESC ^ UINT64_C(0x1000), PAGE), "another page's address accepted");
    CHECK(!q1n1_smmumap_descriptor_ok(EXPECT_DESC & ~UINT64_C(2), PAGE), "a block/reserved type accepted");
    CHECK(!q1n1_smmumap_descriptor_ok(EXPECT_DESC & ~UINT64_C(1), PAGE), "an invalid entry accepted");
    for (i = 0; i < 64; i++) {
        uint64_t bit = UINT64_C(1) << i;
        int want = (EXPECT_DESC | bit) == EXPECT_DESC || (bit & (UINT64_C(0xffc) | (UINT64_C(3) << 53)));
        CHECK(q1n1_smmumap_descriptor_ok(EXPECT_DESC | bit, PAGE) == !!want, "bit %u of a descriptor is judged wrongly", i);
    }
    CHECK(!q1n1_smmumap_descriptor_ok(EXPECT_DESC, PAGE + 0x800) && !q1n1_smmumap_descriptor_ok(EXPECT_DESC, PAGE | (UINT64_C(1) << 50)),
          "an unaligned or too wide page address accepted");
    /* The template check: Device-nGnRnE or nGnRE only, never G or R; AF, writable, XN. */
    for (index = 0; index < 8; index++) {
        for (i = 0; i < 256; i++) {
            uint64_t mair = (uint64_t)i << (8 * index), desc = (UINT64_C(1) << 10) | (UINT64_C(1) << 54) | ((uint64_t)index << 2);
            int want = (i == 0x00 || i == 0x04) ? 0 : R(TEMPLATE_NOT_DEVICE);
            CHECK(q1n1_smmumap_template_check(mair, desc) == want, "MAIR byte %02x at index %u: %d", i, index, q1n1_smmumap_template_check(mair, desc));
        }
    }
    CHECK(q1n1_smmumap_template_check(GOOD_MAIR, TEMPLATE_BLOCK & ~(UINT64_C(1) << 10)) == R(TEMPLATE_NOT_USABLE), "AF clear accepted");
    CHECK(q1n1_smmumap_template_check(GOOD_MAIR, TEMPLATE_BLOCK | (UINT64_C(1) << 7)) == R(TEMPLATE_NOT_USABLE), "read-only accepted");
    CHECK(q1n1_smmumap_template_check(GOOD_MAIR, TEMPLATE_BLOCK & ~(UINT64_C(1) << 54)) == R(TEMPLATE_NOT_USABLE), "executable accepted");
    CHECK(q1n1_smmumap_template_check(GOOD_MAIR, TEMPLATE_BLOCK) == 0, "the good template is refused");
    /* The names: one per reason, all different, all in the page font, none UNKNOWN. */
    for (i = 0; i < R(COUNT); i++) {
        const char *name = q1n1_smmumap_reason_name((int)i);
        unsigned j;
        CHECK(strcmp(name, "UNKNOWN") != 0 && *name, "reason %u has no name", i);
        for (j = 0; j < i; j++) CHECK(strcmp(name, q1n1_smmumap_reason_name((int)j)) != 0, "reasons %u and %u share a name", i, j);
        for (const char *p = name; *p; p++) CHECK((*p >= 'A' && *p <= 'Z') || *p == '_' || (*p >= '0' && *p <= '9'), "name %s is outside the font", name);
    }
    CHECK(!strcmp(q1n1_smmumap_reason_name(R(COUNT)), "UNKNOWN") && !strcmp(q1n1_smmumap_reason_name(-1), "UNKNOWN"), "an unknown reason has a name");
    /* The allow-list is the one page, and it is the one the header names. */
    CHECK(q1n1_smmumap_spec_count == 1 && q1n1_smmumap_specs[0].page_pa == UINT64_C(0x15400000) && q1n1_smmumap_specs[0].template_pa == UINT64_C(0x70000000)
          && !strcmp(q1n1_smmumap_specs[0].name, "PCIE_SMMU0"), "the allow-list is not the one page");
    CHECK(Q1N1_SMMUMAP_TTBR0_EL2 == UINT64_C(0xA7F2E000) && Q1N1_SMMUMAP_WAIT_S == 8u, "the pinned root or the wait changed");
}

/* ---- template ------------------------------------------------------------------------------------------------------------------ */

static void suite_template(void)
{
    static const struct { const char *what; uint64_t clear, set; int reason; } bad[] = {
        {"AF clear", UINT64_C(1) << 10, 0, R(TEMPLATE_NOT_USABLE)},
        {"read-only at EL2", 0, UINT64_C(1) << 7, R(TEMPLATE_NOT_USABLE)},
        {"executable", UINT64_C(1) << 54, 0, R(TEMPLATE_NOT_USABLE)},
        {"Normal (index 1)", UINT64_C(7) << 2, UINT64_C(1) << 2, R(TEMPLATE_NOT_DEVICE)},
        {"Normal (index 2)", UINT64_C(7) << 2, UINT64_C(2) << 2, R(TEMPLATE_NOT_DEVICE)},
        {"Normal (index 3)", UINT64_C(7) << 2, UINT64_C(3) << 2, R(TEMPLATE_NOT_DEVICE)},
    };
    static const uint64_t mair_bad[] = {0x08, 0x0C, 0x01, 0x10, 0x44, 0xFF, 0x05, 0x84};
    unsigned i;
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        NEWWORLD(w);
        W(w, TPLE) = (TEMPLATE_BLOCK & ~bad[i].clear) | bad[i].set;
        GO(w, REFUSED, bad[i].reason, 0, bad[i].what);
    }
    for (i = 0; i < sizeof mair_bad / sizeof mair_bad[0]; i++) {
        NEWWORLD(w);
        w.regs.mair = (GOOD_MAIR & ~UINT64_C(0xff)) | mair_bad[i];
        GO(w, REFUSED, R(TEMPLATE_NOT_DEVICE), 0, "a MAIR byte that is not Device-nGnRnE or nGnRE");
    }
    {
        NEWWORLD(w);
        w.regs.mair = (GOOD_MAIR & ~UINT64_C(0xff)) | 0x04;
        GO(w, MAPPED, R(NONE), 1, "Device-nGnRE is accepted");
        CHECK(W(w, SLOT0) == EXPECT_DESC && model_at(&w, PAGE, 0, 0) >> 56 == 4, "nGnRE page");
    }
    {
        NEWWORLD(w);
        W(w, L1E1) = 0;
        GO(w, REFUSED, R(TEMPLATE_UNMAPPED), 0, "a hole above the template");
    }
    {
        NEWWORLD(w);
        W(w, TPLE) = 0;
        GO(w, REFUSED, R(TEMPLATE_UNMAPPED), 0, "no entry for the template");
    }
    {
        NEWWORLD(w);
        W(w, TPLE) = T_L3B | 3u;
        add_table(&w, T_L3B);
        W(w, T_L3B) = UINT64_C(0x0040000070000643);
        GO(w, MAPPED, R(NONE), 1, "a level-3 page as the template");
        CHECK(W(w, SLOT0) == EXPECT_DESC, "level 3 template: %llx", LL(W(w, SLOT0)));
    }
    {
        NEWWORLD(w);
        W(w, L1E1) = UINT64_C(0x0040000040000641);              /* a 1 GiB block: 0x70000000 is in it */
        GO(w, MAPPED, R(NONE), 1, "a level-1 block as the template");
        CHECK(W(w, SLOT0) == EXPECT_DESC, "level 1 template: %llx", LL(W(w, SLOT0)));
    }
    {
        NEWWORLD(w);
        W(w, TPLE) = TEMPLATE_BLOCK | (UINT64_C(1) << 52) | (UINT64_C(1) << 51) | (UINT64_C(15) << 55) | (UINT64_C(1) << 63);
        GO(w, MAPPED, R(NONE), 1, "a template with bits that are not attributes");
        CHECK(W(w, SLOT0) == EXPECT_DESC, "bits of the template that are not attributes were copied: %llx", LL(W(w, SLOT0)));
    }
    {
        NEWWORLD(w);
        W(w, TPLE) = TEMPLATE_BLOCK | (UINT64_C(1) << 5) | (UINT64_C(1) << 11);
        GO(w, MAPPED, R(NONE), 1, "NS and nG are attributes and are copied");
        CHECK(W(w, SLOT0) == (EXPECT_DESC | (UINT64_C(1) << 5) | (UINT64_C(1) << 11)), "NS and nG: %llx", LL(W(w, SLOT0)));
    }
    {
        NEWWORLD(w);
        force_at(&w, TEMPLATE, 0, 0, UINT64_C(0xFF00000070000B00));
        GO(w, REFUSED, R(AT_DISAGREES), 0, "the AT of the template says Normal where the walk says Device");
    }
    {
        NEWWORLD(w);
        force_at(&w, TEMPLATE, 0, 0, UINT64_C(0x0D));
        GO(w, REFUSED, R(AT_DISAGREES), 0, "the AT of the template faults where the walk finds a page");
    }
}

/* ---- entry, walk --------------------------------------------------------------------------------------------------------------- */

static void suite_entry(void)
{
    static const struct { const char *what; uint64_t value; int reason; } cases[] = {
        {"the page already mapped", EXPECT_DESC, R(ENTRY_VALID)},
        {"another page there", UINT64_C(0x0040000015401643), R(ENTRY_VALID)},
        {"an invalid entry that is not zero", UINT64_C(0x0040000015400642), R(ENTRY_NOT_ZERO)},
        {"only the type bits of an invalid entry", UINT64_C(2), R(ENTRY_NOT_ZERO)},
        {"a reserved level-3 form", UINT64_C(1), R(NO_L3_TABLE)},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        NEWWORLD(w);
        W(w, SLOT0) = cases[i].value;
        GO(w, REFUSED, cases[i].reason, 0, cases[i].what);
        /* Refused at the walk, before the template, the scan and the wait: the later checks (the slot read once more, the scan) would refuse the same
         * worlds for the same reason, eight seconds and 1,500 reads later. */
        CHECK(!has_line(&w, "PAYLOAD SMMUMAP TEMPLATE") && !has_line(&w, "PAYLOAD SMMUMAP TABLE") && !has_line(&w, "PAYLOAD SMMUMAP NEXT"), "%s: refused after the walk", cases[i].what);
    }
}

static void suite_walk(void)
{
    static const struct { const char *what; uint64_t pa; uint64_t value; int reason; } cases[] = {
        {"L2 is a 2 MiB block", L2E, UINT64_C(0x0040000015400641), R(NO_L3_TABLE)},
        {"L2 is a hole", L2E, 0, R(NO_L3_TABLE)},
        {"L1 is a hole", L1E0, 0, R(NO_L3_TABLE)},
        {"L1 is a 1 GiB block", L1E0, UINT64_C(0x0040000000000641), R(NO_L3_TABLE)},
        {"L0 is a hole", L0E, 0, R(NO_L3_TABLE)},
        {"L0 holds a block form", L0E, UINT64_C(0x0040000000000641), R(NO_L3_TABLE)},
        {"a table beyond the physical address size", L2E, (UINT64_C(1) << 45) | 3u, R(TABLE_ADDRESS)},
        {"every control bit set on the table descriptor of L2", L2E, (UINT64_C(0x1f) << 59) | T_L3A | 3u, R(UPPER_FLAGS)},
    };
    unsigned i, level, bit;
    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        NEWWORLD(w);
        W(w, cases[i].pa) = cases[i].value;
        GO(w, REFUSED, cases[i].reason, 0, cases[i].what);
    }
    for (i = 0; i < 4; i++) {
        static const uint64_t where[] = {L0E, L1E0, L2E, L3E};
        NEWWORLD(w);
        w.read_fault[w.read_faults++] = where[i];
        GO(w, REFUSED, R(WALK_FAULT), 0, "a read of the walk aborts");
        {
            char want[48];
            snprintf(want, sizeof want, "PAYLOAD SMMUMAP REFUSED=WALK_FAULT LEVEL=0X%u", i);     /* the level of the read that aborted, not of the last that worked */
            CHECK(has_line(&w, want) && w.reads == i + 1, "the abort at level %u: %u reads, '%s'", i, w.reads, last_line(&w));
        }
    }
    for (level = 0; level < 3; level++) {
        static const uint64_t where[] = {L0E, L1E0, L2E};
        for (bit = 59; bit <= 63; bit++) {
            NEWWORLD(w);
            W(w, where[level]) |= UINT64_C(1) << bit;
            GO(w, REFUSED, R(UPPER_FLAGS), 0, "a hierarchical control bit of a table descriptor");
        }
    }
    {
        NEWWORLD(w);
        W(w, L2E) = T_L3A | 3u | (UINT64_C(0xf) << 55);        /* software bits 58:55 are not controls */
        GO(w, MAPPED, R(NONE), 1, "bits 58:55 of a table descriptor are not controls");
    }
    {
        NEWWORLD(w);
        w.regs.tcr = (w.regs.tcr & ~UINT64_C(0x70000));        /* PS = 32 bits: a table address of 2^33 is beyond it */
        W(w, L2E) = (T_L3A + (UINT64_C(1) << 33)) | 3u;
        GO(w, REFUSED, R(TABLE_ADDRESS), 0, "the table address is checked against PS");
    }
    {
        NEWWORLD(w);                                          /* a table far from every descriptor of the map: proven not RAM before it is loaded from */
        W(w, L2E) = (T_L3A + (UINT64_C(1) << 33)) | 3u;
        GO(w, REFUSED, R(TABLE_NOT_RAM), 0, "a table that no descriptor of the map holds, with PS 44 bits");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP REFUSED=TABLE_NOT_RAM TABLE=0X2A7F31000 TYPE=0XFF LEVEL=0X3") && w.reads == 3,
              "the line '%s' after %u loads", find_line(&w, "PAYLOAD SMMUMAP REFUSED"), w.reads);
    }
    {
        NEWWORLD(w);                                          /* RAM by the map that the model holds no table in: the guarded load itself aborts */
        W(w, L2E) = UINT64_C(0xA7F36000) | 3u;
        GO(w, REFUSED, R(WALK_FAULT), 0, "a table in RAM that the model does not hold");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP REFUSED=WALK_FAULT LEVEL=0X3") && w.reads == 4, "the line '%s' after %u loads", find_line(&w, "PAYLOAD SMMUMAP REFUSED"), w.reads);
    }
    {
        /* The L3 table is also a table of a higher level of the path to the page (or of the path to the template): the descriptor
         * written there would be read as a table descriptor of that level. For the root and the L1 table, slot 0 is the path's own
         * valid descriptor, so the entry is refused first. */
        static const uint64_t shared[] = {T_L2A, T_L2B}, upper[] = {T_L1, T_L0};
        static const char *const wanted[] = {"PAYLOAD SMMUMAP REFUSED=TABLE_SHARED TABLE=0XA7F30000 LEVEL=0X2", "PAYLOAD SMMUMAP REFUSED=TABLE_SHARED TABLE=0XA7F32000 LEVEL=0X2"};
        for (i = 0; i < 2; i++) {
            NEWWORLD(w);
            W(w, L2E) = shared[i] | 3u;
            GO(w, REFUSED, R(TABLE_SHARED), 0, "the level-3 table is a table of another level of the path");
            /* By the walks and at the level of the shared table, before the scan: the scan would find the same world through the level-1 table
             * (and name that level), after the table page was asked for a write and 1,567 words were read. */
            CHECK(has_line(&w, wanted[i]) && !has_line(&w, "PAYLOAD SMMUMAP TABLE VALID"), "shared %u is refused by the scan, not by the walks: %s", i, find_line(&w, "PAYLOAD SMMUMAP REFUSED"));
        }
        for (i = 0; i < 2; i++) {
            NEWWORLD(w);
            W(w, L2E) = upper[i] | 3u;
            GO(w, REFUSED, R(ENTRY_VALID), 0, "the level-3 table is a higher table of the path");
        }
    }
}

/* ---- table, at ------------------------------------------------------------------------------------------------------------------ */

static void suite_table(void)
{
    static const struct { const char *what; uint64_t clear, set, replace; } cases[] = {
        {"the table page is read-only", 0, UINT64_C(1) << 7, 0},
        {"the table page is Device", UINT64_C(7) << 2, 0, 0},
        {"the table page has no access flag", UINT64_C(1) << 10, 0, 0},
        {"the table page is not mapped", 0, 0, 1},
    };
    unsigned i;
    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        NEWWORLD(w);
        W(w, RAME) = cases[i].replace ? 0 : (RAM_BLOCK & ~cases[i].clear) | cases[i].set;
        GO(w, REFUSED, R(TABLE_NOT_WRITABLE), 0, cases[i].what);
    }
    {
        NEWWORLD(w);
        W(w, RAME) = UINT64_C(0x00400000A7C0074D);               /* maps the table's address to another page */
        GO(w, REFUSED, R(TABLE_NOT_WRITABLE), 0, "the table page's address maps to another page");
    }
    {
        NEWWORLD(w);
        force_at(&w, T_L3A, 1, 0, UINT64_C(0x0F));
        GO(w, REFUSED, R(TABLE_NOT_WRITABLE), 0, "the AT of the table page for a write says permission fault");
    }
    {
        NEWWORLD(w);
        W(w, RAME) = (RAM_BLOCK & ~(UINT64_C(7) << 2)) | (UINT64_C(1) << 2);        /* Normal non-cacheable: ordinary memory */
        GO(w, MAPPED, R(NONE), 1, "a Normal non-cacheable table page is ordinary memory");
    }
    {
        NEWWORLD(w);
        w.regs.sctlr |= UINT64_C(1) << 19;
        GO(w, MAPPED, R(NONE), 1, "WXN is reported and the AT decides");
    }
}

static void suite_at(void)
{
    uint64_t other = UINT64_C(0x15401B00), device_normal = UINT64_C(0xFF00000015400B00);
    {
        NEWWORLD(w);
        force_at(&w, PAGE, 0, 1, UINT64_C(0x15400B00));
        GO(w, REFUSED, R(AT_DISAGREES), 0, "the AT says the page is already mapped");
    }
    {
        static const unsigned fst[] = {0x06, 0x0D, 0x0B, 0x04, 0x0F, 0x05};     /* L2 translation, permission, access flag, L0, L1 translation */
        for (unsigned i = 0; i < sizeof fst / sizeof fst[0]; i++) {
            NEWWORLD(w);
            force_at(&w, PAGE, 0, 1, fault_par(fst[i]));
            GO(w, REFUSED, R(AT_DISAGREES), 0, "the AT says a fault that is not a level-3 translation fault");
        }
    }
    {
        /* PAR_EL1 with F = 1: bit 8 is PTW and bit 9 is S; either one, or both, says a stage-2 fault, which the EL2 regime cannot have. */
        static const uint64_t stage2[] = {UINT64_C(1) << 8, UINT64_C(1) << 9, UINT64_C(3) << 8};
        for (unsigned i = 0; i < sizeof stage2 / sizeof stage2[0]; i++) {
            NEWWORLD(w);
            force_at(&w, PAGE, 0, 1, fault_par(7) | stage2[i]);
            GO(w, REFUSED, R(AT_DISAGREES), 0, "the AT says a level-3 fault with a stage-2 bit (PTW or S) set");
        }
    }
    {
        NEWWORLD(w);
        force_at(&w, PAGE, 0, 2, other);
        GO(w, REFUSED, R(CHECK_FAILED), 2, "after the store the page translates to another page");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP REFUSED=CHECK_FAILED UNDONE=1") && w.nlines == 10 && W(w, SLOT0) == 0, "put back: %u lines", w.nlines);
        CHECK(strlen(w.seq) >= 15 && !strcmp(w.seq + strlen(w.seq) - 15, "SCDTDIAASCDTDIA"), "the put-back is published like the store: %s", w.seq);
    }
    {
        NEWWORLD(w);
        force_at(&w, PAGE, 1, 2, UINT64_C(0x0F));
        GO(w, REFUSED, R(CHECK_FAILED), 2, "after the store the page is not writable");
    }
    {
        NEWWORLD(w);
        force_at(&w, PAGE, 1, 2, other);
        GO(w, REFUSED, R(CHECK_FAILED), 2, "after the store a write reaches another page");
    }
    {
        NEWWORLD(w);
        force_at(&w, PAGE, 0, 2, device_normal);
        GO(w, REFUSED, R(CHECK_FAILED), 2, "after the store the attributes are not the template's");
        CHECK(strstr(find_line(&w, "PAYLOAD SMMUMAP CHECK"), "ATTR=DIFFERENT"), "the check line for different attributes: %s", find_line(&w, "PAYLOAD SMMUMAP CHECK"));
    }
    {
        /* The page translates to itself with the template's memory type, and the shareability or the NS bit differs: PAR_ATTR_MASK holds more than
         * the type. The template's own PAR is 0x70000B00 (outer shareable, NS, bit 11). */
        static const uint64_t flips[] = {UINT64_C(1) << 9, UINT64_C(1) << 8, UINT64_C(1) << 7, UINT64_C(3) << 7};
        for (unsigned i = 0; i < sizeof flips / sizeof flips[0]; i++) {
            NEWWORLD(w);
            force_at(&w, PAGE, 0, 2, UINT64_C(0x15400B00) ^ flips[i]);
            GO(w, REFUSED, R(CHECK_FAILED), 2, "after the store the shareability or NS differs from the template's");
            CHECK(strstr(find_line(&w, "PAYLOAD SMMUMAP CHECK"), "ATTR=DIFFERENT") && W(w, SLOT0) == 0, "flip %u: %s", i, find_line(&w, "PAYLOAD SMMUMAP CHECK"));
        }
    }
}

/* The status of the two last cases is UNSAFE, not REFUSED: a descriptor may still be in place. */
static void suite_unsafe(void)
{
    {
        NEWWORLD(w);
        force_at(&w, PAGE, 0, 3, UINT64_C(0x15400B00));
        force_at(&w, PAGE, 0, 2, UINT64_C(0x15401B00));
        GO(w, Q1N1_SMMUMAP_UNSAFE, R(ROLLBACK_FAILED), 2, "the page still translates after the put-back");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP REFUSED=ROLLBACK_FAILED SLOT=0XA7F31000") && W(w, SLOT0) == 0, "unsafe lines");
    }
    {
        NEWWORLD(w);
        force_at(&w, PAGE, 0, 2, UINT64_C(0x15401B00));
        w.store_fault_at = 2;
        GO(w, Q1N1_SMMUMAP_UNSAFE, R(ROLLBACK_FAILED), 1, "the put-back store aborts");
        CHECK(W(w, SLOT0) == EXPECT_DESC, "the descriptor stays and the model agrees");
    }
}

/* ---- regs, spec, store ---------------------------------------------------------------------------------------------------------- */

static void suite_regs(void)
{
    static const struct { const char *what; int field; uint64_t clear, set; int reason; } cases[] = {
        {"another TTBR0_EL2", 0, ~UINT64_C(0), UINT64_C(0xA7F2F000), R(TTBR0_UNPINNED)},
        {"the pinned root with CnP", 0, 0, UINT64_C(0xA7F2E001), R(TTBR0_UNPINNED)},
        {"E2H set", 4, 0, UINT64_C(1) << 34, R(REGIME)},
        {"MMU off", 3, 1, 0, R(REGIME)},
        {"big-endian walks", 3, 0, UINT64_C(1) << 25, R(REGIME)},
        {"a 64 KiB granule", 1, UINT64_C(3) << 14, UINT64_C(1) << 14, R(REGIME)},
        {"a 16 KiB granule", 1, UINT64_C(3) << 14, UINT64_C(2) << 14, R(REGIME)},
        {"T0SZ 15", 1, 63, 15, R(REGIME)},
        {"T0SZ 40", 1, 63, 40, R(REGIME)},
        {"T0SZ 63", 1, 63, 63, R(REGIME)},
    };
    unsigned i;
    for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        NEWWORLD(w);
        uint64_t *reg[] = {&w.regs.ttbr0, &w.regs.tcr, &w.regs.mair, &w.regs.sctlr, &w.regs.hcr};
        *reg[cases[i].field] = (*reg[cases[i].field] & ~cases[i].clear) | cases[i].set;
        GO(w, REFUSED, cases[i].reason, 0, cases[i].what);
        CHECK(w.reads == 0 && !strchr(w.seq, 'A'), "%s: the tables were asked something before the regime was judged: %s", cases[i].what, w.seq);
        CHECK(has_line(&w, "PAYLOAD SMMUMAP REGS "), "%s: the registers were not printed", cases[i].what);
    }
    {
        NEWWORLD(w);                                          /* a 39-bit VA: the walk starts at level 1, in TTBR0's table */
        struct table *root = find_table(&w, T_L0);
        w.regs.tcr = (w.regs.tcr & ~UINT64_C(63)) | 25u;
        root->word[0] = T_L2A | 3u;
        root->word[1] = T_L2B | 3u;
        root->word[2] = T_L2C | 3u;
        GO(w, MAPPED, R(NONE), 1, "a level-1 start of the walk");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP TABLE VALID=2 REFS=-/0/1"), "the scan of a walk that starts at level 1: %s", find_line(&w, "PAYLOAD SMMUMAP TABLE"));
    }
    {
        NEWWORLD(w);
        w.regs.tcr = (w.regs.tcr & ~UINT64_C(63)) | 39u;       /* a 25-bit VA: the page is beyond it */
        GO(w, REFUSED, R(NO_L3_TABLE), 0, "the page is beyond the VA range");
    }
    {
        NEWWORLD(w);
        w.regs.ttbr0 = w.regs.tcr = w.regs.mair = w.regs.sctlr = w.regs.hcr = ~UINT64_C(0);
        GO(w, REFUSED, R(TTBR0_UNPINNED), 0, "all ones in every register");
    }
}

static void suite_spec(void)
{
    static const struct q1n1_smmumap_spec specs[] = {
        {"OTHER_PAGE", PAGE + 0x1000, TEMPLATE}, {"OTHER_TEMPLATE", PAGE, TEMPLATE + 0x1000}, {"SAME", PAGE, PAGE},
        {"ZERO", 0, 0}, {"SWAPPED", TEMPLATE, PAGE}, {"WIDE", PAGE | (UINT64_C(1) << 40), TEMPLATE},
    };
    for (unsigned i = 0; i < sizeof specs / sizeof specs[0]; i++) {
        NEWWORLD(w);
        struct q1n1_smmumap_env env;
        struct q1n1_smmumap_result r;
        make_env(&w, &env);
        w_before = w;
        memset(&r, 0xA5, sizeof r);
        CHECK(q1n1_smmumap_page(&env, &specs[i], &r) == REFUSED && r.reason == R(SPEC), "%s was accepted", specs[i].name);
        CHECK(w.seq[0] == 0 && w.applied == 0 && same_tables(&w, &w_before), "%s: the machine was touched: %s", specs[i].name, w.seq);
        CHECK(w.nlines == 3 && has_line(&w, "PAYLOAD SMMUMAP REFUSED=SPEC PAGE=0X") && !strncmp(last_line(&w), "PAYLOAD SMMUMAP DONE MAPPED=0 STORES=0", 38),
              "%s: lines %u, last '%s'", specs[i].name, w.nlines, last_line(&w));
    }
    {
        struct world w;
        struct q1n1_smmumap_env env;
        world_good(&w);
        make_env(&w, &env);
        CHECK(q1n1_smmumap_page(&env, &q1n1_smmumap_specs[0], NULL) == MAPPED, "the listed page is not mapped when no result is wanted");
    }
}

static void suite_store(void)
{
    {
        NEWWORLD(w);
        w.store_fault_at = 1;
        GO(w, REFUSED, R(STORE_FAULT), 0, "the store aborts");
        CHECK(w.attempts == 1 && W(w, SLOT0) == 0 && !strchr(w.seq, 'C') && !strchr(w.seq, 'T'), "an aborted store is published or left something: %s", w.seq);
        CHECK(w.nlines == 9 && has_line(&w, "PAYLOAD SMMUMAP NEXT STORE AFTER 8 S") && has_line(&w, "PAYLOAD SMMUMAP REFUSED=STORE_FAULT SLOT=0X"),
              "the lines around the abort: %u", w.nlines);
    }
    {
        /* The slot is read as zero in the walk and stored eight seconds later: it is read once more just before the store, and what another
         * agent wrote in the meantime is not overwritten. */
        static const uint64_t pokes[] = {UINT64_C(0x0040000015401643), 1, 2, ~UINT64_C(0)};
        for (unsigned i = 0; i < sizeof pokes / sizeof pokes[0]; i++) {
            NEWWORLD(w);
            w.poke_pa = SLOT0;
            w.poke_val = pokes[i];
            w.poke_at = 100;
            GO(w, REFUSED, R(ENTRY_NOT_ZERO), 0, "the slot is written while the step waits");
            CHECK(W(w, SLOT0) == pokes[i], "the step changed what another agent wrote (%llx)", LL(W(w, SLOT0)));
            CHECK(!strchr(w.seq, 'S') && w.events && w.seq[w.events - 1] == 'R' && w.arg[w.events - 1] == SLOT0,
                  "the re-read of the slot is not the last effect before the refusal: %s", w.seq);
            CHECK(has_line(&w, "PAYLOAD SMMUMAP REFUSED=ENTRY_NOT_ZERO DESC=0X"), "the refusal does not name the descriptor it found");
        }
    }
    {
        NEWWORLD(w);                                       /* another agent writes zero: the slot is still zero and the step goes on */
        w.poke_pa = SLOT0;
        w.poke_val = 0;
        w.poke_at = 100;
        GO(w, MAPPED, R(NONE), 1, "the slot is written with zero while the step waits");
    }
    {
        NEWWORLD(w);
        w.late_fault = SLOT0;                              /* the walk read it before the NEXT line; the read just before the store aborts */
        GO(w, REFUSED, R(WALK_FAULT), 0, "the read of the slot just before the store aborts");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP REFUSED=WALK_FAULT LEVEL=0X3") && !strchr(w.seq, 'S'), "the abort of the re-read: %s", w.seq);
    }
}

/* ---- counter, publish ------------------------------------------------------------------------------------------------------------ */

static void suite_counter(void)
{
    static const uint64_t freqs[] = {0, 5, 999999, 1000000001, UINT64_C(3000000000), 1000000, 48000000, 1000000000};
    unsigned i;
    {
        NEWWORLD(w);
        w.no_counter = 1;
        GO(w, REFUSED, R(NO_COUNTER), 0, "no counter");
        CHECK(w.next_seen && has_line(&w, "PAYLOAD SMMUMAP NEXT STORE AFTER 8 S"), "the NEXT line comes before the refusal");
    }
    {
        NEWWORLD(w);
        w.counter_mode = CM_STUCK;
        GO(w, REFUSED, R(COUNTER_UNUSABLE), 0, "a counter that stands still");
        CHECK(w.calls < 2100000u, "a stuck counter was read %llu times", LL(w.calls));
    }
    for (i = 1; i < 40; i += 13) {
        NEWWORLD(w);
        w.counter_mode = CM_BACKWARD;
        w.back_after = i;
        GO(w, REFUSED, R(COUNTER_UNUSABLE), 0, "a counter that goes back");
    }
    for (i = 0; i < sizeof freqs / sizeof freqs[0]; i++) {
        NEWWORLD(w);
        uint64_t f = (freqs[i] < 1000000u || freqs[i] > 1000000000u) ? GOOD_FREQ : freqs[i], span;
        w.freq = freqs[i];
        w.step = f / STEP_DIVISOR;
        GO(w, MAPPED, R(NONE), 1, "a counter frequency in or out of the window");
        span = w.store_at - w.next_at;
        CHECK(span >= 8u * f && span < 8u * f + 3u * w.step, "frequency %llu: the wait was %llu ticks, eight seconds are %llu", LL(freqs[i]), LL(span), LL(8u * f));
    }
#ifdef TEST_SPIN_MAX
    {
        NEWWORLD(w);
        w.step = GOOD_FREQ / 200000u;                              /* 96 ticks: eight seconds need 1.6 million reads, the bound is 1000 */
        GO(w, REFUSED, R(SPIN_BOUND), 0, "a counter that moves too slowly for the bound");
        CHECK(w.calls <= TEST_SPIN_MAX + 2u && w.calls >= TEST_SPIN_MAX, "the bound was %llu reads, not %u", LL(w.calls), TEST_SPIN_MAX);
    }
    {
        NEWWORLD(w);
        w.counter_mode = CM_STUCK;
        GO(w, REFUSED, R(COUNTER_UNUSABLE), 0, "a stuck counter is not the bound");
        CHECK(w.calls <= 102u, "a stuck counter was read %llu times with the lowered count", LL(w.calls));
    }
#else
    {
        NEWWORLD(w);
        w.step = GOOD_FREQ / 200000u;                              /* slow, and still inside the real bound of 2^32 - 1 reads */
        GO(w, MAPPED, R(NONE), 1, "a slow counter inside the bound");
        CHECK(w.calls >= 1599999u, "the slow counter was read %llu times", LL(w.calls));
    }
#endif
}

static void suite_publish(void)
{
    /* Each step of the publication left out (the model ignores it), one at a time: the page is then not visible to the walker, the check says
     * so, and the put-back cannot be proven either, which is UNSAFE and says so. The clean of the slot's line is the one the walk does
     * not need on this model's coherent walker; the model is the strict one (docs/SP11-PAYLOAD-SMMUMAP.md, "The publication"). */
    for (unsigned bit = 0; bit < 5; bit++) {
        NEWWORLD(w);
        w.drop = 1u << bit;
        GO(w, Q1N1_SMMUMAP_UNSAFE, R(ROLLBACK_FAILED), 2, "a step of the publication is missing");
        CHECK(has_line(&w, "PAYLOAD SMMUMAP CHECK PARR=0X") && strstr(find_line(&w, "PAYLOAD SMMUMAP CHECK"), "ATTR=DIFFERENT") != NULL,
              "a missing step %u was not seen by the check", bit);
    }
    {
        NEWWORLD(w);
        w.drop = 0;
        GO(w, MAPPED, R(NONE), 1, "the whole publication");
    }
}

/* ---- map, ram, scan, serror: tools/test-q1n1-sp11-payload-smmumap-scan.c ---------------------------------------------------------------- */

/* ---- fuzz ----------------------------------------------------------------------------------------------------------------------- */

static uint64_t rng_state = UINT64_C(0x9E3779B97F4A7C15);
static uint64_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

/* The leaf descriptor for `va` by the model's own walk, 0 if none. */
static uint64_t model_leaf(struct world *w, uint64_t va)
{
    unsigned bits = 64u - (unsigned)(w->regs.tcr & 63u), level = bits > 39u ? 0u : bits > 30u ? 1u : 2u;
    uint64_t table = w->regs.ttbr0 & ADDR;
    for (;; level++) {
        uint64_t at = table + ((va >> (39u - 9u * level)) & 511u) * 8u, desc;
        if (!find_table(w, at)) return 0;
        desc = *word_ptr(w, at);
        if (!(desc & 1u)) return 0;
        if (level < 3u && (desc & 3u) == 3u) { table = desc & ADDR; continue; }
        return desc;
    }
}

/* The table bases of the walk to `va` by the model's own walk: base[level], 0 where the walk did not reach; 1 when it ends in a level-3 table. */
static int model_path(struct world *w, uint64_t va, uint64_t base[4])
{
    unsigned bits = 64u - (unsigned)(w->regs.tcr & 63u), level = bits > 39u ? 0u : bits > 30u ? 1u : 2u;
    uint64_t table = w->regs.ttbr0 & ADDR;
    for (unsigned i = 0; i < 4; i++) base[i] = 0;
    for (;; level++) {
        uint64_t at = table + ((va >> (39u - 9u * level)) & 511u) * 8u;
        base[level] = table;
        if (!find_table(w, at)) return 0;
        if (level == 3u) return 1;
        if ((*word_ptr(w, at) & 3u) != 3u) return 0;
        table = *word_ptr(w, at) & ADDR;
    }
}

/* How many entries of the table at `base` are table descriptors that point at `target`. */
static unsigned model_refs(struct world *w, uint64_t base, uint64_t target)
{
    unsigned n = 0;
    struct table *t = find_table(w, base);
    for (unsigned i = 0; t && i < 512; i++) n += (t->word[i] & 3u) == 3u && (t->word[i] & ADDR) == target;
    return n;
}

static void suite_fuzz(void)
{
    static const uint64_t words[] = {L0E, L1E0, L1E1, L2E, L3E, TPLE, RAME, SLOT0 + 8, T_L0 + 24u, T_L1 + 56u, T_L2A + 40u, SLOT0 + 16u};
    const unsigned nwords = sizeof words / sizeof words[0];
    unsigned n, mapped = 0, plain = 0, undone = 0, unsafe = 0, by_reason[R(COUNT)] = {0};
    for (n = 0; n < 6000; n++) {
        static struct world w, before;
        struct q1n1_smmumap_result r;
        unsigned k, hits = 1 + (unsigned)(rnd() % 3);
        uint64_t slot;
        int status;
        world_good(&w);
        for (k = 0; k < hits; k++) {
            uint64_t pick = rnd() % 16, bit = rnd() % 64, v = rnd();
            switch (pick) {
            case 0: case 1: *word_ptr(&w, words[rnd() % nwords]) ^= UINT64_C(1) << bit; break;
            case 2: *word_ptr(&w, words[rnd() % nwords]) = v; break;
            case 3: { uint64_t *reg[] = {&w.regs.ttbr0, &w.regs.tcr, &w.regs.mair, &w.regs.sctlr, &w.regs.hcr}; *reg[rnd() % 5] ^= UINT64_C(1) << bit; break; }
            case 4: if (w.read_faults < 4) w.read_fault[w.read_faults++] = words[rnd() % nwords]; break;
            case 5: { static const uint64_t vas[] = {PAGE, TEMPLATE, T_L3A}; force_at(&w, vas[rnd() % 3], (int)(rnd() & 1), (int)(rnd() % 4), v); break; }
            case 6: w.store_fault_at = 1 + (unsigned)(rnd() % 2); break;
            case 7: w.drop = 1u << (rnd() % 5); break;
            case 8: if (rnd() % 200 == 0) w.counter_mode = (int)(1 + rnd() % 2), w.back_after = rnd() % 50; break;
            case 9: w.ext[4].type = (unsigned)(rnd() % 16); build_map(&w); break;
            case 10: w.ext[4].pages = 1 + rnd() % 231; build_map(&w); break;
            case 11: w.poke_pa = SLOT0; w.poke_val = (rnd() & 1) ? 0 : v; w.poke_at = 1 + rnd() % 200; break;
            case 12: w.late_fault = words[rnd() % nwords]; break;
            case 13: w.map_mode = (int)(1 + rnd() % 2); build_map(&w); break;
            case 14: {                                                  /* any kind of descriptor over one page of one of the tables */
                static const uint64_t table_pages[] = {T_L0, T_L1, T_L2A, T_L3A, T_L2B, T_L2C};
                if (w.extents < MAX_EXTENTS) { add_extent(&w, table_pages[rnd() % 6], 1u, (unsigned)(rnd() % 16)); build_map(&w); }
                break;
            }
            default: *word_ptr(&w, words[rnd() % nwords]) = T_L3A | 3u; break;      /* an entry that points at the level-3 table */
            }
        }
        before = w;
        status = run_world(&w, &r);
        common_checks(&w, &before, &r, status);
        by_reason[(unsigned)r.reason < (unsigned)R(COUNT) ? (unsigned)r.reason : 0u]++;
        if (w.nlines > g_lines_max) g_lines_max = w.nlines;
        slot = model_slot(&before, PAGE);
        /* Nothing but the page's level-3 slot changed, whatever happened. */
        for (k = 0; k < w.tables; k++) {
            for (unsigned i = 0; i < 512; i++)
                if (w.t[k].word[i] != before.t[k].word[i]) CHECK(w.t[k].base + 8u * i == slot, "world %u: a word other than the slot changed (%llx)", n, LL(w.t[k].base + 8u * i));
        }
        CHECK(w.attempts <= 2, "world %u: %u store attempts", n, w.attempts);
        if (status == MAPPED) {
            uint64_t leaf = model_leaf(&w, TEMPLATE), want = (leaf & (UINT64_C(0xffc) | (UINT64_C(3) << 53))) | PAGE | 3u;
            uint64_t par_r = model_at(&w, PAGE, 0, 0), par_w = model_at(&w, PAGE, 1, 0), path[4], tpath[4];
            unsigned attr = (unsigned)(par_r >> 56), first_store = 0;
            mapped++;
            CHECK(w.applied == 1 && slot && *word_ptr(&w, slot) == want, "world %u: the descriptor is %llx, the template's attributes give %llx", n, LL(slot ? *word_ptr(&w, slot) : 0), LL(want));
            CHECK(!(par_r & 1u) && !(par_w & 1u) && (par_r & ADDR) == PAGE && (par_w & ADDR) == PAGE, "world %u: the page does not translate to itself", n);
            CHECK(attr == 0x00u || attr == 0x04u, "world %u: the mapped page is memory type %02x, not Device-nGnRnE or nGnRE", n, attr);
            CHECK(w.regs.ttbr0 == Q1N1_SMMUMAP_TTBR0_EL2 && !(w.regs.hcr >> 34 & 1u) && (w.regs.sctlr & 1u) && !(w.regs.sctlr >> 25 & 1u) && !(w.regs.tcr >> 14 & 3u),
                  "world %u: mapped under a regime that is not the pinned one", n);
            /* Every table page of both walks is RAM by the map (written another way), and no entry of the root or of the level-1 table points at the
             * level-3 table. Whatever the world, no load of any run touched a page that is not RAM (common_checks). */
            CHECK(model_path(&w, PAGE, path), "world %u: the model's walk does not end at a level-3 table", n);
            model_path(&w, TEMPLATE, tpath);
            for (unsigned lv = 0; lv < 4; lv++) {
                CHECK(!path[lv] || model_ram(&w, path[lv]), "world %u: the level-%u table %llx of the page is not RAM by the model's map", n, lv, LL(path[lv]));
                CHECK(!tpath[lv] || model_ram(&w, tpath[lv]), "world %u: the level-%u table %llx of the template is not RAM by the model's map", n, lv, LL(tpath[lv]));
            }
            CHECK(!path[0] || model_refs(&w, path[0], path[3]) == 0, "world %u: an entry of the root points at the level-3 table", n);
            CHECK(!path[1] || model_refs(&w, path[1], path[3]) == 0, "world %u: an entry of the level-1 table points at the level-3 table", n);
            /* The store is immediately preceded by a read of the very slot: the slot is read once more just before it is written. */
            while (first_store < w.events && w.seq[first_store] != 'S') first_store++;
            CHECK(first_store > 0 && first_store < w.events && w.seq[first_store - 1] == 'R' && w.arg[first_store - 1] == slot && w.arg2[first_store - 1] == 1,
                  "world %u: the store is not preceded by a read of the slot", n);
        } else if (status == Q1N1_SMMUMAP_UNSAFE) {
            unsafe++;
            CHECK(w.applied >= 1, "world %u: UNSAFE with no store", n);
        } else if (w.applied == 2) {
            undone++;
            CHECK(r.reason == R(CHECK_FAILED), "world %u: two stores and the reason %s", n, q1n1_smmumap_reason_name(r.reason));
        } else {
            plain++;
            CHECK(w.applied == 0, "world %u: refused with %u stores and the reason %s", n, w.applied, q1n1_smmumap_reason_name(r.reason));
        }
    }
    CHECK(mapped >= 500 && plain >= 600 && undone >= 5 && unsafe >= 5, "the fuzz reached too few outcomes: %u mapped, %u refused, %u put back, %u unsafe", mapped, plain, undone, unsafe);
    /* The refusals of the memory map, the scans, the re-read and the stage-2 bits are reached by random worlds, not only by the cases above. */
    CHECK(by_reason[R(TABLE_NOT_RAM)] > 0 && by_reason[R(SCAN_FAULT)] > 0 && by_reason[R(TABLE_SHARED)] > 0 && by_reason[R(ENTRY_NOT_ZERO)] > 0 &&
          by_reason[R(WALK_FAULT)] > 0 && by_reason[R(AT_DISAGREES)] > 0 && by_reason[R(CHECK_FAILED)] > 0,
          "the fuzz did not reach every refusal: RAM %u, scan %u, shared %u, not zero %u, walk fault %u, AT %u, check %u", by_reason[R(TABLE_NOT_RAM)],
          by_reason[R(SCAN_FAULT)], by_reason[R(TABLE_SHARED)], by_reason[R(ENTRY_NOT_ZERO)], by_reason[R(WALK_FAULT)], by_reason[R(AT_DISAGREES)], by_reason[R(CHECK_FAILED)]);
    fprintf(stderr, "FUZZ worlds=%u mapped=%u refused=%u put_back=%u unsafe=%u not_ram=%u scan_fault=%u shared=%u not_zero=%u\n", n, mapped, plain, undone, unsafe,
            by_reason[R(TABLE_NOT_RAM)], by_reason[R(SCAN_FAULT)], by_reason[R(TABLE_SHARED)], by_reason[R(ENTRY_NOT_ZERO)]);
}

/* ---- main ---------------------------------------------------------------------------------------------------------------------- */

static const struct { const char *name; void (*run)(void); } suites[] = {
    {"good", suite_good}, {"pure", suite_pure}, {"template", suite_template}, {"entry", suite_entry}, {"walk", suite_walk},
    {"table", suite_table}, {"at", suite_at}, {"unsafe", suite_unsafe}, {"regs", suite_regs}, {"spec", suite_spec}, {"store", suite_store},
    {"counter", suite_counter}, {"publish", suite_publish}, {"fuzz", suite_fuzz},
};

int main(int argc, char **argv)
{
    const char *want = argc > 1 ? argv[1] : "all";
    unsigned ran = 0, more_checks, more_fails, more_lines;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (strcmp(want, "all") && strcmp(want, "lines-report") && strcmp(want, suites[i].name)) continue;
        g_suite = suites[i].name;
        suites[i].run();
        ran++;
    }
    /* map, ram, scan and serror live in the second file, which counts its own checks. */
    ran += smmumap_scan_suites(want, &more_checks, &more_fails, &more_lines);
    g_checks += more_checks;
    g_fail += more_fails;
    if (more_lines > g_lines_max) g_lines_max = more_lines;
    if (!ran) {
        printf("FAIL: no suite named %s\n", want);
        return 2;
    }
    if (!strcmp(want, "lines-report")) {
        printf("LINES_MAX=%u\n", g_lines_max);
        return g_fail ? 1 : 0;
    }
    if (g_fail) {
        printf("FAILED: %u of %u checks\n", g_fail, g_checks);
        return 1;
    }
    printf("PASS: smmumap %s, %u suites, %u checks\n", want, ran, g_checks);
    return 0;
}
