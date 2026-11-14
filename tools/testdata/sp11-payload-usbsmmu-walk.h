/* SPDX-License-Identifier: MIT */
/* The `bank` and `walk` suites of tools/test-q1n1-sp11-payload-usbsmmu.c, which includes this file after its helpers (CLEAN, HAS,
 * LINE_IS, WALK_IS, run_it, loads_before_line, the model and the fixtures); it is not a header of its own. Evidence:
 * EXPERIMENTAL (host model only), hardware NOT RUN.
 *
 * The page tables are built by the fixture's own builder from the architecture's description (granule, input size, level
 * counts), never from the payload's arithmetic, so that the two can disagree. */

#define TTBR_DEFAULT ((UINT64_C(4) << 48) | UINT64_C(0xa0000000))
#define TCR_DEFAULT 0x803f10u

/* A bank the walk must refuse: the reason leads the line, the raw registers follow, and not one RAM load comes after the
 * context bank lines (the direct unit's 50 RAM loads are the rings and the slot). */
static int refused_bank(uint32_t cbar, uint32_t cba2r, uint32_t sctlr, uint32_t tcr, uint64_t ttbr0, const char *why)
{
    char want[160];
    fx_direct();
    fx_bank(CB_BANK, cbar, cba2r, sctlr, tcr, 5, ttbr0, 0x0004ff44);
    RUN_CLEAN();
    snprintf(want, sizeof want, "WALK UNSUPPORTED %s", why);
    HAS(want);
    HAS_NOT("NEXT WALK");
    HAS_NOT("WALK IOVA=");
    HAS_NOT("WALK SUMMARY");
    CHECK(win_loads[3] == 50);
    snprintf(want, sizeof want, "CBAR=0X%X ", cbar);
    HAS(want);
    snprintf(want, sizeof want, "SCTLR=0X%X", sctlr);
    HAS(want);
    snprintf(want, sizeof want, "TCR=0X%X", tcr);
    HAS(want);
    snprintf(want, sizeof want, "TTBR0=0X%llX", (unsigned long long)ttbr0);
    HAS(want);
    CHECK(nlines <= 20);
    return 0;
}

static int suite_bank(void)
{
    static const char *const type_name[4] = {"S2", "S1_S2BYP", "S1_S2FLT", "NESTED"};
    static const char *const tg0_name[4] = {"4K", "64K", "16K", "RSVD"};
    char want[160];
    for (unsigned type = 0; type < 4; type++) {
        fx_direct();
        fx_bank(CB_BANK, type << 16 | 3, 1, 0x205f7, TCR_DEFAULT, 5, TTBR_DEFAULT, 0x0004ff44);
        RUN_CLEAN();
        snprintf(want, sizeof want, "CB3 CBAR=0X%X TYPE=%s CBA2R=0X1 VA64=1", type << 16 | 3, type_name[type]);
        HAS(want);
        if (type == 1 || type == 2) HAS("NEXT WALK");
        else HAS("WALK UNSUPPORTED");
    }
    for (unsigned tg0 = 0; tg0 < 4; tg0++) {
        fx_direct();
        fx_bank(CB_BANK, 0x10003, 1, 0x205f7, 0x10 | tg0 << 14 | 1u << 23, 5, TTBR_DEFAULT, 0x0004ff44);
        RUN_CLEAN();
        snprintf(want, sizeof want, "T0SZ=0X10 TG0=%s EPD0=0 TCR2=0X5", tg0_name[tg0]);
        HAS(want);
    }
    /* The fault status, TTBR1 and MAIR1 are shown when they are not nothing. */
    fx_direct();
    rset(CB_PAGE(3) + 0x58, 0x402);
    rset64(CB_PAGE(3) + 0x60, UINT64_C(0xdead0000));
    rset(CB_PAGE(3) + 0x68, 0x77);
    RUN_CLEAN();
    HAS("MAIR0=0X4FF44 FSR=0X402");
    HAS("CB3 FAR=0XDEAD0000 FSYNR0=0X77");
    CHECK(win_loads[2] == 173 + 3);
    fx_direct();
    rset64(CB_PAGE(3) + 0x28, 0x1000);
    rset(CB_PAGE(3) + 0x3c, 0x77);
    RUN_CLEAN();
    HAS("MAIR0=0X4FF44 MAIR1=0X77 FSR=0X0");
    HAS("CB3 TTBR1=0X1000");
    fx_direct();
    fx_bank(CB_BANK, 0x10003, 1, 0x205f7, TCR_DEFAULT & ~(1u << 23), 5, TTBR_DEFAULT, 0x0004ff44);
    RUN_CLEAN();
    HAS("FSR=0X0 TTBR1=0X0");
    /* Every combination the walk does not model is refused with its reason and the raw registers. */
    if (refused_bank(0x00000003, 1, 0x205f7, TCR_DEFAULT, TTBR_DEFAULT, "STAGE2_ONLY CBAR=0X3 CBA2R=0X1")) return 1;
    if (refused_bank(0x00030003, 1, 0x205f7, TCR_DEFAULT, TTBR_DEFAULT, "NESTED CBAR=0X30003 CBA2R=0X1")) return 1;
    if (refused_bank(0x00010003, 1, 0x205f6, TCR_DEFAULT, TTBR_DEFAULT,
                     "M0 TRANSLATES_NOTHING INFERRED=BYPASS_LIKE CBAR=0X10003 CBA2R=0X1")) return 1;
    if (refused_bank(0x00020003, 0, 0x205f6, TCR_DEFAULT, TTBR_DEFAULT, "M0 TRANSLATES_NOTHING")) return 1;     /* M0 before VA64 */
    if (refused_bank(0x00010003, 0, 0x205f7, TCR_DEFAULT, TTBR_DEFAULT, "VA64_0 CBAR=0X10003 CBA2R=0X0")) return 1;
    if (refused_bank(0x00010003, 1, 0x205f7, TCR_DEFAULT | 0x80, TTBR_DEFAULT, "EPD0 ")) return 1;
    if (refused_bank(0x00010003, 1, 0x205f7, TCR_DEFAULT | 0xc000, TTBR_DEFAULT, "TG0_RESERVED ")) return 1;
    if (refused_bank(0x00010003, 1, 0x205f7, (TCR_DEFAULT & ~0x3fu) | 15, TTBR_DEFAULT, "T0SZ_RANGE ")) return 1;
    if (refused_bank(0x00010003, 1, 0x205f7, (TCR_DEFAULT & ~0x3fu) | 40, TTBR_DEFAULT, "T0SZ_RANGE ")) return 1;
    if (refused_bank(0x00010003, 1, 0x205f7, (TCR_DEFAULT & ~0x3fu), TTBR_DEFAULT, "T0SZ_RANGE ")) return 1;
    if (refused_bank(0x00010003, 1, 0x205f7, TCR_DEFAULT, TTBR_DEFAULT | 0x800, "TTBR0_MISALIGNED ")) return 1;
    /* A bank whose registers all read zero (RAZ/WI to the non-secure world, or never programmed) is neither stage 2 only nor a
     * bank that translates nothing, whatever its zero TYPE and zero M say: it is its own reason, with no RAM load after it. */
    if (refused_bank(0, 0, 0, 0, 0, "ALL_ZERO CBAR=0X0 CBA2R=0X0 SCTLR=0X0 TCR=0X0 TTBR0=0X0")) return 1;
    fx_direct();
    fx_bank(CB_BANK, 0, 0, 0, 0, 0, 0, 0);                         /* every register of the bank reads zero, not only the five */
    RUN_CLEAN();
    LINE_IS(nlines - 1, "WALK UNSUPPORTED ALL_ZERO CBAR=0X0 CBA2R=0X0 SCTLR=0X0 TCR=0X0 TTBR0=0X0");
    HAS("CB3 CBAR=0X0 TYPE=S2 CBA2R=0X0 VA64=0");
    HAS("CB3 SCTLR=0X0 M=0 TCR=0X0 T0SZ=0 TG0=4K EPD0=0 TCR2=0X0");
    HAS_NOT("STAGE2_ONLY");
    HAS_NOT("TRANSLATES_NOTHING");
    HAS_NOT("BYPASS_LIKE");
    HAS_NOT("NEXT WALK");
    CHECK(win_loads[3] == 50);
    /* Any one of the five registers not zero and the bank is not all zero: TYPE 0 makes it stage 2 only again. */
    for (unsigned r = 0; r < 5; r++) {
        uint32_t reg[4] = {0, 0, 0, 0};                             /* CBAR, CBA2R, SCTLR, TCR */
        uint64_t ttbr0 = 0;
        if (r < 4) reg[r] = 1; else ttbr0 = 0x1000;
        if (refused_bank(reg[0], reg[1], reg[2], reg[3], ttbr0, "STAGE2_ONLY ")) return 1;
    }
    /* Stage 1 switched off is still that when only CBAR is not zero. */
    if (refused_bank(0x00010000, 0, 0, 0, 0, "M0 TRANSLATES_NOTHING INFERRED=BYPASS_LIKE CBAR=0X10000 CBA2R=0X0")) return 1;
    /* A bank whose registers could not all be read is not walked either. */
    fx_direct();
    fault_lo = CB_PAGE(3) + 0x38;
    fault_hi = CB_PAGE(3) + 0x3c;
    CHECK(run_it() == 0);
    CLEAN();
    HAS("BASE=0XA0000000 FAULT AT=MAIR0");
    HAS("WALK UNSUPPORTED NOT_READ");
    return 0;
}

/* The unit with the context bank as just built, `iova` as the probe called STACK; the line of that probe. */
static const char *probe(uint64_t iova)
{
    A = args();
    A.stack_base = iova;
    go(&A);
    if (nlines > max_lines) max_lines = nlines;
    if (nloads > max_loads) max_loads = nloads;
    return walk_of("STACK");
}
#define PROBE_IS(iova, text) do { \
        const char *p_ = probe(iova); \
        CLEAN(); \
        if (!p_ || strcmp(p_, text " STACK")) SHOW_AND_FAIL("probe %llX is \"%s\", not \"%s\"\n", (unsigned long long)(iova), p_ ? p_ : "(none)", text); \
        checks++; \
    } while (0)

static void with_tables(unsigned pg, unsigned t0sz)
{
    fx_direct();
    fx_walkable(pg, t0sz);
}

static int attr_case(uint64_t attr, uint32_t mair0, uint32_t mair1, const char *want)
{
    char text[160];
    with_tables(12, 16);
    pt_map(UINT64_C(0xcf400000), UINT64_C(0xcf400000), 2, attr);
    rset(CB_PAGE(3) + 0x38, mair0);
    rset(CB_PAGE(3) + 0x3c, mair1);
    RUN_CLEAN();
    snprintf(text, sizeof text, "IOVA=0XCF412000 OA=0XCF412000 LVL=2 BLOCK ATTR=%s DCBAAP", want);
    WALK_IS("DCBAAP", text);
    return 0;
}

static int suite_walk(void)
{
    /* 4 KiB granule, 48 bits: four levels. */
    with_tables(12, 16);
    pt_map(UINT64_C(0xcf400000), UINT64_C(0xcf400000), 2, ATTR_DEFAULT);
    pt_map(UINT64_C(0x100001000), UINT64_C(0x200005000), 3, ATTR_DEFAULT);
    pt_map(UINT64_C(0x100003000), UINT64_C(0x800000003000), 3, ATTR_DEFAULT | UINT64_C(1) << 54 | UINT64_C(1) << 52);
    pt_map(UINT64_C(0x140000000), UINT64_C(0x300000000), 1, ATTR_DEFAULT);
    ram_w64(pt_slot(UINT64_C(0x100005000), 3), UINT64_C(0xfffffffffffffffe));       /* bit 0 clear: invalid, whatever else it says */
    ram_w64(pt_slot(UINT64_C(0x8000000000), 0), UINT64_C(0x1) | UINT64_C(0x1000));  /* a block at level 0 does not exist */
    ram_w64(pt_slot(UINT64_C(0x100006000), 3), UINT64_C(0x1) | UINT64_C(0x2000));   /* a level 3 descriptor with bit 1 clear */
    PROBE_IS(UINT64_C(0x100001234), "IOVA=0X100001234 OA=0X200005234 LVL=3 PAGE ATTR=0XFF.WB.ISH.RWU");
    PROBE_IS(UINT64_C(0x100003fff), "IOVA=0X100003FFF OA=0X800000003FFF LVL=3 PAGE ATTR=0XFF.WB.ISH.RWU");
    PROBE_IS(UINT64_C(0x140123456), "IOVA=0X140123456 OA=0X300123456 LVL=1 BLOCK ATTR=0XFF.WB.ISH.RWU");
    PROBE_IS(UINT64_C(0xcf4abcde), "IOVA=0XCF4ABCDE OA=0XCF4ABCDE LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU");
    PROBE_IS(UINT64_C(0x100002000), "IOVA=0X100002000 FAULT LVL=3");
    PROBE_IS(UINT64_C(0x100400000), "IOVA=0X100400000 FAULT LVL=2");
    PROBE_IS(UINT64_C(0x200000000), "IOVA=0X200000000 FAULT LVL=1");
    PROBE_IS(UINT64_C(0x10000000000), "IOVA=0X10000000000 FAULT LVL=0");
    PROBE_IS(UINT64_C(0x1000000000000), "IOVA=0X1000000000000 FAULT LVL=0");
    PROBE_IS(UINT64_C(0xffffffffffffffff), "IOVA=0XFFFFFFFFFFFFFFFF FAULT LVL=0");
    PROBE_IS(UINT64_C(0x100005000), "IOVA=0X100005000 FAULT LVL=3");
    PROBE_IS(UINT64_C(0x8000000000), "IOVA=0X8000000000 STOP=RESERVED_DESCRIPTOR LVL=0");
    PROBE_IS(UINT64_C(0x100006000), "IOVA=0X100006000 STOP=RESERVED_DESCRIPTOR LVL=3");
    /* One descriptor read per level, two loads each: a level 3 page took four of them. */
    CHECK(loads_before_line((unsigned)line_index("WALK IOVA=0X100006000")) == 8);

    /* 4 KiB, 39 bits: three levels, the first at level 1. 25 bits: the first at level 2. */
    with_tables(12, 25);
    pt_map(UINT64_C(0xcf400000), UINT64_C(0xcf400000), 2, ATTR_DEFAULT);
    pt_map(UINT64_C(0x40000000), UINT64_C(0x100000000), 1, ATTR_DEFAULT);
    PROBE_IS(UINT64_C(0x40abcdef), "IOVA=0X40ABCDEF OA=0X100ABCDEF LVL=1 BLOCK ATTR=0XFF.WB.ISH.RWU");
    PROBE_IS(UINT64_C(0xcf4abcde), "IOVA=0XCF4ABCDE OA=0XCF4ABCDE LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU");
    PROBE_IS(UINT64_C(0x880000000), "IOVA=0X880000000 FAULT LVL=1");
    PROBE_IS(UINT64_C(0x8000000000), "IOVA=0X8000000000 FAULT LVL=1");
    with_tables(12, 39);
    pt_map(UINT64_C(0x400000), UINT64_C(0x80400000), 2, ATTR_DEFAULT);
    PROBE_IS(UINT64_C(0x412345), "IOVA=0X412345 OA=0X80412345 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU");
    PROBE_IS(UINT64_C(0x2000000), "IOVA=0X2000000 FAULT LVL=2");
    PROBE_IS(UINT64_C(0x600000), "IOVA=0X600000 FAULT LVL=2");

    /* 16 KiB granule: 48 bits is four levels, two entries at level 0; a block exists at level 2 only. */
    with_tables(14, 16);
    pt_map(UINT64_C(0xce000000), UINT64_C(0xce000000), 2, ATTR_DEFAULT);
    pt_map(UINT64_C(0x100004000), UINT64_C(0x200010000), 3, ATTR_DEFAULT);
    ram_w64(pt_slot(UINT64_C(0x1000000000), 1), UINT64_C(0x1) | UINT64_C(0x40000000000));
    PROBE_IS(UINT64_C(0xcf4abcde), "IOVA=0XCF4ABCDE OA=0XCF4ABCDE LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU");
    PROBE_IS(UINT64_C(0x100004abc), "IOVA=0X100004ABC OA=0X200010ABC LVL=3 PAGE ATTR=0XFF.WB.ISH.RWU");
    PROBE_IS(UINT64_C(0x1000000000), "IOVA=0X1000000000 STOP=RESERVED_DESCRIPTOR LVL=1");
    PROBE_IS(UINT64_C(0x800000000000), "IOVA=0X800000000000 FAULT LVL=0");
    PROBE_IS(UINT64_C(0x1000000000000), "IOVA=0X1000000000000 FAULT LVL=0");
    PROBE_IS(UINT64_C(0x100008000), "IOVA=0X100008000 FAULT LVL=3");

    /* 64 KiB granule: 48 bits is three levels starting at level 1; 42 bits starts at level 2. */
    with_tables(16, 16);
    pt_map(UINT64_C(0xc0000000), UINT64_C(0xc0000000), 2, ATTR_DEFAULT);
    pt_map(UINT64_C(0x100010000), UINT64_C(0x200030000), 3, ATTR_DEFAULT);
    ram_w64(pt_slot(UINT64_C(0x40000000000), 1), UINT64_C(0x1) | UINT64_C(0x80000000000));
    PROBE_IS(UINT64_C(0xcf4abcde), "IOVA=0XCF4ABCDE OA=0XCF4ABCDE LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU");
    PROBE_IS(UINT64_C(0x100010fff), "IOVA=0X100010FFF OA=0X200030FFF LVL=3 PAGE ATTR=0XFF.WB.ISH.RWU");
    PROBE_IS(UINT64_C(0x40000000000), "IOVA=0X40000000000 STOP=RESERVED_DESCRIPTOR LVL=1");
    PROBE_IS(UINT64_C(0x80000000000), "IOVA=0X80000000000 FAULT LVL=1");
    PROBE_IS(UINT64_C(0x100020000), "IOVA=0X100020000 FAULT LVL=3");
    with_tables(16, 22);
    pt_map(UINT64_C(0x20000000), UINT64_C(0x40000000), 2, ATTR_DEFAULT);
    PROBE_IS(UINT64_C(0x20abcdef), "IOVA=0X20ABCDEF OA=0X40ABCDEF LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU");
    PROBE_IS(UINT64_C(0x40000000), "IOVA=0X40000000 FAULT LVL=2");
    PROBE_IS(UINT64_C(0x40000000000), "IOVA=0X40000000000 FAULT LVL=2");      /* 2^42: just outside */

    /* Tables where the memory map says there is no RAM: not loaded, and the line says what the map says. */
    with_tables(12, 16);
    pt_map(UINT64_C(0xcf400000), UINT64_C(0xcf400000), 2, ATTR_DEFAULT);
    ram_w64(pt_slot(UINT64_C(0x100000000), 1), UINT64_C(0xcf510000) | 3);      /* Reserved */
    ram_w64(pt_slot(UINT64_C(0x200000000), 1), UINT64_C(0xcf500000) | 3);      /* ACPI NVS */
    ram_w64(pt_slot(UINT64_C(0x300000000), 1), UINT64_C(0xf0000000) | 3);      /* MMIO */
    ram_w64(pt_slot(UINT64_C(0x400000000), 1), UINT64_C(0x4000000000) | 3);    /* the map does not list it */
    PROBE_IS(UINT64_C(0x100000000), "IOVA=0X100000000 STOP=TABLE_TYPE_0X0 LVL=2");
    PROBE_IS(UINT64_C(0x200000000), "IOVA=0X200000000 STOP=TABLE_TYPE_0XA LVL=2");
    PROBE_IS(UINT64_C(0x300000000), "IOVA=0X300000000 STOP=TABLE_TYPE_0XB LVL=2");
    PROBE_IS(UINT64_C(0x400000000), "IOVA=0X400000000 STOP=TABLE_NOT_IN_MAP LVL=2");
    rset64(CB_PAGE(3) + 0x20, UINT64_C(4) << 48 | UINT64_C(0xcf510000));       /* the root itself */
    PROBE_IS(UINT64_C(0xcf4abcde), "IOVA=0XCF4ABCDE STOP=TABLE_TYPE_0X0 LVL=0");
    rset64(CB_PAGE(3) + 0x20, UINT64_C(4) << 48 | UINT64_C(0x4000000000));
    PROBE_IS(UINT64_C(0xcf4abcde), "IOVA=0XCF4ABCDE STOP=TABLE_NOT_IN_MAP LVL=0");
    rset64(CB_PAGE(3) + 0x20, UINT64_C(0xffff) << 48 | UINT64_C(0xa0000000));  /* the ASID is not part of the address */
    PROBE_IS(UINT64_C(0xcf4abcde), "IOVA=0XCF4ABCDE OA=0XCF4ABCDE LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU");

    /* A table that points at itself, or back at a lower level, ends after four descriptors: eight loads. */
    with_tables(12, 16);
    for (unsigned i = 0; i < 512; i++) ram_w64(pt.root + 8 * i, pt.root | 3);
    PROBE_IS(UINT64_C(0x100001000), "IOVA=0X100001000 OA=0XA0000000 LVL=3 PAGE ATTR=0X44.NC.NSH.RW.NOAF");
    CHECK(loads_before_line((unsigned)line_index("WALK IOVA=0X100001000")) == 8);
    with_tables(12, 16);
    {
        uint64_t l1 = ram_r64(pt_slot(UINT64_C(0x100001000), 0)) & MASK48 & ~UINT64_C(0xfff);
        ram_w64(pt_slot(UINT64_C(0x100001000), 2), l1 | 3);                    /* level 2 points back at level 1 */
    }
    probe(UINT64_C(0x100001000));
    CLEAN();
    CHECK(loads_before_line((unsigned)line_index("WALK IOVA=0X100001000")) <= 8);
    HAS("WALK SUMMARY ");

    /* The summary tells identity from other mappings: three probes mapped, one of them to itself, three faulting. */
    with_tables(12, 16);
    pt_map(UINT64_C(0xcf400000), UINT64_C(0x1cf400000), 2, ATTR_DEFAULT);       /* the DCBAAP's and the event ring's blocks */
    pt_map(UINT64_C(0xcf600000), UINT64_C(0xcf600000), 2, ATTR_DEFAULT);        /* q1n1's stack */
    RUN_CLEAN();
    HAS("WALK SUMMARY PROBES=6 MAPPED=3 IDENTITY=1 FAULT=3 STOP=0");
    WALK_IS("DCBAAP", "IOVA=0XCF412000 OA=0X1CF412000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU DCBAAP");

    /* Attributes: AttrIndx through MAIR0 and MAIR1, SH, AP and AF. */
    if (attr_case(0x400, 0x0004ff44, 0, "0X44.NC.NSH.RW")) return 1;
    if (attr_case(0x684, 0x0004ff44, 0, "0XFF.WB.OSH.RO")) return 1;
    if (attr_case(0x748, 0x0004ff44, 0, "0X4.DEV.ISH.RWU")) return 1;
    if (attr_case(0x74c, 0x0004ff44, 0, "0X0.DEV.ISH.RWU")) return 1;
    if (attr_case(0x710, 0x0004ff44, 0xbb, "0XBB.WT.ISH.RW")) return 1;
    if (attr_case(0x750, 0x0004ff44, 0xbb, "0XBB.WT.ISH.RWU")) return 1;
    if (attr_case(0x754, 0x0004ff44, 0x7fbb, "0X7F.NRM.ISH.RWU")) return 1;
    if (attr_case(0x514, 0x0004ff44, 0x7fbb, "0X7F.NRM.SH_RSVD.RW")) return 1;
    if (attr_case(0x3c4, 0x0004ff44, 0, "0XFF.WB.ISH.ROU.NOAF")) return 1;
    if (attr_case(0x01c, 0x0004ff44, 0xa5000000u, "0XA5.NRM.NSH.RW.NOAF")) return 1;
    return 0;
}
