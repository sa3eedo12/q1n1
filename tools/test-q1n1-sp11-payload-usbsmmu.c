/* SPDX-License-Identifier: MIT */
/* Host test for the payload "usbsmmu" (payloads/usbsmmu.c), built natively with Q1N1_PAYLOAD_HOST_TEST so that CurrentEL comes
 * from a scripted register file and every load from the model in testdata/sp11-payload-usbsmmu-model.h, against the fixtures of
 * testdata/sp11-payload-usbsmmu-fixture.h. Driven by tools/test-q1n1-sp11-payload-usbsmmu.py under ASan and UBSan.
 *
 * The model fails the run on anything the payload must never do (a load that is not 4-byte aligned, a 3001st load, an MMIO
 * address outside the allowed registers of the three windows, in a window after an abort in it, of a context bank no stream
 * selects, a RAM address the memory map does not call usable, a load before the NEXT line of its group), and these suites pin
 * what it prints:
 *   unit     the exact 24 lines of the unit-like fixture (S0's values where it read them, made-up ones elsewhere, the hub topology
 *            the firmware had) and of the direct connection, the loads per window, the order of the NEXT lines, CurrentEL the
 *            first event
 *   xhc      USBSTS and PORTSC decoded bit by bit, a halted xHC with HCE, an all-ones or zero or foreign block read no further
 *   rings    the event ring (wrap, ERDP outside the segment, bad segment), eight slots, misaligned and refused pointers
 *            (Reserved, ACPI NVS, not in the map: never loaded), the type of every descriptor
 *   smmu     the stream match rule, S2CR types, CBNDX past NUMCB, extended stream ids, the fault registers, two different banks
 *   bank     every combination the walk refuses (all zero, stage 2, nested, stage 1 off, formats it does not model), with the raw
 *            registers and no RAM load after it
 *   walk     4 KiB (four and three levels), 16 KiB and 64 KiB granules, blocks at levels 1 and 2, pages, holes, invalid and
 *            reserved descriptors, a table that points at itself, tables outside usable RAM, attribute decoding, OA masks
 *   faults   an abort at every load of the unit, at every kind of address
 *   hostile  every register and memory word all ones, zero or random; thousands of units with hostile words in them
 *   el       any EL but 2: one line, no load; arguments; the memory map's own plausibility
 * `lines-report` prints the most lines and loads of everything above. The test cannot show what the binary does on a core:
 * tools/test-q1n1-sp11-payload-build.py disassembles it, and tools/test-q1n1-sp11-payload-qemu-usbsmmu.py runs it under EDK2 at
 * EL2. Nothing here ran on hardware. Evidence: EXPERIMENTAL (host model only). */
#include "testdata/sp11-payload-usbsmmu-fixture.h"

/* Loads the unit-like runs make, pinned: a payload that reads one register more or less is a different payload. */
#define LOADS_UNIT_HUB 304u
#define LOADS_UNIT_DIRECT 296u

static struct q1n1_payload_args A;
static unsigned max_lines, max_loads;
static uint64_t run_it(void)
{
    uint64_t r;
    A = args();
    r = go(&A);
    if (nlines > max_lines) max_lines = nlines;
    if (nloads > max_loads) max_loads = nloads;
    return r;
}

static int clean_run(int at)
{
    const char *why = violations ? first_violation : bad_lines ? first_bad_line : nlines > LINE_CAP ? "more than 24 lines" :
                      nloads > LOAD_CAP ? "more than 3000 loads" : NULL;
    if (!why) return 1;
    fprintf(stderr, "FAIL line %d: %s (violations %u, bad lines %u, lines %u, loads %u)\n", at, why, violations, bad_lines, nlines, nloads);
    dump_lines(stderr);
    return 0;
}
#define CLEAN() CHECK(clean_run(__LINE__))
#define RUN_CLEAN() do { CHECK(run_it() == 0); CLEAN(); } while (0)
#define SHOW_AND_FAIL(...) do { fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); fprintf(stderr, __VA_ARGS__); dump_lines(stderr); return 1; } while (0)
#define LINE_IS(n, text) do { \
        const char *got_ = line_n(n); \
        if (!got_ || strcmp(got_, text)) SHOW_AND_FAIL("line %u is \"%s\", not \"%s\"\n", (unsigned)(n), got_ ? got_ : "(none)", text); \
        checks++; \
    } while (0)
#define HAS(text) do { if (!line_has(text)) SHOW_AND_FAIL("no line has \"%s\"\n", text); checks++; } while (0)
#define HAS_NOT(text) do { if (line_has(text)) SHOW_AND_FAIL("a line has \"%s\"\n", text); checks++; } while (0)
#define WALK_IS(role, text) do { \
        const char *w_ = walk_of(role); \
        if (!w_ || strcmp(w_, text)) SHOW_AND_FAIL("probe %s is \"%s\", not \"%s\"\n", role, w_ ? w_ : "(none)", text); \
        checks++; \
    } while (0)

/* The loads between the line before line n and line n itself. */
static unsigned loads_before_line(unsigned n)
{
    unsigned lines = 0, loads = 0;
    for (unsigned i = 0; i < nevents; i++) {
        if (events[i].kind == EV_LINE) {
            if (lines++ == n) return loads;
            loads = 0;
        } else if (events[i].kind == EV_LOAD) {
            loads++;
        }
    }
    return loads;
}

/* ---- unit ---------------------------------------------------------------------------------------------------------------- */

static int suite_unit(void)
{
    /* S0's values where it read them, with the hub topology the firmware had: 24 lines, the walk cut to four probes. */
    fx_unit_like();
    RUN_CLEAN();
    CHECK(nlines == 24 && sysreg_reads == 1 && events[0].kind == EV_SYSREG);
    LINE_IS(0, "NEXT U0");
    LINE_IS(1, "U0 CAPL=0X20 CMD=0X0 STS=0X1019:HCH.EINT.PCD.HCE CRCR=0X0 DCBAAP=0XCF412000 CFG=0X40");
    LINE_IS(2, "U0 P1=0XE03:CCS.PED.U0.HS P2=0X81203:CCS.PED.U0.SS");
    LINE_IS(3, "U1 IDLE CAPL=0X20 CMD=0X0 STS=0X1:HCH DCBAAP=0X0 P1=0X2A0:RXDET P2=0X2A0:RXDET");
    LINE_IS(4, "DWC3 ID=0X33313130 GCTL=0X30C11004 GSTS=0X1 BERR=0X0 LTSSM=0X4009");
    LINE_IS(5, "NEXT SMMU");
    LINE_IS(6, "SMMU ID0=0X7C017E9A ID1=0X60800080 ID2=0X7555 SCR0=0X230406 GFSR=0X0");
    LINE_IS(7, "SMMU SMRG=0X9A NCB=0X80 CBBASE=0X15080000 S1420=SMR3.TRANS.CB3 S1460=SMR4.TRANS.CB3");
    LINE_IS(8, "NEXT RINGS");
    LINE_IS(9, "RINGS CSZ=1 ERSTSZ=0X1 ERSTBA=0XCF415240 ERDP=0XCF414CB8 SEG0=0XCF414000/0X100");
    LINE_IS(10, "TRB M1=PSC.1.0.1 M2=CMD.1.3.1 M3=XFER.1.3.1 AT=0.0.0.0");
    LINE_IS(11, "U0S1 RT=0 RP=1 SPD=3 HUB=0 ST=3 AD=1 EP1=1.4.0X40 EP3=1.7.0X1");
    LINE_IS(12, "U0S2 RT=0 RP=2 SPD=4 HUB=0 ST=3 AD=2 EP1=1.4.0X200 EP3=1.7.0X2");
    LINE_IS(13, "U0S3 RT=3 RP=2 SPD=4 HUB=0 ST=3 AD=3 EP1=1.4.0X200 EP2=1.2.0X400 EP5=1.6.0X400");
    LINE_IS(14, "NEXT CB3");
    LINE_IS(15, "CB3 CBAR=0X10003 TYPE=S1_S2BYP CBA2R=0X1 VA64=1");
    LINE_IS(16, "CB3 SCTLR=0X205F7 M=1 TCR=0X803F10 T0SZ=0X10 TG0=4K EPD0=0 TCR2=0X5");
    LINE_IS(17, "CB3 TTBR0=0X40000A0000000 ASID=0X4 BASE=0XA0000000 MAIR0=0X4FF44 FSR=0X0");
    LINE_IS(18, "NEXT WALK");
    LINE_IS(19, "WALK IOVA=0XCF412000 OA=0XCF412000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU DCBAAP");
    LINE_IS(20, "WALK IOVA=0XCF610000 OA=0XCF610000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU STACK");
    LINE_IS(21, "WALK IOVA=0X880000000 OA=0X880000000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU CONVLO");
    LINE_IS(22, "WALK IOVA=0X97FFFF000 OA=0X97FFFF000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU CONVHI");
    LINE_IS(23, "WALK SUMMARY PROBES=4 MAPPED=4 IDENTITY=4 FAULT=0 STOP=0 CUTS=2");
    CHECK(next_n == 5 && next_order[0] == 1 && next_order[1] == 2 && next_order[2] == 3 && next_order[3] == 4 && next_order[4] == 5);
    CHECK(nloads == LOADS_UNIT_HUB);
    CHECK(loads_before_line(0) == 0);           /* nothing is read before the first NEXT line */
    CHECK(win_loads[0] == 24 && win_loads[1] == 13 && win_loads[2] == 173 && win_loads[3] == 94);

    /* The direct connection the operator uses next: one slot, so the walk gets six probes: exactly 24 lines. */
    fx_direct();
    RUN_CLEAN();
    CHECK(nlines == 24);
    LINE_IS(11, "U0S1 RT=0 RP=2 SPD=4 HUB=0 ST=3 AD=1 EP1=1.4.0X200 EP2=1.2.0X400 EP5=1.6.0X400");
    LINE_IS(12, "NEXT CB3");
    LINE_IS(16, "NEXT WALK");
    LINE_IS(17, "WALK IOVA=0XCF412000 OA=0XCF412000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU DCBAAP");
    LINE_IS(18, "WALK IOVA=0XCF610000 OA=0XCF610000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU STACK");
    LINE_IS(19, "WALK IOVA=0X880000000 OA=0X880000000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU CONVLO");
    LINE_IS(20, "WALK IOVA=0X97FFFF000 OA=0X97FFFF000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU CONVHI");
    LINE_IS(21, "WALK IOVA=0XCF414CB0 OA=0XCF414CB0 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU ERDP");
    LINE_IS(22, "WALK IOVA=0X80000000 OA=0X80000000 LVL=2 BLOCK ATTR=0XFF.WB.ISH.RWU RAMLO");
    LINE_IS(23, "WALK SUMMARY PROBES=6 MAPPED=6 IDENTITY=6 FAULT=0 STOP=0");
    CHECK(nloads == LOADS_UNIT_DIRECT);
    CHECK(win_loads[0] == 24 && win_loads[1] == 13 && win_loads[2] == 173 && win_loads[3] == 86);

    /* The same with 32-byte contexts (HCCPARAMS1.CSZ 0): the endpoint contexts are 32 bytes apart. */
    fx_csz = 0;
    fx_direct();
    RUN_CLEAN();
    fx_csz = 1;
    LINE_IS(9, "RINGS CSZ=0 ERSTSZ=0X1 ERSTBA=0XCF415240 ERDP=0XCF414CB8 SEG0=0XCF414000/0X100");
    LINE_IS(11, "U0S1 RT=0 RP=2 SPD=4 HUB=0 ST=3 AD=1 EP1=1.4.0X200 EP2=1.2.0X400 EP5=1.6.0X400");

    /* U1 is the busy controller and U0 idle: the stick is on U1, and every group follows it. */
    fx_direct();
    fx_xhci(U1_BASE, 0, 0x18, DCBAA, 0xe03, 0x2a0);
    fx_rings(U1_BASE);
    fx_xhci(U0_BASE, 0, 1, 0, 0x2a0, 0x2a0);
    RUN_CLEAN();
    HAS("U0 IDLE ");
    HAS("U1 CAPL=0X20");
    HAS("U1S1 RT=0 RP=2 SPD=4");
    HAS("NEXT RINGS");
    return 0;
}

/* ---- xhc ----------------------------------------------------------------------------------------------------------------- */

static int suite_xhc(void)
{
    static const struct { unsigned bit; const char *name; } known[] = {{0, "HCH"}, {2, "HSE"}, {3, "EINT"}, {4, "PCD"}, {8, "SSS"},
                                                                       {9, "RSS"}, {10, "SRE"}, {11, "CNR"}, {12, "HCE"}};
    static const char *const pls[16] = {"U0", "U1", "U2", "U3", "DIS", "RXDET", "INACT", "POLL", "RECOV", "HOTRST", "COMPL", "TEST",
                                        "RSVD", "RSVD", "RSVD", "RESUME"};
    static const char *const spd[16] = {"", "FS", "LS", "HS", "SS", "SSP", "SPD_6", "SPD_7", "SPD_8", "SPD_9", "SPD_0XA", "SPD_0XB",
                                        "SPD_0XC", "SPD_0XD", "SPD_0XE", "SPD_0XF"};
    char want[160];
    unsigned base_u0;
    fx_direct();
    RUN_CLEAN();
    base_u0 = win_loads[0];
    /* USBSTS: every bit that has a name, alone, is that name; a bit that has none is OTHER. */
    for (unsigned bit = 0; bit < 32; bit++) {
        const char *name = NULL;
        for (unsigned i = 0; i < sizeof known / sizeof known[0]; i++)
            if (known[i].bit == bit) name = known[i].name;
        fx_direct();
        fx_xhci(U0_BASE, 0x5, 1u << bit, DCBAA, 0xe03, 0x81203);
        fx_rings(U0_BASE);
        RUN_CLEAN();
        if (name) snprintf(want, sizeof want, "STS=0X%X:%s ", 1u << bit, name);
        else snprintf(want, sizeof want, "STS=0X%X:OTHER_0X%X ", 1u << bit, 1u << bit);
        HAS(want);
        HAS("U0 CAPL=0X20 CMD=0X5 ");
    }
    fx_direct();
    fx_xhci(U0_BASE, 0, 0, DCBAA, 0xe03, 0x81203);
    fx_rings(U0_BASE);
    RUN_CLEAN();
    HAS("STS=0X0:NONE ");
    fx_xhci(U0_BASE, 0, 0x1039, DCBAA, 0xe03, 0x81203);
    fx_rings(U0_BASE);
    RUN_CLEAN();
    HAS("STS=0X1039:HCH.EINT.PCD.HCE.OTHER_0X20 ");

    /* PORTSC: connect and enable, every link state, every speed. */
    for (unsigned state = 0; state < 16; state++)
        for (unsigned speed = 0; speed < 16; speed++) {
            uint32_t sc = 3 | state << 5 | speed << 10;
            fx_direct();
            fx_xhci(U0_BASE, 0, 0x18, DCBAA, sc, 0);
            RUN_CLEAN();
            snprintf(want, sizeof want, "P1=0X%X:CCS.PED.%s%s%s P2=0X0:U0", sc, pls[state], speed ? "." : "", spd[speed]);
            HAS(want);
        }
    fx_direct();
    fx_xhci(U0_BASE, 0, 0x18, DCBAA, 1, 2);
    RUN_CLEAN();
    HAS("P1=0X1:CCS.U0 P2=0X2:PED.U0");

    /* Nothing there: all ones, zeros, something that is not an xHC. Nothing more is read from the block. */
    fx_direct();
    rset(U0_BASE, 0xffffffffu);
    RUN_CLEAN();
    HAS("U0 UNREADABLE WHY=ALL_ONES CAP0=0XFFFFFFFF");
    HAS("DWC3 SKIPPED=U0_NOT_READ");
    HAS("RINGS SKIPPED=NO_XHC");
    CHECK(win_loads[0] == 1 && win_loads[1] == 13);
    fx_direct();
    rset(U1_BASE, 0xffffffffu);
    RUN_CLEAN();
    HAS("U1 UNREADABLE WHY=ALL_ONES CAP0=0XFFFFFFFF");
    CHECK(win_loads[1] == 1 && win_loads[0] == base_u0);
    fx_direct();
    rset(U0_BASE, 0);
    RUN_CLEAN();
    HAS("U0 UNREADABLE WHY=ZERO");
    CHECK(win_loads[0] == 1);
    fx_direct();
    rset(U0_BASE, 0x01100010);                  /* CAPLENGTH 0x10: not an xHC */
    RUN_CLEAN();
    HAS("U0 NOT_XHCI CAP0=0X1100010 HCS1=0X2000840");
    CHECK(win_loads[0] == 4);
    fx_direct();
    rset(U0_BASE, 0x00010020);                  /* HCIVERSION 1: not an xHC */
    RUN_CLEAN();
    HAS("U0 NOT_XHCI ");
    fx_direct();
    rset(U0_BASE + 4, 0x02000800);              /* no slots */
    RUN_CLEAN();
    HAS("U0 NOT_XHCI ");
    fx_direct();
    rset(U0_BASE + 4, 0x00000840);              /* no ports */
    RUN_CLEAN();
    HAS("U0 NOT_XHCI ");
    fx_direct();
    rset(U0_BASE + 0x24, 0xffffffffu);          /* USBSTS all ones: the block went away under us */
    RUN_CLEAN();
    HAS("U0 UNREADABLE WHY=ALL_ONES ");

    /* DWC3: an ID that is not one is read no further. */
    fx_direct();
    rset(U0_BASE + 0xc120, 0xffffffffu);
    RUN_CLEAN();
    HAS("DWC3 UNREADABLE ID=0XFFFFFFFF");
    CHECK(win_loads[0] == base_u0 - 5);
    fx_direct();
    rset(U0_BASE + 0xc120, 0);
    RUN_CLEAN();
    HAS("DWC3 UNREADABLE ID=0X0");
    fx_direct();
    rset64(U0_BASE + 0xc130, UINT64_C(0x0000000100001000));
    RUN_CLEAN();
    HAS("BERR=0X100001000 ");

    /* One port only: P2 is not read. */
    fx_direct();
    rset(U0_BASE + 4, 0x01000840);
    RUN_CLEAN();
    HAS("U0 P1=0XE03:CCS.PED.U0.HS");
    HAS_NOT("P2=0X81203");
    CHECK(win_loads[0] == base_u0 - 1);

    /* Both controllers busy: the budget still holds and both are decoded. */
    fx_direct();
    fx_xhci(U1_BASE, 0, 0x18, DCBAA, 0xe03, 0x81203);
    RUN_CLEAN();
    HAS("U1 CAPL=0X20 CMD=0X0 STS=0X18:EINT.PCD CRCR=0X0 DCBAAP=0XCF412000 CFG=0X40");
    HAS("U1 P1=0XE03:CCS.PED.U0.HS P2=0X81203:CCS.PED.U0.SS");
    CHECK(nlines == 24);
    return 0;
}

/* ---- rings --------------------------------------------------------------------------------------------------------------- */

#define ERDP_REG (U0_BASE + 0x1000 + 0x38)

static int suite_rings(void)
{
    char want[200];
    /* The ring wraps inside the first segment: ERDP at index 0 has the last three TRBs of the segment before it. */
    fx_direct();
    rset64(ERDP_REG, RING);
    fx_trb(RING + 255 * 16, 34, 0x13, 0x45, 1, 2);
    fx_trb(RING + 254 * 16, 33, 4, 0x2, 0, 0);
    fx_trb(RING + 253 * 16, 0x3f, 0xff, 0xff, 1, 0);
    fx_trb(RING + 0, 32, 5, 6, 1, 0);
    RUN_CLEAN();
    LINE_IS(10, "TRB M1=PSC.0X13.0X45.1 M2=CMD.4.2.0 M3=0X3F.0XFF.0XFF.1 AT=XFER.5.6.1");
    /* All four TRBs are inside the first segment: sixteen loads, none outside [RING, RING + 0x1000). */
    CHECK(loads_before_line(10) == 16);
    for (unsigned i = 0, seen = 0; i < nevents; i++) {
        if (events[i].kind == EV_LINE) seen++;
        if (events[i].kind == EV_LOAD && seen == 10) CHECK(events[i].addr >= RING && events[i].addr < RING + 0x1000);
    }
    /* The smallest segment: sixteen TRBs; the TRB before index 1 is index 0, and two before is index 15. */
    fx_direct();
    ram_w32(ERST + 8, 16);
    rset64(ERDP_REG, RING + 16);
    fx_trb(RING + 0, 33, 1, 0, 1, 0);
    fx_trb(RING + 15 * 16, 34, 1, 0, 1, 0);
    fx_trb(RING + 14 * 16, 35, 1, 0, 0, 0);
    RUN_CLEAN();
    HAS("SEG0=0XCF414000/0X10");
    HAS("TRB M1=CMD.1.0.1 M2=PSC.1.0.1 M3=BWR.1.0.0 AT=0.0.0.0");
    /* ERDP outside the first segment: no TRB is read, and the line says why. */
    fx_direct();
    rset64(ERDP_REG, RING + 0x1000);
    RUN_CLEAN();
    HAS("TRB SKIPPED=ERDP_NOT_IN_SEG0");
    fx_direct();
    rset64(ERDP_REG, RING - 0x10);
    RUN_CLEAN();
    HAS("TRB SKIPPED=ERDP_NOT_IN_SEG0");
    /* No segment table, an empty one, a bad size. */
    fx_direct();
    rset(U0_BASE + 0x1000 + 0x28, 0);
    RUN_CLEAN();
    HAS("SEG0=NO_ERST");
    HAS("TRB SKIPPED=NO_SEG0");
    fx_direct();
    rset64(U0_BASE + 0x1000 + 0x30, 0);
    RUN_CLEAN();
    HAS("SEG0=NO_ERST");
    for (unsigned i = 0; i < 4; i++) {
        static const uint32_t sizes[4] = {0, 15, 4097, 0xffff};
        fx_direct();
        ram_w32(ERST + 8, sizes[i]);
        RUN_CLEAN();
        snprintf(want, sizeof want, "SEG0=BAD_SIZE/0X%X", sizes[i]);
        HAS(want);
        HAS("TRB SKIPPED=NO_SEG0");
    }
    fx_direct();
    ram_w32(ERST + 8, 4096);
    rset64(ERDP_REG, RING + 4096 * 16 - 16);
    RUN_CLEAN();
    HAS("SEG0=0XCF414000/0X1000");
    /* The segment table, or the segment, where the memory map says it is not RAM. */
    fx_direct();
    rset64(U0_BASE + 0x1000 + 0x30, UINT64_C(0xcf510000));
    RUN_CLEAN();
    HAS("ERSTBA=0XCF510000 ERDP=0XCF414CB8 REFUSED=TYPE_0X0 AT=ERST");
    HAS("TRB SKIPPED=NO_SEG0");
    fx_direct();
    ram_w64(ERST, UINT64_C(0xcf500000));
    rset64(ERDP_REG, UINT64_C(0xcf500100));
    RUN_CLEAN();
    HAS("SEG0=0XCF500000/0X100");
    HAS("TRB REFUSED=TYPE_0XA");
    return 0;
}

static void eight_slots(unsigned config)
{
    static const struct fx_ep ep[] = {{1, 1, 4, 0x40}, {0, 0, 0, 0}};
    fx_direct();
    for (unsigned id = 1; id <= 8; id++) {
        ram_w64(DCBAA + 8 * id, CTX1 + 0x1000 * (id - 1));
        fx_slot(CTX1 + 0x1000 * (id - 1), id, 3, id & 1 ? 1 : 2, id, 0, ep);
    }
    if (config) rset(U0_BASE + 0x20 + 0x38, config);
}

static int suite_slots(void)
{
    char want[200];
    /* Eight slots: the budget allows three lines here and the rest is counted. */
    eight_slots(0);
    RUN_CLEAN();
    HAS("U0S1 RT=1 RP=1 SPD=3 HUB=0 ST=3 AD=1 EP1=1.4.0X40");
    HAS("U0S2 RT=2 RP=2 ");
    HAS("U0S3 RT=3 RP=1 SPD=3 HUB=0 ST=3 AD=3 EP1=1.4.0X40 MORE=5");
    HAS_NOT("U0S4 ");
    HAS("WALK SUMMARY PROBES=4 ");
    HAS("CUTS=3");
    /* CONFIG limits the scan to the slots the firmware enabled: two of the eight. */
    eight_slots(2);
    RUN_CLEAN();
    HAS("U0S1 ");
    HAS("U0S2 ");
    HAS_NOT("U0S3 ");
    /* Slot ids past the eighth are never read, whatever CONFIG says. */
    fx_direct();
    ram_w64(DCBAA + 8 * 9, CTX2);
    RUN_CLEAN();
    for (unsigned i = 0; i < nevents; i++) CHECK(events[i].kind != EV_LOAD || events[i].addr != DCBAA + 72);
    /* The pointers of the firmware are 64-byte aligned or they are refused, and refused is not loaded. */
    fx_direct();
    rset64(U0_BASE + 0x20 + 0x30, DCBAA + 8);
    RUN_CLEAN();
    HAS("U0 SLOTS=DCBAAP_MISALIGNED");
    fx_direct();
    rset64(U0_BASE + 0x20 + 0x30, 0);
    RUN_CLEAN();
    HAS("U0 SLOTS=NO_DCBAAP");
    HAS("WALK SUMMARY PROBES=5 ");              /* no DCBAAP probe */
    fx_direct();
    memset(ram_at(DCBAA, 0x100), 0, 0x100);
    RUN_CLEAN();
    HAS("U0 SLOTS=NONE");
    fx_direct();
    ram_w64(DCBAA + 8, CTX1 + 0x20);
    RUN_CLEAN();
    snprintf(want, sizeof want, "U0S1 CTX=0X%llX REFUSED=MISALIGNED", (unsigned long long)(CTX1 + 0x20));
    HAS(want);
    /* Whatever kind of descriptor the firmware's memory is in: only usable RAM is loaded. */
    for (unsigned type = 0; type < 20; type++) {
        unsigned ram = (type >= 1 && type <= 7) || type == 9;
        fx_direct();
        map_clear();
        map_add(type, FW_BASE, 0x100);
        map_add(7, UINT64_C(0x80000000), 0x40000);
        map_add(7, UINT64_C(0x880000000), 0x100000);
        map_add(1, UINT64_C(0xcf600000), 4);
        map_add(2, UINT64_C(0xcf610000), 16);
        RUN_CLEAN();
        if (ram) {
            HAS("U0S1 RT=0 RP=2 SPD=4");
        } else {
            snprintf(want, sizeof want, "U0 SLOTS=UNREAD REFUSED=TYPE_0X%X", type);
            HAS(want);
        }
    }
    fx_direct();
    map_clear();                                /* the memory map does not list the firmware's memory at all */
    map_add(7, UINT64_C(0x80000000), 0x40000);
    RUN_CLEAN();
    HAS("U0 SLOTS=UNREAD REFUSED=NOT_IN_MAP");
    fx_direct();
    map_clear();                                /* RAM that ends where the array's last entry would begin */
    map_add(7, FW_BASE, 0x12);
    map_add(7, UINT64_C(0x80000000), 0x40000);
    rset64(U0_BASE + 0x20 + 0x30, FW_BASE + 0x11fc0);
    RUN_CLEAN();
    HAS("U0 SLOTS=UNREAD REFUSED=NOT_IN_MAP");
    fx_direct();
    map_clear();                                /* RAM whose last byte of a word is claimed by another kind of memory */
    map_add(7, FW_BASE, 0x13);
    map_add(0, FW_BASE + 0x12002, 1);           /* an odd start: no tool makes one, a hostile map might */
    map_add(7, UINT64_C(0x80000000), 0x40000);
    rset64(U0_BASE + 0x20 + 0x30, FW_BASE + 0x11fc0);
    RUN_CLEAN();
    HAS("U0 SLOTS=UNREAD REFUSED=TYPE_0X0");
    /* 31 endpoints: the line holds what fits and the rest is counted. */
    fx_direct();
    {
        struct fx_ep all[32];
        for (unsigned i = 0; i < 31; i++) all[i] = (struct fx_ep){i + 1, 1, 2 + i % 6, 0x200 + i};
        all[31] = (struct fx_ep){0, 0, 0, 0};
        fx_slot(CTX1, 0, 4, 2, 1, 0, all);
    }
    RUN_CLEAN();
    HAS("U0S1 RT=0 RP=2 SPD=4 HUB=0 ST=3 AD=1 EP1=1.2.0X200 EP2=1.3.0X201 EP3=1.4.0X202");
    HAS_NOT(" EP4=");
    HAS("CUTS=0X1C");
    return 0;
}

/* ---- smmu ---------------------------------------------------------------------------------------------------------------- */

static int suite_smmu(void)
{
    /* Global registers: an all-ones or zero ID0 and the stream match registers are read no further. */
    fx_direct();
    rset(SMMU_BASE + 0x20, 0xffffffffu);
    RUN_CLEAN();
    HAS("SMMU UNREADABLE ID0=0XFFFFFFFF SCR0=0X230406");
    HAS("CB SKIPPED=NO_STREAMS");
    HAS("WALK SKIPPED=NO_BANK");
    CHECK(win_loads[2] == 2);
    fx_direct();
    rset(SMMU_BASE, 0xffffffffu);
    RUN_CLEAN();
    HAS("SMMU UNREADABLE ID0=0X7C017E9A SCR0=0XFFFFFFFF");
    CHECK(win_loads[2] == 2);
    fx_direct();
    rset(SMMU_BASE + 0x20, 0);
    RUN_CLEAN();
    HAS("SMMU UNREADABLE ID0=0X0 ");
    /* A recorded fault: the address and the syndromes are read, and only then. */
    fx_direct();
    rset(SMMU_BASE + 0x48, 0x80000002u);
    rset64(SMMU_BASE + 0x40, UINT64_C(0x0000001234567000));
    rset(SMMU_BASE + 0x50, 0x11);
    rset(SMMU_BASE + 0x54, 0x22);
    rset(SMMU_BASE + 0x58, 0x33);
    RUN_CLEAN();
    HAS("SMMU ID0=0X7C017E9A ID1=0X60800080 ID2=0X7555 SCR0=0X230406 GFSR=0X80000002");
    HAS("SMMU GFAR=0X1234567000 GFSYNR0=0X11 GFSYNR1=0X22 GFSYNR2=0X33");
    CHECK(win_loads[2] == 173 + 5);
    /* The stream match rule: the valid bit, the mask, the lowest match wins, the matches are counted. */
    fx_direct();
    rset(SMMU_BASE + 0x800 + 4 * 3, 0x00001420);                /* valid bit clear: no match */
    rset(SMMU_BASE + 0x800 + 4 * 4, 0x00001460);
    rset(SMMU_BASE + 0x800, 0x801f1400);                        /* mask 0x1F over 0x1400: 0x1400 to 0x141F, not 0x1420 */
    RUN_CLEAN();
    HAS("S1420=NOMATCH S1460=NOMATCH");
    HAS("CB SKIPPED=NO_TRANSLATING_STREAM_BELOW_NCB");
    HAS("WALK SKIPPED=NO_BANK");
    fx_direct();
    rset(SMMU_BASE + 0x800 + 4, 0x80ff1400);                    /* mask 0xFF over 0x1400: both streams */
    rset(SMMU_BASE + 0xc00 + 4, 3);
    RUN_CLEAN();
    HAS("CBBASE=0X15080000 S1420=SMR1.TRANS.CB3.MULTI2");
    HAS("SMMU S1460=SMR1.TRANS.CB3.MULTI2");
    fx_direct();
    rset(SMMU_BASE + 0x800 + 4, 0x80001420);                    /* a second exact match: counted, the lowest index stays */
    rset(SMMU_BASE + 0xc00 + 4, 0x10007);
    RUN_CLEAN();
    HAS("CBBASE=0X15080000 S1420=SMR1.BYPASS.MULTI2");
    HAS("SMMU S1460=SMR4.TRANS.CB3");
    /* The bits above NUMSIDB are not part of the stream id: 0x9420 matches 0x1420 with 15 implemented bits. */
    fx_direct();
    rset(SMMU_BASE + 0x800 + 4 * 3, 0x80009420);
    RUN_CLEAN();
    HAS("S1420=SMR3.TRANS.CB3 ");
    /* S2CR types: only a translating stream names a bank. */
    for (unsigned type = 0; type < 4; type++) {
        static const char *const want[4] = {"S1420=SMR3.TRANS.CB3 S1460=SMR4.TRANS.CB3", "S1420=SMR3.BYPASS S1460=SMR4.BYPASS",
                                            "S1420=SMR3.FAULT S1460=SMR4.FAULT", "S1420=SMR3.RSVD S1460=SMR4.RSVD"};
        fx_direct();
        rset(SMMU_BASE + 0xc00 + 4 * 3, type << 16 | 3);
        rset(SMMU_BASE + 0xc00 + 4 * 4, type << 16 | 3);
        RUN_CLEAN();
        HAS(want[type]);
        if (type) {
            HAS("CB SKIPPED=NO_TRANSLATING_STREAM_BELOW_NCB");
            HAS_NOT("NEXT CB");
        }
    }
    /* CBNDX at NUMCB is no bank: off by one is the classic. Marked .BAD and never read. */
    fx_direct();
    rset(SMMU_BASE + 0xc00 + 4 * 3, 0x80);
    rset(SMMU_BASE + 0xc00 + 4 * 4, 0x80);
    RUN_CLEAN();
    HAS("S1420=SMR3.TRANS.CB128.BAD");
    HAS("SMMU S1460=SMR4.TRANS.CB128.BAD");
    HAS("CB SKIPPED=NO_TRANSLATING_STREAM_BELOW_NCB");
    fx_direct();
    rset(SMMU_BASE + 0xc00 + 4 * 3, 0xff);
    RUN_CLEAN();
    HAS("S1420=SMR3.TRANS.CB255.BAD");
    HAS("NEXT CB3");                                            /* U1's stream still names bank 3 */
    /* The highest bank there is, NUMCB - 1, is read: its page is the last of the window. */
    fx_direct();
    expected_banks[0] = 127;
    expected_banks_n = 1;
    rset(SMMU_BASE + 0xc00 + 4 * 3, 127);
    rset(SMMU_BASE + 0xc00 + 4 * 4, 127);
    fx_bank(127, 0x00010003, 1, 0, 0, 0, 0, 0);
    RUN_CLEAN();
    HAS("NEXT CB127");
    HAS("CB127 CBAR=0X10003 TYPE=S1_S2BYP CBA2R=0X1 VA64=1");
    /* Two streams, two banks: both are read, and the walk keeps its two probes (the budget is 24 lines). */
    fx_direct();
    expected_banks[0] = 3;
    expected_banks[1] = 5;
    expected_banks_n = 2;
    rset(SMMU_BASE + 0xc00 + 4 * 4, 5);
    fx_bank(5, 0x00020005, 1, 0x205f7, 0x803f10, 0, 0, 0x4ff44);
    RUN_CLEAN();
    HAS("S1420=SMR3.TRANS.CB3 S1460=SMR4.TRANS.CB5");
    HAS("NEXT CB3");
    HAS("NEXT CB5");
    HAS("CB5 CBAR=0X20005 TYPE=S1_S2FLT ");
    CHECK(nlines == 24);
    HAS("WALK SUMMARY PROBES=2 ");
    expected_banks_n = 0;
    /* Extended stream ids move the valid bit: refused, not guessed at, and no match register is read. */
    fx_direct();
    rset(SMMU_BASE, 0x230406 | 8);
    RUN_CLEAN();
    HAS("STREAMS=UNSUPPORTED_EXID");
    HAS("CB SKIPPED=NO_STREAMS");
    CHECK(win_loads[2] == 5);
    /* NUMSMRG 0: nothing to scan. NUMSMRG 255: scanned, no more. */
    fx_direct();
    rset(SMMU_BASE + 0x20, 0x7C017E00);
    RUN_CLEAN();
    HAS("SMRG=0X0 ");
    HAS("S1420=NOMATCH S1460=NOMATCH");
    CHECK(win_loads[2] == 5);
    fx_direct();
    rset(SMMU_BASE + 0x20, 0x7C017EFF);
    RUN_CLEAN();
    HAS("SMRG=0XFF ");
    CHECK(win_loads[2] == 5 + 255 + 2 + 12);
    /* Register pages of 4 KiB and of 64 KiB: the bank's own page follows the global pages. */
    fx_direct();
    rset(SMMU_BASE + 0x24, 0x80000000u | 0x00800000u | 1u << 28 | 0x80);
    RUN_CLEAN();
    HAS("CBBASE=0X15040000 ");                                  /* 2 << 1 = 4 pages of 64 KiB */
    return 0;
}

/* ---- bank and walk: in a file of their own, included here because they use everything above ---- */

#include "testdata/sp11-payload-usbsmmu-walk.h"

/* ---- faults -------------------------------------------------------------------------------------------------------------- */

static int suite_faults(void)
{
    unsigned total;
    fx_direct();
    RUN_CLEAN();
    total = nloads;
    CHECK(total == LOADS_UNIT_DIRECT);
    /* An abort at each load of the unit in turn. The run ends, prints its reason and reads nothing more from that window. */
    for (unsigned k = 1; k <= total; k++) {
        fx_direct();
        fault_index = (long)k;
        CHECK(run_it() == 0);
        CLEAN();
        CHECK(nfaults == 1);
        CHECK(line_has("FAULT"));
    }
    /* The same for the hub topology and for a busy U1: the other groups. */
    fx_unit_like();
    RUN_CLEAN();
    total = nloads;
    for (unsigned k = 1; k <= total; k += 3) {
        fx_unit_like();
        fault_index = (long)k;
        CHECK(run_it() == 0);
        CLEAN();
        CHECK(line_has("FAULT"));
    }
    /* An abort at every address of one kind: a whole window, a register page, all of RAM, the tables. */
    static const struct { uint64_t lo, hi; const char *what; } kinds[] = {
        {U0_BASE, U0_BASE + XHC_SIZE, "U0 FAULT AT=CAP0"},
        {U1_BASE, U1_BASE + XHC_SIZE, "U1 FAULT AT=CAP0"},
        {U0_BASE + 0xc000, U0_BASE + 0xd000, "DWC3 FAULT AT=GSNPSID"},
        {SMMU_BASE, SMMU_BASE + SMMU_SIZE, "SMMU FAULT AT=SCR0"},
        {SMMU_BASE + 0x800, SMMU_BASE + 0xc00, "AT=SMR"},
        {SMMU_BASE + 0xc00, SMMU_BASE + 0x1000, "AT=S2CR"},
        {SMMU_BASE + 0x1000, SMMU_BASE + 0x2000, "CB3 FAULT AT=CBAR"},
        {CB_PAGE(3), CB_PAGE(3) + 0x1000, "CB3 FAULT AT=SCTLR"},
        {CB_PAGE(3) + 0x20, CB_PAGE(3) + 0x30, "AT=TTBR0"},
        {U0_BASE + 0x1000, U0_BASE + 0x1100, "RINGS CSZ=1 FAULT AT=ERSTSZ"},
        {DCBAA, DCBAA + 0x100, "U0 SLOTS=UNREAD FAULT"},
        {CTX1, CTX1 + 0x100, "U0S1 CTX=0XCF416AC0 FAULT"},
        {ERST, ERST + 0x10, "FAULT AT=ERST"},
        {RING, RING + 0x1000, "TRB FAULT"},
        {TBL_BASE, TBL_END, "STOP=TABLE_FAULT LVL=0"},
        {UINT64_C(0x80000000), UINT64_C(0x1000000000000), NULL},       /* all RAM */
    };
    for (unsigned i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        fx_direct();
        fault_lo = kinds[i].lo;
        fault_hi = kinds[i].hi;
        if (i == sizeof kinds / sizeof kinds[0] - 1) { fault_lo = UINT64_C(0x80000000); fault_hi = UINT64_C(0x1000000000000); }
        CHECK(run_it() == 0);
        CLEAN();
        if (kinds[i].what) HAS(kinds[i].what);
        HAS("FAULT");
        if (kinds[i].what && i < 3) CHECK(win_loads[i == 1 ? 1 : 0] <= (i == 2 ? 24 : 1));
    }
    return 0;
}

/* ---- hostile ------------------------------------------------------------------------------------------------------------- */

static int suite_hostile(void)
{
    static const uint32_t fills[] = {0, 0xffffffffu, 1, 0x80000000u, 0x7fffffffu, 0x10000, 0xfffffff0u, 0xdeadbeefu, 0x0a600000u};
    for (unsigned i = 0; i < sizeof fills / sizeof fills[0]; i++) {
        fx_direct();
        mode = MODE_FILL;
        fill_value = fills[i];
        expected_banks_n = 0;                   /* hostile registers may name any bank below NUMCB */
        RUN_CLEAN();
        fx_unit_like();
        mode = MODE_FILL;
        fill_value = fills[i];
        expected_banks_n = 0;
        RUN_CLEAN();
    }
    for (uint64_t seed = 0; seed < 300; seed++) {
        fx_direct();
        mode = MODE_RANDOM;
        rng_seed = seed;
        expected_banks_n = 0;
        RUN_CLEAN();
    }
    /* Units that are nearly right: a handful of hostile words in the registers, the rings, the tables and the memory map. */
    for (uint64_t seed = 0; seed < 4000; seed++) {
        if (seed & 1) fx_unit_like(); else fx_direct();
        fx_perturb(seed, 1 + (unsigned)(seed % 9));
        expected_banks_n = 0;
        CHECK(run_it() == 0);
        CLEAN();
        if (line_has("NEXT WALK")) {
            CHECK(!strncmp(line_n(nlines - 1), "WALK SUMMARY", 12));
            CHECK(line_has("WALK SUMMARY PROBES=") && !line_has("WALK SUMMARY PROBES=0"));
        }
    }
    /* The first load of a hostile unit is still the first load of a unit: nothing reads before the first NEXT line. */
    fx_direct();
    mode = MODE_FILL;
    fill_value = 0xffffffffu;
    RUN_CLEAN();
    CHECK(loads_before_line(0) == 0);
    return 0;
}

/* ---- el, args, map ------------------------------------------------------------------------------------------------------- */

static int suite_el(void)
{
    for (uint64_t el = 0; el < 4; el++) {
        fx_direct();
        el_raw = el << 2;
        RUN_CLEAN();
        CHECK(sysreg_reads == 1 && events[0].kind == EV_SYSREG);
        if (el == 2) {
            CHECK(nlines == 24);
        } else {
            CHECK(nlines == 1 && nloads == 0);
            LINE_IS(0, "SKIPPED_NOT_AT_EL2");
        }
    }
    fx_direct();
    el_raw = (UINT64_C(0xffffffffffffff00) | 2 << 2);          /* the reserved bits of CurrentEL are not an EL */
    RUN_CLEAN();
    CHECK(nlines == 24);
    fx_direct();
    el_raw = 1 << 2;                                           /* EL1 at a payload without load32: still only the skip line */
    A = args();
    A.ops.load32 = NULL;
    CHECK(go(&A) == 0 && nlines == 1);

    /* Arguments: wrong magic, version, size, missing ops. Nothing is printed, read or asked of the register file. */
    for (unsigned i = 0; i < 6; i++) {
        fx_direct();
        A = args();
        if (i == 0) A.magic ^= 1;
        if (i == 1) A.version = 2;
        if (i == 2) A.size = sizeof A - 8;
        if (i == 3) A.ops.puts = NULL;
        if (i == 4) A.ops.hex = NULL;
        CHECK(go(i == 5 ? NULL : &A) == Q1N1_PAYLOAD_RET_BAD_ARGS);
        CHECK(nlines == 0 && nloads == 0 && sysreg_reads == 0);
    }
    fx_direct();
    A = args();
    A.ops.load32 = NULL;
    CHECK(go(&A) == Q1N1_PAYLOAD_RET_BAD_ARGS);
    LINE_IS(0, "REFUSED_NO_LOAD32");
    CHECK(nlines == 1 && nloads == 0);

    /* A memory map that makes no sense is no map: every RAM load is refused and the MMIO is read as usual. */
    for (unsigned i = 0; i < 12; i++) {
        fx_direct();
        A = args();
        switch (i) {
        case 0: A.map_base = 0; break;
        case 1: A.map_stride = 39; break;
        case 2: A.map_stride = 44; A.map_size = 44 * map_n; break;
        case 3: A.map_stride = 4104; A.map_size = 4104 * map_n; break;
        case 4: A.map_size = 0; break;
        case 5: A.map_size = MAP_STRIDE * map_n - 8; break;
        case 6: A.map_base += 4; break;
        case 7: { uint64_t v = UINT64_C(1) << 40; memcpy(map_buf + 24, &v, 8); break; }
        case 8: { uint64_t v = ~UINT64_C(0) - 0xfff; memcpy(map_buf + 8, &v, 8); break; }
        case 9: A.map_stride = 32; A.map_size = 32 * map_n; break;
        case 10: { uint64_t v = UINT64_C(0xfffffffffffff000); memcpy(map_buf + 8, &v, 8); memcpy(map_buf + 24, &(uint64_t){2}, 8); break; }
        default: A.map_stride = 0; break;
        }
        CHECK(go(&A) == 0);
        CLEAN();
        HAS("U0 SLOTS=UNREAD REFUSED=NO_MAP");
        HAS("REFUSED=NO_MAP AT=ERST");
        CHECK(win_loads[3] == 0);
        HAS("U0 CAPL=0X20");
    }
    /* A thousand and twenty-four descriptors are a map; a thousand and twenty-five are not. */
    for (unsigned count = 1024; count <= 1025; count++) {
        fx_direct();
        for (unsigned i = map_n; i < count; i++) map_add(11, UINT64_C(0xf1000000) + (uint64_t)i * 4096, 1);
        RUN_CLEAN();
        if (count == 1024) HAS("U0S1 RT=0 RP=2 SPD=4"); else HAS("U0 SLOTS=UNREAD REFUSED=NO_MAP");
    }
    /* A map with a descriptor stride larger than the fields, as UEFI is free to make it. */
    fx_direct();
    {
        static uint8_t wide[48 * 16 + 64];
        uint8_t *at = wide + 8 - ((uintptr_t)wide & 7);
        for (unsigned i = 0; i < map_n; i++) memcpy(at + i * 64, map_buf + i * MAP_STRIDE, MAP_STRIDE);
        A = args();
        A.map_base = (uintptr_t)at;
        A.map_stride = 64;
        A.map_size = 64 * map_n;
        CHECK(go(&A) == 0);
        CLEAN();
        HAS("U0S1 RT=0 RP=2 SPD=4");
    }
    /* A stride that is no multiple of 8 puts the 64-bit fields at odd addresses: refused even though every descriptor is sound. */
    fx_direct();
    {
        static uint8_t odd[44 * 16 + 64];
        uint8_t *at = odd + 8 - ((uintptr_t)odd & 7);
        for (unsigned i = 0; i < map_n; i++) memcpy(at + i * 44, map_buf + i * MAP_STRIDE, 40);
        A = args();
        A.map_base = (uintptr_t)at;
        A.map_stride = 44;
        A.map_size = 44 * map_n;
        CHECK(go(&A) == 0);
        CLEAN();
        HAS("U0 SLOTS=UNREAD REFUSED=NO_MAP");
        CHECK(win_loads[3] == 0);
    }
    return 0;
}

/* ---- what the document prints ---------------------------------------------------------------------------------------------- */

/* The lines of the two unit-like fixtures, as `dump hub` and `dump direct`: docs/SP11-PAYLOAD-USBSMMU.md gives them and
 * tools/test-q1n1-sp11-payload-usbsmmu.py compares. */
static int dump_unit(const char *which)
{
    if (!strcmp(which, "hub")) fx_unit_like();
    else fx_direct();
    CHECK(run_it() == 0);
    for (unsigned i = 0; i < nlines; i++) printf("PAYLOAD USBSMMU %s\n", line_n(i));
    return 0;
}

/* ---- the numbers for the planning table ----------------------------------------------------------------------------------- */

/* The most lines and loads of everything the suites ran, plus a few thousand more hostile units. */
static int report_lines(void)
{
    if (suite_unit() || suite_smmu() || suite_slots() || suite_bank() || suite_walk()) return 1;
    for (uint64_t seed = 0; seed < 3000; seed++) {
        if (seed & 1) fx_unit_like(); else fx_direct();
        fx_perturb(seed + 99, 1 + (unsigned)(seed % 12));
        run_it();
    }
    printf("LINES_MAX=%u\nLOADS_MAX=%u\n", max_lines, max_loads);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"unit", suite_unit}, {"xhc", suite_xhc}, {"rings", suite_rings}, {"slots", suite_slots}, {"smmu", suite_smmu},
        {"bank", suite_bank}, {"walk", suite_walk}, {"faults", suite_faults}, {"hostile", suite_hostile}, {"el", suite_el},
    };
    unsigned ran = 0;
    if (argc > 1 && !strcmp(argv[1], "lines-report")) return report_lines();
    if (argc > 2 && !strcmp(argv[1], "dump")) return dump_unit(argv[2]);
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) {
            fprintf(stderr, "FAIL: suite %s\n", suites[i].name);
            return 1;
        }
        ran++;
    }
    CHECK(max_lines == 24 && max_loads <= LOAD_CAP);
    printf("PASS: %u payload usbsmmu suites, %u checks (most lines %u, most loads %u)\n", ran, checks, max_lines, max_loads);
    return 0;
}
