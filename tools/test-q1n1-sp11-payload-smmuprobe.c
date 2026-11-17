/* SPDX-License-Identifier: MIT */
/* Host test for the smmuprobe payload (payloads/smmuprobe.c, docs/SP11-PAYLOAD-SMMUPROBE.md), built natively with Q1N1_PAYLOAD_HOST_TEST
 * so that its register reads, its AT S1E2R and its guarded loads come from the machine modelled in
 * tools/test-q1n1-sp11-payload-smmuprobe-world.h. Driven by tools/test-q1n1-sp11-payload-smmuprobe.py under ASan and UBSan.
 *
 * Suites: unit (the page of a good world, the exact loads in order, the ATs, the registers, the order and the eight seconds), config (an
 * absent function, faults, loops and hostile pointers in both capability lists, the page edge, link decoding), smmu (a fault at each
 * register, and the loads that follow it), verdict (every outcome of the stream table lookup, linear and two-level), ack (CR0 against
 * CR0ACK), pages (what the MMU says of each device page: unmapped, Normal, Device, and nothing is read where it says no), tablepages
 * (the same for the descriptor's page and the entry's), ram (every type of memory map descriptor, descriptor edges, bad maps), counter
 * (the eight seconds, a missing, stuck or backward counter, an absurd CNTFRQ_EL0), el (not at EL2, bad arguments, no load op), budget
 * (the line budget, the load cap), worst (the world that prints the most lines), fuzz (random worlds against an oracle written
 * another way).
 *
 * What it cannot show: what the unit does at these addresses, what an EL3 does with a read that hangs, or what the binary does: the Python
 * driver disassembles the built binary for that. Evidence: EXPERIMENTAL (host model only); hardware NOT RUN. */
#include "test-q1n1-sp11-payload-smmuprobe-world.h"

/* ---- Unit: a good world ---------------------------------------------------------------------------------------------------------- */

/* The page of the good world (the model prints it: docs/SP11-PAYLOAD-SMMUPROBE.md, "What the host model prints"); every value was
 * checked by hand against the scripted words. */
static const char *const unit_page[] = {
    P "START CURRENTEL=0X8 FREQ=19200000 ECAM=0X70000000 SMMU=0X15400000",
    P "MAP RP=DEVICE.NSH EP=DEVICE.NSH SMMU=DEVICE.NSH",
    P "RP ID=0X11117CB CMDSTS=0X100007 CLASSREV=0X6040001 HDR=0X10010 BUSES=0X10100",
    P "RP CAPPTR=0X40",
    P "EP ID=0XA80B144D CMDSTS=0X100406 CLASSREV=0X1080200 HDR=0X10 BAR0=0X60800004",
    P "EP BAR1=0X0 CAPPTR=0X40",
    P "NEXT PCIE_CAPS AFTER 8 S",
    P "RP.PCIE AT=0X70 HDR=0X420010 TYPE=4 DEVCTLSTA=0X2810 LNKCAP=0X100C44",
    P "RP.PCIE LNKCTLSTA=0X20440040 LINK=GEN4.X4 DLLA=1 LNKCAP2=0X1E LNKCTL2STA2=0X4",
    P "EP.PCIE AT=0X80 HDR=0X20010 TYPE=0 DEVCTLSTA=0X2810 LNKCAP=0XC44",
    P "EP.PCIE LNKCTLSTA=0X440040 LINK=GEN4.X4 LNKCAP2=0X1E LNKCTL2STA2=0X4",
    P "RP.AER AT=0X140 UESTA=0X4000 UEMASK=0X400000 CESTA=0X2000 CEMASK=0X0 ROOTERR=0X0",
    P "EP.AER AT=0X100 UESTA=0X0 UEMASK=0X400000 CESTA=0X0 CEMASK=0XE000",
    P "NEXT SMMU_REGISTERS AFTER 8 S",
    P "SMMU IDR0=0X5A000000 IDR1=0X5A000004 IDR2=0X5A000008 IDR3=0X5A00000C",
    P "SMMU IDR4=0X5A000010 IDR5=0X5A000014 IIDR=0X5A000018 AIDR=0X5A00001C CR0=0XD",
    P "SMMU CR0ACK=0XD GBPA=0X1000 GERROR=0X0 STRTAB_BASE=0X400000008A000000",
    P "SMMU STRTAB_CFG=0X10294",
    P "STRTAB FMT=1 SPLIT=10 LOG2SIZE=20 BASE=0X8A000000 SID=0X60100",
    P "L1 AT=0X8A000C00 MAP=WB.IS DESC=0X8A40000B",
    P "STE AT=0X8A404000 MAP=WB.IS V=1 CONFIG=6 DW0=0XD DW1=0X0 DW2=0XD409000000007",
    P "STE DW3=0X8C000000",
    P "S2 VMID=7 T0SZ=16 SL0=2 TG=1 AA64=1 TTB=0X8C000000",
    P "VERDICT STREAM=0X60100 MODE=S2 WHY=NONE",
    P "DONE SMMU_GROUP_RAN LOADS=67 FAULTS=0 REFUSED=0 SMMU_TRIED=14",
};
#define UNIT_LINES (sizeof unit_page / sizeof unit_page[0])

#define RPo(o) (RP_PAGE + (o))
#define EPo(o) (EP_PAGE + (o))
#define SMo(o) (SMMU_PAGE + (o))
/* The loads of the good world, in the order the brief gives: both headers, the PCI Express capabilities and the AER capabilities (each
 * list walked from its head), then the SMMU registers, the level-1 descriptor and the four doublewords of the entry. */
static const uint64_t unit_loads[] = {
    RPo(0x00), RPo(0x04), RPo(0x08), RPo(0x0c), RPo(0x18), RPo(0x34),
    EPo(0x00), EPo(0x04), EPo(0x08), EPo(0x0c), EPo(0x10), EPo(0x14), EPo(0x34),
    RPo(0x40), RPo(0x50), RPo(0x70), RPo(0x78), RPo(0x7c), RPo(0x80), RPo(0x9c), RPo(0xa0),
    EPo(0x40), EPo(0x50), EPo(0x70), EPo(0x80), EPo(0x88), EPo(0x8c), EPo(0x90), EPo(0xac), EPo(0xb0),
    RPo(0x100), RPo(0x140), RPo(0x144), RPo(0x148), RPo(0x150), RPo(0x154), RPo(0x170),
    EPo(0x100), EPo(0x104), EPo(0x108), EPo(0x110), EPo(0x114),
    SMo(0x00), SMo(0x04), SMo(0x08), SMo(0x0c), SMo(0x10), SMo(0x14), SMo(0x18), SMo(0x1c), SMo(0x20), SMo(0x24), SMo(0x44), SMo(0x60),
    SMo(0x80), SMo(0x84), SMo(0x88),
    L1_AT, L1_AT + 4,
    STE_AT, STE_AT + 4, STE_AT + 8, STE_AT + 12, STE_AT + 16, STE_AT + 20, STE_AT + 24, STE_AT + 28,
};
#define UNIT_LOADS (sizeof unit_loads / sizeof unit_loads[0])
#define CONFIG_LOADS 42u                /* the loads of the six configuration groups of the good world */

/* The first load made after the NEXT line at index `k` is the next thing the payload does: no line in between, eight seconds later (and
 * not nine: one counter step is a millisecond or so), at `want`. */
static int check_wait(int k, uint64_t want, uint64_t freq)
{
    int i = first_load_after((unsigned)k);
    CHECK(k >= 0 && i >= 0);
    CHECK_EQ(loads[i].lines, k + 1);
    CHECK_EQ(loads[i].addr, want);
    CHECK(loads[i].clock - line_clock[k] >= 8 * freq);
    CHECK(loads[i].clock - line_clock[k] <= 8 * freq + 2000000);
    return 0;
}

static int suite_unit(void)
{
    struct world w;
    int k1, k2, i1, i2;
    world_good(&w);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK_EQ(line_count, UNIT_LINES);
    for (unsigned i = 0; i < line_count && i < UNIT_LINES; i++) {
        if (strcmp(lines[i], unit_page[i])) fprintf(stderr, "line %u:\n  %s\n  %s\n", i, lines[i], unit_page[i]);
        CHECK(!strcmp(lines[i], unit_page[i]));
    }
    CHECK_EQ(load_n, UNIT_LOADS);
    for (unsigned i = 0; i < load_n && i < UNIT_LOADS; i++) {
        if (loads[i].addr != unit_loads[i]) fprintf(stderr, "load %u: %#llx, wanted %#llx\n", i, (unsigned long long)loads[i].addr, (unsigned long long)unit_loads[i]);
        CHECK_EQ(loads[i].addr, unit_loads[i]);
        CHECK_EQ(loads[i].rc, 0);
    }
    CHECK_EQ(at_count, 5);
    CHECK_EQ(at_log[0], RP_PAGE);
    CHECK_EQ(at_log[1], EP_PAGE);
    CHECK_EQ(at_log[2], SMMU_PAGE);
    CHECK_EQ(at_log[3], L1_AT);
    CHECK_EQ(at_log[4], STE_AT);
    CHECK_EQ(read_count, 2);
    CHECK(!strcmp(read_log[0], "CurrentEL") && !strcmp(read_log[1], "CNTFRQ_EL0"));
    k1 = find_line(P "NEXT PCIE_CAPS");
    k2 = find_line(P "NEXT SMMU_REGISTERS");
    CHECK(k1 >= 0 && k2 > k1);
    if (check_wait(k1, RP_PAGE + 0x40, FREQ) || check_wait(k2, SMMU_PAGE, FREQ)) return 1;
    i1 = first_load_after((unsigned)k1);
    i2 = first_load_after((unsigned)k2);
    for (int i = 0; i < i1; i++) {                       /* before the first NEXT: only the dwords below the capability lists */
        CHECK((loads[i].addr & ~UINT64_C(0xfff)) == RP_PAGE || (loads[i].addr & ~UINT64_C(0xfff)) == EP_PAGE);
        CHECK((loads[i].addr & 0xfff) < 0x40);
    }
    for (int i = i1; i < i2; i++) CHECK((loads[i].addr & ~UINT64_C(0xfff)) == RP_PAGE || (loads[i].addr & ~UINT64_C(0xfff)) == EP_PAGE);
    world_free(&w);
    return 0;
}

/* ---- Config: the two functions ---------------------------------------------------------------------------------------------------- */

#define SCEN(...) do { world_good(&w); __VA_ARGS__; CHECK_EQ(go(&w.a), 0); CHECK_DISCIPLINE(); } while (0)
#define END() world_free(&w)

static int suite_config(void)
{
    struct world w;
    /* An absent function: the id is all ones, or the vendor is. Nothing else of it is read, and the other groups still run. */
    SCEN(bus_set(RP_PAGE, 0xffffffff));
    CHECK_LINE(P "RP ID=0XFFFFFFFF ABSENT");
    CHECK_LINE(P "RP.PCIE PCIE=NOT_READ");
    CHECK_LINE(P "RP.AER AER=NO_PCIE_CAP");
    CHECK_EQ(loads_in(RP_PAGE, RP_PAGE + 0x1000), 1);
    CHECK_LINE(P "VERDICT STREAM=0X60100 MODE=S2 WHY=NONE");
    CHECK_TOKEN(P "EP.PCIE ", "LINK=GEN4.X4");
    END();
    SCEN(bus_set(EP_PAGE, 0x1234ffff));
    CHECK_LINE(P "EP ID=0X1234FFFF ABSENT");
    CHECK_EQ(loads_in(EP_PAGE, EP_PAGE + 0x1000), 1);
    CHECK_LINE(P "EP.PCIE PCIE=NOT_READ");
    END();
    /* A fault at the id: the rest of the function is not attempted; a fault at the capability pointer says so on the head line. */
    SCEN(bus_fault(RP_PAGE));
    CHECK_LINE(P "RP ID=FAULT CMDSTS=NOT_ATTEMPTED CLASSREV=NOT_ATTEMPTED HDR=NOT_ATTEMPTED");
    CHECK_EQ(loads_in(RP_PAGE, RP_PAGE + 0x1000), 1);
    CHECK_LINE(P "RP.PCIE PCIE=NOT_READ");
    CHECK_LINE(P "RP.AER AER=NO_PCIE_CAP");
    CHECK_TOKEN(P "EP.AER ", "AT=0X100");
    END();
    SCEN(bus_fault(RP_PAGE + 0x34));
    CHECK_TOKEN(P "RP ", "CAPPTR=FAULT");
    CHECK_EQ(loads_in(RP_PAGE, RP_PAGE + 0x1000), 6);
    CHECK_LINE(P "RP.PCIE PCIE=NOT_READ");
    END();
    /* No capability list (status bit 4 clear): the pointer is not read. */
    SCEN(bus_set(RP_PAGE + 4, 0x00000007));
    CHECK_NO_TOKEN(P "RP ", "CAPPTR=");
    CHECK_EQ(loads_in(RP_PAGE + 0x34, RP_PAGE + 0x38), 0);
    CHECK_LINE(P "RP.PCIE PCIE=NONE");
    CHECK_LINE(P "RP.AER AER=NO_PCIE_CAP");
    END();
    /* Hostile capability lists: a loop, a two-step loop, a pointer below 0x40, the last legal dword, unaligned pointers. */
    SCEN(bus_set(RP_PAGE + 0x40, 0x00004001));
    CHECK_EQ(loads_in(RP_PAGE + 0x40, RP_PAGE + 0x44), 16);
    CHECK_LINE(P "RP.PCIE PCIE=NONE");
    CHECK_LINE(P "RP.AER AER=NO_PCIE_CAP");
    END();
    SCEN(bus_set(RP_PAGE + 0x40, 0x00005001); bus_set(RP_PAGE + 0x50, 0x00004005));
    CHECK_EQ(loads_in(RP_PAGE + 0x40, RP_PAGE + 0x54), 16);
    CHECK_LINE(P "RP.PCIE PCIE=NONE");
    END();
    SCEN(bus_set(RP_PAGE + 0x34, 0x3c));
    CHECK_TOKEN(P "RP ", "CAPPTR=0X3C");
    CHECK_EQ(loads_in(RP_PAGE + 0x40, RP_PAGE + 0x1000), 0);
    CHECK_LINE(P "RP.PCIE PCIE=NONE");
    END();
    SCEN(bus_set(RP_PAGE + 0x34, 0xfc); bus_set(RP_PAGE + 0xfc, 0x00000101));
    CHECK_EQ(loads_in(RP_PAGE + 0x40, RP_PAGE + 0x1000), 1);
    CHECK_EQ(loads_in(RP_PAGE + 0xfc, RP_PAGE + 0x100), 1);
    CHECK_LINE(P "RP.PCIE PCIE=NONE");
    END();
    SCEN(bus_set(RP_PAGE + 0x34, 0x43));
    CHECK_TOKEN(P "RP ", "CAPPTR=0X43");
    CHECK_TOKEN(P "RP.PCIE ", "AT=0X70");
    END();
    SCEN(bus_set(RP_PAGE + 0x40, 0x00005301));
    CHECK_TOKEN(P "RP.PCIE ", "AT=0X70");
    END();
    /* PCI Express capability version 1 has no Link Capabilities 2; a fault in the Link Status stops the function. */
    SCEN(bus_set(RP_PAGE + 0x70, 0x00410010));
    CHECK_TOKEN(P "RP.PCIE ", "TYPE=4");
    CHECK_NO_TOKEN(P "RP.PCIE ", "LNKCAP2=");
    CHECK_EQ(loads_in(RP_PAGE + 0x9c, RP_PAGE + 0xa4), 0);
    CHECK_TOKEN(P "RP.AER ", "ROOTERR=0X0");
    END();
    SCEN(bus_fault(RP_PAGE + 0x80));
    CHECK_TOKEN(P "RP.PCIE ", "LNKCTLSTA=FAULT");
    CHECK_NO_TOKEN(P "RP.PCIE ", "LINK=");
    CHECK_TOKEN(P "RP.PCIE ", "LNKCAP2=NOT_ATTEMPTED");
    CHECK_TOKEN(P "RP.PCIE ", "LNKCTL2STA2=NOT_ATTEMPTED");
    CHECK_LINE(P "RP.AER AER=NOT_READ");
    CHECK_TOKEN(P "EP.PCIE ", "LINK=GEN4.X4");
    END();
    /* Hostile extended lists: a loop, an empty or all-ones header, a pointer below 0x100, AER at the last dword of the page. */
    SCEN(bus_set(RP_PAGE + 0x100, 0x1001000b));
    CHECK_EQ(loads_in(RP_PAGE + 0x100, RP_PAGE + 0x104), 24);
    CHECK_LINE(P "RP.AER AER=NONE");
    END();
    SCEN(bus_set(RP_PAGE + 0x100, 0x00000000));
    CHECK_EQ(loads_in(RP_PAGE + 0x100, RP_PAGE + 0x104), 1);
    CHECK_LINE(P "RP.AER AER=NONE");
    END();
    SCEN(bus_set(RP_PAGE + 0x100, 0xffffffff));
    CHECK_LINE(P "RP.AER AER=NONE");
    END();
    SCEN(bus_set(RP_PAGE + 0x100, 0x0fc1000b));
    CHECK_EQ(loads_in(RP_PAGE, RP_PAGE + 0x1000), 15);                      /* head 6, capabilities 3 + 5, one AER header read */
    CHECK_LINE(P "RP.AER AER=NONE");
    END();
    SCEN(bus_set(RP_PAGE + 0x100, 0x14010101));
    CHECK_TOKEN(P "RP.AER ", "AT=0X140");                                  /* the id is 16 bits wide: 0x0101 is not AER */
    END();
    SCEN(bus_set(RP_PAGE + 0x70, 0x0042a010));
    CHECK_TOKEN(P "RP.PCIE ", "AT=0X70");                                  /* the id is 8 bits wide: the next pointer is not part of it */
    END();
    /* A fault in the middle of a list stops that function: the capability walk, the extended walk, the first read of it. */
    SCEN(bus_fault(RP_PAGE + 0x50));
    CHECK_LINE(P "RP.PCIE PCIE=NOT_READ");
    CHECK_LINE(P "RP.AER AER=NO_PCIE_CAP");
    CHECK_EQ(loads_in(RP_PAGE + 0x40, RP_PAGE + 0x1000), 2);
    END();
    SCEN(bus_fault(RP_PAGE + 0x140));
    CHECK_LINE(P "RP.AER AER=FAULT");
    CHECK_EQ(loads_in(RP_PAGE + 0x100, RP_PAGE + 0x1000), 2);
    END();
    SCEN(bus_fault(EP_PAGE + 0x100));
    CHECK_LINE(P "EP.AER AER=FAULT");
    END();
    SCEN(bus_set(EP_PAGE + 0x100, 0xffc1000b); bus_set(EP_PAGE + 0xffc, 0x00020001));
    CHECK_TOKEN(P "EP.AER ", "AT=0XFFC");
    CHECK_TOKEN(P "EP.AER ", "UESTA=NOT_ATTEMPTED");
    CHECK_TOKEN(P "EP.AER ", "CEMASK=NOT_ATTEMPTED");
    CHECK_EQ(loads_in(EP_PAGE + 0xffc, EP_PAGE + 0x1000), 1);
    END();
    /* The root error status only for a root port (the capability's type), not for any bridge. */
    SCEN(bus_set(RP_PAGE + 0x70, 0x00620010));
    CHECK_TOKEN(P "RP.PCIE ", "TYPE=6");
    CHECK_NO_TOKEN(P "RP.AER ", "ROOTERR=");
    END();
    /* Data link layer active: only where Link Capabilities bit 20 says the function reports it, and then bit 13 of the status. */
    SCEN(bus_set(RP_PAGE + 0x80, 0x00440040));
    CHECK_TOKEN(P "RP.PCIE ", "DLLA=0");
    END();
    SCEN(bus_set(RP_PAGE + 0x7c, 0x00000c44));
    CHECK_NO_TOKEN(P "RP.PCIE ", "DLLA=");
    END();
    SCEN(bus_set(EP_PAGE + 0x8c, 0x00100c44));
    CHECK_TOKEN(P "EP.PCIE ", "DLLA=0");
    END();
    SCEN(bus_set(EP_PAGE + 0x8c, 0x00100c44); bus_set(EP_PAGE + 0x90, 0x20440040));
    CHECK_TOKEN(P "EP.PCIE ", "DLLA=1");
    END();
    /* The link as the status register says it: speed code and width, nothing of the bits around them. */
    static const struct { uint32_t sta; const char *text; } links[] = {
        {0x0000, "SPEED0.X0"}, {0x0011, "GEN1.X1"}, {0x0022, "GEN2.X2"}, {0x0083, "GEN3.X8"}, {0x0104, "GEN4.X16"}, {0x03f5, "GEN5.X63"},
        {0x0206, "GEN6.X32"}, {0x0007, "SPEED7.X0"}, {0x000f, "SPEED15.X0"}, {0xfc04, "GEN4.X0"}, {0xfc54, "GEN4.X5"},
    };
    for (unsigned i = 0; i < sizeof links / sizeof links[0]; i++) {
        char token[40];
        snprintf(token, sizeof token, "LINK=%s", links[i].text);
        SCEN(bus_set(EP_PAGE + 0x90, links[i].sta << 16));
        CHECK_TOKEN(P "EP.PCIE ", token);
        END();
    }
    /* The header type: the multi-function bit does not hide a bridge, a CardBus header has neither bus numbers nor BARs, and an
     * endpoint header shows both BARs. */
    SCEN(bus_set(RP_PAGE + 0x0c, 0x00810010));
    CHECK_TOKEN(P "RP ", "BUSES=0X10100");
    END();
    SCEN(bus_set(RP_PAGE + 0x0c, 0x00020010));
    CHECK_NO_TOKEN(P "RP ", "BUSES=");
    CHECK_NO_TOKEN(P "RP ", "BAR0=");
    CHECK_TOKEN(P "RP ", "CAPPTR=0X40");
    END();
    SCEN(bus_set(RP_PAGE + 0x0c, 0x00000010); bus_set(RP_PAGE + 0x10, 0x11110004); bus_set(RP_PAGE + 0x14, 0x22220000));
    CHECK_TOKEN(P "RP ", "BAR0=0X11110004");
    CHECK_TOKEN(P "RP ", "BAR1=0X22220000");
    CHECK_NO_TOKEN(P "RP ", "BUSES=");
    END();
    return 0;
}

/* ---- SMMU: a fault at each register ------------------------------------------------------------------------------------------------ */

static int suite_smmu(void)
{
    struct world w;
    for (unsigned enabled = 0; enabled < 2; enabled++)
        for (unsigned k = 0; k < 14; k++)
            for (unsigned hi = 0; hi < (k == 12 ? 2u : 1u); hi++) {
                struct smmu_cfg s = good_smmu;
                uint64_t at = SMMU_PAGE + smmu_offsets[k] + (hi ? 4 : 0);
                unsigned before = k + (k > 12), attempted = before + (k == 12 ? 1 + hi : 1);
                const char *mode = "UNKNOWN", *why;
                char want[128];
                s.cr0 = enabled ? 0xd : 0;
                s.gbpa = enabled ? 0x1000 : 0x100000;
                world_good(&w);
                put_smmu(&s);
                bus_fault(at);
                CHECK_EQ(go(&w.a), 0);
                CHECK_DISCIPLINE();
                CHECK_EQ(loads_in(SMMU_PAGE, SMMU_PAGE + 0x90), attempted);
                CHECK_EQ(load_n, CONFIG_LOADS + attempted);                  /* and no RAM word at all */
                CHECK_EQ(at_count, 3);
                for (unsigned i = 0; i < 14; i++) {
                    char tok[32];
                    snprintf(tok, sizeof tok, "%s=%s", smmu_names[i], i < k ? "0X" : i == k ? "FAULT" : "NOT_ATTEMPTED");
                    if (!has_token(P "SMMU ", tok, i >= k)) {
                        fprintf(stderr, "FAIL: no %s (k=%u hi=%u enabled=%u)\n", tok, k, hi, enabled);
                        return 1;
                    }
                    checks++;
                }
                if (k <= 8) why = "CR0_NOT_READ";
                else if (k == 9) why = "CR0ACK_NOT_READ";
                else if (enabled) why = "STRTAB_NOT_READ";
                else if (k <= 10) why = "GBPA_NOT_READ";
                else {
                    mode = "ABORT_GLOBAL";
                    why = "SMMU_DISABLED";
                }
                snprintf(want, sizeof want, P "VERDICT STREAM=0X60100 MODE=%s WHY=%s", mode, why);
                CHECK_LINE(want);
                snprintf(want, sizeof want, "SMMU_TRIED=%u", k + 1);
                CHECK_TOKEN(P "DONE ", want);
                CHECK_TOKEN(P "DONE ", "FAULTS=1");
                CHECK_NO_LINE(P "STRTAB ");
                CHECK_NO_LINE(P "L1 ");
                CHECK_NO_LINE(P "STE ");
                world_free(&w);
            }
    return 0;
}

/* ---- Verdict: every outcome of the stream table lookup --------------------------------------------------------------------------- */

#define LB UINT64_C(0x80000000)
#define LSTE UINT64_C(0x81804000)       /* a linear table at LB: the entry of StreamID 0x60100 is at LB + 0x60100 * 64 */
struct vcase {
    const char *name;
    uint32_t cr0, gbpa;
    uint64_t base;
    uint32_t cfg;
    uint64_t l1_at, l1;                 /* an L1 line is expected at l1_at (0: none); the descriptor is scripted when l1_reads > 0 */
    unsigned l1_reads;
    uint64_t ste_at, dw0;               /* an STE line is expected at ste_at (0: none); the entry is scripted when ste_reads > 0 */
    unsigned ste_reads;
    uint64_t fault_at;                  /* a scripted fault (0: none) */
    const char *mode, *why;
};
static const struct vcase vcases[] = {
    /* linear table, LOG2SIZE 20 */
    {"lin-s2", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, 0xd, 8, 0, "S2", "NONE"},
    {"lin-s1", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, 0x100b, 8, 0, "S1", "NONE"},
    {"lin-s1s2", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, 0xf, 8, 0, "S1S2", "NONE"},
    {"lin-bypass", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, 0x9, 8, 0, "BYPASS", "NONE"},
    {"lin-abort", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, 0x1, 8, 0, "ABORT", "NONE"},
    {"lin-invalid-zero", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, 0x0, 8, 0, "INVALID", "NONE"},
    {"lin-invalid-v-clear", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, UINT64_C(0xfffffffffffffffe), 8, 0, "INVALID", "NONE"},
    {"lin-reserved-1", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, 0x3, 8, 0, "RESERVED", "NONE"},
    {"lin-reserved-2", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, 0x5, 8, 0, "RESERVED", "NONE"},
    {"lin-reserved-3", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, UINT64_C(0xfffffffffffffff7), 8, 0, "RESERVED", "NONE"},
    /* a StreamID beyond the table, a table that just holds it, reserved formats */
    {"sid-beyond-18", 0xd, 0, LB, 0x12, 0, 0, 0, 0, 0, 0, 0, "NO_STE", "SID_BEYOND_TABLE"},
    {"sid-beyond-0", 0xd, 0, LB, 0x00, 0, 0, 0, 0, 0, 0, 0, "NO_STE", "SID_BEYOND_TABLE"},
    {"sid-fits-19", 0xd, 0, LB, 0x13, 0, 0, 0, LSTE, 0xd, 8, 0, "S2", "NONE"},
    {"fmt-2", 0xd, 0, LB, 0x20014, 0, 0, 0, 0, 0, 0, 0, "UNKNOWN", "STRTAB_FORMAT"},
    {"fmt-3", 0xd, 0, LB, 0x30014, 0, 0, 0, 0, 0, 0, 0, "UNKNOWN", "STRTAB_FORMAT"},
    {"base-all-ones", 0xd, 0, UINT64_C(0xffffffffffffffff), 0x14, 0, 0, 0, UINT64_C(0x10000001803fc0), 0, 0, 0, "UNKNOWN", "TABLE_NOT_RAM"},
    /* two levels: SPLIT 10, 8 and 6 (each lands the descriptor and the entry somewhere else), spans, unusable pointers */
    {"2l-split-10-s2", 0xd, 0, TB, 0x10294, L1_AT, 0x8a40000b, 2, STE_AT, 0xd, 8, 0, "S2", "NONE"},
    {"2l-split-8-bypass", 0xd, 0, TB, 0x10214, 0x8a003008, 0x8a300009, 2, 0x8a300000, 0x9, 8, 0, "BYPASS", "NONE"},
    {"2l-split-6-abort", 0xd, 0, TB, 0x10194, 0x8a00c020, 0x8a200007, 2, 0x8a200000, 0x1, 8, 0, "ABORT", "NONE"},
    {"2l-span-0", 0xd, 0, TB, 0x10294, L1_AT, 0x8a400000, 2, 0, 0, 0, 0, "NO_STE", "NO_L2_TABLE"},
    {"2l-span-9-too-small", 0xd, 0, TB, 0x10294, L1_AT, 0x8a400009, 2, 0, 0, 0, 0, "NO_STE", "BEYOND_L2_SPAN"},
    {"2l-span-10-just-enough", 0xd, 0, TB, 0x10294, L1_AT, 0x8a40000a, 2, STE_AT, 0xd, 8, 0, "S2", "NONE"},
    {"2l-span-31", 0xd, 0, TB, 0x10294, L1_AT, 0x8a40001f, 2, STE_AT, 0x9, 8, 0, "BYPASS", "NONE"},
    {"2l-span-16", 0xd, 0, TB, 0x10294, L1_AT, 0x8a400010, 2, STE_AT, 0xd, 8, 0, "S2", "NONE"},
    {"2l-l2ptr-bit-50", 0xd, 0, TB, 0x10294, L1_AT, UINT64_C(0x000f00008a40000b), 2, UINT64_C(0x000f00008a404000), 0, 0, 0, "UNKNOWN", "TABLE_NOT_RAM"},
    {"lin-base-bit-50", 0xd, 0, UINT64_C(0x000f000080000000), 0x14, 0, 0, 0, UINT64_C(0x000f000081804000), 0, 0, 0, "UNKNOWN", "TABLE_NOT_RAM"},
    {"2l-split-0", 0xd, 0, TB, 0x10014, 0, 0, 0, 0, 0, 0, 0, "UNKNOWN", "STRTAB_SPLIT"},
    {"2l-split-5", 0xd, 0, TB, 0x10154, 0, 0, 0, 0, 0, 0, 0, "UNKNOWN", "STRTAB_SPLIT"},
    {"2l-split-7", 0xd, 0, TB, 0x101d4, 0, 0, 0, 0, 0, 0, 0, "UNKNOWN", "STRTAB_SPLIT"},
    {"2l-split-9", 0xd, 0, TB, 0x10254, 0, 0, 0, 0, 0, 0, 0, "UNKNOWN", "STRTAB_SPLIT"},
    {"2l-split-11", 0xd, 0, TB, 0x102d4, 0, 0, 0, 0, 0, 0, 0, "UNKNOWN", "STRTAB_SPLIT"},
    {"2l-split-31", 0xd, 0, TB, 0x107d4, 0, 0, 0, 0, 0, 0, 0, "UNKNOWN", "STRTAB_SPLIT"},
    {"2l-l2ptr-all-ones", 0xd, 0, TB, 0x10294, L1_AT, UINT64_C(0xffffffffffffffeb), 2, UINT64_C(0x10000000003fc0), 0, 0, 0, "UNKNOWN", "TABLE_NOT_RAM"},
    {"2l-table-in-reserved-memory", 0xd, 0, UINT64_C(0xa0000000), 0x10294, UINT64_C(0xa0000c00), 0, 0, 0, 0, 0, 0, "UNKNOWN", "TABLE_NOT_RAM"},
    {"2l-l1-fault-low", 0xd, 0, TB, 0x10294, L1_AT, 0x8a40000b, 1, 0, 0, 0, L1_AT, "UNKNOWN", "L1_NOT_READ"},
    {"2l-l1-fault-high", 0xd, 0, TB, 0x10294, L1_AT, 0x8a40000b, 2, 0, 0, 0, L1_AT + 4, "UNKNOWN", "L1_NOT_READ"},
    /* a fault inside the entry: the words after it are not read */
    {"lin-ste-fault-dw0-high", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, 0xd, 2, LSTE + 4, "UNKNOWN", "STE_NOT_READ"},
    {"lin-ste-fault-dw2-low", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, 0xd, 5, LSTE + 16, "UNKNOWN", "STE_NOT_READ"},
    {"lin-ste-fault-dw3-high", 0xd, 0, LB, 0x14, 0, 0, 0, LSTE, 0xd, 8, LSTE + 28, "UNKNOWN", "STE_NOT_READ"},
    /* the SMMU is off: GBPA decides, only bit 20 of it, and the table is not looked at */
    {"off-bypass", 0x0, 0x0, TB, 0x10294, 0, 0, 0, 0, 0, 0, 0, "BYPASS_GLOBAL", "SMMU_DISABLED"},
    {"off-abort", 0xe, 0x100000, TB, 0x10294, 0, 0, 0, 0, 0, 0, 0, "ABORT_GLOBAL", "SMMU_DISABLED"},
    {"off-other-gbpa-bits", 0xfffffffe, 0xffefffff, TB, 0x10294, 0, 0, 0, 0, 0, 0, 0, "BYPASS_GLOBAL", "SMMU_DISABLED"},
    {"on-ignores-gbpa-abort", 0xd, 0x100000, LB, 0x14, 0, 0, 0, LSTE, 0xd, 8, 0, "S2", "NONE"},
};

static int run_vcase(const struct vcase *c)
{
    struct world w;
    struct smmu_cfg s = {c->cr0, c->gbpa, 0, c->base, c->cfg};
    int s2 = !strcmp(c->mode, "S2") || !strcmp(c->mode, "S1S2");
    char want[128];
    world_good(&w);
    bus_clear();
    ram_ok_n = 0;
    put_rp();
    put_ep();
    put_smmu(&s);
    if (c->l1_reads) {
        bus_set64(c->l1_at, c->l1);
        allow_ram(c->l1_at, c->l1_at + 8);
    }
    if (c->ste_reads) {
        const uint64_t dw[4] = {c->dw0, good_dw[1], good_dw[2], good_dw[3]};
        put_dwords(c->ste_at, dw);
        allow_ram(c->ste_at, c->ste_at + 32);
    }
    if (c->fault_at) bus_fault(c->fault_at);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    snprintf(want, sizeof want, P "VERDICT STREAM=0X60100 MODE=%s WHY=%s", c->mode, c->why);
    CHECK_LINE(want);
    CHECK_EQ(loads_in(c->l1_at, c->l1_at + 8), c->l1_reads);
    CHECK_EQ(loads_in(c->ste_at, c->ste_at + 32), c->ste_reads);
    CHECK_EQ(load_n - loads_in(RP_PAGE, RP_PAGE + 0x1000) - loads_in(EP_PAGE, EP_PAGE + 0x1000) - loads_in(SMMU_PAGE, SMMU_PAGE + 0x90),
             c->l1_reads + c->ste_reads);
    CHECK_EQ(at_count, 3 + !!c->l1_at + !!c->ste_reads);
    if (c->l1_at) {
        snprintf(want, sizeof want, "AT=0X%llX", (unsigned long long)c->l1_at);
        CHECK_TOKEN(P "L1 ", want);
    } else {
        CHECK_NO_LINE(P "L1 ");
    }
    if (c->ste_at) {
        snprintf(want, sizeof want, "AT=0X%llX", (unsigned long long)c->ste_at);
        CHECK_TOKEN(P "STE ", want);
    } else {
        CHECK_NO_LINE(P "STE ");
    }
    if (s2) CHECK_TOKEN(P "S2 ", "VMID=7"); else CHECK_NO_LINE(P "S2 ");
    if (c->cr0 & 1) CHECK_TOKEN(P "STRTAB ", "SID=0X60100"); else CHECK_NO_LINE(P "STRTAB ");
    world_free(&w);
    return 0;
}

static int suite_verdict(void)
{
    for (unsigned i = 0; i < sizeof vcases / sizeof vcases[0]; i++)
        if (run_vcase(&vcases[i])) {
            fprintf(stderr, "  in case %s\n", vcases[i].name);
            return 1;
        }
    return 0;
}

/* ---- Ack: CR0 is what was asked, CR0ACK is what the SMMU says it did ------------------------------------------------------------- */

static int suite_ack(void)
{
    struct world w;
    static const struct {
        uint32_t cr0, ack;
        const char *mode, *why;
    } cases[] = {
        {0xd, 0xd, "S2", "NONE"},                                          /* the same: the entry decides */
        {0x0, 0x0, "BYPASS_GLOBAL", "SMMU_DISABLED"},                      /* the same, off: GBPA decides */
        {0xd, 0xc, "UNKNOWN", "CR0_ACK_DISAGREE"},                         /* enable asked, not acknowledged */
        {0x0, 0x1, "UNKNOWN", "CR0_ACK_DISAGREE"},                         /* disable asked, still enabled */
        {0xc, 0xd, "UNKNOWN", "CR0_ACK_DISAGREE"},                         /* disable asked, enabled: the enable bit alone differs */
        {0xd, 0x1d, "UNKNOWN", "CR0_ACK_DISAGREE"},                        /* the enable bit agrees, another does not */
        {0xd, 0x5, "UNKNOWN", "CR0_ACK_DISAGREE"},
        {0xffffffff, 0x7fffffff, "UNKNOWN", "CR0_ACK_DISAGREE"},           /* only the top bit differs */
        {0xfffffffe, 0xfffffffe, "BYPASS_GLOBAL", "SMMU_DISABLED"},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        struct smmu_cfg s = good_smmu;
        char want[128];
        int decided = strcmp(cases[i].why, "CR0_ACK_DISAGREE") != 0;
        s.cr0 = cases[i].cr0;
        world_good(&w);
        put_smmu(&s);
        bus_set(SMMU_PAGE + 0x24, cases[i].ack);
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        snprintf(want, sizeof want, P "VERDICT STREAM=0X60100 MODE=%s WHY=%s", cases[i].mode, cases[i].why);
        if (!has_line(want)) fprintf(stderr, "  in case %u: cr0 %#x, cr0ack %#x\n", i, cases[i].cr0, cases[i].ack);
        CHECK_LINE(want);
        CHECK_TOKEN(P "DONE ", "SMMU_TRIED=14");                          /* the registers are all read: the disagreement is seen, not avoided */
        CHECK_EQ(loads_in(SMMU_PAGE, SMMU_PAGE + 0x90), 15);
        if (decided && cases[i].cr0 & 1) {
            CHECK_EQ(load_n, UNIT_LOADS);
        } else {
            CHECK_EQ(load_n, CONFIG_LOADS + 15);                          /* no table word at all */
            CHECK_NO_LINE(P "STRTAB ");
            CHECK_NO_LINE(P "L1 ");
            CHECK_NO_LINE(P "STE ");
        }
        world_free(&w);
    }
    return 0;
}

/* ---- Pages: the MMU is asked before a page is read, and its answer is obeyed ------------------------------------------------------ */

struct page_case {
    const char *name;
    uint8_t mapped, attr, fst;
    const char *seen;                   /* what the MAP line says of the page */
    int device_ok;                      /* 1 when a device page mapped like this may be read */
};
static const struct page_case page_cases[] = {
    {"device-nGnRnE", 1, 0x00, 0, "DEVICE.NSH", 1},
    {"device-nGnRE", 1, 0x04, 0, "DEVICE.NSH", 1},
    {"device-nGRE", 1, 0x08, 0, "DEVICE.NSH", 1},
    {"device-GRE", 1, 0x0c, 0, "DEVICE.NSH", 1},
    {"normal-non-cacheable", 1, ATTR_NC, 0, "NC.NSH", 0},
    {"normal-write-through", 1, ATTR_WT, 0, "WT.NSH", 0},
    {"normal-write-back", 1, ATTR_WB, 0, "WB.NSH", 0},
    {"device-like-high-nibble-with-low-bits", 1, 0x01, 0, "OTHER=0X1.NSH", 0},
    {"device-gre-with-a-reserved-bit", 1, 0x0e, 0, "OTHER=0XE.NSH", 0},
    {"low-nibble-zero-high-nibble-not", 1, 0x10, 0, "OTHER=0X10.NSH", 0},
    {"unmapped-translation-fault", 0, 0, 0x05, "FAULT=0X5:TRANS_L1", 0},
    {"unmapped-address-size-fault", 0, 0, 0x00, "FAULT=0X0:ADDR_L0", 0},
};
#define PAGE_CASES (sizeof page_cases / sizeof page_cases[0])

static void page_set(uint64_t base, const struct page_case *c)
{
    if (c->mapped) tr_map(base, base + 0x1000, c->attr, SH_NONE);
    else tr_fault(base, base + 0x1000, c->fst);
}

static int suite_pages(void)
{
    struct world w;
    static const struct {
        const char *name;
        uint64_t base, bytes;
        unsigned loads;
    } pages[3] = {{"RP", RP_PAGE, 0x1000, 21}, {"EP", EP_PAGE, 0x1000, 21}, {"SMMU", SMMU_PAGE, 0x90, 15}};
    for (unsigned p = 0; p < 3; p++)
        for (unsigned i = 0; i < PAGE_CASES; i++) {
            const struct page_case *c = &page_cases[i];
            char want[128];
            world_good(&w);
            page_set(pages[p].base, c);
            CHECK_EQ(go(&w.a), 0);
            CHECK_DISCIPLINE();
            snprintf(want, sizeof want, "%s=%s", pages[p].name, c->seen);
            if (!has_token(P "MAP ", want, 1)) fprintf(stderr, "  in page %s, case %s\n", pages[p].name, c->name);
            CHECK_TOKEN(P "MAP ", want);
            if (c->device_ok) {
                CHECK_EQ(at_count, 5);
                CHECK_EQ(load_n, UNIT_LOADS);
                CHECK_LINE(P "VERDICT STREAM=0X60100 MODE=S2 WHY=NONE");
                CHECK_NO_TOKEN(P "DONE ", "REFUSED=1");
            } else if (p == 2) {                                           /* the SMMU's page: no read, no wait, a verdict that says why */
                CHECK_EQ(loads_in(SMMU_PAGE, SMMU_PAGE + 0x1000), 0);
                CHECK_EQ(load_n, CONFIG_LOADS);
                CHECK_EQ(at_count, 3);
                snprintf(want, sizeof want, P "VERDICT STREAM=0X60100 MODE=UNKNOWN WHY=%s", c->mapped ? "SMMU_PAGE_NOT_DEVICE" : "SMMU_PAGE_UNMAPPED");
                CHECK_LINE(want);
                CHECK_LINE(P "DONE SMMU_GROUP_SKIPPED LOADS=42 FAULTS=0 REFUSED=0 SMMU_TRIED=0");
                CHECK_EQ(count_prefix(P "NEXT "), 1);
                CHECK_NO_LINE(P "NEXT SMMU_REGISTERS");
                CHECK_NO_LINE(P "SMMU ");
                CHECK_NO_LINE(P "STRTAB ");
            } else {                                                       /* a function's page: its first read is refused, and the rest follow it */
                CHECK_EQ(at_count, 5);
                CHECK_EQ(loads_in(pages[p].base, pages[p].base + 0x1000), 0);
                CHECK_EQ(load_n, UNIT_LOADS - pages[p].loads);
                snprintf(want, sizeof want, P "%s ", pages[p].name);
                CHECK_TOKEN(want, "ID=REFUSED:126");
                snprintf(want, sizeof want, P "%s.PCIE PCIE=NOT_READ", pages[p].name);
                CHECK_LINE(want);
                CHECK_TOKEN(P "DONE ", "REFUSED=1");
                CHECK_LINE(P "VERDICT STREAM=0X60100 MODE=S2 WHY=NONE");        /* the other function and the SMMU are read as ever */
            }
            world_free(&w);
        }
    return 0;
}

/* The pages of the stream table: the descriptor's and the entry's. RAM may be mapped as anything; only a missing mapping refuses. */
static int suite_table_pages(void)
{
    struct world w;
    const uint64_t l1_page = L1_AT & ~UINT64_C(0xfff), ste_page = STE_AT & ~UINT64_C(0xfff);
    world_good(&w);
    tr_fault(l1_page, l1_page + 0x1000, 0x05);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK_TOKEN(P "L1 ", "MAP=FAULT=0X5:TRANS_L1");
    CHECK_TOKEN(P "L1 ", "MEMMAP_TYPE=7");
    CHECK_EQ(loads_in(L1_AT, L1_AT + 8), 0);
    CHECK_EQ(loads_in(STE_AT, STE_AT + 32), 0);
    CHECK_LINE(P "VERDICT STREAM=0X60100 MODE=UNKNOWN WHY=L1_UNMAPPED");
    CHECK_NO_LINE(P "STE ");
    CHECK_EQ(at_count, 4);
    world_free(&w);

    world_good(&w);
    tr_fault(ste_page, ste_page + 0x1000, 0x05);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK_TOKEN(P "L1 ", "MAP=WB.IS");
    CHECK_EQ(loads_in(L1_AT, L1_AT + 8), 2);
    CHECK_TOKEN(P "STE ", "MAP=FAULT=0X5:TRANS_L1");
    CHECK_TOKEN(P "STE ", "NOT_READ");
    CHECK_EQ(loads_in(STE_AT, STE_AT + 32), 0);
    CHECK_LINE(P "VERDICT STREAM=0X60100 MODE=UNKNOWN WHY=STE_UNMAPPED");
    CHECK_NO_LINE(P "S2 ");
    CHECK_EQ(at_count, 5);
    world_free(&w);

    for (unsigned i = 0; i < PAGE_CASES; i++) {                              /* RAM mapped as Device, Normal or anything else is read */
        const struct page_case *c = &page_cases[i];
        char want[64];
        if (!c->mapped) continue;
        world_good(&w);
        tr_map(l1_page, l1_page + 0x1000, c->attr, SH_NONE);
        tr_map(ste_page, ste_page + 0x1000, c->attr, SH_NONE);
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        snprintf(want, sizeof want, "MAP=%s", c->seen);
        CHECK_TOKEN(P "L1 ", want);
        CHECK_TOKEN(P "STE ", want);
        CHECK_EQ(load_n, UNIT_LOADS);
        CHECK_LINE(P "VERDICT STREAM=0X60100 MODE=S2 WHY=NONE");
        world_free(&w);
    }

    {                                                                       /* a linear table: only the entry's page is asked */
        struct smmu_cfg s = {0xd, 0, 0, LB, 0x14};
        world_good(&w);
        bus_clear();
        ram_ok_n = 0;
        put_rp();
        put_ep();
        put_smmu(&s);
        put_dwords(LSTE, good_dw);
        allow_ram(LSTE, LSTE + 32);
        tr_fault(LSTE & ~UINT64_C(0xfff), (LSTE & ~UINT64_C(0xfff)) + 0x1000, 0x05);
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK_LINE(P "VERDICT STREAM=0X60100 MODE=UNKNOWN WHY=STE_UNMAPPED");
        CHECK_EQ(loads_in(LSTE, LSTE + 32), 0);
        CHECK_NO_LINE(P "L1 ");
        CHECK_EQ(at_count, 4);
        world_free(&w);
    }
    return 0;
}

/* ---- RAM: what the memory map lets the payload read ------------------------------------------------------------------------------- */

/* One linear table at LB (the entry is at LSTE + `shift`, the base is moved to match) over the map `list`: is the entry read, and what is
 * said when it is not (`type`: the memory map type printed, or NULL for the lines MEMMAP_TYPE=<token>). */
static int ram_case(const struct d *list, unsigned count, uint64_t shift, int readable, const char *type)
{
    struct world w;
    struct smmu_cfg s = {0xd, 0, 0, LB + shift, 0x14};
    uint64_t at = LSTE + shift;
    char want[64];
    world_new(&w, list, count);
    put_rp();
    put_ep();
    put_smmu(&s);
    if (readable) {
        put_dwords(at, good_dw);
        allow_ram(at, at + 32);
    } else {
        put_dwords(at, good_dw);                    /* scripted, but never to be read */
    }
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    if (readable) {
        CHECK_EQ(loads_in(at, at + 32), 8);
        CHECK_LINE(P "VERDICT STREAM=0X60100 MODE=S2 WHY=NONE");
    } else {
        CHECK_EQ(loads_in(at, at + 32), 0);
        CHECK_LINE(P "VERDICT STREAM=0X60100 MODE=UNKNOWN WHY=TABLE_NOT_RAM");
        snprintf(want, sizeof want, "MEMMAP_TYPE=%s", type);
        CHECK_TOKEN(P "STE ", want);
        CHECK_TOKEN(P "STE ", "NOT_READ");
        CHECK_EQ(at_count, 3);
    }
    world_free(&w);
    return 0;
}

static int suite_ram(void)
{
    struct world w;
    /* Every type of descriptor over the entry's page: only loader, boot services, runtime, conventional and ACPI reclaim memory is read. */
    for (unsigned t = 0; t < 16; t++) {
        const struct d list[3] = {{7, LB, 0x1804}, {t, LSTE, 1}, {7, LSTE + 0x1000, 0x100}};
        int usable = (t >= 1 && t <= 7) || t == 9;
        char type[8];
        snprintf(type, sizeof type, "%u", t);
        if (ram_case(list, 3, 0, usable, type)) {
            fprintf(stderr, "  in type %u\n", t);
            return 1;
        }
    }
    /* The edges: the last 64 bytes of an extent are read, the first 64 after it are not, and any overlap with a type that must not be read
     * refuses, whichever descriptor is listed first. */
    {
        const struct d edge[1] = {{7, LB, 0x1805}};
        const struct d past[2] = {{7, LB, 0x1805}, {0, LSTE + 0x1000, 1}};
        const struct d over_after[2] = {{7, LB, 0x20000}, {0, LSTE, 1}};
        const struct d over_before[2] = {{0, LSTE, 1}, {7, LB, 0x20000}};
        const struct d both_usable[2] = {{7, LB, 0x20000}, {4, LSTE, 1}};
        const struct d unaligned[2] = {{7, LB, 0x1804}, {7, LSTE + 0x800, 1}};
        const struct d empty[2] = {{7, LB, 0x1804}, {7, LSTE, 0}};
        const struct d abut[2] = {{0, LSTE - 0x1000, 1}, {7, LSTE, 0x100}};
        if (ram_case(edge, 1, 0xfc0, 1, 0)) return 1;
        if (ram_case(past, 2, 0xfc0, 1, 0)) return 1;            /* the reserved page right after the entry does not overlap it */
        if (ram_case(abut, 2, 0, 1, 0)) return 1;                /* nor does the reserved page right before it */
        if (ram_case(edge, 1, 0x1000, 0, "NOT_IN_MAP")) return 1;
        if (ram_case(past, 2, 0x1000, 0, "0")) return 1;
        if (ram_case(over_after, 2, 0, 0, "0")) return 1;
        if (ram_case(over_before, 2, 0, 0, "0")) return 1;
        if (ram_case(both_usable, 2, 0, 1, 0)) return 1;
        if (ram_case(unaligned, 2, 0, 0, "NOT_IN_MAP")) return 1;
        if (ram_case(empty, 2, 0, 0, "NOT_IN_MAP")) return 1;
    }
    /* A map that cannot be read safely: nothing is read from RAM and the line says so. */
    for (unsigned v = 0; v < 6; v++) {
        static struct d big[1025];
        struct smmu_cfg s = {0xd, 0, 0, LB, 0x14};
        if (v == 5)
            for (unsigned i = 0; i < 1025; i++) big[i] = (struct d){7, LB + i * 0x1000, 1};
        world_new(&w, v == 5 ? big : std_map, v == 5 ? 1025 : STD_COUNT);
        put_rp();
        put_ep();
        put_smmu(&s);
        put_dwords(LSTE, good_dw);
        if (v == 0) w.a.map_base = 0;
        if (v == 1) {                                    /* below the 40 bytes of a descriptor, and whole descriptors: only that refuses it */
            w.a.map_stride = 32;
            w.a.map_size = 160;
        }
        if (v == 2) {                                    /* not a multiple of 8, and whole descriptors: only that refuses it */
            w.a.map_stride = 44;
            w.a.map_size = 220;
        }
        if (v == 3) w.a.map_size += 8;
        if (v == 4) w.a.map_size = 0;
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK_EQ(loads_in(LB, UINT64_C(1) << 48), 0);
        CHECK_TOKEN(P "STE ", "MEMMAP_TYPE=MAP_UNUSABLE");
        CHECK_LINE(P "VERDICT STREAM=0X60100 MODE=UNKNOWN WHY=TABLE_NOT_RAM");
        world_free(&w);
    }
    return 0;
}

/* ---- Counter, EL, arguments --------------------------------------------------------------------------------------------------------- */

static int suite_counter(void)
{
    struct world w;
    static const struct { uint64_t cntfrq, used; } freqs[] = {
        {0, 19200000}, {1, 19200000}, {999999, 19200000}, {1000000, 1000000}, {24000000, 24000000}, {1000000000, 1000000000},
        {1000000001, 19200000}, {UINT64_C(0xffffffffff), 19200000},
    };
    for (unsigned i = 0; i < sizeof freqs / sizeof freqs[0]; i++) {
        char want[32];
        world_good(&w);
        reg_set("CNTFRQ_EL0", freqs[i].cntfrq);
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        snprintf(want, sizeof want, "FREQ=%llu", (unsigned long long)freqs[i].used);
        CHECK_TOKEN(P "START ", want);
        if (check_wait(find_line(P "NEXT PCIE_CAPS"), RP_PAGE + 0x40, freqs[i].used) ||
            check_wait(find_line(P "NEXT SMMU_REGISTERS"), SMMU_PAGE, freqs[i].used))
            return 1;
        world_free(&w);
    }
    /* No counter op, a counter that stands still, one that goes back: both groups are announced, neither is read. */
    for (unsigned v = 0; v < 3; v++) {
        world_good(&w);
        if (v == 0) w.a.ops.counter = 0;
        if (v == 1) clock_set(1000, 0, 1);
        if (v == 2) clock_set(UINT64_C(1) << 40, 1000, 2);
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK_LINE(P "NEXT PCIE_CAPS AFTER 8 S");
        CHECK_LINE(P "NEXT SMMU_REGISTERS AFTER 8 S");
        CHECK_LINE(v == 0 ? P "PCIE_CAPS SKIPPED=NO_COUNTER" : P "PCIE_CAPS SKIPPED=COUNTER_UNUSABLE");
        CHECK_LINE(v == 0 ? P "SMMU_REGISTERS SKIPPED=NO_COUNTER" : P "SMMU_REGISTERS SKIPPED=COUNTER_UNUSABLE");
        CHECK_EQ(load_n, 13);                                                /* the two headers only */
        CHECK_EQ(at_count, 3);
        CHECK_LINE(P "VERDICT STREAM=0X60100 MODE=UNKNOWN WHY=GROUP_SKIPPED");
        CHECK_LINE(P "DONE SMMU_GROUP_SKIPPED LOADS=13 FAULTS=0 REFUSED=0 SMMU_TRIED=0");
        CHECK_NO_LINE(P "RP.PCIE ");
        CHECK_NO_LINE(P "SMMU ");
        world_free(&w);
    }
    return 0;
}

static int suite_el(void)
{
    struct world w;
    static const uint64_t levels[] = {0, 1, 3};
    for (unsigned i = 0; i < 3; i++) {
        char want[96];
        world_good(&w);
        set_el(levels[i]);
        CHECK_EQ(go(&w.a), 2);
        CHECK_EQ(line_count, 2);
        snprintf(want, sizeof want, P "START CURRENTEL=0X%llX FREQ=19200000 ECAM=0X70000000 SMMU=0X15400000", (unsigned long long)levels[i] << 2);
        CHECK_LINE(want);
        CHECK_LINE(P "REFUSED NOT_AT_EL2");
        CHECK_EQ(load_n, 0);
        CHECK_EQ(at_count, 0);
        world_free(&w);
    }
    /* A refusal before anything is printed or read: wrong magic, version or size, a missing puts or hex. */
    for (unsigned v = 0; v < 6; v++) {
        world_good(&w);
        if (v == 0) w.a.magic ^= 1;
        if (v == 1) w.a.version++;
        if (v == 2) w.a.size--;
        if (v == 3) w.a.ops.puts = 0;
        if (v == 4) w.a.ops.hex = 0;
        if (v == 5) {
            page_clear();
            CHECK_EQ(payload_entry(0), Q1N1_PAYLOAD_RET_BAD_ARGS);
        } else {
            CHECK_EQ(go(&w.a), Q1N1_PAYLOAD_RET_BAD_ARGS);
        }
        CHECK_EQ(line_count, 0);
        CHECK_EQ(read_count, 0);
        CHECK_EQ(load_n, 0);
        CHECK_EQ(at_count, 0);
        world_free(&w);
    }
    world_good(&w);
    w.a.ops.load32 = 0;
    CHECK_EQ(go(&w.a), 3);
    CHECK_EQ(line_count, 2);
    CHECK_LINE(P "REFUSED NO_LOAD_OP");
    CHECK_EQ(at_count, 0);
    world_free(&w);
    return 0;
}

static unsigned most_lines;
static int suite_budget(void)
{
    struct world w;
    world_good(&w);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK(find_line(P "DONE ") == (int)line_count - 1);
    CHECK_EQ(count_prefix(P "NEXT "), 2);
    CHECK_EQ(count_prefix(P "VERDICT "), 1);
    if (TEST_BUDGET < UNIT_LINES) {                      /* a small page: lines are dropped, counted, and the four that matter stay */
        char want[32];
        CHECK_EQ(line_count, TEST_BUDGET);
        snprintf(want, sizeof want, "SUPPRESSED=%u", (unsigned)(UNIT_LINES - line_count));
        CHECK_TOKEN(P "DONE ", want);
    } else {
        CHECK_NO_TOKEN(P "DONE ", "SUPPRESSED=");
    }
    if (TEST_LOAD_CAP < UNIT_LOADS) {                    /* a small cap: no more loads than it, the rest refused by the payload itself */
        char want[32];
        CHECK_EQ(op_calls, TEST_LOAD_CAP);
        snprintf(want, sizeof want, "LOADS=%d", TEST_LOAD_CAP);
        CHECK_TOKEN(P "DONE ", want);
        CHECK_ANY(P, "REFUSED:5");
    } else {
        CHECK(op_calls < TEST_LOAD_CAP);
    }
    if (line_count > most_lines) most_lines = line_count;
    world_free(&w);
    return 0;
}

/* ---- Worst: every value at full width, every walk a long one ------------------------------------------------------------------------- */

static void fill_function(uint64_t p, uint32_t hdr, uint32_t pcie_cap)
{
    bus_set(p + 0x00, 0xfffefffe);
    bus_set(p + 0x04, 0xffffffff);
    bus_set(p + 0x08, 0xffffffff);
    bus_set(p + 0x0c, hdr);
    for (unsigned o = 0x10; o <= 0x18; o += 4) bus_set(p + o, 0xffffffff);
    bus_set(p + 0x34, 0xffffff40);
    bus_set(p + 0x40, pcie_cap);
    for (unsigned o = 0x48; o <= 0x50; o += 4) bus_set(p + o, 0xffffffff);
    bus_set(p + 0x6c, 0xffffffff);
    bus_set(p + 0x70, 0xffffffff);
    bus_set(p + 0x100, 0xffff0001);
    for (unsigned o = 0x104; o <= 0x114; o += 4) bus_set(p + o, 0xffffffff);
    bus_set(p + 0x130, 0xffffffff);
}
static int suite_worst(void)
{
    struct world w;
    struct smmu_cfg s = {0xffffffff, 0xffffffff, 0xffffffff, UINT64_C(0x400000008a000000), 0xfffdfa94};
    const uint64_t dw[4] = {~UINT64_C(0), ~UINT64_C(0), ~UINT64_C(0), ~UINT64_C(0)};
    world_new(&w, std_map, STD_COUNT);
    fill_function(RP_PAGE, 0xff81ffff, 0xff4fff10);
    fill_function(EP_PAGE, 0xff80ffff, 0xffffff10);
    put_smmu(&s);
    for (unsigned i = 0; i < 8; i++) bus_set(SMMU_PAGE + smmu_offsets[i], 0xffffffff);
    bus_set64(L1_AT, UINT64_C(0xfff000008a40000b));
    put_dwords(STE_AT, dw);
    allow_ram(L1_AT, L1_AT + 8);
    allow_ram(STE_AT, STE_AT + 32);
    tr_map(RP_PAGE, RP_PAGE + 0x1000, ATTR_DEVICE, SH_NONE);              /* the longest answer of a page that may be read: Device, NS, not an identity */
    tr_table[tr_count - 1].ns = 1;
    tr_table[tr_count - 1].delta = 0x1000;
    tr_map(EP_PAGE, EP_PAGE + 0x1000, ATTR_DEVICE, SH_NONE);
    tr_table[tr_count - 1].ns = 1;
    tr_table[tr_count - 1].delta = 0x1000;
    tr_map(SMMU_PAGE, SMMU_PAGE + 0x10000, ATTR_DEVICE, SH_NONE);
    tr_table[tr_count - 1].ns = 1;
    tr_table[tr_count - 1].delta = 0x1000;
    tr_map(0x8a000000, 0x8a001000, ATTR_NC, SH_OUTER);
    tr_table[tr_count - 1].ns = 1;
    tr_table[tr_count - 1].delta = 0x1000;
    tr_map(0x8a404000, 0x8a405000, ATTR_WB, SH_INNER);
    tr_table[tr_count - 1].ns = 1;
    tr_table[tr_count - 1].delta = 0x1000;
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK_LINE(P "VERDICT STREAM=0X60100 MODE=S1S2 WHY=NONE");
    CHECK(find_line(P "DONE ") == (int)line_count - 1);
    CHECK_EQ(count_prefix(P "NEXT "), 2);
    if (TEST_BUDGET >= 36) {                             /* nothing is dropped in the world that prints the most */
        CHECK_NO_TOKEN(P "DONE ", "SUPPRESSED=");
        CHECK_TOKEN(P "MAP ", "RP=DEVICE.NSH.NS1.NONIDENT");
        CHECK_TOKEN(P "MAP ", "EP=DEVICE.NSH.NS1.NONIDENT");
        CHECK_TOKEN(P "MAP ", "SMMU=DEVICE.NSH.NS1.NONIDENT");
        CHECK_TOKEN(P "L1 ", "MAP=NC.OS.NS1.NONIDENT");
        CHECK_TOKEN(P "STE ", "MAP=WB.IS.NS1.NONIDENT");
        CHECK_TOKEN(P "S2 ", "VMID=65535");
        CHECK_TOKEN(P "S2 ", "TG=3");
        CHECK_TOKEN(P "S2 ", "T0SZ=63");
        CHECK_TOKEN(P "S2 ", "SL0=3");
        CHECK_TOKEN(P "S2 ", "TTB=0XFFFFFFFFFFFF0");
        CHECK_TOKEN(P "RP.PCIE ", "LINK=SPEED15.X63");
    }
    if (line_count > most_lines) most_lines = line_count;
    world_free(&w);
    return 0;
}

#include "test-q1n1-sp11-payload-smmuprobe-fuzz.h"

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"unit", suite_unit}, {"config", suite_config}, {"smmu", suite_smmu}, {"verdict", suite_verdict}, {"ack", suite_ack},
        {"pages", suite_pages}, {"tablepages", suite_table_pages}, {"ram", suite_ram}, {"counter", suite_counter}, {"el", suite_el},
        {"budget", suite_budget}, {"worst", suite_worst}, {"fuzz", suite_fuzz},
    };
    unsigned ran = 0;
    if (argc > 1 && !strcmp(argv[1], "page")) {
        struct world w;
        world_good(&w);
        go(&w.a);
        for (unsigned i = 0; i < line_count; i++) printf("%s\n", lines[i]);
        world_free(&w);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "lines-report")) {
        if (suite_budget() || suite_worst() || suite_fuzz()) return 1;
        printf("LINES_MAX=%u\n", most_lines);
        return 0;
    }
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], "all") && strcmp(argv[1], suites[i].name)) continue;
        if (suites[i].run()) {
            fprintf(stderr, "FAIL: suite %s\n", suites[i].name);
            return 1;
        }
        ran++;
    }
    printf("PASS: %u payload smmuprobe suites, %u checks\n", ran, checks);
    return 0;
}
