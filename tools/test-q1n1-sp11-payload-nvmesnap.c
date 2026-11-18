/* SPDX-License-Identifier: MIT */
/* Host test for the nvmesnap payload (payloads/nvmesnap.c, docs/SP11-PAYLOAD-NVMESNAP.md), built natively with Q1N1_PAYLOAD_HOST_TEST so that its
 * register reads, its AT S1E2R and its guarded loads come from the machine modelled in tools/test-q1n1-sp11-payload-nvmesnap-world.h. Driven by
 * tools/test-q1n1-sp11-payload-nvmesnap.py under ASan and UBSan.
 *
 * Suites: unit (the page of a good world, the exact loads in order, the ATs, the registers, the order and the eight seconds), gates (every reason
 * the controller registers are not read, and the cases that must not be refused: tools/test-q1n1-sp11-payload-nvmesnap-gates.h), gatemap (every
 * type of memory map descriptor over the registers), pages (what the MMU says of each configuration page), faults (a fault at each load of the good
 * world and what follows it), nvfaults (a fault at each controller register load, in either block), ctrl (controller states, CSTS read twice, all ones,
 * register decoding, admin queue sizes), queues (queue addresses, every type of memory map descriptor, descriptor edges, bad maps, page attributes,
 * the words of a slot read data first, faults: tools/test-q1n1-sp11-payload-nvmesnap-queues.h), counter (the eight seconds three times, a missing,
 * stuck or backward counter, a counter that dies at the second or the third wait, a slow counter, and with a lowered bound on the reads of a wait
 * the SPIN_BOUND token a dead counter does not give), el (not at EL2, bad arguments, no load op), budget (the line budget, the load cap),
 * worst (the world that prints the most lines), fuzz (random worlds against an oracle written another way:
 * tools/test-q1n1-sp11-payload-nvmesnap-fuzz.h).
 *
 * What it cannot show: what the unit does at these addresses, what an EL3 does with a read that hangs, or what the binary does: the Python driver
 * disassembles the built binary for that. Evidence: EXPERIMENTAL (host model only); hardware NOT RUN. */
#include "test-q1n1-sp11-payload-nvmesnap-world.h"
#include "test-q1n1-sp11-payload-nvmesnap-gates.h"

/* ---- Unit: a good world ---------------------------------------------------------------------------------------------------------- */

/* The page of the good world (the model prints it: docs/SP11-PAYLOAD-NVMESNAP.md, "What the host model prints"); every value was checked by hand
 * against the scripted words. */
static const char *const unit_page[] = {
    P "START CURRENTEL=0X8 FREQ=19200000 ECAM=0X70000000 WINDOW=0X70300000",
    P "MAP RP=DEVICE.NSH EP=DEVICE.NSH",
    P "RP ID=0X2221111 CMDSTS=0X100007 CLASSREV=0X6040001 HDR=0X10010 BUSES=0X10100",
    P "RP MEMWIN=0X73F07030 CAPPTR=0X40",
    P "EP ID=0XFEED1D1D CMDSTS=0X100406 CLASSREV=0X1080201 HDR=0X10 BAR0=0X70300004",
    P "EP BAR1=0X0 CAPPTR=0X40",
    P "NEXT CAPS AFTER 8 S",
    P "RP.LINK LINK=GEN4.X4 TYPE=4 DLLA=1 LT=0 ASPM=3 LNKCAP=0X100C44 LNKCTLSTA=0X20440043",
    P "EP.PM PMCSR=0X8 D=0",
    P "EP.LINK LINK=GEN4.X4 TYPE=0 ASPM=1 LNKCAP=0XC44 LNKCTLSTA=0X440041",
    P "GATE LINK=UP RPMEM=1 MEM=1 BME=1 D=0 BAR0=0X70300000 MAP=DEVICE.NSH WHY=NONE",
    P "NEXT NVME_REGS AFTER 8 S",
    P "NVME CAP=0X3100323C0301FF CSTS=0X1 CC=0X460081 VS=0X20100",
    P "CAP MQES=511 CQR=1 TO=60 DSTRD=2 NSSRS=1 CSS=0X1 MPSMIN=1 MPSMAX=3 PMRS=0 CMBS=0",
    P "CTRL VER=2.1.0 EN=1 RDY=1 CFS=0 SHST=0 CSS=0 MPS=1 AMS=0 SHN=0 IOSQES=6 IOCQES=4",
    P "NEXT NVME_AQ AFTER 8 S",
    P "NVME.AQ CSTS2=0X1 AQA=0X30003 ASQ=0X80100000 ACQ=0X80101000",
    P "AQ ASQE=4 ACQE=4",
    P "NEXT ADMIN_QUEUES",
    P "ASQ AT=0X80100000 MEMMAP_TYPE=7 MAP=WB.IS",
    P "SQ0 DW0=0X30006 OPC=0X6 CID=0X3 NSID=0X0 PRP1=0X80200000 CDW10=0X1 CDW11=0X0",
    P "SQ1 DW0=0X40005 OPC=0X5 CID=0X4 NSID=0X0 PRP1=0X80300000 CDW10=0X3F0001 CDW11=0X1",
    P "ACQ AT=0X80101000 MEMMAP_TYPE=7 MAP=WB.IS",
    P "CQ0 DW0=0X0 DW3=0X10003 CID=0X3 P=1 SC=0X0 SCT=0 SQHD=0X1 SQID=0X0",
    P "CQ1 DW0=0X0 DW3=0X10004 CID=0X4 P=1 SC=0X0 SCT=0 SQHD=0X2 SQID=0X0",
    P "VERDICT CTRL=RUNNING QUEUES=READ LINK=UP WHY=NONE",
    P "DONE NVME_GROUP_RAN LOADS=55 FAULTS=0 REFUSED=0 NVME_TRIED=8",
};
#define UNIT_LINES (sizeof unit_page / sizeof unit_page[0])

/* The loads of the good world, in the order the design gives: both headers, the capability lists with the registers of each as soon as it is found,
 * the controller registers (CAP, CSTS, CC, VS; then CSTS again and the three registers Linux never reads), and the two admin queues, the words of
 * a slot data first. */
static const uint64_t unit_loads[] = {
    RPo(0x00), RPo(0x04), RPo(0x08), RPo(0x0c), RPo(0x18), RPo(0x20), RPo(0x34),
    EPo(0x00), EPo(0x04), EPo(0x08), EPo(0x0c), EPo(0x10), EPo(0x14), EPo(0x34),
    RPo(0x40), RPo(0x50), RPo(0x70), RPo(0x7c), RPo(0x80),
    EPo(0x40), EPo(0x44), EPo(0x50), EPo(0x70), EPo(0x80), EPo(0x8c), EPo(0x90),
    NVo(0x00), NVo(0x04), NVo(0x1c), NVo(0x14), NVo(0x08),
    NVo(0x1c), NVo(0x24), NVo(0x28), NVo(0x2c), NVo(0x30), NVo(0x34),
    ASQ_GOOD + 0, ASQ_GOOD + 24, ASQ_GOOD + 28, ASQ_GOOD + 4, ASQ_GOOD + 40, ASQ_GOOD + 44,
    ASQ_GOOD + 64, ASQ_GOOD + 88, ASQ_GOOD + 92, ASQ_GOOD + 68, ASQ_GOOD + 104, ASQ_GOOD + 108,
    ACQ_GOOD + 12, ACQ_GOOD + 8, ACQ_GOOD + 0, ACQ_GOOD + 28, ACQ_GOOD + 24, ACQ_GOOD + 16,
};
#define UNIT_LOADS (sizeof unit_loads / sizeof unit_loads[0])
#define HEADER_LOADS 14u                /* the loads of the two headers of the good world */
#define CAPS_LOADS 12u                  /* the loads of the two capability groups */
#define NV_LOADS 11u                    /* the loads of the controller registers */
#define FIRST_NV 26u                    /* the index in unit_loads of the first controller register */
#define FIRST_AQ 31u                    /* ... and of the second block, which starts with CSTS again */
#define FIRST_QUEUE 37u

/* The first load made after the line at index `k` is the next thing the payload does: no line in between, eight seconds later (and not nine: one
 * counter step is a millisecond or so), at `want`. */
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
    int k1, k2, k3, k4, i4, rp_link;
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
    CHECK_EQ(at_log[2], BAR_GOOD);
    CHECK_EQ(at_log[3], ASQ_GOOD);
    CHECK_EQ(at_log[4], ACQ_GOOD);
    CHECK_EQ(read_count, 2);
    CHECK(!strcmp(read_log[0], "CurrentEL") && !strcmp(read_log[1], "CNTFRQ_EL0"));
    /* The order: both headers, then the first NEXT line and eight seconds, then the port's capabilities and its link line, the endpoint's and the
     * gate; the second NEXT line and eight seconds, then CAP, CSTS, CC, VS and their decode; the third NEXT line and eight seconds, then CSTS again
     * and the three registers Linux never reads; the fourth NEXT line, which makes no wait, then the queues. */
    k1 = find_line(P "NEXT CAPS");
    k2 = find_line(P "NEXT NVME_REGS");
    k3 = find_line(P "NEXT NVME_AQ");
    k4 = find_line(P "NEXT ADMIN_QUEUES");
    rp_link = find_line(P "RP.LINK");
    CHECK(k1 >= 0 && k2 > k1 && k3 > k2 && k4 > k3 && rp_link > k1);
    CHECK(loads[HEADER_LOADS - 1].lines <= (unsigned)k1);            /* the headers are read before the NEXT line is printed */
    CHECK_EQ(find_line(P "GATE"), k2 - 1);
    CHECK_EQ(first_load_after((unsigned)k1), HEADER_LOADS);
    /* The first load of every block is a register Linux reads on the same page: a capability header, CAP, CSTS. */
    CHECK_EQ(check_wait(k1, RPo(0x40), FREQ), 0);
    CHECK_EQ(check_wait(k2, NVo(0x00), FREQ), 0);
    CHECK_EQ(check_wait(k3, NVo(0x1c), FREQ), 0);
    CHECK_EQ(first_load_after((unsigned)k3), (int)FIRST_AQ);
    i4 = first_load_after((unsigned)k4);
    CHECK(i4 >= 0);
    CHECK_EQ(loads[i4].addr, ASQ_GOOD);
    CHECK(loads[i4].clock - line_clock[k4] < FREQ);                  /* RAM words: no wait */
    /* What was read is printed before the next risky load: the port's link line before the endpoint's capability list (its header is read first,
     * before the first NEXT, as the X2 image did), the first block's decode before the second block. */
    CHECK(loads[18].lines <= (unsigned)rp_link && loads[19].lines > (unsigned)rp_link);
    CHECK(find_line(P "NVME ") < k3 && find_line(P "CAP ") < k3 && find_line(P "CTRL") < k3 && loads[FIRST_AQ].lines > (unsigned)k3);
    CHECK_EQ(find_line(P "VERDICT"), (int)line_count - 2);
    CHECK_EQ(find_line(P "DONE"), (int)line_count - 1);
    CHECK_EQ(loads_in(RP_PAGE, RP_PAGE + 0x1000) + loads_in(EP_PAGE, EP_PAGE + 0x1000), HEADER_LOADS + CAPS_LOADS);
    CHECK_EQ(loads_in(BAR_GOOD, BAR_GOOD + 0x4000), NV_LOADS);
    CHECK_EQ(loads_in(ASQ_GOOD, ASQ_GOOD + 0x1000) + loads_in(ACQ_GOOD, ACQ_GOOD + 0x1000), 12u + 6u);
    world_free(&w);
    return 0;
}

/* ---- The gates -------------------------------------------------------------------------------------------------------------------- */

static int suite_gates(void)
{
    struct world w;
    unsigned steps;
    for (unsigned i = 0; i < GATE_SCENS; i++) {
        if (run_scenario(&gate_scens[i], 0, 0)) {
            fprintf(stderr, "scenario %s\n", gate_scens[i].name);
            return 1;
        }
    }
    /* A capability list that points at itself is walked a bounded number of times, then given up. */
    world_good(&w);
    a_rp_cap_loop(&w);
    nv_allowed = 0;
    ram_ok_n = 0;
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    steps = loads_in(RPo(0x40), RPo(0x44));
    CHECK(steps >= 2 && steps <= 16);
    world_free(&w);
    return 0;
}

/* A descriptor added to the memory map over the controller's registers: RAM of any usable type there is refused, anything else (reserved, unusable,
 * ACPI NVS, MMIO, a descriptor next to the page and not on it) is not. */
static int suite_gate_map(void)
{
    static const struct scen shut = {"map", a_none, "BAR0_IN_RAM", 1, 1}, open = {"map", a_none, "NONE", 1, 1};
    struct d cover = {7, BAR_GOOD - 0x1000, 3}, before = {7, BAR_GOOD - 0x1000, 1}, after = {7, BAR_GOOD + 0x1000, 1};
    struct d both[2] = {{11, BAR_GOOD, 1}, {7, BAR_GOOD, 1}};
    for (uint32_t type = 0; type <= 15; type++) {
        struct d over = {type, BAR_GOOD, 1};
        int usable = (type >= 1 && type <= 7) || type == 9;
        if (run_scenario(usable ? &shut : &open, &over, 1)) {
            fprintf(stderr, "type %u over the BAR\n", type);
            return 1;
        }
    }
    CHECK_EQ(run_scenario(&shut, &cover, 1), 0);                    /* one that covers the page and its neighbours */
    CHECK_EQ(run_scenario(&open, &before, 1), 0);                   /* one that ends where the page starts */
    CHECK_EQ(run_scenario(&open, &after, 1), 0);                    /* one that starts after the page */
    CHECK_EQ(run_scenario(&shut, both, 2), 0);                      /* an MMIO descriptor does not hide a RAM one over the same page */
    both[0].type = 7;
    both[1].type = 11;
    CHECK_EQ(run_scenario(&shut, both, 2), 0);                      /* nor the other way round */
    return 0;
}

/* The MMU says no to a configuration page: nothing is read there (code 126), and the verdict names the function as not read. */
static int suite_pages(void)
{
    static const struct { uint64_t page; int attr; const char *why, *label; } cases[] = {
        {RP_PAGE, -1, "RP_NOT_READ", P "RP"}, {RP_PAGE, ATTR_WB, "RP_NOT_READ", P "RP"}, {RP_PAGE, ATTR_NC, "RP_NOT_READ", P "RP"},
        {RP_PAGE, ATTR_WT, "RP_NOT_READ", P "RP"}, {EP_PAGE, -1, "EP_NOT_READ", P "EP"}, {EP_PAGE, ATTR_WB, "EP_NOT_READ", P "EP"},
        {EP_PAGE, ATTR_NC, "EP_NOT_READ", P "EP"}, {EP_PAGE, ATTR_WT, "EP_NOT_READ", P "EP"},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        struct world w;
        char token[64];
        world_good(&w);
        if (cases[i].attr < 0) tr_fault(cases[i].page, cases[i].page + 0x1000, 0x07);
        else tr_map(cases[i].page, cases[i].page + 0x1000, (uint8_t)cases[i].attr, SH_INNER);
        nv_allowed = 0;
        ram_ok_n = 0;
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK_EQ(loads_in(cases[i].page, cases[i].page + 0x1000), 0);       /* nothing was read from the page the MMU refused */
        snprintf(token, sizeof token, "WHY=%s", cases[i].why);
        CHECK_TOKEN(P "VERDICT", token);
        CHECK_NO_LINE(P "NEXT CAPS");
        CHECK_NO_LINE(P "NEXT NVME_REGS");
        CHECK_TOKEN(P "DONE", "REFUSED=1");                                 /* the first read was refused, and the function stopped there */
        CHECK_TOKEN(cases[i].label, "ID=REFUSED:126");
        world_free(&w);
    }
    return 0;
}

/* ---- Faults: a load that does not return, at each place the good world loads ------------------------------------------------------- */

/* The WHY a fault at load `i` of the good world must give, and whether the controller registers are still read after it. */
static const char *fault_why(unsigned i, int *registers_read)
{
    *registers_read = 0;
    if (i < 6) return "RP_NOT_READ";                                         /* id, command, class, header type, buses, window */
    if (i == 6) return "CAPS_NOT_READ";                                      /* the capability pointer: the lists are never read */
    if (i < 13) return "EP_NOT_READ";                                        /* id, command, class, header type, both BAR words */
    if (i == 13) return "CAPS_NOT_READ";
    if (i < 24) return "CAPS_NOT_READ";                                      /* the port's list walk, link capabilities and status; the endpoint's walk and PMCSR */
    *registers_read = 1;
    if (i < FIRST_NV) return "NONE";                                         /* the endpoint's own link registers: informational only */
    if (i < FIRST_AQ) return "REGISTERS_NOT_READ";                           /* CAP, CSTS, CC, VS */
    if (i < FIRST_QUEUE) return "AQ_REGISTERS_NOT_READ";                     /* CSTS again, AQA, ASQ, ACQ: the first block was decoded and says so */
    return "NONE";
}

static int suite_faults(void)
{
    for (unsigned i = 0; i < UNIT_LOADS; i++) {
        struct world w;
        int registers = 0;
        const char *want = fault_why(i, &registers);
        char token[64];
        int k;
        unsigned nth = 0;
        world_good(&w);
        for (unsigned j = 0; j < i; j++) nth += unit_loads[j] == unit_loads[i];         /* CSTS is read twice: the fault is at the load, not the word */
        if (nth) bus_nth_fault(unit_loads[i], nth);
        else bus_fault(unit_loads[i]);
        if (!registers) {
            nv_allowed = 0;
            ram_ok_n = 0;
        }
        CHECK_EQ(go(&w.a), 0);
        if (stray || after_fault || unsafe_loads)
            fprintf(stderr, "fault at load %u (%#llx): stray %u after %u unsafe %u\n", i, (unsigned long long)unit_loads[i], stray, after_fault, unsafe_loads);
        CHECK_DISCIPLINE();
        CHECK(load_n > i);
        CHECK_EQ(loads[i].addr, unit_loads[i]);                              /* the loads before it were the good world's */
        CHECK_EQ(loads[i].rc, Q1N1_PAYLOAD_LOAD_E_FAULT);
        CHECK_TOKEN(P "DONE", "FAULTS=1");
        snprintf(token, sizeof token, "WHY=%s", want);
        k = find_line(P "VERDICT");
        CHECK(k >= 0);
        if (!has_token(P "VERDICT", token, 1)) fprintf(stderr, "fault at load %u (%#llx): %s, wanted %s\n", i, (unsigned long long)unit_loads[i], lines[k], token);
        CHECK_TOKEN(P "VERDICT", token);
        if (!registers) CHECK_EQ(loads_in(BAR_GOOD, BAR_GOOD + 0x4000), 0);
        world_free(&w);
    }
    return 0;
}

/* Some line that starts with `prefix` contains `text`. */
static int line_has(const char *prefix, const char *text)
{
    for (unsigned i = 0; i < line_count; i++)
        if (!strncmp(lines[i], prefix, strlen(prefix)) && strstr(lines[i], text)) return 1;
    return 0;
}

/* The index in unit_loads of the nth load (0 based) of `addr`. */
static int unit_index(uint64_t addr, unsigned nth)
{
    for (unsigned i = 0; i < UNIT_LOADS; i++)
        if (unit_loads[i] == addr && nth-- == 0) return (int)i;
    return -1;
}

/* The controller registers: a fault at each load, the rest of its block "not attempted", and no queue is read. A fault in the first block (CAP,
 * CSTS, CC, VS) says REGISTERS_NOT_READ and the second block is never announced; a fault in the second (CSTS again, AQA, ASQ, ACQ) says
 * AQ_REGISTERS_NOT_READ, after the first block was decoded. The state is known when CSTS and CC were read, whatever came after them. */
static int suite_nv_faults(void)
{
    static const struct { uint32_t off; unsigned nth; int second; const char *name, *ctrl; int not_attempted; } regs_[] = {
        {0x00, 0, 0, "CAP=FAULT", "CTRL=UNKNOWN", 1}, {0x04, 0, 0, "CAP=FAULT", "CTRL=UNKNOWN", 1}, {0x1c, 0, 0, "CSTS=FAULT", "CTRL=UNKNOWN", 1},
        {0x14, 0, 0, "CC=FAULT", "CTRL=UNKNOWN", 1}, {0x08, 0, 0, "VS=FAULT", "CTRL=RUNNING", 0},
        {0x1c, 1, 1, "CSTS2=FAULT", "CTRL=RUNNING", 1}, {0x24, 0, 1, "AQA=FAULT", "CTRL=RUNNING", 1}, {0x28, 0, 1, "ASQ=FAULT", "CTRL=RUNNING", 1},
        {0x2c, 0, 1, "ASQ=FAULT", "CTRL=RUNNING", 1}, {0x30, 0, 1, "ACQ=FAULT", "CTRL=RUNNING", 0}, {0x34, 0, 1, "ACQ=FAULT", "CTRL=RUNNING", 0},
    };
    for (unsigned i = 0; i < sizeof regs_ / sizeof regs_[0]; i++) {
        struct world w;
        int at = unit_index(NVo(regs_[i].off), regs_[i].nth);
        const char *label = regs_[i].second ? P "NVME.AQ " : P "NVME ";
        CHECK(at >= (int)FIRST_NV && at < (int)FIRST_QUEUE);
        world_good(&w);
        if (regs_[i].nth) bus_nth_fault(NVo(regs_[i].off), regs_[i].nth);
        else bus_fault(NVo(regs_[i].off));
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK_TOKEN(label, regs_[i].name);
        CHECK_TOKEN(P "VERDICT", regs_[i].second ? "WHY=AQ_REGISTERS_NOT_READ" : "WHY=REGISTERS_NOT_READ");
        CHECK_EQ(loads_in(BAR_GOOD, BAR_GOOD + 0x4000), (unsigned)(at - (int)FIRST_NV + 1));   /* up to and including the fault, nothing after it */
        CHECK_EQ(loads_in(ASQ_GOOD, ASQ_GOOD + 0x1000) + loads_in(ACQ_GOOD, ACQ_GOOD + 0x1000), 0);   /* no queue without the registers */
        CHECK_EQ(line_has(label, "NOT_ATTEMPTED"), regs_[i].not_attempted);
        CHECK_TOKEN(P "VERDICT", regs_[i].ctrl);
        CHECK_TOKEN(P "VERDICT", "QUEUES=NOT_READ");
        CHECK_NO_LINE(P "NEXT ADMIN_QUEUES");
        if (regs_[i].second) {
            CHECK_LINE(P "NEXT NVME_AQ AFTER 8 S");
        } else {
            CHECK_NO_LINE(P "NEXT NVME_AQ");                                 /* a fault in the first block: the second is never announced */
            CHECK_NO_LINE(P "NVME.AQ ");
        }
        world_free(&w);
    }
    return 0;
}

/* ---- The controller's state, its registers, the queue sizes ----------------------------------------------------------------------- */

static int ctrl_case(const char *name, uint32_t cc, uint32_t csts, const char *ctrl, const char *queues)
{
    struct world w;
    char t1[48], t2[48];
    struct nv_cfg n = good_nv;
    world_good(&w);
    n.cc = cc;
    n.csts = csts;
    put_nvme(BAR_GOOD, &n);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    snprintf(t1, sizeof t1, "CTRL=%s", ctrl);
    snprintf(t2, sizeof t2, "QUEUES=%s", queues);
    if (!has_token(P "VERDICT", t1, 1) || !has_token(P "VERDICT", t2, 1)) fprintf(stderr, "%s: %s\n", name, lines[find_line(P "VERDICT")]);
    CHECK_TOKEN(P "VERDICT", t1);
    CHECK_TOKEN(P "VERDICT", t2);
    CHECK_TOKEN(P "VERDICT", "WHY=NONE");
    if (strcmp(queues, "READ")) {
        CHECK_NO_LINE(P "NEXT ADMIN_QUEUES");
        CHECK_EQ(loads_in(ASQ_GOOD, ASQ_GOOD + 0x1000) + loads_in(ACQ_GOOD, ACQ_GOOD + 0x1000), 0);
    }
    world_free(&w);
    return 0;
}

static int aqa_case(uint32_t aqa, const char *queues, unsigned sq_slots, unsigned cq_slots, int odd)
{
    struct world w;
    struct nv_cfg n = good_nv;
    char token[48];
    world_good(&w);
    n.aqa = aqa;
    put_nvme(BAR_GOOD, &n);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    snprintf(token, sizeof token, "QUEUES=%s", queues);
    if (!has_token(P "VERDICT", token, 1)) fprintf(stderr, "AQA %#x: %s\n", aqa, lines[find_line(P "VERDICT")]);
    CHECK_TOKEN(P "VERDICT", token);
    CHECK_EQ(loads_in(ASQ_GOOD, ASQ_GOOD + 0x1000), 6u * sq_slots);
    CHECK_EQ(loads_in(ACQ_GOOD, ACQ_GOOD + 0x1000), 3u * cq_slots);
    if (odd) CHECK_TOKEN(P "AQ ", "ODD");                           /* a reserved bit (15:12, 31:28) is set: the sizes are shown, marked odd */
    else CHECK_NO_TOKEN(P "AQ ", "ODD");
    world_free(&w);
    return 0;
}

/* A controller that answers with all ones is not decoded: the first block is read through (a completed read is not a fault), CTRL says ODD and
 * the verdict says ALL_ONES, and the second block and the queues are not read. */
static int ones_case(const char *name, uint64_t cap, uint32_t cc, uint32_t csts)
{
    struct world w;
    struct nv_cfg n = good_nv;
    world_good(&w);
    n.cap = cap;
    n.cc = cc;
    n.csts = csts;
    put_nvme(BAR_GOOD, &n);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    if (!has_token(P "VERDICT", "CTRL=ALL_ONES", 1)) fprintf(stderr, "%s: %s\n", name, lines[find_line(P "VERDICT")]);
    CHECK_TOKEN(P "VERDICT", "CTRL=ALL_ONES");
    CHECK_TOKEN(P "VERDICT", "QUEUES=NOT_READ");
    CHECK_TOKEN(P "VERDICT", "WHY=REGISTERS_ALL_ONES");
    CHECK_LINE(P "CTRL ODD=ALL_ONES");
    CHECK_NO_LINE(P "CAP ");
    CHECK_NO_LINE(P "NEXT NVME_AQ");
    CHECK_NO_LINE(P "NEXT ADMIN_QUEUES");
    CHECK_EQ(loads_in(BAR_GOOD, BAR_GOOD + 0x4000), FIRST_AQ - FIRST_NV);
    CHECK_EQ(loads_in(ASQ_GOOD, ASQ_GOOD + 0x1000) + loads_in(ACQ_GOOD, ACQ_GOOD + 0x1000), 0);
    world_free(&w);
    return 0;
}

/* CSTS read a second time, at the start of the second block: what it says of the state the first read showed. `second` is the value of the second
 * read; a fault is tried by suite_nv_faults. */
static int csts2_case(const char *name, uint32_t cc, uint32_t csts, uint32_t second, const char *ctrl, const char *queues, const char *why, unsigned bar_loads)
{
    struct world w;
    struct nv_cfg n = good_nv;
    char t1[48], t2[48], t3[48];
    world_good(&w);
    n.cc = cc;
    n.csts = csts;
    put_nvme(BAR_GOOD, &n);
    bus_nth(NVo(0x1c), 1, second);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    snprintf(t1, sizeof t1, "CTRL=%s", ctrl);
    snprintf(t2, sizeof t2, "QUEUES=%s", queues);
    snprintf(t3, sizeof t3, "WHY=%s", why);
    if (!has_token(P "VERDICT", t1, 1) || !has_token(P "VERDICT", t2, 1) || !has_token(P "VERDICT", t3, 1)) fprintf(stderr, "%s: %s\n", name, lines[find_line(P "VERDICT")]);
    CHECK_TOKEN(P "VERDICT", t1);
    CHECK_TOKEN(P "VERDICT", t2);
    CHECK_TOKEN(P "VERDICT", t3);
    CHECK_EQ(loads_in(BAR_GOOD, BAR_GOOD + 0x4000), bar_loads);
    world_free(&w);
    return 0;
}

static int decode_case(uint64_t cap, uint32_t vs, uint32_t cc, uint32_t csts, const char *raw, const char *cap_line, const char *cap_more, const char *ctrl_line,
                       const char *ctrl_more, const char *ctrl)
{
    struct world w;
    struct nv_cfg n = good_nv;
    world_good(&w);
    n.cap = cap;
    n.vs = vs;
    n.cc = cc;
    n.csts = csts;
    put_nvme(BAR_GOOD, &n);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK_LINE(raw);
    CHECK_LINE(cap_line);
    if (cap_more) CHECK_LINE(cap_more);
    CHECK_LINE(ctrl_line);
    if (ctrl_more) CHECK_LINE(ctrl_more);
    CHECK_TOKEN(P "VERDICT", ctrl);
    world_free(&w);
    return 0;
}

/* One bit at a time: every field the payload prints of CAP, VS, CC, CSTS and AQA with a single bit set, against the field positions of the NVMe Base
 * Specification written here as lowest and highest bit (INFERRED from the specification, which is not a file of this tree). */
struct field {
    const char *key;
    unsigned lo, hi;
    int hex;
};
static const struct field cap_fields[] = {
    {"MQES", 0, 15, 0}, {"CQR", 16, 16, 0}, {"TO", 24, 31, 0}, {"DSTRD", 32, 35, 0}, {"NSSRS", 36, 36, 0},
    {"CSS", 37, 44, 1}, {"MPSMIN", 48, 51, 0}, {"MPSMAX", 52, 55, 0}, {"PMRS", 56, 56, 0}, {"CMBS", 57, 57, 0},
};
static const struct field cc_fields[] = {
    {"EN", 0, 0, 0}, {"CSS", 4, 6, 0}, {"MPS", 7, 10, 0}, {"AMS", 11, 13, 0}, {"SHN", 14, 15, 0}, {"IOSQES", 16, 19, 0}, {"IOCQES", 20, 23, 0},
};
static const struct field csts_fields[] = {{"RDY", 0, 0, 0}, {"CFS", 1, 1, 0}, {"SHST", 2, 3, 0}};

static int has_fields(const char *label, uint64_t word, const struct field *f, unsigned n)
{
    for (unsigned i = 0; i < n; i++) {
        uint64_t v = (word >> f[i].lo) & ((UINT64_C(1) << (f[i].hi - f[i].lo + 1)) - 1);
        char token[48];
        snprintf(token, sizeof token, f[i].hex ? "%s=0X%llX" : "%s=%llu", f[i].key, (unsigned long long)v);
        if (!has_token(label, token, 1)) {
            fprintf(stderr, "no %s on a '%s' line (word %#llx)\n", token, label, (unsigned long long)word);
            return 0;
        }
    }
    return 1;
}

static int suite_register_bits(void)
{
    for (unsigned b = 0; b < 64; b++) {
        struct world w;
        struct nv_cfg n = good_nv;
        n.cap = UINT64_C(1) << b;
        world_good(&w);
        put_nvme(BAR_GOOD, &n);
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK(has_fields(P "CAP", n.cap, cap_fields, sizeof cap_fields / sizeof cap_fields[0]));
        world_free(&w);
    }
    for (unsigned b = 0; b < 32; b++) {
        struct world w;
        struct nv_cfg n = good_nv;
        char token[48];
        uint32_t bit = UINT32_C(1) << b;
        n.vs = bit;
        n.cc = bit;
        n.csts = bit;
        n.aqa = bit;
        world_good(&w);
        put_nvme(BAR_GOOD, &n);
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        snprintf(token, sizeof token, "VER=%u.%u.%u", bit >> 16, bit >> 8 & 0xffu, bit & 0xffu);
        CHECK_TOKEN(P "CTRL", token);
        CHECK(has_fields(P "CTRL", bit, cc_fields, sizeof cc_fields / sizeof cc_fields[0]));
        CHECK(has_fields(P "CTRL", bit, csts_fields, sizeof csts_fields / sizeof csts_fields[0]));
        snprintf(token, sizeof token, "ASQE=%u", (bit & 0xfffu) + 1u);
        CHECK_TOKEN(P "AQ", token);
        snprintf(token, sizeof token, "ACQE=%u", (bit >> 16 & 0xfffu) + 1u);
        CHECK_TOKEN(P "AQ", token);
        world_free(&w);
    }
    return 0;
}

static int suite_ctrl(void)
{
    /* The state: enabled and ready, disabled, in transition either way, fatal, shutting down or shut down. */
    CHECK_EQ(ctrl_case("running", 0x00460001, 0x1, "RUNNING", "READ"), 0);
    CHECK_EQ(ctrl_case("disabled", 0x00460000, 0x0, "DISABLED", "NOT_ENABLED"), 0);
    CHECK_EQ(ctrl_case("enabling", 0x00460001, 0x0, "TRANSITION", "NOT_ENABLED"), 0);
    CHECK_EQ(ctrl_case("disabling", 0x00460000, 0x1, "TRANSITION", "NOT_ENABLED"), 0);
    CHECK_EQ(ctrl_case("fatal", 0x00460001, 0x3, "FATAL", "NOT_ENABLED"), 0);
    CHECK_EQ(ctrl_case("fatal-not-ready", 0x00460000, 0x2, "FATAL", "NOT_ENABLED"), 0);
    CHECK_EQ(ctrl_case("shutdown-occurring", 0x00464001, 0x5, "SHUTDOWN", "NOT_ENABLED"), 0);
    CHECK_EQ(ctrl_case("shutdown-complete", 0x00464000, 0x8, "SHUTDOWN", "NOT_ENABLED"), 0);
    CHECK_EQ(ctrl_case("shutdown-reserved", 0x00460001, 0xd, "SHUTDOWN", "NOT_ENABLED"), 0);
    CHECK_EQ(ctrl_case("nssro-only", 0x00460001, 0x11, "RUNNING", "READ"), 0);
    CHECK_EQ(ctrl_case("paused", 0x00460001, 0x21, "RUNNING", "READ"), 0);
    /* The queue sizes: AQA is zero based in 12 bits, a queue of one entry is no queue, 4096 entries is the most; a reserved bit (15:12, 31:28) is
     * shown as odd, and does not change the sizes. */
    CHECK_EQ(aqa_case(0x00010001, "READ", 2, 2, 0), 0);
    CHECK_EQ(aqa_case(0x00000000, "NO_QUEUES", 0, 0, 0), 0);
    CHECK_EQ(aqa_case(0x00010000, "NO_QUEUES", 0, 0, 0), 0);
    CHECK_EQ(aqa_case(0x00000001, "NO_QUEUES", 0, 0, 0), 0);
    CHECK_EQ(aqa_case(0x00020002, "READ", 2, 2, 0), 0);
    CHECK_EQ(aqa_case(0x0fff0fff, "READ", 2, 2, 0), 0);
    CHECK_EQ(aqa_case(0xffffffff, "READ", 2, 2, 1), 0);
    CHECK_EQ(aqa_case(0x10011001, "READ", 2, 2, 1), 0);
    CHECK_EQ(aqa_case(0x00011000, "NO_QUEUES", 0, 0, 1), 0);
    CHECK_EQ(aqa_case(0x80010001, "READ", 2, 2, 1), 0);
    /* A controller that answers with all ones: any one of CAP, CC and CSTS says so. */
    CHECK_EQ(ones_case("all", ~UINT64_C(0), 0xffffffff, 0xffffffff), 0);
    CHECK_EQ(ones_case("csts", good_nv.cap, good_nv.cc, 0xffffffff), 0);
    CHECK_EQ(ones_case("cc", good_nv.cap, 0xffffffff, 0x1), 0);
    CHECK_EQ(ones_case("cap", ~UINT64_C(0), good_nv.cc, 0x1), 0);
    /* CSTS read twice: a change of RDY, CFS or SHST between the two reads is a controller in transition whatever the first read said; NSSRO and PP
     * (bits 4 and 5) are not part of the state; all ones the second time stops the block. */
    CHECK_EQ(csts2_case("same", 0x00460001, 0x1, 0x1, "RUNNING", "READ", "NONE", 11), 0);
    CHECK_EQ(csts2_case("rdy-dropped", 0x00460001, 0x1, 0x0, "TRANSITION", "NOT_ENABLED", "NONE", 11), 0);
    CHECK_EQ(csts2_case("cfs-set", 0x00460001, 0x1, 0x3, "TRANSITION", "NOT_ENABLED", "NONE", 11), 0);
    CHECK_EQ(csts2_case("shst-2", 0x00460001, 0x1, 0x5, "TRANSITION", "NOT_ENABLED", "NONE", 11), 0);
    CHECK_EQ(csts2_case("shst-3", 0x00460001, 0x1, 0x9, "TRANSITION", "NOT_ENABLED", "NONE", 11), 0);
    CHECK_EQ(csts2_case("nssro-only", 0x00460001, 0x1, 0x11, "RUNNING", "READ", "NONE", 11), 0);
    CHECK_EQ(csts2_case("pp-only", 0x00460001, 0x1, 0x21, "RUNNING", "READ", "NONE", 11), 0);
    CHECK_EQ(csts2_case("disabled-then-ready", 0x00460000, 0x0, 0x1, "TRANSITION", "NOT_ENABLED", "NONE", 11), 0);
    CHECK_EQ(csts2_case("fatal-then-clear", 0x00460001, 0x3, 0x1, "TRANSITION", "NOT_ENABLED", "NONE", 11), 0);
    CHECK_EQ(csts2_case("all-ones", 0x00460001, 0x1, 0xffffffff, "ALL_ONES", "NOT_READ", "REGISTERS_ALL_ONES", 6), 0);
    /* The decoding of CAP, VS, CC and CSTS, field by field, with values that tell the fields apart. */
    CHECK_EQ(decode_case(UINT64_C(0x0123456789abcdef), 0x00010400, 0x00a5d5d1, 0x1, P "NVME CAP=0X123456789ABCDEF CSTS=0X1 CC=0XA5D5D1 VS=0X10400",
                         P "CAP MQES=52719 CQR=1 TO=137 DSTRD=7 NSSRS=0 CSS=0X2B MPSMIN=3 MPSMAX=2 PMRS=1", P "CAP CMBS=0",
                         P "CTRL VER=1.4.0 EN=1 RDY=1 CFS=0 SHST=0 CSS=5 MPS=11 AMS=2 SHN=3 IOSQES=5 IOCQES=10", 0, "CTRL=RUNNING"), 0);
    CHECK_EQ(decode_case(UINT64_C(0x0300000000000000), 0xffffffff, 0x00f00001, 0x3d, P "NVME CAP=0X300000000000000 CSTS=0X3D CC=0XF00001 VS=0XFFFFFFFF",
                         P "CAP MQES=0 CQR=0 TO=0 DSTRD=0 NSSRS=0 CSS=0X0 MPSMIN=0 MPSMAX=0 PMRS=1 CMBS=1", 0,
                         P "CTRL VER=65535.255.255 EN=1 RDY=1 CFS=0 SHST=3 CSS=0 MPS=0 AMS=0 SHN=0 IOSQES=0", P "CTRL IOCQES=15", "CTRL=SHUTDOWN"), 0);
    return suite_register_bits();
}

#include "test-q1n1-sp11-payload-nvmesnap-queues.h"


/* ---- The counter, the exception level, the arguments ---------------------------------------------------------------------------- */

static int suite_counter(void)
{
    struct world w;
    /* No counter op: the NEXT line is printed and the wait is not made; nothing past the headers is read. */
    world_good(&w);
    w.a.ops.counter = 0;
    nv_allowed = 0;
    ram_ok_n = 0;
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK_LINE(P "NEXT CAPS AFTER 8 S");
    CHECK_LINE(P "CAPS SKIPPED=NO_COUNTER");
    CHECK_TOKEN(P "VERDICT", "WHY=CAPS_NOT_RUN");
    CHECK_NO_LINE(P "NEXT NVME_REGS");
    CHECK_EQ(load_n, HEADER_LOADS);
    world_free(&w);
    /* A counter that stands still, and one that goes back: the wait is not made, and the payload says so. */
    for (int mode = 1; mode <= 2; mode++) {
        world_good(&w);
        clock_set(UINT64_C(1) << 40, 1000000, mode);
        nv_allowed = 0;
        ram_ok_n = 0;
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK_LINE(P "CAPS SKIPPED=COUNTER_UNUSABLE");
        CHECK_TOKEN(P "VERDICT", "WHY=CAPS_NOT_RUN");
        CHECK_EQ(load_n, HEADER_LOADS);
        world_free(&w);
    }
    /* An absurd CNTFRQ_EL0 is replaced by 19.2 MHz: the wait is still eight seconds of the counter at that rate. */
    for (unsigned i = 0; i < 3; i++) {
        uint64_t absurd = i == 0 ? 0 : i == 1 ? 999999 : UINT64_C(1000000001);
        int k1;
        world_good(&w);
        reg_set("CNTFRQ_EL0", absurd);
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK_LINE(P "START CURRENTEL=0X8 FREQ=19200000 ECAM=0X70000000 WINDOW=0X70300000");
        k1 = find_line(P "NEXT CAPS");
        CHECK_EQ(check_wait(k1, RPo(0x40), 19200000), 0);
        world_free(&w);
    }
    /* The limits of the accepted range are accepted, and the wait is made at that rate: 1 MHz and 1 GHz. */
    for (uint64_t freq = 1000000; freq <= 1000000000; freq *= 1000) {
        int k1;
        uint64_t waited;
        world_good(&w);
        reg_set("CNTFRQ_EL0", freq);
        clock_set(1000000, freq / 20, 0);
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        k1 = find_line(P "NEXT CAPS");
        CHECK(k1 >= 0);
        waited = loads[first_load_after((unsigned)k1)].clock - line_clock[k1];
        CHECK(waited >= 8 * freq && waited <= 8 * freq + freq / 10);
        world_free(&w);
    }
    /* A counter that works for the first wait and stands still for the second: the registers are not read, and the verdict says why. */
    world_good(&w);
    w.a.ops.counter = counter_stops_at_registers;
    nv_allowed = 0;
    ram_ok_n = 0;
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK_LINE(P "NEXT NVME_REGS AFTER 8 S");
    CHECK_LINE(P "NVME_REGS SKIPPED=COUNTER_UNUSABLE");
    CHECK_TOKEN(P "VERDICT", "WHY=GROUP_SKIPPED");
    CHECK_TOKEN(P "DONE", "NVME_GROUP_SKIPPED");
    CHECK_NO_LINE(P "NEXT NVME_AQ");
    CHECK_EQ(loads_in(BAR_GOOD, BAR_GOOD + 0x4000), 0);
    world_free(&w);
    /* A counter that works for two waits and stands still for the third: the first block was read and decoded, the second is not read, and the
     * verdict says the group was skipped, not that a register failed. */
    world_good(&w);
    w.a.ops.counter = counter_stops_at_aq;
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK_LINE(P "NEXT NVME_AQ AFTER 8 S");
    CHECK_LINE(P "NVME_AQ SKIPPED=COUNTER_UNUSABLE");
    CHECK_TOKEN(P "VERDICT", "WHY=GROUP_SKIPPED");
    CHECK_TOKEN(P "VERDICT", "CTRL=RUNNING");
    CHECK_TOKEN(P "VERDICT", "QUEUES=NOT_READ");
    CHECK_TOKEN(P "DONE", "NVME_GROUP_RAN");
    CHECK_TOKEN(P "DONE", "NVME_TRIED=4");
    CHECK_NO_LINE(P "NVME.AQ ");
    CHECK_NO_LINE(P "NEXT ADMIN_QUEUES");
    CHECK_EQ(loads_in(BAR_GOOD, BAR_GOOD + 0x4000), FIRST_AQ - FIRST_NV);
    world_free(&w);
    /* A counter that stands still from the start is given up on after a bounded number of reads. */
    world_good(&w);
    clock_set(UINT64_C(1) << 40, 1000000, 1);
    nv_allowed = 0;
    ram_ok_n = 0;
    CHECK_EQ(go(&w.a), 0);
    CHECK(clock_calls <= 2100000);
    CHECK_LINE(P "CAPS SKIPPED=COUNTER_UNUSABLE");
    CHECK_NO_LINE(P "CAPS SKIPPED=SPIN_BOUND");
    world_free(&w);
#ifdef TEST_SPIN_MAX
    /* The bound on the reads of one wait, built small (SPIN_MAX and COUNTER_STUCK_READS of the payload are lowered): a counter that moves but needs
     * more reads than the bound to finish is not made to wait, and the page says SPIN_BOUND, which is not what a dead counter says. One that needs
     * exactly the bound finishes. The model must not step so fast that the bound can never matter: the steps here are the finest that finish,
     * one more tick short of that, and one tick a read. */
    {
        static const struct { const char *name; uint64_t step; int made; } steps[] = {
            {"exactly the bound", 8 * (uint64_t)FREQ / TEST_SPIN_MAX, 1},
            {"one read more than the bound", 8 * (uint64_t)FREQ / TEST_SPIN_MAX - 1, 0},
            {"a tick a read", 1, 0},
        };
        _Static_assert(8 * (uint64_t)FREQ % TEST_SPIN_MAX == 0, "the finest finishing step must divide the wait");
        for (unsigned i = 0; i < sizeof steps / sizeof steps[0]; i++) {
            world_good(&w);
            clock_set(1000000, steps[i].step, 0);
            if (!steps[i].made) {
                nv_allowed = 0;
                ram_ok_n = 0;
            }
            CHECK_EQ(go(&w.a), 0);
            CHECK_DISCIPLINE();
            if (steps[i].made != (line_count == UNIT_LINES)) fprintf(stderr, "step %s: %u lines\n", steps[i].name, line_count);
            CHECK_EQ(line_count == UNIT_LINES, steps[i].made);
            if (!steps[i].made) {
                CHECK_LINE(P "CAPS SKIPPED=SPIN_BOUND");
                CHECK_NO_LINE(P "CAPS SKIPPED=COUNTER_UNUSABLE");
                CHECK_TOKEN(P "VERDICT", "WHY=CAPS_NOT_RUN");
                CHECK_EQ(load_n, HEADER_LOADS);
                CHECK(clock_calls <= TEST_SPIN_MAX + 2);                /* the read of the start, and the bound */
            }
            world_free(&w);
        }
        /* A dead counter in the same build still says so, and not SPIN_BOUND: it stands still, or goes back. */
        for (int mode = 1; mode <= 2; mode++) {
            world_good(&w);
            clock_set(UINT64_C(1) << 40, 1000000, mode);
            nv_allowed = 0;
            ram_ok_n = 0;
            CHECK_EQ(go(&w.a), 0);
            CHECK_DISCIPLINE();
            CHECK_LINE(P "CAPS SKIPPED=COUNTER_UNUSABLE");
            CHECK_NO_LINE(P "CAPS SKIPPED=SPIN_BOUND");
            CHECK(clock_calls <= COUNTER_STUCK_READS + 2);
            world_free(&w);
        }
    }
#else
    /* A counter that moves slowly (a hundred ticks a read: a million and a half reads for eight seconds, three times) still finishes every wait: the
     * bound on the reads of a wait is far above what a real counter needs, and this model is not stepped so fast that it could not matter. */
    world_good(&w);
    clock_set(1000000, 100, 0);
    counter_limit = 10000000;
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK_EQ(line_count, UNIT_LINES);
    CHECK(clock_calls > 4000000);
    CHECK_NO_LINE(P "CAPS SKIPPED");
    world_free(&w);
#endif
    return 0;
}

static int suite_el(void)
{
    struct world w;
    for (uint64_t el = 0; el <= 3; el++) {
        if (el == 2) continue;
        world_good(&w);
        set_el(el);
        CHECK_EQ(go(&w.a), 2);
        CHECK_EQ(line_count, 2);
        CHECK_LINE(P "REFUSED NOT_AT_EL2");
        CHECK_EQ(load_n, 0);
        CHECK_EQ(at_count, 0);
        world_free(&w);
    }
    for (unsigned bad = 0; bad < 5; bad++) {
        world_good(&w);
        switch (bad) {
        case 0: w.a.magic ^= 1; break;
        case 1: w.a.version = 2; break;
        case 2: w.a.size = sizeof w.a - 1; break;
        case 3: w.a.ops.puts = 0; break;
        default: w.a.ops.hex = 0; break;
        }
        CHECK_EQ(go(&w.a), Q1N1_PAYLOAD_RET_BAD_ARGS);
        CHECK_EQ(line_count, 0);
        CHECK_EQ(load_n, 0);
        world_free(&w);
    }
    CHECK_EQ(payload_entry(0), Q1N1_PAYLOAD_RET_BAD_ARGS);
    world_good(&w);
    w.a.ops.load32 = 0;
    CHECK_EQ(go(&w.a), 3);
    CHECK_LINE(P "REFUSED NO_LOAD_OP");
    CHECK_EQ(at_count, 0);
    world_free(&w);
    return 0;
}

/* ---- Budget, worst case ---------------------------------------------------------------------------------------------------------- */

static unsigned most_lines;

/* The payload with a smaller page or load cap than the shipped one: what may be dropped is dropped and counted; what may not never is. */
static int suite_budget(void)
{
    struct world w;
    world_good(&w);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    most_lines = line_count > most_lines ? line_count : most_lines;
#if TEST_LOAD_CAP < 55
    /* The cap falls inside the page's reads: the read that would pass it is refused and not made, counted as a refusal and never as a fault,
     * named with its code where the page shows it, and nothing after it is read. */
    {
        char token[32];
        CHECK_EQ(load_n, TEST_LOAD_CAP);
        snprintf(token, sizeof token, "LOADS=%u", TEST_LOAD_CAP);
        CHECK_TOKEN(P "DONE", token);
        CHECK_TOKEN(P "DONE", "REFUSED=1");
        CHECK_TOKEN(P "DONE", "FAULTS=0");
        CHECK_NO_LINE(P "NEXT NVME_REGS");
#if TEST_LOAD_CAP == 10
        snprintf(token, sizeof token, "HDR=REFUSED:%u", (unsigned)(uint8_t)Q1N1_PAYLOAD_LOAD_E_BUDGET);
        CHECK_TOKEN(P "EP", token);                                  /* the eleventh load is the endpoint's header type */
        CHECK_TOKEN(P "VERDICT", "WHY=EP_NOT_READ");
        CHECK_NO_LINE(P "NEXT CAPS");
#else
        CHECK_TOKEN(P "VERDICT", "WHY=CAPS_NOT_READ");               /* the capability walk of the endpoint is cut short */
        CHECK_LINE(P "NEXT CAPS AFTER 8 S");
#endif
    }
#elif TEST_BUDGET < 30
    {
        unsigned suppressed = 0;
        CHECK_LINE(P "NEXT CAPS AFTER 8 S");
        CHECK_LINE(P "NEXT NVME_REGS AFTER 8 S");
        CHECK_LINE(P "NEXT NVME_AQ AFTER 8 S");
        CHECK_LINE(P "NEXT ADMIN_QUEUES");
        CHECK(find_line(P "VERDICT") >= 0);
        CHECK_EQ(find_line(P "DONE"), (int)line_count - 1);
        CHECK_EQ(line_count, TEST_BUDGET);
        for (const char *p = lines[line_count - 1]; (p = strstr(p, "SUPPRESSED=")); p++) suppressed = (unsigned)atoi(p + 11);
        CHECK_EQ(suppressed + line_count, UNIT_LINES);
    }
#else
    CHECK_EQ(line_count, UNIT_LINES);
    CHECK_NO_TOKEN(P "DONE", "SUPPRESSED=");
#endif
    world_free(&w);
    return 0;
}

/* The world that prints the most lines: values as long as they can be in every place, so that the page wraps wherever it can. */
static int suite_worst(void)
{
    static const uint8_t sqw[6] = {0, 1, 6, 7, 10, 11}, cqw[3] = {0, 2, 3};
    struct world w;
    struct nv_cfg n = good_nv;
    world_good(&w);
    bus_set(RPo(0x00), 0xfffffffeu);
    bus_set(RPo(0x04), 0xfff1ffffu);
    bus_set(RPo(0x08), 0x06040fffu);
    bus_set(RPo(0x0c), 0x00810010u);
    bus_set(EPo(0x00), 0xfffffffeu);
    bus_set(EPo(0x04), 0xfff1ffffu);
    bus_set(EPo(0x08), 0x010802ffu);
    n.cap = UINT64_C(0xfeffffffffffffff);
    n.vs = 0xfffffffe;
    n.cc = 0xfffffff1;
    n.aqa = 0x0fff0fff;
    put_nvme(BAR_GOOD, &n);
    for (unsigned i = 0; i < 6; i++) {
        bus_set(ASQ_GOOD + 4u * sqw[i], 0xfffffff0u + i);
        bus_set(ASQ_GOOD + 64 + 4u * sqw[i], 0xffffffe0u + i);
    }
    for (unsigned i = 0; i < 3; i++) {
        bus_set(ACQ_GOOD + 4u * cqw[i], 0xfffffff0u + i);
        bus_set(ACQ_GOOD + 16 + 4u * cqw[i], 0xffffffe0u + i);
    }
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK_TOKEN(P "VERDICT", "QUEUES=READ");
    most_lines = line_count > most_lines ? line_count : most_lines;
#if TEST_BUDGET >= 30
    CHECK_LINE(P "AQ ASQE=4096 ACQE=4096");                          /* a smaller page may drop it */
    CHECK(line_count >= UNIT_LINES);
#endif
    world_free(&w);
    return 0;
}

#include "test-q1n1-sp11-payload-nvmesnap-fuzz.h"

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*run)(void); } suites[] = {
        {"unit", suite_unit}, {"gates", suite_gates}, {"gatemap", suite_gate_map}, {"pages", suite_pages}, {"faults", suite_faults},
        {"nvfaults", suite_nv_faults}, {"ctrl", suite_ctrl}, {"queues", suite_queues}, {"counter", suite_counter}, {"el", suite_el},
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
    printf("PASS: %u payload nvmesnap suites, %u checks\n", ran, checks);
    return 0;
}
