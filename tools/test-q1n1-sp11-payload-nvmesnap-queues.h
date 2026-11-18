/* SPDX-License-Identifier: MIT */
/* The admin queue suites of the nvmesnap host test (tools/test-q1n1-sp11-payload-nvmesnap.c): the queue addresses, every type of memory map
 * descriptor under the queue pages, the edges of the descriptors, the attributes of the pages, bad memory maps, the fields of an entry, a fault at
 * each word of a slot (the words are read data first), and a fault at each load of the good world's queues. Included by the main file after the
 * world, the scenarios and the loads of the good world. Evidence: EXPERIMENTAL (host model only). */
#pragma once

struct qcase {
    const char *name;
    uint64_t asq, acq;
    const char *queues;
    int sq_read, cq_read;               /* the pages the payload reads in this world */
};

static void queue_world(struct world *w, uint64_t asq, uint64_t acq, int sq_read, int cq_read, const struct d *list, unsigned count)
{
    struct nv_cfg n = good_nv;
    world_new(w, list, count);
    put_rp();
    put_ep();
    n.asq = asq;
    n.acq = acq;
    put_nvme(BAR_GOOD, &n);
    if (asq && !(asq & 0xfff) && asq < (UINT64_C(1) << 47)) put_sq(asq);
    if (acq && !(acq & 0xfff) && acq < (UINT64_C(1) << 47)) put_cq(acq);
    ram_ok_n = 0;
    if (sq_read) allow_ram(asq, asq + 128);
    if (cq_read) allow_ram(acq, acq + 32);
}

static int queue_check(const char *name, const char *queues)
{
    char token[48];
    snprintf(token, sizeof token, "QUEUES=%s", queues);
    if (!has_token(P "VERDICT", token, 1)) fprintf(stderr, "%s: %s\n", name, lines[find_line(P "VERDICT")]);
    CHECK_TOKEN(P "VERDICT", token);
    return 0;
}

static int suite_queue_addresses(void)
{
    static const struct qcase cases[] = {
        {"asq zero", 0, ACQ_GOOD, "BAD_ADDRESS", 0, 0},
        {"acq zero", ASQ_GOOD, 0, "BAD_ADDRESS", 0, 0},
        {"both zero", 0, 0, "BAD_ADDRESS", 0, 0},
        {"asq unaligned", ASQ_GOOD + 0x40, ACQ_GOOD, "BAD_ADDRESS", 0, 0},
        {"acq unaligned", ASQ_GOOD, ACQ_GOOD + 4, "BAD_ADDRESS", 0, 0},
        {"asq 4k-1", ASQ_GOOD + 0xfff, ACQ_GOOD, "BAD_ADDRESS", 0, 0},
        {"same page", ASQ_GOOD, ASQ_GOOD, "BAD_ADDRESS", 0, 0},
        {"asq 2^48", UINT64_C(1) << 48, ACQ_GOOD, "BAD_ADDRESS", 0, 0},
        {"acq above 2^48", ASQ_GOOD, UINT64_C(0xffff000000000000), "BAD_ADDRESS", 0, 0},
        {"asq just below 2^48", (UINT64_C(1) << 48) - 0x1000, ACQ_GOOD, "NOT_RAM", 0, 1},
        {"queues in reserved memory", 0xa0000000, 0xa0001000, "NOT_RAM", 0, 0},
        {"queues in loader data", 0xa1000000, 0xa1001000, "READ", 1, 1},
        {"queues in mmio", 0xb0000000, 0xb0001000, "NOT_RAM", 0, 0},
        {"queues in acpi reclaim", 0xc0000000, 0xc0001000, "READ", 1, 1},
        {"queues in no descriptor", 0x60000000, 0x60001000, "NOT_RAM", 0, 0},
        {"sq in ram, cq in reserved", ASQ_GOOD, 0xa0000000, "NOT_RAM", 1, 0},
        {"sq in reserved, cq in ram", 0xa0000000, ACQ_GOOD, "NOT_RAM", 0, 1},
        {"queues at the end of the extent", 0xa0000000 - 0x2000, 0xa0000000 - 0x1000, "READ", 1, 1},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        struct world w;
        queue_world(&w, cases[i].asq, cases[i].acq, cases[i].sq_read, cases[i].cq_read, std_map, STD_COUNT);
        if (cases[i].sq_read) tr_map(cases[i].asq, cases[i].asq + 0x1000, ATTR_WB, SH_INNER);
        if (cases[i].cq_read) tr_map(cases[i].acq, cases[i].acq + 0x1000, ATTR_WB, SH_INNER);
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK_TOKEN(P "VERDICT", "WHY=NONE");
        if (queue_check(cases[i].name, cases[i].queues)) return 1;
        CHECK_EQ(loads_in(cases[i].asq, cases[i].asq + 128) >= 1 || !cases[i].sq_read, 1);
        world_free(&w);
    }
    return 0;
}

/* The memory map decides which memory may be read: every type of descriptor under the two queue pages, one at a time. */
static int suite_queue_types(void)
{
    for (uint32_t type = 0; type <= 15; type++) {
        struct d list[STD_COUNT];
        struct world w;
        int usable = (type >= 1 && type <= 7) || type == 9;
        memcpy(list, std_map + 1, (STD_COUNT - 1) * sizeof std_map[0]);       /* the standard conventional descriptor is out of the way */
        list[STD_COUNT - 1] = (struct d){type, ASQ_GOOD & ~UINT64_C(0xfffff), 0x200};
        queue_world(&w, ASQ_GOOD, ACQ_GOOD, usable, usable, list, STD_COUNT);
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK_TOKEN(P "VERDICT", usable ? "QUEUES=READ" : "QUEUES=NOT_RAM");
        if (!usable) {
            CHECK_EQ(loads_in(ASQ_GOOD, ASQ_GOOD + 0x1000) + loads_in(ACQ_GOOD, ACQ_GOOD + 0x1000), 0);
            CHECK_TOKEN(P "ASQ", "NOT_READ");
        }
        world_free(&w);
    }
    return 0;
}

/* Descriptor edges around the queue: the extent that ends exactly where the page starts, one that starts after it, a usable extent beside a
 * reserved one, a descriptor that is not page aligned (not used), and a map that disagrees with itself. */
static int edge_case(const struct d *list, unsigned count, const char *queues, int sq_read, int cq_read)
{
    struct world w;
    queue_world(&w, ASQ_GOOD, ACQ_GOOD, sq_read, cq_read, list, count);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    if (queue_check("edge", queues)) return 1;
    world_free(&w);
    return 0;
}

static int suite_queue_edges(void)
{
    uint64_t at = ASQ_GOOD;
    struct d exact[] = {{7, at, 1}, {7, ACQ_GOOD, 1}};                            /* each page in its own descriptor */
    struct d split[] = {{7, at, 1}, {0, ACQ_GOOD, 1}};                            /* the completion queue's page is reserved */
    struct d two[] = {{7, at, 1}, {7, at + 0x1000, 1}};
    struct d overlap[] = {{7, at, 2}, {0, at, 1}};                                /* a reserved descriptor over a usable one: refused */
    struct d overlap_late[] = {{0, at, 1}, {7, at, 2}};                           /* in the other order: refused too */
    struct d ends_early[] = {{7, at - 0x1000, 1}, {7, ACQ_GOOD, 1}};              /* the usable extent ends where the page starts */
    struct d after_reserved[] = {{0, at - 0x1000, 1}, {7, at, 1}, {7, ACQ_GOOD, 1}};     /* a reserved one that ends where the page starts: not over it */
    struct d starts_late[] = {{7, at + 0x1000, 1}};                               /* and one that starts after the page */
    struct d unaligned[] = {{7, at, 2}, {0, at + 128, 1}};                        /* a descriptor that is not page aligned is not used */
    CHECK_EQ(edge_case(exact, 2, "READ", 1, 1), 0);
    CHECK_EQ(edge_case(split, 2, "NOT_RAM", 1, 0), 0);
    CHECK_EQ(edge_case(two, 2, "READ", 1, 1), 0);
    CHECK_EQ(edge_case(overlap, 2, "NOT_RAM", 0, 1), 0);
    CHECK_EQ(edge_case(overlap_late, 2, "NOT_RAM", 0, 1), 0);
    CHECK_EQ(edge_case(ends_early, 2, "NOT_RAM", 0, 1), 0);
    CHECK_EQ(edge_case(after_reserved, 3, "READ", 1, 1), 0);
    CHECK_EQ(edge_case(starts_late, 1, "NOT_RAM", 0, 1), 0);
    CHECK_EQ(edge_case(unaligned, 2, "READ", 1, 1), 0);
    return 0;
}

/* The attributes of the queue pages as the MMU reports them, an unmapped page, and a completion queue unmapped after a submission queue read. */
static int suite_queue_pages(void)
{
    static const struct { const char *name; int attr; const char *map; } cases[] = {
        {"wb", ATTR_WB, "MAP=WB.IS"}, {"wt", ATTR_WT, "MAP=WT.IS"}, {"nc", ATTR_NC, "MAP=NC.IS"}, {"device", ATTR_DEVICE, "MAP=DEVICE.IS"},
        {"other", 0x77, "MAP=OTHER=0X77.IS"}, {"unmapped", -1, "MAP=FAULT=0X7:TRANS_L3"},
    };
    struct world w;
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        world_good(&w);
        if (cases[i].attr < 0) tr_fault(ASQ_GOOD, ASQ_GOOD + 0x2000, 0x07);
        else tr_map(ASQ_GOOD, ASQ_GOOD + 0x2000, (uint8_t)cases[i].attr, SH_INNER);
        if (cases[i].attr < 0) ram_ok_n = 0;
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        if (!has_token(P "ASQ", cases[i].map, 1)) fprintf(stderr, "%s: %s\n", cases[i].name, lines[find_line(P "ASQ")]);
        CHECK_TOKEN(P "ASQ", cases[i].map);
        CHECK_TOKEN(P "VERDICT", cases[i].attr < 0 ? "QUEUES=PAGE_UNMAPPED" : "QUEUES=READ");
        if (cases[i].attr < 0) CHECK_EQ(loads_in(ASQ_GOOD, ASQ_GOOD + 0x2000), 0);
        world_free(&w);
    }
    world_good(&w);
    tr_fault(ACQ_GOOD, ACQ_GOOD + 0x1000, 0x07);
    ram_ok_n = 0;
    allow_ram(ASQ_GOOD, ASQ_GOOD + 128);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK_TOKEN(P "VERDICT", "QUEUES=PAGE_UNMAPPED");
    CHECK_EQ(loads_in(ASQ_GOOD, ASQ_GOOD + 0x1000), 12u);
    CHECK_EQ(loads_in(ACQ_GOOD, ACQ_GOOD + 0x1000), 0);
    world_free(&w);
    return 0;
}

/* A memory map the payload cannot read: the gate says so and nothing of RAM or of the controller is read. */
static int suite_queue_maps(void)
{
    for (unsigned bad = 0; bad < 5; bad++) {
        struct world w;
        world_good(&w);
        switch (bad) {
        case 0: w.a.map_stride = 4; break;
        case 1: w.a.map_stride = 44; break;
        case 2: w.a.map_size = 0; break;
        case 3: w.a.map_size = 48 * 5 + 7; break;
        default: w.a.map_base = 0; break;
        }
        nv_allowed = 0;
        ram_ok_n = 0;
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK_TOKEN(P "VERDICT", "WHY=MEMORY_MAP_UNREADABLE");
        world_free(&w);
    }
    /* 1024 descriptors are scanned; 1025 are too many to read the map with. */
    for (unsigned count = 1024; count <= 1025; count++) {
        static struct d many[1025];
        struct world w;
        for (unsigned i = 0; i < count; i++) many[i] = (struct d){0, UINT64_C(0x100000000) + (uint64_t)i * 0x1000, 1};
        queue_world(&w, ASQ_GOOD, ACQ_GOOD, 0, 0, many, count);
        if (count > 1024) nv_allowed = 0;
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK_TOKEN(P "VERDICT", count > 1024 ? "WHY=MEMORY_MAP_UNREADABLE" : "WHY=NONE");
        world_free(&w);
    }
    return 0;
}

/* The fields of a submission and a completion entry, with values that tell the fields apart: every bit a field may not take is set around it. */
static int suite_queue_fields(void)
{
    struct world w;
    world_good(&w);
    bus_set(ASQ_GOOD + 4 * 0, 0x1234c106);
    bus_set(ASQ_GOOD + 4 * 1, 0xffffffff);
    bus_set(ASQ_GOOD + 4 * 6, 0x80200000);
    bus_set(ASQ_GOOD + 4 * 7, 0x00000001);
    bus_set(ASQ_GOOD + 4 * 10, 0xa5a5a5a5);
    bus_set(ASQ_GOOD + 4 * 11, 0x5a5a5a5a);
    bus_set(ACQ_GOOD + 0, 0xcafebabe);
    bus_set(ACQ_GOOD + 8, 0xabcd1234);
    bus_set(ACQ_GOOD + 12, 0xfb697fff);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    CHECK_TOKEN(P "SQ0", "DW0=0X1234C106");
    CHECK_TOKEN(P "SQ0", "OPC=0X6");
    CHECK_TOKEN(P "SQ0", "CID=0X1234");
    CHECK_TOKEN(P "SQ0", "NSID=0XFFFFFFFF");
    CHECK_TOKEN(P "SQ0", "PRP1=0X180200000");
    CHECK_TOKEN(P "SQ0", "CDW10=0XA5A5A5A5");
    CHECK_TOKEN(P "SQ0", "CDW11=0X5A5A5A5A");
    CHECK_TOKEN(P "CQ0", "DW0=0XCAFEBABE");
    CHECK_TOKEN(P "CQ0", "DW3=0XFB697FFF");
    CHECK_TOKEN(P "CQ0", "CID=0X7FFF");
    CHECK_TOKEN(P "CQ0", "P=1");
    CHECK_TOKEN(P "CQ0", "SC=0XB4");
    CHECK_TOKEN(P "CQ0", "SCT=5");
    CHECK_TOKEN(P "CQ0", "SQHD=0X1234");
    CHECK_TOKEN(P "CQ0", "SQID=0XABCD");
    world_free(&w);
    return 0;
}

/* The words of a slot are read data first, so that an abort costs the least: a fault at each word of the first entry of each queue, in the order the
 * words are read, shows what was read before it and names the fault and what was not attempted after it. The next slot and the other queue are
 * not read. */
struct wcase {
    uint32_t off;
    const char *must[8];
    const char *never[3];
};
static int word_case(uint64_t base, const char *label, const char *next_label, const char *other_queue, const struct wcase *c)
{
    struct world w;
    world_good(&w);
    bus_fault(base + c->off);
    CHECK_EQ(go(&w.a), 0);
    CHECK_DISCIPLINE();
    for (unsigned i = 0; i < 8 && c->must[i]; i++) {
        if (!has_token(label, c->must[i], 1)) fprintf(stderr, "%s fault at +%u: no %s: %s\n", label, c->off, c->must[i], lines[find_line(label)]);
        CHECK_TOKEN(label, c->must[i]);
    }
    for (unsigned i = 0; i < 3 && c->never[i]; i++) CHECK_NO_TOKEN(label, c->never[i]);
    CHECK_NO_LINE(next_label);
    CHECK_TOKEN(P "VERDICT", "QUEUES=FAULT");
    if (other_queue) CHECK_NO_LINE(other_queue);
    world_free(&w);
    return 0;
}

static int suite_queue_words(void)
{
    static const struct wcase sq[6] = {
        {0, {"DW0=FAULT", "NSID=NOT_ATTEMPTED", "PRP1=NOT_ATTEMPTED", "CDW10=NOT_ATTEMPTED", "CDW11=NOT_ATTEMPTED"}, {"OPC=0X6"}},
        {24, {"DW0=0X30006", "OPC=0X6", "CID=0X3", "PRP1=FAULT", "NSID=NOT_ATTEMPTED", "CDW10=NOT_ATTEMPTED", "CDW11=NOT_ATTEMPTED"}, {0}},
        {28, {"DW0=0X30006", "PRP1=FAULT", "NSID=NOT_ATTEMPTED", "CDW10=NOT_ATTEMPTED", "CDW11=NOT_ATTEMPTED"}, {0}},
        {4, {"DW0=0X30006", "NSID=FAULT", "PRP1=0X80200000", "CDW10=NOT_ATTEMPTED", "CDW11=NOT_ATTEMPTED"}, {0}},
        {40, {"DW0=0X30006", "NSID=0X0", "PRP1=0X80200000", "CDW10=FAULT", "CDW11=NOT_ATTEMPTED"}, {0}},
        {44, {"DW0=0X30006", "NSID=0X0", "PRP1=0X80200000", "CDW10=0X1", "CDW11=FAULT"}, {0}},
    };
    static const struct wcase cq[3] = {
        {12, {"DW0=NOT_ATTEMPTED", "DW3=FAULT", "DW2=NOT_ATTEMPTED"}, {"CID=0X3"}},
        {8, {"DW0=NOT_ATTEMPTED", "DW3=0X10003", "CID=0X3", "P=1", "DW2=FAULT"}, {"SQHD=0X1"}},
        {0, {"DW0=FAULT", "DW3=0X10003", "CID=0X3", "SQHD=0X1", "SQID=0X0"}, {0}},
    };
    for (unsigned i = 0; i < 6; i++)
        if (word_case(ASQ_GOOD, P "SQ0 ", P "SQ1", P "ACQ ", &sq[i])) return 1;
    for (unsigned i = 0; i < 3; i++)
        if (word_case(ACQ_GOOD, P "CQ0 ", P "CQ1", 0, &cq[i])) return 1;
    return 0;
}

static int suite_queues(void)
{
    if (suite_queue_addresses() || suite_queue_types() || suite_queue_edges() || suite_queue_pages() || suite_queue_maps() || suite_queue_fields() ||
        suite_queue_words())
        return 1;
    /* A fault in a submission queue word stops that queue and the completion queue is not read; a fault in a completion queue word ends it. */
    for (unsigned k = 0; k < 18; k++) {
        struct world w;
        world_good(&w);
        bus_fault(unit_loads[FIRST_QUEUE + k]);
        CHECK_EQ(go(&w.a), 0);
        CHECK_DISCIPLINE();
        CHECK_TOKEN(P "VERDICT", "QUEUES=FAULT");
        CHECK_TOKEN(P "VERDICT", "WHY=NONE");
        CHECK_TOKEN(P "DONE", "FAULTS=1");
        if (k < 12) CHECK_EQ(loads_in(ACQ_GOOD, ACQ_GOOD + 0x1000), 0);
        world_free(&w);
    }
    return 0;
}
