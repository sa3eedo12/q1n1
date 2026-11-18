/* SPDX-License-Identifier: MIT */
/* The modelled machine of the nvmesnap host test (tools/test-q1n1-sp11-payload-nvmesnap.c): what a build machine cannot run, built around the real
 * payload source compiled with Q1N1_PAYLOAD_HOST_TEST, on top of tools/test-q1n1-sp11-payload-mmu-world.h.
 *
 *   bus      the PCIe configuration pages of the two functions, the controller registers at the endpoint's BAR0, and a few RAM words, scripted per
 *            test; an address nobody scripted, or scripted as a fault, answers the guarded load with a fault, as an abort does
 *   loads    every load that reached the op, logged with the model clock and the number of lines printed at that moment, and judged as it is made
 *            by rules written here from the brief, not from the payload: inside the two configuration pages, the 0x38 bytes of registers of the BAR
 *            the test says may be read (none in a world whose gate must stay shut), or a RAM extent the test allows; never in a group after a read of
 *            that group did not return; never at a page the translation model does not map or (for a device) does not map as Device (a stray load,
 *            a load after a failed read and a load at such a page are counted, and every world must end with all three at zero)
 *   worlds   the good world: a made-up but self-consistent unit, with values chosen to tell fields apart, NOT read from any unit
 *
 * Nothing here runs at EL2 or on hardware. Evidence: EXPERIMENTAL (host model only). */
#pragma once
#pragma clang diagnostic ignored "-Wunused-function"
#include "test-q1n1-sp11-payload-mmu-world.h"

#ifndef TEST_BUDGET
#define TEST_BUDGET 34                  /* the payload's PL_PAGE_LINES; a variant is built with a smaller page */
#endif
#ifndef TEST_LOAD_CAP
#define TEST_LOAD_CAP 400               /* the payload's LOAD_CAP */
#endif

#define P "PAYLOAD NVMESNAP "
#define FREQ 19200000u
#define RP_PAGE UINT64_C(0x70000000)
#define EP_PAGE UINT64_C(0x70100000)
#define BAR_GOOD UINT64_C(0x70300000)
#define NV_WORDS 14u                    /* the registers below +0x38 */
#define NV_BYTES (4u * NV_WORDS)
#define ASQ_GOOD UINT64_C(0x80100000)
#define ACQ_GOOD UINT64_C(0x80101000)

/* ---- The scripted machine ------------------------------------------------------------------------------------------------------- */

enum { ST_NONE, ST_VALUE, ST_FAULT };
enum { G_RP, G_EP, G_NV, G_RAM, G_COUNT };

static uint32_t cfg_value[2][1024];
static uint8_t cfg_state[2][1024];
static uint32_t nv_value[NV_WORDS];
static uint8_t nv_state[NV_WORDS];
static uint64_t nv_base;                /* where the model's controller registers are; 0: nowhere */
static uint64_t nv_allowed;             /* where the judge lets the payload read them; 0: nowhere */
/* The n-th load (0 based) of one address answers a value or a fault instead of the scripted word: a register that reads differently the second
 * time (the payload reads CSTS twice). */
static struct {
    int on;
    uint64_t addr;
    unsigned nth;
    uint32_t value;
    uint8_t state;
} nth_override;
struct ram_cell {
    uint64_t addr;
    uint32_t value;
    uint8_t state;
};
static struct ram_cell ram_cells[256];
static unsigned ram_count;

/* The value and state slots of the scripted word at `addr`, and the group it belongs to; -1 when no group holds it. */
static int cell_find(uint64_t addr, int create, uint32_t **value, uint8_t **state)
{
    if (addr >= RP_PAGE && addr < RP_PAGE + 4096) {
        *value = &cfg_value[0][(addr - RP_PAGE) / 4];
        *state = &cfg_state[0][(addr - RP_PAGE) / 4];
        return G_RP;
    }
    if (addr >= EP_PAGE && addr < EP_PAGE + 4096) {
        *value = &cfg_value[1][(addr - EP_PAGE) / 4];
        *state = &cfg_state[1][(addr - EP_PAGE) / 4];
        return G_EP;
    }
    if (nv_base && addr >= nv_base && addr < nv_base + NV_BYTES) {
        *value = &nv_value[(addr - nv_base) / 4];
        *state = &nv_state[(addr - nv_base) / 4];
        return G_NV;
    }
    for (unsigned i = 0; i < ram_count; i++)
        if (ram_cells[i].addr == addr) {
            *value = &ram_cells[i].value;
            *state = &ram_cells[i].state;
            return G_RAM;
        }
    if (create && ram_count < 256) {
        ram_cells[ram_count] = (struct ram_cell){addr, 0, ST_NONE};
        *value = &ram_cells[ram_count].value;
        *state = &ram_cells[ram_count].state;
        ram_count++;
        return G_RAM;
    }
    return -1;
}
static void bus_set(uint64_t addr, uint32_t v)
{
    uint32_t *value;
    uint8_t *state;
    if (cell_find(addr, 1, &value, &state) < 0) {
        fprintf(stderr, "test bug: no room for %#llx\n", (unsigned long long)addr);
        exit(3);
    }
    *value = v;
    *state = ST_VALUE;
}
static void bus_set64(uint64_t addr, uint64_t v)
{
    bus_set(addr, (uint32_t)v);
    bus_set(addr + 4, (uint32_t)(v >> 32));
}
static void bus_fault(uint64_t addr)
{
    uint32_t *value;
    uint8_t *state;
    if (cell_find(addr, 1, &value, &state) < 0) exit(3);
    *state = ST_FAULT;
}
static void bus_clear(void)
{
    memset(cfg_state, 0, sizeof cfg_state);
    memset(nv_state, 0, sizeof nv_state);
    ram_count = 0;
    nv_base = nv_allowed = 0;
    nth_override.on = 0;
}
static void bus_nth(uint64_t addr, unsigned nth, uint32_t v)
{
    nth_override.on = 1;
    nth_override.addr = addr;
    nth_override.nth = nth;
    nth_override.value = v;
    nth_override.state = ST_VALUE;
}
static void bus_nth_fault(uint64_t addr, unsigned nth)
{
    bus_nth(addr, nth, 0);
    nth_override.state = ST_FAULT;
}
/* 1 and the value when `addr` holds a scripted value: what the oracle reads; the payload's loads go through bus_load32. */
static int peek(uint64_t addr, uint32_t *v)
{
    uint32_t *value;
    uint8_t *state;
    if (cell_find(addr, 0, &value, &state) < 0 || *state != ST_VALUE) return 0;
    *v = *value;
    return 1;
}
/* The same for the n-th load of the address. */
static int peek_nth(uint64_t addr, unsigned nth, uint32_t *v)
{
    if (nth_override.on && nth_override.addr == addr && nth_override.nth == nth) {
        *v = nth_override.value;
        return nth_override.state == ST_VALUE;
    }
    return peek(addr, v);
}
static int peek64(uint64_t addr, uint64_t *v)
{
    uint32_t lo, hi;
    if (!peek(addr, &lo) || !peek(addr + 4, &hi)) return 0;
    *v = lo | (uint64_t)hi << 32;
    return 1;
}

struct load_rec {
    uint64_t addr, clock;
    unsigned lines;
    int32_t rc;
};
#define LOADS_KEEP 1024u
static struct load_rec loads[LOADS_KEEP];
static unsigned load_n, op_calls;
static unsigned stray, after_fault, unsafe_loads;
static uint64_t first_stray;
static int group_dead[G_COUNT];
static struct {
    uint64_t lo, hi;
} ram_ok[4];                            /* the RAM the memory map approves in this world: the only RAM that may be read */
static unsigned ram_ok_n;
static void allow_ram(uint64_t lo, uint64_t hi)
{
    ram_ok[ram_ok_n].lo = lo;
    ram_ok[ram_ok_n++].hi = hi;
}

static int classify(uint64_t addr)
{
    if (addr >= RP_PAGE && addr < RP_PAGE + 0x1000) return G_RP;
    if (addr >= EP_PAGE && addr < EP_PAGE + 0x1000) return G_EP;
    if (nv_allowed && addr >= nv_allowed && addr < nv_allowed + NV_BYTES) return G_NV;
    for (unsigned i = 0; i < ram_ok_n; i++)
        if (addr >= ram_ok[i].lo && addr < ram_ok[i].hi) return G_RAM;
    return -1;
}

/* The rule for a load, written here from the brief: the page it lands in must be mapped by the translation model, and a page of a device must
 * be a Device mapping (a MAIR byte whose high nibble is 0 and whose bits 1:0 are 0: nGnRnE, nGnRE, nGRE, GRE). RAM may be any mapping. */
static int page_allows_load(uint64_t addr, int group)
{
    const struct tr_range *r = tr_find(addr);
    if (!r || !r->mapped) return 0;
    return group == G_RAM || ((r->attr & 0xf0) == 0 && (r->attr & 3) == 0);
}

static int32_t bus_load32(uint64_t addr, uint32_t *out)
{
    uint32_t *value;
    uint8_t *state;
    int group, rc = Q1N1_PAYLOAD_LOAD_OK;
    unsigned seen = 0;
    op_calls++;
    if (!out) return Q1N1_PAYLOAD_LOAD_E_PARAM;
    if ((addr & 3) || ((uintptr_t)out & 3)) return Q1N1_PAYLOAD_LOAD_E_ALIGN;
    if (addr > (UINT64_C(1) << 48) - 4) return Q1N1_PAYLOAD_LOAD_E_RANGE;
    if (op_calls > Q1N1_PAYLOAD_LOADS_MAX) return Q1N1_PAYLOAD_LOAD_E_BUDGET;
    group = classify(addr);
    if (group < 0) {
        if (!stray++) first_stray = addr;
    } else if (group_dead[group]) {
        after_fault++;
    }
    if (group >= 0 && !page_allows_load(addr, group)) unsafe_loads++;
    for (unsigned i = 0; i < load_n && i < LOADS_KEEP; i++) seen += loads[i].addr == addr;
    if (nth_override.on && nth_override.addr == addr && nth_override.nth == seen) {
        if (nth_override.state != ST_VALUE) rc = Q1N1_PAYLOAD_LOAD_E_FAULT;
        else *out = nth_override.value;
    } else if (cell_find(addr, 0, &value, &state) < 0 || *state != ST_VALUE) {
        rc = Q1N1_PAYLOAD_LOAD_E_FAULT;
    } else {
        *out = *value;
    }
    if (rc && group >= 0) group_dead[group] = 1;
    if (load_n < LOADS_KEEP) loads[load_n] = (struct load_rec){addr, clock_now, line_count, rc};
    load_n++;
    return rc;
}
/* Loads in [lo, hi), and the index of the first load made after `lines` lines were printed (-1: none). */
static unsigned loads_in(uint64_t lo, uint64_t hi)
{
    unsigned n = 0;
    for (unsigned i = 0; i < load_n && i < LOADS_KEEP; i++) n += loads[i].addr >= lo && loads[i].addr < hi;
    return n;
}
static int first_load_after(unsigned lines)
{
    for (unsigned i = 0; i < load_n && i < LOADS_KEEP; i++)
        if (loads[i].lines > lines) return (int)i;
    return -1;
}

/* Some line that starts with `prefix` holds the space-delimited token `tok` (exact), or one that starts with it (not exact). */
static int has_token(const char *prefix, const char *tok, int exact)
{
    size_t n = strlen(tok);
    for (unsigned i = 0; i < line_count; i++) {
        const char *p = lines[i];
        if (strncmp(p, prefix, strlen(prefix))) continue;
        for (p += strlen(prefix) - 1; (p = strchr(p, ' ')) != 0; p += 1)
            if (!strncmp(p + 1, tok, n) && (!exact || p[1 + n] == ' ' || p[1 + n] == 0)) return 1;
    }
    return 0;
}

/* ---- Worlds ---------------------------------------------------------------------------------------------------------------------- */

struct d {
    uint32_t type;
    uint64_t start, pages;
};
static struct world_map build_map(const struct d *list, unsigned count, uint64_t stride)
{
    struct world_map m = map_new(stride, count);
    for (unsigned i = 0; i < count; i++) map_put(&m, i, list[i].type, list[i].start, list[i].pages, 0xf);
    return m;
}
/* A map in the shape of a real one, made up: 512 MiB of conventional memory that holds the queues of the good world, and one extent of each of
 * a few types the payload must not read. The controller's BAR is in no descriptor, as on the unit. */
static const struct d std_map[] = {
    {7, 0x80000000, 0x20000}, {0, 0xa0000000, 0x400}, {2, 0xa1000000, 0x100}, {11, 0xb0000000, 0x400}, {9, 0xc0000000, 0x10},
};
#define STD_COUNT (sizeof std_map / sizeof std_map[0])

struct world {
    struct q1n1_payload_args a;
    struct world_map m;
};
/* The counter of every world: the clock of the shared model, with an end to a wait that never ends. A wait that gives up on a counter that stands
 * still reads it two million times, and a page with three of them (a dead counter from the start, or a payload that does not stop at the first)
 * about six million; a payload that reads it many more times would hang the test, so it fails here. A test of a slow counter raises the limit. */
static uint64_t counter_limit = 7000000;
static uint64_t counter_with_limit(void)
{
    if (clock_calls > counter_limit) {
        fprintf(stderr, "FAIL %s:%d: the counter was read %llu times: an unbounded wait\n", __FILE__, __LINE__, (unsigned long long)clock_calls);
        exit(1);
    }
    return fake_counter();
}
/* A counter that runs until the page announces the controller registers and then stands still: the second wait cannot be made. (The page is only
 * searched while the clock runs: a stuck counter is read two million times.) */
static uint64_t counter_stops_at_registers(void)
{
    if (clock_mode == 0 && find_line(P "NEXT NVME_REGS") >= 0) clock_mode = 1;
    return counter_with_limit();
}
/* The same for the third wait, before CSTS is read again and the three registers Linux never reads. */
static uint64_t counter_stops_at_aq(void)
{
    if (clock_mode == 0 && find_line(P "NEXT NVME_AQ") >= 0) clock_mode = 1;
    return counter_with_limit();
}
static void world_free(struct world *w)
{
    guarded_free(&w->m.mem);
}
static void set_el(uint64_t el)
{
    reg_reset();
    reg_set("CurrentEL", el << 2);
    reg_set("CNTFRQ_EL0", FREQ);
}
static void world_new(struct world *w, const struct d *list, unsigned count)
{
    world_reset();
    set_el(2);
    bus_clear();
    counter_limit = 7000000;
    memset(group_dead, 0, sizeof group_dead);
    stray = after_fault = unsafe_loads = 0;
    first_stray = 0;
    ram_ok_n = 0;
    load_n = op_calls = 0;
    tr_map(RP_PAGE, RP_PAGE + 0x1000, ATTR_DEVICE, SH_NONE);
    tr_map(EP_PAGE, EP_PAGE + 0x1000, ATTR_DEVICE, SH_NONE);
    tr_map(BAR_GOOD, BAR_GOOD + 0x4000, ATTR_DEVICE, SH_NONE);
    tr_map(0x80000000, 0xa0000000, ATTR_WB, SH_INNER);
    w->a = args_new();
    w->a.ops.load32 = bus_load32;
    w->a.ops.counter = counter_with_limit;
    w->m = build_map(list, count, 48);
    args_map(&w->a, &w->m);
}

/* The root port, 00:00.0: a bridge (class 0x0604, header type 1), buses 0, 1, 1, a memory window of 0x70300000 to 0x73ffffff, capabilities at
 * 0x40 (power management), 0x50 (MSI) and 0x70 (PCI Express, version 2, root port, reports the data link layer, which is active). */
static void put_rp(void)
{
    uint64_t p = RP_PAGE;
    bus_set(p + 0x00, 0x02221111);
    bus_set(p + 0x04, 0x00100007);
    bus_set(p + 0x08, 0x06040001);
    bus_set(p + 0x0c, 0x00010010);
    bus_set(p + 0x18, 0x00010100);
    bus_set(p + 0x20, 0x73f07030);
    bus_set(p + 0x34, 0x00000040);
    bus_set(p + 0x40, 0x00035001);
    bus_set(p + 0x50, 0x00807005);
    bus_set(p + 0x70, 0x00420010);
    bus_set(p + 0x7c, 0x00100c44);
    bus_set(p + 0x80, 0x20440043);
}
/* The endpoint, 01:00.0: an NVM Express function (class 0x010802, header type 0), memory space and bus master on, BAR0 a 64-bit memory BAR at
 * 0x70300000, capabilities at 0x40 (power management, D0), 0x50 (MSI), 0x70 (MSI-X) and 0x80 (PCI Express, version 2, endpoint). */
static void put_ep(void)
{
    uint64_t p = EP_PAGE;
    bus_set(p + 0x00, 0xfeed1d1d);
    bus_set(p + 0x04, 0x00100406);
    bus_set(p + 0x08, 0x01080201);
    bus_set(p + 0x0c, 0x00000010);
    bus_set(p + 0x10, 0x70300004);
    bus_set(p + 0x14, 0x00000000);
    bus_set(p + 0x34, 0x00000040);
    bus_set(p + 0x40, 0x00035001);
    bus_set(p + 0x44, 0x00000008);
    bus_set(p + 0x50, 0x00807005);
    bus_set(p + 0x70, 0x00808011);
    bus_set(p + 0x80, 0x00020010);
    bus_set(p + 0x8c, 0x00000c44);
    bus_set(p + 0x90, 0x00440041);
}

struct nv_cfg {
    uint64_t cap, asq, acq;
    uint32_t vs, cc, csts, aqa;
};
/* Values chosen to tell fields apart: MQES 511, CQR 1, AMS 1, TO 60, DSTRD 2, NSSRS 1, CSS 1, MPSMIN 1, MPSMAX 3, no CMB, no PMR, no boot
 * partitions; version 2.1.0; enabled and ready with I/O entry sizes 6 and 4 and a page size of 8 KiB; admin queues of four entries. */
static const struct nv_cfg good_nv = {UINT64_C(0x003100323c0301ff), ASQ_GOOD, ACQ_GOOD, 0x00020100, 0x00460081, 0x00000001, 0x00030003};
static void put_nvme(uint64_t bar, const struct nv_cfg *n)
{
    nv_base = nv_allowed = bar;
    for (unsigned i = 0; i < NV_WORDS; i++) {
        nv_value[i] = 0;
        nv_state[i] = ST_NONE;
    }
    bus_set64(bar + 0x00, n->cap);
    bus_set(bar + 0x08, n->vs);
    bus_set(bar + 0x14, n->cc);
    bus_set(bar + 0x1c, n->csts);
    bus_set(bar + 0x24, n->aqa);
    bus_set64(bar + 0x28, n->asq);
    bus_set64(bar + 0x30, n->acq);
}
/* The first two slots of each admin queue of the good world: Identify (CNS 1) with CID 3 and Create I/O Completion Queue (qid 1, 64 entries)
 * with CID 4, and their completions: success, phase 1, submission queue head 1 and 2. */
static void put_sq(uint64_t asq)
{
    bus_set(asq + 4 * 0, 0x00030006);
    bus_set(asq + 4 * 1, 0x00000000);
    bus_set64(asq + 4 * 6, UINT64_C(0x80200000));
    bus_set(asq + 4 * 10, 0x00000001);
    bus_set(asq + 4 * 11, 0x00000000);
    bus_set(asq + 64 + 4 * 0, 0x00040005);
    bus_set(asq + 64 + 4 * 1, 0x00000000);
    bus_set64(asq + 64 + 4 * 6, UINT64_C(0x80300000));
    bus_set(asq + 64 + 4 * 10, 0x003f0001);
    bus_set(asq + 64 + 4 * 11, 0x00000001);
}
static void put_cq(uint64_t acq)
{
    bus_set(acq + 0, 0x00000000);
    bus_set(acq + 8, 0x00000001);
    bus_set(acq + 12, 0x00010003);
    bus_set(acq + 16 + 0, 0x00000000);
    bus_set(acq + 16 + 8, 0x00000002);
    bus_set(acq + 16 + 12, 0x00010004);
}
static void put_queues(uint64_t asq, uint64_t acq)
{
    put_sq(asq);
    put_cq(acq);
}
static void world_good(struct world *w)
{
    world_new(w, std_map, STD_COUNT);
    put_rp();
    put_ep();
    put_nvme(BAR_GOOD, &good_nv);
    put_queues(ASQ_GOOD, ACQ_GOOD);
    allow_ram(ASQ_GOOD, ASQ_GOOD + 128);
    allow_ram(ACQ_GOOD, ACQ_GOOD + 32);
}

static uint64_t go(struct q1n1_payload_args *a)
{
    page_clear();
    read_count = 0;
    load_n = op_calls = 0;
    at_count = 0;
    return payload_entry(a);
}
/* The payload followed the discipline in this world: nothing was loaded outside the windows, nothing after a failed read, nothing at a page the
 * MMU model does not map (or, for a device, does not map as Device), every line was in the page font and within 100 characters, and the page
 * stayed within its budget. */
#define CHECK_DISCIPLINE() do { \
        if (stray) fprintf(stderr, "stray load at %#llx\n", (unsigned long long)first_stray); \
        CHECK_EQ(stray, 0); \
        CHECK_EQ(after_fault, 0); \
        CHECK_EQ(unsafe_loads, 0); \
        CHECK(font_violations == 0 && long_lines == 0); \
        CHECK(line_count <= TEST_BUDGET); \
    } while (0)
#define CHECK_TOKEN(prefix, tok) do { \
        if (!has_token(prefix, tok, 1)) { fprintf(stderr, "FAIL %s:%d: no '%s' token on a '%s' line\n", __FILE__, __LINE__, tok, prefix); return 1; } \
        checks++; \
    } while (0)
#define CHECK_NO_TOKEN(prefix, tok) do { \
        if (has_token(prefix, tok, 0)) { fprintf(stderr, "FAIL %s:%d: a '%s' token on a '%s' line\n", __FILE__, __LINE__, tok, prefix); return 1; } \
        checks++; \
    } while (0)
/* On a missing line, show the lines that start with the same three words (the group and kind), so that a difference is seen at once. */
static void show_near(const char *text)
{
    size_t n = 0;
    for (int words = 0; text[n] && words < 3; n++) words += text[n] == ' ';
    for (unsigned i = 0; i < line_count; i++)
        if (!strncmp(lines[i], text, n)) fprintf(stderr, "  got '%s'\n", lines[i]);
}
#define CHECK_LINE(text) do { \
        if (!has_line(text)) { fprintf(stderr, "FAIL %s:%d: no line '%s'\n", __FILE__, __LINE__, text); show_near(text); return 1; } \
        checks++; \
    } while (0)
#define CHECK_NO_LINE(prefix) do { \
        if (find_line(prefix) >= 0) { fprintf(stderr, "FAIL %s:%d: a line '%s'\n", __FILE__, __LINE__, prefix); return 1; } \
        checks++; \
    } while (0)
