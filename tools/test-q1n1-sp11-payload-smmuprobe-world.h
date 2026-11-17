/* SPDX-License-Identifier: MIT */
/* The modelled machine of the smmuprobe host test (tools/test-q1n1-sp11-payload-smmuprobe.c): what a build machine cannot run, built
 * around the real payload source compiled with Q1N1_PAYLOAD_HOST_TEST, on top of tools/test-q1n1-sp11-payload-mmu-world.h.
 *
 *   bus      the PCIe configuration pages of the two functions, the SMMUv3 register page below +0x90 and a few RAM words, scripted per
 *            test; an address nobody scripted, or scripted as a fault, answers the guarded load with a fault, as an abort does
 *   loads    every load that reached the op, logged with the model clock and the number of lines printed at that moment, and judged as
 *            it is made by rules written here from the brief, not from the payload: inside one of the three device windows or a RAM
 *            extent the test allows, never in a group after a read of that group did not return, and never at a page the translation
 *            model does not map or (for a device) does not map as Device (a stray load, a load after a failed read and a load at such a
 *            page are counted, and every world must end with all three at zero)
 *   worlds   the good world (a made-up but self-consistent unit: values chosen to tell fields apart, NOT read from any unit)
 *
 * Nothing here runs at EL2 or on hardware. Evidence: EXPERIMENTAL (host model only). */
#pragma once
#pragma clang diagnostic ignored "-Wunused-function"
#include "test-q1n1-sp11-payload-mmu-world.h"

#ifndef TEST_BUDGET
#define TEST_BUDGET 36                  /* the payload's PL_PAGE_LINES; a variant is built with a smaller page */
#endif
#ifndef TEST_LOAD_CAP
#define TEST_LOAD_CAP 400               /* the payload's LOAD_CAP */
#endif

#define P "PAYLOAD SMMUPROBE "
#define FREQ 19200000u
#define RP_PAGE UINT64_C(0x70000000)
#define EP_PAGE UINT64_C(0x70100000)
#define SMMU_PAGE UINT64_C(0x15400000)
#define SID 0x60100u

/* ---- The scripted machine ------------------------------------------------------------------------------------------------------- */

enum { ST_NONE, ST_VALUE, ST_FAULT };
enum { G_RP, G_EP, G_SMMU, G_RAM, G_COUNT };
#define SMMU_WORDS 36u                  /* the register page below +0x90 */

static uint32_t cfg_value[2][1024];
static uint8_t cfg_state[2][1024];
static uint32_t smmu_value[SMMU_WORDS];
static uint8_t smmu_state[SMMU_WORDS];
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
    if (addr >= SMMU_PAGE && addr < SMMU_PAGE + SMMU_WORDS * 4) {
        *value = &smmu_value[(addr - SMMU_PAGE) / 4];
        *state = &smmu_state[(addr - SMMU_PAGE) / 4];
        return G_SMMU;
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
    memset(smmu_state, 0, sizeof smmu_state);
    ram_count = 0;
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
    if (addr >= SMMU_PAGE && addr < SMMU_PAGE + 0x90) return G_SMMU;
    for (unsigned i = 0; i < ram_ok_n; i++)
        if (addr >= ram_ok[i].lo && addr < ram_ok[i].hi) return G_RAM;
    return -1;
}

/* The rule for a load, written here from the brief: the page it lands in must be mapped by the translation model, and a page of a device
 * must be a Device mapping (a MAIR byte whose high nibble is 0 and whose bits 1:0 are 0: nGnRnE, nGnRE, nGRE, GRE). RAM may be any mapping. */
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
    op_calls++;
    if (!out) return Q1N1_PAYLOAD_LOAD_E_PARAM;
    if ((addr & 3) || ((uintptr_t)out & 3)) return Q1N1_PAYLOAD_LOAD_E_ALIGN;
    if (addr > (UINT64_C(1) << 48) - 4) return Q1N1_PAYLOAD_LOAD_E_RANGE;
    if (op_calls > Q1N1_PAYLOAD_LOADS_MAX) return Q1N1_PAYLOAD_LOAD_E_BUDGET;
    group = classify(addr);
    if (group < 0) {
        if (!stray++) first_stray = addr;
    } else if (group_dead[group] || (group == G_RAM && group_dead[G_SMMU])) {
        after_fault++;
    }
    if (group >= 0 && !page_allows_load(addr, group)) unsafe_loads++;
    if (cell_find(addr, 0, &value, &state) < 0 || *state != ST_VALUE) rc = Q1N1_PAYLOAD_LOAD_E_FAULT;
    else *out = *value;
    if (rc && group >= 0) group_dead[group] = 1;
    if (load_n < LOADS_KEEP) loads[load_n] = (struct load_rec){addr, clock_now, line_count, rc};
    load_n++;
    return rc;
}
/* Loads in [lo, hi), and the index of the first load at or after the line count `lines` (-1: none). */
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
/* A map in the shape of a real one, made up: 512 MiB of conventional memory that holds the tables of the good world, and one extent
 * of each of a few types the payload must not read. */
static const struct d std_map[] = {
    {7, 0x80000000, 0x20000}, {0, 0xa0000000, 0x400}, {2, 0xa1000000, 0x100}, {11, 0xb0000000, 0x400}, {9, 0xc0000000, 0x10},
};
#define STD_COUNT (sizeof std_map / sizeof std_map[0])

struct world {
    struct q1n1_payload_args a;
    struct world_map m;
};
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
    memset(group_dead, 0, sizeof group_dead);
    stray = after_fault = unsafe_loads = 0;
    first_stray = 0;
    ram_ok_n = 0;
    load_n = op_calls = 0;
    tr_map(RP_PAGE, RP_PAGE + 0x1000, ATTR_DEVICE, SH_NONE);
    tr_map(EP_PAGE, EP_PAGE + 0x1000, ATTR_DEVICE, SH_NONE);
    tr_map(SMMU_PAGE, SMMU_PAGE + 0x10000, ATTR_DEVICE, SH_NONE);
    tr_map(0x80000000, 0xa0000000, ATTR_WB, SH_INNER);
    w->a = args_new();
    w->a.ops.load32 = bus_load32;
    w->m = build_map(list, count, 48);
    args_map(&w->a, &w->m);
}

/* The root port, 00:00.0: a bridge, capabilities at 0x40 (power management), 0x50 (MSI) and 0x70 (PCI Express, version 2, root port),
 * extended capabilities at 0x100 (a vendor one) and 0x140 (AER). */
static void put_rp(void)
{
    uint64_t p = RP_PAGE;
    bus_set(p + 0x00, 0x011117cb);
    bus_set(p + 0x04, 0x00100007);
    bus_set(p + 0x08, 0x06040001);
    bus_set(p + 0x0c, 0x00010010);
    bus_set(p + 0x18, 0x00010100);
    bus_set(p + 0x34, 0x00000040);
    bus_set(p + 0x40, 0x00035001);
    bus_set(p + 0x50, 0x00807005);
    bus_set(p + 0x70, 0x00420010);
    bus_set(p + 0x78, 0x00002810);
    bus_set(p + 0x7c, 0x00100c44);
    bus_set(p + 0x80, 0x20440040);
    bus_set(p + 0x9c, 0x0000001e);
    bus_set(p + 0xa0, 0x00000004);
    bus_set(p + 0x100, 0x1401000b);
    bus_set(p + 0x140, 0x00020001);
    bus_set(p + 0x144, 0x00004000);
    bus_set(p + 0x148, 0x00400000);
    bus_set(p + 0x150, 0x00002000);
    bus_set(p + 0x154, 0x00000000);
    bus_set(p + 0x170, 0x00000000);
}
/* The endpoint, 01:00.0: an NVMe class device, capabilities at 0x40, 0x50, 0x70 (MSI-X) and 0x80 (PCI Express, version 2, endpoint),
 * AER first in the extended list at 0x100. */
static void put_ep(void)
{
    uint64_t p = EP_PAGE;
    bus_set(p + 0x00, 0xa80b144d);
    bus_set(p + 0x04, 0x00100406);
    bus_set(p + 0x08, 0x01080200);
    bus_set(p + 0x0c, 0x00000010);
    bus_set(p + 0x10, 0x60800004);
    bus_set(p + 0x14, 0x00000000);
    bus_set(p + 0x34, 0x00000040);
    bus_set(p + 0x40, 0x00035001);
    bus_set(p + 0x50, 0x00807005);
    bus_set(p + 0x70, 0x00108011);
    bus_set(p + 0x80, 0x00020010);
    bus_set(p + 0x88, 0x00002810);
    bus_set(p + 0x8c, 0x00000c44);
    bus_set(p + 0x90, 0x00440040);
    bus_set(p + 0xac, 0x0000001e);
    bus_set(p + 0xb0, 0x00000004);
    bus_set(p + 0x100, 0x00020001);
    bus_set(p + 0x104, 0x00000000);
    bus_set(p + 0x108, 0x00400000);
    bus_set(p + 0x110, 0x00000000);
    bus_set(p + 0x114, 0x0000e000);
}

struct smmu_cfg {
    uint32_t cr0, gbpa, gerror;
    uint64_t base;
    uint32_t cfg;
};
static const uint8_t smmu_offsets[14] = {0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x44, 0x60, 0x80, 0x88};
static const char *const smmu_names[14] = {"IDR0", "IDR1", "IDR2", "IDR3", "IDR4", "IDR5", "IIDR", "AIDR", "CR0", "CR0ACK", "GBPA",
                                          "GERROR", "STRTAB_BASE", "STRTAB_CFG"};
static void put_smmu(const struct smmu_cfg *s)
{
    for (unsigned i = 0; i < 8; i++) bus_set(SMMU_PAGE + smmu_offsets[i], 0x5a000000u + smmu_offsets[i]);
    bus_set(SMMU_PAGE + 0x20, s->cr0);
    bus_set(SMMU_PAGE + 0x24, s->cr0);
    bus_set(SMMU_PAGE + 0x44, s->gbpa);
    bus_set(SMMU_PAGE + 0x60, s->gerror);
    bus_set64(SMMU_PAGE + 0x80, s->base);
    bus_set(SMMU_PAGE + 0x88, s->cfg);
}
static void put_dwords(uint64_t at, const uint64_t dw[4])
{
    for (unsigned i = 0; i < 4; i++) bus_set64(at + 8 * i, dw[i]);
}

/* The good world's stream table: two levels, SPLIT 10, LOG2SIZE 20, base 0x8a000000. StreamID 0x60100 is in level-1 slot 0x180 (at
 * 0x8a000c00), whose descriptor (Span 11, level-2 table at 0x8a400000) holds entry 0x100, at 0x8a404000: stage 2 translation. */
#define TB UINT64_C(0x8a000000)
#define L1_AT UINT64_C(0x8a000c00)
#define STE_AT UINT64_C(0x8a404000)
static const struct smmu_cfg good_smmu = {0xd, 0x1000, 0, UINT64_C(0x400000008a000000), 0x10294};
static const uint64_t good_dw[4] = {0xd, 0, UINT64_C(0x000d409000000007), 0x8c000000};
static void world_good(struct world *w)
{
    world_new(w, std_map, STD_COUNT);
    put_rp();
    put_ep();
    put_smmu(&good_smmu);
    bus_set64(L1_AT, UINT64_C(0x8a40000b));
    put_dwords(STE_AT, good_dw);
    allow_ram(L1_AT, L1_AT + 8);
    allow_ram(STE_AT, STE_AT + 32);
}

static uint64_t go(struct q1n1_payload_args *a)
{
    page_clear();
    read_count = 0;
    load_n = op_calls = 0;
    at_count = 0;
    return payload_entry(a);
}
/* The payload followed the discipline in this world: nothing was loaded outside the windows, nothing after a failed read, nothing at a
 * page the MMU model does not map (or, for a device, does not map as Device), every line was in the page font and within 100
 * characters, and the page stayed within its budget. */
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
#define CHECK_LINE(text) do { \
        if (!has_line(text)) { fprintf(stderr, "FAIL %s:%d: no line '%s'\n", __FILE__, __LINE__, text); return 1; } \
        checks++; \
    } while (0)
#define CHECK_NO_LINE(prefix) do { \
        if (find_line(prefix) >= 0) { fprintf(stderr, "FAIL %s:%d: a line '%s'\n", __FILE__, __LINE__, prefix); return 1; } \
        checks++; \
    } while (0)
