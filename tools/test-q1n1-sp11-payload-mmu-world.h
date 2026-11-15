/* SPDX-License-Identifier: MIT */
/* The modelled machine of the el2mem and hashbig host tests (tools/test-q1n1-sp11-payload-el2mem.c, -hashbig.c): what a build machine
 * cannot run, built around the real payload sources compiled with Q1N1_PAYLOAD_HOST_TEST.
 *
 *   translation   AT S1E2R as a list of ranges, the later one overriding the earlier (so that a hole is a fault range added over a
 *                 mapping): attribute byte, shareability, NS, an output address offset, or a fault code; every address asked about is logged
 *   registers     a scripted system register file that logs every read, with the model clock and the number of lines printed at that moment
 *   clock         ops.counter: a model clock that advances by a step per call, or stands still, or goes back
 *   load32        a guarded load that insists the translation model says mapped (the payload must have asked AT first) and can abort
 *   map, memory   buffers placed against a PROT_NONE page on both sides, so that one byte read outside the intended bytes is a SEGV
 *   page          every line the payload printed, checked against the page font and the 100-character cap as it arrives
 *
 * Nothing here runs at EL2 or on hardware: every address is a number in the model, and the registers have the values a test scripts, not
 * values observed on the unit (except where a comment says so). Evidence: EXPERIMENTAL (host model only). */
#pragma once
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#include "sp11-payload.h"

uint64_t payload_entry(const struct q1n1_payload_args *a);

static unsigned checks;
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)
#define CHECK_EQ(a, b) do { \
        uint64_t va_ = (uint64_t)(a), vb_ = (uint64_t)(b); \
        if (va_ != vb_) { fprintf(stderr, "FAIL %s:%d: %s = %#llx, wanted %#llx\n", __FILE__, __LINE__, #a, (unsigned long long)va_, (unsigned long long)vb_); return 1; } \
        checks++; \
    } while (0)

#define MIB_ (UINT64_C(1) << 20)
#define PAGE_ UINT64_C(4096)
#define ATTR_WB 0xff
#define ATTR_WT 0xbb
#define ATTR_NC 0x44
#define ATTR_DEVICE 0x00
#define SH_NONE 0
#define SH_OUTER 2
#define SH_INNER 3

/* ---- Translation ------------------------------------------------------------------------------------------------------------- */

struct tr_range {
    uint64_t start, end, delta;
    int mapped;
    uint8_t attr, sh, ns, fst;
};
static struct tr_range tr_table[512];
static unsigned tr_count;
#define AT_LOG_MAX 40000u
static uint64_t at_log[AT_LOG_MAX];
static unsigned at_count;

static void tr_reset(void)
{
    tr_count = 0;
    at_count = 0;
}
static void tr_map(uint64_t start, uint64_t end, uint8_t attr, uint8_t sh)
{
    tr_table[tr_count++] = (struct tr_range){.start = start, .end = end, .mapped = 1, .attr = attr, .sh = sh};
}
static void tr_fault(uint64_t start, uint64_t end, uint8_t fst)
{
    tr_table[tr_count++] = (struct tr_range){.start = start, .end = end, .mapped = 0, .fst = fst};
}
static const struct tr_range *tr_find(uint64_t va)
{
    for (unsigned i = tr_count; i-- > 0;)
        if (va >= tr_table[i].start && va < tr_table[i].end) return &tr_table[i];
    return 0;
}
/* The PAR_EL1 an AT would leave: F, FST with RES1 bit 11 for a fault; ATTR, NS, SH, PA and RES1 bit 11 for a mapping. */
static uint64_t tr_par(uint64_t va)
{
    const struct tr_range *r = tr_find(va);
    if (!r || !r->mapped) return 1u | (uint64_t)(r ? r->fst : 0x04) << 1 | 1u << 11;
    return (uint64_t)r->attr << 56 | ((va + r->delta) & UINT64_C(0x000ffffffffff000)) | (uint64_t)r->ns << 9 | (uint64_t)r->sh << 7 | 1u << 11;
}
uint64_t pl_host_at_s1e2r(uint64_t va);
uint64_t pl_host_at_s1e2r(uint64_t va)
{
    if (at_count < AT_LOG_MAX) at_log[at_count] = va;
    at_count++;
    return tr_par(va);
}
static int tr_is_mapped(uint64_t va)
{
    const struct tr_range *r = tr_find(va);
    return r && r->mapped;
}

/* ---- Clock, registers, ops, page ---------------------------------------------------------------------------------------------- */

static uint64_t clock_now, clock_step, clock_calls;
static int clock_mode;                      /* 0 advancing, 1 standing still, 2 going back */
static void clock_set(uint64_t start, uint64_t step, int mode)
{
    clock_now = start;
    clock_step = step;
    clock_mode = mode;
    clock_calls = 0;
}
static uint64_t fake_counter(void)
{
    clock_calls++;
    if (clock_mode == 0) clock_now += clock_step;
    else if (clock_mode == 2) clock_now -= clock_step;
    return clock_now;
}

#define LINES_KEEP 160u
static char lines[LINES_KEEP][128];
static uint64_t line_clock[LINES_KEEP];
static unsigned line_count, line_total;
static int font_violations, long_lines;
static int in_page_font(const char *text)
{
    for (; *text; text++)
        if (!((*text >= 'A' && *text <= 'Z') || (*text >= '0' && *text <= '9') || strchr(" :-./=?()_", *text))) return 0;
    return 1;
}
static void fake_puts(const char *line)
{
    if (!in_page_font(line)) font_violations++;
    if (strlen(line) > 100) long_lines++;
    if (line_count < LINES_KEEP) {
        snprintf(lines[line_count], sizeof lines[0], "%s", line);
        line_clock[line_count] = clock_now;
        line_count++;
    }
    line_total++;
}
static uint32_t fake_hex(char *dst, uint32_t cap, uint64_t value)
{
    return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value);
}
static int has_line(const char *text)
{
    for (unsigned i = 0; i < line_count; i++)
        if (!strcmp(lines[i], text)) return 1;
    return 0;
}
/* The index of the first line that starts with `prefix`, or -1. */
static inline int find_line(const char *prefix)
{
    for (unsigned i = 0; i < line_count; i++)
        if (!strncmp(lines[i], prefix, strlen(prefix))) return (int)i;
    return -1;
}
static inline int count_prefix(const char *prefix)
{
    int n = 0;
    for (unsigned i = 0; i < line_count; i++) n += !strncmp(lines[i], prefix, strlen(prefix));
    return n;
}
static void page_clear(void)
{
    line_count = line_total = 0;
    font_violations = long_lines = 0;
}
/* The first line that starts with `prefix` must hold `needle`; on a failure the line is printed. */
#define CHECK_HAS(prefix, needle) do { \
        int at_ = find_line(prefix); \
        if (at_ < 0 || !strstr(lines[at_], needle)) { \
            fprintf(stderr, "FAIL %s:%d: the line '%s' does not hold '%s': %s\n", __FILE__, __LINE__, prefix, needle, at_ < 0 ? "(no such line)" : lines[at_]); \
            return 1; \
        } \
        checks++; \
    } while (0)
/* Some line that starts with `prefix` holds `needle` (a group may wrap onto several lines). */
#define CHECK_ANY(prefix, needle) do { \
        int found_ = 0; \
        for (unsigned i_ = 0; i_ < line_count; i_++) found_ |= !strncmp(lines[i_], prefix, strlen(prefix)) && strstr(lines[i_], needle) != 0; \
        if (!found_) { \
            fprintf(stderr, "FAIL %s:%d: no line '%s' holds '%s'\n", __FILE__, __LINE__, prefix, needle); \
            return 1; \
        } \
        checks++; \
    } while (0)

/* The scripted register file: name, value. `reg_set` changes one; every read is logged with the clock and the lines printed so far. */
struct reg_entry {
    const char *name;
    uint64_t value;
};
static struct reg_entry regs[32];
static unsigned reg_count;
static const char *read_log[64];
static uint64_t read_clock[64];
static unsigned read_lines[64], read_count;
static void reg_reset(void)
{
    reg_count = 0;
    read_count = 0;
}
static void reg_set(const char *name, uint64_t value)
{
    for (unsigned i = 0; i < reg_count; i++)
        if (!strcmp(regs[i].name, name)) {
            regs[i].value = value;
            return;
        }
    regs[reg_count++] = (struct reg_entry){name, value};
}
uint64_t pl_host_sysreg(const char *name);
uint64_t pl_host_sysreg(const char *name)
{
    if (read_count < 64) {
        read_log[read_count] = name;
        read_clock[read_count] = clock_now;
        read_lines[read_count] = line_count;
        read_count++;
    }
    for (unsigned i = 0; i < reg_count; i++)
        if (!strcmp(regs[i].name, name)) return regs[i].value;
    fprintf(stderr, "FAIL: the payload read a register the test does not know: %s\n", name);
    exit(3);
}
static inline int was_read(const char *name)
{
    for (unsigned i = 0; i < read_count; i++)
        if (!strcmp(read_log[i], name)) return 1;
    return 0;
}
static inline int read_index(const char *name)
{
    for (unsigned i = 0; i < read_count; i++)
        if (!strcmp(read_log[i], name)) return (int)i;
    return -1;
}

/* load32: refuses what the runner's refuses (alignment, 48 bits, a NULL destination, the 4096 budget), insists that an AT said mapped
 * (model_strict) and aborts at the one address a test names. */
static uint64_t load_log[64], load_abort_at = UINT64_MAX;
static unsigned load_count, load_budget_calls;
static int load_strict = 1, load_unmapped_calls;
static int32_t fake_load32(uint64_t addr, uint32_t *out)
{
    load_budget_calls++;
    if (!out) return Q1N1_PAYLOAD_LOAD_E_PARAM;
    if ((addr & 3) || ((uintptr_t)out & 3)) return Q1N1_PAYLOAD_LOAD_E_ALIGN;
    if (addr > (UINT64_C(1) << 48) - 4) return Q1N1_PAYLOAD_LOAD_E_RANGE;
    if (load_budget_calls > Q1N1_PAYLOAD_LOADS_MAX) return Q1N1_PAYLOAD_LOAD_E_BUDGET;
    if (load_count < 64) load_log[load_count] = addr;
    load_count++;
    if (!tr_is_mapped(addr)) load_unmapped_calls++;
    if (addr == load_abort_at) return Q1N1_PAYLOAD_LOAD_E_FAULT;
    *out = (uint32_t)(addr ^ addr >> 32 ^ 0xa5a50000u);
    return 0;
}

/* ---- Guarded memory ------------------------------------------------------------------------------------------------------------ */

struct guarded {
    uint8_t *all, *data;
    size_t bytes, total;
};
/* `bytes` of memory that end exactly at a PROT_NONE page (at_end) or begin right after one (else: then the start is aligned to the host's
 * page, which is a multiple of 4 KiB) and have another PROT_NONE page on the other side. The host's page size is used for the guards: it is
 * 16 KiB on the machines this was written on, not the 4 KiB of the model. */
static struct guarded guarded_alloc(size_t bytes, int at_end)
{
    struct guarded g;
    size_t host = (size_t)sysconf(_SC_PAGESIZE), pages = (bytes + host - 1) / host + (bytes == 0);
    g.total = (pages + 2) * host;
    g.all = mmap(0, g.total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (g.all == MAP_FAILED) {
        perror("mmap");
        exit(3);
    }
    mprotect(g.all, host, PROT_NONE);
    mprotect(g.all + (pages + 1) * host, host, PROT_NONE);
    g.data = at_end ? g.all + (pages + 1) * host - ((bytes + 7) & ~(size_t)7) : g.all + host;
    g.bytes = bytes;
    return g;
}
static void guarded_free(struct guarded *g)
{
    munmap(g->all, g->total);
}

/* ---- The UEFI memory map ------------------------------------------------------------------------------------------------------- */

struct world_map {
    struct guarded mem;
    uint64_t stride, count;
};
static struct world_map map_new(uint64_t stride, uint64_t count)
{
    struct world_map m = {guarded_alloc(stride * count, 1), stride, count};
    return m;
}
static void map_put(struct world_map *m, uint64_t i, uint32_t type, uint64_t start, uint64_t pages, uint64_t attribute)
{
    uint8_t *d = m->mem.data + i * m->stride;
    memcpy(d, &type, 4);
    memcpy(d + 8, &start, 8);
    memcpy(d + 16, &start, 8);
    memcpy(d + 24, &pages, 8);
    memcpy(d + 32, &attribute, 8);
}

static struct q1n1_payload_args args_new(void)
{
    struct q1n1_payload_args a;
    memset(&a, 0, sizeof a);
    a.magic = Q1N1_PAYLOAD_ABI_MAGIC;
    a.version = Q1N1_PAYLOAD_ABI_VERSION;
    a.size = sizeof a;
    a.ops.puts = fake_puts;
    a.ops.hex = fake_hex;
    a.ops.load32 = fake_load32;
    a.ops.counter = fake_counter;
    a.payload_base = UINT64_C(0xcc200000);
    a.payload_size = 12288;
    a.stack_base = UINT64_C(0xcc300000);
    a.stack_size = Q1N1_PAYLOAD_STACK_BYTES;
    return a;
}
static void args_map(struct q1n1_payload_args *a, const struct world_map *m)
{
    a->map_base = (uint64_t)(uintptr_t)m->mem.data;
    a->map_size = m->stride * m->count;
    a->map_stride = m->stride;
}

/* Everything back to the start of a world: translation, registers, clock, loads, page. */
static void world_reset(void)
{
    tr_reset();
    reg_reset();
    page_clear();
    clock_set(1000000, 1000000, 0);
    load_count = load_budget_calls = 0;
    load_abort_at = UINT64_MAX;
    load_unmapped_calls = 0;
    memset(load_log, 0, sizeof load_log);
}
