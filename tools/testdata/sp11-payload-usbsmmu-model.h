/* SPDX-License-Identifier: MIT */
/* The scripted platform of tools/test-q1n1-sp11-payload-usbsmmu.c: what the usbsmmu payload (payloads/usbsmmu.c) is run against
 * on a host. Nothing here is hardware; it is a model, EXPERIMENTAL, built from the values the S0 survey OBSERVED on the unit
 * (docs/SP11-PAYLOAD-USBSMMU.md lists them) and from the architecture where S0 had nothing.
 *
 * The model is a fake of the four ops of the payload ABI, and an oracle behind load32 that fails the test on anything the payload
 * must never do:
 *   - a load that is not 4-byte aligned, or that is beyond the 3000 loads the payload promises;
 *   - an MMIO load outside the three windows, at a register this payload has no business reading (PAR, RESUME, the TLB
 *     operations, ATS, another context bank, the stream match registers past NUMSMRG...), or in a window after an abort in it;
 *   - a RAM load at an address the UEFI memory map does not call usable RAM (types 1 to 7 and 9);
 *   - a load that comes before the NEXT line that names its group, or before the groups that precede it.
 * Every load is also logged in order with the lines the payload printed, so a test can look at what happened between. */
#pragma once
/* The helpers are shared by several test programs, each of which uses a subset. */
#pragma GCC diagnostic ignored "-Wunused-function"
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_PAYLOAD 1
#include "sp11-payload.h"

uint64_t payload_entry(const struct q1n1_payload_args *a);

#define U0_BASE UINT64_C(0x0a600000)
#define U1_BASE UINT64_C(0x0a800000)
#define XHC_SIZE UINT64_C(0xfc100)
#define SMMU_BASE UINT64_C(0x15000000)
#define SMMU_SIZE UINT64_C(0x100000)
#define LOAD_CAP 3000u
#define LINE_CAP 24u

/* ---- Failures --------------------------------------------------------------------------------------------------------- */

static unsigned checks, violations;
static char first_violation[240];
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)

static void violate(const char *fmt, ...)
{
    va_list ap;
    if (!violations++) {
        va_start(ap, fmt);
        vsnprintf(first_violation, sizeof first_violation, fmt, ap);
        va_end(ap);
    }
}

/* ---- The scripted registers -------------------------------------------------------------------------------------------- */

enum { MODE_SCRIPT, MODE_FILL, MODE_RANDOM };
#define MAX_REGS 3000u
static struct { uint64_t addr; uint32_t value; } regs[MAX_REGS];
static unsigned nregs;
static int mode;
static uint32_t fill_value;
static uint64_t rng_seed;

static uint64_t mix(uint64_t x)
{
    x += UINT64_C(0x9e3779b97f4a7c15);
    x = (x ^ x >> 30) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ x >> 27) * UINT64_C(0x94d049bb133111eb);
    return x ^ x >> 31;
}

static void rset(uint64_t addr, uint32_t value)
{
    for (unsigned i = 0; i < nregs; i++)
        if (regs[i].addr == addr) { regs[i].value = value; return; }
    if (nregs >= MAX_REGS) { fprintf(stderr, "FAIL: register table full\n"); exit(2); }
    regs[nregs].addr = addr;
    regs[nregs].value = value;
    nregs++;
}
static void rset64(uint64_t addr, uint64_t value) { rset(addr, (uint32_t)value); rset(addr + 4, (uint32_t)(value >> 32)); }

/* What the model answers at an MMIO address: the script, else the fill value or a value that depends only on the address. */
static uint32_t mmio_value(uint64_t addr)
{
    if (mode == MODE_FILL) return fill_value;
    if (mode == MODE_RANDOM) {
        uint64_t m = mix(addr ^ rng_seed);
        /* Mostly small numbers and flags, sometimes all ones or zero, the way broken hardware answers. */
        switch (m & 7) {
        case 0: return 0xffffffffu;
        case 1: return 0;
        case 2: return (uint32_t)(m >> 8) & 0xff;
        case 3: return (uint32_t)(m >> 8) & 0xffff;
        default: return (uint32_t)(m >> 16);
        }
    }
    for (unsigned i = 0; i < nregs; i++)
        if (regs[i].addr == addr) return regs[i].value;
    return 0;
}

/* ---- RAM and the memory map --------------------------------------------------------------------------------------------- */

#define MAX_REGIONS 16u
static struct { uint64_t base, size; uint8_t *mem; } ram[MAX_REGIONS];
static unsigned nram;

static void ram_add(uint64_t base, uint64_t size)
{
    if (nram >= MAX_REGIONS) { fprintf(stderr, "FAIL: RAM table full\n"); exit(2); }
    ram[nram].base = base;
    ram[nram].size = size;
    ram[nram].mem = calloc(1, size);
    nram++;
}
static uint8_t *ram_at(uint64_t addr, uint64_t n)
{
    for (unsigned i = 0; i < nram; i++)
        if (addr >= ram[i].base && addr - ram[i].base <= ram[i].size - n && n <= ram[i].size) return ram[i].mem + (addr - ram[i].base);
    return NULL;
}
static void ram_w32(uint64_t addr, uint32_t v)
{
    uint8_t *p = ram_at(addr, 4);
    if (!p) { fprintf(stderr, "FAIL: fixture writes outside its RAM: %" PRIX64 "\n", addr); exit(2); }
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void ram_w64(uint64_t addr, uint64_t v) { ram_w32(addr, (uint32_t)v); ram_w32(addr + 4, (uint32_t)(v >> 32)); }

#define MAP_STRIDE 48u
#define MAP_MAX 1100u
static uint8_t map_buf[MAP_STRIDE * MAP_MAX] __attribute__((aligned(16)));
static unsigned map_n;
static uint64_t map_size_override;
static void map_clear(void) { memset(map_buf, 0, sizeof map_buf); map_n = 0; map_size_override = 0; }
static void map_add(uint32_t type, uint64_t start, uint64_t pages)
{
    uint8_t *d = map_buf + (uint64_t)map_n * MAP_STRIDE;
    memcpy(d, &type, 4);
    memcpy(d + 8, &start, 8);
    memcpy(d + 24, &pages, 8);
    memset(d + 32, 0xff, 8);                        /* the attribute word: not the payload's business */
    map_n++;
}
/* The oracle's own reading of the map, independent of the payload's: 1 when `addr` lies in a descriptor of usable RAM and in
 * no descriptor of another kind. */
static int oracle_byte_usable(uint64_t addr)
{
    int in_ram = 0;
    for (unsigned i = 0; i < map_n; i++) {
        uint32_t type;
        uint64_t start, pages;
        memcpy(&type, map_buf + (uint64_t)i * MAP_STRIDE, 4);
        memcpy(&start, map_buf + (uint64_t)i * MAP_STRIDE + 8, 8);
        memcpy(&pages, map_buf + (uint64_t)i * MAP_STRIDE + 24, 8);
        if (pages >= (UINT64_C(1) << 40) || addr < start || addr - start >= pages * 4096u) continue;
        if ((type >= 1 && type <= 7) || type == 9) in_ram = 1;
        else return 0;
    }
    return in_ram;
}
/* A 4-byte load is usable when its first and its last byte are. */
static int oracle_usable(uint64_t addr) { return addr + 3 >= addr && oracle_byte_usable(addr) && oracle_byte_usable(addr + 3); }

/* ---- Lines and loads, in order ------------------------------------------------------------------------------------------ */

enum { EV_LINE, EV_LOAD, EV_SYSREG };
#define MAX_EVENTS 40000u
static struct { int kind; uint64_t addr; char text[104]; } events[MAX_EVENTS];
static unsigned nevents, nlines, nloads, nfaults, bad_lines, win_loads[4], sysreg_reads;     /* win_loads[3]: RAM */
static char first_bad_line[160];

/* NEXT lines seen so far, to tie each load to the line that announces it. */
static int seen_u0, seen_smmu, seen_rings, seen_cb, seen_walk;
static unsigned next_order[8], next_n;      /* the order the NEXT lines came in */
static int seen_bank[256];

static long fault_index;                    /* the load (1-based) that aborts; 0 none */
static uint64_t fault_lo, fault_hi;         /* loads in [lo, hi) abort */
static int window_aborted[3];
static unsigned expected_banks[2];
static unsigned expected_banks_n;           /* 0: any bank below NUMCB */
static unsigned fault_log;

static void log_event(int kind, uint64_t addr, const char *text)
{
    if (nevents >= MAX_EVENTS) { fprintf(stderr, "FAIL: the event log is full\n"); exit(2); }
    events[nevents].kind = kind;
    events[nevents].addr = addr;
    snprintf(events[nevents].text, sizeof events[0].text, "%s", text ? text : "");
    nevents++;
}

static int in_font(const char *text)
{
    for (; *text; text++)
        if (!((*text >= 'A' && *text <= 'Z') || (*text >= '0' && *text <= '9') || strchr(" :-./=?()_", *text))) return 0;
    return 1;
}

static void fake_puts(const char *line)
{
    static const char prefix[] = "PAYLOAD USBSMMU ";
    if (strlen(line) > Q1N1_PAYLOAD_LINE_MAX || !in_font(line) || strncmp(line, prefix, sizeof prefix - 1)) {
        bad_lines++;
        if (!first_bad_line[0]) snprintf(first_bad_line, sizeof first_bad_line, "%.159s", line);
    }
    nlines++;
    log_event(EV_LINE, 0, line);
    const char *t = line + sizeof prefix - 1;
    if (!strncmp(t, "NEXT ", 5)) {
        unsigned group = 0;
        if (!strcmp(t + 5, "U0")) { seen_u0 = 1; group = 1; }
        else if (!strcmp(t + 5, "SMMU")) { seen_smmu = 1; group = 2; }
        else if (!strcmp(t + 5, "RINGS")) { seen_rings = 1; group = 3; }
        else if (!strncmp(t + 5, "CB", 2)) { seen_cb = 1; group = 4; seen_bank[atoi(t + 7) & 255] = 1; }
        else if (!strcmp(t + 5, "WALK")) { seen_walk = 1; group = 5; }
        if (!group) violate("an unknown NEXT line: %s", line);
        else if (next_n < 8) next_order[next_n++] = group;
    }
}
static uint32_t fake_hex(char *dst, uint32_t cap, uint64_t value) { return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value); }

/* The geometry of the SMMU as the model answers it, for the oracle. */
static uint32_t smmu_reg(uint64_t off) { return mmio_value(SMMU_BASE + off); }
static unsigned smmu_pagesize(void) { return smmu_reg(0x24) >> 31 ? 65536u : 4096u; }
static unsigned smmu_numpage(void) { return 2u << (smmu_reg(0x24) >> 28 & 7); }

/* Whether the payload may read this register of a window at all. Returns the bank number for a context bank register (-1 if
 * none) through *bank. */
static int mmio_allowed(unsigned win, uint64_t off, int *group, int *bank)
{
    *bank = -1;
    if (win < 2) {
        uint64_t base = win ? U1_BASE : U0_BASE;
        uint32_t caplen = mmio_value(base) & 0xff;
        uint64_t rt = (uint64_t)(mmio_value(base + 0x18) & ~0x1fu);
        *group = 1;
        if (off == 0 || off == 4 || off == 0x10 || off == 0x18) return 1;
        if (off >= caplen && off < caplen + 0x40) {
            uint64_t r = off - caplen;
            if (r == 0 || r == 4 || r == 0x18 || r == 0x1c || r == 0x30 || r == 0x34 || r == 0x38) return 1;
        }
        if (off == caplen + 0x400 || off == caplen + 0x410) return 1;
        if (off == rt + 0x28 || off == rt + 0x30 || off == rt + 0x34 || off == rt + 0x38 || off == rt + 0x3c) return 1;
        if (!win && (off == 0xc110 || off == 0xc118 || off == 0xc120 || off == 0xc130 || off == 0xc134 || off == 0xc164)) return 1;
        return 0;
    }
    unsigned pagesize = smmu_pagesize(), numpage = smmu_numpage();
    uint32_t numsmrg = smmu_reg(0x20) & 0xff, numcb = smmu_reg(0x24) & 0xff;
    if (off < pagesize) {
        *group = 2;
        if (off == 0 || off == 0x20 || off == 0x24 || off == 0x28 || off == 0x48) return 1;
        if (smmu_reg(0x48) && (off == 0x40 || off == 0x44 || off == 0x50 || off == 0x54 || off == 0x58)) return 1;
        if (off >= 0x800 && off < 0x800 + 4u * (numsmrg < 256 ? numsmrg : 256)) return 1;
        if (off >= 0xc00 && off < 0xc00 + 4u * (numsmrg < 256 ? numsmrg : 256)) return 1;
        return 0;
    }
    *group = 4;
    if (off < 2u * pagesize) {
        uint64_t r = off - pagesize;
        if (r < 0x800) *bank = (int)(r / 4);
        else if (r < 0x1000 && pagesize >= 0x1000) *bank = (int)((r - 0x800) / 4);
        return *bank >= 0 && (unsigned)*bank < numcb;
    }
    if (off >= (uint64_t)numpage * pagesize && off < (uint64_t)(numpage + 256) * pagesize) {
        uint64_t r = off - (uint64_t)numpage * pagesize;
        uint64_t reg = r % pagesize;
        *bank = (int)(r / pagesize);
        if ((unsigned)*bank >= numcb) return 0;
        return reg == 0 || reg == 0x10 || reg == 0x20 || reg == 0x24 || reg == 0x28 || reg == 0x2c || reg == 0x30 || reg == 0x38 ||
               reg == 0x3c || reg == 0x58 || reg == 0x60 || reg == 0x64 || reg == 0x68;
    }
    return 0;
}

static int bank_expected(int bank)
{
    if (!expected_banks_n) return 1;
    for (unsigned i = 0; i < expected_banks_n; i++)
        if (expected_banks[i] == (unsigned)bank) return 1;
    return 0;
}

static int32_t fake_load32(uint64_t addr, uint32_t *out)
{
    uint32_t value = 0;
    unsigned win = 9;
    nloads++;
    log_event(EV_LOAD, addr, NULL);
    if (!out) return Q1N1_PAYLOAD_LOAD_E_PARAM;
    if (addr & 3) { violate("a load at a misaligned address %" PRIX64, addr); return Q1N1_PAYLOAD_LOAD_E_ALIGN; }
    if (nloads > LOAD_CAP) violate("more than %u loads", LOAD_CAP);
    if (addr >= U0_BASE && addr < U0_BASE + XHC_SIZE) win = 0;
    else if (addr >= U1_BASE && addr < U1_BASE + XHC_SIZE) win = 1;
    else if (addr >= SMMU_BASE && addr < SMMU_BASE + SMMU_SIZE) win = 2;
    win_loads[win < 3 ? win : 3]++;

    if (win < 3) {
        int group, bank;
        uint64_t off = addr - (win == 0 ? U0_BASE : win == 1 ? U1_BASE : SMMU_BASE);
        if (window_aborted[win]) violate("a load in window %u after an abort in it: %" PRIX64, win, addr);
        if (!mmio_allowed(win, off, &group, &bank)) violate("a load of a register it must not read: window %u offset %" PRIX64, win, off);
        else if (bank >= 0 && (!bank_expected(bank))) violate("a load of context bank %d, which no stream selects: offset %" PRIX64, bank, off);
        if (win < 2 && !seen_u0) violate("an xHC load before NEXT U0");
        if (win == 2 && group == 2 && !seen_smmu) violate("an SMMU global load before NEXT SMMU");
        if (win == 2 && group == 4 && (bank < 0 || !seen_bank[bank & 255])) violate("a context bank load before NEXT CB%d", bank);
        value = mmio_value(addr);
    } else {
        if (!oracle_usable(addr)) violate("a load at %" PRIX64 ", outside the three windows and not in usable RAM of the memory map", addr);
        if (!seen_rings) violate("a RAM load before NEXT RINGS: %" PRIX64, addr);
        if (seen_cb && !seen_walk) violate("a RAM load between NEXT CB and NEXT WALK: %" PRIX64, addr);
        uint8_t *p = ram_at(addr, 4);
        if (p) value = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
        if (mode == MODE_FILL && p) value = fill_value;
        else if (mode == MODE_RANDOM && p) value = (uint32_t)mix(addr ^ rng_seed) >> (mix(addr) & 7);
        if (!p) { nfaults++; return Q1N1_PAYLOAD_LOAD_E_FAULT; }
    }
    if ((fault_index && (long)nloads == fault_index) || (addr >= fault_lo && addr < fault_hi)) {
        nfaults++;
        if (win < 3) window_aborted[win] = 1;
        return Q1N1_PAYLOAD_LOAD_E_FAULT;
    }
    *out = value;
    return Q1N1_PAYLOAD_LOAD_OK;
}
static uint64_t fake_counter(void) { fprintf(stderr, "FAIL: usbsmmu used counter\n"); exit(3); }

/* ---- CurrentEL, and the run ------------------------------------------------------------------------------------------------ */

static uint64_t el_raw = 2 << 2;
uint64_t pl_host_sysreg(const char *name);
uint64_t pl_host_sysreg(const char *name)
{
    if (strcasecmp(name, "CurrentEL")) {
        fprintf(stderr, "FAIL: usbsmmu read a system register it is not allowed: %s\n", name);
        exit(3);
    }
    sysreg_reads++;
    log_event(EV_SYSREG, 0, name);
    return el_raw;
}

static struct q1n1_payload_args args(void)
{
    struct q1n1_payload_args a;
    memset(&a, 0, sizeof a);
    a.magic = Q1N1_PAYLOAD_ABI_MAGIC;
    a.version = Q1N1_PAYLOAD_ABI_VERSION;
    a.size = sizeof a;
    a.payload_base = UINT64_C(0xcf600000);
    a.payload_size = 0x4000;
    a.map_base = (uintptr_t)map_buf;
    a.map_size = (map_size_override ? map_size_override : (uint64_t)map_n * MAP_STRIDE);
    a.map_stride = MAP_STRIDE;
    a.stack_base = UINT64_C(0xcf610000);
    a.stack_size = 0x10000;
    a.ops.puts = fake_puts;
    a.ops.hex = fake_hex;
    a.ops.load32 = fake_load32;
    a.ops.counter = fake_counter;
    return a;
}

static void run_reset(void)
{
    nevents = nlines = nloads = nfaults = bad_lines = sysreg_reads = 0;
    memset(win_loads, 0, sizeof win_loads);
    first_bad_line[0] = 0;
    violations = 0;
    first_violation[0] = 0;
    seen_u0 = seen_smmu = seen_rings = seen_cb = seen_walk = 0;
    next_n = 0;
    memset(seen_bank, 0, sizeof seen_bank);
    memset(window_aborted, 0, sizeof window_aborted);
}
static uint64_t go(const struct q1n1_payload_args *a)
{
    run_reset();
    return payload_entry(a);
}

/* Lines, in order, as text. */
static const char *line_n(unsigned n)
{
    unsigned seen = 0;
    for (unsigned i = 0; i < nevents; i++)
        if (events[i].kind == EV_LINE && seen++ == n) return events[i].text + 16;
    return NULL;
}
static int line_has(const char *needle)
{
    for (unsigned i = 0; i < nevents; i++)
        if (events[i].kind == EV_LINE && strstr(events[i].text, needle)) return 1;
    return 0;
}
static int line_index(const char *prefix)
{
    unsigned seen = 0;
    for (unsigned i = 0; i < nevents; i++)
        if (events[i].kind == EV_LINE) {
            if (!strncmp(events[i].text + 16, prefix, strlen(prefix))) return (int)seen;
            seen++;
        }
    return -1;
}
static void dump_lines(FILE *f)
{
    for (unsigned i = 0; i < nevents; i++)
        if (events[i].kind == EV_LINE) fprintf(f, "  %s\n", events[i].text);
}
