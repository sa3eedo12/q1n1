/* SPDX-License-Identifier: MIT */
/* Native tests for the EL2 half of the stick-log survey (platform/uefi/sp11-stk-el2.c): the whole
 * sequence, run against a fake SoC whose clock controller, USB controllers, SMMU and DRAM are plain
 * arrays. The fake bus answers only the guarded load the survey is allowed to ask for; a store, a
 * load outside every window and every RAM range it was given, a load of memory the memory map does
 * not call RAM, and a runaway number of loads are all counted and fail the test.
 *
 * Expected lines are written out by hand from docs/SP11-STICK-LOG.md Appendix A. None of this runs on
 * a Surface Pro 11; evidence: EXPERIMENTAL, host model only, hardware NOT RUN. */
#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_STK_SURVEY 1
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sp11-stk-survey.h"

static unsigned checks;
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)
#define CHECK_STR(got, want) do { \
        if (strcmp((got), (want))) { \
            fprintf(stderr, "FAIL %s:%d: got \"%s\" want \"%s\"\n", __FILE__, __LINE__, (got), (want)); \
            return 1; \
        } \
        checks++; \
    } while (0)

/* The windows and offsets of Appendix A, typed here independently of the code under test. */
#define GCC_BASE UINT64_C(0x00100000)
#define SMMU_BASE UINT64_C(0x15000000)
#define U0_BASE UINT64_C(0x0a600000)
#define U1_BASE UINT64_C(0x0a800000)
#define U_SIZE UINT64_C(0xfc100)
static const uint64_t ubase[2] = {U0_BASE, U1_BASE};
static const struct { uint32_t gdscr, master, utmi, sleep, cfgnoc, aggre; } gcc[2] = {
    {0x39004, 0x39018, 0x39028, 0x39024, 0x3908c, 0x39090},
    {0xa1004, 0xa1018, 0xa1028, 0xa1024, 0xa108c, 0xa1090},
};
static const uint32_t gcc_shared[4] = {0x2d034, 0x2d014, 0x2d028, 0x2d02c};     /* NOC SYS NORTH SOUTH */

#define RAM_BASE UINT64_C(0x80000000)
#define RAM_SIZE 0x100000u
#define FORBIDDEN_BASE UINT64_C(0x90000000)       /* the fake bus serves it; the memory map calls it firmware */
#define FORBIDDEN_SIZE 0x10000u

/* ---- The fake SoC ---- */

#define MAX_REGS 4096
#define MAX_TRACE 4096
struct soc {
    uint8_t ram[RAM_SIZE];
    uint8_t forbidden[FORBIDDEN_SIZE];
    struct { uint64_t addr; uint32_t value; } reg[MAX_REGS];
    unsigned nreg;
    int attr[STK_WINDOWS];                        /* what the fake stage 1 says about each window */
    long fault_at, fault_from;                    /* the Nth load aborts; every load from the Nth on aborts */
    int fault_window;                             /* every MMIO load of this window aborts (-1: none) */
    int fault_ram;                                /* every load of DRAM aborts */
    unsigned max_loads;
    /* what happened */
    unsigned loads, stores, stray, forbidden_loads, runaway;
    unsigned win_loads[STK_WINDOWS], ram_loads;
    struct { uint64_t addr; int win; int faulted; } trace[MAX_TRACE];
    unsigned ntrace;
};

static int soc_window(uint64_t addr)
{
    for (int w = 0; w < STK_WINDOWS; w++)
        if (addr >= stk_windows[w].base && addr < stk_windows[w].base + stk_windows[w].size) return w;
    return -1;
}

static void soc_reg(struct soc *s, uint64_t addr, uint32_t v)
{
    for (unsigned i = 0; i < s->nreg; i++)
        if (s->reg[i].addr == addr) { s->reg[i].value = v; return; }
    if (s->nreg < MAX_REGS) { s->reg[s->nreg].addr = addr; s->reg[s->nreg].value = v; s->nreg++; }
}
static uint32_t soc_peek(const struct soc *s, uint64_t addr)
{
    for (unsigned i = 0; i < s->nreg; i++)
        if (s->reg[i].addr == addr) return s->reg[i].value;
    return 0;
}

static struct soc *cur;      /* the soc being run, for the recording sink */

static int fake_guarded(void *ctx, int kind, uint64_t dst, uint64_t src, uint64_t size)
{
    struct soc *s = ctx;
    /* The survey may only load. A store kind is a violation, however it came to be asked for. */
    if (kind != STK_G_COPY32) { s->stores++; return 1; }
    if (!size || (size & 3) || (src & 3)) { s->stray++; return 1; }
    unsigned index = s->loads++;
    if (s->loads > s->max_loads) { s->runaway = 1; return 1; }
    int win = soc_window(src);
    int in_ram = src >= RAM_BASE && src - RAM_BASE <= RAM_SIZE && RAM_SIZE - (src - RAM_BASE) >= size;
    int in_forbidden = src >= FORBIDDEN_BASE && src - FORBIDDEN_BASE <= FORBIDDEN_SIZE &&
                       FORBIDDEN_SIZE - (src - FORBIDDEN_BASE) >= size;
    int fault = (long)index == s->fault_at || (s->fault_from >= 0 && (long)index >= s->fault_from) ||
                (win >= 0 && s->fault_window == win) || (in_ram && s->fault_ram);
    if (s->ntrace < MAX_TRACE) {
        s->trace[s->ntrace].addr = src;
        s->trace[s->ntrace].win = win >= 0 ? win : in_ram ? 100 : -1;
        s->trace[s->ntrace].faulted = fault;
        s->ntrace++;
    }
    if (win >= 0) {
        if (size != 4) { s->stray++; return 1; }          /* registers are read one dword at a time */
        s->win_loads[win]++;
    } else if (in_ram) {
        s->ram_loads++;
    } else if (in_forbidden) {
        s->forbidden_loads++;                             /* it would answer; the survey must not ask */
    } else {
        s->stray++;
        return 1;
    }
    if (fault) return 1;
    for (uint64_t off = 0; off < size; off += 4) {
        uint32_t v = 0;
        if (win >= 0) v = soc_peek(s, src + off);
        else if (in_ram) memcpy(&v, s->ram + (src - RAM_BASE) + off, 4);
        else memcpy(&v, s->forbidden + (src - FORBIDDEN_BASE) + off, 4);
        memcpy((void *)(uintptr_t)(dst + off), &v, 4);
    }
    return 0;
}

static int fake_attr(void *ctx, uint64_t phys)
{
    struct soc *s = ctx;
    int w = soc_window(phys);
    if (w >= 0) return s->attr[w];
    if (phys >= RAM_BASE && phys < RAM_BASE + RAM_SIZE) return STK_ATTR_NORMAL;
    if (phys >= FORBIDDEN_BASE && phys < FORBIDDEN_BASE + FORBIDDEN_SIZE) return STK_ATTR_NORMAL;
    return STK_ATTR_NONE;
}

static void soc_reset(struct soc *s)
{
    memset(s, 0, sizeof *s);
    for (int w = 0; w < STK_WINDOWS; w++) s->attr[w] = STK_ATTR_DEVICE;
    s->fault_at = s->fault_from = -1;
    s->fault_window = -1;
    s->max_loads = 3000;
    memset(s->forbidden, 0xa5, sizeof s->forbidden);
}

/* The memory map the survey is given: RAM in two adjacent descriptors, a reserved range over the
 * USB windows, MMIO over the SMMU, and firmware memory (ACPI NVS) at the forbidden range. */
static struct q1n1_sp11_gop_map_entry map[] = {
    {4, RAM_BASE, RAM_SIZE / 4096 / 2, 0xf},
    {2, RAM_BASE + RAM_SIZE / 2, RAM_SIZE / 4096 / 2, 0xf},
    {0, 0x0a600000, 0x400, 0},
    {11, 0x15000000, 0x100, 0},
    {10, FORBIDDEN_BASE, FORBIDDEN_SIZE / 4096, 0xf},
};
#define NMAP (sizeof map / sizeof map[0])

/* ---- Recording ---- */

struct rec {
    char line[160][STK_LINE_MAX + 8];
    unsigned loads_at[160];
    unsigned n, bad, at_calls;
};
static void rec_emit(void *ctx, const char *line)
{
    struct rec *r = ctx;
    if (strlen(line) > STK_LINE_MAX || !stk_text_ok(line) || strncmp(line, "STK ", 4)) r->bad++;
    if (r->n < 160) {
        snprintf(r->line[r->n], sizeof r->line[0], "%s", line);
        r->loads_at[r->n] = cur ? cur->loads : 0;
        r->n++;
    }
}
static void rec_at(void *ctx, const char *where) { (void)where; ((struct rec *)ctx)->at_calls++; }

static int starts(const char *line, const char *prefix)
{
    size_t n = strlen(prefix);
    return !strncmp(line, prefix, n) && (line[n] == ' ' || line[n] == 0);
}
static int find(const struct rec *r, const char *prefix)
{
    for (unsigned i = 0; i < r->n; i++)
        if (starts(r->line[i], prefix)) return (int)i;
    return -1;
}
static unsigned count(const struct rec *r, const char *prefix)
{
    unsigned c = 0;
    for (unsigned i = 0; i < r->n; i++) c += starts(r->line[i], prefix);
    return c;
}
/* All physical lines of one logical line (a prefix repeated on continuation lines), fields joined by a
 * space. */
static char *logical(const struct rec *r, const char *prefix, char *out, size_t cap)
{
    size_t n = 0, plen = strlen(prefix);
    out[0] = 0;
    for (unsigned i = 0; i < r->n; i++) {
        if (!starts(r->line[i], prefix)) continue;
        const char *rest = r->line[i] + plen;
        if (*rest == ' ') rest++;
        if (n && n + 1 < cap) out[n++] = ' ';
        for (; *rest && n + 1 < cap; rest++) out[n++] = *rest;
        out[n] = 0;
    }
    return out;
}
#define LOGICAL(r, prefix, want) do { \
        char buf_[512]; \
        logical((r), (prefix), buf_, sizeof buf_); \
        if (strcmp(buf_, (want))) { \
            fprintf(stderr, "FAIL %s:%d: %s\n  got  \"%s\"\n  want \"%s\"\n", __FILE__, __LINE__, (prefix), buf_, (want)); \
            return 1; \
        } \
        checks++; \
    } while (0)

static struct stk_p2 *no_p2;
struct run_opts {
    const struct stk_p2 *p2;
    const struct q1n1_sp11_gop_map_entry *map;
    uint32_t nmap;
    int map_ok;
    unsigned sink_lines_start;
};
static struct run_opts opts_default(void) { struct run_opts o = {NULL, map, NMAP, 1, 0}; return o; }

static struct stk_sink last_sink;

/* Runs the survey and asserts the invariants every run owes, whatever the SoC did. The counters are
 * per run: a scenario may be run again after a register is changed. */
static int run(struct soc *s, struct rec *r, struct stk_result *res, const struct run_opts *o)
{
    struct stk_ops ops = {fake_guarded, fake_attr, s};
    struct stk_sink sink;
    s->loads = s->stores = s->stray = s->forbidden_loads = s->runaway = s->ram_loads = s->ntrace = 0;
    memset(s->win_loads, 0, sizeof s->win_loads);
    memset(r, 0, sizeof *r);
    memset(&sink, 0, sizeof sink);
    sink.emit = rec_emit; sink.at = rec_at; sink.ctx = r;
    struct stk_el2_args args = {&ops, o->p2, o->map, o->nmap, o->map_ok, RAM_BASE, &sink};
    cur = s;
    stk_el2_run(&args, res);
    cur = NULL;
    last_sink = sink;
    CHECK(s->stores == 0);                                  /* loads only */
    CHECK(s->stray == 0);                                   /* every load was inside a window or RAM */
    CHECK(s->forbidden_loads == 0);                         /* nothing the memory map calls firmware was read */
    CHECK(!s->runaway && s->loads <= STK_MAX_READS);
    CHECK(r->bad == 0);                                     /* every line within 100 characters and the font */
    CHECK(sink.lines <= STK_MAX_LINES && r->n == sink.lines);
    CHECK(r->n >= 1 && starts(r->line[r->n - 1], "STK P3 VERDICT"));   /* the verdict is always the last line */
    if (res->reads != s->loads - s->stray) {
        fprintf(stderr, "FAIL %s:%d: survey counted %u loads, the bus saw %u (stray %u)\n", __FILE__, __LINE__,
                res->reads, s->loads, s->stray);
        return 1;
    }
    checks++;
    (void)no_p2;
    return 0;
}

/* ---- Building a controller ---- */

struct xhci_cfg {
    uint32_t caplen, hciver, slots, ports, hcs2, hcc1, dboff, rtsoff;
    int caps;                                             /* write the USB 2 and USB 3 protocol capabilities */
    uint32_t usbcmd, usbsts, config;
    uint64_t crcr, dcbaap, erstba, erdp;
    uint32_t portsc[8];
    uint32_t dwc3[6];                                     /* GSNPSID GCTL GSTS GBUSERR USB2CFG USB3PIPE */
    uint32_t glue[2];
};
static struct xhci_cfg xhci_default(void)
{
    struct xhci_cfg c;
    memset(&c, 0, sizeof c);
    c.caplen = 0x20; c.hciver = 0x110; c.slots = 32; c.ports = 2; c.hcs2 = 0xff0001;
    c.hcc1 = 0x01200001; c.dboff = 0x2000; c.rtsoff = 0x1000; c.caps = 1;
    c.usbcmd = 0; c.usbsts = 1; c.config = 0x20;
    c.crcr = RAM_BASE + 0x4001; c.dcbaap = RAM_BASE + 0x1000; c.erstba = RAM_BASE + 0x5000;
    c.erdp = RAM_BASE + 0x5018;
    c.portsc[0] = 0xe03; c.portsc[1] = 0x2a0;
    c.dwc3[0] = 0x5533330a; c.dwc3[1] = 0x1002; c.dwc3[2] = 0x7e800001; c.dwc3[3] = 0;
    c.dwc3[4] = 0x40102450; c.dwc3[5] = 0x010c0002;
    c.glue[0] = 0x10000000; c.glue[1] = 0x1000000;
    return c;
}

static void soc_xhci(struct soc *s, int unit, const struct xhci_cfg *c)
{
    uint64_t b = ubase[unit];
    uint32_t op = c->caplen;
    soc_reg(s, b + 0x00, c->caplen | c->hciver << 16);
    soc_reg(s, b + 0x04, c->slots | 8u << 8 | c->ports << 24);
    soc_reg(s, b + 0x08, c->hcs2);
    soc_reg(s, b + 0x10, c->hcc1);
    soc_reg(s, b + 0x14, c->dboff);
    soc_reg(s, b + 0x18, c->rtsoff);
    soc_reg(s, b + op + 0x00, c->usbcmd);
    soc_reg(s, b + op + 0x04, c->usbsts);
    soc_reg(s, b + op + 0x18, (uint32_t)c->crcr);
    soc_reg(s, b + op + 0x1c, (uint32_t)(c->crcr >> 32));
    soc_reg(s, b + op + 0x30, (uint32_t)c->dcbaap);
    soc_reg(s, b + op + 0x34, (uint32_t)(c->dcbaap >> 32));
    soc_reg(s, b + op + 0x38, c->config);
    for (unsigned p = 0; p < c->ports && p < 8; p++) soc_reg(s, b + op + 0x400 + 0x10 * p, c->portsc[p]);
    uint32_t rt = c->rtsoff & ~0x1fu;
    soc_reg(s, b + rt + 0x30, (uint32_t)c->erstba);
    soc_reg(s, b + rt + 0x34, (uint32_t)(c->erstba >> 32));
    soc_reg(s, b + rt + 0x38, (uint32_t)c->erdp);
    soc_reg(s, b + rt + 0x3c, (uint32_t)(c->erdp >> 32));
    if (c->caps && c->hcc1 >> 16) {
        uint64_t x = b + (c->hcc1 >> 16) * 4;
        soc_reg(s, x + 0x00, 2 | 4 << 8 | 0x00 << 16 | 2u << 24);        /* USB 2.0, next in 4 dwords */
        soc_reg(s, x + 0x04, 0x20425355);
        soc_reg(s, x + 0x08, 1 | 1 << 8);                                  /* port 1, one port */
        soc_reg(s, x + 0x10, 2 | 0 << 8 | 0x10 << 16 | 3u << 24);        /* USB 3.1, last */
        soc_reg(s, x + 0x14, 0x20425355);
        soc_reg(s, x + 0x18, 2 | 1 << 8);                                  /* port 2, one port */
    }
    soc_reg(s, b + 0xc120, c->dwc3[0]);
    soc_reg(s, b + 0xc110, c->dwc3[1]);
    soc_reg(s, b + 0xc118, c->dwc3[2]);
    soc_reg(s, b + 0xc130, c->dwc3[3]);
    soc_reg(s, b + 0xc200, c->dwc3[4]);
    soc_reg(s, b + 0xc2c0, c->dwc3[5]);
    soc_reg(s, b + 0xf8810, c->glue[0]);
    soc_reg(s, b + 0xf8830, c->glue[1]);
}

static void soc_gcc(struct soc *s, int unit, int on)
{
    soc_reg(s, GCC_BASE + gcc[unit].gdscr, on ? 0x80000004u : 0x1u);
    uint32_t clk = on ? 0x1u : 0x80000000u;
    soc_reg(s, GCC_BASE + gcc[unit].master, clk);
    soc_reg(s, GCC_BASE + gcc[unit].utmi, clk);
    soc_reg(s, GCC_BASE + gcc[unit].sleep, clk);
    soc_reg(s, GCC_BASE + gcc[unit].cfgnoc, on ? 0x3u : clk);
    soc_reg(s, GCC_BASE + gcc[unit].aggre, on ? 0x3u : clk);
}
static void soc_gcc_shared(struct soc *s, int on)
{
    for (unsigned i = 0; i < 4; i++) soc_reg(s, GCC_BASE + gcc_shared[i], on ? 0x1u : 0x80000000u);
}

static void ram32(struct soc *s, uint64_t addr, uint32_t v) { memcpy(s->ram + (addr - RAM_BASE), &v, 4); }
static void ram64(struct soc *s, uint64_t addr, uint64_t v) { memcpy(s->ram + (addr - RAM_BASE), &v, 8); }

/* An output device context: the slot context's four dwords, and endpoint contexts at 32 byte steps. */
static void ram_slot(struct soc *s, uint64_t ctx, uint32_t route, unsigned speed, int hub, unsigned entries,
                     unsigned root, unsigned address, unsigned state)
{
    ram32(s, ctx, route | speed << 20 | (uint32_t)(hub ? 1 : 0) << 26 | entries << 27);
    ram32(s, ctx + 4, root << 16);
    ram32(s, ctx + 12, address | state << 27);
}
static void ram_ep(struct soc *s, uint64_t ctx, unsigned dci, unsigned state, unsigned type, unsigned mps)
{
    ram32(s, ctx + 32u * dci, state);
    ram32(s, ctx + 32u * dci + 4, type << 3 | mps << 16);
}

/* The firmware's slots: a hub in slot 1 on root port 1, and the stick behind it in slot 2. */
static void soc_slots(struct soc *s)
{
    uint64_t dcbaa = RAM_BASE + 0x1000;
    ram64(s, dcbaa + 8, RAM_BASE + 0x2000);
    ram64(s, dcbaa + 16, RAM_BASE + 0x3000);
    ram_slot(s, RAM_BASE + 0x2000, 0, 3, 1, 3, 1, 1, 3);
    ram_ep(s, RAM_BASE + 0x2000, 1, 1, 4, 64);
    ram_ep(s, RAM_BASE + 0x2000, 3, 1, 7, 2);
    ram_slot(s, RAM_BASE + 0x3000, 0x2, 3, 0, 4, 1, 2, 3);
    ram_ep(s, RAM_BASE + 0x3000, 1, 1, 4, 64);
    ram_ep(s, RAM_BASE + 0x3000, 3, 1, 6, 512);
    ram_ep(s, RAM_BASE + 0x3000, 4, 1, 2, 512);
}

static void soc_smmu(struct soc *s)
{
    soc_reg(s, SMMU_BASE + 0x20, 15u << 9 | 8);           /* ID0: 15 stream id bits, 8 groups */
    soc_reg(s, SMMU_BASE + 0x00, 0x400);                  /* sCR0: USFCFG */
    soc_reg(s, SMMU_BASE + 0x48, 0);
    soc_reg(s, SMMU_BASE + 0x800 + 4 * 3, 0x80000000u | 0x1420);
    soc_reg(s, SMMU_BASE + 0xc00 + 4 * 3, 1u << 16);                       /* bypass */
    soc_reg(s, SMMU_BASE + 0x800 + 4 * 5, 0x80000000u | 0x20u << 16 | 0x1440);
    soc_reg(s, SMMU_BASE + 0xc00 + 4 * 5, 7);                              /* translate, bank 7 */
}

/* Scenario A: usb_1_ss0 is powered with the stick (behind a hub) on its root port 1 and the
 * controller halted by the firmware; usb_1_ss1 is powered off. */
static void scenario_a(struct soc *s)
{
    struct xhci_cfg c = xhci_default();
    soc_reset(s);
    soc_gcc(s, 0, 1);
    soc_gcc(s, 1, 0);
    soc_gcc_shared(s, 1);
    soc_xhci(s, 0, &c);
    soc_slots(s);
    soc_smmu(s);
}

/* Scenario B: both controllers are powered; the second has a device on its port 2 and no slot. */
static void scenario_b(struct soc *s)
{
    struct xhci_cfg c = xhci_default(), d = xhci_default();
    soc_reset(s);
    soc_gcc(s, 0, 1);
    soc_gcc(s, 1, 1);
    soc_gcc_shared(s, 1);
    soc_xhci(s, 0, &c);
    d.portsc[0] = 0x2a0;
    d.portsc[1] = 0x1e03;                                 /* connected, enabled, powered, SuperSpeed */
    d.dcbaap = 0;
    d.crcr = 0;
    d.erstba = 0;
    d.erdp = 0;
    soc_xhci(s, 1, &d);
    soc_slots(s);
    soc_smmu(s);
}

/* ---- The golden run ---- */

static int test_golden(void)
{
    static struct soc s;
    static struct rec r;
    struct stk_result res;
    struct run_opts o = opts_default();
    scenario_a(&s);
    if (run(&s, &r, &res, &o)) return 1;

    LOGICAL(&r, "STK P3 MAP", "GCC=DEVICE SMMU=DEVICE U0=DEVICE U1=DEVICE RAM=NORMAL");
    LOGICAL(&r, "STK P3 GCC U0",
            "GDSCR=0X80000004 PWR=1 SWC=0 MASTER=0X1 UTMI=0X1 SLEEP=0X1 CFGNOC=0X3 AGGRE=0X3");
    LOGICAL(&r, "STK P3 GCC U1", "GDSCR=0X1 PWR=0 SWC=1 MASTER=0X80000000 UTMI=0X80000000 SLEEP=0X80000000 "
                                 "CFGNOC=0X80000000 AGGRE=0X80000000");
    CHECK(count(&r, "STK P3 GCC U1") == 2);                  /* all clocks off does not fit one line: it splits */
    LOGICAL(&r, "STK P3 GCC SHARED", "NOC=0X1 SYS=0X1 NORTH=0X1 SOUTH=0X1");
    LOGICAL(&r, "STK P3 GATE", "U0=ON U1=OFF");
    LOGICAL(&r, "STK P3 U0 ID", "CAPLEN=0X20 HCIVER=0X110 SLOTS=32 PORTS=2 HCS2=0XFF0001 HCC1=0X1200001 "
                                "DBOFF=0X2000 RTSOFF=0X1000");
    LOGICAL(&r, "STK P3 U0 XECP", "PROTO0=USB2 REV=0X200 FIRST=1 COUNT=1 PROTO1=USB3 REV=0X310 FIRST=2 COUNT=1");
    LOGICAL(&r, "STK P3 U0 OP", "USBCMD=0X0 USBSTS=0X1 RS=0 HCH=1 HSE=0 CNR=0 CRCR=0X80004001 "
                                "DCBAAP=0X80001000 CONFIG=0X20");
    LOGICAL(&r, "STK P3 U0 PORT1", "SC=0XE03 CCS=1 PED=1 PP=1 PLS=0 SPEED=3");
    LOGICAL(&r, "STK P3 U0 PORT2", "SC=0X2A0 CCS=0 PED=0 PP=1 PLS=5 SPEED=0");
    CHECK(find(&r, "STK P3 U0 PORT3") < 0);                  /* the controller has two ports */
    LOGICAL(&r, "STK P3 U0 DWC3", "GSNPSID=0X5533330A GCTL=0X1002 PRTCAPDIR=1 GSTS=0X7E800001 CURMOD=1 "
                                  "GBUSERR=0X0 USB2CFG=0X40102450 USB3PIPE=0X10C0002");
    LOGICAL(&r, "STK P3 U0 GLUE", "HSPHY=0X10000000 SSPHY=0X1000000");
    LOGICAL(&r, "STK P3 U0 FWRINGS", "DCBAAP=0X80001000 CRCR=0X80004001 ERSTBA=0X80005000 ERDP=0X80005018 INRAM=1");
    LOGICAL(&r, "STK P3 U0 SLOT1", "CTX=0X80002000 ROUTE=0X0 HUB=1 ROOTPORT=1 SPEED=3 STATE=3 ADDR=1 "
                                   "EP1=1.4.0X40 EP3=1.7.0X2");
    LOGICAL(&r, "STK P3 U0 SLOT2", "CTX=0X80003000 ROUTE=0X2 HUB=0 ROOTPORT=1 SPEED=3 STATE=3 ADDR=2 "
                                   "EP1=1.4.0X40 EP3=1.6.0X200 EP4=1.2.0X200");
    CHECK(count(&r, "STK P3 U0 SLOT2") == 2);                /* the endpoint list moved to a continuation line */
    CHECK(find(&r, "STK P3 U0 SLOT3") < 0);
    LOGICAL(&r, "STK P3 U1", "SKIPPED=GATE_OFF");
    CHECK(find(&r, "STK P3 U1 ID") < 0 && find(&r, "STK NEXT U1") < 0 && find(&r, "STK NEXT FWRINGS1") < 0);
    CHECK_STR(r.line[find(&r, "STK P3 SMMU")],
              "STK P3 SMMU ID0=0X1E08 NUMSMRG=8 SCR0=0X400 USFCFG=1 CLIENTPD=0 EXID=0 GFSR=0X0");
    LOGICAL(&r, "STK P3 SMMU S1420", "SMR=3 TYPE=BYPASS CBNDX=0");
    LOGICAL(&r, "STK P3 SMMU S1460", "SMR=5 TYPE=TRANS CBNDX=7");
    LOGICAL(&r, "STK P3 VERDICT", "U0=STICK-PRESENT-HALTED U1=GATED-OFF SMMU=BYPASS");
    CHECK(res.verdict[0] == STK_V_STICK_HALTED && res.verdict[1] == STK_V_GATED_OFF && res.smmu == STK_SMMU_BYPASS);
    CHECK(res.gate[0] == STK_GATE_ON && res.gate[1] == STK_GATE_OFF);

    /* The order of design section 3.6, each block after its STK NEXT line, and the NEXT line before the
     * block's first load. */
    static const char *const order[] = {
        "STK NEXT MAP", "STK P3 MAP", "STK NEXT GCC", "STK P3 GCC U0", "STK P3 GCC U1", "STK P3 GCC SHARED",
        "STK P3 GATE", "STK P3 U1", "STK NEXT U0", "STK P3 U0 ID", "STK P3 U0 XECP", "STK P3 U0 OP", "STK P3 U0 PORT1",
        "STK P3 U0 PORT2", "STK P3 U0 DWC3", "STK P3 U0 GLUE", "STK NEXT FWRINGS0", "STK P3 U0 FWRINGS",
        "STK P3 U0 SLOT1", "STK P3 U0 SLOT2", "STK NEXT SMMU", "STK P3 SMMU", "STK P3 SMMU S1420",
        "STK P3 SMMU S1460", "STK P3 VERDICT",
    };
    int previous = -1;
    for (unsigned i = 0; i < sizeof order / sizeof order[0]; i++) {
        /* STK P3 U1 is printed between GATE and NEXT U0: it is the "gate off" line. */
        int at = find(&r, order[i]);
        CHECK(at >= 0);
        if (strcmp(order[i], "STK P3 U1") == 0) { previous = at; continue; }
        CHECK(at > previous || !strcmp(order[i], "STK NEXT U0"));
        previous = at;
    }
    int next_u0 = find(&r, "STK NEXT U0");
    unsigned first_u0 = 0, first_gcc = 0, first_smmu = 0, first_ram = 0;
    for (unsigned i = 0; i < s.ntrace; i++) {
        if (s.trace[i].win == STK_WIN_U0 && !first_u0) first_u0 = i + 1;
        if (s.trace[i].win == STK_WIN_GCC && !first_gcc) first_gcc = i + 1;
        if (s.trace[i].win == STK_WIN_SMMU && !first_smmu) first_smmu = i + 1;
        if (s.trace[i].win == 100 && !first_ram) first_ram = i + 1;
    }
    CHECK(r.loads_at[next_u0] < first_u0);                  /* printed before the first load of the block */
    CHECK(r.loads_at[find(&r, "STK NEXT GCC")] < first_gcc);
    CHECK(r.loads_at[find(&r, "STK NEXT SMMU")] < first_smmu);
    CHECK(r.loads_at[find(&r, "STK NEXT FWRINGS0")] < first_ram);
    CHECK(r.at_calls >= 10);                                 /* the in-place marker was moved, and is not a line */
    CHECK(s.win_loads[STK_WIN_U1] == 0);                     /* the gated-off controller was never read */
    CHECK(s.win_loads[STK_WIN_GCC] == 6 + 6 + 4);
    return 0;
}

static int test_both_controllers(void)
{
    static struct soc s;
    static struct rec r;
    struct stk_result res;
    struct run_opts o = opts_default();
    scenario_b(&s);
    if (run(&s, &r, &res, &o)) return 1;
    /* Appendix A's NEXT blocks, in its order: MAP, GCC, U0, U1, FWRINGS0, FWRINGS1, SMMU. */
    static const char *const next[] = {"MAP", "GCC", "U0", "U1", "FWRINGS0", "FWRINGS1", "SMMU"};
    unsigned seen = 0;
    int previous = -1;
    for (unsigned i = 0; i < r.n; i++) {
        if (strncmp(r.line[i], "STK NEXT ", 9)) continue;
        CHECK(seen < 7 && !strcmp(r.line[i] + 9, next[seen]));
        CHECK((int)i > previous);
        previous = (int)i;
        seen++;
    }
    CHECK(seen == 7);
    LOGICAL(&r, "STK P3 GATE", "U0=ON U1=ON");
    LOGICAL(&r, "STK P3 U1 PORT1", "SC=0X2A0 CCS=0 PED=0 PP=1 PLS=5 SPEED=0");
    LOGICAL(&r, "STK P3 U1 PORT2", "SC=0X1E03 CCS=1 PED=1 PP=1 PLS=0 SPEED=7");
    LOGICAL(&r, "STK P3 U1 FWRINGS", "DCBAAP=0X0 CRCR=0X0 ERSTBA=0X0 ERDP=0X0 INRAM=0");
    LOGICAL(&r, "STK P3 U1 SLOT", "SKIPPED=NO_DCBAAP");
    CHECK(res.verdict[0] == STK_V_STICK_HALTED && res.verdict[1] == STK_V_CONNECTED);
    /* The stick's controller is U0, so the SMMU verdict is that of stream 0x1420: bypass. */
    CHECK(res.smmu == STK_SMMU_BYPASS);
    CHECK(s.win_loads[STK_WIN_U0] > 0 && s.win_loads[STK_WIN_U1] > 0);
    return 0;
}

/* ---- Verdicts end to end ---- */

static int verdict_of(void (*tweak)(struct soc *), int unit, int expect, const char *label)
{
    static struct soc s;
    static struct rec r;
    struct stk_result res;
    struct run_opts o = opts_default();
    scenario_b(&s);
    tweak(&s);
    if (run(&s, &r, &res, &o)) return 1;
    if (res.verdict[unit] != expect) {
        fprintf(stderr, "FAIL verdict %s: got %s want %s\n", label, stk_verdict_name(res.verdict[unit]),
                stk_verdict_name(expect));
        return 1;
    }
    char want[32];
    snprintf(want, sizeof want, "U%d=%s", unit, stk_verdict_name(expect));
    CHECK(strstr(r.line[r.n - 1], want) != NULL);
    checks++;
    return 0;
}

static void t_running(struct soc *s) { soc_reg(s, U0_BASE + 0x24, 0); soc_reg(s, U0_BASE + 0x20, 1); }
static void t_noport(struct soc *s) { soc_reg(s, U0_BASE + 0x420, 0x2a0); }
static void t_ccs_no_pp(struct soc *s) { soc_reg(s, U0_BASE + 0x420, 0x001); }
static void t_not_xhci(struct soc *s) { soc_reg(s, U0_BASE + 0x00, 0xffffffffu); }
static void t_zero_xhci(struct soc *s) { soc_reg(s, U0_BASE + 0x00, 0); }
static void t_old_version(struct soc *s) { soc_reg(s, U0_BASE + 0x00, 0x20 | 0x0080u << 16); }
static void t_odd_caplen(struct soc *s) { soc_reg(s, U0_BASE + 0x00, 0x21 | 0x0110u << 16); }
static void t_partial(struct soc *s) { soc_reg(s, GCC_BASE + gcc[0].aggre, 0x80000003u); }
static void t_off(struct soc *s) { soc_reg(s, GCC_BASE + gcc[0].gdscr, 0x1); }
static void t_shared_off(struct soc *s) { soc_reg(s, GCC_BASE + gcc_shared[2], 0x80000000u); }
static void t_usbsts_ones(struct soc *s) { soc_reg(s, U0_BASE + 0x24, 0xffffffffu); }
static void t_no_slots(struct soc *s)
{
    uint64_t dcbaa = RAM_BASE + 0x1000;
    ram64(s, dcbaa + 8, 0);
    ram64(s, dcbaa + 16, 0);
}
static void t_slot_other_port(struct soc *s) { ram_slot(s, RAM_BASE + 0x3000, 0, 3, 0, 4, 2, 2, 3); ram_slot(s, RAM_BASE + 0x2000, 0, 3, 1, 3, 2, 1, 3); }
static void t_fault_u0(struct soc *s) { s->fault_window = STK_WIN_U0; }
static void t_gcc_fault(struct soc *s) { s->fault_window = STK_WIN_GCC; }
static void t_big_config(struct soc *s) { soc_reg(s, U0_BASE + 0x20 + 0x38, 0xff); }

static int test_verdicts(void)
{
    /* scenario_b: U0 has the stick (halted), U1 a connected device with no slot. */
    if (verdict_of(t_running, 0, STK_V_STICK_RUNNING, "running")) return 1;
    if (verdict_of(t_noport, 0, STK_V_IDLE, "nothing connected")) return 1;
    if (verdict_of(t_ccs_no_pp, 0, STK_V_INCONSISTENT, "CCS with PP clear")) return 1;
    if (verdict_of(t_not_xhci, 0, STK_V_NOT_XHCI, "all ones")) return 1;
    if (verdict_of(t_zero_xhci, 0, STK_V_NOT_XHCI, "all zero")) return 1;
    if (verdict_of(t_old_version, 0, STK_V_NOT_XHCI, "HCIVERSION below 0.90")) return 1;
    if (verdict_of(t_odd_caplen, 0, STK_V_NOT_XHCI, "CAPLENGTH not whole dwords")) return 1;
    if (verdict_of(t_partial, 0, STK_V_GATED_OFF, "a clock off")) return 1;
    if (verdict_of(t_off, 0, STK_V_GATED_OFF, "GDSC off")) return 1;
    if (verdict_of(t_shared_off, 0, STK_V_GATED_OFF, "a shared clock off")) return 1;
    if (verdict_of(t_usbsts_ones, 0, STK_V_INCONSISTENT, "USBSTS all ones")) return 1;
    if (verdict_of(t_no_slots, 0, STK_V_CONNECTED, "connected, firmware slots gone")) return 1;
    if (verdict_of(t_slot_other_port, 0, STK_V_CONNECTED, "slots on another port")) return 1;
    if (verdict_of(t_fault_u0, 0, STK_V_FAULT, "controller aborts")) return 1;
    if (verdict_of(t_gcc_fault, 0, STK_V_FAULT, "clock controller aborts")) return 1;
    if (verdict_of(t_gcc_fault, 1, STK_V_FAULT, "clock controller aborts (second)")) return 1;
    if (verdict_of(t_big_config, 0, STK_V_STICK_HALTED, "CONFIG larger than the scan")) return 1;
    return 0;
}

/* ---- Policy: what the survey refuses to read ---- */

static int test_windows_refused(void)
{
    static struct soc s;
    static struct rec r;
    struct stk_result res;
    struct run_opts o = opts_default();

    /* The clock controller mapped Normal: never read through it, whatever the map says. */
    scenario_a(&s);
    s.attr[STK_WIN_GCC] = STK_ATTR_NORMAL;
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(s.win_loads[STK_WIN_GCC] == 0);
    CHECK(find(&r, "STK P3 GCC U0") >= 0 && strstr(r.line[find(&r, "STK P3 GCC U0")], "SKIPPED=NOT_DEVICE"));
    LOGICAL(&r, "STK P3 GATE", "U0=? U1=?");
    CHECK(res.verdict[0] == STK_V_UNREAD && res.verdict[1] == STK_V_UNREAD);
    CHECK(s.win_loads[STK_WIN_U0] == 0 && s.win_loads[STK_WIN_U1] == 0);        /* no gate, no controller */
    CHECK(s.win_loads[STK_WIN_SMMU] > 0);                    /* the SMMU is a separate window and is still read */
    CHECK(strstr(r.line[find(&r, "STK P3 MAP")], "GCC=NORMAL") != NULL);

    /* Unmapped at stage 1: refused, not read. */
    scenario_a(&s);
    s.attr[STK_WIN_U0] = STK_ATTR_NONE;
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(s.win_loads[STK_WIN_U0] == 0);
    CHECK(strstr(r.line[find(&r, "STK P3 U0 ID")], "SKIPPED=UNMAPPED") != NULL);
    CHECK(res.verdict[0] == STK_V_UNREAD);
    CHECK(strstr(r.line[find(&r, "STK P3 MAP")], "U0=NONE") != NULL);

    /* A mapping attribute that could not be read: refused as unknown. */
    scenario_a(&s);
    s.attr[STK_WIN_SMMU] = STK_ATTR_UNKNOWN;
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(s.win_loads[STK_WIN_SMMU] == 0 && res.smmu == STK_SMMU_UNREAD);
    CHECK(strstr(r.line[find(&r, "STK P3 SMMU")], "SKIPPED=ATTR_UNKNOWN") != NULL);
    CHECK(strstr(r.line[find(&r, "STK P3 SMMU S1420")], "SKIPPED=NO_GLOBAL") != NULL);
    CHECK(strstr(r.line[find(&r, "STK P3 MAP")], "SMMU=?") != NULL);

    /* The memory map calls a window RAM, or firmware memory: refused before any access, with the reason. */
    struct q1n1_sp11_gop_map_entry ram_over_gcc[] = {
        {4, RAM_BASE, RAM_SIZE / 4096, 0xf}, {7, GCC_BASE, 0x200, 0}, {10, FORBIDDEN_BASE, FORBIDDEN_SIZE / 4096, 0},
    };
    scenario_a(&s);
    o = opts_default();
    o.map = ram_over_gcc; o.nmap = 3;
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(s.win_loads[STK_WIN_GCC] == 0);
    CHECK(strstr(r.line[find(&r, "STK P3 GCC U0")], "SKIPPED=MAP_RAM") != NULL);
    CHECK(res.verdict[0] == STK_V_UNREAD);
    CHECK(s.win_loads[STK_WIN_SMMU] > 0);                    /* the other windows are not affected */
    struct q1n1_sp11_gop_map_entry nvs_over_u0[] = {
        {4, RAM_BASE, RAM_SIZE / 4096, 0xf}, {10, U0_BASE, 0x100, 0}, {10, FORBIDDEN_BASE, FORBIDDEN_SIZE / 4096, 0},
    };
    scenario_a(&s);
    o.map = nvs_over_u0; o.nmap = 3;
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(s.win_loads[STK_WIN_U0] == 0 && s.win_loads[STK_WIN_GCC] > 0);
    CHECK(strstr(r.line[find(&r, "STK P3 U0 ID")], "SKIPPED=MAP_RAM") != NULL);
    CHECK(res.verdict[0] == STK_V_UNREAD);

    /* No usable memory map: no window can be shown not to be RAM, so nothing is read at all. */
    scenario_a(&s);
    o = opts_default();
    o.map_ok = 0;
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(s.loads == 0);
    CHECK(strstr(r.line[find(&r, "STK P3 GCC U0")], "SKIPPED=NO_MAP") != NULL);
    CHECK(strstr(r.line[find(&r, "STK P3 SMMU")], "SKIPPED=NO_MAP") != NULL);
    CHECK(res.verdict[0] == STK_V_UNREAD && res.smmu == STK_SMMU_UNREAD);
    scenario_a(&s);
    o.map = NULL; o.nmap = 0; o.map_ok = 1;                  /* a map that parsed but shows nothing */
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(s.ram_loads == 0);                                  /* no pointer is followed into memory the map does not show */
    return 0;
}

/* Pointers read from the controller are followed only into RAM. */
static int test_pointers(void)
{
    static struct soc s;
    static struct rec r;
    struct stk_result res;
    struct run_opts o = opts_default();

    /* DCBAAP into firmware memory the fake bus would happily serve: INRAM=0 and nothing is read there. */
    struct xhci_cfg c = xhci_default();
    scenario_a(&s);
    c.dcbaap = FORBIDDEN_BASE;
    soc_xhci(&s, 0, &c);
    if (run(&s, &r, &res, &o)) return 1;
    LOGICAL(&r, "STK P3 U0 FWRINGS", "DCBAAP=0X90000000 CRCR=0X80004001 ERSTBA=0X80005000 ERDP=0X80005018 INRAM=0");
    LOGICAL(&r, "STK P3 U0 SLOT", "SKIPPED=NOT_RAM");
    CHECK(s.forbidden_loads == 0 && s.ram_loads == 0);
    CHECK(res.verdict[0] == STK_V_CONNECTED);                /* CCS on port 1 but no slot evidence */
    /* DCBAAP below RAM, past RAM, misaligned, zero. */
    uint64_t bad[] = {0x40, RAM_BASE + RAM_SIZE, RAM_BASE + 0x1008, RAM_BASE + RAM_SIZE - 64, 0};
    const char *why[] = {"NOT_RAM", "NOT_RAM", "MISALIGNED", "NOT_RAM", "NO_DCBAAP"};
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        scenario_a(&s);
        c = xhci_default();
        c.dcbaap = bad[i];
        soc_xhci(&s, 0, &c);
        if (run(&s, &r, &res, &o)) return 1;
        char want[32];
        snprintf(want, sizeof want, "SKIPPED=%s", why[i]);
        CHECK(strstr(r.line[find(&r, "STK P3 U0 SLOT")], want) != NULL);
        CHECK(s.ram_loads == 0 && res.verdict[0] == STK_V_CONNECTED);
    }
    /* Ring pointers outside RAM clear INRAM but the DCBAA, which is in RAM, is still followed. */
    c = xhci_default();
    scenario_a(&s);
    c.erstba = FORBIDDEN_BASE;
    soc_xhci(&s, 0, &c);
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(strstr(r.line[find(&r, "STK P3 U0 FWRINGS")], "INRAM=0") != NULL);
    CHECK(find(&r, "STK P3 U0 SLOT2") >= 0 && s.forbidden_loads == 0);
    c = xhci_default();
    scenario_a(&s);
    c.crcr = 0x1000;                                          /* an address in no descriptor */
    soc_xhci(&s, 0, &c);
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(strstr(r.line[find(&r, "STK P3 U0 FWRINGS")], "INRAM=0") != NULL);
    /* A zero CRCR (it reads back without its pointer on some controllers) does not clear INRAM. */
    c = xhci_default();
    scenario_a(&s);
    c.crcr = 0;
    soc_xhci(&s, 0, &c);
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(strstr(r.line[find(&r, "STK P3 U0 FWRINGS")], "INRAM=1") != NULL);
    /* RTSOFF is the device's word: the event ring registers are read inside the window or not at all
     * (a 32 bit sum would wrap into some register that is inside). */
    static const uint32_t rts[] = {0xffffffe0u, 0xfc0e0u, 0x7fffffe0u};
    for (unsigned i = 0; i < 3; i++) {
        c = xhci_default();
        scenario_a(&s);
        c.rtsoff = rts[i];
        soc_xhci(&s, 0, &c);
        if (run(&s, &r, &res, &o)) return 1;
        CHECK(strstr(r.line[find(&r, "STK P3 U0 FWRINGS")], "ERSTBA=? ERDP=? INRAM=1 SKIPPED=RANGE") != NULL);
    }

    /* Device contexts the DCBAA points at outside RAM, into firmware memory, or misaligned. */
    scenario_a(&s);
    uint64_t dcbaa = RAM_BASE + 0x1000;
    ram64(&s, dcbaa + 8, FORBIDDEN_BASE);
    ram64(&s, dcbaa + 16, RAM_BASE + 0x3010);
    ram64(&s, dcbaa + 24, 0x40);
    ram64(&s, dcbaa + 32, RAM_BASE + RAM_SIZE - 64);          /* the head fits; the endpoint contexts do not */
    ram32(&s, RAM_BASE + RAM_SIZE - 64, 31u << 27);
    if (run(&s, &r, &res, &o)) return 1;
    LOGICAL(&r, "STK P3 U0 SLOT1", "CTX=0X90000000 SKIPPED=NOT_RAM");
    LOGICAL(&r, "STK P3 U0 SLOT2", "CTX=0X80003010 SKIPPED=RANGE");
    LOGICAL(&r, "STK P3 U0 SLOT3", "CTX=0X40 SKIPPED=NOT_RAM MORESLOTS=1");
    CHECK(s.forbidden_loads == 0);
    CHECK(res.verdict[0] == STK_V_CONNECTED);

    /* 64 byte contexts (HCCPARAMS1.CSZ): the endpoint contexts are 64 bytes apart. */
    scenario_a(&s);
    c = xhci_default();
    c.hcc1 |= 4;
    soc_xhci(&s, 0, &c);
    ram64(&s, RAM_BASE + 0x1000 + 8, RAM_BASE + 0x6000);
    ram64(&s, RAM_BASE + 0x1000 + 16, 0);
    ram32(&s, RAM_BASE + 0x6000, 3u << 20 | 2u << 27);
    ram32(&s, RAM_BASE + 0x6004, 1u << 16);
    ram32(&s, RAM_BASE + 0x600c, 1 | 3u << 27);
    ram32(&s, RAM_BASE + 0x6000 + 64, 1);
    ram32(&s, RAM_BASE + 0x6004 + 64, 4 << 3 | 8 << 16);
    if (run(&s, &r, &res, &o)) return 1;
    LOGICAL(&r, "STK P3 U0 SLOT1", "CTX=0X80006000 ROUTE=0X0 HUB=0 ROOTPORT=1 SPEED=3 STATE=3 ADDR=1 EP1=1.4.0X8");
    CHECK(res.verdict[0] == STK_V_STICK_HALTED);
    return 0;
}

/* ---- SMMU ---- */

static int test_smmu(void)
{
    static struct soc s;
    static struct rec r;
    struct stk_result res;
    struct run_opts o = opts_default();

    /* Nothing is mapped to the stick's stream, USFCFG clear: transactions pass through. */
    scenario_a(&s);
    soc_reg(&s, SMMU_BASE + 0x800 + 4 * 3, 0);
    soc_reg(&s, SMMU_BASE + 0x800 + 4 * 5, 0);
    soc_reg(&s, SMMU_BASE + 0x00, 0);
    if (run(&s, &r, &res, &o)) return 1;
    LOGICAL(&r, "STK P3 SMMU S1420", "SMR=NONE TYPE=NONE CBNDX=NONE");
    LOGICAL(&r, "STK P3 SMMU S1460", "SMR=NONE TYPE=NONE CBNDX=NONE");
    CHECK(res.smmu == STK_SMMU_BYPASS);
    /* The same with USFCFG set: an unmatched stream faults. */
    soc_reg(&s, SMMU_BASE + 0x00, 0x400);
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(res.smmu == STK_SMMU_FAULT);
    /* An S2CR that says translate for the stick's stream, and fault. */
    scenario_a(&s);
    soc_reg(&s, SMMU_BASE + 0xc00 + 4 * 3, 0);
    soc_reg(&s, SMMU_BASE + 0xc00 + 4 * 3, 5);
    if (run(&s, &r, &res, &o)) return 1;
    LOGICAL(&r, "STK P3 SMMU S1420", "SMR=3 TYPE=TRANS CBNDX=5");
    CHECK(res.smmu == STK_SMMU_TRANS);
    soc_reg(&s, SMMU_BASE + 0xc00 + 4 * 3, 2u << 16);
    if (run(&s, &r, &res, &o)) return 1;
    LOGICAL(&r, "STK P3 SMMU S1420", "SMR=3 TYPE=FAULT CBNDX=0");
    CHECK(res.smmu == STK_SMMU_FAULT);
    /* Two entries match the stick's stream: a multi-match, reported and faulted. */
    scenario_a(&s);
    soc_reg(&s, SMMU_BASE + 0x800 + 4 * 6, 0x80000000u | 0x1420);
    if (run(&s, &r, &res, &o)) return 1;
    LOGICAL(&r, "STK P3 SMMU S1420", "SMR=3 TYPE=BYPASS CBNDX=0 MULTI=2");
    CHECK(res.smmu == STK_SMMU_FAULT);
    /* CLIENTPD: the SMMU is out of the way. */
    scenario_a(&s);
    soc_reg(&s, SMMU_BASE + 0x00, 0x401);
    soc_reg(&s, SMMU_BASE + 0xc00 + 4 * 3, 2u << 16);
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(res.smmu == STK_SMMU_BYPASS && strstr(r.line[find(&r, "STK P3 SMMU")], "CLIENTPD=1") != NULL);
    /* With no stick in sight both streams are judged: one translating stream is TRANS. */
    scenario_a(&s);
    soc_reg(&s, GCC_BASE + gcc[0].gdscr, 0x1);                  /* U0 off too */
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(res.verdict[0] == STK_V_GATED_OFF && res.smmu == STK_SMMU_TRANS);
    /* A block that is not an SMMU (all ones, what the bus returns for nothing): not read as one. */
    scenario_a(&s);
    soc_reg(&s, SMMU_BASE + 0x20, 0xffffffffu);
    soc_reg(&s, SMMU_BASE + 0x00, 0xffffffffu);
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(res.smmu == STK_SMMU_UNREAD);
    CHECK(strstr(r.line[find(&r, "STK P3 SMMU S1420")], "SKIPPED=NOT_SMMU") != NULL);
    {
        char smmu[256];                                       /* raw words kept, decoded fields not claimed */
        logical(&r, "STK P3 SMMU", smmu, sizeof smmu);
        CHECK(strstr(smmu, "ID0=0XFFFFFFFF NUMSMRG=? SCR0=0XFFFFFFFF USFCFG=? CLIENTPD=? EXID=? ") != NULL);
        CHECK(strstr(smmu, "SKIPPED=NOT_SMMU") != NULL);
    }
    CHECK(s.win_loads[STK_WIN_SMMU] == 3);                      /* only the three global registers */
    /* A scan of 255 entries is bounded by NUMSMRG's width. */
    scenario_a(&s);
    soc_reg(&s, SMMU_BASE + 0x20, 15u << 9 | 0xff);
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(s.win_loads[STK_WIN_SMMU] == 3 + 255 + 2);
    /* Extended stream ids: validity from the S2CR. */
    scenario_a(&s);
    soc_reg(&s, SMMU_BASE + 0x00, 0x408);
    soc_reg(&s, SMMU_BASE + 0x800 + 4 * 3, 0x1420);
    soc_reg(&s, SMMU_BASE + 0xc00 + 4 * 3, 1u << 10 | 1u << 16);
    if (run(&s, &r, &res, &o)) return 1;
    LOGICAL(&r, "STK P3 SMMU S1420", "SMR=3 TYPE=BYPASS CBNDX=0");
    return 0;
}

/* ---- Fault injection ---- */

static int test_fault_sweep(void)
{
    static struct soc s;
    static struct rec r, base;
    struct stk_result res, base_res;
    struct run_opts o = opts_default();

    scenario_b(&s);
    if (run(&s, &base, &base_res, &o)) return 1;
    unsigned total = s.loads;
    CHECK(total > 100 && total < 600);

    /* One load aborts, at each point in turn. */
    for (unsigned k = 0; k < total; k++) {
        scenario_b(&s);
        s.fault_at = (long)k;
        if (run(&s, &r, &res, &o)) { fprintf(stderr, "  (fault at load %u)\n", k); return 1; }
        CHECK(s.loads <= total);                              /* a fault never makes the survey read more */
        /* Every later block is still printed. */
        CHECK(find(&r, "STK NEXT MAP") >= 0 && find(&r, "STK NEXT GCC") >= 0);
        CHECK(find(&r, "STK NEXT SMMU") >= 0 && find(&r, "STK P3 SMMU S1420") >= 0 && find(&r, "STK P3 SMMU S1460") >= 0);
        CHECK(find(&r, "STK P3 GATE") >= 0);
        /* After an abort in a controller's window, that window is not read again; and a controller
         * whose own load aborted is not called anything but FAULT. */
        int window = s.trace[k].win;
        CHECK(s.trace[k].faulted);
        if (window == STK_WIN_U0 || window == STK_WIN_U1) {
            for (unsigned i = k + 1; i < s.ntrace; i++) CHECK(s.trace[i].win != window);
            CHECK(res.verdict[window - STK_WIN_U0] == STK_V_FAULT);
        } else if (window == STK_WIN_GCC) {
            /* A gate register that did not read: its controller cannot be ON. */
            CHECK(res.gate[0] != STK_GATE_ON || res.gate[1] != STK_GATE_ON);
            CHECK(res.verdict[0] == STK_V_FAULT || res.verdict[1] == STK_V_FAULT);
        } else if (window == STK_WIN_SMMU) {
            CHECK(res.smmu == STK_SMMU_UNREAD || res.smmu == STK_SMMU_FAULT || res.smmu == STK_SMMU_BYPASS ||
                  res.smmu == STK_SMMU_TRANS);
        } else if (window == 100) {
            /* A fault in a firmware structure belongs to the controller whose pointer it followed. */
            CHECK(res.verdict[0] == STK_V_FAULT || res.verdict[1] == STK_V_FAULT);
        }
        /* Everything a fault leaves is shown as FAULT=<register> or ?. */
        CHECK(count(&r, "STK P3 VERDICT") == 1);
    }

    /* Everything from one load on aborts (a block that stays dead). */
    for (unsigned k = 0; k < total; k += 3) {
        scenario_b(&s);
        s.fault_from = (long)k;
        if (run(&s, &r, &res, &o)) { fprintf(stderr, "  (persistent fault from load %u)\n", k); return 1; }
        CHECK(find(&r, "STK NEXT SMMU") >= 0 && find(&r, "STK P3 VERDICT") >= 0);
        CHECK(s.loads <= total);
    }
    /* Every window dead, one at a time: the others are still read and the survey reaches its verdict. */
    for (int w = 0; w < STK_WINDOWS; w++) {
        scenario_b(&s);
        s.fault_window = w;
        if (run(&s, &r, &res, &o)) return 1;
        CHECK(s.win_loads[w] <= (w == STK_WIN_GCC ? 6 + 6 + 4 : w == STK_WIN_SMMU ? 3 : 20));
        CHECK(find(&r, "STK NEXT SMMU") >= 0);
        if (w == STK_WIN_GCC) CHECK(res.verdict[0] == STK_V_FAULT && res.verdict[1] == STK_V_FAULT);
        if (w == STK_WIN_U0) CHECK(res.verdict[0] == STK_V_FAULT && res.verdict[1] == STK_V_CONNECTED);
        if (w == STK_WIN_U1) CHECK(res.verdict[1] == STK_V_FAULT && res.verdict[0] == STK_V_STICK_HALTED);
        if (w == STK_WIN_SMMU) CHECK(res.smmu == STK_SMMU_UNREAD && find(&r, "STK P3 SMMU S1420") >= 0);
    }
    /* DRAM dead: no firmware structure can be read. The controller whose slot walk aborts is FAULT; the
     * one with no DCBAA to follow is not affected; the SMMU is. */
    scenario_b(&s);
    s.fault_ram = 1;
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(res.verdict[0] == STK_V_FAULT && res.verdict[1] == STK_V_CONNECTED);
    CHECK(s.ram_loads == 1);                                  /* the DCBAA read aborted; no context was tried */
    CHECK(strstr(r.line[find(&r, "STK P3 U0 SLOT")], "FAULT=DCBAA") != NULL);
    CHECK(find(&r, "STK NEXT FWRINGS1") >= 0 && find(&r, "STK NEXT SMMU") >= 0);
    CHECK(res.smmu == STK_SMMU_TRANS);          /* 1420 bypasses, 1460 translates; the worse one is reported */
    return 0;
}

/* ---- Bounds ---- */

/* The worst case Appendix A allows: both controllers powered, four ports each, every slot in use with
 * more endpoints than a line can carry, a clock controller that is all off so its lines split, and the
 * longest P2 text there is. It must stay within 60 lines, keep the SMMU block and the verdict, and say
 * how many lines it dropped. */
static int test_worst_case(void)
{
    static struct soc s;
    static struct rec r;
    static struct stk_p2 p2;
    struct stk_result res;
    struct run_opts o = opts_default();
    struct xhci_cfg c = xhci_default();

    soc_reset(&s);
    soc_gcc(&s, 0, 1);
    soc_gcc(&s, 1, 1);
    soc_gcc_shared(&s, 1);
    c.ports = 4;
    for (unsigned i = 0; i < 4; i++) c.portsc[i] = 0xe03;
    soc_xhci(&s, 0, &c);
    soc_xhci(&s, 1, &c);
    uint64_t dcbaa = RAM_BASE + 0x1000;
    for (unsigned slot = 1; slot <= 8; slot++) {
        uint64_t ctx = RAM_BASE + 0x2000 + 0x1000u * slot;
        ram64(&s, dcbaa + 8 * slot, ctx);
        ram_slot(&s, ctx, slot, 3, slot == 1, 31, 1 + (slot & 3), slot, 3);
        for (unsigned dci = 1; dci <= 31; dci++) ram_ep(&s, ctx, dci, 1, 2 + dci % 6, 0x200);
    }
    soc_smmu(&s);
    /* The most P2 lines there are, each of the greatest length. */
    for (unsigned i = 0; i < STK_P2_MAX_LINES; i++) {
        memset(p2.line[i], 'X', STK_LINE_MAX);
        memcpy(p2.line[i], "STK P2 FILL ", 12);
        p2.line[i][STK_LINE_MAX] = 0;
    }
    p2.count = STK_P2_MAX_LINES;
    o.p2 = &p2;
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(r.n <= STK_MAX_LINES);
    CHECK(last_sink.dropped > 0);                             /* this much does not fit */
    int trunc = find(&r, "STK P3 TRUNC");
    char want[32];
    snprintf(want, sizeof want, "DROPPED=%u", last_sink.dropped);
    CHECK(trunc >= 0 && strstr(r.line[trunc], want) != NULL);
    /* What must not be lost: the SMMU block and the verdict, and the NEXT before the SMMU. */
    CHECK(find(&r, "STK NEXT SMMU") >= 0 && find(&r, "STK P3 SMMU") >= 0);
    CHECK(find(&r, "STK P3 SMMU S1420") >= 0 && find(&r, "STK P3 SMMU S1460") >= 0);
    CHECK(trunc < (int)r.n - 1 && starts(r.line[r.n - 1], "STK P3 VERDICT"));
    /* The first lines are the P2 text, replayed. */
    CHECK(!strncmp(r.line[0], "STK P2 FILL XXX", 15));
    /* Never more than four ports and three slots per controller, whatever the budget did. */
    CHECK(find(&r, "STK P3 U0 PORT5") < 0 && find(&r, "STK P3 U0 SLOT4") < 0);
    CHECK(find(&r, "STK P3 U1 PORT5") < 0 && find(&r, "STK P3 U1 SLOT4") < 0);
    /* With a P2 of ordinary length the first controller prints whole: the scan reads at most 8 slots
     * and shows 3, and four ports, with the rest of the slots counted. */
    p2.count = 6;
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(find(&r, "STK P3 U0 PORT4") >= 0 && find(&r, "STK P3 U0 PORT5") < 0);
    CHECK(find(&r, "STK P3 U0 SLOT3") >= 0 && find(&r, "STK P3 U0 SLOT4") < 0);
    char slot3[512];
    logical(&r, "STK P3 U0 SLOT3", slot3, sizeof slot3);
    CHECK(strstr(slot3, "MORE=25") != NULL && strstr(slot3, "MORESLOTS=5") != NULL);   /* 31 endpoints, 6 shown; 8 slots, 3 shown */
    CHECK(s.ram_loads <= 2 * (1 + 8 * (1 + 31)));
    return 0;
}

/* Without the worst case, the lines the page holds are within the cap with room to spare. */
static int test_typical_size(void)
{
    static struct soc s;
    static struct rec r;
    struct stk_result res;
    struct run_opts o = opts_default();
    static struct stk_p2 p2;
    scenario_b(&s);
    snprintf(p2.line[0], sizeof p2.line[0], "STK P2 BUILD GATE=1 REV=CE219120");
    snprintf(p2.line[1], sizeof p2.line[1], "STK P2 SELF PATH=PCI(81.0)/USB(1.0)/USB(2.0)/HD(1.MBR)");
    p2.count = 2;
    o.p2 = &p2;
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(last_sink.dropped == 0 && r.n <= 50);
    CHECK(!strcmp(r.line[0], "STK P2 BUILD GATE=1 REV=CE219120"));
    CHECK(!strncmp(r.line[1], "STK P2 SELF PATH=PCI(81.0)", 26));
    CHECK(find(&r, "STK P3 TRUNC") < 0);
    return 0;
}

/* The read budget of the whole survey is a backstop of its own. */
static int test_read_budget(void)
{
    static struct soc s;
    static struct rec r;
    struct stk_result res;
    struct run_opts o = opts_default();
    scenario_b(&s);
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(res.reads == s.loads && res.faults == 0 && res.refusals == 0);
    /* A register file that never stops asking for more is cut off: ports 255 with a slot walk as
     * long as the architecture allows, and extended capabilities that never end. */
    scenario_b(&s);
    struct xhci_cfg c = xhci_default();
    c.ports = 255;
    c.hcc1 = 0x00010001;                                      /* the first capability at dword 1 */
    c.caps = 0;
    soc_xhci(&s, 0, &c);
    for (unsigned off = 4; off < 0x1000; off += 4) soc_reg(&s, U0_BASE + off, 0x00000101u);   /* id 1, next 1: endless */
    soc_reg(&s, U0_BASE + 0x04, 255u | 255u << 24);
    soc_reg(&s, U0_BASE + 0x10, 0x00010001);
    if (run(&s, &r, &res, &o)) return 1;
    CHECK(s.loads < 400);
    CHECK(count(&r, "STK P3 U0 PORT1") + count(&r, "STK P3 U0 PORT2") + count(&r, "STK P3 U0 PORT3") +
          count(&r, "STK P3 U0 PORT4") <= 4 && find(&r, "STK P3 U0 PORT5") < 0);
    return 0;
}

/* ---- Run all ---- */

static const struct { const char *name; int (*fn)(void); } suites[] = {
    {"golden", test_golden}, {"both", test_both_controllers}, {"verdicts", test_verdicts},
    {"windows", test_windows_refused}, {"pointers", test_pointers}, {"smmu", test_smmu},
    {"fault-sweep", test_fault_sweep}, {"worst-case", test_worst_case}, {"typical", test_typical_size},
    {"budget", test_read_budget},
};

int main(int argc, char **argv)
{
    alarm(120);                                 /* a survey that loops fails by the clock, never hangs the run */
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], suites[i].name) && strcmp(argv[1], "all")) continue;
        unsigned before = checks;
        if (suites[i].fn()) {
            fprintf(stderr, "FAIL: suite %s\n", suites[i].name);
            return 1;
        }
        printf("PASS %-12s %u checks\n", suites[i].name, checks - before);
        ran++;
    }
    if (!ran) { fprintf(stderr, "no suite named %s\n", argc > 1 ? argv[1] : "(none)"); return 2; }
    printf("PASS: %u stick-log survey EL2 suites, %u checks\n", ran, checks);
    return 0;
}
