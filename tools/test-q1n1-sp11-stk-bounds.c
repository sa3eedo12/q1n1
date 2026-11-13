/* SPDX-License-Identifier: MIT */
/* Native tests for the bounds of the stick-log survey's firmware-structure walk and of its P2 text:
 * the walk over the device context base address array and the device contexts the firmware left
 * (sp11-stk-rules.c, stk_slot_walk) with every pointer outside RAM, misaligned or faulting, and the
 * most lines the P2 formatters can ever print (sp11-stk-p2fmt.c) against the keeper's size. The rest
 * of the pure logic is in test-q1n1-sp11-stk.c; the EL2 sequencer and the P2 queries have their own
 * programs. All are driven by tools/test-q1n1-sp11-stk.py under ASan and UBSan.
 *
 * None of this runs on a Surface Pro 11: evidence EXPERIMENTAL, host model only, hardware NOT RUN. */
#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_STK_SURVEY 1
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

/* ---- slot walk ------------------------------------------------------------------------------------ */

struct fake_ram {
    uint64_t base;
    uint8_t mem[0x10000];
    uint64_t not_ram_lo, not_ram_hi;       /* a range the callback refuses, the way the map would */
    unsigned reads, refused;
    int fault_at;
};
static int ram_read(void *ctx, uint64_t phys, void *dst, uint32_t size)
{
    struct fake_ram *r = ctx;
    if (phys < r->base || phys - r->base > sizeof r->mem || sizeof r->mem - (phys - r->base) < size ||
        (phys < r->not_ram_hi && phys + size > r->not_ram_lo)) {
        r->refused++;
        return STK_E_NOT_RAM;
    }
    if ((int)r->reads == r->fault_at) { r->reads++; return STK_E_FAULT; }
    r->reads++;
    memcpy(dst, r->mem + (phys - r->base), size);
    return STK_OK;
}
static void ram_put32(struct fake_ram *r, uint64_t addr, uint32_t v) { memcpy(r->mem + (addr - r->base), &v, 4); }
static void ram_put64(struct fake_ram *r, uint64_t addr, uint64_t v) { memcpy(r->mem + (addr - r->base), &v, 8); }

static int test_slots(void)
{
    struct stk_slots sw;
    static struct fake_ram r;
    memset(&r, 0, sizeof r);
    r.base = 0x80000000; r.fault_at = -1; r.not_ram_lo = r.not_ram_hi = 0;
    uint64_t dcbaa = r.base + 0x1000;
    /* Slot 1: a hub, one endpoint besides the default control one. Slot 3: a device behind it. */
    ram_put64(&r, dcbaa + 8 * 1, r.base + 0x2000);
    ram_put64(&r, dcbaa + 8 * 3, r.base + 0x3000);
    ram_put32(&r, r.base + 0x2000, 1 << 26 | 3 << 20 | 3 << 27);     /* hub, high speed, 3 context entries */
    ram_put32(&r, r.base + 0x2004, 1 << 16);                         /* root port 1 */
    ram_put32(&r, r.base + 0x200c, 3u << 27 | 1);                    /* configured, address 1 */
    ram_put32(&r, r.base + 0x2000 + 32 * 1, 1);                      /* EP0: running */
    ram_put32(&r, r.base + 0x2004 + 32 * 1, 4 << 3 | 64 << 16);      /* control, 64 bytes */
    ram_put32(&r, r.base + 0x2000 + 32 * 3, 1);                      /* DCI 3: running */
    ram_put32(&r, r.base + 0x2004 + 32 * 3, 7 << 3 | 2 << 16);       /* interrupt IN, 2 bytes */
    ram_put32(&r, r.base + 0x3000, 0x2 | 3 << 20 | 4 << 27);         /* route 2, high speed, 4 entries */
    ram_put32(&r, r.base + 0x3004, 1 << 16);
    ram_put32(&r, r.base + 0x300c, 3u << 27 | 2);
    ram_put32(&r, r.base + 0x3000 + 32 * 1, 1);
    ram_put32(&r, r.base + 0x3004 + 32 * 1, 4 << 3 | 64 << 16);
    ram_put32(&r, r.base + 0x3000 + 32 * 3, 1);
    ram_put32(&r, r.base + 0x3004 + 32 * 3, 6 << 3 | 512 << 16);    /* bulk IN */
    ram_put32(&r, r.base + 0x3000 + 32 * 4, 1);
    ram_put32(&r, r.base + 0x3004 + 32 * 4, 2 << 3 | 512 << 16);    /* bulk OUT */
    stk_slot_walk(ram_read, &r, dcbaa, 8, 32, &sw);
    CHECK(sw.status == STK_OK && sw.scanned == 8 && sw.nonempty == 2 && sw.shown == 2);
    CHECK(sw.slot_id[0] == 1 && sw.slot_id[1] == 3);
    CHECK(sw.slot[0].ctx == r.base + 0x2000 && sw.slot[0].hub == 1 && sw.slot[0].speed == 3 &&
          sw.slot[0].root_port == 1 && sw.slot[0].state == 3 && sw.slot[0].address == 1 && sw.slot[0].route == 0);
    CHECK(sw.slot[0].eps == 2 && sw.slot[0].shown == 2 && sw.slot[0].ep[0].dci == 1 && sw.slot[0].ep[1].dci == 3);
    CHECK(sw.slot[0].ep[1].type == 7 && sw.slot[0].ep[1].mps == 2 && sw.slot[0].ep[1].state == 1);
    CHECK(sw.slot[1].route == 2 && sw.slot[1].hub == 0 && sw.slot[1].address == 2 && sw.slot[1].eps == 3);
    CHECK(sw.slot[1].ep[1].type == 6 && sw.slot[1].ep[1].mps == 512 && sw.slot[1].ep[2].type == 2);
    /* 64 byte contexts: the endpoint contexts move. */
    {
        static struct fake_ram big;
        memset(&big, 0, sizeof big);
        big.base = 0x80000000; big.fault_at = -1;
        ram_put64(&big, big.base + 0x1000 + 8, big.base + 0x2000);
        ram_put32(&big, big.base + 0x2000, 3 << 20 | 1 << 27);
        ram_put32(&big, big.base + 0x2000 + 64, 1);
        ram_put32(&big, big.base + 0x2004 + 64, 4 << 3 | 8 << 16);
        stk_slot_walk(ram_read, &big, big.base + 0x1000, 8, 64, &sw);
        CHECK(sw.status == STK_OK && sw.shown == 1 && sw.slot[0].eps == 1 && sw.slot[0].ep[0].mps == 8);
        stk_slot_walk(ram_read, &big, big.base + 0x1000, 8, 48, &sw);   /* not a size an xHC has */
        CHECK(sw.status == STK_E_RANGE);
    }

    /* The scan covers at most STK_SLOTS_SCANNED entries however many slots the controller has. */
    unsigned before = r.reads;
    stk_slot_walk(ram_read, &r, dcbaa, 255, 32, &sw);
    CHECK(sw.scanned == STK_SLOTS_SCANNED && sw.status == STK_OK);
    CHECK(r.reads - before <= 1 + 2 * (1 + 31));
    /* A misaligned DCBAAP is refused before any read. */
    before = r.reads;
    stk_slot_walk(ram_read, &r, dcbaa + 8, 8, 32, &sw);
    CHECK(sw.status == STK_E_RANGE && r.reads == before);

    /* Pointers outside RAM: below it, past it, into a range the callback refuses, misaligned, and a
     * context whose endpoint contexts would run off the end of RAM. None is loaded through. */
    r.not_ram_lo = r.base + 0x8000; r.not_ram_hi = r.base + 0x9000;
    memset(r.mem + 0x1000, 0, 0x100);
    ram_put64(&r, dcbaa + 8 * 1, 0x40);                               /* nowhere near RAM */
    ram_put64(&r, dcbaa + 8 * 2, r.base + sizeof r.mem + 0x100);     /* past the end */
    ram_put64(&r, dcbaa + 8 * 3, r.base + 0x8000);                    /* the refused range */
    ram_put64(&r, dcbaa + 8 * 4, r.base + 0x2010);                    /* not 64 byte aligned */
    ram_put64(&r, dcbaa + 8 * 5, r.base + sizeof r.mem - 64);        /* head fits, endpoints do not */
    ram_put32(&r, r.base + sizeof r.mem - 64, 3 << 27);              /* claims 3 endpoint contexts */
    stk_slot_walk(ram_read, &r, dcbaa, 8, 32, &sw);
    CHECK(sw.status == STK_OK && sw.nonempty == 5 && sw.shown == STK_SLOTS_SHOWN);
    CHECK(sw.slot[0].err == STK_E_NOT_RAM && sw.slot[1].err == STK_E_NOT_RAM && sw.slot[2].err == STK_E_NOT_RAM);
    CHECK(sw.slot_id[0] == 1 && sw.slot_id[2] == 3);
    /* Only the first three non-empty entries are decoded; the walk kept counting the others. */
    memset(r.mem + 0x1000, 0, 0x100);
    ram_put64(&r, dcbaa + 8 * 4, r.base + 0x2010);
    ram_put64(&r, dcbaa + 8 * 5, r.base + sizeof r.mem - 64);
    stk_slot_walk(ram_read, &r, dcbaa, 8, 32, &sw);
    CHECK(sw.nonempty == 2 && sw.shown == 2 && sw.slot[0].err == STK_E_RANGE);
    CHECK(sw.slot[1].err == STK_OK && sw.slot[1].entries == 3 && sw.slot[1].eps == 0);   /* its endpoints were refused */
    /* The DCBAA itself outside RAM: the walk stops with that error. */
    stk_slot_walk(ram_read, &r, 0x40, 8, 32, &sw);
    CHECK(sw.status == STK_E_NOT_RAM && sw.shown == 0);
    /* A fault at each read ends the walk and nothing is read after it. */
    memset(r.mem + 0x1000, 0, 0x100);
    ram_put64(&r, dcbaa + 8 * 1, r.base + 0x2000);
    for (int at = 0; at < 5; at++) {                                  /* the DCBAA, the head, three endpoint contexts */
        r.reads = 0; r.fault_at = at;
        stk_slot_walk(ram_read, &r, dcbaa, 8, 32, &sw);
        CHECK(sw.status == STK_E_FAULT && r.reads == (unsigned)at + 1);
    }
    return 0;
}

/* ---- P2 line bound ----------------------------------------------------------------------------------- */

struct run {
    char con[40][STK_LINE_MAX + 8];
    unsigned n_con, bad, lines;
};
static void con_emit(void *ctx, const char *line)
{
    struct run *r = ctx;
    r->lines++;
    if (strlen(line) > STK_LINE_MAX || !stk_text_ok(line) || strncmp(line, "STK P2 ", 7)) r->bad++;
    if (r->n_con < 40) {
        snprintf(r->con[r->n_con], sizeof r->con[0], "%s", line);
        r->n_con++;
    }
}

static void put_node(uint8_t *path, unsigned *n, unsigned type, unsigned sub, const void *body, unsigned body_len)
{
    unsigned len = 4 + body_len;
    path[*n] = (uint8_t)type; path[*n + 1] = (uint8_t)sub;
    path[*n + 2] = (uint8_t)len; path[*n + 3] = (uint8_t)(len >> 8);
    if (body_len) memcpy(path + *n + 4, body, body_len);
    *n += len;
}

static int test_bounds(void)
{
    /* The longest the formatters can ever be: every field at its widest, a path with six USB nodes
     * and a hard drive node, three controllers shown of an enormous number. */
    struct run c;
    struct stk_sink sink = {con_emit, NULL, &c, 0, 0};
    struct stk_dp_info dp;
    struct stk_p2_media media = {1, UINT64_MAX, UINT32_MAX, 1, 1};
    struct stk_p2_usbio io = {1, 0xffff, 0xff, 0xff, 0xff, 1, 1, 0xff, 0xff, 0xffff, 0xfffe};
    struct stk_p2_hc hc[STK_P2_HC_SHOWN];
    struct stk_p2_baseline b = {1, NULL, 0, STK_P2_PORT2_READ, 0xff, 0xffffffffu, 0xffffffffu, 0xffffffffu,
                                0xffffffffu, UINT64_MAX, UINT64_MAX};
    uint8_t path[600], ff2[2] = {0xff, 0xff}, acpi[8] = {0xd0, 0x41, 0x03, 0x0a, 0, 0, 0, 0}, hd[38];
    unsigned n = 0;

    memset(&c, 0, sizeof c);
    memset(hd, 0xff, sizeof hd);
    put_node(path, &n, 2, 1, acpi, 8);
    put_node(path, &n, 1, 1, ff2, 2);
    for (unsigned i = 0; i < 6; i++) put_node(path, &n, 3, 5, ff2, 2);
    put_node(path, &n, 4, 1, hd, 38);
    put_node(path, &n, 0x7f, 0xff, NULL, 0);
    stk_dp_walk(path, n, &dp);
    for (unsigned i = 0; i < STK_P2_HC_SHOWN; i++) {
        hc[i].pci_io = 1; hc[i].bar_ok = hc[i].class_ok = hc[i].loc_ok = 1;
        hc[i].bar0 = UINT64_MAX; hc[i].class_code = 0xffffffu;
        hc[i].seg = hc[i].bus = hc[i].dev = hc[i].fn = UINT64_MAX;
    }
    stk_p2_fmt_build(&sink, "ffffffff");
    stk_p2_fmt_self(&sink, &dp);
    stk_p2_fmt_hub(&sink, &dp);
    stk_p2_fmt_blk(&sink, &media, &dp);
    stk_p2_fmt_usbio(&sink, &io, NULL);
    stk_p2_fmt_hc(&sink, 0xffffffffu, hc, STK_P2_HC_SHOWN);
    stk_p2_fmt_baseline(&sink, &b);
    CHECK(c.bad == 0);
    /* STK_P2_MAX_LINES is the proven maximum, not a guess: with every field at its widest the
     * formatters print exactly that many lines, so the keeper never has to drop one. */
    CHECK(c.lines == STK_P2_MAX_LINES);

    /* The replay says so when the keeper lost lines. */
    {
        static struct stk_p2 kept;
        struct run r;
        struct stk_sink out = {con_emit, NULL, &r, 0, 0};
        memset(&r, 0, sizeof r);
        memset(&kept, 0, sizeof kept);
        for (unsigned i = 0; i < STK_P2_MAX_LINES; i++) snprintf(kept.line[i], sizeof kept.line[i], "STK P2 FILL N=%u", i);
        kept.count = STK_P2_MAX_LINES;
        stk_p2_replay(&out, &kept);
        CHECK(r.n_con == STK_P2_MAX_LINES && r.bad == 0);
        kept.dropped = 3;
        memset(&r, 0, sizeof r);
        memset(&out, 0, sizeof out);
        out.emit = con_emit;
        out.ctx = &r;
        stk_p2_replay(&out, &kept);
        CHECK(r.n_con == STK_P2_MAX_LINES + 1 && !strcmp(r.con[STK_P2_MAX_LINES], "STK P2 DROPPED N=3"));
        stk_p2_replay(&out, NULL);                              /* no P2 at all is fine */
    }
    return 0;
}

static const struct { const char *name; int (*fn)(void); } suites[] = {
    {"slots", test_slots}, {"p2-bounds", test_bounds},
};

int main(int argc, char **argv)
{
    alarm(60);
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], suites[i].name) && strcmp(argv[1], "all")) continue;
        unsigned before = checks;
        if (suites[i].fn()) {
            fprintf(stderr, "FAIL: suite %s\n", suites[i].name);
            return 1;
        }
        printf("PASS %-13s %u checks\n", suites[i].name, checks - before);
        ran++;
    }
    if (!ran) { fprintf(stderr, "no suite named %s\n", argc > 1 ? argv[1] : "(none)"); return 2; }
    printf("PASS: %u stick-log survey bounds suites, %u checks\n", ran, checks);
    return 0;
}
