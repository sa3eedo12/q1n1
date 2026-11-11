/* SPDX-License-Identifier: MIT */
/* Lifecycle model for platform/uefi/usb-ports.c built with SNAP_PLATFORM_SP11: the real manager, mocked controller
 * drivers, a table instead of the A16's hard-coded bases. HOST MODEL ONLY: it says nothing about a Surface Pro 11.
 *
 * What it pins: the manager takes each controller's base and glue offset from the table and touches nothing else (in
 * particular neither A16 base unless the table lists it); a table that fails its own rules is refused before any
 * register is read; controllers are judged by IP family and xHCI limits, not by A16 equalities; host-only ports never
 * take the device role and are not reset while they wait for a cable; shared state is not adopted across platforms or
 * across a table change without stopping the old controller. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "usb-ports.h"
#include "sp11-usb-ports.h"

#define WINDOW 0x200000u
#define CHECK(x) do { assert(x); checks++; } while (0)
static unsigned checks;

struct model {
    uintptr_t base;
    unsigned partner, dtr, halt_failure, writes, reads, halts;
    unsigned device_starts, host_starts, opens, rebinds;
    uint32_t gsnpsid, cap, hcs1, gctl, dctl, cmd, status;
    uintptr_t last_qscratch;
    uint8_t input[32];
    unsigned head, tail;
} model[4];
static struct q1n1_sp11_usb_table table;
static unsigned stray, a16_touch, allow_a16;
static uint64_t now;
static void *arena;

const struct q1n1_sp11_usb_table *q1n1_sp11_usb_table_get(void) { return &table; }

static int find(uintptr_t address)
{
    for (unsigned i = 0; i < 4; i++)
        if (model[i].base && address >= model[i].base && address < model[i].base + WINDOW) return (int)i;
    stray++;
    if (!allow_a16 && ((address >= 0x0a600000 && address < 0x0a600000 + WINDOW) ||
                       (address >= 0x0a800000 && address < 0x0a800000 + WINDOW)))
        a16_touch++;
    return -1;
}
uint64_t xhci_now_us(void) { return now; }
void qdwc3_delay_us(uint64_t us) { now += us; }
uint32_t qdwc3_rd(uintptr_t address)
{
    int k = find(address);
    if (k < 0) return 0;
    struct model *m = &model[k];
    m->reads++;
    uintptr_t offset = address - m->base, op = m->cap & 0xff;   /* operational registers follow CAPLENGTH */
    if (offset == op) return m->cmd;
    if (offset == op + 4) return m->status;
    switch (offset) {
    case 0: return m->cap;
    case 4: return m->hcs1;
    case 0xc110: return m->gctl;
    case 0xc120: return m->gsnpsid;
    case 0xc704: return m->dctl;
    case 0xc70c: return (m->dctl & (1u << 31)) ? 0 : (1u << 22);
    default: return 0;
    }
}
void qdwc3_wr(uintptr_t address, uint32_t value)
{
    int k = find(address);
    if (k < 0) return;
    struct model *m = &model[k];
    m->writes++;
    uintptr_t offset = address - m->base;
    if (offset == (m->cap & 0xff)) {
        m->cmd = value;
        if (!(value & 1)) m->halts++;
        if (!m->halt_failure) m->status = (value & 1) ? 0 : 1;
        return;
    }
    switch (offset) {
    case 0xc110: m->gctl = value; break;
    case 0xc704: m->dctl = value; break;
    default: break;
    }
}
int qdwc3_takeover(struct qdwc3 *d, uintptr_t base, uintptr_t qs, const struct qdwc3_saved *saved,
                   uint8_t *dma, uint64_t size)
{
    int k = find(base);
    assert(k >= 0 && ((model[k].gctl >> 12) & 3) == 2 && size == QDWC3_ARENA_SIZE);
    assert(dma >= (uint8_t *)arena && dma + size <= (uint8_t *)arena + Q1N1_USB_ARENA_SIZE);
    memset(d, 0, sizeof(*d));
    d->regs = base; d->qscratch = qs; d->saved = saved; d->arena = dma;
    d->stats.init_step = 8;
    model[k].last_qscratch = qs;
    model[k].dctl = 1u << 31;
    model[k].device_starts++;
    return 0;
}
void qdwc3_poll(struct qdwc3 *d) { if (model[find(d->regs)].partner == Q1N1_USB_HOST) d->stats.configured = 1; }
int qdwc3_link_down(const struct qdwc3 *d) { return model[find(d->regs)].partner != Q1N1_USB_HOST; }
int qdwc3_ready(const struct qdwc3 *d, unsigned pipe) { return !pipe && d->stats.configured && model[find(d->regs)].dtr; }
void qdwc3_stop(struct qdwc3 *d) { model[find(d->regs)].dctl = 0; }
static size_t input(unsigned i, uint8_t *buffer, size_t count)
{
    struct model *m = &model[i];
    size_t got = 0;
    while (got < count && m->tail < m->head) buffer[got++] = m->input[m->tail++];
    return got;
}
size_t qdwc3_read(struct qdwc3 *d, unsigned pipe, uint8_t *b, size_t n)
{ return pipe ? 0 : input((unsigned)find(d->regs), b, n); }
size_t qdwc3_write(struct qdwc3 *d, unsigned pipe, const uint8_t *b, size_t n)
{ (void)d; (void)pipe; (void)b; return n; }
int xhci_init(struct xhci *x, uintptr_t base, uint8_t *dma, uint64_t size)
{
    int k = find(base);
    assert(k >= 0 && ((model[k].gctl >> 12) & 3) == 1);
    assert(dma >= (uint8_t *)arena && dma + size <= (uint8_t *)arena + Q1N1_USB_ARENA_SIZE);
    memset(x, 0, sizeof(*x));
    x->base = base; x->max_ports = 2; x->dma = dma; x->stats.init_step = 4;
    model[k].status = 0; model[k].cmd = 1; model[k].host_starts++;
    return 0;
}
uint32_t xhci_portsc(struct xhci *x, uint32_t port)
{ return port == 1 && model[find(x->base)].partner == Q1N1_USB_DEVICE ? 0xe03 : 0x2a0; }
int xhci_running(struct xhci *x) { return model[find(x->base)].cmd & 1; }
int ncm_open(struct ncm *n, struct xhci *x, uint32_t which, uint32_t wait)
{
    (void)which; (void)wait;
    memset(n, 0, sizeof(*n)); n->x = x; n->stats.init_step = 9;
    n->device.port = 1; n->device.slot = 1;
    model[find(x->base)].opens++;
    return 0;
}
void ncm_close(struct ncm *n) { n->x = NULL; }
static int net_ready(void *ctx) { return ((struct ncm_proxy *)ctx)->have_peer; }
static void net_poll(void *ctx) { (void)ctx; }
static size_t net_read(void *ctx, uint8_t *b, size_t n)
{ return input((unsigned)find(((struct ncm_proxy *)ctx)->n->x->base), b, n); }
static size_t net_write(void *ctx, const uint8_t *b, size_t n)
{ (void)ctx; (void)b; return n; }
void ncm_attach_batch(struct ncm *n, uint8_t *buffer, uint32_t size) { (void)n; (void)buffer; (void)size; }
void ncm_attach_side(struct ncm *n, uint8_t *buffer, uint32_t size) { (void)n; (void)buffer; (void)size; }
void ncm_proxy_rebind(struct ncm_proxy *p, struct ncm *n)
{
    p->n = n;
    p->io = (struct q1n1_io){.read = net_read, .write = net_write, .ready = net_ready, .poll = net_poll, .ctx = p};
    model[find(n->x->base)].rebinds++;
}
void ncm_proxy_init(struct ncm_proxy *p, struct ncm *n, uint64_t timeout)
{ (void)timeout; memset(p, 0, sizeof(*p)); ncm_proxy_rebind(p, n); p->have_peer = 1; }
void ncm_proxy_announce(struct ncm_proxy *p) { (void)p; }
void ncm_proxy_call_poll(struct ncm_proxy *p) { (void)p; }

static struct q1n1_sp11_usb_table make_table(uint64_t b0, uint64_t b1, uint32_t flags, uint32_t qscratch)
{
    struct q1n1_sp11_usb_table t;
    memset(&t, 0, sizeof(t));
    t.magic = Q1N1_SP11_USB_MAGIC; t.version = Q1N1_SP11_USB_VERSION; t.count = 2;
    t.port[0] = (struct q1n1_sp11_usb_port){.dwc3_base = b0, .window_size = 0xfd000, .qscratch_offset = qscratch, .flags = flags};
    t.port[1] = (struct q1n1_sp11_usb_port){.dwc3_base = b1, .window_size = 0xfd000, .qscratch_offset = qscratch, .flags = flags};
    return t;
}
static void reset_models(unsigned a, unsigned b)
{
    memset(arena, 0, Q1N1_USB_ARENA_SIZE); memset(model, 0, sizeof(model));
    now = 1; stray = a16_touch = 0;
    for (unsigned i = 0; i < 2; i++) {
        model[i].base = (uintptr_t)table.port[i].dwc3_base;
        model[i].gsnpsid = 0x5533330a; model[i].cap = 0x01100020; model[i].hcs1 = 0x02000040;
        model[i].gctl = 0x102001; model[i].status = 1; model[i].dtr = 1;
    }
    model[0].partner = a; model[1].partner = b;
}
static struct q1n1_usb_ports *start(unsigned a, unsigned b)
{
    reset_models(a, b);
    return q1n1_usb_ports_init(arena, Q1N1_USB_ARENA_SIZE, 0);
}
static void advance(struct q1n1_usb_ports *s, uint64_t us) { now += us; q1n1_usb_ports_poll(s); }
static void settle(struct q1n1_usb_ports *s) { for (unsigned n = 0; n < 50; n++) advance(s, 100000); }
static unsigned all_reads(void) { return model[0].reads + model[1].reads + stray; }
static unsigned all_writes(void) { return model[0].writes + model[1].writes; }

int main(void)
{
    assert(!posix_memalign(&arena, 0x10000, Q1N1_USB_ARENA_SIZE));
    const uint32_t host_only = Q1N1_SP11_USB_PORT_HOST_ONLY;
    struct q1n1_sp11_usb_table a = make_table(0x0c000000, 0x0c200000, host_only, 0xf8800);
    struct q1n1_sp11_usb_table b = make_table(0x0d000000, 0x0d200000, host_only, 0xf9000);
    extern const uint64_t q1n1_usb_ports_contract[3];
    CHECK(q1n1_usb_ports_contract[1] == 2);          /* not the A16's version 1: stages never adopt across platforms */

    /* A table that fails its own rules is refused before any register is read or any state is written. */
    struct q1n1_sp11_usb_table bad[6];
    for (unsigned i = 0; i < 6; i++) bad[i] = a;
    bad[0].magic ^= 1;
    bad[1].count = 0;
    bad[2].port[0].dwc3_base = 0x0a600000;           /* an A16 base without the independent-listing flag */
    bad[3].port[1].dwc3_base = bad[3].port[0].dwc3_base + 0x1000;   /* overlap */
    bad[4].port[0].qscratch_offset = 0x1000;
    bad[5].version = 9;
    for (unsigned i = 0; i < 6; i++) {
        table = bad[i];
        reset_models(0, 0);
        table = bad[i];
        for (unsigned k = 0; k < 2; k++) model[k].base = (uintptr_t)a.port[k].dwc3_base;
        CHECK(q1n1_usb_ports_init(arena, Q1N1_USB_ARENA_SIZE, 0) == NULL);
        CHECK(all_reads() == 0 && all_writes() == 0);
        CHECK(((uint64_t *)arena)[0] == 0);
    }

    /* Valid table, bases that are nobody's A16 constants: the manager follows the table and only the table. */
    table = a;
    struct q1n1_usb_ports *s = start(Q1N1_USB_DEVICE, 0);
    CHECK(s && s->port[0].base == 0x0c000000 && s->port[1].base == 0x0c200000);
    CHECK(s->port[0].qscratch == 0x0c000000 + 0xf8800 && s->port[1].qscratch == 0x0c200000 + 0xf8800);
    CHECK(s->status[0].base == 0x0c000000 && s->status[1].base == 0x0c200000);
    settle(s);
    CHECK(s->status[0].role == Q1N1_USB_HOST && s->status[0].connected && model[0].opens == 1);
    CHECK(stray == 0 && a16_touch == 0);
    table = b;
    s = start(Q1N1_USB_DEVICE, Q1N1_USB_DEVICE);
    CHECK(s->port[0].qscratch == 0x0d000000 + 0xf9000 && s->port[1].qscratch == 0x0d200000 + 0xf9000);
    settle(s);
    CHECK(s->status[0].connected && s->status[1].connected && stray == 0 && a16_touch == 0);

    /* The real Denali bases are accepted only with the independent-listing flag, and then they are used. */
    table = make_table(0x0a600000, 0x0a800000, host_only | Q1N1_SP11_USB_PORT_A16_BASE_LISTED, 0xf8800);
    allow_a16 = 1;
    s = start(Q1N1_USB_DEVICE, 0);
    CHECK(s && s->port[0].base == 0x0a600000 && s->port[1].base == 0x0a800000);
    settle(s);
    CHECK(s->status[0].connected && stray == 0);
    allow_a16 = 0;

    /* Identity is judged by IP family and xHCI limits; the A16's exact values are not required or relied on. */
    table = a;
    reset_models(0, Q1N1_USB_DEVICE);
    model[0].gsnpsid = 0x33313130;                   /* the A16's core id is a valid DWC3 family here too */
    s = q1n1_usb_ports_init(arena, Q1N1_USB_ARENA_SIZE, 0);
    settle(s);
    CHECK(s->status[0].role == Q1N1_USB_HOST && s->status[1].connected);
    const struct { uint32_t gsnpsid, cap, hcs1; } refused[] = {
        {0x12345678, 0x01100020, 0x02000040},        /* not a DWC3 family */
        {0, 0x01100020, 0x02000040},                 /* a gated block reads zero */
        {0xffffffff, 0xffffffff, 0xffffffff},        /* or all ones */
        {0x5533330a, 0x0110001c, 0x02000040},        /* CAPLENGTH below the capability block */
        {0x5533330a, 0x00ff0020, 0x02000040},        /* xHCI older than 1.0 */
        {0x5533330a, 0x01100020, 0x00000040},        /* no ports */
    };
    for (unsigned i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        reset_models(0, Q1N1_USB_DEVICE);
        model[0].gsnpsid = refused[i].gsnpsid; model[0].cap = refused[i].cap; model[0].hcs1 = refused[i].hcs1;
        s = q1n1_usb_ports_init(arena, Q1N1_USB_ARENA_SIZE, 0);
        settle(s);
        CHECK(s->status[0].role == Q1N1_USB_UNSUPPORTED && model[0].writes == 0 && model[0].host_starts == 0);
        CHECK(s->status[1].connected);               /* the other controller is unaffected */
    }
    table = a; table.port[0].expect_gsnpsid = 0x5533330a;
    reset_models(0, 0);
    model[0].gsnpsid = 0x5533330b;                   /* a family match is not enough once the exact id is pinned */
    s = q1n1_usb_ports_init(arena, Q1N1_USB_ARENA_SIZE, 0);
    CHECK(s->status[0].role == Q1N1_USB_UNSUPPORTED && model[0].writes == 0);

    /* Host-only: a controller waiting for a cable keeps running (no reset) and never becomes a device. */
    table = a;
    s = start(0, 0);
    for (unsigned n = 0; n < 1200; n++) advance(s, 100000);
    CHECK(model[0].device_starts == 0 && model[1].device_starts == 0);
    CHECK(model[0].host_starts == 1 && model[1].host_starts == 1);
    CHECK(s->status[0].role == Q1N1_USB_HOST && !s->status[0].connected);
    model[0].partner = Q1N1_USB_DEVICE;
    settle(s);
    CHECK(s->status[0].connected && model[0].opens == 1);
    model[0].partner = 0;                            /* cable pulled: recover as a host, again without a device attempt */
    advance(s, 1); advance(s, 600000);
    for (unsigned n = 0; n < 30; n++) advance(s, 100000);
    CHECK(s->status[0].disconnects == 1 && model[0].host_starts == 2 && model[0].device_starts == 0);
    model[0].partner = Q1N1_USB_DEVICE;
    settle(s);
    CHECK(s->status[0].connected && model[0].opens == 2);
    /* Firmware left the controller in device mode: the first attempt is still a host attempt. */
    reset_models(0, 0);
    model[0].gctl = 0x102001;
    s = q1n1_usb_ports_init(arena, Q1N1_USB_ARENA_SIZE, 0);
    CHECK(s->port[0].next_role == Q1N1_USB_DEVICE);
    settle(s);
    CHECK(model[0].device_starts == 0 && model[0].host_starts >= 1 && s->status[0].role == Q1N1_USB_HOST);

    /* Without the flag the A16 alternation is back: the same silent cable gets a device attempt. */
    table = make_table(0x0c000000, 0x0c200000, 0, 0xf8800);
    s = start(0, 0);
    for (unsigned n = 0; n < 200; n++) advance(s, 100000);
    CHECK(model[0].device_starts >= 1 && model[0].host_starts >= 1);
    CHECK(model[0].last_qscratch == 0x0c000000 + 0xf8800);

    /* A one-controller table: the second slot owns nothing and no register of any second base is touched. */
    table = a; table.count = 1; memset(&table.port[1], 0, sizeof(table.port[1]));
    reset_models(Q1N1_USB_DEVICE, Q1N1_USB_DEVICE);
    model[1].base = 0;
    s = q1n1_usb_ports_init(arena, Q1N1_USB_ARENA_SIZE, 0);
    settle(s);
    CHECK(s->status[0].connected && s->status[1].role == Q1N1_USB_UNSUPPORTED && stray == 0);

    /* Adoption: the same table keeps a live link; a table change stops the old controller; version 1 is not adopted. */
    table = a;
    s = start(Q1N1_USB_DEVICE, Q1N1_USB_DEVICE);
    settle(s);
    CHECK(s->status[0].connected && s->status[1].connected);
    unsigned hosts = model[0].host_starts;
    q1n1_usb_ports_handoff(s);
    s = q1n1_usb_ports_init(arena, Q1N1_USB_ARENA_SIZE, 1);
    CHECK(model[0].host_starts == hosts && s->status[0].connected);
    unsigned halts = model[0].halts;
    table = b;
    /* The old controllers still answer at their old bases (slots 0 and 1); the new table's controllers are slots 2
     * and 3. The new manager must stop the old ones through the bases its state recorded, then start the new ones. */
    for (unsigned i = 0; i < 2; i++) {
        memset(&model[2 + i], 0, sizeof(model[2 + i]));
        model[2 + i].base = (uintptr_t)b.port[i].dwc3_base;
        model[2 + i].gsnpsid = 0x5533330a; model[2 + i].cap = 0x01100020; model[2 + i].hcs1 = 0x02000040;
        model[2 + i].gctl = 0x102001; model[2 + i].status = 1; model[2 + i].dtr = 1;
        model[2 + i].partner = Q1N1_USB_DEVICE;
    }
    stray = 0;
    s = q1n1_usb_ports_init(arena, Q1N1_USB_ARENA_SIZE, 1);
    CHECK(s && s->port[0].base == 0x0d000000 && s->port[1].base == 0x0d200000);
    CHECK(model[0].halts > halts && !(model[0].cmd & 1) && !(model[1].cmd & 1));   /* old xHCI engines are stopped */
    CHECK(s->port[0].qscratch == 0x0d000000 + 0xf9000);
    for (unsigned n = 0; n < 50; n++) advance(s, 100000);
    CHECK(model[2].host_starts == 1 && model[3].host_starts == 1 && s->status[0].connected && s->status[1].connected);
    CHECK(model[0].host_starts == hosts && stray == 0);                            /* nothing restarts the old ones */
    /* An old controller that will not halt must not be reused: the slot is marked unusable, not silently moved. */
    table = a;
    s = start(Q1N1_USB_DEVICE, 0);
    settle(s);
    q1n1_usb_ports_handoff(s);
    model[0].halt_failure = 1;
    model[0].status = 0;
    table = b;
    model[2].cmd = 0; model[2].status = 1; model[2].host_starts = 0;
    s = q1n1_usb_ports_init(arena, Q1N1_USB_ARENA_SIZE, 1);
    CHECK(s->status[0].role == Q1N1_USB_UNSUPPORTED && model[2].host_starts == 0);
    CHECK(s->port[0].base == 0x0c000000);                                          /* still the old, un-halted controller */

    /* State left by a version-1 (A16) stage is reset, not adopted. */
    table = a;
    s = start(Q1N1_USB_DEVICE, 0);
    settle(s);
    s->version = 1;
    q1n1_usb_ports_handoff(s);
    model[0].cmd = 0; model[0].status = 1;
    s = q1n1_usb_ports_init(arena, Q1N1_USB_ARENA_SIZE, 1);
    CHECK(s->version == 2 && s->status[0].role == Q1N1_USB_OFF && !s->status[0].connected);
    free(arena);
    printf("PASS %u SP11 USB-port lifecycle checks\n", checks);
    return 0;
}
