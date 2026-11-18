/* SPDX-License-Identifier: MIT */
/* The fuzz suite of the nvmesnap host test (tools/test-q1n1-sp11-payload-nvmesnap.c): random worlds, each the good world with a few things changed
 * (any word of a configuration page, a controller register or a queue; the translation of any page; the memory map; the counter), run against an
 * oracle that is written another way. The oracle reads the scripted words and the translation model and says what the payload must conclude and
 * how many loads it must make in each window; it shares no code with the payload and works from the specification's conditions, in a flat
 * sequence, not from the payload's functions. Each world is also held to the discipline of the world model (no stray load, none after a fault, none
 * at a page the MMU does not map as the rule wants). Evidence: EXPERIMENTAL (host model only). */
#pragma once

static uint64_t fz_state = UINT64_C(0x2545f4914f6cdd1d);
static uint32_t fz_next(void)
{
    fz_state ^= fz_state >> 12;
    fz_state ^= fz_state << 25;
    fz_state ^= fz_state >> 27;
    return (uint32_t)((fz_state * UINT64_C(0x2545f4914f6cdd1d)) >> 32);
}
static uint32_t fz(uint32_t n) { return n ? fz_next() % n : 0; }
#define FZ_PICK(arr) ((arr)[fz((uint32_t)(sizeof (arr) / sizeof (arr)[0]))])

struct fzcase {
    struct d list[STD_COUNT + 4];
    unsigned nlist;
    int counter;                        /* 0 runs, 1 no op, 2 stands still, 3 goes back, 4 stops at the second wait, 5 stops at the third */
    uint64_t bar;                       /* where the endpoint's BAR0 points in this world */
};

/* A word of a page: a fault one time in eight, else one of the choices, else (a little less than one time in four) a random word. */
static void fz_word(uint64_t addr, const uint32_t *choices, unsigned n)
{
    uint32_t r = fz(16);
    if (r < 2) bus_fault(addr);
    else if (r < 5 || !n) bus_set(addr, fz_next());
    else bus_set(addr, choices[fz(n)]);
}
#define FZ_WORD(addr, arr) fz_word((addr), (arr), (unsigned)(sizeof (arr) / sizeof (arr)[0]))

/* One change to the world. */
static void fz_change(struct fzcase *f, unsigned kind)
{
    static const uint32_t ids[] = {0xffffffffu, 0x0222ffffu, 0x02221111u, 0xfeed1d1du, 0xfeedffffu};
    static const uint32_t cmds[] = {0x00100007u, 0x00000007u, 0x00100000u, 0x00000000u, 0x00100406u, 0x00100404u, 0x00100402u, 0x00000406u};
    static const uint32_t classes[] = {0x06040001u, 0x06000001u, 0x01080002u, 0x06040abcu, 0x01080201u, 0x01080101u, 0x02000001u, 0x01080301u};
    static const uint32_t hdrs[] = {0x00010010u, 0x00810010u, 0x00000010u, 0x00800010u, 0x00020010u};
    static const uint32_t buses[] = {0x00010100u, 0x00010101u, 0x00020200u, 0x00ff0100u, 0x00000100u, 0x00010000u};
    static const uint32_t windows[] = {0x73f07030u, 0x73f07040u, 0x70207030u, 0x70307030u, 0x70007ff0u, 0x73f0703fu, 0x7330702fu, 0x00000000u};
    static const uint32_t ptrs[] = {0x40u, 0x41u, 0x30u, 0x100u, 0x50u, 0x70u, 0x7cu, 0x80u, 0u, 0xfcu};
    static const uint32_t capwords[] = {0x00035001u, 0x00807005u, 0x00420010u, 0x00004001u, 0x00000000u, 0x00007010u, 0x00008011u, 0x00020010u, 0x00ff0001u,
                                        0x00620010u, 0x00920010u, 0x00720010u, 0x00120010u};
    static const uint32_t lcaps[] = {0x00100c44u, 0x00000c44u, 0x00100000u, 0xffffffffu};
    static const uint32_t lstas[] = {0x20440043u, 0x00440043u, 0x28440043u, 0x08440043u, 0xffffffffu, 0x00000000u};
    static const uint32_t pmcsrs[] = {8u, 9u, 10u, 11u, 0u, 0xffffffffu};
    static const uint32_t bar0s[] = {0x70300004u, 0x70300000u, 0x70300005u, 0x70300002u, 0x70300006u, 0x70300014u, 0x7030000cu, 0x702ff004u,
                                     0x74000004u, 0x70300104u, 0x70400004u, 0xffffffffu, 0x73fff004u};
    static const uint32_t bar1s[] = {0u, 1u, 0x12345678u};
    static const uint64_t attrs[] = {ATTR_WB, ATTR_NC, ATTR_WT, ATTR_DEVICE, 0x0c, 0x01, 0x77, 0x04};
    static const uint64_t conv[] = {ASQ_GOOD, 0, 0xa0000000, 0xb0000000, 0xc0000000, 0x90000000, 0x80100040, UINT64_C(1) << 48, 0xa1000000, 0x60000000};
    static const uint32_t ccs[] = {0x00460081u, 0x00460080u, 0x00460001u, 0x00464001u, 0u, 0xffffffffu};
    static const uint32_t cstss[] = {1u, 0u, 3u, 2u, 5u, 8u, 0xdu, 0x11u, 0x21u, 0xffffffffu};
    static const uint32_t aqas[] = {0x00030003u, 0x00010001u, 0u, 0x0fff0fffu, 0xffffffffu, 1u, 0x00010000u, 0x10011001u};
    uint64_t at;
    switch (kind) {
    case 0: FZ_WORD(RPo(0x00), ids); break;
    case 1: FZ_WORD(RPo(0x04), cmds); break;
    case 2: FZ_WORD(RPo(0x08), classes); break;
    case 3: FZ_WORD(RPo(0x0c), hdrs); break;
    case 4: FZ_WORD(RPo(0x18), buses); break;
    case 5: FZ_WORD(RPo(0x20), windows); break;
    case 6: FZ_WORD(RPo(0x34), ptrs); break;
    case 7: FZ_WORD(RPo(0x40 + 0x10 * fz(5)), capwords); break;
    case 8:
        if (fz(2)) fz_word(RPo(0x7c), lcaps, 4);
        else fz_word(RPo(0x80), lstas, 6);
        break;
    case 9: FZ_WORD(EPo(0x00), ids); break;
    case 10: FZ_WORD(EPo(0x04), cmds); break;
    case 11: FZ_WORD(EPo(0x08), classes); break;
    case 12: FZ_WORD(EPo(0x0c), hdrs); break;
    case 13: FZ_WORD(EPo(0x10), bar0s); break;
    case 14: FZ_WORD(EPo(0x14), bar1s); break;
    case 15: FZ_WORD(EPo(0x34), ptrs); break;
    case 16: FZ_WORD(EPo(0x40 + 0x10 * fz(5)), capwords); break;
    case 17: FZ_WORD(EPo(0x44), pmcsrs); break;
    case 18:
        if (fz(2)) fz_word(EPo(0x8c), lcaps, 4);
        else fz_word(EPo(0x90), lstas, 6);
        break;
    case 19:                                                            /* the translation of a configuration page or of the registers */
        at = fz(3) == 0 ? RP_PAGE : fz(2) ? EP_PAGE : BAR_GOOD;
        if (fz(4) == 0) tr_fault(at, at + 0x1000, 0x07);
        else tr_map(at, at + 0x1000, (uint8_t)FZ_PICK(attrs), SH_INNER);
        break;
    case 20:                                                            /* a descriptor over the registers or a queue page */
        if (f->nlist < STD_COUNT + 4) {
            at = fz(2) ? BAR_GOOD : fz(2) ? ASQ_GOOD : ACQ_GOOD;
            f->list[f->nlist++] = (struct d){fz(16), at, 1};
        }
        break;
    case 21: at = BAR_GOOD + 4 * fz(14); if (fz(4)) bus_fault(at); break;   /* a register that does not answer */
    case 22:
        switch (fz(7)) {
        case 0: bus_set64(NVo(0x00), fz(2) ? UINT64_C(0x0123456789abcdef) : fz(2) ? 0 : ~UINT64_C(0)); break;
        case 1: bus_set(NVo(0x08), fz_next()); break;
        case 2: bus_set(NVo(0x14), ccs[fz(6)]); break;
        case 3: bus_set(NVo(0x1c), cstss[fz(10)]); break;
        case 4: bus_set(NVo(0x24), aqas[fz(8)]); break;
        case 5: bus_set64(NVo(0x28), FZ_PICK(conv)); break;
        default: bus_set64(NVo(0x30), FZ_PICK(conv)); break;
        }
        break;
    case 23:                                                            /* a queue word, or the translation of a queue page */
        if (fz(2)) {
            at = fz(2) ? ASQ_GOOD + 4 * (fz(2) ? fz(16) : 16 + fz(16)) : ACQ_GOOD + 4 * fz(8);
            if (fz(3)) bus_fault(at);
            else bus_set(at, fz_next());
        } else {
            at = fz(2) ? ASQ_GOOD : ACQ_GOOD;
            if (fz(3) == 0) tr_fault(at, at + 0x1000, 0x07);
            else tr_map(at, at + 0x1000, (uint8_t)FZ_PICK(attrs), SH_INNER);
        }
        break;
    case 24: f->counter = (int)fz(6); break;
    case 25:                                                            /* CSTS read a second time: a fault, all ones, or another state */
        if (fz(3) == 0) bus_nth_fault(NVo(0x1c), 1);
        else bus_nth(NVo(0x1c), 1, cstss[fz(10)]);
        break;
    default: break;
    }
}
#define FZ_KINDS 26u

/* ---- The oracle ------------------------------------------------------------------------------------------------------------------ */

static int fz_dev_ok(uint64_t page)
{
    const struct tr_range *r = tr_find(page);
    return r && r->mapped && (r->attr & 0xf0) == 0 && (r->attr & 3) == 0;
}
static int fz_mapped(uint64_t page)
{
    const struct tr_range *r = tr_find(page);
    return r && r->mapped;
}
static int fz_usable(uint32_t type) { return (type >= 1 && type <= 7) || type == 9; }

struct ofn {
    uint64_t page;
    int ok, dead;
};
static int ord(struct ofn *f, uint32_t off, uint32_t *v)
{
    if (f->dead) return 0;
    if (!f->ok || !peek(f->page + off, v)) {
        f->dead = 1;
        return 0;
    }
    return 1;
}
struct ohead {
    struct ofn f;
    int id_ok, cmd_ok, cls_ok, hdr_ok, a_ok, b_ok, absent;
    uint32_t id, cmd, cls, hdr, a, b, capptr;
};
static void oread_head(struct ohead *h, uint64_t page)
{
    uint32_t ptr;
    memset(h, 0, sizeof *h);
    h->f.page = page;
    h->f.ok = fz_dev_ok(page);
    h->id_ok = ord(&h->f, 0x00, &h->id);
    if (h->id_ok && (h->id == 0xffffffffu || (h->id & 0xffffu) == 0xffffu)) {
        h->absent = 1;
        h->f.dead = 1;
        return;
    }
    h->cmd_ok = ord(&h->f, 0x04, &h->cmd);
    h->cls_ok = ord(&h->f, 0x08, &h->cls);
    h->hdr_ok = ord(&h->f, 0x0c, &h->hdr);
    if (h->hdr_ok && (h->hdr >> 16 & 0x7f) == 0) {
        h->a_ok = ord(&h->f, 0x10, &h->a);
        h->b_ok = ord(&h->f, 0x14, &h->b);
    } else if (h->hdr_ok && (h->hdr >> 16 & 0x7f) == 1) {
        h->a_ok = ord(&h->f, 0x18, &h->a);
        h->b_ok = ord(&h->f, 0x20, &h->b);
    }
    if (h->cmd_ok && (h->cmd >> 20 & 1) && ord(&h->f, 0x34, &ptr)) h->capptr = ptr & 0xfc;
}

struct ocaps {
    int walk_ok, has_pmcsr, has_lcap, has_lsta;
    uint32_t pm, pcie, pcie_hdr, pmcsr, lcap, lsta;
};
/* The lists as the specification reads them: at most 16 steps through pointers that stay in 0x40 to 0xff, the registers of a capability as soon as
 * it is found (a read that does not answer ends the page), and both found ends the walk. */
static void oread_caps(struct ohead *h, int want_pm, struct ocaps *c)
{
    uint32_t at = h->capptr, v;
    memset(c, 0, sizeof *c);
    c->walk_ok = !h->f.dead;
    for (unsigned step = 0; c->walk_ok && step < 16 && at >= 0x40 && at < 0x100; step++) {
        if (!ord(&h->f, at, &v)) {
            c->walk_ok = 0;
            break;
        }
        if ((v & 0xff) == 0x01 && want_pm && !c->pm) {
            c->pm = at;
            c->has_pmcsr = ord(&h->f, at + 4, &c->pmcsr);
        } else if ((v & 0xff) == 0x10 && !c->pcie) {
            c->pcie = at;
            c->pcie_hdr = v;
            c->has_lcap = ord(&h->f, at + 0x0c, &c->lcap);
            c->has_lsta = ord(&h->f, at + 0x10, &c->lsta);
        }
        if ((c->pm || !want_pm) && c->pcie) break;
        at = (v >> 8) & 0xfc;
    }
}

struct expect {
    const char *why, *ctrl, *queues;
    int open, second_block;
    uint64_t bar;
    unsigned nv_loads, sq_loads, cq_loads, sq_slots, cq_slots;
    uint64_t asq, acq;
    int sq_allowed, cq_allowed;
};

/* How a descriptor list sees [at, at + n): 0 in none, 1 inside one usable descriptor and no other kind overlaps it, 2 a descriptor that is not
 * usable overlaps it, 3 only part of it is in usable ones. */
static int fz_ram_class(const struct fzcase *f, uint64_t at, uint64_t n)
{
    int inside = 0;
    for (unsigned i = 0; i < f->nlist; i++) {
        uint64_t s = f->list[i].start, e = s + f->list[i].pages * 4096;
        if (at >= e || at + n <= s) continue;
        if (!fz_usable(f->list[i].type)) return 2;
        if (at >= s && e - at >= n) inside = 1;
    }
    return inside ? 1 : 0;
}
static int fz_usable_overlap(const struct fzcase *f, uint64_t at, uint64_t n)
{
    for (unsigned i = 0; i < f->nlist; i++) {
        uint64_t s = f->list[i].start, e = s + f->list[i].pages * 4096;
        if (!(at >= e || at + n <= s) && fz_usable(f->list[i].type)) return 1;
    }
    return 0;
}

/* One admin queue as the specification reads it: its slots, word by word, until a word does not answer. Returns the Q_* name. */
static const char *fz_queue(const struct fzcase *f, uint64_t at, uint64_t entries, unsigned entry_bytes, const unsigned *words, unsigned nwords,
                            unsigned *loads, unsigned *slots, int *allowed)
{
    unsigned peek_slots = entries < 2 ? (unsigned)entries : 2;
    uint32_t v;
    *loads = *slots = 0;
    *allowed = 0;
    if (fz_ram_class(f, at, (uint64_t)peek_slots * entry_bytes) != 1) return "NOT_RAM";
    if (!fz_mapped(at)) return "PAGE_UNMAPPED";
    *allowed = 1;
    for (unsigned slot = 0; slot < peek_slots; slot++) {
        (*slots)++;
        for (unsigned i = 0; i < nwords; i++) {
            (*loads)++;
            if (!peek(at + (uint64_t)slot * entry_bytes + 4u * words[i], &v)) return "FAULT";
        }
    }
    return "READ";
}

static const char *fz_ctrl_name(unsigned s)
{
    return s == 1 ? "RUNNING" : s == 2 ? "DISABLED" : s == 3 ? "TRANSITION" : s == 4 ? "FATAL" : s == 5 ? "SHUTDOWN" : s == 6 ? "ALL_ONES" : "UNKNOWN";
}

static void oracle(const struct fzcase *f, struct expect *e)
{
    static const unsigned sqw[6] = {0, 6, 7, 1, 10, 11}, cqw[3] = {3, 2, 0};      /* the words of a slot, in the order they are read */
    static const unsigned a_off[4] = {0x00, 0x1c, 0x14, 0x08}, a_wide[4] = {2, 1, 1, 1};
    static const unsigned b_off[3] = {0x24, 0x28, 0x30}, b_wide[3] = {1, 2, 2};
    struct ohead rp, ep;
    struct ocaps rc, ec;
    uint32_t b0, b1, a_val[4][2], b_val[3][2], csts2 = 0, cc = 0, csts = 0, type, ptype;
    uint64_t addr, base, limit, asq, acq, entries_sq, entries_cq;
    unsigned cstate = 0, a_got = 0, b_got = 0;
    int caps_run = f->counter == 0 || f->counter >= 4, regs_wait = f->counter == 0 || f->counter == 5, aq_wait = f->counter == 0;
    int a_fault = 0, b_fault = 0, csts2_ok = 0;
    memset(e, 0, sizeof *e);
    memset(&rc, 0, sizeof rc);
    memset(&ec, 0, sizeof ec);
    memset(a_val, 0, sizeof a_val);
    memset(b_val, 0, sizeof b_val);
    e->why = "NONE";
    e->ctrl = "UNKNOWN";
    e->queues = "NOT_READ";
    oread_head(&rp, RP_PAGE);
    oread_head(&ep, EP_PAGE);
    if (rp.absent) { e->why = "RP_ABSENT"; return; }
    if (!(rp.id_ok && rp.cmd_ok && rp.cls_ok && rp.hdr_ok)) { e->why = "RP_NOT_READ"; return; }
    if ((rp.cls >> 16) != 0x0604 || (rp.hdr >> 16 & 0x7f) != 1) { e->why = "RP_NOT_BRIDGE"; return; }
    if (!(rp.a_ok && rp.b_ok)) { e->why = "RP_NOT_READ"; return; }
    if (ep.absent) { e->why = "EP_ABSENT"; return; }
    if (!(ep.id_ok && ep.cmd_ok && ep.cls_ok && ep.hdr_ok)) { e->why = "EP_NOT_READ"; return; }
    if ((ep.cls >> 8) != 0x010802 || (ep.hdr >> 16 & 0x7f) != 0) { e->why = "EP_NOT_NVME"; return; }
    if (!(ep.a_ok && ep.b_ok)) { e->why = "EP_NOT_READ"; return; }
    if ((rp.a & 0xff) != 0 || (rp.a >> 8 & 0xff) != 1 || (rp.a >> 16 & 0xff) < 1) { e->why = "BRIDGE_BUSES"; return; }
    if (caps_run) {
        oread_caps(&rp, 0, &rc);
        oread_caps(&ep, 1, &ec);
    }
    if (!caps_run) { e->why = "CAPS_NOT_RUN"; return; }
    if (!rc.walk_ok || !ec.walk_ok || (ec.pm && !ec.has_pmcsr)) { e->why = "CAPS_NOT_READ"; return; }
    if (!rc.pcie) { e->why = "NO_LINK_CAPABILITY"; return; }
    if (!rc.has_lcap || !rc.has_lsta) { e->why = "CAPS_NOT_READ"; return; }
    ptype = rc.pcie_hdr >> 20 & 15;
    if (ptype != 4 && ptype != 6) { e->why = "LINK_UNPROVEN"; return; }
    if (!(rc.lcap >> 20 & 1)) { e->why = "LINK_UNPROVEN"; return; }
    if (!(rc.lsta >> 29 & 1)) { e->why = "LINK_DOWN"; return; }
    if (rc.lsta >> 27 & 1) { e->why = "LINK_TRAINING"; return; }
    if (!(ep.cmd >> 1 & 1)) { e->why = "MEMORY_SPACE_OFF"; return; }
    if (ec.pm && (ec.pmcsr & 3)) { e->why = "NOT_IN_D0"; return; }
    b0 = ep.a;
    b1 = ep.b;
    type = b0 >> 1 & 3;
    if ((b0 & 1) || (type != 0 && type != 2)) { e->why = "BAR0_NOT_MEMORY"; return; }
    addr = b0 & ~0xfu;
    if (type == 2) addr |= (uint64_t)b1 << 32;
    if (addr & 0xfff) { e->why = "BAR0_UNALIGNED"; return; }
    if (addr < 0x70300000u || addr + 0x38 > 0x74000000u) { e->why = "BAR0_OUTSIDE_PLATFORM_WINDOW"; return; }
    if (!(rp.cmd >> 1 & 1)) { e->why = "BRIDGE_MEMORY_OFF"; return; }
    base = (uint64_t)(rp.b & 0xfff0u) << 16;
    limit = (rp.b & 0xfff00000u) | 0xfffffu;
    if (base > limit || addr < base || addr + 0x38 - 1 > limit) { e->why = "BAR0_OUTSIDE_BRIDGE_WINDOW"; return; }
    if (fz_usable_overlap(f, addr, 0x38)) { e->why = "BAR0_IN_RAM"; return; }
    if (!fz_mapped(addr)) { e->why = "BAR0_PAGE_UNMAPPED"; return; }
    if (!fz_dev_ok(addr)) { e->why = "BAR0_PAGE_NOT_DEVICE"; return; }
    e->open = 1;
    e->bar = addr;
    if (!regs_wait) { e->why = "GROUP_SKIPPED"; return; }
    /* The first block: CAP, CSTS, CC, VS, until one does not answer. */
    for (unsigned i = 0; i < 4 && !a_fault; i++) {
        for (unsigned j = 0; j < a_wide[i] && !a_fault; j++) {
            e->nv_loads++;
            if (!peek(addr + a_off[i] + 4 * j, &a_val[i][j])) a_fault = 1;
        }
        if (!a_fault) a_got |= 1u << i;
    }
    if ((a_got & 6u) == 6u) {                                           /* CSTS and CC answered: the state does not need CAP or VS */
        csts = a_val[1][0];
        cc = a_val[2][0];
        if (csts == 0xffffffffu || cc == 0xffffffffu || ((a_got & 1u) && a_val[0][0] == 0xffffffffu && a_val[0][1] == 0xffffffffu)) cstate = 6;
        else cstate = csts >> 1 & 1 ? 4 : csts >> 2 & 3 ? 5 : (cc & 1) && (csts & 1) ? 1 : !(cc & 1) && !(csts & 1) ? 2 : 3;
    }
    e->ctrl = fz_ctrl_name(cstate);
    if (a_fault) { e->why = "REGISTERS_NOT_READ"; return; }
    if (cstate == 6) { e->why = "REGISTERS_ALL_ONES"; return; }
    e->second_block = 1;
    if (!aq_wait) { e->why = "GROUP_SKIPPED"; return; }
    /* The second block: CSTS again (nothing else when it does not answer or reads all ones), AQA, ASQ, ACQ. */
    e->nv_loads++;
    csts2_ok = peek_nth(addr + 0x1c, 1, &csts2);
    if (!csts2_ok) b_fault = 1;
    for (unsigned i = 0; i < 3 && csts2_ok && csts2 != 0xffffffffu && !b_fault; i++) {
        for (unsigned j = 0; j < b_wide[i] && !b_fault; j++) {
            e->nv_loads++;
            if (!peek(addr + b_off[i] + 4 * j, &b_val[i][j])) b_fault = 1;
        }
        if (!b_fault) b_got |= 1u << i;
    }
    if (csts2_ok) cstate = csts2 == 0xffffffffu ? 6 : ((csts ^ csts2) & 0xfu) ? 3 : cstate;
    e->ctrl = fz_ctrl_name(cstate);
    if (b_fault) { e->why = "AQ_REGISTERS_NOT_READ"; return; }
    if (cstate == 6) { e->why = "REGISTERS_ALL_ONES"; return; }
    if (cstate != 1) { e->queues = "NOT_ENABLED"; return; }
    if (b_got != 7u) return;
    entries_sq = (b_val[0][0] & 0xfff) + 1u;
    entries_cq = (b_val[0][0] >> 16 & 0xfff) + 1u;
    asq = b_val[1][0] | (uint64_t)b_val[1][1] << 32;
    acq = b_val[2][0] | (uint64_t)b_val[2][1] << 32;
    if (entries_sq < 2 || entries_cq < 2) { e->queues = "NO_QUEUES"; return; }
    if (!asq || (asq & 0xfff) || asq >= (UINT64_C(1) << 48) || !acq || (acq & 0xfff) || acq >= (UINT64_C(1) << 48) || asq == acq) {
        e->queues = "BAD_ADDRESS";
        return;
    }
    e->asq = asq;
    e->acq = acq;
    e->queues = fz_queue(f, asq, entries_sq, 64, sqw, 6, &e->sq_loads, &e->sq_slots, &e->sq_allowed);
    if (strcmp(e->queues, "FAULT")) {
        const char *cq = fz_queue(f, acq, entries_cq, 16, cqw, 3, &e->cq_loads, &e->cq_slots, &e->cq_allowed);
        if (!strcmp(e->queues, "READ")) e->queues = cq;
    }
}

static unsigned most_fuzz_lines;

static int suite_fuzz(void)
{
    unsigned iterations = 6000, quiet_runs = 0, open_runs = 0, ran_queues = 0;
    unsigned second_runs = 0, ones_runs = 0, aq_fail_runs = 0, skipped_runs = 0, transition_runs = 0, unproven_runs = 0, bridge_off_runs = 0;
    fz_state = UINT64_C(0x2545f4914f6cdd1d);
    for (unsigned it = 0; it < iterations; it++) {
        struct fzcase f;
        struct world w;
        struct expect e;
        unsigned changes = fz(4) + (it % 7 == 0 ? 0 : 1);
        char t1[64], t2[64], t3[64];
        memset(&f, 0, sizeof f);
        memcpy(f.list, std_map, sizeof std_map);
        f.nlist = STD_COUNT;
        /* The descriptors are chosen first, the world is built from them, then every other change is made to the built world. */
        {
            unsigned saved[8], n = 0;
            for (unsigned k = 0; k < changes && n < 8; k++) saved[n++] = fz(FZ_KINDS);
            for (unsigned k = 0; k < n; k++)
                if (saved[k] == 20) fz_change(&f, 20);
            world_new(&w, f.list, f.nlist);
            put_rp();
            put_ep();
            put_nvme(BAR_GOOD, &good_nv);
            put_queues(ASQ_GOOD, ACQ_GOOD);
            for (unsigned k = 0; k < n; k++)
                if (saved[k] != 20) fz_change(&f, saved[k]);
        }
        if (f.counter == 1) w.a.ops.counter = 0;
        else if (f.counter == 2) clock_set(UINT64_C(1) << 40, 1000000, 1);
        else if (f.counter == 3) clock_set(UINT64_C(1) << 40, 1000000, 2);
        else if (f.counter == 4) w.a.ops.counter = counter_stops_at_registers;
        else if (f.counter == 5) w.a.ops.counter = counter_stops_at_aq;
        oracle(&f, &e);
        nv_allowed = e.open ? e.bar : 0;
        ram_ok_n = 0;
        if (e.sq_allowed) allow_ram(e.asq, e.asq + (uint64_t)e.sq_slots * 64);
        if (e.cq_allowed) allow_ram(e.acq, e.acq + (uint64_t)e.cq_slots * 16);
        CHECK_EQ(go(&w.a), 0);
        if (stray || after_fault || unsafe_loads) fprintf(stderr, "iteration %u: stray %u (%#llx) after-fault %u unsafe %u\n", it, stray, (unsigned long long)first_stray, after_fault, unsafe_loads);
        CHECK_DISCIPLINE();
        snprintf(t1, sizeof t1, "WHY=%s", e.why);
        snprintf(t2, sizeof t2, "CTRL=%s", e.ctrl);
        snprintf(t3, sizeof t3, "QUEUES=%s", e.queues);
        if (!has_token(P "VERDICT", t1, 1) || !has_token(P "VERDICT", t2, 1) || !has_token(P "VERDICT", t3, 1)) {
            int k = find_line(P "VERDICT");
            fprintf(stderr, "iteration %u: %s\n  wanted %s %s %s\n", it, k >= 0 ? lines[k] : "(no verdict)", t1, t2, t3);
        }
        CHECK_TOKEN(P "VERDICT", t1);
        CHECK_TOKEN(P "VERDICT", t2);
        CHECK_TOKEN(P "VERDICT", t3);
        if (e.open) {
            CHECK_EQ(loads_in(e.bar, e.bar + 0x38), e.nv_loads);
            CHECK_LINE(P "NEXT NVME_REGS AFTER 8 S");
        } else {
            CHECK_NO_LINE(P "NEXT NVME_REGS");
        }
        if (e.second_block) CHECK_LINE(P "NEXT NVME_AQ AFTER 8 S");
        else CHECK_NO_LINE(P "NEXT NVME_AQ");
        if (e.asq) {
            CHECK_EQ(loads_in(e.asq, e.asq + 0x1000), e.sq_loads);
            CHECK_EQ(loads_in(e.acq, e.acq + 0x1000), e.cq_loads);
        }
        most_fuzz_lines = line_count > most_fuzz_lines ? line_count : most_fuzz_lines;
        most_lines = line_count > most_lines ? line_count : most_lines;
        open_runs += e.open;
        ran_queues += e.sq_loads != 0;
        quiet_runs += !e.open;
        second_runs += e.second_block;
        ones_runs += !strcmp(e.why, "REGISTERS_ALL_ONES");
        aq_fail_runs += !strcmp(e.why, "AQ_REGISTERS_NOT_READ");
        skipped_runs += !strcmp(e.why, "GROUP_SKIPPED");
        transition_runs += !strcmp(e.ctrl, "TRANSITION") && e.second_block;
        unproven_runs += !strcmp(e.why, "LINK_UNPROVEN");
        bridge_off_runs += !strcmp(e.why, "BRIDGE_MEMORY_OFF");
        world_free(&w);
    }
    /* The fuzz must visit both sides of the main gate and the queues. */
    CHECK(open_runs > iterations / 20);
    CHECK(quiet_runs > iterations / 20);
    CHECK(ran_queues > iterations / 50);
    /* ... and the paths of the second block, the all-ones controller, a skipped wait, the port types and the bridge's memory space. */
    CHECK(second_runs > iterations / 20 && ones_runs > 10 && aq_fail_runs > 30 && skipped_runs > 20 && transition_runs > 20);
    CHECK(unproven_runs > 20 && bridge_off_runs > 20);
    return 0;
}
