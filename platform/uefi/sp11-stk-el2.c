/* SPDX-License-Identifier: MIT */
/* The EL2 half of the stick-log survey (sp11-stk-survey.h): reads the clock controller, both Denali
 * USB controllers and the SMMU, in the order of docs/SP11-STICK-LOG.md section 3.6, and prints what it
 * found as the Appendix A lines. It runs after ExitBootServices, so it has no firmware to ask: only
 * loads through stk_ops.guarded, and the memory map saved before the bounce.
 *
 * Rules every read passes (stk_env_rd32 / stk_env_ram_read), because one forgotten check is a hang:
 *   - a window register must lie inside its window and be 32 bit aligned;
 *   - the memory map must not call the window RAM or firmware memory (it is checked once, here);
 *   - the page holding the register must be mapped Device at stage 1 (Normal would let the CPU
 *     prefetch, and an unmapped page would only fault);
 *   - a pointer read from a device register is followed only into memory the map shows as RAM;
 *   - the whole survey issues at most STK_MAX_READS loads.
 * Controller registers are read only when the gate is ON: a read of a power or clock gated block can
 * hang the bus, and a hang is recovered only by a power cycle. The first abort in a controller ends
 * all further MMIO to it. */
#include "sp11-stk-survey.h"

#if Q1N1_SP11_STK_SURVEY

/* VERIFIED as what the pinned Hamoa device tree says (hamoa.dtsi:758-760 gcc, :5254-5256 usb_1_ss0,
 * :5345 usb_1_ss1, :8436-8438 apps_smmu); that the unit uses them is INFERRED. */
const struct stk_window stk_windows[STK_WINDOWS] = {
    [STK_WIN_GCC] = {"GCC", 0x00100000u, 0x200000u},
    [STK_WIN_SMMU] = {"SMMU", 0x15000000u, 0x100000u},
    [STK_WIN_U0] = {"U0", 0x0a600000u, 0xfc100u},
    [STK_WIN_U1] = {"U1", 0x0a800000u, 0xfc100u},
};

/* GCC registers, offsets from the GCC base (gcc-x1e80100.c): the GDSCR of gcc_usb30_prim_gdsc (:6740)
 * and gcc_usb30_sec_gdsc (:6752); each controller's own branch clocks master, mock_utmi, sleep
 * (:5369 :5387 :5405 / :5418 :5436 :5454), cfg_noc (:2801 / :2821) and aggre (:2493 / :2513); and the
 * four shared NoC clocks aggre_usb_noc (:2613), sys_noc_usb (:5107), anoc north (:2876), south (:2891). */
struct gcc_regs {
    uint32_t gdscr, master, utmi, sleep, cfgnoc, aggre;
};
static const struct gcc_regs gcc_ctrl[STK_CONTROLLERS] = {
    {0x39004, 0x39018, 0x39028, 0x39024, 0x3908c, 0x39090},
    {0xa1004, 0xa1018, 0xa1028, 0xa1024, 0xa108c, 0xa1090},
};
static const uint32_t gcc_shared[4] = {0x2d034, 0x2d014, 0x2d028, 0x2d02c};

/* The streams of the two controllers in apps_smmu (hamoa.dtsi:5307, :5398). */
static const uint32_t stream_ids[STK_STREAMS] = {0x1420, 0x1460};

/* DWC3 and glue registers, offsets from the controller base (core.h:102-143; dwc3-qcom.c:26,30,41). */
#define DWC3_GCTL 0xc110u
#define DWC3_GSTS 0xc118u
#define DWC3_GSNPSID 0xc120u
#define DWC3_GBUSERRADDR0 0xc130u
#define DWC3_GUSB2PHYCFG 0xc200u
#define DWC3_GUSB3PIPECTL 0xc2c0u
#define GLUE_BASE 0xf8800u
#define GLUE_HS_PHY_CTRL (GLUE_BASE + 0x10u)
#define GLUE_SS_PHY_CTRL (GLUE_BASE + 0x30u)

/* xHCI registers: capability dwords from the base, operational registers from the base + CAPLENGTH,
 * runtime registers from the base + RTSOFF, interrupter 0 at +0x20 (xHCI 5.3, 5.4, 5.5). */
#define CAP_HCSPARAMS1 0x04u
#define CAP_HCSPARAMS2 0x08u
#define CAP_HCCPARAMS1 0x10u
#define CAP_DBOFF 0x14u
#define CAP_RTSOFF 0x18u
#define OP_USBCMD 0x00u
#define OP_USBSTS 0x04u
#define OP_CRCR 0x18u
#define OP_DCBAAP 0x30u
#define OP_CONFIG 0x38u
#define OP_PORTSC(n) (0x400u + 0x10u * ((n) - 1u))
#define RT_IR0_ERSTBA 0x30u     /* 0x20 + 0x10 */
#define RT_IR0_ERDP 0x38u       /* 0x20 + 0x18 */

#define SMMU_SCR0 0x00u
#define SMMU_ID0 0x20u
#define SMMU_SGFSR 0x48u

/* ---- The read environment ---------------------------------------------------------------------- */

struct env {
    const struct stk_el2_args *a;
    const struct stk_ops *ops;
    struct stk_sink *sink;
    int window_err[STK_WINDOWS];
    unsigned reads, faults, refusals;
};

/* The one place the survey touches device or firmware memory. STK_G_COPY32 is a load from `src`; a
 * store kind here would write a register, which nothing in the survey may do. */
static int load32(const struct stk_ops *ops, void *dst, uint64_t src, uint32_t size)
{
    return ops->guarded(ops->ctx, STK_G_COPY32, (uint64_t)(uintptr_t)dst, src, size);
}

static int env_rd32(struct env *e, int win, uint64_t off, uint32_t *value)
{
    const struct stk_window *w = &stk_windows[win];
    uint32_t tmp = 0;
    *value = 0;
    if ((off & 3) || off >= w->size || w->size - off < 4) return STK_E_RANGE;
    if (e->window_err[win]) { e->refusals++; return e->window_err[win]; }
    if (e->reads >= STK_MAX_READS) { e->refusals++; return STK_E_BUDGET; }
    uint64_t address = w->base + off;
    int attr = e->ops->attr(e->ops->ctx, address);
    if (attr != STK_ATTR_DEVICE) {
        e->refusals++;
        return attr == STK_ATTR_NONE ? STK_E_UNMAPPED : attr == STK_ATTR_NORMAL ? STK_E_NOT_DEVICE : STK_E_ATTR;
    }
    e->reads++;
    if (load32(e->ops, &tmp, address, 4)) { e->faults++; return STK_E_FAULT; }
    *value = tmp;
    return STK_OK;
}

static int env_ram_read(void *ctx, uint64_t phys, void *dst, uint32_t size)
{
    struct env *e = ctx;
    if ((phys & 3) || !size || (size & 3)) return STK_E_RANGE;
    if (!e->a->map_ok || !stk_map_range_is_ram(e->a->map, e->a->map_count, phys, size)) {
        e->refusals++;
        return STK_E_NOT_RAM;
    }
    if (e->reads >= STK_MAX_READS) { e->refusals++; return STK_E_BUDGET; }
    e->reads++;
    if (load32(e->ops, dst, phys, size)) { e->faults++; return STK_E_FAULT; }
    return STK_OK;
}

struct winrd {
    struct env *e;
    int win;
};
static int winrd_fn(void *ctx, uint32_t off, uint32_t *value)
{
    struct winrd *w = ctx;
    return env_rd32(w->e, w->win, off, value);
}

/* ---- Register sets: first failure wins, a fault ends the set ------------------------------------- */

struct rdset {
    struct env *e;
    int win;
    int stop;
    int first_err;
    const char *first_reg;
};

static void set_rd(struct rdset *s, const char *name, uint64_t off, struct stk_reg *r)
{
    if (s->stop) {
        r->v = 0;
        r->err = STK_E_NOT_READ;
        return;
    }
    r->err = env_rd32(s->e, s->win, off, &r->v);
    if (r->err && !s->first_err) {
        s->first_err = r->err;
        s->first_reg = name;
    }
    if (r->err == STK_E_FAULT) s->stop = 1;
}

/* A 64 bit register is read as two dwords, low then high, which the xHCI specification allows for
 * every register; it is unreadable if either half is. */
struct reg64 {
    uint64_t v;
    int err;
};
static void set_rd64(struct rdset *s, const char *name, uint64_t off, struct reg64 *r)
{
    struct stk_reg lo, hi;
    set_rd(s, name, off, &lo);
    set_rd(s, name, off + 4, &hi);
    r->err = lo.err ? lo.err : hi.err;
    r->v = r->err ? 0 : (uint64_t)lo.v | (uint64_t)hi.v << 32;
}

static void kv_hex(struct stk_line *l, const char *key, const struct stk_reg *r)
{
    if (r->err) stk_line_unknown(l, key);
    else stk_line_hex(l, key, r->v);
}
static void kv_hex64(struct stk_line *l, const char *key, const struct reg64 *r)
{
    if (r->err) stk_line_unknown(l, key);
    else stk_line_hex(l, key, r->v);
}
static void kv_dec(struct stk_line *l, const char *key, const struct stk_reg *r, unsigned shift, uint32_t mask)
{
    if (r->err) stk_line_unknown(l, key);
    else stk_line_dec(l, key, (r->v >> shift) & mask);
}
static void kv_bit(struct stk_line *l, const char *key, const struct stk_reg *r, unsigned bit)
{
    if (r->err) stk_line_unknown(l, key);
    else stk_line_flag(l, key, (r->v >> bit) & 1);
}

/* A guarded abort is FAULT=<register>; any other reason a register could not be read is
 * SKIPPED=<reason>. */
static void note(struct stk_line *l, const struct rdset *s)
{
    if (!s->first_err) return;
    if (s->first_err == STK_E_FAULT) stk_line_str(l, "FAULT", s->first_reg);
    else stk_line_str(l, "SKIPPED", stk_err_name(s->first_err));
}

static void next(struct env *e, const char *block, int essential)
{
    struct stk_line l;
    stk_line_begin(&l, e->sink, "STK NEXT", essential);
    stk_line_word(&l, block);
    stk_line_end(&l);
    stk_sink_at(e->sink, block);
}

static void skipped(struct env *e, const char *prefix, const char *reason, int essential)
{
    struct stk_line l;
    stk_line_begin(&l, e->sink, prefix, essential);
    stk_line_str(&l, "SKIPPED", reason);
    stk_line_end(&l);
}

/* ---- MAP ----------------------------------------------------------------------------------------- */

static const char *attr_name(int attr)
{
    switch (attr) {
    case STK_ATTR_DEVICE: return "DEVICE";
    case STK_ATTR_NORMAL: return "NORMAL";
    case STK_ATTR_NONE: return "NONE";
    default: return "?";
    }
}

static void blk_map(struct env *e)
{
    struct stk_line l;
    next(e, "MAP", 0);
    stk_line_begin(&l, e->sink, "STK P3 MAP", 0);
    stk_line_str(&l, "GCC", attr_name(e->ops->attr(e->ops->ctx, stk_windows[STK_WIN_GCC].base)));
    stk_line_str(&l, "SMMU", attr_name(e->ops->attr(e->ops->ctx, stk_windows[STK_WIN_SMMU].base)));
    stk_line_str(&l, "U0", attr_name(e->ops->attr(e->ops->ctx, stk_windows[STK_WIN_U0].base)));
    stk_line_str(&l, "U1", attr_name(e->ops->attr(e->ops->ctx, stk_windows[STK_WIN_U1].base)));
    stk_line_str(&l, "RAM", attr_name(e->ops->attr(e->ops->ctx, e->a->ram_sample)));
    stk_line_end(&l);
}

/* ---- Controllers --------------------------------------------------------------------------------- */

struct ctrl {
    unsigned idx;
    int win;
    char name[3];                   /* "U0" */
    int gate;
    int gcc_fault;
    int stopped;                    /* an abort: no further MMIO to this controller */
    int id_ok, plausible, op_ok;
    uint32_t caplen, slots, ports, hcc1, rtsoff;
    struct reg64 crcr, dcbaap;
    struct stk_reg config;
    struct stk_ctrl_obs obs;
};

static int plausible_xhci(const struct stk_reg *cap0, const struct stk_reg *hcs1)
{
    uint32_t caplen = cap0->v & 0xff, version = cap0->v >> 16;
    /* All ones is what a bus error or an absent block returns; HCIVERSION is 0x0090 to 0x01xx for
     * xHCI 0.96 to 1.x and CAPLENGTH is a whole number of dwords past the 0x1c capability registers. */
    if (cap0->v == 0xffffffffu || cap0->v == 0) return 0;
    if (caplen < 0x1c || (caplen & 3)) return 0;
    if (version < 0x0090 || version > 0x01ff) return 0;
    return (hcs1->v & 0xff) != 0 && (hcs1->v >> 24) != 0;
}

static void prefix_of(char *dst, const char *head, const char *name, const char *tail)
{
    unsigned n = 0;
    while (*head) dst[n++] = *head++;
    while (*name) dst[n++] = *name++;
    while (*tail) dst[n++] = *tail++;
    dst[n] = 0;
}

/* The first abort in a controller's window ends all further MMIO to it: whatever stopped one load
 * would stop the next, and an access to a block that has just misbehaved is not worth the risk. */
static void ctrl_stop(struct ctrl *c, int err)
{
    if (err == STK_E_FAULT) {
        c->stopped = 1;
        c->obs.fault = 1;
    }
}

static void skip_rest(struct env *e, struct ctrl *c)
{
    char prefix[16];
    prefix_of(prefix, "STK P3 ", c->name, "");
    skipped(e, prefix, "AFTER_FAULT", 0);
}

static void blk_id(struct env *e, struct ctrl *c)
{
    struct rdset s = {e, c->win, 0, 0, NULL};
    struct stk_reg cap0, hcs1, hcs2, hcc1, dboff, rtsoff;
    struct stk_line l;
    char prefix[24];
    stk_sink_at(e->sink, "ID");
    set_rd(&s, "CAP0", 0, &cap0);
    set_rd(&s, "HCSPARAMS1", CAP_HCSPARAMS1, &hcs1);
    set_rd(&s, "HCSPARAMS2", CAP_HCSPARAMS2, &hcs2);
    set_rd(&s, "HCCPARAMS1", CAP_HCCPARAMS1, &hcc1);
    set_rd(&s, "DBOFF", CAP_DBOFF, &dboff);
    set_rd(&s, "RTSOFF", CAP_RTSOFF, &rtsoff);
    prefix_of(prefix, "STK P3 ", c->name, " ID");
    stk_line_begin(&l, e->sink, prefix, 0);
    if (cap0.err) {
        stk_line_unknown(&l, "CAPLEN");
        stk_line_unknown(&l, "HCIVER");
    } else {
        stk_line_hex(&l, "CAPLEN", cap0.v & 0xff);
        stk_line_hex(&l, "HCIVER", cap0.v >> 16);
    }
    kv_dec(&l, "SLOTS", &hcs1, 0, 0xff);
    kv_dec(&l, "PORTS", &hcs1, 24, 0xff);
    kv_hex(&l, "HCS2", &hcs2);
    kv_hex(&l, "HCC1", &hcc1);
    kv_hex(&l, "DBOFF", &dboff);
    kv_hex(&l, "RTSOFF", &rtsoff);
    note(&l, &s);
    stk_line_end(&l);
    ctrl_stop(c, s.first_err);
    c->id_ok = !cap0.err && !hcs1.err && !hcs2.err && !hcc1.err && !dboff.err && !rtsoff.err;
    c->obs.id_read = c->id_ok;
    if (!c->id_ok) return;
    c->plausible = plausible_xhci(&cap0, &hcs1);
    c->obs.xhci_plausible = c->plausible;
    c->caplen = cap0.v & 0xff;
    c->slots = hcs1.v & 0xff;
    c->ports = hcs1.v >> 24;
    c->hcc1 = hcc1.v;
    c->rtsoff = rtsoff.v & ~0x1fu;
}

static void blk_xecp(struct env *e, struct ctrl *c)
{
    struct stk_xecp x;
    struct stk_line l;
    struct winrd w = {e, c->win};
    char prefix[24];
    stk_sink_at(e->sink, "XECP");
    stk_xecp_walk(winrd_fn, &w, c->hcc1 >> 16, stk_windows[c->win].size, &x);
    prefix_of(prefix, "STK P3 ", c->name, " XECP");
    stk_line_begin(&l, e->sink, prefix, 0);
    for (unsigned k = 0; k < x.protos; k++) {
        char key[8] = "PROTO0", value[8] = "USB";
        unsigned at = 3;
        key[5] = (char)('0' + k);
        if (x.proto[k].major < 10) value[at++] = (char)('0' + x.proto[k].major);
        else value[at++] = '?';
        value[at] = 0;
        stk_line_str(&l, key, value);
        stk_line_hex(&l, "REV", (uint64_t)x.proto[k].major << 8 | x.proto[k].minor);
        stk_line_dec(&l, "FIRST", x.proto[k].first);
        stk_line_dec(&l, "COUNT", x.proto[k].count);
    }
    if (!x.protos) stk_line_str(&l, "PROTO", "NONE");
    if (x.truncated) stk_line_flag(&l, "TRUNC", 1);
    if (x.status == STK_E_FAULT) stk_line_str(&l, "FAULT", "XECP");
    else if (x.status) stk_line_str(&l, "SKIPPED", stk_err_name(x.status));
    stk_line_end(&l);
    ctrl_stop(c, x.status);
}

static void blk_op(struct env *e, struct ctrl *c)
{
    struct rdset s = {e, c->win, 0, 0, NULL};
    struct stk_reg usbcmd, usbsts;
    struct stk_line l;
    char prefix[24];
    uint32_t op = c->caplen;
    stk_sink_at(e->sink, "OP");
    set_rd(&s, "USBCMD", op + OP_USBCMD, &usbcmd);
    set_rd(&s, "USBSTS", op + OP_USBSTS, &usbsts);
    set_rd64(&s, "CRCR", op + OP_CRCR, &c->crcr);
    set_rd64(&s, "DCBAAP", op + OP_DCBAAP, &c->dcbaap);
    set_rd(&s, "CONFIG", op + OP_CONFIG, &c->config);
    prefix_of(prefix, "STK P3 ", c->name, " OP");
    stk_line_begin(&l, e->sink, prefix, 0);
    kv_hex(&l, "USBCMD", &usbcmd);
    kv_hex(&l, "USBSTS", &usbsts);
    kv_bit(&l, "RS", &usbcmd, 0);
    kv_bit(&l, "HCH", &usbsts, 0);
    kv_bit(&l, "HSE", &usbsts, 2);
    kv_bit(&l, "CNR", &usbsts, 11);
    kv_hex64(&l, "CRCR", &c->crcr);
    kv_hex64(&l, "DCBAAP", &c->dcbaap);
    kv_hex(&l, "CONFIG", &c->config);
    note(&l, &s);
    stk_line_end(&l);
    ctrl_stop(c, s.first_err);
    c->obs.usbsts_read = !usbsts.err;
    c->obs.usbsts_allones = !usbsts.err && usbsts.v == 0xffffffffu;
    c->obs.hch = !usbsts.err && (usbsts.v & 1);
    c->op_ok = !usbcmd.err && !usbsts.err && !c->crcr.err && !c->dcbaap.err && !c->config.err;
}

static void blk_ports(struct env *e, struct ctrl *c)
{
    unsigned shown = c->ports < STK_PORTS_SHOWN ? c->ports : STK_PORTS_SHOWN;
    int stop = 0;
    c->obs.ports = shown;
    for (unsigned n = 1; n <= shown; n++) {
        struct rdset s = {e, c->win, stop, 0, NULL};
        struct stk_reg sc;
        struct stk_line l;
        char prefix[24];
        unsigned at;
        stk_sink_at(e->sink, "PORT");
        set_rd(&s, "PORTSC", c->caplen + OP_PORTSC(n), &sc);
        stop = s.stop;
        at = 0;
        prefix_of(prefix, "STK P3 ", c->name, " PORT");
        while (prefix[at]) at++;
        prefix[at++] = (char)('0' + n);
        prefix[at] = 0;
        stk_line_begin(&l, e->sink, prefix, 0);
        kv_hex(&l, "SC", &sc);
        kv_bit(&l, "CCS", &sc, 0);
        kv_bit(&l, "PED", &sc, 1);
        kv_bit(&l, "PP", &sc, 9);
        if (sc.err) { stk_line_unknown(&l, "PLS"); stk_line_unknown(&l, "SPEED"); }
        else { stk_line_dec(&l, "PLS", stk_port_pls(sc.v)); stk_line_dec(&l, "SPEED", stk_port_speed(sc.v)); }
        note(&l, &s);
        stk_line_end(&l);
        c->obs.port[n - 1].read = !sc.err;
        c->obs.port[n - 1].sc = sc.v;
        ctrl_stop(c, s.first_err);
    }
}

static void blk_dwc3(struct env *e, struct ctrl *c)
{
    struct rdset s = {e, c->win, 0, 0, NULL};
    struct stk_reg id, gctl, gsts, buserr, usb2, usb3;
    struct stk_line l;
    char prefix[24];
    stk_sink_at(e->sink, "DWC3");
    set_rd(&s, "GSNPSID", DWC3_GSNPSID, &id);
    set_rd(&s, "GCTL", DWC3_GCTL, &gctl);
    set_rd(&s, "GSTS", DWC3_GSTS, &gsts);
    set_rd(&s, "GBUSERR", DWC3_GBUSERRADDR0, &buserr);
    set_rd(&s, "USB2CFG", DWC3_GUSB2PHYCFG, &usb2);
    set_rd(&s, "USB3PIPE", DWC3_GUSB3PIPECTL, &usb3);
    prefix_of(prefix, "STK P3 ", c->name, " DWC3");
    stk_line_begin(&l, e->sink, prefix, 0);
    kv_hex(&l, "GSNPSID", &id);
    kv_hex(&l, "GCTL", &gctl);
    kv_dec(&l, "PRTCAPDIR", &gctl, 12, 3);
    kv_hex(&l, "GSTS", &gsts);
    kv_dec(&l, "CURMOD", &gsts, 0, 3);
    kv_hex(&l, "GBUSERR", &buserr);
    kv_hex(&l, "USB2CFG", &usb2);
    kv_hex(&l, "USB3PIPE", &usb3);
    note(&l, &s);
    stk_line_end(&l);
    ctrl_stop(c, s.first_err);
}

static void blk_glue(struct env *e, struct ctrl *c)
{
    struct rdset s = {e, c->win, 0, 0, NULL};
    struct stk_reg hs, ss;
    struct stk_line l;
    char prefix[24];
    stk_sink_at(e->sink, "GLUE");
    set_rd(&s, "HSPHY", GLUE_HS_PHY_CTRL, &hs);
    set_rd(&s, "SSPHY", GLUE_SS_PHY_CTRL, &ss);
    prefix_of(prefix, "STK P3 ", c->name, " GLUE");
    stk_line_begin(&l, e->sink, prefix, 0);
    kv_hex(&l, "HSPHY", &hs);
    kv_hex(&l, "SSPHY", &ss);
    note(&l, &s);
    stk_line_end(&l);
    ctrl_stop(c, s.first_err);
}

/* STEP 4 and 5 of section 3.6 for one controller: ID, XECP, OP, PORT, then DWC3 and the glue. */
static void blk_ctrl(struct env *e, struct ctrl *c)
{
    char prefix[24];
    prefix_of(prefix, "STK P3 ", c->name, "");
    if (c->gate != STK_GATE_ON) {
        char reason[16];
        prefix_of(reason, "GATE_", c->gate == STK_GATE_OFF ? "OFF" : c->gate == STK_GATE_PARTIAL ? "PARTIAL" : "UNKNOWN", "");
        skipped(e, prefix, reason, 0);
        return;
    }
    next(e, c->name, 0);
    blk_id(e, c);
    if (c->stopped) { skip_rest(e, c); return; }
    if (!c->id_ok) {
        prefix_of(prefix, "STK P3 ", c->name, " XHCI");
        skipped(e, prefix, "ID_UNREAD", 0);
    } else if (!c->plausible) {
        prefix_of(prefix, "STK P3 ", c->name, " XHCI");
        skipped(e, prefix, "NOT_XHCI", 0);
    } else {
        blk_xecp(e, c);
        if (c->stopped) { skip_rest(e, c); return; }
        blk_op(e, c);
        if (c->stopped) { skip_rest(e, c); return; }
        blk_ports(e, c);
        if (c->stopped) { skip_rest(e, c); return; }
    }
    blk_dwc3(e, c);
    if (c->stopped) { skip_rest(e, c); return; }
    blk_glue(e, c);
}

/* ---- Firmware rings and slots ------------------------------------------------------------------- */

static int ptr_in_ram(const struct env *e, uint64_t pointer, uint64_t size)
{
    return e->a->map_ok && stk_map_range_is_ram(e->a->map, e->a->map_count, pointer, size);
}

static void put_slot_line(struct env *e, struct ctrl *c, unsigned id, const struct stk_slot *s,
                          unsigned more_slots)
{
    struct stk_line l;
    char prefix[24];
    unsigned at;
    prefix_of(prefix, "STK P3 ", c->name, " SLOT");
    at = 0;
    while (prefix[at]) at++;
    prefix[at++] = (char)('0' + id);
    prefix[at] = 0;
    stk_line_begin(&l, e->sink, prefix, 0);
    stk_line_hex(&l, "CTX", s->ctx);
    if (s->err) {
        stk_line_str(&l, "SKIPPED", stk_err_name(s->err));
    } else {
        stk_line_hex(&l, "ROUTE", s->route);
        stk_line_flag(&l, "HUB", s->hub);
        stk_line_dec(&l, "ROOTPORT", s->root_port);
        stk_line_dec(&l, "SPEED", s->speed);
        stk_line_dec(&l, "STATE", s->state);
        stk_line_dec(&l, "ADDR", s->address);
        for (unsigned k = 0; k < s->shown; k++) {
            char key[8] = "EP", value[24];
            unsigned kn = 2, vn = 0;
            if (s->ep[k].dci >= 10) key[kn++] = (char)('0' + s->ep[k].dci / 10);
            key[kn++] = (char)('0' + s->ep[k].dci % 10);
            key[kn] = 0;
            value[vn++] = (char)('0' + s->ep[k].state);
            value[vn++] = '.';
            value[vn++] = (char)('0' + s->ep[k].type);
            value[vn++] = '.';
            vn += (unsigned)stk_fmt_hex(value + vn, sizeof value - vn, s->ep[k].mps);
            value[vn] = 0;
            stk_line_str(&l, key, value);
        }
        if (s->eps > s->shown) stk_line_dec(&l, "MORE", s->eps - s->shown);
    }
    if (more_slots) stk_line_dec(&l, "MORESLOTS", more_slots);
    stk_line_end(&l);
}

/* STEP 6: the firmware's DCBAA, command ring and event ring pointers, and the device contexts they lead
 * to. The pointers come from registers, so each is checked against the memory map before any load. */
static void blk_fwrings(struct env *e, struct ctrl *c)
{
    char prefix[24];
    /* A controller that was not read, or whose ID or OP block did not read, has said why on its own
     * lines already; there are no pointers to follow. */
    if (c->gate != STK_GATE_ON || !c->id_ok || !c->plausible || !c->op_ok) return;
    prefix_of(prefix, "STK P3 ", c->name, " FWRINGS");
    char block[16];
    prefix_of(block, "FWRINGS", c->name + 1, "");
    struct reg64 erstba = {0, STK_E_NOT_READ}, erdp = {0, STK_E_NOT_READ};
    struct rdset s = {e, c->win, c->stopped, 0, NULL};
    next(e, block, 0);
    if (!c->stopped) {
        /* RTSOFF is whatever the controller says: add in 64 bits, so a huge value is refused as out of
         * the window and does not wrap around to some register that is. */
        set_rd64(&s, "ERSTBA", (uint64_t)c->rtsoff + RT_IR0_ERSTBA, &erstba);
        set_rd64(&s, "ERDP", (uint64_t)c->rtsoff + RT_IR0_ERDP, &erdp);
        ctrl_stop(c, s.first_err);
    }

    uint64_t dcbaa = c->dcbaap.v & ~UINT64_C(0x3f);
    unsigned scan = c->config.v & 0xff ? c->config.v & 0xff : c->slots;
    if (scan > STK_SLOTS_SCANNED) scan = STK_SLOTS_SCANNED;
    int aligned = !(c->dcbaap.v & 0x3f);
    int dcbaa_ok = aligned && dcbaa && ptr_in_ram(e, dcbaa, 8 * (scan + 1));
    uint64_t crcr_ptr = c->crcr.v & ~UINT64_C(0x3f), erstba_ptr = erstba.v & ~UINT64_C(0x3f);
    uint64_t erdp_ptr = erdp.v & ~UINT64_C(0xf);
    /* An unprogrammed (zero) pointer is not followed and does not count against INRAM; CRCR often
     * reads back without its pointer at all. */
    int inram = dcbaa_ok && (!crcr_ptr || ptr_in_ram(e, crcr_ptr, 16)) &&
                (!erstba_ptr || ptr_in_ram(e, erstba_ptr, 16)) && (!erdp_ptr || ptr_in_ram(e, erdp_ptr, 16));

    struct stk_line l;
    stk_line_begin(&l, e->sink, prefix, 0);
    kv_hex64(&l, "DCBAAP", &c->dcbaap);
    kv_hex64(&l, "CRCR", &c->crcr);
    kv_hex64(&l, "ERSTBA", &erstba);
    kv_hex64(&l, "ERDP", &erdp);
    stk_line_flag(&l, "INRAM", inram);
    note(&l, &s);
    stk_line_end(&l);

    prefix_of(prefix, "STK P3 ", c->name, " SLOT");
    if (!dcbaa_ok) {
        skipped(e, prefix, !dcbaa ? "NO_DCBAAP" : !aligned ? "MISALIGNED" : e->a->map_ok ? "NOT_RAM" : "NO_MAP", 0);
        return;
    }
    stk_sink_at(e->sink, "SLOT");
    struct stk_slots sw;
    unsigned ctxsz = (c->hcc1 >> 2) & 1 ? 64 : 32;
    stk_slot_walk(env_ram_read, e, dcbaa, scan, ctxsz, &sw);
    if (sw.status) {
        stk_line_begin(&l, e->sink, prefix, 0);
        if (sw.status == STK_E_FAULT) stk_line_str(&l, "FAULT", "DCBAA");
        else stk_line_str(&l, "SKIPPED", stk_err_name(sw.status));
        stk_line_end(&l);
        if (sw.status == STK_E_FAULT) { c->obs.fault = 1; c->stopped = 1; }
        return;
    }
    c->obs.slots_read = 1;
    if (!sw.shown) {
        stk_line_begin(&l, e->sink, prefix, 0);
        stk_line_dec(&l, "NONEMPTY", 0);
        stk_line_end(&l);
        return;
    }
    for (unsigned k = 0; k < sw.shown; k++) {
        put_slot_line(e, c, sw.slot_id[k], &sw.slot[k], k + 1 == sw.shown ? sw.nonempty - sw.shown : 0);
        if (!sw.slot[k].err && c->obs.slots < STK_SLOTS_SHOWN) c->obs.slot[c->obs.slots++] = sw.slot[k];
    }
}

/* ---- SMMU ---------------------------------------------------------------------------------------- */

static void put_stream(struct env *e, unsigned s, const struct stk_smr_scan *scan, int scan_err, const char *skip)
{
    struct stk_line l;
    char prefix[24] = "STK P3 SMMU S";
    unsigned at = 13;
    /* The stream id in plain hex, the way the device tree writes it: S1420, S1460. */
    char digits[8];
    unsigned d = 0;
    uint32_t v = stream_ids[s];
    do { digits[d++] = "0123456789ABCDEF"[v & 15]; v >>= 4; } while (v);
    while (d) prefix[at++] = digits[--d];
    prefix[at] = 0;
    stk_line_begin(&l, e->sink, prefix, 1);
    if (skip) {
        stk_line_str(&l, "SKIPPED", skip);
    } else if (scan_err) {
        if (scan_err == STK_E_FAULT) stk_line_str(&l, "FAULT", "SMR");
        else stk_line_str(&l, "SKIPPED", stk_err_name(scan_err));
    } else {
        const struct stk_stream *st = &scan->stream[s];
        if (!st->found) {
            stk_line_str(&l, "SMR", "NONE");
            stk_line_str(&l, "TYPE", "NONE");
            stk_line_str(&l, "CBNDX", "NONE");
        } else {
            stk_line_dec(&l, "SMR", st->index);
            if (!st->s2cr_read) {
                stk_line_unknown(&l, "TYPE");
                stk_line_unknown(&l, "CBNDX");
            } else {
                stk_line_str(&l, "TYPE", st->type == 0 ? "TRANS" : st->type == 1 ? "BYPASS" : st->type == 2 ? "FAULT" : "?");
                stk_line_dec(&l, "CBNDX", st->cbndx);
            }
            if (st->matches > 1) stk_line_dec(&l, "MULTI", st->matches);
        }
    }
    stk_line_end(&l);
}

static void blk_smmu(struct env *e, struct stk_smmu_obs *obs)
{
    struct rdset s = {e, STK_WIN_SMMU, 0, 0, NULL};
    struct stk_reg scr0, id0, gfsr;
    struct stk_line l;
    struct stk_smr_scan scan = {0};
    int scan_err = STK_OK;
    next(e, "SMMU", 1);
    set_rd(&s, "SCR0", SMMU_SCR0, &scr0);
    set_rd(&s, "ID0", SMMU_ID0, &id0);
    set_rd(&s, "GFSR", SMMU_SGFSR, &gfsr);
    int answered = !scr0.err && !id0.err;
    /* All ones is what the bus returns for a block that is not there, and no SMMU has an ID0 or an sCR0
     * like that: such a block is not read as an SMMU, whatever its bits would then claim. */
    int plausible = answered && id0.v != 0xffffffffu && scr0.v != 0xffffffffu;
    const char *skip = !answered ? "NO_GLOBAL" : !plausible ? "NOT_SMMU" : NULL;
    stk_line_begin(&l, e->sink, "STK P3 SMMU", 1);
    kv_hex(&l, "ID0", &id0);
    if (!id0.err && !plausible) stk_line_unknown(&l, "NUMSMRG");
    else kv_dec(&l, "NUMSMRG", &id0, 0, 0xff);
    kv_hex(&l, "SCR0", &scr0);
    if (!scr0.err && !plausible) {
        stk_line_unknown(&l, "USFCFG");
        stk_line_unknown(&l, "CLIENTPD");
        stk_line_unknown(&l, "EXID");
    } else {
        kv_bit(&l, "USFCFG", &scr0, 10);
        kv_bit(&l, "CLIENTPD", &scr0, 0);
        kv_bit(&l, "EXID", &scr0, 3);
    }
    kv_hex(&l, "GFSR", &gfsr);
    note(&l, &s);
    if (answered && !plausible && !s.first_err) stk_line_str(&l, "SKIPPED", skip);
    stk_line_end(&l);

    obs->global_read = plausible;
    obs->clientpd = plausible && (scr0.v & 1);
    obs->usfcfg = plausible && ((scr0.v >> 10) & 1);
    if (plausible) {
        struct winrd w = {e, STK_WIN_SMMU};
        stk_sink_at(e->sink, "SMR");
        stk_smr_scan(winrd_fn, &w, id0.v & 0xff, (scr0.v >> 3) & 1, (id0.v >> 9) & 0xf, stream_ids, &scan);
        scan_err = scan.status;
        if (!scan_err)
            for (unsigned k = 0; k < STK_STREAMS; k++) obs->stream[k] = scan.stream[k];
    }
    for (unsigned k = 0; k < STK_STREAMS; k++) put_stream(e, k, &scan, scan_err, skip);
}

/* ---- The run ------------------------------------------------------------------------------------- */

void stk_el2_run(const struct stk_el2_args *args, struct stk_result *result)
{
    struct env e = {args, args->ops, args->sink, {0}, 0, 0, 0};
    struct ctrl ctrl[STK_CONTROLLERS];
    struct stk_reg gdscr[STK_CONTROLLERS], clk[STK_CONTROLLERS][STK_GATE_CLOCKS];
    int shared_fault = 0, own_fault[STK_CONTROLLERS];

    for (unsigned w = 0; w < STK_WINDOWS; w++) {
        const struct stk_window *win = &stk_windows[w];
        e.window_err[w] = !args->map_ok ? STK_E_NO_MAP
                          : !stk_map_range_allows_device(args->map, args->map_count, win->base, win->size) ? STK_E_MAP_RAM
                                                                                                          : STK_OK;
    }
    for (unsigned i = 0; i < STK_CONTROLLERS; i++) {
        ctrl[i] = (struct ctrl){0};
        ctrl[i].idx = i;
        ctrl[i].win = STK_WIN_U0 + (int)i;
        ctrl[i].name[0] = 'U';
        ctrl[i].name[1] = (char)('0' + i);
    }

    stk_p2_replay(args->sink, args->p2);
    blk_map(&e);

    /* GCC: the GDSC and the controller's own clocks, then the four shared NoC clocks. */
    next(&e, "GCC", 0);
    for (unsigned i = 0; i < STK_CONTROLLERS; i++) {
        struct rdset s = {&e, STK_WIN_GCC, 0, 0, NULL};
        struct stk_line l;
        char prefix[24];
        stk_sink_at(args->sink, i ? "GCC U1" : "GCC U0");
        set_rd(&s, "GDSCR", gcc_ctrl[i].gdscr, &gdscr[i]);
        set_rd(&s, "MASTER", gcc_ctrl[i].master, &clk[i][0]);
        set_rd(&s, "UTMI", gcc_ctrl[i].utmi, &clk[i][1]);
        set_rd(&s, "SLEEP", gcc_ctrl[i].sleep, &clk[i][2]);
        set_rd(&s, "CFGNOC", gcc_ctrl[i].cfgnoc, &clk[i][3]);
        set_rd(&s, "AGGRE", gcc_ctrl[i].aggre, &clk[i][4]);
        prefix_of(prefix, "STK P3 GCC ", ctrl[i].name, "");
        stk_line_begin(&l, args->sink, prefix, 0);
        kv_hex(&l, "GDSCR", &gdscr[i]);
        kv_bit(&l, "PWR", &gdscr[i], 31);
        kv_bit(&l, "SWC", &gdscr[i], 0);
        kv_hex(&l, "MASTER", &clk[i][0]);
        kv_hex(&l, "UTMI", &clk[i][1]);
        kv_hex(&l, "SLEEP", &clk[i][2]);
        kv_hex(&l, "CFGNOC", &clk[i][3]);
        kv_hex(&l, "AGGRE", &clk[i][4]);
        note(&l, &s);
        stk_line_end(&l);
        own_fault[i] = s.first_err == STK_E_FAULT;
    }
    {
        struct rdset s = {&e, STK_WIN_GCC, 0, 0, NULL};
        struct stk_line l;
        struct stk_reg shared[4];
        stk_sink_at(args->sink, "GCC SHARED");
        set_rd(&s, "NOC", gcc_shared[0], &shared[0]);
        set_rd(&s, "SYS", gcc_shared[1], &shared[1]);
        set_rd(&s, "NORTH", gcc_shared[2], &shared[2]);
        set_rd(&s, "SOUTH", gcc_shared[3], &shared[3]);
        stk_line_begin(&l, args->sink, "STK P3 GCC SHARED", 0);
        kv_hex(&l, "NOC", &shared[0]);
        kv_hex(&l, "SYS", &shared[1]);
        kv_hex(&l, "NORTH", &shared[2]);
        kv_hex(&l, "SOUTH", &shared[3]);
        note(&l, &s);
        stk_line_end(&l);
        shared_fault = s.first_err == STK_E_FAULT;
        for (unsigned i = 0; i < STK_CONTROLLERS; i++)
            for (unsigned k = 0; k < 4; k++) clk[i][5 + k] = shared[k];
    }

    /* GATE: pure, from what was read. */
    {
        struct stk_line l;
        stk_line_begin(&l, args->sink, "STK P3 GATE", 0);
        for (unsigned i = 0; i < STK_CONTROLLERS; i++) {
            ctrl[i].gate = stk_gate(&gdscr[i], clk[i]);
            ctrl[i].gcc_fault = own_fault[i] || shared_fault;
            ctrl[i].obs.gate = ctrl[i].gate;
            ctrl[i].obs.gcc_fault = ctrl[i].gcc_fault;
            stk_line_str(&l, ctrl[i].name, stk_gate_name(ctrl[i].gate));
        }
        stk_line_end(&l);
    }

    for (unsigned i = 0; i < STK_CONTROLLERS; i++) blk_ctrl(&e, &ctrl[i]);
    for (unsigned i = 0; i < STK_CONTROLLERS; i++) blk_fwrings(&e, &ctrl[i]);

    struct stk_smmu_obs smmu = {0};
    blk_smmu(&e, &smmu);

    int verdict[STK_CONTROLLERS];
    unsigned mask = 0;
    for (unsigned i = 0; i < STK_CONTROLLERS; i++) {
        verdict[i] = stk_ctrl_verdict(&ctrl[i].obs);
        if (verdict[i] == STK_V_STICK_RUNNING || verdict[i] == STK_V_STICK_HALTED) mask |= 1u << i;
    }
    /* The stick's stream when one controller shows it; otherwise both are judged. */
    int smmu_verdict = stk_smmu_verdict(&smmu, mask ? mask : (1u << STK_STREAMS) - 1u);

    struct stk_line l;
    if (args->sink->dropped) {
        stk_line_begin(&l, args->sink, "STK P3 TRUNC", 1);
        stk_line_dec(&l, "DROPPED", args->sink->dropped);
        stk_line_end(&l);
    }
    stk_sink_at(args->sink, "DONE");
    stk_line_begin(&l, args->sink, "STK P3 VERDICT", 1);
    for (unsigned i = 0; i < STK_CONTROLLERS; i++) stk_line_str(&l, ctrl[i].name, stk_verdict_name(verdict[i]));
    stk_line_str(&l, "SMMU", stk_smmu_name(smmu_verdict));
    stk_line_end(&l);

    if (result) {
        for (unsigned i = 0; i < STK_CONTROLLERS; i++) {
            result->verdict[i] = verdict[i];
            result->gate[i] = ctrl[i].gate;
        }
        result->smmu = smmu_verdict;
        result->reads = e.reads;
        result->faults = e.faults;
        result->refusals = e.refusals;
    }
}

#endif /* Q1N1_SP11_STK_SURVEY */
