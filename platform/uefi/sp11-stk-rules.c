/* SPDX-License-Identifier: MIT */
/* The survey's decisions and bounded walkers (sp11-stk-survey.h): memory map classification, the
 * gate rule, the verdicts, and the walks over xHCI extended capabilities, the firmware's slot
 * contexts and the SMMU stream match registers. All of it works through read callbacks that apply
 * the policy checks (window, memory map, mapping attribute) before any load, so it can be driven by
 * a fake register file. Every loop has a bound that does not depend on what a register says.
 *
 * Register layouts: the xHCI ones follow the xHCI specification (not fetched here: INFERRED from the
 * field positions q1n1's own xhci.c already uses, root port at bits 23:16 of slot dword 1, speed at
 * 23:20 of dword 0, context entries at 31:27); the SMMU ones are VERIFIED only as what the pinned
 * Linux arm-smmu.h says. */
#include "sp11-stk-survey.h"

#if Q1N1_SP11_STK_SURVEY

const char *stk_err_name(int err)
{
    switch (err) {
    case STK_E_FAULT: return "FAULT";
    case STK_E_RANGE: return "RANGE";
    case STK_E_NO_MAP: return "NO_MAP";
    case STK_E_MAP_RAM: return "MAP_RAM";
    case STK_E_UNMAPPED: return "UNMAPPED";
    case STK_E_NOT_DEVICE: return "NOT_DEVICE";
    case STK_E_ATTR: return "ATTR_UNKNOWN";
    case STK_E_NOT_RAM: return "NOT_RAM";
    case STK_E_BUDGET: return "BUDGET";
    case STK_E_NOT_READ: return "NOT_READ";
    default: return "?";
    }
}

/* ---- Memory map ---------------------------------------------------------------------------------- */

int stk_type_is_ram(uint32_t type) { return (type >= 1 && type <= 7) || type == 9; }
int stk_type_allows_device(uint32_t type) { return type == 0 || type == 11 || type == 12; }

/* A descriptor with no pages, or with a page count that cannot be a real range, describes nothing. */
static int span(const struct q1n1_sp11_gop_map_entry *d, uint64_t *start, uint64_t *end)
{
    if (!d->pages || d->pages >= (UINT64_C(1) << 40)) return 0;
    *start = d->base;
    *end = d->base + d->pages * 4096;
    return *end > *start;
}

int stk_map_range_is_ram(const struct q1n1_sp11_gop_map_entry *map, uint32_t count, uint64_t base,
                         uint64_t size)
{
    uint64_t end = base + size, start, stop;
    if (!map || !size || end < base) return 0;
    /* A descriptor of another kind over any of the bytes makes the answer no, even if RAM also
     * covers them: the map is then contradicting itself and nothing here follows a pointer into it. */
    for (uint32_t i = 0; i < count; i++)
        if (span(&map[i], &start, &stop) && start < end && stop > base && !stk_type_is_ram(map[i].type)) return 0;
    uint64_t at = base;
    /* Each pass moves to the end of one descriptor holding `at`, so `count` passes are enough; RAM
     * split over adjacent descriptors is still RAM. */
    for (uint32_t pass = 0; pass <= count && at < end; pass++) {
        uint64_t next = at;
        for (uint32_t i = 0; i < count; i++)
            if (span(&map[i], &start, &stop) && start <= at && at < stop && stk_type_is_ram(map[i].type) && stop > next)
                next = stop;
        if (next == at) return 0;
        at = next;
    }
    return at >= end;
}

int stk_map_range_allows_device(const struct q1n1_sp11_gop_map_entry *map, uint32_t count, uint64_t base,
                                uint64_t size)
{
    uint64_t end = base + size, start, stop;
    if (!map || !size || end < base) return 0;
    for (uint32_t i = 0; i < count; i++)
        if (span(&map[i], &start, &stop) && start < end && stop > base && !stk_type_allows_device(map[i].type))
            return 0;
    return 1;
}

/* ---- Gate ---------------------------------------------------------------------------------------- */

/* GDSCR bit 31 is PWR_ON (gdsc.c PWR_ON_MASK) and a branch clock's bit 31 is CLK_OFF
 * (clk-branch.h CBCR_CLK_OFF). All nine clocks here are clk_branch2 with BRANCH_HALT or
 * BRANCH_HALT_VOTED, so "bit 31 clear" is "running" and none is inverted (gcc-x1e80100.c).
 *
 * The rule is conservative on purpose (docs/SP11-STICK-LOG.md section 3.6): the voted clocks are
 * also hardware clock gated (hwcg_bit 1), and Linux does not check their halt bit in that mode, so a
 * clock that is off but unneeded reads PARTIAL and the controller is not read. A register that could
 * not be read proves nothing: it makes the gate UNKNOWN, never ON. */
int stk_gate(const struct stk_reg *gdscr, const struct stk_reg clk[STK_GATE_CLOCKS])
{
    if (gdscr->err) return STK_GATE_UNKNOWN;
    if (!(gdscr->v >> 31)) return STK_GATE_OFF;
    int unknown = 0;
    for (unsigned i = 0; i < STK_GATE_CLOCKS; i++) {
        if (clk[i].err) unknown = 1;
        else if (clk[i].v >> 31) return STK_GATE_PARTIAL;
    }
    return unknown ? STK_GATE_UNKNOWN : STK_GATE_ON;
}

const char *stk_gate_name(int gate)
{
    switch (gate) {
    case STK_GATE_ON: return "ON";
    case STK_GATE_PARTIAL: return "PARTIAL";
    case STK_GATE_OFF: return "OFF";
    default: return "?";
    }
}

/* ---- Verdicts ------------------------------------------------------------------------------------ */

const char *stk_verdict_name(int verdict)
{
    switch (verdict) {
    case STK_V_GATED_OFF: return "GATED-OFF";
    case STK_V_FAULT: return "FAULT";
    case STK_V_NOT_XHCI: return "NOT-XHCI";
    case STK_V_STICK_RUNNING: return "STICK-PRESENT-RUNNING";
    case STK_V_STICK_HALTED: return "STICK-PRESENT-HALTED";
    case STK_V_IDLE: return "IDLE";
    case STK_V_INCONSISTENT: return "INCONSISTENT";
    case STK_V_UNREAD: return "UNREAD";
    case STK_V_CONNECTED: return "CONNECTED-NO-SLOT";
    default: return "?";
    }
}

/* PORTSC: CCS bit 0, PED bit 1, PP bit 9 (xHCI 5.4.8). The rules the specification states: a port
 * that is not powered is not connected (CCS reads 0 when PP is 0), and only a connected, powered
 * port can be enabled. All ones is what a bus error or a missing device returns, never a port. */
int stk_port_inconsistent(uint32_t sc)
{
    int ccs = sc & 1, ped = (sc >> 1) & 1, pp = (sc >> 9) & 1;
    return (ccs && !pp) || (ped && !ccs) || (ped && !pp) || sc == 0xffffffffu;
}

unsigned stk_port_pls(uint32_t sc) { return (sc >> 5) & 0xf; }
unsigned stk_port_speed(uint32_t sc) { return (sc >> 10) & 0xf; }

int stk_ctrl_verdict(const struct stk_ctrl_obs *o)
{
    if (o->gate == STK_GATE_UNKNOWN) return o->gcc_fault ? STK_V_FAULT : STK_V_UNREAD;
    if (o->gate != STK_GATE_ON) return STK_V_GATED_OFF;
    /* Past this point the controller was read; any abort anywhere in it is the headline. */
    if (o->fault) return STK_V_FAULT;
    if (!o->id_read) return STK_V_UNREAD;
    if (!o->xhci_plausible) return STK_V_NOT_XHCI;
    if (!o->usbsts_read) return STK_V_UNREAD;
    if (o->usbsts_allones) return STK_V_INCONSISTENT;
    int connected = 0, stick = 0, unread = 0;
    for (unsigned i = 0; i < o->ports && i < STK_PORTS_SHOWN; i++) {
        const struct stk_port *p = &o->port[i];
        if (!p->read) { unread = 1; continue; }
        if (stk_port_inconsistent(p->sc)) return STK_V_INCONSISTENT;
        if (p->sc & 1) {
            connected = 1;
            /* Port numbers are 1 based, and a slot names its root port the same way. */
            for (unsigned s = 0; s < o->slots && s < STK_SLOTS_SHOWN; s++)
                if (o->slot[s].root_port == i + 1) stick = 1;
        }
    }
    if (stick) return o->hch ? STK_V_STICK_HALTED : STK_V_STICK_RUNNING;
    if (connected) return STK_V_CONNECTED;
    return unread ? STK_V_UNREAD : STK_V_IDLE;
}

const char *stk_smmu_name(int verdict)
{
    switch (verdict) {
    case STK_SMMU_BYPASS: return "BYPASS";
    case STK_SMMU_TRANS: return "TRANS";
    case STK_SMMU_FAULT: return "FAULT";
    default: return "UNREAD";
    }
}

/* What one stream does to a DMA transaction. CLIENTPD set means the SMMU is out of the way for every
 * stream (client port disabled: transactions bypass). A stream no entry matches follows sCR0.USFCFG:
 * faulted when set, passed through when clear. Two entries matching one stream is a multi-match,
 * which the hardware faults. S2CR type 3 is reserved: not claimed to be anything but a fault. */
static int stream_state(const struct stk_smmu_obs *o, const struct stk_stream *s)
{
    if (!o->global_read || !s->scanned) return STK_SMMU_UNREAD;
    if (o->clientpd) return STK_SMMU_BYPASS;
    if (s->found) {
        if (s->matches > 1) return STK_SMMU_FAULT;
        if (!s->s2cr_read) return STK_SMMU_UNREAD;
        if (s->type == 0) return STK_SMMU_TRANS;
        if (s->type == 1) return STK_SMMU_BYPASS;
        return STK_SMMU_FAULT;
    }
    return o->usfcfg ? STK_SMMU_FAULT : STK_SMMU_BYPASS;
}

/* The worst state over the streams in stream_mask: FAULT, then UNREAD, then TRANS, then BYPASS. */
int stk_smmu_verdict(const struct stk_smmu_obs *o, unsigned stream_mask)
{
    static const int rank[] = {[STK_SMMU_BYPASS] = 0, [STK_SMMU_TRANS] = 1, [STK_SMMU_UNREAD] = 2,
                               [STK_SMMU_FAULT] = 3};
    int worst = -1;
    int result = STK_SMMU_UNREAD;
    for (unsigned s = 0; s < STK_STREAMS; s++) {
        if (!(stream_mask & (1u << s))) continue;
        int state = stream_state(o, &o->stream[s]);
        if (rank[state] > worst) { worst = rank[state]; result = state; }
    }
    return result;
}

/* ---- xHCI extended capabilities ------------------------------------------------------------------- */

#define XECP_ID_PROTOCOL 2
#define XECP_NAME_USB 0x20425355u       /* "USB " */

/* HCCPARAMS1.xECP is a dword offset from the window base; each capability's "next" is a dword offset
 * from itself, 8 bits, so every step goes forward. A list can still be endless (a register file that
 * keeps answering with a next pointer), so the walk visits at most STK_XECP_MAX_CAPS capabilities and
 * never reads outside the window. */
void stk_xecp_walk(stk_rd32_fn rd, void *ctx, uint32_t xecp, uint32_t window_size, struct stk_xecp *out)
{
    out->status = STK_OK;
    out->caps = out->protos = 0;
    out->truncated = 0;
    if (!xecp) return;
    uint32_t off = xecp * 4;
    for (unsigned n = 0; n < STK_XECP_MAX_CAPS; n++) {
        uint32_t d0, d1, d2;
        int err;
        if (off > window_size || window_size - off < 4) { out->status = STK_E_RANGE; return; }
        if ((err = rd(ctx, off, &d0))) { out->status = err; return; }
        out->caps++;
        if ((d0 & 0xff) == XECP_ID_PROTOCOL) {
            if ((err = rd(ctx, off + 4, &d1)) || (err = rd(ctx, off + 8, &d2))) { out->status = err; return; }
            if (d1 == XECP_NAME_USB && out->protos < STK_XECP_PROTOS) {
                out->proto[out->protos].major = d0 >> 24;
                out->proto[out->protos].minor = (d0 >> 16) & 0xff;
                out->proto[out->protos].first = d2 & 0xff;
                out->proto[out->protos].count = (d2 >> 8) & 0xff;
                out->protos++;
            }
        }
        unsigned next = (d0 >> 8) & 0xff;
        if (!next) return;
        off += next * 4;
    }
    out->truncated = 1;
}

/* ---- The firmware's device contexts --------------------------------------------------------------- */

void stk_slot_decode_head(const uint32_t dw[4], struct stk_slot *out)
{
    out->route = dw[0] & 0xfffff;
    out->speed = (dw[0] >> 20) & 0xf;
    out->hub = (dw[0] >> 26) & 1;
    out->entries = dw[0] >> 27;
    out->root_port = (dw[1] >> 16) & 0xff;
    out->address = dw[3] & 0xff;
    out->state = dw[3] >> 27;
}

#define DCBAA_ALIGN 64u
#define EP_DCI_MAX 31u

/* Reads `slots` entries of the device context base address array and decodes the contexts they point
 * at. Every pointer is handed to `rd` (which refuses what the memory map does not show as RAM) before
 * anything is loaded through it, and is refused here when it is not 64 byte aligned. A refused slot
 * is kept with its error; an abort ends the walk. */
void stk_slot_walk(stk_ram_read_fn rd, void *ctx, uint64_t dcbaap, unsigned slots, unsigned ctxsz,
                   struct stk_slots *out)
{
    uint32_t raw[2 * (STK_SLOTS_SCANNED + 1)];
    out->status = STK_OK;
    out->scanned = out->nonempty = out->shown = 0;
    if (slots > STK_SLOTS_SCANNED) slots = STK_SLOTS_SCANNED;
    if (ctxsz != 32 && ctxsz != 64) { out->status = STK_E_RANGE; return; }
    if (dcbaap & (DCBAA_ALIGN - 1)) { out->status = STK_E_RANGE; return; }
    int err = rd(ctx, dcbaap, raw, 8 * (slots + 1));
    if (err) { out->status = err; return; }
    for (unsigned id = 1; id <= slots; id++) {
        uint64_t entry = (uint64_t)raw[2 * id] | (uint64_t)raw[2 * id + 1] << 32;
        out->scanned++;
        if (!entry) continue;
        out->nonempty++;
        if (out->shown >= STK_SLOTS_SHOWN) continue;
        struct stk_slot *s = &out->slot[out->shown];
        out->slot_id[out->shown] = id;
        out->shown++;
        s->ctx = entry;
        s->err = STK_OK;
        s->eps = s->shown = 0;
        s->route = s->root_port = s->speed = s->state = s->address = s->entries = 0;
        s->hub = 0;
        uint32_t head[4];
        if (entry & (DCBAA_ALIGN - 1)) { s->err = STK_E_RANGE; continue; }
        if ((err = rd(ctx, entry, head, sizeof head))) {
            if (err == STK_E_FAULT) { out->status = err; return; }
            s->err = err;
            continue;
        }
        stk_slot_decode_head(head, s);
        unsigned last = s->entries < EP_DCI_MAX ? s->entries : EP_DCI_MAX;
        for (unsigned dci = 1; dci <= last; dci++) {
            uint32_t ep[2];
            if ((err = rd(ctx, entry + (uint64_t)dci * ctxsz, ep, sizeof ep))) {
                if (err == STK_E_FAULT) { out->status = err; return; }
                break;
            }
            if (!(ep[0] & 7)) continue;       /* disabled */
            s->eps++;
            if (s->shown < STK_EP_SHOWN) {
                s->ep[s->shown].dci = dci;
                s->ep[s->shown].state = ep[0] & 7;
                s->ep[s->shown].type = (ep[1] >> 3) & 7;
                s->ep[s->shown].mps = ep[1] >> 16;
                s->shown++;
            }
        }
    }
}

/* ---- SMMU stream matching ------------------------------------------------------------------------ */

#define SMMU_SMR(n) (0x800u + 4u * (n))
#define SMMU_S2CR(n) (0xc00u + 4u * (n))

/* One pass over the stream match registers serves both streams. An entry counts when it is valid
 * (SMR bit 31, or S2CR.EXIDVALID in extended mode) and ((stream ^ id) & ~mask) is zero over the
 * stream id bits the SMMU implements; the lowest match wins and further matches are counted, since
 * two matching entries is a multi-match. The scan is bounded by NUMSMRG's own width. */
void stk_smr_scan(stk_rd32_fn rd, void *ctx, unsigned numsmrg, int exid, unsigned numsidb,
                  const uint32_t stream_id[STK_STREAMS], struct stk_smr_scan *out)
{
    out->status = STK_OK;
    out->scanned = 0;
    for (unsigned s = 0; s < STK_STREAMS; s++) {
        out->stream[s].scanned = out->stream[s].found = out->stream[s].s2cr_read = 0;
        out->stream[s].index = out->stream[s].matches = out->stream[s].type = out->stream[s].cbndx = 0;
    }
    if (numsmrg > STK_SMR_MAX) numsmrg = STK_SMR_MAX;
    uint32_t implemented = exid || numsidb >= 16 ? 0xffffu : (1u << numsidb) - 1u;
    for (unsigned n = 0; n < numsmrg; n++) {
        uint32_t smr, s2cr = 0;
        int err = rd(ctx, SMMU_SMR(n), &smr);
        if (!err && exid) err = rd(ctx, SMMU_S2CR(n), &s2cr);
        if (err) { out->status = err; return; }
        out->scanned++;
        if (!(exid ? (s2cr >> 10) & 1 : smr >> 31)) continue;
        uint32_t id = smr & 0xffff, mask = (smr >> 16) & 0xffff;
        for (unsigned s = 0; s < STK_STREAMS; s++) {
            if ((stream_id[s] ^ id) & ~mask & implemented) continue;
            if (!out->stream[s].matches++) {
                out->stream[s].found = 1;
                out->stream[s].index = n;
            }
        }
    }
    for (unsigned s = 0; s < STK_STREAMS; s++) {
        struct stk_stream *st = &out->stream[s];
        st->scanned = 1;
        if (!st->found) continue;
        uint32_t s2cr;
        if (rd(ctx, SMMU_S2CR(st->index), &s2cr)) continue;
        st->s2cr_read = 1;
        st->type = (s2cr >> 16) & 3;
        st->cbndx = s2cr & 0xff;
    }
}

#endif /* Q1N1_SP11_STK_SURVEY */
