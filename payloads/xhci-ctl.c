/* SPDX-License-Identifier: MIT */
/* Payload "xhci", the controller sequence (docs/SP11-PAYLOAD-XHCI.md; xhci-priv.h lists the parts): the announcement that opens each write
 * group, then reset, program, run, No Op and halt, and the attempt that strings them together over one arena. Every store goes through
 * store() and ram_put() (xhci-io.c); every device register it reads goes through rd32(). */
#include "xhci-priv.h"

/* ---- The announcement --------------------------------------------------------------------------------------------------------------- */

/* NEXT <what> AFTER 8 S, eight seconds on the counter, then the group is open. W_LINES, and nothing opened, if the line could not be printed;
 * W_CLOCK, and nothing opened, if the counter does not run. */
OUT_OF_LINE int announce(struct ctx *c, unsigned group, const char *what, uint64_t base, uint64_t pages)
{
    int printed;
    if (group == G_ARENA) printed = say(c, "NEXT ARENA %d %s %x PAGES %d AFTER 8 S", U(c->arena.id), arena_name[c->arena.id], base, pages);
    else printed = say(c, "NEXT %s AFTER 8 S", what);
    if (!printed) return W_LINES;
    if (!delay_ticks(c, c->hz * WAIT_BEFORE_WRITE_S)) return W_CLOCK;
    c->armed |= group;
    return W_NONE;
}

/* ---- The controller ------------------------------------------------------------------------------------------------------------------ */

/* Reads a register until (value & mask) == want, every POLL_US for the first POLL_FAST_WINDOW_US and every POLL_SLOW_US after that (a reset may take a second
 * and does not need a thousand loads). W_NONE; W_EVENT on a timeout; W_READ, W_BUDGET or W_CLOCK. */
int poll_xhc(struct ctx *c, uint64_t off, const char *name, uint32_t mask, uint32_t want, uint32_t timeout_us, uint32_t *last)
{
    uint64_t start = c->a->ops.counter(), fast = (uint64_t)POLL_FAST_WINDOW_US * c->hz / 1000000u;
    for (;;) {
        uint64_t elapsed;
        if (rd32(c, TARGET, off, last, name)) return c->failure == RD_BUDGET ? W_BUDGET : W_READ;
        if ((*last & mask) == want) return W_NONE;
        elapsed = c->a->ops.counter() - start;
        if (elapsed >= (uint64_t)timeout_us * c->hz / 1000000u) return W_EVENT;
        if (!delay_us(c, elapsed < fast ? POLL_US : POLL_SLOW_US)) return W_CLOCK;
    }
}

OUT_OF_LINE int read_state(struct ctx *c)
{
    struct xhc *x = &c->x[TARGET];
    if (rd32(c, TARGET, x->op + OP_USBCMD, &x->cmd, "USBCMD") || rd32(c, TARGET, x->op + OP_USBSTS, &x->sts, "USBSTS")) return W_READ;
    c->cmd_seen = x->cmd;
    return W_NONE;
}

/* Clears R/S if set and waits for HCH. W_NONE once the controller reads halted. */
OUT_OF_LINE int xhc_halt(struct ctx *c, uint32_t *sts)
{
    int why = read_state(c);
    if (why) return why;
    if (c->x[TARGET].cmd & CMD_RS && store(c, G_STOP, SR_USBCMD, c->x[TARGET].cmd & ~(uint32_t)CMD_RS)) return W_STORE;
    why = poll_xhc(c, c->x[TARGET].op + OP_USBSTS, "USBSTS", STS_HCH, STS_HCH, T_HALT_US, sts);
    return why == W_EVENT ? W_HALT : why;
}

/* Halt if running, HCRST, then HCRST and CNR must clear (xHCI 1.2 sections 4.2 and 5.4.1) and the controller must read halted without HSE or HCE. */
OUT_OF_LINE int xhc_reset(struct ctx *c, struct result *r)
{
    const struct xhc *x = &c->x[TARGET];
    uint32_t sts = 0, cmd = 0;
    int why = read_state(c);
    r->stage = STG_RESET;
    if (why) return why;
    if ((x->cmd & CMD_RS) || !(x->sts & STS_HCH)) {
        why = xhc_halt(c, &sts);
        if (why) return why;
        if ((why = read_state(c))) return why;
    }
    if (store(c, G_RESET, SR_USBCMD, x->cmd | CMD_HCRST)) return W_STORE;
    why = poll_xhc(c, x->op + OP_USBCMD, "USBCMD", CMD_HCRST, 0, T_RESET_US, &cmd);
    if (why) return why == W_EVENT ? W_HCRST : why;
    why = poll_xhc(c, x->op + OP_USBSTS, "USBSTS", STS_CNR, 0, T_CNR_US, &sts);
    r->sts = sts;
    if (why) return why == W_EVENT ? W_CNR : why;
    return sts & STS_HCE ? W_HCE : sts & STS_HSE ? W_HSE : sts & STS_HCH ? W_NONE : W_HCH;
}

/* The registers of the arena's structures in the order of xHCI 1.2 section 4.2. CONFIG, DCBAAP, ERSTSZ, ERSTBA and ERDP are read back; CRCR is not (its
 * pointer reads zero in a halted xHC, INFERRED), and nor are the doorbell and IMAN, which hold no value. */
OUT_OF_LINE int xhc_program(struct ctx *c, struct result *r)
{
    const struct xhc *x = &c->x[TARGET];
    uint64_t base = c->arena.base, dcbaa = base + OFF_DCBAA, cmd = base + OFF_CMD, erst = base + OFF_ERST, event = base + OFF_EVENT, got64 = 0;
    uint32_t got32 = 0;
    r->stage = STG_PROGRAM;
    if (store(c, G_PROGRAM, SR_CONFIG, x->slots)) return W_STORE;
    if (store(c, G_PROGRAM, SR_DCBAAP_LO, (uint32_t)dcbaa) || store(c, G_PROGRAM, SR_DCBAAP_HI, (uint32_t)(dcbaa >> 32))) return W_STORE;
    if (store(c, G_PROGRAM, SR_CRCR_LO, (uint32_t)cmd | CRCR_RCS) || store(c, G_PROGRAM, SR_CRCR_HI, (uint32_t)(cmd >> 32))) return W_STORE;
    if (store(c, G_PROGRAM, SR_ERSTSZ, 1)) return W_STORE;
    if (store(c, G_PROGRAM, SR_ERDP_LO, (uint32_t)event) || store(c, G_PROGRAM, SR_ERDP_HI, (uint32_t)(event >> 32))) return W_STORE;
    if (store(c, G_PROGRAM, SR_ERSTBA_LO, (uint32_t)erst) || store(c, G_PROGRAM, SR_ERSTBA_HI, (uint32_t)(erst >> 32))) return W_STORE;
    if (rd32(c, TARGET, x->op + OP_CONFIG, &got32, "CONFIG") || rd64(c, TARGET, x->op + OP_DCBAAP, &got64, "DCBAAP")) return W_READ;
    if (got32 != x->slots || got64 != dcbaa) return W_HELD;
    if (rd32(c, TARGET, x->ir0 + IR_ERSTSZ, &got32, "ERSTSZ") || rd64(c, TARGET, x->ir0 + IR_ERSTBA, &got64, "ERSTBA")) return W_READ;
    if (got32 != 1 || got64 != erst) return W_HELD;
    if (rd64(c, TARGET, x->ir0 + IR_ERDP, &got64, "ERDP")) return W_READ;
    return got64 == event ? W_NONE : W_HELD;
}

/* R/S, then HCH must clear: the xHC runs. HSE or HCE at the poll is the answer. */
OUT_OF_LINE int xhc_run(struct ctx *c, struct result *r)
{
    uint32_t sts = 0;
    int why = read_state(c);
    r->stage = STG_RUN;
    if (why) return why;
    if (store(c, G_RUN, SR_USBCMD, c->x[TARGET].cmd | CMD_RS)) return W_STORE;
    why = poll_xhc(c, c->x[TARGET].op + OP_USBSTS, "USBSTS", STS_HCH, 0, T_RUN_US, &sts);
    r->sts = sts;
    if (sts & STS_HCE) return W_HCE;
    if (sts & STS_HSE) return W_HSE;
    return why == W_EVENT ? W_HCH : why;
}

/* Takes the valid events from the ring's dequeue position (the cycle bit is 1 for the first lap, which is all this reads). A port status
 * change, which a controller posts once it runs, is counted and skipped. W_NONE: the No Op completed. W_POINTER, W_CODE: a completion
 * that is not the one for our TRB, or not a success. W_STORE: a cache operation the arena gate refused. -1: nothing yet. */
OUT_OF_LINE int events_take(struct ctx *c, struct result *r, uint32_t *index, uint64_t trb, uint64_t ring)
{
    while (*index < EVENTS_MAX) {
        uint64_t slot = ring + (uint64_t)*index * TRB_BYTES, pointer;
        uint32_t control, status;
        for (uint64_t at = slot; at < slot + TRB_BYTES; at += CACHE_STEP) {
            if (!arena_range(c, at, CACHE_STEP)) return W_STORE;
            dc_civac(at);
        }
        dsb_sy();
        control = ram_load32(slot + 12);
        if (!(control & 1u)) return -1;
        pointer = (uint64_t)ram_load32(slot) | (uint64_t)ram_load32(slot + 4) << 32;
        status = ram_load32(slot + 8);
        (*index)++;
        r->events++;
        if ((control >> 10 & 0x3f) == TRB_PORT_STATUS) {
            r->psc++;
        } else if ((control >> 10 & 0x3f) == TRB_CMD_COMPLETION) {
            r->cc = status >> 24;
            return pointer != trb ? W_POINTER : r->cc != CC_SUCCESS ? W_CODE : W_NONE;
        }
    }
    return -1;
}

/* One No Op Command TRB, the doorbell, and the Command Completion Event: type, a success code, the pointer to our TRB and the cycle bit
 * (xHCI 1.2 sections 4.6.2, 6.4.2.2 and 4.9.4). An event ring slot that is not all zero and not valid is an event written with the wrong
 * cycle bit: a bad completion, not a silent controller. Once an event was taken the ring is handed back (ERDP with EHB) and IP is cleared.
 * A controller that says it posted an event (USBSTS.EINT, clear when the doorbell was rung) while the ring holds none has written it somewhere else
 * (or our reads do not see it): that is a REDIRECT, a bad completion that ends the run, not a timeout that tries the next arena. */
OUT_OF_LINE int xhc_noop(struct ctx *c, struct result *r)
{
    const struct xhc *x = &c->x[TARGET];
    uint64_t trb = c->arena.base + OFF_CMD, ring = c->arena.base + OFF_EVENT, start, dequeue;
    uint32_t index = 0, sts = 0, before = 0;
    int found;
    r->stage = STG_NOOP;
    ram_put64(c, trb, 0);
    ram_put(c, trb + 8, 0);
    dsb_sy();
    ram_put(c, trb + 12, TRB_NOOP_CMD << 10 | 1u);      /* the cycle bit lands last: the xHC may look at the TRB the moment it flips */
    clean_range(c, trb, TRB_BYTES);
    if (rd32(c, TARGET, x->op + OP_USBSTS, &before, "USBSTS")) return c->failure == RD_BUDGET ? W_BUDGET : W_READ;
    if (store(c, G_NOOP, SR_DB0, 0)) return W_STORE;
    start = c->a->ops.counter();
    for (;;) {
        if (rd32(c, TARGET, x->op + OP_USBSTS, &sts, "USBSTS")) return c->failure == RD_BUDGET ? W_BUDGET : W_READ;
        r->sts = sts;
        if (sts & STS_HCE) return W_HCE;
        if (sts & STS_HSE) return W_HSE;
        found = events_take(c, r, &index, trb, ring);
        if (found != -1) break;
        if (c->a->ops.counter() - start >= (uint64_t)T_EVENT_US * c->hz / 1000000u) {
            uint64_t slot = ring + (uint64_t)index * TRB_BYTES;
            if (!arena_range(c, slot, TRB_BYTES)) return W_STORE;
            if (ram_load32(slot) | ram_load32(slot + 4) | ram_load32(slot + 8) | ram_load32(slot + 12)) return W_CYCLE;
            return !r->events && (sts & STS_EINT) && !(before & STS_EINT) ? W_REDIRECT : W_EVENT;
        }
        if (!delay_us(c, POLL_US)) return W_CLOCK;
    }
    if (found == W_STORE) return W_STORE;
    dequeue = ring + (uint64_t)index * TRB_BYTES;
    if (store(c, G_NOOP, SR_ERDP_LO, (uint32_t)dequeue | ERDP_EHB) || store(c, G_NOOP, SR_ERDP_HI, (uint32_t)(dequeue >> 32))) return W_STORE;
    if (store(c, G_NOOP, SR_IMAN, IMAN_IP)) return W_STORE;
    return found;
}

/* ---- One attempt -------------------------------------------------------------------------------------------------------------------- */

/* A reason about the arena (nothing came, a bus error) is its answer and another arena may help: a timeout or a Host System Error, with or without a change of
 * the SMMU's fault registers, is the SC2 experiment. A bad completion (a wrong code, pointer or cycle, or a REDIRECT: an event posted that is not in the ring)
 * ends the run: a controller that answers wrongly is not given another fresh DMA in this boot. A reason about the controller itself (it would not reset or hold its
 * registers) or about the payload (the clock, a refused store, a failed read, the load budget) ends the run as well. */
OUT_OF_LINE void classify(struct result *r, int why)
{
    r->why = (uint32_t)why;
    r->verdict = why == W_NONE ? V_OK : why == W_HSE || why == W_HCE ? V_HSE :
                 why == W_CODE || why == W_POINTER || why == W_CYCLE || why == W_REDIRECT ? V_BAD : V_TIMEOUT;
    r->fatal = why != W_NONE && (r->stage == STG_RESET || r->stage == STG_PROGRAM || r->verdict == V_BAD || why == W_CLOCK || why == W_STORE ||
                                 why == W_BUDGET || why == W_READ || why == W_LINES);
}

/* ARENA, RESET, PROGRAM, RUN and NOOP, each opened by its NEXT line and eight seconds, in every attempt; then, whatever happened, the halt, and the zeroing of
 * the arena if the controller is confirmed halted (a controller that may still be running into it is not given zeros under its feet). The controller is left
 * halted but still programmed: DCBAAP, CRCR, ERSTBA and ERDP keep pointing into the arena, which is zero again; no store beyond the thirteen is made to undo it. */
void attempt(struct ctx *c, const struct arena *ar, struct result *r)
{
    uint32_t sts = 0;
    int why, stopped = W_NONE;
    r->verdict = V_NONE;
    r->stage = STG_ARENA;
    r->why = r->cc = r->sts = r->events = r->psc = r->fatal = 0;
    r->halted = 2;
    c->arena = *ar;
    c->armed = 0;                           /* every attempt opens every group again, each after its own NEXT line and eight seconds */
    why = announce(c, G_ARENA, 0, ar->base, ar->pages);
    if (!why) arena_build(c, c->x[TARGET].scratch);
    if (!why && c->ram_refusal) why = W_STORE;
    if (!why) why = announce(c, G_RESET, "RESET", 0, 0);
    if (!why) why = xhc_reset(c, r);
    if (!why) why = announce(c, G_PROGRAM, "PROGRAM", 0, 0);
    if (!why) why = xhc_program(c, r);
    if (!why) why = announce(c, G_RUN, "RUN", 0, 0);
    if (!why) why = xhc_run(c, r);
    if (!why) why = announce(c, G_NOOP, "NOOP", 0, 0);
    if (!why) why = xhc_noop(c, r);
    classify(r, why);
    if (c->armed & ~(unsigned)G_ARENA) {
        stopped = xhc_halt(c, &sts);
        if (!stopped) r->sts = sts;
    }
    r->halted = !stopped ? 1 : stopped == W_READ || stopped == W_STORE ? 2 : 0;
    if (r->halted == 1 && (c->armed & G_ARENA)) arena_zero(c);
    else if (r->halted != 1) r->fatal = 1;
}
