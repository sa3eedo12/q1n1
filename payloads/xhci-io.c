/* SPDX-License-Identifier: MIT */
/* Payload "xhci", the instructions and their gates (docs/SP11-PAYLOAD-XHCI.md; xhci-priv.h lists the parts). This file holds every load
 * from a device or from RAM that the xHC may have written, every store to a device register or to an arena, and every cache or barrier
 * instruction of the binary, one helper each; and the gates that every one of them passes: xhc_store (the registers, the groups, the window),
 * ram_put (the arena) and arena_range (the arena, for every cache operation). tools/test-q1n1-sp11-payload-xhci.py holds the compiled code
 * to exactly two stores through a pointer that is not the payload's own memory, the two sinks, and the source to one call of each; its `gates`
 * suite calls the gates directly with every input they must refuse. */
#include "xhci-priv.h"

/* ---- The instructions, one helper each ---------------------------------------------------------------------------------------------- */

/* The only store to a device register in the binary. */
SINK void mmio_store32(uint64_t a, uint32_t v) { HW(pl_host_mmio_store32(a, v), *(volatile uint32_t *)(uintptr_t)a = v); }
/* The only store to an arena in the binary. */
SINK void ram_store32(uint64_t a, uint32_t v) { HW(pl_host_ram_store32(a, v), *(volatile uint32_t *)(uintptr_t)a = v); }
/* The only load of RAM that the xHC may have written: the event TRB. */
SINK uint32_t ram_load32(uint64_t a) { return HW(pl_host_ram_load32(a), *(volatile const uint32_t *)(uintptr_t)a); }
/* Clean to the point of coherency: what the CPU wrote reaches memory before the xHC reads it. */
SINK void dc_cvac(uint64_t a) { HW(pl_host_cache("cvac", a), __asm__ volatile("dc cvac, %0" : : "r"(a) : "memory")); }
/* Clean and invalidate: the next load comes from memory, where the xHC wrote, and no dirty data of ours is thrown away. */
SINK void dc_civac(uint64_t a) { HW(pl_host_cache("civac", a), __asm__ volatile("dc civac, %0" : : "r"(a) : "memory")); }
SINK void dsb_sy(void) { HW(pl_host_cache("dsb", 0), __asm__ volatile("dsb sy" : : : "memory")); }

/* ---- Time -------------------------------------------------------------------------------------------------------------------------- */

/* Waits `ticks` on the runner's counter; 0 if the counter does not run or runs backwards (a read below the first would end the wait at once:
 * the filming window is not given up for a counter that lies). */
int delay_ticks(const struct ctx *c, uint64_t ticks)
{
    uint64_t start = c->a->ops.counter(), last = start;
    uint32_t same = 0;
    for (;;) {
        uint64_t now = c->a->ops.counter();
        if (now < start) return 0;
        if (now - start >= ticks) return 1;
        if (now == last) {
            if (++same >= COUNTER_STUCK_READS) return 0;
        } else {
            last = now;
            same = 0;
        }
    }
}

int delay_us(const struct ctx *c, uint64_t us)
{
    return delay_ticks(c, us * c->hz / 1000000u);
}

/* ---- Reads: every access to a device register goes through rd32 ---------------------------------------------------------------------- */

/* A register of a window. The first abort ends all reads of that window: whatever stopped one load would stop the next. */
int rd32(struct ctx *c, unsigned win, uint64_t off, uint32_t *value, const char *name)
{
    int rc;
    *value = 0;
    if (!windows[win].base) {
        rc = RD_ABSENT;
    } else if (off & 3) {
        rc = RD_ALIGN;
    } else if (off >= windows[win].size || windows[win].size - off < 4) {
        rc = RD_RANGE;
    } else if (c->dead & (1u << win)) {
        rc = RD_DEAD;
    } else if (c->loads >= LOAD_CAP) {
        rc = RD_BUDGET;
    } else {
        int32_t err;
        c->loads++;
        err = c->a->ops.load32(windows[win].base + off, &c->word);
        if (err) {
            rc = err == Q1N1_PAYLOAD_LOAD_E_FAULT ? RD_FAULT : RD_BAD_OP;
            c->dead |= 1u << win;
        } else {
            *value = c->word;
            rc = RD_OK;
        }
    }
    if (rc && !c->failed) {
        c->failed = name;
        c->failure = (uint32_t)rc;
    }
    return rc;
}

int rd64(struct ctx *c, unsigned win, uint64_t off, uint64_t *value, const char *name)
{
    uint32_t lo = 0, hi = 0;
    int rc = rd32(c, win, off, &lo, name);
    if (!rc) rc = rd32(c, win, off + 4, &hi, name);
    *value = rc ? 0 : (uint64_t)lo | (uint64_t)hi << 32;
    return rc;
}

/* ---- Stores: the gates --------------------------------------------------------------------------------------------------------------- */

/* The one place a register of the controller is stored to. The group must be open and one the register may be written in. USBCMD may differ
 * from what was last read only in RS and HCRST and never sets both, and its group is its value's (HCRST, RS, or a halt); IMAN only clears IP;
 * the doorbell only rings doorbell 0 with target 0. */
OUT_OF_LINE int xhc_store(struct ctx *c, unsigned group, unsigned reg, uint32_t value)
{
    const struct xhc *x = &c->x[TARGET];
    uint64_t off;
    if (reg >= SR_COUNT) return STORE_BAD_REG;
    off = reg_offset(x, reg);
    if (reg == SR_USBCMD) {
        if (((value ^ c->cmd_seen) & ~(uint32_t)(CMD_RS | CMD_HCRST)) || (value & CMD_RS && value & CMD_HCRST)) return STORE_BITS;
        if (group != (value & CMD_HCRST ? G_RESET : value & CMD_RS ? G_RUN : G_STOP)) return STORE_BITS;
    } else if (!(reg_groups[reg] & group) || (reg == SR_IMAN && value != IMAN_IP) || (reg == SR_DB0 && value)) {
        return STORE_BITS;
    }
    if (group ? !(c->armed & group) : !c->armed) return STORE_NOT_ARMED;
    if (c->dead & (1u << TARGET)) return STORE_DEAD;
    if (off & 3 || off > store_limit() - 4) return STORE_RANGE;
    c->stores++;
    mmio_store32(windows[TARGET].base + off, value);
    return STORE_OK;
}

/* A refused store is the payload's own bug or a hostile register value: it is named on the page and ends the run. */
GATE int store(struct ctx *c, unsigned group, unsigned reg, uint32_t value)
{
    int rc = xhc_store(c, group, reg, value);
    if (rc && !c->store_refusal) c->store_refusal = (uint32_t)rc | (reg + 1u) << 8;
    return rc;
}

/* A word of the current arena and nowhere else, in an open ARENA group: the gate of every RAM store. The bounds are one unsigned difference, so that an address
 * below the arena wraps to a huge value instead of passing, one near the top of the address space cannot wrap past the end, and an arena of no pages admits nothing. */
GATE void ram_put(struct ctx *c, uint64_t address, uint32_t value)
{
    uint64_t size = (uint64_t)c->arena.pages * PAGE;
    if (!(c->armed & G_ARENA) || (address & 3) || size < 4 || address - c->arena.base > size - 4) {
        c->ram_refusal = 1;
        return;
    }
    ram_store32(address, value);
}

void ram_put64(struct ctx *c, uint64_t address, uint64_t value)
{
    ram_put(c, address, (uint32_t)value);
    ram_put(c, address + 4, (uint32_t)(value >> 32));
}

/* The gate of every cache operation: `bytes` from `start` lie inside the arena of the attempt, which is the only memory the payload maintains. A refusal
 * is named like a refused RAM store (STORE_REFUSED on the END line). The same difference as in ram_put, and no sum that could wrap. */
GATE int arena_range(struct ctx *c, uint64_t start, uint64_t bytes)
{
    uint64_t size = (uint64_t)c->arena.pages * PAGE;
    if (!bytes || bytes > size || start - c->arena.base > size - bytes) {
        c->ram_refusal = 1;
        return 0;
    }
    return 1;
}

/* Cleans [start, start + bytes) to memory, one DC CVAC per CACHE_STEP, each after its own check against the arena (the first refusal ends the loop), then DSB SY. */
void clean_range(struct ctx *c, uint64_t start, uint64_t bytes)
{
    for (uint64_t at = start & ~(uint64_t)(CACHE_STEP - 1); at < start + bytes; at += CACHE_STEP) {
        if (!arena_range(c, at, CACHE_STEP)) break;
        dc_cvac(at);
    }
    dsb_sy();
}
