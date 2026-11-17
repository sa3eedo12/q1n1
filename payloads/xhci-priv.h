/* SPDX-License-Identifier: MIT */
/* The internal interface of the payload "xhci" (docs/SP11-PAYLOAD-XHCI.md): the context its parts share, and what each part offers the
 * others. The parts are compilation units of one binary (the Makefile links them into xhci0.bin and xhci1.bin):
 *
 *   xhci.c        the entry point: pre-flight (identity and state of the controller), the attempts, the verdict
 *   xhci-io.c     the only instructions that load from a device or RAM, store to either, or maintain a cache, and the gates every store passes
 *   xhci-text.c   the page: the template formatter and the line budget
 *   xhci-map.c    the UEFI memory map and the arenas
 *   xhci-ctl.c    the controller sequence: announce, reset, program, run, No Op, halt
 *   xhci-smmu.c   the SMMU stream, its fault registers and the DWC3 bus error address (reads only)
 *   xhci-watch.c  the plug watch (reads only)
 *
 * tools/test-q1n1-sp11-payload-xhci.py holds every one of these files to the record: two store sinks, the gates, the register list. */
#pragma once
#include <stdarg.h>
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* The host test replaces what a build machine cannot run: MRS of two registers, the stores, the RAM loads and the caches. */
uint64_t pl_host_sysreg(const char *name);
void pl_host_mmio_store32(uint64_t phys, uint32_t value);
uint32_t pl_host_ram_load32(uint64_t phys);
void pl_host_ram_store32(uint64_t phys, uint32_t value);
void pl_host_cache(const char *op, uint64_t phys);
#define SYSREG(name) pl_host_sysreg(#name)
#define HW(host, real) host
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#define HW(host, real) real
#endif

#include "xhci-regs.h"

#define PREFIX "PAYLOAD XHCI "
#define OUT_OF_LINE static __attribute__((noinline))
#define SINK __attribute__((noinline))
#define GATE __attribute__((noinline))
#define U(x) ((uint64_t)(x))

struct xhc {
    uint32_t cap0, hcs1, hcs2, hcc1, dboff, rtsoff, pagesize, dwc3_id;
    uint32_t caplen, slots, intrs, ports, scratch, ac64, csz;
    uint32_t cmd, sts, cfg, portsc[PORTS_WATCHED];
    uint64_t crcr, dcbaap, op, ir0, db;         /* the last three are offsets from the window base */
};

struct arena {
    uint64_t base;
    uint32_t pages, id;
};

/* The SMMU context the stream goes through (read once), and the fault registers (read before and after every attempt). */
struct smmu {
    uint32_t ok, numcb, pagesize, numpage, matched, type, cb, have_cb;
};

struct faults {
    uint32_t gfsr, gfsynr0, fsr, fsynr0, berr_valid;
    uint64_t gfar, far, berr;
};

struct map {
    uint64_t base, stride;
    uint32_t count, ok;
};

struct result {
    uint32_t verdict, stage, why, cc, sts, events, psc, halted, fatal;
};

struct ctx {
    const struct q1n1_payload_args *a;
    uint32_t word;                  /* the load32 destination: the runner wants it on the payload stack, and the context is */
    uint32_t loads, lines, cuts, dead, armed, stores, failure, store_refusal, ram_refusal, cmd_seen, closing;
    const char *failed;
    uint64_t hz;
    struct map map;
    struct xhc x[2];
    struct smmu smmu;
    struct faults before;
    struct arena arena;
};

enum { RD_OK, RD_RANGE, RD_ALIGN, RD_DEAD, RD_BUDGET, RD_FAULT, RD_BAD_OP, RD_ABSENT };

/* Where register `reg` of the record lies from the window base: its block's offset (read from the controller) plus its own. The pre-flight checks
 * every one of them against STORE_LIMIT with this function and the store gate computes its address with it, so that the two cannot disagree. */
static inline uint64_t reg_offset(const struct xhc *x, unsigned reg)
{
    return (reg_map[reg].from == 0 ? x->op : reg_map[reg].from == 1 ? x->ir0 : x->db) + reg_map[reg].off;
}

/* The first offset of the target's window that no store may reach: the DWC3 global registers (or the window's end, for a build aimed at a smaller window). */
static inline uint64_t store_limit(void)
{
    return windows[TARGET].size < STORE_LIMIT ? windows[TARGET].size : STORE_LIMIT;
}

/* xhci-io.c */
void mmio_store32(uint64_t a, uint32_t v);
void ram_store32(uint64_t a, uint32_t v);
uint32_t ram_load32(uint64_t a);
void dc_cvac(uint64_t a);
void dc_civac(uint64_t a);
void dsb_sy(void);
int delay_ticks(const struct ctx *c, uint64_t ticks);
int delay_us(const struct ctx *c, uint64_t us);
int rd32(struct ctx *c, unsigned win, uint64_t off, uint32_t *value, const char *name);
int rd64(struct ctx *c, unsigned win, uint64_t off, uint64_t *value, const char *name);
int store(struct ctx *c, unsigned group, unsigned reg, uint32_t value);
void ram_put(struct ctx *c, uint64_t address, uint32_t value);
void ram_put64(struct ctx *c, uint64_t address, uint64_t value);
int arena_range(struct ctx *c, uint64_t start, uint64_t bytes);
void clean_range(struct ctx *c, uint64_t start, uint64_t bytes);

/* xhci-text.c */
void put_dec(struct pl_line *line, uint64_t value);
int emit(struct ctx *c, const struct pl_line *line);
void line_to(const struct ctx *c, struct pl_line *line, const char *f, ...);
int say(struct ctx *c, const char *f, ...);

/* xhci-map.c */
void map_init(struct ctx *c);
int arena_for(const struct ctx *c, unsigned id, uint32_t pages, struct arena *out);
void arena_build(struct ctx *c, uint32_t scratch);
void arena_zero(struct ctx *c);

/* xhci-ctl.c */
int poll_xhc(struct ctx *c, uint64_t off, const char *name, uint32_t mask, uint32_t want, uint32_t timeout_us, uint32_t *last);
void attempt(struct ctx *c, const struct arena *ar, struct result *r);

/* xhci-smmu.c */
int smmu_scan(struct ctx *c, struct smmu *s);
int fault_regs(struct ctx *c, struct faults *f);
int faults_same(const struct faults *a, const struct faults *b);
void say_faults(struct ctx *c, const char *head, unsigned attempt, const struct faults *f);
unsigned faults_lines(const struct ctx *c, const struct faults *f);

/* xhci-watch.c */
int room(const struct ctx *c, unsigned reserve);
void watch_run(struct ctx *c, unsigned reserve);
