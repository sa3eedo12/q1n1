/* SPDX-License-Identifier: MIT */
/* The machine the mapping step runs on in tools/test-q1n1-sp11-payload-smmumap.c (platform/uefi/sp11-smmumap.c,
 * docs/SP11-PAYLOAD-SMMUMAP.md): sparse 4 KiB translation tables the step reads and writes, an AT model that walks them
 * (written apart from the step's own walk, in another style), faults it can be told to raise, a counter, and a log of every
 * effect in order.
 *
 * The AT model sees a store to a table slot only after the whole publication of it has happened in the architected order:
 * DC CVAC of the slot's line, DSB, TLBI for the page, DSB, ISB. Anything less and it still answers with the descriptor that was
 * there before, so a step that leaves out or reorders a barrier fails its own check here, instead of passing on a model that
 * is more generous than the hardware. Hardware: NOT RUN. Evidence: EXPERIMENTAL (host model only). */
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sp11-smmumap.h"

#define MAX_TABLES 14u
#define MAX_EVENTS 200u
#define MAX_LINES 48u
#define MAX_FORCE 6u
#define MAX_EXTENTS 12u
#define MAP_STRIDE 48u                  /* the unit's descriptor size (40 are used): type, pad, physical start, virtual start, pages, attributes */
#define ADDR Q1N1_SMMUMAP_ADDR
#define PAGE Q1N1_SMMUMAP_PAGE_PA
#define TEMPLATE Q1N1_SMMUMAP_TEMPLATE_PA

/* The good world's tables: the root is the pinned TTBR0_EL2, the others are where a model of the unit's firmware might have put
 * them. The page's path is L0[0], L1[0], L2A[0xAA] -> L3A, slot 0 (the AT of S1 said "level-3 translation fault"). The template's
 * is L0[0], L1[1], L2B[0x180], a 2 MiB Device block. The tables themselves sit in a Normal block of L2C. */
#define T_L0 Q1N1_SMMUMAP_TTBR0_EL2
#define T_L1 UINT64_C(0xA7F2F000)
#define T_L2A UINT64_C(0xA7F30000)
#define T_L3A UINT64_C(0xA7F31000)
#define T_L2B UINT64_C(0xA7F32000)
#define T_L2C UINT64_C(0xA7F33000)
#define SLOT0 T_L3A                                         /* the level-3 slot of the page: index 0 */
#define TEMPLATE_BLOCK UINT64_C(0x0040000070000641)         /* block, AttrIndx 0, AP[1], outer shareable, AF, XN */
#define RAM_BLOCK UINT64_C(0x00400000A7E0074D)              /* block, AttrIndx 3 (Normal), AP[1], inner shareable, AF, XN */
#define EXPECT_DESC UINT64_C(0x0040000015400643)            /* the page's descriptor: the block's attributes, type 0b11 */
#define GOOD_TCR UINT64_C(0x80843514)
#define GOOD_MAIR UINT64_C(0xFFBB4400)
#define GOOD_SCTLR UINT64_C(0x100030C5183D)
#define GOOD_HCR UINT64_C(0x88000010)
#define GOOD_FREQ UINT64_C(19200000)
/* One read of the model's counter is a millisecond, so that eight seconds are 8000 reads, far under the real bound of 2^32 - 1. The build
 * with a lowered bound (TEST_SPIN_MAX) steps ten milliseconds, 800 reads, under the lowered bound of 1000: only the slow counter of the
 * counter suite may then hit it. */
#ifdef TEST_SPIN_MAX
#define STEP_DIVISOR 100u
#else
#define STEP_DIVISOR 1000u
#endif
#define PAR_DEVICE_TEMPLATE UINT64_C(0x70000B00)            /* Device, outer shareable, NS, bit 11 */

enum { CM_NORMAL, CM_STUCK, CM_BACKWARD };

struct table {
    uint64_t base;
    uint64_t word[512];
};
/* What the AT instruction answers for `va`, whatever the tables say; `phase` 0 always, 1 before the first store, 2 after the
 * descriptor was stored, 3 after it was put back. */
struct force {
    uint64_t va, par;
    int write, phase;
};
/* One descriptor of the modelled UEFI memory map. */
struct extent {
    uint64_t start, pages, attr;
    unsigned type;
};
enum { MAP_NORMAL, MAP_NULL, MAP_STRIDE_SHORT };

struct world {
    struct table t[MAX_TABLES];
    unsigned tables;
    struct q1n1_smmumap_regs regs;
    uint64_t read_fault[4];             /* a read of one of these aborts */
    unsigned read_faults;
    uint64_t late_fault;                /* a read of this address aborts once the NEXT line is out: the read just before the store */
    unsigned store_fault_at;            /* the Nth store (1-based) aborts: 0 never */
    uint64_t poke_pa, poke_val;         /* another agent writes poke_val at poke_pa when the counter has been read poke_at times */
    uint64_t poke_at;
    /* When a line that starts with poke_map_line is printed, a one-page extent of poke_map_type is added over poke_map_start (a memory map that
     * changes under the step, which the real one cannot do: it shows that no proof outlives the line it was made before, and reaches branches
     * that the proofs of the walks make unreachable by construction). */
    const char *poke_map_line;
    uint64_t poke_map_start;
    unsigned poke_map_type;
    struct q1n1_smmumap_env *env;       /* the environment of the run in progress: a changed map must reach its map_size */
    struct force force[MAX_FORCE];
    unsigned forces;
    struct extent ext[MAX_EXTENTS];
    unsigned extents;
    uint8_t mapbuf[MAX_EXTENTS * MAP_STRIDE];
    uint64_t map_size, map_stride;
    int map_mode;
    int counter_mode, no_counter;
    uint64_t freq, step, now, calls, back_after;
    unsigned drop;                      /* bit n: the model ignores step n of a publication (clean, dsb, tlbi, dsb, isb) */
    int isr_pending, poll_found, poll_still, no_poll;     /* ISR_EL1.A, and what the runner's SError poll answers */
    uint64_t poll_syndrome;
    unsigned polls;
    /* what happened */
    char seq[MAX_EVENTS + 1];           /* R read (a run of consecutive words of one page is one event: arg2 is its length), S store, A AT, C clean, D dsb, T tlbi, I isb, G regs */
    uint64_t arg[MAX_EVENTS], arg2[MAX_EVENTS];
    unsigned events;
    char lines[MAX_LINES][160];
    unsigned nlines;
    unsigned applied, attempts, stray, reads;
    unsigned stray_reads;               /* loads the step made into a page that model_ram says is not RAM: none may be made, aborted or not */
    uint64_t store_pa[4], store_val[4];
    uint64_t next_at, store_at;
    int next_seen, store_before_next;
    /* the walker's view of the last store: it sees the old word until the publication is whole */
    int pend_active, pend_stage;
    uint64_t pend_slot, pend_old;
};

static struct world *cur;
static unsigned g_checks, g_fail;
static const char *g_suite = "";
#define CHECK(cond, ...) do { \
        g_checks++; \
        if (!(cond)) { g_fail++; printf("FAIL %s: ", g_suite); printf(__VA_ARGS__); printf("\n"); } \
    } while (0)
#define LL(x) ((unsigned long long)(x))

static void log_event(char kind, uint64_t a, uint64_t b)
{
    struct world *w = cur;
    if (kind == 'R' && w->events && w->seq[w->events - 1] == 'R') {
        unsigned last = w->events - 1;
        if ((a & ~UINT64_C(0xfff)) == (w->arg[last] & ~UINT64_C(0xfff)) && a == w->arg[last] + 8u * w->arg2[last]) {
            w->arg2[last]++;                                    /* the next word of the same page: the scans read a thousand of them */
            return;
        }
    }
    if (w->events >= MAX_EVENTS) return;
    w->seq[w->events] = kind;
    w->arg[w->events] = a;
    w->arg2[w->events] = kind == 'R' ? 1u : b;
    w->seq[++w->events] = 0;
}

static struct table *find_table(struct world *w, uint64_t pa)
{
    for (unsigned i = 0; i < w->tables; i++)
        if (w->t[i].base == (pa & ~UINT64_C(0xfff))) return &w->t[i];
    return NULL;
}

static struct table *add_table(struct world *w, uint64_t base)
{
    if (w->tables >= MAX_TABLES) { printf("FAIL model: too many tables\n"); exit(2); }
    memset(&w->t[w->tables], 0, sizeof w->t[0]);
    w->t[w->tables].base = base;
    return &w->t[w->tables++];
}

static uint64_t *word_ptr(struct world *w, uint64_t pa)
{
    struct table *t = find_table(w, pa);
    return t ? &t->word[(pa & 0xfff) >> 3] : NULL;
}

/* The walker's word: the descriptor from before a store whose publication is not whole. */
static uint64_t walker_word(struct world *w, uint64_t pa, int walker)
{
    uint64_t *p = word_ptr(w, pa);
    if (!p) return 0;
    if (walker && w->pend_active && w->pend_stage < 6 && pa == w->pend_slot) return w->pend_old;
    return *p;
}

static uint64_t fault_par(unsigned fst)
{
    return UINT64_C(1) | ((uint64_t)fst << 1);
}

/* PAR_EL1 after AT S1E2R/W. With F = bit 0 set: FST = bits 6:1, PTW = bit 8 and S = bit 9 (the two stage-2 bits; Linux asm/sysreg.h
 * SYS_PAR_EL1_PTW BIT(8), SYS_PAR_EL1_S BIT(9)). With F clear: PA = bits 47:12, SH = 8:7, NS = 9, bit 11 set, ATTR = 63:56. The
 * levels of the fault codes are those of the Arm ARM: translation 4 + level, access flag 8 + level, permission 12 + level. */
static uint64_t model_at(struct world *w, uint64_t va, int write, int walker)
{
    unsigned bits = 64u - (unsigned)(w->regs.tcr & 63u);
    unsigned level = bits > 39u ? 0u : bits > 30u ? 1u : 2u;
    uint64_t table = w->regs.ttbr0 & ADDR;
    for (;; level++) {
        unsigned shift = 39u - 9u * level;
        uint64_t at = table + ((va >> shift) & 511u) * 8u, desc;
        if (!find_table(w, at)) return fault_par(4u + level);          /* an abort of the walk: any fault will do */
        desc = walker_word(w, at, walker);
        if (!(desc & 1u)) return fault_par(4u + level);
        if (level < 3u && (desc & 3u) == 3u) { table = desc & ADDR; continue; }
        if (level == 3u ? (desc & 3u) != 3u : level == 0u) return fault_par(4u + level);
        if (!(desc & (UINT64_C(1) << 10))) return fault_par(8u + level);
        if (write && (desc & (UINT64_C(1) << 7))) return fault_par(12u + level);
        {
            unsigned index = (unsigned)((desc >> 2) & 7u);
            uint64_t attr = (w->regs.mair >> (8u * index)) & 0xffu;
            uint64_t mask = level == 3u ? UINT64_C(0xfff) : (UINT64_C(1) << shift) - 1u;
            uint64_t pa = ((desc & ADDR) & ~mask) | (va & mask & ~UINT64_C(0xfff));
            unsigned sh = (attr & 0xf0u) ? (unsigned)((desc >> 8) & 3u) : 2u;      /* Device memory is always outer shareable */
            return (attr << 56) | (pa & ADDR) | ((uint64_t)sh << 7) | (UINT64_C(1) << 9) | (UINT64_C(1) << 11);
        }
    }
}

/* The address of the level-3 slot of `va` by the model's own walk, 0 when the walk does not end in a level-3 table: where the one store
 * may go, whatever the tables hold. */
static uint64_t model_slot(struct world *w, uint64_t va)
{
    unsigned bits = 64u - (unsigned)(w->regs.tcr & 63u);
    unsigned level = bits > 39u ? 0u : bits > 30u ? 1u : 2u;
    uint64_t table = w->regs.ttbr0 & ADDR;
    for (;; level++) {
        uint64_t at = table + ((va >> (39u - 9u * level)) & 511u) * 8u;
        if (!find_table(w, at)) return 0;
        if (level == 3u) return at;
        if ((*word_ptr(w, at) & 3u) != 3u) return 0;
        table = *word_ptr(w, at) & ADDR;
    }
}

/* ---- The environment the step is given ------------------------------------------------------------------------------------- */

static void add_extent(struct world *w, uint64_t start, uint64_t pages, unsigned type);
static void build_map(struct world *w);

static void m_emit(const char *line)
{
    struct world *w = cur;
    if (w->nlines < MAX_LINES) snprintf(w->lines[w->nlines], sizeof w->lines[0], "%s", line);
    w->nlines++;
    if (!strncmp(line, "PAYLOAD SMMUMAP NEXT STORE AFTER", 32)) {
        w->next_seen = 1;
        w->next_at = w->now;
    }
    if (w->poke_map_line && !strncmp(line, w->poke_map_line, strlen(w->poke_map_line))) {
        add_extent(w, w->poke_map_start, 1u, w->poke_map_type);
        build_map(w);
        if (w->env) w->env->map_size = w->map_size;
    }
}

static uint64_t m_counter(void)
{
    struct world *w = cur;
    w->calls++;
    if (w->poke_at && w->calls == w->poke_at) *word_ptr(w, w->poke_pa) = w->poke_val;     /* another agent writes while the step waits */
    if (w->counter_mode == CM_STUCK) return w->now;
    if (w->counter_mode == CM_BACKWARD) {
        if (w->calls > w->back_after) return (UINT64_C(1) << 40) - 1000u;
        return w->now = (UINT64_C(1) << 40) + w->calls * w->step;
    }
    return w->now += w->step;
}

static void m_regs(struct q1n1_smmumap_regs *out)
{
    log_event('G', 0, 0);
    *out = cur->regs;
}

static int model_ram(const struct world *w, uint64_t page);

static int m_read64(uint64_t pa, uint64_t *value)
{
    struct world *w = cur;
    log_event('R', pa, 0);
    w->reads++;
    if (!model_ram(w, pa & ~UINT64_C(0xfff))) w->stray_reads++;       /* judged by the model's own reading of the map, not the step's */
    for (unsigned i = 0; i < w->read_faults; i++)
        if (w->read_fault[i] == pa) return 1;
    if (w->late_fault && w->next_seen && pa == w->late_fault) return 1;
    if (!find_table(w, pa) || (pa & 7u)) return 1;                      /* RAM the model does not hold: the guarded load aborts */
    *value = walker_word(w, pa, 0);
    return 0;
}

/* The runner's SError poll and the read of ISR_EL1.A, as the world answers them. */
static int m_serror_poll(uint64_t *syndrome, int *still)
{
    struct world *w = cur;
    w->polls++;
    *syndrome = w->poll_found ? w->poll_syndrome : 0;
    *still = w->poll_still;
    return w->poll_found;
}

static int m_serror_pending(void)
{
    return cur->isr_pending;
}

static int m_store64(uint64_t pa, uint64_t value)
{
    struct world *w = cur;
    uint64_t *p = word_ptr(w, pa);
    log_event('S', pa, value);
    w->attempts++;
    if (w->store_fault_at && w->attempts == w->store_fault_at) return 1;
    if (!p || (pa & 7u)) {
        w->stray++;                                                      /* a store outside the tables, or torn: a failure of the step */
        return 1;
    }
    if (!w->next_seen) w->store_before_next = 1;
    w->pend_active = 1;
    w->pend_slot = pa;
    w->pend_old = *p;
    w->pend_stage = 1;
    *p = value;
    if (w->applied < 4) {
        w->store_pa[w->applied] = pa;
        w->store_val[w->applied] = value;
    }
    if (!w->applied) w->store_at = w->now;
    w->applied++;
    return 0;
}

static int m_at(uint64_t va, int write, uint64_t *par)
{
    struct world *w = cur;
    int phase = w->applied == 0 ? 1 : w->applied == 1 ? 2 : 3;
    log_event('A', va, (uint64_t)write);
    for (unsigned i = 0; i < w->forces; i++) {
        if (w->force[i].va == va && w->force[i].write == write && (!w->force[i].phase || w->force[i].phase == phase)) {
            *par = w->force[i].par;
            return 0;
        }
    }
    *par = model_at(w, va, write, 1);
    return 0;
}

static void m_clean(uint64_t va)
{
    struct world *w = cur;
    log_event('C', va, 0);
    if (!(w->drop & 1u) && w->pend_active && w->pend_stage == 1 && (va & ~UINT64_C(63)) == (w->pend_slot & ~UINT64_C(63))) w->pend_stage = 2;
}

static void m_dsb(void)
{
    struct world *w = cur;
    log_event('D', 0, 0);
    if (!(w->drop & 2u) && w->pend_active && w->pend_stage == 2) w->pend_stage = 3;
    else if (!(w->drop & 8u) && w->pend_active && w->pend_stage == 4) w->pend_stage = 5;
}

static void m_tlbi(uint64_t va)
{
    struct world *w = cur;
    log_event('T', va, 0);
    if (!(w->drop & 4u) && w->pend_active && w->pend_stage == 3 && (va & ~UINT64_C(0xfff)) == PAGE) w->pend_stage = 4;
}

static void m_isb(void)
{
    struct world *w = cur;
    log_event('I', 0, 0);
    if (!(w->drop & 16u) && w->pend_active && w->pend_stage == 5) w->pend_stage = 6;
}

/* ---- Worlds ----------------------------------------------------------------------------------------------------------------- */

static void put_le(uint8_t *p, uint64_t v, unsigned bytes)
{
    for (unsigned i = 0; i < bytes; i++) p[i] = (uint8_t)(v >> (8u * i));
}

static void add_extent(struct world *w, uint64_t start, uint64_t pages, unsigned type)
{
    if (w->extents >= MAX_EXTENTS) { printf("FAIL model: too many extents\n"); exit(2); }
    /* Writeback-capable memory for the types that are memory, uncached and runtime for MMIO: what tells reserved DRAM from reserved MMIO. */
    w->ext[w->extents++] = (struct extent){start, pages, (type == 11 || type == 12) ? UINT64_C(0x8000000000000001) : UINT64_C(0xf), type};
}

/* The map the step is given, built from the extents (call it again after a test changed them). */
static void build_map(struct world *w)
{
    memset(w->mapbuf, 0, sizeof w->mapbuf);
    for (unsigned i = 0; i < w->extents; i++) {
        uint8_t *d = w->mapbuf + i * MAP_STRIDE;
        put_le(d, w->ext[i].type, 4);
        put_le(d + 8, w->ext[i].start, 8);
        put_le(d + 16, w->ext[i].start, 8);
        put_le(d + 24, w->ext[i].pages, 8);
        put_le(d + 32, w->ext[i].attr, 8);
    }
    w->map_size = (uint64_t)w->extents * MAP_STRIDE;
    w->map_stride = w->map_mode == MAP_STRIDE_SHORT ? 32u : MAP_STRIDE;
}

/* The same question as the step's, answered from the extents and written another way: the page is RAM when no extent that overlaps it is
 * anything else and one extent holds all of it. */
static int model_ram(const struct world *w, uint64_t page)
{
    int held = 0;
    for (unsigned i = 0; i < w->extents; i++) {
        uint64_t start = w->ext[i].start, pages = w->ext[i].pages, end;
        unsigned type = w->ext[i].type;
        int ram = (type >= 1 && type <= 7) || type == 9;
        /* A descriptor that is no usable range (unaligned, empty, beyond 2^48, or reaching beyond it) is skipped, as the payloads skip it. */
        if ((start & 0xfffu) || !pages || start >= (UINT64_C(1) << 48) || pages > ((UINT64_C(1) << 48) - start) / 4096u) continue;
        end = start + pages * 4096u;
        if (page + 4096u <= start || page >= end) continue;
        if (!ram) return 0;
        if (page >= start && page + 4096u <= end) held = 1;
    }
    return held;
}

static void world_good(struct world *w)
{
    struct table *l0, *l1, *l2a, *l3a, *l2b, *l2c;
    memset(w, 0, sizeof *w);
    w->regs.ttbr0 = Q1N1_SMMUMAP_TTBR0_EL2;
    w->regs.tcr = GOOD_TCR;
    w->regs.mair = GOOD_MAIR;
    w->regs.sctlr = GOOD_SCTLR;
    w->regs.hcr = GOOD_HCR;
    w->freq = GOOD_FREQ;
    w->step = GOOD_FREQ / STEP_DIVISOR;
    /* The map is a model, not the unit's: an extent of boot services data of 231 pages at 0xA7F19000 (a third-party report from another SoC, quoted
     * in Snapintosh docs/SP11-Q1N1-BOOT-STUDY.md, names that range; it contains the root 0xA7F2E000 this unit printed), conventional memory around it,
     * and the two windows the step reads or maps, as MMIO. Which extent holds the unit's level-3 table is UNKNOWN until a run prints it. */
    add_extent(w, UINT64_C(0x00000000), 0x100u, 0u);
    add_extent(w, UINT64_C(0x15000000), 0x600u, 11u);
    add_extent(w, UINT64_C(0x70000000), 0x400u, 11u);
    add_extent(w, UINT64_C(0x80000000), 0x27F19u, 7u);
    add_extent(w, UINT64_C(0xA7F19000), 231u, 4u);
    add_extent(w, UINT64_C(0xA8000000), 0x1000u, 7u);
    build_map(w);
    l0 = add_table(w, T_L0);
    l1 = add_table(w, T_L1);
    l2a = add_table(w, T_L2A);
    l3a = add_table(w, T_L3A);
    l2b = add_table(w, T_L2B);
    l2c = add_table(w, T_L2C);
    l0->word[0] = T_L1 | 3u;
    l1->word[0] = T_L2A | 3u;
    l1->word[1] = T_L2B | 3u;
    l1->word[2] = T_L2C | 3u;
    l2a->word[0xAA] = T_L3A | 3u;
    l3a->word[1] = UINT64_C(0x0040000015401643);                        /* the neighbours stay as they are */
    l3a->word[511] = UINT64_C(0x00400000155FF643);
    l2b->word[0x180] = TEMPLATE_BLOCK;
    l2c->word[0x13F] = RAM_BLOCK;
}

static void force_at(struct world *w, uint64_t va, int write, int phase, uint64_t par)
{
    if (w->forces >= MAX_FORCE) { printf("FAIL model: too many forced ATs\n"); exit(2); }
    w->force[w->forces++] = (struct force){va, par, write, phase};
}

/* The environment of a world; a test that calls the logic itself (another spec, the line after the chain) builds it the same way. */
static void make_env(struct world *w, struct q1n1_smmumap_env *env)
{
    cur = w;
    env->emit = m_emit;
    env->counter = w->no_counter ? NULL : m_counter;
    env->freq = w->freq;
    env->regs = m_regs;
    env->read64 = m_read64;
    env->store64 = m_store64;
    env->at = m_at;
    env->clean = m_clean;
    env->dsb = m_dsb;
    env->tlbi = m_tlbi;
    env->isb = m_isb;
    env->map = w->map_mode == MAP_NULL ? NULL : w->mapbuf;
    env->map_size = w->map_size;
    env->map_stride = w->map_stride;
    env->serror_poll = w->no_poll ? NULL : m_serror_poll;
    env->serror_pending = m_serror_pending;
    w->env = env;
}

static int run_world(struct world *w, struct q1n1_smmumap_result *r)
{
    struct q1n1_smmumap_env env;
    make_env(w, &env);
    memset(r, 0xA5, sizeof *r);                                         /* a field the step forgets to set shows */
    return q1n1_smmumap_run(&env, r);
}

static int same_tables(const struct world *a, const struct world *b)
{
    if (a->tables != b->tables) return 0;
    for (unsigned i = 0; i < a->tables; i++)
        if (a->t[i].base != b->t[i].base || memcmp(a->t[i].word, b->t[i].word, sizeof a->t[i].word)) return 0;
    return 1;
}

static const char *last_line(const struct world *w)
{
    return w->nlines && w->nlines <= MAX_LINES ? w->lines[w->nlines - 1] : "";
}

static int has_line(const struct world *w, const char *prefix)
{
    for (unsigned i = 0; i < w->nlines && i < MAX_LINES; i++)
        if (!strncmp(w->lines[i], prefix, strlen(prefix))) return 1;
    return 0;
}

/* The first line that starts with `prefix`, or "". */
static const char *find_line(const struct world *w, const char *prefix)
{
    for (unsigned i = 0; i < w->nlines && i < MAX_LINES; i++)
        if (!strncmp(w->lines[i], prefix, strlen(prefix))) return w->lines[i];
    return "";
}

/* The checks every world has to pass whatever the answer: nothing outside the slot, at most the store and the put-back, the
 * lines in the page's font and within the line limit, the same lines for the same answer, and `DONE` last. */
static void common_checks(const struct world *w, struct world *before, const struct q1n1_smmumap_result *r, int status)
{
    char want[96];
    uint64_t slot = model_slot(before, PAGE);
    CHECK(status == r->status, "the return value %d is not the result's status %d", status, r->status);
    CHECK(w->stray == 0, "a store outside the table slot of the page (%u)", w->stray);
    CHECK(w->stray_reads == 0, "%u loads into a page that the memory map does not call RAM", w->stray_reads);
    CHECK(w->applied <= 2 && w->attempts <= 2, "more than a store and its put-back: %u applied, %u attempted", w->applied, w->attempts);
    CHECK(w->nlines > 1 && w->nlines <= 10, "%u lines (1 to 10 are budgeted)", w->nlines);
    CHECK(w->events < MAX_EVENTS, "the event log is full");
    CHECK(w->reads <= 2056u, "%u reads: the scans are bounded by 2,047 (511 + 3 x 512), the two walks by 8 and the slot once more by 1", w->reads);
    CHECK(w->polls == 0 && (r->serror_before == 0 || r->serror_before == 1), "the step polled for an SError (%u) or left serror_before as %d", w->polls, r->serror_before);
    for (unsigned i = 0; i < w->nlines && i < MAX_LINES; i++) {
        const char *p = w->lines[i];
        CHECK(strlen(p) <= 100, "line %u is %zu characters", i, strlen(p));
        CHECK(!strncmp(p, "PAYLOAD SMMUMAP ", 16), "line %u does not start with the tag: %s", i, p);
        for (; *p; p++)
            CHECK((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || strchr(" :-./=?()_", *p), "a character outside the page font in %s", w->lines[i]);
    }
    snprintf(want, sizeof want, "PAYLOAD SMMUMAP DONE MAPPED=%d STORES=%u", status == Q1N1_SMMUMAP_MAPPED, r->stores);
    CHECK(!strncmp(last_line(w), want, strlen(want)), "last line '%s', wanted '%s'", last_line(w), want);
    CHECK(status != Q1N1_SMMUMAP_UNSAFE || strstr(last_line(w), " UNSAFE"), "UNSAFE without its word on the last line");
    CHECK(r->stores == w->applied, "result says %u stores, the model applied %u", r->stores, w->applied);
    CHECK(!w->store_before_next, "a store before the NEXT line");
    if (w->applied == 0 && !w->poke_at) CHECK(same_tables(w, before), "tables changed with no store");
    if (status == Q1N1_SMMUMAP_REFUSED && w->applied == 2) CHECK(same_tables(w, before), "tables not as they were after the put-back");
    if (w->applied >= 1) {
        uint64_t v = w->store_val[0];
        CHECK(slot && w->store_pa[0] == slot, "the first store went to %llx, the page's level-3 slot is %llx", LL(w->store_pa[0]), LL(slot));
        CHECK((v & 3u) == 3u && (v & ADDR) == PAGE && !(v & ~(ADDR | UINT64_C(3) | UINT64_C(0xffc) | (UINT64_C(3) << 53))),
              "the first store is not a 4 KiB page descriptor of the page and nothing more: %llx", LL(v));
    }
    if (w->applied == 2) CHECK(w->store_pa[1] == w->store_pa[0] && w->store_val[1] == 0, "the put-back is %llx at %llx", LL(w->store_val[1]), LL(w->store_pa[1]));
}

/* ---- what the suites of both test files share ------------------------------------------------------------------------------------- */

/* Words of the good world the suites change, by name: one word of each table of the path, the template's leaf and the RAM block's. */
#define L0E T_L0
#define L1E0 T_L1
#define L1E1 (T_L1 + 8u)
#define L2E (T_L2A + 8u * 0xAAu)
#define L3E SLOT0
#define TPLE (T_L2B + 8u * 0x180u)
#define RAME (T_L2C + 8u * 0x13Fu)
#define T_L3B UINT64_C(0xA7F34000)
#define W(w, pa) (*word_ptr(&(w), (pa)))
#define NEWWORLD(w) struct world w, w##_before; (void)&w##_before; world_good(&w)
#define GO(w, status, reason, stores, what) do { w##_before = w; expect(&w, &w##_before, status, reason, stores, what); } while (0)
#define REFUSED Q1N1_SMMUMAP_REFUSED
#define MAPPED Q1N1_SMMUMAP_MAPPED
#define R(name) Q1N1_SMMUMAP_R_##name

static unsigned g_lines_max;

/* Runs the step in `w` and checks the common properties and the three things a case names: the status, the reason and how many stores were made. */
static void expect(struct world *w, struct world *before, int status, int reason, unsigned stores, const char *what)
{
    struct q1n1_smmumap_result r;
    int got = run_world(w, &r);
    common_checks(w, before, &r, got);
    if (w->nlines > g_lines_max) g_lines_max = w->nlines;
    CHECK(got == status, "%s: status %d, wanted %d (last line: %s)", what, got, status, last_line(w));
    CHECK(r.reason == reason, "%s: reason %s, wanted %s", what, q1n1_smmumap_reason_name(r.reason), q1n1_smmumap_reason_name(reason));
    CHECK(w->applied == stores, "%s: %u stores, wanted %u", what, w->applied, stores);
    if (reason != R(NONE)) {
        char name[64];
        snprintf(name, sizeof name, "PAYLOAD SMMUMAP REFUSED=%s", q1n1_smmumap_reason_name(reason));
        CHECK(has_line(w, name), "%s: no line '%s'", what, name);
    }
}

/* The suites in the second file (tools/test-q1n1-sp11-payload-smmumap-scan.c), run by the one main of the first: those of `want` ("all", "lines-report" or a
 * name), their checks and failures and the most lines of a page they saw. Returns how many suites ran. */
unsigned smmumap_scan_suites(const char *want, unsigned *checks, unsigned *fails, unsigned *lines_max);
