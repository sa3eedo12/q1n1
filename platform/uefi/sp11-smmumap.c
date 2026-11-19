/* SPDX-License-Identifier: MIT */
/* See sp11-smmumap.h and docs/SP11-PAYLOAD-SMMUMAP.md. The order of the checks is the order of the questions, cheapest and
 * most reversible first, and nothing is written until every one has been answered: the root of the tables, the regime,
 * the walk to the page's level-3 slot (which must be zero; every table of it is proven RAM by the memory map before the word is
 * loaded from it), the AT instruction agreeing with the walk, the walk to the template's leaf (proven the same way), the AT agreeing
 * with it, the table page being writable, the scan of the table and of the path's tables, the descriptor being exactly one page.
 * Then the NEXT line and its wait, the slot read once more, the one store, the barriers and the TLB invalidation, and the AT
 * check of the result, which is undone if it fails. */
#include "sp11-smmumap.h"

#if Q1N1_SP11_SMMUMAP

#define TABLE_UPPER_BITS UINT64_C(0xf800000000000000)   /* NSTable, APTable[1:0], UXNTable, PXNTable of a table descriptor */
#define DESC_AF (UINT64_C(1) << 10)
#define DESC_AP_RO (UINT64_C(1) << 7)                   /* AP[2]: read-only */
#define DESC_XN (UINT64_C(1) << 54)                     /* UXN, the one execute-never bit of the non-VHE EL2 regime */
#define SCTLR_M UINT64_C(1)
#define SCTLR_EE (UINT64_C(1) << 25)
#define HCR_E2H (UINT64_C(1) << 34)
#define PAR_ATTR_MASK (UINT64_C(0xff00000000000000) | UINT64_C(0x380))   /* ATTR, NS and SH: what the descriptor's attributes decide */
/* PAR_EL1 with F = 1: bit 8 is PTW (the fault was a stage-2 fault during a stage-1 table walk) and bit 9 is S (a stage-2 fault); Linux
 * asm/sysreg.h SYS_PAR_EL1_PTW BIT(8), SYS_PAR_EL1_S BIT(9). The EL2 regime has no stage 2, so either set is not the stage-1 level-3
 * translation fault the walk predicted. */
#define PAR_FAULT_STAGE2 (UINT64_C(3) << 8)
#define FST_TRANSLATION_L3 0x07u
#define EFI_DESC_MIN 40u                                /* type, pad, physical start, virtual start, pages, attributes */
#define MAP_DESCRIPTORS_MAX 1024u
#define MAP_ADDRESS_LIMIT (UINT64_C(1) << 48)
#define PAGE_BYTES UINT64_C(4096)

/* Waits of the NEXT line: the payloads' bounds (nvmesnap): the counter standing still for this many reads is dead, and a wait
 * is given up only after 2^32 - 1 reads, far above what eight seconds need at any loop speed. */
#ifndef SMMUMAP_SPIN_MAX
#define SMMUMAP_SPIN_MAX 0xffffffffu
#endif
#ifndef SMMUMAP_STUCK_READS
#define SMMUMAP_STUCK_READS 2000000u
#endif
/* The counter's frequency is read from CNTFRQ_EL0, which firmware sets and which can be wrong: outside this window the
 * unit's 19.2 MHz is used, so that eight "seconds" cannot be a few microseconds (the NEXT line would not be seen) or hours. */
#define COUNTER_HZ_DEFAULT UINT64_C(19200000)
#define COUNTER_HZ_MIN UINT64_C(1000000)
#define COUNTER_HZ_MAX UINT64_C(1000000000)

const struct q1n1_smmumap_spec q1n1_smmumap_specs[] = {
    {"PCIE_SMMU0", Q1N1_SMMUMAP_PAGE_PA, Q1N1_SMMUMAP_TEMPLATE_PA},
};
const unsigned q1n1_smmumap_spec_count = sizeof q1n1_smmumap_specs / sizeof q1n1_smmumap_specs[0];

const char *q1n1_smmumap_reason_name(int reason)
{
    switch (reason) {
    case Q1N1_SMMUMAP_R_NONE: return "NONE";
    case Q1N1_SMMUMAP_R_NO_COUNTER: return "NO_COUNTER";
    case Q1N1_SMMUMAP_R_COUNTER_UNUSABLE: return "COUNTER_UNUSABLE";
    case Q1N1_SMMUMAP_R_SPIN_BOUND: return "SPIN_BOUND";
    case Q1N1_SMMUMAP_R_SPEC: return "SPEC";
    case Q1N1_SMMUMAP_R_TTBR0_UNPINNED: return "TTBR0_UNPINNED";
    case Q1N1_SMMUMAP_R_REGIME: return "REGIME";
    case Q1N1_SMMUMAP_R_WALK_FAULT: return "WALK_FAULT";
    case Q1N1_SMMUMAP_R_NO_L3_TABLE: return "NO_L3_TABLE";
    case Q1N1_SMMUMAP_R_UPPER_FLAGS: return "UPPER_FLAGS";
    case Q1N1_SMMUMAP_R_TABLE_ADDRESS: return "TABLE_ADDRESS";
    case Q1N1_SMMUMAP_R_TABLE_SHARED: return "TABLE_SHARED";
    case Q1N1_SMMUMAP_R_TABLE_NOT_RAM: return "TABLE_NOT_RAM";
    case Q1N1_SMMUMAP_R_SCAN_FAULT: return "SCAN_FAULT";
    case Q1N1_SMMUMAP_R_AT_DISAGREES: return "AT_DISAGREES";
    case Q1N1_SMMUMAP_R_ENTRY_VALID: return "ENTRY_VALID";
    case Q1N1_SMMUMAP_R_ENTRY_NOT_ZERO: return "ENTRY_NOT_ZERO";
    case Q1N1_SMMUMAP_R_TEMPLATE_UNMAPPED: return "TEMPLATE_UNMAPPED";
    case Q1N1_SMMUMAP_R_TEMPLATE_NOT_DEVICE: return "TEMPLATE_NOT_DEVICE";
    case Q1N1_SMMUMAP_R_TEMPLATE_NOT_USABLE: return "TEMPLATE_NOT_USABLE";
    case Q1N1_SMMUMAP_R_TABLE_NOT_WRITABLE: return "TABLE_NOT_WRITABLE";
    case Q1N1_SMMUMAP_R_DESCRIPTOR: return "DESCRIPTOR";
    case Q1N1_SMMUMAP_R_STORE_FAULT: return "STORE_FAULT";
    case Q1N1_SMMUMAP_R_CHECK_FAILED: return "CHECK_FAILED";
    case Q1N1_SMMUMAP_R_ROLLBACK_FAILED: return "ROLLBACK_FAILED";
    }
    return "UNKNOWN";
}

/* The descriptor of a 4 KiB page at level 3: type 0b11, the page's address, and the attributes of the template and nothing
 * else: not the contiguous hint (bit 52, which would claim sixteen neighbours), not the dirty-bit modifier, not the
 * software or implementation bits. The execute-never bit is a template attribute: the check below refuses a template that
 * has it clear, so it is set here whatever else. */
uint64_t q1n1_smmumap_descriptor(uint64_t page_pa, uint64_t template_desc)
{
    return (page_pa & Q1N1_SMMUMAP_ADDR) | UINT64_C(3) | (template_desc & (Q1N1_SMMUMAP_ATTR_LOW | Q1N1_SMMUMAP_ATTR_HIGH));
}

int q1n1_smmumap_descriptor_ok(uint64_t desc, uint64_t page_pa)
{
    if ((page_pa & UINT64_C(0xfff)) || (page_pa & ~Q1N1_SMMUMAP_ADDR)) return 0;
    if ((desc & UINT64_C(3)) != UINT64_C(3)) return 0;                                   /* a page, not a block or a table */
    if ((desc & Q1N1_SMMUMAP_ADDR) != page_pa) return 0;                                 /* that page and no other */
    return !(desc & ~(Q1N1_SMMUMAP_ADDR | UINT64_C(3) | Q1N1_SMMUMAP_ATTR_LOW | Q1N1_SMMUMAP_ATTR_HIGH));
}

/* A template is usable when its attributes are the ones MMIO registers need at EL2: Device and non-gathering,
 * non-reordering (MAIR attribute 0x00 nGnRnE, which is the unit's only Device entry, or 0x04 nGnRE; never G or R), the
 * access flag set (clear, the first access faults), writable at EL2, and execute-never. */
int q1n1_smmumap_template_check(uint64_t mair, uint64_t desc)
{
    unsigned index = (unsigned)((desc >> 2) & 7u);
    unsigned attr = (unsigned)((mair >> (8u * index)) & 0xffu);
    if (attr != 0x00u && attr != 0x04u) return Q1N1_SMMUMAP_R_TEMPLATE_NOT_DEVICE;
    if (!(desc & DESC_AF) || (desc & DESC_AP_RO) || !(desc & DESC_XN)) return Q1N1_SMMUMAP_R_TEMPLATE_NOT_USABLE;
    return 0;
}

/* ---- The memory map ------------------------------------------------------------------------------------------------------- */

int q1n1_smmumap_ram_type(int type)
{
    return (type >= 1 && type <= 7) || type == 9;
}

static uint64_t le32(const uint8_t *p)
{
    return (uint64_t)p[0] | (uint64_t)p[1] << 8 | (uint64_t)p[2] << 16 | (uint64_t)p[3] << 24;
}

static uint64_t le64(const uint8_t *p)
{
    return le32(p) | le32(p + 4) << 32;
}

/* The same decisions as the payloads' map_type_of (payloads/nvmesnap.c, smmuprobe.c) and the limits of their map check on the descriptors (a
 * stride of at least 40 and a multiple of 8, whole descriptors, at most 1,024 of them), so that the runner and the payload that follows it
 * cannot disagree about what is RAM. It does not repeat that check's two rules about the buffer itself (8-byte aligned, inside the 48-bit
 * space: pl_map_check in payloads/payload-mmu.h): the descriptors are read byte by byte here, so alignment does not matter, and the buffer
 * is the runner's own allocation, which the firmware places in the physical space (INFERRED, not measured). A type above 0xFFFF (no EFI type
 * is; the payloads call 1 to 7 and 9 RAM) is answered as 0xFFFF, so that no answer can be taken for the -1 or -2 of this function. The
 * descriptors are read in place, one at a time. */
int q1n1_smmumap_map_type(const uint8_t *map, uint64_t size, uint64_t stride, uint64_t pa, uint64_t bytes, uint64_t *attr)
{
    int found = -1;
    uint64_t found_attr = 0;
    if (attr) *attr = 0;
    if (!map || stride < EFI_DESC_MIN || (stride & 7u) || !size || size % stride || size / stride > MAP_DESCRIPTORS_MAX) return -2;
    if (!bytes || pa + bytes < pa) return -2;                  /* an empty or wrapping range is not a question */
    for (uint64_t i = 0; i < size / stride; i++) {
        const uint8_t *d = map + i * stride;
        uint64_t start = le64(d + 8), pages = le64(d + 24), end, raw = le32(d);
        int type = raw > 0xffffu ? 0xffff : (int)raw;
        if ((start & (PAGE_BYTES - 1)) || !pages || start >= MAP_ADDRESS_LIMIT || pages > (MAP_ADDRESS_LIMIT - start) / PAGE_BYTES) continue;
        end = start + pages * PAGE_BYTES;
        if (pa >= end || pa + bytes <= start) continue;
        if (!q1n1_smmumap_ram_type(type)) {
            if (attr) *attr = le64(d + 32);
            return type;
        }
        if (pa >= start && end - pa >= bytes) {
            found = type;
            found_attr = le64(d + 32);
        }
    }
    if (attr) *attr = found_attr;
    return found;
}

/* ---- The loads: the one place that calls env->read64 ---------------------------------------------------------------------- */

/* What the memory map said of the last page a load was asked about. `ok` says that page is RAM, so that the next load in the same page asks
 * nothing (a scan reads 512 words of one page); a page that is not RAM is asked about again each time. `type` and `attr` are map_type's
 * answers: the descriptor that decided, for the refusal's line. */
struct ram_proof {
    uint64_t page, attr;
    int type, ok;
};
enum { LOAD_OK, LOAD_ABORT, LOAD_NOT_RAM };

/* One guarded 64-bit load of a table word, made only in a page that the memory map calls RAM. The proof comes first, so that a page that is
 * not RAM (a device's registers, reserved memory, a page no descriptor holds, any page when the map cannot be read) is never loaded from,
 * whatever the tables say: LOAD_NOT_RAM, with `p` saying why. LOAD_ABORT: the guarded load aborted. Every load of the step comes through
 * here (tools/test-q1n1-sp11-payload-smmumap.py pins that env->read64 is called nowhere else). */
static int load_ram(const struct q1n1_smmumap_env *env, uint64_t at, uint64_t *value, struct ram_proof *p)
{
    uint64_t page = at & ~(PAGE_BYTES - 1u);
    if (!p->ok || p->page != page) {
        p->page = page;
        p->type = q1n1_smmumap_map_type(env->map, env->map_size, env->map_stride, page, PAGE_BYTES, &p->attr);
        p->ok = q1n1_smmumap_ram_type(p->type);
    }
    if (!p->ok) return LOAD_NOT_RAM;
    return env->read64(at, value) ? LOAD_ABORT : LOAD_OK;
}

/* ---- The software walk of the EL2 stage-1 tables (4 KiB granule, one VA range) ------------------------------------------ */

enum { WALK_PAGE, WALK_BLOCK, WALK_INVALID, WALK_FAULT, WALK_FORMAT, WALK_ADDRESS, WALK_NOT_RAM };
struct walk {
    uint64_t desc[4], at[4];    /* the descriptor read at each level and where it was read */
    uint64_t base[4];           /* the table each of them was read from */
    unsigned last;              /* the level of the last descriptor read; where a read aborted or was refused, the level of that read */
    uint64_t upper;             /* the hierarchical controls (bits 63:59) of the table descriptors passed */
    uint64_t table;             /* the base of the table read last */
    struct ram_proof proof;     /* the memory map's answer for the last table page: for WALK_NOT_RAM, the page that is not RAM and why */
};

static unsigned physical_bits(uint64_t tcr)
{
    static const unsigned bits[] = {32, 36, 40, 42, 44, 48};
    unsigned ps = (unsigned)((tcr >> 16) & 7u);
    return ps < 6u ? bits[ps] : 48u;                   /* 52-bit sizes are beyond the 48 bits of the masks used here */
}

/* The same arithmetic as q1n1_mmu_attr (live-battery.c), which returns only the attribute byte and is part of the pinned
 * runner, so it is not changed: this one returns the descriptors and where they sit. Each table is proven RAM by the memory map before
 * the word is loaded from it (the root, each table of the path, the level-3 table before its slot): WALK_NOT_RAM, nothing loaded. */
static int walk(const struct q1n1_smmumap_env *env, const struct q1n1_smmumap_regs *regs, uint64_t va, struct walk *w)
{
    uint32_t t0sz = (uint32_t)(regs->tcr & 63u);
    uint32_t bits = 64u - t0sz;
    unsigned level = 4u - (bits - 12u + 8u) / 9u;
    uint64_t table = regs->ttbr0 & Q1N1_SMMUMAP_ADDR;
    unsigned pa_bits = physical_bits(regs->tcr);
    for (unsigned i = 0; i < 4; i++) w->desc[i] = w->at[i] = w->base[i] = 0;
    w->last = level;
    w->upper = 0;
    w->table = table;
    w->proof.page = w->proof.attr = 0;
    w->proof.type = w->proof.ok = 0;
    if (va >> bits) return WALK_FORMAT;
    for (;; level++) {
        uint32_t shift = 12u + 9u * (3u - level);
        uint64_t at, desc = 0;
        int got;
        if (table >> pa_bits) return WALK_ADDRESS;
        at = table + ((va >> shift) & 0x1ffu) * 8u;
        w->table = table;
        w->base[level] = table;
        w->last = level;
        got = load_ram(env, at, &desc, &w->proof);
        if (got == LOAD_NOT_RAM) return WALK_NOT_RAM;
        if (got == LOAD_ABORT) return WALK_FAULT;
        w->desc[level] = desc;
        w->at[level] = at;
        if (!(desc & 1u)) return WALK_INVALID;
        if (level == 3u) return (desc & 3u) == 3u ? WALK_PAGE : WALK_FORMAT;
        if ((desc & 3u) == 1u) return level == 0u ? WALK_FORMAT : WALK_BLOCK;
        w->upper |= desc & TABLE_UPPER_BITS;
        table = desc & Q1N1_SMMUMAP_ADDR;
    }
}

/* ---- Lines ---------------------------------------------------------------------------------------------------------------- */

static void begin(struct q1n1_payload_line *line, const char *kind)
{
    q1n1_payload_line_begin(line, "PAYLOAD SMMUMAP");
    q1n1_payload_line_word(line, kind);
}

static void done(const struct q1n1_smmumap_env *env, struct q1n1_smmumap_result *out, int status, int reason)
{
    struct q1n1_payload_line line;
    out->status = status;
    out->reason = reason;
    begin(&line, "DONE");
    q1n1_payload_line_dec(&line, "MAPPED", status == Q1N1_SMMUMAP_MAPPED);
    q1n1_payload_line_dec(&line, "STORES", out->stores);
    if (status == Q1N1_SMMUMAP_UNSAFE) q1n1_payload_line_word(&line, "UNSAFE");
    env->emit(line.buf);
}

/* One named refusal: `PAYLOAD SMMUMAP REFUSED=<NAME>` with up to two numbers that say where, then DONE. This call writes
 * nothing; the put-back (CHECK_FAILED) and the UNSAFE refusal are the caller's. */
static int refuse(const struct q1n1_smmumap_env *env, struct q1n1_smmumap_result *out, int reason, const char *k1,
                  uint64_t v1, const char *k2, uint64_t v2)
{
    struct q1n1_payload_line line;
    q1n1_payload_line_begin(&line, "PAYLOAD SMMUMAP REFUSED=");
    q1n1_payload_line_raw(&line, q1n1_smmumap_reason_name(reason));
    if (k1) q1n1_payload_line_hex(&line, k1, v1);
    if (k2) q1n1_payload_line_hex(&line, k2, v2);
    env->emit(line.buf);
    done(env, out, Q1N1_SMMUMAP_REFUSED, reason);
    return Q1N1_SMMUMAP_REFUSED;
}

/* The refusal of a table page that the memory map does not call RAM, made before the load from it: `TABLE=` the page, `TYPE=` the EFI type of the
 * descriptor that decided (0XFF: none holds the page; 0XFE: the map cannot be read), `LEVEL=` the level of the table, and `ATTR=` that descriptor's
 * attribute word (reserved DRAM and reserved MMIO differ in it), which is the longest field, last, and printed only when the whole of it fits the
 * line: a field is never cut. */
static int refuse_not_ram(const struct q1n1_smmumap_env *env, struct q1n1_smmumap_result *out, const struct ram_proof *p, unsigned level)
{
    struct q1n1_payload_line line;
    char text[24];
    q1n1_payload_line_begin(&line, "PAYLOAD SMMUMAP REFUSED=");
    q1n1_payload_line_raw(&line, q1n1_smmumap_reason_name(Q1N1_SMMUMAP_R_TABLE_NOT_RAM));
    q1n1_payload_line_hex(&line, "TABLE", p->page);
    q1n1_payload_line_hex(&line, "TYPE", p->type == -1 ? Q1N1_SMMUMAP_TYPE_NOT_IN_MAP : p->type == -2 ? Q1N1_SMMUMAP_TYPE_MAP_UNUSABLE : (uint64_t)p->type);
    q1n1_payload_line_hex(&line, "LEVEL", level);
    if (p->type >= 0 && line.len + 6u + q1n1_payload_fmt_hex(text, sizeof text, p->attr) <= Q1N1_PAYLOAD_LINE_MAX)
        q1n1_payload_line_hex(&line, "ATTR", p->attr);
    env->emit(line.buf);
    done(env, out, Q1N1_SMMUMAP_REFUSED, Q1N1_SMMUMAP_R_TABLE_NOT_RAM);
    return Q1N1_SMMUMAP_REFUSED;
}

/* ---- The wait of the NEXT line ------------------------------------------------------------------------------------------- */

static int wait_seconds(const struct q1n1_smmumap_env *env, unsigned seconds)
{
    uint64_t start, last, now, spins = 0, freq = env->freq;
    uint32_t same = 0;
    if (!env->counter) return Q1N1_SMMUMAP_R_NO_COUNTER;
    if (freq < COUNTER_HZ_MIN || freq > COUNTER_HZ_MAX) freq = COUNTER_HZ_DEFAULT;
    start = last = env->counter();
    for (;;) {
        now = env->counter();
        if (now < start) return Q1N1_SMMUMAP_R_COUNTER_UNUSABLE;
        if (now - start >= seconds * freq) return Q1N1_SMMUMAP_R_NONE;
        if (now == last) {
            if (++same >= SMMUMAP_STUCK_READS) return Q1N1_SMMUMAP_R_COUNTER_UNUSABLE;
        } else {
            last = now;
            same = 0;
        }
        if (++spins >= SMMUMAP_SPIN_MAX) return Q1N1_SMMUMAP_R_SPIN_BOUND;
    }
}

/* ---- The regime ------------------------------------------------------------------------------------------------------------ */

static int regime(const struct q1n1_smmumap_regs *r)
{
    uint32_t t0sz = (uint32_t)(r->tcr & 63u);
    if (r->ttbr0 != Q1N1_SMMUMAP_TTBR0_EL2) return Q1N1_SMMUMAP_R_TTBR0_UNPINNED;
    if (!(r->sctlr & SCTLR_M) || (r->sctlr & SCTLR_EE)) return Q1N1_SMMUMAP_R_REGIME;      /* MMU on, little-endian walks */
    if (r->hcr & HCR_E2H) return Q1N1_SMMUMAP_R_REGIME;                                    /* the EL2 regime, one VA range */
    if ((r->tcr >> 14) & 3u) return Q1N1_SMMUMAP_R_REGIME;                                 /* 4 KiB granule */
    if (t0sz < 16u || t0sz > 39u) return Q1N1_SMMUMAP_R_REGIME;
    return Q1N1_SMMUMAP_R_NONE;
}

static int par_page(uint64_t par, uint64_t pa)
{
    return !(par & 1u) && (par & Q1N1_SMMUMAP_ADDR) == pa;
}

/* The barriers and the invalidation after a descriptor changed. The change is a last-level (level 3) entry of the EL2
 * regime, so the invalidation is by VA and last level only (TLBI VALE2IS: the walk caches of the upper levels hold no
 * entry that changed); inner shareable because the table is shared by every CPU that runs EL2 on it. The line is cleaned
 * first: a walk that does not snoop the data cache (TCR_EL2 says it does, but "never assume") must see the store. */
static void publish(const struct q1n1_smmumap_env *env, uint64_t slot, uint64_t page_va)
{
    env->clean(slot);
    env->dsb();
    env->tlbi(page_va);
    env->dsb();
    env->isb();
}

static int remove_descriptor(const struct q1n1_smmumap_env *env, struct q1n1_smmumap_result *out, uint64_t slot, uint64_t page_pa)
{
    uint64_t par = 0;
    if (env->store64(slot, 0)) return 0;
    out->stores++;
    publish(env, slot, page_pa);
    env->at(page_pa, 0, &par);
    return (par & 1u) != 0;                 /* it translates no more */
}

/* ---- The evidence scan: who else uses the level-3 table ------------------------------------------------------------------ */

/* The questions this step leaves open, answered by reading and printed (the document's UNKNOWN: what the other slots of the table hold
 * and who else points at it). Bounded: the 511 other slots of the level-3 table and every entry of the level-0, 1 and 2 tables of the
 * path, at most 2,047 guarded loads (511 + 3 x 512; 1,567 on the unit's regime, whose start table has 32 entries), no write. Each goes
 * through load_ram, so none is made into a page the memory map does not call RAM; the tables of the path were proven RAM by the walk. */
struct scan {
    unsigned valid;                 /* valid entries among the other 511 slots of the level-3 table */
    int refs[3];                    /* table descriptors of the level-3 table in the level-0, 1 and 2 tables of the path; -1: the walk of this
                                     * regime starts below that level, so the path has no table there (no table is ever skipped otherwise) */
    uint64_t at;                    /* where a load aborted or was refused */
    unsigned level;                 /* ... in which table: 3 the level-3 table, else the level of the table of the path */
    struct ram_proof bad;           /* the proof of the last page asked about: for LOAD_NOT_RAM the page that is not RAM and why */
};

/* The entries of the table that a walk starts at: a 44-bit VA starts at level 0 with 32 of them, not 512. */
static unsigned start_entries(unsigned bits, unsigned level)
{
    unsigned top = bits - (12u + 9u * (3u - level));
    return top >= 9u ? 512u : 1u << top;
}

/* LOAD_OK, or the first load that did not succeed: LOAD_ABORT (`s->at`, `s->level`) or LOAD_NOT_RAM (the same, and `s->bad`). */
static int scan_tables(const struct q1n1_smmumap_env *env, const struct q1n1_smmumap_regs *regs, const struct walk *target, uint64_t slot, struct scan *s)
{
    unsigned bits = 64u - (unsigned)(regs->tcr & 63u), first = 4u - (bits - 12u + 8u) / 9u, level, i;
    uint64_t value;
    int got;
    s->valid = 0;
    s->at = 0;
    s->level = 3;
    s->bad.page = s->bad.attr = 0;
    s->bad.type = s->bad.ok = 0;
    for (i = 0; i < 512; i++) {
        uint64_t at = target->table + 8u * i;
        if (at == slot) continue;
        got = load_ram(env, at, &value, &s->bad);
        if (got != LOAD_OK) {
            s->at = at;
            return got;
        }
        s->valid += (unsigned)(value & 1u);
    }
    for (level = 0; level < 3; level++) {
        unsigned entries = level == first ? start_entries(bits, level) : 512u;
        s->refs[level] = -1;
        if (level < first) continue;
        s->refs[level] = 0;
        for (i = 0; i < entries; i++) {
            uint64_t at = target->base[level] + 8u * i;
            got = load_ram(env, at, &value, &s->bad);
            if (got != LOAD_OK) {
                s->at = at;
                s->level = level;
                return got;
            }
            if ((value & 3u) == 3u && (value & Q1N1_SMMUMAP_ADDR) == target->table) s->refs[level]++;
        }
    }
    return LOAD_OK;
}

static void put_scan(struct q1n1_payload_line *line, const struct scan *s)
{
    char one[24];
    q1n1_payload_line_dec(line, "VALID", s->valid);
    q1n1_payload_line_raw(line, " REFS=");
    for (unsigned level = 0; level < 3; level++) {
        if (level) q1n1_payload_line_raw(line, "/");
        if (s->refs[level] < 0) {
            q1n1_payload_line_raw(line, "-");
        } else {
            q1n1_payload_fmt_dec(one, sizeof one, (uint64_t)s->refs[level]);
            q1n1_payload_line_raw(line, one);
        }
    }
}

int q1n1_smmumap_page(const struct q1n1_smmumap_env *env, const struct q1n1_smmumap_spec *spec, struct q1n1_smmumap_result *out)
{
    struct q1n1_smmumap_result local;
    struct q1n1_smmumap_regs regs;
    struct walk target, tpl;
    struct scan found;
    struct ram_proof reread;
    struct q1n1_payload_line line;
    uint64_t par = 0, par_template = 0, par_table = 0, desc, slot, again = 0, mair_byte;
    char seconds[24];
    unsigned allowed = 0, i;
    int status, reason, got;

    if (!out) out = &local;
    out->status = Q1N1_SMMUMAP_REFUSED;
    out->reason = Q1N1_SMMUMAP_R_NONE;
    out->stores = 0;
    out->desc = out->slot = 0;
    out->serror_before = 0;

    begin(&line, "START");
    q1n1_payload_line_word(&line, spec->name);
    q1n1_payload_line_hex(&line, "PAGE", spec->page_pa);
    q1n1_payload_line_hex(&line, "TEMPLATE", spec->template_pa);
    for (i = 0; i < q1n1_smmumap_spec_count; i++)
        allowed |= spec->page_pa == q1n1_smmumap_specs[i].page_pa && spec->template_pa == q1n1_smmumap_specs[i].template_pa;
    if (!allowed) {
        env->emit(line.buf);
        return refuse(env, out, Q1N1_SMMUMAP_R_SPEC, "PAGE", spec->page_pa, 0, 0);
    }

    /* 1. The registers, printed before anything is asked of the tables. */
    env->regs(&regs);
    q1n1_payload_line_hex(&line, "TTBR0", regs.ttbr0);
    env->emit(line.buf);
    begin(&line, "REGS");
    q1n1_payload_line_hex(&line, "TCR", regs.tcr);
    q1n1_payload_line_hex(&line, "MAIR", regs.mair);
    q1n1_payload_line_hex(&line, "SCTLR", regs.sctlr);
    q1n1_payload_line_hex(&line, "HCR", regs.hcr);
    env->emit(line.buf);
    reason = regime(&regs);
    if (reason) return refuse(env, out, reason, "TTBR0", regs.ttbr0, "TCR", regs.tcr);

    /* 2. The walk to the page: three tables, and a level-3 slot that is zero. */
    status = walk(env, &regs, spec->page_pa, &target);
    begin(&line, "WALK");
    q1n1_payload_line_hex(&line, "L0", target.desc[0]);
    q1n1_payload_line_hex(&line, "L1", target.desc[1]);
    q1n1_payload_line_hex(&line, "L2", target.desc[2]);
    q1n1_payload_line_hex(&line, "SLOT", target.at[3]);
    q1n1_payload_line_hex(&line, "OLD", target.desc[3]);
    env->emit(line.buf);
    if (status == WALK_NOT_RAM) return refuse_not_ram(env, out, &target.proof, target.last);
    if (status == WALK_FAULT) return refuse(env, out, Q1N1_SMMUMAP_R_WALK_FAULT, "LEVEL", target.last, 0, 0);
    if (status == WALK_ADDRESS) return refuse(env, out, Q1N1_SMMUMAP_R_TABLE_ADDRESS, "TABLE", target.table, 0, 0);
    if (status == WALK_PAGE) return refuse(env, out, Q1N1_SMMUMAP_R_ENTRY_VALID, "DESC", target.desc[3], 0, 0);
    if (status != WALK_INVALID || target.last != 3u)
        return refuse(env, out, Q1N1_SMMUMAP_R_NO_L3_TABLE, "LEVEL", target.last, "DESC", target.desc[target.last]);
    if (target.upper) return refuse(env, out, Q1N1_SMMUMAP_R_UPPER_FLAGS, "FLAGS", target.upper, 0, 0);
    if (target.desc[3]) return refuse(env, out, Q1N1_SMMUMAP_R_ENTRY_NOT_ZERO, "DESC", target.desc[3], 0, 0);
    slot = target.at[3];
    if (((slot & UINT64_C(0xfff)) >> 3) != ((spec->page_pa >> 12) & UINT64_C(0x1ff)) || (slot & ~UINT64_C(0xfff)) != target.table)
        return refuse(env, out, Q1N1_SMMUMAP_R_DESCRIPTOR, "SLOT", slot, 0, 0);
    /* A table that is also a table of a higher level on this path would read the descriptor written here as a table descriptor
     * of that level, and map something else. */
    for (i = 0; i < 3; i++)
        if (target.base[i] == target.table) return refuse(env, out, Q1N1_SMMUMAP_R_TABLE_SHARED, "TABLE", target.table, "LEVEL", i);
    /* The hardware must agree with the walk: a level-3 translation fault at the first stage, the one S1 observed. */
    env->at(spec->page_pa, 0, &par);
    if (!(par & 1u) || ((par >> 1) & 0x3fu) != FST_TRANSLATION_L3 || (par & PAR_FAULT_STAGE2))
        return refuse(env, out, Q1N1_SMMUMAP_R_AT_DISAGREES, "PAGE", spec->page_pa, "PAR", par);

    /* 3. The template: the Device entry the same runner's payloads already read. */
    status = walk(env, &regs, spec->template_pa, &tpl);
    if (status == WALK_NOT_RAM) return refuse_not_ram(env, out, &tpl.proof, tpl.last);
    if (status == WALK_FAULT) return refuse(env, out, Q1N1_SMMUMAP_R_WALK_FAULT, "LEVEL", tpl.last, 0, 0);
    if (status != WALK_PAGE && status != WALK_BLOCK)
        return refuse(env, out, Q1N1_SMMUMAP_R_TEMPLATE_UNMAPPED, "LEVEL", tpl.last, "DESC", tpl.desc[tpl.last]);
    mair_byte = (regs.mair >> (8u * (unsigned)((tpl.desc[tpl.last] >> 2) & 7u))) & 0xffu;
    env->at(spec->template_pa, 0, &par_template);
    begin(&line, "TEMPLATE");
    q1n1_payload_line_hex(&line, "LEVEL", tpl.last);
    q1n1_payload_line_hex(&line, "DESC", tpl.desc[tpl.last]);
    q1n1_payload_line_hex(&line, "ATTR", mair_byte);
    q1n1_payload_line_hex(&line, "PAR", par_template);
    env->emit(line.buf);
    reason = q1n1_smmumap_template_check(regs.mair, tpl.desc[tpl.last]);
    if (reason) return refuse(env, out, reason, "DESC", tpl.desc[tpl.last], "ATTR", mair_byte);
    for (i = 0; i <= tpl.last; i++)
        if (tpl.base[i] && tpl.base[i] == target.table) return refuse(env, out, Q1N1_SMMUMAP_R_TABLE_SHARED, "TABLE", target.table, "LEVEL", i);
    if ((par_template & 1u) || (par_template >> 56) != mair_byte)
        return refuse(env, out, Q1N1_SMMUMAP_R_AT_DISAGREES, "PAGE", spec->template_pa, "PAR", par_template);

    /* 4. The table page must take a store at EL2 and be ordinary memory: asked of the hardware, which sees every level of
     * control (an access permission in a table descriptor above, a read-only mapping), and which makes no access. */
    env->at(target.table, 1, &par_table);
    if (!par_page(par_table, target.table) || !((par_table >> 56) & 0xf0u))
        return refuse(env, out, Q1N1_SMMUMAP_R_TABLE_NOT_WRITABLE, "TABLE", target.table, "PAR", par_table);

    /* 4b. What the neighbours of the slot are and who else points at the table: read, bounded, printed. Only a pointer to the table
     * from a higher table of the path is refused (the page would then be read as a table of that level, and the descriptor written
     * here as a table descriptor of the SMMU's registers); the others, and the valid neighbours, are evidence for the document. Every
     * load goes through load_ram; the tables of the path were proven RAM by the walk, so none is skipped. */
    got = scan_tables(env, &regs, &target, slot, &found);
    if (got == LOAD_NOT_RAM) return refuse_not_ram(env, out, &found.bad, found.level);
    if (got == LOAD_ABORT) return refuse(env, out, Q1N1_SMMUMAP_R_SCAN_FAULT, "AT", found.at, "LEVEL", found.level);
    begin(&line, "TABLE");
    put_scan(&line, &found);
    env->emit(line.buf);
    if (found.refs[0] > 0 || found.refs[1] > 0)
        return refuse(env, out, Q1N1_SMMUMAP_R_TABLE_SHARED, "TABLE", target.table, "LEVEL", found.refs[0] > 0 ? 0u : 1u);

    /* 5. The descriptor, and that it is that one page. */
    desc = q1n1_smmumap_descriptor(spec->page_pa, tpl.desc[tpl.last]);
    if (!q1n1_smmumap_descriptor_ok(desc, spec->page_pa)) return refuse(env, out, Q1N1_SMMUMAP_R_DESCRIPTOR, "DESC", desc, 0, 0);
    begin(&line, "STORE");
    q1n1_payload_line_hex(&line, "SLOT", slot);
    q1n1_payload_line_hex(&line, "DESC", desc);
    q1n1_payload_line_word(&line, "TABLEW=OK");
    env->emit(line.buf);

    /* 6. The NEXT line, then the wait: a board that stops during the store, the invalidation or the checks leaves this line last. */
    q1n1_payload_fmt_dec(seconds, sizeof seconds, Q1N1_SMMUMAP_WAIT_S);
    begin(&line, "NEXT STORE AFTER");
    q1n1_payload_line_word(&line, seconds);
    q1n1_payload_line_word(&line, "S");
    env->emit(line.buf);
    reason = wait_seconds(env, Q1N1_SMMUMAP_WAIT_S);
    if (reason) return refuse(env, out, reason, 0, 0, 0, 0);

    /* The slot was read as zero in the walk, eight seconds and a few thousand reads ago: read it once more, just before the store (through
     * load_ram with a proof of its own, so that the page is asked about again). */
    reread.page = reread.attr = 0;
    reread.type = reread.ok = 0;
    got = load_ram(env, slot, &again, &reread);
    if (got == LOAD_NOT_RAM) return refuse_not_ram(env, out, &reread, 3);
    if (got == LOAD_ABORT) return refuse(env, out, Q1N1_SMMUMAP_R_WALK_FAULT, "LEVEL", 3, 0, 0);
    if (again) return refuse(env, out, Q1N1_SMMUMAP_R_ENTRY_NOT_ZERO, "DESC", again, 0, 0);

    /* 7. THE store: one 64-bit store of a descriptor into a slot that was read as zero, then the barriers and the invalidation. */
    if (env->store64(slot, desc)) return refuse(env, out, Q1N1_SMMUMAP_R_STORE_FAULT, "SLOT", slot, 0, 0);
    out->stores++;
    out->desc = desc;
    out->slot = slot;
    publish(env, slot, spec->page_pa);

    /* 8. The check: the page translates to itself, readable and writable at EL2, with the attributes of the template's. */
    {
        uint64_t par_r = 0, par_w = 0;
        int good;
        env->at(spec->page_pa, 0, &par_r);
        env->at(spec->page_pa, 1, &par_w);
        good = par_page(par_r, spec->page_pa) && par_page(par_w, spec->page_pa) && !((par_r ^ par_template) & PAR_ATTR_MASK);
        begin(&line, "CHECK");
        q1n1_payload_line_hex(&line, "PARR", par_r);
        q1n1_payload_line_hex(&line, "PARW", par_w);
        q1n1_payload_line_word(&line, good ? "ATTR=SAME" : "ATTR=DIFFERENT");
        env->emit(line.buf);
        if (!good) {
            if (remove_descriptor(env, out, slot, spec->page_pa)) {
                struct q1n1_payload_line undone;
                q1n1_payload_line_begin(&undone, "PAYLOAD SMMUMAP REFUSED=CHECK_FAILED");
                q1n1_payload_line_word(&undone, "UNDONE=1");
                env->emit(undone.buf);
                done(env, out, Q1N1_SMMUMAP_REFUSED, Q1N1_SMMUMAP_R_CHECK_FAILED);
                return Q1N1_SMMUMAP_REFUSED;
            }
            q1n1_payload_line_begin(&line, "PAYLOAD SMMUMAP REFUSED=ROLLBACK_FAILED");
            q1n1_payload_line_hex(&line, "SLOT", slot);
            env->emit(line.buf);
            done(env, out, Q1N1_SMMUMAP_UNSAFE, Q1N1_SMMUMAP_R_ROLLBACK_FAILED);
            return Q1N1_SMMUMAP_UNSAFE;
        }
    }
    out->serror_before = env->serror_pending ? env->serror_pending() != 0 : 0;
    done(env, out, Q1N1_SMMUMAP_MAPPED, Q1N1_SMMUMAP_R_NONE);
    return Q1N1_SMMUMAP_MAPPED;
}

int q1n1_smmumap_run(const struct q1n1_smmumap_env *env, struct q1n1_smmumap_result *result)
{
    return q1n1_smmumap_page(env, &q1n1_smmumap_specs[0], result);
}

/* An asynchronous SError that a bad access leaves pending is neither taken nor shown while DAIF.A is masked, so the first read of the
 * SMMU's page (smmuprobe's) could leave one that nothing reports. The poll is the proxy's (main.c), made once, here, after the chain, and
 * nothing else in the runner catches or clears an SError. It CONSUMES what it finds (ESB and a clear of DISR_EL1, or DAIF.A unmasked for
 * two instructions so that q1n1's handler takes and swallows it). FOUND: one was pending when the poll ran, raised by a payload of the
 * chain or later, not necessarily by smmuprobe's read; `before` (ISR_EL1.A as the step ended, before any payload ran) separates only the
 * step's own past. NONE is not "the read was error-free": EL3 may take an SError itself, and DISR_EL1 and ISR_EL1 then read zero. */
void q1n1_smmumap_after_chain(const struct q1n1_smmumap_env *env, const struct q1n1_smmumap_result *result)
{
    struct q1n1_payload_line line;
    uint64_t syndrome = 0;
    int still = 0, found;
    if (!result || result->status != Q1N1_SMMUMAP_MAPPED || !env->serror_poll) return;
    found = env->serror_poll(&syndrome, &still);
    begin(&line, found ? "SERROR=FOUND" : "SERROR=NONE");
    if (found) q1n1_payload_line_hex(&line, "SYNDROME", syndrome);
    q1n1_payload_line_dec(&line, "PENDING", still != 0);
    q1n1_payload_line_dec(&line, "BEFORE", result->serror_before != 0);
    env->emit(line.buf);
}

#endif /* Q1N1_SP11_SMMUMAP */
