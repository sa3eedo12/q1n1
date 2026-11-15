/* SPDX-License-Identifier: MIT */
/* Asking the MMU what EL2's own stage 1 maps, and reading the firmware's final memory map, shared by the el2mem and hashbig payloads
 * (docs/SP11-PAYLOAD-EL2MEM.md, docs/SP11-PAYLOAD-HASHBIG.md). Header only and static, like payload-util.h: a payload is one .c file,
 * so each binary holds one copy of the AT wrapper, one `at s1e2r`, one `isb` and one read of PAR_EL1.
 *
 * AT S1E2R translates an address through the EL2 stage-1 tables as a load at EL2 would and leaves the answer in PAR_EL1. It makes no
 * access at the address and takes no data abort: a missing mapping, or a walk that ends in an external abort, is reported in PAR_EL1.F
 * and PAR_EL1.FST. An ISB must separate the AT from the read of PAR_EL1, or the read may still see the old value. What it does touch is
 * the stage-1 table memory (the walk) and PAR_EL1 itself. Nothing of q1n1's runner image reads or writes PAR_EL1 (only src/hv_vm.c
 * does, around its own AT; the runner is built without it: VERIFIED by a search of the tree, host fact), so clobbering it is harmless
 * to what runs after the payload returns.
 *
 * PAR_EL1 as it is decoded here (VERIFIED against the definitions in Linux arch/arm64/include/asm/sysreg.h, read 2026-11-16; the Arm
 * ARM was not re-read): bit 0 F; with F == 1 FST is bits 6:1; with F == 0 SH is bits 8:7, NS bit 9, the output address bits 51:12 and
 * ATTR bits 63:56. ATTR is already the MAIR byte of the mapping (the same encoding as one Attr<n> field of MAIR_ELx), not an index
 * into MAIR_EL2. What the NS bit means for a Non-secure EL2 translation is UNKNOWN: it is shown as it reads, never interpreted. Bit 11
 * is RES1 or NSE depending on the architecture version and is not used.
 *
 * Evidence: EXPERIMENTAL; hardware NOT RUN. */
#pragma once
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* The host test replaces the instruction: a model of the translation answers with the PAR_EL1 value it would have left. */
uint64_t pl_host_at_s1e2r(uint64_t va);
#endif

#define PL_PAGE_BYTES UINT64_C(4096)

/* One AT S1E2R and the read of PAR_EL1 that follows its ISB. Out of line on purpose: the one place the instruction sits. */
static __attribute__((noinline)) uint64_t pl_at_s1e2r(uint64_t va)
{
#ifdef Q1N1_PAYLOAD_HOST_TEST
    return pl_host_at_s1e2r(va);
#else
    uint64_t par;
    __asm__ volatile("at s1e2r, %1\n\tisb\n\tmrs %0, par_el1" : "=r"(par) : "r"(va) : "memory");
    return par;
#endif
}

/* The decoded answer for one address. `mapped` is PAR_EL1.F == 0; the rest of that group is meaningful only then, `fst` only when
 * not. `ident` says the output page is the input page (the firmware's tables are expected to be an identity map). */
struct pl_walk {
    uint64_t pa;
    uint8_t mapped, attr, sh, ns, fst, ident;
};

static inline void pl_walk_decode(uint64_t par, uint64_t va, struct pl_walk *w)
{
    w->mapped = !(par & 1);
    w->pa = w->mapped ? par & UINT64_C(0x000ffffffffff000) : 0;
    w->attr = w->mapped ? (uint8_t)(par >> 56) : 0;
    w->sh = w->mapped ? (uint8_t)(par >> 7 & 3) : 0;
    w->ns = w->mapped ? (uint8_t)(par >> 9 & 1) : 0;
    w->fst = w->mapped ? 0 : (uint8_t)(par >> 1 & 63);
    w->ident = w->mapped && w->pa == (va & UINT64_C(0x000ffffffffff000));
}

static inline void pl_walk_page(uint64_t va, struct pl_walk *w)
{
    pl_walk_decode(pl_at_s1e2r(va), va, w);
}

/* Every field that tells two results apart, in one word: results with equal keys fold into one run. Faults differ by FST only. */
static inline uint32_t pl_walk_key(const struct pl_walk *w)
{
    if (!w->mapped) return w->fst;
    return 1u << 24 | (uint32_t)w->attr << 16 | (uint32_t)w->sh << 4 | (uint32_t)w->ns << 2 | w->ident;
}

enum { PL_ATTR_DEVICE, PL_ATTR_NC, PL_ATTR_WT, PL_ATTR_WB, PL_ATTR_OTHER };

/* A MAIR attribute byte. Device: the high nibble 0 and no bits 1:0 (nGnRnE, nGnRE, nGRE, GRE). Normal: one cacheability per nibble,
 * 0b0100 non-cacheable, 0b10xx write-through and 0b11xx write-back, both non-transient. Anything else (transient hints, one nibble
 * differing from the other, tagged memory) is OTHER and printed as the byte. */
static inline unsigned pl_attr_class(uint8_t attr)
{
    unsigned outer = attr >> 4, inner = attr & 15u;
    if (outer == 0) return (inner & 3u) == 0 ? PL_ATTR_DEVICE : PL_ATTR_OTHER;
    if (outer == 4 && inner == 4) return PL_ATTR_NC;
    if (outer >> 2 == 2 && inner >> 2 == 2) return PL_ATTR_WT;
    if (outer >> 2 == 3 && inner >> 2 == 3) return PL_ATTR_WB;
    return PL_ATTR_OTHER;
}

/* "WB", "WT", "NC", "DEVICE" or "OTHER=0XNN". */
static inline void pl_put_attr(const struct q1n1_payload_args *a, struct pl_line *line, uint8_t attr)
{
    static const char name[4][7] = {"DEVICE", "NC", "WT", "WB"};
    unsigned cls = pl_attr_class(attr);
    if (cls < PL_ATTR_OTHER) {
        pl_text(line, name[cls]);
    } else {
        pl_text(line, "OTHER=");
        pl_hex(a, line, attr);
    }
}

/* "NSH" (non-shareable), "OS", "IS" or "RES" (the reserved encoding 0b01). */
static inline void pl_put_sh(struct pl_line *line, uint8_t sh)
{
    static const char name[4][4] = {"NSH", "RES", "OS", "IS"};
    pl_text(line, name[sh & 3]);
}

/* FST: the fault class and level for the encodings that have one (the low two bits of 0b00xxLL to 0b11xxLL are the level), the
 * raw code as well, always. */
static inline void pl_put_fst(const struct q1n1_payload_args *a, struct pl_line *line, uint8_t fst)
{
    static const char name[4][7] = {"ADDR", "TRANS", "ACCESS", "PERM"};
    pl_hex(a, line, fst);
    if (fst >> 4 == 0) {
        pl_text(line, ":");
        pl_text(line, name[fst >> 2 & 3]);
        pl_text(line, fst & 3 ? "_L" : "_L0");
        if (fst & 3) {
            char digit[2] = {(char)('0' + (fst & 3)), 0};
            pl_text(line, digit);
        }
    }
}

/* "WB.IS" for a mapped page, with ".NS1" for a set NS bit and ".NONIDENT" for an output page other than the input page;
 * "FAULT=0X5:TRANS_L1" for a fault. */
static inline void pl_put_walk(const struct q1n1_payload_args *a, struct pl_line *line, const struct pl_walk *w)
{
    if (!w->mapped) {
        pl_text(line, "FAULT=");
        pl_put_fst(a, line, w->fst);
        return;
    }
    pl_put_attr(a, line, w->attr);
    pl_text(line, ".");
    pl_put_sh(line, w->sh);
    if (w->ns) pl_text(line, ".NS1");
    if (!w->ident) pl_text(line, ".NONIDENT");
}

/* ---- The final UEFI memory map, read in place --------------------------------------------------------------------------------- */
/* The map ExitBootServices was given is in the runner's memory and stays readable (a->map_base, map_size, map_stride). It is read where
 * it is, through the pointer in the arguments, which pl_desc_read reloads for every descriptor and nothing keeps anywhere else (the
 * binary check proves that: tools/sp11_payload_memcheck.py). Every other read of RAM or of a device is the runner's guarded load32. */

#define PL_ADDRESS_LIMIT (UINT64_C(1) << 48)
#define PL_DESC_BYTES_MIN 40u           /* type, pad, physical start, virtual start, pages, attributes: the UEFI descriptor */
#define PL_DESCRIPTORS_MAX 1024u
#define PL_EFI_LOADER_CODE 1u
#define PL_EFI_LOADER_DATA 2u
#define PL_EFI_CONVENTIONAL 7u

enum {
    PL_MAP_OK, PL_MAP_STRIDE_BELOW_40, PL_MAP_STRIDE_NOT_8, PL_MAP_SIZE, PL_MAP_BUFFER, PL_MAP_TOO_MANY,
};

struct pl_desc {
    uint64_t start, end;
    uint32_t type;
};

typedef uint64_t __attribute__((may_alias)) pl_u64a;
typedef uint32_t __attribute__((may_alias)) pl_u32a;

/* PL_MAP_OK when the map may be read, otherwise why not; reads nothing of it. The stride must hold a whole descriptor and keep its
 * 8-byte fields aligned, the size must be whole descriptors (a descriptor partly beyond the end of the buffer is never read), the buffer
 * must be aligned and inside the 48-bit space, and the count is bounded so that the scans stay short. */
static inline unsigned pl_map_check(const struct q1n1_payload_args *a)
{
    uint64_t base = a->map_base, size = a->map_size, stride = a->map_stride;
    if (stride < PL_DESC_BYTES_MIN) return PL_MAP_STRIDE_BELOW_40;
    if (stride & 7u) return PL_MAP_STRIDE_NOT_8;
    if (!size || size % stride) return PL_MAP_SIZE;
    if (!base || (base & 7u) || base >= PL_ADDRESS_LIMIT || size > PL_ADDRESS_LIMIT - base) return PL_MAP_BUFFER;
    if (size / stride > PL_DESCRIPTORS_MAX) return PL_MAP_TOO_MANY;
    return PL_MAP_OK;
}

/* The reason pl_map_check gave, as text. */
static inline void pl_put_map_refusal(struct pl_line *line, unsigned code)
{
    switch (code) {
    case PL_MAP_STRIDE_BELOW_40: pl_text(line, "STRIDE_BELOW_40"); break;
    case PL_MAP_STRIDE_NOT_8: pl_text(line, "STRIDE_NOT_A_MULTIPLE_OF_8"); break;
    case PL_MAP_SIZE: pl_text(line, "SIZE_NOT_WHOLE_DESCRIPTORS"); break;
    case PL_MAP_BUFFER: pl_text(line, "BUFFER_OUT_OF_RANGE"); break;
    default: pl_text(line, "TOO_MANY_DESCRIPTORS"); break;
    }
}

/* Descriptor i, in place. Called only for i below map_size / map_stride after pl_map_check said OK, so every field lies inside the
 * buffer. Returns 0 for a descriptor that is no usable range (unaligned, empty, or not inside the 48-bit space). */
static __attribute__((noinline)) int pl_desc_read(const struct q1n1_payload_args *a, uint64_t i, struct pl_desc *d)
{
    const uint8_t *p = (const uint8_t *)(uintptr_t)(a->map_base + i * a->map_stride);
    uint64_t pages = *(const pl_u64a *)(p + 24);
    d->type = *(const pl_u32a *)p;
    d->start = *(const pl_u64a *)(p + 8);
    d->end = 0;
    if ((d->start & (PL_PAGE_BYTES - 1)) || !pages || d->start >= PL_ADDRESS_LIMIT ||
        pages > (PL_ADDRESS_LIMIT - d->start) / PL_PAGE_BYTES)
        return 0;
    d->end = d->start + pages * PL_PAGE_BYTES;
    return 1;
}
