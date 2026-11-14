/* SPDX-License-Identifier: MIT */
/* Payload "usbsmmu" (S0b): reads, with loads only, the USB controllers, the firmware's xHCI structures and the SMMU context
 * bank the stick's DMA goes through, to decide whether an EL2 xHCI driver may give the xHC DMA memory of its own and where
 * (docs/SP11-PAYLOAD-USBSMMU.md has the registers, their evidence labels and the decisions). Every access is an ops.load32
 * (the runner's memory map is read in place); CurrentEL is the only system register. Nothing is stored or barriered.
 *
 * Groups, in the order of what a reset would cost. A NEXT line precedes each group that reads what the unit has not been
 * read for yet, so the last line on the panel names what hung: U0 (xHC and DWC3 registers), SMMU (global space 0, the stream
 * match registers), RINGS (the firmware's DCBAA, device contexts and event ring: RAM), CB<n> (the context bank the streams
 * match: never read on the unit before, the one real risk), WALK (that bank's stage-1 tables walked in software: RAM).
 *
 * Safety, each rule with a seeded bug in the host test: MMIO only in three windows, 4-byte aligned, a block only once its
 * identity looks plausible, nothing more from a window after an abort in it; only the bank(s) the streams match, below NUMCB;
 * a RAM address from hardware or memory is loaded only if the UEFI memory map calls it usable RAM (types 1 to 7 and 9);
 * everything bounded (3000 loads, 8 slots, 256 stream match registers, 4 table levels, 1024 map descriptors, 24 lines);
 * an unsupported format is a printed reason, never a guess.
 *
 * Output: at most LINE_CAP lines whatever the hardware says: a group reserves what the later ones need (room()), a field that
 * does not fit is dropped and counted in CUTS, never cut in half. A value below 10 is one digit, a larger one 0X and the
 * fewest upper-case hex digits; indices (slot, endpoint, bank, match register) are decimal. */
#include "payload-util.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
/* No MRS can run on a build machine: the host test supplies the register file. */
uint64_t pl_host_sysreg(const char *name);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#define PREFIX "PAYLOAD USBSMMU "
#define OUT_OF_LINE static __attribute__((noinline))     /* the reviewed binary stays small: one body per helper */

#define LINE_CAP 24u
#define LOAD_CAP 3000u              /* the ABI allows 4096 per call */
#define SLOTS_SCANNED 8u            /* device context base address array entries 1..8 */
#define SLOT_LINES_MAX 4u
#define SMR_SCANNED_MAX 256u
#define MAP_DESCRIPTORS_MAX 1024u
#define MAP_STRIDE_MAX 4096u
#define PROBES_MAX 7u

/* The only device addresses this payload reads: reg of usb_1_ss0, usb_1_ss1 and apps_smmu in the pinned Hamoa device tree
 * (VERIFIED); the S0 survey read all three on the unit (OBSERVED). */
enum { WIN_U0, WIN_U1, WIN_SMMU, WINDOWS };
static const struct {
    uint64_t base;
    uint32_t size;
} windows[WINDOWS] = {{0x0a600000u, 0xfc100u}, {0x0a800000u, 0xfc100u}, {0x15000000u, 0x100000u}};

/* xHCI 1.2: capability registers from the window base, operational ones from base + CAPLENGTH, runtime ones from base +
 * RTSOFF, where interrupter 0 sits at +0x20: ERSTSZ +8, ERSTBA +0x10, ERDP +0x18. */
enum {
    CAP_CAP0 = 0x00, CAP_HCSPARAMS1 = 0x04, CAP_HCCPARAMS1 = 0x10, CAP_RTSOFF = 0x18,
    OP_USBCMD = 0x00, OP_USBSTS = 0x04, OP_CRCR = 0x18, OP_DCBAAP = 0x30, OP_CONFIG = 0x38,
    RT_ERSTSZ = 0x28, RT_ERSTBA = 0x30, RT_ERDP = 0x38,
};
#define OP_PORTSC(n) (0x400u + 0x10u * ((n) - 1u))
/* DWC3 global registers from the window base (core.h of the pinned Linux files, VERIFIED). */
enum {
    DWC3_GCTL = 0xc110, DWC3_GSTS = 0xc118, DWC3_GSNPSID = 0xc120, DWC3_GBUSERRADDR0 = 0xc130, DWC3_GBUSERRADDR1 = 0xc134,
    DWC3_GDBGLTSSM = 0xc164,
};
/* SMMUv2 (arm-smmu.h, VERIFIED; sGFAR is the architecture's, not in that file). Global space 1 is one page up: CBAR(n) at +4n,
 * CBA2R(n) at +0x800+4n. Context bank n's own page: see bank_page(). */
enum {
    SMMU_SCR0 = 0x00, SMMU_ID0 = 0x20, SMMU_ID1 = 0x24, SMMU_ID2 = 0x28, SMMU_GFAR = 0x40, SMMU_GFSR = 0x48, SMMU_GFSYNR0 = 0x50,
    CB_SCTLR = 0x00, CB_TCR2 = 0x10, CB_TTBR0 = 0x20, CB_TTBR1 = 0x28, CB_TCR = 0x30, CB_MAIR0 = 0x38, CB_MAIR1 = 0x3c,
    CB_FSR = 0x58, CB_FAR = 0x60, CB_FSYNR0 = 0x68,
};
#define SMMU_SMR(n) (0x800u + 4u * (n))
#define SMMU_S2CR(n) (0xc00u + 4u * (n))
#define GR1_CBAR(n) (4u * (n))
#define GR1_CBA2R(n) (0x800u + 4u * (n))

/* The streams of the two controllers (iommus of usb_1_ss0 and usb_1_ss1 in the pinned hamoa.dtsi, VERIFIED). */
static const uint32_t stream_id[2] = {0x1420u, 0x1460u};

enum { XS_FAILED, XS_OK, XS_ALL_ONES, XS_ZERO, XS_NOT_XHCI };
struct xhc {
    uint32_t state, idle, nports, cap0, hcs1, hcc1, rtsoff, cmd, sts, cfg, portsc[2];
    uint64_t crcr, dcbaap;
};

struct map {
    uint64_t base, stride;
    uint32_t count, ok;
};

struct smmu {
    uint32_t ok, scanned, exid, scr0, id0, id1, id2, gfsr, numsmrg, numcb, pagesize, numpage;
    uint32_t found[2], index[2], type[2], cbndx[2], matches[2], s2cr_ok[2];
};

/* `have` has a bit per register that really came from the unit. */
#define HAVE_CBAR 1u
#define HAVE_CBA2R 2u
#define HAVE_SCTLR 4u
#define HAVE_TCR 8u
#define HAVE_TTBR0 16u
#define HAVE_MAIR 32u
#define HAVE_ALL 63u
struct bank {
    uint32_t n, have, cbar, cba2r, sctlr, tcr, tcr2, mair0, mair1, fsr, fsynr0;
    uint64_t ttbr0, ttbr1, far;
};

struct ctx {
    const struct q1n1_payload_args *a;
    uint32_t word;                  /* the load32 destination: the runner wants it on the payload stack, and the context is */
    uint32_t loads, lines, cuts, dead[WINDOWS], type, failure, primary, have_conv, have_ram;
    const char *failed;             /* the first register a group could not read */
    struct map map;
    struct xhc xhc[2];
    struct smmu smmu;
    struct bank bank;
    uint64_t dcbaap, erdp, conv_lo, conv_hi, ram_lo, ram_hi;
};

enum { RD_OK, RD_RANGE, RD_ALIGN, RD_DEAD, RD_BUDGET, RD_FAULT, RD_BAD_OP, RD_NO_MAP, RD_NOT_IN_MAP, RD_NOT_RAM };
static const char reason_name[10][12] = {"", "RANGE", "MISALIGNED", "AFTER_FAULT", "BUDGET", "FAULT", "LOAD32", "NO_MAP",
                                         "NOT_IN_MAP", "TYPE_"};

/* ---- Text ---- */

OUT_OF_LINE void tx(struct pl_line *line, const char *text)
{
    pl_text(line, text);
}

OUT_OF_LINE void hx(const struct ctx *c, struct pl_line *line, uint64_t value)
{
    pl_hex(c->a, line, value);
}

OUT_OF_LINE void dec(struct pl_line *line, uint32_t value)
{
    char digits[10];
    unsigned n = 0;
    do {
        digits[n++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    while (n && line->len < Q1N1_PAYLOAD_LINE_MAX) line->buf[line->len++] = digits[--n];
    line->buf[line->len] = 0;
}

OUT_OF_LINE void num(const struct ctx *c, struct pl_line *line, uint64_t value)
{
    if (value < 10) dec(line, (uint32_t)value);
    else hx(c, line, value);
}

OUT_OF_LINE void emit(struct ctx *c, const struct pl_line *line)
{
    if (c->lines >= LINE_CAP) {
        c->cuts++;
        return;
    }
    c->lines++;
    pl_emit(c->a, line);
}

OUT_OF_LINE void say(struct ctx *c, const char *text)
{
    struct pl_line line;
    pl_begin(&line);
    tx(&line, PREFIX);
    tx(&line, text);
    emit(c, &line);
}

/* True when n more lines still leave `reserve` lines for what the groups after this one must print. */
OUT_OF_LINE int room(const struct ctx *c, unsigned n, unsigned reserve)
{
    return c->lines + n + reserve <= LINE_CAP;
}

/* One group's line(s), packed: PREFIX <head> <fields>. A field that does not fit starts the next line while the group has one
 * left (max_lines); otherwise it is dropped and counted, never cut. */
struct out {
    struct ctx *c;
    const char *head;
    struct pl_line line;
    unsigned lines, max_lines, filled;
};

OUT_OF_LINE void out_start(struct out *o)
{
    pl_begin(&o->line);
    tx(&o->line, PREFIX);
    tx(&o->line, o->head);
    o->filled = 0;
}

OUT_OF_LINE void out_begin(struct out *o, struct ctx *c, const char *head, unsigned max_lines)
{
    o->c = c;
    o->head = head;
    o->lines = 0;
    o->max_lines = max_lines;
    out_start(o);
}

/* Prints the line being packed, if it holds a field, and starts the next. */
OUT_OF_LINE void out_end(struct out *o)
{
    if (o->filled) {
        emit(o->c, &o->line);
        o->lines++;
    }
    out_start(o);
}

OUT_OF_LINE void out_put(struct out *o, const struct pl_line *item)
{
    if (o->line.len + 1 + item->len > Q1N1_PAYLOAD_LINE_MAX) {
        if (o->lines + 1 >= o->max_lines) {
            o->c->cuts++;
            return;
        }
        out_end(o);
        if (o->line.len + 1 + item->len > Q1N1_PAYLOAD_LINE_MAX) {
            o->c->cuts++;
            return;
        }
    }
    tx(&o->line, " ");
    tx(&o->line, item->buf);
    o->filled = 1;
}

OUT_OF_LINE void key(struct pl_line *item, const char *name)
{
    pl_begin(item);
    tx(item, name);
    tx(item, "=");
}

OUT_OF_LINE void kh(struct out *o, const char *name, uint64_t value)
{
    struct pl_line item;
    key(&item, name);
    hx(o->c, &item, value);
    out_put(o, &item);
}

OUT_OF_LINE void kn(struct out *o, const char *name, uint64_t value)
{
    struct pl_line item;
    key(&item, name);
    num(o->c, &item, value);
    out_put(o, &item);
}

OUT_OF_LINE void kt(struct out *o, const char *name, const char *text)
{
    struct pl_line item;
    key(&item, name);
    tx(&item, text);
    out_put(o, &item);
}

OUT_OF_LINE void kw(struct out *o, const char *word)
{
    struct pl_line item;
    pl_begin(&item);
    tx(&item, word);
    out_put(o, &item);
}

/* A whole line that is one finding: <head> <name>=<text>. */
OUT_OF_LINE void note(struct ctx *c, const char *head, const char *name, const char *text)
{
    struct out o;
    out_begin(&o, c, head, 1);
    kt(&o, name, text);
    out_end(&o);
}

/* FAULT (a guarded load aborted) or REFUSED=<why>. */
OUT_OF_LINE void fail_item(struct out *o, int rc)
{
    struct pl_line item;
    pl_begin(&item);
    if (rc != RD_FAULT) tx(&item, "REFUSED=");
    tx(&item, reason_name[rc]);
    if (rc == RD_NOT_RAM) hx(o->c, &item, o->c->type);
    out_put(o, &item);
}

/* The first register a group could not read, so that the last line names what failed. */
OUT_OF_LINE void out_failure(struct out *o)
{
    fail_item(o, o->c->failure);
    kt(o, "AT", o->c->failed ? o->c->failed : "?");
}

/* ---- Reads: every access this payload makes goes through load() ---- */

OUT_OF_LINE int load(struct ctx *c, uint64_t phys, uint32_t *value)
{
    int32_t err;
    *value = 0;
    if (c->loads >= LOAD_CAP) return RD_BUDGET;
    c->loads++;
    err = c->a->ops.load32(phys, &c->word);
    if (err == Q1N1_PAYLOAD_LOAD_E_FAULT) return RD_FAULT;
    if (err) return RD_BAD_OP;
    *value = c->word;
    return RD_OK;
}

/* A register of a window. The first abort ends all reads of that window: whatever stopped one load would stop the next. */
OUT_OF_LINE int rd32(struct ctx *c, unsigned win, uint64_t off, uint32_t *value, const char *name)
{
    int rc;
    *value = 0;
    if (off & 3) {
        rc = RD_ALIGN;
    } else if (off >= windows[win].size || windows[win].size - off < 4) {
        rc = RD_RANGE;
    } else if (c->dead[win]) {
        rc = RD_DEAD;
    } else {
        rc = load(c, windows[win].base + off, value);
        if (rc == RD_FAULT || rc == RD_BAD_OP) c->dead[win] = 1;
    }
    if (rc && !c->failed) {
        c->failed = name;
        c->failure = (uint32_t)rc;
    }
    return rc;
}

OUT_OF_LINE int rd64(struct ctx *c, unsigned win, uint64_t off, uint64_t *value, const char *name)
{
    uint32_t lo = 0, hi = 0;
    int rc = rd32(c, win, off, &lo, name);
    if (!rc) rc = rd32(c, win, off + 4, &hi, name);
    *value = rc ? 0 : (uint64_t)lo | (uint64_t)hi << 32;
    return rc;
}

/* ---- The UEFI memory map ---- */

static inline uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static inline uint64_t le64(const uint8_t *p)
{
    return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32;
}

/* EFI_MEMORY_DESCRIPTOR: Type u32 at 0, PhysicalStart u64 at 8, NumberOfPages u64 at 24. The map is the runner's own memory
 * (what ExitBootServices was given), read in place. */
static inline const uint8_t *descriptor(const struct ctx *c, uint32_t i)
{
    return (const uint8_t *)(uintptr_t)(c->map.base + (uint64_t)i * c->map.stride);
}

/* Loader code and data, boot services code and data, runtime code and data, conventional, ACPI reclaim. Reserved (0),
 * unusable (8), ACPI NVS (10), MMIO (11, 12), persistent (13) and anything unlisted are not. */
static inline int type_is_ram(uint32_t type)
{
    return (type >= 1 && type <= 7) || type == 9;
}

/* A map whose size, stride or entries make no sense is no map, and then every RAM load is refused. The stride must be a
 * multiple of 8 so that every field is naturally aligned whatever the compiler makes of the reads. */
OUT_OF_LINE void map_init(struct ctx *c)
{
    const struct q1n1_payload_args *a = c->a;
    uint64_t entries;
    c->map.ok = 0;
    c->map.count = 0;
    if (!a->map_base || (a->map_base & 7) || a->map_stride < 40 || a->map_stride > MAP_STRIDE_MAX || (a->map_stride & 7) ||
        !a->map_size || a->map_size % a->map_stride || a->map_base + a->map_size < a->map_base)
        return;
    entries = a->map_size / a->map_stride;
    if (entries > MAP_DESCRIPTORS_MAX) return;
    c->map.base = a->map_base;
    c->map.stride = a->map_stride;
    c->map.count = (uint32_t)entries;
    for (uint32_t i = 0; i < c->map.count; i++) {
        const uint8_t *d = descriptor(c, i);
        uint64_t pages = le64(d + 24), start = le64(d + 8);
        if (pages >= (UINT64_C(1) << 40) || start + pages * 4096u < start) return;     /* the map contradicts itself */
    }
    c->map.ok = 1;
}

/* 0 when the four bytes at addr are usable RAM: no descriptor of another kind covers the first or the last of them and a
 * descriptor of RAM does. Else the reason, and the offending type in c->type. */
OUT_OF_LINE int map_check(struct ctx *c, uint64_t addr)
{
    if (!c->map.ok) return RD_NO_MAP;
    if (addr + 3 < addr) return RD_NOT_IN_MAP;
    for (unsigned end = 0; end < 2; end++) {
        uint64_t at = addr + 3u * end;
        int in_ram = 0;
        for (uint32_t i = 0; i < c->map.count; i++) {
            const uint8_t *d = descriptor(c, i);
            uint64_t start = le64(d + 8);
            if (at < start || at - start >= le64(d + 24) * 4096u) continue;
            if (!type_is_ram(le32(d))) {
                c->type = le32(d);
                return RD_NOT_RAM;
            }
            in_ram = 1;
        }
        if (!in_ram) return RD_NOT_IN_MAP;
    }
    return RD_OK;
}

/* The ends of the usable RAM the map lists and of its largest conventional region, which the walk probes. */
OUT_OF_LINE void map_extents(struct ctx *c)
{
    uint64_t best = 0;
    c->have_conv = c->have_ram = 0;
    if (!c->map.ok) return;
    for (uint32_t i = 0; i < c->map.count; i++) {
        const uint8_t *d = descriptor(c, i);
        uint64_t start = le64(d + 8), pages = le64(d + 24), last = start + pages * 4096u - 4096u;
        if (!pages || !type_is_ram(le32(d))) continue;
        if (!c->have_ram || start < c->ram_lo) c->ram_lo = start;
        if (!c->have_ram || last > c->ram_hi) c->ram_hi = last;
        c->have_ram = 1;
        if (le32(d) == 7 && pages > best) {
            best = pages;
            c->conv_lo = start;
            c->conv_hi = last;
            c->have_conv = 1;
        }
    }
}

/* RAM: a 4-byte aligned word, loaded only after the map says it is usable RAM. */
OUT_OF_LINE int ram32(struct ctx *c, uint64_t addr, uint32_t *value)
{
    int rc;
    *value = 0;
    if (addr & 3) return RD_ALIGN;
    rc = map_check(c, addr);
    return rc ? rc : load(c, addr, value);
}

OUT_OF_LINE int ram64(struct ctx *c, uint64_t addr, uint64_t *value)
{
    uint32_t lo = 0, hi = 0;
    int rc = ram32(c, addr, &lo);
    if (!rc) rc = ram32(c, addr + 4, &hi);
    *value = rc ? 0 : (uint64_t)lo | (uint64_t)hi << 32;
    return rc;
}

OUT_OF_LINE int read_words(struct ctx *c, uint64_t addr, uint32_t *words, unsigned n)
{
    for (unsigned i = 0; i < n; i++) {
        int rc = ram32(c, addr + 4u * i, &words[i]);
        if (rc) return rc;
    }
    return RD_OK;
}

/* ---- Decoders ---- */

/* xHCI 1.2 USBSTS: HCH 0, HSE 2, EINT 3, PCD 4, SSS 8, RSS 9, SRE 10, CNR 11, HCE 12. */
static const uint8_t sts_bit[9] = {0, 2, 3, 4, 8, 9, 10, 11, 12};
static const char sts_name[9][5] = {"HCH", "HSE", "EINT", "PCD", "SSS", "RSS", "SRE", "CNR", "HCE"};
/* PORTSC.PLS: 0 U0 .. 3 U3, 4 disabled, 5 RxDetect, 6 inactive, 7 polling, 8 recovery, 9 hot reset, 10 compliance, 11 test
 * mode, 15 resume. Port speed IDs (default protocol speed IDs): 1 full, 2 low, 3 high, 4 SuperSpeed, 5 SuperSpeedPlus. */
static const char pls_name[16][7] = {"U0", "U1", "U2", "U3", "DIS", "RXDET", "INACT", "POLL", "RECOV", "HOTRST", "COMPL",
                                     "TEST", "RSVD", "RSVD", "RSVD", "RESUME"};
static const char speed_name[6][4] = {"", "FS", "LS", "HS", "SS", "SSP"};
/* Event TRB types 32 to 39. */
static const char trb_name[8][7] = {"XFER", "CMD", "PSC", "BWR", "DB", "HC", "DEVNOT", "MFWRAP"};

/* KEY=0XRAW:TOKEN.TOKEN */
OUT_OF_LINE void dot(struct pl_line *item, unsigned *tokens, const char *text)
{
    tx(item, *tokens ? "." : ":");
    tx(item, text);
    (*tokens)++;
}

OUT_OF_LINE void field_sts(struct out *o, const char *name, uint32_t sts)
{
    struct pl_line item;
    unsigned tokens = 0;
    uint32_t known = 0;
    key(&item, name);
    hx(o->c, &item, sts);
    for (unsigned i = 0; i < 9; i++) {
        known |= 1u << sts_bit[i];
        if (sts >> sts_bit[i] & 1) dot(&item, &tokens, sts_name[i]);
    }
    if (!sts) dot(&item, &tokens, "NONE");
    if (sts & ~known) {
        dot(&item, &tokens, "OTHER_");
        hx(o->c, &item, sts & ~known);
    }
    out_put(o, &item);
}

OUT_OF_LINE void field_port(struct out *o, const char *name, uint32_t sc)
{
    struct pl_line item;
    unsigned tokens = 0, speed = sc >> 10 & 15;
    key(&item, name);
    hx(o->c, &item, sc);
    if (sc & 1) dot(&item, &tokens, "CCS");
    if (sc >> 1 & 1) dot(&item, &tokens, "PED");
    dot(&item, &tokens, pls_name[sc >> 5 & 15]);
    if (speed >= 1 && speed <= 5) {
        dot(&item, &tokens, speed_name[speed]);
    } else if (speed) {
        dot(&item, &tokens, "SPD_");
        num(o->c, &item, speed);
    }
    out_put(o, &item);
}

/* ---- Group U0: xHC registers of both controllers, then DWC3 ---- */

/* A controller answers like an xHC: CAPLENGTH a whole number of dwords past the 0x1c capability registers, HCIVERSION 0.90 to
 * 1.xx, at least one slot and one port. All ones is what a bus error or an absent block returns, never a controller. */
OUT_OF_LINE void read_xhc(struct ctx *c, unsigned i)
{
    struct xhc *x = &c->xhc[i];
    unsigned win = WIN_U0 + i;
    uint32_t caplen, version;
    c->failed = 0;
    x->state = XS_FAILED;
    x->idle = x->nports = 0;
    if (rd32(c, win, CAP_CAP0, &x->cap0, "CAP0")) return;
    if (!x->cap0 || x->cap0 == 0xffffffffu) {
        x->state = x->cap0 ? XS_ALL_ONES : XS_ZERO;
        return;
    }
    caplen = x->cap0 & 0xff;
    version = x->cap0 >> 16;
    if (rd32(c, win, CAP_HCSPARAMS1, &x->hcs1, "HCSPARAMS1") || rd32(c, win, CAP_HCCPARAMS1, &x->hcc1, "HCCPARAMS1") ||
        rd32(c, win, CAP_RTSOFF, &x->rtsoff, "RTSOFF"))
        return;
    if (caplen < 0x1c || (caplen & 3) || version < 0x90 || version > 0x1ff || !(x->hcs1 & 0xff) || !(x->hcs1 >> 24)) {
        x->state = XS_NOT_XHCI;
        return;
    }
    if (rd32(c, win, caplen + OP_USBCMD, &x->cmd, "USBCMD") || rd32(c, win, caplen + OP_USBSTS, &x->sts, "USBSTS") ||
        rd64(c, win, caplen + OP_CRCR, &x->crcr, "CRCR") || rd64(c, win, caplen + OP_DCBAAP, &x->dcbaap, "DCBAAP") ||
        rd32(c, win, caplen + OP_CONFIG, &x->cfg, "CONFIG"))
        return;
    if (x->sts == 0xffffffffu) {
        x->state = XS_ALL_ONES;
        return;
    }
    x->nports = (x->hcs1 >> 24) < 2 ? (x->hcs1 >> 24) : 2;
    for (unsigned p = 0; p < x->nports; p++)
        if (rd32(c, win, caplen + OP_PORTSC(p + 1), &x->portsc[p], p ? "PORTSC2" : "PORTSC1")) return;
    x->state = XS_OK;
    x->idle = !x->dcbaap && !(x->portsc[0] & 1) && !(x->nports > 1 && (x->portsc[1] & 1));
}

/* U<i>: all in one line when nothing is connected and no DCBAA is set (IDLE); else the registers in one line and the ports in
 * the next (`split`), or all in one line when the budget has no second line to give; a field that does not fit is dropped. */
OUT_OF_LINE void print_xhc(struct ctx *c, unsigned i, int split)
{
    const struct xhc *x = &c->xhc[i];
    const char *head = i ? "U1" : "U0";
    struct out o;
    out_begin(&o, c, head, 1);
    if (x->state != XS_OK) {
        if (x->state == XS_ALL_ONES || x->state == XS_ZERO) {
            kw(&o, "UNREADABLE");
            kt(&o, "WHY", x->state == XS_ZERO ? "ZERO" : "ALL_ONES");
            kh(&o, "CAP0", x->cap0);
        } else if (x->state == XS_NOT_XHCI) {
            kw(&o, "NOT_XHCI");
            kh(&o, "CAP0", x->cap0);
            kh(&o, "HCS1", x->hcs1);
        } else {
            out_failure(&o);
        }
        out_end(&o);
        return;
    }
    if (x->idle) kw(&o, "IDLE");
    kh(&o, "CAPL", x->cap0 & 0xff);
    kh(&o, "CMD", x->cmd);
    field_sts(&o, "STS", x->sts);
    if (!x->idle) kh(&o, "CRCR", x->crcr);
    kh(&o, "DCBAAP", x->dcbaap);
    if (!x->idle) kh(&o, "CFG", x->cfg);
    if (split && !x->idle) {
        out_end(&o);
        out_begin(&o, c, head, 1);
    }
    field_port(&o, "P1", x->portsc[0]);
    if (x->nports > 1) field_port(&o, "P2", x->portsc[1]);
    out_end(&o);
}

/* DWC3 of usb_1_ss0: the ID first, and only a block that answers with a plausible one is read further. */
OUT_OF_LINE void group_dwc3(struct ctx *c)
{
    struct out o;
    uint32_t id = 0, gctl = 0, gsts = 0, lo = 0, hi = 0, ltssm = 0;
    c->failed = 0;
    out_begin(&o, c, "DWC3", 1);
    if (c->xhc[0].state != XS_OK) {
        kt(&o, "SKIPPED", "U0_NOT_READ");
    } else if (rd32(c, WIN_U0, DWC3_GSNPSID, &id, "GSNPSID")) {
        out_failure(&o);
    } else if (id == 0 || id == 0xffffffffu) {
        kw(&o, "UNREADABLE");
        kh(&o, "ID", id);
    } else if (rd32(c, WIN_U0, DWC3_GCTL, &gctl, "GCTL") || rd32(c, WIN_U0, DWC3_GSTS, &gsts, "GSTS") ||
               rd32(c, WIN_U0, DWC3_GBUSERRADDR0, &lo, "GBUSERRADDR0") || rd32(c, WIN_U0, DWC3_GBUSERRADDR1, &hi, "GBUSERRADDR1") ||
               rd32(c, WIN_U0, DWC3_GDBGLTSSM, &ltssm, "GDBGLTSSM")) {
        kh(&o, "ID", id);
        out_failure(&o);
    } else {
        kh(&o, "ID", id);
        kh(&o, "GCTL", gctl);
        kh(&o, "GSTS", gsts);
        kh(&o, "BERR", (uint64_t)hi << 32 | lo);
        kh(&o, "LTSSM", ltssm);
    }
    out_end(&o);
}

/* What the groups after one print at least, so that an optional line asks room() first: SMMU 3, RINGS 4 (NEXT, RINGS, TRB, one
 * slot), CB 4, WALK 6 (NEXT, four probes, the summary). Only a second bank may cut the walk to two probes. */
#define RESERVE_AFTER_U0 17u
#define RESERVE_AFTER_SMMU 14u
#define RESERVE_AFTER_RINGS 10u
#define RESERVE_AFTER_CB 4u

OUT_OF_LINE void group_u0(struct ctx *c)
{
    say(c, "NEXT U0");
    read_xhc(c, 0);
    print_xhc(c, 0, 1);
    read_xhc(c, 1);
    print_xhc(c, 1, room(c, 3, RESERVE_AFTER_U0));      /* U1's two lines and the DWC3 line */
    /* The stick is on the first controller that is busy; with none busy U0 stays the one the other groups follow. */
    c->primary = c->xhc[0].state == XS_OK && !c->xhc[0].idle ? 0 : c->xhc[1].state == XS_OK && !c->xhc[1].idle ? 1 : 0;
    group_dwc3(c);
}

/* ---- Group SMMU: global space 0 and the stream match registers ---- */

OUT_OF_LINE void read_smmu_global(struct ctx *c)
{
    struct smmu *s = &c->smmu;
    c->failed = 0;
    s->ok = 0;
    if (rd32(c, WIN_SMMU, SMMU_SCR0, &s->scr0, "SCR0") || rd32(c, WIN_SMMU, SMMU_ID0, &s->id0, "ID0")) return;
    if (s->id0 == 0 || s->id0 == 0xffffffffu || s->scr0 == 0xffffffffu) return;
    if (rd32(c, WIN_SMMU, SMMU_ID1, &s->id1, "ID1") || rd32(c, WIN_SMMU, SMMU_ID2, &s->id2, "ID2") ||
        rd32(c, WIN_SMMU, SMMU_GFSR, &s->gfsr, "GFSR"))
        return;
    s->ok = 1;
}

/* The stream match rule of the S0 survey (sp11-stk-rules.c): an entry counts when it is valid and ((stream ^ id) & ~mask) is
 * zero over the implemented stream id bits; the lowest match wins, the others are counted. The survey also reads extended
 * stream ids (the valid bit moves to S2CR); sCR0.EXIDENABLE was clear on the unit (S0, OBSERVED), so this payload refuses
 * that mode instead of reading S2CR for it. */
OUT_OF_LINE void scan_streams(struct ctx *c)
{
    struct smmu *s = &c->smmu;
    uint32_t sidb = s->id0 >> 9 & 15, implemented = sidb >= 16 ? 0xffffu : (1u << sidb) - 1u;
    unsigned limit = s->numsmrg < SMR_SCANNED_MAX ? s->numsmrg : SMR_SCANNED_MAX;
    c->failed = 0;
    s->scanned = 0;
    s->exid = s->scr0 >> 3 & 1;
    for (unsigned k = 0; k < 2; k++) s->found[k] = s->matches[k] = s->index[k] = s->s2cr_ok[k] = s->type[k] = s->cbndx[k] = 0;
    if (s->exid) return;
    for (unsigned n = 0; n < limit; n++) {
        uint32_t smr;
        if (rd32(c, WIN_SMMU, SMMU_SMR(n), &smr, "SMR")) return;
        if (!(smr >> 31)) continue;
        for (unsigned k = 0; k < 2; k++) {
            if ((stream_id[k] ^ (smr & 0xffffu)) & ~(smr >> 16 & 0xffffu) & implemented) continue;
            if (!s->matches[k]++) {
                s->found[k] = 1;
                s->index[k] = n;
            }
        }
    }
    for (unsigned k = 0; k < 2; k++) {
        uint32_t s2cr;
        if (!s->found[k]) continue;
        if (rd32(c, WIN_SMMU, SMMU_S2CR(s->index[k]), &s2cr, "S2CR")) return;
        s->s2cr_ok[k] = 1;
        s->type[k] = s2cr >> 16 & 3;
        s->cbndx[k] = s2cr & 0xff;
    }
    s->scanned = 1;
}

/* Where context bank n's page is: after the global pages, NUMPAGE = 2^(NUMPAGENDXB+1) of them, each 4 KiB or 64 KiB. */
OUT_OF_LINE uint64_t bank_page(const struct smmu *s, uint32_t n)
{
    return (uint64_t)(s->numpage + n) * s->pagesize;
}

static const char s2cr_type_name[4][7] = {"TRANS", "BYPASS", "FAULT", "RSVD"};
static const char cbar_type_name[4][9] = {"S2", "S1_S2BYP", "S1_S2FLT", "NESTED"};
static const char tg0_name[4][5] = {"4K", "64K", "16K", "RSVD"};

/* S<stream id>=SMR<n>.<TYPE>.CB<n>: the first stream match register that matches, what its S2CR does and, for a translating
 * stream, the context bank (.BAD when it is not below NUMCB). */
OUT_OF_LINE void field_stream(struct out *o, unsigned k)
{
    const struct smmu *s = &o->c->smmu;
    struct pl_line item, id;
    pl_begin(&id);
    hx(o->c, &id, stream_id[k]);
    pl_begin(&item);
    tx(&item, "S");
    tx(&item, id.buf + 2);
    tx(&item, "=");
    if (!s->found[k]) {
        tx(&item, "NOMATCH");
    } else {
        tx(&item, "SMR");
        dec(&item, s->index[k]);
        if (!s->s2cr_ok[k]) {
            tx(&item, ".S2CR_UNREAD");
        } else {
            tx(&item, ".");
            tx(&item, s2cr_type_name[s->type[k]]);
            if (s->type[k] == 0) {
                tx(&item, ".CB");
                dec(&item, s->cbndx[k]);
                if (s->cbndx[k] >= s->numcb) tx(&item, ".BAD");
            }
        }
        if (s->matches[k] > 1) {
            tx(&item, ".MULTI");
            dec(&item, s->matches[k]);
        }
    }
    out_put(o, &item);
}

OUT_OF_LINE void group_smmu(struct ctx *c)
{
    struct smmu *s = &c->smmu;
    struct out o;
    say(c, "NEXT SMMU");
    read_smmu_global(c);
    out_begin(&o, c, "SMMU", 1);
    if (!s->ok) {
        if (c->failed) {
            out_failure(&o);
        } else {
            kw(&o, "UNREADABLE");
            kh(&o, "ID0", s->id0);
            kh(&o, "SCR0", s->scr0);
        }
        out_end(&o);
        return;
    }
    s->numsmrg = s->id0 & 0xff;
    s->numcb = s->id1 & 0xff;
    s->pagesize = s->id1 >> 31 ? 65536u : 4096u;
    s->numpage = 2u << (s->id1 >> 28 & 7);
    kh(&o, "ID0", s->id0);
    kh(&o, "ID1", s->id1);
    kh(&o, "ID2", s->id2);
    kh(&o, "SCR0", s->scr0);
    kh(&o, "GFSR", s->gfsr);
    out_end(&o);

    /* The fault address and syndromes mean something only when the global fault status says a fault was recorded. */
    if (s->gfsr && room(c, 1, RESERVE_AFTER_SMMU + 1)) {
        uint64_t gfar;
        uint32_t syn[3];
        c->failed = 0;
        out_begin(&o, c, "SMMU", 1);
        if (rd64(c, WIN_SMMU, SMMU_GFAR, &gfar, "GFAR") || rd32(c, WIN_SMMU, SMMU_GFSYNR0, &syn[0], "GFSYNR0") ||
            rd32(c, WIN_SMMU, SMMU_GFSYNR0 + 4, &syn[1], "GFSYNR1") || rd32(c, WIN_SMMU, SMMU_GFSYNR0 + 8, &syn[2], "GFSYNR2")) {
            out_failure(&o);
        } else {
            kh(&o, "GFAR", gfar);
            kh(&o, "GFSYNR0", syn[0]);
            kh(&o, "GFSYNR1", syn[1]);
            kh(&o, "GFSYNR2", syn[2]);
        }
        out_end(&o);
    }

    scan_streams(c);
    out_begin(&o, c, "SMMU", room(c, 1, RESERVE_AFTER_SMMU) ? 2 : 1);      /* two matches of one stream make a long token */
    kh(&o, "SMRG", s->numsmrg);
    kh(&o, "NCB", s->numcb);
    kh(&o, "CBBASE", windows[WIN_SMMU].base + bank_page(s, 0));
    if (s->exid) {
        kt(&o, "STREAMS", "UNSUPPORTED_EXID");
    } else if (!s->scanned) {
        out_failure(&o);
    } else {
        field_stream(&o, 0);
        field_stream(&o, 1);
    }
    out_end(&o);
}

/* ---- Group RINGS: the firmware's event ring and device contexts ---- */

/* <type>.<completion code>.<slot id>.<cycle bit> of an event TRB. */
OUT_OF_LINE void field_trb(struct out *o, const char *name, const uint32_t t[4])
{
    struct pl_line item;
    unsigned type = t[3] >> 10 & 0x3f;
    key(&item, name);
    if (type >= 32 && type <= 39) tx(&item, trb_name[type - 32]);
    else num(o->c, &item, type);
    tx(&item, ".");
    num(o->c, &item, t[2] >> 24);
    tx(&item, ".");
    num(o->c, &item, t[3] >> 24);
    tx(&item, ".");
    dec(&item, t[3] & 1);
    out_put(o, &item);
}

/* One device context of the firmware: the slot context, then each endpoint context that is not disabled. Contexts are 32 or 64
 * bytes as HCCPARAMS1.CSZ says, and the endpoint context of device context index n sits n contexts in. */
OUT_OF_LINE void slot_line(struct ctx *c, unsigned ctrl, unsigned id, uint64_t entry, uint32_t more)
{
    const struct xhc *x = &c->xhc[ctrl];
    uint32_t ctxsize = x->hcc1 >> 2 & 1 ? 64u : 32u, head[4];
    char name[5] = {'U', (char)('0' + ctrl), 'S', (char)('0' + id), 0};
    struct out o;
    int rc = (entry & 0x3f) ? RD_ALIGN : read_words(c, entry, head, 4);     /* contexts are 64-byte aligned */
    out_begin(&o, c, name, 1);
    if (rc) {
        kh(&o, "CTX", entry);
        fail_item(&o, rc);
        out_end(&o);
        return;
    }
    kn(&o, "RT", head[0] & 0xfffff);
    kn(&o, "RP", head[1] >> 16 & 0xff);
    kn(&o, "SPD", head[0] >> 20 & 15);
    kn(&o, "HUB", head[0] >> 26 & 1);
    kn(&o, "ST", head[3] >> 27);
    kn(&o, "AD", head[3] & 0xff);
    for (uint32_t dci = 1; dci <= head[0] >> 27; dci++) {       /* Context Entries is 5 bits: at most 31 */
        uint32_t ep[2];
        struct pl_line item;
        rc = read_words(c, entry + (uint64_t)dci * ctxsize, ep, 2);
        if (rc) {
            fail_item(&o, rc);
            kt(&o, "AT", "EP");
            break;
        }
        if (!(ep[0] & 7)) continue;
        pl_begin(&item);
        tx(&item, "EP");
        dec(&item, dci);
        tx(&item, "=");
        num(c, &item, ep[0] & 7);
        tx(&item, ".");
        num(c, &item, ep[1] >> 3 & 7);
        tx(&item, ".");
        hx(c, &item, ep[1] >> 16);
        out_put(&o, &item);
    }
    if (more) kn(&o, "MORE", more);
    out_end(&o);
}

/* The device context base address array of one controller: entries 1 to 8, the non-zero ones decoded. The first slot line is
 * mandatory for the controller the stick is on; the others take whatever lines the later groups can spare. */
OUT_OF_LINE void slots_of(struct ctx *c, unsigned ctrl, int mandatory)
{
    const struct xhc *x = &c->xhc[ctrl];
    uint64_t entry[SLOTS_SCANNED + 1];
    unsigned ids[SLOTS_SCANNED], nonzero = 0, show, scan = x->cfg & 0xff ? x->cfg & 0xff : x->hcs1 & 0xff;
    char name[5] = {'U', (char)('0' + ctrl), 0, 0, 0};
    struct out o;
    if (x->state != XS_OK) return;
    if (scan > SLOTS_SCANNED) scan = SLOTS_SCANNED;
    if (!x->dcbaap || (x->dcbaap & 0x3f)) {
        if (mandatory) note(c, name, "SLOTS", x->dcbaap ? "DCBAAP_MISALIGNED" : "NO_DCBAAP");
        return;
    }
    for (unsigned id = 1; id <= scan; id++) {
        int rc = ram64(c, x->dcbaap + 8u * id, &entry[id]);
        if (rc) {
            out_begin(&o, c, name, 1);
            kt(&o, "SLOTS", "UNREAD");
            fail_item(&o, rc);
            out_end(&o);
            return;
        }
        if (entry[id]) ids[nonzero++] = id;
    }
    if (!nonzero) {
        if (mandatory) note(c, name, "SLOTS", "NONE");
        return;
    }
    show = mandatory ? 1u : 0u;
    while (show < nonzero && show < SLOT_LINES_MAX && room(c, show + 1, RESERVE_AFTER_RINGS)) show++;
    if (show < nonzero) c->cuts++;
    for (unsigned k = 0; k < show; k++) slot_line(c, ctrl, ids[k], entry[ids[k]], k + 1 == show ? nonzero - show : 0);
}

/* The last three event TRBs before ERDP and the one at it (the firmware's driver handled those before it stopped). Only the
 * first segment is read and the index wraps inside it. ERDP bits 3:0 are the segment index and Event Handler Busy, not address. */
OUT_OF_LINE void ring_trbs(struct ctx *c, uint64_t seg, uint32_t size, uint64_t erdp)
{
    static const char tag[4][3] = {"AT", "M1", "M2", "M3"};
    uint32_t trb[4][4], here = (uint32_t)((erdp - seg) / 16u);
    int rc = RD_OK;
    struct out o;
    for (unsigned k = 0; k < 4 && !rc; k++) rc = read_words(c, seg + (uint64_t)(k ? (here + size - k) % size : here) * 16u, trb[k], 4);
    out_begin(&o, c, "TRB", 1);
    if (rc) {
        fail_item(&o, rc);
    } else {
        for (unsigned k = 1; k < 4; k++) field_trb(&o, tag[k], trb[k]);
        field_trb(&o, tag[0], trb[0]);
    }
    out_end(&o);
}

OUT_OF_LINE void group_rings(struct ctx *c)
{
    const struct xhc *x = &c->xhc[c->primary];
    unsigned win = WIN_U0 + c->primary;
    uint64_t rt = x->rtsoff & ~0x1fu, erstba = 0, erdp = 0, seg = 0;
    uint32_t erstsz = 0, entry[4] = {0, 0, 0, 0}, size = 0;
    int rc = RD_OK, seg_ok = 0, have_erst;
    struct out o;
    say(c, "NEXT RINGS");
    if (x->state != XS_OK) {
        note(c, "RINGS", "SKIPPED", "NO_XHC");
        return;
    }
    c->dcbaap = x->dcbaap;
    c->failed = 0;
    out_begin(&o, c, "RINGS", 1);
    kn(&o, "CSZ", x->hcc1 >> 2 & 1);
    if (rd32(c, win, rt + RT_ERSTSZ, &erstsz, "ERSTSZ") || rd64(c, win, rt + RT_ERSTBA, &erstba, "ERSTBA") ||
        rd64(c, win, rt + RT_ERDP, &erdp, "ERDP")) {
        out_failure(&o);
        out_end(&o);
        return;
    }
    c->erdp = erdp;
    kh(&o, "ERSTSZ", erstsz & 0xffff);
    kh(&o, "ERSTBA", erstba);
    kh(&o, "ERDP", erdp);
    /* The first segment table entry: base in dwords 0 and 1 (bits 63:6), size in TRBs in dword 2 (15:0). */
    have_erst = (erstba & ~UINT64_C(0x3f)) && (erstsz & 0xffff);
    if (have_erst) rc = read_words(c, erstba & ~UINT64_C(0x3f), entry, 4);
    if (!have_erst) {
        kt(&o, "SEG0", "NO_ERST");
    } else if (rc) {
        fail_item(&o, rc);
        kt(&o, "AT", "ERST");
    } else {
        struct pl_line item;
        seg = ((uint64_t)entry[0] | (uint64_t)entry[1] << 32) & ~UINT64_C(0x3f);
        size = entry[2] & 0xffff;
        seg_ok = size >= 16 && size <= 4096;                    /* xHCI 6.5: a segment has 16 to 4096 TRBs */
        key(&item, "SEG0");
        if (seg_ok) {
            hx(c, &item, seg);
            tx(&item, "/");
        } else {
            tx(&item, "BAD_SIZE/");
        }
        hx(c, &item, size);
        out_put(&o, &item);
    }
    out_end(&o);

    if (seg_ok && (erdp & ~UINT64_C(0xf)) >= seg && (erdp & ~UINT64_C(0xf)) - seg < (uint64_t)size * 16u)
        ring_trbs(c, seg, size, erdp & ~UINT64_C(0xf));
    else
        note(c, "TRB", "SKIPPED", seg_ok ? "ERDP_NOT_IN_SEG0" : "NO_SEG0");

    slots_of(c, c->primary, 1);
    if (c->xhc[1 - c->primary].dcbaap) slots_of(c, 1 - c->primary, 0);
}

/* ---- Group CB: the context bank(s) the USB streams match ---- */

/* The translating banks, the primary controller's stream first: not bypass, not fault, and below NUMCB. */
OUT_OF_LINE unsigned pick_banks(const struct ctx *c, uint32_t banks[2])
{
    const struct smmu *s = &c->smmu;
    unsigned n = 0;
    for (unsigned i = 0; i < 2; i++) {
        unsigned k = i ? 1 - c->primary : c->primary;
        if (!s->found[k] || !s->s2cr_ok[k] || s->type[k] != 0 || s->cbndx[k] >= s->numcb) continue;
        if (n && banks[0] == s->cbndx[k]) continue;
        banks[n++] = s->cbndx[k];
    }
    return n;
}

/* The bank's registers in three lines: type and format; control; tables, memory attributes and the fault status. */
OUT_OF_LINE void read_bank(struct ctx *c, struct bank *b, uint32_t n)
{
    const struct smmu *s = &c->smmu;
    uint64_t gr1 = s->pagesize, page = bank_page(s, n);
    struct pl_line head, next;
    struct out o;
    int ok;
    for (size_t i = 0; i < sizeof *b; i++) ((volatile uint8_t *)b)[i] = 0;
    b->n = n;
    pl_begin(&head);
    tx(&head, "CB");
    dec(&head, n);
    pl_begin(&next);
    tx(&next, PREFIX "NEXT ");
    tx(&next, head.buf);
    emit(c, &next);

    c->failed = 0;
    ok = !rd32(c, WIN_SMMU, gr1 + GR1_CBAR(n), &b->cbar, "CBAR") && !rd32(c, WIN_SMMU, gr1 + GR1_CBA2R(n), &b->cba2r, "CBA2R");
    out_begin(&o, c, head.buf, 1);
    if (ok) {
        b->have = HAVE_CBAR | HAVE_CBA2R;
        kh(&o, "CBAR", b->cbar);
        kt(&o, "TYPE", cbar_type_name[b->cbar >> 16 & 3]);
        kh(&o, "CBA2R", b->cba2r);
        kn(&o, "VA64", b->cba2r & 1);
    } else {
        out_failure(&o);
    }
    out_end(&o);
    if (!ok) return;

    c->failed = 0;
    ok = !rd32(c, WIN_SMMU, page + CB_SCTLR, &b->sctlr, "SCTLR") && !rd32(c, WIN_SMMU, page + CB_TCR, &b->tcr, "TCR") &&
         !rd32(c, WIN_SMMU, page + CB_TCR2, &b->tcr2, "TCR2");
    out_begin(&o, c, head.buf, 1);
    if (ok) {
        b->have |= HAVE_SCTLR | HAVE_TCR;
        kh(&o, "SCTLR", b->sctlr);
        kn(&o, "M", b->sctlr & 1);
        kh(&o, "TCR", b->tcr);
        kn(&o, "T0SZ", b->tcr & 0x3f);
        kt(&o, "TG0", tg0_name[b->tcr >> 14 & 3]);
        kn(&o, "EPD0", b->tcr >> 7 & 1);
        kh(&o, "TCR2", b->tcr2);
    } else {
        out_failure(&o);
    }
    out_end(&o);
    if (!ok) return;

    c->failed = 0;
    ok = !rd64(c, WIN_SMMU, page + CB_TTBR0, &b->ttbr0, "TTBR0");
    if (ok) b->have |= HAVE_TTBR0;
    ok = ok && !rd32(c, WIN_SMMU, page + CB_MAIR0, &b->mair0, "MAIR0") && !rd32(c, WIN_SMMU, page + CB_MAIR1, &b->mair1, "MAIR1");
    if (ok) b->have |= HAVE_MAIR;
    ok = ok && !rd64(c, WIN_SMMU, page + CB_TTBR1, &b->ttbr1, "TTBR1") && !rd32(c, WIN_SMMU, page + CB_FSR, &b->fsr, "FSR");
    /* The fault address and syndrome mean something only when the fault status says a fault was recorded. */
    if (ok && b->fsr) ok = !rd64(c, WIN_SMMU, page + CB_FAR, &b->far, "FAR") && !rd32(c, WIN_SMMU, page + CB_FSYNR0, &b->fsynr0, "FSYNR0");
    out_begin(&o, c, head.buf, room(c, 2, 6) ? 2 : 1);      /* the second line only when the walk keeps its six */
    if (b->have & HAVE_TTBR0) {
        kh(&o, "TTBR0", b->ttbr0);
        kh(&o, "ASID", b->ttbr0 >> 48);
        if (b->ttbr0 >> 48) kh(&o, "BASE", b->ttbr0 & ((UINT64_C(1) << 48) - 1));
    }
    if (b->have & HAVE_MAIR) {
        kh(&o, "MAIR0", b->mair0);
        if (b->mair1) kh(&o, "MAIR1", b->mair1);
    }
    if (ok) {
        kh(&o, "FSR", b->fsr);
        if (b->fsr) {
            kh(&o, "FAR", b->far);
            kh(&o, "FSYNR0", b->fsynr0);
        }
        if (b->ttbr1 || !(b->tcr >> 23 & 1)) kh(&o, "TTBR1", b->ttbr1);
    } else {
        out_failure(&o);
    }
    out_end(&o);
}

OUT_OF_LINE void group_cb(struct ctx *c)
{
    uint32_t banks[2] = {0, 0};
    unsigned n;
    struct bank second;
    c->bank.have = 0;
    if (!c->smmu.scanned) {
        note(c, "CB", "SKIPPED", "NO_STREAMS");
        return;
    }
    n = pick_banks(c, banks);
    if (!n) {
        note(c, "CB", "SKIPPED", "NO_TRANSLATING_STREAM_BELOW_NCB");
        return;
    }
    read_bank(c, &c->bank, banks[0]);
    if (n > 1) {
        if (room(c, 4, RESERVE_AFTER_CB)) read_bank(c, &second, banks[1]);
        else c->cuts++;
    }
}

/* ---- Group WALK: the stage-1 tables of the bank, in software ---- */

struct walk {
    uint64_t root, table_mask;
    uint32_t pg, bpl, ias, start, mair0, mair1;
};

/* A block descriptor is allowed at one level of each granule: 4 KiB levels 1 and 2, 16 KiB and 64 KiB level 2. */
static inline int block_allowed(uint32_t pg, uint32_t level)
{
    return level == 2 || (pg == 12 && level == 1);
}

enum { WY_OK, WY_NOT_READ, WY_ALL_ZERO, WY_STAGE2_ONLY, WY_NESTED, WY_M0, WY_VA64_0, WY_EPD0, WY_TG0, WY_T0SZ,
       WY_TTBR0_MISALIGNED };
static const char walk_why[11][17] = {"", "NOT_READ", "ALL_ZERO", "STAGE2_ONLY", "NESTED", "M0", "VA64_0", "EPD0", "TG0_RESERVED",
                                      "T0SZ_RANGE", "TTBR0_MISALIGNED"};

/* WY_OK when the bank is one this walk understands, else why not. A bank whose registers all read zero may be RAZ/WI to the
 * non-secure world (INFERRED) or never programmed: its zero CBAR.TYPE would pass for stage 2 only and its zero SCTLR.M for
 * stage 1 switched off, and neither is known. Stage-2 or nested banks, a bank that translates nothing, 32-bit formats, TTBR0
 * walks disabled and a granule or size the walk does not model are refused too, not guessed at. */
OUT_OF_LINE int walk_setup(const struct bank *b, struct walk *w)
{
    uint32_t tg0 = b->tcr >> 14 & 3, t0sz = b->tcr & 0x3f, type = b->cbar >> 16 & 3, top, bytes;
    if ((b->have & HAVE_ALL) != HAVE_ALL) return WY_NOT_READ;
    if (!(b->cbar | b->cba2r | b->sctlr | b->tcr | b->ttbr0)) return WY_ALL_ZERO;
    if (type == 0) return WY_STAGE2_ONLY;
    if (type == 3) return WY_NESTED;
    if (!(b->sctlr & 1)) return WY_M0;
    if (!(b->cba2r & 1)) return WY_VA64_0;
    if (b->tcr >> 7 & 1) return WY_EPD0;
    if (tg0 == 3) return WY_TG0;
    if (t0sz < 16 || t0sz > 39) return WY_T0SZ;
    w->pg = tg0 == 0 ? 12u : tg0 == 2 ? 14u : 16u;
    w->bpl = w->pg - 3;
    w->ias = 64 - t0sz;
    /* The start level is the deepest one whose table still covers the top input bit. */
    w->start = 0;
    for (uint32_t level = 4; level-- > 0;) {
        if (w->pg + w->bpl * (3 - level) + w->bpl >= w->ias) {
            w->start = level;
            break;
        }
    }
    top = w->ias - (w->pg + w->bpl * (3 - w->start));
    bytes = (1u << top) * 8u;
    if (bytes < 64) bytes = 64;                                 /* the smallest alignment a TTBR base has */
    w->root = b->ttbr0 & ((UINT64_C(1) << 48) - 1);
    if (w->root & (bytes - 1)) return WY_TTBR0_MISALIGNED;
    w->table_mask = ((UINT64_C(1) << 48) - 1) & ~((UINT64_C(1) << w->pg) - 1);
    w->mair0 = b->mair0;
    w->mair1 = b->mair1;
    return WY_OK;
}

/* ATTR=<MAIR byte>.<WB|NC|WT|DEV|NRM>.<NSH|OSH|ISH>.<RO|RW>[U][.NOAF]: AttrIndx through MAIR, SH, AP[2:1] (U: user) and AF. */
OUT_OF_LINE void field_attr(struct out *o, const struct walk *w, uint64_t desc)
{
    struct pl_line item;
    uint32_t index = desc >> 2 & 7, attr = ((index < 4 ? w->mair0 : w->mair1) >> (8 * (index & 3))) & 0xff, sh = desc >> 8 & 3;
    key(&item, "ATTR");
    hx(o->c, &item, attr);
    tx(&item, attr == 0xff ? ".WB" : attr == 0x44 ? ".NC" : attr == 0xbb ? ".WT" : !(attr & 0xf0) ? ".DEV" : ".NRM");
    tx(&item, sh == 0 ? ".NSH" : sh == 2 ? ".OSH" : sh == 3 ? ".ISH" : ".SH_RSVD");
    tx(&item, desc >> 7 & 1 ? ".RO" : ".RW");
    if (desc >> 6 & 1) tx(&item, "U");
    if (!(desc >> 10 & 1)) tx(&item, ".NOAF");
    out_put(o, &item);
}

enum { WK_MAPPED, WK_FAULT, WK_STOP };

/* One IOVA: at most four levels, one descriptor read at each, descending only through a table descriptor, so no table is
 * visited twice whatever the descriptors say. Prints the OA, level and kind, or FAULT with the level, or STOP with the reason. */
OUT_OF_LINE int walk_one(struct ctx *c, const struct walk *w, uint64_t iova, const char *role, int *identity)
{
    struct out o;
    uint64_t table = w->root;
    uint32_t level = w->start;
    int result = WK_STOP, done = 0;
    *identity = 0;
    out_begin(&o, c, "WALK", 1);
    kh(&o, "IOVA", iova);
    if (iova >> w->ias) {                                       /* outside the TTBR0 range: no TTBR0 walk, a translation fault */
        kw(&o, "FAULT");
        kn(&o, "LVL", level);
        result = WK_FAULT;
        done = 1;
    }
    for (unsigned step = 0; step < 4 && !done; step++) {
        uint32_t shift = w->pg + w->bpl * (3 - level), bits = level == w->start ? w->ias - shift : w->bpl;
        uint64_t desc, index = iova >> shift & ((UINT64_C(1) << bits) - 1);
        int rc = ram64(c, table + index * 8u, &desc);
        if (rc) {
            struct pl_line item;
            key(&item, "STOP");
            tx(&item, "TABLE_");
            tx(&item, reason_name[rc]);
            if (rc == RD_NOT_RAM) hx(c, &item, c->type);
            out_put(&o, &item);
            kn(&o, "LVL", level);
            done = 1;
        } else if (!(desc & 1)) {
            kw(&o, "FAULT");
            kn(&o, "LVL", level);
            result = WK_FAULT;
            done = 1;
        } else if (level < 3 && desc & 2) {
            table = desc & w->table_mask;
            level++;
        } else if (level == 3 ? !(desc & 2) : !block_allowed(w->pg, level)) {
            kt(&o, "STOP", "RESERVED_DESCRIPTOR");
            kn(&o, "LVL", level);
            done = 1;
        } else {
            uint64_t span = UINT64_C(1) << shift;
            uint64_t oa = (desc & ((UINT64_C(1) << 48) - 1) & ~(span - 1)) | (iova & (span - 1));
            kh(&o, "OA", oa);
            kn(&o, "LVL", level);
            kw(&o, level == 3 ? "PAGE" : "BLOCK");
            field_attr(&o, w, desc);
            result = WK_MAPPED;
            *identity = oa == iova;
            done = 1;
        }
    }
    if (!done) kt(&o, "STOP", "DEPTH");
    kw(&o, role);
    out_end(&o);
    return result;
}

struct probe {
    uint64_t iova;
    const char *role;
};

/* A candidate joins the list when it is a real address and no earlier one lies in the same 4 KiB page. */
OUT_OF_LINE void add_probe(struct probe *list, unsigned *n, uint64_t iova, const char *role, int valid)
{
    if (!valid || *n >= PROBES_MAX) return;
    for (unsigned i = 0; i < *n; i++)
        if (list[i].iova >> 12 == iova >> 12) return;
    list[*n].iova = iova;
    list[*n].role = role;
    (*n)++;
}

OUT_OF_LINE void group_walk(struct ctx *c)
{
    const struct q1n1_payload_args *a = c->a;
    const struct bank *b = &c->bank;
    struct walk w;
    struct probe list[PROBES_MAX];
    unsigned n = 0, allowed, mapped = 0, identity_n = 0, faults = 0, stops = 0;
    int why;
    struct out o;
    if (!(b->have & HAVE_CBAR)) {
        note(c, "WALK", "SKIPPED", "NO_BANK");
        return;
    }
    why = walk_setup(b, &w);
    if (why) {
        out_begin(&o, c, "WALK", 2);
        kw(&o, "UNSUPPORTED");
        kw(&o, walk_why[why]);
        if (why == WY_M0) {                                     /* the bank translates nothing: reported, not walked */
            kw(&o, "TRANSLATES_NOTHING");
            kt(&o, "INFERRED", "BYPASS_LIKE");
        }
        if (b->have & HAVE_CBAR) kh(&o, "CBAR", b->cbar);
        if (b->have & HAVE_CBA2R) kh(&o, "CBA2R", b->cba2r);
        if (b->have & HAVE_SCTLR) kh(&o, "SCTLR", b->sctlr);
        if (b->have & HAVE_TCR) kh(&o, "TCR", b->tcr);
        if (b->have & HAVE_TTBR0) kh(&o, "TTBR0", b->ttbr0);
        out_end(&o);
        return;
    }
    say(c, "NEXT WALK");
    /* In the order of what each probe settles: the firmware's own xHCI memory, q1n1's own, the far ends of the largest
     * conventional region, the top and the bottom of usable RAM, the event ring. */
    add_probe(list, &n, c->dcbaap & ~UINT64_C(0x3f), "DCBAAP", c->dcbaap != 0);
    add_probe(list, &n, a->stack_base, "STACK", a->stack_base != 0);
    add_probe(list, &n, c->conv_lo, "CONVLO", c->have_conv);
    add_probe(list, &n, c->conv_hi, "CONVHI", c->have_conv);
    add_probe(list, &n, c->ram_hi, "RAMHI", c->have_ram);
    add_probe(list, &n, c->erdp & ~UINT64_C(0xf), "ERDP", c->erdp != 0);
    add_probe(list, &n, c->ram_lo, "RAMLO", c->have_ram);
    allowed = LINE_CAP > c->lines + 1 ? LINE_CAP - c->lines - 1 : 0;       /* the summary keeps its line */
    if (n > allowed) {
        c->cuts += n - allowed;
        n = allowed;
    }
    for (unsigned i = 0; i < n; i++) {
        int identity, r = walk_one(c, &w, list[i].iova, list[i].role, &identity);
        mapped += r == WK_MAPPED;
        identity_n += identity;
        faults += r == WK_FAULT;
        stops += r == WK_STOP;
    }
    out_begin(&o, c, "WALK SUMMARY", 1);
    kn(&o, "PROBES", n);
    kn(&o, "MAPPED", mapped);
    kn(&o, "IDENTITY", identity_n);
    kn(&o, "FAULT", faults);
    kn(&o, "STOP", stops);
    if (c->cuts) kn(&o, "CUTS", c->cuts);
    out_end(&o);
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct ctx c;
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    for (size_t i = 0; i < sizeof c; i++) ((volatile uint8_t *)&c)[i] = 0;
    c.a = a;
    if ((SYSREG(CurrentEL) >> 2 & 3) != 2) {
        say(&c, "SKIPPED_NOT_AT_EL2");
        return 0;
    }
    if (!a->ops.load32) {
        say(&c, "REFUSED_NO_LOAD32");
        return Q1N1_PAYLOAD_RET_BAD_ARGS;
    }
    map_init(&c);
    map_extents(&c);
    group_u0(&c);
    group_smmu(&c);
    group_rings(&c);
    group_cb(&c);
    group_walk(&c);
    return 0;
}
