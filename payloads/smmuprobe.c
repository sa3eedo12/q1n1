/* SPDX-License-Identifier: MIT */
/* Payload "smmuprobe": what the PCIe SMMUv3 does with the internal SSD's stream, and the state of the PCIe link the SSD is on
 * (docs/SP11-PAYLOAD-SMMUPROBE.md). READ ONLY: guarded loads of the PCIe configuration space of two functions, guarded loads of the
 * SMMUv3 register page and of the stream table entry, MRS of CurrentEL, CNTFRQ_EL0 and PAR_EL1, and AT S1E2R with the ISB it needs.
 * No store but to its own stack, no MSR, no DC, no IC, no TLBI, no SMC, no write to any device: no doorbell, no CC write, no admin
 * command (the tests disassemble the binary and prove it, tools/sp11_payload_memcheck.py). EXPERIMENTAL; hardware NOT RUN.
 *
 * Why. The monitor's NVMe window (Snapintosh docs/SP11-NVME-WINDOW.md, questions D5 to D7 and D14) needs to know whether the SSD's DMA
 * is translated, bypassed or aborted by the PCIe SMMUv3. The third X2 image read the endpoint and the controller at EL2 and its read of
 * the SMMUv3 at 0x15400000 faulted in two boots (runs 6 and 7 of Snapintosh docs/SP11-X2-TESTS.md, test T07), so the state is UNKNOWN.
 * This payload asks again, in an order that stops at the first fault, and names the result of every read: a value, a fault, a refusal
 * or not attempted.
 *
 * Order (the reads that cannot cost the screen first):
 *   1. CurrentEL; not at EL2 it says so and does nothing else. The addresses that will be read are asked of the MMU first (AT S1E2R:
 *      mapped in EL2's stage 1 or not, and with which attributes), which makes no access at them. A page the MMU says is unmapped, and
 *      a device page it says is not a Device mapping, is never loaded from: the answer is on the MAP line and in the verdict.
 *   2. The configuration header of the root port (00:00.0) and of the endpoint (01:00.0) of segment 6: the addresses the X2 image
 *      already read at EL2 (OBSERVED in one boot: run 7).
 *   3. NEXT line and a wait, then the PCI Express capability and the Advanced Error Reporting capability of both (link status, device
 *      status, error status): the first reads of this unit's configuration space above offset 0x40.
 *   4. NEXT line and a wait, then the SMMUv3: ID registers, CR0 and CR0ACK, GBPA, GERROR, STRTAB_BASE and STRTAB_BASE_CFG, in that
 *      order, stopping at the first read that does not return a value (the rest are "not attempted"); then, if the table registers were
 *      read, the stream table entry of the endpoint's stream, only if the UEFI memory map says the table is usable RAM and the MMU says
 *      its page is mapped. Whether the SMMU is enabled is decided from CR0ACK, what the SMMU acknowledged, and only when CR0 (what was
 *      asked) is the same: a CR0 that differs from its acknowledgement is an update that is pending or was refused, and the verdict is
 *      UNKNOWN. If the MMU refused the SMMU's page in step 1 this step makes no read and prints no NEXT line.
 *
 * Reading discipline, each rule with a seeded bug in the host test: a load is made only inside one of four windows (the root port's
 * configuration page, the endpoint's, the SMMU's registers below 0x90, and the one RAM extent the memory map approved for the entry
 * being read), within a budget, and only in a page the MMU approved (rd() refuses the rest: a Normal mapping of a device page could fill
 * a cache line around the register that was asked for, and no register of this set is known to be harmless to read around: INFERRED);
 * a function or the SMMU group is never read again after a read that did not return; every list read
 * from hardware (the capability lists) is walked at most a fixed number of times through pointers that are masked to dword offsets
 * inside its range. The memory map is read in place through the pointer in the arguments, as el2mem does; every other read of RAM or
 * a device is the runner's load32.
 *
 * Lines: at most 36 (the runner draws 40 per payload), each at most 100 characters; the lines marked essential (the two NEXT lines,
 * the verdict and the last line) are never dropped. The page and the arguments are passed explicitly to every function, never kept in
 * a structure: the binary check proves where stores go by following pointers from the arguments and the stack. */
#define PL_PAGE_PREFIX "PAYLOAD SMMUPROBE "
#ifndef PL_PAGE_LINES
#define PL_PAGE_LINES 36u       /* at most 40 lines per call are drawn (docs/SP11-PAYLOAD.md); a test may build a smaller page */
#endif
#include "payload-page.h"
#include "payload-mmu.h"

#ifdef Q1N1_PAYLOAD_HOST_TEST
uint64_t pl_host_sysreg(const char *name);
#define SYSREG(name) pl_host_sysreg(#name)
#else
#define SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
#endif

#define OUT_OF_LINE static __attribute__((noinline))

#define ESSENTIAL_LINES 4u              /* the two NEXT lines, the verdict and the last line */
enum { RET_OK = 0, RET_NOT_EL2 = 2, RET_NO_LOAD_OP = 3 };       /* 1 is Q1N1_PAYLOAD_RET_BAD_ARGS */
#ifndef LOAD_CAP
#define LOAD_CAP 400u                   /* the ABI allows 4096; the longest run makes about 150; a test may build a smaller cap */
#endif
#define WAIT_BEFORE_READ_S 8u
#define COUNTER_HZ_DEFAULT 19200000u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u
#define COUNTER_STUCK_READS 2000000u

/* The addresses this payload reads, the expected values of config/boards/sp11.json "storage.nvme" in the Snapintosh tree
 * (OBSERVED once on one unit: docs/SP11-NVME-WINDOW.md section 7.1; the SMMU and the StreamID window from the unit's IORT).
 * ECAM: the MCFG allocation of segment 6, buses 0 and 1; a function's page is base + (bus << 20 | device << 15 | function << 12). */
#define ECAM_BASE UINT64_C(0x70000000)
#define RP_BUS 0u                       /* the root port, 00:00.0 */
#define EP_BUS 1u                       /* the endpoint, 01:00.0, RID 0x100 */
#define EP_RID 0x100u
#define SMMU_BASE UINT64_C(0x15400000)  /* the PCIe SMMUv3, 64 KiB register page 0 */
#define SMMU_READ_END 0x90u             /* no register above STRTAB_BASE_CFG (+0x88) is read */
#define STREAM_BASE UINT64_C(0x60000)   /* IORT: segment 6's RIDs 0 to 0xffff map to StreamIDs 0x60000 and up */
#define STREAM_ID (STREAM_BASE + EP_RID)
#define SIZE_STE 64u
#define ADDR_51_6 UINT64_C(0x000fffffffffffc0)  /* STRTAB_BASE.ADDR, L1STD.L2Ptr: bits 51:6 */
#define ADDR_51_4 UINT64_C(0x000ffffffffffff0)  /* STE.S2TTB: bits 51:4 */

#define ROOT_PORT_PAGE (ECAM_BASE + ((uint64_t)RP_BUS << 20))
#define ENDPOINT_PAGE (ECAM_BASE + ((uint64_t)EP_BUS << 20))
#define CFG_PAGE_BYTES 0x1000u

#define CAP_STEPS 16u                   /* a capability list of 256 bytes cannot hold more than 48; 16 is more than any device has */
#define EXT_STEPS 24u
#define CAP_PCIE 0x10u
#define PCIE_TYPE_ROOT_PORT 4u          /* Device/Port Type of the PCI Express capability register: the root port of a root complex */
#define EXT_AER 0x0001u

/* A reading: a value, a fault, a refusal (the op or this payload said no) or never tried. */
enum { RS_NA, RS_VALUE, RS_FAULT, RS_REFUSED };
#define RC_OUTSIDE 0x7fu                /* this payload's own refusal: the address is in no window it may read */
#define RC_PAGE 0x7eu                   /* this payload's own refusal: the MMU did not approve the page (unmapped, or not a Device mapping) */

/* The device pages whose approval by the MMU rd() keeps, and what the MMU said of one (AT S1E2R, which makes no access at the page).
 * PS_UNASKED is the state before the question: nothing is read from a page nobody asked about. */
enum { PAGE_RP, PAGE_EP, PAGE_SMMU, PAGE_COUNT };
enum { PS_UNASKED, PS_OK, PS_UNMAPPED, PS_NOT_DEVICE };

struct reading {
    uint64_t value;
    uint8_t state, code;
};

struct ctx {
    struct pl_page page;
    uint32_t word;                      /* the load32 destination: the runner wants it inside the payload stack, and the context is */
    uint32_t loads, faults, refused;
    uint64_t ram_lo, ram_hi;            /* the one RAM extent the memory map approved for the next entry; empty when 0 */
    uint8_t approved[PAGE_COUNT];       /* PS_*: what the MMU said of each device page; loads are made only where it is PS_OK */
};
#define PG(c) (&(c)->page)

struct fn {
    uint64_t page;
    uint8_t dead;                       /* a read of this function did not return: nothing more is read of it */
};

/* ---- The one place a load is made --------------------------------------------------------------------------------------------- */

/* Every load of this payload goes through here, and only these windows are ever read: the callers' own bounds are the first guard, this
 * is the last. Every address a caller can form is a multiple of 4 (the pointers are masked), and the runner refuses any other. */
OUT_OF_LINE int in_window(const struct ctx *c, uint64_t addr)
{
    if (addr >= ROOT_PORT_PAGE && addr < ROOT_PORT_PAGE + CFG_PAGE_BYTES) return 1;
    if (addr >= ENDPOINT_PAGE && addr < ENDPOINT_PAGE + CFG_PAGE_BYTES) return 1;
    if (addr >= SMMU_BASE && addr < SMMU_BASE + SMMU_READ_END) return 1;
    return c->ram_hi && addr >= c->ram_lo && addr < c->ram_hi && c->ram_hi - addr >= 4u;
}

/* What the MMU said of the device page that holds `addr` (PS_OK for RAM: its extent is approved by the memory map and its page is asked
 * about by the caller before the first load, because the page of a table is only known once the table's registers are read). */
OUT_OF_LINE unsigned page_approval(const struct ctx *c, uint64_t addr)
{
    if (addr >= ROOT_PORT_PAGE && addr < ROOT_PORT_PAGE + CFG_PAGE_BYTES) return c->approved[PAGE_RP];
    if (addr >= ENDPOINT_PAGE && addr < ENDPOINT_PAGE + CFG_PAGE_BYTES) return c->approved[PAGE_EP];
    if (addr >= SMMU_BASE && addr < SMMU_BASE + SMMU_READ_END) return c->approved[PAGE_SMMU];
    return PS_OK;
}

OUT_OF_LINE struct reading rd(const struct q1n1_payload_args *a, struct ctx *c, uint64_t addr)
{
    struct reading r = {0, RS_VALUE, 0};
    int rc;
    if (c->loads >= LOAD_CAP) {
        rc = Q1N1_PAYLOAD_LOAD_E_BUDGET;
    } else if (!in_window(c, addr)) {
        rc = RC_OUTSIDE;
    } else if (page_approval(c, addr) != PS_OK) {
        rc = RC_PAGE;
    } else {
        c->loads++;
        rc = a->ops.load32(addr, &c->word);
    }
    if (rc == Q1N1_PAYLOAD_LOAD_OK) {
        r.value = c->word;
        return r;
    }
    r.state = rc == Q1N1_PAYLOAD_LOAD_E_FAULT ? RS_FAULT : RS_REFUSED;
    r.code = (uint8_t)rc;
    if (r.state == RS_FAULT) c->faults++;
    else c->refused++;
    return r;
}

/* Two loads as one 64-bit value: low word first; the pair is a value only if both words are. */
OUT_OF_LINE struct reading rd64(const struct q1n1_payload_args *a, struct ctx *c, uint64_t addr)
{
    struct reading lo = rd(a, c, addr), hi;
    if (lo.state != RS_VALUE) return lo;
    hi = rd(a, c, addr + 4u);
    if (hi.state != RS_VALUE) return hi;
    lo.value |= hi.value << 32;
    return lo;
}

OUT_OF_LINE void add_reading(const struct q1n1_payload_args *a, struct ctx *c, const char *name, struct reading r)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, name);
    pl_text(&item, "=");
    if (r.state == RS_VALUE) {
        pl_hex(a, &item, r.value);
    } else if (r.state == RS_FAULT) {
        pl_text(&item, "FAULT");
    } else if (r.state == RS_REFUSED) {
        pl_text(&item, "REFUSED:");
        pl_dec(&item, r.code);
    } else {
        pl_text(&item, "NOT_ATTEMPTED");
    }
    pl_page_add(a, PG(c), item.buf);
}

OUT_OF_LINE void add_walk_of(const struct q1n1_payload_args *a, struct ctx *c, const char *key, const struct pl_walk *w)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, key);
    pl_text(&item, "=");
    pl_put_walk(a, &item, w);
    pl_page_add(a, PG(c), item.buf);
}

/* What a load at a page may do, given the MMU's answer for it: nothing when it is unmapped (the load would only fault), and, for a
 * device page, nothing when the mapping is not a Device one. A Normal mapping could fill a cache line around the register that is
 * asked for, and no register in this set is known to be harmless to read around (INFERRED: the reads are meant to be the only
 * accesses). A page of RAM may be Normal, so for it only a missing mapping refuses. */
OUT_OF_LINE unsigned page_verdict(const struct pl_walk *w, int device)
{
    if (!w->mapped) return PS_UNMAPPED;
    if (device && pl_attr_class(w->attr) != PL_ATTR_DEVICE) return PS_NOT_DEVICE;
    return PS_OK;
}

/* One AT S1E2R for the page at `va`, printed as key=<answer>, and the verdict on it. */
OUT_OF_LINE unsigned add_walk(const struct q1n1_payload_args *a, struct ctx *c, const char *key, uint64_t va, int device)
{
    struct pl_walk w;
    pl_walk_page(va, &w);
    add_walk_of(a, c, key, &w);
    return page_verdict(&w, device);
}

/* ---- PCI configuration space -------------------------------------------------------------------------------------------------- */

/* A dword of a function's configuration space; not attempted when an earlier read of that function did not return, or when the offset
 * is outside the function's 4 KiB page. */
OUT_OF_LINE struct reading cfg(const struct q1n1_payload_args *a, struct ctx *c, struct fn *f, uint32_t off)
{
    struct reading r = {0, RS_NA, 0};
    if (f->dead || off >= CFG_PAGE_BYTES) return r;
    r = rd(a, c, f->page + off);
    if (r.state != RS_VALUE) f->dead = 1;
    return r;
}

struct head {
    uint8_t cap_ptr;                    /* the capability list head, 0 when the status register says there is no list */
    uint8_t pcie_type;                  /* the port type of the PCI Express capability once it is found (4 is a root port) */
};

/* The first reads of a function: ids, command and status, class, header type, then the bridge's bus numbers or the endpoint's BAR0.
 * One line. These are the dwords the X2 image already read at EL2. */
OUT_OF_LINE void report_head(const struct q1n1_payload_args *a, struct ctx *c, const char *label, struct fn *f, struct head *h)
{
    struct reading id, cmd, cls, hdr, ptr;
    pl_page_open(PG(c), label, 0);
    id = cfg(a, c, f, 0x00);
    add_reading(a, c, "ID", id);
    if (id.state == RS_VALUE && (id.value == 0xffffffffu || (id.value & 0xffffu) == 0xffffu)) {
        pl_page_add(a, PG(c), "ABSENT");
        f->dead = 1;
        pl_page_flush(a, PG(c));
        return;
    }
    cmd = cfg(a, c, f, 0x04);
    cls = cfg(a, c, f, 0x08);
    hdr = cfg(a, c, f, 0x0c);
    add_reading(a, c, "CMDSTS", cmd);
    add_reading(a, c, "CLASSREV", cls);
    add_reading(a, c, "HDR", hdr);
    if (hdr.state == RS_VALUE && (hdr.value >> 16 & 0x7fu) == 0u) {
        add_reading(a, c, "BAR0", cfg(a, c, f, 0x10));
        add_reading(a, c, "BAR1", cfg(a, c, f, 0x14));
    } else if (hdr.state == RS_VALUE && (hdr.value >> 16 & 0x7fu) == 1u) {
        add_reading(a, c, "BUSES", cfg(a, c, f, 0x18));
    }
    if (cmd.state == RS_VALUE && (cmd.value >> 20 & 1u)) {              /* status bit 4: there is a capability list */
        ptr = cfg(a, c, f, 0x34);
        add_reading(a, c, "CAPPTR", ptr);
        if (ptr.state == RS_VALUE) h->cap_ptr = (uint8_t)(ptr.value & 0xfcu);
    }
    pl_page_flush(a, PG(c));
}

/* "GEN4.X4": the negotiated speed and width of the Link Status register (PCI Express Base Specification: the speed codes 1 to 6 are
 * 2.5, 5, 8, 16, 32 and 64 GT/s; any other code is printed as SPEED<code>). */
OUT_OF_LINE void put_link(struct pl_line *item, uint32_t sta)
{
    uint32_t speed = sta & 15u, width = sta >> 4 & 63u;
    pl_text(item, speed >= 1u && speed <= 6u ? "GEN" : "SPEED");
    pl_dec(item, speed);
    pl_text(item, ".X");
    pl_dec(item, width);
}

/* The decoded link, and whether the Data Link Layer is active only where Link Capabilities bit 20 says this function reports it
 * (a port): on an endpoint Link Status bit 13 is reserved, and reading it as "down" would say something the device did not. */
OUT_OF_LINE void add_link(const struct q1n1_payload_args *a, struct ctx *c, struct reading cap, struct reading dw)
{
    struct pl_line item;
    if (dw.state != RS_VALUE) return;
    pl_begin(&item);
    pl_text(&item, "LINK=");
    put_link(&item, (uint32_t)(dw.value >> 16));
    pl_page_add(a, PG(c), item.buf);
    if (cap.state == RS_VALUE && (cap.value >> 20 & 1u)) pl_add_dec(a, PG(c), "DLLA", dw.value >> 29 & 1u);
}

/* The PCI Express capability: where it is, the port type, and the device and link status. Returns its offset, 0 when there is none.
 * The capability list is walked at most CAP_STEPS times, through pointers that stay in 0x40 to 0xff, so a loop in it ends the walk. */
OUT_OF_LINE uint32_t report_pcie(const struct q1n1_payload_args *a, struct ctx *c, const char *label, struct fn *f, struct head *h)
{
    struct reading hdr = {0, RS_NA, 0}, linkcap, linksta;
    uint32_t ptr = h->cap_ptr, at = 0, version;
    for (uint32_t step = 0; step < CAP_STEPS && ptr >= 0x40u && ptr < 0x100u; step++) {
        struct reading r = cfg(a, c, f, ptr);
        if (r.state != RS_VALUE) break;
        if ((r.value & 0xffu) == CAP_PCIE) {
            at = ptr;
            hdr = r;
            break;
        }
        ptr = (uint32_t)(r.value >> 8) & 0xfcu;
    }
    pl_page_open(PG(c), label, 0);
    if (!at) {
        pl_page_add(a, PG(c), f->dead ? "PCIE=NOT_READ" : "PCIE=NONE");
        pl_page_flush(a, PG(c));
        return 0;
    }
    version = (uint32_t)(hdr.value >> 16 & 15u);
    h->pcie_type = (uint8_t)(hdr.value >> 20 & 15u);
    pl_add_hex(a, PG(c), "AT", at);
    add_reading(a, c, "HDR", hdr);
    pl_add_dec(a, PG(c), "TYPE", h->pcie_type);
    add_reading(a, c, "DEVCTLSTA", cfg(a, c, f, at + 0x08u));
    linkcap = cfg(a, c, f, at + 0x0cu);
    add_reading(a, c, "LNKCAP", linkcap);
    linksta = cfg(a, c, f, at + 0x10u);
    add_reading(a, c, "LNKCTLSTA", linksta);
    add_link(a, c, linkcap, linksta);
    if (version >= 2u) {
        add_reading(a, c, "LNKCAP2", cfg(a, c, f, at + 0x2cu));
        add_reading(a, c, "LNKCTL2STA2", cfg(a, c, f, at + 0x30u));
    }
    pl_page_flush(a, PG(c));
    return at;
}

/* The Advanced Error Reporting capability, found by walking the extended capability list from 0x100; only for a function that has a PCI
 * Express capability (the extended space belongs to PCI Express). Error status registers are read, never cleared. */
OUT_OF_LINE void report_aer(const struct q1n1_payload_args *a, struct ctx *c, const char *label, struct fn *f, uint32_t pcie_at,
                            const struct head *h)
{
    uint32_t ptr = 0x100u, at = 0;
    struct reading r = {0, RS_NA, 0};
    pl_page_open(PG(c), label, 0);
    if (!pcie_at) {
        pl_page_add(a, PG(c), "AER=NO_PCIE_CAP");
        pl_page_flush(a, PG(c));
        return;
    }
    for (uint32_t step = 0; step < EXT_STEPS && ptr >= 0x100u && ptr < CFG_PAGE_BYTES; step++) {
        r = cfg(a, c, f, ptr);
        if (r.state != RS_VALUE || r.value == 0 || r.value == 0xffffffffu) break;
        if ((r.value & 0xffffu) == EXT_AER) {
            at = ptr;
            break;
        }
        ptr = (uint32_t)(r.value >> 20) & 0xffcu;
    }
    if (!at) {
        pl_page_add(a, PG(c), r.state == RS_FAULT ? "AER=FAULT" : f->dead ? "AER=NOT_READ" : "AER=NONE");
        pl_page_flush(a, PG(c));
        return;
    }
    pl_add_hex(a, PG(c), "AT", at);
    add_reading(a, c, "UESTA", cfg(a, c, f, at + 0x04u));
    add_reading(a, c, "UEMASK", cfg(a, c, f, at + 0x08u));
    add_reading(a, c, "CESTA", cfg(a, c, f, at + 0x10u));
    add_reading(a, c, "CEMASK", cfg(a, c, f, at + 0x14u));
    if (h->pcie_type == PCIE_TYPE_ROOT_PORT) add_reading(a, c, "ROOTERR", cfg(a, c, f, at + 0x30u));
    pl_page_flush(a, PG(c));
}

/* ---- The SMMUv3 ---------------------------------------------------------------------------------------------------------------- */

/* Register page 0 of an SMMUv3 (Arm IHI 0070, the register map). q1n1's tools/nvme_m3.py class Smmu reads CR0, GBPA, STRTAB_BASE and
 * STRTAB_BASE_CFG at these offsets and decodes them as this payload does. One row per register; STRTAB_BASE is 64 bits. */
enum { SR_IDR0, SR_IDR1, SR_IDR2, SR_IDR3, SR_IDR4, SR_IDR5, SR_IIDR, SR_AIDR, SR_CR0, SR_CR0ACK, SR_GBPA, SR_GERROR,
       SR_STRTAB_BASE, SR_STRTAB_CFG, SR_COUNT };
static const struct {
    char name[12];
    uint8_t offset;
    uint8_t wide;
} smmu_regs[SR_COUNT] = {
    {"IDR0", 0x00, 0}, {"IDR1", 0x04, 0}, {"IDR2", 0x08, 0}, {"IDR3", 0x0c, 0}, {"IDR4", 0x10, 0}, {"IDR5", 0x14, 0},
    {"IIDR", 0x18, 0}, {"AIDR", 0x1c, 0}, {"CR0", 0x20, 0}, {"CR0ACK", 0x24, 0}, {"GBPA", 0x44, 0}, {"GERROR", 0x60, 0},
    {"STRTAB_BASE", 0x80, 1}, {"STRTAB_CFG", 0x88, 0},
};

struct smmu_view {
    struct reading reg[SR_COUNT];
    uint32_t made;                      /* how many registers were tried */
};

/* Reads the registers in table order and stops after the first that does not return a value: the rest stay "not attempted". */
OUT_OF_LINE void read_smmu(const struct q1n1_payload_args *a, struct ctx *c, struct smmu_view *v)
{
    int stopped = 0;
    pl_page_open(PG(c), "SMMU", 0);
    for (unsigned i = 0; i < SR_COUNT; i++) {
        if (!stopped) {
            uint64_t at = SMMU_BASE + smmu_regs[i].offset;
            v->reg[i] = smmu_regs[i].wide ? rd64(a, c, at) : rd(a, c, at);
            v->made++;
            if (v->reg[i].state != RS_VALUE) stopped = 1;
        }
        add_reading(a, c, smmu_regs[i].name, v->reg[i]);
    }
    pl_page_flush(a, PG(c));
}

/* What the SSD's stream does. The first two are decided by the global registers (the SMMU is off: GBPA says), the rest by the stream
 * table entry; NO_STE is a stream the table has no entry for (a StreamID beyond the table, a level-1 descriptor without a level-2
 * table, an index beyond its span). UNKNOWN means the answer could not be read, and WHY says where it stopped. */
enum { M_UNKNOWN, M_BYPASS_GLOBAL, M_ABORT_GLOBAL, M_BYPASS, M_ABORT, M_INVALID, M_NO_STE, M_S1, M_S2, M_S1S2, M_RESERVED };
/* Why a verdict is what it is (or why none could be made). */
enum { W_NONE, W_NO_CR0, W_NO_GBPA, W_NO_STRTAB, W_FORMAT, W_SPLIT, W_SID_BEYOND_TABLE, W_L1_NOT_READ, W_L2_SPAN, W_TABLE_NOT_RAM,
       W_STE_NOT_READ, W_SMMU_OFF, W_NO_L2, W_SKIPPED, W_NO_CR0ACK, W_CR0_DISAGREE, W_L1_UNMAPPED, W_STE_UNMAPPED, W_SMMU_UNMAPPED,
       W_SMMU_NOT_DEVICE };

struct verdict {
    unsigned mode, why;
};

/* The names are returned from switches, not looked up in a table: every pointer a string helper then reads through is the address of
 * a literal, which the binary check (tools/sp11_payload_memcheck.py) can prove is the payload's own image, and which needs no
 * relocation. The functions are always inlined because the check forgets a pointer a call returns. An unknown value is a bug in
 * this payload; it prints as UNKNOWN or NONE rather than reading past anything. */
#define INLINE_NAME static inline __attribute__((always_inline))

INLINE_NAME const char *mode_text(unsigned mode)
{
    switch (mode) {
    case M_BYPASS_GLOBAL: return "BYPASS_GLOBAL";
    case M_ABORT_GLOBAL: return "ABORT_GLOBAL";
    case M_BYPASS: return "BYPASS";
    case M_ABORT: return "ABORT";
    case M_INVALID: return "INVALID";
    case M_NO_STE: return "NO_STE";
    case M_S1: return "S1";
    case M_S2: return "S2";
    case M_S1S2: return "S1S2";
    case M_RESERVED: return "RESERVED";
    default: return "UNKNOWN";
    }
}

INLINE_NAME const char *why_text(unsigned why)
{
    switch (why) {
    case W_NO_CR0: return "CR0_NOT_READ";
    case W_NO_GBPA: return "GBPA_NOT_READ";
    case W_NO_STRTAB: return "STRTAB_NOT_READ";
    case W_FORMAT: return "STRTAB_FORMAT";
    case W_SPLIT: return "STRTAB_SPLIT";
    case W_SID_BEYOND_TABLE: return "SID_BEYOND_TABLE";
    case W_L1_NOT_READ: return "L1_NOT_READ";
    case W_L2_SPAN: return "BEYOND_L2_SPAN";
    case W_TABLE_NOT_RAM: return "TABLE_NOT_RAM";
    case W_STE_NOT_READ: return "STE_NOT_READ";
    case W_SMMU_OFF: return "SMMU_DISABLED";
    case W_NO_L2: return "NO_L2_TABLE";
    case W_SKIPPED: return "GROUP_SKIPPED";
    case W_NO_CR0ACK: return "CR0ACK_NOT_READ";
    case W_CR0_DISAGREE: return "CR0_ACK_DISAGREE";
    case W_L1_UNMAPPED: return "L1_UNMAPPED";
    case W_STE_UNMAPPED: return "STE_UNMAPPED";
    case W_SMMU_UNMAPPED: return "SMMU_PAGE_UNMAPPED";
    case W_SMMU_NOT_DEVICE: return "SMMU_PAGE_NOT_DEVICE";
    default: return "NONE";
    }
}

/* RAM the firmware or the OS may have left readable: loader, boot services, runtime services, conventional and ACPI reclaim memory,
 * the types usbsmmu also accepts. A reserved, unusable, ACPI NVS or MMIO descriptor is memory somebody else owns: never read. */
OUT_OF_LINE int usable_type(int type)
{
    return (type >= 1 && type <= 7) || type == 9;
}

/* The type of the memory map descriptor that holds [addr, addr + bytes): -1 when none does, -2 when the map cannot be read safely.
 * Any descriptor that overlaps the range and is not memory the payload may read (usable_type) decides it, wherever it is in the map and
 * whatever else holds the range, so a map that disagrees with itself is never read through. Reads the map in place, as el2mem does. */
OUT_OF_LINE int map_type_of(const struct q1n1_payload_args *a, uint64_t addr, uint64_t bytes)
{
    struct pl_desc d;
    uint64_t count;
    int found = -1;
    if (pl_map_check(a) != PL_MAP_OK) return -2;
    count = a->map_size / a->map_stride;
    for (uint64_t i = 0; i < count; i++) {
        if (!pl_desc_read(a, i, &d) || addr >= d.end || addr + bytes <= d.start) continue;
        if (!usable_type((int)d.type)) return (int)d.type;
        if (addr >= d.start && d.end - addr >= bytes) found = (int)d.type;
    }
    return found;
}

/* Approves [addr, addr + bytes) for loading, if the memory map says it is usable RAM; otherwise says what it is. One extent is open at
 * a time: approving the next one, or failing to, closes the last. */
OUT_OF_LINE int approve_ram(const struct q1n1_payload_args *a, struct ctx *c, uint64_t addr, uint64_t bytes, int *type)
{
    *type = map_type_of(a, addr, bytes);
    c->ram_lo = c->ram_hi = 0;
    if (!usable_type(*type)) return 0;
    c->ram_lo = addr;
    c->ram_hi = addr + bytes;
    return 1;
}

OUT_OF_LINE void add_type(const struct q1n1_payload_args *a, struct ctx *c, const char *key, int type)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, key);
    pl_text(&item, "=");
    if (type == -2) pl_text(&item, "MAP_UNUSABLE");
    else if (type == -1) pl_text(&item, "NOT_IN_MAP");
    else pl_dec(&item, (uint64_t)type);
    pl_page_add(a, PG(c), item.buf);
}

/* The decoding of a stream table entry's first doubleword, as q1n1's Smmu does: V is bit 0, Config bits 3:1 (0 abort, 4 bypass,
 * 5 stage 1, 6 stage 2, 7 both; the others are reserved). */
OUT_OF_LINE unsigned ste_mode(uint64_t dw0)
{
    if (!(dw0 & 1u)) return M_INVALID;
    switch (dw0 >> 1 & 7u) {
    case 0: return M_ABORT;
    case 4: return M_BYPASS;
    case 5: return M_S1;
    case 6: return M_S2;
    case 7: return M_S1S2;
    default: return M_RESERVED;
    }
}

/* What locate_ste found, and what it asked of the MMU, in one structure on the caller's stack (the binary check follows pointers into a
 * structure, and a call with ten pointers would hide some of them). */
struct located {
    uint64_t ste, l1_at;                /* the entry's address; the level-1 descriptor's address, 0 when the table has one level */
    struct pl_walk l1_walk;             /* the MMU's answer for the descriptor's page, valid when l1_at is not 0 */
    struct reading l1;                  /* the descriptor, when it was read */
    int type;                           /* the memory map's type for the descriptor's extent */
};

/* The stream table lookup of SMMUv3 for StreamID `sid`: where its entry is, from STRTAB_BASE and STRTAB_BASE_CFG, reading the level-1
 * descriptor from RAM when the table has two levels (STRTAB_BASE_CFG.FMT 1, SPLIT 6, 8 or 10). Returns W_NONE and the entry's address,
 * or why not. W_SID_BEYOND_TABLE, W_NO_L2 (a level-1 descriptor with Span 0: no level-2 table) and W_L2_SPAN (an index past the
 * level-2 table's 2^(Span - 1) entries) all say the table has no entry for the stream. The MMU is asked about the descriptor's page
 * before the descriptor is read, and a page it does not map is not read: W_L1_UNMAPPED. */
OUT_OF_LINE unsigned locate_ste(const struct q1n1_payload_args *a, struct ctx *c, uint64_t strtab, uint32_t cfgreg, uint64_t sid,
                                struct located *out)
{
    uint64_t *ste = &out->ste, *l1_at = &out->l1_at;
    struct pl_walk *l1_walk = &out->l1_walk;
    struct reading *l1 = &out->l1;
    int *type = &out->type;
    uint32_t fmt = cfgreg >> 16 & 3u, split = cfgreg >> 6 & 0x1fu, log2size = cfgreg & 0x3fu;
    uint64_t base = strtab & ADDR_51_6, span, index;
    *l1_at = 0;
    *type = 0;
    if (fmt > 1u) return W_FORMAT;
    if (sid >> log2size) return W_SID_BEYOND_TABLE;
    if (fmt == 0u) {
        *ste = base + sid * SIZE_STE;
        return W_NONE;
    }
    if (split != 6u && split != 8u && split != 10u) return W_SPLIT;
    *l1_at = base + (sid >> split) * 8u;
    pl_walk_page(*l1_at, l1_walk);
    if (!approve_ram(a, c, *l1_at, 8u, type)) return W_TABLE_NOT_RAM;
    if (page_verdict(l1_walk, 0) != PS_OK) return W_L1_UNMAPPED;
    *l1 = rd64(a, c, *l1_at);
    if (l1->state != RS_VALUE) return W_L1_NOT_READ;
    span = l1->value & 0x1fu;
    index = sid & (((uint64_t)1 << split) - 1u);
    if (!span) return W_NO_L2;
    if (index >> (span - 1u)) return W_L2_SPAN;
    *ste = (l1->value & ADDR_51_6) + index * SIZE_STE;
    return W_NONE;
}

/* The entry's four doublewords: each a value, or not attempted after the first read that did not return one. 1 when all four are values. */
OUT_OF_LINE int read_ste(const struct q1n1_payload_args *a, struct ctx *c, uint64_t ste, struct reading w[4])
{
    for (unsigned i = 0; i < 4u; i++) {
        w[i] = rd64(a, c, ste + 8u * i);
        if (w[i].state != RS_VALUE) return 0;
    }
    return 1;
}

OUT_OF_LINE void add_doublewords(const struct q1n1_payload_args *a, struct ctx *c, const struct reading w[4])
{
    for (unsigned i = 0; i < 4u; i++) {
        struct pl_line key;
        pl_begin(&key);
        pl_text(&key, "DW");
        pl_dec(&key, i);
        add_reading(a, c, key.buf, w[i]);
    }
}

OUT_OF_LINE void report_stream(const struct q1n1_payload_args *a, struct ctx *c, const struct smmu_view *v, struct verdict *out)
{
    const struct reading *cr0 = &v->reg[SR_CR0], *ack = &v->reg[SR_CR0ACK], *gbpa = &v->reg[SR_GBPA];
    const struct reading *tab = &v->reg[SR_STRTAB_BASE], *cfgreg = &v->reg[SR_STRTAB_CFG];
    struct reading w[4] = {{0, RS_NA, 0}, {0, RS_NA, 0}, {0, RS_NA, 0}, {0, RS_NA, 0}};
    struct located loc;
    uint64_t ste, l1_at;
    unsigned why;
    int type, whole;
    out->mode = M_UNKNOWN;
    out->why = W_NONE;
    if (cr0->state != RS_VALUE) {
        out->why = W_NO_CR0;
        return;
    }
    if (ack->state != RS_VALUE) {
        out->why = W_NO_CR0ACK;
        return;
    }
    if (cr0->value != ack->value) {                                 /* an update of CR0 is pending or was refused: no state to name */
        out->why = W_CR0_DISAGREE;
        return;
    }
    if (!(ack->value & 1u)) {                                       /* SMMUEN clear: every stream follows GBPA */
        if (gbpa->state != RS_VALUE) {
            out->why = W_NO_GBPA;
            return;
        }
        out->mode = gbpa->value >> 20 & 1u ? M_ABORT_GLOBAL : M_BYPASS_GLOBAL;
        out->why = W_SMMU_OFF;
        return;
    }
    if (tab->state != RS_VALUE || cfgreg->state != RS_VALUE) {
        out->why = W_NO_STRTAB;
        return;
    }
    pl_page_open(PG(c), "STRTAB", 0);
    pl_add_dec(a, PG(c), "FMT", cfgreg->value >> 16 & 3u);
    pl_add_dec(a, PG(c), "SPLIT", cfgreg->value >> 6 & 0x1fu);
    pl_add_dec(a, PG(c), "LOG2SIZE", cfgreg->value & 0x3fu);
    pl_add_hex(a, PG(c), "BASE", tab->value & ADDR_51_6);
    pl_add_hex(a, PG(c), "SID", STREAM_ID);
    pl_page_flush(a, PG(c));
    pl_zero(&loc, sizeof loc);
    why = locate_ste(a, c, tab->value, (uint32_t)cfgreg->value, STREAM_ID, &loc);
    ste = loc.ste;
    l1_at = loc.l1_at;
    type = loc.type;
    if (l1_at) {
        pl_page_open(PG(c), "L1", 0);
        pl_add_hex(a, PG(c), "AT", l1_at);
        add_walk_of(a, c, "MAP", &loc.l1_walk);
        if (loc.l1.state == RS_NA) add_type(a, c, "MEMMAP_TYPE", type);
        else add_reading(a, c, "DESC", loc.l1);
        pl_page_flush(a, PG(c));
    }
    if (why != W_NONE) {
        out->why = why;
        if (why == W_NO_L2 || why == W_SID_BEYOND_TABLE || why == W_L2_SPAN) out->mode = M_NO_STE;
        return;
    }
    pl_page_open(PG(c), "STE", 0);
    pl_add_hex(a, PG(c), "AT", ste);
    if (!approve_ram(a, c, ste, SIZE_STE, &type)) {
        add_type(a, c, "MEMMAP_TYPE", type);
        pl_page_add(a, PG(c), "NOT_READ");
        pl_page_flush(a, PG(c));
        out->why = W_TABLE_NOT_RAM;
        return;
    }
    if (add_walk(a, c, "MAP", ste, 0) != PS_OK) {
        pl_page_add(a, PG(c), "NOT_READ");
        pl_page_flush(a, PG(c));
        out->why = W_STE_UNMAPPED;
        return;
    }
    whole = read_ste(a, c, ste, w);
    if (whole) {
        pl_add_dec(a, PG(c), "V", w[0].value & 1u);
        pl_add_dec(a, PG(c), "CONFIG", w[0].value >> 1 & 7u);
    }
    add_doublewords(a, c, w);
    pl_page_flush(a, PG(c));
    if (!whole) {
        out->why = W_STE_NOT_READ;
        return;
    }
    out->mode = ste_mode(w[0].value);
    if (out->mode == M_S2 || out->mode == M_S1S2) {
        pl_page_open(PG(c), "S2", 0);
        pl_add_dec(a, PG(c), "VMID", w[2].value & 0xffffu);
        pl_add_dec(a, PG(c), "T0SZ", w[2].value >> 32 & 0x3fu);
        pl_add_dec(a, PG(c), "SL0", w[2].value >> 38 & 3u);
        pl_add_dec(a, PG(c), "TG", w[2].value >> 46 & 3u);
        pl_add_dec(a, PG(c), "AA64", w[2].value >> 51 & 1u);
        pl_add_hex(a, PG(c), "TTB", w[3].value & ADDR_51_4);
        pl_page_flush(a, PG(c));
    }
}

/* ---- Waiting before a read that may cost the screen ---------------------------------------------------------------------------- */

/* Waits `seconds` of the counter; 0 if the counter does not run, or runs backwards (a wait that cannot be measured is not made). */
OUT_OF_LINE int wait_seconds(const struct q1n1_payload_args *a, uint64_t freq, unsigned seconds)
{
    uint64_t start = a->ops.counter(), last = start, now;
    uint32_t same = 0;
    for (;;) {
        now = a->ops.counter();
        if (now < start) return 0;
        if (now - start >= seconds * freq) return 1;
        if (now == last) {
            if (++same >= COUNTER_STUCK_READS) return 0;
        } else {
            last = now;
            same = 0;
        }
    }
}

/* "NEXT <name> AFTER 8 S" and the wait: the last line on the panel names the group that hung. 0, and a line saying so, when the wait
 * cannot be made (the reads are then never made). */
OUT_OF_LINE int announce(const struct q1n1_payload_args *a, struct pl_page *p, uint64_t freq, const char *name)
{
    struct pl_line text;
    pl_begin(&text);
    pl_text(&text, name);
    pl_text(&text, " AFTER ");
    pl_dec(&text, WAIT_BEFORE_READ_S);
    pl_text(&text, " S");
    pl_say(a, p, "NEXT", text.buf, 1);
    if (!a->ops.counter) {
        pl_say(a, p, name, "SKIPPED=NO_COUNTER", 0);
        return 0;
    }
    if (!wait_seconds(a, freq, WAIT_BEFORE_READ_S)) {
        pl_say(a, p, name, "SKIPPED=COUNTER_UNUSABLE", 0);
        return 0;
    }
    return 1;
}

OUT_OF_LINE void say_verdict(const struct q1n1_payload_args *a, struct ctx *c, const struct verdict *v)
{
    struct pl_line item;
    pl_page_open(PG(c), "VERDICT", 1);
    pl_add_hex(a, PG(c), "STREAM", STREAM_ID);
    pl_begin(&item);
    pl_text(&item, "MODE=");
    pl_text(&item, mode_text(v->mode));
    pl_page_add(a, PG(c), item.buf);
    pl_begin(&item);
    pl_text(&item, "WHY=");
    pl_text(&item, why_text(v->why));
    pl_page_add(a, PG(c), item.buf);
    pl_page_flush(a, PG(c));
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct ctx c;
    struct fn rp, ep;
    struct head rp_head = {0, 0}, ep_head = {0, 0};
    struct smmu_view view;
    struct verdict verdict = {M_UNKNOWN, W_NONE};
    uint64_t current_el, freq;
    uint32_t rp_pcie, ep_pcie;
    int smmu_read = 0;
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    pl_zero(&c, sizeof c);
    pl_zero(&rp, sizeof rp);
    pl_zero(&ep, sizeof ep);
    pl_zero(&view, sizeof view);
    pl_page_init(PG(&c), ESSENTIAL_LINES);
    current_el = SYSREG(CurrentEL);
    freq = SYSREG(CNTFRQ_EL0);
    if (freq < COUNTER_HZ_MIN || freq > COUNTER_HZ_MAX) freq = COUNTER_HZ_DEFAULT;
    pl_page_open(PG(&c), "START", 0);
    pl_add_hex(a, PG(&c), "CURRENTEL", current_el);
    pl_add_dec(a, PG(&c), "FREQ", freq);
    pl_add_hex(a, PG(&c), "ECAM", ECAM_BASE);
    pl_add_hex(a, PG(&c), "SMMU", SMMU_BASE);
    pl_page_flush(a, PG(&c));
    if ((current_el >> 2 & 3) != 2) {
        pl_say(a, PG(&c), "REFUSED", "NOT_AT_EL2", 1);
        return RET_NOT_EL2;
    }
    if (!a->ops.load32) {
        pl_say(a, PG(&c), "REFUSED", "NO_LOAD_OP", 1);
        return RET_NO_LOAD_OP;
    }
    rp.page = ROOT_PORT_PAGE;
    ep.page = ENDPOINT_PAGE;

    pl_page_open(PG(&c), "MAP", 0);
    c.approved[PAGE_RP] = (uint8_t)add_walk(a, &c, "RP", ROOT_PORT_PAGE, 1);
    c.approved[PAGE_EP] = (uint8_t)add_walk(a, &c, "EP", ENDPOINT_PAGE, 1);
    c.approved[PAGE_SMMU] = (uint8_t)add_walk(a, &c, "SMMU", SMMU_BASE, 1);
    pl_page_flush(a, PG(&c));

    report_head(a, &c, "RP", &rp, &rp_head);
    report_head(a, &c, "EP", &ep, &ep_head);

    if (announce(a, PG(&c), freq, "PCIE_CAPS")) {
        rp_pcie = report_pcie(a, &c, "RP.PCIE", &rp, &rp_head);
        ep_pcie = report_pcie(a, &c, "EP.PCIE", &ep, &ep_head);
        report_aer(a, &c, "RP.AER", &rp, rp_pcie, &rp_head);
        report_aer(a, &c, "EP.AER", &ep, ep_pcie, &ep_head);
    }

    if (c.approved[PAGE_SMMU] != PS_OK) {                           /* the MMU said no: nothing is read, so there is nothing to wait for */
        verdict.why = c.approved[PAGE_SMMU] == PS_UNMAPPED ? W_SMMU_UNMAPPED : W_SMMU_NOT_DEVICE;
    } else if (announce(a, PG(&c), freq, "SMMU_REGISTERS")) {
        read_smmu(a, &c, &view);
        smmu_read = 1;
        report_stream(a, &c, &view, &verdict);
    } else {
        verdict.why = W_SKIPPED;
    }
    say_verdict(a, &c, &verdict);

    pl_page_open(PG(&c), "DONE", 1);
    pl_page_add(a, PG(&c), smmu_read ? "SMMU_GROUP_RAN" : "SMMU_GROUP_SKIPPED");
    pl_add_dec(a, PG(&c), "LOADS", c.loads);
    pl_add_dec(a, PG(&c), "FAULTS", c.faults);
    pl_add_dec(a, PG(&c), "REFUSED", c.refused);
    pl_add_dec(a, PG(&c), "SMMU_TRIED", view.made);
    if (c.page.suppressed) pl_add_dec(a, PG(&c), "SUPPRESSED", c.page.suppressed);
    pl_page_flush(a, PG(&c));
    return RET_OK;
}
