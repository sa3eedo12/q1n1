/* SPDX-License-Identifier: MIT */
/* Payload "nvmesnap": the state of the internal SSD's PCIe link, endpoint and NVMe controller as the firmware left them (docs/SP11-PAYLOAD-NVMESNAP.md).
 * READ ONLY: guarded loads of the configuration space of two PCIe functions, of eight NVMe controller registers and of the firmware's two admin
 * queue pages; MRS of CurrentEL, CNTFRQ_EL0 and PAR_EL1; AT S1E2R. No store but to its own stack, no MSR, DC, IC, TLBI, SMC, no write to any
 * device (no doorbell, no CC write, no admin command): the tests disassemble the binary (tools/sp11_payload_memcheck.py). EXPERIMENTAL; hardware NOT RUN.
 * Why, the order of the reads and the lines it prints: docs/SP11-PAYLOAD-NVMESNAP.md. In short: each block that can cost the screen (CAPS, NVME_REGS,
 * NVME_AQ, ADMIN_QUEUES) has its own NEXT line and, for the three that touch a device, an 8 s wait before it; it starts with a register Linux reads on
 * the same page (a hang at the first load then says the page is dead, not that a register is odd) and ends with what Linux never reads (AQA, ASQ, ACQ).
 *
 * Discipline (each rule has a seeded bug in the host test): a load is made only inside one of four windows (the two configuration pages, the 0x38
 * bytes of registers of the BAR gate two opened, the RAM extent the memory map approved for the queue being read), within a budget and only in a
 * page the MMU approved (rd() refuses the rest); a function or a block is never read again after a read that did not return; lists read from
 * hardware are walked a bounded number of times through masked pointers. Nothing above 0x37 of the controller is read (doorbells start at 0x1000).
 * At most 34 lines of at most 100 characters (the runner draws 40 per payload and a chain with smmuprobe must fit the panel); the NEXT lines, the
 * verdict and the last line are never dropped. The page and arguments are passed to every function, never kept in a structure (the binary check
 * follows pointers from the arguments and the stack to prove where stores go). */
#define PL_PAGE_PREFIX "PAYLOAD NVMESNAP "
#ifndef PL_PAGE_LINES
#define PL_PAGE_LINES 34u       /* at most 40 lines per call are drawn (docs/SP11-PAYLOAD.md); a test may build a smaller page */
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

#define ESSENTIAL_LINES 6u              /* the four NEXT lines, the verdict and the last line */
enum { RET_OK = 0, RET_NOT_EL2 = 2, RET_NO_LOAD_OP = 3 };       /* 1 is Q1N1_PAYLOAD_RET_BAD_ARGS */
#ifndef LOAD_CAP
#define LOAD_CAP 400u                   /* the ABI allows 4096; the longest run makes about 80; a test may build a smaller cap */
#endif
#define WAIT_BEFORE_READ_S 8u
#define COUNTER_HZ_DEFAULT 19200000u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u
#ifndef COUNTER_STUCK_READS
#define COUNTER_STUCK_READS 2000000u    /* reads without a tick after which the counter is dead (a test may build a smaller count) */
#endif
#ifndef SPIN_MAX
#define SPIN_MAX 0xffffffffu            /* reads in one wait: eight seconds need far fewer at any loop speed (a test may build a smaller bound) */
#endif
enum { WAIT_MADE, WAIT_DEAD, WAIT_SPIN };

/* The addresses this payload reads: the expected values of config/boards/sp11.json "storage.nvme" (OBSERVED once on one unit: Snapintosh
 * docs/SP11-NVME-WINDOW.md section 7.1). ECAM: the MCFG allocation of segment 6; a function's page is base + (bus << 20 | device << 15 | function << 12). */
#define ECAM_BASE UINT64_C(0x70000000)
#define RP_BUS 0u                       /* the root port, 00:00.0 */
#define EP_BUS 1u                       /* the endpoint, 01:00.0 */
/* The root complex's non-prefetchable memory window (Linux hamoa.dtsi, node pcie6a, ranges; the pinned copy, INFERRED for this unit). */
#define PCIE_MEM_BASE UINT64_C(0x70300000)
#define PCIE_MEM_END UINT64_C(0x74000000)
#define ROOT_PORT_PAGE (ECAM_BASE + ((uint64_t)RP_BUS << 20))
#define ENDPOINT_PAGE (ECAM_BASE + ((uint64_t)EP_BUS << 20))
#define CFG_PAGE_BYTES 0x1000u
#define NVME_READ_END 0x38u             /* the registers read end here; nothing at or above is read */
#define BAR_PAGE_MASK UINT64_C(0xfff)

#define CLASS_BRIDGE 0x0604u            /* class code bits 23:8 of the root port: PCI-to-PCI bridge, any programming interface */
#define CLASS_NVME 0x010802u            /* mass storage, non-volatile memory, NVM Express */
#define CAP_STEPS 16u                   /* a 256-byte list holds at most 48 capabilities; 16 is more than any device has */
#define CAP_PM 0x01u
#define CAP_PCIE 0x10u
/* The PCI Express capability's device/port type (dword bits 23:20): the link status registers mean what they are read as only for these. */
#define PCIE_TYPE_ENDPOINT 0u
#define PCIE_TYPE_LEGACY_ENDPOINT 1u
#define PCIE_TYPE_ROOT_PORT 4u
#define PCIE_TYPE_DOWNSTREAM_PORT 6u
#define ALL_ONES32 0xffffffffu          /* what a completed read of an absent device returns */

#define SQE_BYTES 64u
#define CQE_BYTES 16u
#define PEEK_ENTRIES 2u                 /* slots 0 and 1: the admin queues are two entries long on the one unit read */
#define QUEUE_ENTRIES_MAX 4096u         /* AQA.ASQS and AQA.ACQS are 12 bits, zero based */
#define ADDR_BITS_MAX 48u

/* A reading: a value, a fault, a refusal (the op or this payload said no) or never tried. */
enum { RS_NA, RS_VALUE, RS_FAULT, RS_REFUSED };
#define RC_OUTSIDE 0x7fu                /* this payload's own refusal: the address is in no window it may read */
#define RC_PAGE 0x7eu                   /* this payload's own refusal: the MMU did not approve the page */

/* The device pages whose approval by the MMU rd() keeps, and what the MMU said of one (AT S1E2R makes no access at the page). PS_UNASKED: nothing
 * is read from a page nobody asked about. */
enum { PAGE_RP, PAGE_EP, PAGE_BAR0, PAGE_COUNT };
enum { PS_UNASKED, PS_OK, PS_UNMAPPED, PS_NOT_DEVICE };

struct reading {
    uint64_t value;
    uint8_t state, code;
};

struct ctx {
    struct pl_page page;
    uint32_t word;                      /* the load32 destination: the runner wants it inside the payload stack, and the context is */
    uint32_t loads, faults, refused;
    uint64_t ram_lo, ram_hi;            /* the one RAM extent the memory map approved for the queue being read; empty when 0 */
    uint64_t bar0;                      /* the page of the controller registers the second gate opened; 0 until then */
    uint8_t approved[PAGE_COUNT];       /* PS_*: what the MMU said of each device page; loads are made only where it is PS_OK */
};
#define PG(c) (&(c)->page)

struct fn {
    uint64_t page;
    uint8_t dead;                       /* a read of this function did not return: nothing more is read of it */
};

/* The one place a load is made. Every load of this payload goes through rd(), and only these windows are ever read: the callers' own bounds are
 * the first guard, this is the last. Addresses a caller can form are multiples of 4 (the pointers are masked); the runner refuses any other. A device
 * page is loaded from only where the MMU approved it (c->approved, asked before the first load); the RAM extent is approved by the memory map and
 * its page asked about by read_queue before the first load. */
enum { WIN_RAM = PAGE_COUNT, WIN_NONE };
OUT_OF_LINE unsigned window_of(const struct ctx *c, uint64_t addr)
{
    if (addr >= ROOT_PORT_PAGE && addr < ROOT_PORT_PAGE + CFG_PAGE_BYTES) return PAGE_RP;
    if (addr >= ENDPOINT_PAGE && addr < ENDPOINT_PAGE + CFG_PAGE_BYTES) return PAGE_EP;
    if (c->bar0 && addr >= c->bar0 && addr < c->bar0 + NVME_READ_END) return PAGE_BAR0;
    if (c->ram_hi && addr >= c->ram_lo && addr < c->ram_hi && c->ram_hi - addr >= 4u) return WIN_RAM;
    return WIN_NONE;
}

OUT_OF_LINE struct reading rd(const struct q1n1_payload_args *a, struct ctx *c, uint64_t addr)
{
    struct reading r = {0, RS_VALUE, 0};
    unsigned win = window_of(c, addr);
    int rc;
    if (c->loads >= LOAD_CAP) {
        rc = Q1N1_PAYLOAD_LOAD_E_BUDGET;
    } else if (win == WIN_NONE) {
        rc = RC_OUTSIDE;
    } else if (win < PAGE_COUNT && c->approved[win] != PS_OK) {
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

/* Two loads as one 64-bit value, low word first (as the NVMe specification asks of a 64-bit register read in two parts); a value only if both are. */
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

OUT_OF_LINE void add_text(const struct q1n1_payload_args *a, struct ctx *c, const char *key, const char *text)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, key);
    pl_text(&item, "=");
    pl_text(&item, text);
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

/* What a load at a page may do given the MMU's answer: nothing when it is unmapped or, for a device page, not a Device mapping (a Normal mapping
 * could fill a cache line around the register: INFERRED). A page of RAM may be Normal, so for it only a missing mapping refuses. */
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

/* A dword of a function's configuration space; not attempted when an earlier read of that function did not return, or when the offset is
 * outside the function's 4 KiB page. */
OUT_OF_LINE struct reading cfg(const struct q1n1_payload_args *a, struct ctx *c, struct fn *f, uint32_t off)
{
    struct reading r = {0, RS_NA, 0};
    if (f->dead || off >= CFG_PAGE_BYTES) return r;
    r = rd(a, c, f->page + off);
    if (r.state != RS_VALUE) f->dead = 1;
    return r;
}

/* What the first reads of a function said. `cap_ptr` is the capability list head, 0 when the status register says there is no list. */
struct head {
    struct reading id, cmd, cls, hdr, bar0, bar1, buses, memwin;
    uint8_t cap_ptr;
    uint8_t absent;                     /* the id read as no function (all ones, or a vendor of all ones) */
};

OUT_OF_LINE int is_absent(struct reading id)
{
    return id.state == RS_VALUE && (id.value == 0xffffffffu || (id.value & 0xffffu) == 0xffffu);
}

/* The first reads of a function: ids, command and status, class, header type, then the bridge's bus numbers and memory window, or the endpoint's
 * two BAR words, and the capability pointer. One line. All but the bridge's window were read by the X2 image at EL2. */
OUT_OF_LINE void report_head(const struct q1n1_payload_args *a, struct ctx *c, const char *label, struct fn *f, struct head *h)
{
    struct reading ptr;
    uint32_t type;
    pl_page_open(PG(c), label, 0);
    h->id = cfg(a, c, f, 0x00);
    add_reading(a, c, "ID", h->id);
    if (is_absent(h->id)) {
        pl_page_add(a, PG(c), "ABSENT");
        h->absent = 1;
        f->dead = 1;
        pl_page_flush(a, PG(c));
        return;
    }
    h->cmd = cfg(a, c, f, 0x04);
    h->cls = cfg(a, c, f, 0x08);
    h->hdr = cfg(a, c, f, 0x0c);
    add_reading(a, c, "CMDSTS", h->cmd);
    add_reading(a, c, "CLASSREV", h->cls);
    add_reading(a, c, "HDR", h->hdr);
    type = h->hdr.state == RS_VALUE ? (uint32_t)(h->hdr.value >> 16 & 0x7fu) : 0xffu;
    if (type == 0u) {
        h->bar0 = cfg(a, c, f, 0x10);
        h->bar1 = cfg(a, c, f, 0x14);
        add_reading(a, c, "BAR0", h->bar0);
        add_reading(a, c, "BAR1", h->bar1);
    } else if (type == 1u) {
        h->buses = cfg(a, c, f, 0x18);
        h->memwin = cfg(a, c, f, 0x20);
        add_reading(a, c, "BUSES", h->buses);
        add_reading(a, c, "MEMWIN", h->memwin);
    }
    if (h->cmd.state == RS_VALUE && (h->cmd.value >> 20 & 1u)) {        /* status bit 4: there is a capability list */
        ptr = cfg(a, c, f, 0x34);
        add_reading(a, c, "CAPPTR", ptr);
        if (ptr.state == RS_VALUE) h->cap_ptr = (uint8_t)(ptr.value & 0xfcu);
    }
    pl_page_flush(a, PG(c));
}

/* What one function's capability lists gave: where the power management and PCI Express capabilities are, the PCI Express dword that holds the port
 * type, and their registers. `walk` is RS_VALUE when the list ended (or ran into its bounds), else the failing state of a read. */
struct caps {
    struct reading pcie_hdr, pm_csr, link_cap, link_sta;
    uint32_t pm_at, pcie_at;
    uint8_t walk;
};

/* Walks the capability list at most CAP_STEPS times through pointers that stay in 0x40..0xff (a loop ends the walk) and stops once both capabilities
 * are found. A capability's registers are read as soon as it is found: a read that does not return ends the page, so what the walk exists for must
 * not wait behind the headers of later capabilities. */
OUT_OF_LINE void read_caps(const struct q1n1_payload_args *a, struct ctx *c, struct fn *f, const struct head *h, int want_pm, struct caps *out)
{
    uint32_t ptr = h->cap_ptr;
    out->walk = RS_VALUE;
    if (f->dead) {                                                      /* a read of the header did not return: the lists are not read */
        out->walk = RS_FAULT;
        return;
    }
    for (uint32_t step = 0; step < CAP_STEPS && ptr >= 0x40u && ptr < 0x100u; step++) {
        struct reading r = cfg(a, c, f, ptr);
        uint32_t id;
        if (r.state != RS_VALUE) {
            out->walk = r.state;
            break;
        }
        id = (uint32_t)(r.value & 0xffu);
        if (id == CAP_PM && want_pm && !out->pm_at) {
            out->pm_at = ptr;
            out->pm_csr = cfg(a, c, f, ptr + 0x04u);
        } else if (id == CAP_PCIE && !out->pcie_at) {
            out->pcie_at = ptr;
            out->pcie_hdr = r;
            out->link_cap = cfg(a, c, f, ptr + 0x0cu);
            out->link_sta = cfg(a, c, f, ptr + 0x10u);
        }
        if ((out->pm_at || !want_pm) && out->pcie_at) break;
        ptr = (uint32_t)(r.value >> 8) & 0xfcu;
    }
}

/* "GEN4.X4": the negotiated speed and width of the Link Status register (speed codes 1 to 6 are 2.5 to 64 GT/s; any other prints as SPEED<code>). */
OUT_OF_LINE void put_link(struct pl_line *item, uint32_t sta)
{
    uint32_t speed = sta & 15u, width = sta >> 4 & 63u;
    pl_text(item, speed >= 1u && speed <= 6u ? "GEN" : "SPEED");
    pl_dec(item, speed);
    pl_text(item, ".X");
    pl_dec(item, width);
}

/* The device/port type of a function's PCI Express capability, 0xff when it was not read. */
OUT_OF_LINE uint32_t pcie_type(const struct caps *k)
{
    return k->pcie_hdr.state == RS_VALUE ? (uint32_t)(k->pcie_hdr.value >> 20 & 15u) : 0xffu;
}

/* The link of one function from the dword at the PCI Express capability's +0x10 (Link Control low, Link Status high). The data link layer bits (Link
 * Status 13 and 11) are shown only where Link Capabilities bit 20 says they exist: on an endpoint they are reserved, and "down" would be invented. A
 * decode that does not hold (wrong port type, link not up) is marked ODD, not dropped. */
OUT_OF_LINE void report_link(const struct q1n1_payload_args *a, struct ctx *c, const char *label, const struct fn *f, const struct caps *k, int port)
{
    struct pl_line item;
    uint32_t type = pcie_type(k);
    pl_page_open(PG(c), label, 0);
    if (!k->pcie_at) {
        pl_page_add(a, PG(c), f->dead || k->walk != RS_VALUE ? "PCIE=NOT_READ" : "PCIE=NONE");
        pl_page_flush(a, PG(c));
        return;
    }
    if (k->link_sta.state == RS_VALUE) {
        int reports = k->link_cap.state == RS_VALUE && (k->link_cap.value >> 20 & 1u);
        int dll_up = k->link_sta.value >> 29 & 1u, training = k->link_sta.value >> 27 & 1u;
        int odd = port ? (type != PCIE_TYPE_ROOT_PORT && type != PCIE_TYPE_DOWNSTREAM_PORT) || (reports && (!dll_up || training))
                       : (type != PCIE_TYPE_ENDPOINT && type != PCIE_TYPE_LEGACY_ENDPOINT);
        pl_begin(&item);
        pl_text(&item, "LINK=");
        put_link(&item, (uint32_t)(k->link_sta.value >> 16));
        pl_page_add(a, PG(c), item.buf);
        if (odd) pl_page_add(a, PG(c), "ODD");
        pl_add_dec(a, PG(c), "TYPE", type);
        if (reports) {
            pl_add_dec(a, PG(c), "DLLA", dll_up);
            pl_add_dec(a, PG(c), "LT", training);
        }
        pl_add_dec(a, PG(c), "ASPM", k->link_sta.value & 3u);
    }
    add_reading(a, c, "LNKCAP", k->link_cap);
    add_reading(a, c, "LNKCTLSTA", k->link_sta);
    pl_page_flush(a, PG(c));
}

OUT_OF_LINE void report_pm(const struct q1n1_payload_args *a, struct ctx *c, const struct fn *f, const struct caps *k)
{
    pl_page_open(PG(c), "EP.PM", 0);
    if (!k->pm_at) {
        pl_page_add(a, PG(c), f->dead || k->walk != RS_VALUE ? "PM=NOT_READ" : "PM=NONE");
    } else {
        add_reading(a, c, "PMCSR", k->pm_csr);
        if (k->pm_csr.state == RS_VALUE) pl_add_dec(a, PG(c), "D", k->pm_csr.value & 3u);
    }
    pl_page_flush(a, PG(c));
}

/* The gates. Why the controller registers were not read, or W_NONE when they were allowed. The first reason in this order is the one reported. A
 * read that did not return is "not read", never "absent", "off" or "down": a failed read is not reported as the thing it gates on. */
enum { W_NONE, W_RP_ABSENT, W_RP_NOT_READ, W_RP_NOT_BRIDGE, W_EP_ABSENT, W_EP_NOT_READ, W_EP_NOT_NVME, W_BUSES, W_CAPS_NOT_RUN,
       W_CAPS_NOT_READ, W_NO_LINK_CAP, W_LINK_UNPROVEN, W_LINK_DOWN, W_LINK_TRAINING, W_MEM_OFF, W_NOT_D0, W_BAR0_TYPE, W_BAR0_UNALIGNED,
       W_BAR0_PLATFORM, W_BRIDGE_MEM_OFF, W_BAR0_BRIDGE, W_MAP_UNREADABLE, W_BAR0_RAM, W_BAR0_UNMAPPED, W_BAR0_NOT_DEVICE, W_GROUP_SKIPPED,
       W_NO_REGISTERS, W_ALL_ONES, W_AQ_NOT_READ };
enum { L_NA, L_UP, L_DOWN, L_UNPROVEN };

/* The names are returned from switches, not looked up in a table: every pointer a string helper reads through is then the address of a literal,
 * which the binary check (tools/sp11_payload_memcheck.py) can prove is the payload's own image. Always inlined because the check forgets a
 * pointer a call returns. An unknown value prints as NONE rather than reading past anything. */
#define INLINE_NAME static inline __attribute__((always_inline))

INLINE_NAME const char *why_text(unsigned why)
{
    switch (why) {
    case W_RP_ABSENT: return "RP_ABSENT";
    case W_RP_NOT_READ: return "RP_NOT_READ";
    case W_RP_NOT_BRIDGE: return "RP_NOT_BRIDGE";
    case W_EP_ABSENT: return "EP_ABSENT";
    case W_EP_NOT_READ: return "EP_NOT_READ";
    case W_EP_NOT_NVME: return "EP_NOT_NVME";
    case W_BUSES: return "BRIDGE_BUSES";
    case W_CAPS_NOT_RUN: return "CAPS_NOT_RUN";
    case W_CAPS_NOT_READ: return "CAPS_NOT_READ";
    case W_NO_LINK_CAP: return "NO_LINK_CAPABILITY";
    case W_LINK_UNPROVEN: return "LINK_UNPROVEN";
    case W_LINK_DOWN: return "LINK_DOWN";
    case W_LINK_TRAINING: return "LINK_TRAINING";
    case W_MEM_OFF: return "MEMORY_SPACE_OFF";
    case W_NOT_D0: return "NOT_IN_D0";
    case W_BAR0_TYPE: return "BAR0_NOT_MEMORY";
    case W_BAR0_UNALIGNED: return "BAR0_UNALIGNED";
    case W_BAR0_PLATFORM: return "BAR0_OUTSIDE_PLATFORM_WINDOW";
    case W_BRIDGE_MEM_OFF: return "BRIDGE_MEMORY_OFF";
    case W_BAR0_BRIDGE: return "BAR0_OUTSIDE_BRIDGE_WINDOW";
    case W_MAP_UNREADABLE: return "MEMORY_MAP_UNREADABLE";
    case W_BAR0_RAM: return "BAR0_IN_RAM";
    case W_BAR0_UNMAPPED: return "BAR0_PAGE_UNMAPPED";
    case W_BAR0_NOT_DEVICE: return "BAR0_PAGE_NOT_DEVICE";
    case W_GROUP_SKIPPED: return "GROUP_SKIPPED";
    case W_NO_REGISTERS: return "REGISTERS_NOT_READ";
    case W_ALL_ONES: return "REGISTERS_ALL_ONES";
    case W_AQ_NOT_READ: return "AQ_REGISTERS_NOT_READ";
    default: return "NONE";
    }
}

INLINE_NAME const char *link_text(unsigned link)
{
    switch (link) {
    case L_UP: return "UP";
    case L_DOWN: return "DOWN";
    case L_UNPROVEN: return "UNPROVEN";
    default: return "NA";
    }
}

/* Memory the firmware or OS may have left readable: loader, boot services, runtime services, conventional and ACPI reclaim. Reserved, unusable, ACPI
 * NVS and MMIO descriptors belong to somebody else: never read. */
OUT_OF_LINE int usable_type(int type)
{
    return (type >= 1 && type <= 7) || type == 9;
}

/* The type of the memory map descriptor that holds [addr, addr + bytes): -1 when none does, -2 when the map cannot be read safely. Any descriptor
 * that overlaps the range and is not memory the payload may read decides it, so a map that disagrees with itself is never read through. */
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

/* 1 when usable RAM overlaps [addr, addr + bytes), 0 when none does, -1 when the map cannot be read safely (a map that cannot be read cannot say
 * that a window of device registers is not RAM). */
OUT_OF_LINE int ram_overlap(const struct q1n1_payload_args *a, uint64_t addr, uint64_t bytes)
{
    struct pl_desc d;
    uint64_t count;
    if (pl_map_check(a) != PL_MAP_OK) return -1;
    count = a->map_size / a->map_stride;
    for (uint64_t i = 0; i < count; i++) {
        if (!pl_desc_read(a, i, &d) || addr >= d.end || addr + bytes <= d.start) continue;
        if (usable_type((int)d.type)) return 1;
    }
    return 0;
}

/* Approves [addr, addr + bytes) for loading if the memory map says it is usable RAM, else says what it is. One extent is open at a time. */
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

/* Everything the gates look at, as read. */
struct snap {
    struct head rp, ep;
    struct caps rp_caps, ep_caps;
    uint8_t caps_run;                   /* the capability groups were announced, waited for and read */
};

/* What gate one (the headers) says: the first reason, in order, that the capability lists and the registers are not worth reading. A word that did
 * not return is "not read", never "absent" (what a function that answers with all ones says). */
OUT_OF_LINE unsigned gate_headers(const struct snap *s)
{
    const struct head *rp = &s->rp, *ep = &s->ep;
    if (rp->absent) return W_RP_ABSENT;
    if (rp->id.state != RS_VALUE || rp->cmd.state != RS_VALUE || rp->cls.state != RS_VALUE || rp->hdr.state != RS_VALUE) return W_RP_NOT_READ;
    if ((rp->cls.value >> 16 & 0xffffu) != CLASS_BRIDGE || (rp->hdr.value >> 16 & 0x7fu) != 1u) return W_RP_NOT_BRIDGE;
    if (rp->buses.state != RS_VALUE || rp->memwin.state != RS_VALUE) return W_RP_NOT_READ;
    if (ep->absent) return W_EP_ABSENT;
    if (ep->id.state != RS_VALUE || ep->cmd.state != RS_VALUE || ep->cls.state != RS_VALUE || ep->hdr.state != RS_VALUE) return W_EP_NOT_READ;
    if ((ep->cls.value >> 8 & 0xffffffu) != CLASS_NVME || (ep->hdr.value >> 16 & 0x7fu) != 0u) return W_EP_NOT_NVME;
    if (ep->bar0.state != RS_VALUE || ep->bar1.state != RS_VALUE) return W_EP_NOT_READ;
    if ((rp->buses.value & 0xffu) != RP_BUS || (rp->buses.value >> 8 & 0xffu) != EP_BUS || (rp->buses.value >> 16 & 0xffu) < EP_BUS) return W_BUSES;
    return W_NONE;
}

/* The link the root port reports, and whether it is proven: the port must be a root or downstream port (the data link layer bits are defined for
 * those only), report the data link layer (Link Capabilities bit 20) and show it active (Link Status bit 13, dword bit 29) and not training (bit 11,
 * dword bit 27). A port that does not report it leaves the link UNPROVEN: the endpoint answering a configuration read is not accepted instead. */
OUT_OF_LINE unsigned link_state(const struct snap *s)
{
    const struct caps *k = &s->rp_caps;
    if (!k->pcie_at || k->link_cap.state != RS_VALUE || k->link_sta.state != RS_VALUE) return L_NA;
    if (pcie_type(k) != PCIE_TYPE_ROOT_PORT && pcie_type(k) != PCIE_TYPE_DOWNSTREAM_PORT) return L_UNPROVEN;
    if (!(k->link_cap.value >> 20 & 1u)) return L_UNPROVEN;
    if (!(k->link_sta.value >> 29 & 1u)) return L_DOWN;
    return L_UP;
}

/* The BAR0 address of the endpoint: a 32-bit or 64-bit memory BAR with the flag bits masked off, 0 when it is neither. */
OUT_OF_LINE uint64_t bar_address(const struct head *ep, int *valid)
{
    uint32_t type = (uint32_t)(ep->bar0.value & 0xfu);
    uint64_t base = ep->bar0.value & ~UINT64_C(0xf);
    *valid = 0;
    if (ep->bar0.state != RS_VALUE || (type & 1u)) return 0;                    /* an I/O BAR is not a register window */
    if ((type >> 1 & 3u) == 2u) {                                               /* 64-bit: the next BAR is its high word */
        if (ep->bar1.state != RS_VALUE) return 0;
        base |= ep->bar1.value << 32;
    } else if ((type >> 1 & 3u) != 0u) {
        return 0;                                                               /* 1 MiB or reserved type */
    }
    *valid = 1;
    return base;
}

/* The second gate, after the capability lists: why the controller registers may not be read, or W_NONE. The caller asks the MMU and the memory
 * map afterwards, once the address is plausible. `bar` is where the endpoint's BAR0 points. */
OUT_OF_LINE unsigned gate_registers(const struct snap *s, uint64_t *bar)
{
    const struct head *rp = &s->rp, *ep = &s->ep;
    uint64_t base, limit, address;
    unsigned link;
    int valid;
    *bar = 0;
    if (!s->caps_run) return W_CAPS_NOT_RUN;
    if (s->rp_caps.walk != RS_VALUE || s->ep_caps.walk != RS_VALUE) return W_CAPS_NOT_READ;
    if (s->ep_caps.pm_at && s->ep_caps.pm_csr.state != RS_VALUE) return W_CAPS_NOT_READ;
    link = link_state(s);
    if (link == L_NA) return s->rp_caps.pcie_at ? W_CAPS_NOT_READ : W_NO_LINK_CAP;
    if (link == L_UNPROVEN) return W_LINK_UNPROVEN;
    if (link == L_DOWN) return W_LINK_DOWN;
    if (s->rp_caps.link_sta.value >> 27 & 1u) return W_LINK_TRAINING;
    if (!(ep->cmd.value >> 1 & 1u)) return W_MEM_OFF;
    if (s->ep_caps.pm_at && (s->ep_caps.pm_csr.value & 3u)) return W_NOT_D0;
    address = bar_address(ep, &valid);
    if (!valid) return W_BAR0_TYPE;
    if (address & BAR_PAGE_MASK) return W_BAR0_UNALIGNED;
    if (address < PCIE_MEM_BASE || address > PCIE_MEM_END - NVME_READ_END) return W_BAR0_PLATFORM;
    if (!(rp->cmd.value >> 1 & 1u)) return W_BRIDGE_MEM_OFF;                    /* the bridge's window forwards nothing while its memory space is off */
    if (rp->memwin.state != RS_VALUE) return W_BAR0_BRIDGE;
    base = (rp->memwin.value & 0xfff0u) << 16;
    limit = (rp->memwin.value & 0xfff00000u) | 0xfffffu;
    if (base > limit || address < base || address > limit - NVME_READ_END + 1u) return W_BAR0_BRIDGE;
    *bar = address;
    return W_NONE;
}

/* The registers read, at these offsets and no others (the X2 image read the same seven, probes/uefi/tests/pciio.h, in another order). Block one is
 * what Linux's nvme driver reads, CAP first, the state before the version (an abort costs what comes after it). Block two is CSTS again (if it does
 * not return, or reads all ones, nothing else is read), then AQA, ASQ, ACQ, which Linux writes. 64-bit registers are two loads, low word first. */
enum { NR_CAP, NR_CSTS, NR_CC, NR_VS, NR_CSTS2, NR_AQA, NR_ASQ, NR_ACQ, NR_COUNT };
#define NR_FIRST_BLOCK 4u               /* registers 0 to 3 are the first block, 4 to 7 the second */
static const struct {
    char name[6];
    uint8_t offset;
    uint8_t wide;
} nvme_regs[NR_COUNT] = {
    {"CAP", 0x00, 1}, {"CSTS", 0x1c, 0}, {"CC", 0x14, 0}, {"VS", 0x08, 0}, {"CSTS2", 0x1c, 0}, {"AQA", 0x24, 0}, {"ASQ", 0x28, 1}, {"ACQ", 0x30, 1},
};

struct view {
    struct reading reg[NR_COUNT];
    uint32_t made;                      /* how many registers were tried */
};

/* Reads registers [first, last) in table order, stopping after the first that does not return a value (or the second block's CSTS reading all
 * ones): the rest stay "not attempted". */
OUT_OF_LINE void read_nvme(const struct q1n1_payload_args *a, struct ctx *c, struct view *v, unsigned first, unsigned last)
{
    int stopped = 0;
    pl_page_open(PG(c), first ? "NVME.AQ" : "NVME", 0);
    for (unsigned i = first; i < last; i++) {
        if (!stopped) {
            uint64_t at = c->bar0 + nvme_regs[i].offset;
            v->reg[i] = nvme_regs[i].wide ? rd64(a, c, at) : rd(a, c, at);
            v->made++;
            if (v->reg[i].state != RS_VALUE || (i == NR_CSTS2 && v->reg[i].value == ALL_ONES32)) stopped = 1;
        }
        add_reading(a, c, nvme_regs[i].name, v->reg[i]);
    }
    pl_page_flush(a, PG(c));
}

enum { C_UNKNOWN, C_RUNNING, C_DISABLED, C_TRANSITION, C_FATAL, C_SHUTDOWN, C_ALL_ONES };
enum { Q_NOT_READ, Q_READ, Q_NOT_ENABLED, Q_NO_QUEUES, Q_BAD_ADDRESS, Q_NOT_RAM, Q_UNMAPPED, Q_FAULT };

INLINE_NAME const char *ctrl_text(unsigned state)
{
    switch (state) {
    case C_RUNNING: return "RUNNING";
    case C_DISABLED: return "DISABLED";
    case C_TRANSITION: return "TRANSITION";
    case C_FATAL: return "FATAL";
    case C_SHUTDOWN: return "SHUTDOWN";
    case C_ALL_ONES: return "ALL_ONES";
    default: return "UNKNOWN";
    }
}

INLINE_NAME const char *queues_text(unsigned state)
{
    switch (state) {
    case Q_READ: return "READ";
    case Q_NOT_ENABLED: return "NOT_ENABLED";
    case Q_NO_QUEUES: return "NO_QUEUES";
    case Q_BAD_ADDRESS: return "BAD_ADDRESS";
    case Q_NOT_RAM: return "NOT_RAM";
    case Q_UNMAPPED: return "PAGE_UNMAPPED";
    case Q_FAULT: return "FAULT";
    default: return "NOT_READ";
    }
}

/* What the controller registers say, decoded as the NVMe Base Specification lays them out (INFERRED from it; the raw values are the evidence).
 * CAP: MQES 15:0, CQR 16, TO 31:24, DSTRD 35:32, NSSRS 36, CSS 44:37, MPSMIN 51:48, MPSMAX 55:52, PMRS 56, CMBS 57. VS: MJR 31:16, MNR 15:8, TER 7:0.
 * CC: EN 0, CSS 6:4, MPS 10:7, AMS 13:11, SHN 15:14, IOSQES 19:16, IOCQES 23:20. CSTS: RDY 0, CFS 1, SHST 3:2. AQA: ASQS 11:0, ACQS 27:16. */
struct ctrl {
    unsigned state;
    uint64_t sq_entries, cq_entries;    /* AQA, one based; 0 when AQA was not read */
};

OUT_OF_LINE unsigned ctrl_state(const struct view *v)
{
    uint64_t cc = v->reg[NR_CC].value, csts = v->reg[NR_CSTS].value;
    if (v->reg[NR_CC].state != RS_VALUE || v->reg[NR_CSTS].state != RS_VALUE) return C_UNKNOWN;
    if (cc == ALL_ONES32 || csts == ALL_ONES32 || (v->reg[NR_CAP].state == RS_VALUE && v->reg[NR_CAP].value == ~UINT64_C(0))) return C_ALL_ONES;
    if (csts >> 1 & 1u) return C_FATAL;
    if (csts >> 2 & 3u) return C_SHUTDOWN;
    if ((cc & 1u) && (csts & 1u)) return C_RUNNING;
    if (!(cc & 1u) && !(csts & 1u)) return C_DISABLED;
    return C_TRANSITION;
}

/* The first block's lines: CAP and the controller's state. A controller that reads as all ones is not decoded: all-ones fields would say fatal and
 * shut down about a device that did not answer. */
OUT_OF_LINE void report_ctrl(const struct q1n1_payload_args *a, struct ctx *c, const struct view *v, struct ctrl *out)
{
    const struct reading *cap = &v->reg[NR_CAP], *vs = &v->reg[NR_VS], *cc = &v->reg[NR_CC], *csts = &v->reg[NR_CSTS];
    out->state = ctrl_state(v);
    if (out->state == C_ALL_ONES) {
        pl_say(a, PG(c), "CTRL", "ODD=ALL_ONES", 0);
        return;
    }
    if (cap->state == RS_VALUE) {
        pl_page_open(PG(c), "CAP", 0);
        pl_add_dec(a, PG(c), "MQES", cap->value & 0xffffu);
        pl_add_dec(a, PG(c), "CQR", cap->value >> 16 & 1u);
        pl_add_dec(a, PG(c), "TO", cap->value >> 24 & 0xffu);
        pl_add_dec(a, PG(c), "DSTRD", cap->value >> 32 & 15u);
        pl_add_dec(a, PG(c), "NSSRS", cap->value >> 36 & 1u);
        pl_add_hex(a, PG(c), "CSS", cap->value >> 37 & 0xffu);
        pl_add_dec(a, PG(c), "MPSMIN", cap->value >> 48 & 15u);
        pl_add_dec(a, PG(c), "MPSMAX", cap->value >> 52 & 15u);
        pl_add_dec(a, PG(c), "PMRS", cap->value >> 56 & 1u);
        pl_add_dec(a, PG(c), "CMBS", cap->value >> 57 & 1u);
        pl_page_flush(a, PG(c));
    }
    pl_page_open(PG(c), "CTRL", 0);
    if (vs->state == RS_VALUE) {
        struct pl_line item;
        pl_begin(&item);
        pl_text(&item, "VER=");
        pl_dec(&item, vs->value >> 16 & 0xffffu);
        pl_text(&item, ".");
        pl_dec(&item, vs->value >> 8 & 0xffu);
        pl_text(&item, ".");
        pl_dec(&item, vs->value & 0xffu);
        pl_page_add(a, PG(c), item.buf);
    }
    if (cc->state == RS_VALUE) pl_add_dec(a, PG(c), "EN", cc->value & 1u);
    if (csts->state == RS_VALUE) {
        pl_add_dec(a, PG(c), "RDY", csts->value & 1u);
        pl_add_dec(a, PG(c), "CFS", csts->value >> 1 & 1u);
        pl_add_dec(a, PG(c), "SHST", csts->value >> 2 & 3u);
    }
    if (cc->state == RS_VALUE) {
        pl_add_dec(a, PG(c), "CSS", cc->value >> 4 & 7u);
        pl_add_dec(a, PG(c), "MPS", cc->value >> 7 & 15u);
        pl_add_dec(a, PG(c), "AMS", cc->value >> 11 & 7u);
        pl_add_dec(a, PG(c), "SHN", cc->value >> 14 & 3u);
        pl_add_dec(a, PG(c), "IOSQES", cc->value >> 16 & 15u);
        pl_add_dec(a, PG(c), "IOCQES", cc->value >> 20 & 15u);
    }
    pl_page_flush(a, PG(c));
}

/* The second block's line: the admin queue sizes. A set reserved bit (15:12, 31:28) marks the decode ODD; the sizes are still printed. */
OUT_OF_LINE void report_aq(const struct q1n1_payload_args *a, struct ctx *c, const struct view *v, struct ctrl *out)
{
    const struct reading *aqa = &v->reg[NR_AQA];
    if (aqa->state != RS_VALUE) return;
    out->sq_entries = (aqa->value & 0xfffu) + 1u;
    out->cq_entries = (aqa->value >> 16 & 0xfffu) + 1u;
    pl_page_open(PG(c), "AQ", 0);
    pl_add_dec(a, PG(c), "ASQE", out->sq_entries);
    pl_add_dec(a, PG(c), "ACQE", out->cq_entries);
    if (aqa->value & 0xf000f000u) pl_page_add(a, PG(c), "ODD");
    pl_page_flush(a, PG(c));
}

/* What the second CSTS read says of the state decided from the first: all ones means nothing answers, and a ready, fatal or shutdown bit that
 * moved between the two reads means the controller was changing, not in the state the first read showed. */
OUT_OF_LINE void settle_ctrl(const struct view *v, struct ctrl *k)
{
    const struct reading *csts = &v->reg[NR_CSTS], *again = &v->reg[NR_CSTS2];
    if (again->state != RS_VALUE) return;
    if (again->value == ALL_ONES32) k->state = C_ALL_ONES;
    else if ((csts->value ^ again->value) & 0xfu) k->state = C_TRANSITION;
}

/* Why a block gave nothing, or W_NONE: a read in it that did not return (a register never tried after one that failed is that failure's, not a
 * reason of its own), or a controller that read as all ones. */
OUT_OF_LINE unsigned why_block(const struct view *v, const struct ctrl *k, unsigned first, unsigned last)
{
    for (unsigned i = first; i < last; i++)
        if (v->reg[i].state == RS_FAULT || v->reg[i].state == RS_REFUSED) return first ? W_AQ_NOT_READ : W_NO_REGISTERS;
    return k->state == C_ALL_ONES ? W_ALL_ONES : W_NONE;
}

/* A slot's words are read data first, since a read of RAM that does not return ends all reads of RAM. Submission entry: CDW0 (opcode, command id),
 * PRP1 low and high (where the firmware's DMA went), NSID, CDW10, CDW11. Completion entry: DW3 (command id, phase, status), DW2 (submission queue
 * head and id), DW0. */
static const uint8_t sqe_words[6] = {0, 6, 7, 1, 10, 11};
static const uint8_t cqe_words[3] = {3, 2, 0};

/* One slot: `n` dwords read in the order of `words`, each a value, or not attempted after the first read that did not return one. 1 when all are
 * values. */
OUT_OF_LINE int read_slot(const struct q1n1_payload_args *a, struct ctx *c, uint64_t at, const uint8_t *words, unsigned n, struct reading *w)
{
    for (unsigned i = 0; i < n; i++) {
        w[i] = rd(a, c, at + 4u * words[i]);
        if (w[i].state != RS_VALUE) {
            for (unsigned j = i + 1u; j < n; j++) w[j] = (struct reading){0, RS_NA, 0};
            return 0;
        }
    }
    return 1;
}

/* One submission queue slot as read (w[] in the order of sqe_words): the raw first doubleword, its opcode and command id, then the rest. A word that
 * did not return is named and the words after it are "not attempted". */
OUT_OF_LINE void add_sq_slot(const struct q1n1_payload_args *a, struct ctx *c, const struct reading w[6])
{
    add_reading(a, c, "DW0", w[0]);
    if (w[0].state == RS_VALUE) {
        pl_add_hex(a, PG(c), "OPC", w[0].value & 0xffu);
        pl_add_hex(a, PG(c), "CID", w[0].value >> 16 & 0xffffu);
    }
    add_reading(a, c, "NSID", w[3]);
    if (w[1].state == RS_VALUE && w[2].state == RS_VALUE) pl_add_hex(a, PG(c), "PRP1", w[1].value | w[2].value << 32);
    else add_reading(a, c, "PRP1", w[1].state != RS_VALUE ? w[1] : w[2]);
    add_reading(a, c, "CDW10", w[4]);
    add_reading(a, c, "CDW11", w[5]);
}

/* One completion queue slot as read (w[] in the order of cqe_words): the raw first and last doublewords, the command id, phase and status of the
 * last, and the submission queue head and id of the middle one. */
OUT_OF_LINE void add_cq_slot(const struct q1n1_payload_args *a, struct ctx *c, const struct reading w[3])
{
    add_reading(a, c, "DW0", w[2]);
    add_reading(a, c, "DW3", w[0]);
    if (w[0].state == RS_VALUE) {
        pl_add_hex(a, PG(c), "CID", w[0].value & 0xffffu);
        pl_add_dec(a, PG(c), "P", w[0].value >> 16 & 1u);
        pl_add_hex(a, PG(c), "SC", w[0].value >> 17 & 0xffu);
        pl_add_dec(a, PG(c), "SCT", w[0].value >> 25 & 7u);
    }
    if (w[1].state == RS_VALUE) {
        pl_add_hex(a, PG(c), "SQHD", w[1].value & 0xffffu);
        pl_add_hex(a, PG(c), "SQID", w[1].value >> 16 & 0xffffu);
    } else {
        add_reading(a, c, "DW2", w[1]);
    }
}

/* The first PEEK_ENTRIES slots of one admin queue page: the page is asked of the memory map (usable RAM only) and of the MMU (mapped), and read
 * only if both approve. Prints one line for the page and one for each slot. Returns a Q_* code: Q_READ when every word of every slot returned. */
OUT_OF_LINE unsigned read_queue(const struct q1n1_payload_args *a, struct ctx *c, const char *page_label, const char *slot_label, uint64_t at,
                                uint64_t entries, unsigned entry_bytes, const uint8_t *words, unsigned nwords)
{
    struct reading w[6];
    unsigned peek = entries < PEEK_ENTRIES ? (unsigned)entries : PEEK_ENTRIES, result = Q_READ;
    int type, ram;
    pl_zero(w, sizeof w);
    pl_page_open(PG(c), page_label, 0);
    pl_add_hex(a, PG(c), "AT", at);
    ram = approve_ram(a, c, at, (uint64_t)peek * entry_bytes, &type);
    add_type(a, c, "MEMMAP_TYPE", type);
    if (!ram) result = Q_NOT_RAM;
    else if (add_walk(a, c, "MAP", at, 0) != PS_OK) result = Q_UNMAPPED;
    if (result != Q_READ) {
        pl_page_add(a, PG(c), "NOT_READ");
        pl_page_flush(a, PG(c));
        return result;
    }
    pl_page_flush(a, PG(c));
    for (unsigned slot = 0; slot < peek; slot++) {
        int whole = read_slot(a, c, at + (uint64_t)slot * entry_bytes, words, nwords, w);
        struct pl_line label;
        pl_begin(&label);
        pl_text(&label, slot_label);
        pl_dec(&label, slot);
        pl_page_open(PG(c), label.buf, 0);
        if (entry_bytes == SQE_BYTES) add_sq_slot(a, c, w);
        else add_cq_slot(a, c, w);
        pl_page_flush(a, PG(c));
        if (!whole) {
            result = Q_FAULT;
            break;
        }
    }
    c->ram_lo = c->ram_hi = 0;
    return result;
}

/* A page-aligned queue address inside the 48-bit space, which is what ASQ and ACQ hold (bits 63:12). */
OUT_OF_LINE int queue_address_ok(uint64_t at)
{
    return at && !(at & BAR_PAGE_MASK) && at < (UINT64_C(1) << ADDR_BITS_MAX);
}

/* The firmware's admin queues, read only when the controller is enabled, ready and not fatal (a stopped controller holds addresses nobody promised
 * to keep), the sizes are plausible and the two pages differ. NEXT line, no wait: these are RAM words. Returns Q_*. */
OUT_OF_LINE unsigned read_queues(const struct q1n1_payload_args *a, struct ctx *c, const struct view *v, const struct ctrl *k)
{
    uint64_t asq = v->reg[NR_ASQ].value, acq = v->reg[NR_ACQ].value;
    unsigned sq, cq;
    if (k->state == C_UNKNOWN) return Q_NOT_READ;
    if (k->state != C_RUNNING) return Q_NOT_ENABLED;
    if (v->reg[NR_AQA].state != RS_VALUE || v->reg[NR_ASQ].state != RS_VALUE || v->reg[NR_ACQ].state != RS_VALUE) return Q_NOT_READ;
    if (k->sq_entries < 2u || k->cq_entries < 2u || k->sq_entries > QUEUE_ENTRIES_MAX || k->cq_entries > QUEUE_ENTRIES_MAX) return Q_NO_QUEUES;
    if (!queue_address_ok(asq) || !queue_address_ok(acq) || asq == acq) return Q_BAD_ADDRESS;
    pl_say(a, PG(c), "NEXT", "ADMIN_QUEUES", 1);
    sq = read_queue(a, c, "ASQ", "SQ", asq, k->sq_entries, SQE_BYTES, sqe_words, 6u);
    if (sq == Q_FAULT) return sq;                                   /* a read of RAM did not return: no more RAM is read */
    cq = read_queue(a, c, "ACQ", "CQ", acq, k->cq_entries, CQE_BYTES, cqe_words, 3u);
    return sq != Q_READ ? sq : cq;
}

/* Waits `seconds` of the counter: WAIT_MADE; WAIT_DEAD when it stands still or goes back (a wait that cannot be measured is not made); WAIT_SPIN
 * when it moves but SPIN_MAX reads did not reach the end. */
OUT_OF_LINE unsigned wait_seconds(const struct q1n1_payload_args *a, uint64_t freq, unsigned seconds)
{
    uint64_t start = a->ops.counter(), last = start, now, spins = 0;
    uint32_t same = 0;
    for (;;) {
        now = a->ops.counter();
        if (now < start) return WAIT_DEAD;
        if (now - start >= seconds * freq) return WAIT_MADE;
        if (now == last) {
            if (++same >= COUNTER_STUCK_READS) return WAIT_DEAD;
        } else {
            last = now;
            same = 0;
        }
        if (++spins >= SPIN_MAX) return WAIT_SPIN;
    }
}

/* "NEXT <name> AFTER 8 S" and the wait: the last line on the panel names the block that hung. 0 and a line saying why when the wait is not made
 * (the reads then are not either): NO_COUNTER, COUNTER_UNUSABLE (stands still or goes back), SPIN_BOUND (moves, but did not finish in SPIN_MAX reads). */
OUT_OF_LINE int announce(const struct q1n1_payload_args *a, struct pl_page *p, uint64_t freq, const char *name)
{
    struct pl_line text;
    unsigned waited;
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
    waited = wait_seconds(a, freq, WAIT_BEFORE_READ_S);
    if (waited != WAIT_MADE) {
        pl_say(a, p, name, waited == WAIT_SPIN ? "SKIPPED=SPIN_BOUND" : "SKIPPED=COUNTER_UNUSABLE", 0);
        return 0;
    }
    return 1;
}

/* The gate line: what each condition read as and why the registers were (not) read. `bar_walk` is always the caller's own stack object (the binary
 * check cannot prove where a load goes through a pointer that may be null); `mapped` says whether it holds an answer. */
OUT_OF_LINE void say_gate(const struct q1n1_payload_args *a, struct ctx *c, const struct snap *s, unsigned why, uint64_t bar, const struct pl_walk *bar_walk,
                          int mapped)
{
    pl_page_open(PG(c), "GATE", 0);
    add_text(a, c, "LINK", link_text(link_state(s)));
    if (s->rp.cmd.state == RS_VALUE) pl_add_dec(a, PG(c), "RPMEM", s->rp.cmd.value >> 1 & 1u);
    if (s->ep.cmd.state == RS_VALUE) {
        pl_add_dec(a, PG(c), "MEM", s->ep.cmd.value >> 1 & 1u);
        pl_add_dec(a, PG(c), "BME", s->ep.cmd.value >> 2 & 1u);
    }
    if (s->ep_caps.pm_at && s->ep_caps.pm_csr.state == RS_VALUE) pl_add_dec(a, PG(c), "D", s->ep_caps.pm_csr.value & 3u);
    if (bar) pl_add_hex(a, PG(c), "BAR0", bar);
    if (mapped) add_walk_of(a, c, "MAP", bar_walk);
    add_text(a, c, "WHY", why_text(why));
    pl_page_flush(a, PG(c));
}

OUT_OF_LINE void say_verdict(const struct q1n1_payload_args *a, struct ctx *c, const struct snap *s, unsigned ctrl, unsigned queues, unsigned why)
{
    pl_page_open(PG(c), "VERDICT", 1);
    add_text(a, c, "CTRL", ctrl_text(ctrl));
    add_text(a, c, "QUEUES", queues_text(queues));
    add_text(a, c, "LINK", link_text(link_state(s)));
    add_text(a, c, "WHY", why_text(why));
    pl_page_flush(a, PG(c));
}

uint64_t payload_entry(const struct q1n1_payload_args *a);
uint64_t payload_entry(const struct q1n1_payload_args *a)
{
    struct ctx c;
    struct fn rp, ep;
    struct snap snap;
    struct view view;
    struct ctrl ctrl;
    struct pl_walk bar_walk;
    uint64_t current_el, freq, bar = 0;
    unsigned why, queues = Q_NOT_READ;
    int ran = 0, mapped = 0;
    if (!pl_args_ok(a)) return Q1N1_PAYLOAD_RET_BAD_ARGS;
    pl_zero(&c, sizeof c);
    pl_zero(&rp, sizeof rp);
    pl_zero(&ep, sizeof ep);
    pl_zero(&snap, sizeof snap);
    pl_zero(&view, sizeof view);
    pl_zero(&ctrl, sizeof ctrl);
    pl_zero(&bar_walk, sizeof bar_walk);
    pl_page_init(PG(&c), ESSENTIAL_LINES);
    current_el = SYSREG(CurrentEL);
    freq = SYSREG(CNTFRQ_EL0);
    if (freq < COUNTER_HZ_MIN || freq > COUNTER_HZ_MAX) freq = COUNTER_HZ_DEFAULT;
    pl_page_open(PG(&c), "START", 0);
    pl_add_hex(a, PG(&c), "CURRENTEL", current_el);
    pl_add_dec(a, PG(&c), "FREQ", freq);
    pl_add_hex(a, PG(&c), "ECAM", ECAM_BASE);
    pl_add_hex(a, PG(&c), "WINDOW", PCIE_MEM_BASE);
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
    pl_page_flush(a, PG(&c));

    report_head(a, &c, "RP", &rp, &snap.rp);
    report_head(a, &c, "EP", &ep, &snap.ep);
    why = gate_headers(&snap);

    if (why == W_NONE && announce(a, PG(&c), freq, "CAPS")) {
        read_caps(a, &c, &rp, &snap.rp, 0, &snap.rp_caps);
        report_link(a, &c, "RP.LINK", &rp, &snap.rp_caps, 1);
        read_caps(a, &c, &ep, &snap.ep, 1, &snap.ep_caps);
        snap.caps_run = 1;
        report_pm(a, &c, &ep, &snap.ep_caps);
        report_link(a, &c, "EP.LINK", &ep, &snap.ep_caps, 0);
    }
    if (why == W_NONE) {
        why = gate_registers(&snap, &bar);
        if (why == W_NONE) {
            int overlap = ram_overlap(a, bar, NVME_READ_END);
            why = overlap < 0 ? W_MAP_UNREADABLE : overlap ? W_BAR0_RAM : W_NONE;
        }
        if (why == W_NONE) {
            unsigned verdict;
            pl_walk_page(bar, &bar_walk);
            mapped = 1;
            verdict = page_verdict(&bar_walk, 1);
            why = verdict == PS_UNMAPPED ? W_BAR0_UNMAPPED : verdict == PS_NOT_DEVICE ? W_BAR0_NOT_DEVICE : W_NONE;
        }
        say_gate(a, &c, &snap, why, bar, &bar_walk, mapped);
    }

    if (why == W_NONE) {
        c.bar0 = bar;
        c.approved[PAGE_BAR0] = PS_OK;
        if (!announce(a, PG(&c), freq, "NVME_REGS")) {
            why = W_GROUP_SKIPPED;
        } else {
            read_nvme(a, &c, &view, 0, NR_FIRST_BLOCK);
            ran = 1;
            report_ctrl(a, &c, &view, &ctrl);
            why = why_block(&view, &ctrl, 0, NR_FIRST_BLOCK);
        }
    }
    if (why == W_NONE) {
        if (!announce(a, PG(&c), freq, "NVME_AQ")) {
            why = W_GROUP_SKIPPED;
        } else {
            read_nvme(a, &c, &view, NR_FIRST_BLOCK, NR_COUNT);
            settle_ctrl(&view, &ctrl);
            report_aq(a, &c, &view, &ctrl);
            why = why_block(&view, &ctrl, NR_FIRST_BLOCK, NR_COUNT);
            if (why == W_NONE) queues = read_queues(a, &c, &view, &ctrl);
        }
    }
    say_verdict(a, &c, &snap, ctrl.state, queues, why);

    pl_page_open(PG(&c), "DONE", 1);
    pl_page_add(a, PG(&c), ran ? "NVME_GROUP_RAN" : "NVME_GROUP_SKIPPED");
    pl_add_dec(a, PG(&c), "LOADS", c.loads);
    pl_add_dec(a, PG(&c), "FAULTS", c.faults);
    pl_add_dec(a, PG(&c), "REFUSED", c.refused);
    pl_add_dec(a, PG(&c), "NVME_TRIED", view.made);
    if (c.page.suppressed) pl_add_dec(a, PG(&c), "SUPPRESSED", c.page.suppressed);
    pl_page_flush(a, PG(&c));
    return RET_OK;
}
