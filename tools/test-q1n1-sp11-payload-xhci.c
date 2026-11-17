/* SPDX-License-Identifier: MIT */
/* Host test of the payload "xhci" (payloads/xhci*.c, stage S1 of the Surface Pro 11 stick study), built natively with
 * Q1N1_PAYLOAD_HOST_TEST and one XHCI_S1_CONTROLLER, under ASan and UBSan, and driven by tools/test-q1n1-sp11-payload-xhci.py. This file is
 * the model, the audit and main; the suites are in test-q1n1-sp11-payload-xhci-cases.c and what the two share in the header of this name.
 *
 * The controller is q1n1's own native xHCI simulator (tools/test-q1n1-xhci.c, included here with its main compiled out and the hooks it
 * gained for this test: the geometry, the DMA pointer and the command completion). Around it this file models what the payload touches:
 * the DWC3 core registers (read only), the apps SMMU (stream match, S2CR, the fault registers of context bank 3: read only, and a DMA the
 * SMMU refuses changes them), the other controller's ports, the UEFI memory map, the RAM of the arenas behind a NON-COHERENT cache (a CPU
 * store is not seen by the xHC until it is cleaned, an xHC write not seen by the CPU until its line is invalidated), a counter and the page.
 *
 * An audit independent of the payload watches every access. Stores: only the thirteen registers of the authorisation record (REGISTERS),
 * USBCMD only in RS and HCRST, each only after the NEXT line of its group and eight seconds of counter; RAM stores only inside the arena
 * the last NEXT ARENA line named, and no byte outside it changes; cache operations only inside that arena as well. Reads: only the registers the
 * payload documents. The xHCI rules of
 * sections 4.2, 4.9.4 and 4.20 as this model knows them (written from the specification and QEMU's xHC, not from the payload): HCRST only
 * when halted, ERSTBA after ERSTSZ and ERDP, a 64-bit register low word first, R/S only with DCBAAP, CRCR, the event ring and, when
 * HCSPARAMS2 asks, a scratchpad array of zeroed pages of the arena, no write of the structure registers while running, alignments, a No Op
 * command, ERDP never beyond what the controller enqueued; an event the controller posts sets IMAN.IP and USBSTS.EINT (RW1C: a halt does not
 * clear it, a reset does). A violation fails the run.
 *
 * Suites: nominal, scratch, refuse, faults, fallback, watch, edges, fuzz, gates (test-q1n1-sp11-payload-xhci-gates.c: the store gates called
 * directly), registers (prints the table the Python test compares with the
 * record). Nothing here runs on hardware. Evidence: EXPERIMENTAL (host model only). */
#include "test-q1n1-sp11-payload-xhci.h"

#define SIM_MMIO 0x10000
#define SIM_SLOTS 65
#define SIM_PORTS 2
#define XHCI_SIM_NO_MAIN 1
static void *model_dma(uint64_t address, size_t length);
static void model_command_done(uint32_t type, uint64_t address);
#define SIM_DMA(address, length) model_dma((address), (length))
#define SIM_COMMAND_DONE(type, address) model_command_done((type), (address))
#include "test-q1n1-xhci.c"

struct world W;
struct region regions[REGIONS];
struct q1n1_payload_args args;
static uint8_t map_buffer[16 * 48] __attribute__((aligned(8)));
static uint32_t other_port[2];

char lines[LINES_MAX][128];
unsigned nlines, loads, ram_stores, bad_lines, dma_faults, dma_outside, nstores;
static unsigned cache_ops, ops_since_dsb, attempt_no, scripts_done, armed_model;
static uint32_t violations_mask, gsts_model, berr_lo, berr_hi;
static char first_vio[240], first_bad[160];
struct store stores[STORES_MAX];
uint64_t arena_base, arena_bytes, suite_checks, ret_value;
static uint64_t now_ticks, counter_reads, armed_at[8], hang_limit, hcrst_until, cnr_until, counter_skew;
static unsigned back_countdown, back_armed;
char stores_joined[STORES_MAX * 14];
static unsigned cur_arena, phase, lo_written, reset_done;
/* every arena an attempt has named so far: each one is zeroed again once its controller is confirmed halted */
static struct { uint64_t base, bytes; unsigned stores; } arenas_seen[8];
static unsigned narenas_seen;
unsigned fail_count, checks_count;

static void violation(int kind, const char *detail)
{
    violations_mask |= 1u << kind;
    if (!first_vio[0]) snprintf(first_vio, sizeof first_vio, "kind %d: %s", kind, detail);
}

unsigned model_violation_mask(void) { return violations_mask; }
const char *model_first_violation(void) { return first_vio; }

/* ---- The registers of the authorisation record: the one table of this test ---------------------------------------------------------- */

enum { FROM_OP, FROM_IR, FROM_DB };
static const struct { const char *name; int from; unsigned off; } REGISTERS[] = {
    {"USBCMD", FROM_OP, 0x00}, {"CRCR_LO", FROM_OP, 0x18}, {"CRCR_HI", FROM_OP, 0x1c}, {"DCBAAP_LO", FROM_OP, 0x30}, {"DCBAAP_HI", FROM_OP, 0x34},
    {"CONFIG", FROM_OP, 0x38}, {"ERSTSZ", FROM_IR, 0x08}, {"ERSTBA_LO", FROM_IR, 0x10}, {"ERSTBA_HI", FROM_IR, 0x14}, {"ERDP_LO", FROM_IR, 0x18},
    {"ERDP_HI", FROM_IR, 0x1c}, {"IMAN", FROM_IR, 0x00}, {"DB0", FROM_DB, 0x00}};
#define NREGS (sizeof REGISTERS / sizeof REGISTERS[0])

static unsigned reg_offset_of(unsigned i)
{
    return (REGISTERS[i].from == FROM_OP ? CAPLENGTH : REGISTERS[i].from == FROM_IR ? RTSOFF + 0x20 : DBOFF) + REGISTERS[i].off;
}

/* ---- RAM with a non-coherent cache -------------------------------------------------------------------------------------------------- */

static struct region *find_region(uint64_t phys, size_t length)
{
    for (unsigned i = 0; i < REGIONS; i++)
        if (phys >= regions[i].base && phys + length <= regions[i].base + regions[i].size) return &regions[i];
    return NULL;
}

static void regions_init(void)
{
    static const struct { uint64_t base; size_t size; } layout[REGIONS] = {
        {UINT64_C(0xCEC90000), 0x10000}, {UINT64_C(0xCF410000), 0x10000}, {UINT64_C(0xC3D00000), 0x100000}, {UINT64_C(0x880000000), 0x100000},
        {UINT64_C(0x90000000), 0x10000}};
    for (unsigned i = 0; i < REGIONS; i++) {
        regions[i].base = layout[i].base;
        regions[i].size = layout[i].size;
        regions[i].dram = calloc(1, layout[i].size);
        regions[i].cpu = calloc(1, layout[i].size);
        regions[i].state = calloc(1, layout[i].size / LINE);
    }
}

/* Every byte starts as 0xA5: a store outside the arena, a scratchpad page that was not zeroed and a TRB the xHC read before it was cleaned
 * all show. */
static void regions_reset(void)
{
    for (unsigned i = 0; i < REGIONS; i++) {
        memset(regions[i].dram, 0xA5, regions[i].size);
        memset(regions[i].cpu, 0xA5, regions[i].size);
        memset(regions[i].state, 0, regions[i].size / LINE);
    }
}

uint32_t pl_host_ram_load32(uint64_t phys);
uint32_t pl_host_ram_load32(uint64_t phys)
{
    struct region *r = find_region(phys, 4);
    size_t off, line;
    uint32_t value;
    if (!r) {
        violation(VIO_UNMAPPED_RAM, "a RAM load outside every region");
        return 0;
    }
    off = phys - r->base;
    line = off / LINE;
    if (!W.coherent && r->state[line] == 0) {
        memcpy(r->cpu + line * LINE, r->dram + line * LINE, LINE);
        r->state[line] = 1;
    }
    memcpy(&value, (W.coherent ? r->dram : r->cpu) + off, 4);
    return value;
}

void pl_host_ram_store32(uint64_t phys, uint32_t value);
void pl_host_ram_store32(uint64_t phys, uint32_t value)
{
    struct region *r = find_region(phys, 4);
    size_t off, line;
    ram_stores++;
    if (narenas_seen) arenas_seen[narenas_seen - 1].stores++;
    if (!r) {
        violation(VIO_UNMAPPED_RAM, "a RAM store outside every region");
        return;
    }
    if (!(armed_model & 1u)) violation(VIO_NOT_ARMED_RAM, "a RAM store before the ARENA group");
    else if (now_ticks - armed_at[0] < NSEC(8)) violation(VIO_RAM_EARLY, "a RAM store under eight seconds after the ARENA line");
    if (phys < arena_base || phys + 4 > arena_base + arena_bytes) violation(VIO_RAM_OUTSIDE, "a RAM store outside the arena the NEXT line named");
    if (sim.running && !(phys >= arena_base + 0x400 && phys < arena_base + 0x410))
        violation(VIO_RAM_RUNNING, "a RAM store into the arena while the controller may run, other than the No Op TRB");
    off = phys - r->base;
    line = off / LINE;
    if (W.coherent) {
        memcpy(r->dram + off, &value, 4);
        return;
    }
    if (r->state[line] == 0) memcpy(r->cpu + line * LINE, r->dram + line * LINE, LINE);
    memcpy(r->cpu + off, &value, 4);
    r->state[line] = 2;
}

void pl_host_cache(const char *op, uint64_t phys);
void pl_host_cache(const char *op, uint64_t phys)
{
    struct region *r;
    size_t line;
    int invalidate = !strcmp(op, "civac");
    if (!strcmp(op, "dsb")) {
        ops_since_dsb = 0;
        return;
    }
    cache_ops++;
    ops_since_dsb++;
    /* A cache operation maintains memory the payload does not own if it is aimed outside the arena the last NEXT ARENA line named. */
    if (phys < arena_base || phys - arena_base >= arena_bytes) violation(VIO_DC_OUTSIDE, "a cache operation outside the arena the NEXT line named");
    r = find_region(phys, 1);
    if (!r || W.coherent) return;
    line = (phys - r->base) / LINE;
    if (r->state[line] == 2) memcpy(r->dram + line * LINE, r->cpu + line * LINE, LINE);
    if (r->state[line] == 2 || invalidate) r->state[line] = invalidate ? 0 : 1;
}

/* What the xHC sees: DRAM, through the SMMU. A refused DMA updates the SMMU's fault registers and the DWC3's bus error address. */
static void *model_dma(uint64_t address, size_t length)
{
    struct region *r = find_region(address, length);
    unsigned id = r ? (unsigned)(r - regions) : 0;
    if (!r || !(W.iommu >> id & 1u)) {
        dma_faults++;
        if (!W.berr_only) {
            W.cb_fsr |= 2;
            W.cb_far = address;
        }
        gsts_model |= 1u << 4;
        if (W.berr_only != 2) {
            berr_lo = (uint32_t)address;
            berr_hi = (uint32_t)(address >> 32);
        }
        return NULL;
    }
    if (arena_bytes && (address < arena_base || address + length > arena_base + arena_bytes)) dma_outside++;
    return r->dram + (address - r->base);
}

/* ---- The command the model has no use for, a No Op, and what a faulty controller does with it ------------------------------------------- */

/* An event the controller posts also sets IMAN.IP and USBSTS.EINT (xHCI 1.2 sections 4.17 and 5.4.2: EINT is set when the IP of an interrupter goes from 0 to
 * 1), unless the write of the event itself was refused: then the controller halts with HSE instead. The payload reads EINT to tell an event it cannot find
 * from silence. A reset clears both (the simulator rebuilds the registers). */
static void model_post(uint64_t parameter, uint32_t status, uint32_t control)
{
    unsigned faults = dma_faults;
    sim_event(parameter, status, control);
    if (dma_faults != faults) return;
    mmio_w32(OP(4), mmio_r32(OP(4)) | (1u << 3));
    mmio_w32(IR(0), mmio_r32(IR(0)) | 1u);
}

static void model_command_done(uint32_t type, uint64_t address)
{
    unsigned bit = 1u << cur_arena;
    uint32_t code = W.code ? W.code : 1;
    if (type != 23) violation(VIO_BAD_COMMAND, "the command is not a No Op Command TRB");
    for (uint32_t n = 0; n < W.psc_events && (W.knob[K_PSC] & bit); n++) model_post((uint64_t)1 << 24, 1u << 24, 34u << 10);
    if (W.knob[K_SILENT] & bit) return;
    if (W.knob[K_REDIRECT] & bit) {
        uint64_t saved = sim.event_ring;                    /* the event lands in a ring that is not ours */
        sim.event_ring = regions[R_DECOY].base;
        model_post(address, 1u << 24, 33u << 10);
        sim.event_ring = saved;
        return;
    }
    if (W.knob[K_CYCLE] & bit) {
        sim.event_cycle ^= 1;
        model_post(address, 1u << 24, 33u << 10);
        sim.event_cycle ^= 1;
        return;
    }
    model_post((W.knob[K_POINTER] & bit) ? address + 16 : address, ((W.knob[K_CODE] & bit) ? code : 1u) << 24, 33u << 10);
}

/* ---- Stores to the controller: the gates of the record and the rules of the specification ------------------------------------------------ */

static const char *store_name(unsigned offset, uint32_t value)
{
    for (unsigned i = 0; i < NREGS; i++) {
        if (reg_offset_of(i) != offset) continue;
        return i == 0 ? (value & 2 ? "USBCMD:HCRST" : value & 1 ? "USBCMD:RS" : "USBCMD:STOP") : REGISTERS[i].name;
    }
    return NULL;
}

static unsigned group_of(const char *name)
{
    if (!strcmp(name, "USBCMD:HCRST")) return 2;
    if (!strcmp(name, "USBCMD:RS")) return 8;
    if (!strcmp(name, "USBCMD:STOP")) return 0;
    if (!strcmp(name, "DB0") || !strcmp(name, "IMAN")) return 16;
    return !strncmp(name, "ERDP", 4) && phase == 2 ? 16 : 4;
}

/* The audit reads DRAM directly: what the payload programmed must be right whether or not this environment lets the xHC reach it. */
static const uint8_t *raw_dram(uint64_t address, size_t length)
{
    struct region *r = find_region(address, length);
    return r ? r->dram + (address - r->base) : NULL;
}

/* At R/S: DCBAAP, CRCR, the event ring and CONFIG are programmed and aligned, and the scratchpad array is there when the controller asks. */
static void check_run_setup(void)
{
    uint64_t dcbaap = mmio_r64(OP(0x30)), crcr = mmio_r64(OP(0x18)) & ~0x3fULL, erstba = mmio_r64(IR(0x10)), erdp = mmio_r64(IR(0x18)) & ~0xfULL;
    const uint8_t *d;
    uint64_t first = 1;
    if (!dcbaap || !crcr || !erstba || !erdp || !mmio_r32(IR(0x08)) || !mmio_r32(OP(0x38)) || (dcbaap & 63) || (erstba & 63)) {
        violation(VIO_RS_SETUP, "R/S before DCBAAP, CRCR, the event ring and CONFIG are programmed and aligned");
        return;
    }
    d = raw_dram(dcbaap, 8);
    if (!d) {
        violation(VIO_RS_SCRATCH, "DCBAAP does not point at DRAM");
        return;
    }
    memcpy(&first, d, 8);
    if (!W.scratch) {
        if (first) violation(VIO_RS_SCRATCH, "DCBAA[0] is not zero though no scratchpad buffer is required");
        return;
    }
    {
        const uint8_t *e = (first && !(first & 63)) ? raw_dram(first, 8ull * W.scratch) : NULL;
        uint64_t seen[64];
        if (!e) {
            violation(VIO_RS_SCRATCH, "DCBAA[0] is not a 64-byte aligned array the xHC can read: the scratchpad buffer array is missing");
            return;
        }
        for (uint32_t i = 0; i < W.scratch && i < 64; i++) {
            uint64_t page;
            const uint8_t *p;
            memcpy(&page, e + 8 * i, 8);
            p = (page & 4095) ? NULL : raw_dram(page, 4096);
            if (!p || page < arena_base || page + 4096 > arena_base + arena_bytes) {
                violation(VIO_RS_SCRATCH, "a scratchpad entry is not a whole page of the arena");
                return;
            }
            for (unsigned k = 0; k < 4096; k += 4) {
                uint32_t v;
                memcpy(&v, p + k, 4);
                if (v) {
                    violation(VIO_RS_SCRATCH, "a scratchpad page is not zero in DRAM (it was not zeroed and cleaned)");
                    return;
                }
            }
            for (uint32_t j = 0; j < i; j++)
                if (seen[j] == page) violation(VIO_RS_SCRATCH, "two scratchpad entries name one page");
            seen[i] = page;
        }
    }
}

void pl_host_mmio_store32(uint64_t phys, uint32_t value);
void pl_host_mmio_store32(uint64_t phys, uint32_t value)
{
    uint64_t base = BASE_OF(T);
    const char *name;
    unsigned offset, group;
    char detail[120];
    static const char *const highs[] = {"CRCR_HI", "DCBAAP_HI", "ERSTBA_HI", "ERDP_HI"}, *const lows[] = {"CRCR_LO", "DCBAAP_LO", "ERSTBA_LO", "ERDP_LO"};
    if (phys >= SMMU_BASE && phys < SMMU_BASE + 0x100000) return violation(VIO_STORE_SMMU, "a store to the SMMU");
    if (phys < base || phys >= base + WINDOW) return violation(VIO_STORE_OUTSIDE, "a store outside the controller's window");
    offset = (unsigned)(phys - base);
    name = store_name(offset, value);
    if (!name) {
        snprintf(detail, sizeof detail, "offset 0x%x is not a register of the record", offset);
        return violation(VIO_STORE_OUTSIDE, detail);
    }
    if (nstores < STORES_MAX) {
        stores[nstores].now = now_ticks;
        stores[nstores].offset = offset;
        stores[nstores].value = value;
        snprintf(stores[nstores].name, sizeof stores[nstores].name, "%s", name);
        nstores++;
    }
    group = group_of(name);
    if (ops_since_dsb) violation(VIO_NO_BARRIER, name);
    if (group ? !(armed_model & group) : !armed_model) violation(VIO_NOT_ARMED, name);
    else if (group && now_ticks - armed_at[__builtin_ctz(group)] < NSEC(8)) violation(VIO_TOO_EARLY, name);

    if (!strncmp(name, "USBCMD", 6)) {
        uint32_t current = mmio_r32(OP(0));
        if ((value ^ current) & ~3u) violation(VIO_STORE_BITS, "USBCMD changed in a bit other than RS and HCRST");
        if (value & 2) {
            if (!(mmio_r32(OP(4)) & 1u) || (current & 1u) || sim.running) violation(VIO_HCRST_RUNNING, "HCRST while the controller runs");
            lo_written = phase = 0;
        } else if (value & 1) {
            if (mmio_r32(OP(4)) & (1u << 11)) violation(VIO_RS_SETUP, "R/S while CNR");
            check_run_setup();
            phase = 1;
        }
    } else if (!strcmp(name, "DB0")) {
        if (!sim.running || value) violation(VIO_DB, "doorbell 0 rung while halted, or with a target");
        phase = 2;
    } else if (!strcmp(name, "IMAN")) {
        if (value != 1) violation(VIO_IMAN, "IMAN written with more than IP");
    } else if (!strncmp(name, "ERDP", 4) && phase == 2) {
        if (!strcmp(name, "ERDP_LO")) {
            uint64_t enqueue = sim.event_ring + (uint64_t)sim.event_index * 16, dq = (mmio_r64(IR(0x18)) & ~0xffffffffULL) | (value & ~0xfu);
            if (!(value & 8) || dq > enqueue || dq < sim.event_ring) violation(VIO_ERDP, "ERDP without EHB, or beyond what the controller enqueued");
        }
    } else if (sim.running) {
        violation(VIO_WRITE_RUNNING, name);
    }
    if (!strcmp(name, "ERSTBA_LO") && (!mmio_r32(IR(0x08)) || !mmio_r64(IR(0x18)))) violation(VIO_ERSTBA_ORDER, "ERSTBA before ERSTSZ and ERDP");
    if ((!strcmp(name, "ERSTBA_LO") || !strcmp(name, "DCBAAP_LO")) && (value & 63)) violation(VIO_ALIGN, "a table address is not 64-byte aligned");
    if (!strcmp(name, "CRCR_LO") && ((value & ~1u) & 63)) violation(VIO_ALIGN, "CRCR pointer not 64-byte aligned, or a control bit set");
    if (!strcmp(name, "CONFIG") && value > (mmio_r32(4) & 0xff)) violation(VIO_STORE_BITS, "CONFIG above MaxSlots");
    for (unsigned i = 0; i < 4; i++) {
        if (!strcmp(name, lows[i])) lo_written |= 1u << i;
        if (!strcmp(name, highs[i]) && !(lo_written >> i & 1u)) violation(VIO_HIGH_FIRST, name);
    }

    if (W.readback_wrong && !strcmp(name, "ERSTBA_LO")) return;          /* the write is lost */
    {
        uint32_t eint = mmio_r32(OP(4)) & (1u << 3);                    /* USBSTS.EINT is write-1-to-clear: a halt or a run does not clear it, a reset does */
        xhci_wr32(sim.base + offset, value);
        if (!strcmp(name, "USBCMD:STOP") || !strcmp(name, "USBCMD:RS")) mmio_w32(OP(4), mmio_r32(OP(4)) | eint);
    }
    if (!strcmp(name, "USBCMD:HCRST")) {
        if (W.hcrst_stuck) mmio_w32(OP(0), mmio_r32(OP(0)) | 2u);
        else if (W.cnr_after_reset) mmio_w32(OP(4), mmio_r32(OP(4)) | (1u << 11));
        if (W.hcrst_ms) {                                   /* a slow reset: HCRST reads set until the time is up */
            mmio_w32(OP(0), mmio_r32(OP(0)) | 2u);
            hcrst_until = now_ticks + NSEC(W.hcrst_ms) / 1000;
        }
        if (W.cnr_ms) {                                     /* and CNR after it */
            mmio_w32(OP(4), mmio_r32(OP(4)) | (1u << 11));
            cnr_until = now_ticks + NSEC(W.cnr_ms) / 1000;
        }
        reset_done = 1;
        if (W.reset_error) mmio_w32(OP(4), mmio_r32(OP(4)) | (W.reset_error == 1 ? 1u << 2 : 1u << 12));
    } else if (!strcmp(name, "USBCMD:STOP") && W.halt_stuck) {
        mmio_w32(OP(4), mmio_r32(OP(4)) & ~1u);
        sim.running = 1;                                    /* a controller that ignores the halt: it may still be running into its arena */
    } else if (!strcmp(name, "USBCMD:RS")) {
        if (W.run_stuck) mmio_w32(OP(4), mmio_r32(OP(4)) | 1u);
        if (W.eint_at_run >> cur_arena & 1u) mmio_w32(OP(4), mmio_r32(OP(4)) | (1u << 3));
        if (W.knob[K_HSE_RUN] >> cur_arena & 1u) sim_bus_error();
        if (W.knob[K_HCE_RUN] >> cur_arena & 1u) mmio_w32(OP(4), mmio_r32(OP(4)) | (1u << 12));
    }
}

/* ---- Reads: the registers the payload documents, and nothing else --------------------------------------------------------------------------- */

static void port_script(void)
{
    for (unsigned i = 0; i < W.scripts; i++) {
        if ((scripts_done >> i & 1u) || now_ticks < NSEC(W.script[i].at_s)) continue;
        scripts_done |= 1u << i;
        if (W.script[i].win == (unsigned)T) mmio_w32(OP(0x400 + 0x10 * (W.script[i].port - 1)), W.script[i].value);
        else other_port[W.script[i].port - 1] = W.script[i].value;
    }
}

static const unsigned XHC_READS[] = {0x00, 0x04, 0x08, 0x10, 0x14, 0x18, OP(0), OP(4), OP(8), OP(0x18), OP(0x1c), OP(0x30), OP(0x34), OP(0x38),
                                     OP(0x400), OP(0x410), IR(0x08), IR(0x10), IR(0x14), IR(0x18), IR(0x1c)};

/* A slow reset ends when its time is up: HCRST, then CNR, clear in USBCMD and USBSTS. */
static void settle(void)
{
    if (hcrst_until && now_ticks >= hcrst_until) {
        mmio_w32(OP(0), mmio_r32(OP(0)) & ~2u);
        hcrst_until = 0;
    }
    if (cnr_until && now_ticks >= cnr_until) {
        mmio_w32(OP(4), mmio_r32(OP(4)) & ~(1u << 11));
        cnr_until = 0;
    }
}

static int32_t fake_load32(uint64_t addr, uint32_t *out)
{
    uint64_t base = BASE_OF(T), other = BASE_OF(1 - T);
    *out = 0;
    loads++;
    if (addr & 3) return Q1N1_PAYLOAD_LOAD_E_ALIGN;
    if (loads > Q1N1_PAYLOAD_LOADS_MAX) return Q1N1_PAYLOAD_LOAD_E_BUDGET;
    port_script();
    settle();
    if (addr >= base && addr < base + WINDOW) {
        unsigned off = (unsigned)(addr - base), ok = 0;
        if (W.xhc_fault_off && off + 1 == W.xhc_fault_off && loads >= W.xhc_fault_after) return Q1N1_PAYLOAD_LOAD_E_FAULT;
        if (off >= 0xc000 && off < 0xd000) {
            if (W.dwc3_fault) return Q1N1_PAYLOAD_LOAD_E_FAULT;
            *out = off == 0xc120 ? W.gsnpsid : off == 0xc118 ? gsts_model : off == 0xc130 ? berr_lo : off == 0xc134 ? berr_hi : 0;
            if (off != 0xc120 && off != 0xc118 && off != 0xc130 && off != 0xc134) violation(VIO_READ, "an undocumented DWC3 register");
            return 0;
        }
        for (unsigned i = 0; i < sizeof XHC_READS / sizeof XHC_READS[0]; i++) ok |= XHC_READS[i] == off;
        if (!ok) {
            char d[80];
            snprintf(d, sizeof d, "undocumented xHC register 0x%x", off);
            violation(VIO_READ, d);
        }
        *out = xhci_rd32(sim.base + off);
        return 0;
    }
    if (addr >= other && addr < other + WINDOW) {
        unsigned off = (unsigned)(addr - other);
        if (off == 0) *out = W.other_cap0;
        else if (off == 4) *out = (2u << 24) | (8u << 8) | 64u;
        else if (off == OP(0x400) || off == OP(0x410)) *out = other_port[(off - OP(0x400)) / 0x10];
        else violation(VIO_READ, "an undocumented register of the other controller");
        return 0;
    }
    if (addr >= SMMU_BASE && addr < SMMU_BASE + 0x100000) {
        unsigned off = (unsigned)(addr - SMMU_BASE);
        if (W.smmu_fault_off && off == W.smmu_fault_off && loads >= W.smmu_fault_after) return Q1N1_PAYLOAD_LOAD_E_FAULT;
        if (off == 0x20) *out = W.smmu_id0;
        else if (off == 0x24) *out = W.smmu_id1;
        else if (off == 0x48) *out = W.gfsr;
        else if (off == 0x40 || off == 0x44 || off == 0x50) {
            if (!W.gfsr) violation(VIO_READ, "sGFAR or sGFSYNR0 read though sGFSR is zero");
            *out = off == 0x50 ? 0x1234 : 0;
        } else if (off >= 0x800 && off < 0x800 + 4 * 154) {
            unsigned n = (off - 0x800) / 4;
            *out = W.no_smr ? 0 : n == 3 ? 0x80001420u : n == 4 ? 0x80001460u : 0;
        } else if (off >= 0xc00 && off < 0xc00 + 4 * 154) {
            *out = ((off - 0xc00) / 4 == 3 || (off - 0xc00) / 4 == 4) ? 3u : 0;
        } else if (addr >= CB3 && addr < CB3 + 0x1000) {
            unsigned r = (unsigned)(addr - CB3);
            if (r == 0x58) *out = W.cb_fsr;
            else if (r == 0x60 || r == 0x64 || r == 0x68) {
                if (!W.cb_fsr) violation(VIO_READ, "FAR or FSYNR0 read though FSR is zero");
                *out = r == 0x60 ? (uint32_t)W.cb_far : r == 0x64 ? (uint32_t)(W.cb_far >> 32) : 0x46005D;
            } else violation(VIO_READ, "an undocumented context bank register");
        } else {
            violation(VIO_READ, "an undocumented SMMU register");
        }
        return 0;
    }
    violation(VIO_UNKNOWN_WINDOW, "a read outside the three windows");
    return Q1N1_PAYLOAD_LOAD_E_FAULT;
}

uint64_t pl_host_sysreg(const char *name);
uint64_t pl_host_sysreg(const char *name)
{
    if (!strcmp(name, "CurrentEL")) return (uint64_t)W.el << 2;
    if (!strcmp(name, "cntfrq_el0")) return HZ;
    violation(VIO_SYSREG, name);
    return 0;
}

static uint64_t fake_counter(void)
{
    if (++counter_reads > hang_limit) {
        fprintf(stderr, "FAIL: HANG, the payload did not finish in %" PRIu64 " counter reads\n", hang_limit);
        exit(3);
    }
    if (!W.stuck_after || counter_reads <= W.stuck_after) now_ticks += W.tick;
    /* A counter that is set back reads below what it read before; now_ticks stays the true time, which is what the audit's eight seconds are made of. The
     * counter has run for a while before the run, so that a set-back is a subtraction that does not wrap. */
    if (W.back_ticks && ((W.back_after && counter_reads == W.back_after) || (back_countdown && !--back_countdown))) counter_skew += W.back_ticks;
    return COUNTER_BASE + now_ticks - counter_skew;
}

static int in_font(const char *text)
{
    for (; *text; text++)
        if (!((*text >= 'A' && *text <= 'Z') || (*text >= '0' && *text <= '9') || strchr(" :-./=?()_", *text))) return 0;
    return 1;
}

static void fake_puts(const char *line)
{
    if (strlen(line) > 99 || !in_font(line)) {
        if (!bad_lines) snprintf(first_bad, sizeof first_bad, "%s", line);
        bad_lines++;
    }
    if (nlines < LINES_MAX) snprintf(lines[nlines], sizeof lines[0], "%s", line);
    nlines++;
    if (!strncmp(line, "PAYLOAD XHCI NEXT ", 18)) {
        const char *g = line + 18;
        unsigned group = !strncmp(g, "ARENA", 5) ? 1 : !strncmp(g, "RESET", 5) ? 2 : !strncmp(g, "PROGRAM", 7) ? 4 : !strncmp(g, "RUN", 3) ? 8 :
                         !strncmp(g, "NOOP", 4) ? 16 : 0;
        if (group == 1) {
            unsigned id = 0, pages = 0;
            unsigned long long base = 0;
            char name[16];
            armed_model &= 2u;
            attempt_no++;
            phase = 0;
            dma_outside = 0;                /* judged per attempt: an earlier attempt may have been fooled into DMA elsewhere */
            if (sscanf(g, "ARENA %u %15s 0X%llX PAGES %u", &id, name, &base, &pages) == 4) {
                cur_arena = id;
                arena_base = base;
                arena_bytes = (uint64_t)pages * 4096;
                if (narenas_seen < 8) {
                    arenas_seen[narenas_seen].base = base;
                    arenas_seen[narenas_seen].bytes = arena_bytes;
                    narenas_seen++;
                }
            }
        }
        if (group) {
            armed_model |= group;
            armed_at[__builtin_ctz(group)] = now_ticks;
        }
        if (W.stall_at_next && !W.stuck_after) W.stuck_after = counter_reads;
        if (W.back_at_next && !back_armed) {
            back_armed = 1;
            back_countdown = W.back_at_next;
        }
    }
    if (W.stall_in_watch && !W.stuck_after && !strncmp(line, "PAYLOAD XHCI WATCH 30 S", 23)) W.stuck_after = counter_reads;
}

static uint32_t fake_hex(char *dst, uint32_t cap, uint64_t value) { return (uint32_t)q1n1_payload_fmt_hex(dst, cap, value); }

/* ---- The world: the unit as far as it is known, and what each scenario changes ------------------------------------------------------------ */

static void build_map(void)
{
    struct { uint32_t type; uint64_t phys, pages; } d[] = {
        {W.low_missing ? 2u : 7u, 0x80000000u, (0xC3E00000u - 0x80000000u) / 4096}, {2, 0xC3E00000u, 0x9000000u / 4096},
        {2, regions[R_STACK].base, 0x10000 / 4096}, {W.fw_not_free ? 2u : 4u, 0xCF400000u, 0x100000 / 4096},
        {W.high_not_free ? 0u : 7u, UINT64_C(0x880000000), UINT64_C(0x780000000) / 4096}, {11, 0x0a000000u, 0x1000000 / 4096}};
    memset(map_buffer, 0, sizeof map_buffer);
    for (unsigned i = 0; i < sizeof d / sizeof d[0]; i++) {
        memcpy(map_buffer + 48 * i, &d[i].type, 4);
        memcpy(map_buffer + 48 * i + 8, &d[i].phys, 8);
        memcpy(map_buffer + 48 * i + 24, &d[i].pages, 8);
    }
    args.map_base = W.map_missing ? 0 : (uint64_t)(uintptr_t)map_buffer;
    args.map_size = sizeof d;
    args.map_stride = 48;
    args.map_size = sizeof d / sizeof d[0] * 48;
}

void world_default(void)
{
    memset(&W, 0, sizeof W);
    W.gsnpsid = 0x33313130;
    W.hciversion = 0x0110;
    W.caplen_reg = CAPLENGTH;
    W.hcs1 = (2u << 24) | (8u << 8) | 64u;
    W.scratch = 2;
    W.hcc1 = 0x0110FFC5;
    W.dboff_reg = DBOFF;
    W.rtsoff_reg = RTSOFF;
    W.pagesize = 1;
    W.init_sts = T ? 0x1 : 0x11;
    W.iommu = (1u << REGIONS) - 1;
    W.el = 2;
    W.tick = 20000;
    W.smmu_id0 = 0x7C017E9A;
    W.smmu_id1 = 0x6000005F;
    W.cb_fsr = 0x400;
    W.cb_far = UINT64_C(0x953FDF7CF7F7);
    W.other_cap0 = 0x01100020;
    W.code = 13;
}

void world_apply(void)
{
    sim_reset();
    mmio_w32(0x00, (W.hciversion << 16) | W.caplen_reg);
    mmio_w32(0x04, W.hcs1);
    mmio_w32(0x08, ((W.scratch & 31u) << 27) | ((W.scratch >> 5 & 31u) << 21));
    mmio_w32(0x10, W.hcc1);
    mmio_w32(0x14, W.dboff_reg);
    mmio_w32(0x18, W.rtsoff_reg);
    mmio_w32(OP(0), W.init_cmd);
    mmio_w32(OP(4), W.init_sts | (W.cnr_initial ? 1u << 11 : 0));
    mmio_w32(OP(8), W.pagesize);
    mmio_w32(OP(0x400), 0x20002A0);
    mmio_w32(OP(0x410), 0x20002A0);
    sim.running = W.init_cmd & 1u;
    other_port[0] = other_port[1] = 0x20002A0;
    regions_reset();
    memset(lines, 0, sizeof lines);
    memset(stores, 0, sizeof stores);
    nlines = loads = ram_stores = cache_ops = ops_since_dsb = bad_lines = dma_faults = dma_outside = nstores = attempt_no = scripts_done = armed_model = 0;
    violations_mask = gsts_model = berr_lo = berr_hi = 0;
    first_vio[0] = first_bad[0] = 0;
    now_ticks = counter_reads = hcrst_until = cnr_until = counter_skew = 0;
    back_countdown = back_armed = 0;
    arena_base = arena_bytes = cur_arena = phase = lo_written = reset_done = 0;
    memset(arenas_seen, 0, sizeof arenas_seen);
    narenas_seen = 0;
    hang_limit = 6000000;
    memset(&args, 0, sizeof args);
    args.magic = Q1N1_PAYLOAD_ABI_MAGIC;
    args.version = Q1N1_PAYLOAD_ABI_VERSION;
    args.size = sizeof args;
    args.stack_base = regions[R_STACK].base;
    args.stack_size = Q1N1_PAYLOAD_STACK_BYTES;
    args.ops.puts = fake_puts;
    args.ops.hex = fake_hex;
    args.ops.load32 = fake_load32;
    args.ops.counter = fake_counter;
    build_map();
}

/* ---- Running, and what is true of every run ---------------------------------------------------------------------------------------------- */

const char *has_prefix(const char *prefix)
{
    for (unsigned i = 0; i < nlines && i < LINES_MAX; i++)
        if (!strncmp(lines[i], prefix, strlen(prefix))) return lines[i];
    return NULL;
}

int has(const char *line)
{
    for (unsigned i = 0; i < nlines && i < LINES_MAX; i++)
        if (!strcmp(lines[i], line)) return 1;
    return 0;
}

unsigned count_prefix(const char *prefix)
{
    unsigned n = 0;
    for (unsigned i = 0; i < nlines && i < LINES_MAX; i++) n += !strncmp(lines[i], prefix, strlen(prefix));
    return n;
}

static int in_any_arena(uint64_t phys)
{
    for (unsigned i = 0; i < narenas_seen; i++)
        if (phys >= arenas_seen[i].base && phys < arenas_seen[i].base + arenas_seen[i].bytes) return 1;
    return 0;
}

static int arena_clean_outside(void)
{
    /* No byte outside the arenas the attempts named changed, in any region, in DRAM or in the CPU's copy: nothing else was stored to. */
    for (unsigned i = 0; i < REGIONS; i++)
        for (size_t k = 0; k < regions[i].size; k++) {
            uint64_t phys = regions[i].base + k;
            if (!in_any_arena(phys) && (regions[i].dram[k] != 0xA5 || (regions[i].state[k / LINE] == 2 && regions[i].cpu[k] != 0xA5)) && i != R_DECOY) return 0;
        }
    return 1;
}

/* An arena the payload wrote to is zero in DRAM again once the controller is halted; one it never wrote to is as it was. */
static int arenas_back_to_zero(void)
{
    for (unsigned a = 0; a < narenas_seen; a++) {
        struct region *r = find_region(arenas_seen[a].base, 4);
        for (uint64_t k = 0; r && k < arenas_seen[a].bytes; k++) {
            uint8_t byte = r->dram[arenas_seen[a].base - r->base + k];
            if (byte != (arenas_seen[a].stores ? 0 : 0xA5)) return 0;
        }
    }
    return 1;
}

static int generic(const char *label)
{
    const char *end = has_prefix("PAYLOAD XHCI END "), *verdict = has_prefix("PAYLOAD XHCI VERDICT ");
    char joined[STORES_MAX * 14 + 1] = "";
    int refused;
    for (unsigned i = 0; i < nstores; i++) strncat(joined, stores[i].name, 15), strncat(joined, ";", 2);
    snprintf(stores_joined, sizeof stores_joined, "%s", joined);
    if (violations_mask) {
        fprintf(stderr, "FAIL (%s): a rule was broken: %s\n", label, first_vio);
        return 1;
    }
    if (nlines > XHCI_S1_LINE_CAP || nlines > Q1N1_PAYLOAD_LINES_MAX || bad_lines) {
        fprintf(stderr, "FAIL (%s): %u lines, %u not in the font or too long (first: %s)\n", label, nlines, bad_lines, first_bad);
        return 1;
    }
    if (loads > Q1N1_PAYLOAD_LOADS_MAX || loads > XHCI_S1_LOAD_CAP) {
        fprintf(stderr, "FAIL (%s): %u loads\n", label, loads);
        return 1;
    }
    if (ret_value != 0) {
        fprintf(stderr, "FAIL (%s): returned %" PRIu64 "\n", label, ret_value);
        return 1;
    }
    for (unsigned i = 0; i < nlines && i < LINES_MAX; i++)
        if (strncmp(lines[i], "PAYLOAD XHCI ", 13)) {
            fprintf(stderr, "FAIL (%s): a line without the prefix: %s\n", label, lines[i]);
            return 1;
        }
    if (nlines && !verdict && W.el == 2) {
        fprintf(stderr, "FAIL (%s): no VERDICT line\n", label);
        return 1;
    }
    refused = verdict && strstr(verdict, "REFUSED");
    if (refused && (nstores || ram_stores)) {
        fprintf(stderr, "FAIL (%s): a refusal after %u stores and %u RAM stores\n", label, nstores, ram_stores);
        return 1;
    }
    if (!refused && verdict && !end) {
        fprintf(stderr, "FAIL (%s): no END line\n", label);
        return 1;
    }
    if (end) {
        unsigned w = 0, l = 0;
        if (sscanf(strstr(end, "WRITES="), "WRITES=%u LOADS=%u", &w, &l) != 2 || w != nstores || l != loads) {
            fprintf(stderr, "FAIL (%s): END says %s, the model counted %u stores and %u loads\n", label, end, nstores, loads);
            return 1;
        }
        if (strstr(end, "HALTED=YES") && nstores && (sim.running || !(mmio_r32(OP(4)) & 1u) || (mmio_r32(OP(0)) & 1u))) {
            fprintf(stderr, "FAIL (%s): HALTED=YES but the controller runs\n", label);
            return 1;
        }
        if (strstr(end, "HALTED=YES") && !arena_clean_outside()) {
            fprintf(stderr, "FAIL (%s): a byte outside the arena changed\n", label);
            return 1;
        }
        if (strstr(end, "HALTED=YES") && narenas_seen && !arenas_back_to_zero()) {
            fprintf(stderr, "FAIL (%s): an arena is not zero at the end\n", label);
            return 1;
        }
    }
    if (verdict && strstr(verdict, "NOOP_OK") && (dma_outside || (!count_prefix("PAYLOAD XHCI R") && !strstr(end, "LINES_CUT")))) {
        fprintf(stderr, "FAIL (%s): NOOP_OK with DMA outside the arena or no result line\n", label);
        return 1;
    }
    return 0;
}

int go(const char *label)
{
    world_apply();
    ret_value = payload_entry(&args);
    suite_checks++;
    if (getenv("XHCI_TEST_DUMP")) {
        printf("---- %s (return %" PRIu64 ", %u lines, %u stores, %u loads, %u dma faults)\n", label, ret_value, nlines, nstores, loads, dma_faults);
        for (unsigned i = 0; i < nlines && i < LINES_MAX; i++) printf("%s\n", lines[i]);
    }
    return generic(label);
}

int verdict_is(const char *text)
{
    char line[200];
    snprintf(line, sizeof line, "PAYLOAD XHCI VERDICT %s", text);
    return has_prefix(line) != NULL;
}

/* The table the Python test compares with the header and the source of the payload. */
static int suite_registers(void)
{
    for (unsigned i = 0; i < NREGS; i++) printf("REG %s %d 0x%x\n", REGISTERS[i].name, REGISTERS[i].from, REGISTERS[i].off);
    return 0;
}

int main(int argc, char **argv)
{
    static const struct { const char *name; int (*fn)(void); } suites[] = {
        {"nominal", suite_nominal}, {"scratch", suite_scratch}, {"refuse", suite_refuse}, {"faults", suite_faults},
        {"fallback", suite_fallback}, {"watch", suite_watch}, {"edges", suite_edges}, {"gates", suite_gates}, {"fuzz", suite_fuzz}};
    const char *which = XHCI_S1_LINE_CAP < 40u || XHCI_S1_LOAD_CAP < 3800u ? "fuzz" : argc > 1 ? argv[1] : "all";
    unsigned run = 0;
    if (!strcmp(which, "registers")) return suite_registers();
    regions_init();
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (strcmp(which, "all") && strcmp(which, suites[i].name)) continue;
        if (suites[i].fn()) {
            fprintf(stderr, "suite %s FAILED\n", suites[i].name);
            return 1;
        }
        run++;
    }
    if (!run) {
        fprintf(stderr, "no suite named %s\n", which);
        return 2;
    }
    printf("PASS: %u payload xhci suites, %u checks, %" PRIu64 " runs (controller %d)\n", run, checks_count + fail_count, suite_checks, T);
    return 0;
}
