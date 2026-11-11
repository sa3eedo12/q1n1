/* SPDX-License-Identifier: MIT */
/* Validation of the Surface Pro 11 USB controller table. See sp11-usb-ports.h for the contract. Pure functions: no
 * allocation, no I/O, no state. Compiled only for SNAP_PLATFORM_SP11. */
#include "sp11-usb-ports.h"

#if SNAP_PLATFORM_SP11

#define PAGE_MASK 0xfffu
/* The monitor's stage 2 is 36 bits wide; nothing at or beyond it can be mapped (docs/SURFACE-PRO-11.md, E3). */
#define IPA_LIMIT (UINT64_C(1) << 36)
/* Hamoa places its DWC3 nodes 2 MiB apart, so a larger claim would reach the neighbour (hamoa.dtsi:5016-5347). */
#define WINDOW_MAX 0x200000u
/* The glue block must not start inside the DWC3 core registers (Linux dwc3-qcom.c SDM845_DWC3_CORE_SIZE) and q1n1
 * touches 0x68 bytes of it at most; Linux maps 0x400 (SDM845_QSCRATCH_SIZE). */
#define CORE_SPAN 0xcd00u
#define QSCRATCH_SPAN 0x400u

/* The two bases usb-ports.c and usb-ebs.h hard-code for the A16. An SP11 controller may sit at one of them only
 * because the descriptor lists it with an independent source (the flag), never because the A16 code has it. */
static const uint64_t a16_hard_coded_base[] = {UINT64_C(0x0a600000), UINT64_C(0x0a800000)};

static int is_a16_base(uint64_t base)
{
    for (unsigned i = 0; i < sizeof(a16_hard_coded_base) / sizeof(a16_hard_coded_base[0]); i++)
        if (a16_hard_coded_base[i] == base) return 1;
    return 0;
}

/* GSNPSID[31:16] is the DWC3 IP family: 0x5533 DWC_usb3, 0x3331 DWC_usb31, 0x3332 DWC_usb32 (Linux core.h:1293-1295). */
static int is_dwc3_family(uint32_t id)
{
    uint32_t family = id >> 16;
    return family == 0x5533u || family == 0x3331u || family == 0x3332u;
}

int q1n1_sp11_usb_table_validate(const struct q1n1_sp11_usb_table *t)
{
    if (!t) return Q1N1_SP11_USB_ERR_NULL;
    if (t->magic != Q1N1_SP11_USB_MAGIC) return Q1N1_SP11_USB_ERR_MAGIC;
    if (t->version != Q1N1_SP11_USB_VERSION) return Q1N1_SP11_USB_ERR_VERSION;
    if (t->count < 1 || t->count > Q1N1_SP11_USB_MAX_PORTS) return Q1N1_SP11_USB_ERR_COUNT;
    for (uint32_t i = t->count; i < Q1N1_SP11_USB_MAX_PORTS; i++) {
        const struct q1n1_sp11_usb_port *p = &t->port[i];
        if (p->dwc3_base || p->window_size || p->qscratch_offset || p->expect_gsnpsid || p->flags)
            return Q1N1_SP11_USB_ERR_RESERVED;
    }
    for (uint32_t i = 0; i < t->count; i++) {
        const struct q1n1_sp11_usb_port *p = &t->port[i];
        if (p->flags & ~Q1N1_SP11_USB_PORT_KNOWN_FLAGS) return Q1N1_SP11_USB_ERR_FLAGS;
        if (!p->dwc3_base || (p->dwc3_base & PAGE_MASK)) return Q1N1_SP11_USB_ERR_BASE;
        if (!p->window_size || (p->window_size & PAGE_MASK) || p->window_size > WINDOW_MAX)
            return Q1N1_SP11_USB_ERR_WINDOW;
        /* base + size >= limit, without forming a sum that could wrap. */
        if (p->dwc3_base >= IPA_LIMIT || p->window_size >= IPA_LIMIT - p->dwc3_base) return Q1N1_SP11_USB_ERR_LIMIT;
        if ((p->qscratch_offset & 3u) || p->qscratch_offset < CORE_SPAN || p->window_size < QSCRATCH_SPAN ||
            p->qscratch_offset > p->window_size - QSCRATCH_SPAN)
            return Q1N1_SP11_USB_ERR_QSCRATCH;
        if (p->expect_gsnpsid && !is_dwc3_family(p->expect_gsnpsid)) return Q1N1_SP11_USB_ERR_IDENTITY;
        if (is_a16_base(p->dwc3_base) && !(p->flags & Q1N1_SP11_USB_PORT_A16_BASE_LISTED))
            return Q1N1_SP11_USB_ERR_A16_BASE;
    }
    for (uint32_t i = 0; i < t->count; i++)
        for (uint32_t j = i + 1; j < t->count; j++) {
            const struct q1n1_sp11_usb_port *a = &t->port[i], *b = &t->port[j];
            if (a->dwc3_base < b->dwc3_base + b->window_size && b->dwc3_base < a->dwc3_base + a->window_size)
                return Q1N1_SP11_USB_ERR_OVERLAP;
        }
    return Q1N1_SP11_USB_OK;
}

const char *q1n1_sp11_usb_error_name(int code)
{
    static const char *const names[Q1N1_SP11_USB_ERR_COUNT_ALL] = {
        "OK", "NULL", "MAGIC", "VERSION", "COUNT", "RESERVED", "FLAGS", "BASE",
        "WINDOW", "LIMIT", "QSCRATCH", "IDENTITY", "A16_BASE", "OVERLAP"};
    return code >= 0 && code < Q1N1_SP11_USB_ERR_COUNT_ALL ? names[code] : "UNKNOWN";
}

const struct q1n1_sp11_usb_port *q1n1_sp11_usb_port_for_base(const struct q1n1_sp11_usb_table *t, uint64_t base)
{
    if (!t) return 0;
    for (uint32_t i = 0; i < t->count && i < Q1N1_SP11_USB_MAX_PORTS; i++)
        if (t->port[i].dwc3_base == base) return &t->port[i];
    return 0;
}

int q1n1_sp11_usb_controller_ok(const struct q1n1_sp11_usb_port *port, uint32_t gsnpsid, uint32_t cap_dword,
                                uint32_t hcsparams1)
{
    if (!port) return Q1N1_SP11_USB_ID_FAMILY;
    if (port->expect_gsnpsid ? gsnpsid != port->expect_gsnpsid : !is_dwc3_family(gsnpsid))
        return Q1N1_SP11_USB_ID_FAMILY;
    /* xHCI 1.x: the operational registers follow CAPLENGTH, which covers at least the 0x20-byte capability block. */
    uint32_t caplength = cap_dword & 0xffu;
    if (caplength < 0x20u || (caplength & 3u)) return Q1N1_SP11_USB_ID_CAPLENGTH;
    uint32_t hciversion = cap_dword >> 16;
    if (hciversion < 0x0100u || hciversion >= 0x0200u) return Q1N1_SP11_USB_ID_HCIVERSION;
    uint32_t max_ports = hcsparams1 >> 24;
    if (!max_ports || max_ports > 16u) return Q1N1_SP11_USB_ID_MAXPORTS;
    return Q1N1_SP11_USB_ID_OK;
}

#endif /* SNAP_PLATFORM_SP11 */
