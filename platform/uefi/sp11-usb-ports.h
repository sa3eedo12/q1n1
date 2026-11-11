/* SPDX-License-Identifier: MIT */
/* USB host-controller table for the Surface Pro 11 (SNAP_PLATFORM_SP11), derived from a board descriptor.
 *
 * The A16 build hard-codes its two DWC3 bases and the glue offset in usb-ports.c. Nothing about the Surface Pro 11
 * may be taken from those constants: its controllers come from a table that Snapintosh's tools/sp11_usb_ports.py
 * derives from the board descriptor and writes as C (`emit-c`), and that this unit validates again before any
 * register is read. Every value in the table is INFERRED from a public device tree through the descriptor; no
 * hardware has confirmed one. The default build (SNAP_PLATFORM_SP11 undefined) compiles none of this and is
 * byte-identical to the build without it.
 *
 * ABI shared with tools/sp11_usb_ports.py (TABLE_MAGIC, TABLE_VERSION, the field order and the error names). Change
 * both together and bump the version. Unknown values fail closed: nothing here supplies a default for a base, a
 * window, a glue offset or a core id. `expect_gsnpsid` is the one field allowed to be 0, meaning "not measured yet":
 * the core is then accepted by IP family only, and the exact id is recorded for the run report.
 *
 * Threading and ownership: the table is read-only data linked into the image; validation is pure and reentrant. */
#pragma once
#include <stdint.h>

#ifndef SNAP_PLATFORM_SP11
#define SNAP_PLATFORM_SP11 0
#endif

#if SNAP_PLATFORM_SP11

#define Q1N1_SP11_USB_MAGIC UINT64_C(0x3142535531315053) /* "SP11USB1", little endian */
#define Q1N1_SP11_USB_VERSION 1u
#define Q1N1_SP11_USB_MAX_PORTS 2u

/* Controller stays a host: the Denali device tree sets dr_mode = "host" on both enabled controllers and a device-mode
 * takeover forces a VBUS override that the Type-C firmware did not ask for. INFERRED; relax only with evidence. */
#define Q1N1_SP11_USB_PORT_HOST_ONLY (1u << 0)
/* The base equals one of the A16's hard-coded bases and the descriptor lists it with an independent source. */
#define Q1N1_SP11_USB_PORT_A16_BASE_LISTED (1u << 1)
#define Q1N1_SP11_USB_PORT_KNOWN_FLAGS (Q1N1_SP11_USB_PORT_HOST_ONLY | Q1N1_SP11_USB_PORT_A16_BASE_LISTED)

struct q1n1_sp11_usb_port {
    uint64_t dwc3_base;       /* physical address of the xHCI/DWC3 register block; a descriptor range base */
    uint32_t window_size;     /* bytes the descriptor claims for it; a 4 KiB multiple, at most 2 MiB */
    uint32_t qscratch_offset; /* Qualcomm glue block, relative to dwc3_base; inside the window */
    uint32_t expect_gsnpsid;  /* exact core id (offset 0xc120) once measured, else 0 */
    uint32_t flags;
};

struct q1n1_sp11_usb_table {
    uint64_t magic;
    uint32_t version;
    uint32_t count;           /* entries in use; the rest must be all zero */
    struct q1n1_sp11_usb_port port[Q1N1_SP11_USB_MAX_PORTS];
};
_Static_assert(sizeof(struct q1n1_sp11_usb_port) == 24, "table entry layout is shared with sp11_usb_ports.py");
_Static_assert(sizeof(struct q1n1_sp11_usb_table) == 64, "table layout is shared with sp11_usb_ports.py");

/* Result of validating a table. The first rule broken wins, in this order; the names are shared with the host tool. */
enum {
    Q1N1_SP11_USB_OK = 0,
    Q1N1_SP11_USB_ERR_NULL,
    Q1N1_SP11_USB_ERR_MAGIC,
    Q1N1_SP11_USB_ERR_VERSION,
    Q1N1_SP11_USB_ERR_COUNT,
    Q1N1_SP11_USB_ERR_RESERVED,
    Q1N1_SP11_USB_ERR_FLAGS,
    Q1N1_SP11_USB_ERR_BASE,
    Q1N1_SP11_USB_ERR_WINDOW,
    Q1N1_SP11_USB_ERR_LIMIT,
    Q1N1_SP11_USB_ERR_QSCRATCH,
    Q1N1_SP11_USB_ERR_IDENTITY,
    Q1N1_SP11_USB_ERR_A16_BASE,
    Q1N1_SP11_USB_ERR_OVERLAP,
    Q1N1_SP11_USB_ERR_COUNT_ALL /* number of codes, not an error */
};

/* Why a live controller was refused (q1n1_sp11_usb_controller_ok). */
enum {
    Q1N1_SP11_USB_ID_OK = 0,
    Q1N1_SP11_USB_ID_FAMILY,    /* GSNPSID[31:16] is not a DWC3 IP family, or an exact id was expected and differs */
    Q1N1_SP11_USB_ID_CAPLENGTH, /* xHCI CAPLENGTH below 0x20 or not a multiple of 4 */
    Q1N1_SP11_USB_ID_HCIVERSION,/* xHCI interface version outside 1.0.x */
    Q1N1_SP11_USB_ID_MAXPORTS   /* HCSPARAMS1.MaxPorts is 0 or above 16 */
};

/* Pure check of a table; no memory outside it is read. Returns Q1N1_SP11_USB_OK or the first error. */
int q1n1_sp11_usb_table_validate(const struct q1n1_sp11_usb_table *table);
const char *q1n1_sp11_usb_error_name(int code);

/* The entry whose dwc3_base is `base`, or NULL. The table must already have validated. */
const struct q1n1_sp11_usb_port *q1n1_sp11_usb_port_for_base(const struct q1n1_sp11_usb_table *table, uint64_t base);

/* Judge raw register reads from a candidate controller: GSNPSID (base+0xc120), the dword at base+0 (CAPLENGTH in bits
 * 7:0, HCIVERSION in 31:16) and HCSPARAMS1 (base+4). The A16 equality checks are not used: the exact SP11 core
 * release is UNKNOWN until X2 reads it, and the xHCI limits below come from the xHCI specification. */
int q1n1_sp11_usb_controller_ok(const struct q1n1_sp11_usb_port *port, uint32_t gsnpsid, uint32_t cap_dword,
                                uint32_t hcsparams1);

/* The table in use. A build generated by tools/sp11_usb_ports.py defines it next to the data; a host test defines its
 * own. Never defined by q1n1 itself, so a build without a derived table does not link. */
const struct q1n1_sp11_usb_table *q1n1_sp11_usb_table_get(void);

#endif /* SNAP_PLATFORM_SP11 */
