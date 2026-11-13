/* SPDX-License-Identifier: MIT */
/* Surface Pro 11 stick-log survey, stage S0: a read-only look at the USB controller the boot stick sits
 * on (docs/SP11-STICK-LOG.md of the Snapintosh repository: section 3.5/3.6, section 6 stage S0 and
 * Appendix A, which fix the line names and fields printed here; docs/SP11-STK-SURVEY.md in this
 * repository describes the build).
 *
 * Opt-in twice over. Q1N1_SP11_STK_SURVEY (default 0) needs SNAP_PLATFORM_SP11=1 and is an #error
 * without it; with the gate at 0 every file of the survey compiles to nothing and main.c is
 * preprocessed to the same text as without the survey, so the default and the plain SP11 builds are
 * byte-identical to what they were (tools/test-q1n1-sp11-entry.py, DefaultOff). The survey image is a
 * separate build target (platform/uefi/Makefile, STK_SURVEY=1) and runs with the same --el2 argument.
 *
 * What the survey is allowed to do: LOAD. Nothing here stores to a device register, a clock, a
 * power domain, a PHY, an SMMU or an xHCI. The only platform primitive that touches memory is
 * stk_ops.guarded, which main.c backs with live_guarded (the recoverable-fault copy the proxy and the
 * live battery path already use); the survey only ever asks it for STK_G_COPY32 and
 * tools/test-q1n1-sp11-stk.* fail if a store kind is requested.
 *
 * Evidence labels (docs/SP11-STICK-LOG.md): every register offset below is VERIFIED only as "what the
 * pinned Linux source says" (revision 7475ea8b58616b33c04afb976cf0fbaad9dd63fb); that the unit
 * behaves so is INFERRED. Nothing here has run on a Surface Pro 11: hardware NOT RUN. */
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifndef SNAP_PLATFORM_SP11
#define SNAP_PLATFORM_SP11 0
#endif
#ifndef Q1N1_SP11_STK_SURVEY
#define Q1N1_SP11_STK_SURVEY 0
#endif
#if Q1N1_SP11_STK_SURVEY && !SNAP_PLATFORM_SP11
#error "Q1N1_SP11_STK_SURVEY=1 needs SNAP_PLATFORM_SP11=1: the survey reads the Surface Pro 11's windows"
#endif

#if Q1N1_SP11_STK_SURVEY

#include "sp11-fbgop.h"

/* ---- Text: the page font, the 100 character line and the 60 line budget ------------------------- */

/* q1n1's page font has A-Z 0-9 : - . / = ? ( ) _ (main.c alphabet; screen_char folds lower case). A
 * space only advances the cursor. Nothing else is drawn, so nothing else is ever printed. */
#define STK_LINE_MAX 100u
/* Every STK line the survey prints, the repeated P2 lines included (Appendix A: at most 60). */
#define STK_MAX_LINES 60u
/* Ordinary lines stop this many short of the cap, so that the lines that must not be lost (the SMMU
 * block, the truncation notice and the verdict) always have room. */
#define STK_RESERVED_LINES 6u

struct stk_sink {
    /* One finished line, no terminator. main.c mirrors it to the UART and draws it. */
    void (*emit)(void *ctx, const char *line);
    /* Optional, screen only: where the survey is about to read. It rewrites one row in place and is
     * not a line (it is never mirrored and never counted), so a hang can be placed finer than the
     * STK NEXT lines, which Appendix A fixes at block granularity. */
    void (*at)(void *ctx, const char *where);
    void *ctx;
    unsigned lines;     /* lines handed to emit */
    unsigned dropped;   /* lines refused because the budget was spent */
};
/* 1 when the line went out. An essential line may use the whole cap; an ordinary one stops
 * STK_RESERVED_LINES earlier. */
int stk_sink_put(struct stk_sink *sink, const char *line, int essential);
void stk_sink_at(struct stk_sink *sink, const char *where);

/* "0X" and the fewest digits, upper case (value 0 is "0X0"). Returns the length; the text is cut,
 * never overrun, when cap is too small. */
size_t stk_fmt_hex(char *dst, size_t cap, uint64_t value);
size_t stk_fmt_dec(char *dst, size_t cap, uint64_t value);
/* Folds lower case up and replaces everything outside the font with '_'. */
void stk_sanitize(char *text);
/* 1 when every character is in the font or a space. */
int stk_text_ok(const char *text);

/* key=value fields appended to a prefix. A field that would pass 100 characters starts a new line
 * with the same prefix, so a long block is split, never clipped. */
struct stk_line {
    struct stk_sink *sink;
    char buf[STK_LINE_MAX + 1];
    unsigned len, prefix_len, fields;
    int essential;
};
void stk_line_begin(struct stk_line *line, struct stk_sink *sink, const char *prefix, int essential);
void stk_line_word(struct stk_line *line, const char *word);
void stk_line_hex(struct stk_line *line, const char *key, uint64_t value);
void stk_line_dec(struct stk_line *line, const char *key, uint64_t value);
void stk_line_flag(struct stk_line *line, const char *key, int value);
void stk_line_str(struct stk_line *line, const char *key, const char *value);
void stk_line_unknown(struct stk_line *line, const char *key);   /* KEY=? */
void stk_line_end(struct stk_line *line);

/* ---- UEFI device paths (P2). Pure: a byte buffer in, text and numbers out ---------------------------- */

#define STK_DP_MAX_BYTES 512u    /* never read further than this, whatever the path claims */
#define STK_DP_MAX_NODES 32u
#define STK_DP_TEXT_MAX 80u
#define STK_DP_MAX_USB 3u

enum {
    STK_DP_OK = 0,
    STK_DP_NULL,        /* no path */
    STK_DP_MALFORMED,   /* a node shorter than its own header, or a length that is not whole */
    STK_DP_TRUNCATED,   /* ran out of bytes (or nodes) before an end node */
    STK_DP_TEXT_CUT,    /* well formed, but the text does not fit (ends in "...") */
};

struct stk_dp_info {
    int status;
    unsigned nodes;                         /* walked, end node excluded */
    unsigned bytes;                         /* length including the end node, when one was found */
    unsigned usb_nodes;
    uint8_t usb_port[STK_DP_MAX_USB];       /* port index of the first USB nodes, in path order */
    unsigned first_usb_offset;              /* valid when usb_nodes > 0 */
    unsigned last_usb_end;                  /* offset just past the last USB node, valid when usb_nodes > 0 */
    int has_hd;
    unsigned hd_offset;                     /* byte offset of the first hard drive node */
    uint32_t hd_partition;
    uint64_t hd_start, hd_size;
    char text[STK_DP_TEXT_MAX + 1];        /* PCI(81.0)/USB(1.0)/USB(2.0)/HD(1.MBR); other nodes T<type>.<subtype> */
};
/* Reads at most max_bytes (and never more than STK_DP_MAX_BYTES) from dp. */
void stk_dp_walk(const uint8_t *dp, size_t max_bytes, struct stk_dp_info *out);
/* 1 when path `a` (walked to its end node, within a_max) is byte for byte the first `prefix_bytes`
 * of path `b`: how a host controller handle is matched to the front of the stick's path. */
int stk_dp_is_prefix(const uint8_t *a, size_t a_max, const uint8_t *b, size_t b_max, unsigned prefix_bytes);

/* ---- Facts gathered at P2 and the lines they become ------------------------------------------------ */

#define STK_P2_MAX_LINES 16u
#define STK_P2_HC_SHOWN 3u

/* The P2 lines, kept for the EL2 page: the firmware's protocols are gone after ExitBootServices and
 * one photograph has to hold both. Plain text, already within the font. */
struct stk_p2 {
    char line[STK_P2_MAX_LINES][STK_LINE_MAX + 1];
    unsigned count;
    unsigned dropped;
};
void stk_p2_replay(struct stk_sink *sink, const struct stk_p2 *p2);

struct stk_p2_media {
    int present;                    /* Block I/O of the raw disk was found */
    uint64_t last_lba;
    uint32_t block_size;
    int removable, read_only;
};
struct stk_p2_usbio {
    int present;
    uint16_t bcd_usb;               /* the only device descriptor field kept: no vendor, product or serial */
    uint8_t cls, sub, proto;
    int have_in, have_out;
    uint8_t ep_in, ep_out;
    uint16_t mps_in, mps_out;
};
struct stk_p2_hc {
    int pci_io;                     /* the handle has a PCI I/O protocol */
    int bar_ok, class_ok, loc_ok;
    uint64_t bar0;
    uint32_t class_code;            /* base class, sub class, programming interface */
    uint64_t seg, bus, dev, fn;
};
/* PORTSC2 of the baseline: the controller has no second port, it was read, or it has one that could not be. */
enum { STK_P2_NO_PORT2 = 0, STK_P2_PORT2_READ, STK_P2_PORT2_UNREADABLE };
struct stk_p2_baseline {
    int attempted;                  /* an HC handle matched the stick's path and had a PCI I/O */
    const char *skipped;            /* reason, when nothing could be produced */
    int index;                      /* 0 or 1 when BAR 0 equals the usb_1_ss0 / usb_1_ss1 window, else -1 */
    int portsc2;                    /* STK_P2_NO_PORT2, STK_P2_PORT2_READ or STK_P2_PORT2_UNREADABLE */
    uint32_t caplen, usbcmd, usbsts, portsc1, portsc2_value;
    uint64_t crcr, dcbaap;
};

/* The P2 line formatters, one per Appendix A row. Each appends to `sink`. */
void stk_p2_fmt_build(struct stk_sink *sink, const char *stamp);
void stk_p2_fmt_self(struct stk_sink *sink, const struct stk_dp_info *dp);
void stk_p2_fmt_hub(struct stk_sink *sink, const struct stk_dp_info *dp);
void stk_p2_fmt_blk(struct stk_sink *sink, const struct stk_p2_media *media, const struct stk_dp_info *dp);
void stk_p2_fmt_usbio(struct stk_sink *sink, const struct stk_p2_usbio *io, const char *skipped);
void stk_p2_fmt_hc(struct stk_sink *sink, unsigned total, const struct stk_p2_hc *hc, unsigned shown);
void stk_p2_fmt_baseline(struct stk_sink *sink, const struct stk_p2_baseline *b);

/* ---- The EL2 survey ------------------------------------------------------------------------------ */

/* Guarded memory primitive. The shape is main.c's live_guarded(kind, dst, src, size): `size` bytes
 * (a multiple of 4) are copied from `src` to the RAM at `dst` with the recoverable-fault guard on,
 * and the return value is non-zero when the access aborted. STK_G_COPY32 loads from `src`. The other
 * kinds exist in the platform primitive and are forbidden here: STK_G_SET32 is a store to `src`. */
#define STK_G_COPY32 0
#define STK_G_SET32 2

/* Stage-1 attribute class of one page, from q1n1_mmu_attr. */
enum { STK_ATTR_UNKNOWN = 0, STK_ATTR_DEVICE, STK_ATTR_NORMAL, STK_ATTR_NONE };

struct stk_ops {
    int (*guarded)(void *ctx, int kind, uint64_t dst, uint64_t src, uint64_t size);
    int (*attr)(void *ctx, uint64_t phys);
    void *ctx;
};

/* Why a register or memory read produced no value. */
enum {
    STK_OK = 0,
    STK_E_FAULT,        /* the guarded load aborted */
    STK_E_RANGE,        /* outside the window it was asked in, or misaligned */
    STK_E_NO_MAP,       /* no usable memory map: no window can be shown not to be RAM */
    STK_E_MAP_RAM,      /* the memory map calls the window RAM or firmware memory */
    STK_E_UNMAPPED,     /* stage 1 does not map the page */
    STK_E_NOT_DEVICE,   /* stage 1 maps the page Normal: never read device registers through that */
    STK_E_ATTR,         /* the mapping attribute could not be read */
    STK_E_NOT_RAM,      /* a pointer the memory map does not show as RAM */
    STK_E_BUDGET,       /* the read budget of the whole survey is spent */
    STK_E_NOT_READ,     /* never attempted: an earlier read of the same block failed */
};
const char *stk_err_name(int err);

struct stk_reg {
    uint32_t v;
    int err;
};

enum { STK_WIN_GCC = 0, STK_WIN_SMMU, STK_WIN_U0, STK_WIN_U1, STK_WINDOWS };
struct stk_window {
    const char *name;
    uint64_t base, size;
};
extern const struct stk_window stk_windows[STK_WINDOWS];
#define STK_CONTROLLERS 2u

/* Total loads the survey may issue, whatever a register file claims: a backstop behind the bound
 * every walker has of its own. */
#define STK_MAX_READS 2000u

/* Memory map classification. RAM is what a pointer read from a device register may be followed into:
 * loader, boot services, runtime, conventional and ACPI reclaim memory (types 1-7 and 9). A device
 * window may only be listed as reserved, memory mapped I/O or port space (types 0, 11, 12), or not at
 * all; any other descriptor over it means it is memory. */
int stk_type_is_ram(uint32_t type);
int stk_type_allows_device(uint32_t type);
/* Every byte of [base, base + size) is inside RAM descriptors and no other kind overlaps it. */
int stk_map_range_is_ram(const struct q1n1_sp11_gop_map_entry *map, uint32_t count, uint64_t base,
                         uint64_t size);
/* No byte of the range is inside a descriptor that makes it memory. */
int stk_map_range_allows_device(const struct q1n1_sp11_gop_map_entry *map, uint32_t count, uint64_t base,
                                uint64_t size);

/* Gate: from the GDSC and the nine clocks a controller needs (five its own, four shared). */
enum { STK_GATE_ON = 0, STK_GATE_PARTIAL, STK_GATE_OFF, STK_GATE_UNKNOWN };
#define STK_GATE_CLOCKS 9u
int stk_gate(const struct stk_reg *gdscr, const struct stk_reg clk[STK_GATE_CLOCKS]);
const char *stk_gate_name(int gate);

/* xHCI facts the verdict needs. */
#define STK_PORTS_SHOWN 4u
#define STK_SLOTS_SHOWN 3u
#define STK_EP_SHOWN 6u
#define STK_SLOTS_SCANNED 8u
#define STK_XECP_MAX_CAPS 16u
#define STK_XECP_PROTOS 4u

struct stk_port {
    int read;               /* PORTSC was read */
    uint32_t sc;
};
struct stk_slot {
    uint64_t ctx;
    int err;                /* 0, or why the context could not be read (a pointer that is not 64 byte aligned or not RAM) */
    uint32_t route;
    int hub;
    unsigned root_port, speed, state, address, entries;
    unsigned eps;           /* endpoint contexts that are not disabled */
    unsigned shown;         /* of those, kept below */
    struct { unsigned dci, state, type, mps; } ep[STK_EP_SHOWN];
};

enum {
    STK_V_GATED_OFF = 0, STK_V_FAULT, STK_V_NOT_XHCI, STK_V_STICK_RUNNING, STK_V_STICK_HALTED, STK_V_IDLE,
    STK_V_INCONSISTENT,
    /* Not in Appendix A's list, added because the table must hold for every input the survey can
     * produce: a controller that was never read, without any fault, must not be called FAULT or
     * GATED-OFF; and a connected port with no firmware slot must not be called IDLE or STICK-PRESENT. */
    STK_V_UNREAD, STK_V_CONNECTED,
};
const char *stk_verdict_name(int verdict);

struct stk_ctrl_obs {
    int gate;                   /* STK_GATE_* */
    int gcc_fault;              /* a gate register read aborted */
    int fault;                  /* any later load of this controller aborted (MMIO or the DRAM behind it) */
    int id_read;                /* the capability registers were read */
    int xhci_plausible;
    int usbsts_read, usbsts_allones, hch;
    unsigned ports;             /* entries of port[] */
    struct stk_port port[STK_PORTS_SHOWN];
    int slots_read;             /* the slot walk ran */
    unsigned slots;             /* entries of slot[] */
    struct stk_slot slot[STK_SLOTS_SHOWN];
};
int stk_port_inconsistent(uint32_t sc);
int stk_ctrl_verdict(const struct stk_ctrl_obs *obs);

/* SMMU */
enum { STK_SMMU_BYPASS = 0, STK_SMMU_TRANS, STK_SMMU_FAULT, STK_SMMU_UNREAD };
const char *stk_smmu_name(int verdict);
#define STK_STREAMS 2u
#define STK_SMR_MAX 256u            /* ID0.NUMSMRG is 8 bits: the architecture's own bound */

struct stk_stream {
    int scanned;                /* the scan completed */
    int found;
    unsigned index;             /* lowest matching entry */
    unsigned matches;           /* valid entries that match; more than one is a multi-match */
    int s2cr_read;
    unsigned type, cbndx;       /* S2CR of the lowest match: TYPE 0 translate, 1 bypass, 2 fault */
};
struct stk_smmu_obs {
    int global_read;            /* sCR0 and ID0 were read */
    int clientpd, usfcfg;
    struct stk_stream stream[STK_STREAMS];
};
int stk_smmu_verdict(const struct stk_smmu_obs *obs, unsigned stream_mask);

/* Read callback over one window: `off` is an offset inside it. Applies every policy check (window,
 * memory map, mapping attribute) before it loads, and counts. */
typedef int (*stk_rd32_fn)(void *ctx, uint32_t off, uint32_t *value);

/* Bounded xHCI walkers over a read callback. */
struct stk_xecp {
    int status;                 /* STK_OK, or the error that stopped the walk */
    unsigned caps;              /* capabilities visited */
    unsigned protos;
    int truncated;              /* more capabilities than STK_XECP_MAX_CAPS */
    struct { unsigned major, minor, first, count; } proto[STK_XECP_PROTOS];
};
/* xecp: HCCPARAMS1 bits 31:16, a dword offset from the window base. Visits at most
 * STK_XECP_MAX_CAPS capabilities, each strictly after the last, none outside `window_size`. */
void stk_xecp_walk(stk_rd32_fn rd, void *ctx, uint32_t xecp, uint32_t window_size, struct stk_xecp *out);

/* Decoders for the structures the firmware left in DRAM. */
void stk_slot_decode_head(const uint32_t dw[4], struct stk_slot *out);
unsigned stk_port_speed(uint32_t sc);
unsigned stk_port_pls(uint32_t sc);
/* Load `size` bytes (a multiple of 4) of RAM at `phys` into `dst`. The implementation refuses what the
 * memory map does not show as RAM (STK_E_NOT_RAM) before it loads. */
typedef int (*stk_ram_read_fn)(void *ctx, uint64_t phys, void *dst, uint32_t size);
struct stk_slots {
    int status;                 /* STK_OK, or the error that stopped the walk (a fault, or an unusable DCBAAP) */
    unsigned scanned;           /* DCBAA entries examined */
    unsigned nonempty;          /* entries that were not zero */
    unsigned shown;             /* entries of slot[] */
    unsigned slot_id[STK_SLOTS_SHOWN];
    struct stk_slot slot[STK_SLOTS_SHOWN];
};
/* The device context base address array at `dcbaap` (64 byte aligned) and the first STK_SLOTS_SHOWN
 * non-empty contexts of its first `slots` entries (at most STK_SLOTS_SCANNED). `ctxsz` is 32 or 64
 * (HCCPARAMS1.CSZ). */
void stk_slot_walk(stk_ram_read_fn rd, void *ctx, uint64_t dcbaap, unsigned slots, unsigned ctxsz,
                   struct stk_slots *out);
/* The lowest SMR that matches `stream`, over the entries the callback can read. */
struct stk_smr_scan {
    int status;                 /* STK_OK or the error that stopped the scan */
    unsigned scanned;
    struct stk_stream stream[STK_STREAMS];
};
void stk_smr_scan(stk_rd32_fn rd, void *ctx, unsigned numsmrg, int exid, unsigned numsidb,
                  const uint32_t stream_id[STK_STREAMS], struct stk_smr_scan *out);

/* The EL2 survey. Prints P2 again, then MAP, GCC, GATE, the controllers, FWRINGS and SLOT, the SMMU
 * and the verdict, in that order, each block after a STK NEXT line. */
struct stk_el2_args {
    const struct stk_ops *ops;
    const struct stk_p2 *p2;                /* may be NULL */
    const struct q1n1_sp11_gop_map_entry *map;
    uint32_t map_count;
    int map_ok;                             /* the saved memory map parsed */
    uint64_t ram_sample;                    /* an address known to be RAM, for the MAP line */
    struct stk_sink *sink;
};
struct stk_result {
    int verdict[STK_CONTROLLERS];
    int smmu;
    int gate[STK_CONTROLLERS];
    unsigned reads, faults, refusals;
};
void stk_el2_run(const struct stk_el2_args *args, struct stk_result *result);

/* ---- Where the survey lines go on the panel ---------------------------------------------------------- */

#define STK_LAYOUT_RIGHT 0
#define STK_LAYOUT_BELOW 1
/* The widest line of the existing EL2 page, in characters, with a margin. The QEMU test pins it. */
#define STK_PAGE_COLS 90u
struct stk_layout {
    int placement;
    uint32_t scale, col0, row0, rows;
};
/* page_scale: the scale the existing page is drawn at; page_rows: the rows it has used. Right of the
 * page at scale 2 (or 1) when the panel is wide enough, otherwise below it. Starts under the emblem. */
void stk_layout(uint32_t width, uint32_t height, uint32_t page_scale, uint32_t page_rows,
                struct stk_layout *out);

#endif /* Q1N1_SP11_STK_SURVEY */
