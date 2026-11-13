/* SPDX-License-Identifier: MIT */
/* q1n1 Qualcomm UEFI payload (ASUS Zenbook A16 UX3607OA, BIOS312).
 *   (no option)   preflight: report entry EL, GOP and SPCR, return to the shell.
 *   --el2         framebuffer foothold after ExitBootServices (optional --uart, --fault-test).
 *   --boot        A16 USB boot window (firmware USB0 CDC ACM), then the m1n1-protocol
 *                 proxy at EL2 over q1n1's own DWC3 driver (1209:316D A16-Q1N1-EL2).
 *   --uart-proxy  the same proxy over an SPCR PL011 (QEMU validation path).
 * No Apple boot_args, ADT, AIC, DART or CPU chicken bits are used. Firmware
 * mappings stay in place; after EBS only ResetSystem is called.
 */
#include "efi.h"
#include "fbcon.h"
#include "console.h"
#include "sysinfo.h"
#include "gicv3.h"
#include "xhci.h"
#include "ncm.h"
#include "ncm-proxy.h"
#include "usb-ports.h"
#include "q1n1-bootinfo.h"
#include "boot-window.h"
#include "q1n1-proxy.h"
#include "preload.h"
#include "gpt-survey.h"
#include "live-battery.h"
#include "gpu-el2.h"
#include "call-service.h"

#ifndef SNAP_PLATFORM_SP11
#define SNAP_PLATFORM_SP11 0
#endif
#if SNAP_PLATFORM_SP11
#include "sp11-ebs-ranges.h"
#include "sp11-fbgop.h"
#include "sp11-stage-table.h"
#endif
/* The read-only stick-log survey (docs/SP11-STK-SURVEY.md): default off, the survey image is its own
 * build target (platform/uefi/Makefile, STK_SURVEY=1). With the gate at 0 nothing below the #if lines
 * that mention it reaches the compiler, so every other build is unchanged. */
#ifndef Q1N1_SP11_STK_SURVEY
#define Q1N1_SP11_STK_SURVEY 0
#endif
#if Q1N1_SP11_STK_SURVEY
#if !SNAP_PLATFORM_SP11
#error "Q1N1_SP11_STK_SURVEY=1 needs SNAP_PLATFORM_SP11=1: the survey reads the Surface Pro 11's windows"
#endif
#ifdef Q1N1_STAGE
#error "the stick-log survey is part of the EFI image, not of a chainloaded stage"
#endif
#include "sp11-stk-efi.h"
#endif

static struct {
    volatile uint32_t *pixels;
    uint32_t width, height, stride, format, red, green, blue;
    uint32_t row, col, scale;
    uint64_t bytes;
} fb;
static struct {
    uint64_t base;
    uint32_t irq;
    uint8_t type, baud;
    int enabled;
} uart;
static uint64_t before_el, map_size, map_stride;
static int fault_test;
extern const uint8_t q1n1_logo[];
extern void q1n1_enter(void) __attribute__((noreturn));

#define MODE_FOOTHOLD 0
#define MODE_USB_PROXY 1
#define MODE_UART_PROXY 2
#define HEAP_BYTES (64u << 20)
#define MAP_BYTES (256u * 1024)
#define STAGE_BYTES (16u << 20)
#define EFI_ALLOCATE_ADDRESS 2
#if SNAP_PLATFORM_SP11
/* A fixed, human-readable identity for whichever photograph has to answer "which code ran"
 * (docs/SP11-Q1N1-BOOT-STUDY.md section 5.5): this patch's own branch/workstream label plus the
 * commit the Makefile stamped (SP11_BUILD_STAMP; UNSTAMPED when built outside a checkout). */
#ifndef SP11_BUILD_STAMP
#define SP11_BUILD_STAMP "UNSTAMPED"
#endif
#define SP11_BUILD_ID "sa3eedo12-sp11-boot (WS-B B1) " SP11_BUILD_STAMP
#endif

/* Written for an unhandled exception and passed as the REQ_BOOT info pointer. */
struct q1n1_exception {
    uint64_t regs[31], sp, spsr, elr, esr, far, el, vector;
};

static int mode;
static struct efi_runtime_services *rt;
static uint64_t hz, proxy_start;
static struct qdwc3_saved saved;
#ifndef Q1N1_STAGE
static struct q1n1_boot_result boot;
#endif
static struct q1n1_bootinfo info;
static uint64_t preload_verify(uint64_t index)
{
    if(info.preload_size!=sizeof(struct q1n1_preload_cache)) return 0;
    return (uint64_t)q1n1_preload_verify((const void *)(uintptr_t)info.preload_table,index);
}
static struct q1n1_exception exception;
static const struct q1n1_io *proxy_io;
static struct q1n1_gic gic;
/* The tick can interrupt the polled loop, so the driver has one owner at a time. */
static int in_exception, resetting;
static uint32_t status_row = 16;
static struct q1n1_usb_ports *usb_ports;
static int no_cdc;

static uint64_t stage_config;       /* logo choice etc., patched into a stage image */
extern const uint8_t q1n1_asahi_logo[];
/* The low two bits of the config word. The dragon is the default: centred where
 * m1n1 puts its logo, or parked in a corner per generation so a chainload is
 * visible at a glance. The upstream Asahi mark remains selectable. */
#define LOGO_CENTRE 0
#define LOGO_CORNER 1
#define LOGO_NONE 2
#define LOGO_ASAHI 3
/* Refresh only idle ports; preserve the transport carrying this request. */
uint64_t q1n1_xhci_retry(void) { return q1n1_usb_ports_refresh(usb_ports); }
uint64_t q1n1_ncm_proxy_run(uint64_t seconds)
{
    (void)seconds;
    if (!usb_ports) return ~0ull;
    uint64_t frames = 0;
    for (unsigned i = 0; i < Q1N1_USB_PORTS; i++) frames += usb_ports->port[i].proxy.stats.frames_in;
    return frames; /* Both links are already served continuously. */
}

void *memcpy(void *dest, const void *src, size_t n)
{
    uint8_t *d = dest; const uint8_t *s = src;
    while (n--) *d++ = *s++;
    return dest;
}
void *memset(void *dest, int value, size_t n)
{
    uint8_t *d = dest;
    while (n--) *d++ = (uint8_t)value;
    return dest;
}
static int same(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;
    while (n--) if (*x++ != *y++) return 0;
    return 1;
}
static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t get64(const uint8_t *p) { return get32(p) | (uint64_t)get32(p + 4) << 32; }
static uint64_t current_el(void) { uint64_t v; __asm__ volatile("mrs %0, CurrentEL" : "=r"(v)); return v >> 2; }
static uint64_t counter(void) { uint64_t v; __asm__ volatile("mrs %0, cntpct_el0" : "=r"(v)); return v; }
static uint64_t frequency(void) { uint64_t v; __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v)); return v; }

/* Out-of-band service for a long P_CALL (call-service.h). The stop port is
 * answered by the ordinary poll too, so an idle q1n1 says "not armed". */
static struct q1n1_call_state call_state;
static volatile int call_polling;   /* inside q1n1_usb_ports_call_poll */
/* The payload's console view, only for the duration of its POLL. */
static struct q1n1_console_view *console_view;
static uint32_t stop_port(void *ctx, const uint8_t *data, uint32_t length, uint8_t *reply)
{
    if (q1n1_console_request(data, length))
        return q1n1_console_datagram(ctx, console_view, data, length, reply, NCM_SIDE_REPLY_MAX);
    return q1n1_stop_datagram(ctx, data, length, counter(), reply);
}
_Static_assert(NCM_SIDE_REPLY_MAX >= Q1N1_CONSOLE_REPLY_MAX, "a console reply fits the side port");
static void call_stats(void)
{
    struct ncm_side_stats side;
    ncm_proxy_side_stats(&side);
    call_state.dropped_proxy = side.call_dropped;
    call_state.replies = side.replies;
    call_state.reply_failures = side.reply_failures;
}
/* bootinfo call_service: only from the CPU inside the current P_CALL. */
uint64_t q1n1_call_service(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3);
uint64_t q1n1_call_service(uint64_t op, uint64_t a1, uint64_t a2, uint64_t a3)
{
    uint64_t result;
    switch (op) {
    case Q1N1_CALL_ARM: result = q1n1_call_arm(&call_state, a1); break;
    case Q1N1_CALL_DISARM: result = q1n1_call_disarm(&call_state); break;
    case Q1N1_CALL_POLL:
        if (call_state.polls != UINT64_MAX) call_state.polls++;
        console_view = (struct q1n1_console_view *)(uintptr_t)a3;
        if (console_view && console_view->magic == Q1N1_CONSOLE_VIEW_MAGIC &&
            console_view->polls_seen != UINT64_MAX)
            console_view->polls_seen++;
        call_polling = 1;
        q1n1_usb_ports_call_poll(usb_ports);
        call_polling = 0;
        console_view = 0;
        result = q1n1_call_take(&call_state, (void *)(uintptr_t)a1, a2);
        break;
    default: result = Q1N1_CALL_E_OP; break;
    }
    call_stats();
    return result;
}
static uint32_t rd(uint32_t offset) { return *(volatile uint32_t *)(uintptr_t)(uart.base + offset); }
static void wr(uint32_t offset, uint32_t v)
{
    *(volatile uint32_t *)(uintptr_t)(uart.base + offset) = v;
    __asm__ volatile("dsb sy" ::: "memory");
}
static int poll(uint32_t offset, uint32_t mask, uint32_t expected)
{
    uint64_t start = counter(), timeout = frequency() / 100; /* 10 ms, plus iteration cap */
    for (unsigned n = 0; n < 1000000; n++) {
        if ((rd(offset) & mask) == expected) return 1;
        if (counter() - start > timeout) break;
    }
    return 0;
}

/* Only use an already configured UART. Do not guess clocks, pins or power domains.
 * SPCR 0x13 describes Qualcomm GENI. Register definitions: Linux geni-se.h and
 * qcom_geni_serial.c. This small polled sequence is independently implemented.
 */
static int uart_byte(uint8_t c)
{
    if (!uart.enabled) return 0;
    if (uart.type == 3) { /* ARM PL011, used by QEMU */
        if (!poll(0x18, 1u << 5, 0)) goto failed;
        wr(0, c);
        return 1;
    }
    if (uart.type == 0x13) {
        /* Require UART firmware, FIFO mode, and an idle main sequencer. */
        if (((rd(0x68) >> 8) & 0xff) != 2 || (rd(0x258) & 1) ||
            !poll(0x40, 1, 0)) goto failed;
        wr(0x618, 1);       /* Clear previous command completion. */
        wr(0x270, 1);       /* One byte for this transfer. */
        wr(0x600, 1u << 27);/* UART START_TX. */
        wr(0x700, c);       /* First packed byte in the FIFO word. */
        if (!poll(0x610, 1, 1)) {
            wr(0x604, 2);   /* Abort this timed out command. */
            poll(0x610, 1u << 5, 1u << 5);
            wr(0x618, 1u << 5);
            goto failed;
        }
        wr(0x618, 1);
        return 1;
    }
failed:
    uart.enabled = 0;
    return 0;
}

/* A compact independently authored 5x7 console font, row-major. */
static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:-./=?()_";
static const uint8_t glyphs[][7] = {
    {14,17,17,31,17,17,17},{30,17,17,30,17,17,30},{14,17,16,16,16,17,14},
    {30,17,17,17,17,17,30},{31,16,16,30,16,16,31},{31,16,16,30,16,16,16},
    {14,17,16,23,17,17,15},{17,17,17,31,17,17,17},{14,4,4,4,4,4,14},
    {7,2,2,2,2,18,12},{17,18,20,24,20,18,17},{16,16,16,16,16,16,31},
    {17,27,21,21,17,17,17},{17,25,21,19,17,17,17},{14,17,17,17,17,17,14},
    {30,17,17,30,16,16,16},{14,17,17,17,21,18,13},{30,17,17,30,20,18,17},
    {15,16,16,14,1,1,30},{31,4,4,4,4,4,4},{17,17,17,17,17,17,14},
    {17,17,17,17,17,10,4},{17,17,17,21,21,21,10},{17,17,10,4,10,17,17},
    {17,17,10,4,4,4,4},{31,1,2,4,8,16,31},
    {14,17,19,21,25,17,14},{4,12,4,4,4,4,14},{14,17,1,2,4,8,31},
    {30,1,1,14,1,1,30},{2,6,10,18,31,2,2},{31,16,16,30,1,1,30},
    {14,16,16,30,17,17,14},{31,1,2,4,8,8,8},{14,17,17,14,17,17,14},
    {14,17,17,15,1,1,14},{0,4,4,0,4,4,0},{0,0,0,31,0,0,0},
    {0,0,0,0,0,4,4},{1,2,2,4,8,8,16},{0,0,31,0,31,0,0},
    {14,17,1,2,4,0,4},{2,4,8,8,8,4,2},{8,4,2,2,2,4,8},
    {0,0,0,0,0,0,31}
};
_Static_assert(sizeof(glyphs) / sizeof(glyphs[0]) == sizeof(alphabet) - 1, "font size");

static uint32_t component(uint8_t value, uint32_t mask)
{
    if (!mask) return 0;
    unsigned shift = 0;
    while (!(mask & 1)) { mask >>= 1; shift++; }
    return (uint32_t)(((uint64_t)value * mask / 255) << shift);
}
static uint32_t color(uint32_t rgb)
{
    return component((uint8_t)(rgb >> 16), fb.red) |
           component((uint8_t)(rgb >> 8), fb.green) | component((uint8_t)rgb, fb.blue);
}
static void pixel(uint32_t x, uint32_t y, uint32_t value)
{
    if (fb.pixels && x < fb.width && y < fb.height) fb.pixels[(uint64_t)y * fb.stride + x] = value;
}
static void rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t rgb)
{
    uint32_t v = color(rgb);
    for (uint32_t j = 0; j < h && y + j < fb.height; j++)
        for (uint32_t i = 0; i < w && x + i < fb.width; i++) pixel(x + i, y + j, v);
    __asm__ volatile("dsb sy" ::: "memory");
}
static void screen_char(char c)
{
    if (!fb.pixels) return;
    if (c == '\r') return;
    if (c == '\n') { fb.col = 0; fb.row++; return; }
    if (c >= 'a' && c <= 'z') c -= 32;
    if (20 + (fb.col + 1) * 6 * fb.scale >= fb.width) { fb.col = 0; fb.row++; }
    uint32_t y = 20 + fb.row * 9 * fb.scale;
    if (y + 7 * fb.scale >= fb.height) return;
    for (unsigned g = 0; g < sizeof(alphabet) - 1; g++) if (alphabet[g] == c) {
        for (unsigned j = 0; j < 7; j++) for (unsigned i = 0; i < 5; i++)
            if (glyphs[g][j] & (1u << (4 - i)))
                rect(20 + fb.col * 6 * fb.scale + i * fb.scale, y + j * fb.scale,
                     fb.scale, fb.scale, 0xe8edf5);
        break;
    }
    fb.col++;
}
static void out(const char *s)
{
    while (*s) {
        if (*s == '\n') uart_byte('\r');
        uart_byte((uint8_t)*s);
        screen_char(*s++);
    }
}
static void hex(uint64_t v)
{
    char s[19] = "0X0000000000000000";
    for (unsigned i = 0; i < 16; i++) { s[17-i] = "0123456789ABCDEF"[v & 15]; v >>= 4; }
    out(s);
}
static void field(const char *label, uint64_t v) { out(label); hex(v); out("\n"); }
/* The inverse of component(), for compositing against what is already drawn. */
static uint8_t channel(uint32_t value, uint32_t mask)
{
    if (!mask) return 0;
    unsigned shift = 0;
    while (!(mask & 1)) { mask >>= 1; shift++; }
    return (uint8_t)((uint64_t)((value >> shift) & mask) * 255 / mask);
}
/* Premultiplied source-over, so the emblem lands on the firmware's screen as a
 * dragon rather than as a dragon in a black box. */
static void draw_logo_at(uint32_t left, uint32_t top)
{
    if (fb.width < 600 || fb.height < 280 || !fb.pixels) return;
    for (unsigned y = 0; y < 256; y++) for (unsigned x = 0; x < 256; x++) {
        const uint8_t *p = q1n1_logo + (y * 256 + x) * 4;
        uint32_t a = p[3];
        if (!a) continue;
        uint32_t r = p[0], g = p[1], b = p[2];
        if (a < 255 && left + x < fb.width && top + y < fb.height) {
            uint32_t under = fb.pixels[(uint64_t)(top + y) * fb.stride + left + x], inv = 255 - a;
            r += (uint32_t)channel(under, fb.red) * inv / 255;
            g += (uint32_t)channel(under, fb.green) * inv / 255;
            b += (uint32_t)channel(under, fb.blue) * inv / 255;
        }
        pixel(left + x, top + y, color(r << 16 | g << 8 | b));
    }
}
static void draw_logo(void) { draw_logo_at(fb.width - 276, 20); }
/* Each chainloaded generation parks the logo in a different corner, so the
 * screen says at a glance which one is running. All four avoid the text area. */
static void draw_logo_for_generation(uint64_t generation)
{
    uint32_t right = fb.width > 296 ? fb.width - 276 : 20;
    uint32_t bottom = fb.height > 296 ? fb.height - 276 : 20;
    uint32_t middle = fb.height > 296 ? fb.height / 2 - 128 : 20;
    switch (generation & 3) {
    case 0: draw_logo_at(right, 20); break;
    case 1: draw_logo_at(right, bottom); break;
    case 2: draw_logo_at(20, bottom); break;
    default: draw_logo_at(right, middle); break;
    }
}

#ifndef Q1N1_STAGE
static int checksum(const uint8_t *p, uint32_t n)
{
    uint8_t sum = 0;
    while (n--) sum += *p++;
    return !sum;
}
static int table_valid(const uint8_t *p)
{
    uint32_t n = get32(p + 4);
    return n >= 36 && n <= 1024 * 1024 && checksum(p, n);
}
static void find_uart(struct efi_system_table *st)
{
    const efi_guid acpi = {0x8868e871,0xe4f1,0x11d3,{0xbc,0x22,0,0x80,0xc7,0x3c,0x88,0x81}};
    for (uint64_t i = 0; i < st->table_count; i++) {
        if (!same(&st->tables[i].guid, &acpi, sizeof(acpi))) continue;
        const uint8_t *rsdp = st->tables[i].table;
        if (!same(rsdp,"RSD PTR ",8) || !checksum(rsdp,20) || rsdp[15] < 2) continue;
        uint32_t length = get32(rsdp + 20);
        if (length < 36 || length > 4096 || !checksum(rsdp,length)) continue;
        info.acpi_rsdp = (uintptr_t)rsdp;
        const uint8_t *xsdt = (const void *)(uintptr_t)get64(rsdp + 24);
        if (!xsdt || !same(xsdt,"XSDT",4) || !table_valid(xsdt)) continue;
        uint32_t size = get32(xsdt + 4);
        for (uint32_t off = 36; off + 8 <= size; off += 8) {
            const uint8_t *t = (const void *)(uintptr_t)get64(xsdt + off);
            if (!t || !same(t,"SPCR",4) || !table_valid(t) || get32(t+4) < 80) continue;
            /* GAS must describe 32-bit system-memory access with no bit offset. */
            if (t[40] != 0 || t[41] != 32 || t[42] != 0 || (t[43] != 0 && t[43] != 3 && t[43] != 32)) continue;
            uart.type = t[36]; uart.base = get64(t+44); uart.irq = get32(t+54); uart.baud = t[58];
            if (uart.base & 3) uart.base = 0;
            return;
        }
    }
}
static void find_smbios(struct efi_system_table *st)
{
    const efi_guid smbios3 = {0xf2fd1544,0x9794,0x4a2c,{0x99,0x2e,0xe5,0xbb,0xcf,0x20,0xe3,0x94}};
    for (uint64_t i = 0; i < st->table_count; i++)
        if (same(&st->tables[i].guid, &smbios3, sizeof(smbios3))) info.smbios3 = (uintptr_t)st->tables[i].table;
}
#if SNAP_PLATFORM_SP11
static int sp11_gop_status = Q1N1_SP11_GOP_ABSENT, sp11_gop_rule = Q1N1_SP11_GOP_RULE_NONE;
/* 128 KiB, 16-byte aligned: the size and alignment of probes/uefi/probe_main.c's own memory-map
 * buffer (Snapintosh repository), which holds this unit's 226-descriptor, 10848-byte map with
 * more than ten times to spare. The entry array holds as many descriptors as the buffer can (40
 * bytes is the smallest UEFI defines), so any map GetMemoryMap accepts into the buffer also fits
 * the array and q1n1_sp11_gop_map_parse's TOO_MANY refusal is a backstop, not an expected path.
 * An earlier 24 KiB buffer capped at 512 entries and dropped the end of a longer map silently. */
#define SP11_GOP_MAP_BUF_BYTES (128u * 1024u)
#define SP11_GOP_MAX_MAP_ENTRIES (SP11_GOP_MAP_BUF_BYTES / 40u)
/* Shared by find_framebuffer (before any allocation) and sp11_report_ebs (just before
 * ExitBootServices): each fully rewrites it, so neither sees the other's entries. */
static struct q1n1_sp11_gop_map_entry sp11_map_entries[SP11_GOP_MAX_MAP_ENTRIES];
/* The handle-enumeration buffer, pre-sized and caller-owned, not grown: a count this image
 * cannot represent is refused (count capped below), never silently truncated without saying so.
 * 32 matches probes/uefi/probe_main.c's own PROBE_MAX_GOP_HANDLES -- the same bound, for the same
 * reason (ample headroom over any GOP handle count a real system publishes). */
#define SP11_GOP_MAX_RAW_HANDLES 32u
/* Everything find_framebuffer saw, kept for sp11_report_gop: a refusal on a unit with no serial
 * console and no way to re-run interactively has to say why on the one photograph a hardware
 * attempt yields, and the plain text console it prints on needs no framebuffer. */
static struct {
    efi_status locate_status, map_status;
    uint64_t handle_bytes, map_bytes, map_stride;
    uint32_t map_count, count;
    int map_parse, check[Q1N1_SP11_GOP_MAX_CANDIDATES];
    struct q1n1_sp11_gop_candidate cand[Q1N1_SP11_GOP_MAX_CANDIDATES];
    uint32_t overlaps[Q1N1_SP11_GOP_MAX_CANDIDATES];
    struct q1n1_sp11_gop_map_entry first_overlap[Q1N1_SP11_GOP_MAX_CANDIDATES];
} sp11_gop_diag;
/* Replaces the single, unvalidated locate_protocol() call below with the two-tier,
 * memory-map-validated selection proven under the UEFI Shell on this unit (docs/
 * SP11-Q1N1-BOOT-STUDY.md section 8.2): every GOP the firmware offers is examined, the
 * console's own GOP wins if it passes validation (SEL=CONSOLE), otherwise every candidate is
 * judged as if it were the console and a single agreeing framebuffer wins (SEL=SAME) -- never a
 * guess among disagreeing candidates (AMBIGUOUS GOP, nothing drawn). sp11_gop_status/
 * sp11_gop_rule are read back by proxy_main's own early diagnostic line (section 5.5).
 *
 * Enumeration uses LocateHandle with a caller-supplied, pre-sized buffer (the exact call style
 * probes/uefi/probe_main.c's gather_gop already uses and that is OBSERVED to find this unit's GOP
 * handles under the UEFI Shell, 2026-11-11/12), not LocateHandleBuffer (a different boot service
 * that internally allocates its own buffer via AllocatePool): a first hardware attempt with
 * LocateHandleBuffer found it returning no handles at all for this exact protocol GUID on this
 * unit, while the probe's LocateHandle call succeeds for the same GUID in the same shell session.
 * Nothing here explains that difference (both are standard UEFI boot services; this unit's own
 * firmware is not public), so the safer engineering choice is the mechanism already proven on
 * this hardware, not a further, unverified theory about why the other one failed. */
static void find_framebuffer(struct efi_system_table *st)
{
    efi_guid guid = {0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
    efi_handle handles[SP11_GOP_MAX_RAW_HANDLES];
    uint64_t size = sizeof handles;
    sp11_gop_diag.locate_status = st->boot->locate_handle(EFI_BY_PROTOCOL, &guid, NULL, &size, handles);
    sp11_gop_diag.handle_bytes = size;
    if (sp11_gop_diag.locate_status) {
        sp11_gop_status = Q1N1_SP11_GOP_ABSENT;
        return;
    }
    uint64_t handle_count = size / sizeof(efi_handle);
    if (handle_count > SP11_GOP_MAX_RAW_HANDLES) handle_count = SP11_GOP_MAX_RAW_HANDLES;
    static uint8_t map_buf[SP11_GOP_MAP_BUF_BYTES] __attribute__((aligned(16)));
    struct q1n1_sp11_gop_map_entry *map_entries = sp11_map_entries;
    uint64_t map_size = sizeof map_buf, map_key = 0, map_stride = 0;
    uint32_t map_version = 0, map_count = 0;
    sp11_gop_diag.map_status = st->boot->get_memory_map(&map_size, map_buf, &map_key, &map_stride, &map_version);
    sp11_gop_diag.map_parse = Q1N1_SP11_MAP_EMPTY;
    if (!sp11_gop_diag.map_status)
        sp11_gop_diag.map_parse = q1n1_sp11_gop_map_parse(map_buf, map_size, map_stride, map_entries,
                                                          SP11_GOP_MAX_MAP_ENTRIES, &map_count);
    sp11_gop_diag.map_bytes = map_size;
    sp11_gop_diag.map_stride = map_stride;
    sp11_gop_diag.map_count = map_count;

    struct q1n1_sp11_gop_candidate *cand = sp11_gop_diag.cand;
    uint32_t count = 0;
    for (uint64_t i = 0; i < handle_count && count < Q1N1_SP11_GOP_MAX_CANDIDATES; i++) {
        struct efi_gop *gop = NULL;
        if (st->boot->handle_protocol(handles[i], &guid, (void **)&gop) || !gop || !gop->mode || !gop->mode->info)
            continue;
        struct efi_gop_info *gi = gop->mode->info;
        cand[count].is_console = handles[i] == st->console_out_handle;
        cand[count].base = gop->mode->framebuffer;
        cand[count].size_bytes = gop->mode->framebuffer_size;
        cand[count].width = gi->width; cand[count].height = gi->height;
        cand[count].pixels_per_scanline = gi->stride; cand[count].pixel_format = gi->format;
        count++;
    }
    sp11_gop_diag.count = count;
    for (uint32_t i = 0; i < count; i++) {
        sp11_gop_diag.check[i] = q1n1_sp11_gop_check(map_entries, map_count, &cand[i]);
        uint64_t end = cand[i].base + (cand[i].size_bytes ? cand[i].size_bytes : 4);
        for (uint32_t m = 0; m < map_count; m++) {
            uint64_t m_end = map_entries[m].base + map_entries[m].pages * 4096u;
            if (map_entries[m].base >= end || m_end <= cand[i].base) continue;
            if (!sp11_gop_diag.overlaps[i]) sp11_gop_diag.first_overlap[i] = map_entries[m];
            sp11_gop_diag.overlaps[i]++;
        }
    }

    struct q1n1_sp11_gop_result result;
    q1n1_sp11_gop_select(map_entries, map_count, cand, count, &result);
    sp11_gop_status = result.status;
    sp11_gop_rule = result.rule;
    if (result.status != Q1N1_SP11_GOP_OK) return;

    const struct q1n1_sp11_gop_candidate *c = &cand[result.index];
    fb.pixels = (void *)(uintptr_t)c->base;
    fb.bytes = c->size_bytes;
    fb.width = c->width; fb.height = c->height; fb.stride = c->pixels_per_scanline; fb.format = c->pixel_format;
    fb.red = c->pixel_format == 0 ? 0xff : 0xff0000;
    fb.green = 0xff00;
    fb.blue = c->pixel_format == 0 ? 0xff0000 : 0xff;
    fb.scale = fb.width >= 1600 ? 3 : 2;
}
#else
static void find_framebuffer(struct efi_system_table *st)
{
    efi_guid guid = {0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
    struct efi_gop *gop = NULL;
    if (st->boot->locate_protocol(&guid, NULL, (void **)&gop) || !gop || !gop->mode || !gop->mode->info) return;
    struct efi_gop_info *info = gop->mode->info;
    if (gop->mode->info_size < sizeof(*info) || info->format > 2 ||
        !info->width || !info->height || info->width > info->stride ||
        (uint64_t)info->stride * info->height > gop->mode->framebuffer_size / 4 ||
        !gop->mode->framebuffer) return;
    fb.pixels = (void *)(uintptr_t)gop->mode->framebuffer;
    fb.bytes = gop->mode->framebuffer_size;
    fb.width = info->width; fb.height = info->height; fb.stride = info->stride; fb.format = info->format;
    fb.red = info->format == 0 ? 0xff : 0xff0000;
    fb.green = 0xff00;
    fb.blue = info->format == 0 ? 0xff0000 : 0xff;
    if (info->format == 2) { fb.red = info->red; fb.green = info->green; fb.blue = info->blue; }
    fb.scale = fb.width >= 1600 ? 3 : 2;
}
#endif /* SNAP_PLATFORM_SP11 */
static int option(struct efi_loaded_image *image, const char *word)
{
    if (!image || !image->options || image->options_size > 65536) return 0;
    unsigned n = image->options_size / 2;
    for (unsigned i = 0; i < n && image->options[i]; i++) {
        if (i && image->options[i-1] != ' ') continue;
        unsigned j = 0;
        while (word[j] && i+j < n && image->options[i+j] == (uint8_t)word[j]) j++;
        if (!word[j] && (i+j == n || !image->options[i+j] || image->options[i+j] == ' ')) return 1;
    }
    return 0;
}
static void firmware_out(struct efi_system_table *st, const char *s)
{
    char16 chunk[120];
    while (*s) {
        unsigned i = 0;
        while (*s && i < 117) { if (*s == '\n') chunk[i++] = '\r'; chunk[i++] = (uint8_t)*s++; }
        chunk[i] = 0;
        if (st->console_out) st->console_out->output(st->console_out, chunk);
    }
}
#if SNAP_PLATFORM_SP11
/* Report text is built into a buffer (never printed piecemeal) so the same bytes can go to the
 * firmware console now and be drawn again on the ExitBootServices failure page, which repaints the
 * whole screen and would otherwise erase them. Append-only and truncating: it cannot overrun. */
struct sp11_text { char buf[2048]; unsigned len; };
static void txt_str(struct sp11_text *t, const char *s)
{
    while (*s && t->len < sizeof t->buf - 1) t->buf[t->len++] = *s++;
    t->buf[t->len] = 0;
}
static void txt_hex(struct sp11_text *t, uint64_t v)
{
    char s[19] = "0x";
    unsigned digits = 1;
    for (uint64_t rest = v >> 4; rest; rest >>= 4) digits++;
    for (unsigned i = 0; i < digits; i++) s[2 + digits - 1 - i] = "0123456789ABCDEF"[(v >> (4 * i)) & 15];
    s[2 + digits] = 0;
    txt_str(t, s);
}
static void txt_dec(struct sp11_text *t, uint64_t v)
{
    char s[21];
    unsigned i = sizeof s - 1;
    s[i] = 0;
    do { s[--i] = (char)('0' + v % 10); v /= 10; } while (v);
    txt_str(t, s + i);
}
/* sp11_report_ebs's text. Kept, not just printed: the ExitBootServices failure page and the --el2
 * success page both repaint the whole screen, and each shows it again. */
static struct sp11_text sp11_ebs_text;

/* Reads one system register. Only ever expanded for a register this code reads at EL2 after
 * checking CurrentEL: at EL1 an EL2 register read is UNDEFINED and would take q1n1's exception
 * path instead of drawing the page. */
#define SP11_SYSREG(name) ({ uint64_t value_; __asm__ volatile("mrs %0, " #name : "=r"(value_)); value_; })
static const char *bit_text(uint64_t value, unsigned bit) { return (value >> bit) & 1 ? "1" : "0"; }

/* The EL2 state slbounce's return left the CPU in, read-only, for the post-ExitBootServices page. Until
 * this ran, the VHE host state (E2H and TGE set, stage 2 off) was INFERRED from the X2 test image's
 * T01 read, not seen from q1n1's own entry. The register set is the one the de-VHE decision and any
 * monitor entry depend on. Deliberately absent: CNTVOFF_EL2 and CNTPOFF_EL2, whose accesses the
 * stalled X2 timer test (T03) touched and Linux treats as broken on Oryon X1 (SURFACE-PRO-11.md
 * E17): nothing here is allowed to wedge the core. TTBR1_EL2 is read only when E2H is set, the one
 * case where it is part of the translation regime; it is spelled by encoding because the assembler
 * accepts the name only with FEAT_VHE enabled in the target.
 *
 * The page font has capital letters, digits and : - . / = ? ( ) _ only, so flags are key=value. */
static void sp11_report_el2_state(void)
{
    uint64_t hcr = SP11_SYSREG(hcr_el2), sctlr = SP11_SYSREG(sctlr_el2);
    out("EL2 STATE (READ ONLY)\n");
    out("HCR_EL2 "); hex(hcr);
    out(" E2H="); out(bit_text(hcr, 34)); out(" TGE="); out(bit_text(hcr, 27));
    out(" VM="); out(bit_text(hcr, 0)); out(" RW="); out(bit_text(hcr, 31)); out("\n");
    out("SCTLR_EL2 "); hex(sctlr);
    out(" M="); out(bit_text(sctlr, 0)); out(" C="); out(bit_text(sctlr, 2));
    out(" I="); out(bit_text(sctlr, 12)); out(" WXN="); out(bit_text(sctlr, 19));
    out(" EE="); out(bit_text(sctlr, 25)); out("\n");
    field("TCR_EL2 ", SP11_SYSREG(tcr_el2));
    field("TTBR0_EL2 ", SP11_SYSREG(ttbr0_el2));
    if ((hcr >> 34) & 1) field("TTBR1_EL2 ", SP11_SYSREG(S3_4_C2_C0_1));
    field("MAIR_EL2 ", SP11_SYSREG(mair_el2));
    field("VBAR_EL2 ", SP11_SYSREG(vbar_el2));
    field("CPTR_EL2 ", SP11_SYSREG(cptr_el2));
    field("CNTHCTL_EL2 ", SP11_SYSREG(cnthctl_el2));
    field("CNTFRQ_EL0 ", SP11_SYSREG(cntfrq_el0));
    field("MPIDR_EL1 ", SP11_SYSREG(mpidr_el1));
    field("DAIF ", SP11_SYSREG(daif));
    field("SPSEL ", SP11_SYSREG(spsel));
}

/* Redraws "UPTIME n S" on a fixed row once per heartbeat, so a single photograph taken long after
 * the page appeared shows how long the core has been running (a blinking block alone shows only
 * that it is). Drawn straight to the screen, never through out(): a once-a-second line must not be
 * mirrored to the UART. The cursor is restored so nothing printed later moves. */
static void sp11_draw_uptime(uint32_t row, uint64_t seconds)
{
    char digits[21];
    unsigned i = sizeof digits - 1;
    digits[i] = 0;
    do { digits[--i] = (char)('0' + seconds % 10); seconds /= 10; } while (seconds);
    uint32_t saved_row = fb.row, saved_col = fb.col;
    rect(20, 20 + row * 9 * fb.scale, 32 * 6 * fb.scale, 9 * fb.scale, 0x080b10);
    fb.row = row; fb.col = 0;
    for (const char *s = "UPTIME "; *s; s++) screen_char(*s);
    for (const char *s = digits + i; *s; s++) screen_char(*s);
    screen_char(' '); screen_char('S');
    fb.row = saved_row; fb.col = saved_col;
}
/* The facts find_framebuffer acted on, on the plain text console (no framebuffer needed). Printed
 * whether or not a GOP was accepted: on a unit with no serial console, one photograph of a refusal
 * has to distinguish "no map", "map too short", "wrong candidate" and "type rejected" by itself. */
static void sp11_report_gop(struct efi_system_table *st)
{
    static struct sp11_text text;
    struct sp11_text *t = &text;
    t->len = 0;
    txt_str(t, "SP11 GOP: locate_handle status "); txt_hex(t, sp11_gop_diag.locate_status);
    if (sp11_gop_diag.locate_status) {
        txt_str(t, ", size "); txt_dec(t, sp11_gop_diag.handle_bytes); txt_str(t, "\n");
        firmware_out(st, t->buf);
        return;
    }
    txt_str(t, ", "); txt_dec(t, sp11_gop_diag.handle_bytes / sizeof(efi_handle));
    txt_str(t, " handles, "); txt_dec(t, sp11_gop_diag.count); txt_str(t, " with a mode\n");
    txt_str(t, "SP11 GOP: map status "); txt_hex(t, sp11_gop_diag.map_status);
    txt_str(t, ", "); txt_str(t, q1n1_sp11_map_status_name(sp11_gop_diag.map_parse));
    txt_str(t, ", "); txt_dec(t, sp11_gop_diag.map_bytes);
    txt_str(t, " bytes, stride "); txt_dec(t, sp11_gop_diag.map_stride);
    txt_str(t, ", "); txt_dec(t, sp11_gop_diag.map_count); txt_str(t, " entries\n");
    for (uint32_t i = 0; i < sp11_gop_diag.count && i < 4; i++) {
        const struct q1n1_sp11_gop_candidate *c = &sp11_gop_diag.cand[i];
        txt_str(t, "SP11 GOP: #"); txt_dec(t, i);
        txt_str(t, c->is_console ? " console " : " other ");
        txt_dec(t, c->width); txt_str(t, "x"); txt_dec(t, c->height);
        txt_str(t, " stride "); txt_dec(t, c->pixels_per_scanline);
        txt_str(t, " fmt "); txt_dec(t, c->pixel_format); txt_str(t, "\n");
        txt_str(t, "SP11 GOP: #"); txt_dec(t, i);
        txt_str(t, " base "); txt_hex(t, c->base);
        txt_str(t, " bytes "); txt_hex(t, c->size_bytes);
        txt_str(t, " -> "); txt_str(t, q1n1_sp11_gop_status_name(sp11_gop_diag.check[i]));
        txt_str(t, "\nSP11 GOP: #"); txt_dec(t, i);
        txt_str(t, " map overlaps "); txt_dec(t, sp11_gop_diag.overlaps[i]);
        if (sp11_gop_diag.overlaps[i]) {
            txt_str(t, ", first: type "); txt_dec(t, sp11_gop_diag.first_overlap[i].type);
            txt_str(t, " attr "); txt_hex(t, sp11_gop_diag.first_overlap[i].attribute);
            txt_str(t, " base "); txt_hex(t, sp11_gop_diag.first_overlap[i].base);
            txt_str(t, " pages "); txt_hex(t, sp11_gop_diag.first_overlap[i].pages);
        }
        txt_str(t, "\n");
    }
    txt_str(t, "SP11 GOP: select "); txt_str(t, q1n1_sp11_gop_status_name(sp11_gop_status));
    txt_str(t, ", rule "); txt_str(t, q1n1_sp11_gop_rule_name(sp11_gop_rule)); txt_str(t, "\n");
    firmware_out(st, t->buf);
}
#endif /* SNAP_PLATFORM_SP11 */
#endif /* !Q1N1_STAGE */

/* ---- Post-EBS services shared by the proxy modes ---- */

uint32_t qdwc3_rd(uintptr_t address) { return *(volatile uint32_t *)address; }
void qdwc3_wr(uintptr_t address, uint32_t value) { *(volatile uint32_t *)address = value; }
void qdwc3_delay_us(uint64_t us)
{
    uint64_t start = counter(), wait = hz * us / 1000000 + 1;
    while (counter() - start < wait) __asm__ volatile("yield");
}
static void wait_seconds(unsigned seconds)
{
    uint64_t start = counter();
    while (counter() - start < hz * seconds) __asm__ volatile("yield");
}

/* The xHCI host driver's platform hooks. Separate from the DWC3 gadget's so a
 * native harness can substitute a simulated controller for either one. */
uint32_t xhci_rd32(uintptr_t address) { return *(volatile uint32_t *)address; }
void xhci_wr32(uintptr_t address, uint32_t value) { *(volatile uint32_t *)address = value; }
uint64_t xhci_rd64(uintptr_t address) { return *(volatile uint64_t *)address; }
void xhci_wr64(uintptr_t address, uint64_t value) { *(volatile uint64_t *)address = value; }
void xhci_delay_us(uint64_t microseconds) { qdwc3_delay_us(microseconds); }
uint64_t xhci_now_us(void) { return hz ? counter() * 1000000u / hz : 0; }
static void reset_now(void) __attribute__((noreturn));
static void reset_now(void)
{
    if (!resetting) {
        resetting = 1;
        q1n1_gic_stop(&gic);
        /* Present a clean USB disconnect so the Mac notices the reboot at once. */
        q1n1_usb_ports_stop(usb_ports);
    }
    if (rt && rt->reset_system) rt->reset_system(0, 0, 0, NULL);
    __asm__ volatile("mov x0, #0x0009\n movk x0, #0x8400, lsl #16\n smc #0" ::: "x0", "x1", "x2", "x3", "memory");
    for (;;) __asm__ volatile("wfe");
}

uint64_t q1n1_platform_ticks(void) { return counter(); }
uint64_t q1n1_platform_hz(void) { return hz; }
uint64_t q1n1_platform_bootargs(void) { return (uintptr_t)&info; }
uint64_t q1n1_platform_base(void) { return info.image_base; }
void q1n1_platform_reboot(void) { reset_now(); }

/* SError accounting for the proxy (q1n1-proxy.h). PSTATE.A stays set: the
 * point is to find an SError that an access left pending, not to take it in
 * whatever code next unmasks. */
static int serror_mechanism = -1;
static volatile int serror_window;
static volatile uint64_t serror_window_esr, serror_window_hits;
#define DISR_A (UINT64_C(1) << 31)
#define ISR_A (UINT64_C(1) << 8)

uint64_t q1n1_platform_serror_mechanism(void)
{
    if (serror_mechanism < 0) {
        uint64_t pfr0;
        __asm__ volatile("mrs %0, id_aa64pfr0_el1" : "=r"(pfr0));
        serror_mechanism = (pfr0 >> 28) & 15 ? Q1N1_SERROR_RAS : Q1N1_SERROR_ISR;
    }
    return (uint64_t)serror_mechanism;
}

int q1n1_platform_serror_poll(uint64_t *syndrome, int *still_pending)
{
    uint64_t disr = 0, isr;
    int found = 0;
    /* Let the access complete first: an error response reaches the core only
     * once the transaction does. */
    __asm__ volatile("dsb sy\n isb" ::: "memory");
    if (q1n1_platform_serror_mechanism() == Q1N1_SERROR_RAS) {
        /* ESB (hint #16) with PSTATE.A set defers a pending physical SError:
         * its syndrome lands in DISR_EL1 (s3_0_c12_c1_1) and it stops being
         * pending. Both encodings assemble without +ras. */
        __asm__ volatile("hint #16\n isb\n mrs %0, s3_0_c12_c1_1" : "=r"(disr) : : "memory");
        if (disr & DISR_A) {
            *syndrome = disr;
            found = 1;
            __asm__ volatile("msr s3_0_c12_c1_1, xzr\n isb" ::: "memory");
        }
    }
    __asm__ volatile("mrs %0, isr_el1" : "=r"(isr));
    if (isr & ISR_A) {
        /* Still pending (no RAS, or ESB could not defer it): take it here, where
         * q1n1_exception expects it, instead of wherever A is cleared next. */
        serror_window_hits = 0;
        serror_window = 1;
        __asm__ volatile("msr daifclr, #4\n isb\n nop\n msr daifset, #4\n isb" ::: "memory");
        serror_window = 0;
        if (serror_window_hits) {
            if (!found) *syndrome = serror_window_esr;
            found = 1;
        }
        __asm__ volatile("mrs %0, isr_el1" : "=r"(isr));
    }
    *still_pending = (isr & ISR_A) != 0;
    return found;
}

/* ---- Live battery (live-battery.h): memory access for the GLINK client ----
 * Everything is read through the proxy's leaf helpers under
 * Q1N1_GUARD_RETURN, so an address the EL2 tables do not map comes back as a
 * refusal. The previous guard and fault count are restored for the proxy. */
void q1n1_memcpy64(uint64_t dst, uint64_t src, uint64_t size);
void q1n1_memcpy32(uint64_t dst, uint64_t src, uint64_t size);
void q1n1_memset32(uint64_t dst, uint64_t value, uint64_t size);
static int live_guarded(int kind, uint64_t dst, uint64_t src, uint64_t size)
{
    uint64_t guard = q1n1_exc_guard, count = q1n1_exc_count;
    q1n1_exc_count = 0;
    q1n1_exc_guard = Q1N1_GUARD_RETURN;
    if (kind == 0) q1n1_memcpy32(dst, src, size);
    else if (kind == 1) q1n1_memcpy64(dst, src, size);
    else q1n1_memset32(dst, src, size);
    __asm__ volatile("dsb sy" ::: "memory");
    int faulted = q1n1_exc_count != 0;
    q1n1_exc_guard = guard;
    q1n1_exc_count = count;
    return faulted ? Q1N1_LIVE_EFAULT : 0;
}
static int live_read(void *ctx, void *dst, uint64_t phys, uint32_t size)
{
    (void)ctx;
    if ((phys & 3) || (size & 3) || ((uintptr_t)dst & 3)) return Q1N1_LIVE_EFAULT;
    return live_guarded(0, (uintptr_t)dst, phys, size);
}
static int live_write32(void *ctx, uint64_t phys, uint32_t value)
{
    (void)ctx;
    if (phys & 3) return Q1N1_LIVE_EFAULT;
    return live_guarded(2, phys, value, 4);
}
static int live_read64(void *ctx, uint64_t phys, uint64_t *value)
{
    (void)ctx;
    return live_guarded(1, (uintptr_t)value, phys, 8);
}
static volatile uint8_t *live_map(void *ctx, uint64_t phys, uint64_t size)
{
    (void)ctx; (void)size;
    return (volatile uint8_t *)(uintptr_t)phys;   /* firmware's identity map at EL2 */
}
static int live_attr(void *ctx, uint64_t phys, uint32_t *attr)
{
    (void)ctx;
    uint64_t sctlr, ttbr, tcr, mair;
    if (current_el() == 2) {
        __asm__ volatile("mrs %0, sctlr_el2" : "=r"(sctlr));
        __asm__ volatile("mrs %0, ttbr0_el2" : "=r"(ttbr));
        __asm__ volatile("mrs %0, tcr_el2" : "=r"(tcr));
        __asm__ volatile("mrs %0, mair_el2" : "=r"(mair));
    } else {
        __asm__ volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
        __asm__ volatile("mrs %0, ttbr0_el1" : "=r"(ttbr));
        __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr));
        __asm__ volatile("mrs %0, mair_el1" : "=r"(mair));
    }
    if (!(sctlr & 1)) { *attr = 0; return 0; }   /* MMU off: every access is Device */
    return q1n1_mmu_attr(ttbr, tcr, mair, phys, live_read64, 0, attr);
}
static int live_in_memory_map(void *ctx, uint64_t phys, uint64_t size)
{
    (void)ctx;
    if (!info.memory_map || !info.memory_map_stride || info.memory_map_stride < 40) return 0;
    for (uint64_t at = 0; at + info.memory_map_stride <= info.memory_map_size; at += info.memory_map_stride) {
        const uint8_t *d = (const uint8_t *)(uintptr_t)(info.memory_map + at);
        uint64_t start = get64(d + 8), pages = get64(d + 24);
        if (phys >= start && pages < (1ull << 40) && phys + size <= start + pages * 4096) return 1;
    }
    return 0;
}
static uint64_t live_now_us(void *ctx)
{
    (void)ctx;
    uint64_t t = counter();
    return hz ? t / hz * 1000000u + t % hz * 1000000u / hz : 0;
}
static void live_relax(void *ctx) { (void)ctx; qdwc3_delay_us(10); }
static const struct q1n1_live_platform live_platform = {
    .read = live_read, .write32 = live_write32, .map = live_map, .attr = live_attr,
    .in_memory_map = live_in_memory_map, .now_us = live_now_us, .relax = live_relax,
};
/* bootinfo battery_call: x0 flags, x1 timeout ms, x2 SMEM host, x3/x4 SMEM
 * base/size overrides. Returns 0 or a negative status (live-battery.h). */
uint64_t q1n1_battery_call(uint64_t flags, uint64_t timeout_ms, uint64_t host, uint64_t base, uint64_t size);
uint64_t q1n1_battery_call(uint64_t flags, uint64_t timeout_ms, uint64_t host, uint64_t base, uint64_t size)
{
    if (!hz) return (uint64_t)(int64_t)Q1N1_LIVE_ECLOCK;   /* every deadline is in counter time */
    return (uint64_t)(int64_t)q1n1_live_battery_run(&live_platform, flags, timeout_ms, host, base, size);
}

/* ---- Adreno Stage 3 (gpu-el2.h): the GPU arena and the guarded SMC ---- */
static uint64_t gpu_exclude[7][2];
static int gpu_attr(uint64_t phys, uint32_t *attr) { return live_attr(0, phys, attr); }
static void gpu_delay(uint64_t microseconds) { qdwc3_delay_us(microseconds); }
/* x0..x7 in and out. Under Q1N1_GUARD_SKIP an SMC that is UNDEFINED at EL2
 * (SCR_EL3.SMD) is stepped over and counted instead of stopping the payload. */
static int gpu_smc(uint64_t r[8])
{
    uint64_t guard = q1n1_exc_guard, count = q1n1_exc_count;
    q1n1_exc_count = 0;
    q1n1_exc_guard = Q1N1_GUARD_SKIP;
    register uint64_t x0 __asm__("x0") = r[0], x1 __asm__("x1") = r[1], x2 __asm__("x2") = r[2];
    register uint64_t x3 __asm__("x3") = r[3], x4 __asm__("x4") = r[4], x5 __asm__("x5") = r[5];
    register uint64_t x6 __asm__("x6") = r[6], x7 __asm__("x7") = r[7];
    __asm__ volatile("smc #0"
                     : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4), "+r"(x5), "+r"(x6), "+r"(x7)
                     :
                     : "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "memory");
    int trapped = q1n1_exc_count != 0;
    q1n1_exc_guard = guard;
    q1n1_exc_count = count;
    r[0] = x0; r[1] = x1; r[2] = x2; r[3] = x3; r[4] = x4; r[5] = x5; r[6] = x6; r[7] = x7;
    return trapped;
}
/* Q1N1_GPU_STORE32 (gpu-el2.h): the line holding phys is clean and invalid
 * before the store, so the store fills it fresh from DRAM, and it is cleaned
 * and invalidated straight after, so what the GMU wrote to the rest of the
 * line in the meantime is only at risk for one line fill, not a round trip. */
static void gpu_store32(uint64_t phys, uint32_t value)
{
    __asm__ volatile("dsb sy\n dc civac, %0\n dsb sy" : : "r"(phys) : "memory");
    *(volatile uint32_t *)(uintptr_t)phys = value;
    __asm__ volatile("dsb sy\n dc civac, %0\n dsb sy" : : "r"(phys) : "memory");
}
/* A new arena (gpu-el2.h "A fresh arena"): 64-bit zero stores, then clean
 * and invalidate every line to the point of coherency, so the GPU sees zeros
 * and no dirty line is left to be evicted over what it writes later. Used
 * before ExitBootServices (UEFI's identity map) and by a claim at EL2 (the
 * claim has already checked the range is mapped Normal). */
static void gpu_zero(uint64_t phys, uint64_t size)
{
    volatile uint64_t *p = (volatile uint64_t *)(uintptr_t)phys;
    for (uint64_t n = 0; n < size / 8; n++) p[n] = 0;
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uint64_t line = UINT64_C(4) << (ctr >> 16 & 0xf);
    __asm__ volatile("dsb sy" ::: "memory");
    for (uint64_t at = phys & ~(line - 1); at < phys + size; at += line)
        __asm__ volatile("dc civac, %0" : : "r"(at) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}
static void gpu_setup(void)
{
    /* q1n1's own memory. None of it is Conventional in the final map, so
     * this is defence in depth for a claim, not the mechanism. */
    const uint64_t ranges[7][2] = {
        {info.heap_base, info.heap_size}, {info.dma_base, info.dma_size}, {info.stage_base, info.stage_size},
        {info.image_base, info.image_size}, {info.memory_map, info.memory_map_size},
        {info.preload_table, info.preload_size}, {info.fb_base, info.fb_size},
    };
    for (unsigned n = 0; n < 7; n++) { gpu_exclude[n][0] = ranges[n][0]; gpu_exclude[n][1] = ranges[n][1]; }
    struct q1n1_gpu_platform platform = {
        .memory_map = info.memory_map, .memory_map_size = info.memory_map_size,
        .memory_map_stride = info.memory_map_stride, .exclude = (const uint64_t (*)[2])gpu_exclude,
        .exclude_count = 7, .attr = gpu_attr, .delay_us = gpu_delay, .smc = gpu_smc, .store32 = gpu_store32, .zero = gpu_zero,
        .boot_base = &info.gpu_arena_base, .boot_size = &info.gpu_arena_size, .boot_flags = &info.gpu_arena_flags,
    };
    q1n1_gpu_init(&platform);
    info.gpu_call = (uintptr_t)q1n1_gpu_call;
    info.gpu_state = (uintptr_t)q1n1_gpu_state_record();
}

static uint64_t last_status;
static uint64_t last_shift;
static uint64_t last_swap;
static int console_enabled = 1;

uint64_t q1n1_platform_fb_console(int enabled)
{
    uint64_t previous = console_enabled;
    console_enabled = !!enabled;
    return previous;
}

/* How often the console steps around its anti-burn-in grid. Two minutes is well
 * inside the hours it takes an OLED to retain an image, and far enough apart
 * that the framebuffer copy it costs is not worth measuring. */
#define CON_SHIFT_SECONDS 120
/* And how often the text column changes sides. The grid handles a lit sub-pixel
 * holding one glyph stroke; it does nothing about half the panel being lit and
 * the other half black for the whole session, which with a centred emblem is
 * the actual shape on screen. Five minutes gives each side a real rest without
 * the screen looking like it has a fault. */
#define CON_SWAP_SECONDS 300

static void status_lines(void)
{
    const struct q1n1_proxy_stats *p = &q1n1_proxy_stats;
    if (hz && counter() - last_shift > (uint64_t)CON_SHIFT_SECONDS * hz) {
        last_shift = counter();
        con_shift_next();
    }
    /* Only the column moves; rows are untouched, so status_row still points at
     * the same lines and the status block redraws itself on the new side. */
    if (hz && counter() - last_swap > (uint64_t)CON_SWAP_SECONDS * hz) {
        last_swap = counter();
        con_swap_side();
    }
    for (uint32_t row = status_row; row < status_row + 6; row++) con_clear_row(row);
    con_at(status_row, 0);
    con_puts("proxy: up "); con_dec((counter() - proxy_start) / hz);
    con_puts(" s, "); con_dec(p->requests); con_puts(" requests, "); con_dec(p->proxy_calls);
    con_puts(" ops, last "); con_hexn(p->last_opcode, 3); con_puts("\n");
    con_puts("proxy: read "); con_dec(p->read_bytes); con_puts(" B, wrote "); con_dec(p->write_bytes);
    con_puts(" B, csum err "); con_dec(p->checksum_errors); con_puts(", timeouts "); con_dec(p->timeouts);
    con_puts(", bad cmd "); con_dec(p->bad_commands); con_puts(", exc "); con_dec(p->exceptions); con_puts("\n");
    con_puts("gic: "); con_dec(gic.ticks); con_puts(" ticks at "); con_dec(gic.rate);
    con_puts(" Hz, serviced "); con_dec(gic.serviced); con_puts(", skipped "); con_dec(gic.skipped);
    con_puts(", spurious "); con_dec(gic.spurious);
    if (mode != MODE_USB_PROXY || !usb_ports) return;
    for (unsigned i = 0; i < Q1N1_USB_PORTS; i++) {
        const struct q1n1_usb_port_status *st = &usb_ports->status[i];
        const struct q1n1_usb_port *port = &usb_ports->port[i];
        con_puts("\nusb"); con_dec(i); con_puts(": ");
        if (st->role == Q1N1_USB_HOST) {
            con_puts("host NCM "); con_puts(st->connected ? "up" : "discovering");
            con_puts(", frames "); con_dec(port->ncm.stats.frames_in);
            con_puts("/"); con_dec(port->ncm.stats.frames_out);
        } else if (st->role == Q1N1_USB_DEVICE) {
            con_puts("CDC cfg "); con_dec(port->device.stats.configured);
            con_puts(", setups "); con_dec(port->device.stats.setups);
            con_puts(", rx "); con_dec(port->device.stats.rx_bytes);
            con_puts(", tx "); con_dec(port->device.stats.tx_bytes);
        } else con_puts(st->role == Q1N1_USB_UNSUPPORTED ? "unavailable" : "retrying");
        con_puts(", attempts "); con_dec(st->attempts);
        con_puts(", disconnects "); con_dec(st->disconnects);
    }
}
/* The last live battery reading, on the row the panel clears but does not use. */
static void status_panel(void)
{
    status_lines();
    const struct q1n1_live_battery *battery = q1n1_live_battery_result();
    if (!battery->calls) return;
    con_at(status_row + 5, 0);
    con_puts("battery: ");
    con_puts(battery->text);
}
static void status_tick(void)
{
    q1n1_live_battery_tick(&live_platform);
    if (!console_enabled) return;
    uint64_t now = counter();
    if (now - last_status >= hz) { last_status = now; status_panel(); }
}

static void managed_usb_poll(void *ctx)
{
    if (call_polling) {
        /* Back in the proxy loop with a call poll that never returned: the
         * payload faulted inside it and unwound its P_CALL. Release what the
         * call poll held, or the link carrying the reply is never serviced. */
        struct q1n1_usb_ports *s = ctx;
        call_polling = 0;
        console_view = 0;
        s->busy = 0;
        ncm_proxy_call_reset();
        q1n1_call_disarm(&call_state);
        if (call_state.recoveries != UINT64_MAX) call_state.recoveries++;
    }
    q1n1_usb_ports_poll(ctx);
    status_tick();
}

static size_t pl011_read(void *ctx, uint8_t *b, size_t n)
{
    (void)ctx;
    size_t k = 0;
    while (k < n && !(rd(0x18) & (1u << 4))) b[k++] = (uint8_t)rd(0);
    return k;
}
static size_t pl011_write(void *ctx, const uint8_t *b, size_t n)
{
    (void)ctx;
    size_t k = 0;
    while (k < n && !(rd(0x18) & (1u << 5))) *(volatile uint32_t *)(uintptr_t)uart.base = b[k++];
    return k;
}
static void pl011_poll(void *ctx) { (void)ctx; status_tick(); }
static int pl011_ready(void *ctx) { (void)ctx; return 1; }
static const struct q1n1_io pl011_io = {.read = pl011_read, .write = pl011_write,
                                        .poll = pl011_poll, .ready = pl011_ready};

void q1n1_fault(uint64_t esr, uint64_t elr, uint64_t far) __attribute__((noreturn));
void q1n1_fault(uint64_t esr, uint64_t elr, uint64_t far)
{
    uart.enabled = 0; /* The fault may itself be an inaccessible UART. */
    if (mode != MODE_FOOTHOLD) {
        for (uint32_t row = status_row + 7; row < status_row + 12; row++) con_clear_row(row);
        con_at(status_row + 7, 0);
        con_puts("q1n1: unhandled exception\n");
        con_puts("  esr "); con_hex(esr); con_puts("  elr "); con_hex(elr);
        con_puts("  far "); con_hex(far); con_puts("\n");
        if (no_cdc) {
            /* Resetting here loops: the boot window already re-armed BootNext,
             * so the next boot lands straight back in the same fault. Halt and
             * let the screen be the diagnostic; a power cycle spends the
             * one-shot BootNext and returns to Windows. */
            con_puts("q1n1: halted - no console to report to; power cycle for Windows\n");
            for (;;) __asm__ volatile("wfe");
        }
        con_puts("q1n1: resetting in 30 s\n");
        wait_seconds(30);
        reset_now();
    }
    rect(0,0,fb.width,8,0xff3040);
    out("\nQ1N1 SYNCHRONOUS EXCEPTION\n");
    field("ESR ",esr); field("ELR ",elr); field("FAR ",far);
    for (;;) __asm__ volatile("wfe");
}

/* Called from the vectors in entry.S (Q1N1_EXCEPTION_FRAME) with x0-x30 and SP. */
void q1n1_exception(uint64_t *frame, uint64_t vector);
void q1n1_exception(uint64_t *frame, uint64_t vector)
{
    int el2 = current_el() == 2;
    uint64_t esr, elr, far, spsr;
    if (el2) {
        __asm__ volatile("mrs %0, esr_el2" : "=r"(esr)); __asm__ volatile("mrs %0, elr_el2" : "=r"(elr));
        __asm__ volatile("mrs %0, far_el2" : "=r"(far)); __asm__ volatile("mrs %0, spsr_el2" : "=r"(spsr));
    } else {
        __asm__ volatile("mrs %0, esr_el1" : "=r"(esr)); __asm__ volatile("mrs %0, elr_el1" : "=r"(elr));
        __asm__ volatile("mrs %0, far_el1" : "=r"(far)); __asm__ volatile("mrs %0, spsr_el1" : "=r"(spsr));
    }
    if (resetting) reset_now();
    if ((vector & 3) == 3 && serror_window) {
        /* The deliberate window in q1n1_platform_serror_poll: record, and
         * resume with A masked so a level-sensitive source cannot pin the
         * core in the window (q1n1-proxy.h). */
        serror_window_esr = esr;
        serror_window_hits++;
        spsr = q1n1_serror_window_spsr(spsr);
        if (el2) __asm__ volatile("msr spsr_el2, %0" : : "r"(spsr) : "memory");
        else __asm__ volatile("msr spsr_el1, %0" : : "r"(spsr) : "memory");
        return;
    }
    if ((vector & 3) == 1) { /* IRQ: the EL2 timer tick keeps the link alive */
        uint32_t intid = q1n1_gic_handle(&gic);
        if (intid == gic.intid) q1n1_usb_ports_tick(usb_ports);
        return;
    }
    uint64_t guard = q1n1_exc_guard & Q1N1_GUARD_TYPE_MASK;
    if ((vector & 3) == 0 && guard != Q1N1_GUARD_OFF) {
        if (guard == Q1N1_GUARD_SKIP) {
            elr += 4;
        } else if (guard == Q1N1_GUARD_MARK) {
            /* A load or store: the destination register is Rt in bits 4:0. */
            uint32_t insn = *(const uint32_t *)(uintptr_t)elr;
            if ((insn & 0x1f) < 31) frame[insn & 0x1f] = Q1N1_GUARD_MARKER;
            elr += 4;
        } else {
            /* Leaf helpers in proxy-asm.S: return to the caller with a marker. */
            frame[0] = Q1N1_GUARD_MARKER;
            elr = frame[30];
            q1n1_exc_guard = Q1N1_GUARD_OFF;
        }
        q1n1_exc_count++;
        if (el2) __asm__ volatile("msr elr_el2, %0" : : "r"(elr) : "memory");
        else __asm__ volatile("msr elr_el1, %0" : : "r"(elr) : "memory");
        return;
    }
    q1n1_proxy_stats.exceptions++;
    if (mode != MODE_FOOTHOLD && proxy_io && !in_exception) {
        in_exception = 1;
        for (unsigned n = 0; n < 31; n++) exception.regs[n] = frame[n];
        exception.sp = frame[31]; exception.spsr = spsr; exception.elr = elr;
        exception.esr = esr; exception.far = far; exception.el = el2 ? 2 : 1; exception.vector = vector;
        uint64_t result = q1n1_proxy_run(proxy_io, Q1N1_START_EXCEPTION, (uint32_t)(vector & 3), (uintptr_t)&exception);
        in_exception = 0;
        if (result == Q1N1_EXC_RET_HANDLED) {
            for (unsigned n = 0; n < 31; n++) frame[n] = exception.regs[n];
            elr = exception.elr; spsr = exception.spsr;
            if (el2) {
                __asm__ volatile("msr elr_el2, %0" : : "r"(elr) : "memory");
                __asm__ volatile("msr spsr_el2, %0" : : "r"(spsr) : "memory");
            } else {
                __asm__ volatile("msr elr_el1, %0" : : "r"(elr) : "memory");
                __asm__ volatile("msr spsr_el1, %0" : : "r"(spsr) : "memory");
            }
            return;
        }
    }
    q1n1_fault(esr, elr, far);
}

static void proxy_main(void) __attribute__((noreturn));
static void proxy_main(void)
{
    uint64_t el = current_el(), midr;
    __asm__ volatile("mrs %0, midr_el1" : "=r"(midr));
    info.current_el = el;
    proxy_start = counter();
    /* Start both panel timers here. They are compared against a counter that
     * has been running since power-on, so leaving them at zero makes the first
     * comparison true and the console jumps as soon as it is drawn. */
    last_shift = last_swap = proxy_start;
    con_init(info.fb_base, (uint32_t)info.fb_width, (uint32_t)info.fb_height,
             (uint32_t)info.fb_stride, (uint32_t)info.fb_format);
    /* Keep diagnostics fixed. Automatic pixel shifts and side swaps also
     * move pixels drawn by a guest, corrupting its independently positioned
     * console. The proxy can relinquish all status drawing at handoff. */
    con_retains(0);
    con_clear();
    switch (stage_config & 3) {
    case LOGO_CORNER: draw_logo_for_generation(info.stage_generation); break;
    case LOGO_NONE: break;
    /* Reserve first: the emblem is placed relative to the text column, so the
     * column has to be sized before the mark knows which half it belongs in. */
    case LOGO_ASAHI:
        con_reserve_emblem(256);
        con_emblem(q1n1_asahi_logo, 256);
        break;
    default:
        con_reserve_emblem(256);
        con_emblem(q1n1_logo, 256);
        break;
    }

#if SNAP_PLATFORM_SP11
#ifndef Q1N1_STAGE
    /* docs/SP11-Q1N1-BOOT-STUDY.md section 5.5 point 3: the framebuffer console comes up and shows
     * something durable -- a build id, the entry/current EL -- before GIC bring-up or any USB-link
     * attempt, so that if the unexplained post-bounce reset (constraint 5) recurs, whatever got
     * drawn survives as a photographable record. con_init/the logo switch above are already the
     * earliest point the console is usable; this block is placed before even the pre-existing
     * "q1n1 payload @ ..."/EL-confirmed line below, so it is first on screen before
     * sysinfo_acpi/sysinfo_cpu/sysinfo_uefi/sysinfo_smbios/sysinfo_memory parse ACPI/SMBIOS/the
     * memory map -- new, unfamiliar data on this platform that this design does not want to spend
     * part of the unexplained reset budget on before the two facts a photograph most needs exist.
     *
     * !Q1N1_STAGE: sp11_gop_status/sp11_gop_rule are set only by find_framebuffer (the #ifndef
     * Q1N1_STAGE block above), which a chainloaded stage never calls -- it inherits an already-
     * drawn framebuffer through bootinfo instead of re-selecting a GOP (F15). This diagnostic is
     * about what *this image itself* discovered bringing its own console up, so it is specific to
     * the original EFI image, not every stage after it; carrying the GOP outcome across a
     * chainload would need a new bootinfo field, out of this patch's scope (see REPORT.md). */
    con_at(0, 0);
    con_puts("q1n1: SP11 build " SP11_BUILD_ID "\n");
    con_puts("q1n1: entry EL "); con_dec(info.entry_el); con_puts(", current EL "); con_dec(el);
    con_puts("\n");
    con_puts(sp11_gop_status == Q1N1_SP11_GOP_OK ? "q1n1: GOP SEL=" : "q1n1: GOP REFUSED=");
    con_puts(sp11_gop_status == Q1N1_SP11_GOP_OK ? q1n1_sp11_gop_rule_name(sp11_gop_rule)
                                                 : q1n1_sp11_gop_status_name(sp11_gop_status));
    con_puts("\n");
#endif /* !Q1N1_STAGE */
#endif /* SNAP_PLATFORM_SP11 */

    /* An m1n1-shaped boot log: subsystem, colon, what it found. */
    con_at(0, 0);
    con_puts("q1n1 ");
    if (info.stage_generation) {
        con_puts("stage "); con_dec(info.stage_generation); con_puts(" @ ");
        con_hexn(info.image_base, 8); con_puts(" (chainloaded over the proxy)\n");
    } else {
        con_puts("payload @ "); con_hexn(info.image_base, 8); con_puts(" (loaded by firmware)\n");
    }
    con_puts(el == 2 ? "q1n1: EL2 confirmed after ExitBootServices (entry EL"
                     : "q1n1: WARNING - running at EL1, not EL2 (entry EL");
    con_dec(info.entry_el); con_puts(")\n");
    uint64_t cores = 0;
    sysinfo_acpi(info.acpi_rsdp, &cores);
    sysinfo_cpu(hz, cores);
    sysinfo_uefi(info.system_table);
    sysinfo_smbios(info.smbios3);
    sysinfo_memory(info.memory_map, info.memory_map_size, info.memory_map_stride);
    con_puts("fb init: "); con_dec(info.fb_width); con_puts("x"); con_dec(info.fb_height);
    con_puts(" [s="); con_dec(info.fb_stride); con_puts("] @"); con_hexn(info.fb_base, 8); con_puts("\n");
    con_puts("fb console: max rows "); con_dec(con_rows()); con_puts(", max cols "); con_dec(con_cols());
    con_puts("\n");
    con_puts("fb panel: console fixed, automatic movement disabled\n");
    con_puts("fb: display logo\n");
    con_puts("q1n1 mem: heap "); con_dec(info.heap_size >> 20); con_puts(" MiB @ "); con_hexn(info.heap_base, 8);
    con_puts(", dma "); con_dec(info.dma_size >> 20); con_puts(" MiB @ "); con_hexn(info.dma_base, 8);
    con_puts(", stage "); con_dec(info.stage_size >> 20); con_puts(" MiB @ "); con_hexn(info.stage_base, 8);
    con_puts("\n");

    if (mode == MODE_USB_PROXY) {
        if (info.heap_size < Q1N1_USB_ARENA_SIZE + 0x10000) {
            con_puts("USB: insufficient DMA scratch; halted\n");
            for (;;) __asm__ volatile("wfe");
        }
        uint8_t *arena = (void *)(uintptr_t)((info.heap_base + info.heap_size - Q1N1_USB_ARENA_SIZE) & ~0xffffull);
        usb_ports = q1n1_usb_ports_init(arena, Q1N1_USB_ARENA_SIZE, info.stage_generation != 0);
        if (!usb_ports) {
            con_puts("USB: invalid arena; halted\n");
            for (;;) __asm__ volatile("wfe");
        }
        usb_ports->io.poll = managed_usb_poll;
        proxy_io = &usb_ports->io;
        info.usb_ports = (uintptr_t)usb_ports->status;
        info.usb_port_count = Q1N1_USB_PORTS;
        info.usb_stats = (uintptr_t)&usb_ports->port[0].device.stats;
        info.xhci_base = 0;
        info.xhci_stats = (uintptr_t)&usb_ports->port[0].host.stats;
        info.ncm_stats = (uintptr_t)&usb_ports->port[0].ncm.stats;
        info.ncm_proxy_stats = (uintptr_t)&usb_ports->port[0].proxy.stats;
        con_puts("usb: independent host/CDC discovery on both controllers\n");
    } else {
        con_puts("uart: pl011 @ "); con_hexn(uart.base, 8); con_puts("\n");
        proxy_io = &pl011_io;
    }

    info.battery_call = (uintptr_t)q1n1_battery_call;
    info.battery_result = (uintptr_t)q1n1_live_battery_result();
    info.battery_session = (uintptr_t)q1n1_live_battery_session();
    q1n1_call_init(&call_state);
    ncm_proxy_side_port(Q1N1_STOP_PORT, stop_port, &call_state);
    info.call_service = (uintptr_t)q1n1_call_service;
    info.call_service_state = (uintptr_t)&call_state;
    gpu_setup();

    int tick = q1n1_gic_init(&gic, info.acpi_rsdp, hz, 1000);
    info.gic_distributor = gic.distributor;
    info.gic_redistributor = gic.redistributor;
    info.gic_stats = (uintptr_t)&gic;
    if (tick) {
        con_puts("gic: unavailable, status "); con_dec((uint64_t)(-(int64_t)tick));
        con_puts(" - the link is serviced by polling only\n");
    } else {
        con_puts("gic: dist @ "); con_hexn(gic.distributor, 8);
        con_puts(" redist @ "); con_hexn(gic.redistributor, 8);
        con_puts(", EL2 timer ppi "); con_dec(gic.intid);
        con_puts(" at "); con_dec(gic.rate); con_puts(" Hz\n");
        q1n1_gic_start(&gic);
    }
    con_puts("Initialization complete.\n");
    con_puts("Running proxy...\n");
    /* Anchor the live panel under the log, but never past the last row: on a
     * small screen the panel replaces the tail of the log instead of scrolling
     * it on every redraw. */
    status_row = con_row() + 1;
    if (status_row + 7 > con_rows()) status_row = con_rows() > 7 ? con_rows() - 7 : 0;

    for (;;) {
        q1n1_proxy_run(proxy_io, Q1N1_START_BOOT, 0, (uintptr_t)&info);
        if (!q1n1_next_stage.entry) continue;
        /* Chainload: stop the tick first so the outgoing vectors and driver
         * state cannot be entered once the new stage owns the hardware. */
        q1n1_gic_stop(&gic);
        if (q1n1_usb_ports_handoff(usb_ports)) {
            q1n1_next_stage.entry = q1n1_next_stage.argument = 0;
            con_puts("q1n1: chainload refused: USB DMA did not halt\n");
            q1n1_gic_start(&gic);
            continue;
        }
        uint64_t entry = q1n1_next_stage.entry;
        uint64_t argument = q1n1_next_stage.argument ? q1n1_next_stage.argument : (uintptr_t)&info;
        q1n1_next_stage.entry = q1n1_next_stage.argument = 0;
        con_at(status_row + 7, 0);
        con_clear_row(status_row + 7);
        /* A q1n1 stage takes bootinfo in x0 and continues the GLINK session.
         * Anything else is leaving q1n1: hand the SoCCP back the way the
         * firmware does at ExitBootServices (live-battery.h, RELEASE). */
        if (argument != (uintptr_t)&info && hz) {
            int released = q1n1_live_battery_release(&live_platform);
            if (released) {
                con_puts("q1n1: GLINK release before handoff failed, status -");
                con_dec((uint64_t)-(int64_t)released);
                con_puts("\n");
                con_at(status_row + 8, 0);
            }
        }
        con_puts("q1n1: chainloading a stage at "); con_hexn(entry, 8); con_puts("\n");
        __asm__ volatile("dsb sy\n isb" ::: "memory");
        ((void (*)(uint64_t))(uintptr_t)entry)(argument);
        con_puts("q1n1: the stage returned; resetting\n");
        reset_now();
    }
}

#if Q1N1_SP11_STK_SURVEY
/* ---- Stick-log survey (sp11-stk-survey.h): the platform side ----
 * P2 runs inside leave_firmware, before the last GetMemoryMap, and keeps its lines here for the
 * EL2 page. At EL2 the survey reads through live_guarded (the recoverable-fault copy the proxy
 * uses): an abort comes back as an error instead of a dead core. This layer only forwards loads; the
 * policy (windows, memory map, mapping attribute, the gate) is in sp11-stk-el2.c, where the native
 * tests drive it. */
static struct stk_p2 stk_p2_saved;
static int stk_requested;           /* set by the --el2 flow only: --boot and --uart-proxy never run it */

static void stk_p2_console(void *ctx, const char *line)
{
    firmware_out((struct efi_system_table *)ctx, line);
    firmware_out((struct efi_system_table *)ctx, "\n");
}

static int stk_guarded(void *ctx, int kind, uint64_t dst, uint64_t src, uint64_t size)
{
    (void)ctx;
    /* Loads only. sp11-stk-el2.c never asks for another kind; a store kind is refused here too, so
     * that a mistake there is an error and not a write to a device register. */
    if (kind != STK_G_COPY32) return 1;
    return live_guarded(0, dst, src, size);
}

static int stk_attr(void *ctx, uint64_t phys)
{
    uint32_t attr = 0;
    int status = live_attr(ctx, phys, &attr);
    if (status == -3) return STK_ATTR_NONE;      /* q1n1_mmu_attr: no valid descriptor */
    if (status) return STK_ATTR_UNKNOWN;
    return q1n1_mmu_attr_device(attr) ? STK_ATTR_DEVICE : STK_ATTR_NORMAL;
}

/* The survey draws with the page's own screen_char at its own origin and scale (stk_layout), and
 * restores the page cursor, so nothing the existing page prints is moved or redrawn. */
static struct stk_layout stk_page;
static uint32_t stk_next_row;

static void stk_draw(uint32_t row, const char *text)
{
    uint32_t scale = fb.scale, saved_row = fb.row, saved_col = fb.col;
    fb.scale = stk_page.scale;
    fb.row = row;
    fb.col = stk_page.col0;
    for (const char *s = text; *s; s++) screen_char(*s);
    fb.scale = scale; fb.row = saved_row; fb.col = saved_col;
}

/* A line goes to the UART like out() and to the panel in the survey's region; past the region's last
 * row it is still mirrored but not drawn. */
static void stk_emit(void *ctx, const char *line)
{
    (void)ctx;
    for (const char *s = line; *s; s++) uart_byte((uint8_t)*s);
    uart_byte('\r');
    uart_byte('\n');
    if (stk_next_row < stk_page.row0 + stk_page.rows) stk_draw(stk_next_row, line);
    stk_next_row++;
}

/* The in-place marker on the row above the lines: where the survey is about to read. Screen only. */
static void stk_at(void *ctx, const char *where)
{
    char text[40] = "STK AT ";
    unsigned n = 7;
    (void)ctx;
    while (*where && n < sizeof text - 1) text[n++] = *where++;
    text[n] = 0;
    rect(20 + stk_page.col0 * 6 * stk_page.scale, 20 + stk_page.row0 * 9 * stk_page.scale,
         (STK_LINE_MAX + 1) * 6 * stk_page.scale, 9 * stk_page.scale, 0x080b10);
    stk_draw(stk_page.row0, text);
}

/* Reads the saved memory map, places the survey on the panel and runs it. Called once, at EL2. */
static void sp11_stk_el2_survey(void)
{
    uint32_t count = 0;
    int parse = q1n1_sp11_gop_map_parse((const uint8_t *)(uintptr_t)info.memory_map, info.memory_map_size,
                                        info.memory_map_stride, sp11_map_entries, SP11_GOP_MAX_MAP_ENTRIES, &count);
    struct stk_ops ops = {stk_guarded, stk_attr, 0};
    struct stk_sink sink = {stk_emit, stk_at, 0, 0, 0};
    struct stk_el2_args args = {&ops, stk_requested ? &stk_p2_saved : 0, sp11_map_entries, count,
                                parse == Q1N1_SP11_MAP_OK, info.memory_map, &sink};
    struct stk_result result;
    stk_layout(fb.width, fb.height, fb.scale, fb.row, &stk_page);
    stk_next_row = stk_page.row0 + 1;
    stk_el2_run(&args, &result);
}
#endif /* Q1N1_SP11_STK_SURVEY */

void q1n1_main(void) __attribute__((noreturn));
void q1n1_main(void)
{
#if SNAP_PLATFORM_SP11
    /* Fail-closed EL2 check (docs/SP11-Q1N1-BOOT-STUDY.md section 5.3): the first instruction run
     * after leave_firmware's exit_boot_services call returns, before proxy_main (F09's existing
     * gap: a cosmetic warning, then an unconditional 55-line walk into q1n1_gic_init's EL2-only
     * register writes). Read CurrentEL fresh -- never before this line -- and refuse outright if
     * it is not 2, rather than only warn and continue. Does not apply to the --el2 diagnostic
     * (MODE_FOOTHOLD): showing "EL2 NOT REACHED" without refusing is that tool's entire purpose.
     *
     * Reuses G03's own drawing primitives (rect/out/field, q1n1_fault's own building blocks) for
     * the same visual convention, but not q1n1_fault() itself: that function resets after 30 s for
     * mode != MODE_FOOTHOLD (q1n1_fault, above), which is the opposite of what constraint 4/section
     * 5.3 requires here (no ResetSystem, no automatic PSCI reset -- an automatic retry into the
     * same failing bounce is not obviously safer than a diagnosable halt). This patch's REPORT.md
     * records this as the one place "reuse G03, do not build a new one" could not mean "call the
     * existing function unchanged" and says so rather than silently choosing either reading. */
    if (mode != MODE_FOOTHOLD && current_el() != 2) {
        uart.enabled = 0;
        rect(0,0,fb.width,fb.height,0x080b10);
        rect(0,0,fb.width,8,0xff3040);
        out("Q1N1 SP11: EL2 NOT REACHED AFTER EXITBOOTSERVICES\n");
        field("ENTRY EL ",before_el); field("CURRENT EL ",current_el());
        out("HALTED - NO RESET - SLBOUNCE DID NOT REACH EL2\n");
        for (;;) __asm__ volatile("wfe");
    }
#endif
    if (mode != MODE_FOOTHOLD) proxy_main();
    uint64_t el = current_el(), midr;
    __asm__ volatile("mrs %0, midr_el1" : "=r"(midr));
    rect(0,0,fb.width,fb.height,0x080b10);
    rect(0,0,fb.width,8,el == 2 ? 0x35e38b : 0xffb347);
    draw_logo();
#if SNAP_PLATFORM_SP11 && !defined(Q1N1_STAGE)
    out("Q1N1 / SNAPDRAGON BRINGUP\n");
    out("BUILD " SP11_BUILD_STAMP "\n");
    /* The uptime line lives here, directly under the build stamp, so it stays on screen however
     * long the page below it grows (a small display clips the bottom rows). */
    uint32_t uptime_row = fb.row;
    out("\n\n");
#else
    out("Q1N1 / SNAPDRAGON BRINGUP\n\n");
#endif
    out(el == 2 ? "EL2 CONFIRMED AFTER EXITBOOTSERVICES\n" : "EL2 NOT REACHED - STILL IN EL1\n");
    field("ENTRY EL ",before_el); field("CURRENT EL ",el); field("MIDR ",midr);
    field("FRAMEBUFFER ",(uint64_t)(uintptr_t)fb.pixels);
    field("SPCR UART ",uart.base); field("SPCR TYPE ",uart.type);
    field("SPCR GSI ",uart.irq); field("SPCR BAUD CODE ",uart.baud);
    field("MEMORY DESCRIPTORS ",map_stride ? map_size / map_stride : 0);
    out(uart.enabled ? "POLLED UART TX ACTIVE\n" : "UART TX DISABLED OR UNAVAILABLE\n");
#if SNAP_PLATFORM_SP11
#ifndef Q1N1_STAGE
    /* What the scoped sweep was asked to accept and the map it was checked against: this page
     * replaced the console text that showed them just before ExitBootServices. */
    out(sp11_ebs_text.buf);
    /* Only at EL2: an EL2 register read at EL1 is UNDEFINED. */
    if (el == 2) sp11_report_el2_state();
    else out("EL2 STATE NOT READ (NOT AT EL2)\n");
#endif
#endif
    out("USB PROXY: RUN Q1N1.EFI --BOOT\n\n");
    out("BOOT FOOTHOLD ONLY - NO GUEST OR SMP YET\n");
    out("POWER CYCLE TO RETURN TO FIRMWARE\n");
    if (fault_test) __asm__ volatile("brk #0");
#if SNAP_PLATFORM_SP11 && !defined(Q1N1_STAGE)
    uint64_t start = counter(), last = start, ticks = frequency();
#else
    uint64_t last = counter(), ticks = frequency();
#endif
    unsigned beat = 0;
#if SNAP_PLATFORM_SP11 && !defined(Q1N1_STAGE)
    sp11_draw_uptime(uptime_row, 0);
#if Q1N1_SP11_STK_SURVEY
    /* After the existing page is complete: the survey adds lines, it replaces none. */
    if (el == 2) sp11_stk_el2_survey();
    else out("STK P3 SKIPPED=NOT_AT_EL2\n");
#endif
#endif
    for (;;) {
        if (counter() - last >= ticks) {
            last = counter(); beat++;
            if (fb.height >= 20) rect(20,fb.height-16,32,8,beat & 1 ? 0x35e38b : 0x173023);
#if SNAP_PLATFORM_SP11 && !defined(Q1N1_STAGE)
            /* From the counter, not the beat count: each beat restarts the interval, so the count
             * runs slow by however long the redraw took. A zero CNTFRQ_EL0 falls back to the beats. */
            sp11_draw_uptime(uptime_row, ticks ? (counter() - start) / ticks : beat);
#endif
        }
        __asm__ volatile("yield");
    }
}

#ifndef Q1N1_STAGE
#if SNAP_PLATFORM_SP11
/* The table last handed to sp11_declare_ranges, the label of each range in it, and what the write
 * returned: kept so sp11_report_ebs can show exactly what the sweep will be asked to accept.
 * sp11_declared.count stays 0 until something is written. */
static struct sp11_ebs_ranges_table sp11_declared;
static const char *sp11_declared_label[SP11_EBS_MAX_RANGES];
static efi_status sp11_declared_status;

/* Builds and writes the declared-ranges table (docs/SP11-Q1N1-BOOT-STUDY.md section 4.4/7.2): what
 * q1n1 dirtied through the cache and still reads after ExitBootServices. Only populated ranges are
 * listed, so the --el2 diagnostic (no heap, DMA arena, stage slot or preload table) declares just
 * its image and its map buffer, and the full --boot flow declares up to six. The image range is
 * the whole PE image including its .bss, and q1n1_enter's stack lives inside it (entry.S). The
 * memory-map-buffer range is this function's own `map`/MAP_BYTES, the full allocation, not the
 * live map_size a retried get_memory_map call can shrink to; MAP_BYTES is fixed before the retry
 * loop starts, so writing this once here, before that loop, is correct for every attempt inside it.
 *
 * The framebuffer is deliberately not declared. On this unit it is wholly inside a RESERVED
 * (type 0) descriptor (OBSERVED, probe dumps x1-run01..03), a type the scoped sweep refuses by
 * design (it takes only the seven types upstream's blanket sweep took, which never included 0), so
 * declaring it would make ExitBootServices fail on every attempt; nothing reads it afterwards, and
 * a stale dirty pixel line is cosmetic (INFERRED, not yet exercised on hardware).
 *
 * A write failure is not itself fatal here: the paired slbounce fork, if built with
 * SLBOUNCE_SCOPED_SWEEP, refuses ExitBootServices on its own when the variable is absent or
 * malformed (q1n1 need not duplicate that policy, only supply the data this function can); the
 * status is kept for sp11_report_ebs. */
static void sp11_declare_ranges(struct efi_system_table *st, uint64_t map_base, uint64_t map_bytes)
{
    /* Not the global `rt`: only proxy_efi_main sets that, and the --el2 diagnostic never does, so
     * relying on it declared nothing there (found by running --el2 end to end under QEMU). */
    struct efi_runtime_services *runtime = st->runtime_services;
    if (!runtime) return;
    struct sp11_ebs_ranges_table t = {0};
    t.magic = SP11_EBS_RANGES_MAGIC;
    t.version = SP11_EBS_RANGES_VERSION;
    /* 1 MiB: this project's own existing GPU-submission chunk cap (AGENTS.md: "never submit a
     * single CP_MEMCPY larger than 1 MiB"), reused here for the same reason
     * tools/sp11_ebs_sweep_model.py's DEFAULT_CHUNK_CAP is -- an unmeasured but bounded unit of
     * work, not a measurement of any real hang's cause. */
    t.chunk_cap = 1u << 20;
    struct sp11_ebs_range ranges[6] = {
        {info.heap_base, info.heap_size}, {info.dma_base, info.dma_size},
        {info.stage_base, info.stage_size}, {info.image_base, info.image_size},
        {map_base, map_bytes}, {info.preload_table, info.preload_size},
    };
    static const char *const labels[6] = {"heap", "dma", "stage", "image", "map", "preload"};
    for (unsigned i = 0; i < 6 && t.count < SP11_EBS_MAX_RANGES; i++) {
        if (!ranges[i].size) continue; /* skip an unpopulated optional range */
        sp11_declared_label[t.count] = labels[i];
        t.range[t.count++] = ranges[i];
    }
    if (t.count == 0) return; /* nothing to declare; never write an empty table */
    t.checksum = sp11_ebs_ranges_fnv((const uint8_t *)&t, offsetof(struct sp11_ebs_ranges_table, checksum));
    efi_guid guid = SP11_EBS_RANGES_GUID_INIT;
    static const char16 name[] = SP11_EBS_RANGES_VARIABLE_NAME_U16;
    sp11_declared = t;
    sp11_declared_status = runtime->set_variable(name, &guid, 2 /* EFI_VARIABLE_BOOTSERVICE_ACCESS */, sizeof t, &t);
}

/* Each declared range against the memory map about to be handed to the sweep: shown on the firmware
 * console just before the ExitBootServices attempt and, kept in sp11_ebs_text, again on the failure
 * page and the --el2 success page, both of which repaint the screen with a font that has only
 * A-Z 0-9 and : - . / = ? ( ) _ -- hence key=value, no commas or plus signs. slbounce's scoped
 * sweep refuses with a bare EFI_ABORTED and prints nothing, so these facts are what tells a
 * refusal's causes apart (it sweeps types 1-6 and 9 only, wants EFI_MEMORY_WB, attribute bit 3,
 * and the range inside exactly one descriptor, and holds at most 512 descriptors). Facts, not a
 * verdict: the policy stays in slbounce, where it cannot drift from this copy of it.
 *
 * The map is read into the caller's own `map` buffer, still unused at this point, and everything
 * here happens before the retry loop's first get_memory_map, so no allocation this causes can make
 * the loop's key stale. */
static void sp11_report_ebs(struct efi_system_table *st, uint64_t map)
{
    struct sp11_text *t = &sp11_ebs_text;
    uint64_t size = MAP_BYTES, key = 0, stride = 0;
    uint32_t version = 0, count = 0;
    efi_status status = st->boot->get_memory_map(&size, (void *)(uintptr_t)map, &key, &stride, &version);
    int parse = Q1N1_SP11_MAP_EMPTY;
    if (!status)
        parse = q1n1_sp11_gop_map_parse((const uint8_t *)(uintptr_t)map, size, stride, sp11_map_entries,
                                        SP11_GOP_MAX_MAP_ENTRIES, &count);
    t->len = 0;
    if (sp11_declared.count) {
        txt_str(t, "SP11 EBS: set_variable="); txt_hex(t, sp11_declared_status);
        txt_str(t, " ranges="); txt_dec(t, sp11_declared.count);
        txt_str(t, " chunk="); txt_hex(t, sp11_declared.chunk_cap); txt_str(t, "\n");
    } else {
        txt_str(t, "SP11 EBS: no ranges declared\n");
    }
    txt_str(t, "SP11 EBS: map status="); txt_hex(t, status);
    txt_str(t, " parse="); txt_str(t, q1n1_sp11_map_status_name(parse));
    txt_str(t, " entries="); txt_dec(t, count); txt_str(t, "\n");
    for (uint32_t r = 0; r < sp11_declared.count; r++) {
        struct q1n1_sp11_range_facts f;
        q1n1_sp11_range_facts(sp11_map_entries, count, sp11_declared.range[r].base,
                              sp11_declared.range[r].size, &f);
        txt_str(t, "SP11 EBS: r"); txt_dec(t, r); txt_str(t, " "); txt_str(t, sp11_declared_label[r]);
        txt_str(t, " base="); txt_hex(t, sp11_declared.range[r].base);
        txt_str(t, " size="); txt_hex(t, sp11_declared.range[r].size);
        txt_str(t, " desc="); txt_dec(t, f.overlapping); txt_str(t, " type="); txt_dec(t, f.type);
        txt_str(t, " attr="); txt_hex(t, f.attribute);
        txt_str(t, f.contained ? " contained=yes\n" : " contained=NO\n");
    }
    firmware_out(st, t->buf);
}
#endif

static efi_status leave_firmware(efi_handle handle, struct efi_system_table *st, const char *message)
{
    efi_status status = st->boot->set_watchdog(0,0,0,NULL);
    if (status) return status;
    /* Preallocate ample map room. After an EBS attempt, only retry GetMemoryMap
     * and EBS. No logging, allocation, protocol or firmware console calls. */
    uint64_t map = 0, key = 0;
    uint32_t version = 0;
    status = st->boot->allocate_pages(0,EFI_LOADER_DATA,MAP_BYTES / 4096,&map);
    if (status) return status;
#if SNAP_PLATFORM_SP11
    /* Declared for every entry point, --el2 included: the scoped sweep refuses ExitBootServices
     * outright when no table exists, so declaring nothing would make every --el2 attempt fail
     * closed before it reaches the point it exists to test. The table lists only populated ranges:
     * the diagnostic's is its image and this map buffer. */
    sp11_declare_ranges(st, map, MAP_BYTES);
    sp11_report_ebs(st, map);
#if Q1N1_SP11_STK_SURVEY
    /* The survey's P2 queries use firmware protocols, so they run here: after the allocations above
     * and before the retry loop below, whose first call is the GetMemoryMap whose key ExitBootServices
     * needs. Nothing between that call and ExitBootServices may allocate, so nothing of the survey
     * runs there. Only the --el2 flow asks for it. */
    if (stk_requested) stk_p2_collect(st, handle, SP11_BUILD_STAMP, &stk_p2_saved, stk_p2_console, st);
#endif
#endif
    firmware_out(st,message);
    for (unsigned attempt = 0; attempt < 3; attempt++) {
        map_size = MAP_BYTES;
        status = st->boot->get_memory_map(&map_size,(void *)(uintptr_t)map,&key,&map_stride,&version);
        if (status) break;
        info.memory_map = map; info.memory_map_size = map_size;
        info.memory_map_stride = map_stride; info.memory_map_version = version;
        status = st->boot->exit_boot_services(handle,key);
        if (!status) q1n1_enter();
        if (status != EFI_INVALID_PARAMETER) break;
    }
    /* Firmware may be partly shut down. Never return to the UEFI caller now. */
    __asm__ volatile("msr daifset, #15" ::: "memory");
    uart.enabled = 0;
    rect(0,0,fb.width,fb.height,0x080b10);
    out("EXITBOOTSERVICES FAILED\n"); field("STATUS ",status);
#if SNAP_PLATFORM_SP11
    out(sp11_ebs_text.buf);
#endif
    for (;;) __asm__ volatile("wfe");
}

/* --boot and --uart-proxy. For --boot every refusal returns 0 so the startup
 * script continues to Windows; only an explicit shell choice returns nonzero. */
static efi_status proxy_efi_main(efi_handle handle, struct efi_system_table *st, struct efi_loaded_image *image)
{
    int usb_mode = option(image, "--boot");
    efi_status refused = usb_mode ? 0 : EFI_UNSUPPORTED;
    rt = st->runtime_services;
    hz = frequency();
#if SNAP_PLATFORM_SP11
    /* Named, one condition at a time, so a refusal can be diagnosed on the plain text console
     * (unlike fbcon, it needs no GOP framebuffer, so it is the one channel every one of these
     * six failure modes can still reach) without collapsing them into one message -- on a
     * platform with no serial console and no way to re-run interactively (this unit, so far),
     * that costs a whole physical test cycle to tell two causes apart. fbcon_init(st) is called
     * under the exact same guard the original expression used (ok_image && ok_rt && ok_hz &&
     * ok_fb): never before those four hold, and exactly once, so this changes no observable
     * behaviour, only what can be read back about it. */
    int ok_image = image != NULL;
    int ok_rt = rt != NULL;
    int ok_hz = hz != 0;
    int ok_fb = fb.pixels != NULL;
    int ok_fbcon = ok_image && ok_rt && ok_hz && ok_fb && fbcon_init(st);
    int ok_el = before_el == 1 || before_el == 2;
    if (!ok_image || !ok_rt || !ok_hz || !ok_fb || !ok_fbcon || !ok_el) {
        firmware_out(st, ok_image ? "SP11: LoadedImage ok.\n" : "SP11: LoadedImage MISSING.\n");
        firmware_out(st, ok_rt ? "SP11: RuntimeServices ok.\n" : "SP11: RuntimeServices MISSING.\n");
        firmware_out(st, ok_hz ? "SP11: timer frequency ok.\n" : "SP11: timer frequency ZERO.\n");
        firmware_out(st, ok_fb ? "SP11: framebuffer ok.\n" : "SP11: framebuffer ABSENT.\n");
        if (!ok_fb) {
            firmware_out(st, "SP11: GOP status=");
            firmware_out(st, q1n1_sp11_gop_status_name(sp11_gop_status));
            firmware_out(st, "\n");
        } else if (ok_image && ok_rt && ok_hz) {
            /* fbcon_init was actually attempted (the same guard as above): say whether it, not
             * an earlier precondition, is what failed. */
            firmware_out(st, ok_fbcon ? "SP11: fbcon_init ok.\n" : "SP11: fbcon_init FAILED.\n");
        }
        firmware_out(st, ok_el ? "SP11: entry EL ok.\n" : "SP11: entry EL UNEXPECTED.\n");
        firmware_out(st, "REFUSED: LoadedImage, runtime services, timer, or framebuffer unavailable.\n");
        return refused;
    }
#else
    if (!image || !rt || !hz || !fb.pixels || !fbcon_init(st) || (before_el != 1 && before_el != 2)) {
        firmware_out(st, "REFUSED: LoadedImage, runtime services, timer, or framebuffer unavailable.\n");
        return refused;
    }
#endif /* SNAP_PLATFORM_SP11 */
    info.magic = Q1N1_BOOTINFO_MAGIC; info.version = 1; info.size = sizeof(info);
    info.image_base = (uintptr_t)image->image_base; info.image_size = image->image_size;
    info.entry_el = before_el; info.timer_hz = hz;
    info.system_table = (uintptr_t)st; info.runtime_services = (uintptr_t)rt;
    info.config_tables = (uintptr_t)st->tables; info.config_count = st->table_count;
    info.fb_base = (uintptr_t)fb.pixels; info.fb_size = fb.bytes; info.fb_width = fb.width;
    info.fb_height = fb.height; info.fb_stride = fb.stride; info.fb_format = fb.format;
    info.proxy_stats = (uintptr_t)&q1n1_proxy_stats; info.exception = (uintptr_t)&exception;
    find_smbios(st);
    if (usb_mode) {
        efi_status status = q1n1_boot_window(handle, st, &boot, option(image, "--auto"));
        info.boot_current = boot.boot_current; info.return_armed = boot.return_armed;
        info.arm_status = boot.arm_status; info.entry_status = boot.entry_status;
        if (status) { firmware_out(st, "Boot window did not complete; continuing to Windows.\n"); return 0; }
        if (boot.choice == Q1N1_BOOT_WINDOWS) { firmware_out(st, "Continuing to Windows.\n"); return 0; }
        if (boot.choice == Q1N1_BOOT_SHELL) { firmware_out(st, "Staying in the UEFI shell.\n"); return EFI_ERROR(21); }
        if (boot.choice == Q1N1_BOOT_PROXY_NCM) {
            /* No dock: the device-mode controller is left untouched and there is
             * no console to take over. Everything rides on the NCM link, which
             * proxy_main brings up after ExitBootServices. */
            firmware_out(st, "No USB0 host; the proxy will answer on the NCM link only.\n");
            no_cdc = 1;
            mode = MODE_USB_PROXY;
            info.mode = MODE_USB_PROXY;
            /* Published so host tools never read through a null pointer; the
             * counters simply stay zero because the gadget is never started. */
            info.usb_stats = 0;
        } else {
        usb_ebs_saved(&boot.snapshot, &saved);
        if (qdwc3_rd(USB_EBS_DWC3_BASE + 0xc120) != saved.gsnpsid) {
            firmware_out(st, "REFUSED: live DWC3 ID differs from the boot-window snapshot.\n");
            return 0;
        }
        uint64_t address = 0xffffffff;
        status = st->boot->allocate_pages(EFI_ALLOCATE_MAX_ADDRESS, EFI_LOADER_DATA, QDWC3_ARENA_SIZE / 4096, &address);
        if (status || (address & 0xfff)) { firmware_out(st, "REFUSED: no DMA arena below 4 GiB.\n"); return 0; }
        info.dma_base = address; info.dma_size = QDWC3_ARENA_SIZE;
        info.usb_dwc3 = USB_EBS_DWC3_BASE; info.usb_qscratch = USB_EBS_QSCRATCH_BASE;
        info.usb_snapshot = (uintptr_t)&boot.snapshot; info.usb_stats = 0;
        mode = MODE_USB_PROXY;
        info.mode = MODE_USB_PROXY;
        }
    } else {
        if (!uart.base || uart.type != 3) {
            firmware_out(st, "REFUSED: --uart-proxy needs an SPCR PL011 (QEMU); GENI is not qualified.\n");
            return refused;
        }
        mode = MODE_UART_PROXY;
        info.mode = MODE_UART_PROXY;
    }
    uint64_t heap = 0;
    if (st->boot->allocate_pages(0, 1 /* EfiLoaderCode */, HEAP_BYTES / 4096, &heap)) {
        firmware_out(st, "REFUSED: could not allocate the proxy heap.\n");
        mode = MODE_FOOTHOLD;
        return refused;
    }
    info.heap_base = heap; info.heap_size = HEAP_BYTES;
    /* A fixed region for chainloaded stages: they are linked for one of these
     * addresses, so no relocation is needed. The host picks the matching
     * binary by reading stage_base back out of bootinfo. */
#if SNAP_PLATFORM_SP11
    /* docs/SP11-Q1N1-BOOT-STUDY.md section 9.1: a board-config-supplied candidate list, refusing
     * to fall back to the A16 addresses -- the SP11 DRAM map is UNKNOWN until X2 item 8 measures
     * it, the same fail-closed posture SP11-HOST-LINK-STUDY.md already uses for the USB table
     * ("nothing here supplies a default... unknown values fail closed"). An invalid or missing
     * table (no generator has been built for this one yet, section 12 item 3) leaves stage_base/
     * stage_size at 0: no chainload target exists, but the SP11 flow still reaches a framebuffer
     * console (constraint 5/section 5.5), which does not itself require a stage slot. */
    const struct q1n1_sp11_stage_table *stage_table = q1n1_sp11_stage_table_get();
    if (q1n1_sp11_stage_table_validate(stage_table) == Q1N1_SP11_STAGE_OK) {
        for (uint32_t n = 0; n < stage_table->count; n++) {
            uint64_t address = stage_table->candidate[n];
            if (!st->boot->allocate_pages(EFI_ALLOCATE_ADDRESS, 1 /* EfiLoaderCode */,
                                          Q1N1_SP11_STAGE_BYTES / 4096, &address)) {
                info.stage_base = address;
                info.stage_size = Q1N1_SP11_STAGE_BYTES;
                break;
            }
        }
    }
#else
    static const uint64_t stage_candidates[] = {0xb0000000, 0x4c000000, 0xa0000000};
    for (unsigned n = 0; n < sizeof(stage_candidates) / sizeof(stage_candidates[0]); n++) {
        uint64_t address = stage_candidates[n];
        if (!st->boot->allocate_pages(EFI_ALLOCATE_ADDRESS, 1 /* EfiLoaderCode */,
                                      STAGE_BYTES / 4096, &address)) {
            info.stage_base = address;
            info.stage_size = STAGE_BYTES;
            break;
        }
    }
#endif
    /* The Adreno GPU arena (gpu-el2.h), reserved while firmware can still say
     * no: the final map then calls it LoaderData and nothing reuses it.
     * Optional -- without it a stage claims one from Conventional memory.
     * AllocatePages only aligns to 4 KiB: take 2 MiB more, keep the 2 MiB
     * aligned 32 MiB inside, and give the head and tail back. Zeroed and
     * cleaned before it is published (gpu-el2.h "A fresh arena"). */
    const uint64_t gpu_align = UINT64_C(2) << 20;
    uint64_t gpu_arena = 0xffffffffull;
    if (!st->boot->allocate_pages(EFI_ALLOCATE_MAX_ADDRESS, EFI_LOADER_DATA,
                                  (Q1N1_GPU_ARENA_BYTES + gpu_align) / 4096, &gpu_arena)) {
        uint64_t base = (gpu_arena + gpu_align - 1) & ~(gpu_align - 1);
        uint64_t head = base - gpu_arena, tail = gpu_align - head;
        if (head) st->boot->free_pages(gpu_arena, head / 4096);
        if (tail) st->boot->free_pages(base + Q1N1_GPU_ARENA_BYTES, tail / 4096);
        gpu_zero(base, Q1N1_GPU_ARENA_BYTES);
        info.gpu_arena_base = base;
        info.gpu_arena_size = Q1N1_GPU_ARENA_BYTES;
        info.gpu_arena_flags = Q1N1_GPU_ARENA_EFI;
    }
    /* All filesystem reads and allocations finish before the final memory map.
     * Cache errors leave the ordinary proxy/upload path available. */
    if(st->boot->set_watchdog(0,0,0,NULL)) return refused;
    firmware_out(st,"Checking SSD preload manifest.\n");
    info.preload_status=q1n1_preload(st->boot,&info.preload_table,&info.preload_size);
    info.preload_diagnostics=(uintptr_t)&q1n1_preload_diagnostics;
    info.preload_verify=(uintptr_t)preload_verify;
    firmware_out(st,info.preload_status==0 ? "SSD preload verified and reserved.\n" :
                    info.preload_status==EFI_NOT_FOUND && q1n1_preload_diagnostics.phase==2 ?
                    "No SSD preload manifest; host upload available.\n" :
                    "SSD preload refused; host upload available.\n");
    /* Read-only: copies both GPT copies of each whole fixed disk for the host.
     * Never writes storage; failure only leaves gpt_survey zero. */
    info.gpt_survey=q1n1_gpt_survey(st->boot,&info.gpt_survey_size);
    firmware_out(st,info.gpt_survey ? "GPT survey recorded (read-only).\n" : "GPT survey unavailable.\n");
    uart.enabled = 0; /* The proxy owns the UART byte stream. */
    efi_status status = leave_firmware(handle, st, "Leaving firmware for the q1n1 proxy.\n");
    mode = MODE_FOOTHOLD;
    return usb_mode ? 0 : status;
}

efi_status efi_main(efi_handle handle, struct efi_system_table *st)
{
    efi_guid loaded_guid = {0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
    struct efi_loaded_image *image = NULL;
    st->boot->handle_protocol(handle, &loaded_guid, (void **)&image);
    before_el = current_el();
    find_framebuffer(st);
    find_uart(st);
    firmware_out(st,"q1n1 AArch64 UEFI entry.\n");
    firmware_out(st,before_el == 2 ? "Entry EL: 2\n" : "Entry EL: 1\n");
    firmware_out(st,fb.pixels ? "GOP framebuffer captured.\n" : "No usable GOP framebuffer.\n");
#if SNAP_PLATFORM_SP11
    sp11_report_gop(st);
#endif
    firmware_out(st,uart.base ? "ACPI SPCR UART found.\n" : "No usable ACPI SPCR UART.\n");
    if (option(image,"--boot") || option(image,"--uart-proxy")) return proxy_efi_main(handle, st, image);
    if (!option(image,"--el2")) {
        firmware_out(st,"Preflight only. No ExitBootServices or UART MMIO.\n");
        if (before_el == 2)
            firmware_out(st,"Already at EL2. Run q1n1.efi --el2 directly, or --boot for the A16 USB proxy.\n"
                            "Do not load slbounce or run sltest at EL2.\n");
        else
            firmware_out(st,"At EL1: qualify sltest before using slbounce.\n"
                            "Use SLBOUNCE_ALWAYS_SWITCH=1 for this ACPI target,\n"
                            "then run q1n1.efi --el2 (optional --uart).\n");
        return 0;
    }
    if (!fb.pixels || (before_el != 1 && before_el != 2)) return EFI_UNSUPPORTED;
    uart.enabled = option(image,"--uart") && uart.base && (uart.type == 3 || uart.type == 0x13);
    fault_test = option(image,"--fault-test");
#if SNAP_PLATFORM_SP11
    /* The scoped sweep needs this image's range (code, data, bss and the stack inside it) to
     * declare it: info is otherwise filled only on the --boot/--uart-proxy path. Without a loaded
     * image there is nothing to declare, so refuse here rather than reach a refused ExitBootServices. */
    if (!image) return EFI_UNSUPPORTED;
    info.image_base = (uintptr_t)image->image_base;
    info.image_size = image->image_size;
#endif
#if Q1N1_SP11_STK_SURVEY
    stk_requested = 1;      /* this is the --el2 flow: --boot and --uart-proxy returned above */
#endif
    return leave_firmware(handle, st, "Leaving firmware now. Green bar = EL2; amber = EL1.\n");
}
#else /* Q1N1_STAGE: a flat payload chainloaded over the proxy */

/* Entered from stage-entry in entry.S with the inherited bootinfo. Firmware is
 * long gone; everything this needs was recorded before ExitBootServices. */
extern char __stage_base[]; /* the address this image was linked for */

extern const uint64_t q1n1_stage_config;

void q1n1_stage_main(struct q1n1_bootinfo *inherited)
{
    stage_config = q1n1_stage_config;
    memset(&info, 0, sizeof(info));
    memcpy(&info, inherited, inherited->size < sizeof(info) ? inherited->size : sizeof(info));
    info.size = sizeof(info);
    /* Continue the previous stage's GLINK session (its record is still in the
     * other slot); refused unless its magic, version and size match ours. */
    if (info.battery_session)
        q1n1_live_battery_adopt((const void *)(uintptr_t)info.battery_session, sizeof(struct q1n1_glink_session));
    info.preload_verify=(uintptr_t)preload_verify;
    info.stage_generation++;
    /* Where this stage actually runs, which is not necessarily the region base:
     * successive chainloads alternate slots, and the host picks the free one by
     * comparing image_base against each candidate's link address. */
    info.image_base = (uintptr_t)__stage_base;
    info.image_size = info.stage_size;
    info.proxy_stats = (uintptr_t)&q1n1_proxy_stats;
    info.exception = (uintptr_t)&exception;
    info.usb_stats = 0;
    info.gic_stats = (uintptr_t)&gic;
    hz = info.timer_hz;
    rt = (struct efi_runtime_services *)(uintptr_t)info.runtime_services;
    mode = (int)info.mode;
    uart.base = 0;
    uart.enabled = 0;
    if (mode == MODE_UART_PROXY) {
        /* The PL011 base is not in bootinfo; rediscover it from ACPI. */
        const uint8_t *rsdp = (const void *)(uintptr_t)info.acpi_rsdp;
        if (rsdp) {
            const uint8_t *xsdt = (const void *)(uintptr_t)get64(rsdp + 24);
            uint32_t size = xsdt ? get32(xsdt + 4) : 0;
            for (uint32_t offset = 36; xsdt && offset + 8 <= size; offset += 8) {
                const uint8_t *table = (const void *)(uintptr_t)get64(xsdt + offset);
                if (!table || !same(table, "SPCR", 4)) continue;
                uart.type = table[36];
                uart.base = get64(table + 44);
                break;
            }
        }
    }
    /* No snapshot means the payload never took the device-mode controller
     * over, which is how a dock-free boot looks. That is a property of the
     * boot, so every stage after it inherits it. */
    no_cdc = mode == MODE_USB_PROXY && !info.usb_snapshot;
    if (info.usb_snapshot)
        usb_ebs_saved((const struct usb_ebs_snapshot *)(uintptr_t)info.usb_snapshot, &saved);
    fbcon_init_fields(info.fb_base, (uint32_t)info.fb_width, (uint32_t)info.fb_height,
                      (uint32_t)info.fb_stride, (uint32_t)info.fb_format);
    fb.pixels = (void *)(uintptr_t)info.fb_base;
    fb.width = (uint32_t)info.fb_width; fb.height = (uint32_t)info.fb_height;
    fb.stride = (uint32_t)info.fb_stride; fb.format = (uint32_t)info.fb_format;
    fb.red = info.fb_format == 0 ? 0xff : 0xff0000;
    fb.green = 0xff00;
    fb.blue = info.fb_format == 0 ? 0xff0000 : 0xff;
    fb.scale = fb.width >= 1600 ? 3 : 2;
    proxy_main();
}
#endif /* Q1N1_STAGE */
