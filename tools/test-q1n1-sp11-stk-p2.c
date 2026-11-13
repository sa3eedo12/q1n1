/* SPDX-License-Identifier: MIT */
/* Native tests for the P2 half of the stick-log survey (platform/uefi/sp11-stk-p2.c): the queries it
 * makes of the firmware's protocols before ExitBootServices, against a fake firmware (handle database,
 * HandleProtocol, LocateHandle, LocateDevicePath's longest-prefix rule, FreePool, PCI I/O, USB I/O)
 * that counts every call the survey must never make: an allocation, the memory map, a transfer, a
 * string descriptor, a write. Device paths are heap blocks of exactly their bytes, so a read past an
 * end node is an AddressSanitizer report. The vendor id, product id and serial string index in the
 * fake descriptors must never be printed. Expected lines are written by hand from Appendix A of
 * docs/SP11-STICK-LOG.md. None of this runs on a Surface Pro 11: EXPERIMENTAL, hardware NOT RUN. */
#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_STK_SURVEY 1
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sp11-stk-efi.h"

static unsigned checks;
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)

/* ---- Device path builders ---- */

struct pb {
    uint8_t b[640];
    unsigned n;
};
static void pb_node(struct pb *p, unsigned type, unsigned sub, const void *body, unsigned body_len)
{
    unsigned len = 4 + body_len;
    p->b[p->n] = (uint8_t)type;
    p->b[p->n + 1] = (uint8_t)sub;
    p->b[p->n + 2] = (uint8_t)len;
    p->b[p->n + 3] = (uint8_t)(len >> 8);
    if (body_len) memcpy(p->b + p->n + 4, body, body_len);
    p->n += len;
}
static void pb_acpi(struct pb *p)
{
    const uint8_t body[8] = {0xd0, 0x41, 0x03, 0x0a, 0, 0, 0, 0};
    pb_node(p, 2, 1, body, 8);
}
static void pb_pci(struct pb *p, unsigned dev, unsigned fn)
{
    const uint8_t body[2] = {(uint8_t)fn, (uint8_t)dev};
    pb_node(p, 1, 1, body, 2);
}
static void pb_usb(struct pb *p, unsigned port, unsigned iface)
{
    const uint8_t body[2] = {(uint8_t)port, (uint8_t)iface};
    pb_node(p, 3, 5, body, 2);
}
static void pb_unit(struct pb *p)
{
    const uint8_t body[1] = {0};
    pb_node(p, 3, 0x11, body, 1);
}
static void pb_hd(struct pb *p, uint32_t number, uint64_t start, uint64_t size, unsigned mbr_type)
{
    uint8_t body[38] = {0};
    memcpy(body, &number, 4);
    memcpy(body + 4, &start, 8);
    memcpy(body + 12, &size, 8);
    memset(body + 20, 0xa5, 16);
    body[36] = (uint8_t)mbr_type;
    body[37] = 1;
    pb_node(p, 4, 1, body, 38);
}
static void pb_end(struct pb *p) { pb_node(p, 0x7f, 0xff, NULL, 0); }

/* ---- The fake firmware ---- */

#define MAX_HANDLES 48
#define MAX_OWNED 512
#define MAX_TRACE 32
#define VENDOR_ID 0xbeef
#define PRODUCT_ID 0xcafe
#define SERIAL_INDEX 0xa7

struct fake_usb {
    struct stk_efi_usb_io io;
    uint8_t dev[STK_USB_DEVICE_DESC_BYTES];
    uint8_t intf[STK_USB_INTERFACE_DESC_BYTES];
    uint8_t ep[16][STK_USB_ENDPOINT_DESC_BYTES];
    int fail_dev, fail_intf;
    unsigned fail_ep_mask;
    unsigned calls_dev, calls_intf, calls_ep;
};

struct fake_pci {
    struct stk_efi_pci_io io;
    uint8_t cfg[256];
    int cfg_fail;
    uint32_t regs[0x180];             /* the memory BAR as dwords */
    uint32_t window;                  /* bytes Mem.Read will serve */
    int mem_fail_at;                  /* the Nth Mem.Read fails; -1 never */
    int attr_mode;                    /* 0: GetBarAttributes unsupported; 1: returns a QWORD descriptor */
    uint64_t attr_base;
    int loc_ok;
    uint64_t seg, bus, dev, fn;
    unsigned mem_reads, cfg_reads, attr_calls;
    uint32_t mem_trace[MAX_TRACE];
    unsigned mem_trace_n;
};

struct fh {
    const char *name;
    uint8_t *dp;
    struct efi_loaded_image *image;
    struct stk_efi_block_io *bio;
    struct fake_usb *usb;
    struct fake_pci *pci;
    int is_hc;
};

static struct {
    struct fh h[MAX_HANDLES];
    unsigned n;
    unsigned forbidden;               /* calls the P2 queries must never make */
    unsigned free_calls;
    int outstanding;                  /* pool buffers the firmware handed out and nobody freed */
    uint64_t locate_handle_status;    /* forced LocateHandle status, 0 for the real behaviour */
    void *owned[MAX_OWNED];
    unsigned n_owned;
} W;

static void *own(void *p)
{
    if (W.n_owned >= MAX_OWNED) { fprintf(stderr, "test bug: too many allocations\n"); exit(2); }
    W.owned[W.n_owned++] = p;
    return p;
}
static void world_reset(void)
{
    for (unsigned i = 0; i < W.n_owned; i++) free(W.owned[i]);
    memset(&W, 0, sizeof W);
}

static void trap(void) { W.forbidden++; }
#define TRAP ((void *)trap)

static const efi_guid G_LOADED = STK_GUID_LOADED_IMAGE, G_DP = STK_GUID_DEVICE_PATH, G_BLK = STK_GUID_BLOCK_IO;
static const efi_guid G_USB = STK_GUID_USB_IO, G_HC = STK_GUID_USB2_HC, G_PCI = STK_GUID_PCI_IO;
static int guid_eq(const efi_guid *a, const efi_guid *b) { return !memcmp(a, b, sizeof *a); }

static struct fh *as_fh(efi_handle handle)
{
    for (unsigned i = 0; i < W.n; i++)
        if (&W.h[i] == handle) return &W.h[i];
    return NULL;
}

static efi_status fake_handle_protocol(efi_handle handle, efi_guid *guid, void **out)
{
    struct fh *h = as_fh(handle);
    void *p = NULL;
    if (!h || !guid || !out) return EFI_INVALID_PARAMETER;
    if (guid_eq(guid, &G_LOADED)) p = h->image;
    else if (guid_eq(guid, &G_DP)) p = h->dp;
    else if (guid_eq(guid, &G_BLK)) p = h->bio;
    else if (guid_eq(guid, &G_USB)) p = h->usb;
    else if (guid_eq(guid, &G_PCI)) p = h->pci;
    else if (guid_eq(guid, &G_HC)) p = h->is_hc ? (void *)h : NULL;
    else W.forbidden++;                           /* a protocol the survey has no business asking for */
    if (!p) return EFI_UNSUPPORTED;
    *out = p;
    return 0;
}

static efi_status fake_locate_handle(uint32_t type, efi_guid *guid, void *key, uint64_t *size, efi_handle *buffer)
{
    unsigned count = 0, k = 0;
    if (type != EFI_BY_PROTOCOL || !guid || key || !size) { W.forbidden++; return EFI_INVALID_PARAMETER; }
    if (W.locate_handle_status) return W.locate_handle_status;
    if (!guid_eq(guid, &G_HC)) { W.forbidden++; return EFI_NOT_FOUND; }
    for (unsigned i = 0; i < W.n; i++) count += W.h[i].is_hc != 0;
    if (!count) { *size = 0; return EFI_NOT_FOUND; }
    if (*size < count * sizeof(efi_handle)) { *size = count * sizeof(efi_handle); return EFI_BUFFER_TOO_SMALL; }
    for (unsigned i = 0; i < W.n; i++)
        if (W.h[i].is_hc) buffer[k++] = &W.h[i];
    *size = count * sizeof(efi_handle);
    return 0;
}

/* Bytes before the end node, 0xffffffff for a path that is not well formed. */
static unsigned dp_len(const uint8_t *dp)
{
    unsigned n = 0;
    while (!(dp[n] == 0x7f && dp[n + 1] == 0xff)) {
        unsigned len = (unsigned)dp[n + 2] | (unsigned)dp[n + 3] << 8;
        if (len < 4 || n + len > 600) return ~0u;
        n += len;
    }
    return n;
}

/* UEFI 2.x 7.3: the handle with the protocol whose path is the longest prefix of the given one; the
 * path pointer is advanced past what matched. */
static efi_status fake_locate_device_path(efi_guid *guid, const uint8_t **path, efi_handle *device)
{
    const uint8_t *want;
    unsigned want_len, best_len = 0;
    struct fh *best = NULL;
    if (!guid || !path || !*path || !device) return EFI_INVALID_PARAMETER;
    want = *path;
    want_len = dp_len(want);
    if (want_len == ~0u) return EFI_INVALID_PARAMETER;
    for (unsigned i = 0; i < W.n; i++) {
        struct fh *h = &W.h[i];
        int has = guid_eq(guid, &G_BLK) ? h->bio != NULL : guid_eq(guid, &G_USB) ? h->usb != NULL : 0;
        unsigned len;
        if (!has || !h->dp) continue;
        len = dp_len(h->dp);
        if (len == ~0u || len > want_len || memcmp(h->dp, want, len)) continue;
        if (!best || len > best_len) { best = h; best_len = len; }
    }
    if (!best) return EFI_NOT_FOUND;
    *path = want + best_len;
    *device = best;
    return 0;
}

static efi_status fake_free_pool(void *p)
{
    W.free_calls++;
    if (!p) return EFI_INVALID_PARAMETER;
    free(p);
    W.outstanding--;
    return 0;
}
static efi_status fake_allocate_pages(uint32_t a, uint32_t b, uint64_t c, uint64_t *d)
{
    (void)a; (void)b; (void)c; (void)d;
    W.forbidden++;
    return EFI_UNSUPPORTED;
}
static efi_status fake_get_memory_map(uint64_t *a, void *b, uint64_t *c, uint64_t *d, uint32_t *e)
{
    (void)a; (void)b; (void)c; (void)d; (void)e;
    W.forbidden++;
    return EFI_UNSUPPORTED;
}
static efi_status fake_exit_boot_services(efi_handle a, uint64_t b)
{
    (void)a; (void)b;
    W.forbidden++;
    return EFI_UNSUPPORTED;
}

/* ---- Fake USB I/O: descriptors only, from the cache ---- */

static efi_status usb_get_device(struct stk_efi_usb_io *io, uint8_t *out)
{
    struct fake_usb *f = (struct fake_usb *)io;
    f->calls_dev++;
    if (f->fail_dev) return EFI_UNSUPPORTED;
    memcpy(out, f->dev, sizeof f->dev);
    return 0;
}
static efi_status usb_get_interface(struct stk_efi_usb_io *io, uint8_t *out)
{
    struct fake_usb *f = (struct fake_usb *)io;
    f->calls_intf++;
    if (f->fail_intf) return EFI_UNSUPPORTED;
    memcpy(out, f->intf, sizeof f->intf);
    return 0;
}
static efi_status usb_get_endpoint(struct stk_efi_usb_io *io, uint8_t index, uint8_t *out)
{
    struct fake_usb *f = (struct fake_usb *)io;
    f->calls_ep++;
    if (index > 15 || (f->fail_ep_mask >> index & 1)) return EFI_UNSUPPORTED;
    memcpy(out, f->ep[index], STK_USB_ENDPOINT_DESC_BYTES);
    return 0;
}

static void set_ep(struct fake_usb *f, unsigned i, unsigned address, unsigned attributes, unsigned mps)
{
    f->ep[i][0] = 7;
    f->ep[i][1] = 5;
    f->ep[i][STK_USB_EP_ADDRESS] = (uint8_t)address;
    f->ep[i][STK_USB_EP_ATTRIBUTES] = (uint8_t)attributes;
    f->ep[i][STK_USB_EP_MAX_PACKET] = (uint8_t)mps;
    f->ep[i][STK_USB_EP_MAX_PACKET + 1] = (uint8_t)(mps >> 8);
    f->ep[i][6] = 0;
}

/* A mass storage interface (class 8) at SuperSpeed, or a hub (class 9). */
static struct fake_usb *new_usb(unsigned bcd_usb, int hub)
{
    struct fake_usb *f = own(calloc(1, sizeof *f));
    f->io.get_device_descriptor = usb_get_device;
    f->io.get_interface_descriptor = usb_get_interface;
    f->io.get_endpoint_descriptor = usb_get_endpoint;
    f->io.control_transfer = f->io.bulk_transfer = f->io.async_interrupt_transfer = TRAP;
    f->io.sync_interrupt_transfer = f->io.isochronous_transfer = f->io.async_isochronous_transfer = TRAP;
    f->io.get_config_descriptor = f->io.get_string_descriptor = f->io.get_supported_languages = TRAP;
    f->io.port_reset = TRAP;
    f->dev[0] = 18; f->dev[1] = 1;
    f->dev[STK_USB_BCD_USB] = (uint8_t)bcd_usb;
    f->dev[STK_USB_BCD_USB + 1] = (uint8_t)(bcd_usb >> 8);
    f->dev[7] = 9;
    f->dev[8] = VENDOR_ID & 0xff; f->dev[9] = VENDOR_ID >> 8;
    f->dev[10] = PRODUCT_ID & 0xff; f->dev[11] = PRODUCT_ID >> 8;
    f->dev[14] = 1; f->dev[15] = 2; f->dev[16] = SERIAL_INDEX; f->dev[17] = 1;
    f->intf[0] = 9; f->intf[1] = 4;
    if (hub) {
        f->intf[STK_USB_IF_NUM_ENDPOINTS] = 1;
        f->intf[STK_USB_IF_CLASS] = 9; f->intf[STK_USB_IF_SUBCLASS] = 0; f->intf[STK_USB_IF_PROTOCOL] = 1;
        set_ep(f, 0, 0x81, 3, 4);
    } else {
        f->intf[STK_USB_IF_NUM_ENDPOINTS] = 2;
        f->intf[STK_USB_IF_CLASS] = 8; f->intf[STK_USB_IF_SUBCLASS] = 6; f->intf[STK_USB_IF_PROTOCOL] = 0x50;
        set_ep(f, 0, 0x81, 2, 0x400);
        set_ep(f, 1, 0x02, 2, 0x400);
    }
    return f;
}

/* ---- Fake PCI I/O ---- */

static efi_status pci_cfg_read(struct stk_efi_pci_io *io, uint32_t width, uint32_t offset, uint64_t count, void *buffer)
{
    struct fake_pci *f = (struct fake_pci *)io;
    unsigned unit = width == STK_PCI_WIDTH_UINT8 ? 1 : width == STK_PCI_WIDTH_UINT32 ? 4 : 0;
    f->cfg_reads++;
    if (f->cfg_fail) return EFI_ERROR(7);
    if (!unit || offset + count * unit > sizeof f->cfg) return EFI_UNSUPPORTED;
    memcpy(buffer, f->cfg + offset, count * unit);
    return 0;
}
static efi_status pci_mem_read(struct stk_efi_pci_io *io, uint32_t width, uint8_t bar, uint64_t offset, uint64_t count,
                               void *buffer)
{
    struct fake_pci *f = (struct fake_pci *)io;
    unsigned index = f->mem_reads++;
    if (f->mem_trace_n < MAX_TRACE) f->mem_trace[f->mem_trace_n++] = (uint32_t)offset;
    if (width != STK_PCI_WIDTH_UINT32 || bar != 0 || count != 1 || (offset & 3) || offset + 4 > f->window)
        return EFI_UNSUPPORTED;
    if ((int)index == f->mem_fail_at) return EFI_ERROR(7);
    memcpy(buffer, &f->regs[offset / 4], 4);
    return 0;
}
static efi_status pci_get_location(struct stk_efi_pci_io *io, uint64_t *seg, uint64_t *bus, uint64_t *dev, uint64_t *fn)
{
    struct fake_pci *f = (struct fake_pci *)io;
    if (!f->loc_ok) return EFI_UNSUPPORTED;
    *seg = f->seg; *bus = f->bus; *dev = f->dev; *fn = f->fn;
    return 0;
}
static efi_status pci_get_bar_attributes(struct stk_efi_pci_io *io, uint8_t bar, uint64_t *supports, void **resources)
{
    struct fake_pci *f = (struct fake_pci *)io;
    uint8_t *d;
    (void)supports;
    f->attr_calls++;
    if (!f->attr_mode || bar != 0 || !resources) return EFI_UNSUPPORTED;
    d = calloc(1, 48);
    W.outstanding++;                              /* a firmware pool buffer: the caller must FreePool it */
    d[0] = f->attr_mode == 2 ? 0x88 : STK_ACPI_QWORD_TAG;          /* mode 2: not a QWORD descriptor */
    d[1] = f->attr_mode == 3 ? 10 : 43;                            /* mode 3: too short to hold an address */
    memcpy(d + STK_ACPI_QWORD_MIN, &f->attr_base, 8);
    d[46] = 0x79;
    *resources = d;
    return 0;
}

/* A controller that looks like the Denali xHCI: version 1.10, CAPLENGTH 0x40, two ports; run, a
 * connected port 1 and a disconnected powered port 2. */
static struct fake_pci *new_pci(uint64_t bar0, unsigned dev)
{
    struct fake_pci *f = own(calloc(1, sizeof *f));
    f->io.poll_mem = f->io.poll_io = TRAP;
    f->io.mem.read = pci_mem_read;
    f->io.mem.write = TRAP;
    f->io.io.read = f->io.io.write = TRAP;
    f->io.pci.read = pci_cfg_read;
    f->io.pci.write = TRAP;
    f->io.copy_mem = f->io.map = f->io.unmap = f->io.allocate_buffer = f->io.free_buffer = f->io.flush = TRAP;
    f->io.get_location = pci_get_location;
    f->io.attributes = TRAP;
    f->io.get_bar_attributes = pci_get_bar_attributes;
    f->io.set_bar_attributes = TRAP;
    f->io.rom_image = TRAP;
    f->cfg[STK_PCI_CLASSCODE] = 0x30;
    f->cfg[STK_PCI_CLASSCODE + 1] = 0x03;
    f->cfg[STK_PCI_CLASSCODE + 2] = 0x0c;
    {
        uint32_t lo = (uint32_t)(bar0 & 0xfffffff0u) | 4u, hi = (uint32_t)(bar0 >> 32);
        memcpy(f->cfg + STK_PCI_BAR0, &lo, 4);
        memcpy(f->cfg + STK_PCI_BAR0 + 4, &hi, 4);
    }
    f->mem_fail_at = -1;
    f->window = 0x500;
    f->regs[0x00 / 4] = 0x01100040u;              /* HCIVERSION 1.10, CAPLENGTH 0x40 */
    f->regs[0x04 / 4] = 0x02000040u;              /* MaxPorts 2, MaxSlots 0x40 */
    f->regs[0x40 / 4] = 0x5;                      /* USBCMD: run, interrupter enable */
    f->regs[0x44 / 4] = 0x0;                      /* USBSTS */
    f->regs[0x58 / 4] = 0x0; f->regs[0x5c / 4] = 0x0;
    f->regs[0x70 / 4] = 0x08b1a000u; f->regs[0x74 / 4] = 0x0;
    f->regs[0x440 / 4] = 0x1203;                  /* PORTSC1 */
    f->regs[0x450 / 4] = 0x2a0;                   /* PORTSC2 */
    f->loc_ok = 1;
    f->dev = dev;
    return f;
}

static struct stk_efi_block_io *new_bio(uint64_t last, uint32_t block_size, int removable, int read_only, int logical)
{
    struct stk_efi_block_io *b = own(calloc(1, sizeof *b));
    struct stk_efi_block_io_media *m = own(calloc(1, sizeof *m));
    m->present = 1;
    m->removable = (uint8_t)removable;
    m->read_only = (uint8_t)read_only;
    m->logical_partition = (uint8_t)logical;
    m->block_size = block_size;
    m->last_block = last;
    b->revision = 0x20001;
    b->media = m;
    return b;
}

static struct fh *new_handle(const char *name)
{
    struct fh *h;
    if (W.n >= MAX_HANDLES) { fprintf(stderr, "test bug: too many handles\n"); exit(2); }
    h = &W.h[W.n++];
    memset(h, 0, sizeof *h);
    h->name = name;
    return h;
}
/* The path as a heap block of exactly its bytes, end node included. */
static void set_dp(struct fh *h, const struct pb *p)
{
    h->dp = own(malloc(p->n));
    memcpy(h->dp, p->b, p->n);
}
/* A padded block, for the paths a walker may run off the end of. */
static void set_dp_padded(struct fh *h, const struct pb *p)
{
    h->dp = own(calloc(1, 640));
    memcpy(h->dp, p->b, p->n);
}

/* ---- A world built from a shape ---- */

struct shape {
    int acpi;                    /* a PciRoot node in front */
    unsigned pci_dev;
    unsigned usb_ports[3];
    unsigned n_usb;
    int unit;                    /* a logical unit node after the last USB node */
    int hd;                      /* a hard drive node: the stick has a partition table */
    unsigned hd_number, hd_type;
    uint64_t hd_start, hd_size;
    int other_hc_first;          /* the other controller is listed before the stick's */
    int stick_hc_has_pci;        /* the stick's controller has a PCI I/O protocol */
    int with_other_hc;
    unsigned extra_hc_before;    /* further controllers listed before the stick's */
};
static struct shape shape_hub(void)
{
    struct shape s = {1, 0x81, {1, 2, 0}, 2, 1, 1, 1, 1, 0x800, 0x3b8000, 1, 1, 1, 0};
    return s;
}

struct world {
    struct fh *image, *part, *disk, *usbif[3], *hc_stick, *hc_other;
    struct fake_pci *pci_stick, *pci_other;
};

static void path_hc(struct pb *p, const struct shape *s)
{
    p->n = 0;
    if (s->acpi) pb_acpi(p);
    pb_pci(p, s->pci_dev, 0);
}
static void path_usb(struct pb *p, const struct shape *s, unsigned nodes)
{
    path_hc(p, s);
    for (unsigned i = 0; i < nodes; i++) pb_usb(p, s->usb_ports[i], 0);
}
static void path_disk(struct pb *p, const struct shape *s)
{
    path_usb(p, s, s->n_usb);
    if (s->unit) pb_unit(p);
}
static void path_part(struct pb *p, const struct shape *s)
{
    path_disk(p, s);
    if (s->hd) pb_hd(p, s->hd_number, s->hd_start, s->hd_size, s->hd_type);
}

static const uint64_t BAR_U0 = 0x0a600000u, BAR_U1 = 0x0a800000u;

static void build_world(const struct shape *s, struct world *w)
{
    struct pb p;
    world_reset();
    memset(w, 0, sizeof *w);

    for (unsigned i = 0; i < s->extra_hc_before; i++) {
        struct shape o = *s;
        struct fh *h = new_handle("hc-extra");
        o.pci_dev = 0x90 + i;
        h->is_hc = 1;
        path_hc(&p, &o); pb_end(&p); set_dp(h, &p);
        h->pci = new_pci(BAR_U1, o.pci_dev);
    }
    if (s->with_other_hc && s->other_hc_first) {
        struct shape o = *s;
        o.pci_dev = s->pci_dev + 1;
        w->hc_other = new_handle("hc-other");
        w->hc_other->is_hc = 1;
        path_hc(&p, &o); pb_end(&p); set_dp(w->hc_other, &p);
        w->pci_other = w->hc_other->pci = new_pci(BAR_U1, o.pci_dev);
    }
    w->hc_stick = new_handle("hc-stick");
    w->hc_stick->is_hc = 1;
    path_hc(&p, s); pb_end(&p); set_dp(w->hc_stick, &p);
    if (s->stick_hc_has_pci) w->pci_stick = w->hc_stick->pci = new_pci(BAR_U0, s->pci_dev);
    if (s->with_other_hc && !s->other_hc_first) {
        struct shape o = *s;
        o.pci_dev = s->pci_dev + 1;
        w->hc_other = new_handle("hc-other");
        w->hc_other->is_hc = 1;
        path_hc(&p, &o); pb_end(&p); set_dp(w->hc_other, &p);
        w->pci_other = w->hc_other->pci = new_pci(BAR_U1, o.pci_dev);
    }

    /* One USB I/O handle per USB node: hubs on the way, the mass storage interface last. */
    for (unsigned i = 0; i < s->n_usb; i++) {
        w->usbif[i] = new_handle("usb-interface");
        path_usb(&p, s, i + 1); pb_end(&p); set_dp(w->usbif[i], &p);
        w->usbif[i]->usb = new_usb(0x320, i + 1 < s->n_usb);
    }
    /* The raw disk: the unit child of the last interface, or the interface handle itself. */
    if (s->unit || !s->n_usb) {
        w->disk = new_handle("disk");
        path_disk(&p, s); pb_end(&p); set_dp(w->disk, &p);
    } else {
        w->disk = w->usbif[s->n_usb - 1];
    }
    w->disk->bio = new_bio(0x1d1bfff, 512, s->n_usb != 0, 0, 0);
    if (s->hd) {
        w->part = new_handle("partition");
        path_part(&p, s); pb_end(&p); set_dp(w->part, &p);
        w->part->bio = new_bio(s->hd_size - 1, 512, s->n_usb != 0, 0, 1);
    }
    w->image = new_handle("image");
    w->image->image = own(calloc(1, sizeof *w->image->image));
    w->image->image->device = s->hd ? (efi_handle)w->part : (efi_handle)w->disk;
}

/* ---- Running the queries and what every run owes ---- */

struct run {
    struct stk_p2 p2;
    char con[40][STK_LINE_MAX + 8];
    unsigned n_con;
    unsigned bad;
};
static void con_emit(void *ctx, const char *line)
{
    struct run *r = ctx;
    if (strlen(line) > STK_LINE_MAX || !stk_text_ok(line) || strncmp(line, "STK P2 ", 7)) r->bad++;
    if (r->n_con < 40) {
        snprintf(r->con[r->n_con], sizeof r->con[0], "%s", line);
        r->n_con++;
    }
}

static struct efi_boot_services bs;
static struct efi_system_table st;

static void firmware_init(void)
{
    memset(&bs, 0, sizeof bs);
    bs.raise_tpl = bs.restore_tpl = TRAP;
    bs.allocate_pages = fake_allocate_pages;
    bs.get_memory_map = fake_get_memory_map;
    bs.allocate_pool = TRAP;
    bs.free_pool = fake_free_pool;
    bs.create_event = bs.set_timer = bs.wait_event = bs.signal_event = bs.close_event = bs.check_event = TRAP;
    bs.install_protocol = bs.reinstall_protocol = bs.uninstall_protocol = TRAP;
    bs.handle_protocol = fake_handle_protocol;
    bs.locate_handle = fake_locate_handle;
    bs.locate_device_path = (void *)fake_locate_device_path;
    bs.install_config = bs.load_image = bs.start_image = bs.exit = bs.unload_image = TRAP;
    bs.exit_boot_services = fake_exit_boot_services;
    bs.get_next_monotonic_count = bs.stall = TRAP;
    bs.disconnect_controller = bs.open_protocol = bs.close_protocol = bs.open_protocol_information = TRAP;
    bs.protocols_per_handle = TRAP;
    memset(&st, 0, sizeof st);
    st.boot = &bs;
}

static void run_p2(struct run *r, efi_handle image, const char *stamp, int with_console)
{
    /* Counters are per run: a world may be run again after a change. */
    for (unsigned i = 0; i < W.n; i++) {
        struct fake_usb *u = W.h[i].usb;
        struct fake_pci *p = W.h[i].pci;
        if (u) u->calls_dev = u->calls_intf = u->calls_ep = 0;
        if (p) { p->mem_reads = p->cfg_reads = p->attr_calls = p->mem_trace_n = 0; }
    }
    W.forbidden = W.free_calls = 0;
    memset(r, 0, sizeof *r);
    memset(&r->p2, 0xcc, sizeof r->p2);          /* the collector must initialise what it reports */
    firmware_init();
    stk_p2_collect(&st, image, stamp, &r->p2, with_console ? con_emit : NULL, r);
}

static int contains(const char *hay, const char *needle) { return strstr(hay, needle) != NULL; }

static unsigned total_mem_reads(void)
{
    unsigned n = 0;
    for (unsigned i = 0; i < W.n; i++)
        if (W.h[i].pci) n += W.h[i].pci->mem_reads;
    return n;
}

#define BAD(...) do { fprintf(stderr, "FAIL line %d: ", line); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); return 1; } while (0)

/* Everything a run owes however the firmware answered. */
static int invariants(const struct run *r, int line)
{
    /* Neither the vendor id, the product id nor the serial string index is printed, in hex or in
     * decimal, and no field is labelled as one. */
    static const char *const banned[] = {"BEEF", "CAFE", "48879", "51966", "VID=", "PID=", "SERIAL", "VENDOR", "PRODUCT", "MANUF"};
    if (W.forbidden) BAD("%u forbidden firmware calls", W.forbidden);
    if (W.outstanding) BAD("%d pool buffers not freed", W.outstanding);
    if (r->bad) BAD("%u lines outside the font, over 100 characters or not P2", r->bad);
    if (r->p2.count > STK_P2_MAX_LINES) BAD("%u kept lines", r->p2.count);
    if (r->p2.count + r->p2.dropped != r->n_con && r->n_con < 40)
        BAD("kept %u + dropped %u != printed %u", r->p2.count, r->p2.dropped, r->n_con);
    for (unsigned i = 0; i < r->p2.count && i < r->n_con; i++)
        if (strcmp(r->p2.line[i], r->con[i])) BAD("kept line %u differs from the printed one", i);
    for (unsigned i = 0; i < r->n_con; i++)
        for (unsigned b = 0; b < sizeof banned / sizeof banned[0]; b++)
            if (contains(r->con[i], banned[b])) BAD("identifier leaked: %s", r->con[i]);
    for (unsigned i = 0; i < W.n; i++) {
        struct fake_usb *u = W.h[i].usb;
        struct fake_pci *p = W.h[i].pci;
        if (u && (u->calls_dev > 1 || u->calls_intf > 1 || u->calls_ep > STK_USB_EP_INDEX_MAX)) BAD("descriptor calls out of bound");
        if (p && p->mem_reads > 10) BAD("%u memory reads", p->mem_reads);
    }
    if (total_mem_reads() > 10) BAD("%u memory reads in all", total_mem_reads());
    checks++;
    return 0;
}
#define INVARIANTS(r) do { if (invariants((r), __LINE__)) return 1; } while (0)

static int expect_lines(const struct run *r, const char *const *want, unsigned n, int line)
{
    int ok = r->n_con == n;
    for (unsigned i = 0; ok && i < n; i++) ok = !strcmp(r->con[i], want[i]);
    if (!ok) {
        fprintf(stderr, "FAIL %s:%d: P2 lines differ\n", __FILE__, line);
        for (unsigned i = 0; i < r->n_con; i++) fprintf(stderr, "  got  %s\n", r->con[i]);
        for (unsigned i = 0; i < n; i++) fprintf(stderr, "  want %s\n", want[i]);
        return 1;
    }
    checks++;
    return 0;
}
#define EXPECT(r, ...) do { \
        const char *w_[] = {__VA_ARGS__}; \
        if (expect_lines((r), w_, sizeof w_ / sizeof w_[0], __LINE__)) return 1; \
    } while (0)

/* The index of the first printed line with this prefix, or -1. */
static int find(const struct run *r, const char *prefix)
{
    for (unsigned i = 0; i < r->n_con; i++)
        if (!strncmp(r->con[i], prefix, strlen(prefix))) return (int)i;
    return -1;
}

static const char *EXPECT_BASELINE =
    "STK P2 U0 CAPLEN=0X40 USBCMD=0X5 USBSTS=0X0 CRCR=0X0 DCBAAP=0X8B1A000 PORTSC1=0X1203 PORTSC2=0X2A0";

/* ---- Shapes of the path ---- */

static int test_shapes(void)
{
    struct world w;
    struct run r;
    struct shape s;

    /* The stick's real shape: a PCI node whose device number does not fit in 5 bits, a hub and the
     * stick behind it, the mass storage child, a partition. The other controller is listed first. */
    s = shape_hub();
    build_world(&s, &w);
    run_p2(&r, w.image, "abcdef12", 1);
    EXPECT(&r,
           "STK P2 BUILD GATE=1 REV=ABCDEF12",
           "STK P2 SELF PATH=T2.1/PCI(81.0)/USB(1.0)/USB(2.0)/T3.11/HD(1.MBR)",
           "STK P2 HUB USBNODES=2 ROOTIDX=1 HUBPORTIDX=2",
           "STK P2 BLK LASTLBA=0X1D1BFFF BLKSZ=0X200 REMOVABLE=1 READONLY=0 PARTSTART=0X800 PARTSIZE=0X3B8000",
           "STK P2 USBIO BCDUSB=0X320 CLASS=0X8 SUB=0X6 PROTO=0X50 EPIN=0X81 EPOUT=0X2 MPS=0X400",
           "STK P2 HC N=2",
           "STK P2 HC HC0 BAR0=0XA800000 CLASS=0XC0330 LOC=0.0.82.0",
           "STK P2 HC HC1 BAR0=0XA600000 CLASS=0XC0330 LOC=0.0.81.0",
           EXPECT_BASELINE);
    INVARIANTS(&r);
    CHECK(r.p2.count == 9 && r.p2.dropped == 0);
    /* Only the stick's own controller was read; the other saw configuration space only. */
    CHECK(w.pci_stick->mem_reads == 10 && w.pci_other->mem_reads == 0);
    {
        static const uint32_t trace[10] = {0x0, 0x4, 0x40, 0x44, 0x58, 0x5c, 0x70, 0x74, 0x440, 0x450};
        CHECK(w.pci_stick->mem_trace_n == 10 && !memcmp(w.pci_stick->mem_trace, trace, sizeof trace));
    }
    CHECK(W.free_calls == 0);                              /* BAR0 came from configuration space */
    /* The stick's interface was asked for descriptors only, the hub's not at all. */
    CHECK(w.usbif[0]->usb->calls_dev == 0 && w.usbif[0]->usb->calls_intf == 0 && w.usbif[0]->usb->calls_ep == 0);
    CHECK(w.usbif[1]->usb->calls_dev == 1 && w.usbif[1]->usb->calls_intf == 1 && w.usbif[1]->usb->calls_ep == 2);
    for (unsigned i = 0; i < r.n_con; i++)
        CHECK(!contains(r.con[i], "0XA7") && !contains(r.con[i], "=167"));     /* the serial string index */

    /* The same stick with no logical unit node: the interface handle is also the raw disk. */
    s = shape_hub();
    s.unit = 0;
    build_world(&s, &w);
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[1], "STK P2 SELF PATH=T2.1/PCI(81.0)/USB(1.0)/USB(2.0)/HD(1.MBR)"));
    CHECK(!strcmp(r.con[3], "STK P2 BLK LASTLBA=0X1D1BFFF BLKSZ=0X200 REMOVABLE=1 READONLY=0 PARTSTART=0X800 PARTSIZE=0X3B8000"));
    CHECK(!strcmp(r.con[4], "STK P2 USBIO BCDUSB=0X320 CLASS=0X8 SUB=0X6 PROTO=0X50 EPIN=0X81 EPOUT=0X2 MPS=0X400"));
    INVARIANTS(&r);

    /* A direct attachment: one USB node, a GPT partition, no PciRoot in front. */
    s = shape_hub();
    s.acpi = 0;
    s.n_usb = 1;
    s.usb_ports[0] = 3;
    s.hd_number = 2;
    s.hd_type = 2;
    s.hd_start = 0x20;
    s.hd_size = 0x100;
    build_world(&s, &w);
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[1], "STK P2 SELF PATH=PCI(81.0)/USB(3.0)/T3.11/HD(2.GPT)"));
    CHECK(!strcmp(r.con[2], "STK P2 HUB USBNODES=1 ROOTIDX=3 HUBPORTIDX=NONE"));
    CHECK(!strcmp(r.con[3], "STK P2 BLK LASTLBA=0X1D1BFFF BLKSZ=0X200 REMOVABLE=1 READONLY=0 PARTSTART=0X20 PARTSIZE=0X100"));
    CHECK(!strncmp(r.con[4], "STK P2 USBIO BCDUSB=0X320 CLASS=0X8 ", 36));
    CHECK(find(&r, "STK P2 U0 CAPLEN") >= 0);              /* the stick's controller, found without the root node */
    INVARIANTS(&r);

    /* A bare volume: no hard drive node, the image's own handle carries the raw media. */
    s = shape_hub();
    s.n_usb = 1;
    s.usb_ports[0] = 1;
    s.hd = 0;
    build_world(&s, &w);
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[1], "STK P2 SELF PATH=T2.1/PCI(81.0)/USB(1.0)/T3.11"));
    CHECK(!strcmp(r.con[3], "STK P2 BLK LASTLBA=0X1D1BFFF BLKSZ=0X200 REMOVABLE=1 READONLY=0 PARTSTART=0X0 PARTSIZE=NONE"));
    INVARIANTS(&r);

    /* Not USB at all: a PCI disk, as under QEMU. */
    s = shape_hub();
    s.n_usb = 0;
    s.unit = 0;
    s.pci_dev = 1;
    s.with_other_hc = 0;
    s.stick_hc_has_pci = 0;
    build_world(&s, &w);
    w.hc_stick->is_hc = 0;
    run_p2(&r, w.image, "abcdef12", 1);
    EXPECT(&r,
           "STK P2 BUILD GATE=1 REV=ABCDEF12",
           "STK P2 SELF PATH=T2.1/PCI(1.0)/HD(1.MBR)",
           "STK P2 HUB USBNODES=0 ROOTIDX=NONE HUBPORTIDX=NONE",
           "STK P2 BLK LASTLBA=0X1D1BFFF BLKSZ=0X200 REMOVABLE=0 READONLY=0 PARTSTART=0X800 PARTSIZE=0X3B8000",
           "STK P2 USBIO SKIPPED=NO_USB_NODE",
           "STK P2 HC N=0",
           "STK P2 UX SKIPPED=NOT_USB");
    INVARIANTS(&r);

    /* A build stamp that is not a hex revision says so; the font folds and replaces the rest. */
    s = shape_hub();
    build_world(&s, &w);
    run_p2(&r, w.image, "PROOF", 1);
    CHECK(!strcmp(r.con[0], "STK P2 BUILD GATE=1 REV=?"));
    run_p2(&r, w.image, "0123abcd-dirty", 1);
    CHECK(!strcmp(r.con[0], "STK P2 BUILD GATE=1 REV=0123ABCD"));
    run_p2(&r, w.image, NULL, 1);
    CHECK(!strcmp(r.con[0], "STK P2 BUILD GATE=1 REV=?"));
    INVARIANTS(&r);

    /* Without a console callback the lines are still kept, and run again they are the same. */
    s = shape_hub();
    build_world(&s, &w);
    run_p2(&r, w.image, "abcdef12", 0);
    CHECK(r.n_con == 0 && r.p2.count == 9 && r.p2.dropped == 0);
    CHECK(!strcmp(r.p2.line[0], "STK P2 BUILD GATE=1 REV=ABCDEF12") && !strcmp(r.p2.line[8], EXPECT_BASELINE));
    return 0;
}

/* ---- The baseline ---- */

static int test_baseline(void)
{
    struct world w;
    struct run r;
    struct shape s = shape_hub();
    static const uint32_t full_trace[10] = {0x0, 0x4, 0x40, 0x44, 0x58, 0x5c, 0x70, 0x74, 0x440, 0x450};

    /* The stick's controller is the fifth of five: it is still found, and only it is read. */
    s.with_other_hc = 0;
    s.extra_hc_before = 4;
    build_world(&s, &w);
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(find(&r, "STK P2 HC N=5 MORE=2") == 5);
    CHECK(find(&r, "STK P2 HC HC0") == 6 && find(&r, "STK P2 HC HC1") == 7 && find(&r, "STK P2 HC HC2") == 8);
    CHECK(find(&r, "STK P2 HC HC3") < 0);
    CHECK(!strcmp(r.con[r.n_con - 1], EXPECT_BASELINE));
    CHECK(w.pci_stick->mem_reads == 10 && total_mem_reads() == 10);
    INVARIANTS(&r);

    /* Only one port: no second PORTSC read, and the line says NONE. */
    s = shape_hub();
    build_world(&s, &w);
    w.pci_stick->regs[1] = 0x01000040u;
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[r.n_con - 1],
                  "STK P2 U0 CAPLEN=0X40 USBCMD=0X5 USBSTS=0X0 CRCR=0X0 DCBAAP=0X8B1A000 PORTSC1=0X1203 PORTSC2=NONE"));
    CHECK(w.pci_stick->mem_reads == 9);
    INVARIANTS(&r);

    /* A controller that does not look like xHCI is not read further than its capability dwords. */
    {
        struct { uint32_t cap0; const char *why; } bad[] = {
            {0xffffffffu, "all ones"},  {0x01100000u, "no CAPLENGTH"}, {0x0110001bu, "CAPLENGTH too small"},
            {0x011000fdu, "CAPLENGTH too large"}, {0x01100041u, "CAPLENGTH not a dword multiple"},
            {0x00890040u, "version below 0.9"}, {0x02000040u, "version above 1.ff"}, {0x00000000u, "zero"},
        };
        for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            s = shape_hub();
            build_world(&s, &w);
            w.pci_stick->regs[0] = bad[i].cap0;
            run_p2(&r, w.image, "abcdef12", 1);
            if (strcmp(r.con[r.n_con - 1], "STK P2 U0 SKIPPED=NOT_XHCI")) {
                fprintf(stderr, "FAIL %s:%d: %s: %s\n", __FILE__, __LINE__, bad[i].why, r.con[r.n_con - 1]);
                return 1;
            }
            CHECK(w.pci_stick->mem_reads == 2);               /* the two capability dwords and no more */
            INVARIANTS(&r);
        }
        /* The edges that are xHCI: 0.90, 1.ff, CAPLENGTH 0x1c and 0xfc. */
        uint32_t good[] = {0x00900040u, 0x01ff0040u, 0x0110001cu, 0x011000fcu};
        for (unsigned i = 0; i < sizeof good / sizeof good[0]; i++) {
            s = shape_hub();
            build_world(&s, &w);
            w.pci_stick->regs[0] = good[i];
            run_p2(&r, w.image, "abcdef12", 1);
            CHECK(!contains(r.con[r.n_con - 1], "SKIPPED") && w.pci_stick->mem_reads >= 9);
            INVARIANTS(&r);
        }
    }

    /* A read that fails, at each point: the baseline says MEM_READ and stops asking. The one read
     * that may fail without ending it is PORTSC2, which is then "?" (not NONE: the port exists). */
    for (unsigned k = 0; k < 10; k++) {
        s = shape_hub();
        build_world(&s, &w);
        w.pci_stick->mem_fail_at = (int)k;
        run_p2(&r, w.image, "abcdef12", 1);
        if (k < 9) {
            CHECK(!strcmp(r.con[r.n_con - 1], "STK P2 U0 SKIPPED=MEM_READ"));
        } else {
            CHECK(!strcmp(r.con[r.n_con - 1],
                          "STK P2 U0 CAPLEN=0X40 USBCMD=0X5 USBSTS=0X0 CRCR=0X0 DCBAAP=0X8B1A000 PORTSC1=0X1203 PORTSC2=?"));
        }
        CHECK(w.pci_stick->mem_reads == k + 1);
        CHECK(!memcmp(w.pci_stick->mem_trace, full_trace, (size_t)w.pci_stick->mem_reads * 4));
        INVARIANTS(&r);
    }

    /* No MMIO service at all. */
    s = shape_hub();
    build_world(&s, &w);
    w.pci_stick->io.mem.read = NULL;
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[r.n_con - 1], "STK P2 U0 SKIPPED=MEM_READ"));
    INVARIANTS(&r);

    /* The stick's controller has no PCI I/O: nothing of it can be read, and the other one is not
     * read in its place. */
    s = shape_hub();
    s.stick_hc_has_pci = 0;
    build_world(&s, &w);
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(find(&r, "STK P2 HC HC1 PCIIO=NONE") >= 0);
    CHECK(!strcmp(r.con[r.n_con - 1], "STK P2 UX SKIPPED=NO_PCIIO"));
    CHECK(total_mem_reads() == 0);
    INVARIANTS(&r);

    /* No controller of the stick's path among the handles: skipped, and nothing read. */
    s = shape_hub();
    build_world(&s, &w);
    w.hc_stick->is_hc = 0;
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[r.n_con - 1], "STK P2 UX SKIPPED=NO_HC_MATCH"));
    CHECK(total_mem_reads() == 0);
    INVARIANTS(&r);
    /* A controller whose path is longer than or differs from the stick's front is not its controller. */
    s = shape_hub();
    build_world(&s, &w);
    {
        struct pb p;
        struct shape o = s;
        w.hc_stick->dp = NULL;
        path_usb(&p, &o, 1); pb_end(&p); set_dp(w.hc_stick, &p);
    }
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[r.n_con - 1], "STK P2 UX SKIPPED=NO_HC_MATCH") && total_mem_reads() == 0);
    INVARIANTS(&r);
    /* No handle at all with the host controller protocol. */
    s = shape_hub();
    build_world(&s, &w);
    w.hc_stick->is_hc = 0;
    w.hc_other->is_hc = 0;
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(find(&r, "STK P2 HC N=0") >= 0 && !strcmp(r.con[r.n_con - 1], "STK P2 UX SKIPPED=NO_HC_MATCH"));
    INVARIANTS(&r);

    /* BAR 0 from configuration space as a 32 bit BAR, then as an I/O BAR with the fallback. */
    s = shape_hub();
    build_world(&s, &w);
    {
        uint32_t lo = 0x0a600000u, hi = 0xdeadbeefu;     /* 32 bit BAR: the next dword is BAR 1 */
        memcpy(w.pci_stick->cfg + STK_PCI_BAR0, &lo, 4);
        memcpy(w.pci_stick->cfg + STK_PCI_BAR0 + 4, &hi, 4);
    }
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[find(&r, "STK P2 HC HC1")], "STK P2 HC HC1 BAR0=0XA600000 CLASS=0XC0330 LOC=0.0.81.0"));
    CHECK(!strcmp(r.con[r.n_con - 1], EXPECT_BASELINE));
    INVARIANTS(&r);

    s = shape_hub();
    build_world(&s, &w);
    {
        uint32_t io_bar = 0x1001u;
        memcpy(w.pci_stick->cfg + STK_PCI_BAR0, &io_bar, 4);
        w.pci_stick->attr_mode = 1;
        w.pci_stick->attr_base = BAR_U0;
    }
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[find(&r, "STK P2 HC HC1")], "STK P2 HC HC1 BAR0=0XA600000 CLASS=0XC0330 LOC=0.0.81.0"));
    CHECK(w.pci_stick->attr_calls == 1 && W.free_calls == 1 && W.outstanding == 0);    /* the pool buffer was freed */
    CHECK(!strcmp(r.con[r.n_con - 1], EXPECT_BASELINE));
    INVARIANTS(&r);

    /* Neither says where BAR 0 is: BAR0=?, and the baseline is labelled UX. */
    s = shape_hub();
    build_world(&s, &w);
    w.pci_stick->cfg_fail = 1;
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[find(&r, "STK P2 HC HC1")], "STK P2 HC HC1 BAR0=? CLASS=? LOC=0.0.81.0"));
    CHECK(!strncmp(r.con[r.n_con - 1], "STK P2 UX CAPLEN=0X40 ", 22));
    INVARIANTS(&r);

    /* A BAR 0 of zero is not an address. */
    s = shape_hub();
    build_world(&s, &w);
    memset(w.pci_stick->cfg + STK_PCI_BAR0, 0, 8);
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(contains(r.con[find(&r, "STK P2 HC HC1")], "BAR0=?"));
    INVARIANTS(&r);

    /* A descriptor that is not what the specification says is not believed, and is still freed. */
    for (int mode = 2; mode <= 3; mode++) {
        s = shape_hub();
        build_world(&s, &w);
        {
            uint32_t io_bar = 1u;
            memcpy(w.pci_stick->cfg + STK_PCI_BAR0, &io_bar, 4);
            w.pci_stick->attr_mode = mode;
            w.pci_stick->attr_base = BAR_U0;
        }
        run_p2(&r, w.image, "abcdef12", 1);
        CHECK(contains(r.con[find(&r, "STK P2 HC HC1")], "BAR0=?"));
        CHECK(W.free_calls == 1 && W.outstanding == 0);
        INVARIANTS(&r);
    }
    return 0;
}

/* ---- Protocols that are missing or fail ---- */

static int test_missing(void)
{
    struct world w;
    struct run r;
    struct shape s;

    /* No loaded image protocol, no device handle, no device path: the path is unknown. */
    for (int how = 0; how < 3; how++) {
        s = shape_hub();
        build_world(&s, &w);
        if (how == 0) w.image->image = NULL;
        if (how == 1) w.image->image->device = NULL;
        if (how == 2) w.part->dp = NULL;
        run_p2(&r, w.image, "abcdef12", 1);
        CHECK(!strcmp(r.con[1], "STK P2 SELF PATH=NONE"));
        CHECK(!strcmp(r.con[2], "STK P2 HUB SKIPPED=NO_PATH"));
        CHECK(!strcmp(r.con[3], "STK P2 BLK LASTLBA=? BLKSZ=? REMOVABLE=? READONLY=? PARTSTART=0X0 PARTSIZE=NONE"));
        CHECK(!strcmp(r.con[4], "STK P2 USBIO SKIPPED=NO_PATH"));
        CHECK(find(&r, "STK P2 HC N=2") >= 0);
        CHECK(!strcmp(r.con[r.n_con - 1], "STK P2 UX SKIPPED=NO_PATH") && total_mem_reads() == 0);
        INVARIANTS(&r);
    }

    /* The raw disk has no Block I/O, or reports itself as a partition, or has no media. */
    for (int how = 0; how < 3; how++) {
        s = shape_hub();
        build_world(&s, &w);
        if (how == 0) w.disk->bio = NULL;
        if (how == 1) { struct stk_efi_block_io_media *m = (struct stk_efi_block_io_media *)w.disk->bio->media; m->logical_partition = 1; }
        if (how == 2) w.disk->bio->media = NULL;
        run_p2(&r, w.image, "abcdef12", 1);
        CHECK(!strcmp(r.con[3], "STK P2 BLK LASTLBA=? BLKSZ=? REMOVABLE=? READONLY=? PARTSTART=0X800 PARTSIZE=0X3B8000"));
        INVARIANTS(&r);
    }
    /* A match short of the stick's own disk (an ancestor with Block I/O) is not the disk. */
    s = shape_hub();
    build_world(&s, &w);
    w.disk->bio = NULL;
    w.usbif[1]->bio = new_bio(0x77, 4096, 0, 1, 0);
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(contains(r.con[3], "LASTLBA=? "));
    INVARIANTS(&r);
    /* A read-only, fixed, 4 KiB disk is reported as it is; the line is too long for one row, so it
     * continues on a second line with the same prefix. */
    s = shape_hub();
    build_world(&s, &w);
    w.disk->bio = new_bio(0xffffffffffffffffull, 4096, 0, 1, 0);
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[3], "STK P2 BLK LASTLBA=0XFFFFFFFFFFFFFFFF BLKSZ=0X1000 REMOVABLE=0 READONLY=1 PARTSTART=0X800"));
    CHECK(!strcmp(r.con[4], "STK P2 BLK PARTSIZE=0X3B8000"));
    INVARIANTS(&r);

    /* USB I/O: missing, on an ancestor only, or failing in each descriptor call. */
    s = shape_hub();
    build_world(&s, &w);
    w.usbif[1]->usb = NULL;
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[4], "STK P2 USBIO SKIPPED=NO_STICK_USB_IO"));      /* the hub's interface is not the stick's */
    INVARIANTS(&r);
    s = shape_hub();
    build_world(&s, &w);
    w.usbif[0]->usb = NULL;
    w.usbif[1]->usb = NULL;
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[4], "STK P2 USBIO SKIPPED=NO_USB_IO"));
    INVARIANTS(&r);
    s = shape_hub();
    build_world(&s, &w);
    w.usbif[1]->usb->fail_dev = 1;
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[4], "STK P2 USBIO SKIPPED=NO_DEVICE_DESC"));
    INVARIANTS(&r);
    s = shape_hub();
    build_world(&s, &w);
    w.usbif[1]->usb->fail_intf = 1;
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[4], "STK P2 USBIO SKIPPED=NO_INTERFACE_DESC"));
    INVARIANTS(&r);
    s = shape_hub();
    build_world(&s, &w);
    w.usbif[1]->usb->fail_ep_mask = 1;                       /* endpoint 0 (IN) unreadable */
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[4], "STK P2 USBIO BCDUSB=0X320 CLASS=0X8 SUB=0X6 PROTO=0X50 EPIN=NONE EPOUT=0X2 MPS=0X400"));
    INVARIANTS(&r);
    s = shape_hub();
    build_world(&s, &w);
    w.usbif[1]->usb->fail_ep_mask = 3;
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[4], "STK P2 USBIO BCDUSB=0X320 CLASS=0X8 SUB=0X6 PROTO=0X50 EPIN=NONE EPOUT=NONE MPS=NONE"));
    INVARIANTS(&r);
    /* Endpoints that are not bulk are not the stick's bulk pipes; two INs keep the first; endpoint
     * counts beyond 16 are not followed. */
    s = shape_hub();
    build_world(&s, &w);
    {
        struct fake_usb *u = w.usbif[1]->usb;
        u->intf[STK_USB_IF_NUM_ENDPOINTS] = 255;
        set_ep(u, 0, 0x83, 3, 8);          /* interrupt in */
        set_ep(u, 1, 0x82, 2, 0x200);      /* bulk in */
        set_ep(u, 2, 0x84, 2, 0x100);      /* a second bulk in: ignored */
        set_ep(u, 3, 0x05, 2, 0x200);      /* bulk out */
        for (unsigned i = 4; i < 16; i++) set_ep(u, i, 0x86, 2, 0x40);
    }
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[4], "STK P2 USBIO BCDUSB=0X320 CLASS=0X8 SUB=0X6 PROTO=0X50 EPIN=0X82 EPOUT=0X5 MPS=0X200"));
    CHECK(w.usbif[1]->usb->calls_ep == 16);                   /* bounded, whatever the descriptor claims */
    INVARIANTS(&r);
    /* Bulk endpoints of different packet sizes are both reported. */
    s = shape_hub();
    build_world(&s, &w);
    set_ep(w.usbif[1]->usb, 1, 0x02, 2, 0x200);
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[4], "STK P2 USBIO BCDUSB=0X320 CLASS=0X8 SUB=0X6 PROTO=0X50 EPIN=0X81 EPOUT=0X2 MPS=0X400 MPSOUT=0X200"));
    INVARIANTS(&r);

    /* LocateHandle failing with an error of its own. */
    s = shape_hub();
    build_world(&s, &w);
    W.locate_handle_status = EFI_ERROR(7);
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[5], "STK P2 HC SKIPPED=LOCATE STATUS=0X8000000000000007"));
    CHECK(!strcmp(r.con[r.n_con - 1], "STK P2 UX SKIPPED=NO_HC_MATCH") && total_mem_reads() == 0);
    INVARIANTS(&r);
    /* More handles than the buffer holds: counted, none read. */
    s = shape_hub();
    build_world(&s, &w);
    for (unsigned i = 0; i < 38; i++) {
        struct fh *h = new_handle("many");
        struct pb p;
        path_hc(&p, &s); pb_end(&p); set_dp(h, &p);
        h->is_hc = 1;
        h->pci = new_pci(BAR_U1, 0x40 + i);
    }
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[5], "STK P2 HC N=40 MORE=40"));
    CHECK(!strcmp(r.con[r.n_con - 1], "STK P2 UX SKIPPED=NO_HC_MATCH") && total_mem_reads() == 0);
    INVARIANTS(&r);
    /* Exactly 32, the buffer's worth: all are considered. */
    s = shape_hub();
    build_world(&s, &w);
    for (unsigned i = 0; i < 30; i++) {
        struct fh *h = new_handle("many");
        struct pb p;
        struct shape o = s;
        o.pci_dev = 0x40 + i;
        path_hc(&p, &o); pb_end(&p); set_dp(h, &p);
        h->is_hc = 1;
        h->pci = new_pci(BAR_U1, 0x40 + i);
    }
    run_p2(&r, w.image, "abcdef12", 1);
    CHECK(!strcmp(r.con[5], "STK P2 HC N=32 MORE=29"));
    CHECK(!strcmp(r.con[r.n_con - 1], EXPECT_BASELINE) && total_mem_reads() == 10);
    INVARIANTS(&r);
    return 0;
}

/* ---- Random firmware: nothing may run away, whatever the bytes say ---- */

static uint32_t rng_state = 0x2545f491u;
static uint32_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static int test_fuzz(void)
{
    struct world w;
    struct run r;
    for (unsigned iter = 0; iter < 400; iter++) {
        struct shape s = shape_hub();
        s.n_usb = rnd() % 3 + (rnd() & 1);
        if (s.n_usb > 3) s.n_usb = 3;
        s.unit = rnd() & 1;
        s.hd = rnd() & 1;
        s.acpi = rnd() & 1;
        s.stick_hc_has_pci = (rnd() % 8) != 0;
        s.other_hc_first = rnd() & 1;
        s.with_other_hc = rnd() & 1;
        build_world(&s, &w);
        /* Scramble descriptors, registers, configuration space and paths. */
        for (unsigned i = 0; i < W.n; i++) {
            struct fh *h = &W.h[i];
            if (h->usb && (rnd() & 1)) {
                for (unsigned b = 0; b < sizeof h->usb->intf; b++) if (rnd() % 3 == 0) h->usb->intf[b] = (uint8_t)rnd();
                for (unsigned e = 0; e < 16; e++) for (unsigned b = 0; b < STK_USB_ENDPOINT_DESC_BYTES; b++)
                    if (rnd() % 4 == 0) h->usb->ep[e][b] = (uint8_t)rnd();
                h->usb->fail_dev = (rnd() % 8) == 0;
                h->usb->fail_intf = (rnd() % 8) == 0;
                h->usb->fail_ep_mask = rnd() & 0xffff & (rnd() & 1 ? 0xffffu : 0);
                /* keep the identifiers recognisable */
                h->usb->dev[8] = VENDOR_ID & 0xff; h->usb->dev[9] = VENDOR_ID >> 8;
                h->usb->dev[10] = PRODUCT_ID & 0xff; h->usb->dev[11] = PRODUCT_ID >> 8;
                h->usb->dev[STK_USB_BCD_USB] = 0x10; h->usb->dev[STK_USB_BCD_USB + 1] = 0x03;
            }
            if (h->pci) {
                for (unsigned b = 0; b < 0x140; b++) if (rnd() % 5 == 0) h->pci->regs[b] = rnd() & 0x00ffffffu;
                h->pci->cfg_fail = (rnd() % 6) == 0;
                h->pci->mem_fail_at = (rnd() % 6) == 0 ? (int)(rnd() % 12) : -1;
                if (rnd() % 4 == 0) { h->pci->attr_mode = 1; h->pci->attr_base = rnd() & 0x00ffffffu; }
                h->pci->loc_ok = (rnd() % 5) != 0;
                for (unsigned b = 0; b < 8; b++) if (rnd() % 4 == 0) h->pci->cfg[STK_PCI_BAR0 + b] = (uint8_t)rnd();
            }
            if (h->bio && (rnd() & 1)) {
                struct stk_efi_block_io_media *m = (struct stk_efi_block_io_media *)h->bio->media;
                m->last_block = ((uint64_t)rnd() << 32) | rnd();
                m->block_size = rnd();
                m->removable = (uint8_t)rnd();
                m->read_only = (uint8_t)rnd();
                m->logical_partition = (uint8_t)(rnd() & 1);
            }
            /* Random paths: cut, extended or overwritten, in padded blocks. */
            if (h->dp && rnd() % 3 == 0) {
                struct pb p;
                unsigned len = dp_len(h->dp);
                p.n = 0;
                if (len != ~0u && len + 4 <= sizeof p.b) {
                    memcpy(p.b, h->dp, len + 4);
                    p.n = len + 4;
                    switch (rnd() % 4) {
                    case 0: p.n = rnd() % (len + 4); break;                       /* cut anywhere, end node lost */
                    case 1: p.b[rnd() % p.n] = (uint8_t)rnd(); break;             /* one byte changed */
                    case 2: pb_usb(&p, rnd() & 0xff, rnd() & 0xff); break;         /* junk after the end node */
                    default: for (unsigned b = 0; b < p.n; b++) if (rnd() % 7 == 0) p.b[b] = (uint8_t)rnd(); break;
                    }
                    memset(p.b + p.n, 0, sizeof p.b - p.n);
                    set_dp_padded(h, &p);
                }
            }
        }
        run_p2(&r, w.image, "abcdef12", 1);
        if (invariants(&r, __LINE__)) { fprintf(stderr, "  (fuzz iteration %u)\n", iter); return 1; }
        CHECK(r.n_con >= 6 && !strncmp(r.con[0], "STK P2 BUILD", 12));
    }
    return 0;
}

struct suite {
    const char *name;
    int (*fn)(void);
};

int main(int argc, char **argv)
{
    static const struct suite suites[] = {
        {"shapes", test_shapes}, {"baseline", test_baseline}, {"missing", test_missing}, {"fuzz", test_fuzz},
    };
    unsigned ran = 0, failed = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        unsigned before = checks;
        if (argc > 1 && strcmp(argv[1], suites[i].name) && strcmp(argv[1], "all")) continue;
        ran++;
        if (suites[i].fn()) {
            fprintf(stderr, "FAIL: suite %s\n", suites[i].name);
            failed++;
            continue;
        }
        printf("PASS %-9s %u checks\n", suites[i].name, checks - before);
    }
    world_reset();
    if (!ran) { fprintf(stderr, "no suite named %s\n", argc > 1 ? argv[1] : "(none)"); return 2; }
    if (failed) return 1;
    printf("PASS: %u stick-log survey P2 suites, %u checks\n", ran, checks);
    return 0;
}
