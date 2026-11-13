/* SPDX-License-Identifier: MIT */
/* The P2 half of the stick-log survey (sp11-stk-efi.h): what the firmware's own protocols say about
 * the stick q1n1 was loaded from and the USB host controllers, taken before ExitBootServices while
 * those protocols still exist. It formats through the same line builder as the EL2 half and keeps the
 * lines for the EL2 page.
 *
 * Nothing here is a device access of q1n1's own. The one controller register read (the baseline)
 * goes through the firmware's PCI I/O Mem.Read, which is how the firmware's own xHCI driver reads the
 * same registers, on the host controller the stick's device path runs through: the controller the
 * firmware used moments ago to load this very image, so it is powered, clocked and running. q1n1's
 * recoverable-fault guard does not exist before ExitBootServices (the vectors are the firmware's), so
 * a raw load here would have no guard; PCI I/O is the access that is safe at this point. No other
 * handle's registers are touched, and nothing is ever written.
 *
 * Never read or printed: a vendor or product id, a serial number or any string descriptor. The USB
 * device descriptor is taken into a local buffer only for bcdUSB, and cleared again. */
#include "sp11-stk-efi.h"

#if Q1N1_SP11_STK_SURVEY

#define STK_MAX_HC_HANDLES 32u
#define XHCI_CAPLEN_MIN 0x1cu
#define XHCI_CAPLEN_MAX 0xfcu
#define XHCI_VERSION_MIN 0x0090u
#define XHCI_VERSION_MAX 0x01ffu
#define XHCI_OP_USBCMD 0x00u
#define XHCI_OP_USBSTS 0x04u
#define XHCI_OP_CRCR 0x18u
#define XHCI_OP_DCBAAP 0x30u
#define XHCI_OP_PORTSC(n) (0x400u + 0x10u * ((n) - 1u))

struct rec {
    struct stk_p2 *p2;
    void (*console)(void *ctx, const char *line);
    void *ctx;
};

static void rec_emit(void *vctx, const char *line)
{
    struct rec *r = vctx;
    if (r->p2->count < STK_P2_MAX_LINES) {
        char *dst = r->p2->line[r->p2->count++];
        unsigned n = 0;
        while (line[n] && n < STK_LINE_MAX) { dst[n] = line[n]; n++; }
        dst[n] = 0;
    } else {
        r->p2->dropped++;
    }
    if (r->console) r->console(r->ctx, line);
}

static uint64_t le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* Block I/O of the raw disk: the handle whose device path is the stick's path up to its hard drive
 * node, or (a bare volume) the handle the image came from. A partition's own media would report the
 * partition's size as if it were the disk's, so a logical partition is never taken for the disk. */
static void query_media(struct efi_boot_services *bs, efi_handle device, const uint8_t *self,
                        const struct stk_dp_info *dp, struct stk_p2_media *media)
{
    efi_guid blk = STK_GUID_BLOCK_IO;
    efi_handle raw = NULL;
    struct stk_efi_block_io *bio = NULL;
    if (!self) return;
    if (dp->has_hd) {
        uint8_t prefix[STK_DP_MAX_BYTES + 4];
        const uint8_t *p = prefix;
        if (dp->hd_offset > STK_DP_MAX_BYTES) return;
        for (unsigned i = 0; i < dp->hd_offset; i++) prefix[i] = self[i];
        prefix[dp->hd_offset] = 0x7f;
        prefix[dp->hd_offset + 1] = 0xff;
        prefix[dp->hd_offset + 2] = 4;
        prefix[dp->hd_offset + 3] = 0;
        if (((stk_efi_locate_device_path_fn)bs->locate_device_path)(&blk, &p, &raw) || !raw) return;
        /* A match short of the whole prefix is an ancestor, not the disk. */
        if (p != prefix + dp->hd_offset) return;
    } else {
        raw = device;
    }
    if (!raw || bs->handle_protocol(raw, &blk, (void **)&bio) || !bio || !bio->media) return;
    if (dp->has_hd && bio->media->logical_partition) return;
    media->present = 1;
    media->last_lba = bio->media->last_block;
    media->block_size = bio->media->block_size;
    media->removable = bio->media->removable != 0;
    media->read_only = bio->media->read_only != 0;
}

/* The stick's mass storage interface: the USB I/O handle closest to the front of its path. */
static const char *query_usbio(struct efi_boot_services *bs, const uint8_t *self, const struct stk_dp_info *dp,
                               struct stk_p2_usbio *io)
{
    efi_guid usb = STK_GUID_USB_IO;
    efi_handle h = NULL;
    struct stk_efi_usb_io *uio = NULL;
    const uint8_t *p = self;
    uint8_t dev[STK_USB_DEVICE_DESC_BYTES] = {0}, intf[STK_USB_INTERFACE_DESC_BYTES] = {0};
    if (!self) return "NO_PATH";
    if (!dp->usb_nodes) return "NO_USB_NODE";
    if (((stk_efi_locate_device_path_fn)bs->locate_device_path)(&usb, &p, &h) || !h) return "NO_USB_IO";
    /* The match must reach the stick's own interface (the last USB node). One that stops short is the
     * hub or the controller above it, and its class would be reported as the stick's. A pointer the
     * firmware moved outside the path is not believed either. */
    uintptr_t matched = (uintptr_t)p - (uintptr_t)self;
    if ((uintptr_t)p < (uintptr_t)self || matched < dp->last_usb_end || matched > dp->bytes) return "NO_STICK_USB_IO";
    if (bs->handle_protocol(h, &usb, (void **)&uio) || !uio) return "NO_USB_IO";
    if (!uio->get_device_descriptor || uio->get_device_descriptor(uio, dev)) return "NO_DEVICE_DESC";
    io->bcd_usb = (uint16_t)(dev[STK_USB_BCD_USB] | dev[STK_USB_BCD_USB + 1] << 8);
    for (unsigned i = 0; i < sizeof dev; i++) dev[i] = 0;
    if (!uio->get_interface_descriptor || uio->get_interface_descriptor(uio, intf)) return "NO_INTERFACE_DESC";
    io->cls = intf[STK_USB_IF_CLASS];
    io->sub = intf[STK_USB_IF_SUBCLASS];
    io->proto = intf[STK_USB_IF_PROTOCOL];
    for (unsigned i = 0; i < intf[STK_USB_IF_NUM_ENDPOINTS] && i < STK_USB_EP_INDEX_MAX; i++) {
        uint8_t ep[STK_USB_ENDPOINT_DESC_BYTES] = {0};
        if (!uio->get_endpoint_descriptor || uio->get_endpoint_descriptor(uio, (uint8_t)i, ep)) continue;
        if ((ep[STK_USB_EP_ATTRIBUTES] & 3) != STK_USB_EP_BULK) continue;
        uint8_t address = ep[STK_USB_EP_ADDRESS];
        uint16_t mps = (uint16_t)(ep[STK_USB_EP_MAX_PACKET] | ep[STK_USB_EP_MAX_PACKET + 1] << 8);
        if (address & STK_USB_EP_DIR_IN) {
            if (!io->have_in) { io->have_in = 1; io->ep_in = address; io->mps_in = mps; }
        } else if (!io->have_out) {
            io->have_out = 1; io->ep_out = address; io->mps_out = mps;
        }
    }
    io->present = 1;
    return NULL;
}

/* BAR 0 from configuration space: a 32 bit memory BAR, or a 64 bit one with its upper half. */
static int bar0_from_config(struct stk_efi_pci_io *pci, uint64_t *base)
{
    uint32_t bar[2] = {0, 0};
    if (pci->pci.read(pci, STK_PCI_WIDTH_UINT32, STK_PCI_BAR0, 2, bar)) return 0;
    if (bar[0] & 1) return 0;                          /* an I/O space BAR */
    *base = bar[0] & ~UINT64_C(0xf);
    if (((bar[0] >> 1) & 3) == 2) *base |= (uint64_t)bar[1] << 32;
    return *base != 0;
}

/* Fallback when configuration space does not say: the firmware's own description of BAR 0. The buffer
 * it returns comes from the firmware pool and is freed here. */
static int bar0_from_attributes(struct efi_boot_services *bs, struct stk_efi_pci_io *pci, uint64_t *base)
{
    void *resources = NULL;
    int ok = 0;
    if (!pci->get_bar_attributes || pci->get_bar_attributes(pci, 0, NULL, &resources) || !resources) return 0;
    const uint8_t *d = resources;
    if (d[0] == STK_ACPI_QWORD_TAG && (unsigned)(d[1] | d[2] << 8) >= STK_ACPI_QWORD_BYTES - 3) {
        *base = le64(d + STK_ACPI_QWORD_MIN);
        ok = *base != 0;
    }
    if (bs->free_pool) bs->free_pool(resources);
    return ok;
}

static int mem32(struct stk_efi_pci_io *pci, uint64_t offset, uint32_t *value)
{
    return pci->mem.read(pci, STK_PCI_WIDTH_UINT32, 0, offset, 1, value) == 0;
}

/* The firmware-mediated baseline: capability length and version first; the rest only if they say
 * xHCI. Loads through PCI I/O, on the stick's own controller only. */
static void read_baseline(struct stk_efi_pci_io *pci, uint64_t bar0, int bar_ok, struct stk_p2_baseline *b)
{
    uint32_t cap0, hcs1, lo, hi;
    b->attempted = 1;
    b->skipped = NULL;
    b->index = bar_ok && bar0 == stk_windows[STK_WIN_U0].base ? 0 : bar_ok && bar0 == stk_windows[STK_WIN_U1].base ? 1 : -1;
    if (!pci->mem.read || !mem32(pci, 0, &cap0) || !mem32(pci, 4, &hcs1)) { b->skipped = "MEM_READ"; return; }
    b->caplen = cap0 & 0xff;
    uint32_t version = cap0 >> 16;
    if (cap0 == 0xffffffffu || b->caplen < XHCI_CAPLEN_MIN || b->caplen > XHCI_CAPLEN_MAX || (b->caplen & 3) ||
        version < XHCI_VERSION_MIN || version > XHCI_VERSION_MAX) {
        b->skipped = "NOT_XHCI";
        return;
    }
    uint32_t op = b->caplen;
    if (!mem32(pci, op + XHCI_OP_USBCMD, &b->usbcmd) || !mem32(pci, op + XHCI_OP_USBSTS, &b->usbsts) ||
        !mem32(pci, op + XHCI_OP_CRCR, &lo) || !mem32(pci, op + XHCI_OP_CRCR + 4, &hi)) { b->skipped = "MEM_READ"; return; }
    b->crcr = (uint64_t)lo | (uint64_t)hi << 32;
    if (!mem32(pci, op + XHCI_OP_DCBAAP, &lo) || !mem32(pci, op + XHCI_OP_DCBAAP + 4, &hi)) { b->skipped = "MEM_READ"; return; }
    b->dcbaap = (uint64_t)lo | (uint64_t)hi << 32;
    if (!mem32(pci, op + XHCI_OP_PORTSC(1), &b->portsc1)) { b->skipped = "MEM_READ"; return; }
    /* Only what the controller says it has: a second PORTSC exists when MaxPorts is at least 2. A
     * second port that does not read is "?", not NONE: absent and unreadable are different findings. */
    b->portsc2 = STK_P2_NO_PORT2;
    if ((hcs1 >> 24) >= 2)
        b->portsc2 = mem32(pci, op + XHCI_OP_PORTSC(2), &b->portsc2_value) ? STK_P2_PORT2_READ : STK_P2_PORT2_UNREADABLE;
}

void stk_p2_collect(struct efi_system_table *st, efi_handle image_handle, const char *stamp, struct stk_p2 *out,
                    void (*console)(void *ctx, const char *line), void *console_ctx)
{
    struct efi_boot_services *bs = st->boot;
    struct rec rec = {out, console, console_ctx};
    struct stk_sink sink = {rec_emit, NULL, &rec, 0, 0};
    efi_guid loaded_guid = STK_GUID_LOADED_IMAGE, dp_guid = STK_GUID_DEVICE_PATH, hc_guid = STK_GUID_USB2_HC;
    efi_guid pci_guid = STK_GUID_PCI_IO;
    struct efi_loaded_image *image = NULL;
    const uint8_t *self = NULL;
    struct stk_dp_info dp;
    struct stk_p2_media media = {0};
    struct stk_p2_usbio io = {0};
    struct stk_p2_baseline baseline = {0};

    out->count = out->dropped = 0;
    stk_p2_fmt_build(&sink, stamp);

    if (!bs->handle_protocol(image_handle, &loaded_guid, (void **)&image) && image && image->device)
        bs->handle_protocol(image->device, &dp_guid, (void **)&self);
    stk_dp_walk(self, STK_DP_MAX_BYTES, &dp);
    stk_p2_fmt_self(&sink, &dp);
    stk_p2_fmt_hub(&sink, &dp);

    query_media(bs, image ? image->device : NULL, self, &dp, &media);
    stk_p2_fmt_blk(&sink, &media, &dp);

    const char *skipped = query_usbio(bs, self, &dp, &io);
    stk_p2_fmt_usbio(&sink, &io, skipped);

    /* The host controllers. The one whose device path is the front of the stick's path is the stick's. */
    efi_handle handles[STK_MAX_HC_HANDLES];
    uint64_t size = sizeof handles;
    efi_status status = bs->locate_handle(EFI_BY_PROTOCOL, &hc_guid, NULL, &size, handles);
    struct stk_p2_hc hc[STK_P2_HC_SHOWN] = {{0}};
    unsigned total = 0, shown = 0;
    int stick_found = 0, stick_without_pci_io = 0;
    if (status && status != EFI_NOT_FOUND && status != EFI_BUFFER_TOO_SMALL) {
        struct stk_line l;
        stk_line_begin(&l, &sink, "STK P2 HC", 0);
        stk_line_str(&l, "SKIPPED", "LOCATE");
        stk_line_hex(&l, "STATUS", status);
        stk_line_end(&l);
    } else {
        if (status != EFI_NOT_FOUND) total = (unsigned)(size / sizeof(efi_handle));
        /* Too many handles for the buffer: the count is still known, the handles are not. */
        unsigned usable = status == EFI_BUFFER_TOO_SMALL ? 0 : total;
        for (unsigned i = 0; i < usable && i < STK_MAX_HC_HANDLES; i++) {
            struct stk_efi_pci_io *pci = NULL;
            struct stk_p2_hc facts = {0};
            uint8_t class_bytes[3] = {0, 0, 0};
            uint64_t base = 0;
            const uint8_t *hcdp = NULL;
            if (!bs->handle_protocol(handles[i], &pci_guid, (void **)&pci) && pci) {
                facts.pci_io = 1;
                if (pci->pci.read && !pci->pci.read(pci, STK_PCI_WIDTH_UINT8, STK_PCI_CLASSCODE, 3, class_bytes)) {
                    facts.class_ok = 1;
                    facts.class_code = (uint32_t)class_bytes[2] << 16 | (uint32_t)class_bytes[1] << 8 | class_bytes[0];
                }
                if ((pci->pci.read && bar0_from_config(pci, &base)) || bar0_from_attributes(bs, pci, &base)) {
                    facts.bar_ok = 1;
                    facts.bar0 = base;
                }
                if (pci->get_location && !pci->get_location(pci, &facts.seg, &facts.bus, &facts.dev, &facts.fn))
                    facts.loc_ok = 1;
            }
            if (i < STK_P2_HC_SHOWN) { hc[i] = facts; shown = i + 1; }
            if (stick_found || stick_without_pci_io || !self || !dp.usb_nodes || !dp.bytes) continue;
            if (bs->handle_protocol(handles[i], &dp_guid, (void **)&hcdp) ||
                !stk_dp_is_prefix(hcdp, STK_DP_MAX_BYTES, self, dp.bytes, dp.first_usb_offset))
                continue;
            if (facts.pci_io) {
                stick_found = 1;
                read_baseline(pci, facts.bar0, facts.bar_ok, &baseline);
            } else {
                stick_without_pci_io = 1;
            }
        }
        stk_p2_fmt_hc(&sink, total, hc, shown);
    }
    if (!stick_found) {
        baseline.index = -1;
        baseline.skipped = !self ? "NO_PATH" : !dp.usb_nodes ? "NOT_USB" : stick_without_pci_io ? "NO_PCIIO" : "NO_HC_MATCH";
        baseline.attempted = 1;
    }
    stk_p2_fmt_baseline(&sink, &baseline);
}

#endif /* Q1N1_SP11_STK_SURVEY */
