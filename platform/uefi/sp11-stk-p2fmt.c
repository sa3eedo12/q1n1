/* SPDX-License-Identifier: MIT */
/* The P2 lines of docs/SP11-STICK-LOG.md Appendix A, one formatter per row (sp11-stk-survey.h). They
 * take plain facts, so a native test can drive every shape of path and firmware answer without a
 * firmware. Nothing here prints a vendor id, a product id, a serial number or any string a device
 * supplied: the only device fields that reach a line are classes, addresses and sizes. */
#include "sp11-stk-survey.h"

#if Q1N1_SP11_STK_SURVEY

static void begin(struct stk_line *l, struct stk_sink *s, const char *prefix) { stk_line_begin(l, s, prefix, 0); }

static int is_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'); }

/* The Makefile stamps the build with the commit abbreviation (and -DIRTY), folded to the page font;
 * the first eight characters are the revision when they are all hex digits. */
void stk_p2_fmt_build(struct stk_sink *sink, const char *stamp)
{
    struct stk_line l;
    char rev[9];
    unsigned n = 0;
    while (n < 8 && stamp && is_hex(stamp[n])) { rev[n] = stamp[n]; n++; }
    rev[n] = 0;
    begin(&l, sink, "STK P2 BUILD");
    stk_line_flag(&l, "GATE", 1);
    if (n == 8) stk_line_str(&l, "REV", rev);
    else stk_line_unknown(&l, "REV");
    stk_line_end(&l);
}

static const char *dp_error(int status)
{
    switch (status) {
    case STK_DP_MALFORMED: return "MALFORMED";
    case STK_DP_TRUNCATED: return "TRUNCATED";
    default: return NULL;
    }
}

void stk_p2_fmt_self(struct stk_sink *sink, const struct stk_dp_info *dp)
{
    struct stk_line l;
    begin(&l, sink, "STK P2 SELF");
    if (dp->status == STK_DP_NULL || !dp->nodes) stk_line_str(&l, "PATH", "NONE");
    else stk_line_str(&l, "PATH", dp->text);
    if (dp_error(dp->status)) stk_line_str(&l, "PATHERR", dp_error(dp->status));
    stk_line_end(&l);
}

static void index_or_none(struct stk_line *l, const char *key, const struct stk_dp_info *dp, unsigned n)
{
    if (dp->usb_nodes > n && n < STK_DP_MAX_USB) stk_line_dec(l, key, dp->usb_port[n]);
    else stk_line_str(l, key, "NONE");
}

void stk_p2_fmt_hub(struct stk_sink *sink, const struct stk_dp_info *dp)
{
    struct stk_line l;
    begin(&l, sink, "STK P2 HUB");
    if (dp->status == STK_DP_NULL) {
        stk_line_str(&l, "SKIPPED", "NO_PATH");
        stk_line_end(&l);
        return;
    }
    stk_line_dec(&l, "USBNODES", dp->usb_nodes);
    index_or_none(&l, "ROOTIDX", dp, 0);
    index_or_none(&l, "HUBPORTIDX", dp, 1);
    if (dp->usb_nodes > 2) index_or_none(&l, "DEEPIDX", dp, 2);
    if (dp->usb_nodes > STK_DP_MAX_USB) stk_line_dec(&l, "MORE", dp->usb_nodes - STK_DP_MAX_USB);
    stk_line_end(&l);
}

void stk_p2_fmt_blk(struct stk_sink *sink, const struct stk_p2_media *m, const struct stk_dp_info *dp)
{
    struct stk_line l;
    begin(&l, sink, "STK P2 BLK");
    if (m->present) {
        stk_line_hex(&l, "LASTLBA", m->last_lba);
        stk_line_hex(&l, "BLKSZ", m->block_size);
        stk_line_flag(&l, "REMOVABLE", m->removable);
        stk_line_flag(&l, "READONLY", m->read_only);
    } else {
        stk_line_unknown(&l, "LASTLBA");
        stk_line_unknown(&l, "BLKSZ");
        stk_line_unknown(&l, "REMOVABLE");
        stk_line_unknown(&l, "READONLY");
    }
    /* A bare volume has no hard drive node, so the partition starts at the first block. */
    if (dp->has_hd) {
        stk_line_hex(&l, "PARTSTART", dp->hd_start);
        stk_line_hex(&l, "PARTSIZE", dp->hd_size);
    } else {
        stk_line_hex(&l, "PARTSTART", 0);
        stk_line_str(&l, "PARTSIZE", "NONE");
    }
    stk_line_end(&l);
}

void stk_p2_fmt_usbio(struct stk_sink *sink, const struct stk_p2_usbio *io, const char *skipped)
{
    struct stk_line l;
    begin(&l, sink, "STK P2 USBIO");
    if (!io->present) {
        stk_line_str(&l, "SKIPPED", skipped ? skipped : "NO_USB_IO");
        stk_line_end(&l);
        return;
    }
    stk_line_hex(&l, "BCDUSB", io->bcd_usb);
    stk_line_hex(&l, "CLASS", io->cls);
    stk_line_hex(&l, "SUB", io->sub);
    stk_line_hex(&l, "PROTO", io->proto);
    if (io->have_in) stk_line_hex(&l, "EPIN", io->ep_in);
    else stk_line_str(&l, "EPIN", "NONE");
    if (io->have_out) stk_line_hex(&l, "EPOUT", io->ep_out);
    else stk_line_str(&l, "EPOUT", "NONE");
    if (io->have_in) stk_line_hex(&l, "MPS", io->mps_in);
    else if (io->have_out) stk_line_hex(&l, "MPS", io->mps_out);
    else stk_line_str(&l, "MPS", "NONE");
    /* The two bulk endpoints of one interface normally agree; say so when they do not. */
    if (io->have_in && io->have_out && io->mps_in != io->mps_out) stk_line_hex(&l, "MPSOUT", io->mps_out);
    stk_line_end(&l);
}

/* seg.bus.dev.fn in plain hex, the way a device path writes a PCI node. */
static void put_loc(char *dst, size_t cap, const struct stk_p2_hc *hc)
{
    const uint64_t parts[4] = {hc->seg, hc->bus, hc->dev, hc->fn};
    size_t n = 0;
    for (unsigned i = 0; i < 4; i++) {
        char digits[16];
        unsigned d = 0;
        uint64_t v = parts[i];
        do { digits[d++] = "0123456789ABCDEF"[v & 15]; v >>= 4; } while (v);
        if (i && n + 1 < cap) dst[n++] = '.';
        while (d && n + 1 < cap) dst[n++] = digits[--d];
    }
    dst[n] = 0;
}

void stk_p2_fmt_hc(struct stk_sink *sink, unsigned total, const struct stk_p2_hc *hc, unsigned shown)
{
    struct stk_line l;
    begin(&l, sink, "STK P2 HC");
    stk_line_dec(&l, "N", total);
    if (total > shown) stk_line_dec(&l, "MORE", total - shown);
    stk_line_end(&l);
    for (unsigned i = 0; i < shown && i < total; i++) {
        char prefix[24] = "STK P2 HC HC";
        unsigned at = 12;
        char digits[12];
        unsigned d = 0, v = i;
        do { digits[d++] = (char)('0' + v % 10); v /= 10; } while (v);
        while (d) prefix[at++] = digits[--d];
        prefix[at] = 0;
        begin(&l, sink, prefix);
        if (!hc[i].pci_io) {
            stk_line_str(&l, "PCIIO", "NONE");
        } else {
            if (hc[i].bar_ok) stk_line_hex(&l, "BAR0", hc[i].bar0);
            else stk_line_unknown(&l, "BAR0");
            if (hc[i].class_ok) stk_line_hex(&l, "CLASS", hc[i].class_code);
            else stk_line_unknown(&l, "CLASS");
            if (hc[i].loc_ok) {
                char loc[48];
                put_loc(loc, sizeof loc, &hc[i]);
                stk_line_str(&l, "LOC", loc);
            } else {
                stk_line_unknown(&l, "LOC");
            }
        }
        stk_line_end(&l);
    }
}

void stk_p2_fmt_baseline(struct stk_sink *sink, const struct stk_p2_baseline *b)
{
    struct stk_line l;
    char prefix[16] = "STK P2 U";
    prefix[8] = b->index == 0 ? '0' : b->index == 1 ? '1' : 'X';
    prefix[9] = 0;
    begin(&l, sink, prefix);
    if (!b->attempted || b->skipped) {
        stk_line_str(&l, "SKIPPED", b->skipped ? b->skipped : "NO_HC");
        stk_line_end(&l);
        return;
    }
    stk_line_hex(&l, "CAPLEN", b->caplen);
    stk_line_hex(&l, "USBCMD", b->usbcmd);
    stk_line_hex(&l, "USBSTS", b->usbsts);
    stk_line_hex(&l, "CRCR", b->crcr);
    stk_line_hex(&l, "DCBAAP", b->dcbaap);
    stk_line_hex(&l, "PORTSC1", b->portsc1);
    if (b->portsc2 == STK_P2_PORT2_READ) stk_line_hex(&l, "PORTSC2", b->portsc2_value);
    else if (b->portsc2 == STK_P2_PORT2_UNREADABLE) stk_line_unknown(&l, "PORTSC2");
    else stk_line_str(&l, "PORTSC2", "NONE");
    stk_line_end(&l);
}

#endif /* Q1N1_SP11_STK_SURVEY */
