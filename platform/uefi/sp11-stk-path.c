/* SPDX-License-Identifier: MIT */
/* UEFI device path walker and formatter for the survey's P2 lines (sp11-stk-survey.h). Pure: it reads
 * a byte buffer and never further than the bound it is given, so a malformed or unterminated path
 * (firmware memory this code cannot vouch for) ends the walk instead of running past it.
 *
 * Node layouts are the UEFI device path ones: type, subtype, a 16 bit little endian length that
 * covers the whole node. Read by byte so a node at any alignment is fine. */
#include "sp11-stk-survey.h"

#if Q1N1_SP11_STK_SURVEY

#define DP_TYPE_HARDWARE 0x01
#define DP_SUB_PCI 0x01
#define DP_TYPE_MESSAGING 0x03
#define DP_SUB_USB 0x05
#define DP_TYPE_MEDIA 0x04
#define DP_SUB_HARD_DRIVE 0x01
#define DP_TYPE_END 0x7f
#define DP_NODE_HEADER 4u
#define DP_PCI_BYTES 6u        /* header, function, device */
#define DP_USB_BYTES 6u        /* header, parent port, interface */
#define DP_HD_BYTES 42u        /* header, partition number, start, size, 16 byte signature, two type bytes */
#define DP_HD_NUMBER 4u
#define DP_HD_START 8u
#define DP_HD_SIZE 16u
#define DP_HD_MBR_TYPE 40u
#define DP_HD_MBR 1u           /* PC-AT compatible MBR */
#define DP_HD_GPT 2u

static unsigned le16(const uint8_t *p) { return (unsigned)p[0] | (unsigned)p[1] << 8; }
static uint32_t le32(const uint8_t *p) { return (uint32_t)le16(p) | (uint32_t)le16(p + 2) << 16; }
static uint64_t le64(const uint8_t *p) { return le32(p) | (uint64_t)le32(p + 4) << 32; }

struct text {
    char *buf;
    unsigned len;
    int cut;
};

/* A path that does not fit ends in "...": the dots overwrite the tail when there is no room after
 * it, so what is shown is never mistaken for the whole path. */
static void text_node(struct text *t, const char *node, size_t node_len, unsigned count)
{
    unsigned need = (count ? 1u : 0u) + (unsigned)node_len;
    if (t->cut) return;
    if (t->len + need > STK_DP_TEXT_MAX) {
        unsigned at = t->len < STK_DP_TEXT_MAX - 3 ? t->len : STK_DP_TEXT_MAX - 3;
        for (unsigned i = 0; i < 3; i++) t->buf[at + i] = '.';
        t->len = at + 3;
        t->buf[t->len] = 0;
        t->cut = 1;
        return;
    }
    if (count) t->buf[t->len++] = '/';
    for (size_t i = 0; i < node_len; i++) t->buf[t->len++] = node[i];
    t->buf[t->len] = 0;
}

/* Hex digits without a prefix, the way a path is written: PCI(81.0). */
static unsigned put_hex(char *dst, unsigned at, uint64_t value)
{
    char digits[16];
    unsigned n = 0;
    do { digits[n++] = "0123456789ABCDEF"[value & 15]; value >>= 4; } while (value);
    while (n) dst[at++] = digits[--n];
    return at;
}

static unsigned put_str(char *dst, unsigned at, const char *s)
{
    while (*s) dst[at++] = *s++;
    return at;
}

void stk_dp_walk(const uint8_t *dp, size_t max_bytes, struct stk_dp_info *out)
{
    out->status = STK_DP_OK;
    out->nodes = out->bytes = out->usb_nodes = 0;
    for (unsigned i = 0; i < STK_DP_MAX_USB; i++) out->usb_port[i] = 0;
    out->first_usb_offset = out->last_usb_end = 0;
    out->has_hd = 0;
    out->hd_offset = out->hd_partition = 0;
    out->hd_start = out->hd_size = 0;
    out->text[0] = 0;
    if (!dp) {
        out->status = STK_DP_NULL;
        return;
    }
    if (max_bytes > STK_DP_MAX_BYTES) max_bytes = STK_DP_MAX_BYTES;

    struct text t = {out->text, 0, 0};
    int soft_malformed = 0, ended = 0;
    unsigned off = 0;
    while (!ended) {
        if (off + DP_NODE_HEADER > max_bytes) { out->status = STK_DP_TRUNCATED; break; }
        unsigned type = dp[off], sub = dp[off + 1], len = le16(dp + off + 2);
        if (len < DP_NODE_HEADER) { out->status = STK_DP_MALFORMED; break; }
        if (len > max_bytes - off) { out->status = STK_DP_TRUNCATED; break; }
        if (type == DP_TYPE_END) {
            /* End of this instance or of the whole path; nothing after is part of the path. */
            if (len != DP_NODE_HEADER) soft_malformed = 1;
            out->bytes = off + len;
            ended = 1;
            break;
        }
        if (out->nodes >= STK_DP_MAX_NODES) { out->status = STK_DP_TRUNCATED; break; }

        char node[24];
        unsigned n = 0;
        if (type == DP_TYPE_HARDWARE && sub == DP_SUB_PCI && len == DP_PCI_BYTES) {
            n = put_str(node, n, "PCI(");
            n = put_hex(node, n, dp[off + 5]);          /* device; function is the byte before it */
            node[n++] = '.';
            n = put_hex(node, n, dp[off + 4]);
            node[n++] = ')';
        } else if (type == DP_TYPE_MESSAGING && sub == DP_SUB_USB && len == DP_USB_BYTES) {
            n = put_str(node, n, "USB(");
            n = put_hex(node, n, dp[off + 4]);          /* parent port index, from 0 */
            node[n++] = '.';
            n = put_hex(node, n, dp[off + 5]);
            node[n++] = ')';
            if (out->usb_nodes < STK_DP_MAX_USB) out->usb_port[out->usb_nodes] = dp[off + 4];
            if (!out->usb_nodes) out->first_usb_offset = off;
            out->usb_nodes++;
            out->last_usb_end = off + len;
        } else if (type == DP_TYPE_MEDIA && sub == DP_SUB_HARD_DRIVE && len == DP_HD_BYTES) {
            unsigned kind = dp[off + DP_HD_MBR_TYPE];
            n = put_str(node, n, "HD(");
            n = put_hex(node, n, le32(dp + off + DP_HD_NUMBER));
            node[n++] = '.';
            if (kind == DP_HD_MBR) n = put_str(node, n, "MBR");
            else if (kind == DP_HD_GPT) n = put_str(node, n, "GPT");
            else { node[n++] = 'T'; n = put_hex(node, n, kind); }
            node[n++] = ')';
            if (!out->has_hd) {
                out->has_hd = 1;
                out->hd_offset = off;
                out->hd_partition = le32(dp + off + DP_HD_NUMBER);
                out->hd_start = le64(dp + off + DP_HD_START);
                out->hd_size = le64(dp + off + DP_HD_SIZE);
            }
        } else {
            /* Any node this code does not read, and a known one of the wrong length (counted as
             * malformed: the length is what moves the walk, but what is inside it cannot be trusted). */
            if ((type == DP_TYPE_HARDWARE && sub == DP_SUB_PCI) || (type == DP_TYPE_MESSAGING && sub == DP_SUB_USB) ||
                (type == DP_TYPE_MEDIA && sub == DP_SUB_HARD_DRIVE))
                soft_malformed = 1;
            node[n++] = 'T';
            n = put_hex(node, n, type);
            node[n++] = '.';
            n = put_hex(node, n, sub);
        }
        text_node(&t, node, n, out->nodes);
        out->nodes++;
        off += len;
    }
    if (out->status == STK_DP_OK && soft_malformed) out->status = STK_DP_MALFORMED;
    if (out->status == STK_DP_OK && t.cut) out->status = STK_DP_TEXT_CUT;
}

int stk_dp_is_prefix(const uint8_t *a, size_t a_max, const uint8_t *b, size_t b_max, unsigned prefix_bytes)
{
    struct stk_dp_info info;
    if (!a || !b) return 0;
    stk_dp_walk(a, a_max, &info);
    /* Only a path that ends where it says it does can be a prefix; its end node is not part of it. */
    if ((info.status != STK_DP_OK && info.status != STK_DP_TEXT_CUT) || info.bytes < DP_NODE_HEADER) return 0;
    unsigned a_len = info.bytes - DP_NODE_HEADER;
    if (a_len != prefix_bytes || prefix_bytes > b_max || prefix_bytes > STK_DP_MAX_BYTES) return 0;
    for (unsigned i = 0; i < prefix_bytes; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

#endif /* Q1N1_SP11_STK_SURVEY */
