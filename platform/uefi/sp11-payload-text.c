/* SPDX-License-Identifier: MIT */
/* The runner's text layer (sp11-payload.h): numbers, the page font, and where the lines go on the panel.
 * Pure: no EFI, no MMIO, so the native tests drive it directly. */
#include "sp11-payload.h"

#if Q1N1_SP11_PAYLOAD

size_t q1n1_payload_fmt_hex(char *dst, size_t cap, uint64_t value)
{
    char digits[16];
    unsigned n = 0;
    do { digits[n++] = "0123456789ABCDEF"[value & 15]; value >>= 4; } while (value);
    size_t len = 0;
    if (!cap) return 0;
    if (len + 1 < cap) dst[len++] = '0';
    if (len + 1 < cap) dst[len++] = 'X';
    while (n && len + 1 < cap) dst[len++] = digits[--n];
    dst[len] = 0;
    return len;
}

size_t q1n1_payload_fmt_dec(char *dst, size_t cap, uint64_t value)
{
    char digits[20];
    unsigned n = 0;
    do { digits[n++] = (char)('0' + value % 10); value /= 10; } while (value);
    size_t len = 0;
    if (!cap) return 0;
    while (n && len + 1 < cap) dst[len++] = digits[--n];
    dst[len] = 0;
    return len;
}

static int in_font(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ' || c == ':' || c == '-' || c == '.' ||
           c == '/' || c == '=' || c == '?' || c == '(' || c == ')' || c == '_';
}

void q1n1_payload_sanitize(char *text)
{
    for (; *text; text++) {
        if (*text >= 'a' && *text <= 'z') *text = (char)(*text - 32);
        if (!in_font(*text)) *text = '_';
    }
}

static void put_text(struct q1n1_payload_line *line, const char *text)
{
    while (*text && line->len < Q1N1_PAYLOAD_LINE_MAX) line->buf[line->len++] = *text++;
    line->buf[line->len] = 0;
}

void q1n1_payload_line_begin(struct q1n1_payload_line *line, const char *prefix)
{
    line->len = 0;
    line->buf[0] = 0;
    put_text(line, prefix);
}

void q1n1_payload_line_raw(struct q1n1_payload_line *line, const char *text)
{
    put_text(line, text);
}

void q1n1_payload_line_word(struct q1n1_payload_line *line, const char *word)
{
    put_text(line, " ");
    put_text(line, word);
}

void q1n1_payload_line_hex(struct q1n1_payload_line *line, const char *key, uint64_t value)
{
    char text[24];
    q1n1_payload_fmt_hex(text, sizeof text, value);
    put_text(line, " ");
    put_text(line, key);
    put_text(line, "=");
    put_text(line, text);
}

void q1n1_payload_line_dec(struct q1n1_payload_line *line, const char *key, uint64_t value)
{
    char text[24];
    q1n1_payload_fmt_dec(text, sizeof text, value);
    put_text(line, " ");
    put_text(line, key);
    put_text(line, "=");
    put_text(line, text);
}

void q1n1_payload_line_digest(struct q1n1_payload_line *line, const char *key, const uint8_t *digest)
{
    char text[17];
    for (unsigned i = 0; i < 8; i++) {
        text[2 * i] = "0123456789ABCDEF"[digest[i] >> 4];
        text[2 * i + 1] = "0123456789ABCDEF"[digest[i] & 15];
    }
    text[16] = 0;
    put_text(line, " ");
    if (key && *key) {
        put_text(line, key);
        put_text(line, "=");
    }
    put_text(line, text);
}

/* This is the survey's stk_layout (sp11-stk-text.c), copied on purpose: the survey image has to stay
 * byte-identical to the commit before the runner, so no survey file may change, and the two images
 * are never one build, so they cannot share an object. tools/test-q1n1-sp11-payload.py compiles both
 * and compares them over a grid of panel sizes, so the copy cannot drift.
 *
 * Text is 5x7 pixels at `scale`, 6 and 9 pixels apart, from (20, 20) (main.c screen_char); a row is
 * drawn only when its last pixel row is above the bottom edge, and a column wraps when it would reach
 * the right edge. The emblem sits at the top right, 256 pixels square and 20 from the edges. */
#define PAD 20u
#define GAP 24u
#define EMBLEM_BOTTOM 296u
/* The widest line of the existing EL2 page, in characters, with a margin (the survey's STK_PAGE_COLS). */
#define PAGE_COLS 90u
#define NEED_COLS (Q1N1_PAYLOAD_LINE_MAX + 1u)
/* The runner's lines, and two spare rows. */
#define NEED_ROWS (Q1N1_PAYLOAD_REGION_LINES + 2u)

static uint32_t rows_fit(uint32_t height, uint32_t scale)
{
    /* Row r is drawn when PAD + r * 9 * scale + 7 * scale < height. */
    if (height <= PAD + 7 * scale) return 0;
    return (height - PAD - 7 * scale - 1) / (9 * scale) + 1;
}

void q1n1_payload_region_place(uint32_t width, uint32_t height, uint32_t page_scale, uint32_t page_rows,
                               struct q1n1_payload_region *out)
{
    out->placement = Q1N1_PAYLOAD_REGION_BELOW;
    out->scale = page_scale ? page_scale : 1;
    out->col0 = 0;
    out->row0 = page_rows;
    out->rows = rows_fit(height, out->scale) > page_rows ? rows_fit(height, out->scale) - page_rows : 0;
    if (!page_scale) return;
    uint32_t left = PAD + PAGE_COLS * 6 * page_scale + GAP;
    for (uint32_t scale = page_scale < 2 ? page_scale : 2; scale >= 1; scale--) {
        uint32_t col0 = (left - PAD + 6 * scale - 1) / (6 * scale);
        /* The last column is drawn without wrapping when PAD + (col + 1) * 6 * scale < width. */
        uint32_t last = PAD + (col0 + NEED_COLS - 1) * 6 * scale;
        uint32_t row0 = (EMBLEM_BOTTOM - PAD + 9 * scale - 1) / (9 * scale);
        uint32_t fit = rows_fit(height, scale);
        if (last < width && fit > row0 && fit - row0 >= NEED_ROWS) {
            out->placement = Q1N1_PAYLOAD_REGION_RIGHT;
            out->scale = scale;
            out->col0 = col0;
            out->row0 = row0;
            out->rows = fit - row0;
            return;
        }
        if (scale == 1) break;
    }
}

#endif /* Q1N1_SP11_PAYLOAD */
