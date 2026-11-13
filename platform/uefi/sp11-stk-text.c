/* SPDX-License-Identifier: MIT */
/* The survey's text layer (sp11-stk-survey.h): numbers, the page font, the 100 character line and
 * the 60 line budget, and where the lines go on the panel. Pure; no EFI, no MMIO. */
#include "sp11-stk-survey.h"

#if Q1N1_SP11_STK_SURVEY

size_t stk_fmt_hex(char *dst, size_t cap, uint64_t value)
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

size_t stk_fmt_dec(char *dst, size_t cap, uint64_t value)
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

void stk_sanitize(char *text)
{
    for (; *text; text++) {
        if (*text >= 'a' && *text <= 'z') *text = (char)(*text - 32);
        if (!in_font(*text)) *text = '_';
    }
}

int stk_text_ok(const char *text)
{
    for (; *text; text++)
        if (!in_font(*text)) return 0;
    return 1;
}

int stk_sink_put(struct stk_sink *sink, const char *line, int essential)
{
    unsigned limit = essential ? STK_MAX_LINES : STK_MAX_LINES - STK_RESERVED_LINES;
    if (sink->lines >= limit) {
        sink->dropped++;
        return 0;
    }
    sink->lines++;
    if (sink->emit) sink->emit(sink->ctx, line);
    return 1;
}

void stk_sink_at(struct stk_sink *sink, const char *where)
{
    if (sink->at) sink->at(sink->ctx, where);
}

static size_t text_len(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static void flush(struct stk_line *line)
{
    line->buf[line->len] = 0;
    stk_sanitize(line->buf);
    stk_sink_put(line->sink, line->buf, line->essential);
    line->len = line->prefix_len;
    line->buf[line->len] = 0;
    line->fields = 0;
}

static void append_field(struct stk_line *line, const char *field)
{
    size_t flen = text_len(field);
    /* A field that does not fit moves to a continuation line that repeats the prefix, so every
     * physical line says what it belongs to. A line holding only its prefix is never flushed. */
    if (line->fields && line->len + 1 + flen > STK_LINE_MAX) flush(line);
    if (line->len + 1 + flen > STK_LINE_MAX) flen = STK_LINE_MAX > line->len + 1 ? STK_LINE_MAX - line->len - 1 : 0;
    line->buf[line->len++] = ' ';
    for (size_t i = 0; i < flen; i++) line->buf[line->len++] = field[i];
    line->buf[line->len] = 0;
    line->fields++;
}

void stk_line_begin(struct stk_line *line, struct stk_sink *sink, const char *prefix, int essential)
{
    line->sink = sink;
    line->essential = essential;
    line->len = 0;
    line->fields = 0;
    while (*prefix && line->len < STK_LINE_MAX) line->buf[line->len++] = *prefix++;
    line->buf[line->len] = 0;
    line->prefix_len = line->len;
}

void stk_line_word(struct stk_line *line, const char *word) { append_field(line, word); }

/* key=value into a scratch field, as long as a whole line can carry (a device path is 80 characters). */
static void keyed(struct stk_line *line, const char *key, const char *value, size_t value_len)
{
    char field[STK_LINE_MAX + 2];
    size_t n = 0;
    while (*key && n < sizeof field - 2) field[n++] = *key++;
    field[n++] = '=';
    for (size_t i = 0; i < value_len && n < sizeof field - 1; i++) field[n++] = value[i];
    field[n] = 0;
    append_field(line, field);
}

void stk_line_hex(struct stk_line *line, const char *key, uint64_t value)
{
    char text[24];
    keyed(line, key, text, stk_fmt_hex(text, sizeof text, value));
}

void stk_line_dec(struct stk_line *line, const char *key, uint64_t value)
{
    char text[24];
    keyed(line, key, text, stk_fmt_dec(text, sizeof text, value));
}

void stk_line_flag(struct stk_line *line, const char *key, int value) { keyed(line, key, value ? "1" : "0", 1); }
void stk_line_str(struct stk_line *line, const char *key, const char *value)
{
    keyed(line, key, value, text_len(value));
}
void stk_line_unknown(struct stk_line *line, const char *key) { keyed(line, key, "?", 1); }

void stk_line_end(struct stk_line *line)
{
    if (line->fields) flush(line);
}

void stk_p2_replay(struct stk_sink *sink, const struct stk_p2 *p2)
{
    if (!p2) return;
    for (unsigned i = 0; i < p2->count && i < STK_P2_MAX_LINES; i++) stk_sink_put(sink, p2->line[i], 0);
    /* Lines the keeper had no room for were still printed at P2 time; the page must say it lost them. */
    if (p2->dropped) {
        struct stk_line l;
        stk_line_begin(&l, sink, "STK P2 DROPPED", 1);
        stk_line_dec(&l, "N", p2->dropped);
        stk_line_end(&l);
    }
}

/* ---- Where the lines go ------------------------------------------------------------------------ */

/* Text is 5x7 pixels at `scale`, 6 and 9 pixels apart, from (20, 20) (main.c screen_char); a row is
 * drawn only when its last pixel row is above the bottom edge, and a column wraps when it would reach
 * the right edge. The emblem sits at the top right, 256 pixels square and 20 from the edges. */
#define PAD 20u
#define GAP 24u
#define EMBLEM_BOTTOM 296u
#define NEED_COLS (STK_LINE_MAX + 1u)
/* The survey lines, the in-place marker above them, and one spare. */
#define NEED_ROWS (STK_MAX_LINES + 2u)

static uint32_t rows_fit(uint32_t height, uint32_t scale)
{
    /* Row r is drawn when PAD + r * 9 * scale + 7 * scale < height. */
    if (height <= PAD + 7 * scale) return 0;
    return (height - PAD - 7 * scale - 1) / (9 * scale) + 1;
}

void stk_layout(uint32_t width, uint32_t height, uint32_t page_scale, uint32_t page_rows,
                struct stk_layout *out)
{
    out->placement = STK_LAYOUT_BELOW;
    out->scale = page_scale ? page_scale : 1;
    out->col0 = 0;
    out->row0 = page_rows;
    out->rows = rows_fit(height, out->scale) > page_rows ? rows_fit(height, out->scale) - page_rows : 0;
    if (!page_scale) return;
    uint32_t left = PAD + STK_PAGE_COLS * 6 * page_scale + GAP;
    for (uint32_t scale = page_scale < 2 ? page_scale : 2; scale >= 1; scale--) {
        uint32_t col0 = (left - PAD + 6 * scale - 1) / (6 * scale);
        /* The last column is drawn without wrapping when PAD + (col + 1) * 6 * scale < width. */
        uint32_t last = PAD + (col0 + NEED_COLS - 1) * 6 * scale;
        uint32_t row0 = (EMBLEM_BOTTOM - PAD + 9 * scale - 1) / (9 * scale);
        uint32_t fit = rows_fit(height, scale);
        if (last < width && fit > row0 && fit - row0 >= NEED_ROWS) {
            out->placement = STK_LAYOUT_RIGHT;
            out->scale = scale;
            out->col0 = col0;
            out->row0 = row0;
            out->rows = fit - row0;
            return;
        }
        if (scale == 1) break;
    }
}

#endif /* Q1N1_SP11_STK_SURVEY */
