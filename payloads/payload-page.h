/* SPDX-License-Identifier: MIT */
/* The page a payload prints, shared by el2mem and hashbig (docs/SP11-PAYLOAD-EL2MEM.md, docs/SP11-PAYLOAD-HASHBIG.md): lines of
 * "<PL_PAGE_PREFIX><label> <items>", at most PL_PAGE_LINES of them, the lines marked essential never dropped. A payload defines
 * PL_PAGE_PREFIX (a string literal) and PL_PAGE_LINES before including this and passes a pl_page it keeps on its stack.
 *
 * Why a budget in the payload: the runner's page holds 60 lines at the least and 89 on the unit's panel, and every payload of a chain
 * and the runner's own three lines per payload come out of it. A line that is not essential is dropped, and counted, once it would
 * leave no room for the essential lines still to come (the NEXT lines and the last one), so a long report can never push them out.
 *
 * Header only and static, like payload-util.h. Every function is out of line, so the reviewed binary stays small and the one place
 * that writes the line buffer is one function. The pointers handed to these functions are always the caller's own stack or a string
 * literal, which is what the binary check relies on (tools/sp11_payload_memcheck.py). Evidence: EXPERIMENTAL; hardware NOT RUN. */
#pragma once
#include "payload-util.h"

#ifndef PL_PAGE_PREFIX
#error "define PL_PAGE_PREFIX before including payload-page.h"
#endif
#ifndef PL_PAGE_LINES
#error "define PL_PAGE_LINES before including payload-page.h"
#endif

#define PL_OUT static inline __attribute__((noinline))

struct pl_page {
    unsigned used, suppressed, essential_left, items, essential;
    uint32_t base;
    struct pl_line line;
};

/* Zeroes whole words through a volatile pointer: a plain loop would be turned into a memset call, which a payload has no libc for. */
PL_OUT void pl_zero(void *where, uint64_t bytes)
{
    volatile uint32_t *word = where;
    for (uint64_t i = 0; i < bytes / 4; i++) word[i] = 0;
}

/* `essential_lines` is how many essential lines the payload will still print: they are kept out of the budget of the others. */
PL_OUT void pl_page_init(struct pl_page *p, unsigned essential_lines)
{
    pl_zero(p, sizeof *p);
    p->essential_left = essential_lines;
}

PL_OUT void pl_page_flush(const struct q1n1_payload_args *a, struct pl_page *p)
{
    if (!p->items) return;
    if (p->essential) {
        if (p->essential_left) p->essential_left--;
    } else if (p->used + p->essential_left >= PL_PAGE_LINES) {
        p->suppressed++;
        p->items = 0;
        return;
    }
    p->used++;
    pl_emit(a, &p->line);
    p->items = 0;
}

PL_OUT void pl_page_open(struct pl_page *p, const char *label, int essential)
{
    pl_begin(&p->line);
    pl_text(&p->line, PL_PAGE_PREFIX);
    pl_text(&p->line, label);
    p->base = p->line.len;
    p->items = 0;
    p->essential = essential;
}

/* One entry of the open line; an entry is never cut, a full line is emitted and the label opened again. */
PL_OUT void pl_page_add(const struct q1n1_payload_args *a, struct pl_page *p, const char *text)
{
    uint32_t length = 0;
    while (text[length]) length++;
    if (p->items && p->line.len + 1 + length > Q1N1_PAYLOAD_LINE_MAX) {
        pl_page_flush(a, p);
        p->line.len = p->base;
        p->line.buf[p->base] = 0;
    }
    pl_text(&p->line, " ");
    pl_text(&p->line, text);
    p->items++;
}

/* A whole line: the label and one text. */
PL_OUT void pl_say(const struct q1n1_payload_args *a, struct pl_page *p, const char *label, const char *text, int essential)
{
    pl_page_open(p, label, essential);
    pl_page_add(a, p, text);
    pl_page_flush(a, p);
}

/* An unsigned decimal (ops.hex has no decimal form). */
PL_OUT void pl_dec(struct pl_line *line, uint64_t value)
{
    char digits[20];
    unsigned n = 0;
    do {
        digits[n++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    while (n && line->len < Q1N1_PAYLOAD_LINE_MAX) line->buf[line->len++] = digits[--n];
    line->buf[line->len] = 0;
}

/* KEY=0XVALUE and KEY=DECIMAL as entries of the open line. */
PL_OUT void pl_add_hex(const struct q1n1_payload_args *a, struct pl_page *p, const char *key, uint64_t value)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, key);
    pl_text(&item, "=");
    pl_hex(a, &item, value);
    pl_page_add(a, p, item.buf);
}

PL_OUT void pl_add_dec(const struct q1n1_payload_args *a, struct pl_page *p, const char *key, uint64_t value)
{
    struct pl_line item;
    pl_begin(&item);
    pl_text(&item, key);
    pl_text(&item, "=");
    pl_dec(&item, value);
    pl_page_add(a, p, item.buf);
}
