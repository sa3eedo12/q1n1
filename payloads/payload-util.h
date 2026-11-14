/* SPDX-License-Identifier: MIT */
/* Helpers for writing a payload (docs/SP11-PAYLOAD.md). Header only and static inline, so that a payload
 * is one .c file: there is no payload runtime to link, no libc, no global to relocate. Include it and
 * sp11-payload-abi.h (the build passes -Iplatform/uefi) and write payload_entry. */
#pragma once
#include "sp11-payload-abi.h"

/* One line being built in a payload's own stack frame. */
struct pl_line {
    char buf[Q1N1_PAYLOAD_LINE_MAX + 1];
    uint32_t len;
};

static inline void pl_begin(struct pl_line *line)
{
    line->len = 0;
    line->buf[0] = 0;
}

static inline void pl_text(struct pl_line *line, const char *text)
{
    while (*text && line->len < Q1N1_PAYLOAD_LINE_MAX) line->buf[line->len++] = *text++;
    line->buf[line->len] = 0;
}

/* "0X" and the fewest upper-case hex digits, through the runner's own formatter. */
static inline void pl_hex(const struct q1n1_payload_args *a, struct pl_line *line, uint64_t value)
{
    line->len += a->ops.hex(line->buf + line->len, Q1N1_PAYLOAD_LINE_MAX + 1 - line->len, value);
}

static inline void pl_emit(const struct q1n1_payload_args *a, const struct pl_line *line)
{
    a->ops.puts(line->buf);
}

/* PREFIX KEY=0XVALUE */
static inline void pl_keyed_hex(const struct q1n1_payload_args *a, const char *prefix, const char *key,
                                uint64_t value)
{
    struct pl_line line;
    pl_begin(&line);
    pl_text(&line, prefix);
    pl_text(&line, key);
    pl_text(&line, "=");
    pl_hex(a, &line, value);
    pl_emit(a, &line);
}

/* PREFIX KEY=TEXT */
static inline void pl_keyed_text(const struct q1n1_payload_args *a, const char *prefix, const char *key,
                                 const char *text)
{
    struct pl_line line;
    pl_begin(&line);
    pl_text(&line, prefix);
    pl_text(&line, key);
    pl_text(&line, "=");
    pl_text(&line, text);
    pl_emit(a, &line);
}

/* The arguments a payload may rely on: the right magic and version, a table at least as large as the
 * version-1 one, and the two ops every payload needs to say anything. */
static inline int pl_args_ok(const struct q1n1_payload_args *a)
{
    return a && a->magic == Q1N1_PAYLOAD_ABI_MAGIC && a->version == Q1N1_PAYLOAD_ABI_VERSION &&
           a->size >= sizeof *a && a->ops.puts && a->ops.hex;
}
