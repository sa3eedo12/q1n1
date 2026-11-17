/* SPDX-License-Identifier: MIT */
/* Payload "xhci", the page (docs/SP11-PAYLOAD-XHCI.md; xhci-priv.h lists the parts): the template formatter every line goes through and the
 * line budget of the call. The runner keeps at most Q1N1_PAYLOAD_LINES_MAX lines of Q1N1_PAYLOAD_LINE_MAX characters; a line that does not fit
 * is counted and the END line says so, and the host test requires that no line of a real run is. */
#include "xhci-priv.h"

void put_dec(struct pl_line *line, uint64_t value)
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

/* 0X<raw>, then ":" and the names of the USBSTS bits that matter here; any other bit is in the raw value. */
OUT_OF_LINE void put_sts(const struct ctx *c, struct pl_line *line, uint32_t sts)
{
    static const struct {
        uint32_t bit;
        char name[5];
    } bits[] = {{STS_HCH, "HCH"}, {STS_HSE, "HSE"}, {STS_EINT, "EINT"}, {STS_PCD, "PCD"}, {STS_CNR, "CNR"}, {STS_HCE, "HCE"}};
    unsigned tokens = 0;
    pl_hex(c->a, line, sts);
    for (unsigned i = 0; i < sizeof bits / sizeof bits[0]; i++) {
        if (!(sts & bits[i].bit)) continue;
        pl_text(line, tokens++ ? "." : ":");
        pl_text(line, bits[i].name);
    }
}

/* 0X<raw>, then ":" and CCS, PED, the link state and the speed, the way usbsmmu prints them. */
OUT_OF_LINE void put_port(const struct ctx *c, struct pl_line *line, uint32_t sc)
{
    static const char pls[16][7] = {"U0", "U1", "U2", "U3", "DIS", "RXDET", "INACT", "POLL", "RECOV", "HOTRST", "COMPL", "TEST", "RSVD", "RSVD",
                                    "RSVD", "RESUME"};
    static const char speed[6][4] = {"", "FS", "LS", "HS", "SS", "SSP"};
    unsigned speed_id = sc >> 10 & 15;
    pl_hex(c->a, line, sc);
    pl_text(line, ":");
    if (sc & 1) pl_text(line, "CCS.");
    if (sc >> 1 & 1) pl_text(line, "PED.");
    pl_text(line, pls[sc >> 5 & 15]);
    if (speed_id >= 1 && speed_id <= 5) {
        pl_text(line, ".");
        pl_text(line, speed[speed_id]);
    }
}

/* A tiny formatter, so that a line is one readable template: %x hex (0X...), %d decimal, %s text, %S USBSTS, %P PORTSC. Every number is
 * passed as a uint64_t (U()). */
OUT_OF_LINE void format_to(const struct ctx *c, struct pl_line *line, const char *f, va_list ap)
{
    for (; *f; f++) {
        if (*f != '%') {
            if (line->len < Q1N1_PAYLOAD_LINE_MAX) line->buf[line->len++] = *f;
            line->buf[line->len] = 0;
            continue;
        }
        switch (*++f) {
        case 'x': pl_hex(c->a, line, va_arg(ap, uint64_t)); break;
        case 'd': put_dec(line, va_arg(ap, uint64_t)); break;
        case 's': pl_text(line, va_arg(ap, const char *)); break;
        case 'S': put_sts(c, line, (uint32_t)va_arg(ap, uint64_t)); break;
        case 'P': put_port(c, line, (uint32_t)va_arg(ap, uint64_t)); break;
        default: break;
        }
    }
}

/* Non-zero if the line was printed: an announcement that was not may not open its group. */
int emit(struct ctx *c, const struct pl_line *line)
{
    if (line->len >= Q1N1_PAYLOAD_LINE_MAX) c->cuts++;
    if (c->lines + (c->closing ? 0u : CLOSING_LINES) >= LINE_CAP) {
        c->cuts++;
        return 0;
    }
    c->lines++;
    pl_emit(c->a, line);
    return 1;
}

/* Appends one template to a line under construction. */
void line_to(const struct ctx *c, struct pl_line *line, const char *f, ...)
{
    va_list ap;
    va_start(ap, f);
    format_to(c, line, f, ap);
    va_end(ap);
}

/* PAYLOAD XHCI <template>, printed. */
int say(struct ctx *c, const char *f, ...)
{
    struct pl_line line;
    va_list ap;
    pl_begin(&line);
    pl_text(&line, PREFIX);
    va_start(ap, f);
    format_to(c, &line, f, ap);
    va_end(ap);
    return emit(c, &line);
}
