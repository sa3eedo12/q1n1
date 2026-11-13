/* SPDX-License-Identifier: MIT */
/* Native tests for the pure parts of the stick-log survey (platform/uefi/sp11-stk-*.c): the text
 * layer, the device path walker, the gate and verdict rules, the memory map classification and the
 * bounded walkers over a fake register file. The firmware-structure walk and the P2 line bound are in
 * test-q1n1-sp11-stk-bounds.c, the EL2 sequencer is tested against a fake SoC in
 * test-q1n1-sp11-stk-el2.c and the firmware queries in test-q1n1-sp11-stk-p2.c; all four are driven
 * by tools/test-q1n1-sp11-stk.py under AddressSanitizer and UndefinedBehaviorSanitizer.
 *
 * Expected values are written out by hand from docs/SP11-STICK-LOG.md (Appendix A), not computed by
 * the code under test. None of this runs on a Surface Pro 11; evidence: EXPERIMENTAL, host model only,
 * hardware NOT RUN. */
#define SNAP_PLATFORM_SP11 1
#define Q1N1_SP11_STK_SURVEY 1
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sp11-stk-survey.h"

static unsigned checks;
#define CHECK(x) do { \
        if (!(x)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } \
        checks++; \
    } while (0)
#define CHECK_STR(got, want) do { \
        if (strcmp((got), (want))) { \
            fprintf(stderr, "FAIL %s:%d: got \"%s\" want \"%s\"\n", __FILE__, __LINE__, (got), (want)); \
            return 1; \
        } \
        checks++; \
    } while (0)

/* ---- A sink that keeps what it is given and refuses anything the page could not show ---------------- */

struct rec {
    char line[160][STK_LINE_MAX + 8];
    unsigned n, bad;
    unsigned at_calls;
};
static void rec_emit(void *ctx, const char *line)
{
    struct rec *r = ctx;
    size_t len = strlen(line);
    if (len > STK_LINE_MAX || !stk_text_ok(line)) r->bad++;
    if (r->n < 160) {
        snprintf(r->line[r->n], sizeof r->line[0], "%s", line);
        r->n++;
    }
}
static void rec_at(void *ctx, const char *where)
{
    struct rec *r = ctx;
    (void)where;
    r->at_calls++;
}
static void rec_init(struct rec *r, struct stk_sink *sink)
{
    memset(r, 0, sizeof *r);
    memset(sink, 0, sizeof *sink);
    sink->emit = rec_emit;
    sink->at = rec_at;
    sink->ctx = r;
}

/* ---- text -------------------------------------------------------------------------------------- */

static int test_text(void)
{
    char buf[32];
    CHECK(stk_fmt_hex(buf, sizeof buf, 0) == 3 && !strcmp(buf, "0X0"));
    CHECK(stk_fmt_hex(buf, sizeof buf, 0x1420) == 6 && !strcmp(buf, "0X1420"));
    CHECK(!strcmp((stk_fmt_hex(buf, sizeof buf, UINT64_MAX), buf), "0XFFFFFFFFFFFFFFFF"));
    CHECK(!strcmp((stk_fmt_hex(buf, sizeof buf, 0xabcdef), buf), "0XABCDEF"));     /* upper case */
    CHECK(!strcmp((stk_fmt_dec(buf, sizeof buf, 0), buf), "0"));
    CHECK(!strcmp((stk_fmt_dec(buf, sizeof buf, UINT64_MAX), buf), "18446744073709551615"));
    /* A buffer that is too small is cut, never overrun (ASan watches the 4 byte canary). */
    char tiny[4 + 4];
    memset(tiny, 'Z', sizeof tiny);
    CHECK(stk_fmt_hex(tiny, 4, 0x1234) == 3 && !strcmp(tiny, "0X1") && tiny[4] == 'Z');
    CHECK(stk_fmt_hex(tiny, 0, 5) == 0);

    char text[64];
    snprintf(text, sizeof text, "abc DEF 012:-./=?()_ x");
    stk_sanitize(text);
    CHECK_STR(text, "ABC DEF 012:-./=?()_ X");
    snprintf(text, sizeof text, "a,b+c<d>e*f%%g#h\t\n\x7f\xc3");
    stk_sanitize(text);
    CHECK(stk_text_ok(text) && !strcmp(text, "A_B_C_D_E_F_G_H____"));
    CHECK(stk_text_ok("STK P3 U0 ID CAPLEN=0X20 SC=? NONE ()/.-_:="));
    CHECK(!stk_text_ok("lower") && !stk_text_ok("a,b") && !stk_text_ok("tab\t") && !stk_text_ok("x\n"));

    /* Line builder: a field stays whole, a long block splits with the prefix repeated, and a line is
     * never longer than 100 characters. */
    struct rec r;
    struct stk_sink sink;
    struct stk_line l;
    rec_init(&r, &sink);
    stk_line_begin(&l, &sink, "STK P3 TEST", 0);
    stk_line_hex(&l, "A", 0x10);
    stk_line_dec(&l, "B", 42);
    stk_line_flag(&l, "C", 1);
    stk_line_flag(&l, "D", 0);
    stk_line_str(&l, "E", "NONE");
    stk_line_unknown(&l, "F");
    stk_line_word(&l, "WORD");
    stk_line_end(&l);
    CHECK(r.n == 1 && r.bad == 0);
    CHECK_STR(r.line[0], "STK P3 TEST A=0X10 B=42 C=1 D=0 E=NONE F=? WORD");
    stk_line_end(&l);                                         /* nothing pending: nothing printed */
    CHECK(r.n == 1);

    /* Exactly 100 characters is allowed; more starts a new line. "STK P3 TEST" is 11 and each
     * " Kxx=0X1234567" field is 14, so six fields make 95 and the seventh (109) must move. */
    rec_init(&r, &sink);
    stk_line_begin(&l, &sink, "STK P3 TEST", 0);
    for (int i = 0; i < 7; i++) {
        char key[4] = {'K', (char)('0' + i / 10), (char)('0' + i % 10), 0};
        stk_line_hex(&l, key, 0x1234567);
    }
    stk_line_end(&l);
    CHECK(r.n == 2 && r.bad == 0);
    CHECK(strlen(r.line[0]) == 11 + 6 * 14 && strlen(r.line[0]) <= STK_LINE_MAX);
    CHECK(!strcmp(r.line[1], "STK P3 TEST K06=0X1234567"));
    /* A field that makes the line exactly 100 stays. */
    rec_init(&r, &sink);
    stk_line_begin(&l, &sink, "STK P3 TEST", 0);
    char pad[100];
    memset(pad, 'X', 100 - 11 - 1 - 2);                      /* "S=" and these make the whole line 100 */
    pad[100 - 11 - 1 - 2] = 0;
    stk_line_str(&l, "S", pad);
    stk_line_end(&l);
    CHECK(r.n == 1 && strlen(r.line[0]) == STK_LINE_MAX);
    stk_line_begin(&l, &sink, "STK P3 TEST", 0);
    stk_line_str(&l, "S", pad);
    stk_line_str(&l, "T", "1");
    stk_line_end(&l);
    CHECK(r.n == 3 && !strcmp(r.line[2], "STK P3 TEST T=1"));
    /* A single field longer than a whole line is cut to fit, never overrun. */
    rec_init(&r, &sink);
    stk_line_begin(&l, &sink, "STK P3 TEST", 0);
    char huge[300];
    memset(huge, 'Q', sizeof huge - 1);
    huge[sizeof huge - 1] = 0;
    stk_line_str(&l, "H", huge);
    stk_line_end(&l);
    CHECK(r.n == 1 && strlen(r.line[0]) == STK_LINE_MAX && r.bad == 0);
    /* Lower case and characters outside the font never reach the sink. */
    rec_init(&r, &sink);
    stk_line_begin(&l, &sink, "stk p3 test", 0);
    stk_line_str(&l, "k", "a,b");
    stk_line_end(&l);
    CHECK(r.n == 1 && r.bad == 0 && !strcmp(r.line[0], "STK P3 TEST K=A_B"));

    /* The budget: 60 lines in all; an ordinary line stops STK_RESERVED_LINES short of that. */
    CHECK(STK_MAX_LINES == 60 && STK_LINE_MAX == 100);
    rec_init(&r, &sink);
    for (unsigned i = 0; i < 100; i++) stk_sink_put(&sink, "STK P3 ORDINARY", 0);
    CHECK(sink.lines == STK_MAX_LINES - STK_RESERVED_LINES && sink.dropped == 100 - sink.lines);
    for (unsigned i = 0; i < 100; i++) stk_sink_put(&sink, "STK P3 ESSENTIAL", 1);
    CHECK(sink.lines == STK_MAX_LINES && r.n == STK_MAX_LINES);
    CHECK(stk_sink_put(&sink, "STK P3 ONE MORE", 1) == 0);
    /* stk_sink_at is never a line. */
    stk_sink_at(&sink, "X");
    CHECK(sink.lines == STK_MAX_LINES && r.at_calls == 1);
    struct stk_sink silent = {0};
    stk_sink_at(&silent, "no callback");                      /* a sink without `at` is fine */
    CHECK(stk_sink_put(&silent, "STK X", 0) == 1);
    return 0;
}

/* ---- device paths ------------------------------------------------------------------------------ */

static unsigned put_node(uint8_t *p, unsigned type, unsigned sub, const uint8_t *body, unsigned body_len)
{
    unsigned len = 4 + body_len;
    p[0] = (uint8_t)type; p[1] = (uint8_t)sub; p[2] = (uint8_t)len; p[3] = (uint8_t)(len >> 8);
    if (body_len) memcpy(p + 4, body, body_len);
    return len;
}
static unsigned put_pci(uint8_t *p, unsigned dev, unsigned fn)
{
    uint8_t body[2] = {(uint8_t)fn, (uint8_t)dev};
    return put_node(p, 1, 1, body, 2);
}
static unsigned put_usb(uint8_t *p, unsigned port, unsigned iface)
{
    uint8_t body[2] = {(uint8_t)port, (uint8_t)iface};
    return put_node(p, 3, 5, body, 2);
}
static unsigned put_hd(uint8_t *p, uint32_t number, uint64_t start, uint64_t size, unsigned mbr_type)
{
    uint8_t body[38] = {0};
    memcpy(body, &number, 4);
    memcpy(body + 4, &start, 8);
    memcpy(body + 12, &size, 8);
    memset(body + 20, 0xa5, 16);                              /* the signature: never read */
    body[36] = (uint8_t)mbr_type;
    body[37] = 1;
    return put_node(p, 4, 1, body, 38);
}
static unsigned put_end(uint8_t *p) { return put_node(p, 0x7f, 0xff, NULL, 0); }

/* Copies the path to the end of a heap block of exactly its size, so reading one byte past the
 * bound the walker was given is a heap-buffer-overflow. */
static uint8_t *exact(const uint8_t *p, size_t n)
{
    uint8_t *copy = malloc(n ? n : 1);
    if (n) memcpy(copy, p, n);
    return copy;
}

static int walk(const uint8_t *p, size_t n, struct stk_dp_info *out)
{
    uint8_t *copy = exact(p, n);
    stk_dp_walk(copy, n, out);
    free(copy);
    return out->status;
}

static int test_path(void)
{
    uint8_t path[256];
    unsigned n;
    struct stk_dp_info info;

    /* The stick's own shape: a PCI node whose device number does not fit in 5 bits, two USB nodes,
     * a hard drive node (docs/SP11-STICK-LOG.md 3.1). */
    n = 0;
    n += put_pci(path + n, 0x81, 0);
    n += put_usb(path + n, 1, 0);
    n += put_usb(path + n, 2, 0);
    unsigned hd_at = n;
    n += put_hd(path + n, 1, 0x800, 0x3b8000, 1);
    n += put_end(path + n);
    CHECK(walk(path, n, &info) == STK_DP_OK);
    CHECK_STR(info.text, "PCI(81.0)/USB(1.0)/USB(2.0)/HD(1.MBR)");
    CHECK(info.nodes == 4 && info.bytes == n && info.usb_nodes == 2);
    CHECK(info.usb_port[0] == 1 && info.usb_port[1] == 2);
    CHECK(info.first_usb_offset == 6 && info.last_usb_end == 18);
    CHECK(info.has_hd && info.hd_offset == hd_at && info.hd_partition == 1);
    CHECK(info.hd_start == 0x800 && info.hd_size == 0x3b8000);

    /* One USB node: a direct attachment. */
    n = 0;
    n += put_pci(path + n, 0x81, 0);
    n += put_usb(path + n, 0, 0);
    n += put_hd(path + n, 2, 0x20, 0x100, 2);
    n += put_end(path + n);
    CHECK(walk(path, n, &info) == STK_DP_OK);
    CHECK_STR(info.text, "PCI(81.0)/USB(0.0)/HD(2.GPT)");
    CHECK(info.usb_nodes == 1 && info.usb_port[0] == 0);

    /* Other nodes are T<type>.<subtype> in hex; an ACPI node, a logical unit node, an unknown MBR type. */
    n = 0;
    uint8_t acpi[8] = {0x41, 0xd0, 0x0a, 0x03, 0, 0, 0, 0};
    n += put_node(path + n, 2, 1, acpi, 8);
    n += put_pci(path + n, 0x1, 0x2);
    n += put_usb(path + n, 0x1f, 1);
    uint8_t lun[1] = {0};
    n += put_node(path + n, 3, 0x11, lun, 1);
    n += put_hd(path + n, 0x1a, 0, 1, 7);
    n += put_end(path + n);
    CHECK(walk(path, n, &info) == STK_DP_OK);
    CHECK_STR(info.text, "T2.1/PCI(1.2)/USB(1F.1)/T3.11/HD(1A.T7)");
    CHECK(info.nodes == 5 && info.usb_nodes == 1);

    /* No USB and no hard drive node (a bare volume on something else). */
    n = 0;
    n += put_pci(path + n, 3, 0);
    n += put_end(path + n);
    CHECK(walk(path, n, &info) == STK_DP_OK && !info.has_hd && info.usb_nodes == 0);
    CHECK_STR(info.text, "PCI(3.0)");

    /* Three and four USB nodes: ports kept for the first three, the count for all. */
    n = 0;
    for (unsigned i = 0; i < 4; i++) n += put_usb(path + n, i + 1, 0);
    n += put_end(path + n);
    CHECK(walk(path, n, &info) == STK_DP_OK && info.usb_nodes == 4);
    CHECK(info.usb_port[0] == 1 && info.usb_port[1] == 2 && info.usb_port[2] == 3);

    /* An end node alone is an empty path; a null pointer is NULL; both print nothing. */
    n = put_end(path);
    CHECK(walk(path, n, &info) == STK_DP_OK && info.nodes == 0 && !info.text[0]);
    stk_dp_walk(NULL, 10, &info);
    CHECK(info.status == STK_DP_NULL && info.nodes == 0);

    /* The end node of an instance also ends the walk; whatever follows is not part of the path. */
    n = 0;
    n += put_pci(path + n, 4, 0);
    n += put_node(path + n, 0x7f, 0x01, NULL, 0);
    n += put_usb(path + n, 9, 9);
    CHECK(walk(path, n, &info) == STK_DP_OK && info.nodes == 1 && info.usb_nodes == 0);

    /* Truncated and malformed paths. Each is a heap block of exactly the bytes handed over. */
    n = 0;
    n += put_pci(path + n, 0x81, 0);
    n += put_usb(path + n, 1, 0);
    unsigned full = n + put_end(path + n);
    for (unsigned cut = 0; cut < full; cut++) {                 /* no end node, or a node cut in two */
        walk(path, cut, &info);
        CHECK(info.status == STK_DP_TRUNCATED || (cut == 0 && info.status == STK_DP_TRUNCATED));
        CHECK(info.nodes <= 2);
    }
    CHECK(walk(path, full, &info) == STK_DP_OK && info.bytes == full);
    /* The path is followed only as far as the bound: a longer buffer with the end node after it is
     * still a truncated path. */
    CHECK(walk(path, full - 4, &info) == STK_DP_TRUNCATED);
    /* A node shorter than its own header. */
    uint8_t bad[8] = {1, 1, 3, 0, 0, 0, 0, 0};
    CHECK(walk(bad, sizeof bad, &info) == STK_DP_MALFORMED && info.nodes == 0);
    uint8_t zero_len[8] = {1, 1, 0, 0, 0, 0, 0, 0};
    CHECK(walk(zero_len, sizeof zero_len, &info) == STK_DP_MALFORMED);
    /* A node that claims to run past the buffer. */
    uint8_t over[6] = {3, 5, 0xff, 0x7f, 0, 0};
    CHECK(walk(over, sizeof over, &info) == STK_DP_TRUNCATED);
    /* A PCI node of the wrong length is kept as T1.1 and the path is flagged, but still walked. */
    n = 0;
    uint8_t wide[4] = {0, 0x81, 0, 0};
    n += put_node(path + n, 1, 1, wide, 4);
    n += put_usb(path + n, 1, 0);
    n += put_end(path + n);
    CHECK(walk(path, n, &info) == STK_DP_MALFORMED);
    CHECK_STR(info.text, "T1.1/USB(1.0)");
    CHECK(info.usb_nodes == 1);
    /* An end node that is not 4 bytes long. */
    n = 0;
    n += put_pci(path + n, 1, 0);
    uint8_t pad[2] = {0, 0};
    n += put_node(path + n, 0x7f, 0xff, pad, 2);
    CHECK(walk(path, n, &info) == STK_DP_MALFORMED && info.bytes == n);

    /* A path longer than the walker will read: no end node inside STK_DP_MAX_BYTES, and more nodes
     * than it keeps. It stops at the bound without reading past it. */
    uint8_t *big = malloc(STK_DP_MAX_BYTES + 64);
    n = 0;
    while (n + 6 <= STK_DP_MAX_BYTES + 64) n += put_usb(big + n, n & 0xff, 0);
    uint8_t *exact_big = exact(big, n);
    stk_dp_walk(exact_big, n, &info);
    CHECK(info.status == STK_DP_TRUNCATED && info.nodes <= STK_DP_MAX_NODES && info.usb_nodes == info.nodes);
    free(exact_big);
    /* Same bytes, but handed over as a buffer shorter than STK_DP_MAX_BYTES: the bound given wins. */
    exact_big = exact(big, 40);
    stk_dp_walk(exact_big, 40, &info);
    CHECK(info.status == STK_DP_TRUNCATED && info.nodes == 6);
    free(exact_big);
    free(big);

    /* Text longer than the buffer: ends in "..." and says so. 24 nodes of "USB(FF.FF)" is 240 chars. */
    n = 0;
    for (unsigned i = 0; i < 20; i++) n += put_usb(path + n, 0xff, 0xff);
    n += put_end(path + n);
    CHECK(walk(path, n, &info) == STK_DP_TEXT_CUT);
    CHECK(strlen(info.text) <= STK_DP_TEXT_MAX && !strcmp(info.text + strlen(info.text) - 3, "..."));
    CHECK(info.nodes == 20 && info.usb_nodes == 20 && info.bytes == n);
    CHECK(stk_text_ok(info.text));
    /* A path that fits to the character is not cut: 8 nodes of "USB(FF.FF)" and 7 slashes is 87, so
     * use 7 of them (76 chars) plus a short one. */
    n = 0;
    for (unsigned i = 0; i < 7; i++) n += put_usb(path + n, 0xff, 0xff);
    n += put_end(path + n);
    CHECK(walk(path, n, &info) == STK_DP_OK && strlen(info.text) == 7 * 10 + 6);

    /* A host controller path is a prefix of the stick's when it is the stick's path up to the first
     * USB node, byte for byte, and ends exactly there. */
    uint8_t stick[128], hc[64], other[64];
    unsigned sn = 0, hn = 0, on = 0;
    sn += put_pci(stick + sn, 0x81, 0);
    unsigned usb_at = sn;
    sn += put_usb(stick + sn, 1, 0);
    sn += put_usb(stick + sn, 2, 0);
    sn += put_end(stick + sn);
    hn += put_pci(hc + hn, 0x81, 0);
    hn += put_end(hc + hn);
    on += put_pci(other + on, 0x80, 0);
    on += put_end(other + on);
    CHECK(stk_dp_is_prefix(hc, hn, stick, sn, usb_at));
    CHECK(!stk_dp_is_prefix(other, on, stick, sn, usb_at));            /* a different device */
    CHECK(!stk_dp_is_prefix(hc, hn, stick, sn, usb_at + 6));           /* the prefix is longer than the HC path */
    CHECK(!stk_dp_is_prefix(hc, hn, stick, usb_at - 1, usb_at));       /* the stick's path is too short */
    CHECK(!stk_dp_is_prefix(NULL, 0, stick, sn, usb_at) && !stk_dp_is_prefix(hc, hn, NULL, 0, usb_at));
    uint8_t unterminated[6];
    put_pci(unterminated, 0x81, 0);
    CHECK(!stk_dp_is_prefix(unterminated, sizeof unterminated, stick, sn, usb_at));
    return 0;
}

/* ---- gate -------------------------------------------------------------------------------------- */

static struct stk_reg reg_ok(uint32_t v) { struct stk_reg r = {v, STK_OK}; return r; }
static struct stk_reg reg_err(int err) { struct stk_reg r = {0, err}; return r; }

static int test_gate(void)
{
    /* All 3^10 combinations of GDSCR (fault, power off, power on) and nine clocks (fault, off,
     * running), against the rule of Appendix A restated as counts. */
    unsigned combos = 0, on = 0, partial = 0, off = 0, unknown = 0;
    for (unsigned code = 0; code < 59049; code++) {
        unsigned digits[10], c = code;
        for (unsigned i = 0; i < 10; i++) { digits[i] = c % 3; c /= 3; }
        struct stk_reg gdscr = digits[0] == 0 ? reg_err(STK_E_FAULT) : reg_ok(digits[0] == 1 ? 0x1 : 0x80000004u);
        struct stk_reg clk[STK_GATE_CLOCKS];
        unsigned clock_off = 0, clock_fault = 0;
        for (unsigned i = 0; i < STK_GATE_CLOCKS; i++) {
            unsigned d = digits[1 + i];
            clk[i] = d == 0 ? reg_err(i & 1 ? STK_E_FAULT : STK_E_NOT_DEVICE) : reg_ok(d == 1 ? 0x80000000u : 0x1u);
            clock_fault += d == 0;
            clock_off += d == 1;
        }
        int want;
        if (digits[0] == 0) want = STK_GATE_UNKNOWN;
        else if (digits[0] == 1) want = STK_GATE_OFF;                    /* PWR=0 */
        else if (clock_off) want = STK_GATE_PARTIAL;                     /* PWR=1 and a clock known off */
        else if (clock_fault) want = STK_GATE_UNKNOWN;                   /* a clock that could not be read */
        else want = STK_GATE_ON;
        CHECK(stk_gate(&gdscr, clk) == want);
        combos++;
        on += want == STK_GATE_ON; partial += want == STK_GATE_PARTIAL; off += want == STK_GATE_OFF;
        unknown += want == STK_GATE_UNKNOWN;
    }
    CHECK(combos == 59049 && on == 1 && partial + off + unknown + on == combos);
    CHECK(off == 19683 && partial > 0 && unknown > 0);
    /* The two bits that matter: PWR is bit 31 of the GDSCR and CLK_OFF is bit 31 of a clock. The other
     * 31 bits do not change the answer. */
    struct stk_reg clk[STK_GATE_CLOCKS];
    for (unsigned i = 0; i < STK_GATE_CLOCKS; i++) clk[i] = reg_ok(0x7fffffffu);
    struct stk_reg power = reg_ok(0x80000000u), no_power = reg_ok(0x7fffffffu);
    CHECK(stk_gate(&power, clk) == STK_GATE_ON && stk_gate(&no_power, clk) == STK_GATE_OFF);
    clk[4] = reg_ok(0x80000000u);
    CHECK(stk_gate(&power, clk) == STK_GATE_PARTIAL);
    CHECK_STR(stk_gate_name(STK_GATE_ON), "ON");
    CHECK_STR(stk_gate_name(STK_GATE_PARTIAL), "PARTIAL");
    CHECK_STR(stk_gate_name(STK_GATE_OFF), "OFF");
    CHECK_STR(stk_gate_name(STK_GATE_UNKNOWN), "?");
    return 0;
}

/* ---- verdicts ---------------------------------------------------------------------------------- */

/* The verdict table restated as a decision list over named conditions, a different shape from the
 * code under test. Rows are tried in order; the first whose condition holds names the verdict. */
static int oracle(const struct stk_ctrl_obs *o)
{
    int has_conn = 0, has_stick = 0, has_unread = 0, bad_port = 0;
    for (unsigned i = 0; i < o->ports; i++) {
        if (!o->port[i].read) { has_unread = 1; continue; }
        uint32_t sc = o->port[i].sc;
        int ccs = sc & 1, ped = sc >> 1 & 1, pp = sc >> 9 & 1;
        if ((ccs && !pp) || (ped && !ccs) || (ped && !pp) || sc == 0xffffffffu) bad_port = 1;
        if (ccs) {
            has_conn = 1;
            for (unsigned s = 0; s < o->slots; s++) if (o->slot[s].root_port == i + 1) has_stick = 1;
        }
    }
    struct { int cond, verdict; } rows[] = {
        {o->gate == STK_GATE_UNKNOWN && o->gcc_fault, STK_V_FAULT},
        {o->gate == STK_GATE_UNKNOWN, STK_V_UNREAD},
        {o->gate != STK_GATE_ON, STK_V_GATED_OFF},
        {o->fault, STK_V_FAULT},
        {!o->id_read, STK_V_UNREAD},
        {!o->xhci_plausible, STK_V_NOT_XHCI},
        {!o->usbsts_read, STK_V_UNREAD},
        {o->usbsts_allones || bad_port, STK_V_INCONSISTENT},
        {has_stick && o->hch, STK_V_STICK_HALTED},
        {has_stick, STK_V_STICK_RUNNING},
        {has_conn, STK_V_CONNECTED},
        {has_unread, STK_V_UNREAD},
    };
    for (unsigned i = 0; i < sizeof rows / sizeof rows[0]; i++)
        if (rows[i].cond) return rows[i].verdict;
    return STK_V_IDLE;
}

static int test_verdict(void)
{
    static const uint32_t ports[] = {
        0x0,        /* nothing: powered off, nothing connected */
        0x2a0,      /* PP, no device: RxDetect */
        0xe03,      /* connected, enabled, powered */
        0x201,      /* connected, powered, not enabled */
        0x001,      /* connected, NOT powered: forbidden */
        0x002,      /* enabled, not connected, not powered: forbidden */
        0x202,      /* enabled, not connected, powered: forbidden */
        0xffffffffu,
    };
    unsigned total = 0, seen[16] = {0};
    for (int gate = 0; gate < 4; gate++)
    for (int gcc_fault = 0; gcc_fault < 2; gcc_fault++)
    for (int fault = 0; fault < 2; fault++)
    for (int id_read = 0; id_read < 2; id_read++)
    for (int plausible = 0; plausible < 2; plausible++)
    for (int sts_read = 0; sts_read < 2; sts_read++)
    for (int allones = 0; allones < 2; allones++)
    for (int hch = 0; hch < 2; hch++)
    for (unsigned p0 = 0; p0 < 9; p0++)
    for (unsigned p1 = 0; p1 < 9; p1++)
    for (unsigned sl = 0; sl < 4; sl++) {
        struct stk_ctrl_obs o;
        memset(&o, 0, sizeof o);
        o.gate = gate; o.gcc_fault = gcc_fault; o.fault = fault; o.id_read = id_read;
        o.xhci_plausible = plausible; o.usbsts_read = sts_read; o.usbsts_allones = allones; o.hch = hch;
        o.ports = 2;
        /* p == 8 is "this port was not read". */
        o.port[0].read = p0 != 8; o.port[0].sc = p0 == 8 ? 0 : ports[p0];
        o.port[1].read = p1 != 8; o.port[1].sc = p1 == 8 ? 0 : ports[p1];
        /* Slots: none, one on root port 1, one on root port 2, one on root port 3 (no such port). */
        o.slots = sl ? 1 : 0;
        if (sl) o.slot[0].root_port = sl;
        int got = stk_ctrl_verdict(&o), want = oracle(&o);
        if (got != want) {
            fprintf(stderr, "FAIL verdict gate=%d gccf=%d f=%d id=%d pl=%d sts=%d ao=%d hch=%d p0=%u p1=%u sl=%u: got %s want %s\n",
                    gate, gcc_fault, fault, id_read, plausible, sts_read, allones, hch, p0, p1, sl,
                    stk_verdict_name(got), stk_verdict_name(want));
            return 1;
        }
        seen[got]++;
        total++;
    }
    CHECK(total == 4 * 2 * 2 * 2 * 2 * 2 * 2 * 2 * 9 * 9 * 4);
    /* Every verdict the survey can name is reachable. */
    for (int v = 0; v <= STK_V_CONNECTED; v++) CHECK(seen[v] > 0);

    /* The named cases of Appendix A, one by one. */
    struct stk_ctrl_obs o;
    memset(&o, 0, sizeof o);
    o.gate = STK_GATE_ON; o.id_read = o.xhci_plausible = o.usbsts_read = 1; o.ports = 2;
    o.port[0].read = o.port[1].read = 1;
    CHECK(stk_ctrl_verdict(&o) == STK_V_IDLE);
    o.port[0].sc = 0x201;                                    /* connected and powered, no slot */
    CHECK(stk_ctrl_verdict(&o) == STK_V_CONNECTED);
    o.slots = 1; o.slot[0].root_port = 1; o.hch = 1;
    CHECK(stk_ctrl_verdict(&o) == STK_V_STICK_HALTED);
    o.hch = 0;
    CHECK(stk_ctrl_verdict(&o) == STK_V_STICK_RUNNING);
    o.port[0].sc = 0x001;                                    /* CCS=1 with PP=0 */
    CHECK(stk_ctrl_verdict(&o) == STK_V_INCONSISTENT);
    o.port[0].sc = 0x201;
    o.gate = STK_GATE_PARTIAL;
    CHECK(stk_ctrl_verdict(&o) == STK_V_GATED_OFF);
    o.gate = STK_GATE_OFF;
    CHECK(stk_ctrl_verdict(&o) == STK_V_GATED_OFF);
    o.gate = STK_GATE_ON; o.xhci_plausible = 0;
    CHECK(stk_ctrl_verdict(&o) == STK_V_NOT_XHCI);
    o.xhci_plausible = 1; o.fault = 1;
    CHECK(stk_ctrl_verdict(&o) == STK_V_FAULT);
    CHECK_STR(stk_verdict_name(STK_V_GATED_OFF), "GATED-OFF");
    CHECK_STR(stk_verdict_name(STK_V_FAULT), "FAULT");
    CHECK_STR(stk_verdict_name(STK_V_NOT_XHCI), "NOT-XHCI");
    CHECK_STR(stk_verdict_name(STK_V_STICK_RUNNING), "STICK-PRESENT-RUNNING");
    CHECK_STR(stk_verdict_name(STK_V_STICK_HALTED), "STICK-PRESENT-HALTED");
    CHECK_STR(stk_verdict_name(STK_V_IDLE), "IDLE");
    CHECK_STR(stk_verdict_name(STK_V_INCONSISTENT), "INCONSISTENT");
    CHECK_STR(stk_verdict_name(STK_V_UNREAD), "UNREAD");
    CHECK_STR(stk_verdict_name(STK_V_CONNECTED), "CONNECTED-NO-SLOT");

    /* Port rules on their own. */
    CHECK(!stk_port_inconsistent(0) && !stk_port_inconsistent(0x2a0) && !stk_port_inconsistent(0xe03));
    CHECK(stk_port_inconsistent(0x1) && stk_port_inconsistent(0x2) && stk_port_inconsistent(0x202));
    CHECK(stk_port_inconsistent(0xffffffffu));
    CHECK(stk_port_pls(0x2a0) == 5 && stk_port_speed(0xe03) == 3 && stk_port_speed(0x1c00) == 7);
    return 0;
}

/* ---- SMMU verdict ------------------------------------------------------------------------------ */

static int test_smmu_verdict(void)
{
    struct stk_smmu_obs o;
    memset(&o, 0, sizeof o);
    /* Nothing read: UNREAD, whatever the streams hold. */
    CHECK(stk_smmu_verdict(&o, 3) == STK_SMMU_UNREAD);
    o.global_read = 1;
    for (int k = 0; k < 2; k++) { o.stream[k].scanned = 1; }
    /* No entry matches: USFCFG decides. */
    CHECK(stk_smmu_verdict(&o, 3) == STK_SMMU_BYPASS);
    o.usfcfg = 1;
    CHECK(stk_smmu_verdict(&o, 3) == STK_SMMU_FAULT);
    o.clientpd = 1;                                          /* the SMMU is out of the way for everyone */
    CHECK(stk_smmu_verdict(&o, 3) == STK_SMMU_BYPASS);
    o.clientpd = 0; o.usfcfg = 0;
    /* A match: the S2CR type decides, 0 translate, 1 bypass, 2 fault, 3 reserved is not called anything good. */
    for (unsigned type = 0; type < 4; type++) {
        o.stream[0].found = 1; o.stream[0].matches = 1; o.stream[0].s2cr_read = 1; o.stream[0].type = type;
        int want = type == 0 ? STK_SMMU_TRANS : type == 1 ? STK_SMMU_BYPASS : STK_SMMU_FAULT;
        CHECK(stk_smmu_verdict(&o, 1) == want);
    }
    /* A multi-match faults whatever the type. */
    o.stream[0].type = 1; o.stream[0].matches = 2;
    CHECK(stk_smmu_verdict(&o, 1) == STK_SMMU_FAULT);
    o.stream[0].matches = 1;
    /* A match whose S2CR could not be read is UNREAD. */
    o.stream[0].s2cr_read = 0;
    CHECK(stk_smmu_verdict(&o, 1) == STK_SMMU_UNREAD);
    o.stream[0].s2cr_read = 1;
    /* Which streams are judged: the mask. FAULT beats UNREAD beats TRANS beats BYPASS. */
    o.stream[0].type = 1;                                    /* stream 0 bypass */
    o.stream[1].found = 1; o.stream[1].matches = 1; o.stream[1].s2cr_read = 1; o.stream[1].type = 0;
    CHECK(stk_smmu_verdict(&o, 1) == STK_SMMU_BYPASS);
    CHECK(stk_smmu_verdict(&o, 2) == STK_SMMU_TRANS);
    CHECK(stk_smmu_verdict(&o, 3) == STK_SMMU_TRANS);
    o.stream[0].scanned = 0;
    CHECK(stk_smmu_verdict(&o, 3) == STK_SMMU_UNREAD);
    o.stream[1].type = 2;
    CHECK(stk_smmu_verdict(&o, 3) == STK_SMMU_FAULT);
    CHECK(stk_smmu_verdict(&o, 0) == STK_SMMU_UNREAD);       /* no stream asked about: nothing is claimed */
    CHECK_STR(stk_smmu_name(STK_SMMU_BYPASS), "BYPASS");
    CHECK_STR(stk_smmu_name(STK_SMMU_TRANS), "TRANS");
    CHECK_STR(stk_smmu_name(STK_SMMU_FAULT), "FAULT");
    CHECK_STR(stk_smmu_name(STK_SMMU_UNREAD), "UNREAD");
    return 0;
}

/* ---- memory map -------------------------------------------------------------------------------- */

static struct q1n1_sp11_gop_map_entry ent(uint32_t type, uint64_t base, uint64_t pages)
{
    struct q1n1_sp11_gop_map_entry e = {type, base, pages, 0xf};
    return e;
}

static int test_map(void)
{
    for (uint32_t t = 0; t < 16; t++) {
        int ram = (t >= 1 && t <= 7) || t == 9;
        CHECK(stk_type_is_ram(t) == ram);
        CHECK(stk_type_allows_device(t) == (t == 0 || t == 11 || t == 12));
    }
    struct q1n1_sp11_gop_map_entry map[] = {
        ent(4, 0x80000000, 0x80),            /* boot services data, then...        */
        ent(2, 0x80080000, 0x80),            /* ...loader data: RAM across two descriptors */
        ent(0, 0x80100000, 0x10),            /* reserved right after                */
        ent(11, 0x0a600000, 0x100),          /* MMIO                                */
        ent(7, 0x90000000, 0x100),           /* conventional                        */
        ent(10, 0x90100000, 0x10),           /* ACPI NVS: firmware memory           */
        ent(6, 0xa0000000, 0),               /* an empty descriptor describes nothing */
        ent(4, 0xb0000000, UINT64_C(1) << 40), /* a count that cannot be real describes nothing */
    };
    uint32_t n = sizeof map / sizeof map[0];
    /* RAM: inside one descriptor, across the join of two, up to the exact end. */
    CHECK(stk_map_range_is_ram(map, n, 0x80000000, 0x1000));
    CHECK(stk_map_range_is_ram(map, n, 0x8007f000, 0x2000));             /* across the join */
    CHECK(stk_map_range_is_ram(map, n, 0x80000000, 0x100000));           /* exactly both */
    CHECK(!stk_map_range_is_ram(map, n, 0x80000000, 0x100001));          /* one byte into the reserved range */
    CHECK(!stk_map_range_is_ram(map, n, 0x800ff000, 0x2000));            /* runs into reserved */
    CHECK(!stk_map_range_is_ram(map, n, 0x80100000, 0x10));              /* reserved is not RAM */
    CHECK(!stk_map_range_is_ram(map, n, 0x0a600000, 4));                 /* MMIO is not RAM */
    CHECK(!stk_map_range_is_ram(map, n, 0x90100000, 4));                 /* ACPI NVS is not RAM */
    CHECK(!stk_map_range_is_ram(map, n, 0x70000000, 4));                 /* not described: not RAM */
    CHECK(!stk_map_range_is_ram(map, n, 0xa0000000, 4));                 /* the empty descriptor */
    CHECK(!stk_map_range_is_ram(map, n, 0xb0000000, 4));                 /* the impossible one */
    CHECK(!stk_map_range_is_ram(map, n, 0x80000000, 0) && !stk_map_range_is_ram(NULL, 0, 0x80000000, 4));
    CHECK(!stk_map_range_is_ram(map, n, UINT64_MAX - 2, 8));             /* wraps: never RAM */
    CHECK(!stk_map_range_is_ram(map, 0, 0x80000000, 4));                 /* an empty map shows nothing */
    /* A descriptor of another kind over RAM makes the map contradict itself: refused. */
    struct q1n1_sp11_gop_map_entry overlap[] = {ent(4, 0x80000000, 0x100), ent(11, 0x80010000, 0x1)};
    CHECK(stk_map_range_is_ram(overlap, 2, 0x80000000, 0x10000));
    CHECK(!stk_map_range_is_ram(overlap, 2, 0x8000f000, 0x2000));
    CHECK(!stk_map_range_is_ram(overlap, 2, 0x80010000, 4));
    /* Device windows: fine over MMIO, reserved, port space or nothing; never over memory or firmware. */
    CHECK(stk_map_range_allows_device(map, n, 0x0a600000, 0xfc100));
    CHECK(stk_map_range_allows_device(map, n, 0x80100000, 0x1000));      /* reserved */
    CHECK(stk_map_range_allows_device(map, n, 0x15000000, 0x100000));    /* not in the map at all */
    CHECK(!stk_map_range_allows_device(map, n, 0x80000000, 0x1000));     /* boot services data */
    CHECK(!stk_map_range_allows_device(map, n, 0x90100000, 0x1000));     /* ACPI NVS */
    CHECK(!stk_map_range_allows_device(map, n, 0x7ffff000, 0x2000));     /* straddles into RAM */
    CHECK(stk_map_range_allows_device(map, n, 0x0a5ff000, 0x2000));     /* straddles into MMIO: fine */
    CHECK(!stk_map_range_allows_device(map, n, 0x80000000, 0) && !stk_map_range_allows_device(NULL, 0, 0, 4));
    for (uint32_t t = 0; t < 16; t++) {
        struct q1n1_sp11_gop_map_entry one[] = {ent(t, 0x15000000, 0x100)};
        CHECK(stk_map_range_allows_device(one, 1, 0x15000000, 0x100000) == (t == 0 || t == 11 || t == 12));
    }
    return 0;
}

/* ---- walkers over a fake register file ----------------------------------------------------------- */

struct fake_regs {
    uint32_t window;
    struct { uint32_t off, value; } reg[64];
    unsigned n;
    unsigned reads;
    unsigned outside;                       /* reads the callback was asked to make outside `window` */
    uint32_t last_off;
    int fault_at;                           /* the Nth read fails with this; -1 never */
    int fault_err;
    int echo_next;                          /* every capability dword answers "next = 1": an endless list */
    uint32_t echo_value;
};
static void fr_set(struct fake_regs *f, uint32_t off, uint32_t value)
{
    f->reg[f->n].off = off;
    f->reg[f->n].value = value;
    f->n++;
}
static int fr_read(void *ctx, uint32_t off, uint32_t *value)
{
    struct fake_regs *f = ctx;
    *value = 0;
    if (off > f->window || f->window - off < 4) { f->outside++; return STK_E_RANGE; }
    if ((int)f->reads == f->fault_at) { f->reads++; return f->fault_err; }
    f->reads++;
    f->last_off = off;
    if (f->echo_next) { *value = f->echo_value; return STK_OK; }
    for (unsigned i = 0; i < f->n; i++)
        if (f->reg[i].off == off) { *value = f->reg[i].value; return STK_OK; }
    return STK_OK;
}

static uint32_t cap(unsigned id, unsigned next, unsigned minor, unsigned major)
{
    return id | next << 8 | minor << 16 | (uint32_t)major << 24;
}

static int test_xecp(void)
{
    struct stk_xecp x;
    struct fake_regs f;
    /* The usual two: USB 2.0 on port 1, USB 3.1 on port 2, from dword offset 0x120 (byte 0x480). */
    memset(&f, 0, sizeof f);
    f.window = 0xfc100; f.fault_at = -1;
    fr_set(&f, 0x480, cap(2, 4, 0x00, 2));      /* next is 4 dwords on */
    fr_set(&f, 0x484, 0x20425355);
    fr_set(&f, 0x488, 1 | 1 << 8);
    fr_set(&f, 0x48c, 0);
    fr_set(&f, 0x490, cap(2, 0, 0x10, 3));
    fr_set(&f, 0x494, 0x20425355);
    fr_set(&f, 0x498, 2 | 1 << 8);
    stk_xecp_walk(fr_read, &f, 0x120, f.window, &x);
    CHECK(x.status == STK_OK && x.caps == 2 && x.protos == 2 && !x.truncated);
    CHECK(x.proto[0].major == 2 && x.proto[0].minor == 0 && x.proto[0].first == 1 && x.proto[0].count == 1);
    CHECK(x.proto[1].major == 3 && x.proto[1].minor == 0x10 && x.proto[1].first == 2 && x.proto[1].count == 1);
    CHECK(f.reads == 2 + 2 * 2);                  /* dword 0 of each, and dwords 1 and 2 of a protocol capability */

    /* No list at all: nothing is read. */
    memset(&f, 0, sizeof f);
    f.window = 0xfc100; f.fault_at = -1;
    stk_xecp_walk(fr_read, &f, 0, f.window, &x);
    CHECK(x.status == STK_OK && x.caps == 0 && x.protos == 0 && f.reads == 0);

    /* An endless list: every capability says "next is the following dword". Visited 16 times, no more. */
    memset(&f, 0, sizeof f);
    f.window = 0xfc100; f.fault_at = -1; f.echo_next = 1; f.echo_value = cap(1, 1, 0, 0);
    stk_xecp_walk(fr_read, &f, 0x120, f.window, &x);
    CHECK(x.caps == STK_XECP_MAX_CAPS && x.truncated && x.status == STK_OK);
    CHECK(f.reads == STK_XECP_MAX_CAPS && f.outside == 0);
    /* Every capability answers with another id and a non-zero next: the walk still stops at the bound. */
    memset(&f, 0, sizeof f);
    f.window = 0xfc100; f.fault_at = -1; f.echo_next = 1; f.echo_value = 0x20425355;
    stk_xecp_walk(fr_read, &f, 0x120, f.window, &x);
    CHECK(x.caps == STK_XECP_MAX_CAPS && x.truncated && f.reads == STK_XECP_MAX_CAPS);
    /* A cycle through a protocol capability: id 2, next 1, name "USB " on the following dword (a
     * register file that answers the same dword everywhere cannot be both, so use two values). */
    memset(&f, 0, sizeof f);
    f.window = 0xfc100; f.fault_at = -1;
    for (uint32_t off = 0x480; off < 0x480 + 4 * 64; off += 4) fr_set(&f, off, cap(2, 1, 0, 3));
    stk_xecp_walk(fr_read, &f, 0x120, f.window, &x);
    CHECK(x.caps == STK_XECP_MAX_CAPS && x.truncated);
    CHECK(f.reads <= STK_XECP_MAX_CAPS * 3);

    /* Zero-length steps: "next" 0 ends the list at once, whatever follows. */
    memset(&f, 0, sizeof f);
    f.window = 0xfc100; f.fault_at = -1;
    fr_set(&f, 0x480, cap(2, 0, 0, 2));
    fr_set(&f, 0x484, 0x20425355);
    fr_set(&f, 0x488, 1 | 4 << 8);
    fr_set(&f, 0x48c, 0);
    fr_set(&f, 0x490, cap(2, 0, 0, 3));         /* never reached */
    stk_xecp_walk(fr_read, &f, 0x120, f.window, &x);
    CHECK(x.caps == 1 && x.protos == 1 && x.proto[0].count == 4);

    /* An offset beyond the window: refused before any read. xECP is 16 bits, so the first capability
     * can be as far as 0x3fffc bytes in: inside the real 0xfc100 byte window, outside a smaller one. */
    memset(&f, 0, sizeof f);
    f.window = 0x10000; f.fault_at = -1;
    stk_xecp_walk(fr_read, &f, 0xffff, f.window, &x);
    CHECK(x.status == STK_E_RANGE && x.caps == 0 && f.reads == 0 && f.outside == 0);
    stk_xecp_walk(fr_read, &f, 0x4001, f.window, &x);         /* 0x10004: starts past the window */
    CHECK(x.status == STK_E_RANGE && f.reads == 0);
    stk_xecp_walk(fr_read, &f, 0x4000, f.window, &x);         /* 0x10000 = the window size: the first dword is outside */
    CHECK(x.status == STK_E_RANGE && f.reads == 0);
    stk_xecp_walk(fr_read, &f, 0x3fff, f.window, &x);         /* the last dword of the window is inside */
    CHECK(x.status == STK_OK && f.reads == 1 && x.caps == 1);
    memset(&f, 0, sizeof f);
    f.window = 0xfc100; f.fault_at = -1;
    stk_xecp_walk(fr_read, &f, 0xffff, f.window, &x);          /* 0x3fffc: inside the real window */
    CHECK(x.status == STK_OK && f.reads == 1);
    /* A chain that walks off the end of a small window stops there, without reading outside it. */
    memset(&f, 0, sizeof f);
    f.window = 0x100; f.fault_at = -1; f.echo_next = 1; f.echo_value = cap(1, 0x40, 0, 0);
    stk_xecp_walk(fr_read, &f, 0x20, f.window, &x);           /* 0x80, then 0x180 is outside */
    CHECK(x.status == STK_E_RANGE && x.caps == 1 && f.outside == 0 && f.reads == 1);
    /* A wrong name string is skipped, and more than four protocols keep the first four. */
    memset(&f, 0, sizeof f);
    f.window = 0xfc100; f.fault_at = -1;
    fr_set(&f, 0x480, cap(2, 4, 0, 2)); fr_set(&f, 0x484, 0x31313131); fr_set(&f, 0x488, 1 | 1 << 8);
    for (unsigned i = 1; i <= 6; i++) {
        uint32_t at = 0x480 + 16 * i;
        fr_set(&f, at, cap(2, i < 6 ? 4 : 0, 0, 3));
        fr_set(&f, at + 4, 0x20425355);
        fr_set(&f, at + 8, i | 1 << 8);
    }
    stk_xecp_walk(fr_read, &f, 0x120, f.window, &x);
    CHECK(x.caps == 7 && x.protos == STK_XECP_PROTOS && x.proto[0].first == 1 && x.proto[3].first == 4);
    /* A read that fails ends the walk with its error. */
    for (int at = 0; at < 6; at++) {
        memset(&f, 0, sizeof f);
        f.window = 0xfc100; f.fault_at = at; f.fault_err = STK_E_FAULT;
        fr_set(&f, 0x480, cap(2, 4, 0, 2)); fr_set(&f, 0x484, 0x20425355); fr_set(&f, 0x488, 1 | 1 << 8);
        fr_set(&f, 0x490, cap(2, 0, 0x10, 3)); fr_set(&f, 0x494, 0x20425355); fr_set(&f, 0x498, 2 | 1 << 8);
        stk_xecp_walk(fr_read, &f, 0x120, f.window, &x);
        CHECK(x.status == STK_E_FAULT && f.reads == (unsigned)at + 1);
    }
    return 0;
}

/* ---- SMR scan ------------------------------------------------------------------------------------ */

#define SMR(n) (0x800u + 4u * (n))
#define S2CR(n) (0xc00u + 4u * (n))

static int test_smr(void)
{
    static const uint32_t streams[STK_STREAMS] = {0x1420, 0x1460};
    struct stk_smr_scan s;
    struct fake_regs f;

    /* The documented example: two entries, one per stream, one with a mask. */
    memset(&f, 0, sizeof f);
    f.window = 0x100000; f.fault_at = -1;
    fr_set(&f, SMR(3), 0x80000000 | 0x1420);              /* valid, exact */
    fr_set(&f, SMR(5), 0x80000000 | 0x20 << 16 | 0x1440);/* valid, mask 0x20: matches 0x1440 and 0x1460 */
    fr_set(&f, S2CR(3), 1 << 16);                          /* bypass */
    fr_set(&f, S2CR(5), 7);                                /* translate, context bank 7 */
    stk_smr_scan(fr_read, &f, 8, 0, 15, streams, &s);
    CHECK(s.status == STK_OK && s.scanned == 8);
    CHECK(s.stream[0].scanned && s.stream[0].found && s.stream[0].index == 3 && s.stream[0].matches == 1);
    CHECK(s.stream[0].s2cr_read && s.stream[0].type == 1 && s.stream[0].cbndx == 0);
    CHECK(s.stream[1].found && s.stream[1].index == 5 && s.stream[1].type == 0 && s.stream[1].cbndx == 7);
    CHECK(f.reads == 8 + 2);                               /* each SMR once, and the two S2CRs that matched */

    /* All entries invalid: no match, however well their ids would match. */
    memset(&f, 0, sizeof f);
    f.window = 0x100000; f.fault_at = -1;
    for (unsigned n = 0; n < 8; n++) fr_set(&f, SMR(n), 0x1420);       /* bit 31 clear */
    stk_smr_scan(fr_read, &f, 8, 0, 15, streams, &s);
    CHECK(s.status == STK_OK && !s.stream[0].found && !s.stream[1].found && s.stream[0].scanned);
    CHECK(f.reads == 8);                                              /* no S2CR is read for a non-match */

    /* An entry that matches twice, or two entries that match one stream: the lowest wins, the count says 2. */
    memset(&f, 0, sizeof f);
    f.window = 0x100000; f.fault_at = -1;
    fr_set(&f, SMR(2), 0x80000000 | 0x1420);
    fr_set(&f, SMR(6), 0x80000000 | 0xffffu << 16);        /* everything matches */
    fr_set(&f, S2CR(2), 2 << 16);
    stk_smr_scan(fr_read, &f, 8, 0, 15, streams, &s);
    CHECK(s.stream[0].matches == 2 && s.stream[0].index == 2 && s.stream[0].type == 2);
    CHECK(s.stream[1].matches == 1 && s.stream[1].index == 6);
    /* One entry whose mask makes it match both streams. */
    memset(&f, 0, sizeof f);
    f.window = 0x100000; f.fault_at = -1;
    fr_set(&f, SMR(0), 0x80000000 | 0x7fff << 16);
    stk_smr_scan(fr_read, &f, 1, 0, 15, streams, &s);
    CHECK(s.stream[0].found && s.stream[1].found && s.stream[0].matches == 1 && s.stream[1].matches == 1);

    /* Only the implemented stream id bits count: with 12 bits, 0x1420 (bit 12 set) and 0x0420 are the
     * same stream id to the SMMU, so an entry for 0x0420 matches 0x1420 but not 0x1460. */
    memset(&f, 0, sizeof f);
    f.window = 0x100000; f.fault_at = -1;
    fr_set(&f, SMR(0), 0x80000000 | 0x0420);
    stk_smr_scan(fr_read, &f, 1, 0, 12, streams, &s);
    CHECK(s.stream[0].found && !s.stream[1].found);
    /* With 13 bits they differ. */
    stk_smr_scan(fr_read, &f, 1, 0, 13, streams, &s);
    CHECK(!s.stream[0].found && !s.stream[1].found);
    /* Extended ids: validity comes from S2CR.EXIDVALID (bit 10), SMR bit 31 means nothing there. */
    memset(&f, 0, sizeof f);
    f.window = 0x100000; f.fault_at = -1;
    fr_set(&f, SMR(0), 0x80000000 | 0x1420);              /* bit 31 set, but S2CR says invalid */
    fr_set(&f, SMR(1), 0x1420);                            /* bit 31 clear, S2CR says valid */
    fr_set(&f, S2CR(1), 1 << 10 | 1 << 16 | 9);
    stk_smr_scan(fr_read, &f, 2, 1, 15, streams, &s);
    CHECK(s.stream[0].found && s.stream[0].index == 1 && s.stream[0].matches == 1);
    CHECK(s.stream[0].type == 1 && s.stream[0].cbndx == 9);

    /* The scan is bounded by the architecture's width of NUMSMRG, whatever it is told. */
    memset(&f, 0, sizeof f);
    f.window = 0x100000; f.fault_at = -1;
    stk_smr_scan(fr_read, &f, 100000, 0, 15, streams, &s);
    CHECK(s.status == STK_OK && s.scanned == STK_SMR_MAX && f.reads == STK_SMR_MAX && f.outside == 0);
    memset(&f, 0, sizeof f);
    f.window = 0x100000; f.fault_at = -1;
    stk_smr_scan(fr_read, &f, 0, 0, 15, streams, &s);
    CHECK(s.status == STK_OK && f.reads == 0 && s.stream[0].scanned && !s.stream[0].found);
    /* A window too small for the table: the read that falls outside ends the scan, never goes beyond. */
    memset(&f, 0, sizeof f);
    f.window = 0x810; f.fault_at = -1;
    stk_smr_scan(fr_read, &f, 100, 0, 15, streams, &s);
    CHECK(s.status == STK_E_RANGE && !s.stream[0].scanned && f.outside == 1);
    /* A fault at each read in turn ends the scan with it and reads nothing after. */
    for (int at = 0; at < 5; at++) {
        memset(&f, 0, sizeof f);
        f.window = 0x100000; f.fault_at = at; f.fault_err = STK_E_FAULT;
        fr_set(&f, SMR(1), 0x80000000 | 0x1420);
        stk_smr_scan(fr_read, &f, 4, 0, 15, streams, &s);
        CHECK(s.status == STK_E_FAULT && !s.stream[0].scanned || at >= 4);
    }
    /* A fault only on the S2CR read: the stream is scanned and found, its type is not known. */
    memset(&f, 0, sizeof f);
    f.window = 0x100000; f.fault_at = 4; f.fault_err = STK_E_FAULT;
    fr_set(&f, SMR(1), 0x80000000 | 0x1420);
    stk_smr_scan(fr_read, &f, 4, 0, 15, streams, &s);
    CHECK(s.status == STK_OK && s.stream[0].found && !s.stream[0].s2cr_read);
    return 0;
}

/* ---- layout ------------------------------------------------------------------------------------ */

static int test_layout(void)
{
    struct stk_layout l;
    /* The Surface Pro 11 panel: 2880x1920, the page at scale 3 with about 38 rows used. */
    stk_layout(2880, 1920, 3, 38, &l);
    CHECK(l.placement == STK_LAYOUT_RIGHT && l.scale == 2);
    uint32_t x0 = 20 + l.col0 * 6 * l.scale, x1 = 20 + (l.col0 + STK_LINE_MAX) * 6 * l.scale;
    CHECK(x0 >= 20 + STK_PAGE_COLS * 6 * 3);                 /* right of the widest page line */
    CHECK(x1 < 2880);                                        /* the last character is drawn without wrapping */
    CHECK(20 + l.row0 * 9 * l.scale >= 296);                 /* below the emblem */
    CHECK(l.rows >= STK_MAX_LINES + 2);
    CHECK(20 + (l.row0 + l.rows - 1) * 9 * l.scale + 7 * l.scale < 1920);   /* the last row is drawn */
    /* Narrower panels fall back to below the page, at the page's own scale. */
    stk_layout(1920, 1280, 3, 38, &l);
    CHECK(l.placement == STK_LAYOUT_BELOW && l.scale == 3 && l.col0 == 0 && l.row0 == 38);
    stk_layout(800, 600, 2, 37, &l);
    CHECK(l.placement == STK_LAYOUT_BELOW && l.scale == 2 && l.row0 == 37);
    /* A wide but short panel cannot hold the rows to its right at scale 2 or 1: below it is. */
    stk_layout(3840, 400, 3, 10, &l);
    CHECK(l.placement == STK_LAYOUT_BELOW);
    /* Wide enough only at scale 1. */
    stk_layout(2300, 1920, 3, 38, &l);
    CHECK(l.placement == STK_LAYOUT_RIGHT && l.scale == 1);
    x1 = 20 + (l.col0 + STK_LINE_MAX) * 6 * l.scale;
    CHECK(x1 < 2300 && 20 + l.col0 * 6 * l.scale >= 20 + STK_PAGE_COLS * 6 * 3);
    /* Degenerate sizes do not misbehave. */
    stk_layout(0, 0, 0, 0, &l);
    CHECK(l.placement == STK_LAYOUT_BELOW && l.rows == 0);
    stk_layout(10, 10, 3, 500, &l);
    CHECK(l.placement == STK_LAYOUT_BELOW && l.rows == 0);
    /* The page's own widest line (85 characters under QEMU) fits the reserved width. */
    CHECK(STK_PAGE_COLS >= 88);
    return 0;
}

/* ---- one command per suite ------------------------------------------------------------------------ */

static const struct { const char *name; int (*fn)(void); } suites[] = {
    {"text", test_text}, {"path", test_path}, {"gate", test_gate}, {"verdict", test_verdict},
    {"smmu-verdict", test_smmu_verdict}, {"map", test_map}, {"xecp", test_xecp}, {"smr", test_smr},
    {"layout", test_layout},
};

int main(int argc, char **argv)
{
    alarm(60);                                  /* a loop the bounds should have stopped fails, never hangs */
    unsigned ran = 0;
    for (unsigned i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        if (argc > 1 && strcmp(argv[1], suites[i].name) && strcmp(argv[1], "all")) continue;
        unsigned before = checks;
        int bad = suites[i].fn();
        if (bad) {
            fprintf(stderr, "FAIL: suite %s\n", suites[i].name);
            return 1;
        }
        printf("PASS %-13s %u checks\n", suites[i].name, checks - before);
        ran++;
    }
    if (!ran) { fprintf(stderr, "no suite named %s\n", argc > 1 ? argv[1] : "(none)"); return 2; }
    printf("PASS: %u stick-log survey logic suites, %u checks\n", ran, checks);
    return 0;
}
