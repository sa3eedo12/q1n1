/* SPDX-License-Identifier: MIT */
/* The model behind the host test of the payload "tsnap" (tools/test-q1n1-sp11-payload-tsnap.c holds the suites; tools/test-q1n1-sp11-payload-tsnap.py builds and drives it). It is
 * what the payload runs against in place of the unit: eight register windows (the SROT and the TM of four blocks), the runner's four ops with its page rules (a line is cut at 100
 * characters, 40 lines per call, the font), a counter, and a CPU's two system registers. It holds its OWN list of the addresses a read may reach, written from the pinned driver
 * and not from the payload's tables, its own decode of a status word and its own arithmetic of every line that depends on the words (the oracle at the end: sums, packed lines, the
 * conversion lines), so that a wrong table or a wrong rule in the payload is a difference and not an echo.
 *
 * Everything a run does is logged in order: every printed line and every load, so that the suites can say where a line stood among the loads. A load outside the list, a load of a
 * window after an abort of it, a load of a block that its NEXT line did not announce, a line past the page's rules: each is a failed check on the spot. Nothing here ran on hardware.
 * Evidence: EXPERIMENTAL (host model only); every value of the fixtures is made up and none is the unit's. */
#pragma once
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TSNAP_SRC
#define TSNAP_SRC "../payloads/tsnap.c"
#endif
#include TSNAP_SRC

/* A failed check is shown once per place in the source (with how often it failed at the end of the run), so that the first hundreds of failures of one bug do not hide the other places. */
#define CHECK(cond) do { m_checks++; if (!(cond)) { static unsigned char shown_; m_fails++; if (!shown_) { shown_ = 1; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } } while (0)
static unsigned m_checks, m_fails, m_maxlines, m_maxloads;

/* ---- The model's own constants (not the payload's) ---- */
#define M_BLOCKS 4
#define M_WINDOWS 8                         /* 0..3 SROT, 4..7 TM */
#define M_WORDS 1024                        /* 0x1000 bytes */
static const uint32_t M_BASE[M_WINDOWS] = {0x0c222000u, 0x0c223000u, 0x0c224000u, 0x0c225000u, 0x0c271000u, 0x0c272000u, 0x0c273000u, 0x0c274000u};
#define M_SROT(n) (n)
#define M_TM(n) (4 + (n))
#define M_HZ 19200000u
#define M_LINES_MAX 40                      /* the runner's per-call line cap: later lines are dropped and counted */
#define M_EVENTS 2048

/* ---- The registers ---- */
static uint32_t m_reg[M_WINDOWS][M_WORDS];
static uint32_t m_s2_reg[M_WINDOWS][M_WORDS];
static unsigned char m_s2_set[M_WINDOWS][M_WORDS];  /* a word whose value changes when the second reading starts */

/* What a read may reach: the offsets of the pinned driver (tsens-v2.c:14-17, 36, 39, 44-45): the SROT HW_VER, CTRL and the sixteen conversion words, the TM interrupt status
 * words, the sixteen status words and TRDY. */
static int m_allowed(unsigned win, uint32_t off)
{
    if (win < 4) return off == 0x00 || off == 0x04 || (off >= 0x60 && off <= 0x9c && !(off & 3));
    return off == 0x08 || off == 0x14 || off == 0xe4 || (off >= 0xa0 && off <= 0xdc && !(off & 3));
}

/* ---- Behaviour switches ---- */
static int m_abort_nth, m_hang_nth;          /* the load (0-based, counting every load) that aborts or hangs, or -1 */
static uint32_t m_abort_windows;             /* every load of these windows aborts */
static int m_abort_from_nth;                 /* every load from this one on aborts (an SError storm), or -1 */
static unsigned m_el;                        /* the CurrentEL field the CPU reports */
static uint64_t m_cntfrq;
static int m_no_load32, m_no_counter, m_bad_args;
static uint64_t m_step;                      /* counter ticks per read of it; 0 is a counter that does not run */
static unsigned m_freeze_after;              /* the counter stands still from the read after this many (0: never) */
static int m_backwards;
static uint64_t m_counter_value;
static unsigned m_counter_reads, m_sysreg_reads;
static jmp_buf m_hang_jmp;
static int m_hung;
static uint64_t m_ret;

/* ---- The log ---- */
static char m_lines[M_EVENTS][128];
static unsigned m_nlines, m_dropped;
struct m_event { char kind; unsigned win; uint32_t off; unsigned line; };
static struct m_event m_ev[M_EVENTS];
static unsigned m_nev;
static unsigned m_nloads, m_aborted, m_wloads[M_WINDOWS];
static uint32_t m_dead_windows;
static unsigned m_lines_before_load[M_EVENTS];
static uint32_t m_load_addr[M_EVENTS];
static unsigned m_load_win[M_EVENTS];
static uint32_t m_load_off[M_EVENTS];
static int m_phase;                          /* 1: the first reading, 2: after the counter jumped by a second or more */
static uint64_t m_last_load_counter;
/* What the page has announced so far: -1 nothing yet, -2 nothing more (the pass is over). */
static int m_ann_block;                      /* the S1 block of the last `NEXT T<n>` line */
static int m_ann_ident;                      /* the S1 block whose identity line `T<n> VER=` was printed last: its TM window may be read */
static int m_ann_s2;                         /* `NEXT S2 AFTER 2 S` was printed */
static int m_s2_skipped;                     /* `S2 SKIPPED ...` was printed: no second-reading load may follow */
static int m_ann_s2_block;                   /* the block named by the end of the last S2 line (-1 before the first: any) */
static int m_ann_conv;                       /* the block named by the last `NEXT CONV T<n>`, as a line or as the end of a line */

static const char FONT[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:-./=?()_ ";

static void m_reset(void)
{
    memset(m_reg, 0, sizeof m_reg);
    memset(m_s2_reg, 0, sizeof m_s2_reg);
    memset(m_s2_set, 0, sizeof m_s2_set);
    m_abort_nth = m_hang_nth = m_abort_from_nth = -1;
    m_abort_windows = 0;
    m_el = 2;
    m_cntfrq = M_HZ;
    m_no_load32 = m_no_counter = m_bad_args = 0;
    m_step = 20000;
    m_freeze_after = 0;
    m_backwards = 0;
    m_counter_value = 1000000;
    m_counter_reads = m_sysreg_reads = 0;
    m_hung = 0;
    m_ret = 0;
    memset(m_lines, 0, sizeof m_lines);
    m_nlines = m_dropped = 0;
    m_nev = 0;
    m_nloads = m_aborted = 0;
    memset(m_wloads, 0, sizeof m_wloads);
    m_dead_windows = 0;
    m_phase = 1;
    m_last_load_counter = 0;
    m_ann_block = m_ann_ident = m_ann_conv = -1;
    m_ann_s2 = m_s2_skipped = 0;
    m_ann_s2_block = -1;
}

/* ---- The runner's ops ---- */
static uint32_t m_hex(char *dst, uint32_t cap, uint64_t value)
{
    char text[24];
    uint32_t n = (uint32_t)snprintf(text, sizeof text, "0X%llX", (unsigned long long)value);
    if (n >= cap) n = cap ? cap - 1 : 0;
    memcpy(dst, text, n);
    if (cap) dst[n] = 0;
    return n;
}

/* The block that a line ends by announcing: `... NEXT CONV T<d>` for the key "NEXT CONV T", `... NEXT T<d>` for "NEXT T" (the line may be only the announcement); -1 when it ends in
 * neither. */
static int m_announces(const char *text, const char *key)
{
    size_t n = strlen(text), k = strlen(key);
    if (n < k + 1 || text[n - 1] < '0' || text[n - 1] > '3') return -1;
    if (strncmp(text + n - k - 1, key, k)) return -1;
    if (n > k + 1 && text[n - k - 2] != ' ') return -1;
    return text[n - 1] - '0';
}

static void m_puts(const char *line)
{
    size_t n = strlen(line);
    const char *text = line + strlen(PREFIX);
    int named;
    if (m_nlines >= M_LINES_MAX) {
        m_dropped++;
        return;
    }
    CHECK(n <= Q1N1_PAYLOAD_LINE_MAX);
    for (size_t i = 0; i < n; i++) CHECK(strchr(FONT, line[i]) != NULL);
    memcpy(m_lines[m_nlines], line, n < 127 ? n : 127);
    if (m_nev < M_EVENTS) {
        m_ev[m_nev].kind = 'P';
        m_ev[m_nev].line = m_nlines;
        m_nev++;
    }
    /* The announcements: what the loads that follow may reach. A line that ends one pass without naming a block closes it (-2). */
    if (!strncmp(line, PREFIX "NEXT T", 20) && line[20] >= '0' && line[20] <= '3' && line[21] == 0) m_ann_block = line[20] - '0';
    if (text[0] == 'T' && text[1] >= '0' && text[1] <= '3' && !strncmp(text + 2, " VER=", 5)) m_ann_ident = text[1] - '0';
    if (!strcmp(line, PREFIX "NEXT S2 AFTER 2 S")) m_ann_s2 = 1;
    if (!strncmp(text, "S2 SKIPPED", 10)) m_s2_skipped = 1;
    if (!strncmp(text, "S2 T", 4) && text[4] >= '0' && text[4] <= '3' && text[5] == ' ') {
        named = m_announces(text, "NEXT T");
        m_ann_s2_block = named >= 0 ? named : -2;
    }
    named = m_announces(text, "NEXT CONV T");
    if (named >= 0) m_ann_conv = named;
    else if (!strncmp(text, "CONV T", 6)) m_ann_conv = -2;
    m_nlines++;
}

static uint64_t m_counter_fn(void)
{
    m_counter_reads++;
    if (m_freeze_after && m_counter_reads > m_freeze_after) return m_counter_value;
    if (m_backwards) m_counter_value -= m_step ? m_step : 1;
    else m_counter_value += m_step;
    return m_counter_value;
}

uint64_t pl_host_sysreg(const char *name);
uint64_t pl_host_sysreg(const char *name)
{
    m_sysreg_reads++;
    if (!strcmp(name, "CurrentEL")) return (uint64_t)m_el << 2;
    if (!strcmp(name, "cntfrq_el0")) return m_cntfrq;
    CHECK(!"a system register other than CurrentEL and CNTFRQ_EL0");
    return 0;
}

static int m_locate(uint64_t addr, unsigned *win, uint32_t *off)
{
    for (unsigned w = 0; w < M_WINDOWS; w++) {
        if (addr >= M_BASE[w] && addr < (uint64_t)M_BASE[w] + 0x1000u) {
            *win = w;
            *off = (uint32_t)(addr - M_BASE[w]);
            return 1;
        }
    }
    return 0;
}

/* The conversion pass reads the SROT conversion words and the two TM interrupt status words; everything else the payload reads belongs to a reading of the status words. */
static int m_is_pass(unsigned win, uint32_t off)
{
    return (win < 4 && off >= 0x60) || (win >= 4 && (off == 0x08 || off == 0x14));
}

/* What a load of a register means for the announcement rules: the block it belongs to and the pass of the page it must come in. The conversion pass needs the block to have been named by
 * a `NEXT CONV T<n>`; the second reading needs the page to have announced it, not to have skipped it, and the block to be the one the last S2 line named (any, for the first); the
 * first reading needs the block's `NEXT T<n>` and, for its TM window, its identity line. */
static void m_check_announced(unsigned win, uint32_t off)
{
    unsigned n = win & 3;
    int second = m_phase == 2;
    if (m_is_pass(win, off)) {
        CHECK(m_ann_conv == (int)n);
    } else if (second) {
        CHECK(m_ann_s2 && !m_s2_skipped && m_ann_conv == -1);
        CHECK(m_ann_s2_block == -1 || m_ann_s2_block == (int)n);
        CHECK((win < 4 && off == 0x04) || (win >= 4 && (off == 0xe4 || (off >= 0xa0 && off <= 0xdc))));
    } else {
        CHECK(!m_ann_s2 && m_ann_conv == -1);
        CHECK(m_ann_block == (int)n);
        if (win >= 4) CHECK(m_ann_ident == (int)n);
    }
}

static int32_t m_load32(uint64_t addr, uint32_t *out)
{
    unsigned win = 0, idx;
    uint32_t off = 0;
    int located;
    if (!out) return Q1N1_PAYLOAD_LOAD_E_PARAM;
    if (addr & 3 || (uintptr_t)out & 3) return Q1N1_PAYLOAD_LOAD_E_ALIGN;
    if (addr + 4 > (UINT64_C(1) << 48)) return Q1N1_PAYLOAD_LOAD_E_RANGE;
    if (m_nloads >= Q1N1_PAYLOAD_LOADS_MAX) return Q1N1_PAYLOAD_LOAD_E_BUDGET;
    idx = m_nloads++;
    located = m_locate(addr, &win, &off);
    /* The first load of the second reading, after the page announced it: the world moves on, and the wait the page announced must have happened. The conversion pass is no part of
     * it: it may follow a second reading that was skipped. */
    if (m_phase == 1 && m_ann_s2 && !(located && m_is_pass(win, off))) {
        uint64_t hz = (m_cntfrq >= 1000000 && m_cntfrq <= 1000000000) ? m_cntfrq : M_HZ;
        CHECK(m_last_load_counter && (int64_t)(m_counter_value - m_last_load_counter) >= (int64_t)(2 * hz));
        m_phase = 2;
        for (unsigned w = 0; w < M_WINDOWS; w++)
            for (unsigned i = 0; i < M_WORDS; i++)
                if (m_s2_set[w][i]) m_reg[w][i] = m_s2_reg[w][i];
    }
    m_last_load_counter = m_counter_value;
    if (!located) {
        CHECK(!"a load outside the eight windows");
        return Q1N1_PAYLOAD_LOAD_E_FAULT;
    }
    CHECK(m_allowed(win, off));
    CHECK(!(m_dead_windows >> win & 1));
    m_check_announced(win, off);
    m_wloads[win]++;
    if (idx < M_EVENTS) {
        m_load_addr[idx] = (uint32_t)addr;
        m_load_win[idx] = win;
        m_load_off[idx] = off;
        m_lines_before_load[idx] = m_nlines;
    }
    if (m_nev < M_EVENTS) {
        m_ev[m_nev].kind = 'L';
        m_ev[m_nev].win = win;
        m_ev[m_nev].off = off;
        m_ev[m_nev].line = m_nlines;
        m_nev++;
    }
    if (m_hang_nth == (int)idx) longjmp(m_hang_jmp, 1);
    if ((int)idx == m_abort_nth || (m_abort_windows >> win & 1) || (m_abort_from_nth >= 0 && (int)idx >= m_abort_from_nth)) {
        m_dead_windows |= 1u << win;
        m_aborted++;
        return Q1N1_PAYLOAD_LOAD_E_FAULT;
    }
    *out = m_reg[win][off / 4];
    return Q1N1_PAYLOAD_LOAD_OK;
}

static void m_run(void)
{
    struct q1n1_payload_args a;
    memset(&a, 0, sizeof a);
    a.magic = Q1N1_PAYLOAD_ABI_MAGIC;
    a.version = Q1N1_PAYLOAD_ABI_VERSION;
    a.size = m_bad_args ? 8 : (uint32_t)sizeof a;
    a.ops.puts = m_puts;
    a.ops.hex = m_hex;
    a.ops.load32 = m_no_load32 ? NULL : m_load32;
    a.ops.counter = m_no_counter ? NULL : m_counter_fn;
    m_hung = 0;
    if (!setjmp(m_hang_jmp)) m_ret = payload_entry(&a);
    else m_hung = 1;
}

/* ---- Reading the page ---- */
static int m_line_is(unsigned i, const char *text)
{
    char want[128];
    snprintf(want, sizeof want, "%s%s", PREFIX, text);
    return i < m_nlines && !strcmp(m_lines[i], want);
}

/* The index of the first line at or after `from` that is exactly PREFIX + tail, or starts with it and a space (or, for a tail that ends in `=`, with it), else -1. */
static int m_find(const char *tail, unsigned from)
{
    char want[128];
    size_t n;
    snprintf(want, sizeof want, "%s%s", PREFIX, tail);
    n = strlen(want);
    for (unsigned i = from; i < m_nlines; i++)
        if (!strncmp(m_lines[i], want, n) && (m_lines[i][n] == 0 || m_lines[i][n] == ' ' || want[n - 1] == '=')) return (int)i;
    return -1;
}

/* The text of a line without the prefix. */
static const char *m_text(unsigned i)
{
    return i < m_nlines ? m_lines[i] + strlen(PREFIX) : "";
}

/* The value of the token KEY= on a line (decimal), or -1 when it has none or it is not a number. */
static long m_field(const char *line, const char *key)
{
    char want[32];
    const char *p = line;
    size_t n;
    snprintf(want, sizeof want, "%s=", key);
    n = strlen(want);
    while ((p = strstr(p, want)) != NULL) {
        if ((p == line || p[-1] == ' ') && p[n] >= '0' && p[n] <= '9') return strtol(p + n, NULL, 10);
        p += n;
    }
    return -1;
}

/* The token that starts with KEY= on a line, copied up to the next space; "" when absent. */
static const char *m_token(const char *line, const char *key)
{
    static char out[8][64];
    static unsigned which;
    char want[32];
    const char *p = line;
    size_t n;
    char *dst = out[which++ & 7];
    snprintf(want, sizeof want, "%s=", key);
    n = strlen(want);
    dst[0] = 0;
    while ((p = strstr(p, want)) != NULL) {
        if (p == line || p[-1] == ' ') {
            size_t len = strcspn(p + n, " ");
            memcpy(dst, p + n, len < 63 ? len : 63);
            dst[len < 63 ? len : 63] = 0;
            return dst;
        }
        p += n;
    }
    return dst;
}

/* ---- The model's own decode of a status word ---- */
static void m_cell(uint32_t raw, char *out)
{
    int t = (int)(raw & 0xfff);
    if (t >= 2048) t -= 4096;
    if (raw >> 22) strcpy(out, "O");
    else if (!(raw >> 21 & 1)) strcpy(out, "?");
    else if (t < -400 || t > 1200) strcpy(out, "O");
    else snprintf(out, 16, "%d", t);
}

static int m_valid_tenths(uint32_t raw, int *t)
{
    char cell[16];
    int v = (int)(raw & 0xfff);
    if (v >= 2048) v -= 4096;
    m_cell(raw, cell);
    *t = v;
    return cell[0] != '?' && cell[0] != 'O';
}

/* ---- Fixtures ---- */
static const unsigned M_COUNT[M_BLOCKS] = {13, 11, 11, 15};      /* the sensor ids a DT zone reads on each block (hamoa.dtsi:9123-9915) */

static int m_tenths(unsigned n, unsigned i)
{
    return 300 + 7 * (int)n + 3 * (int)i;
}

static int m_tenths2(unsigned n, unsigned i)
{
    return m_tenths(n, i) + (int)((n + i) % 3) - 1;
}

static uint32_t m_status(int tenths)
{
    return (1u << 21) | ((uint32_t)tenths & 0xfff);
}

static void m_set(unsigned win, uint32_t off, uint32_t value)
{
    m_reg[win][off / 4] = value;
}

static void m_set2(unsigned win, uint32_t off, uint32_t value)
{
    m_s2_reg[win][off / 4] = value;
    m_s2_set[win][off / 4] = 1;
}

/* Four healthy blocks (made-up: not the unit's values): HW_VER 2.4.0, enabled, temperature format, the sensors a DT zone reads enabled, ready, 30.0 C and up, a conversion word per
 * enabled sensor, no interrupt status; in the second reading every sensor moves by -0.1, 0 or +0.1 C. */
static void m_fx_unit(void)
{
    m_reset();
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        uint32_t mask = (1u << M_COUNT[n]) - 1;
        m_set(M_SROT(n), 0x00, 0x20040000u);
        m_set(M_SROT(n), 0x04, (1u << 21) | (mask << 3) | 1u);
        m_set(M_TM(n), 0xe4, 1);
        for (unsigned i = 0; i < M_COUNT[n]; i++) {
            m_set(M_TM(n), 0xa0 + 4 * i, m_status(m_tenths(n, i)));
            m_set2(M_TM(n), 0xa0 + 4 * i, m_status(m_tenths2(n, i)));
            m_set(M_SROT(n), 0x60 + 4 * i, 0x01b3416au + i);
        }
    }
}

/* One run of the payload on what the model holds now, and what every run must satisfy: the page and the counters. */
static void m_check_run_invariants(void);
#define RUN_CLEAN() do { m_run(); CHECK(!m_hung); m_check_run_invariants(); } while (0)

static void m_check_run_invariants(void)
{
    if (m_nlines > m_maxlines) m_maxlines = m_nlines;
    if (m_nloads > m_maxloads) m_maxloads = m_nloads;
    CHECK(m_dropped == 0);
    CHECK(m_nlines <= LINE_CAP);
    CHECK(m_nloads <= LOAD_CAP);
    CHECK(m_nlines >= 1);
    if (m_nlines == 0) return;
    for (unsigned i = 0; i < m_nlines; i++) {
        CHECK(!strncmp(m_lines[i], PREFIX, strlen(PREFIX)));
        CHECK(strlen(m_lines[i]) <= Q1N1_PAYLOAD_LINE_MAX);
    }
    if (!m_hung && m_ret == 0 && m_el == 2 && !m_no_load32) {
        /* A normal end: the last line is END, its counters are the model's, and LINES is the page's length. */
        const char *last = m_text(m_nlines - 1);
        CHECK(!strncmp(last, "END LOADS=", 10));
        CHECK(m_field(last, "LOADS") == (long)m_nloads);
        CHECK(m_field(last, "FAULTS") == (long)m_aborted);
        CHECK(m_field(last, "LINES") == (long)m_nlines);
        CHECK(m_nlines >= 1 && m_nev <= M_EVENTS);
    }
}

/* ---- The model's oracle: what a page must say for the words the model holds ---- */
/* The builds with small caps run only the cap suite, so the oracle is unused there. */
#pragma clang diagnostic ignored "-Wunused-function"
struct m_sum {
    unsigned valid, out, odd, crit;
    int min, max;
    unsigned min_at, max_at;
};

static void m_oracle(const uint32_t w[M_BLOCKS][16], struct m_sum *s)
{
    memset(s, 0, sizeof *s);
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        for (unsigned i = 0; i < 16; i++) {
            uint32_t raw = w[n][i];
            int t = (int)(raw & 0xfff);
            if (t >= 2048) t -= 4096;
            if (raw >> 22) {
                s->odd++;
                continue;
            }
            if (raw >> 19 & 3) s->crit++;
            if (!(raw >> 21 & 1)) continue;
            if (t < -400 || t > 1200) {
                s->out++;
                continue;
            }
            if (!s->valid || t < s->min) {
                s->min = t;
                s->min_at = n << 4 | i;
            }
            if (!s->valid || t > s->max) {
                s->max = t;
                s->max_at = n << 4 | i;
            }
            s->valid++;
        }
    }
}

/* The model's own rule for a packed line: the fields in order, each added only if the whole line stays within 100 characters (the prefix takes 14); one that does not fit is dropped. */
static void m_pack(char *out, size_t cap, const char *head, char items[][48], unsigned n)
{
    size_t limit = Q1N1_PAYLOAD_LINE_MAX - strlen(PREFIX);
    snprintf(out, cap, "%s", head);
    for (unsigned i = 0; i < n; i++) {
        if (strlen(out) + 1 + strlen(items[i]) <= limit) {
            strcat(out, " ");
            strcat(out, items[i]);
        }
    }
}

/* A SUM line from the model's own arithmetic: V of 64, the extremes with their sensors, what is flagged critical, out of range and odd. */
static void m_sum_line(char *out, const char *name, const struct m_sum *s, int second, unsigned chg, unsigned both, int dmax)
{
    char tok[10][48];
    unsigned n = 0;
    snprintf(tok[n++], 48, "V=%u/64", s->valid);
    if (s->valid) snprintf(tok[n++], 48, "MIN=%d(T%u.%u)", s->min, s->min_at >> 4, s->min_at & 15);
    else snprintf(tok[n++], 48, "MIN=NA");
    if (s->valid) snprintf(tok[n++], 48, "MAX=%d(T%u.%u)", s->max, s->max_at >> 4, s->max_at & 15);
    else snprintf(tok[n++], 48, "MAX=NA");
    if (second) {
        snprintf(tok[n++], 48, "CHG=%u/%u", chg, both);
        snprintf(tok[n++], 48, "DMAX=%d", dmax);
    }
    snprintf(tok[n++], 48, "CRIT=%u", s->crit);
    snprintf(tok[n++], 48, "OUT=%u", s->out);
    snprintf(tok[n++], 48, "ODD=%u", s->odd);
    m_pack(out, 160, name, tok, n);
}

/* The status words the model holds for the first and the second reading, as they are before the run. */
struct m_world {
    uint32_t w1[M_BLOCKS][16], w2[M_BLOCKS][16];
};

static void m_capture(struct m_world *w)
{
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        for (unsigned i = 0; i < 16; i++) {
            uint32_t off = 0xa0 + 4 * i;
            w->w1[n][i] = m_reg[M_TM(n)][off / 4];
            w->w2[n][i] = m_s2_set[M_TM(n)][off / 4] ? m_s2_reg[M_TM(n)][off / 4] : w->w1[n][i];
        }
    }
}

/* Names the counters of a page line that disagree with the model's, so that a failure says which count is wrong and not only that a line is. */
static void m_show_fields(const char *want, const char *have)
{
    for (const char *p = want; *p;) {
        size_t word = strcspn(p, " ");
        const char *eq = memchr(p, '=', word);
        size_t klen = eq ? (size_t)(eq - p) : 0;
        char key[24];
        if (klen && klen < sizeof key) {
            memcpy(key, p, klen);
            key[klen] = 0;
            if (strcmp(m_token(want, key), m_token(have, key)) != 0) fprintf(stderr, "  field %s differs\n", key);
        }
        p += word;
        while (*p == ' ') p++;
    }
}

/* The first line that starts with `head` is exactly `want`; a difference is shown, so that a failing world can be read. */
static void m_expect_line(const char *head, const char *want)
{
    int at = m_find(head, 0);
    CHECK(at >= 0);
    if (at >= 0 && !m_line_is((unsigned)at, want)) {
        CHECK(0 && "a line differs from the model's arithmetic");
        fprintf(stderr, "  want: %s\n  have: %s\n", want, m_text((unsigned)at));
        m_show_fields(want, m_text((unsigned)at));
    }
}

/* The CONV line of block n from the model's own arithmetic, over the model's registers: how many of the sixteen conversion words are non-zero, the lowest and highest of those, the two
 * interrupt status words, and the block that the line names (-1: none). */
static void m_conv_line(char *out, size_t cap, unsigned n, int next)
{
    char tok[8][48], head[16];
    unsigned nz = 0, seen = 0, t = 0;
    uint32_t lo = 0, hi = 0;
    for (unsigned i = 0; i < 16; i++) {
        uint32_t v = m_reg[M_SROT(n)][(0x60 + 4 * i) / 4];
        if (!v) continue;
        nz++;
        if (!seen || v < lo) lo = v;
        if (!seen || v > hi) hi = v;
        seen = 1;
    }
    snprintf(tok[t++], 48, "NZ=%u/16", nz);
    if (seen) snprintf(tok[t++], 48, "LO=0X%X", lo);
    else snprintf(tok[t++], 48, "LO=NA");
    if (seen) snprintf(tok[t++], 48, "HI=0X%X", hi);
    else snprintf(tok[t++], 48, "HI=NA");
    snprintf(tok[t++], 48, "UL=0X%X", m_reg[M_TM(n)][0x08 / 4]);
    snprintf(tok[t++], 48, "CR=0X%X", m_reg[M_TM(n)][0x14 / 4]);
    if (next >= 0) snprintf(tok[t++], 48, "NEXT CONV T%d", next);
    snprintf(head, sizeof head, "CONV T%u", n);
    m_pack(out, cap, head, tok, t);
}

/* Every page line that depends on the words, against the model's own arithmetic, for a world in which all four blocks are healthy and nothing aborts. */
static void m_check_values(const struct m_world *w)
{
    struct m_sum s1, s2, b2;
    unsigned chg_total = 0, both_total = 0;
    int dmax_total = 0;
    char want[160];
    m_oracle(w->w1, &s1);
    m_oracle(w->w2, &s2);
    for (unsigned n = 0; n < M_BLOCKS; n++) {
        char head[16], items[18][48];
        int at;
        unsigned v = 0, chg = 0, both = 0;
        int d_max = 0;
        uint32_t one[M_BLOCKS][16];
        snprintf(head, sizeof head, "T%u R0", n);
        at = m_find(head, 0);
        CHECK(at >= 0);
        for (unsigned half = 0; half < 2; half++) {
            char text[128] = "";
            for (unsigned i = half * 8; i < half * 8 + 8; i++) {
                char tok[16];
                snprintf(tok, sizeof tok, "%s%08X", i % 8 ? " " : "", w->w1[n][i]);
                strcat(text, tok);
            }
            snprintf(want, sizeof want, "T%u R%u %s", n, half * 8, text);
            CHECK(at >= 0 && m_line_is((unsigned)at + half, want));
        }
        for (unsigned i = 0; i < 16; i++) {
            char cell[16];
            m_cell(w->w1[n][i], cell);
            if (cell[0] != '?' && cell[0] != 'O') v++;
            snprintf(items[i], 48, "%s", cell);
        }
        snprintf(items[16], 48, "RDY=0X%X", m_reg[M_TM(n)][0xe4 / 4]);
        snprintf(items[17], 48, "V=%u", v);
        snprintf(head, sizeof head, "T%u C", n);
        m_pack(want, sizeof want, head, items, 18);
        CHECK(at >= 0 && m_line_is((unsigned)at + 2, want));
        memset(one, 0, sizeof one);
        memcpy(one[n], w->w2[n], sizeof one[n]);
        m_oracle(one, &b2);
        for (unsigned i = 0; i < 16; i++) {
            int t1, t2;
            if (m_valid_tenths(w->w1[n][i], &t1) && m_valid_tenths(w->w2[n][i], &t2)) {
                int d = t1 > t2 ? t1 - t2 : t2 - t1;
                both++;
                chg += d != 0;
                if (d > d_max) d_max = d;
            }
        }
        chg_total += chg;
        both_total += both;
        if (d_max > dmax_total) dmax_total = d_max;
        snprintf(head, sizeof head, "S2 T%u", n);
        at = m_find(head, 0);
        CHECK(at >= 0);
        if (at >= 0) {
            const char *line = m_text((unsigned)at);
            char lo[16], hi[16];
            snprintf(lo, sizeof lo, "%d", b2.min);
            snprintf(hi, sizeof hi, "%d", b2.max);
            CHECK(m_field(line, "V") == (long)b2.valid);
            CHECK(!strcmp(m_token(line, "MIN"), b2.valid ? lo : "NA"));
            CHECK(!strcmp(m_token(line, "MAX"), b2.valid ? hi : "NA"));
            CHECK(m_field(line, "CHG") == (long)chg);
            CHECK(m_field(line, "D") == d_max);
            CHECK(m_field(line, "DT") >= 2000 && m_field(line, "DT") < 2100);
            CHECK((n < M_BLOCKS - 1) == (strstr(line, " NEXT T") != NULL));
            if (n < M_BLOCKS - 1) CHECK(strstr(line, " NEXT T") && strstr(line, " NEXT T")[7] == (char)('1' + n));
            else CHECK(m_announces(line, "NEXT CONV T") == 0);                      /* the last line of the second reading names the first block of the conversion pass */
        }
        m_conv_line(want, sizeof want, n, n < M_BLOCKS - 1 ? (int)n + 1 : -1);
        snprintf(head, sizeof head, "CONV T%u", n);
        m_expect_line(head, want);
    }
    m_sum_line(want, "SUM1", &s1, 0, 0, 0, 0);
    m_expect_line("SUM1", want);
    m_sum_line(want, "SUM2", &s2, 1, chg_total, both_total, dmax_total);
    m_expect_line("SUM2", want);
}
