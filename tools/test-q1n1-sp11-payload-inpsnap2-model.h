/* SPDX-License-Identifier: MIT */
/* The model of the host test of the payload "inpsnap2" (tools/test-q1n1-sp11-payload-inpsnap2.c and its suites hold the tests): the payload built natively with Q1N1_PAYLOAD_HOST_TEST, so that
 * CurrentEL comes from a scripted register file and every load from a model of the two windows. Built with INPSNAP2_SRC pointing at a seeded-bug copy of the payload, it is how the mutants
 * are shown to be refused.
 *
 * Two independent things judge every run. The first is a REFERENCE: an interpreter written apart from the payload, from the design (docs/SP11-PAYLOAD-INPSNAP2.md), that reads the
 * model's fixture (a word per row, a fault per row or per window) and says what the page must be, line by line, and which rows the payload must load and when: it is compared with the page
 * and the loads of the run. The second is a set of RULES checked at every load and every line, whatever the fixture: a load that is not 4-byte aligned, past the ABI's 4096 or the payload's
 * cap, at an address the harness's OWN list of rows (below, written from the design and not from the payload's table) does not name, of a row twice, in a block after an abort in it, after
 * an all-ones word, of a block's first row without its `NEXT` line as the last line printed, of the first row of a line without the line before it printed, of a row in the middle of a
 * line after a line went out, of the wrapper's word behind clock words the harness's OWN rule does not hold running; a system register other than CurrentEL; more lines than the ABI or the
 * payload's cap; a line of more than 95 characters or outside the page font; a missing end line. Any access that reaches a device window other than through load32 (the windows are
 * unmapped here, so a payload that dereferences one dies on a signal that the harness turns into that verdict). Nothing here ran on hardware. Evidence: EXPERIMENTAL (host model only). */
#pragma once
#define _GNU_SOURCE
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef INPSNAP2_SRC
#define INPSNAP2_SRC "../payloads/inpsnap2.c"
#endif
#include INPSNAP2_SRC

#pragma clang diagnostic ignored "-Wunused-function"     /* a capped build runs only the cap suite, the shipped one all the others */

/* ---- The harness's own list of rows ------------------------------------------------------------------------------------------------------------ */

enum { XW_GCC, XW_QUP, XW_COUNT };
enum { XB_GATE, XB_RCG, XB_PLL, XB_LVL, XB_QUP, XB_COUNT };
static const struct {
    uint64_t base;
    uint32_t size;
} XW[XW_COUNT] = {{0x00100000u, 0x200000u}, {0x00bc0000u, 0x2000u}};
static const char XB_HEAD[XB_COUNT][5] = {"GATE", "RCG", "PLL", "LVL", "QUP"};

/* Row index (= the page order), window, offset, key as printed, block, page line, and what the row is for the plan: 1 a branch clock word, 2 one that has a hardware gating bit. */
struct x_reg {
    uint8_t win, block, line, kind;
    uint32_t off;
    char key[8];
};
#define XR(w, b, l, k, o, key) {w, b, l, k, o, key}
static const struct x_reg XR_[] = {
    XR(XW_GCC, XB_GATE, 0, 2, 0x23000, "MA0"), XR(XW_GCC, XB_GATE, 0, 2, 0x23004, "SA0"), XR(XW_GCC, XB_GATE, 0, 1, 0x23008, "CR0"),
    XR(XW_GCC, XB_GATE, 1, 1, 0x42274, "SE0"), XR(XW_GCC, XB_GATE, 1, 0, 0x52020, "VT0"), XR(XW_GCC, XB_GATE, 1, 0, 0x52030, "GV"),
    XR(XW_GCC, XB_RCG, 2, 0, 0x4229c, "DFS"), XR(XW_GCC, XB_RCG, 2, 0, 0x42284, "DIV"), XR(XW_GCC, XB_RCG, 2, 0, 0x42288, "CMD"), XR(XW_GCC, XB_RCG, 2, 0, 0x4228c, "CFG"),
    XR(XW_GCC, XB_RCG, 3, 0, 0x42290, "M"), XR(XW_GCC, XB_RCG, 3, 0, 0x42294, "N"), XR(XW_GCC, XB_RCG, 3, 0, 0x42298, "D"),
    XR(XW_GCC, XB_PLL, 4, 0, 0x00000, "MODE"), XR(XW_GCC, XB_PLL, 4, 0, 0x00004, "OP"), XR(XW_GCC, XB_PLL, 4, 0, 0x0000c, "ST"),
    XR(XW_GCC, XB_PLL, 5, 0, 0x00010, "L"), XR(XW_GCC, XB_PLL, 5, 0, 0x00014, "AL"), XR(XW_GCC, XB_PLL, 5, 0, 0x00018, "USR"),
    XR(XW_GCC, XB_LVL, 6, 0, 0x422a4, "LC0"), XR(XW_GCC, XB_LVL, 6, 0, 0x422a8, "LC1"), XR(XW_GCC, XB_LVL, 6, 0, 0x422ac, "LC2"), XR(XW_GCC, XB_LVL, 6, 0, 0x422b0, "LC3"),
    XR(XW_GCC, XB_LVL, 7, 0, 0x422b4, "LC4"), XR(XW_GCC, XB_LVL, 7, 0, 0x422b8, "LC5"), XR(XW_GCC, XB_LVL, 7, 0, 0x422bc, "LC6"), XR(XW_GCC, XB_LVL, 7, 0, 0x422c0, "LC7"),
    XR(XW_GCC, XB_LVL, 8, 0, 0x422e4, "LM0"), XR(XW_GCC, XB_LVL, 8, 0, 0x422e8, "LM1"), XR(XW_GCC, XB_LVL, 8, 0, 0x422ec, "LM2"), XR(XW_GCC, XB_LVL, 8, 0, 0x422f0, "LM3"),
    XR(XW_GCC, XB_LVL, 9, 0, 0x422f4, "LM4"), XR(XW_GCC, XB_LVL, 9, 0, 0x422f8, "LM5"), XR(XW_GCC, XB_LVL, 9, 0, 0x422fc, "LM6"), XR(XW_GCC, XB_LVL, 9, 0, 0x42300, "LM7"),
    XR(XW_GCC, XB_LVL, 10, 0, 0x42324, "LN0"), XR(XW_GCC, XB_LVL, 10, 0, 0x42328, "LN1"), XR(XW_GCC, XB_LVL, 10, 0, 0x4232c, "LN2"), XR(XW_GCC, XB_LVL, 10, 0, 0x42330, "LN3"),
    XR(XW_GCC, XB_LVL, 11, 0, 0x42334, "LN4"), XR(XW_GCC, XB_LVL, 11, 0, 0x42338, "LN5"), XR(XW_GCC, XB_LVL, 11, 0, 0x4233c, "LN6"), XR(XW_GCC, XB_LVL, 11, 0, 0x42340, "LN7"),
    XR(XW_QUP, XB_QUP, 12, 0, 0x00004, "VER"),
};
#define XN (sizeof XR_ / sizeof XR_[0])
#define XLINES 13u
/* First row of each page line and the number of rows in it. */
static const uint8_t XL_FIRST[XLINES] = {0, 3, 6, 10, 13, 16, 19, 23, 27, 31, 35, 39, 43};
static const uint8_t XL_COUNT[XLINES] = {3, 3, 4, 3, 3, 3, 4, 4, 4, 4, 4, 4, 1};
/* First row of each block (and one past the last). */
static const uint8_t XB_FIRST[XB_COUNT + 1] = {0, 6, 13, 19, 43, 44};
/* The rows the wrapper's read depends on, and the vote bit of the two with a hardware gating bit (gcc-x1e80100.c: m_ahb and s_ahb of wrapper 0 enable bits 6 and 7 of 0x52020). */
#define XR_MA0 0u
#define XR_SA0 1u
#define XR_CR0 2u
#define XR_SE0 3u
#define XR_VT0 4u
#define XR_GV 5u
#define XR_DFS 6u
#define XR_VER 43u
static const unsigned X_VOTE_BIT[2] = {6, 7};

/* ---- The state of the model --------------------------------------------------------------------------------------------------------------------- */

static uint32_t m_val[XN];              /* what a row reads */
static uint8_t m_flt[XN];               /* a row whose load aborts */
static unsigned m_win_faults;           /* a bit per window every load of which aborts */
static int m_el, m_have_load32, m_bad_args;
static struct {
    unsigned row, nlines;               /* the row loaded, and the lines printed when it was */
    uint32_t value;
    int fault;
} m_loadlog[4200];
static unsigned m_nloadlog;
static char m_lines[128][220];
static unsigned m_line_loads[128];      /* the loads made when each line was printed */
static unsigned m_nlines, m_nloads, m_nfaults, m_violations, m_sysreg_reads, m_checks, m_fails;
static char m_first_violation[260];
static uint8_t m_seen[XN];              /* a row already loaded in this run */
static unsigned m_dead, m_block_rank, m_lines_at_line_start, m_cur_line, m_stopped_row;
static int m_hang_nth;                  /* the load (0-based) that never returns, or -1 */
static jmp_buf m_hang_jmp;
static int m_hung;
static unsigned m_max_lines, m_max_loads;

static void m_violate(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void m_violate(const char *fmt, ...)
{
    va_list ap;
    if (!m_violations++) {
        va_start(ap, fmt);
        vsnprintf(m_first_violation, sizeof m_first_violation, fmt, ap);
        va_end(ap);
    }
}

static void m_dump(FILE *f)
{
    static unsigned dumps;
    if (dumps++) return;                /* the first failure's page is enough to read; the FAIL lines say the rest */
    fprintf(f, "  page (%u lines, %u loads):\n", m_nlines, m_nloads);
    for (unsigned i = 0; i < m_nlines; i++) fprintf(f, "  %2u %s\n", i, m_lines[i]);
}

#define CHECK(cond) do { m_checks++; if (!(cond)) { m_fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); m_dump(stderr); } } while (0)
/* The same, with what the case in a table is, so that the FAIL line names it. */
#define CHECKM(cond, what) do { m_checks++; if (!(cond)) { m_fails++; fprintf(stderr, "FAIL %s:%d: %s: %s\n", __FILE__, __LINE__, #cond, what); m_dump(stderr); } } while (0)

#if defined(__SANITIZE_ADDRESS__)
#define M_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define M_SANITIZED 1
#endif
#endif
/* The two windows are not mapped in this process: a payload that reads or writes one through a pointer instead of load32 dies on a signal whose address is in a window, and that is
 * reported as what it is. Any other signal keeps its default action (and a sanitized build keeps its own report). */
#ifndef M_SANITIZED
static int m_in_window(uint64_t addr)
{
    for (unsigned w = 0; w < XW_COUNT; w++) if (addr >= XW[w].base && addr - XW[w].base < XW[w].size) return 1;
    return 0;
}

static void m_trap(int sig, siginfo_t *info, void *unused)
{
    static const char verdict[] = "FAIL: an access reached a device window without load32\n";
    (void)unused;
    if (m_in_window((uint64_t)(uintptr_t)info->si_addr)) {
        if (write(2, verdict, sizeof verdict - 1) < 0) _exit(2);
        _exit(1);
    }
    signal(sig, SIG_DFL);
}
#endif

static void m_install_trap(void)
{
#ifndef M_SANITIZED
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = m_trap;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
#endif
}

/* The row at an address, or -1. */
static int m_row_of(uint64_t addr)
{
    for (unsigned i = 0; i < XN; i++) if (XW[XR_[i].win].base + XR_[i].off == addr) return (int)i;
    return -1;
}

static int m_win_of(uint64_t addr)
{
    for (unsigned w = 0; w < XW_COUNT; w++) if (addr >= XW[w].base && addr - XW[w].base < XW[w].size) return (int)w;
    return -1;
}

/* ---- The harness's own rules for a branch clock word and for the wrapper's gate ---------------------------------------------------------------------- */

/* A branch clock word: running when CLK_OFF (bit 31) is clear or the NoC FSM status (bits 30:28) is 2; all ones is no clock word; CLK_OFF set with HW_CTL (bit 1) set on a clock with a
 * hardware gating bit says nothing (hardware gating). Returns 'N' (running), 'F' (stopped), 'H' (hardware gating) or 'O' (all ones). */
static char m_clock_verdict(uint32_t word, int has_hwcg)
{
    if (word == 0xffffffffu) return 'O';
    if (!(word >> 31) || ((word >> 28) & 7) == 2) return 'N';
    return has_hwcg && ((word >> 1) & 1) ? 'H' : 'F';
}

/* The gate of the wrapper's read from the values of the rows as the harness knows them (`known[i]`: the row was read, `value[i]` its word): 0 open, 1 off (a word that read says stopped,
 * or hardware gating with its vote clear), 2 unknown (a word that did not read, all ones, hardware gating with no vote word, or a vote word that is not plausible). */
static int m_gate_of(const int known[], const uint32_t value[])
{
    int off = 0, unknown = 0;
    for (unsigned i = XR_MA0; i <= XR_CR0; i++) {
        char v;
        if (!known[i]) {
            unknown = 1;
            continue;
        }
        v = m_clock_verdict(value[i], i != XR_CR0);
        if (v == 'H') {
            if (!known[XR_VT0]) v = 'O';
            else v = (value[XR_VT0] >> X_VOTE_BIT[i]) & 1 ? 'N' : 'F';
        }
        if (v == 'F') off = 1;
        if (v == 'O') unknown = 1;
    }
    if (!known[XR_VT0] || value[XR_VT0] == 0 || value[XR_VT0] == 0xffffffffu) unknown = 1;
    return off ? 1 : unknown ? 2 : 0;
}

/* ---- The reference page ------------------------------------------------------------------------------------------------------------------------- */

static uint16_t r_crc_table[256];
static int r_crc_ready;
static void r_crc_init(void)
{
    for (unsigned i = 0; i < 256; i++) {
        uint16_t crc = (uint16_t)(i << 8);
        for (unsigned k = 0; k < 8; k++) crc = (uint16_t)((crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1);
        r_crc_table[i] = crc;
    }
    r_crc_ready = 1;
}

static uint16_t r_crc(uint16_t crc, const uint8_t *data, size_t n)
{
    if (!r_crc_ready) r_crc_init();
    while (n--) crc = (uint16_t)((crc << 8) ^ r_crc_table[(crc >> 8) ^ *data++]);
    return crc;
}

/* A word's text as the design says: below 10 one digit, else 0X and the fewest upper-case hex digits; a clock word's verdict after it. */
static void r_value(char *out, size_t size, int state, uint32_t value, unsigned kind)
{
    char verdict[8] = "";
    switch (state) {
    case 1:
        if (kind) {
            char v = m_clock_verdict(value, kind == 2);
            snprintf(verdict, sizeof verdict, v == 'N' ? ".ON" : v == 'F' ? ".OFF" : v == 'H' ? ".HW" : ".ODD");
        }
        if (value < 10) snprintf(out, size, "%u%s", value, verdict);
        else snprintf(out, size, "0X%X%s", value, verdict);
        break;
    case 2:
        snprintf(out, size, "FAULT:%u", value);
        break;
    case 3:
        snprintf(out, size, "SKIP");
        break;
    case 4:
        snprintf(out, size, "BUDGET");
        break;
    default:
        snprintf(out, size, "NA");
        break;
    }
}

/* What the page and the loads must be for the model's current fixture and caps. */
static struct {
    char line[40][220];
    unsigned after[40];                 /* the loads made when the line is printed */
    unsigned n, loads, faults, skips, cuts, blocks;
    unsigned order[XN], norder;         /* the rows loaded, in order */
    int stop_row;
} R;

static void r_put(const char *text, unsigned after)
{
    snprintf(R.line[R.n], sizeof R.line[0], "%s%s", PREFIX, text);
    R.after[R.n++] = after;
}

static int r_room(void) { return R.n + 1u < LINE_CAP; }

static void r_build(void)
{
    int dead[XB_COUNT] = {0}, known[XN] = {0};
    uint32_t value[XN] = {0};
    uint32_t state[XN] = {0};
    char text[240];
    memset(&R, 0, sizeof R);
    R.stop_row = -1;
    snprintf(text, sizeof text, "READ ONLY EL=2 STAGE=I0 CAP=%u/%u", LOAD_CAP, LINE_CAP);
    if (r_room()) r_put(text, 0);
    else R.cuts++;
    if (r_room()) r_put("KEY=VALUE .ON .OFF .HW .ODD=CLOCK FAULT:6=ABORT SKIP=NOT READ K=LINE CRC16", 0);
    else R.cuts++;
    for (unsigned b = 0; b < XB_QUP; b++) {
        if (R.stop_row >= 0) break;
        if (!r_room()) {
            R.cuts++;
            R.blocks |= 1u << b;
            continue;
        }
        snprintf(text, sizeof text, "NEXT %s", XB_HEAD[b]);
        r_put(text, R.loads);
        for (unsigned li = 0; li < XLINES && R.stop_row < 0; li++) {
            unsigned first = XL_FIRST[li], n = XL_COUNT[li];
            uint16_t crc = 0xffff;
            if (XR_[first].block != b) continue;
            if (!r_room()) {
                R.cuts++;
                R.blocks |= 1u << b;
                continue;
            }
            snprintf(text, sizeof text, "%s", XB_HEAD[b]);
            for (unsigned k = 0; k < n; k++) {
                unsigned i = first + k;
                char word[40];
                if (R.stop_row >= 0 || dead[b]) {
                    state[i] = 3;
                    R.skips++;
                    R.blocks |= 1u << b;
                } else if (R.loads >= LOAD_CAP) {
                    state[i] = 4;
                    R.blocks |= 1u << b;
                } else {
                    R.order[R.norder++] = i;
                    R.loads++;
                    if (m_flt[i] || (m_win_faults >> XR_[i].win & 1)) {
                        state[i] = 2;
                        value[i] = 6;
                        dead[b] = 1;
                        R.faults++;
                        R.blocks |= 1u << b;
                    } else {
                        state[i] = 1;
                        value[i] = m_val[i];
                        known[i] = 1;
                        if (value[i] == 0xffffffffu) R.stop_row = (int)i;
                    }
                }
                r_value(word, sizeof word, (int)state[i], value[i], XR_[i].kind);
                {
                    uint8_t bytes[5] = {(uint8_t)state[i], (uint8_t)value[i], (uint8_t)(value[i] >> 8), (uint8_t)(value[i] >> 16), (uint8_t)(value[i] >> 24)};
                    if (state[i] == 3 || state[i] == 4) bytes[1] = bytes[2] = bytes[3] = bytes[4] = 0;
                    crc = r_crc(crc, bytes, sizeof bytes);
                }
                snprintf(text + strlen(text), sizeof text - strlen(text), " %s=%s", XR_[i].key, word);
            }
            snprintf(text + strlen(text), sizeof text - strlen(text), " K=%04X", crc);
            r_put(text, R.loads);
        }
    }
    if (R.stop_row < 0) {
        if (!r_room()) {
            R.cuts++;
            R.blocks |= 1u << XB_QUP;
        } else {
            int gate;
            r_put("NEXT QUP", R.loads);
            gate = m_gate_of(known, value);
            if (gate) {
                R.blocks |= 1u << XB_QUP;
                if (r_room()) r_put(gate == 1 ? "QUP GATED OFF" : "QUP GATED ERR", R.loads);
                else R.cuts++;
            } else if (!r_room()) {
                R.cuts++;
                R.blocks |= 1u << XB_QUP;
            } else {
                char word[40];
                uint16_t crc = 0xffff;
                uint8_t bytes[5];
                if (R.loads >= LOAD_CAP) {
                    state[XR_VER] = 4;
                    R.blocks |= 1u << XB_QUP;
                } else {
                    R.order[R.norder++] = XR_VER;
                    R.loads++;
                    if (m_flt[XR_VER] || (m_win_faults >> XW_QUP & 1)) {
                        state[XR_VER] = 2;
                        value[XR_VER] = 6;
                        R.faults++;
                        R.blocks |= 1u << XB_QUP;
                    } else {
                        state[XR_VER] = 1;
                        value[XR_VER] = m_val[XR_VER];
                        if (value[XR_VER] == 0xffffffffu) R.stop_row = XR_VER;
                    }
                }
                r_value(word, sizeof word, (int)state[XR_VER], value[XR_VER], 0);
                bytes[0] = (uint8_t)state[XR_VER];
                bytes[1] = (uint8_t)value[XR_VER];
                bytes[2] = (uint8_t)(value[XR_VER] >> 8);
                bytes[3] = (uint8_t)(value[XR_VER] >> 16);
                bytes[4] = (uint8_t)(value[XR_VER] >> 24);
                if (state[XR_VER] == 4) bytes[1] = bytes[2] = bytes[3] = bytes[4] = 0;
                crc = r_crc(crc, bytes, sizeof bytes);
                snprintf(text, sizeof text, "QUP VER=%s K=%04X", word, crc);
                r_put(text, R.loads);
            }
        }
    }
    if (R.stop_row >= 0)
        for (unsigned b = XR_[R.stop_row].block; b < XB_COUNT; b++) R.blocks |= 1u << b;
    snprintf(text, sizeof text, "END LOADS=%u FAULTS=%u SKIPS=%u BLK=", R.loads, R.faults, R.skips);
    if (R.blocks < 10) snprintf(text + strlen(text), sizeof text - strlen(text), "%u", R.blocks);
    else snprintf(text + strlen(text), sizeof text - strlen(text), "0X%X", R.blocks);
    snprintf(text + strlen(text), sizeof text - strlen(text), " CUTS=%u LINES=%u STOP=%s", R.cuts, R.n + 1u, R.stop_row >= 0 ? XR_[R.stop_row].key : "NONE");
    r_put(text, R.loads);
}

/* ---- The model's loads and lines ----------------------------------------------------------------------------------------------------------------- */

/* The model's own verdict on the wrapper's word at the time of its load, from the loads made so far. */
static int m_gate_now(void)
{
    int known[XN] = {0};
    uint32_t value[XN] = {0};
    for (unsigned e = 0; e < m_nloadlog; e++) {
        if (m_loadlog[e].fault) continue;
        known[m_loadlog[e].row] = 1;
        value[m_loadlog[e].row] = m_loadlog[e].value;
    }
    return m_gate_of(known, value);
}

static int m_last_line_is(const char *tail)
{
    char want[100];
    snprintf(want, sizeof want, "%s%s", PREFIX, tail);
    return m_nlines && !strcmp(m_lines[m_nlines - 1], want);
}

/* The last line printed is the data line `li` of the page (it starts with its head and its first key). */
static int m_last_line_is_data(unsigned li)
{
    char want[100];
    snprintf(want, sizeof want, "%s%s %s=", PREFIX, XB_HEAD[XR_[XL_FIRST[li]].block], XR_[XL_FIRST[li]].key);
    return m_nlines && !strncmp(m_lines[m_nlines - 1], want, strlen(want));
}

static int32_t m_load32(uint64_t addr, uint32_t *out)
{
    int row = m_row_of(addr);
    int32_t status = Q1N1_PAYLOAD_LOAD_OK;
    uint32_t value = 0;
    *out = 0;
    m_nloads++;
    if (addr & 3) {
        m_violate("load of %#llx is not 4-byte aligned", (unsigned long long)addr);
        return Q1N1_PAYLOAD_LOAD_E_ALIGN;
    }
    if (m_nloads > Q1N1_PAYLOAD_LOADS_MAX) {
        m_violate("load %u is past the ABI's %u", m_nloads, Q1N1_PAYLOAD_LOADS_MAX);
        return Q1N1_PAYLOAD_LOAD_E_BUDGET;
    }
    if (m_nloads > LOAD_CAP) m_violate("load %u is past the payload's cap of %u", m_nloads, LOAD_CAP);
    if (m_hang_nth >= 0 && (int)m_nloads - 1 == m_hang_nth) {
        m_hung = 1;
        longjmp(m_hang_jmp, 1);
    }
    if (row < 0) {
        m_violate("load of %#llx, an address the harness's list names no row at (window %d)", (unsigned long long)addr, m_win_of(addr));
        return Q1N1_PAYLOAD_LOAD_OK;
    }
    if (m_seen[row]) m_violate("%s read twice in one run", XR_[row].key);
    m_seen[row] = 1;
    if (m_stopped_row) m_violate("load of %s after the all-ones word of %s", XR_[row].key, XR_[m_stopped_row - 1].key);
    if (m_dead >> XR_[row].block & 1) m_violate("load of %s after an abort in its block (a retry, or a read the abort should have ended)", XR_[row].key);
    /* The order: a block after the one before it, its first row only with its NEXT line last; a line's first row only with the line before it printed; the rest of a line with nothing
     * printed since its first row. */
    if (XR_[row].block < m_block_rank) {
        m_violate("load of %s (block %s) after a later block", XR_[row].key, XB_HEAD[XR_[row].block]);
    } else {
        unsigned li = XR_[row].line;
        int first_of_line = row == XL_FIRST[li];
        if (XR_[row].block > m_block_rank || (!m_nloadlog && XR_[row].block == 0)) {
            char tail[24];
            snprintf(tail, sizeof tail, "NEXT %s", XB_HEAD[XR_[row].block]);
            if (!m_last_line_is(tail)) m_violate("load of %s (block %s) without `%s` as the last line", XR_[row].key, XB_HEAD[XR_[row].block], tail);
            m_block_rank = XR_[row].block;
        } else if (first_of_line && (li == 0 || !m_last_line_is_data(li - 1u))) {
            m_violate("load of %s, the first word of line %u, before the line before it was printed: a line is read whole and printed before the next is read", XR_[row].key, li);
        }
        if (first_of_line) {
            m_lines_at_line_start = m_nlines;
            m_cur_line = li;
        } else if (li != m_cur_line || m_nlines != m_lines_at_line_start) {
            m_violate("load of %s inside line %u after a line was printed: a line is read whole and then printed", XR_[row].key, li);
        }
    }
    if (row == (int)XR_VER) {
        int gate = m_gate_now();
        if (gate) m_violate("load of VER while the clock words of the wrapper say %s", gate == 1 ? "stopped (or hardware gating with no vote)" : "nothing a gate can trust");
    }
    if (m_win_faults >> XR_[row].win & 1 || m_flt[row]) {
        status = Q1N1_PAYLOAD_LOAD_E_FAULT;
        m_nfaults++;
        m_dead |= 1u << XR_[row].block;
    } else {
        value = m_val[row];
    }
    if (m_nloadlog < sizeof m_loadlog / sizeof m_loadlog[0]) {
        m_loadlog[m_nloadlog].row = (unsigned)row;
        m_loadlog[m_nloadlog].nlines = m_nlines;
        m_loadlog[m_nloadlog].value = status ? 0 : value;
        m_loadlog[m_nloadlog++].fault = status != 0;
    }
    if (!status && value == 0xffffffffu) m_stopped_row = (unsigned)row + 1u;
    if (status) return status;
    *out = value;
    return Q1N1_PAYLOAD_LOAD_OK;
}

static void m_puts(const char *text)
{
    size_t n = strlen(text);
    if (m_nlines >= sizeof m_lines / sizeof m_lines[0]) {
        m_violate("more than 128 lines");
        return;
    }
    if (m_nlines >= Q1N1_PAYLOAD_LINES_MAX) m_violate("line %u is past the ABI's %u", m_nlines + 1, Q1N1_PAYLOAD_LINES_MAX);
    if (n > LINE_FILL) m_violate("a line of %zu characters (a packed line may have %u)", n, (unsigned)LINE_FILL);
    for (size_t i = 0; i < n; i++) {
        char ch = text[i];
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || strchr(" :-./=?()_", ch))) {
            m_violate("character 0x%02x of \"%s\" is not in the page font", (unsigned char)ch, text);
            break;
        }
    }
    if (strncmp(text, PREFIX, strlen(PREFIX))) m_violate("a line without the prefix: \"%s\"", text);
    snprintf(m_lines[m_nlines], sizeof m_lines[0], "%s", text);
    m_line_loads[m_nlines] = m_nloads;
    m_nlines++;
}

static uint32_t m_hex(char *dst, uint32_t cap, uint64_t value)
{
    char tmp[24];
    int n = snprintf(tmp, sizeof tmp, "0X%llX", (unsigned long long)value);
    if (cap == 0) return 0;
    if ((uint32_t)n >= cap) n = (int)cap - 1;
    memcpy(dst, tmp, (size_t)n);
    dst[n] = 0;
    return (uint32_t)n;
}

uint64_t pl_host_sysreg(const char *name)
{
    m_sysreg_reads++;
    if (!strcmp(name, "CurrentEL")) return (uint64_t)m_el << 2;
    m_violate("a system register read: %s", name);
    return 0;
}

static struct q1n1_payload_args m_args(void)
{
    struct q1n1_payload_args a;
    memset(&a, 0, sizeof a);
    a.magic = Q1N1_PAYLOAD_ABI_MAGIC;
    a.version = Q1N1_PAYLOAD_ABI_VERSION;
    a.size = sizeof a;
    a.ops.puts = m_puts;
    a.ops.hex = m_hex;
    a.ops.load32 = m_have_load32 ? m_load32 : NULL;
    if (m_bad_args) a.magic ^= 1;
    return a;
}

/* ---- The fixtures ---------------------------------------------------------------------------------------------------------------------------------- */

static void m_reset_run(void)
{
    m_nlines = m_nloads = m_nfaults = m_violations = m_sysreg_reads = m_nloadlog = 0;
    m_first_violation[0] = 0;
    memset(m_seen, 0, sizeof m_seen);
    m_dead = m_block_rank = m_lines_at_line_start = m_cur_line = m_stopped_row = 0;
    m_hung = 0;
}

static void m_fx_reset(void)
{
    memset(m_val, 0, sizeof m_val);
    memset(m_flt, 0, sizeof m_flt);
    m_win_faults = 0;
    m_el = 2;
    m_have_load32 = 1;
    m_bad_args = 0;
    m_hang_nth = -1;
    m_reset_run();
}

static unsigned m_row(const char *key)
{
    for (unsigned i = 0; i < XN; i++) if (!strcmp(XR_[i].key, key)) return i;
    fprintf(stderr, "the harness has no row %s\n", key);
    exit(2);
}

static void m_set(const char *key, uint32_t value)
{
    unsigned i = m_row(key);
    m_val[i] = value;
    m_flt[i] = 0;
}

static void m_fault(const char *key)
{
    m_flt[m_row(key)] = 1;
}

/* Every row reads `value`: a window of zeros, of all ones. */
static void m_fx_all(uint32_t value)
{
    for (unsigned i = 0; i < XN; i++) m_val[i] = value;
}

/* A unit-like fixture: the five words boot 29 read of the wrapper-0 gate and vote words are the unit's (OBSERVED: MA0 0, SA0 0, CR0 0x4000, SE0 0x80004000 = off, VT0 0x810223D0); every other
 * value is made up, to show what a page looks like: NOT the unit's page. A plain (non-DFS) RCG, a PLL that reads locked, a version 2.5. */
static void m_fx_unit(void)
{
    m_fx_reset();
    m_set("MA0", 0);
    m_set("SA0", 0);
    m_set("CR0", 0x4000);
    m_set("SE0", 0x80004000u);
    m_set("VT0", 0x810223d0u);
    m_set("GV", 1);
    m_set("DFS", 0);
    m_set("DIV", 0);
    m_set("CMD", 0);
    m_set("CFG", 0x2601);
    m_set("M", 0x10);
    m_set("N", 0xffc4);
    m_set("D", 0xffb4);
    m_set("MODE", 0xc0000005u);
    m_set("OP", 1);
    m_set("ST", 0);
    m_set("L", 0x1f);
    m_set("AL", 0x4000);
    m_set("USR", 0x401);
    for (unsigned i = 0; i < 8; i++) {
        char key[8];
        snprintf(key, sizeof key, "LC%u", i);
        m_set(key, 0x2601 + i);
        snprintf(key, sizeof key, "LM%u", i);
        m_set(key, 0x10 + i);
        snprintf(key, sizeof key, "LN%u", i);
        m_set(key, 0xffc4 - i);
    }
    m_set("VER", 0x20050000u);
}

/* One run of the payload against the current model. */
static uint64_t m_go(void)
{
    struct q1n1_payload_args a = m_args();
    uint64_t ret = 0;
    m_reset_run();
    if (setjmp(m_hang_jmp) == 0) ret = payload_entry(&a);
    return ret;
}

/* What every run must satisfy whatever the hardware says, and, at EL2 with a guarded load, that the page and the loads are the reference's. */
static int m_clean(int at)
{
    const char *why = NULL;
    char detail[400] = "";
    if (m_violations) why = m_first_violation;
    else if (m_nlines > LINE_CAP) why = "more lines than the payload's cap";
    else if (m_nloads > LOAD_CAP) why = "more loads than the payload's cap";
    else if (!m_nlines) why = "no line at all";
    else if (m_el == 2 && m_have_load32 && !m_bad_args && !m_hung) {
        r_build();
        if (m_nlines != R.n) {
            snprintf(detail, sizeof detail, "the page has %u lines, the reference's %u", m_nlines, R.n);
            why = detail;
        }
        for (unsigned i = 0; !why && i < m_nlines && i < R.n; i++) {
            if (strcmp(m_lines[i], R.line[i])) {
                snprintf(detail, sizeof detail, "page line %u is \"%s\", the reference's \"%s\"", i, m_lines[i], R.line[i]);
                why = detail;
            }
        }
        if (!why && m_nloadlog != R.norder) {
            snprintf(detail, sizeof detail, "the payload made %u loads, the reference's %u", m_nloadlog, R.norder);
            why = detail;
        }
        for (unsigned i = 0; !why && i < m_nloadlog; i++) {
            if (m_loadlog[i].row != R.order[i]) {
                snprintf(detail, sizeof detail, "load %u is of %s, the reference's %s", i, XR_[m_loadlog[i].row].key, XR_[R.order[i]].key);
                why = detail;
            }
        }
    }
    if (!why) return 1;
    fprintf(stderr, "FAIL line %d: %s (violations %u, lines %u, loads %u)\n", at, why, m_violations, m_nlines, m_nloads);
    m_dump(stderr);
    m_fails++;
    return 0;
}

static void m_track(void)
{
    if (m_nlines > m_max_lines) m_max_lines = m_nlines;
    if (m_nloads > m_max_loads) m_max_loads = m_nloads;
}
#define RUN_CLEAN() do { m_checks++; (void)m_go(); (void)m_clean(__LINE__); m_track(); } while (0)

static int m_has(const char *text)
{
    for (unsigned i = 0; i < m_nlines; i++) if (strstr(m_lines[i], text)) return 1;
    return 0;
}

static int m_line_index(const char *tail)
{
    char want[240];
    snprintf(want, sizeof want, "%s%s", PREFIX, tail);
    for (unsigned i = 0; i < m_nlines; i++) if (!strcmp(m_lines[i], want)) return (int)i;
    return -1;
}

static unsigned m_end_field(const char *name)
{
    char pat[32];
    const char *p;
    snprintf(pat, sizeof pat, " %s=", name);
    p = m_nlines ? strstr(m_lines[m_nlines - 1], pat) : NULL;
    return p ? (unsigned)strtoul(p + strlen(pat), NULL, 0) : 0xffffffffu;
}

static const char *m_end_stop(void)
{
    static char out[16];
    const char *p = m_nlines ? strstr(m_lines[m_nlines - 1], " STOP=") : NULL;
    if (!p) return "";
    snprintf(out, sizeof out, "%s", p + 6);
    return out;
}

/* The text of KEY on the page (without the verdict suffix), or NULL. */
static const char *m_word(const char *key)
{
    static char out[64];
    char pat[24];
    snprintf(pat, sizeof pat, " %s=", key);
    for (unsigned i = 0; i < m_nlines; i++) {
        const char *p = strstr(m_lines[i], pat);
        if (p && !strstr(m_lines[i], " END ") && strncmp(m_lines[i] + strlen(PREFIX), "END ", 4)) {
            size_t n = strcspn(p + strlen(pat), " ");
            snprintf(out, sizeof out, "%.*s", (int)n, p + strlen(pat));
            return out;
        }
    }
    return NULL;
}

static int m_word_is(const char *key, const char *want)
{
    const char *got = m_word(key);
    m_checks++;
    if (got && !strcmp(got, want)) return 1;
    m_fails++;
    fprintf(stderr, "FAIL: %s is %s, not %s\n", key, got ? got : "(absent)", want);
    m_dump(stderr);
    return 0;
}

static unsigned m_loads_of_row(const char *key)
{
    unsigned n = 0, r = m_row(key);
    for (unsigned e = 0; e < m_nloadlog; e++) n += m_loadlog[e].row == r;
    return n;
}
