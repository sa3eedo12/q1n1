/* SPDX-License-Identifier: MIT */
/* The model of the host test of the payload "dispsnap" (tools/test-q1n1-sp11-payload-dispsnap.c holds the suites): the payload built natively with Q1N1_PAYLOAD_HOST_TEST, so that CurrentEL
 * and CNTFRQ_EL0 come from a scripted register file, every load from a fake register file of the four blocks with the harness's own list of registers, and the counter from a model of the
 * runner's. Built with DISPSNAP_SRC pointing at a seeded-bug copy of the payload, it is how the mutants are shown to be refused.
 *
 * The model fails the run on anything the payload must never do: a load that is not 4-byte aligned, past the ABI's 4096, at an address the harness's OWN list (written from the design note and
 * the study's dump list, not from the payload's table) does not name, in a block whose gate the harness's OWN rules (below) hold closed for the memory the run sees, in a window after an abort in
 * it (so no retry either), a block's first load whose `NEXT <block>` line is not the last line printed, a load of a lower block after a higher one, a load of a new line of the table before a line
 * has gone out since the last load of the line before it, the frame counter read when its enable does not say it counts, a snapshot-2 load outside GCC, DISPCC and the interface's STATUS, enable
 * and frame counter, of a word snapshot 1 did not read, behind a gate snapshot 2's own words do not hold open, or not under its `NEXT S2 <window>` line, a wait that starts without `NEXT WAIT` as
 * the last line, a system register other than CurrentEL and CNTFRQ_EL0, more lines than the ABI or the payload's cap, a line of more than 100 characters or outside the page font, a missing end
 * line, a counter read more than five million times (an unbounded wait), and any access that reaches a device window or the framebuffer other than through load32 (the windows and the
 * framebuffer's address are unmapped here, so a payload that dereferences one dies on a signal that the harness turns into that verdict). Nothing here ran on hardware.
 * Evidence: EXPERIMENTAL (host model only). */
#pragma once
#define _GNU_SOURCE
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef DISPSNAP_SRC
#define DISPSNAP_SRC "../payloads/dispsnap.c"
#endif
#include DISPSNAP_SRC

#pragma clang diagnostic ignored "-Wunused-function"     /* a capped build runs only the cap suite, the shipped one all the others */

/* ---- The harness's own list of what may be read ----------------------------------------------------------------------------------------------- */

enum { M_GCC, M_DISPCC, M_MDSS, M_DPU, M_BLOCKS };
static const char M_NAME[M_BLOCKS][7] = {"GCC", "DISPCC", "MDSS", "DPU"};
enum { M_LOAD, M_LINE };
#define X_GCC 0x00100000u
#define X_DISPCC 0x0af00000u
#define X_MDSS 0x0ae00000u
#define X_DPU 0x0ae01000u
#define X_INTF (X_DPU + 0x39000u)               /* INTF_5, the eDP controller's interface */
#define X_CTL(n) (X_DPU + 0x15000u + 0x1000u * (n))
#define X_FB 0x7e0000000000ull                  /* the framebuffer address the arguments carry: nothing is mapped there */

/* block, the page line it is printed on (the harness's numbering), whether the word is read only when the frame counter's enable says it counts, address, the key it is printed under. The
 * addresses are the study's dump list (docs/SP11-DISPLAY-STUDY.md section 8) written out again. */
struct m_reg {
    uint8_t block, line, counter;
    uint32_t addr;
    char key[8];
};
#define MR(b, l, a, k) {b, l, 0, a, k}
#define MC(b, l, a, k) {b, l, 1, a, k}
static const struct m_reg M_REGS[] = {
    MR(M_GCC, 0, X_GCC + 0x27004, "DAHB"),
    MR(M_DISPCC, 1, X_DISPCC + 0x9000, "GDSC"), MR(M_DISPCC, 2, X_DISPCC + 0x80a8, "AHBC"), MR(M_DISPCC, 2, X_DISPCC + 0x800c, "MDPC"),
    MR(M_MDSS, 3, X_MDSS + 0x0, "VER"),
    MR(M_DPU, 4, X_INTF + 0x26c, "ST"), MR(M_DPU, 4, X_INTF + 0x000, "EN"), MR(M_DPU, 4, X_INTF + 0x004, "CFG"), MR(M_DPU, 4, X_INTF + 0x060, "CFG2"),
    MR(M_DPU, 5, X_INTF + 0x008, "HS"), MR(M_DPU, 5, X_INTF + 0x00c, "VP"), MR(M_DPU, 5, X_INTF + 0x01c, "DVS"), MR(M_DPU, 5, X_INTF + 0x024, "DVE"),
    MR(M_DPU, 6, X_INTF + 0x02c, "AVS"), MR(M_DPU, 6, X_INTF + 0x034, "AVE"), MR(M_DPU, 6, X_INTF + 0x03c, "DHC"), MR(M_DPU, 6, X_INTF + 0x040, "AHC"),
    MR(M_DPU, 7, X_INTF + 0x0a8, "FLC"), MC(M_DPU, 7, X_INTF + 0x0ac, "FRA"),
    MR(M_DPU, 8, X_CTL(0) + 0xf4, "C0"), MR(M_DPU, 8, X_CTL(1) + 0xf4, "C1"), MR(M_DPU, 8, X_CTL(2) + 0xf4, "C2"),
    MR(M_DPU, 9, X_CTL(3) + 0xf4, "C3"), MR(M_DPU, 9, X_CTL(4) + 0xf4, "C4"), MR(M_DPU, 9, X_CTL(5) + 0xf4, "C5"),
};
#define M_NREGS (sizeof M_REGS / sizeof M_REGS[0])
#define M_LINES 10u
#define M_DPU_S2(r) ((r)->block == M_DPU && (!strcmp((r)->key, "ST") || !strcmp((r)->key, "EN") || !strcmp((r)->key, "FRA")))

/* ---- The state of the model ------------------------------------------------------------------------------------------------------------------- */

static struct {
    uint32_t addr;
    uint32_t value;
    int fault;
} m_fake[64];
static unsigned m_nfake;
static uint32_t m_fill;
static int m_fill_all;                  /* every address the model is asked about reads m_fill (hostile runs) */
static struct {
    int kind;
    uint32_t addr;
    unsigned phase;
} m_events[2048];
static unsigned m_nevents;
static char m_lines[128][220];
static unsigned m_nlines, m_nloads, m_violations, m_dead, m_phase, m_started, m_sysreg_reads, m_checks, m_fails;
static unsigned m_s2_skipped;           /* a line `S2 SKIPPED ...` has been printed in this run */
static char m_first_violation[240];
static unsigned m_bloads[M_BLOCKS];
static unsigned m_win_faults;           /* a bit per block every load of which aborts */
static uint64_t m_rand_seed;            /* non-zero: an address nobody set reads a pseudo-random word */
static uint64_t m_ctr_now, m_ctr_step, m_ctr_calls, m_ctr_at_last_s1_load, m_gap_ticks, m_ctr_at_fra, m_ctr_at_frb;
static unsigned m_ctr_run, m_wait_checked;      /* counter reads since the last load or line; the wait's start has been checked */
static int m_ctr_mode, m_el, m_have_counter, m_have_load32;
static uint64_t m_hz;
static uint32_t m_frames_per_wait;      /* the frame counter moves by this much during the wait (a 60 Hz panel: 480) */
static void (*m_at_wait)(void);
static unsigned char m_read_ok[M_NREGS];        /* snapshot 1 read this word without an abort */
static int m_prev_line;                         /* the line of the last snapshot-1 load, or -1 */
static unsigned m_lines_at_prev_load;
static uint32_t m_gop_w, m_gop_h, m_gop_stride, m_gop_fmt;
enum { C_RUN, C_STUCK, C_BACK };

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
    fprintf(f, "  page (%u lines, %u loads):\n", m_nlines, m_nloads);
    for (unsigned i = 0; i < m_nlines; i++) fprintf(f, "  %2u %s\n", i, m_lines[i]);
}

#define CHECK(cond) do { m_checks++; if (!(cond)) { m_fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); m_dump(stderr); } } while (0)
/* The same, with what the case in a table is, so that the FAIL line names it. */
#define CHECKM(cond, what) do { m_checks++; if (!(cond)) { m_fails++; fprintf(stderr, "FAIL %s:%d: %s: %s\n", __FILE__, __LINE__, #cond, what); m_dump(stderr); } } while (0)

static int m_has(const char *text)
{
    for (unsigned i = 0; i < m_nlines; i++) if (strstr(m_lines[i], text)) return 1;
    return 0;
}

static const struct m_reg *m_find(uint64_t addr)
{
    for (unsigned i = 0; i < M_NREGS; i++) if (M_REGS[i].addr == addr) return &M_REGS[i];
    return NULL;
}

static int m_index(const struct m_reg *r)
{
    return (int)(r - M_REGS);
}

/* The windows and the framebuffer are not mapped in this process: a payload that reads or writes a device address, or the framebuffer, through a pointer instead of load32 dies on a signal
 * whose address is in one of them, and that is reported as what it is. Any other signal keeps its default action (and a sanitized build keeps its own report). */
#if defined(__SANITIZE_ADDRESS__)
#define M_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define M_SANITIZED 1
#endif
#endif
#ifndef M_SANITIZED
static void m_trap(int sig, siginfo_t *info, void *unused)
{
    static const char verdict[] = "FAIL: an access reached a device window or the framebuffer without load32\n";
    uint64_t a = (uint64_t)(uintptr_t)info->si_addr;
    (void)unused;
    if ((a >= X_GCC && a < X_GCC + 0x200000u) || (a >= X_MDSS && a < X_DISPCC + 0x20000u) || (a >= X_FB && a < X_FB + 0x1000000u)) {
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

/* The value an address reads in the current memory: a fixture's word, a block-wide abort, a pseudo-random word or the fill. `fault` is set for an abort. */
static uint32_t m_value(uint64_t addr, int *fault)
{
    const struct m_reg *r = m_find(addr);
    *fault = 0;
    if (r && (m_win_faults & (1u << r->block))) {
        *fault = 1;
        return 0;
    }
    for (unsigned i = 0; i < m_nfake && !m_fill_all; i++) {
        if (m_fake[i].addr != addr) continue;
        *fault = m_fake[i].fault;
        return m_fake[i].value;
    }
    if (m_rand_seed && !m_fill_all) {
        uint64_t x = (addr ^ m_rand_seed) * UINT64_C(0x9E3779B97F4A7C15);
        x ^= x >> 29;
        x *= UINT64_C(0xBF58476D1CE4E5B9);
        return (uint32_t)(x >> 16) & ((x & 1) ? 0xffffffffu : (x & 2) ? 0x00000003u : 0x80000001u);     /* all kinds: ones, small, bit 31 and bit 0 */
    }
    return m_fill;
}

/* ---- What the harness holds a gate to: its own statement of the rules, written from the design note ---------------------------------------------- */

static int x_word(uint64_t addr, uint32_t *w)
{
    int fault;
    *w = m_value(addr, &fault);
    return !fault && *w != 0xffffffffu;
}

/* A branch clock word that proves its clock runs: enabled and not CLK_OFF. Anything not read, or all ones, proves nothing. None of the clocks of this payload has a hardware gating bit or a
 * skipped halt check, so there is no exemption. */
static int x_runs(uint64_t addr)
{
    uint32_t w;
    return x_word(addr, &w) && (w & 1) && !(w >> 31);
}

#define XG(off) (X_GCC + (off))
#define XD(off) (X_DISPCC + (off))
static int x_ahb_open(void)
{
    return x_runs(XG(0x27004));
}

/* The harness's own verdict numbers (not the payload's): the zero is UNK, as the payload's is, so that a harness that forgets to set one closes the gate too. */
enum { X_DX_UNK, X_DX_OFF, X_DX_HWCTL, X_DX_PART, X_DX_ON };
static unsigned x_clk_mask;
static unsigned x_disp(void)
{
    uint32_t gd, w;
    int known = x_word(XD(0x9000), &gd) && x_word(XD(0x80a8), &w) && x_word(XD(0x800c), &w);
    x_clk_mask = (unsigned)x_runs(XD(0x80a8)) | (unsigned)x_runs(XD(0x800c)) << 1;
    if (!known) return X_DX_UNK;
    if (gd >> 1 & 1) return X_DX_HWCTL;
    if ((gd & 1) || !(gd >> 31)) return X_DX_OFF;
    return x_clk_mask == 3 ? X_DX_ON : X_DX_PART;
}

/* The hardware version word must have been read, and be neither all ones nor zero, before the DPU is read. */
static int x_ver_ok(void)
{
    uint32_t w;
    return x_word(X_MDSS, &w) && w != 0;
}

/* Whether the frame counter's enable says it counts: read, not all ones, not zero. */
static int x_counts(void)
{
    uint32_t w;
    return x_word(X_INTF + 0xa8, &w) && w != 0;
}

/* Whether the harness lets block `b` be read in the current memory (snapshot 1). */
static int x_open(unsigned b)
{
    if (b == M_GCC) return 1;
    if (!x_ahb_open()) return 0;
    if (b == M_DISPCC) return 1;
    if (x_disp() != X_DX_ON) return 0;
    return b != M_DPU || x_ver_ok();
}

/* Whether the harness lets snapshot 2 read block `b` in the current memory, which at that point is the memory after the wait: DISPCC while the display register clock runs, the DPU also while the
 * gate words, read again just before, still say ON. */
static int x_s2_open(unsigned b)
{
    if (b == M_GCC) return 1;
    if (!x_ahb_open()) return 0;
    return b == M_DISPCC || x_disp() == X_DX_ON;
}

/* ---- The runner's ops ------------------------------------------------------------------------------------------------------------------------- */

static int m_last_line_is(const char *tail)
{
    char want[80];
    snprintf(want, sizeof want, "%s%s", PREFIX, tail);
    return m_nlines && !strcmp(m_lines[m_nlines - 1], want);
}

/* The last line is `tail`, or `tail` and a note after a space (snapshot 2 says what it found in the block before on the next NEXT line). */
static int m_last_line_starts(const char *tail)
{
    char want[80];
    size_t n;
    snprintf(want, sizeof want, "%s%s", PREFIX, tail);
    n = strlen(want);
    return m_nlines && !strncmp(m_lines[m_nlines - 1], want, n) && (m_lines[m_nlines - 1][n] == 0 || m_lines[m_nlines - 1][n] == ' ');
}

static int32_t m_load32(uint64_t addr, uint32_t *out)
{
    const struct m_reg *r = m_find(addr);
    int fault, idx;
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
    if (!r) {
        m_violate("load of %#llx, a register no list names", (unsigned long long)addr);
        *out = m_fill;
        return Q1N1_PAYLOAD_LOAD_OK;
    }
    idx = m_index(r);
    m_ctr_run = 0;
    m_bloads[r->block]++;
    if (m_dead >> r->block & 1) m_violate("load of %s %s after an abort in that window (a retry or a read the abort should have ended)", M_NAME[r->block], r->key);
    if (m_phase == 2) {
        char tail[24];
        if (r->block == M_MDSS || (r->block == M_DPU && !M_DPU_S2(r))) m_violate("snapshot-2 load of %s %s: only GCC, DISPCC and the interface's STATUS, enable and frame counter are read again", M_NAME[r->block], r->key);
        if (!m_read_ok[idx]) m_violate("snapshot-2 load of %s %s, a word snapshot 1 did not read", M_NAME[r->block], r->key);
        if (!x_s2_open(r->block)) m_violate("snapshot-2 load of %s %s behind a gate that snapshot 2's own words do not hold open", M_NAME[r->block], r->key);
        snprintf(tail, sizeof tail, "NEXT S2 %s", M_NAME[r->block]);
        if (!m_last_line_starts(tail)) m_violate("snapshot-2 load of %s %s without `%s` as the last line", M_NAME[r->block], r->key, tail);
    } else {
        if (!x_open(r->block)) m_violate("load of %s %s behind a closed gate", M_NAME[r->block], r->key);
        if (r->counter && !x_counts()) m_violate("load of %s %s, the frame counter, while its enable does not say it counts", M_NAME[r->block], r->key);
        if (!(m_started >> r->block & 1)) {
            /* the first load of a block: its NEXT line is the last line, and no later block has started */
            char tail[24];
            snprintf(tail, sizeof tail, "NEXT %s", M_NAME[r->block]);
            if (!m_last_line_is(tail)) m_violate("load of %s %s without `%s` as the last line", M_NAME[r->block], r->key, tail);
            if (m_started >> (r->block + 1)) m_violate("load of %s %s after a later block", M_NAME[r->block], r->key);
            m_started |= 1u << r->block;
        }
        /* a line of the table goes out before the first load of the next one, while the line cap leaves room for it */
        if (m_prev_line >= 0 && m_prev_line != r->line && m_nlines <= m_lines_at_prev_load && m_nlines < NORMAL_LIMIT)
            m_violate("load of %s %s (line %u) before the line %d was printed (a line is read whole and printed before the next is read)", M_NAME[r->block], r->key, r->line, m_prev_line);
        m_prev_line = r->line;
        m_lines_at_prev_load = m_nlines;
        m_ctr_at_last_s1_load = m_ctr_now;
    }
    if (m_phase == 2 && !m_gap_ticks) m_gap_ticks = m_ctr_now - m_ctr_at_last_s1_load;
    if (!strcmp(r->key, "FRA")) {
        if (m_phase == 2) m_ctr_at_frb = m_ctr_now;
        else m_ctr_at_fra = m_ctr_now;
    }
    if (m_nevents < sizeof m_events / sizeof m_events[0]) {
        m_events[m_nevents].kind = M_LOAD;
        m_events[m_nevents].addr = r->addr;
        m_events[m_nevents++].phase = m_phase;
    }
    *out = m_value(addr, &fault);
    if (fault) {
        m_dead |= 1u << r->block;
        *out = 0;
        return Q1N1_PAYLOAD_LOAD_E_FAULT;
    }
    if (m_phase != 2) m_read_ok[idx] = 1;
    return Q1N1_PAYLOAD_LOAD_OK;
}

static void m_set(uint32_t addr, uint32_t value);
static uint32_t m_addr(const char *key);

static void m_puts(const char *text)
{
    size_t n = strlen(text);
    if (m_nlines >= sizeof m_lines / sizeof m_lines[0]) {
        m_violate("more than 128 lines");
        return;
    }
    if (m_nlines >= Q1N1_PAYLOAD_LINES_MAX) m_violate("line %u is past the ABI's %u", m_nlines + 1, Q1N1_PAYLOAD_LINES_MAX);
    if (n > Q1N1_PAYLOAD_LINE_MAX) m_violate("a line of %zu characters", n);
    for (size_t i = 0; i < n; i++) {
        char ch = text[i];
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || strchr(" :-./=?()_", ch))) {
            m_violate("character 0x%02x of \"%s\" is not in the page font", (unsigned char)ch, text);
            break;
        }
    }
    if (strncmp(text, PREFIX, strlen(PREFIX))) m_violate("a line without the prefix: \"%s\"", text);
    snprintf(m_lines[m_nlines], sizeof m_lines[0], "%s", text);
    m_ctr_run = 0;
    if (m_nevents < sizeof m_events / sizeof m_events[0]) {
        m_events[m_nevents].kind = M_LINE;
        m_events[m_nevents].addr = m_nlines;
        m_events[m_nevents++].phase = m_phase;
    }
    m_nlines++;
    if (!strncmp(text + strlen(PREFIX), "NEXT WAIT", 9)) {
        m_phase = 2;
        /* the display went on drawing frames while the model's clock ran: the counter's word moves by what a panel of that rate shows in the gap */
        if (m_frames_per_wait) {
            int fault;
            uint32_t now = m_value(m_addr("FRA"), &fault);
            if (!fault) m_set(m_addr("FRA"), now + m_frames_per_wait);
        }
        if (m_at_wait) m_at_wait();
    }
    if (!strncmp(text + strlen(PREFIX), "S2 SKIPPED", 10)) m_s2_skipped = 1;
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

static uint64_t m_counter(void)
{
    if (++m_ctr_calls > 5000000u) {
        fprintf(stderr, "FAIL: the counter was read %llu times: an unbounded wait\n", (unsigned long long)m_ctr_calls);
        exit(1);
    }
    /* The wait is the first run of two counter reads with no load and no line between them (the single reads after a load of the frame counter and at the start of the run are not): the film
     * must have `NEXT WAIT` as its last line by then. */
    if (++m_ctr_run == 2 && !m_wait_checked) {
        m_wait_checked = 1;
        if (!m_last_line_starts("NEXT WAIT")) m_violate("the wait starts without `NEXT WAIT` as the last line");
    }
    if (m_ctr_mode == C_RUN) m_ctr_now += m_ctr_step;
    else if (m_ctr_mode == C_BACK) m_ctr_now -= m_ctr_step;
    return m_ctr_now;
}

uint64_t pl_host_sysreg(const char *name)
{
    m_sysreg_reads++;
    if (!strcmp(name, "CurrentEL")) return (uint64_t)m_el << 2;
    if (!strcmp(name, "cntfrq_el0")) return m_hz;
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
    a.fb_base = X_FB;
    a.fb_bytes = 0x1000000;
    a.fb_width = m_gop_w;
    a.fb_height = m_gop_h;
    a.fb_stride = m_gop_stride;
    a.fb_format = m_gop_fmt;
    a.ops.puts = m_puts;
    a.ops.hex = m_hex;
    a.ops.load32 = m_have_load32 ? m_load32 : NULL;
    a.ops.counter = m_have_counter ? m_counter : NULL;
    return a;
}

/* ---- Fixtures --------------------------------------------------------------------------------------------------------------------------------- */

static void m_set(uint32_t addr, uint32_t value)
{
    for (unsigned i = 0; i < m_nfake; i++) {
        if (m_fake[i].addr == addr) {
            m_fake[i].value = value;
            m_fake[i].fault = 0;
            return;
        }
    }
    m_fake[m_nfake].addr = addr;
    m_fake[m_nfake].value = value;
    m_fake[m_nfake++].fault = 0;
}

static void m_fault_at(uint32_t addr)
{
    m_set(addr, 0);
    for (unsigned i = 0; i < m_nfake; i++) if (m_fake[i].addr == addr) m_fake[i].fault = 1;
}

/* The word of a key, for the tests that change one: the address of the first row of the harness's list with that key. */
static uint32_t m_addr(const char *key)
{
    for (unsigned i = 0; i < M_NREGS; i++) if (!strcmp(M_REGS[i].key, key)) return M_REGS[i].addr;
    fprintf(stderr, "FAIL: no register %s in the harness's list\n", key);
    exit(2);
}

static void m_reset_run(void)
{
    m_nlines = m_nloads = m_violations = m_dead = m_phase = m_started = m_sysreg_reads = m_nevents = 0;
    m_s2_skipped = 0;
    m_first_violation[0] = 0;
    memset(m_bloads, 0, sizeof m_bloads);
    memset(m_read_ok, 0, sizeof m_read_ok);
    m_prev_line = -1;
    m_lines_at_prev_load = 0;
    m_ctr_now = 1000000;
    m_ctr_calls = m_ctr_at_last_s1_load = m_gap_ticks = m_ctr_at_fra = m_ctr_at_frb = 0;
    m_ctr_run = m_wait_checked = 0;
}

static void m_fx_reset(void)
{
    m_nfake = 0;
    m_fill = 0;
    m_fill_all = 0;
    m_win_faults = 0;
    m_rand_seed = 0;
    m_el = 2;
    m_hz = 19200000u;
    m_ctr_mode = C_RUN;
    m_ctr_step = 192000;        /* 10 ms of the model's 19.2 MHz per read */
    m_have_counter = m_have_load32 = 1;
    m_at_wait = NULL;
    m_frames_per_wait = 480;
    m_gop_w = 2880;             /* made up: the product's panel size, which the unit's GOP may not show (study section 4) */
    m_gop_h = 1920;
    m_gop_stride = 2880;
    m_gop_fmt = 1;
    m_reset_run();
}

/* One run of the payload against the current model. */
static uint64_t m_go(void)
{
    struct q1n1_payload_args a = m_args();
    uint64_t r;
    m_reset_run();
    r = payload_entry(&a);
    return r;
}

/* What every run must satisfy whatever the hardware says. */
static int m_clean(int at)
{
    const char *why = NULL;
    unsigned loads = 0, lines = 0, faults = 0, skips = 0, cuts = 0, gap = 0;
    char blk[24];
    if (m_violations) why = m_first_violation;
    else if (m_nlines > LINE_CAP) why = "more lines than the payload's cap";
    else if (m_nloads > LOAD_CAP) why = "more loads than the payload's cap";
    else if (!m_nlines) why = "no line at all";
    else if (m_el == 2 && m_have_load32) {
        if (sscanf(m_lines[m_nlines - 1], PREFIX "END LOADS=%u FAULTS=%u SKIPS=%u BLK=%23s CUTS=%u GAP_MS=%u LINES=%u",
                   &loads, &faults, &skips, blk, &cuts, &gap, &lines) != 7) why = "the last line is not the end line";
        else if (loads != m_nloads) why = "the end line's LOADS is not the loads made";
        else if (lines != m_nlines) why = "the end line's LINES is not the lines printed";
    }
    if (!why) return 1;
    fprintf(stderr, "FAIL line %d: %s (violations %u, lines %u, loads %u)\n", at, why, m_violations, m_nlines, m_nloads);
    m_dump(stderr);
    m_fails++;
    return 0;
}
static unsigned m_max_lines, m_max_loads;
static void m_track(void)
{
    if (m_nlines > m_max_lines) m_max_lines = m_nlines;
    if (m_nloads > m_max_loads) m_max_loads = m_nloads;
}
#define RUN_CLEAN() do { m_checks++; (void)m_go(); (void)m_clean(__LINE__); m_track(); } while (0)

static unsigned m_end_field(const char *name)
{
    char pat[32];
    const char *p;
    snprintf(pat, sizeof pat, " %s=", name);
    p = m_nlines ? strstr(m_lines[m_nlines - 1], pat) : NULL;
    return p ? (unsigned)strtoul(p + strlen(pat), NULL, 0) : 0xffffffffu;
}

static void m_line_is(unsigned n, const char *text, int at)
{
    char want[240];
    snprintf(want, sizeof want, "%s%s", PREFIX, text);
    m_checks++;
    if (n >= m_nlines || strcmp(m_lines[n], want)) {
        m_fails++;
        fprintf(stderr, "FAIL line %d: page line %u is \"%s\", not \"%s\"\n", at, n, n < m_nlines ? m_lines[n] : "(none)", want);
        m_dump(stderr);
    }
}

static int m_line_index(const char *tail, unsigned from)
{
    char want[100];
    snprintf(want, sizeof want, "%s%s", PREFIX, tail);
    for (unsigned i = from; i < m_nlines; i++) if (!strcmp(m_lines[i], want)) return (int)i;
    return -1;
}

static int m_seen(uint32_t addr)
{
    for (unsigned i = 0; i < m_nevents; i++) if (m_events[i].kind == M_LOAD && m_events[i].addr == addr) return 1;
    return 0;
}

static unsigned m_loads_of(uint32_t addr, unsigned phase)
{
    unsigned n = 0;
    for (unsigned i = 0; i < m_nevents; i++) n += m_events[i].kind == M_LOAD && m_events[i].addr == addr && m_events[i].phase == phase;
    return n;
}

static unsigned m_loads_in(unsigned phase)
{
    unsigned n = 0;
    for (unsigned i = 0; i < m_nevents; i++) n += m_events[i].kind == M_LOAD && m_events[i].phase == phase;
    return n;
}

/* The fixtures. What the unit showed, where it showed it: nothing of the display side (UNKNOWN, hardware NOT RUN). Every value below is MADE UP to show what a page looks like: a display
 * pipeline that runs a 2880 x 1920 mode on INTF_5 at 60 Hz, laid out as Linux programs a DP interface (the arithmetic of the main repo's tools/test-display-pipeline-check.py, written out again). */
static void m_fx_gates(void)
{
    m_set(m_addr("DAHB"), 0x1);
    m_set(m_addr("GDSC"), 0x8022f000); m_set(m_addr("AHBC"), 0x1); m_set(m_addr("MDPC"), 0x1);
    m_set(m_addr("VER"), 9u << 28 | 2u << 16);
}

static void m_fx_intf(unsigned width, unsigned height)
{
    const unsigned hs = 32, hbp = 48, hfp = 80, vs = 5, vbp = 30, vfp = 35;
    const unsigned ht = hs + hbp + width + hfp, vt = vs + vbp + height + vfp;
    const unsigned v0 = (vs + vbp) * ht + hs + hbp;
    const unsigned hctl = (hs + hbp + width - 1) << 16 | (hs + hbp);
    m_set(m_addr("ST"), 1); m_set(m_addr("EN"), 1); m_set(m_addr("CFG"), 0x60000000); m_set(m_addr("CFG2"), 0x10);
    m_set(m_addr("HS"), ht << 16 | hs); m_set(m_addr("VP"), ht * vt);
    m_set(m_addr("DVS"), v0); m_set(m_addr("DVE"), vt * ht - 1 - hfp - vfp * ht);
    m_set(m_addr("AVS"), v0); m_set(m_addr("AVE"), v0 + height * ht - 1);
    m_set(m_addr("DHC"), hctl); m_set(m_addr("AHC"), hctl);
    m_set(m_addr("FLC"), 3); m_set(m_addr("FRA"), 1000);
    m_set(m_addr("C0"), 1u << INTF_INDEX);
    for (unsigned i = 1; i < CTL_COUNT; i++) {
        char key[4];
        snprintf(key, sizeof key, "C%u", i);
        m_set(m_addr(key), 0);
    }
}

/* Every gate open and the pipeline running. */
static void m_fx_on(void)
{
    m_fx_reset();
    m_fx_gates();
    m_fx_intf(2880, 1920);
}

/* The display off as a cold unit would show it: the MDSS GDSC collapsed by software, both clocks off. Nothing behind the gate is read. */
static void m_fx_cold(void)
{
    m_fx_on();
    m_set(m_addr("GDSC"), 0x00222001); m_set(m_addr("AHBC"), 0x80000000); m_set(m_addr("MDPC"), 0x80000000);
}
