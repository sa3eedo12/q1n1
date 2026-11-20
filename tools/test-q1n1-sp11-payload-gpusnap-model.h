/* SPDX-License-Identifier: MIT */
/* The model of the host test of the payload "gpusnap" (tools/test-q1n1-sp11-payload-gpusnap.c holds the suites): the payload built natively with Q1N1_PAYLOAD_HOST_TEST, so that
 * CurrentEL and CNTFRQ_EL0 come from a scripted register file, every load from a fake register file of the six blocks and the counter from a model of the runner's. Built with GPUSNAP_SRC
 * pointing at a seeded-bug copy of the payload, it is how the mutants are shown to be refused.
 *
 * The model fails the run on anything the payload must never do: a load that is not 4-byte aligned, past the ABI's 4096, at an address the harness's OWN list (written from the design note,
 * not from the payload's table) does not name, in the GX window (RBBM and CP) or anywhere else on the GPU's side, in a block whose gate the harness's OWN rules (below) hold closed
 * for the memory the run sees, in a window after an abort in it (so no retry either), a block's first load whose `NEXT <block>` line is not the last line printed, a load of a lower
 * block after a higher one, a load of a new line of the table before a line has gone out since the last load of the line before it, a snapshot-2 load outside GCC and GPUCC, of a word
 * snapshot 1 did not read, or not under its `NEXT S2 <window>` line, a wait that starts without `NEXT WAIT` as the last line, a word no Linux code reads (F_LATE) outside the late phase
 * or a word Linux reads inside it, a late load before the drift report, after a skipped snapshot 2, of a block snapshot 1 did not read, behind a CFG AHB word or CX verdict that snapshot
 * 2's words do not hold open, or not under its `NEXT LATE <block>` line, a system register other than CurrentEL and CNTFRQ_EL0, more lines than the ABI or the payload's cap, a line of more than
 * 100 characters or outside the page font, a missing end line, a counter read more than five million times (an unbounded wait), and any access that reaches a device window other than
 * through load32 (the windows are unmapped here, so a payload that dereferences one dies on a signal that the harness turns into that verdict). Nothing here ran on hardware.
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

#ifndef GPUSNAP_SRC
#define GPUSNAP_SRC "../payloads/gpusnap.c"
#endif
#include GPUSNAP_SRC

#pragma clang diagnostic ignored "-Wunused-function"     /* a capped build runs only the cap suite, the shipped one all the others */

/* ---- The harness's own list of what may be read ----------------------------------------------------------------------------------------------- */

enum { M_GCC, M_GPUCC, M_CXMISC, M_GMU, M_RSCC, M_SMMU, M_BLOCKS };
static const char M_NAME[M_BLOCKS][7] = {"GCC", "GPUCC", "CXMISC", "GMU", "RSCC", "SMMU"};
enum { M_LOAD, M_LINE };
#define X_GCC 0x00100000u
#define X_GPUCC 0x03d90000u
#define X_CXMISC 0x03d9e000u
#define X_GPU 0x03d00000u               /* the GPU base: GMU registers are X_GPU + 4 * dword (a6xx_gmu.h:139) */
#define X_RSCC 0x03d50000u
#define X_SMMU 0x03da0000u
#define X_GX_END 0x03d40000u            /* the GPU window, dt:4016, is [X_GPU, X_GX_END): RBBM and CP, never read */

/* block, the page line it is printed on (the harness's numbering), whether Linux ever reads the word (late: it does not, so the word is read last of all, after the wait and the drift
 * report: a6xx_gmu.c writes SYSRESET at :320 and :333, CM3_CFG at :1010 and PDC_SEQ_START_ADDR at :730 and never reads them, and names FW_BUSY nowhere), address, the key it is printed under */
struct m_reg {
    uint8_t block, line, late;
    uint32_t addr;
    char key[8];
};
#define MR(b, l, a, k) {b, l, 0, a, k}
#define ML(b, l, a, k) {b, l, 1, a, k}
static const struct m_reg M_REGS[] = {
    MR(M_GCC, 0, X_GCC + 0x71004, "CFGA"), MR(M_GCC, 0, X_GCC + 0x71010, "MNOC"), MR(M_GCC, 0, X_GCC + 0x7115c, "AXI_NW"), MR(M_GCC, 0, X_GCC + 0x71018, "SNOC"),
    MR(M_GCC, 1, X_GCC + 0x71008, "QMIP"), MR(M_GCC, 1, X_GCC + 0x52000, "VOTE"), MR(M_GCC, 1, X_GCC + 0x52030, "GP0V"),
    MR(M_GPUCC, 2, X_GPUCC + 0x9108, "CXGD"), MR(M_GPUCC, 2, X_GPUCC + 0x953c, "CXHW"),
    MR(M_GPUCC, 3, X_GPUCC + 0x911c, "AHB"), MR(M_GPUCC, 3, X_GPUCC + 0x913c, "CGMU"), MR(M_GPUCC, 3, X_GPUCC + 0x9144, "CXO"),
    MR(M_GPUCC, 4, X_GPUCC + 0x9148, "HUB"), MR(M_GPUCC, 4, X_GPUCC + 0x900c, "DMT"), MR(M_GPUCC, 4, X_GPUCC + 0x7000, "HLOS"),
    MR(M_GPUCC, 5, X_GPUCC + 0x905c, "GXGD"), MR(M_GPUCC, 5, X_GPUCC + 0x9060, "GXCF"),
    MR(M_GPUCC, 6, X_GPUCC + 0x9004, "CXOA"), MR(M_GPUCC, 6, X_GPUCC + 0x93e8, "HUBA"), MR(M_GPUCC, 6, X_GPUCC + 0x90bc, "GXGM"),
    MR(M_GPUCC, 7, X_GPUCC + 0x9318, "GRC"), MR(M_GPUCC, 7, X_GPUCC + 0x931c, "GRF"), MR(M_GPUCC, 7, X_GPUCC + 0x93ec, "HRC"), MR(M_GPUCC, 7, X_GPUCC + 0x93f0, "HRF"),
    MR(M_GPUCC, 8, X_GPUCC + 0x9010, "XRC"), MR(M_GPUCC, 8, X_GPUCC + 0x9014, "XRF"),
    MR(M_CXMISC, 9, X_CXMISC + 4 * 0x39, "TCMR"),
    MR(M_GMU, 10, X_GPU + 4 * 0x1f8d0, "GXST"), MR(M_GMU, 10, X_GPU + 4 * 0x1f81c, "INIT"), MR(M_GMU, 10, X_GPU + 4 * 0x23b13, "FENS"),
    ML(M_GMU, 11, X_GPU + 4 * 0x1f800, "RST"), ML(M_GMU, 11, X_GPU + 4 * 0x1f82d, "CFG"), ML(M_GMU, 11, X_GPU + 4 * 0x1f81a, "BUSY"),
    MR(M_RSCC, 12, X_RSCC + 4 * 0x101, "BSY"), MR(M_RSCC, 12, X_RSCC + 4 * 0x4, "ST0"),
    MR(M_RSCC, 12, X_RSCC + 4 * (0x346 + 4), "T0"), MR(M_RSCC, 12, X_RSCC + 4 * (0x3ee + 4), "T1"), MR(M_RSCC, 12, X_RSCC + 4 * (0x496 + 4), "T2"),
    MR(M_RSCC, 12, X_RSCC + 4 * (0x53e + 4), "T3"), MR(M_RSCC, 12, X_RSCC + 4 * (0x5e6 + 4), "T4"), MR(M_RSCC, 12, X_RSCC + 4 * (0x68e + 4), "T5"),
    MR(M_RSCC, 12, X_RSCC + 4 * (0x736 + 4), "T6"), MR(M_RSCC, 12, X_RSCC + 4 * (0x7de + 4), "T7"), MR(M_RSCC, 12, X_RSCC + 4 * (0x886 + 4), "T8"),
    MR(M_RSCC, 12, X_RSCC + 4 * (0x92e + 4), "T9"),
    ML(M_RSCC, 13, X_RSCC + 4 * 0x8, "PDCS"),
    MR(M_SMMU, 14, X_SMMU + 0x20, "ID0"), MR(M_SMMU, 14, X_SMMU + 0x24, "ID1"), MR(M_SMMU, 14, X_SMMU + 0x28, "ID2"),
    MR(M_SMMU, 15, X_SMMU + 0x00, "SCR0"), MR(M_SMMU, 15, X_SMMU + 0x48, "GFSR"), MR(M_SMMU, 15, X_SMMU + 0x3c, "ID7"),
};
#define M_NREGS (sizeof M_REGS / sizeof M_REGS[0])
#define M_LINES 16u

/* ---- The state of the model ------------------------------------------------------------------------------------------------------------------- */

static struct {
    uint32_t addr;
    uint32_t value;
    int fault;
} m_fake[128];
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
static unsigned m_s2_skipped, m_drift_seen;     /* a line `S2 SKIPPED ...` / `DRIFT ...` has been printed in this run */
static char m_first_violation[240];
static unsigned m_bloads[M_BLOCKS];
static unsigned m_win_faults;           /* a bit per block every load of which aborts */
static uint64_t m_rand_seed;            /* non-zero: an address nobody set reads a pseudo-random word */
static uint64_t m_ctr_now, m_ctr_step, m_ctr_calls, m_ctr_at_last_s1_load, m_gap_ticks;
static int m_ctr_mode, m_el, m_have_counter, m_have_load32;
static uint64_t m_hz;
static void (*m_at_wait)(void);
static unsigned char m_read_ok[M_NREGS];        /* snapshot 1 read this word without an abort */
static int m_prev_line;                         /* the line of the last snapshot-1 load, or -1 */
static unsigned m_lines_at_prev_load;
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

/* The four windows are not mapped in this process: a payload that reads or writes a device address through a pointer instead of load32 dies on a signal whose address is on the GPU's
 * side, and that is reported as what it is. Any other signal keeps its default action (and a sanitized build keeps its own report). */
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
    static const char verdict[] = "FAIL: an access reached a device window without load32\n";
    uint64_t a = (uint64_t)(uintptr_t)info->si_addr;
    (void)unused;
    if ((a >= X_GCC && a < X_GCC + 0x200000u) || (a >= X_GPU && a < X_SMMU + 0x40000u)) {
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

/* A branch clock word that proves its clock runs: enabled and not CLK_OFF; a clock with a halt check that is skipped needs only the enable, one with a hardware gating bit also passes with
 * that bit set. Anything not read, or all ones, proves nothing. */
static int x_runs(uint64_t addr, int hwcg, int nohalt)
{
    uint32_t w;
    if (!x_word(addr, &w) || !(w & 1)) return 0;
    if (nohalt) return 1;
    if (!(w >> 31)) return 1;
    return hwcg && (w >> 1 & 1);
}

#define XG(off) (X_GCC + (off))
#define XC(off) (X_GPUCC + (off))
static int x_ahb_open(void)
{
    return x_runs(XG(0x71004), 0, 0);
}

/* The harness's own verdict numbers (not the payload's): the zero is UNK, as the payload's is, so that a harness that forgets to set one closes the gate too. The masks are the seven clocks of
 * the GMU node (bit 0 ahb ... bit 6 demet) and the four of the SMMU node (hlos, bus, iface, ahb). */
enum { X_CX_UNK, X_CX_OFF, X_CX_HWCTL, X_CX_PART, X_CX_ON };
static unsigned x_clk_mask, x_sm_mask;
static unsigned x_cx(void)
{
    uint32_t gd, hw;
    int known = x_word(XC(0x9108), &gd) && x_word(XC(0x953c), &hw);
    uint32_t w;
    x_clk_mask = x_sm_mask = 0;
    x_clk_mask |= (unsigned)x_runs(XC(0x911c), 0, 0) << 0;
    x_clk_mask |= (unsigned)x_runs(XC(0x913c), 0, 0) << 1;
    x_clk_mask |= (unsigned)x_runs(XC(0x9144), 0, 0) << 2;
    x_clk_mask |= (unsigned)x_runs(XG(0x7115c), 1, 1) << 3;
    x_clk_mask |= (unsigned)x_runs(XG(0x71010), 1, 0) << 4;
    x_clk_mask |= (unsigned)x_runs(XC(0x9148), 0, 0) << 5;
    x_clk_mask |= (unsigned)x_runs(XC(0x900c), 0, 0) << 6;
    x_sm_mask |= (unsigned)x_runs(XC(0x7000), 0, 0) << 0;
    x_sm_mask |= (unsigned)x_runs(XG(0x71010), 1, 0) << 1;
    x_sm_mask |= (unsigned)x_runs(XG(0x71018), 0, 0) << 2;
    x_sm_mask |= (unsigned)x_runs(XC(0x911c), 0, 0) << 3;
    /* each of the seven clock words must also have been read (a faulted or all-ones word is unknown, not "off") */
    known = known && x_word(XC(0x911c), &w) && x_word(XC(0x913c), &w) && x_word(XC(0x9144), &w) && x_word(XG(0x7115c), &w) && x_word(XG(0x71010), &w) &&
            x_word(XC(0x9148), &w) && x_word(XC(0x900c), &w);
    if (!known) return X_CX_UNK;
    if (gd >> 1 & 1) return X_CX_HWCTL;
    if ((gd & 1) || !(hw >> 31)) return X_CX_OFF;
    return x_clk_mask == 0x7f ? X_CX_ON : X_CX_PART;
}

/* Whether the harness lets block `b` be read in the current memory (snapshot 1). */
static int x_open(unsigned b)
{
    if (b == M_GCC) return 1;
    if (!x_ahb_open()) return 0;
    if (b == M_GPUCC) return 1;
    if (x_cx() != X_CX_ON) return 0;
    return b != M_SMMU || x_sm_mask == 0xf;
}

/* Whether the harness lets the late words of block `b` be read in the current memory, which at that point is the memory after the wait: the state that opened the block must still hold
 * (CFG AHB running, CX verdict ON). */
static int x_late_open(unsigned b)
{
    (void)b;
    return x_ahb_open() && x_cx() == X_CX_ON;
}

/* ---- The runner's ops ------------------------------------------------------------------------------------------------------------------------- */

static int m_last_line_is(const char *tail)
{
    char want[80];
    snprintf(want, sizeof want, "%s%s", PREFIX, tail);
    return m_nlines && !strcmp(m_lines[m_nlines - 1], want);
}

/* The last line is `tail`, or `tail` and a note after a space (snapshot 2 says what it found in GCC on the next NEXT line). */
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
        if (addr >= X_GPU && addr < X_GX_END) m_violate("load of %#llx: a GX register (the GPU window: RBBM, CP), which no stage of S0 may read", (unsigned long long)addr);
        else m_violate("load of %#llx, a register no list names", (unsigned long long)addr);
        *out = m_fill;
        return Q1N1_PAYLOAD_LOAD_OK;
    }
    idx = m_index(r);
    m_bloads[r->block]++;
    if (m_dead >> r->block & 1) m_violate("load of %s %s after an abort in that window (a retry or a read the abort should have ended)", M_NAME[r->block], r->key);
    if (r->late != (m_phase == 3)) {
        if (r->late) m_violate("load of %s %s, a word no Linux code reads, outside the late phase (these are read last of all, under a `NEXT LATE <block>` line, after the wait and the drift report)", M_NAME[r->block], r->key);
        else m_violate("load of %s %s, a word Linux reads, in the late phase", M_NAME[r->block], r->key);
    }
    if (m_phase == 3) {
        char tail[24];
        if (!x_late_open(r->block)) m_violate("late load of %s %s behind a state the harness holds closed (after the wait the CFG AHB clock and the CX verdict must still open it)", M_NAME[r->block], r->key);
        if (!(m_started >> r->block & 1)) m_violate("late load of %s %s, a block snapshot 1 did not read", M_NAME[r->block], r->key);
        if (m_s2_skipped) m_violate("late load of %s %s after snapshot 2 was skipped: no fresh state to judge by", M_NAME[r->block], r->key);
        if (!m_drift_seen) m_violate("late load of %s %s before the drift report", M_NAME[r->block], r->key);
        snprintf(tail, sizeof tail, "NEXT LATE %s", M_NAME[r->block]);
        if (!m_last_line_is(tail)) m_violate("late load of %s %s without `%s` as the last line", M_NAME[r->block], r->key, tail);
    } else if (m_phase == 2) {
        char tail[24];
        if (r->block != M_GCC && r->block != M_GPUCC) m_violate("snapshot-2 load of %s %s: only GCC and GPUCC are read again", M_NAME[r->block], r->key);
        if (!m_read_ok[idx]) m_violate("snapshot-2 load of %s %s, a word snapshot 1 did not read", M_NAME[r->block], r->key);
        if (r->block == M_GPUCC && !x_ahb_open()) m_violate("snapshot-2 load of GPUCC %s behind a CFG AHB word that does not run", r->key);
        snprintf(tail, sizeof tail, "NEXT S2 %s", M_NAME[r->block]);
        if (!m_last_line_starts(tail)) m_violate("snapshot-2 load of %s %s without `%s` as the last line", M_NAME[r->block], r->key, tail);
    } else {
        if (!x_open(r->block)) m_violate("load of %s %s behind a closed gate", M_NAME[r->block], r->key);
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
    if (m_nevents < sizeof m_events / sizeof m_events[0]) {
        m_events[m_nevents].kind = M_LINE;
        m_events[m_nevents].addr = m_nlines;
        m_events[m_nevents++].phase = m_phase;
    }
    m_nlines++;
    if (!strncmp(text + strlen(PREFIX), "NEXT WAIT", 9)) {
        m_phase = 2;
        if (m_at_wait) m_at_wait();
    }
    if (!strncmp(text + strlen(PREFIX), "NEXT LATE ", 10)) m_phase = 3;
    if (!strncmp(text + strlen(PREFIX), "S2 SKIPPED", 10)) m_s2_skipped = 1;
    if (!strncmp(text + strlen(PREFIX), "DRIFT ", 6)) m_drift_seen = 1;
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
    /* the first read is the start of the run, the second the start of the wait: the film must have `NEXT WAIT` as its last line by then */
    if (m_ctr_calls == 2 && !m_last_line_starts("NEXT WAIT")) m_violate("the wait starts without `NEXT WAIT` as the last line");
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
    m_s2_skipped = m_drift_seen = 0;
    m_first_violation[0] = 0;
    memset(m_bloads, 0, sizeof m_bloads);
    memset(m_read_ok, 0, sizeof m_read_ok);
    m_prev_line = -1;
    m_lines_at_prev_load = 0;
    m_ctr_now = 1000000;
    m_ctr_calls = m_ctr_at_last_s1_load = m_gap_ticks = 0;
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

/* The fixtures. What the unit showed, where it showed it: nothing of the GPU side (UNKNOWN, hardware NOT RUN). Every value below is MADE UP to show what a page looks like, except the SMMU's three
 * ID words, which are the ones the apps SMMU (the same IP block, another instance) showed in boot 5 (S0b of docs/SP11-STICK-LOG.md; OBSERVED there, no statement about the GPU's). */
static void m_fx_gcc(void)
{
    m_set(m_addr("CFGA"), 0x1); m_set(m_addr("QMIP"), 0x3); m_set(m_addr("MNOC"), 0x3); m_set(m_addr("SNOC"), 0x1);
    m_set(m_addr("AXI_NW"), 0x3); m_set(m_addr("VOTE"), 0x18001); m_set(m_addr("GP0V"), 0x1);
}

/* GPUCC with the CX power domain off, as a cold unit would most likely show it: GDSC collapsed by software, the clocks off, the GX domain off. */
static void m_fx_gpucc_cold(void)
{
    m_set(m_addr("CXGD"), 0x00222001); m_set(m_addr("CXHW"), 0x0);
    m_set(m_addr("AHB"), 0x80000000); m_set(m_addr("CGMU"), 0x80000000); m_set(m_addr("CXO"), 0x80000000);
    m_set(m_addr("HUB"), 0x80000000); m_set(m_addr("DMT"), 0x80000000); m_set(m_addr("HLOS"), 0x80000000);
    m_set(m_addr("GXGD"), 0x00222001); m_set(m_addr("GXCF"), 0x8000);
    m_set(m_addr("CXOA"), 0x80000000); m_set(m_addr("HUBA"), 0x80000000); m_set(m_addr("GXGM"), 0x80000000);
    m_set(m_addr("GRC"), 0x80000000); m_set(m_addr("GRF"), 0x0); m_set(m_addr("HRC"), 0x80000000); m_set(m_addr("HRF"), 0x100);
    m_set(m_addr("XRC"), 0x80000000); m_set(m_addr("XRF"), 0x0);
}

/* The same with the CX domain on and every clock of both nodes running. */
static void m_fx_gpucc_on(void)
{
    m_fx_gpucc_cold();
    m_set(m_addr("CXGD"), 0x8022f000); m_set(m_addr("CXHW"), 0x80000000);
    m_set(m_addr("AHB"), 0x1); m_set(m_addr("CGMU"), 0x1); m_set(m_addr("CXO"), 0x1); m_set(m_addr("HUB"), 0x1); m_set(m_addr("DMT"), 0x1); m_set(m_addr("HLOS"), 0x1);
    m_set(m_addr("CXOA"), 0x1); m_set(m_addr("HUBA"), 0x1); m_set(m_addr("GRC"), 0x2);
}

static void m_fx_cx(void)
{
    m_set(m_addr("TCMR"), 0);
    m_set(m_addr("RST"), 1); m_set(m_addr("BUSY"), 0); m_set(m_addr("INIT"), 0); m_set(m_addr("CFG"), 0); m_set(m_addr("GXST"), 3); m_set(m_addr("FENS"), 0);
    m_set(m_addr("ST0"), 0); m_set(m_addr("PDCS"), 0); m_set(m_addr("BSY"), 0);
    for (unsigned i = 0; i < 10; i++) {
        char key[4];
        snprintf(key, sizeof key, "T%u", i);
        m_set(m_addr(key), 1);
    }
    m_set(m_addr("SCR0"), 0x230406); m_set(m_addr("GFSR"), 0); m_set(m_addr("ID7"), 0x21);
    m_set(m_addr("ID0"), 0x7C017E9A); m_set(m_addr("ID1"), 0x6000005F); m_set(m_addr("ID2"), 0x5222);
}

static void m_fx_cold(void)
{
    m_fx_reset();
    m_fx_gcc();
    m_fx_gpucc_cold();
    m_fx_cx();                  /* never read: the gate is closed */
}

static void m_fx_on(void)
{
    m_fx_reset();
    m_fx_gcc();
    m_fx_gpucc_on();
    m_fx_cx();
}
