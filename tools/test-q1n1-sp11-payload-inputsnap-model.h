/* SPDX-License-Identifier: MIT */
/* The model of the host test of the payload "inputsnap" (tools/test-q1n1-sp11-payload-inputsnap.c holds the suites): the payload built natively with
 * Q1N1_PAYLOAD_HOST_TEST, so that CurrentEL and CNTFRQ_EL0 come from a scripted register file, every load from a model of the five windows and the counter from a model
 * of the runner's. Built with INPUTSNAP_SRC pointing at a seeded-bug copy of the payload, it is how the mutants are shown to be refused.
 *
 * The model fails the run on anything the payload must never do: a load that is not 4-byte aligned, past the ABI's 4096, outside the five windows, at an offset the
 * harness's OWN list (written from the design note, not from the payload's table) does not name, in the FIFO window of an engine, at a pin the design excludes, in a
 * window after an abort in it (in GCC: in its group of words; so no retry either), the same register twice in one snapshot, a 64-bit register read other than as low then
 * high word, an engine window read while the model's OWN reading of that snapshot's clock words does not say all of the engine's clocks run (a word that aborted, was not
 * read or is stopped counts as stopped), a new block's first load whose NEXT line is not the last line printed, a load of an earlier block after a later one, a
 * snapshot-2 load of a register the harness's snapshot-2 list does not name or not under its `NEXT S2 <window>` line, a system register other than CurrentEL and
 * CNTFRQ_EL0, more lines than the ABI or the payload's cap, a line of more than 100 characters or outside the page font, a missing end line, a counter read more than
 * five million times (an unbounded wait), and any access that reaches a device window other than through load32 (the five windows are unmapped here, so a payload that
 * dereferences one dies on a signal that the harness turns into that verdict). Nothing here ran on hardware. Evidence: EXPERIMENTAL (host model only). */
#pragma once
#define _GNU_SOURCE
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef INPUTSNAP_SRC
#define INPUTSNAP_SRC "../payloads/inputsnap.c"
#endif
#include INPUTSNAP_SRC

#pragma clang diagnostic ignored "-Wunused-function"     /* a capped build runs only the cap suite, the shipped one all the others */

/* ---- The model ----------------------------------------------------------------------------------------------------------------------------- */

enum { M_GCC, M_GIC, M_U2, M_S10, M_TLMM, M_WINDOWS };
static const uint64_t M_BASE[M_WINDOWS] = {0x00100000u, 0x17000000u, 0x00b88000u, 0x00a88000u, 0x0f100000u};
static const uint32_t M_SIZE[M_WINDOWS] = {0x200000u, 0x10000u, 0x1000u, 0x1000u, 0xf00000u};
static const char M_NAME[M_WINDOWS][5] = {"GCC", "GIC", "U2", "S10", "TLMM"};
enum { M_LOAD, M_LINE };

static struct {
    uint64_t addr;
    uint32_t value;
    int fault;
    unsigned hits;
} m_fake[1024];
static unsigned m_nfake;
static uint32_t m_fill;
static int m_fill_all;                  /* every address the model is asked about reads m_fill (hostile runs) */
static struct {
    int kind;
    uint64_t addr;
    unsigned win, phase;
    uint32_t value;
    int fault;
} m_events[16384];
static unsigned m_nevents;
static char m_lines[128][220];
static unsigned m_line_loads[128];      /* the loads made when each line was printed */
static unsigned m_nlines, m_nloads, m_nfaults, m_violations, m_dead, m_gcc_dead, m_phase, m_rank, m_xrank, m_p2_gcc, m_sysreg_reads, m_checks, m_fails;
static char m_first_violation[240];
static unsigned m_wloads[M_WINDOWS];
static unsigned m_win_faults;           /* a bit per window every load of which aborts */
static uint64_t m_rand_seed;            /* non-zero: an address nobody set reads a pseudo-random word */
static uint64_t m_ctr_now, m_ctr_step, m_ctr_calls, m_ctr_at_last_s1_load, m_gap_ticks, m_ctr_every;
static int m_ctr_mode, m_el, m_have_counter, m_have_load32;
static uint64_t m_hz;
static void (*m_at_wait)(void);
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
    static unsigned dumps;
    if (dumps++) return;                /* the first failure's page is enough to read; the FAIL lines say the rest */
    fprintf(f, "  page (%u lines, %u loads):\n", m_nlines, m_nloads);
    for (unsigned i = 0; i < m_nlines; i++) fprintf(f, "  %2u %s\n", i, m_lines[i]);
}

#define CHECK(cond) do { m_checks++; if (!(cond)) { m_fails++; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); m_dump(stderr); } } while (0)

static int m_has(const char *text)
{
    for (unsigned i = 0; i < m_nlines; i++) if (strstr(m_lines[i], text)) return 1;
    return 0;
}

static unsigned m_win_of(uint64_t addr)
{
    for (unsigned w = 0; w < M_WINDOWS; w++) if (addr >= M_BASE[w] && addr - M_BASE[w] < M_SIZE[w]) return w;
    return M_WINDOWS;
}

/* The five windows are not mapped in this process: a payload that reads or writes one through a pointer instead of load32 dies on a signal whose address is in a
 * window, and that is reported as what it is. Any other signal keeps its default action (and a sanitized build keeps its own report). */
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
    unsigned w = m_win_of((uint64_t)(uintptr_t)info->si_addr);
    (void)unused;
    if (w < M_WINDOWS) {
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

/* The harness's own list of what may be read: window mask, snapshot 2 reads it again, 64-bit, GCC group, offset, key as the page prints it. Written from the design of this
 * payload and the registers of docs/SP11-PAYLOAD-INPUTSNAP-REGISTERS.md, not from the payload's table; a pin is two rows (CFG, IN_OUT). */
#define W(w) (1u << (w))
#define M_ENG (W(M_U2) | W(M_S10))
#define M_PIN(n, s2) {W(M_TLMM), 0, 0, 0, (n) * 0x1000u, "F" #n}, {W(M_TLMM), s2, 0, 0, (n) * 0x1000u + 4u, "L" #n}
struct m_reg {
    unsigned wins;
    unsigned s2, wide, group;
    uint32_t off;
    const char *key;
};
static const struct m_reg M_REGS[] = {
    {W(M_GCC), 1, 0, 0, 0x23000, "MA0"}, {W(M_GCC), 1, 0, 0, 0x23004, "SA0"}, {W(M_GCC), 1, 0, 0, 0x23008, "CR0"}, {W(M_GCC), 1, 0, 0, 0x42274, "SE0"},
    {W(M_GCC), 1, 0, 0, 0x23018, "C20"}, {W(M_GCC), 1, 0, 1, 0x23150, "MA1"}, {W(M_GCC), 1, 0, 1, 0x23154, "SA1"}, {W(M_GCC), 1, 0, 1, 0x23158, "CR1"},
    {W(M_GCC), 1, 0, 1, 0x18274, "SE1"}, {W(M_GCC), 1, 0, 1, 0x18280, "QS1"}, {W(M_GCC), 1, 0, 1, 0x23168, "C21"}, {W(M_GCC), 0, 0, 2, 0x52020, "VT0"},
    {W(M_GCC), 0, 0, 2, 0x52008, "VT1"}, {W(M_GCC), 0, 0, 2, 0x52028, "VT2"},
    {W(M_GIC), 0, 0, 0, 0x000, "CTL"}, {W(M_GIC), 0, 0, 0, 0x004, "TYP"},
    {W(M_GIC), 0, 0, 0, 0x11c, "E240"}, {W(M_GIC), 0, 0, 0, 0x21c, "P240"}, {W(M_GIC), 0, 0, 0, 0x09c, "G240"}, {W(M_GIC), 0, 0, 0, 0xc3c, "C240"},
    {W(M_GIC), 0, 1, 0, 0x6780, "R240"},
    {W(M_GIC), 0, 0, 0, 0x14c, "E616"}, {W(M_GIC), 0, 0, 0, 0x24c, "P616"}, {W(M_GIC), 0, 0, 0, 0x0cc, "G616"}, {W(M_GIC), 0, 0, 0, 0xc98, "C616"},
    {W(M_GIC), 0, 1, 0, 0x7340, "R616"},
    {W(M_GIC), 0, 0, 0, 0x168, "E834"}, {W(M_GIC), 0, 0, 0, 0x268, "P834"}, {W(M_GIC), 0, 0, 0, 0x0e8, "G834"}, {W(M_GIC), 0, 0, 0, 0xcd0, "C834"},
    {W(M_GIC), 0, 1, 0, 0x7a10, "R834"},
    {M_ENG, 0, 0, 0, 0x068, "FW"}, {M_ENG, 0, 0, 0, 0x064, "IFD"}, {M_ENG, 0, 0, 0, 0x040, "ST"}, {M_ENG, 0, 0, 0, 0x258, "DMA"}, {M_ENG, 0, 0, 0, 0xe20, "DIF"},
    {M_ENG, 0, 0, 0, 0xe24, "HW0"}, {M_ENG, 0, 0, 0, 0xe28, "HW1"}, {M_ENG, 0, 0, 0, 0x048, "CM"}, {M_ENG, 0, 0, 0, 0x04c, "CS"}, {M_ENG, 0, 0, 0, 0x07c, "CK"},
    {M_ENG, 0, 0, 0, 0x060, "CC"}, {W(M_U2), 0, 0, 0, 0x240, "IOM"}, {W(M_U2), 0, 0, 0, 0x25c, "TCF"}, {W(M_U2), 0, 0, 0, 0x268, "TWL"},
    {W(M_U2), 0, 0, 0, 0x26c, "TSB"}, {W(M_U2), 0, 0, 0, 0x280, "RCF"}, {W(M_U2), 0, 0, 0, 0x28c, "RWL"}, {W(M_U2), 0, 0, 0, 0x294, "STL"},
    {W(M_U2), 0, 0, 0, 0x2a4, "TPA"}, {W(M_U2), 0, 0, 0, 0x2a8, "RPA"}, {W(M_U2), 0, 0, 0, 0x2ac, "MRF"}, {W(M_U2), 0, 0, 0, 0x80c, "TWM"},
    {W(M_U2), 0, 0, 0, 0x810, "RWM"}, {W(M_U2), 0, 0, 0, 0x814, "RFW"},
    {M_ENG, 0, 0, 0, 0x800, "TXF"}, {M_ENG, 0, 0, 0, 0x804, "RXF"}, {M_ENG, 0, 0, 0, 0x610, "MIS"}, {M_ENG, 0, 0, 0, 0x614, "MIE"},
    {M_ENG, 0, 0, 0, 0x640, "SIS"}, {M_ENG, 0, 0, 0, 0x644, "SIE"}, {M_ENG, 0, 0, 0, 0x908, "IOS"},
    M_PIN(8, 0), M_PIN(9, 0), M_PIN(10, 0), M_PIN(11, 0), M_PIN(40, 0), M_PIN(41, 0), M_PIN(42, 0), M_PIN(43, 0), M_PIN(2, 0), M_PIN(48, 0), M_PIN(51, 1),
    M_PIN(64, 0), M_PIN(91, 1),
    {W(M_TLMM), 0, 0, 0, 0x33008, "N51"}, {W(M_TLMM), 0, 0, 0, 0x3300c, "S51"}, {W(M_TLMM), 0, 0, 0, 0x5b008, "N91"}, {W(M_TLMM), 0, 0, 0, 0x5b00c, "S91"},
};
#define M_NREGS (sizeof M_REGS / sizeof M_REGS[0])
/* The registers no Linux driver reads, by the harness's own list (from the pinned drivers: the table of what Linux reads in docs/SP11-PAYLOAD-INPUTSNAP-REGISTERS.md): read once, after snapshot
 * 2 and its drift report, and nothing else is read then. IFD is not among them (the SPI driver reads it), nor are the votes (clk_is_enabled_regmap reads them). */
static const char *const M_FRESH[] = {"CM", "CS", "CK", "CC", "TWL", "TSB", "RWL", "STL", "MRF", "TWM", "RWM", "RFW", "DIF", "G616", "R616", "G834", "R834", "G240", "R240"};
static int m_fresh(const struct m_reg *r)
{
    for (unsigned i = 0; i < sizeof M_FRESH / sizeof M_FRESH[0]; i++) if (!strcmp(M_FRESH[i], r->key)) return 1;
    return 0;
}
/* The first load of each block of snapshot 1, a register of its kind that Linux reads: a clock word (MA0, clk-branch.c), GICD_CTLR, the firmware revision word of an engine, the CFG word
 * of a pin. */
static const uint32_t M_START[M_WINDOWS] = {0x23000, 0x000, 0x068, 0x068, 0x8000};
/* The engine registers snapshot 2 reads again: STATUS, the two FIFO status words, the two IRQ status words and IOS, of the UART engine only. */
static const uint32_t M_U2_S2[] = {0x040, 0x800, 0x804, 0x610, 0x640, 0x908};

/* A snapshot's clock words that every engine read needs, by the harness's own list (the AHB pair, the core clock and the engine's own clock; for SPI also QSPI). The
 * four AHB clocks are the ones that declare a hardware clock gating bit (gcc-x1e80100.c: .hwcg_bit = 1). */
static const uint32_t M_GATE_U2[] = {0x23000, 0x23004, 0x23008, 0x42274};
static const uint32_t M_GATE_S10[] = {0x23150, 0x23154, 0x23158, 0x18274, 0x18280};
static const uint32_t M_HWCG[] = {0x23000, 0x23004, 0x23150, 0x23154};

static int m_in_hwcg(uint32_t off)
{
    for (unsigned i = 0; i < sizeof M_HWCG / sizeof M_HWCG[0]; i++) if (M_HWCG[i] == off) return 1;
    return 0;
}

/* The harness's own reading of a branch clock word: stopped when CLK_OFF (bit 31) is set and the NoC FSM (bits 30:28 = 2) does not say otherwise, and for a clock with
 * a hardware gating bit also when HW_CTL (bit 1) is clear; or when the word is all ones. */
static int m_stopped(uint32_t v, int hwcg)
{
    return v == 0xffffffffu || ((v >> 31) && !(hwcg && ((v >> 1) & 1)) && ((v >> 28) & 7) != 2);
}

/* The register of a window at an offset (the high word of a 64-bit one counts, `hi` says so), or NULL. */
static const struct m_reg *m_reg_of(unsigned w, uint32_t off, unsigned *hi)
{
    *hi = 0;
    for (unsigned i = 0; i < M_NREGS; i++) {
        if (!(M_REGS[i].wins & W(w))) continue;
        if (M_REGS[i].off == off) return &M_REGS[i];
        if (M_REGS[i].wide && M_REGS[i].off + 4 == off) {
            *hi = 1;
            return &M_REGS[i];
        }
    }
    return NULL;
}

/* A snapshot-2 register: the flagged rows of the table; of the engine words only the UART engine's. */
static int m_in_s2(unsigned w, const struct m_reg *r)
{
    if (w == M_U2) {
        for (unsigned i = 0; i < sizeof M_U2_S2 / sizeof M_U2_S2[0]; i++) if (M_U2_S2[i] == r->off) return 1;
        return 0;
    }
    return w != M_S10 && r->s2;
}

/* What no list may ever allow, whatever the table says: the receive and transmit FIFO windows of an engine (a read of the receive FIFO pops bytes), the TPM's pins
 * 44-47 (reserved in x1-microsoft-denali.dtsi:1198) and gpio238, and anything of the pin controller past gpio91's registers. */
static int m_forbidden(unsigned w, uint32_t off)
{
    if (w == M_U2 || w == M_S10) return (off >= 0x700 && off < 0x740) || (off >= 0x780 && off < 0x7c0);
    if (w == M_TLMM) {
        unsigned pin = off / 0x1000u;
        return (pin >= 44 && pin <= 47) || pin >= 238;
    }
    return 0;
}

/* The group of GCC words whose abort ends the reads of the others of the group, or the window's own bit. */
static unsigned m_dead_bit(unsigned w, uint32_t off)
{
    unsigned hi;
    const struct m_reg *r = m_reg_of(w, off, &hi);
    return w == M_GCC ? (r ? r->group : 3u) : w;
}

static int m_is_dead(unsigned w, uint32_t off)
{
    return w == M_GCC ? (int)(m_gcc_dead >> m_dead_bit(w, off) & 1) : (int)(m_dead >> w & 1);
}

static void m_set_dead(unsigned w, uint32_t off)
{
    if (w == M_GCC) m_gcc_dead |= 1u << m_dead_bit(w, off);
    else m_dead |= 1u << w;
}

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

/* The harness's own verdict on an engine's clocks in this snapshot: every one of its clock words was loaded in this snapshot, did not abort and is not stopped. In the late
 * blocks, the snapshot is the freshest one that read clock words: snapshot 2 if it loaded any, else snapshot 1. Returns 1, or 0 with `why` saying which word and what was wrong
 * with it. */
static int m_gate_ok(unsigned w, char *why, size_t size)
{
    const uint32_t *list = w == M_U2 ? M_GATE_U2 : M_GATE_S10;
    unsigned n = w == M_U2 ? 4 : 5, phase = m_phase == 3 ? (m_p2_gcc ? 2u : 1u) : m_phase;
    for (unsigned i = 0; i < n; i++) {
        int found = 0;
        for (unsigned e = 0; e < m_nevents; e++) {
            if (m_events[e].kind != M_LOAD || m_events[e].win != M_GCC || m_events[e].phase != phase || m_events[e].addr != M_BASE[M_GCC] + list[i]) continue;
            found = 1;
            if (m_events[e].fault) {
                snprintf(why, size, "the clock word GCC+%#x of the engine aborted", list[i]);
                return 0;
            }
            if (m_stopped(m_events[e].value, m_in_hwcg(list[i]))) {
                snprintf(why, size, "the clock word GCC+%#x of the engine is stopped (%#x)", list[i], m_events[e].value);
                return 0;
            }
        }
        if (!found) {
            snprintf(why, size, "the clock word GCC+%#x of the engine was not read in this snapshot", list[i]);
            return 0;
        }
    }
    return 1;
}

static const char M_BLOCK[6][5] = {"", "GCC", "GIC", "U2", "S10", "TLMM"};

static int32_t m_load32(uint64_t addr, uint32_t *out)
{
    unsigned w = m_win_of(addr), hi = 0;
    uint32_t off, value = 0;
    int fault = 0, found = 0;
    const struct m_reg *r;
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
    if (w == M_WINDOWS) {
        m_violate("load of %#llx is outside the five windows", (unsigned long long)addr);
        return Q1N1_PAYLOAD_LOAD_OK;
    }
    off = (uint32_t)(addr - M_BASE[w]);
    m_wloads[w]++;
    if (m_forbidden(w, off)) m_violate("load of %s+%#x, a register the design forbids (a FIFO window, pins 44-47, gpio238)", M_NAME[w], off);
    if (m_is_dead(w, off)) m_violate("load of %s+%#x after an abort in that window (a retry or a read the abort should have ended)", M_NAME[w], off);
    r = m_reg_of(w, off, &hi);
    if (!r) m_violate("load of %s+%#x, a register no list names", M_NAME[w], off);
    if (r && m_phase == 2 && !m_in_s2(w, r)) m_violate("snapshot-2 load of %s+%#x, a register the snapshot-2 list does not name", M_NAME[w], off);
    if (r && m_phase == 3 && !m_fresh(r)) m_violate("late-block load of %s+%#x, a register Linux reads: it belongs to snapshot 1 or 2", M_NAME[w], off);
    if (r && m_phase != 3 && m_fresh(r)) m_violate("snapshot-%u load of %s+%#x, a register no Linux driver reads: it is read after snapshot 2 and its drift report only", m_phase, M_NAME[w], off);
    for (unsigned e = 0; e < m_nevents; e++) {
        if (m_events[e].kind == M_LOAD && m_events[e].addr == addr && m_events[e].phase == m_phase) m_violate("%s+%#x read twice in one snapshot", M_NAME[w], off);
    }
    if (hi && !(m_nevents && m_events[m_nevents - 1].kind == M_LOAD && m_events[m_nevents - 1].addr == addr - 4 && !m_events[m_nevents - 1].fault))
        m_violate("the high word %s+%#x of a 64-bit register is not read right after its low word", M_NAME[w], off);
    if (m_phase == 2 && w == M_GCC) m_p2_gcc++;
    if (w == M_U2 || w == M_S10) {
        char why[120];
        if (!m_gate_ok(w, why, sizeof why)) m_violate("load of %s+%#x while %s", M_NAME[w], off, why);
    }
    if (m_phase == 3) {
        unsigned xrank = w == M_U2 ? 1 : w == M_S10 ? 2 : w == M_GIC ? 3 : 0;
        if (!xrank) {
            m_violate("late-block load of %s+%#x: no late block has this window", M_NAME[w], off);
        } else {
            if (xrank < m_xrank) m_violate("late-block load of %s+%#x after a later late block", M_NAME[w], off);
            if (xrank > m_xrank) {
                char tail[24];
                m_xrank = xrank;
                snprintf(tail, sizeof tail, "NEXT X %s", M_NAME[w]);
                if (!m_last_line_is(tail)) m_violate("late-block load of %s+%#x without `%s` as the last line", M_NAME[w], off, tail);
            }
        }
    } else if (m_phase == 2) {
        char tail[24];
        snprintf(tail, sizeof tail, "NEXT S2 %s", M_NAME[w]);
        if (!m_last_line_starts(tail)) m_violate("snapshot-2 load of %s+%#x without `%s` as the last line", M_NAME[w], off, tail);
    } else {
        unsigned rank = w + 1;
        if (rank < m_rank) m_violate("load of %s+%#x (block %s) after a later block", M_NAME[w], off, M_BLOCK[rank]);
        if (rank > m_rank) {
            char tail[24];
            m_rank = rank;
            snprintf(tail, sizeof tail, "NEXT %s", M_BLOCK[rank]);
            if (!m_last_line_is(tail)) m_violate("load of %s+%#x (block %s) without `%s` as the last line", M_NAME[w], off, M_BLOCK[rank], tail);
            if (off != M_START[w]) m_violate("the first load of block %s is %s+%#x, not %#x, the register of its kind that Linux reads and the design starts it with", M_BLOCK[rank], M_NAME[w], off, M_START[w]);
        }
        m_ctr_at_last_s1_load = m_ctr_now;
    }
    if (m_phase == 2 && !m_gap_ticks) m_gap_ticks = m_ctr_now - m_ctr_at_last_s1_load;
    if (m_win_faults & (1u << w)) {
        fault = 1;
    } else {
        for (unsigned i = 0; i < m_nfake && !m_fill_all && !found; i++) {
            if (m_fake[i].addr != addr) continue;
            m_fake[i].hits++;
            found = 1;
            fault = m_fake[i].fault;
            value = m_fake[i].value;
        }
        if (!found && m_rand_seed) {
            uint64_t x = (addr ^ m_rand_seed) * UINT64_C(0x9E3779B97F4A7C15);
            x ^= x >> 29;
            x *= UINT64_C(0xBF58476D1CE4E5B9);
            value = (uint32_t)(x >> 16) & ((x & 1) ? 0xffffffffu : 0x000000ffu);     /* half of the words are small */
        } else if (!found) {
            value = m_fill;
        }
    }
    if (m_nevents < sizeof m_events / sizeof m_events[0]) {
        m_events[m_nevents].kind = M_LOAD;
        m_events[m_nevents].addr = addr;
        m_events[m_nevents].win = w;
        m_events[m_nevents].phase = m_phase;
        m_events[m_nevents].value = fault ? 0 : value;
        m_events[m_nevents++].fault = fault;
    }
    if (fault) {
        m_nfaults++;
        m_set_dead(w, off);
        return Q1N1_PAYLOAD_LOAD_E_FAULT;
    }
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
    m_line_loads[m_nlines] = m_nloads;
    if (m_nevents < sizeof m_events / sizeof m_events[0]) {
        m_events[m_nevents].kind = M_LINE;
        m_events[m_nevents].addr = m_nlines;
        m_events[m_nevents++].phase = m_phase;
    }
    m_nlines++;
    if (!strncmp(text + strlen(PREFIX), "NEXT WAIT", 9)) {
        m_phase = 2;
        if (m_at_wait) m_at_wait();
    } else if (!strncmp(text + strlen(PREFIX), "NEXT X ", 7)) {
        m_phase = 3;
    }
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

/* The counter of the model. C_RUN advances it by `m_ctr_step` on every read, or, when `m_ctr_every` is more than one, once in that many reads (a counter that runs far too slowly
 * for the frequency the system register states, which is what the spin bound is for). The guard below is only the harness's own: no run of the payload may need more reads of
 * the counter than a wait of 8 s at 1 MHz on a counter that advances once per read. */
#define M_CTR_READS_MAX 20000000u
static uint64_t m_counter(void)
{
    if (++m_ctr_calls > M_CTR_READS_MAX) {
        fprintf(stderr, "FAIL: the counter was read %llu times: an unbounded wait\n", (unsigned long long)m_ctr_calls);
        exit(1);
    }
    if (m_ctr_mode == C_RUN && (m_ctr_every <= 1 || m_ctr_calls % m_ctr_every == 0)) m_ctr_now += m_ctr_step;
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

static void m_fset(unsigned w, uint64_t off, uint32_t value)
{
    uint64_t addr = M_BASE[w] + off;
    for (unsigned i = 0; i < m_nfake; i++) {
        if (m_fake[i].addr == addr) {
            m_fake[i].value = value;
            m_fake[i].fault = 0;
            return;
        }
    }
    m_fake[m_nfake].addr = addr;
    m_fake[m_nfake].value = value;
    m_fake[m_nfake].fault = 0;
    m_fake[m_nfake++].hits = 0;
}

static void m_fset64(unsigned w, uint64_t off, uint64_t value)
{
    m_fset(w, off, (uint32_t)value);
    m_fset(w, off + 4, (uint32_t)(value >> 32));
}

static void m_ffault(unsigned w, uint64_t off)
{
    m_fset(w, off, 0);
    for (unsigned i = 0; i < m_nfake; i++) if (m_fake[i].addr == M_BASE[w] + off) m_fake[i].fault = 1;
}

/* ---- The fixtures --------------------------------------------------------------------------------------------------------------------------- */

static void m_reset_run(void)
{
    m_nlines = m_nloads = m_nfaults = m_violations = m_dead = m_gcc_dead = m_rank = m_xrank = m_p2_gcc = m_sysreg_reads = m_nevents = 0;
    m_phase = 1;
    m_first_violation[0] = 0;
    memset(m_wloads, 0, sizeof m_wloads);
    m_ctr_now = 1000000;
    m_ctr_calls = m_ctr_at_last_s1_load = m_gap_ticks = 0;
    for (unsigned i = 0; i < m_nfake; i++) m_fake[i].hits = 0;
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
    m_ctr_every = 1;
    m_have_counter = m_have_load32 = 1;
    m_at_wait = NULL;
    m_reset_run();
}

/* A UART engine and a SPI engine that firmware left clocked and configured, and the words around them. Only GICD_CTLR is OBSERVED (0x10 in boots 3, 12 and 14 of
 * docs/SP11-STICK-LOG.md); every other value is made up to show what a page looks like, so that a reader can tell the decodes apart: C21 is the one stopped clock that
 * gates nothing, PR is 2 on the UART engine and 9 on the SPI one, the pending bit of INTID 616 is set, the receive FIFO and gpio91 differ between the two snapshots only
 * when a test makes them. */
static void m_fx_engine(unsigned w, uint32_t proto)
{
    m_fset(w, 0x068, 0x00000030 | proto << 8);
    m_fset(w, 0x064, 0);
    m_fset(w, 0x040, 0);
    m_fset(w, 0x258, 0);
    m_fset(w, 0xe20, 0x1);
    m_fset(w, 0xe24, 0x0a80e0d4);
    m_fset(w, 0xe28, 0x00000b02);
    m_fset(w, 0x048, 0x10);
    m_fset(w, 0x04c, 0x0);
    m_fset(w, 0x07c, 0x0);
    m_fset(w, 0x060, 0x3);
    m_fset(w, 0x800, 0);
    m_fset(w, 0x804, 0);
    m_fset(w, 0x610, 0);
    m_fset(w, 0x614, 0);
    m_fset(w, 0x640, 0);
    m_fset(w, 0x644, 0);
    m_fset(w, 0x908, 0x2);
}

static void m_fx_unit(void)
{
    static const uint32_t cbcr_on[] = {0x23000, 0x23004, 0x23008, 0x23018, 0x42274, 0x23150, 0x23154, 0x23158, 0x18274, 0x18280};
    static const uint32_t u2[][2] = {{0x240, 0x1ff}, {0x25c, 0x7}, {0x268, 0x8}, {0x26c, 0x20}, {0x280, 0x7}, {0x28c, 0x8}, {0x294, 0x18}, {0x2a4, 0}, {0x2a8, 0},
                                     {0x2ac, 0}, {0x80c, 0x4}, {0x810, 0x20}, {0x814, 0x20}};
    static const unsigned pins[] = {8, 9, 10, 11, 40, 41, 42, 43, 2, 48, 51, 64, 91};
    m_fx_reset();
    for (unsigned i = 0; i < sizeof cbcr_on / sizeof cbcr_on[0]; i++) m_fset(M_GCC, cbcr_on[i], 0x1);
    m_fset(M_GCC, 0x23168, 0x80000000);
    m_fset(M_GCC, 0x52020, 0x10c0);
    m_fset(M_GCC, 0x52008, 0x1380000);
    m_fset(M_GCC, 0x52028, 0x10);
    m_fset(M_GIC, 0x000, 0x10);
    m_fset(M_GIC, 0x004, 0x07790f1f);
    m_fset(M_GIC, 0x11c, 0x10000); m_fset(M_GIC, 0x21c, 0); m_fset(M_GIC, 0x09c, 0x10000); m_fset(M_GIC, 0xc3c, 0x2); m_fset64(M_GIC, 0x6780, 0);
    m_fset(M_GIC, 0x14c, 0); m_fset(M_GIC, 0x24c, 0x100); m_fset(M_GIC, 0x0cc, 0x100); m_fset(M_GIC, 0xc98, 0x20000); m_fset64(M_GIC, 0x7340, 0x100);
    m_fset(M_GIC, 0x168, 0); m_fset(M_GIC, 0x268, 0); m_fset(M_GIC, 0x0e8, 0x4); m_fset(M_GIC, 0xcd0, 0x20); m_fset64(M_GIC, 0x7a10, 0x80000000);
    m_fx_engine(M_U2, 2);
    m_fx_engine(M_S10, 9);
    for (unsigned i = 0; i < sizeof u2 / sizeof u2[0]; i++) m_fset(M_U2, u2[i][0], u2[i][1]);
    for (unsigned i = 0; i < sizeof pins / sizeof pins[0]; i++) {
        m_fset(M_TLMM, pins[i] * 0x1000u, pins[i] == 8 || pins[i] == 9 || pins[i] == 10 || pins[i] == 11 ? 0x4 : pins[i] >= 40 && pins[i] <= 43 ? 0x8 : 0x1);
        m_fset(M_TLMM, pins[i] * 0x1000u + 4, i & 1);
    }
    m_fset(M_TLMM, 0x33008, 0x5);
    m_fset(M_TLMM, 0x3300c, 0);
    m_fset(M_TLMM, 0x5b008, 0x5);
    m_fset(M_TLMM, 0x5b00c, 0);
}

/* One run of the payload against the current model. */
static uint64_t m_go(void)
{
    struct q1n1_payload_args a = m_args();
    m_reset_run();
    return payload_entry(&a);
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
        else if (faults != m_nfaults) why = "the end line's FAULTS is not the aborts the model returned";
    }
    /* A 64-bit register whose low word was read must have its high word read next (unless the low word aborted). */
    for (unsigned e = 0; !why && e < m_nevents; e++) {
        unsigned hi;
        const struct m_reg *r;
        if (m_events[e].kind != M_LOAD || m_events[e].fault) continue;
        r = m_reg_of(m_events[e].win, (uint32_t)(m_events[e].addr - M_BASE[m_events[e].win]), &hi);
        if (r && r->wide && !hi && !(e + 1 < m_nevents && m_events[e + 1].kind == M_LOAD && m_events[e + 1].addr == m_events[e].addr + 4))
            why = "the low word of a 64-bit register was read and its high word was not read next";
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

static unsigned m_loads_of(unsigned w, uint64_t off, unsigned phase)
{
    unsigned n = 0;
    for (unsigned i = 0; i < m_nevents; i++) if (m_events[i].kind == M_LOAD && m_events[i].addr == M_BASE[w] + off && m_events[i].phase == phase) n++;
    return n;
}

static unsigned m_window_loads(unsigned w, unsigned phase)
{
    unsigned n = 0;
    for (unsigned i = 0; i < m_nevents; i++) if (m_events[i].kind == M_LOAD && m_events[i].win == w && m_events[i].phase == phase) n++;
    return n;
}
