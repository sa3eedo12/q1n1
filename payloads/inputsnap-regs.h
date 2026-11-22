/* SPDX-License-Identifier: MIT */
/* Registers, budgets and the read table of the payload "inputsnap" (payloads/inputsnap.c; docs/SP11-PAYLOAD-INPUTSNAP-REGISTERS.md has the file:line of every row, the evidence
 * labels and what the page says). Definitions only. Evidence: VERIFIED is a pinned file (gcc-x1e80100.c, clk-branch.h, hamoa.dtsi, x1-microsoft-denali.dtsi of the Snapintosh
 * refs, and geni-se.h, qcom_geni_serial.c, arm-gic-v3.h, pinctrl-x1e80100.c, pinctrl-msm.c fetched at the same Linux revision by the note that designed this payload),
 * OBSERVED is a table of the unit's own ACPI dump. Nothing here was ever read on the unit by this payload (EXPERIMENTAL).
 * The table holds no pointer: a pointer in .rodata would need a load-address relocation, which the payload's link check refuses. Every table has a power-of-two row
 * size, so that indexing it is a shift and the binary check of tools/sp11_payload_memcheck.py can follow it. */
#pragma once
#include <stdint.h>

/* Budgets. The ABI allows 40 lines and 4096 loads per call; this payload keeps to 34 lines so that it can run in front of a 40-line payload (the xHCI ones: 3 + 6 runner
 * lines + 34 + 40 = 83 of the unit's 89 rows). The host test builds with smaller caps too, to see what happens when they run out. */
#if !defined(INPUTSNAP_LINE_CAP) && !defined(INPUTSNAP_LOAD_CAP) && !defined(INPUTSNAP_SPIN_MAX)
#define INPUTSNAP_SHIPPED_CAPS 1
#endif
#ifndef INPUTSNAP_LINE_CAP
#define INPUTSNAP_LINE_CAP 34u
#endif
#ifndef INPUTSNAP_LOAD_CAP
#define INPUTSNAP_LOAD_CAP 400u
#endif
#ifndef INPUTSNAP_SPIN_MAX
#define INPUTSNAP_SPIN_MAX 0xffffffffu
#endif
#define LINE_CAP INPUTSNAP_LINE_CAP
#define LOAD_CAP INPUTSNAP_LOAD_CAP
/* Reads of the counter the wait may make. The wait ends on the counter, never on this: the 8 s it waits for take, at the few nanoseconds one pass of the loop needs
 * (an indirect call and a system register read), a few hundred million passes, so the bound is a wide margin above the need and only a counter that moves, but far
 * too slowly for its own frequency, reaches it; a dead counter ends the wait first (COUNTER_STUCK_READS, or a counter that runs backwards). The two end differently on the page. */
#define SPIN_MAX INPUTSNAP_SPIN_MAX
/* Lines the lines before keep free: the ordinary lines of the snapshots keep the drift summary and the end line, the lines of the late block (X) the end line. */
#define CLOSING_LINES 2u                /* the drift summary and the end line are never crowded out by the lines before them */
#define KEEP_DATA CLOSING_LINES
#define KEEP_X 1u
#define KEEP_NONE 0u
#define GAP_S 8u                        /* the one wait, between the two snapshots */
#define COUNTER_HZ_DEFAULT 19200000u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u
#define COUNTER_STUCK_READS 2000000u
#define LINE_FILL (Q1N1_PAYLOAD_LINE_MAX - 5u)  /* a packed line stops five characters short of the ABI's 100, as the other snapshot payloads' do */

/* The only device addresses this payload reads: the clock controller (reg of gcc, hamoa.dtsi:758-760), the GIC distributor (intc reg, hamoa.dtsi:8560), the first 4 KiB of
 * the 16 KiB windows of QUP wrapper 0 engine 2 (uart2, hamoa.dtsi:2337-2340: the Surface Aggregator link) and of QUP wrapper 1 engine 2 (spi10, hamoa.dtsi:1688-1691: the
 * touch controller's SPI engine; the unit's ACPI gives both bases and the same lengths, OBSERVED) and the pin controller (tlmm reg, hamoa.dtsi:6119-6121). Every GENI
 * register this payload reads is in the first page (the highest is SE_HW_PARAM_1 at 0xe28). */
enum { WIN_GCC, WIN_GIC, WIN_U2, WIN_S10, WIN_TLMM, WINDOWS };
static const struct {
    uint64_t base;
    uint32_t size, pad;
} windows[WINDOWS] = {{0x00100000u, 0x200000u, 0}, {0x17000000u, 0x10000u, 0}, {0x00b88000u, 0x1000u, 0}, {0x00a88000u, 0x1000u, 0}, {0x0f100000u, 0xf00000u, 0}};
static const char window_name[WINDOWS][8] = {"GCC", "GIC", "U2", "S10", "TLMM"};
_Static_assert(sizeof windows[0] == 16, "inputsnap: a window row is 16 bytes");

/* Blocks in page order. Snapshot 1 reads the registers Linux itself reads (a read precedent in a pinned file: the table's F_FRESH flag is clear), the clock words every engine
 * read depends on first (a block reads nothing it has not been read for yet, so every block is announced: the page ends on the NEXT line of what hung), then the GIC, the two
 * engines (each only if its own clock words read ON), the pin controller last: nobody has read it on this unit and which pins are the secure world's is UNKNOWN. What no
 * Linux driver reads (the F_FRESH rows: serial clock and frame configuration, watermarks, IGROUPR, IROUTER, two read-only status words) is read once, AFTER snapshot 2 and
 * its drift report, in the three late blocks X U2, X S10 and X GIC, each under its own NEXT line, so that a hang on a word nobody has read through Linux can lose nothing
 * the run exists for. The first row of every block is one Linux reads; a block's window is the one of the block it is the late half of. */
enum { B_GCC, B_GIC, B_U2, B_S10, B_TLMM, B_XU2, B_XS10, B_XGIC, BLOCKS };
#define S1_BLOCKS (B_TLMM + 1u)
static const char block_head[BLOCKS][8] = {"GCC", "GIC", "U2", "S10", "TLMM", "X U2", "X S10", "X GIC"};
static const uint8_t block_win[BLOCKS] = {WIN_GCC, WIN_GIC, WIN_U2, WIN_S10, WIN_TLMM, WIN_U2, WIN_S10, WIN_GIC};
/* Lines a block may use at most; a block also keeps to what the later blocks, the second snapshot and the closing lines need (room_for()), and drops, counting it in
 * CUTS, a field that does not fit: never half a field, never a line over the cap. The maxima add up to more than the cap leaves for data on purpose: a block whose
 * engine is gated is one line, so the pool is shared and the page the unit prints is shorter than the sum; DRIFT_LINES are kept for the drift report whatever the
 * blocks before it used. */
static const uint8_t block_lines[BLOCKS] = {5, 3, 4, 3, 4, 3, 2, 3};
#define HEADER_LINES 2u
#define S2_NEXT_LINES 4u                /* NEXT WAIT and the three NEXT S2 lines (GCC, U2, TLMM) */
#define DRIFT_LINES 2u                  /* the drift report's item lines (DG, DU, DT) are never crowded out entirely by the blocks before them */

/* GCC is one flat window of registers that do not all answer alike (the votes were never read on the unit), so an abort there ends the reads of its group, not of the
 * window: the groups are the wrapper 0 words, the wrapper 1 words and the vote words. */
enum { G_W0, G_W1, G_VOTE, GROUPS };
/* The engine a clock word gates (GCC rows only): a bit per engine. An engine is read only when every one of its words has been read and says the clock runs. */
#define GATE_U2 1u
#define GATE_S10 2u
enum { F_BREAK = 1, F_WIDE = 2, F_S2 = 4, F_HWCG = 8, F_FRESH = 16 };       /* a new line starts here; a 64-bit register read as two words; snapshot 2 reads it again; the clock declares a hardware gating bit; no Linux driver reads it (read after snapshot 2) */
enum { D_NONE, D_CBCR, D_FIELD, D_FW, D_STATUS, D_FIFOT, D_FIFOR, D_IOS, D_CBCR_HW };

struct reg {
    uint32_t off;                       /* in the window */
    uint8_t win, grp, gate, flags;
    uint8_t dec, shift, width, block;
    uint32_t spare;
};
_Static_assert(sizeof(struct reg) == 16, "inputsnap: a register row is 16 bytes");

/* One row per register, in page order: (id, key as printed, offset, window, group, gate, flags, decode, shift, width, block). The keys are at most seven characters (the
 * key table has eight-byte rows) and unique within a block. Within a block the rows are in the order of what a single abort costs, because the first abort in a window
 * ends it: what the run exists for comes first (the gate words of the clocks, the engine's identity, status and the words that move, then its configuration), and every
 * row that no Linux driver reads (F_FRESH) is in a late block, read after snapshot 2. The first row of every block is a register Linux reads: a clock word (clk-branch.c),
 * GICD_CTLR, the firmware revision word of an engine, a pin's CFG word. The GIC rows are written out per interrupt: INTID n is bit n % 32 of the word n / 32 of ISENABLER
 * (0x100), ISPENDR (0x200) and IGROUPR (0x080), the two-bit field n % 16 of word n / 16 of ICFGR (0xc00) and the 64-bit register n of IROUTER (0x6000 + 8n): for 240, 616 and 834
 * the words are 7, 19 and 26 and the bits 16, 8 and 2; the ICFGR words 15, 38 and 52 and the fields at bits 1:0, 17:16 and 5:4. A pin's words are CFG at 0x1000 * pin, IO at +4,
 * INTR_CFG at +8 and INTR_STATUS at +0xc. */
#define REG_LIST(X) \
    /* GCC: the clock words (CBCR, bit 31 = CLK_OFF) of wrapper 0 and engine 2's clock, wrapper 1 and engine 2's clock and its QSPI clock, the gate words of each engine before the \
     * clock that gates nothing; then the votes */ \
    X(G_MA0, "MA0", 0x23000, WIN_GCC, G_W0, GATE_U2, F_S2 | F_HWCG, D_CBCR, 0, 0, B_GCC) \
    X(G_SA0, "SA0", 0x23004, WIN_GCC, G_W0, GATE_U2, F_S2 | F_HWCG, D_CBCR, 0, 0, B_GCC) \
    X(G_CR0, "CR0", 0x23008, WIN_GCC, G_W0, GATE_U2, F_S2, D_CBCR, 0, 0, B_GCC) \
    X(G_SE0, "SE0", 0x42274, WIN_GCC, G_W0, GATE_U2, F_S2, D_CBCR, 0, 0, B_GCC) \
    X(G_C20, "C20", 0x23018, WIN_GCC, G_W0, 0, F_S2, D_CBCR, 0, 0, B_GCC) \
    X(G_MA1, "MA1", 0x23150, WIN_GCC, G_W1, GATE_S10, F_S2 | F_BREAK | F_HWCG, D_CBCR, 0, 0, B_GCC) \
    X(G_SA1, "SA1", 0x23154, WIN_GCC, G_W1, GATE_S10, F_S2 | F_HWCG, D_CBCR, 0, 0, B_GCC) \
    X(G_CR1, "CR1", 0x23158, WIN_GCC, G_W1, GATE_S10, F_S2, D_CBCR, 0, 0, B_GCC) \
    X(G_SE1, "SE1", 0x18274, WIN_GCC, G_W1, GATE_S10, F_S2, D_CBCR, 0, 0, B_GCC) \
    X(G_QS1, "QS1", 0x18280, WIN_GCC, G_W1, GATE_S10, F_S2, D_CBCR, 0, 0, B_GCC) \
    X(G_C21, "C21", 0x23168, WIN_GCC, G_W1, 0, F_S2, D_CBCR, 0, 0, B_GCC) \
    X(G_VT0, "VT0", 0x52020, WIN_GCC, G_VOTE, 0, F_BREAK, D_NONE, 0, 0, B_GCC) \
    X(G_VT1, "VT1", 0x52008, WIN_GCC, G_VOTE, 0, 0, D_NONE, 0, 0, B_GCC) \
    X(G_VT2, "VT2", 0x52028, WIN_GCC, G_VOTE, 0, 0, D_NONE, 0, 0, B_GCC) \
    /* GIC: GICD_CTLR and GICD_TYPER (OBSERVED before), then the enable, pending and configuration of INTID 616 (uart2), 834 (spi10) and 240 (the pin controller's summary) */ \
    X(I_CTL, "CTL", 0x0000, WIN_GIC, 0, 0, 0, D_NONE, 0, 0, B_GIC) \
    X(I_TYP, "TYP", 0x0004, WIN_GIC, 0, 0, 0, D_NONE, 0, 0, B_GIC) \
    X(I_E616, "E616", 0x014c, WIN_GIC, 0, 0, F_BREAK, D_FIELD, 8, 1, B_GIC) \
    X(I_P616, "P616", 0x024c, WIN_GIC, 0, 0, 0, D_FIELD, 8, 1, B_GIC) \
    X(I_C616, "C616", 0x0c98, WIN_GIC, 0, 0, 0, D_FIELD, 16, 2, B_GIC) \
    X(I_E834, "E834", 0x0168, WIN_GIC, 0, 0, 0, D_FIELD, 2, 1, B_GIC) \
    X(I_P834, "P834", 0x0268, WIN_GIC, 0, 0, 0, D_FIELD, 2, 1, B_GIC) \
    X(I_C834, "C834", 0x0cd0, WIN_GIC, 0, 0, 0, D_FIELD, 4, 2, B_GIC) \
    X(I_E240, "E240", 0x011c, WIN_GIC, 0, 0, 0, D_FIELD, 16, 1, B_GIC) \
    X(I_P240, "P240", 0x021c, WIN_GIC, 0, 0, 0, D_FIELD, 16, 1, B_GIC) \
    X(I_C240, "C240", 0x0c3c, WIN_GIC, 0, 0, 0, D_FIELD, 0, 2, B_GIC) \
    /* U2: the Surface Aggregator link's engine (QUP wrapper 0, engine 2, 0x00b88000): identity, status and the mode words the counts depend on; the words that move (FIFO status, \
     * interrupt status, IOS); then the interrupt enables, the UART's own configuration and the hardware parameters */ \
    X(U_FW, "FW", 0x0068, WIN_U2, 0, 0, 0, D_FW, 0, 0, B_U2) \
    X(U_IFD, "IFD", 0x0064, WIN_U2, 0, 0, 0, D_NONE, 0, 0, B_U2) \
    X(U_ST, "ST", 0x0040, WIN_U2, 0, 0, F_S2, D_STATUS, 0, 0, B_U2) \
    X(U_DMA, "DMA", 0x0258, WIN_U2, 0, 0, 0, D_NONE, 0, 0, B_U2) \
    X(U_TXF, "TXF", 0x0800, WIN_U2, 0, 0, F_BREAK | F_S2, D_FIFOT, 0, 0, B_U2) \
    X(U_RXF, "RXF", 0x0804, WIN_U2, 0, 0, F_S2, D_FIFOR, 0, 0, B_U2) \
    X(U_MIS, "MIS", 0x0610, WIN_U2, 0, 0, F_S2, D_NONE, 0, 0, B_U2) \
    X(U_SIS, "SIS", 0x0640, WIN_U2, 0, 0, F_S2, D_NONE, 0, 0, B_U2) \
    X(U_IOS, "IOS", 0x0908, WIN_U2, 0, 0, F_S2, D_IOS, 0, 0, B_U2) \
    X(U_MIE, "MIE", 0x0614, WIN_U2, 0, 0, F_BREAK, D_NONE, 0, 0, B_U2) \
    X(U_SIE, "SIE", 0x0644, WIN_U2, 0, 0, 0, D_NONE, 0, 0, B_U2) \
    X(U_IOM, "IOM", 0x0240, WIN_U2, 0, 0, 0, D_NONE, 0, 0, B_U2) \
    X(U_TCF, "TCF", 0x025c, WIN_U2, 0, 0, 0, D_NONE, 0, 0, B_U2) \
    X(U_RCF, "RCF", 0x0280, WIN_U2, 0, 0, 0, D_NONE, 0, 0, B_U2) \
    X(U_TPA, "TPA", 0x02a4, WIN_U2, 0, 0, 0, D_NONE, 0, 0, B_U2) \
    X(U_RPA, "RPA", 0x02a8, WIN_U2, 0, 0, 0, D_NONE, 0, 0, B_U2) \
    X(U_HW0, "HW0", 0x0e24, WIN_U2, 0, 0, 0, D_NONE, 0, 0, B_U2) \
    X(U_HW1, "HW1", 0x0e28, WIN_U2, 0, 0, 0, D_NONE, 0, 0, B_U2) \
    /* S10: the touch controller's engine (QUP wrapper 1, engine 2, 0x00a88000): the words every GENI engine has, nothing of a protocol */ \
    X(S_FW, "FW", 0x0068, WIN_S10, 0, 0, 0, D_FW, 0, 0, B_S10) \
    X(S_IFD, "IFD", 0x0064, WIN_S10, 0, 0, 0, D_NONE, 0, 0, B_S10) \
    X(S_ST, "ST", 0x0040, WIN_S10, 0, 0, 0, D_STATUS, 0, 0, B_S10) \
    X(S_DMA, "DMA", 0x0258, WIN_S10, 0, 0, 0, D_NONE, 0, 0, B_S10) \
    X(S_TXF, "TXF", 0x0800, WIN_S10, 0, 0, 0, D_FIFOT, 0, 0, B_S10) \
    X(S_RXF, "RXF", 0x0804, WIN_S10, 0, 0, 0, D_FIFOR, 0, 0, B_S10) \
    X(S_MIS, "MIS", 0x0610, WIN_S10, 0, 0, 0, D_NONE, 0, 0, B_S10) \
    X(S_SIS, "SIS", 0x0640, WIN_S10, 0, 0, 0, D_NONE, 0, 0, B_S10) \
    X(S_IOS, "IOS", 0x0908, WIN_S10, 0, 0, 0, D_NONE, 0, 0, B_S10) \
    X(S_MIE, "MIE", 0x0614, WIN_S10, 0, 0, 0, D_NONE, 0, 0, B_S10) \
    X(S_SIE, "SIE", 0x0644, WIN_S10, 0, 0, 0, D_NONE, 0, 0, B_S10) \
    X(S_HW0, "HW0", 0x0e24, WIN_S10, 0, 0, 0, D_NONE, 0, 0, B_S10) \
    X(S_HW1, "HW1", 0x0e28, WIN_S10, 0, 0, 0, D_NONE, 0, 0, B_S10) \
    /* TLMM, last of snapshot 1: the UART pins gpio8-11 and the Surface Aggregator's wake line (gpio91), the SPI engine's gpio40-43, the touch interrupt, reset and power lines \
     * (gpio51, 48, 64) and the lid (gpio2). Never gpio44-47 (the TPM's, reserved in x1-microsoft-denali.dtsi:1198) or gpio238. */ \
    X(T_F8, "F8", 0x08000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L8, "L8", 0x08004, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_F9, "F9", 0x09000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L9, "L9", 0x09004, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_F10, "F10", 0x0a000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L10, "L10", 0x0a004, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_F11, "F11", 0x0b000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L11, "L11", 0x0b004, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_F91, "F91", 0x5b000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L91, "L91", 0x5b004, WIN_TLMM, 0, 0, F_S2, D_NONE, 0, 0, B_TLMM) \
    X(T_N91, "N91", 0x5b008, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_S91, "S91", 0x5b00c, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_F40, "F40", 0x28000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L40, "L40", 0x28004, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_F41, "F41", 0x29000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L41, "L41", 0x29004, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_F42, "F42", 0x2a000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L42, "L42", 0x2a004, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_F43, "F43", 0x2b000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L43, "L43", 0x2b004, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_F51, "F51", 0x33000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L51, "L51", 0x33004, WIN_TLMM, 0, 0, F_S2, D_NONE, 0, 0, B_TLMM) \
    X(T_N51, "N51", 0x33008, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_S51, "S51", 0x3300c, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_F48, "F48", 0x30000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L48, "L48", 0x30004, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_F64, "F64", 0x40000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L64, "L64", 0x40004, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_F2, "F2", 0x02000, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    X(T_L2, "L2", 0x02004, WIN_TLMM, 0, 0, 0, D_NONE, 0, 0, B_TLMM) \
    /* X U2, after snapshot 2 and its drift report: the words of the UART engine no Linux driver reads (the serial clock and the frame, the stale count, the manual flow control, the \
     * watermarks, the read-only DMA interface word), the clock configuration first: it says what a working configuration has to be */ \
    X(U_CM, "CM", 0x0048, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    X(U_CS, "CS", 0x004c, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    X(U_CK, "CK", 0x007c, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    X(U_CC, "CC", 0x0060, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    X(U_TWL, "TWL", 0x0268, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    X(U_TSB, "TSB", 0x026c, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    X(U_RWL, "RWL", 0x028c, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    X(U_STL, "STL", 0x0294, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    X(U_MRF, "MRF", 0x02ac, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    X(U_TWM, "TWM", 0x080c, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    X(U_RWM, "RWM", 0x0810, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    X(U_RFW, "RFW", 0x0814, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    X(U_DIF, "DIF", 0x0e20, WIN_U2, 0, 0, F_FRESH, D_NONE, 0, 0, B_XU2) \
    /* X S10: the same for the SPI engine: what its serial clock was set to, and the read-only words */ \
    X(S_CM, "CM", 0x0048, WIN_S10, 0, 0, F_FRESH, D_NONE, 0, 0, B_XS10) \
    X(S_CS, "CS", 0x004c, WIN_S10, 0, 0, F_FRESH, D_NONE, 0, 0, B_XS10) \
    X(S_CK, "CK", 0x007c, WIN_S10, 0, 0, F_FRESH, D_NONE, 0, 0, B_XS10) \
    X(S_CC, "CC", 0x0060, WIN_S10, 0, 0, F_FRESH, D_NONE, 0, 0, B_XS10) \
    X(S_DIF, "DIF", 0x0e20, WIN_S10, 0, 0, F_FRESH, D_NONE, 0, 0, B_XS10) \
    /* X GIC: the group and the routing of INTID 616, 834 and 240, the words that tell whether the interrupt reaches us (what a non-secure read of them returns is UV3) */ \
    X(I_G616, "G616", 0x00cc, WIN_GIC, 0, 0, F_FRESH, D_FIELD, 8, 1, B_XGIC) \
    X(I_R616, "R616", 0x7340, WIN_GIC, 0, 0, F_FRESH | F_WIDE, D_NONE, 0, 0, B_XGIC) \
    X(I_G834, "G834", 0x00e8, WIN_GIC, 0, 0, F_FRESH, D_FIELD, 2, 1, B_XGIC) \
    X(I_R834, "R834", 0x7a10, WIN_GIC, 0, 0, F_FRESH | F_WIDE, D_NONE, 0, 0, B_XGIC) \
    X(I_G240, "G240", 0x009c, WIN_GIC, 0, 0, F_FRESH, D_FIELD, 16, 1, B_XGIC) \
    X(I_R240, "R240", 0x6780, WIN_GIC, 0, 0, F_FRESH | F_WIDE, D_NONE, 0, 0, B_XGIC)

enum {
#define X(id, key, off, win, grp, gate, flags, dec, shift, width, block) R_##id,
    REG_LIST(X)
#undef X
    R_COUNT
};
static const struct reg regs[R_COUNT] = {
#define X(id, key, off, win, grp, gate, flags, dec, shift, width, block) {off, win, grp, gate, flags, dec, shift, width, block, 0},
    REG_LIST(X)
#undef X
};
static const char reg_key[R_COUNT][8] = {
#define X(id, key, off, win, grp, gate, flags, dec, shift, width, block) key,
    REG_LIST(X)
#undef X
};
static const uint8_t block_first[BLOCKS + 1] = {R_G_MA0, R_I_CTL, R_U_FW, R_S_FW, R_T_F8, R_U_CM, R_S_CM, R_I_G616, R_COUNT};
/* The vote that backs each of the four AHB clocks that declare a hardware gating bit: the apps' enable bit of the clock in the vote word it is registered in (gcc-x1e80100.c:4955-4961,
 * 4970-4976, 4985-4991 and 5000-5006: wrapper 0's m_ahb and s_ahb in 0x52020 bits 6 and 7, wrapper 1's in 0x52008 bits 20 and 21). A hardware-gated clock whose CLK_OFF is set is a healthy
 * idle clock only if something asked for it, so the engine gate takes `.HW` as running only when this bit is set in the vote word of the snapshot that read it. */
struct hw_vote {
    uint8_t clock, vote, bit, pad;
};
_Static_assert(sizeof(struct hw_vote) == 4, "inputsnap: a vote row is 4 bytes");
static const struct hw_vote hw_votes[4] = {{R_G_MA0, R_G_VT0, 6, 0}, {R_G_SA0, R_G_VT0, 7, 0}, {R_G_MA1, R_G_VT1, 20, 0}, {R_G_SA1, R_G_VT1, 21, 0}};
#define S1_LOADS_MAX 86u                /* the rows of the first five blocks, once each; no wide row among them */
#define S2_LOADS_MAX 19u                /* the rows flagged F_S2: eleven clock words, six engine words, two pin levels */
#define X_LOADS_MAX 27u                 /* the rows of the late blocks, a wide row as two loads: the table gives all three numbers (tools/test-q1n1-sp11-payload-inputsnap.c) */
_Static_assert(R_COUNT == 110, "inputsnap: the table has 110 rows");
