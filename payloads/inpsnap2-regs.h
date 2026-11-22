/* SPDX-License-Identifier: MIT */
/* Registers, budgets and the read table of the payload "inpsnap2" (payloads/inpsnap2.c; docs/SP11-PAYLOAD-INPSNAP2.md has the file:line of every row, the evidence labels, the page and what each
 * outcome means). It is stage I0 of the input plan: the words that decide how the Type Cover link's UART engine (QUP wrapper 0, engine 2) can be clocked later. Definitions only.
 * Evidence: VERIFIED is a pinned Linux file at 7475ea8b58616b33c04afb976cf0fbaad9dd63fb (hamoa.dtsi, gcc-x1e80100.c, clk-rcg2.c, clk-alpha-pll.c, clk-branch.c, clk-branch.h,
 * qcom-geni-se.c); it never says what the unit does. Nothing here was ever read on the unit by this payload (EXPERIMENTAL), and no QUP wrapper word has ever been read on it at all.
 * The table holds no pointer: a pointer in .rodata would need a load-address relocation, which the payload's link check refuses. Every table has a power-of-two row size, so that
 * indexing it is a shift and the binary check of tools/sp11_payload_memcheck.py can follow it. */
#pragma once
#include <stdint.h>

/* Budgets. The ABI allows 40 lines and 4096 loads per call. The page is at most 21 lines and 44 loads whatever the hardware says: every row of the table once, every line a fixed
 * list of rows. The host test builds with smaller caps too, to see what happens when they run out. */
#if !defined(INPSNAP2_LINE_CAP) && !defined(INPSNAP2_LOAD_CAP)
#define INPSNAP2_SHIPPED_CAPS 1
#endif
#ifndef INPSNAP2_LINE_CAP
#define INPSNAP2_LINE_CAP 24u
#endif
#ifndef INPSNAP2_LOAD_CAP
#define INPSNAP2_LOAD_CAP 44u
#endif
#define LINE_CAP INPSNAP2_LINE_CAP
#define LOAD_CAP INPSNAP2_LOAD_CAP
#define CLOSING_LINES 1u                /* the end line is never crowded out by the lines before it */
#define LINE_FILL (Q1N1_PAYLOAD_LINE_MAX - 5u)  /* a packed line stops five characters short of the ABI's 100, as the other snapshot payloads' do */

/* The two windows this payload reads: the clock controller (reg of gcc, hamoa.dtsi:758-760) and QUP wrapper 0 (qupv3_0 reg, hamoa.dtsi:2141-2143: engine 2, `uart2`, lies at 0x00b88000
 * below it and is not read). Every GCC word is read unconditionally, as the earlier survey payloads read their GCC words (boots 29 to 31: OBSERVED to answer); the wrapper's one word
 * only behind the wrapper's clocks (wrapper_gate()): no read of any QUP window has ever answered on the unit (boot 29 found the engine clocks off and read none). */
enum { WIN_GCC, WIN_QUP, WINDOWS };
#define GCC_BYTES 0x200000u
#define QUP_BYTES 0x2000u
static const struct window {
    uint64_t base;
    uint32_t size, pad;
} windows[WINDOWS] = {{0x00100000u, GCC_BYTES, 0}, {0x00bc0000u, QUP_BYTES, 0}};
static const char window_name[WINDOWS][8] = {"GCC", "QUP"};
_Static_assert(sizeof windows[0] == 16, "inpsnap2: a window row is 16 bytes");
_Static_assert(!(GCC_BYTES & 3) && !(QUP_BYTES & 3), "inpsnap2: a window is a whole number of words, so that an aligned offset inside it has four bytes");

/* Blocks in page order, each in one window, each announced by a `NEXT <block>` line before its first load. GATE: the three clock words the wrapper read depends on, the engine's own
 * clock word and the votes (five read in boot 29, GV in boot 30). RCG: the s2 root clock generator's DFS flag first, then the divider below it and its own words. PLL: GPLL0. LVL: the eight
 * DFS levels' configuration, M and N words. QUP: the wrapper's version, last because it is the one read nobody has made: the plan needs the DFS flag and GPLL0 first, and a hang
 * there keeps everything before it. The first abort in a block ends the reads of the block (the others go on). */
enum { B_GATE, B_RCG, B_PLL, B_LVL, B_QUP, BLOCKS };
static const char block_head[BLOCKS][8] = {"GATE", "RCG", "PLL", "LVL", "QUP"};

/* A row's flags: a branch clock word (CBCR: the page adds .ON, .OFF, .HW or .ODD); a clock that declares a hardware gating bit (hwcg_reg in gcc-x1e80100.c: the two AHB clocks); a
 * clock word the wrapper's read depends on. `vbit` is the bit of VT0 that is the apps' vote for a hardware-gated clock (gcc-x1e80100.c:4955-4961 and 4970-4976: 0x52020 bits 6, 7). */
enum { F_CBCR = 1, F_HWCG = 2, F_WRAP = 4 };

struct reg {
    uint32_t off;                       /* in the window */
    uint8_t win, block, flags, vbit;
    char key[8];                        /* as printed: at most seven characters, unique in the table */
};
_Static_assert(sizeof(struct reg) == 16, "inpsnap2: a register row is 16 bytes");

/* One row per register, in page order: (id, key as printed, offset, window, block, flags, vote bit). The GCC offsets are those of gcc-x1e80100.c (docs/SP11-PAYLOAD-INPSNAP2.md has the
 * file:line of each): the clocks' halt words, the vote words 0x52020 (the apps' enable bits of wrapper 0's clocks) and 0x52030 (GPLL0's apps vote, bit 0), the s2 RCG at cmd_rcgr
 * 0x42288 with its DFS flag at +0x14 and the eight levels' words at +0x1c, +0x5c and +0x9c (clk-rcg2.c:55-60), the read-only divider at 0x42284, and GPLL0 at offset 0 with the
 * Lucid-OLE layout (clk-alpha-pll.c:187-201: opmode +4, status +0xc, L +0x10, alpha +0x14, user control +0x18). Within a block the rows are in the order of what one abort costs: what
 * the plan decides first comes first. */
#define REG_LIST(X) \
    X(MA0, "MA0", 0x23000, WIN_GCC, B_GATE, F_CBCR | F_HWCG | F_WRAP, 6) \
    X(SA0, "SA0", 0x23004, WIN_GCC, B_GATE, F_CBCR | F_HWCG | F_WRAP, 7) \
    X(CR0, "CR0", 0x23008, WIN_GCC, B_GATE, F_CBCR | F_WRAP, 0) \
    X(SE0, "SE0", 0x42274, WIN_GCC, B_GATE, F_CBCR, 0) \
    X(VT0, "VT0", 0x52020, WIN_GCC, B_GATE, 0, 0) \
    X(GV, "GV", 0x52030, WIN_GCC, B_GATE, 0, 0) \
    X(DFS, "DFS", 0x4229c, WIN_GCC, B_RCG, 0, 0) \
    X(DIV, "DIV", 0x42284, WIN_GCC, B_RCG, 0, 0) \
    X(CMD, "CMD", 0x42288, WIN_GCC, B_RCG, 0, 0) \
    X(CFG, "CFG", 0x4228c, WIN_GCC, B_RCG, 0, 0) \
    X(M, "M", 0x42290, WIN_GCC, B_RCG, 0, 0) \
    X(N, "N", 0x42294, WIN_GCC, B_RCG, 0, 0) \
    X(D, "D", 0x42298, WIN_GCC, B_RCG, 0, 0) \
    X(MODE, "MODE", 0x00000, WIN_GCC, B_PLL, 0, 0) \
    X(OP, "OP", 0x00004, WIN_GCC, B_PLL, 0, 0) \
    X(ST, "ST", 0x0000c, WIN_GCC, B_PLL, 0, 0) \
    X(L, "L", 0x00010, WIN_GCC, B_PLL, 0, 0) \
    X(AL, "AL", 0x00014, WIN_GCC, B_PLL, 0, 0) \
    X(USR, "USR", 0x00018, WIN_GCC, B_PLL, 0, 0) \
    X(LC0, "LC0", 0x422a4, WIN_GCC, B_LVL, 0, 0) \
    X(LC1, "LC1", 0x422a8, WIN_GCC, B_LVL, 0, 0) \
    X(LC2, "LC2", 0x422ac, WIN_GCC, B_LVL, 0, 0) \
    X(LC3, "LC3", 0x422b0, WIN_GCC, B_LVL, 0, 0) \
    X(LC4, "LC4", 0x422b4, WIN_GCC, B_LVL, 0, 0) \
    X(LC5, "LC5", 0x422b8, WIN_GCC, B_LVL, 0, 0) \
    X(LC6, "LC6", 0x422bc, WIN_GCC, B_LVL, 0, 0) \
    X(LC7, "LC7", 0x422c0, WIN_GCC, B_LVL, 0, 0) \
    X(LM0, "LM0", 0x422e4, WIN_GCC, B_LVL, 0, 0) \
    X(LM1, "LM1", 0x422e8, WIN_GCC, B_LVL, 0, 0) \
    X(LM2, "LM2", 0x422ec, WIN_GCC, B_LVL, 0, 0) \
    X(LM3, "LM3", 0x422f0, WIN_GCC, B_LVL, 0, 0) \
    X(LM4, "LM4", 0x422f4, WIN_GCC, B_LVL, 0, 0) \
    X(LM5, "LM5", 0x422f8, WIN_GCC, B_LVL, 0, 0) \
    X(LM6, "LM6", 0x422fc, WIN_GCC, B_LVL, 0, 0) \
    X(LM7, "LM7", 0x42300, WIN_GCC, B_LVL, 0, 0) \
    X(LN0, "LN0", 0x42324, WIN_GCC, B_LVL, 0, 0) \
    X(LN1, "LN1", 0x42328, WIN_GCC, B_LVL, 0, 0) \
    X(LN2, "LN2", 0x4232c, WIN_GCC, B_LVL, 0, 0) \
    X(LN3, "LN3", 0x42330, WIN_GCC, B_LVL, 0, 0) \
    X(LN4, "LN4", 0x42334, WIN_GCC, B_LVL, 0, 0) \
    X(LN5, "LN5", 0x42338, WIN_GCC, B_LVL, 0, 0) \
    X(LN6, "LN6", 0x4233c, WIN_GCC, B_LVL, 0, 0) \
    X(LN7, "LN7", 0x42340, WIN_GCC, B_LVL, 0, 0) \
    X(VER, "VER", 0x00004, WIN_QUP, B_QUP, 0, 0)

enum {
#define X(id, key, off, win, block, flags, vbit) R_##id,
    REG_LIST(X)
#undef X
    R_COUNT
};
static const struct reg regs[R_COUNT] = {
#define X(id, key, off, win, block, flags, vbit) {off, win, block, flags, vbit, key},
    REG_LIST(X)
#undef X
};

/* The lines of the page, in reading order: a line is read whole and printed before the first load of the next, so that a hang keeps every line before the one it hit, and each line
 * names the same rows whatever the hardware says (a row that was not read prints why). At most four words a line: the widest word, `KEY=0XFFFFFFFF`, makes the widest line 88 of the
 * 95 characters a packed line may have (a static assertion in payloads/inpsnap2.c). */
enum { L_GATE0, L_GATE1, L_RCG0, L_RCG1, L_PLL0, L_PLL1, L_LC0, L_LC1, L_LM0, L_LM1, L_LN0, L_LN1, L_QUP, LINES };
static const struct line_def {
    uint8_t first, end, block, pad;
    char head[12];
} lines[LINES] = {
    {R_MA0, R_SE0, B_GATE, 0, "GATE"}, {R_SE0, R_DFS, B_GATE, 0, "GATE"}, {R_DFS, R_M, B_RCG, 0, "RCG"}, {R_M, R_MODE, B_RCG, 0, "RCG"},
    {R_MODE, R_L, B_PLL, 0, "PLL"}, {R_L, R_LC0, B_PLL, 0, "PLL"}, {R_LC0, R_LC4, B_LVL, 0, "LVL"}, {R_LC4, R_LM0, B_LVL, 0, "LVL"},
    {R_LM0, R_LM4, B_LVL, 0, "LVL"}, {R_LM4, R_LN0, B_LVL, 0, "LVL"}, {R_LN0, R_LN4, B_LVL, 0, "LVL"}, {R_LN4, R_VER, B_LVL, 0, "LVL"},
    {R_VER, R_COUNT, B_QUP, 0, "QUP"},
};
_Static_assert(sizeof lines[0] == 16, "inpsnap2: a line row is 16 bytes");

#define HEADER_LINES 2u
#define PAGE_LINES (HEADER_LINES + BLOCKS + LINES + CLOSING_LINES)
#define LOADS_MAX R_COUNT               /* every row of the table once */
#ifdef INPSNAP2_SHIPPED_CAPS
_Static_assert(PAGE_LINES <= LINE_CAP, "inpsnap2: the page with every gate open fits the line cap");
_Static_assert(LOADS_MAX <= LOAD_CAP, "inpsnap2: the loads of every row fit the load cap");
#endif
_Static_assert(R_COUNT == 44, "inpsnap2: the table has 44 rows: the 41 words of the I0 survey list and the three clock words the wrapper read depends on");

/* The page's check of a line: CRC-16/CCITT-FALSE (polynomial 0x1021, initial value 0xFFFF, no reflection) of five bytes for each word of the line in order, its state and its value
 * least significant byte first. A transcription of the film is checked against it (tools/sp11_inpsnap2_parse.py of the Snapintosh tree). */
#define CRC_INIT 0xffffu
#define CRC_POLY 0x1021u
enum { V_NONE, V_OK, V_FAULT, V_SKIP, V_BUDGET };
