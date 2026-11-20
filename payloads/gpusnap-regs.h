/* SPDX-License-Identifier: MIT */
/* Registers, budgets and the read table of the payload "gpusnap" (payloads/gpusnap.c; docs/SP11-PAYLOAD-GPUSNAP.md has the file:line of every row, the page and
 * what each outcome would mean). It is stage S0 of the first-contact plan of the Snapintosh tree (docs/SP11-GPU-PORT-PLAN.md section 7.1): the read-only look at the
 * clock and power state of the X1-85 before anything is written. Definitions only.
 * Evidence: VERIFIED is a pinned Linux file at 7475ea8b58616b33c04afb976cf0fbaad9dd63fb (gcc-x1e80100.c, gpucc-x1e80100.c, hamoa.dtsi, arm-smmu.h, a6xx_gmu.xml,
 * a6xx_gmu.c, a6xx.xml and the files the document lists); it never says what the unit does. Nothing here was ever read on the unit by this payload (EXPERIMENTAL), and the
 * GPU words below (GCC 0x71xxx, GPUCC, GMU, RSCC, the GPU SMMU) have never been read on it at all (UNKNOWN whether any aborts, hangs or raises an SError).
 * The table holds no pointer: a pointer in .rodata would need a load-address relocation, which the payload's link check refuses. Every table has a power-of-two row size, so
 * that indexing it is a shift and the binary check of tools/sp11_payload_memcheck.py can follow it. */
#pragma once
#include <stdint.h>

/* Budgets. The ABI allows 40 lines and 4096 loads per call; 34 lines keep a chain with an xHCI payload inside the panel's rows with six to spare (the arithmetic is in
 * docs/SP11-PAYLOAD-GPUSNAP.md, as for usbsnap). The host test builds with smaller caps too, to see what happens when they run out. */
#if !defined(GPUSNAP_LINE_CAP) && !defined(GPUSNAP_LOAD_CAP)
#define GPUSNAP_SHIPPED_CAPS 1
#endif
#ifndef GPUSNAP_LINE_CAP
#define GPUSNAP_LINE_CAP 34u
#endif
#ifndef GPUSNAP_LOAD_CAP
#define GPUSNAP_LOAD_CAP 128u
#endif
#define LINE_CAP GPUSNAP_LINE_CAP
#define LOAD_CAP GPUSNAP_LOAD_CAP
#define CLOSING_LINES 2u                /* the drift summary and the end line are never crowded out by the lines before them */
#define LATE_LINES 4u                   /* NEXT LATE <block> and one line, for each of the two blocks that have words Linux never reads */
#define GAP_S 8u                        /* the one wait, between the two snapshots */
#define COUNTER_HZ_DEFAULT 19200000u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u
#define COUNTER_STUCK_READS 2000000u
/* The wait reads the counter until the gap has passed; a counter that stands still or runs backwards ends it (S2 SKIPPED NO_COUNTER). This bound is for a counter that moves but never gets
 * there (one that jitters, or runs far slower than CNTFRQ_EL0 says): 2^32-1 reads is minutes of the real loop, so a wait that has the counter it says it has never meets it, and a bound that
 * is hit says so with its own token (S2 SKIPPED SPIN). The host test builds with a small bound to make the difference testable. */
#ifndef GPUSNAP_SPIN_MAX
#define GPUSNAP_SPIN_MAX 0xffffffffu
#endif
#define SPIN_MAX GPUSNAP_SPIN_MAX

/* The only device addresses this payload reads (hamoa.dtsi, VERIFIED: gcc dt:758-760, gpucc dt:4227, cx_mem dt:4017, gmu dt:4175, rscc dt:4176, adreno_smmu dt:4239).
 * The GPU window itself (dt:4016, RBBM and CP: the GX side), cx_dbgc (dt:4018) and gmu_pdc (dt:4177) are not here and are never read. The gmu window of the device tree is
 * 0x35000 long and so also spans the GPUCC and CX_MISC windows: an address inside it says nothing about which block it belongs to, so every row names its own window. A window
 * is also a block: the page announces it, gates it and ends its reads at the first abort. */
enum { WIN_GCC, WIN_GPUCC, WIN_CXMISC, WIN_GMU, WIN_RSCC, WIN_SMMU, WINDOWS };
static const struct {
    uint64_t base;
    uint32_t size, pad;
} windows[WINDOWS] = {{0x00100000u, 0x200000u, 0}, {0x03d90000u, 0x0a000u, 0}, {0x03d9e000u, 0x01000u, 0},
                      {0x03d6a000u, 0x35000u, 0}, {0x03d50000u, 0x10000u, 0}, {0x03da0000u, 0x40000u, 0}};
static const char window_name[WINDOWS][8] = {"GCC", "GPUCC", "CXMISC", "GMU", "RSCC", "SMMU"};
_Static_assert(sizeof windows[0] == 16, "gpusnap: a window row is 16 bytes");

/* The GMU's XML offsets are dwords from the GPU base 0x03d00000 (a6xx_gmu.h:139, a6xx_gmu.c:2446), and the GMU window starts 0x6a000 above it. The CX_MISC and RSCC
 * offsets are dwords from their own windows (a6xx_gpu.h:275-278, a6xx_gmu.c:2450). The RSC's TCS status words sit 4 dwords higher on the a740 family, which the X1-85 is
 * (a6xx_gmu.c:1105-1135, a7xx_catalog.c:376-378, adreno_gpu.h:572-577). */
#define GMU_WINDOW_FROM_GPU_BASE 0x6a000u
#define GMU(dword) (4u * (dword) - GMU_WINDOW_FROM_GPU_BASE)
#define RSC(dword) (4u * (dword))
#define CXM(dword) (4u * (dword))
#define RSC_TCS_SEQMEM_DWORDS 4u

/* What a CBCR says (clk-branch.h:63-71): CLK_OFF bit 31, NOC_FSM_STATUS bits 30:28 (ON is 2 once shifted down), CLK_ENABLE bit 0; bit 1 is HW_CTL where a clock has a hwcg bit
 * (gcc-x1e80100.c). */
#define CBCR_CLK_OFF_BIT 31u
#define CBCR_HW_CTL_BIT 1u
#define CBCR_ENABLE_BIT 0u
#define CBCR_FSM_SHIFT 28u
#define CBCR_FSM_MASK 7u
#define CBCR_FSM_ON 2u
/* The CX GDSC (gpucc-x1e80100.c:532-543, gdsc.c:21-27, 61-91): its status is bit 31 of GDS_HW_CTRL, SW_COLLAPSE is GDSCR bit 0 and HW_CONTROL bit 1. */
#define GDSC_PWR_ON_BIT 31u
#define GDSC_SW_COLLAPSE_BIT 0u
#define GDSC_HW_CONTROL_BIT 1u
/* The GX GDSC polls CFG_GDSCR, at +4 (gdsc.c:32-35, 67-83): bit 16 power up complete, bit 15 power down complete. */
#define GXCFG_UP_BIT 16u
#define GXCFG_DOWN_BIT 15u
/* GCC_APCS vote word 0x52000: the two GPU GPLL0 output branches' votes (gcc-x1e80100.c:3063-3064, 3080-3081). */
#define VOTE_CPH_BIT 15u
#define VOTE_DIV_BIT 16u
/* RCG: CFG_REG source select bits 10:8 (clk-rcg2.c:38-39); the gpucc parent maps 0 XO, 1 PLL0, 3 PLL1, 5 GPLL0, 6 GPLL0_DIV (gpucc-x1e80100.c:104-149). */
#define RCG_SRC_SHIFT 8u
#define RCG_SRC_MASK 7u
/* A7XX GMU_SPTPRAC_PWR_CLK_STATUS: bit 0 GX_HM_GDSC_POWER_OFF, bit 1 GX_HM_CLK_OFF (a6xx_gmu.xml:108-111; a6xx_gmu.c:121-136 calls GX on when both are clear). */
#define GXST_OFF_MASK 3u
/* arm-smmu.h:55-72: the fields the page decodes. */
#define SMMU_ID0_NUMSMRG_MASK 0xffu
#define SMMU_ID1_NUMCB_MASK 0xffu
#define SMMU_ID1_PAGESIZE_BIT 31u
#define SMMU_ID1_NUMPAGENDXB_SHIFT 28u
#define SMMU_ID2_PTFS_SHIFT 12u
#define SMMU_ID2_UBS_SHIFT 8u
#define SMMU_ID2_OAS_SHIFT 4u

/* The seven clocks the GMU node lists (hamoa.dtsi:4184-4197): ahb, gmu, cxo, axi, memnoc, hub, demet, in that order, one bit each in the CLK mask of the R4 line; the four
 * clocks the GPU SMMU node lists (hamoa.dtsi:4268-4275): hlos, bus, iface, ahb, in the SM mask. */
#define GMU_CLOCKS 7u
#define SMMU_CLOCKS 4u

/* The CX verdict. CX_UNK is the zero value on purpose: a context that nobody initialised, or that a later edit forgets to set, is closed and never open. */
enum { CX_UNK, CX_OFF, CX_HWCTL, CX_PART, CX_ON, CX_STATES };
static const char cx_name[CX_STATES][8] = {"UNK", "OFF", "HWCTL", "PART", "ON"};
/* Why a block is not read. AHB and SMCLK say that a clock was READ and does not run; AHBERR and SMERR say that a word the gate needed could not be read (an abort, a skip or all ones), which
 * is a different statement: a failed gate read is never reported as the thing it gates on. The four CX reasons follow the four verdicts that close a gate in the same order (CX_UNK, CX_OFF,
 * CX_HWCTL, CX_PART), so that gate_reason() and late_reason() add the verdict to RS_CX_UNK. */
enum { RS_OPEN, RS_CX_UNK, RS_CX_OFF, RS_CX_HWCTL, RS_CX_PART, RS_AHB, RS_SMCLK, RS_AHB_ERR, RS_SM_ERR, RS_NO_S2, REASONS };
static const char reason_name[REASONS][16] = {"", "CX=UNK", "CX=OFF", "CX=HWCTL", "CX=PART", "AHB", "SMCLK", "AHBERR", "SMERR", "NOS2"};
_Static_assert(RS_CX_OFF - RS_CX_UNK == CX_OFF - CX_UNK && RS_CX_HWCTL - RS_CX_UNK == CX_HWCTL - CX_UNK && RS_CX_PART - RS_CX_UNK == CX_PART - CX_UNK,
               "gpusnap: the CX reasons are in the order of the CX verdicts");

/* A row's flags: F_HWCG the clock has a hardware gating bit, bit 1 (Linux skips its halt check while it is set: clk-branch.c:17-27, 72); F_NOHALT its halt check is
 * BRANCH_HALT_SKIP, so CLK_OFF says nothing (gcc-x1e80100.c:2978); F_QUIET the value is read but not printed as a field of its own; F_LATE no Linux code reads the word (it only writes it
 * or never names it: docs/SP11-PAYLOAD-GPUSNAP.md), so it is read after everything else, after the wait and the drift report, each block under its own NEXT LATE line. */
enum { F_HWCG = 1, F_NOHALT = 2, F_QUIET = 4, F_LATE = 8 };
/* How a value is decoded. D_CBCR: .OFF when bit 31 (CLK_OFF) is set, .ON when it is clear and CLK_ENABLE (bit 0) is set; .ODD where that cannot be taken at its word (all ones; CLK_OFF clear
 * with CLK_ENABLE clear, which is what a window of zeros reads; CLK_OFF with HW_CTL set on a clock that has the bit; CLK_OFF with an NoC FSM status of ON); D_RCGCMD: the same for a root clock
 * generator's command word (ROOT_OFF), which has none of those modes, so only all ones is .ODD; D_NW: none (the halt bit is no witness); D_PWR: .ON when bit 31 is set (a GDSC's PWR_ON), .ODD
 * for all ones. A bit field cut from a word of all ones prints ODD. */
enum { D_NONE, D_CBCR, D_NW, D_PWR, D_GDSCR, D_GXCFG, D_VOTE, D_RCGCFG, D_GXST, D_RCGCMD };

struct reg {
    uint8_t win, dec, flags, pad;
    uint32_t off;
    char key[8];
};
_Static_assert(sizeof(struct reg) == 16, "gpusnap: a register row is 16 bytes");

enum {
    /* GCC, always on (R2): the gate inputs first, in the order Linux needs them, then what no gate needs. */
    R_CFGA, R_MNOC, R_AXI, R_SNOC, R_QMIP, R_VOTE, R_GP0V,
    /* GPUCC (R3): the inputs of the CX gate first, then the SMMU's hlos clock, then what the gate does not need. */
    R_CXGD, R_CXHW, R_AHB, R_CGMU, R_CXO, R_HUB, R_DMT, R_HLOS,
    R_GXGD, R_GXCF, R_CXOA, R_HUBA, R_GXGM, R_GRC, R_GRF, R_HRC, R_HRF, R_XRC, R_XRF,
    /* behind the CX gate (R5): the words Linux reads first in each block, the words it never reads (F_LATE) last */
    R_TCMR,
    R_GXST, R_INIT, R_FENS, R_RST, R_CFG, R_BUSY,
    R_BSY, R_ST0, R_T0, R_T1, R_T2, R_T3, R_T4, R_T5, R_T6, R_T7, R_T8, R_T9, R_PDCS,
    R_ID0, R_ID1, R_ID2, R_SCR0, R_GFSR, R_ID7,
    R_COUNT
};
#define TCS_WORDS 10u

#define ROW(win, off, dec, flags, key) {win, dec, flags, 0, off, key}
#define TCS_ROW(n, dword) ROW(WIN_RSCC, RSC((dword) + RSC_TCS_SEQMEM_DWORDS), D_NONE, F_QUIET, n)
static const struct reg regs[R_COUNT] = {
    /* GCC (window gcc, dt:758-760). 0x71004 has no clock struct: it is in the critical list (gcc-x1e80100.c:7451) that common.c:317-318 enables, which is why GPUCC is read
     * only after it reads as running. 0x71008, 0x71010 and 0x71018 are gcc:4262, 3095, 3110; 0x7115c is gcc:2977 (BRANCH_HALT_SKIP, hwcg bit 1); 0x52000 holds the GPU's two
     * GPLL0 output votes (gcc:3063-3064, 3080-3081) and 0x52030 the vote of GPLL0 itself (gcc:117-118). The gate inputs come first so that one abort costs the least. */
    ROW(WIN_GCC, 0x71004, D_CBCR, 0, "CFGA"),
    ROW(WIN_GCC, 0x71010, D_CBCR, F_HWCG, "MNOC"),
    ROW(WIN_GCC, 0x7115c, D_NW, F_HWCG | F_NOHALT, "AXI_NW"),
    ROW(WIN_GCC, 0x71018, D_CBCR, 0, "SNOC"),
    ROW(WIN_GCC, 0x71008, D_CBCR, F_HWCG, "QMIP"),
    ROW(WIN_GCC, 0x52000, D_VOTE, 0, "VOTE"),
    ROW(WIN_GCC, 0x52030, D_NONE, 0, "GP0V"),
    /* GPUCC (window gpucc, dt:4227), gpucc-x1e80100.c: the CX GDSC (gdscr :533, status :534), then the six clocks the GMU and SMMU nodes name (ahb :257, cx_gmu :311, cxo :347,
     * hub_cx_int :463, demet :365, hlos1_vote_gpu_smmu :401). */
    ROW(WIN_GPUCC, 0x9108, D_GDSCR, 0, "CXGD"),
    ROW(WIN_GPUCC, 0x953c, D_PWR, 0, "CXHW"),
    ROW(WIN_GPUCC, 0x911c, D_CBCR, 0, "AHB"),
    ROW(WIN_GPUCC, 0x913c, D_CBCR, 0, "CGMU"),
    ROW(WIN_GPUCC, 0x9144, D_CBCR, 0, "CXO"),
    ROW(WIN_GPUCC, 0x9148, D_CBCR, 0, "HUB"),
    ROW(WIN_GPUCC, 0x900c, D_CBCR, 0, "DMT"),
    ROW(WIN_GPUCC, 0x7000, D_CBCR, 0, "HLOS"),
    /* After the CX verdict: the GX GDSC (:546; its status is in CFG_GDSCR, at +4) and three more branch clocks (cxo_aon :329, hub_aon :445, gx_gmu :414-426; of these only hub_aon has the
     * always-on ops: gx_gmu is a plain branch2 clock with a halt check, and it is read whenever GPUCC is, CX on or off, behind the CFG AHB gate only) and the GMU, hub and XO root clock
     * generators (cmd :182, :197, :212; CFG is cmd + 4: clk-rcg2.c:35). */
    ROW(WIN_GPUCC, 0x905c, D_NONE, 0, "GXGD"),
    ROW(WIN_GPUCC, 0x9060, D_GXCFG, 0, "GXCF"),
    ROW(WIN_GPUCC, 0x9004, D_CBCR, 0, "CXOA"),
    ROW(WIN_GPUCC, 0x93e8, D_CBCR, 0, "HUBA"),
    ROW(WIN_GPUCC, 0x90bc, D_CBCR, 0, "GXGM"),
    ROW(WIN_GPUCC, 0x9318, D_RCGCMD, 0, "GRC"),
    ROW(WIN_GPUCC, 0x931c, D_RCGCFG, 0, "GRF"),
    ROW(WIN_GPUCC, 0x93ec, D_RCGCMD, 0, "HRC"),
    ROW(WIN_GPUCC, 0x93f0, D_RCGCFG, 0, "HRF"),
    ROW(WIN_GPUCC, 0x9010, D_RCGCMD, 0, "XRC"),
    ROW(WIN_GPUCC, 0x9014, D_RCGCFG, 0, "XRF"),
    /* CX_MISC (window cx_mem, dt:4017): TCM_RET_CNTL, dword 0x39 (a6xx.xml:5133; Linux writes 1 at a6xx_gmu.c:964 and reads it at :1364). */
    ROW(WIN_CXMISC, CXM(0x39), D_NONE, 0, "TCMR"),
    /* GMU (window gmu, dt:4175), a6xx_gmu.xml: SPTPRAC_PWR_CLK_STATUS (A7XX, :108-111; read at a6xx_gmu.c:121-136), FW_INIT_RESULT :67 (polled at a6xx_gmu.c:335), AHB_FENCE_STATUS :231
     * (polled at a6xx_gpu.c:76-84) come first: Linux reads them. SYSRESET :64 and CM3_CFG :68 Linux only writes (a6xx_gmu.c:320-333, :1010) and FW_BUSY :66 it never names: they are F_LATE. */
    ROW(WIN_GMU, GMU(0x1f8d0), D_GXST, 0, "GXST"),
    ROW(WIN_GMU, GMU(0x1f81c), D_NONE, 0, "INIT"),
    ROW(WIN_GMU, GMU(0x23b13), D_NONE, 0, "FENS"),
    ROW(WIN_GMU, GMU(0x1f800), D_NONE, F_LATE, "RST"),
    ROW(WIN_GMU, GMU(0x1f82d), D_NONE, F_LATE, "CFG"),
    ROW(WIN_GMU, GMU(0x1f81a), D_NONE, F_LATE, "BUSY"),
    /* RSCC (window rscc, dt:4176), a6xx_gmu.xml: SEQ_BUSY_DRV0 :256 (polled at a6xx_gmu.c:637), RSC_STATUS0_DRV0 :244 (polled at :666), TCS0..9_DRV0_STATUS :259-268 (polled at :1111-1135)
     * come first; PDC_SEQ_START_ADDR :245 Linux only writes (a6xx_gmu.c:730): F_LATE. */
    ROW(WIN_RSCC, RSC(0x0101), D_NONE, 0, "BSY"),
    ROW(WIN_RSCC, RSC(0x0004), D_NONE, 0, "ST0"),
    TCS_ROW("T0", 0x0346), TCS_ROW("T1", 0x03ee), TCS_ROW("T2", 0x0496), TCS_ROW("T3", 0x053e), TCS_ROW("T4", 0x05e6),
    TCS_ROW("T5", 0x068e), TCS_ROW("T6", 0x0736), TCS_ROW("T7", 0x07de), TCS_ROW("T8", 0x0886), TCS_ROW("T9", 0x092e),
    ROW(WIN_RSCC, RSC(0x0008), D_NONE, F_LATE, "PDCS"),
    /* The GPU SMMU (window adreno_smmu, dt:4239), arm-smmu.h: ID0 :45, ID1 :59, ID2 :65 (the identity W2 needs, in the order Linux's probe reads them), then sCR0 :27, sGFSR :83, ID7 :79. Global
     * space 0 only: no stream match entry and no context bank is read. */
    ROW(WIN_SMMU, 0x20, D_NONE, 0, "ID0"),
    ROW(WIN_SMMU, 0x24, D_NONE, 0, "ID1"),
    ROW(WIN_SMMU, 0x28, D_NONE, 0, "ID2"),
    ROW(WIN_SMMU, 0x00, D_NONE, 0, "SCR0"),
    ROW(WIN_SMMU, 0x48, D_NONE, 0, "GFSR"),
    ROW(WIN_SMMU, 0x3c, D_NONE, 0, "ID7"),
};
_Static_assert(sizeof regs / sizeof regs[0] == R_COUNT, "gpusnap: one row per register");

/* The lines of the page, in reading order: a line is read whole and printed before the first load of the next, so that a hang keeps every line before the one it hit. A
 * line holds at most four fields and its widest possible text (eight-digit values with a token) is 99 characters, so that no field is ever cut; the host test's wide fixture
 * shows it. `after`: A_R4 prints the CX verdict as soon as its inputs have gone out, A_SMMU a line that decodes the SMMU's ID words. `late`: the line is read after the wait and the drift
 * report, under a `NEXT <head>` line of its own, and only if the block was read in snapshot 1 and the CX verdict still says ON after the wait. */
enum { A_NONE, A_R4, A_SMMU };
enum { L_GCC0, L_GCC1, L_CX, L_CLK0, L_CLK1, L_GX, L_AON, L_RCG0, L_RCG1, L_TCM, L_GMU0, L_GMU_LATE, L_RSC, L_RSC_LATE, L_SM0, L_SM1, LINES };
static const struct line_def {
    uint8_t win, first, end, after;
    char head[11];
    uint8_t late;
} lines[LINES] = {
    {WIN_GCC, R_CFGA, R_QMIP, A_NONE, "GCC", 0},
    {WIN_GCC, R_QMIP, R_CXGD, A_NONE, "GCC", 0},
    {WIN_GPUCC, R_CXGD, R_AHB, A_NONE, "GPUCC", 0},
    {WIN_GPUCC, R_AHB, R_HUB, A_NONE, "GPUCC", 0},
    {WIN_GPUCC, R_HUB, R_GXGD, A_R4, "GPUCC", 0},
    {WIN_GPUCC, R_GXGD, R_CXOA, A_NONE, "GPUCC", 0},
    {WIN_GPUCC, R_CXOA, R_GRC, A_NONE, "GPUCC", 0},
    {WIN_GPUCC, R_GRC, R_XRC, A_NONE, "GPUCC", 0},
    {WIN_GPUCC, R_XRC, R_TCMR, A_NONE, "GPUCC", 0},
    {WIN_CXMISC, R_TCMR, R_GXST, A_NONE, "CXMISC", 0},
    {WIN_GMU, R_GXST, R_RST, A_NONE, "GMU", 0},
    {WIN_GMU, R_RST, R_BSY, A_NONE, "LATE GMU", 1},
    {WIN_RSCC, R_BSY, R_PDCS, A_NONE, "RSCC", 0},
    {WIN_RSCC, R_PDCS, R_ID0, A_NONE, "LATE RSCC", 1},
    {WIN_SMMU, R_ID0, R_SCR0, A_SMMU, "SMMU", 0},
    {WIN_SMMU, R_SCR0, R_COUNT, A_NONE, "SMMU", 0},
};
_Static_assert(sizeof lines[0] == 16, "gpusnap: a line row is 16 bytes");

/* Lines the page may hold at most when every gate is open, by what they are: the header and legend, a NEXT line for each of the six blocks, the lines of the table that are read in snapshot
 * 1, the CX verdict and the SMMU decode, the wait and the two NEXT S2 lines, the late lines (a NEXT LATE line and one line for each of the two blocks with words Linux never reads) and the
 * closing two. The drift list takes what is left of the lines before the late ones. */
#define HEADER_LINES 2u
#define NEXT_LINES WINDOWS
#define LATE_TABLE_LINES 2u             /* the two late lines of the table: GMU and RSCC */
#define TABLE_LINES (LINES - LATE_TABLE_LINES)
#define EXTRA_LINES 2u                  /* the R4 line and the SMMU decode line */
#define S2_NEXT_LINES 3u                /* NEXT WAIT, NEXT S2 GCC, NEXT S2 GPUCC */
/* Loads: snapshot 1 reads every row but the four late ones once, snapshot 2 the GCC and GPUCC rows again, the late phase the four rows Linux never reads. */
#define LATE_LOADS 4u
#define S1_LOADS (R_COUNT - LATE_LOADS)
#define S2_LOADS (R_TCMR)
