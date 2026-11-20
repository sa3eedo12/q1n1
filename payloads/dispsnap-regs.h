/* SPDX-License-Identifier: MIT */
/* Registers, budgets and the read table of the payload "dispsnap" (payloads/dispsnap.c; docs/SP11-PAYLOAD-DISPSNAP.md has the file:line of every row, the page and what each
 * outcome would mean). It reads, and only reads, the registers the display study of the Snapintosh tree lists for the question "is the display pipeline the firmware left running
 * still active?" (docs/SP11-DISPLAY-STUDY.md section 8, judged by compat/display-pipeline-check.c). Definitions only.
 * Evidence: VERIFIED is a pinned Linux file at 7475ea8b58616b33c04afb976cf0fbaad9dd63fb (hamoa.dtsi, dispcc-x1e80100.c, gcc-x1e80100.c, common.c, gdsc.c, clk-branch.h,
 * dpu_9_2_x1e80100.h, dpu_hw_intf.c, dpu_hw_ctl.c, msm_mdss.c); it never says what the unit does. Nothing here was ever read on the unit by this payload (EXPERIMENTAL), and
 * whether the unit's EL2 stage-1 map reaches the MDSS, DPU and dispcc pages is UNKNOWN. No register below is a clear-on-read or FIFO register (the document names what was left out
 * for that reason). The table holds no pointer: a pointer in .rodata would need a load-address relocation, which the payload's link check refuses. Every table has a power-of-two
 * row size, so that indexing it is a shift and the binary check of tools/sp11_payload_memcheck.py can follow it. */
#pragma once
#include <stdint.h>

/* Budgets. The ABI allows 40 lines and 4096 loads per call; 34 lines keep a chain with an xHCI payload inside the panel's rows with six to spare (the arithmetic is in
 * docs/SP11-PAYLOAD-DISPSNAP.md, as for gpusnap). The host test builds with smaller caps too, to see what happens when they run out. */
#if !defined(DISPSNAP_LINE_CAP) && !defined(DISPSNAP_LOAD_CAP)
#define DISPSNAP_SHIPPED_CAPS 1
#endif
#ifndef DISPSNAP_LINE_CAP
#define DISPSNAP_LINE_CAP 34u
#endif
#ifndef DISPSNAP_LOAD_CAP
#define DISPSNAP_LOAD_CAP 48u
#endif
#define LINE_CAP DISPSNAP_LINE_CAP
#define LOAD_CAP DISPSNAP_LOAD_CAP
#define CLOSING_LINES 2u                /* the drift summary and the end line are never crowded out by the lines before them */
#define GAP_S 8u                        /* the one wait, between the two snapshots */
#define COUNTER_HZ_DEFAULT 19200000u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u
#define COUNTER_STUCK_READS 2000000u
/* The wait reads the counter until the gap has passed; a counter that stands still or runs backwards ends it (S2 SKIPPED NO_COUNTER). This bound is for a counter that moves but never gets
 * there (one that jitters, or runs far slower than CNTFRQ_EL0 says): 2^32-1 reads is minutes of the real loop, so a wait that has the counter it says it has never meets it, and a bound that
 * is hit says so with its own token (S2 SKIPPED SPIN). The host test builds with a small bound to make the difference testable. */
#ifndef DISPSNAP_SPIN_MAX
#define DISPSNAP_SPIN_MAX 0xffffffffu
#endif
#define SPIN_MAX DISPSNAP_SPIN_MAX

/* The only device addresses this payload reads (hamoa.dtsi, VERIFIED: gcc dt:758-760, dispcc dt:6022-6026, mdss dt:5553-5557, the DPU "mdp" region dt:5589-5593). The INTF_5 page and the six
 * CTL pages lie inside the DPU window, which is therefore one window: the first abort in it ends every later read of it. The eDP controller, its PHY, the DPU's VBIF, the interrupt blocks and
 * every pipe, mixer and SMMU register are not here and are never read. */
enum { WIN_GCC, WIN_DISPCC, WIN_MDSS, WIN_DPU, WINDOWS };
static const struct {
    uint64_t base;
    uint32_t size, pad;
} windows[WINDOWS] = {{0x00100000u, 0x200000u, 0}, {0x0af00000u, 0x20000u, 0}, {0x0ae00000u, 0x01000u, 0}, {0x0ae01000u, 0x8f000u, 0}};
static const char window_name[WINDOWS][8] = {"GCC", "DISPCC", "MDSS", "DPU"};
_Static_assert(sizeof windows[0] == 16, "dispsnap: a window row is 16 bytes");

/* The geometry of the DPU window: the eDP controller's interface is INTF_5 (dpu_9_2_x1e80100.h:350-356, hamoa.dtsi:5633-5639), its registers start 0x39000 into the window; the six CTL paths
 * start 0x15000 into it, 0x1000 apart (dpu_9_2_x1e80100.h:28-54), and each path's CTL_INTF_ACTIVE sits 0xf4 into its page (dpu_hw_ctl.c:35). The page prints these numbers on its MAP
 * lines, so that the host side computes every address from what the loads used. */
#define INTF_INDEX 5u
#define INTF_PAGE_OFF 0x39000u
#define CTL_FIRST_OFF 0x15000u
#define CTL_STEP 0x1000u
#define CTL_COUNT 6u
#define CTL_INTF_ACTIVE_OFF 0x0f4u
#define INTF(reg) (INTF_PAGE_OFF + (reg))
#define CTL(n) (CTL_FIRST_OFF + CTL_STEP * (n) + CTL_INTF_ACTIVE_OFF)

/* Register offsets, each named after the Linux symbol that gives it. GCC: gcc-x1e80100.c:7447 (the critical-list entry; it has no clock struct). DISPCC: the GDSC gdscr is dispcc-x1e80100.c:1513, the
 * MDSS AHB branch's halt and enable register :793, the MDP branch's :1333. MDSS: the hardware version is the first register of the MDSS block (msm_mdss.c:283, REG_MDSS_HW_VERSION; the
 * header that defines the offset is generated and not pinned: INFERRED 0, as the study says). INTF: dpu_hw_intf.c:17-75. */
#define GCC_DISP_AHB_CBCR 0x27004u
#define DISPCC_MDSS_GDSCR 0x9000u
#define DISPCC_MDSS_AHB_CBCR 0x80a8u
#define DISPCC_MDSS_MDP_CBCR 0x800cu
#define MDSS_HW_VERSION 0x000u
#define INTF_TIMING_ENGINE_EN 0x000u
#define INTF_CONFIG 0x004u
#define INTF_HSYNC_CTL 0x008u
#define INTF_VSYNC_PERIOD_F0 0x00cu
#define INTF_DISPLAY_V_START_F0 0x01cu
#define INTF_DISPLAY_V_END_F0 0x024u
#define INTF_ACTIVE_V_START_F0 0x02cu
#define INTF_ACTIVE_V_END_F0 0x034u
#define INTF_DISPLAY_HCTL 0x03cu
#define INTF_ACTIVE_HCTL 0x040u
#define INTF_CONFIG2 0x060u
#define INTF_FRAME_LINE_COUNT_EN 0x0a8u
#define INTF_FRAME_COUNT 0x0acu
#define INTF_STATUS 0x26cu

/* What a CBCR says (clk-branch.h:63-71): CLK_OFF bit 31, NOC_FSM_STATUS bits 30:28 (ON is 2 once shifted down), CLK_ENABLE bit 0. None of the three clocks on the list has a hardware gating bit
 * or skips its halt check (dispcc-x1e80100.c:792-808, 1332-1348: BRANCH_HALT, no hwcg), so the exemptions gpusnap needs for some of its clocks do not exist here. */
#define CBCR_CLK_OFF_BIT 31u
#define CBCR_ENABLE_BIT 0u
#define CBCR_FSM_SHIFT 28u
#define CBCR_FSM_MASK 7u
#define CBCR_FSM_ON 2u
/* The MDSS GDSC (dispcc-x1e80100.c:1512-1522, gdsc.c:21-27, 61-91): PWR_ON is bit 31 of its own GDSCR (it has no separate status register), SW_COLLAPSE bit 0, HW_CONTROL bit 1. The domain is
 * declared with HW_CTRL, so the hardware may be in charge of it. */
#define GDSC_PWR_ON_BIT 31u
#define GDSC_SW_COLLAPSE_BIT 0u
#define GDSC_HW_CONTROL_BIT 1u
/* HW_VERSION: major 31:28, minor 27:16 (msm_mdss.c:241-244). */
#define VER_MAJOR_SHIFT 28u
#define VER_MAJOR_MASK 0xfu
#define VER_MINOR_SHIFT 16u
#define VER_MINOR_MASK 0xfffu

/* The two clocks of the display gate, one bit each in the CLK mask of the DG line: the MDSS AHB branch (the register clock) and the MDP branch, which register access to the MDSS and the DPU
 * needs (msm_mdss.c:276-283). */
#define GATE_CLOCKS 2u

/* The display gate's verdict. DX_UNK is the zero value on purpose: a context that nobody initialised, or that a later edit forgets to set, is closed and never open. */
enum { DX_UNK, DX_OFF, DX_HWCTL, DX_PART, DX_ON, DX_STATES };
static const char disp_name[DX_STATES][8] = {"UNK", "OFF", "HWCTL", "PART", "ON"};
/* Why a block is not read. DAHB and VER say that a word was READ and does not allow it; DAHBERR and VERERR say that a word the gate needed could not be read (an abort, a skip or all ones),
 * which is a different statement: a failed gate read is never reported as the thing it gates on. The four DISP reasons follow the four verdicts that close a gate in the same order (DX_UNK,
 * DX_OFF, DX_HWCTL, DX_PART), so that gate_reason() and s2_dpu_reason() add the verdict to RS_DISP_UNK. */
enum { RS_OPEN, RS_DISP_UNK, RS_DISP_OFF, RS_DISP_HWCTL, RS_DISP_PART, RS_DAHB, RS_DAHB_ERR, RS_VER, RS_VER_ERR, REASONS };
static const char reason_name[REASONS][16] = {"", "DISP=UNK", "DISP=OFF", "DISP=HWCTL", "DISP=PART", "DAHB", "DAHBERR", "VER", "VERERR"};
_Static_assert(RS_DISP_OFF - RS_DISP_UNK == DX_OFF - DX_UNK && RS_DISP_HWCTL - RS_DISP_UNK == DX_HWCTL - DX_UNK && RS_DISP_PART - RS_DISP_UNK == DX_PART - DX_UNK,
               "dispsnap: the DISP reasons are in the order of the display verdicts");

/* A row's flags: F_NEEDS_FLC the word is read only if INTF_FRAME_LINE_COUNT_EN was read, is not all ones and is not zero, because the frame counter only counts when that register says so (the
 * study's S8; Linux writes 3 to it, dpu_hw_intf.c:257, and the firmware may not). */
enum { F_NEEDS_FLC = 1 };
/* How a value is decoded. D_CBCR: .OFF when bit 31 (CLK_OFF) is set, .ON when it is clear and CLK_ENABLE (bit 0) is set; .ODD where that cannot be taken at its word (all ones; CLK_OFF clear with
 * CLK_ENABLE clear, which is what a window of zeros reads; CLK_OFF with an NoC FSM status of ON). D_GDSCR: .ON when bit 31 (PWR_ON) is set, .OFF when it is clear, .ODD for all ones, and the
 * SW_COLLAPSE and HW_CONTROL bits as fields of their own. D_VER: the major and minor fields. A bit field cut from a word of all ones prints ODD. */
enum { D_NONE, D_CBCR, D_GDSCR, D_VER };

struct reg {
    uint8_t win, dec, flags, pad;
    uint32_t off;
    char key[8];
};
_Static_assert(sizeof(struct reg) == 16, "dispsnap: a register row is 16 bytes");

enum {
    /* GCC, always on: the display register clock first (Linux enables it by a read-modify-write, common.c:317-318, so it is the word Linux reads in this block). */
    R_DAHB,
    /* DISPCC: the gate's inputs, the GDSC first (Linux reads GDSCR, gdsc.c:127-141), then the two clocks. */
    R_GDSC, R_AHBC, R_MDPC,
    /* MDSS: the hardware version, which Linux reads first (msm_mdss.c:283). */
    R_VER,
    /* DPU, INTF_5: the words Linux reads first (STATUS, CONFIG, CONFIG2), then the enable and the study's timing words, then the counter's enable and the counter. */
    R_ST, R_EN, R_CFG, R_CFG2,
    R_HS, R_VP, R_DVS, R_DVE, R_AVS, R_AVE, R_DHC, R_AHC,
    R_FLC, R_FRA,
    /* DPU, CTL_0 to CTL_5: CTL_INTF_ACTIVE, one bit for each interface (hc:592, 700). */
    R_C0, R_C1, R_C2, R_C3, R_C4, R_C5,
    R_COUNT
};
_Static_assert(R_C5 - R_C0 + 1 == CTL_COUNT, "dispsnap: one row for each CTL path");

#define ROW(win, off, dec, flags, key) {win, dec, flags, 0, off, key}
static const struct reg regs[R_COUNT] = {
    ROW(WIN_GCC, GCC_DISP_AHB_CBCR, D_CBCR, 0, "DAHB"),
    ROW(WIN_DISPCC, DISPCC_MDSS_GDSCR, D_GDSCR, 0, "GDSC"),
    ROW(WIN_DISPCC, DISPCC_MDSS_AHB_CBCR, D_CBCR, 0, "AHBC"),
    ROW(WIN_DISPCC, DISPCC_MDSS_MDP_CBCR, D_CBCR, 0, "MDPC"),
    ROW(WIN_MDSS, MDSS_HW_VERSION, D_VER, 0, "VER"),
    ROW(WIN_DPU, INTF(INTF_STATUS), D_NONE, 0, "ST"),
    ROW(WIN_DPU, INTF(INTF_TIMING_ENGINE_EN), D_NONE, 0, "EN"),
    ROW(WIN_DPU, INTF(INTF_CONFIG), D_NONE, 0, "CFG"),
    ROW(WIN_DPU, INTF(INTF_CONFIG2), D_NONE, 0, "CFG2"),
    ROW(WIN_DPU, INTF(INTF_HSYNC_CTL), D_NONE, 0, "HS"),
    ROW(WIN_DPU, INTF(INTF_VSYNC_PERIOD_F0), D_NONE, 0, "VP"),
    ROW(WIN_DPU, INTF(INTF_DISPLAY_V_START_F0), D_NONE, 0, "DVS"),
    ROW(WIN_DPU, INTF(INTF_DISPLAY_V_END_F0), D_NONE, 0, "DVE"),
    ROW(WIN_DPU, INTF(INTF_ACTIVE_V_START_F0), D_NONE, 0, "AVS"),
    ROW(WIN_DPU, INTF(INTF_ACTIVE_V_END_F0), D_NONE, 0, "AVE"),
    ROW(WIN_DPU, INTF(INTF_DISPLAY_HCTL), D_NONE, 0, "DHC"),
    ROW(WIN_DPU, INTF(INTF_ACTIVE_HCTL), D_NONE, 0, "AHC"),
    ROW(WIN_DPU, INTF(INTF_FRAME_LINE_COUNT_EN), D_NONE, 0, "FLC"),
    ROW(WIN_DPU, INTF(INTF_FRAME_COUNT), D_NONE, F_NEEDS_FLC, "FRA"),
    ROW(WIN_DPU, CTL(0), D_NONE, 0, "C0"),
    ROW(WIN_DPU, CTL(1), D_NONE, 0, "C1"),
    ROW(WIN_DPU, CTL(2), D_NONE, 0, "C2"),
    ROW(WIN_DPU, CTL(3), D_NONE, 0, "C3"),
    ROW(WIN_DPU, CTL(4), D_NONE, 0, "C4"),
    ROW(WIN_DPU, CTL(5), D_NONE, 0, "C5"),
};
_Static_assert(sizeof regs / sizeof regs[0] == R_COUNT, "dispsnap: one row per register");

/* The lines of the page, in reading order: a line is read whole and printed before the first load of the next, so that a hang keeps every line before the one it hit. A line holds at most
 * four fields and its widest possible text (eight-digit values with a token) is 99 characters, so that no field is ever cut; the host test's wide fixture shows it. `after`: A_DG prints the
 * display gate's verdict as soon as its inputs have gone out. */
enum { A_NONE, A_DG };
enum { L_GCC, L_DISP0, L_DISP1, L_MDSS, L_INTF0, L_INTF1, L_INTF2, L_INTF3, L_CTL0, L_CTL1, LINES };
static const struct line_def {
    uint8_t win, first, end, after;
    char head[12];
} lines[LINES] = {
    {WIN_GCC, R_DAHB, R_GDSC, A_NONE, "GCC"},
    {WIN_DISPCC, R_GDSC, R_AHBC, A_NONE, "DISPCC"},
    {WIN_DISPCC, R_AHBC, R_VER, A_DG, "DISPCC"},
    {WIN_MDSS, R_VER, R_ST, A_NONE, "MDSS"},
    {WIN_DPU, R_ST, R_HS, A_NONE, "INTF"},
    {WIN_DPU, R_HS, R_AVS, A_NONE, "INTF"},
    {WIN_DPU, R_AVS, R_FLC, A_NONE, "INTF"},
    {WIN_DPU, R_FLC, R_C0, A_NONE, "INTF"},
    {WIN_DPU, R_C0, R_C3, A_NONE, "CTL"},
    {WIN_DPU, R_C3, R_COUNT, A_NONE, "CTL"},
};
_Static_assert(sizeof lines[0] == 16, "dispsnap: a line row is 16 bytes");

/* Lines the page may hold at most when every gate is open, by what they are: the header, the legend, the GOP line and the two MAP lines, a NEXT line for each of the four blocks, the lines of
 * the table, the display gate's verdict, the wait and the three NEXT S2 lines, the S2 result line, and the closing two (the drift summary and the end line). The drift list takes what is left. */
#define HEADER_LINES 5u
#define NEXT_LINES WINDOWS
#define TABLE_LINES LINES
#define EXTRA_LINES 1u                  /* the DG line */
#define S2_NEXT_LINES 4u                /* NEXT WAIT, NEXT S2 GCC, NEXT S2 DISPCC, NEXT S2 DPU */
#define S2_RESULT_LINES 1u              /* S2 DPU: what the second look at the interface said */
/* Loads: snapshot 1 reads every row once (the frame counter only after its enable says it counts), snapshot 2 the display register clock, the three gate words, the interface's STATUS and
 * enable, and the frame counter again. */
#define S1_LOADS R_COUNT
#define S2_LOADS 7u
