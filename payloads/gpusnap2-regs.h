/* SPDX-License-Identifier: MIT */
/* Registers, budgets and the read tables of the payload "gpusnap2" (payloads/gpusnap2.c; docs/SP11-PAYLOAD-GPUSNAP2.md has the file:line of every row, the page and what each outcome
 * would mean). It is experiment E1 of the GPU port plan (the read-only complement of gpusnap, docs/SP11-GPU-PORT-PLAN.md of the Snapintosh tree and its v2): do the rails and the PLLs
 * already hold what a GPU power-on needs, and what is the thermal and speed-bin baseline. Definitions only.
 * Evidence: VERIFIED is a pinned Linux file at 7475ea8b58616b33c04afb976cf0fbaad9dd63fb (hamoa.dtsi, gpucc-x1e80100.c, clk-alpha-pll.c, clk-branch.h, gdsc.c, cmd-db.c, cmd-db.h,
 * rpmh-rsc.c, rpmh-internal.h, qfprom.c, tsens-v2.c, a7xx_catalog.c, a6xx_gmu.c); it never says what the unit does. Nothing here was ever read on the unit by this payload
 * (EXPERIMENTAL), and the reads of the command database, the apps RSC and the QFPROM have never been made on it at all (UNKNOWN whether any aborts, hangs or raises an SError). The tables
 * hold no pointer: a pointer in .rodata would need a load-address relocation, which the payload's link check refuses. Every table has a power-of-two row size, so that indexing it is a
 * shift and the binary check of tools/sp11_payload_memcheck.py can follow it. */
#pragma once
#include <stdint.h>

/* Budgets. The ABI allows 40 lines and 4096 loads per call. The page is at most 34 lines so that it fits the panel's region alone in its boot (boot 29's film showed 73 rows drawn; alone the page needs 39
 * rows). The loads are bounded by what each block can need at most, and LOADS_MAX adds the bounds up (a static assertion below keeps it under the cap): the memory map (four words of each
 * of MAP_DESC_MAX descriptors and two of each descriptor that overlaps the command database), the command database (version and magic, the resource headers, the entries scanned and
 * two more words of each target found), the RSC and the other blocks. The host test builds with smaller caps too, to see what happens when they run out. */
#if !defined(GPUSNAP2_LINE_CAP) && !defined(GPUSNAP2_LOAD_CAP)
#define GPUSNAP2_SHIPPED_CAPS 1
#endif
#ifndef GPUSNAP2_LINE_CAP
#define GPUSNAP2_LINE_CAP 34u
#endif
#ifndef GPUSNAP2_LOAD_CAP
#define GPUSNAP2_LOAD_CAP 2048u
#endif
#define LINE_CAP GPUSNAP2_LINE_CAP
#define LOAD_CAP GPUSNAP2_LOAD_CAP
#define CLOSING_LINES 1u                /* the end line is never crowded out by the lines before it */

/* The windows (hamoa.dtsi, VERIFIED: gcc dt:758-762, tsens3 dt:2804-2814, gpucc dt:4225-4234, cmd-db dt:516-520, apps_rsc drv-2 dt:8599-8613, qfprom dt:8808-8817); the last one is the final
 * UEFI memory map the runner passes, whose base and size are the arguments' and are filled in at the start. The first abort in a window ends every later read of it. The command database
 * is DRAM and the memory map is RAM: both are read through the same guarded load as the registers, never through a pointer. */
enum { WIN_TSROT, WIN_TTM, WIN_GCC, WIN_GPUCC, WIN_CMDDB, WIN_RSC, WIN_QFPROM, WIN_MAP, WINDOWS };
struct window {
    uint64_t base;
    uint32_t size, pad;
};
_Static_assert(sizeof(struct window) == 16, "gpusnap2: a window row is 16 bytes");
#define CMDDB_BYTES 0x20000u            /* the size of the database's reserved region (hamoa.dtsi:516-520) */
static const struct window windows[WIN_MAP] = {
    {0x0c225000u, 0x01000u, 0}, {0x0c274000u, 0x01000u, 0}, {0x00100000u, 0x200000u, 0}, {0x03d90000u, 0x0a000u, 0},
    {0x81c60000u, CMDDB_BYTES, 0}, {0x17520000u, 0x10000u, 0}, {0x221c8000u, 0x01000u, 0},
};
static const char window_name[WINDOWS][8] = {"TSROT", "TTM", "GCC", "GPUCC", "CMDDB", "RSC2", "QFPROM", "MAP"};

/* ---- The EFI memory map: the gate of the command database (the rule of the A16 flow, tools/a16gpu.py step_cmd_db: read it only if the final map describes all of it as reserved) ---- */
/* EFI_MEMORY_DESCRIPTOR: Type at +0, PhysicalStart at +8, NumberOfPages at +24, Attribute at +32 (UEFI 2.x); a descriptor is `stride` bytes (48 on the unit's maps, DERIVED). */
#define MAP_TYPE_OFF 0u
#define MAP_PHYS_OFF 8u
#define MAP_PAGES_OFF 24u
#define MAP_ATTR_OFF 32u
#define MAP_STRIDE_MIN 40u
#define MAP_STRIDE_MAX 128u
#define MAP_DESC_MAX 320u               /* the unit's six dumps hold 226 to 231 descriptors */
#define MAP_HITS_MAX 8u                 /* descriptors that may overlap the region: UEFI maps do not overlap, so more than a few is a damaged map */
#define EFI_RESERVED 0u                 /* EfiReservedMemoryType */
#define EFI_PAGE_SHIFT 12u
#define MAP_ADDR_LIMIT (1ull << 48)     /* load32 refuses a physical address beyond 48 bits */
enum { MAP_UNREAD, MAP_OPEN, MAP_NONE, MAP_TYPE, MAP_PART, MAP_BAD, MAP_ERR, MAP_STATES };
static const char map_name[MAP_STATES][8] = {"NA", "OPEN", "NONE", "TYPE", "PART", "BAD", "ERR"};

/* ---- The command database (cmd-db.c:36-80, 101, 144-176; VERIFIED as read there) ---- */
/* struct cmd_db_header: version (+0), magic (+4), eight struct rsc_hdr of 16 bytes from +8 (slv_id | header_offset << 16 at +0 of each, data_offset | cnt << 16 at +4), a checksum and a
 * reserved word, then data[] at +0x90. An entry header is 24 bytes: id[8] (+0, +4), two priorities, addr (+16), len | offset << 16 (+20). The entries of a header start at data + header_offset;
 * the aux data of an entry at data + data_offset + offset. The magic bytes db 30 03 0c read as one little-endian word. */
#define CMDDB_HDR_BYTES 0x90u
#define CMDDB_MAGIC 0x0c0330dbu
#define CMDDB_SLV_MAX 8u
#define CMDDB_RSC_HDR_OFF 0x08u
#define CMDDB_RSC_HDR_BYTES 16u
#define CMDDB_ENTRY_BYTES 24u
#define CMDDB_ENTRY_MAX 128u            /* entries scanned in one header: more than the ARC and BCM lists of an RPMh database usually hold (INFERRED) */
#define CMDDB_SCAN_MAX 256u             /* entries scanned in all headers together */
#define CMDDB_SLV_ARC 3u                /* enum cmd_db_hw_type (cmd-db.h:12-20): the `.lvl` rails are ARC resources, the bus clock managers BCM */
#define CMDDB_SLV_BCM 5u
#define CMDDB_AUX_WORDS (LEVELS_MAX / 2u + 1u)  /* the words of a level table: LEVELS_MAX half words, and one more when the table starts on the upper half of a word */
#define LEVELS_MAX 8u                   /* at most eight level values of a rail are read and printed */

/* What the GPU needs of the database (a6xx_gmu.c:1823-1838, 1894-1910: mx.lvl, gfx.lvl, cx.lvl, gmxc.lvl and gbx.lvl by name; a7xx_catalog.c:398-408: the BCMs SH0, MC0 and ACV of the X1-85). The id
 * is eight bytes, zero padded (cmd-db.c:156): two little-endian words. A target row is 32 bytes; `key` is the name on the page (the rails' `.lvl` suffix left off). */
#define ID4(a, b, c, d) ((uint32_t)(uint8_t)(a) | (uint32_t)(uint8_t)(b) << 8 | (uint32_t)(uint8_t)(c) << 16 | (uint32_t)(uint8_t)(d) << 24)
enum { T_CX, T_MX, T_GFX, T_GMXC, T_GBX, T_SH0, T_MC0, T_ACV, TARGETS };
struct target {
    uint32_t w0, w1;
    uint8_t slv, pad[3];
    char key[8];
    uint32_t pad2[3];
};
_Static_assert(sizeof(struct target) == 32, "gpusnap2: a target row is 32 bytes");
static const struct target targets[TARGETS] = {
    {ID4('c', 'x', '.', 'l'), ID4('v', 'l', 0, 0), CMDDB_SLV_ARC, {0, 0, 0}, "CX", {0, 0, 0}},
    {ID4('m', 'x', '.', 'l'), ID4('v', 'l', 0, 0), CMDDB_SLV_ARC, {0, 0, 0}, "MX", {0, 0, 0}},
    {ID4('g', 'f', 'x', '.'), ID4('l', 'v', 'l', 0), CMDDB_SLV_ARC, {0, 0, 0}, "GFX", {0, 0, 0}},
    {ID4('g', 'm', 'x', 'c'), ID4('.', 'l', 'v', 'l'), CMDDB_SLV_ARC, {0, 0, 0}, "GMXC", {0, 0, 0}},
    {ID4('g', 'b', 'x', '.'), ID4('l', 'v', 'l', 0), CMDDB_SLV_ARC, {0, 0, 0}, "GBX", {0, 0, 0}},
    {ID4('S', 'H', '0', 0), 0, CMDDB_SLV_BCM, {0, 0, 0}, "SH0", {0, 0, 0}},
    {ID4('M', 'C', '0', 0), 0, CMDDB_SLV_BCM, {0, 0, 0}, "MC0", {0, 0, 0}},
    {ID4('A', 'C', 'V', 0), 0, CMDDB_SLV_BCM, {0, 0, 0}, "ACV", {0, 0, 0}},
};
#define RAILS 4u                        /* the first four targets are the rails (T_CX, T_MX, T_GFX, T_GMXC): their level tables are printed and the RSC lines look for their votes */

/* ---- The apps RSC, drv-2 (rpmh-rsc.c:41-93, 158-205, 998-1010, 1088-1124; hamoa.dtsi:8599-8613: tcs-offset 0xd00, drv-id 2, tcs-config 3 active, 2 sleep, 2 wake) ---- */
/* The register layout depends on the version in RSC_DRV_ID: Linux takes the 3.0 table for a major of 3 or more and the 2.7 table for any other (rpmh-rsc.c:1094-1097). This payload is stricter: it
 * knows the majors 2 and 3 and reads nothing of the TCSs for another. The TCS ids follow the order of tcs-config: active 0 to 2, sleep 3 and 4, wake 5 and 6. A TCS is 672 bytes apart from
 * tcs_base = base + 0xd00; the command registers repeat every `cmd_stride`. A TCS's enable word is a 16-bit command mask (rpmh-rsc.c:562-564 reads 16 bits of it), so a word with a bit above 15
 * is not taken at its word (INFERRED: Linux itself never looks above bit 15). */
#define RSC_DRV_ID 0x00u
#define RSC_DRV_SOLVER 0x04u
#define RSC_DRV_CHLD 0x0cu
#define RSC_TCS_BASE 0xd00u
#define RSC_TCS_STRIDE 672u
#define RSC_IRQ_ENABLE 0x00u            /* from tcs_base, both versions (rpmh-rsc.c:162-163, 181-182) */
#define RSC_IRQ_STATUS 0x04u
#define RSC_DRV_NUMBER 2u               /* qcom,drv-id */
#define RSC_TCS_NUM 7u
#define RSC_TCS_ACTIVE 0u
#define RSC_TCS_SLEEP 3u
#define RSC_TCS_WAKE 5u
#define RSC_WAKE_COUNT 2u
#define RSC_CMDS_MAX 16u                /* MAX_CMDS_PER_TCS (rpmh-internal.h:15) */
#define RSC_MAJOR_SHIFT 16u
#define RSC_MINOR_SHIFT 8u
#define RSC_NUM_TCS_SHIFT 6u            /* DRV_PRNT_CHLD_CONFIG: six bits of TCS count for each drv, from bit 0 */
#define RSC_NUM_TCS_MASK 0x3fu
#define RSC_NCPT_SHIFT 27u
#define RSC_NCPT_MASK 0x1fu
struct rsc_layout {
    uint32_t major, enable, addr, data, cmd_stride, pad[3];
};
_Static_assert(sizeof(struct rsc_layout) == 32, "gpusnap2: an RSC layout row is 32 bytes");
static const struct rsc_layout rsc_layouts[2] = {
    {2, 0x1cu, 0x34u, 0x38u, 20u, {0, 0, 0}},      /* rpmh_rsc_reg_offset_ver_2_7 */
    {3, 0x2cu, 0x38u, 0x3cu, 24u, {0, 0, 0}},      /* rpmh_rsc_reg_offset_ver_3_0 */
};

/* ---- The QFPROM speed bin (hamoa.dtsi:8808-8817: cell 0x119, two bytes, bits <7 8>; qfprom.c:337-347 aligns a cell to its word, so the field is bits 22:15 of the word at 0x118;
 * a7xx_catalog.c:411-417 maps the fuse value to the bin) ---- */
#define QFPROM_WORD 0x118u
#define QFPROM_FUSE_SHIFT 15u
#define QFPROM_FUSE_MASK 0xffu
struct speedbin {
    uint8_t fuse, bin;
};
static const struct speedbin speedbins[5] = {{0, 0}, {59, 1}, {7, 2}, {232, 3}, {146, 4}};

/* ---- The thermal sensors of the GPU: tsens3, sensors 5 to 12 (hamoa.dtsi:9664-9880 gpuss-0 to gpuss-7); the registers and the decode are tsnap v1.1's (docs/SP11-PAYLOAD-TSNAP.md) ---- */
#define TS_FIRST 5u
#define TS_COUNT 8u
#define SROT_HW_VER 0x00u
#define SROT_CTRL 0x04u
#define TM_STATUS 0xa0u
#define CTRL_EN 0x1u
#define CTRL_SW_RST 0x2u
#define CTRL_SENSOR_SHIFT 3u
#define CTRL_SENSOR_MASK 0xffffu
#define CTRL_CODE_OR_TEMP (1u << 21)
#define ST_TEMP_MASK 0xfffu
#define ST_CRIT_FLAGS (3u << 19)
#define ST_VALID (1u << 21)
#define ST_ID_SHIFT 22u
#define ST_ID_MASK 0x1fu
#define ST_RESERVED_SHIFT 27u
#define TEMP_MIN_TENTHS (-400)
#define TEMP_MAX_TENTHS 1200

/* ---- The clock words (clk-branch.h:63-71, gdsc.c:21-27, 61-91, clk-alpha-pll.c:16-34, 348-349, 1078-1090) ---- */
#define CBCR_CLK_OFF_BIT 31u
#define CBCR_HW_CTL_BIT 1u
#define CBCR_ENABLE_BIT 0u
#define CBCR_FSM_SHIFT 28u
#define CBCR_FSM_MASK 7u
#define CBCR_FSM_ON 2u
#define GDSC_PWR_ON_BIT 31u
#define GDSC_SW_COLLAPSE_BIT 0u
#define GDSC_HW_CONTROL_BIT 1u
#define PLL_OUTCTRL_BIT 0u              /* PLL_MODE bit 0 */
#define PLL_LOCK_DET_BIT 31u            /* PLL_MODE bit 31 */
#define PLL_RUN_BIT 0u                  /* PLL_OPMODE bit 0 (PLL_RUN is 1, PLL_STANDBY 0) */
#define RCG_SRC_SHIFT 8u                /* clk-rcg2.c:38-39: CFG_REG source select 10:8 */
#define RCG_SRC_MASK 7u

/* A row's decode. D_CBCR: .OFF when bit 31 (CLK_OFF) is set, .ON when it is clear and CLK_ENABLE (bit 0) is set, .ODD where that cannot be taken at its word (all ones; CLK_OFF clear with
 * CLK_ENABLE clear, which is what a window of zeros reads; CLK_OFF with an NoC FSM status of ON). D_PWR: .ON when bit 31 is set (a GDSC's PWR_ON), .OFF when clear, .ODD for all ones.
 * D_GDSCR: the raw word and its SW_COLLAPSE and HW_CONTROL bits as fields. D_RCGCMD: ROOT_OFF as .ON/.OFF, .ODD for all ones. D_RCGCFG: the raw word and its source select. D_PLLMODE: the raw word
 * and, after the line's last word, a verdict for the PLL: ON when OPMODE has RUN and MODE has OUTCTRL (trion_pll_is_enabled, which both PLLs' ops use), OFF when both were read and say
 * otherwise, ODD for an all-ones word, NA when a word was not read. A bit field cut from a word of all ones prints ODD. */
enum { D_NONE, D_CBCR, D_PWR, D_GDSCR, D_RCGCMD, D_RCGCFG, D_PLLMODE, D_PLLOP };

struct reg {
    uint8_t win, dec, pad[2];
    uint32_t off;
    char key[8];
};
_Static_assert(sizeof(struct reg) == 16, "gpusnap2: a register row is 16 bytes");

/* The rows, in reading order. GCC: the one word GPUCC needs (Linux sets its enable bit at probe, gcc-x1e80100.c:7451 and common.c:310-320, and boot 30 read it: the unit answered). GPUCC: first the three words
 * boot 30 read and the unit answered (the first load of the block is one that is known to answer, and they say whether CX is still off), then what that run did not read: the two PLLs
 * (clk-alpha-pll.c:187-202 and 302-316 give the offsets of the lucid-ole and zonda-ole layouts the driver picks, gpucc-x1e80100.c:56-102), the fast-forward RCG, the two read-only
 * dividers and the branch clocks (gpucc-x1e80100.c:256-530) and the critical CB clock (:612-614). Not read: the GX-side clocks gx_vsense and mnd1x_0/1 (their domain is not shown to be up),
 * every GPUCC word above 0x9988 and everything in the blocks behind CX (CX_MISC, GMU, RSCC, the GPU SMMU). */
enum {
    R_CFGA,
    R_AHB, R_CXGD, R_CXHW,
    R_P0MODE, R_P0OP, R_P0L, R_P0AL,
    R_P1MODE, R_P1OP, R_P1L, R_P1AL,
    R_FFC, R_FFF, R_XDIV, R_DDIV,
    R_CRC, R_CXFF, R_FM,
    R_MEM, R_SLP, R_CB,
    R_COUNT
};
#define ROW(win, off, dec, key) {win, dec, {0, 0}, off, key}
static const struct reg regs[R_COUNT] = {
    ROW(WIN_GCC, 0x71004, D_CBCR, "CFGA"),
    ROW(WIN_GPUCC, 0x911c, D_CBCR, "AHB"), ROW(WIN_GPUCC, 0x9108, D_GDSCR, "CXGD"), ROW(WIN_GPUCC, 0x953c, D_PWR, "CXHW"),
    ROW(WIN_GPUCC, 0x0000, D_PLLMODE, "MODE"), ROW(WIN_GPUCC, 0x0030, D_PLLOP, "OP"), ROW(WIN_GPUCC, 0x0004, D_NONE, "L"), ROW(WIN_GPUCC, 0x0008, D_NONE, "AL"),
    ROW(WIN_GPUCC, 0x1000, D_PLLMODE, "MODE"), ROW(WIN_GPUCC, 0x1004, D_PLLOP, "OP"), ROW(WIN_GPUCC, 0x1010, D_NONE, "L"), ROW(WIN_GPUCC, 0x1014, D_NONE, "AL"),
    ROW(WIN_GPUCC, 0x9474, D_RCGCMD, "FFC"), ROW(WIN_GPUCC, 0x9478, D_RCGCFG, "FFF"), ROW(WIN_GPUCC, 0x9050, D_NONE, "XDIV"), ROW(WIN_GPUCC, 0x9054, D_NONE, "DDIV"),
    ROW(WIN_GPUCC, 0x9120, D_CBCR, "CRC"), ROW(WIN_GPUCC, 0x914c, D_CBCR, "CXFF"), ROW(WIN_GPUCC, 0x9008, D_CBCR, "FM"),
    ROW(WIN_GPUCC, 0x9150, D_CBCR, "MEM"), ROW(WIN_GPUCC, 0x9134, D_CBCR, "SLP"), ROW(WIN_GPUCC, 0x93a4, D_CBCR, "CB"),
};
_Static_assert(sizeof regs / sizeof regs[0] == R_COUNT, "gpusnap2: one row per register");

/* The lines of the table, in reading order: a line is read whole and printed before the first load of the next, so that a hang keeps every line before the one it hit. `head` is what the
 * line is called on the page; `pll` is 1 for the first and 2 for the second PLL's line, which ends in the PLL's verdict. A line holds at most four fields. */
enum { L_GCC, L_CTX, L_PLL0, L_PLL1, L_RCG, L_BR0, L_BR1, LINES };
static const struct line_def {
    uint8_t win, first, end, pll;
    char head[12];
} lines[LINES] = {
    {WIN_GCC, R_CFGA, R_AHB, 0, "GCC"},
    {WIN_GPUCC, R_AHB, R_P0MODE, 0, "GPUCC"},
    {WIN_GPUCC, R_P0MODE, R_P1MODE, 1, "GPUCC PLL0"},
    {WIN_GPUCC, R_P1MODE, R_FFC, 2, "GPUCC PLL1"},
    {WIN_GPUCC, R_FFC, R_CRC, 0, "GPUCC"},
    {WIN_GPUCC, R_CRC, R_MEM, 0, "GPUCC"},
    {WIN_GPUCC, R_MEM, R_COUNT, 0, "GPUCC"},
};
_Static_assert(sizeof lines[0] == 16, "gpusnap2: a line row is 16 bytes");

/* Why a block is not read. AHB says that the CFG AHB clock was READ and does not run; AHBERR that it could not be read (an abort, a skip or all ones), which is a different statement: a
 * failed gate read is never reported as the thing it gates on. MAP says that the memory map does not prove the command database to be reserved memory (the map line says which way); MAGIC
 * that the database's header word is not the magic Linux checks (cmd-db.c:101-108); ID that the RSC's ID word was not read or is not one (zero, all ones); VER that its major is not one of the
 * two layouts this payload knows; TCS that its configuration word gives drv-2 fewer TCSs than the seven the device tree names. */
enum { RS_OPEN, RS_AHB, RS_AHB_ERR, RS_MAP, RS_MAGIC, RS_ID, RS_VER, RS_TCS, REASONS };
static const char reason_name[REASONS][8] = {"", "AHB", "AHBERR", "MAP", "MAGIC", "ID", "VER", "TCS"};

/* The page, by what it holds when every gate is open: the header and the legend, the blocks (a NEXT line and the lines of the table or of the block), the closing line. */
#define HEADER_LINES 2u
#define TSENS_LINES 4u                  /* NEXT TSENS3, identity, raw words, cells */
#define GCC_LINES 2u                    /* NEXT GCC and the CFG AHB word */
#define GPUCC_LINES (1u + LINES - 1u)   /* NEXT GPUCC and the six lines of the table that are GPUCC's */
#define CMDDB_LINES 7u                  /* NEXT, MAP, HDR, ADDR, BCM and two LVL lines */
#define RSC_LINES 6u                    /* NEXT, ID, CFG, EN and one line for each wake TCS */
#define QFPROM_LINES 2u
#define PAGE_LINES (HEADER_LINES + TSENS_LINES + GCC_LINES + GPUCC_LINES + CMDDB_LINES + RSC_LINES + QFPROM_LINES + CLOSING_LINES)

/* The most loads each block can make, whatever the memory holds. TSENS: the two identity words and the eight status words. GCC: one. GPUCC: the table's rows but the GCC one. MAP: four words of
 * every descriptor and the type and attribute of each of the MAP_HITS_MAX that may overlap the region. CMDDB: version, magic and the two words of each resource header; per entry its first
 * id word and, if that matches a target, its second; the two words (address, length and offset) of each target found; the words of the level tables. RSC: the five words of the
 * identity and configuration lines, the seven enable words, the address of every enabled command of the two wake TCSs and the data word of each that is a rail's. QFPROM: one. */
#define LOADS_TSENS (2u + TS_COUNT)
#define LOADS_GCC 1u
#define LOADS_GPUCC (R_COUNT - 1u)
#define LOADS_MAP (4u * MAP_DESC_MAX + 2u * MAP_HITS_MAX)
#define LOADS_CMDDB (2u + 2u * CMDDB_SLV_MAX + 2u * CMDDB_SCAN_MAX + 2u * TARGETS + RAILS * CMDDB_AUX_WORDS)
#define LOADS_RSC (5u + RSC_TCS_NUM + 2u * RSC_WAKE_COUNT * RSC_CMDS_MAX)
#define LOADS_QFPROM 1u
#define LOADS_MAX (LOADS_TSENS + LOADS_GCC + LOADS_GPUCC + LOADS_MAP + LOADS_CMDDB + LOADS_RSC + LOADS_QFPROM)
#ifdef GPUSNAP2_SHIPPED_CAPS
_Static_assert(PAGE_LINES <= LINE_CAP, "gpusnap2: the page with every gate open fits the line cap");
_Static_assert(LOADS_MAX <= LOAD_CAP, "gpusnap2: the loads every block can make fit the load cap");
#endif
