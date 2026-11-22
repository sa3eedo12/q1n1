/* SPDX-License-Identifier: MIT */
/* Registers, budgets and tables of the payload "tsnap" (payloads/tsnap.c; docs/SP11-PAYLOAD-TSNAP.md has the page, the file:line of every row and what each label
 * means). Definitions only. Evidence: VERIFIED is a pinned source (hamoa.dtsi of the Snapintosh refs; drivers/thermal/qcom/tsens-v2.c, tsens.c and tsens.h of Linux
 * v7.4-rc2, which the document pins); nothing here was ever read on the unit (EXPERIMENTAL, hardware NOT RUN). The tables hold no pointer: a pointer in .rodata
 * would need a load-address relocation, which the payload's link check refuses. */
#pragma once
#include <stdint.h>

/* Budgets. The ABI allows 40 lines and 4096 loads per call; this payload keeps to 34 lines so that it can run ahead of a 40-line payload (an xHCI one) in a chain
 * and stay inside the 89 rows of the panel's region (docs/SP11-PAYLOAD-TSNAP.md has the arithmetic). The host test builds with smaller caps too, to see what
 * happens when they run out. */
#if !defined(TSNAP_LINE_CAP) && !defined(TSNAP_LOAD_CAP) && !defined(TSNAP_SPIN_MAX) && !defined(TSNAP_STUCK_READS)
#define TSNAP_SHIPPED_CAPS 1
#endif
#ifndef TSNAP_LINE_CAP
#define TSNAP_LINE_CAP 34u
#endif
#ifndef TSNAP_LOAD_CAP
#define TSNAP_LOAD_CAP 256u
#endif
/* The wait is the one the page announced or none. A counter that does not move or runs backwards ends it early (S2 SKIPPED NO_COUNTER: STUCK_READS identical reads in a row, or a
 * value below the start). A counter that moves but has not spanned the wait after this many reads ends it as S2 SKIPPED SPIN. A 2 s wait takes 2 s / t reads of t each, so the bound is
 * only reached by a counter far slower than CNTFRQ_EL0 says, or by reads implausibly fast: even t = 1 ns needs 2 * 10^9 reads, less than half of 2^32 - 1. */
#ifndef TSNAP_SPIN_MAX
#define TSNAP_SPIN_MAX 0xffffffffu
#endif
#ifndef TSNAP_STUCK_READS
#define TSNAP_STUCK_READS 2000000u
#endif
#define LINE_CAP TSNAP_LINE_CAP
#define LOAD_CAP TSNAP_LOAD_CAP
#define SPIN_MAX TSNAP_SPIN_MAX
#define STUCK_READS TSNAP_STUCK_READS
#define GAP_S 2u
#define COUNTER_HZ_DEFAULT 19200000u
#define COUNTER_HZ_MIN 1000000u
#define COUNTER_HZ_MAX 1000000000u

/* The four controllers and their sixteen sensor ids each: tsens0..tsens3, `#qcom,sensors = <16>` (hamoa.dtsi:2759-2817, VERIFIED; tsens-v2.c:56 max_sensors 16).
 * The Linux driver numbers the sensors 0..15 (tsens.c:1424). 50 of the 64 are read by a DT thermal zone (hamoa.dtsi:9123-9915); the rest may be unpopulated. */
#define INSTANCES 4u
#define SENSORS 16u
#define WINDOW_SIZE 0x1000u

/* Every window is 0x1000 bytes: the SROT of tsens0..3 at 0x0c222000 + n * 0x1000 and the TM at 0x0c271000 + n * 0x1000, the `reg` pairs of
 * hamoa.dtsi:2761-2762, 2776-2777, 2791-2792, 2806-2807 (VERIFIED). That the unit has the same windows is INFERRED: none of its ACPI tables holds them, and whether its
 * EL2 stage-1 map reaches them is UNKNOWN (a miss is a guarded FAULT:6). Windows 0..3 are SROT, 4..7 TM, so that a dead window is one bit of a byte. The row is 4 bytes: a
 * power of two, so that indexing it is a shift and the binary check of tools/sp11_payload_memcheck.py can follow it. */
enum { WIN_SROT0, WIN_SROT1, WIN_SROT2, WIN_SROT3, WIN_TM0, WIN_TM1, WIN_TM2, WIN_TM3, WINDOWS };
#define WIN_SROT(n) (n)
#define WIN_TM(n) (INSTANCES + (n))
static const uint32_t window_base[WINDOWS] = {0x0c222000u, 0x0c223000u, 0x0c224000u, 0x0c225000u, 0x0c271000u, 0x0c272000u, 0x0c273000u, 0x0c274000u};
_Static_assert(sizeof window_base / sizeof window_base[0] == WINDOWS, "tsnap: one base per window");
_Static_assert(WINDOWS <= 8, "tsnap: the dead windows are the bits of one byte");

/* The order of the blocks on the page and in the reads. tsens3 is last: its zones are the GPU, the NSP and the cameras (hamoa.dtsi:9574-9915), subsystems that may
 * sit in a collapsed power domain, and its critical interrupt is out of sequence with the other three (SPI 770 against 641 to 643, hamoa.dtsi:2765, 2780, 2795, 2810), so it is
 * the block least known to be like the rest; the CPU blocks, which a guard needs first, are read first. */
static const uint8_t block_order[INSTANCES] = {0, 1, 2, 3};

/* SROT (tsens-v2.c:14-17, 29-32, 86-93, VERIFIED as offsets and fields). HW_VER: major 31:28, minor 27:16, step 15:0. CTRL: EN bit 0, SW_RST bit 1, SENSOR_EN 18:3, CODE_OR_TEMP
 * bit 21 (tsens-v2.c:93; 1 is the temperature format in deci-Celsius, tsens-v2.c:27). Only the ipq5332 init writes that bit (init_tsens_v2_no_rpm, tsens-v2.c:223, 253-254, the init of
 * ops_ipq5332, tsens-v2.c:280-282); the generic v2 driver never does (tsens-v2.c:263-266 uses init_common, tsens.c:932, which does not name it), so on this unit it is whatever firmware
 * left, and a clear bit (the other format, INFERRED to be ADC codes) means the status words are not temperatures: the payload prints CODE and decodes none of them. The conversion
 * word of sensor n is at 0x60 + 4n (shift 24:23, slope 22:10, czero 9:0): the generic v2 driver never writes it (tsens-v2.c:263-266), so a non-zero word would be firmware's work
 * (INFERRED); nothing in the pinned tree reads it. */
#define SROT_HW_VER 0x00u
#define SROT_CTRL 0x04u
#define SROT_CONV 0x60u
#define CTRL_EN 0x1u
#define CTRL_SW_RST 0x2u
#define CTRL_SENSOR_SHIFT 3u
#define CTRL_SENSOR_MASK 0xffffu
#define CTRL_CODE_OR_TEMP (1u << 21)

/* TM (tsens-v2.c:36, 39, 44-45, 128-138, VERIFIED as offsets and fields). The status word of sensor n is at 0xa0 + 4n: LAST_TEMP bits 11:0, the violated flags MIN,
 * LOWER, UPPER, CRITICAL and MAX at 16 to 20, VALID at 21; Linux reads these constantly. TRDY at 0xe4, bit 0 (1 = ready): Linux reads it only for HW_VER major 0 (tsens.c:834-835),
 * never for a v2 block, so it is the one word of the first reading with no precedent and is read last. The two interrupt status words are read only to see whether a threshold
 * was ever flagged: the driver clears them through separate registers (0x0c and 0x18, tsens-v2.c:37, 40), so a read is not destructive (INFERRED). Linux reads 0x14 as its
 * bit 31 (WDOG_BARK_STATUS, tsens-v2.c:119, tsens.c:637) and nothing reads 0x08.
 *
 * Bits 26:22 are named by no pinned file: the unit's own words (boot 29, read from a film) carry the sensor's own number there, 0x00200000 + (n << 22) + the temperature, for every
 * sensor of every block (INFERRED from those words, and only the film's reading of them; the field's name is a guess, and the film cannot tell a four-bit field from a five-bit one:
 * the largest id is 15, so bit 26 is never set, and the check below is the same for both). The decode therefore never depends on the field: it is a consistency check, and a word
 * whose field is not the sensor's own index is ODD (an all-ones word is one, as is a word read from the wrong place). Bits 31:27 are reserved (the film's words have them clear): a
 * set bit there is ODD too. Bits 15:12 lie between the two fields the driver names and are not looked at. */
#define TM_UL_STATUS 0x08u
#define TM_CRIT_STATUS 0x14u
#define TM_STATUS 0xa0u
#define TM_TRDY 0xe4u
#define ST_TEMP_MASK 0xfffu
#define ST_CRIT_FLAGS (3u << 19)
#define ST_VALID (1u << 21)
#define ST_ID_SHIFT 22u
#define ST_ID_MASK 0x1fu
#define ST_RESERVED_SHIFT 27u

/* Decode: 12-bit two's complement in tenths of a degree C (tsens.c:386-399 with `.adc = 0`, tsens-v2.c:54; INFERRED for the unit until a reading looks plausible).
 * A word that is VALID but decodes outside this window is OUT: the sensor, the mode or the decode is wrong, not the die (the window is the guard model's, compat/
 * hamoa-thermal.h in the Snapintosh tree). */
#define TEMP_MIN_TENTHS (-400)
#define TEMP_MAX_TENTHS 1200

/* The page, line by line: two header lines; per block NEXT, the identity line (before any load of the TM window), two raw lines and the temperature line (with RDY=); SUM1; NEXT S2 and
 * one line per block (each names the next block, the last one the first block of the conversion pass, so that a hang is named by the last line); one CONV line per block (each names the
 * next block); SUM2 and END, which the lines before them may not crowd out. The nominal page has exactly LINE_CAP lines. */
#define HEADER_LINES 2u
#define BLOCK_LINES 5u
#define SUM1_LINES 1u
#define S2_LINES (1u + INSTANCES)
#define CONV_LINES INSTANCES
#define CLOSING_LINES 2u
#define PAGE_LINES (HEADER_LINES + INSTANCES * BLOCK_LINES + SUM1_LINES + S2_LINES + CONV_LINES + CLOSING_LINES)

/* The loads: per block HW_VER, CTRL, the sixteen status words and TRDY last; in the second reading CTRL, the sixteen status words and TRDY last; after it, per block the sixteen
 * conversion words and the two interrupt status words. */
#define LOADS_S1_BLOCK (3u + SENSORS)
#define LOADS_CONV_BLOCK (SENSORS + 2u)
#define LOADS_S2_BLOCK (2u + SENSORS)
#define LOADS_MAX (INSTANCES * (LOADS_S1_BLOCK + LOADS_CONV_BLOCK + LOADS_S2_BLOCK))

#ifdef TSNAP_SHIPPED_CAPS
_Static_assert(PAGE_LINES <= LINE_CAP, "tsnap: the nominal page fits the line cap");
_Static_assert(LOADS_MAX <= LOAD_CAP, "tsnap: the loads of both readings fit the load cap");
_Static_assert(SPIN_MAX == 0xffffffffu, "tsnap: the wait is bounded by 2^32 - 1 reads, as the document says");
#endif
_Static_assert(LINE_CAP >= CLOSING_LINES, "tsnap: the closing lines fit the cap");
