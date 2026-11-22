<!-- SPDX-License-Identifier: MIT -->
# Payload `tsnap`: a read-only snapshot of the SoC's temperature sensors, twice

**Status: EXPERIMENTAL; hardware NOT RUN.** `payloads/tsnap.c` (stick file `TSNAP.BIN`) reads the four TSENS temperature controllers of the Surface Pro 11's SoC (Snapdragon
X Elite X1E80100, "Hamoa") at EL2 and prints, on the panel, the controllers' identity and enable words, every sensor's raw status word, the temperature that word decodes to, the
minimum and maximum, and the same sensors again 2 s later. It stores nothing: no write to any device, no SMC, no HVC, no barrier, no tick. Before boot 29 nobody had read a temperature on
this unit: the thermal guard model of the Snapintosh tree (`compat/hamoa-thermal.c`) and the A16's own TSENS code assume that these windows are readable at EL2, that firmware
enabled and calibrated them and that the status word decodes as tenths of a degree C, and every one of those was INFERRED; v1's run settled the first two (OBSERVED) and left the decode INFERRED. This
payload is the reading, and it is the evidence that a later guard needs. It is not a guard: it decides nothing and refuses nothing.

**Versions.** v1 (`TSNAP.BIN`, 9,212 bytes, SHA-256 `dc74cd3e2a1d760a3b8053f25790b7ca0a7f40da5589cd0159fc6e177209ab56`) is the file that ran, once, in boot 29 (OBSERVED, one unit: 220 loads, no fault,
four controllers answered, 50 sensors enabled). Its own summary said `SUM1 V=4/64 ... ODD=60`: a decode limit and not a missing reading, because every status word carries the sensor's own number
in bits 26:22 (INFERRED from the raw words on the film; no pinned file names those bits) and v1 took every bit above 21 for reserved. **v1.1 (this source) changes the decode and nothing else**: a
word is odd when that number is not its sensor's own index (a consistency check, never a field the decode depends on), when a bit of 31:27 is set, or by the rules of v1; the loads, their order, the
page's shape and every cap are v1's (section 1, "The status word"). v1.1 is a new file with its own size and SHA-256 and it has **not run**. An independent review of its own (2026-11-22) found the binary named in the
operator's note safe for one read-only run (no blocker, no major finding, two minor ones, applied in this document and its tests); v1's review and its approval do not carry over to it.

Labels (Snapintosh `AGENTS.md`): **VERIFIED** read in a pinned file or shown by a host run, never a statement about the unit; **DERIVED** read in a local dump of the unit's
firmware tables (numbers only); **OBSERVED** a run on the unit (boot 29 ran v1; none exists for v1.1); **INFERRED**; **EXPERIMENTAL** code that exists and has not run; **UNIMPLEMENTED**;
**UNKNOWN**. A SKIP is not a pass.

## 1. What it reads

Four controllers `tsens0..tsens3` (`qcom,x1e80100-tsens`, falling back on `qcom,tsens-v2`: `hamoa.dtsi:2759-2817`; `qcom-tsens.yaml:92-93`; `tsens.c:1216-1217`), each with a
sensor-ROT (SROT) window and a thermal-monitor (TM) window of 0x1000 bytes, and `#qcom,sensors = <16>` (`hamoa.dtsi:2769, 2784, 2799, 2814`; `tsens-v2.c:56`, `tsens.h:23`).
The Linux driver numbers the sensors 0 to 15 (`tsens.c:1424`). VERIFIED as read in the pinned files; that the unit has the same windows is INFERRED (none of its ACPI tables lists them:
a byte search of the DSDT, SSDT and CSRT for the eight bases finds none, DERIVED).

| Block | SROT window | TM window | Interrupt (critical) | Zones of the DT that read it (`hamoa.dtsi:9123-9915`) |
| --- | --- | --- | --- | --- |
| T0 | 0x0c222000 (`:2761-2762`) | 0x0c271000 | SPI 641 (`:2765`) | ids 0 to 12: aoss0, cpu0-0..3 top and btm (1 to 8), cpuss0 top and btm (9, 10), mem (11), video (12) |
| T1 | 0x0c223000 (`:2776-2777`) | 0x0c272000 | SPI 642 (`:2780`) | ids 0 to 10: aoss1, cpu1-0..3 top and btm, cpuss1 top and btm |
| T2 | 0x0c224000 (`:2791-2792`) | 0x0c273000 | SPI 643 (`:2795`) | ids 0 to 10: aoss2, cpu2-0..3 top and btm, cpuss2 top and btm |
| T3 | 0x0c225000 (`:2806-2807`) | 0x0c274000 | SPI 770 (`:2810`) | ids 0 to 14: aoss3, nsp0 to nsp3 (1 to 4), gpuss-0..7 (5 to 12), camera0 and camera1 (13, 14) |

50 of the 64 sensors are read by a thermal zone (VERIFIED by a parse of the pinned copy); ids 13 to 15 of T0, 11 to 15 of T1 and T2, and 15 of T3 feed no zone, and whether they are
populated is UNKNOWN: this payload reads all sixteen of each block and says. The four nodes carry no `clocks`, `power-domains` or `nvmem-cells` (VERIFIED), so whether anything
gates a window on the unit is UNKNOWN; the gate the payload uses is the block's own identity and enable words.

### The registers (every offset VERIFIED in `tsens-v2.c`; their presence and meaning on the unit INFERRED)

| Window | Offset | Register | Fields | Read where |
| --- | --- | --- | --- | --- |
| SROT | 0x00 | HW_VER | major 31:28, minor 27:16, step 15:0 (`tsens-v2.c:14-17, 86-93`) | first, per block; gates the block |
| SROT | 0x04 | CTRL | EN bit 0, SW_RST bit 1, SENSOR_EN bits 18:3, CODE_OR_TEMP bit 21 (`tsens-v2.c:93`; 1 is the temperature format, `tsens-v2.c:27`): only the ipq5332 init writes that bit (`tsens-v2.c:223, 253-254`, the init of `ops_ipq5332`, `tsens-v2.c:280-282`), the generic v2 driver never does (`tsens-v2.c:263-266` uses `init_common`, `tsens.c:932`, which does not name it), so on this unit it is whatever firmware left | second, per block, and again at the start of each block of the second reading; gates the TM window; a clear bit 21 makes the block `CODE` |
| TM | 0xa0 + 4n | Sn_STATUS | LAST_TEMP 11:0, MIN, LOWER, UPPER, CRITICAL, MAX violated at 16 to 20, VALID at 21 (`tsens-v2.c:128-138`); bits 26:22 the sensor's own number and bits 31:27 reserved (the unit's words, not the driver's: "The status word" below) | n = 0 to 15, in both readings, right after the identity line and before TRDY |
| TM | 0xe4 | TRDY | bit 0, 1 = ready (`tsens-v2.c:44-45, 128-138`); Linux reads it only for HW_VER major 0 (`tsens.c:834-835`), never for a v2 block | **last** word of the block's TM window, in both readings; its value is `RDY=` on the temperature line |
| SROT | 0x60 + 4n | Sn_CONVERSION | shift 24:23, slope 22:10, czero 9:0 (`tsens-v2.c:29-32`) | after the second reading, n = 0 to 15, one reading, a block at a time |
| TM | 0x08, 0x14 | UL and CRITICAL interrupt status | one bit per sensor; bit 31 of 0x14 is the block's own watchdog bark on v2.3 and later (`tsens-v2.c:36, 39, 119`); Linux reads 0x14 only as that bit (`tsens.c:637`) and nothing reads 0x08 | after the second reading, one reading, in the block's `CONV` line |

**The status word (v1.1).** The pinned driver names these fields of the word at TM + 0xa0 + 4n and no others: LAST_TEMP bits 11:0, MIN_STATUS 16, LOWER_STATUS 17, UPPER_STATUS 18, CRITICAL_STATUS 19,
MAX_STATUS 20 and VALID 21 (`tsens-v2.c:128-138`; VERIFIED as what the file says, and the class `Refs` of the refs test parses them, so that a field above bit 21 in the pinned copy would be
found). Boot 29 showed that the unit's words are not only those: the raw words on the film were `0x00200000 + (n << 22) + the temperature` for the sensor n, so bits 26:22 hold the sensor's own number
(INFERRED: the coordinator's reading of the film, the digits of which are in no file of this tree; the film cannot tell a four-bit field from a five-bit one, because the largest number is 15 and bit 26
was never set), for the 14 sensors that are not enabled as well as the 50 that are (60 words of 64 had a bit above 21 set, which the old decode counted as odd and which includes them). v1 took every
bit above 21 for reserved and so called 60 of 64 words odd although VALID was set on exactly the 50 sensors that SEN names and the temperatures were plausible (both INFERRED from the film: 38.1 to
42.6 C by hand from the raw words, tenths of a degree INFERRED). v1.1 decodes a word of sensor slot i in this order, and it is the only change:

| Step | Rule | Why |
| --- | --- | --- |
| 1 | a bit of 31:27 set, or the number in bits 26:22 is not i: **ODD** (`O` on the temperature line, counted in `ODD=`, never in `V=`) | the layout of the unit's words is one film of one unit; a word that does not follow it, an all-ones word and a word read from another sensor's slot included, is not decoded and says so |
| 2 | VALID (bit 21) clear: not valid (`?`) | as v1; a sensor that is not enabled reads its own number alone and is `?` |
| 3 | a VALID word of a block whose CTRL has CODE_OR_TEMP clear: **ODD** | as v1 (INFERRED: ADC codes) |
| 4 | VALID and outside -40.0 to 120.0 C: out of range (`O` on the cell, `OUT=`) | as v1 |
| 5 | otherwise the 12-bit two's complement of LAST_TEMP in tenths of a degree C | as v1 |

The number is checked before VALID so that a word of zero in a slot above 0 (a window that reads zero, say) is odd and not `?`: on the unit that would mean a layout that is not the film's, and it
should not pass for "not enabled". Bits 15:12 lie between two fields the driver names, were clear in the film's words and are not looked at (as in v1). The CRITICAL and MAX flags are counted for
every word that is not odd, as in v1. A mismatch is a statement about the layout and never about the die: the raw words stay on the `R` lines.

**The replay of boot 29.** The host test's suite `boot29` runs the payload over the words the page of boot 29 gives (HW_VER `0X20080000`, CTRL `0X9D60FFF9`, `0X9D603FF9`, `0X9D603FF9` and
`0X9D63FFF9`, so SEN `0X1FFF`, `0X7FF`, `0X7FF` and `0X7FFF`: 50 sensors; the lowest word `0x17D` on T1 and the highest `0x1AA` on T0; the four cells of sensor 0 between 38.5 and 39.8 C; T0.0 39.8 C
and 40.2 C in the second reading) and the layout the film implies for every other word; the digits the film gave are the only ones used, and what it did not give (which sensor holds the extreme,
every other temperature, the 14 words of the sensors that are not enabled) is filler inside the bounds, marked as such in the test. It first shows that the world is the film's: the **old** decode over it
prints exactly what the film's summary said (`V=4/64`, `ODD=60`, four clean cells at 38.5 to 39.8 C, `CHG=1/4 DMAX=4`), and a world in which the 14 sensors that are not enabled read zero would have
said `ODD=46`, which is not what the film said. Then v1.1 over the same words prints `SUM1 V=50/64 MIN=381(T1.4) MAX=426(T0.6) CRIT=0 OUT=0 ODD=0` (38.1 to 42.6 C; which sensor holds each extreme
is the test's filler) and in the second reading 50 valid with one sensor moved by 0.4 C. That is a replay of what is read on the film and of one inference, not a second reading of the unit.

**INFERRED, from the film only:** that the 14 sensors that are not enabled read their own number. What the film gave is the count (`ODD=60` of 64 by v1's rule, under which a word with a bit above 21 set was odd) and
the digits above; none of the raw words of boot 29 is in this tree, and the test's words for those 14 sensors are its filler. If they read something else, v1.1 prints `ODD=14` for them and `V=50/64` still stands (the raw
words are on the `R` lines). The first v1.1 page is the first test of this and of the five-bit width of the number field.

**The order of the evidence.** What the run exists for is the sixteen status words of each block, which Linux reads constantly; they come first, after the two words that gate the block
(HW_VER and CTRL: `tsens.c:1018-1031` reads the enable bit, `tsens.c:1092` the version) and after an identity line that is printed before the first load of the TM window. The offsets that no
Linux path reads for a v2 block are read after them and never in front of a temperature: TRDY (0xe4) last in its block, and the conversion words (0x60 and up) and the interrupt status word
0x08, with 0x14 (read by Linux as its bit 31 only), in a pass of their own after the second reading. A fault or a hang at one of them costs what comes after it, never a temperature
already read. Read in front of the temperatures, one abort at such an offset would kill its window (section 3) before a single temperature of the block was on the page, and a hang there would leave no identity line.

Not read: MEASURE_PERIOD (SROT 0x08), the thresholds, the interrupt enables, masks and clears (`tsens-v2.c:37, 40` are the clear registers: a status read is not destructive,
INFERRED from the driver clearing through them), the watchdog log (0x13c). The generic v2 driver never writes a conversion word (`tsens-v2.c:263-266`) and refuses a block whose EN is
clear (`tsens.c:1018-1031`), so enable and conversion words come from firmware on the unit that runs Linux (INFERRED for this unit). The decode is a 12-bit two's complement count of
tenths of a degree C (`tsens.c:386-399`, with `.adc = 0` at `tsens-v2.c:54`): INFERRED for the unit until a reading looks plausible, and only for a block whose CTRL has CODE_OR_TEMP set:
a clear bit is the other result format (INFERRED to be ADC codes), and the payload prints `CODE` for it and decodes none of that block's words (every cell is `O`). Linux trusts a status word only when VALID is set,
tries three times (`tsens.h:24`) and then returns a "stable" fallback value (`tsens.c:329-373`); this payload reads each word once per reading, never retries, and a word without VALID is
`?`. A guard must not copy the fallback. The watchdog fields are read by Linux only for HW_VER minor above 2 (`tsens.c:1092`).

## 2. The page

At most 34 lines of at most 100 characters (the ABI allows 40 and 4096 loads; this payload keeps to 34 lines and 256 loads so that it can run ahead of a 40-line payload: section 4).
A nominal page is 34 lines and 220 loads (`tools/test-q1n1-sp11-payload-tsnap.c`, `--numbers`); 34 is the whole cap, so a page with a gated block is shorter and none is longer:

<!-- numbers -->
LINES 34 LOADS 220 LINE_CAP 34 LOAD_CAP 256 PAGE_LINES 34 LOADS_MAX 220
<!-- /numbers -->

The sample below is the page of the host model's made-up fixture (HW_VER 2.4.0, 30.0 C and up, every sensor moving by at most 0.1 C, the words in the layout of the unit's own: each sensor's
number in bits 26:22): **not the unit's page**, and every value is a fixture's. The `DT=` and `GAP_MS=` values are the model's counter.

<!-- page -->
```
PAYLOAD TSNAP READ ONLY EL=2 HZ=0X124F800 GAP=2 S
PAYLOAD TSNAP KEY T0..T3=BLOCK R=RAW STATUS HEX C=TENTHS OF C INFERRED ?=NOT VALID X=NOT READ O=ODD
PAYLOAD TSNAP NEXT T0
PAYLOAD TSNAP T0 VER=0X20040000 CTL=0X20FFF9 SEN=0X1FFF
PAYLOAD TSNAP T0 R0 0020012C 0060012F 00A00132 00E00135 01200138 0160013B 01A0013E 01E00141
PAYLOAD TSNAP T0 R8 02200144 02600147 02A0014A 02E0014D 03200150 03400000 03800000 03C00000
PAYLOAD TSNAP T0 C 300 303 306 309 312 315 318 321 324 327 330 333 336 ? ? ? RDY=0X1 V=13
PAYLOAD TSNAP NEXT T1
PAYLOAD TSNAP T1 VER=0X20040000 CTL=0X203FF9 SEN=0X7FF
PAYLOAD TSNAP T1 R0 00200133 00600136 00A00139 00E0013C 0120013F 01600142 01A00145 01E00148
PAYLOAD TSNAP T1 R8 0220014B 0260014E 02A00151 02C00000 03000000 03400000 03800000 03C00000
PAYLOAD TSNAP T1 C 307 310 313 316 319 322 325 328 331 334 337 ? ? ? ? ? RDY=0X1 V=11
PAYLOAD TSNAP NEXT T2
PAYLOAD TSNAP T2 VER=0X20040000 CTL=0X203FF9 SEN=0X7FF
PAYLOAD TSNAP T2 R0 0020013A 0060013D 00A00140 00E00143 01200146 01600149 01A0014C 01E0014F
PAYLOAD TSNAP T2 R8 02200152 02600155 02A00158 02C00000 03000000 03400000 03800000 03C00000
PAYLOAD TSNAP T2 C 314 317 320 323 326 329 332 335 338 341 344 ? ? ? ? ? RDY=0X1 V=11
PAYLOAD TSNAP NEXT T3
PAYLOAD TSNAP T3 VER=0X20040000 CTL=0X23FFF9 SEN=0X7FFF
PAYLOAD TSNAP T3 R0 00200141 00600144 00A00147 00E0014A 0120014D 01600150 01A00153 01E00156
PAYLOAD TSNAP T3 R8 02200159 0260015C 02A0015F 02E00162 03200165 03600168 03A0016B 03C00000
PAYLOAD TSNAP T3 C 321 324 327 330 333 336 339 342 345 348 351 354 357 360 363 ? RDY=0X1 V=15
PAYLOAD TSNAP SUM1 V=50/64 MIN=300(T0.0) MAX=363(T3.14) CRIT=0 OUT=0 ODD=0
PAYLOAD TSNAP NEXT S2 AFTER 2 S
PAYLOAD TSNAP S2 T0 V=13 MIN=299 MAX=335 CHG=9 D=1 DT=2006 NEXT T1
PAYLOAD TSNAP S2 T1 V=11 MIN=307 MAX=338 CHG=7 D=1 DT=2006 NEXT T2
PAYLOAD TSNAP S2 T2 V=11 MIN=315 MAX=343 CHG=8 D=1 DT=2006 NEXT T3
PAYLOAD TSNAP S2 T3 V=15 MIN=320 MAX=364 CHG=10 D=1 DT=2006 NEXT CONV T0
PAYLOAD TSNAP CONV T0 NZ=13/16 LO=0X1B3416A HI=0X1B34176 UL=0X0 CR=0X0 NEXT CONV T1
PAYLOAD TSNAP CONV T1 NZ=11/16 LO=0X1B3416A HI=0X1B34174 UL=0X0 CR=0X0 NEXT CONV T2
PAYLOAD TSNAP CONV T2 NZ=11/16 LO=0X1B3416A HI=0X1B34174 UL=0X0 CR=0X0 NEXT CONV T3
PAYLOAD TSNAP CONV T3 NZ=15/16 LO=0X1B3416A HI=0X1B34178 UL=0X0 CR=0X0
PAYLOAD TSNAP SUM2 V=50/64 MIN=299(T0.0) MAX=364(T3.14) CHG=34/50 DMAX=1 CRIT=0 OUT=0 ODD=0
PAYLOAD TSNAP END LOADS=220 FAULTS=0 SKIPS=0 GATED=0 CUTS=0 GAP_MS=2006 LINES=34
```
<!-- /page -->

### What each line says

| Line | Meaning |
| --- | --- |
| `READ ONLY EL=2 HZ=.. GAP=2 S` | `CNTFRQ_EL0` as read (`DEFAULT` after it when it was outside 1 MHz to 1 GHz and 19.2 MHz was used instead); the gap between the two readings |
| `NEXT T<n>` | printed BEFORE the first load of block n; if it cannot be printed the block is not read at all (`NEXT S2 AFTER 2 S` and `NEXT CONV T<n>` do the same for the passes) |
| `T<n> VER= CTL= SEN=` | HW_VER, CTRL and the SENSOR_EN field of CTRL (bits 18:3, shifted down), printed BEFORE the first load of the block's TM window: that window is not read when the line did not go out. After HW_VER alone: `GATED`; after CTRL alone: `OFF` (CTRL read, EN clear or SW_RST set) or `CTLERR` (the CTRL load itself aborted: nothing is known of the block's state); after all three: `CODE` when CTRL bit 21 (CODE_OR_TEMP) is clear |
| `T<n> R0` and `R8` | the raw status words of sensors 0 to 7 and 8 to 15, eight hex digits each (an all-ones word shows as `FFFFFFFF`) |
| `T<n> C ... RDY= V=` | the same sixteen sensors as tenths of a degree C (INFERRED decode, "The status word" above): a number, `?` VALID clear, `O` odd (the word's sensor number, bits 26:22, is not the sensor's own index, or a bit of 31:27 is set: an all-ones word is one), outside -40.0 to 120.0 C, or any VALID word of a `CODE` block; `X` not read. `RDY=` is TRDY (0xe4), read after the sixteen words and the clock read: the word, `FAULT:n`, or `SKIP` when the window had aborted. `V=` is how many cells are a number |
| `SUM1`, `SUM2` | `V=` valid and plausible of 64; `MIN=` and `MAX=` with the sensor as `(T<block>.<id>)`, `NA` when none; in SUM2 `CHG=a/b`: of the b sensors valid and plausible in both readings, a moved by at least 0.1 C, and `DMAX=` the largest move in tenths; `CRIT=` sensors whose CRITICAL or MAX flag is set (words that are not odd); `OUT=` valid but outside the plausible window; `ODD=` words that are odd in the sense above, or a VALID word of a `CODE` block. The fields are in the order of importance: only a page of extreme values loses the last ones, and `CUTS` counts them |
| `S2 T<n> V= MIN= MAX= CHG= D= DT=` | the second reading of block n (CTRL, the sixteen status words, then TRDY): how many are valid, the extremes, how many moved and by how much (tenths), the milliseconds between the two reads of its words. The line ends in `NEXT T<m>` naming the next block and, for the last block, in `NEXT CONV T<n>` naming the first block of the conversion pass, so that a hang is named by the last line. `OFF` when CTRL no longer says running, `CTL=FAULT:n CTLERR` when it aborted, `CODE` when its bit 21 is clear, a `FAULT:n` token for the first word of the block (a status word or TRDY) that aborted |
| `CONV T<n> NZ=a/16 LO= HI= UL= CR=` | the conversion words and the interrupt status of block n, one line per block still running after the second reading: how many of the sixteen SROT conversion words read non-zero (`X` when they were not all read), the lowest and the highest non-zero word (`NA` when none), the two TM interrupt status words (`SKIP` when the TM window had aborted); the line ends in `NEXT CONV T<m>` naming the next block |
| `END LOADS= FAULTS= SKIPS= GATED= CUTS= GAP_MS= LINES=` | the loads made; the loads that aborted; the words not read because an earlier load of the window aborted; the blocks of the first reading not read further (`GATED`, `OFF`, `CTLERR` or unannounced); the fields dropped for lack of room; the milliseconds from the start of the first reading to the start of the second on the real counter; the lines of the page, this one included |

Other tokens: `FAULT:n` (the runner's code for an aborted load: 6), `SKIP` (a word not read because an earlier load of its window aborted), `BUDGET` (the load cap, 256, was reached: the word is not read), `NA`;
`S2 SKIPPED NO_COUNTER` (the counter is stuck for 2,000,000 reads in a row or runs backwards: it cannot time the wait), `S2 SKIPPED SPIN` (the counter moves, but 2^32-1 reads of it did not span the
2 s: the second reading is not made) and `S2 SKIPPED NO_BLOCK` (no block was readable); `SKIPPED_NOT_AT_EL2` and `REFUSED_NO_LOAD32`, one line and no load. A field that does not
fit the 100 characters is dropped and counted in `CUTS`, never cut in half; the next field is still tried, so a short one can follow a long one that was dropped. A temperature line whose
sixteen cells are all four characters wide (every sensor at or above 100.0 C, or at or below -10.0 C) loses `RDY=` and `V=`; with six cells of four characters it loses `V=` only.

## 3. Hazards, and what the order is for

A load of a block that is behind a stopped clock, a collapsed power domain or a protection unit can hang the SoC, and no guard recovers that: the runner's guarded load turns a
synchronous abort into `FAULT:n`, nothing more. A protection-unit violation may instead surface as an SError, which the guard does not catch and q1n1 keeps masked (the load aborts nothing
on the page and the board may reset). One hang is on record for this unit: boot 3's read of the ECAM of PCIe segment 3 never returned and the board rebooted by itself (an operator report,
with a hang and a watchdog reset as the INFERRED cause: [SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md); the Snapintosh tree's `docs/SP11-MONITOR-PORT.md` says the same). Nothing about
the TSENS windows is known. So:

* The blocks go T0, T1, T2 and **T3 last**: its zones are the GPU, the NSP and the cameras (`hamoa.dtsi:9574-9915`), subsystems that may sit in a collapsed power domain, and its critical
  interrupt is out of sequence with the other three; the CPU blocks, which a guard needs first, are read first. That is a judgement (INFERRED), not a fact.
* **The order of what is read.** The two words that gate a block come first (HW_VER, CTRL), then the identity line, then the sixteen status words, which Linux reads all the time, and only
  then TRDY (0xe4); the conversion words and the interrupt status words, which no Linux path reads either (section 1), come after the second reading. Whatever those offsets do, the
  temperatures are on the panel before them. `NEXT T<n>` is printed before the first load of block n, the identity line before the first load of its TM window, `NEXT S2 AFTER 2 S` before the
  wait, and every `S2` and `CONV` line ends by naming the block read next; a block whose line cannot be printed is not read, and neither is the block that a line which did not go out would have
  named.
* **The last line on the panel names what hung.** After `NEXT T2` and nothing else, HW_VER or CTRL of T2; after `T2 VER=...`, one of its first eight status words; after `T2 R0`, one of the
  next eight; after `T2 R8` and no `C` line, TRDY (0xe4); after a `C` line, the first load of the block that the next `NEXT` names; after `NEXT S2 AFTER 2 S`, the wait (the one long silence that is
  no hang: section 6) or the first block's CTRL, status words or TRDY; after an `S2 T<n>` line, the block it names (the second reading of a block is one line, so it names the block and not the
  word); after the `NEXT CONV T<n>` that ends the last `S2` line, and after each `CONV` line, the conversion words and the two interrupt words of the block named. Nothing is read after the last
  `CONV` line. **The limit:** the runner's `payload_emit` (`platform/uefi/main.c`, not touched by this payload) mirrors a line to the UART and draws it with stores into the frame buffer, and the
  payload's next device load follows with no barrier in between. If that load hangs the SoC the last line or lines may never have reached the panel: the last line seen is then older than the
  last line printed, by an unknown number of lines, and so gives a lower bound (the hang is at the loads of that line or of a later one), never an upper one. No such lag is measured or known on the unit.
* A block is read further only after its own words say it is there and running: HW_VER must read (no abort, not 0, not all ones, which is what a block that is not there returns) and
  CTRL must read and say EN set and SW_RST clear. Otherwise the page says `GATED` (HW_VER), `OFF` (CTRL read and not running) or `CTLERR` (the CTRL load aborted: nothing is known of the block's
  state), and the TM window of the block is never touched, in either reading, nor are its conversion words read. A block whose CTRL no longer says running in the second reading (`S2 T<n> OFF`,
  or `CTL=FAULT:n CTLERR`) is not read again by either pass. A block whose CTRL has CODE_OR_TEMP (bit 21) clear is read as usual and says `CODE`: its status words are not decoded (every VALID one
  is an `O`, counted in `ODD=` and never in `V=`, `MIN=`, `MAX=` or `CRIT=`) because they may be ADC codes (INFERRED).
* The first abort in a window (the SROT or the TM of a block) ends every later read of that window, in both readings; no other block is silenced. Nothing is retried. An abort of a block's first
  status word ends the block's lines (no `R8`, no `C`, no TRDY: the window is dead) and its second reading; its conversion words, which are in the SROT window, are still read, and its `UL=` and `CR=`
  say `SKIP`. An abort at TRDY, after the sixteen words, leaves all sixteen temperatures on the page and shows as `RDY=FAULT:6`.
* The wait is the one the page announced, or the second reading is not made. A counter that stands still for 2,000,000 reads in a row (it never moved, or it moved and stopped) or runs backwards
  ends it as `S2 SKIPPED NO_COUNTER`; a counter that moves ends it when the 2 s have passed, or after 2^32-1 reads of it as `S2 SKIPPED SPIN`. Even a read that took 1 ns would need 2 x 10^9 reads for the 2 s,
  under half of the bound, so a counter that runs at its stated frequency never reaches it; a counter far slower than it says keeps the page silent for the whole bound (about 43 s at 10 ns a read,
  7 minutes at 100 ns: INFERRED, a read was never timed).
* It writes nothing: the only stores of the binary are to its own stack, shown by the IR audit and by the binary's memory check (section 5). Reading the status words is INFERRED harmless,
  never shown.

## 4. The chain budget

The runner prints `files + 1` lines of its own once and three per payload (`VERIFY`, `CALL`, `DONE`); the panel's region holds about 89 rows on the unit's panel (computed, never
seen beyond 58: [SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md)) and a payload may print at most 40 lines. `tsnap` prints at most 34, so it can run ahead of a 40-line payload:

<!-- chain-budget -->
| Chain | Lines | Rows left of 89 |
| --- | --- | --- |
| `tsnap` alone | (1 + 1) + 3 + 34 = 39 | 50 |
| `tsnap`, then an xHCI payload (40) | (2 + 1) + 2 x 3 + 34 + 40 = 83 | 6 |
| `tsnap`, then `psci` (30) | (2 + 1) + 2 x 3 + 34 + 30 = 73 | 16 |
| `tsnap`, a second 34-line payload and an xHCI payload | (3 + 1) + 3 x 3 + 34 + 34 + 40 = 121 | none: more rows than the panel has |
<!-- /chain-budget -->

The first run is **alone**: the point is one clean page, and a hang or a reset takes every earlier line of the same chain with it ([SP11-PAYLOAD.md](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot)).

## 5. Tests

All host and QEMU only: no suite touches the unit. Environment as for the other SP11 payload suites (`tools/sp11_payload_testlib.py` finds the LLVM tools).

| Command | What it shows | What it does not show |
| --- | --- | --- |
| `python3 tools/test-q1n1-sp11-payload-tsnap.py` | the host program over a model of the eight windows under ASan and UBSan, at the shipped caps and with small line, load, spin and stuck caps, and (`--slow`) a counter that needs more than 2^28 reads and still completes the wait; the IR audit (no integer becomes a pointer, every store is rooted in the payload's own stack) on the real source and on 12 hand-written faulty texts; the binary check (`tsnap` policy of `tools/sp11_payload_testlib.py`: two system registers, no SMC, no barrier, the memory discipline `read_only`) and the stack depth; the Makefile's bytes equal the test's, two builds identical; the manifest tool; the seeded bugs of `tools/sp11_payload_tsnap_mutants.py` (a wrong window base, an SROT and a TM window swapped, a device word read without the runner's guard, a dropped announcement, an early spin bound, ...), each refused by the stage it names for the reason it names; this document against the header (register and window tables, bit fields, caps), the host model's page and numbers, the chain arithmetic and its links | the unit's windows, their values, whether a read hangs, the SError path |
| `TSNAP_REFS_DIR=.. python3 tools/test-q1n1-sp11-payload-tsnap-refs.py` | every `file:line` of this document, the header and the source, read back from the pinned copies; the digests; the device tree numbers by a parse; without the copies only the ledger checks run (the document carries every pin, every citation is in the ledger, every entry is cited) and the rest SKIPs | anything about the unit |
| `python3 tools/test-q1n1-sp11-payload-qemu-tsnap.py` | the binary behind the runner at EL2 under QEMU/EDK2, alone and after `state`: the runner's counters agree with the page, the page keeps to its lines and the font and is the host model's page for a machine without the windows | any value of the unit; the second reading, the conversion pass and the wait on the counter (QEMU has none of the windows, so every block is GATED, the second reading is skipped and there is no conversion pass) |

The host program's suites: `unit` (the golden page above, the loads exactly the model's own list, each the number of times the page implies), `order` (every NEXT line before the loads
of its block, the identity line before the first load of its TM window, TRDY last in its block, every line right after the loads it holds, the second reading before the conversion pass, T3
last, the closing lines last), `cells` and `random` (every kind of status word against the model's own decode and a table of words, every sensor number in every slot, the reserved bits, the raw lines, the
temperature lines, SUM1 and the second reading, in curated and in 300 random worlds), `boot29` (the replay of the unit's own page: the old decode over the film's words says what the film's summary said,
the new one says 50 valid sensors at 38.1 to 42.6 C), `gate` (HW_VER and CTRL variants: `GATED`, `OFF`, `CTLERR`, `CODE`), `faults` (an abort at every one of the 220 loads, the SROT or the TM windows aborting, every window
aborting, an abort storm from every load on), `hang` (a hang at every one of the 220 loads: the page so far is exactly the clean page up to that load, and its last line names what hung),
`drift` (what moves during the gap, a block that goes `OFF`, `CODE` or `CTLERR` in the second reading, an abort at a status word or at TRDY of it), `counter` (running, stuck, moved and then
stood still, absent, backwards, the frequency's range), `el`, `budget` (the widest page, and which field goes first) and `storm` (1500 random worlds with random words, aborts, hangs and
counters); the model holds its **own** list of what a read may reach, written from the pinned driver and not from the payload's tables, and its own decode, so that a wrong table or a wrong
rule in the payload is a difference and not an echo. With `--slow` one more suite, `slow`, runs at the shipped caps: it takes seconds (268.6 million reads of the model's counter).

### What QEMU shows

QEMU's `virt` machine has none of the eight windows: they lie in its platform-bus region, where nothing is mapped. OBSERVED, QEMU 11.1.3 (`virt,virtualization=on`, TCG, EDK2
stable202408; `tools/test-q1n1-sp11-payload-qemu-tsnap.py`): the first load of every block faults, the payload gates all four blocks, and the page is the host model's page for a machine
in which every window aborts (`--page dead` of the host test), but for the counter frequency (QEMU's is 1 GHz, the model's 19.2 MHz). The runner's own `DONE` line for the same run reads
`LOADS=4 FAULTS=4 REFUSED=0 LINES=14 DROPPED=0`, as the END line does.

<!-- qemu-lines -->
```
PAYLOAD TSNAP READ ONLY EL=2 HZ=<HZ> GAP=2 S
PAYLOAD TSNAP KEY T0..T3=BLOCK R=RAW STATUS HEX C=TENTHS OF C INFERRED ?=NOT VALID X=NOT READ O=ODD
PAYLOAD TSNAP NEXT T0
PAYLOAD TSNAP T0 VER=FAULT:6 GATED
PAYLOAD TSNAP NEXT T1
PAYLOAD TSNAP T1 VER=FAULT:6 GATED
PAYLOAD TSNAP NEXT T2
PAYLOAD TSNAP T2 VER=FAULT:6 GATED
PAYLOAD TSNAP NEXT T3
PAYLOAD TSNAP T3 VER=FAULT:6 GATED
PAYLOAD TSNAP SUM1 V=0/64 MIN=NA MAX=NA CRIT=0 OUT=0 ODD=0
PAYLOAD TSNAP S2 SKIPPED NO_BLOCK
PAYLOAD TSNAP SUM2 V=0/64 MIN=NA MAX=NA CHG=0/0 DMAX=0 CRIT=0 OUT=0 ODD=0
PAYLOAD TSNAP END LOADS=4 FAULTS=4 SKIPS=0 GATED=4 CUTS=0 GAP_MS=0 LINES=14
```
<!-- /qemu-lines -->

That shows the binary at EL2 behind the real runner (the payload's guarded loads and its stack under the runner's checks), a faulted load reported as `FAULT:6`, every block announced before its
load, every block gated, the second reading skipped for want of a readable block (and no conversion pass: nothing is left to read), and the counters of the runner agreeing with the page. It
does **not** show the second reading, the conversion pass, the wait on the counter, a decoded temperature or any value of the unit: no window of QEMU answers, so those paths are exercised only
by the host test's model.

## 6. What it answers, and what it does not

What a page of v1.1 would say once there is one (none exists: the one page that does is v1's, boot 29, whose summary said `V=4/64 ... ODD=60` for the reason "The status word" of section 1 gives). The
labels are those the statement would carry then; the page itself is OBSERVED, a cause or a meaning is whatever the row says.

| The page shows | It says | Label |
| --- | --- | --- |
| `VER=FAULT:6 GATED` for a block | a load of its SROT window aborted: EL2's stage-1 map does not reach it, or a protection unit refused it | the abort OBSERVED, the cause UNKNOWN |
| `VER=0X0` or `VER=0XFFFFFFFF`, `GATED` | the window answered but the block reads as absent or powered down | the answer OBSERVED, the cause UNKNOWN |
| `VER` plausible, `OFF` | CTRL was read and says the block is disabled or in reset: firmware left it so, and a guard that reads it first needs the block enabled | OBSERVED; whether Windows enables it later UNKNOWN |
| `CTL=FAULT:6 CTLERR` | the CTRL load aborted although HW_VER read: nothing is known of whether the block runs, and its TM window was not touched | the abort OBSERVED, the state UNKNOWN |
| `CODE` after `SEN=`, every VALID cell `O` | CTRL bit 21 (CODE_OR_TEMP) is clear: the status words are in the other result format, which the driver selects with that bit (ADC codes, INFERRED); the raw words are on the `R` lines and nothing of the block is in `V=`, `MIN=` or `MAX=` | OBSERVED; the meaning INFERRED |
| `RDY=FAULT:6`, the sixteen cells in place | the TM window answered sixteen words and refused TRDY (0xe4), which no Linux path reads for a v2 block: the temperatures stand, and a guard must not wait for TRDY | OBSERVED |
| `R0 FAULT:6 SKIP ...`, no `R8` or `C` line, `VER` and `CTL` fine | the TM window is unreachable although the SROT is: the guard's TM address assumption is wrong, or something refused the window | the abort OBSERVED, the cause UNKNOWN |
| `FAULT:6` on a later word of `R0` or `R8`, the words after it `SKIP` | the window answered some words and refused one: the refusal is at that offset, and the rest of that window was not read in either reading (`SKIPS` on `END`) | OBSERVED |
| temperatures near room or idle temperature (tens of degrees) and `CHG` above 0 in the second reading | the decode is plausible and the sensors are live | OBSERVED; the decode stays INFERRED (no second source reads the same die) |
| `?` for sensors that a zone reads, or `O` cells | they are not enabled or not populated, or the decode is wrong: compare `SEN=` with the VALID bits and the raw words | OBSERVED |
| `ODD=` above 0 on `SUM1`, `V=` below the number of sensors `SEN=` names | a status word whose sensor number (bits 26:22) is not its sensor's own index, or with a bit of 31:27 set: the layout of boot 29's words (INFERRED from one film) does not hold for it, or its slot returned another word; the `R` lines have the words and `O` on the `C` line marks the sensors. v1 printed `ODD=60` in boot 29 for words that did follow the layout, because it had no number field: that is what v1.1 fixes | OBSERVED; the cause INFERRED |
| `NZ=0/16` on every `CONV` line | the conversion words read zero: the model's `UNCALIBRATED` rule would trip at every poll, or the words are not readable that way | OBSERVED |
| `UL=` or `CR=` non-zero on a `CONV` line | a threshold bit is set; Linux reads 0x14 only as its bit 31 and nothing reads 0x08, so what a bit means is INFERRED (a threshold that firmware set, or an id that reads 0, may set one): not evidence of a thermal event by itself, which is `CRIT=` above 0 at a plausible temperature | OBSERVED; the meaning INFERRED |
| `CRIT=` above 0 at idle | the critical or MAX flag is set: the model's `CRITICAL` rule would stop every run | OBSERVED |
| `S2 SKIPPED NO_COUNTER` | the counter did not run (it stood still for 2,000,000 reads in a row, or ran backwards, or the runner gave none): there is no second reading and no `CHG`; the first reading is whole and the conversion pass still ran | OBSERVED; the cause UNKNOWN |
| `S2 SKIPPED SPIN` | the counter moves, but 2^32-1 reads of it did not span the 2 s: it runs far slower than `CNTFRQ_EL0` says; no second reading, the first is whole | OBSERVED; the cause INFERRED |
| `S2 SKIPPED NO_BLOCK` | no block was readable in the first reading (all gated, off or with a dead TM window): there is nothing to read again and no wait; the conversion pass reads what is still readable (nothing, when every block is gated) | OBSERVED |
| `BUDGET` in place of a word | the payload's own load cap (256) was reached, which the page of 220 loads cannot do: the file is not the one that was approved, or the model's count is wrong | OBSERVED |
| `CUTS` above 0 on the `END` line | a field did not fit the 100 characters and was dropped, never cut: `RDY=` and `V=` of a `C` line when its cells are four characters wide, or the last fields of a `SUM` line; every value is still on the `R` lines | OBSERVED |
| the last line is a `NEXT` line or a line of a block, and nothing after | what section 3 says hung (and its limit: the last line seen can be older than the last printed) | OBSERVED |
| the last line is `NEXT S2 AFTER 2 S`, for longer than 2 s | the wait is still running on a counter slower than it says (it ends by itself after 2^32-1 reads: about 43 s at 10 ns a read, 7 minutes at 100 ns, INFERRED), or the first load after it hung: only the time tells them apart, and a silence of more than 8 minutes is a hang | OBSERVED; the cause UNKNOWN |
| `END` is on the page, then a q1n1 fault page or a reset | the payload finished with nothing in flight; what follows is the runner's or q1n1's: an SError from a load that aborted late is one candidate (the guard does not catch SError and q1n1 keeps it masked, so one that was pending during the payload can surface after `END`), INFERRED; every line above `END` is complete | OBSERVED; the cause UNKNOWN |

Nothing was written to any device, to RAM or to storage, so after any of these rows there is nothing to undo: boot the stick again.

It does not answer: which zone is which sensor on this unit (the Windows driver holds that map), the chassis limits, the cost of a poll (a bus read's latency was not timed), whether the
monitor's own EL2 map (q1n1's identity map, the runner's too: INFERRED the same) reaches the windows when it runs six CPUs, whether a restart is thermal, or what skin temperature is.
A guard that those answers feed is separate work (the SP11 monitor plan of the Snapintosh tree, decision D8), and this payload decides nothing about it.

## 7. The operator's note (nothing here authorises a run)

1. It reads, twice 2 s apart, at most 220 words: per block HW_VER, CTRL and the sixteen status words, then TRDY; 2 s later per block CTRL, the sixteen status words and TRDY again;
   then per block sixteen conversion words and two interrupt status words. It writes nothing to any device, to RAM or to storage (only the runner's panel text); no SMC, no HVC, no
   clock or power change.
2. One hazard: a read can hang the SoC (no guard recovers that): the panel freezes or goes dark and the board may reset; hold the power button. Nothing was written, so there is nothing
   to undo and nothing persistent: boot the stick again. A run that hangs is evidence, and the last line is the answer (section 3, with its limit); a silence after `NEXT S2 AFTER 2 S` is
   the wait on a slow counter for up to 8 minutes and a hang after that (section 6).
3. Run it **alone**, on AC power, with one hardware client. Film the right-hand column from `PAYLOAD CALL` until two minutes after `END`, or for ten minutes when there is no `END`, and keep
   the video's `creationdate`.
4. Approve exactly one file: `TSNAP.BIN` with the size and SHA-256 that the reviewer's note names; any edit of the source changes both and needs a new approval. v1.1 is **not** the file of boot 29
   (v1: 9,212 bytes, `dc74cd3e2a1d760a...`): the digits on the runner's `LOADED` line must be v1.1's, not v1's.

## 8. Evidence ledger and pins

Linux tag v7.4-rc2, which `git ls-remote https://github.com/torvalds/linux` peels to commit `7475ea8b58616b33c04afb976cf0fbaad9dd63fb` (read 2026-11-17). `hamoa.dtsi` is the copy that
`docs/SP11-STICK-LOG.md` of the Snapintosh tree pins in its section 10 (BSD-3-Clause); the four Linux files were fetched read-only for this payload from
`https://raw.githubusercontent.com/torvalds/linux/7475ea8b58616b33c04afb976cf0fbaad9dd63fb/<path>` and are **pinned by this document** (GPL-2.0 for the drivers, GPL-2.0 OR MIT for the
binding; read for facts, offsets, names and constants, nothing copied):

| File | Path in the Linux tree | Bytes | SHA-256 |
| --- | --- | --- | --- |
| `hamoa.dtsi` | `arch/arm64/boot/dts/qcom/hamoa.dtsi` | 233,339 | `d5bb1f7ce37c721d75fb5b4cffc8f58bed4d3ef9786a231a0deca05e917529e0` |
| `tsens-v2.c` | `drivers/thermal/qcom/tsens-v2.c` | 9,454 | `0f0d41735b468d247f9d648980b31b30d91df4976d9f74c48767014c0ec74a12` |
| `tsens.c` | `drivers/thermal/qcom/tsens.c` | 37,688 | `81a23bc20344b0c4803369a95ff2520657c6f5112c48abbcdcf0c73708c065d9` |
| `tsens.h` | `drivers/thermal/qcom/tsens.h` | 18,758 | `86e48413e7e36c76674aa4d0108989ce181f47358f38399578f45818fec734fd` |
| `qcom-tsens.yaml` | `Documentation/devicetree/bindings/thermal/qcom-tsens.yaml` | 13,001 | `afee846cd06abc76a6feb3700919669300b3536dc01810c9ba71867b74b90cd8` |

What the DT says besides the windows (VERIFIED by a parse, `hamoa.dtsi:9123-9915`): 50 zones, one sensor each; every zone has a 115 C critical trip, the 12 of aoss0 to aoss3, mem, video,
nsp0 to nsp3 and camera0 and camera1 a 90 C hot trip, and the 8 `gpuss` zones a 95 C passive trip; the 30 CPU and cpuss zones have only the critical one. These are generic SoC values, not
the Surface Pro 11's chassis limits. The board device trees the Snapintosh tree pins (`x1-microsoft-denali.dtsi`, `x1-el2.dtso`) carry no thermal text.

The status word's fields are in the pinned `tsens-v2.c` (`tsens-v2.c:128-138`), and **no pinned file names bits 26:22 or 31:27 of it**: the class `Refs` of the refs test parses the driver's field list
and fails if the pinned copy declares a field above bit 21. The sensor number is therefore evidence of one film of one unit and no more (INFERRED); no new file is pinned for v1.1.

DERIVED from the unit's firmware tables (six dump runs, one DSDT digest; numbers only, nothing pasted): the DSDT declares 33 `ThermalZone` objects, with `_PSV` between 89.85 and
104.85 C and `_CRT` between 109.85 and 119.85 C. Which TSENS sensor each reads is in Windows' driver, not in ACPI (UNKNOWN).

## 9. Not verified

* OBSERVED once, by v1 in boot 29 (one unit, one boot: 220 loads, `FAULTS=0`, no hang): EL2's stage-1 map reaches the eight windows and a load of every word of the list completes; HW_VER reads
  `0X20080000` on all four blocks; CTRL says enabled with CODE_OR_TEMP set and SEN names 13, 11, 11 and 15 sensors (50); the 2 s wait, the second reading and the conversion pass ran behind the
  real runner. None of that is a statement about v1.1, which has not run, but v1.1 reads the same words in the same order.
* UNKNOWN: that firmware calibrated a block (what the conversion words hold is on the film, not in this tree); which of the sixteen ids are populated beyond what SEN says; whether a status read
  changes anything; whether any register survives a restart; the decode of bits 26:22 as a sensor number beyond the one film (INFERRED).
* UNVERIFIED offsets: none of the TM words 0x08 and 0xe4 (TRDY: Linux reads it only for HW_VER major 0, `tsens.c:834-835`), the TM word 0x14 (Linux reads it only as bit 31, `tsens.c:637`) and the
  SROT conversion words 0x60 to 0x9c has been read on any Snapintosh unit before boot 29 (v1 read them there without a fault), and no Linux path reads them for a v2 block; so the status words come first, 0xe4 is the last word of its block and the other
  three groups are read after the second reading, one block at a time, so that a fault or a hang at one of them costs nothing that was already read.
* The wait for the second reading can take longer than the 2 s it names: for a counter that moves far slower than `CNTFRQ_EL0` says it ends after 2^32-1 reads, about 43 s at 10 ns a read and 7
  minutes at 100 ns (INFERRED; a read of the counter was never timed). A counter that runs at its stated frequency never gets near the bound: it did not in boot 29.
* The model's values are made up, but for the replay of boot 29, which uses the digits the film gave and marks the rest as filler. A passing host test shows that the payload does what this document says
  against a model that was written from the same public sources and the same film, never that the unit does it.
* The IR audit proves the base of every store, not its offset; the offsets are bounded by the sanitizers on every host run.
* Under QEMU there are none of the windows, so every block is gated, the second reading is skipped and there is no conversion pass (section 5); those paths ran behind the real runner only in
  boot 29, for v1.
* How far the panel can lag behind the page at a hang is UNKNOWN: the runner draws a line with no barrier before the payload's next load (section 3).
* Hardware: NOT RUN.
