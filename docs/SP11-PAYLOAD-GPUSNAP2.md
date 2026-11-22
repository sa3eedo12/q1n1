<!-- SPDX-License-Identifier: MIT -->
# Payload `gpusnap2`: a read-only look at what the GPU power-on stage would need

**Status: EXPERIMENTAL; hardware NOT RUN.** `payloads/gpusnap2.c` (stick file `GPUSNAP2.BIN`) is experiment E1 of the GPU port plan (`docs/SP11-GPU-PORT-PLAN.md` of the Snapintosh tree, v2, section 5): the
read-only complement of `gpusnap`, whose run (boot 30) found the GPU's CX power domain OFF and its GX domain not up. At EL2, with plain 32-bit loads through the runner's guarded load, it reads what the
plan needs to decide whether the power-on stage must vote for rails and set up PLLs, and what the thermal and speed-bin baseline is: the temperature sensors of the GPU (tsens3, sensors 5 to 12, decoded as
`tsnap` v1.1 does), the one GCC word GPUCC needs and then 21 GPUCC words (the two PLLs, the fast-forward clock with its dividers, branch clocks), the RPMh command database in DRAM (the addresses and level
tables of the GPU's rails and of the bus clock managers), the apps RSC's TCSs (the votes firmware left in the two wake TCSs for those rails) and the QFPROM speed-bin word. It stores nothing but to its own
stack: no write to any device, no SMC, no HVC, no barrier, no tick, no counter. It decides and refuses nothing.

**What has never been read on the unit.** The command database (DRAM), the apps RSC drv-2 page and the QFPROM have never been read there by any payload, so **the first read of the command database, the first read of
the apps RSC and the first read of the QFPROM are of UNKNOWN risk** (section 3): each may answer, abort (the guard shows `FAULT:6`), hang the bus or raise an SError (the guard does not catch it). Of the 21
GPUCC words, three (AHB, CXGD, CXHW) were read in boot 30; the other 18 have not. The tsens3 words and the GCC word were read in boots 29 and 30 and answered.

Labels (Snapintosh `AGENTS.md`): **VERIFIED** read in a pinned file or shown by a host run, never a statement about the unit; **DERIVED** read in a local dump of the unit's firmware tables (numbers only);
**OBSERVED** a run on the unit (boots 3, 8, 9, 22, 29 and 30 are the ones cited; none exists for this payload); **INFERRED**; **EXPERIMENTAL** code that exists and has not run; **UNIMPLEMENTED**; **UNKNOWN**. A SKIP is not a
pass. Citations are `prefix:line` into the pinned Linux copies ([evidence document](SP11-PAYLOAD-GPUSNAP2-EVIDENCE.md), section A): `dt` hamoa.dtsi, `gcc` gcc-x1e80100.c, `cc` gpucc-x1e80100.c, `cb`
clk-branch.h, `cbc` clk-branch.c, `cmn` common.c, `gd` gdsc.c, `rcg` clk-rcg2.c, `pll` clk-alpha-pll.c, `cat` the Adreno catalog, `gmu` a6xx_gmu.c, `ts2` tsens-v2.c, `rsc` rpmh-rsc.c, `rin`
rpmh-internal.h, `cdb` cmd-db.c, `cdh` cmd-db.h, `qf` qfprom.c, `bnd` the rpmh-rsc binding header.

## 1. What it reads

Seven windows and the final UEFI memory map the runner passes. Every base and size is the device tree's (VERIFIED as read there; that the unit has the same windows is INFERRED).

| Block | Window | Base | Size | Pinned source |
| --- | --- | --- | --- | --- |
| TSENS3 sensor ROT | TSROT | 0x0c225000 | 0x1000 | `dt:2804-2814` |
| TSENS3 thermal monitor | TTM | 0x0c274000 | 0x1000 | `dt:2804-2814` |
| GCC | GCC | 0x00100000 | 0x200000 | `dt:758-762` |
| GPUCC | GPUCC | 0x03d90000 | 0xa000 | `dt:4225-4234` |
| Command database (DRAM, reserved) | CMDDB | 0x81c60000 | 0x20000 | `dt:516-520` |
| Apps RSC, drv-2 page | RSC2 | 0x17520000 | 0x10000 | `dt:8599-8613` |
| QFPROM | QFPROM | 0x221c8000 | 0x1000 | `dt:8808-8817` |
| UEFI memory map | MAP | the runner's argument | its size | not a device |

### The registers (every offset VERIFIED in the pinned file named; presence and meaning on the unit INFERRED)

**Why a read is harmless, in general.** Every register below is read by the pinned Linux drivers in normal operation without an acknowledging write, and none is named a clear-on-read register there; the
status registers that Linux does clear (the RSC's `IRQ_STATUS`) are cleared by a separate write to another register (`rsc:440-449`, `rsc:466-470`), which this payload never makes. That is VERIFIED as Linux's use
and INFERRED harmless for a read at EL2 of this unit; the words with no Linux reader (TCS command data) are read only under a rule (section 3) and are the unknown risk.

**TSENS3** (tsnap v1.1's words, the same decode; boot 29 read all of them: HW_VER `0X20080000`, CTRL `0X9D63FFF9`, SEN `0X7FFF`, OBSERVED):

| Window | Offset | Register | Fields and use |
| --- | --- | --- | --- |
| TSROT | 0x00 | HW_VER | the first load of the payload; the block is gated on it (a word that reads, is not 0 and is not all ones) |
| TSROT | 0x04 | CTRL | EN bit 0, SW_RST bit 1, SENSOR_EN bits 18:3, CODE_OR_TEMP bit 21; the TM window is read only when EN is set, SW_RST clear |
| TTM | 0xa0 + 4n | Sn_STATUS, n = 5 to 12 | LAST_TEMP 11:0, VALID 21, MIN to MAX flags 16 to 20 (`ts2:126-138`); bits 26:22 the sensor's own number, 31:27 reserved (INFERRED from the film of boot 29) |

The eight sensors are the GPU's `gpuss-0` to `gpuss-7` zones (`dt:9664-9668`, `dt:9853-9856`: tsens3 5 to 12). **The status word** is decoded as in `tsnap` v1.1: bits 31:27 set, or bits 26:22 not equal to the sensor's own
index: odd (`O`); VALID clear: not valid (`?`); CODE_OR_TEMP clear: odd; outside -40.0 to 120.0 C: `O` and counted in `OUT=`; otherwise the 12-bit two's complement in tenths of a degree C (INFERRED). The number is a
consistency check, never a field the decode needs; a mismatch says the layout is not the film's and says nothing about the die.

**GCC and GPUCC** (read in this order; the GCC word first, GPUCC only behind it). Decode: `.ON` CLK_OFF (bit 31) clear and CLK_ENABLE (bit 0) set, `.OFF` bit 31 set, `.ODD` where neither can be taken at its word (all
ones; CLK_OFF and CLK_ENABLE both clear, which is what a window of zeros reads; CLK_OFF set with a NoC FSM status of ON, `cbc:43-58`).

| # | Window | Offset | Key | Register | Why it is read, and why a read is harmless |
| --- | --- | --- | --- | --- | --- |
| 1 | GCC | 0x71004 | CFGA | GCC_GPU_CFG_AHB_CLK CBCR (`gcc:7451`) | the gate of every GPUCC word: Linux enables it at probe (`cmn:310-320`); a CBCR is polled by Linux (`cbc:43-58`); boot 30 read it (`1.ON`, OBSERVED) |
| 2 | GPUCC | 0x911c | AHB | GPU_CC_AHB_CLK CBCR (`cc:256-530`) | halt status as above; boot 30 read it (`0.ODD`, OBSERVED) |
| 3 | GPUCC | 0x9108 | CXGD | GPU_CX_GDSCR (`cc:533-534`) | the CX GDSC's control and status word (`gd:21-27`); boot 30 read it (`0X22F801`, OBSERVED) |
| 4 | GPUCC | 0x953c | CXHW | GPU_CX_GDS_HW_CTRL (`cc:533-534`) | PWR_ON as bit 31 (`gd:21-27`); boot 30 read it (`0XDFF4.OFF`, OBSERVED) |
| 5 | GPUCC | 0x0000 | PLL0 MODE | PLL_MODE of gpu_cc_pll0, a zonda-ole PLL at offset 0 (`cc:56-60`, `pll:16-34`) | OUTCTRL bit 0, LOCK_DET bit 31; read by Linux's enable and lock checks |
| 6 | GPUCC | 0x0030 | PLL0 OP | OPMODE of the zonda-ole layout (`pll:302-316`) | RUN is 1 (`pll:348-349`); enabled means OPMODE has RUN and MODE has OUTCTRL (`pll:1078-1090`) |
| 7 | GPUCC | 0x0004 | PLL0 L | L_VAL, zonda-ole (`pll:302-316`) | read by Linux's rate query |
| 8 | GPUCC | 0x0008 | PLL0 AL | ALPHA_VAL, zonda-ole (`pll:302-316`) | read by Linux's rate query |
| 9 | GPUCC | 0x1000 | PLL1 MODE | PLL_MODE of gpu_cc_pll1, a lucid-ole PLL at offset 0x1000 (`cc:87-91`) | as row 5 |
| 10 | GPUCC | 0x1004 | PLL1 OP | OPMODE of the lucid-ole layout (`pll:187-202`) | as row 6 |
| 11 | GPUCC | 0x1010 | PLL1 L | L_VAL, lucid-ole (`pll:187-202`) | as row 7 |
| 12 | GPUCC | 0x1014 | PLL1 AL | ALPHA_VAL, lucid-ole (`pll:187-202`) | as row 8 |
| 13 | GPUCC | 0x9474 | FFC | CMD_RCGR of gpu_cc_ff_clk_src (`cc:160`) | ROOT_OFF is bit 31 (`rcg:33-39`); Linux reads it to know whether the clock runs |
| 14 | GPUCC | 0x9478 | FFF | CFG_RCGR, the next word (`rcg:33-39`) | source select bits 10:8 |
| 15 | GPUCC | 0x9050 | XDIV | the XO divider's register (`cc:242`) | a divider word, read by Linux's rate query |
| 16 | GPUCC | 0x9054 | DDIV | the demet divider's register (`cc:227`) | as row 15 |
| 17 | GPUCC | 0x9120 | CRC | GPU_CC_CRC_AHB_CLK CBCR (`cc:256-530`) | as row 2 |
| 18 | GPUCC | 0x914c | CXFF | GPU_CC_CX_FF_CLK CBCR (`cc:256-530`) | as row 2 |
| 19 | GPUCC | 0x9008 | FM | GPU_CC_FREQ_MEASURE_CLK CBCR (`cc:256-530`) | as row 2 |
| 20 | GPUCC | 0x9150 | MEM | GPU_CC_MEMNOC_GFX_CLK CBCR (`cc:256-530`) | as row 2 |
| 21 | GPUCC | 0x9134 | SLP | GPU_CC_SLEEP_CLK CBCR (`cc:256-530`) | as row 2 |
| 22 | GPUCC | 0x93a4 | CB | GPU_CC_CB_CLK CBCR, the driver's critical clock (`cc:612-614`) | as row 2 |

GPUCC's regmap ends at 0x9988 (`cc:604-610`): nothing above it is read. Linux writes the two PLLs' configuration at probe with nothing of the GPU powered (`cc:638-649`), which is the precedent for the PLL words
answering with CX off; no PLL word has been read on the unit (**UV6**). Not read: the GX-side clocks (gx_vsense at 0x90b0, mnd1x_0 and mnd1x_1 at 0x9288 and 0x928c: their domain is not shown to be up), the Zonda
PLL's STATUS word (0x3c), and **everything behind CX**: CX_MISC, the GMU, the RSCC and the GPU SMMU (CX is off, so a read could hang: they stay unread). Of the words the plan's E1 asks for, two groups were already read
by boot 30 and are not read again here (OBSERVED, boot 30): the GCC words that carry the GPLL0 votes, 0x52000 and 0x52030 (`VOTE=0XE0657B CPH=0 DIV=0 GP0V=0X201`), and the command and configuration words of the GMU and hub
root clock generators, GPUCC 0x9318, 0x931c, 0x93ec and 0x93f0 (`GRC=0X80000000.OFF GRF=0 S=0 HRC=0.ON HRF=0 S=0`).

**The command database** (DRAM; its words are read through the same guarded load, never through a pointer). Offsets are from the region's start; `data` is at 0x90 (`cdb:36-80`):

| Offset | What | Read when, and why a read is harmless |
| --- | --- | --- |
| +0, +4 | version, magic (the bytes db 30 03 0c, one word 0x0c0330db: `cdb:101-108`) | first, behind the memory-map gate; a magic that is not Linux's ends the block. Plain reserved DRAM that Linux's lookup reads (`cdb:144-176`): no side effect; whether EL2 maps it is UNKNOWN (**UV1**) |
| +8 + 16i, +12 + 16i | resource header i < 8: slv_id and header_offset, data_offset and cnt (`cdb:36-80`) | until a header with slv_id 0 (`cdb:144-176`); the same memory |
| 0x90 + header_offset + 24j | entry j of an ARC (type 3) or BCM (type 5) header: id word 0 | for j < cnt, at most 128 per header and 256 in all; word 1 (+4) only when word 0 matches a target; the address (+16) and length with offset (+20) only when both match (`cdb:144-176`, `cdh:12-20`); the same memory |
| 0x90 + data_offset + offset | a matched rail's level table, up to eight 16-bit levels (five words at most) | for cx, mx, gfx and gmxc only (`gmu:1823-1838`, `gmu:1894-1910`); the same memory, and the table must lie inside the region |

The targets are the ARC rails `cx.lvl`, `mx.lvl`, `gfx.lvl`, `gmxc.lvl` and `gbx.lvl` (`gmu:1823-1838`, `gmu:1894-1910`) and the BCMs `SH0`, `MC0` and `ACV` (`cat:398-408`), as eight-byte zero-padded ids. The first match in
list order wins, as in Linux (`cdb:144-176`). The VRM (type 4) list and every other type are never walked.

**The apps RSC, drv-2** (`dt:8599-8613`: tcs-offset 0xd00, drv-id 2, `tcs-config` ACTIVE 3, SLEEP 2, WAKE 2, CONTROL 0; Linux numbers the TCSs in that order, `rsc:1007-1048`, so active 0 to 2, sleep 3 and 4, wake 5 and 6;
`bnd:9-12`). A TCS is 672 bytes apart from 0xd00; the layout follows the version word:

| Offset | Register | Read when, and why a read is harmless |
| --- | --- | --- |
| 0x00 | DRV_ID: major 23:16, minor 15:8 (`rsc:41-46`, `rsc:1088-1097`) | first; the block is gated on a word that reads, is not 0 and is not all ones; major 2 and 3 only (Linux takes the 3.0 layout for any major from 3 on; this payload does not). Linux reads it at probe (`rsc:1088-1097`) |
| 0x04, 0x0c | DRV_SOLVER_CONFIG, DRV_PRNT_CHLD_CONFIG: TCS count of drv-2 in bits 17:12, NCPT 31:27 (`rsc:72-76`, `rsc:996-1010`) | after the ID; the TCS count must be 7 or more. Configuration words Linux reads at probe (`rsc:1122`, `rsc:996-1010`) |
| 0xd00, 0xd04 | IRQ_ENABLE, IRQ_STATUS of the TCS block (`rsc:157-175`, `rsc:440-449`) | on the CFG line; IRQ_ENABLE is read-modify-written by Linux (`rsc:417-428`); STATUS is read by Linux's handler and cleared by a separate write (`rsc:466-470`), not by this read (INFERRED) |
| 0xd00 + 672 t + 0x1c or 0x2c | CMD_ENABLE of TCS t, a 16-bit command mask (`rsc:157-194`, `rsc:560-568`) | for the seven TCSs, wake TCSs first; read by Linux to find the commands a TCS holds (`rsc:560-568`) |
| + 0x34 + 20 j or 0x38 + 24 j | CMD_ADDR of command j (`rsc:157-194`, `rsc:560-568`) | for each enabled command of wake TCSs 5 and 6 only; read by Linux in the same loop (`rsc:560-568`) |
| + 0x38 + 20 j or 0x3c + 24 j | CMD_DATA of command j: **no Linux code reads it** (the driver writes it; responses come from RESP_DATA, `rsc:457-460`) | only for a command whose address equals the address of a rail found in the command database; the last such command wins. Whether a read has a side effect is UNKNOWN (**UV4**): this is the one word with no Linux precedent |

The two layouts are `rpmh_rsc_reg_offset_ver_2_7` (command stride 20) and `_ver_3_0` (stride 24), both with a TCS stride of 672 (`rsc:157-175`, `rsc:176-194`); the maximum number of commands is 16 (`rin:15`).

**The QFPROM.** One word, 0x118 (`dt:8808-8817`: the cell `gpu-speed-bin` at 0x119, two bytes, bits 7 to 14 of the cell; `qf:337-347` adds the byte offset within the word to the bit offset, so the fuse is bits 22:15 of the
word at 0x118). Linux reads whole words at `base + reg` (`qf:319-335`). The fuse value maps to a bin by the catalog: 0 to 0, 59 to 1, 7 to 2, 232 to 3, 146 to 4 (`cat:411-417`); another value prints `SB=?`.

## 2. The page

At most 34 lines of at most 100 characters, the payload's own prefix included (the ABI allows 40 lines and 4096 loads; this payload keeps to 34 lines and 2048 loads, so that it fits the panel's region alone in
its boot: section 4). A nominal page is 31 lines and 1026 loads (`tools/test-q1n1-sp11-payload-gpusnap2.c`, `--numbers`); the loads every block can make at most add up to 1971 (the memory map is the bulk: four words of each of
320 descriptors), and 34 lines is three more than the nominal page needs:

<!-- numbers -->
LINES 31 LOADS 1026 LINE_CAP 34 LOAD_CAP 2048 PAGE_LINES 31 LOADS_MAX 1971
<!-- /numbers -->

The sample below is the page of the host model's made-up fixture, **not the unit's page**. What the unit showed is the identity and control words of tsens3 (boot 29) and the CFG AHB word and the three GPUCC words boot
30 read (the fixture's `AHB=0.ODD CXGD=0X22F801 SC=1 HW=0 CXHW=0XDFF4.OFF` are those); every other value, the whole command database, the RSC and the QFPROM are the fixture's, and the memory map has the shape of the unit's
(a reserved descriptor of 0x2c0 pages at 0x81a40000, DERIVED). The gated and abort pages are in the [evidence document](SP11-PAYLOAD-GPUSNAP2-EVIDENCE.md), section C.

<!-- page -->
```
PAYLOAD GPUSNAP2 READ ONLY EL=2 CAP=2048/34
PAYLOAD GPUSNAP2 KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=NOT TRUSTED NA=NOT READ -=NO VOTE TEMP=0.1 C
PAYLOAD GPUSNAP2 NEXT TSENS3
PAYLOAD GPUSNAP2 T3 VER=0X20080000 CTL=0X9D63FFF9 SEN=0X7FFF
PAYLOAD GPUSNAP2 T3 R5 0160018E 01A00186 01E00181 02200184 02600180 02A00187 02E0018B 03200185
PAYLOAD GPUSNAP2 T3 C5 398 390 385 388 384 391 395 389 V=8 MIN=384(S9) MAX=398(S5)
PAYLOAD GPUSNAP2 NEXT GCC
PAYLOAD GPUSNAP2 GCC CFGA=1.ON
PAYLOAD GPUSNAP2 NEXT GPUCC
PAYLOAD GPUSNAP2 GPUCC AHB=0.ODD CXGD=0X22F801 SC=1 HW=0 CXHW=0XDFF4.OFF
PAYLOAD GPUSNAP2 GPUCC PLL0 MODE=0 OP=0 L=0X29 AL=0XA000 EN=OFF LK=0
PAYLOAD GPUSNAP2 GPUCC PLL1 MODE=0 OP=0 L=0X16 AL=0XEAAA EN=OFF LK=0
PAYLOAD GPUSNAP2 GPUCC FFC=0X80000000.OFF FFF=0X100 S=1 XDIV=0 DDIV=1
PAYLOAD GPUSNAP2 GPUCC CRC=0X80000000.OFF CXFF=0X80000000.OFF FM=0X80000000.OFF
PAYLOAD GPUSNAP2 GPUCC MEM=0X80000000.OFF SLP=0X80000000.OFF CB=0X80000001.OFF
PAYLOAD GPUSNAP2 NEXT CMDDB
PAYLOAD GPUSNAP2 CMDDB MAP DESC=227 HITS=1 T=0 ATTR=1 OPEN
PAYLOAD GPUSNAP2 CMDDB HDR VER=1 MAGIC=OK HDRS=3 ARC=8 BCM=6
PAYLOAD GPUSNAP2 CMDDB ADDR CX=0X30000 MX=0X30004 GFX=0X3000C GMXC=0X30010 GBX=0X30014
PAYLOAD GPUSNAP2 CMDDB BCM SH0=0X50008 MC0=0X50004 ACV=0X50000
PAYLOAD GPUSNAP2 CMDDB LVL CX=9:16/48/64/128/192/256/320/384 MX=8:16/48/64/128/192/256/384/416
PAYLOAD GPUSNAP2 CMDDB LVL GFX=7:16/48/64/128/192/256/384 GMXC=4:16/64/128/256
PAYLOAD GPUSNAP2 NEXT RSC2
PAYLOAD GPUSNAP2 RSC2 ID=0X20701 VER=2.7
PAYLOAD GPUSNAP2 RSC2 CFG SOL=0 CHLD=0X18007000 NT=7 IRQE=7 IRQS=0 NCPT=3
PAYLOAD GPUSNAP2 RSC2 EN W5=7 W6=7 S3=3 S4=3 A0=0 A1=0 A2=0
PAYLOAD GPUSNAP2 RSC2 W5 N=3 CX=64 MX=64 GFX=- GMXC=-
PAYLOAD GPUSNAP2 RSC2 W6 N=3 CX=128 MX=128 GFX=- GMXC=-
PAYLOAD GPUSNAP2 NEXT QFPROM
PAYLOAD GPUSNAP2 QFPROM W118=0X1D9234 FUSE=59 SB=1
PAYLOAD GPUSNAP2 END LOADS=1026 FAULTS=0 SKIPS=0 BLK=0 CUTS=0 LINES=31
```
<!-- /page -->

### What each line says

| Line | Meaning |
| --- | --- |
| `READ ONLY EL=2 CAP=2048/34` | the payload's two caps: loads and lines |
| `NEXT <block>` | printed BEFORE the first load of the block; a block whose line cannot be printed is not read. A gated block has no `NEXT` line, only `<block> GATED BY <why>` |
| `T3 VER= CTL= SEN=` | HW_VER, CTRL and the SENSOR_EN field, printed before the first load of the TM window; after HW_VER alone `GATED`, after CTRL alone `OFF` (EN clear or SW_RST set) or `CTLERR` (the CTRL load aborted), and `CODE` when CODE_OR_TEMP is clear |
| `T3 R5`, `T3 C5` | the raw status words of sensors 5 to 12 (eight hex digits each) and their temperatures in tenths of a degree C (`?` not valid, `O` odd or out of range), `V=` valid, `MIN=` and `MAX=` with the sensor as `(S<n>)`, then `CRIT=`, `OUT=` and `ODD=` when above 0 |
| `GCC CFGA=` | the CFG AHB word; `.ON` opens GPUCC, anything else closes it (`GPUCC GATED BY AHB`; `AHBERR` when the word was not read or is all ones) |
| `GPUCC ...` | the table of section 1, one line for each group of words, read whole and printed before the next is read; `AHB`, `CXGD` with `SC=` (SW_COLLAPSE) and `HW=` (HW_CONTROL), `CXHW`; `PLL0`/`PLL1` with `EN=` (ON, OFF, ODD or NA) and `LK=` the lock detect; `FFC`, `FFF` with `S=` the source select, `XDIV`, `DDIV`; the branch clocks |
| `CMDDB MAP DESC= HITS= T= ATTR=` | the descriptors of the final memory map, how many overlap the region, the first one's type and attribute, and the verdict: `OPEN` (the descriptors that overlap are all type 0, reserved, and cover the whole region), `NONE` (none overlaps), `TYPE` (one is another type), `PART` (they leave a gap), `BAD` (a damaged map: a descriptor not page aligned or past 48 bits, more hits than 8, or arguments that do not describe a map), `ERR` (a map word did not read). Anything but `OPEN` is followed by `CMDDB GATED BY MAP` |
| `CMDDB HDR VER= MAGIC= HDRS= ARC= BCM=` | version, whether the magic is Linux's, the resource headers found and the ARC and BCM entry counts; a bad magic or a version that did not read is `CMDDB GATED BY MAGIC` |
| `CMDDB ADDR`, `CMDDB BCM` | the address of each target; `NONE` not in the list, `PART` not found in the part of the list that was scanned (a cap), `FAULT:n` or `NA` the word that did not read |
| `CMDDB LVL` | `<n>:<levels>`: the number of levels and the first eight, decimal, separated by `/`; `EMPTY`, `ODD` (an odd byte offset), `RANGE` (outside the region) or the token of the word that did not read |
| `RSC2 ID= VER=` | the ID word and `major.minor`; `RSC2 GATED BY ID` (not read, zero or all ones) or `VER` (a major other than 2 and 3) or `TCS` (fewer than 7 TCSs for drv-2) |
| `RSC2 CFG` | the solver and child configuration words, the TCS count `NT=` of drv-2, the interrupt words and `NCPT` |
| `RSC2 EN` | the enable mask of each TCS, wake first (`W5 W6`), then sleep (`S3 S4`), then active (`A0 A1 A2`); a word with a bit above 15 prints `.ODD` |
| `RSC2 W5`, `RSC2 W6` | the wake TCS: `N=` the enabled commands, then for each rail of the database the data word of the last command whose address is the rail's: decimal below 0x10000, else hex; `-` no such command |
| `QFPROM W118= FUSE= SB=` | the word, the fuse field and the speed bin (`?` for a fuse value not in the catalog) |
| `END LOADS= FAULTS= SKIPS= BLK= CUTS= LINES=` | the loads made; those that aborted; the words not read because an earlier load of the window aborted; the mask of the windows that were not read (TSROT 1, TTM 2, GCC 4, GPUCC 8, CMDDB 0x10, RSC 0x20, QFPROM 0x40, memory map 0x80); fields dropped for lack of room; the lines of the page |

Other tokens: `FAULT:n` (the runner's code for an aborted load: 6), `SKIP` (not read because an earlier load of its window aborted), `BUDGET` (the load cap was reached), `NA`, `SKIPPED_NOT_AT_EL2` and
`REFUSED_NO_LOAD32` (one line, no load). A field that does not fit the 100 characters is dropped whole and counted in `CUTS`, never cut in half. The first abort in a window ends every later read of it, the
memory map's included; no other window is silenced. Nothing is retried.

## 3. Hazards, and what the order is for

A load of a block behind a stopped clock, a collapsed power domain or a protection unit can hang the SoC, and no guard recovers that: the runner's guarded load turns a synchronous abort into `FAULT:n`, nothing more. An
SError (a protection-unit violation may surface as one) is not caught and q1n1 keeps it masked: the load aborts nothing on the page and the board may reset. One hang is on record for this unit: boot 3's read of a PCIe
ECAM never returned and the board rebooted by itself ([SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md); an operator report, with a hang and a watchdog reset as the INFERRED cause).

| Window | Read on the unit before | If it goes wrong |
| --- | --- | --- |
| TSROT, TTM | boot 29 read these words and 220 in all, `FAULTS=0` (OBSERVED) | nothing new |
| GCC 0x71004 | boot 30 (OBSERVED) | nothing new |
| GPUCC, 3 of the 21 words | boot 30 read AHB, CXGD, CXHW and 16 others of this window, all answered with CX off (OBSERVED) | the other 18 words are in the same window behind the same gate: UNKNOWN, but the same page of registers |
| **Command database, DRAM** | **never** | **UNKNOWN risk**: the first read may fault (`FAULT:6`), answer, hang or raise an SError |
| **Apps RSC drv-2** | **never** | **UNKNOWN risk**: as above, and the TCS data words have no Linux reader |
| **QFPROM** | **never** | **UNKNOWN risk**: as above; Linux reads the same word through nvmem (`qf:319-335`) |

* **The order, and what it buys.** TSENS3 first (all read before, the value the plan names first), then the one GCC word, then GPUCC behind it, then the command database (whose addresses the RSC lines need), then the RSC, then the
  QFPROM last: the least valuable word and one of the three windows of unknown risk. The three unknown windows come after everything the payload can show without them, so that a hang or a reset keeps the page so far. Each block
  is announced by a `NEXT` line before its first load, each line is read whole and printed before the next is read, and no block is read when its own gate does not stand.
* **The last line on the panel names what hung.** After `NEXT TSENS3` and nothing else, HW_VER; after `T3 VER`, the CTRL word or the eight status words; after `NEXT GCC`, the CFG AHB word; after `NEXT GPUCC`, the AHB word
  or the next table line; after `NEXT CMDDB`, the memory map (it is read before the line that shows its verdict); after `CMDDB MAP ... OPEN`, the first word of the database; after `CMDDB HDR`, the resource headers' later
  words and the entries (the `ADDR` and `BCM` lines come after the whole walk); after `CMDDB BCM`, the level words; after `NEXT RSC2`, the ID; after `RSC2 ID`, the configuration words; after `RSC2 CFG`, the enable words;
  after `RSC2 EN`, the addresses and data words of wake TCS 5, then 6; after `NEXT QFPROM`, the QFPROM word. **The limit:** the runner draws a line with stores into the frame buffer and the payload's next device load follows with
  no barrier; if that load hangs the SoC the last line seen may be older than the last printed one, by an unknown number of lines, so the hang is at that line's loads or a later one's, never an earlier one's.
* **GPUCC is read only behind proof**: the CFG AHB word must read and say `.ON` (enabled, CLK_OFF clear). A word that did not read, or reads all ones, is `AHBERR`: a failed gate read is never reported as the thing it gates on.
  Boot 30 read GPUCC under the same gate.
* **How the command database is read, and what can and cannot be proven.** The region is DRAM that firmware reserves (`dt:516-520`). A payload may not ask the MMU (no `at`, no barrier: the binary check refuses both), so it
  cannot learn whether EL2's stage-1 tables map the region. What is known: (a) the unit's own UEFI memory maps (six dumps of 227, 226, 226, 230, 231 and 231 descriptors, a descriptor size of 48; DERIVED, numbers only) describe the region as
  `EfiReservedMemoryType` inside one descriptor of 0x2c0 pages from 0x81a40000, attribute 0x1, and no other descriptor overlaps it; (b) EL2's stage-1 map reached the conventional RAM and the firmware's allocations
  (types 1 to 7, `WB.OS.NS1`: `el2mem`, boots 8 and 9, OBSERVED), but nothing observed says that it reaches reserved memory or a device region it was not asked about; (c) the PCIe SMMU's page (0x15400000), asked
  with `AT S1E2R` in boot 22, answered a level-3 translation fault ([SP11-PAYLOAD-NVMESNAP.md](SP11-PAYLOAD-NVMESNAP.md)), so a device page that EL2 does not map is a real case on this unit (OBSERVED); (d) the
  guard has never fired on the unit (every run has `FAULTS=0`; that an unmapped page gives a translation fault which the guarded load turns into `FAULT:6` is INFERRED, OBSERVED under QEMU only). So the payload (1) reads the final memory map
  the runner passes, through the same guarded load (it lies in the runner's own allocation, which `el2mem` showed mapped), and **reads the database only if the descriptors that overlap its 128 KiB are all
  type 0 and together cover all of it** (the rule of the A16 flow, `tools/a16gpu.py step_cmd_db` of the Snapintosh tree); any other verdict gates the block and the map line says which; (2) reads the magic before anything
  else of the database and walks nothing behind a magic that is not Linux's; (3) bounds every read: entries 24 bytes at most 128 per list and 256 in all, level tables of at most five words that must lie inside the
  region; (4) ends the block at its first abort. What this **does not** prove: that the region is mapped at EL2 (UNKNOWN: a translation fault would show as `FAULT:6`), that firmware left the database intact after
  ExitBootServices (**UV2**), or that the read raises no SError.
* **The RSC.** Only drv-2 (the apps DRV Linux uses at EL1) is touched, never drv-0 or drv-1. The ID word is read first and gates the rest: a word that does not read, or is 0 or all ones, ends the block (`GATED BY ID`);
  a major other than 2 or 3 is `VER`; fewer than 7 TCSs for drv-2 in the child configuration is `TCS`. Only the wake TCSs' command addresses are read (the live levels show only there, the plan says), and a data word only
  when its address equals the address of a rail found in the database: at most 2 x 16 of them, none when the database was not read. A TCS enable word with a bit above 15 is not a mask and no command of that TCS is read.
* **The QFPROM** is one word, read last.
* **It writes nothing**: the only stores of the binary are to its own stack, shown by the IR audit and by the binary's memory check (section 5). The source holds no write and no barrier; the counter is not read at all.

## 4. The chain budget

The runner prints `files + 1` lines of its own once and three per payload (`VERIFY`, `CALL`, `DONE`); the panel's region holds about 89 rows on the unit's panel (computed). The most rows seen drawn is 73, in boot 29: 9 runner
rows, the 34 lines of `tsnap` and the 30 of `inputsnap`, to the last `PAYLOAD DONE` (OBSERVED once, from the film; [SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md) still records 58, the older number). A payload may print at
most 40 lines. `gpusnap2` prints at most 34, so **alone in its boot it needs 39 rows, within the 73 drawn in boot 29**, and it can run ahead of a 40-line payload:

<!-- chain-budget -->
| Chain | Lines | Rows left of 89 |
| --- | --- | --- |
| `gpusnap2` alone | (1 + 1) + 3 + 34 = 39 | 50 |
| `gpusnap2`, then an xHCI payload (40) | (2 + 1) + 2 x 3 + 34 + 40 = 83 | 6 |
| `gpusnap2`, then `psci` (30) | (2 + 1) + 2 x 3 + 34 + 30 = 73 | 16 |
| `gpusnap2`, then `tsnap` v1.1 (34) | (2 + 1) + 2 x 3 + 34 + 34 = 77 | 12 |
| `gpusnap2`, a second 34-line payload and an xHCI payload | (3 + 1) + 3 x 3 + 34 + 34 + 40 = 121 | none: more rows than the panel has |
<!-- /chain-budget -->

The first run is **alone**: a hang or a reset takes every earlier line of the same chain with it ([SP11-PAYLOAD.md](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot)); `tsnap` v1.1 and `gpusnap2` do not share a boot,
and a chain of the two is 77 rows, more than the 73 ever seen drawn (89 is a computed bound): the last rows of the second page, its `END` and `DONE` lines, would lie beyond anything seen.

## 5. Tests

All host and QEMU only: no suite touches the unit. Environment as for the other SP11 payload suites (`tools/sp11_payload_testlib.py` finds the LLVM tools).

| Command | What it shows | What it does not show |
| --- | --- | --- |
| `python3 tools/test-q1n1-sp11-payload-gpusnap2.py` | the host program over a model of the windows, the command database and the memory map under ASan and UBSan, at the shipped caps and with smaller line and load caps; the IR audit (no integer becomes a pointer, every store is rooted in the payload's own stack) on the real source and on 14 hand-written faulty texts; the binary check (`gpusnap2` policy of `tools/sp11_payload_testlib.py`: one system register, no SMC, no barrier, the memory discipline `read_only`) and the stack depth; two builds that are byte for byte the same; the seeded bugs; this document against the header and the model | anything about the unit |
| `GPUSNAP2_REFS_DIR=.. python3 tools/test-q1n1-sp11-payload-gpusnap2-refs.py` | every `prefix:line` of the two documents, the header and the source's constants, read back from the pinned copies; the digests; the Linux path of every file against the name it is pinned under; without the copies only the ledger checks (paths included) and the statement checks (what the documents and the header say that a review corrected) run and the rest SKIPs | anything about the unit |
| `python3 tools/test-q1n1-sp11-payload-qemu-gpusnap2.py` | the binary behind the runner at EL2 under QEMU/EDK2, alone and after `state`: the runner's counters agree with the page, which keeps to its lines and the font | any value of the unit; the command database and the RSC (QEMU never opens those gates) |

The host program's suites: `unit` (the page above, line by line, every load once, in the model's own list), `order` (every NEXT line before the loads of its block, the blocks in order, each line right after the loads it
holds), `tsens`, `gpucc` (every decode against the model's own, the PLL verdicts, the CFG AHB gate in all its cases), `map` (44 named memory maps, wrap-arounds included, against an independent sort-and-sweep oracle),
`cmddb` (the walk against an independent byte-wise oracle: lists, caps, duplicates, level tables to the end of the region, aborts at every word), `rsc` (both layouts, the version and TCS gates, the rail matches, the data reads),
`qfprom`, `gates` (every gate closed in turn: no load behind it, the reason on the page), `faults` (an abort at every one of the loads, and storms of aborts), `hang` (a hang at every load: the page so far is a prefix of the clean
page and its last line names the block), `random` (1500 random worlds against the page oracle and 600 with aborts), `storm` (hostile fills of every window), `budget` (the worst-case world's loads against the bound the
header derives) and `el` (not at EL2, no `load32`, bad arguments); the model holds its **own** list of what a read may reach, its own decode, its own oracles of the map and the database, written from the pinned files and not from the
payload's tables, so that a wrong table or rule in the payload is a difference and not an echo. A defensive check that the shipped tables never trip (the window and range tests of the read primitive) has no
seeded bug of its own: removing it changes nothing a test can see. The seeded bugs are listed in the [evidence document](SP11-PAYLOAD-GPUSNAP2-EVIDENCE.md), section B.

QEMU shows the structure only: the `virt` machine has none of the windows (the platform bus and the PCIe range abort or read as zeros, the flash answers with the firmware's bytes, and its memory map describes no
region at the database), so the page shows tsens3, the RSC and the QFPROM as `FAULT:6` or a word that is no identity, GCC as whatever the flash holds at 0x171004, and the command database as `GATED BY MAP`. It does
**not** show the command database, the RSC, a decoded temperature or any value of the unit ([evidence document](SP11-PAYLOAD-GPUSNAP2-EVIDENCE.md), section D).

## 6. What it answers, and what it does not

What a page would say once there is one (none exists). The labels are those the statement would carry then; the page itself is OBSERVED, a cause or a meaning is whatever the row says.

| The page shows | It says | Label |
| --- | --- | --- |
| `T3 VER=FAULT:6 GATED` | the TSROT load aborted: not the case in boot 29, so the file is not what was approved, or the map changed | the abort OBSERVED |
| `T3 C5` with temperatures near room or idle temperature and `V=8` | the decode is plausible and the eight GPU sensors are live: the thermal baseline for E5 to E7 | OBSERVED; the decode stays INFERRED |
| `ODD=` above 0 or `?` cells | a word whose sensor number is not its index, or a sensor that is not valid: compare `SEN=` and the `R5` words | OBSERVED; the cause INFERRED |
| `GCC CFGA=` not `.ON` and `GPUCC GATED BY AHB` | the GPU's CFG AHB clock is not running: boot 30 said it was, so something changed between the boots | OBSERVED; the cause UNKNOWN |
| `GPUCC PLL0` or `PLL1` with `EN=OFF` and `L=` set | the PLL is configured and not running (the likely state of a GPU that is off): S1 must start it, with the frequency the `L` and `AL` words give | OBSERVED; the plan's decision follows from it |
| `EN=ON LK=1` | firmware left the PLL running and locked: S1 need not set it up | OBSERVED |
| a GPUCC word `FAULT:6` | the window faults at that offset with CX off; the rest of the window was not read (`SKIPS`) | the abort OBSERVED, the cause UNKNOWN |
| `CMDDB MAP ... NONE`, `TYPE`, `PART` or `BAD`, `CMDDB GATED BY MAP` | the memory map does not describe the database as reserved memory in this boot: nothing of it was read; compare with the DERIVED shape in section 3 | OBSERVED; the cause UNKNOWN |
| `CMDDB MAP ... OPEN` then `HDR VER=FAULT:6 MAGIC=SKIP`, `GATED BY MAGIC` | EL2's stage-1 map does not reach the region, or a protection unit refused the read: the first word aborted | the abort OBSERVED, the cause UNKNOWN |
| `HDR` with `MAGIC=BAD` | what is at the region is not Linux's command database (zeros, ones, or a database of another layout) | OBSERVED; whether firmware keeps it intact after ExitBootServices UNKNOWN (UV2) |
| `CMDDB ADDR` with an address for `CX`, `MX`, `GFX`, `GMXC` and `LVL` tables | the rails exist in the database at these addresses and these levels: S1 can vote for them by address | OBSERVED; that a vote works is E2's question |
| a target `NONE` or `PART` | the rail is not in the part of the list that was scanned: absent, or beyond the caps (128 per list, 256 in all) | OBSERVED |
| `RSC2 ID=FAULT:6`, `GATED BY ID` | the drv-2 page is not mapped at EL2 or refused: no vote word of the unit was read | the abort OBSERVED, the cause UNKNOWN |
| `RSC2 W5` or `W6` with `CX=` and `MX=` set and `GFX=-` | firmware left votes for CX and MX in the wake TCS and none for the GPU's rail: the GPU's rail needs a vote of its own (the plan's E2) | OBSERVED; INFERRED that the wake TCS holds the live levels |
| `RSC2 EN W5=0 W6=0` | the wake TCSs are empty: there is nothing to see in them, and whether the sleep or active TCSs hold votes is on the same line | OBSERVED |
| `QFPROM W118= FUSE= SB=` with a bin | the speed bin by the catalog's table, for the OPP choice (the plan's U8) | OBSERVED; the table INFERRED to be this unit's |
| `BUDGET` in place of a word | the load cap (2048) was reached, which the nominal page (1026 loads) and the worst case (1971) cannot do: the file is not what was approved | OBSERVED |
| `CUTS` above 0 on `END` | a field did not fit and was dropped, never cut; every value is still on its own line elsewhere | OBSERVED |
| the last line is a `NEXT` line or a line of a block, and nothing after | what section 3 says hung (and its limit) | OBSERVED |
| `END` is on the page, then a q1n1 fault page or a reset | the payload finished with nothing in flight; what follows is the runner's or q1n1's (an SError from a load that aborted late is one candidate, INFERRED) | OBSERVED; the cause UNKNOWN |

Nothing was written to any device, to RAM or to storage, so after any of these rows there is nothing to undo: boot the stick again. It does not answer: whether the CX GDSC enables at the current rail levels without a vote
(E2), whether the votes it shows are live (the wake TCS holds what is replayed on a wake-up: INFERRED from the driver, never observed), the GPU's chip id, or what a vote costs.

## 7. The operator's note (nothing here authorises a run)

1. It reads at most 2048 words (1026 in the nominal page, 1971 at the most): the tsens3 sensors, one GCC word, 21 GPUCC words, the final memory map (four words of each descriptor), the command database, the RSC's
   identity, configuration, enable, address and rail data words, and the QFPROM word. It writes nothing to any device, to RAM or to storage (only the runner's panel text); no SMC, no HVC, no clock, power or rail change.
2. One hazard class: a read can hang the SoC (no guard recovers that) or raise an SError: the panel freezes or goes dark and the board may reset; hold the power button. **The first reads of the command database, of the apps RSC
   and of the QFPROM are of unknown risk**: nobody has read them on this unit. Nothing was written, so there is nothing to undo: boot the stick again. A run that hangs is evidence, and the last line is the answer (section 3, with its limit).
3. Run it **alone**, on AC power, with one hardware client. Film the right-hand column from `PAYLOAD CALL` until two minutes after `END`, or for ten minutes when there is no `END`.
4. Approve exactly one file: `GPUSNAP2.BIN` with the size and SHA-256 of the operator's note; any edit of the source that changes the binary changes both and needs a new approval. An independent review (2026-11-22) found the binary named in that note safe for one read-only run: no blocker, no major finding, seven minor ones, applied in this version of the document and its tests; it covers that binary only.

## 8. Evidence ledger and pins

Linux tag v7.4-rc2, which `git ls-remote https://github.com/torvalds/linux` peels to commit `7475ea8b58616b33c04afb976cf0fbaad9dd63fb` (read 2026-11-17). Eighteen files are pinned by SHA-256: eleven by the Snapintosh
tree (`docs/SP11-STICK-LOG.md` section 10) or by the `gpusnap` and `tsnap` documents, and seven fetched read-only for this payload from `https://raw.githubusercontent.com/torvalds/linux/<revision>/<path>`; the files, their
digests and the line ranges the documents cite are in the [evidence document](SP11-PAYLOAD-GPUSNAP2-EVIDENCE.md) (GPL-2.0 for the drivers, BSD-3-Clause for the device tree; read for facts, offsets, names and constants, nothing
copied). `tools/sp11_payload_gpusnap2_refs.py` holds the ledger: every citation of these two documents lies in one of its ranges, and each range is held to the pinned text by the refs test.

DERIVED from the unit's firmware tables (six dump runs; numbers only, nothing pasted): the six memory maps hold 227, 226, 226, 230, 231 and 231 descriptors of 48 bytes (the payload's cap is 320, a margin of 89 over the
largest); in every one the region 0x81c60000 to 0x81c80000 lies inside one reserved descriptor of 0x2c0 pages from 0x81a40000, attribute 0x1. A probe took the dumps, not the runner at its exit from boot services, so the
map the payload reads may differ by a few descriptors: a changed overlap, type or count gates the block and does not read it. The A16's flow (`tools/a16gpu.py step_cmd_db`) is the model for the gate; it ran on another machine.

## 9. Not verified

* **UV1**: whether the unit's EL2 stage-1 map reaches the command database (0x81c60000), the apps RSC drv-2 page (0x17520000) and the QFPROM (0x221c8000): none has ever been read there, so whether a read faults, hangs the
  bus or raises an SError is UNKNOWN. **UV2**: whether the database is intact after ExitBootServices (the magic word is checked, but what the firmware keeps there is not known). **UV3**: the RSC's version on this SoC
  and what firmware left in its wake TCSs. **UV4**: that reading the RSC words, the data words of TCS commands (no Linux reader) and the QFPROM word has no side effect on the unit. **UV5**: the sensor-number field
  (bits 26:22) of a tsens3 status word: no pinned file defines it; INFERRED from the words of boot 29. **UV6**: whether the PLLs read their own state with CX off. **UV7**: what each word means for the plan; the page
  shows words and the decisions are made from them later.
* Hardware: NOT RUN.
* The model's values are made up, but for the words listed in section 2 and the memory map's shape. A passing host test shows that the payload does what this document says against a model written from the same public
  sources, never that the unit does it. The IR audit proves the base of every store, not its offset; the offsets are bounded by the sanitizers on every host run.
* Under QEMU none of the windows exists (section 5): the command database, the RSC, a decoded temperature and the QFPROM's decode ran only in the host test.
* Bit 26 of a status word is covered twice (the reserved mask from bit 27 and the sensor number), so a seeded bug that moves the mask by one bit down is equivalent and has no mutant.
* How far the panel can lag behind the page at a hang is UNKNOWN (section 3).
