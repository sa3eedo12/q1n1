<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `gpusnap`: a read-only look at the clock and power state of the Adreno X1-85, taken before anything is written (stage S0)

`payloads/gpusnap.c` (with `payloads/gpusnap-regs.h`, its register table) is one payload of the stick payload runner described in [SP11-PAYLOAD.md](SP11-PAYLOAD.md): the manifest
and the stick files, [the chain](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot), ABI v1 and the [line catalogue](SP11-PAYLOAD.md#line-catalogue) are defined there and not
repeated. It is stage S0 of the first-contact plan for the GPU (`docs/SP11-GPU-PORT-PLAN.md` section 7.1 of the Snapintosh tree, steps R2 to R5): the words that say whether the GPU's
clocks and its CX power domain are up, read once at entry and once more after an 8 s wait, in an order in which no read needs more than the ones before it proved, and **before any step that
writes** (S1, the CX power-on, is the first). Whether any of it answers on this unit has never been asked: no GPU word has been read there, and whether a read aborts, hangs the bus or
raises an SError is UNKNOWN.

Evidence labels as in the study: VERIFIED (a pinned Linux file says so; never "it was run"), OBSERVED (read on the unit, once), INFERRED, EXPERIMENTAL, UNIMPLEMENTED, UNKNOWN. `S0` in
this document is the stage of the GPU plan; "survey S0", "S0b" and "boot 18A" are the stick log's. The survey S0 and S0b (boot 5, [SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md)) read
USB-side and apps SMMU words, and boot 18A, the first run of `usbsnap`, made 334 guarded loads of GCC, USB controller and apps SMMU words and waited 8 s with the screen lit and no fault
(OBSERVED, one unit, one boot): that shows guarded loads and the wait are survivable in those windows and says **nothing** about a GPU window.

**EXPERIMENTAL; hardware NOT RUN.** Nothing in this document was read from the unit by this payload: the host model, the compiled-code audits, the pinned-copy test and QEMU are all the
evidence there is. It stores **nothing** by its own code (its only stores are to its own stack; the runner draws the lines it prints), makes no `smc` or `hvc`, uses no barrier, starts no
timer and waits once. It needs its own record and the operator's approval of its SHA-256 before any run; this document authorises none. The safety rules with their seeded bugs, the tests, what QEMU
shows and the pinned files are in [SP11-PAYLOAD-GPUSNAP-EVIDENCE.md](SP11-PAYLOAD-GPUSNAP-EVIDENCE.md).

The GX side of the GPU (the GPU window `0x03d00000`: RBBM, CP and the rest) is never read: that window is not in the table, no row can reach it, and the seeded bug that moves a row into it is
refused (`gx-register-read`). Whether GX is up is taken from the GMU's own status word (`GXST`), a CX-side register, as plan 7.1 R6 says.

**The order inside a block is the safety argument too**, because the first abort in a window ends the window. Every block starts with a word that Linux itself reads in that block (a first
load that is known to be one the SoC answers at all, as far as the pinned code shows), the data the run exists for comes next, and the four words **no** Linux code reads are read last of all:
after the wait and the drift report, each block under its own `NEXT LATE` line ([the late words](#the-late-words)).

## What it answers, and what it does not

It answers, on the film: is the clock Linux keeps on for all GPU register access (`GCC_GPU_CFG_AHB_CLK`) running at entry? Is the CX GDSC on, free of software collapse and of hardware control,
with the seven clocks of the GMU node running (the plan's gate R4, printed as the `R4` line)? If so: what does the GMU think of GX (`GX`), has a GMU firmware initialised (`INIT`), is the RSC idle
(`BSY`, `ST0`, `TCS`), and which page table formats and address sizes does the GPU SMMU implement (the `SMMU` decode, which plan item W2 needs)? Then, last of all and only on a state that still
holds, the four late words (`RST`, `CFG`, `BUSY`, `PDCS`). And does anything in GCC or GPUCC **move** during 8 s of nothing (`DRIFT`)? A block whose gate is closed is **not read** (`GATED BY`),
and the words that closed it stay on the page.

It does **not** answer whether the GPU works (nothing is written or started), what a value means on this silicon beyond what the pinned Linux files say (the decodes are theirs: VERIFIED as what
they say, INFERRED for the unit), who owns a block that refuses a read (a `FAULT:6` is a result; plan risk R2, who owns RPMh, the RSC and the GPU SMMU at EL2, stays UNKNOWN), or anything
about a PLL's lock, the PDC (`gmu_pdc`, `0x0b280000`: not read), RPMh, the thermal sensors or the secure world.

## How it follows plan 7.1

| Plan 7.1 | This payload |
| --- | --- |
| R0, R1: host only; the SError guard | not here: a payload has no strict-mode link, and an SError is neither caught nor printed (below) |
| R2: GCC, "AHB branch off: stop" | `NEXT GCC`, seven words, no gate; `GPUCC GATED BY AHB` when `CFGA` does not read as running, and the page goes on to snapshot 2 (a payload cannot "stop" its own reading, only not read). The plan's "GPLL0 votes `0x52000` bits 15-16" are the votes of the GPU's two GPLL0 **output branches**; the PLL's own vote is `GP0V` |
| R3: GPUCC | 19 words: the CX GDSC and the clocks the gates need first, then the `R4` line, then the rest; "an SError or abort: stop" is: the first abort ends the window, the rest of it prints `SKIP`, and nothing is retried |
| R4: the gate | the `R4` line. The plan does not say what "running" is: here it is positive proof (below), judged on the raw words, and an input that was not read or reads all ones is `CX=UNK`, never a pass |
| R5: CX_MISC, GMU, RSCC, then the SMMU | read only behind `CX=ON`; the SMMU also needs its own four clocks (dt:4268-4276). The RSC's TCS status words sit 4 dwords higher on the a740 family (gmu:1105-1108; the X1-85 is a gen2 part: cat:376-377, agh:572-577): the plan names the words, not the offsets. The words Linux never reads are last (late) |
| R6: never any GX register, write or reset | no register of the GPU window (`RBBM_*`, `CP_*`) is read, and nothing is written or reset: the table has no row in the GPU window, there is no store but to the payload's own stack, and the host test and the compiled-code audit refuse both. The GPUCC and GMU words that are about GX (`GXGD`, `GXCF`, `GXGM`, `GXST`) **are read**: they are CX-side words, the plan's R3 and R5 name them (`GXGM`: see the end of the order paragraph below) |

## What it reads, block by block

Windows (every access is a guarded `load32`): GCC `0x00100000` (size `0x200000`: dt:758-760), GPUCC `0x03d90000` (size `0xa000`: dt:4227), CX_MISC (`cx_mem`)
`0x03d9e000` (size `0x1000`: dt:4016-4018), GMU `0x03d6a000` (size `0x35000`: dt:4175-4177), RSCC `0x03d50000` (size `0x10000`: dt:4175-4177), GPU SMMU `0x03da0000` (size `0x40000`: dt:4239).
Not read at all: the GPU window `0x03d00000` (the GX side, dt:4016-4018), `cx_dbgc` `0x03d61000` and `gmu_pdc` `0x0b280000` (dt:4016-4018, dt:4175-4177), the GPU block reset `0x71000` (gcc:7284) and anything in GPUCC
above `0x9988`, the last register the driver declares (gpucc:608). The pinned test checks that no row lies in a block it does not name and that no row of GPUCC lies above that register.

A GMU word in the XML files is a dword offset from the GPU base `0x03d00000` (gmuh:139, gmu:2446), and the GMU window of the device tree (dt:4175-4177) is `0x35000` long and so spans the GPUCC and CX_MISC windows as well:
an address inside it says nothing about which block it belongs to, so each row names its own window and the GMU rows are at `4 x dword - 0x6a000`. CX_MISC and RSCC words are dwords from their own
windows (gpuh:275-278; the RSC has a window of its own: gmu:2450).

The citations are `prefix:line` into the pinned Linux files (revision `7475ea8b58616b33c04afb976cf0fbaad9dd63fb`; [The pinned files](SP11-PAYLOAD-GPUSNAP-EVIDENCE.md#the-pinned-files) has each prefix, path and digest); every one was read in the pinned copy and is held to it by
`tools/test-q1n1-sp11-payload-gpusnap-refs.py`. **None of the 52 words has ever been read on the unit** (UNKNOWN what each holds). The rows are in the order the payload reads them.

| Block | Key | Offset | Source (VERIFIED as what the pinned file says), and whether Linux reads the word |
| --- | --- | --- | --- |
| GCC | `CFGA` | `0x71004` | GCC_GPU_CFG_AHB_CLK: no clock struct; in the critical list (gcc:7451) handed to the common code (gcc:7466-7467), which enables each by a read-modify-write (cmn:317-318, cb:106-109); the gate of GPUCC |
| GCC | `MNOC` | `0x71010` | gcc:3095-3098 (GPU MEMNOC GFX; voted, hardware gating bit 1; the GMU node's memnoc clock) |
| GCC | `AXI_NW` | `0x7115c` | gcc:2977-2980 (DDRSS GPU AXI; halt check skipped, hardware gating bit 1; the GMU node's axi clock; no `.ON`/`.OFF`: NW) |
| GCC | `SNOC` | `0x71018` | gcc:3110-3111 (GPU SNOC DVM GFX; a plain halt check, no hardware gating bit; the SMMU node's iface clock) |
| GCC | `QMIP` | `0x71008` | gcc:4262-4265 (QMIP GPU AHB; voted, hardware gating bit 1) |
| GCC | `VOTE` | `0x52000` | gcc:3063-3064 (bit 15 `CPH`), gcc:3080-3081 (bit 16 `DIV`): the votes of the two GPU GPLL0 output branches |
| GCC | `GP0V` | `0x52030` | gcc:117-118 (the vote of GPLL0 itself, bit 0) |
| GPUCC | `CXGD` | `0x9108` | gpucc:532-543 (CX GDSCR; SW_COLLAPSE bit 0 and HW_CONTROL bit 1: gdsc:26-27); the GDSC code reads and updates it (gdsc:127-141, gdsc:424) |
| GPUCC | `CXHW` | `0x953c` | gpucc:532-543 (gds_hw_ctrl, the status word; PWR_ON bit 31: gdsc:21, gdsc:61-91) |
| GPUCC | `AHB` | `0x911c` | gpucc:257-258 (the GMU and SMMU nodes' ahb clock) |
| GPUCC | `CGMU` | `0x913c` | gpucc:311-312 (the node's gmu clock; always-on ops: gpucc:323, cbc:182-186) |
| GPUCC | `CXO` | `0x9144` | gpucc:347 |
| GPUCC | `HUB` | `0x9148` | gpucc:463 (hub_cx_int, the node's hub clock) |
| GPUCC | `DMT` | `0x900c` | gpucc:365 (demet) |
| GPUCC | `HLOS` | `0x7000` | gpucc:401 (hlos1_vote_gpu_smmu, the SMMU node's hlos clock) |
| GPUCC | `GXGD` | `0x905c` | gpucc:545-557 (GX GDSCR, raw) |
| GPUCC | `GXCF` | `0x9060` | gdsc:32-35 (CFG_GDSCR at +4: power up complete bit 16, power down complete bit 15; the status this domain polls: gpucc:545-557) |
| GPUCC | `CXOA` | `0x9004` | gpucc:329 |
| GPUCC | `HUBA` | `0x93e8` | gpucc:445 |
| GPUCC | `GXGM` | `0x90bc` | gpucc:414-426 (gpu_cc_gx_gmu_clk: plain branch2 ops with a halt check, **not** an always-on clock; the GX GMU clock, read with `CX=OFF` too: below) |
| GPUCC | `GRC` | `0x9318` | gpucc:182 (GMU root clock generator, command word; ROOT_OFF bit 31: rcg:33-39) |
| GPUCC | `GRF` | `0x931c` | its CFG word, command + 4 (rcg:33-39); source select bits 10:8, the parent map is gpucc:104-149 |
| GPUCC | `HRC` | `0x93ec` | gpucc:197 (hub root clock generator) |
| GPUCC | `HRF` | `0x93f0` | its CFG word, as `GRF` |
| GPUCC | `XRC` | `0x9010` | gpucc:212 (XO root clock generator) |
| GPUCC | `XRF` | `0x9014` | its CFG word, as `GRF` |
| CXMISC | `TCMR` | `0xe4` | a6x:5130-5133 (CX_MISC_TCM_RET_CNTL, dword 0x39, A7XX); the window is cx_mem (gpuc:2739); Linux writes 1 (gmu:964) and reads it (gmu:1364) |
| GMU | `GXST` | `0x14340` | xml:108-111 (GMU_SPTPRAC_PWR_CLK_STATUS, A7XX, dword 0x1f8d0: bit 0 GX_HM_GDSC_POWER_OFF, bit 1 GX_HM_CLK_OFF); read: GX is on when both are clear (gmu:121-136) |
| GMU | `INIT` | `0x14070` | xml:66-68 (GMU_CM3_FW_INIT_RESULT, dword 0x1f81c); polled (gmu:335) |
| GMU | `FENS` | `0x24c4c` | xml:231 (GMU_AHB_FENCE_STATUS, dword 0x23b13); polled (gpuc:76) |
| GMU | `RST` | `0x14000` | xml:64 (GMU_CM3_SYSRESET, dword 0x1f800); **late**: Linux only writes it (gmu:320-333) |
| GMU | `CFG` | `0x140b4` | xml:66-68 (GMU_CM3_CFG, dword 0x1f82d); **late**: Linux only writes it (gmu:1010) |
| GMU | `BUSY` | `0x14068` | xml:66-68 (GMU_CM3_FW_BUSY, dword 0x1f81a); **late**: no pinned driver line names it |
| RSCC | `BSY` | `0x404` | xml:256 (SEQ_BUSY_DRV0, dword 0x101); polled (gmu:637) |
| RSCC | `ST0` | `0x10` | xml:244-245 (RSC_STATUS0_DRV0, dword 4); polled (gmu:666) |
| RSCC | `T0` | `0xd28` | xml:259-268 (TCS0_DRV0_STATUS, dword 0x346, plus the 4 of the a740 family: gmu:1105-1108); bit 0 is idle; polled (gmu:1111-1135) |
| RSCC | `T1` | `0xfc8` | as `T0`; dword 0x3ee + 4 |
| RSCC | `T2` | `0x1268` | as `T0`; dword 0x496 + 4 |
| RSCC | `T3` | `0x1508` | as `T0`; dword 0x53e + 4 |
| RSCC | `T4` | `0x17a8` | as `T0`; dword 0x5e6 + 4 |
| RSCC | `T5` | `0x1a48` | as `T0`; dword 0x68e + 4 |
| RSCC | `T6` | `0x1ce8` | as `T0`; dword 0x736 + 4 |
| RSCC | `T7` | `0x1f88` | as `T0`; dword 0x7de + 4 |
| RSCC | `T8` | `0x2228` | as `T0`; dword 0x886 + 4 |
| RSCC | `T9` | `0x24c8` | as `T0`; dword 0x92e + 4 |
| RSCC | `PDCS` | `0x20` | xml:244-245 (PDC_SEQ_START_ADDR, dword 8); **late**: Linux only programs it, to 0x4520 (gmu:730) |
| SMMU | `ID0` | `0x20` | smmu:45 (NUMSMRG bits 7:0: smmu:57) |
| SMMU | `ID1` | `0x24` | smmu:59-63 (PAGESIZE bit 31, NUMPAGENDXB bits 30:28, NUMCB bits 7:0) |
| SMMU | `ID2` | `0x28` | smmu:65-72 (page table formats bits 14:12, UBS 11:8, OAS 7:4, IAS 3:0) |
| SMMU | `SCR0` | `0x0` | smmu:27 (sCR0) |
| SMMU | `GFSR` | `0x48` | smmu:83 (sGFSR) |
| SMMU | `ID7` | `0x3c` | smmu:79 |

**The order, and the gates.** GCC first (no gate: the clock controller is always on, and none of these words has been read before: H0), then GPUCC only if `CFGA` reads as running (H1), then
CX_MISC, the GMU and the RSC only if the `R4` verdict is `CX=ON` (H2), then the SMMU only if, in addition, its own four clocks run (H3: hlos, memnoc, snoc dvm and ahb, the SMMU node's list: dt:4268-4276). The
seven clocks of the GMU node, in the order of the `CLK` mask, are ahb, gmu, cxo, axi, memnoc, hub and demet (dt:4184-4197); both nodes name the CX GDSC as their power domain (dt:4199, dt:4268-4276). A block
that is read is announced by a `NEXT <block>` line first and is not read at all if that line cannot be printed; a block that is not read prints one `<block> GATED BY <why>` line. The first abort in a window
ends every later read of it, in snapshot 2 and the late phase as well. A gate input that **could not be read** is never reported as the thing it gates on: `GATED BY AHB` says that `CFGA` was read and does not
run, `GATED BY AHBERR` that it could not be read (an abort, a skip, all ones); `GATED BY SMCLK` and `GATED BY SMERR` say the same of the SMMU's four clocks, and `CX=UNK` of the CX verdict's inputs.
`GXGM` gates nothing: no gate uses it. The plan's R3 names it, it is not one of the GMU node's seven clocks, and it is a plain branch2 clock with a halt check, not an
always-on one (gpucc:414-426; the always-on ones are `CGMU`, `DMT`, `HUBA`, `HUB`: gpucc:323, gpucc:377, gpucc:457, gpucc:475). It is read whenever GPUCC is, **also with `CX=OFF`** (behind the AHB gate only), and comes after the
`R4` line on the film. That reading it is as safe as the other GPUCC words is INFERRED, not observed: Linux's clock core reads the enable word of a branch clock (cbc:175-179, whose generic `is_enabled` is in
clk-regmap.c, not pinned here).

**What Linux reads decides the order of a block.** For GCC, GPUCC and CX_MISC the words are clock and GDSC registers and one GMU-side register that the pinned code reads or read-modify-writes (cmn:317-318 with
cb:106-109; the halt check, cbc:52; the GDSC code, gdsc:127-141 and gdsc:424; gmu:1364): the first word of each block is one of them (`CFGA`, `CXGD`, `TCMR`). In the GMU and RSC blocks the pinned driver is searched
for each register by name: `GXST` is read (gmu:121-136), `INIT` and `FENS` are polled (gmu:335, gpuc:76), `BSY`, `ST0` and the TCS words are polled (gmu:637, gmu:666, gmu:1111-1135), and those come first (`GXST`,
`BSY`). The SMMU's `ID0` comes first because `arm-smmu.c` (not pinned) probes the ID words first and reads sCR0 and sGFSR when it resets the SMMU: INFERRED, and OBSERVED for the apps SMMU in S0b.

### The late words

Four words are read by no pinned Linux code: GMU `RST` (written at gmu:320-333), `CFG` (written at gmu:1010), `BUSY` (named by no pinned driver line) and RSC `PDCS` (written at gmu:730). A register no driver
reads is the kind of read least likely to have been tried on this silicon (INFERRED), and a window's first abort ends the window, so these are **never read before everything else is on the film**: after the
wait and the drift report, each block (`GMU`, `RSCC`) under its own `NEXT LATE <block>` line, then one `LATE <block>` line with its words. Only a block that snapshot 1 read is visited, and only while snapshot 2's
own words still say what opened it: its CFG AHB word, then the CX verdict over its GCC and GPUCC words (the CX blocks are not read again). Otherwise the page says `LATE <block> GATED BY <why>`: `AHB` or `AHBERR`,
`CX=OFF`, `CX=HWCTL`, `CX=PART`, `CX=UNK`, or `NOS2` when snapshot 2 never ran (no counter, or a wait that gave up): there is then no fresh state to judge by, and nothing is read. A window that aborted in the
meantime has no load to announce: its late words print `SKIP`. The pinned-copy test derives which words are late: a word is late exactly when no line of the pinned `a6xx_gmu.c` or `a6xx_gpu.c` reads it.

**Hazards.** The ABI says a load can still hang the bus and no guard recovers that; the last `NEXT` line names the block that was about to be read, nothing more precise. `load32` recovers the abort of a load
(SP11-PAYLOAD.md); **only synchronous aborts are guarded: an SError is neither caught nor printed by this payload**, and what the unit does then is UNKNOWN. A hang keeps what was printed before it only as far as
the runner's drawing shows it: `payload_emit` (platform/uefi/main.c) mirrors the line to the UART and draws it into the framebuffer with **no barrier** before the next load, so whether the line just printed reached
the panel before a hang is UNKNOWN, and a payload cannot add the barrier (its policy refuses `dsb`). Each line goes out as soon as its loads are done, so the film misses the line being read and, when the hang is in
the first row after a line break, perhaps the one just completed. H0: the GCC words (UNKNOWN whether they answer at EL2). H1: GPUCC, the block the plan's order is built around: the plan's A16 notes say that a read with
its AHB clock stopped is the hang that SoC's first stage met (plan 7.2; INFERRED for this one). H2: CX_MISC, the GMU and the RSC, which Linux reads and writes while the GMU is still held in reset (UV4); what a
powered-down or unclocked part of them does to a read is UNKNOWN, hence the gate. H3: the GPU SMMU, which a hypervisor or an XPU may own (plan risk R2): a refusal would be an abort, a hang would end the page at
`NEXT SMMU`.

**`.OFF` is bit 31 and nothing else, and `.ODD` marks a cell that must not be taken at its word.** The raw word is printed before the token so that the rest can be read: bit 0 is CLK_ENABLE (cb:71); bit 1 is HW_CTL,
the hardware gating bit of the clocks that have one (`QMIP`, `MNOC` and `AXI_NW` here: cbc:17-27); bits 30:28 are NOC_FSM_STATUS (cb:63-65). Linux counts a clock whose FSM status is ON as on although CLK_OFF is
set (cbc:54-58), and does not check CLK_OFF at all for a clock that skips its halt check or is in hardware gated mode (cbc:72). So the token is printed only where it can be read at its word, and a cell where it
cannot says `.ODD` (the raw word beside it is the evidence): a word of all ones (what a failed read returns), CLK_OFF clear with CLK_ENABLE clear (a clock that says it runs without being enabled, which is
what a window of zeros reads: `CFGA=0` is `.ODD`, never `.ON`), CLK_OFF set with HW_CTL set on a clock that has the bit, CLK_OFF set with an FSM status of ON; the same
bits on a clock without that mode are an ordinary `.OFF`. A root clock generator's command word has none of those modes (its bit 31 is ROOT_OFF: rcg:33-39), so only all ones is `.ODD` there, and a GDSC status word
(`CXHW`) is `.ODD` only for all ones. A bit field cut from a word of all ones (`SC`, `HW`, `UP`, `DN`, `CPH`, `DIV`, `S`) prints `ODD`; `GX=ODD` is a GMU GX status word with a bit above bit 1 set or all ones (the
A7XX layout defines two bits: xml:108-111); `TCS=ODD` is any TCS word of all ones. A gate never opens on an unread, faulted or all-ones word, and it is judged on the raw word, not on the `.ODD` mark: a clock **runs** when its
word was read, is not all ones, has CLK_ENABLE set and CLK_OFF clear, with Linux's own exceptions for the two data-path clocks `MNOC` and `AXI_NW` (a hardware gated clock with HW_CTL set passes with CLK_OFF set;
`AXI_NW` needs the enable bit only), so an odd `MNOC` (`0X80000003`) or `AXI_NW` (`0X80000001`) word still opens the CX gate (`MNOC` prints `.ODD`, `AXI_NW` no token). The register-path gates (`CFGA`, `AHB`, `CGMU`,
`CXO`, the CX GDSC) need positive proof (that these are the words which decide whether a register read is safe is INFERRED): an FSM status of ON with CLK_OFF set does **not** count, and `CFGA` gets no exemption at all.

**`AXI_NW`** (`0x7115c`) has a halt check of BRANCH_HALT_SKIP and a hardware gating bit (gcc:2977-2980): the driver never looks at its CLK_OFF, so bit 31 is no witness (NW) and the page prints the raw word and no token.

**The CX GDSC.** Its status is not in its GDSCR: the driver reads it from `gds_hw_ctrl`, `0x953c`, bit 31 (gdsc:61-91, gpucc:532-543): `CXHW`, with `.ON` for PWR_ON. The domain is VOTABLE with RETAIN_FF
(gpucc:532-543), so other masters (the GMU, the RSC) may vote it on or off, which is why a CX under hardware control (`HW`, GDSCR bit 1) is **not** called on (`CX=HWCTL`). The GX domain is printed as two raw
words only (`GXGD`; `GXCF`, whose bits 16 and 15 are `UP` and `DN`) and no verdict is made from them.

**GPLL0.** `VOTE` bits 15 and 16 are the votes of the two GPU GPLL0 output branches (gcc:3063-3064, gcc:3080-3081), not of GPLL0, whose own vote is bit 0 of `GP0V` (gcc:117-118). Neither says the PLL has locked:
its lock status is not read (UNIMPLEMENTED).

**`common.c`** (cmn:317-318, the code that enables the critical clocks) is in no pin table of the plan or the study; its SHA-256 `ebefa181817ee8218b314218bbd94315ba239ff4f816a6565af3ec6aeed14226` is recorded here and checked by
the pinned-copy test.

**What could not be verified.** No pinned file says any of the following, and none is VERIFIED: UV1, what any GPU word holds on the unit: none was ever read there, so whether a read aborts, hangs the bus or raises an SError is UNKNOWN.
UV2, that GPUCC answers while `GCC_GPU_CFG_AHB_CLK` runs: Linux keeps that clock enabled (gcc:7451, cmn:317-318) and reads GPUCC all the time, which makes it a premise for the unit and not a fact about it. UV3, that bit 31 of GDS_HW_CTRL
reads 1 when the CX domain is on on this unit: it is what Linux reads (gdsc:61-91), and the first reading is this run. UV4, that CX_MISC, the GMU window and the RSC answer while the CX domain is on and the GMU is still held in reset: Linux reads
and writes them in that state (gmu:730, gmu:964), the unit has not been asked. UV5, what the size codes of `ID2` (`IAS`, `OAS`, `UBS`) stand for in bits: the codes are defined in `arm-smmu.c`, which is not pinned, so they are printed as codes (the apps SMMU read
`0x5222` in boot 5, which the results document calls 40 bits). UV6, which software owns these blocks at EL2 (the hypervisor, an XPU, the secure world): plan risk R2 lists it as open, and a refused read is the answer.

## The page

The numbers below are measured on runs of the host model (the host test binary built from `tools/test-q1n1-sp11-payload-gpusnap.c`, run with `--numbers`), and the document test compares them with this table.

<!-- numbers -->
| Name | Value | Meaning |
| --- | --- | --- |
| `registers` | 52 | rows of the register table |
| `line_cap` | 34 | lines the payload prints at most (the ABI allows 40; the chain budget below is why it keeps six back) |
| `load_cap` | 128 | loads the payload makes at most |
| `abi_lines` | 40 | the ABI's limit of lines per call |
| `abi_loads` | 4096 | the ABI's limit of loads per call |
| `open_lines` | 33 | lines of the open sample page below (every gate open) |
| `open_snapshot1_lines` | 24 | of them before `NEXT WAIT 8 S` |
| `open_late_lines` | 4 | of them the late lines: `NEXT LATE` and one line for each of `GMU` and `RSCC` |
| `open_loads` | 78 | loads of the open sample run |
| `open_snapshot1_loads` | 48 | of them in snapshot 1: every row but the four late ones |
| `open_snapshot2_loads` | 26 | of them in snapshot 2: the 7 GCC and 19 GPUCC rows |
| `open_late_loads` | 4 | of them the late words |
| `cold_lines` | 23 | lines of the cold sample (the CX domain off: nothing behind it is read, so there are no late lines) |
| `cold_loads` | 52 | loads of that run: the 26 rows of GCC and GPUCC in each snapshot |
| `ahboff_lines` | 14 | lines when `CFGA` reads `.OFF`: GPUCC and what is behind it are not read |
| `ahboff_loads` | 14 | loads then: the 7 GCC rows twice |
| `wide_lines` | 33 | lines of the open fixture with eight-digit values everywhere: the longest lines, nothing cut |
| `wide_cuts` | 0 | fields the cap kept off that page |
| `wideflipmost_lines` | 32 | the wide fixture with every GCC and GPUCC word but `CFGA` moving in the wait: the drift list keeps to the room the lines before it leave |
| `wideflipmost_cuts` | 22 | fields and lines the cap kept off that page |
| `wideflipmost_more` | 22 | the `MORE=` of its summary: drift items that did not fit |
<!-- /numbers -->

The sample is the **host model's** page for a fixture, not a page from the unit: every value is made up, except the SMMU's `SCR0`, `ID0`, `ID1` and `ID2`, which are the apps SMMU's from boot 5 (a different SMMU
from the GPU's, used here only as realistic bit patterns). It is a CX domain that is on with all its clocks running and the GMU held in reset.

<!-- page-open -->
```
PAYLOAD GPUSNAP READ ONLY EL=2 HZ=0X124F800 GAP=8 S
PAYLOAD GPUSNAP KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=BIT 31 NOT TRUSTED NO GPU-WINDOW REGISTER IS READ
PAYLOAD GPUSNAP NEXT GCC
PAYLOAD GPUSNAP GCC CFGA=1.ON MNOC=3.ON AXI_NW=3 SNOC=1.ON
PAYLOAD GPUSNAP GCC QMIP=3.ON VOTE=0X18001 CPH=1 DIV=1 GP0V=1
PAYLOAD GPUSNAP NEXT GPUCC
PAYLOAD GPUSNAP GPUCC CXGD=0X8022F000 SC=0 HW=0 CXHW=0X80000000.ON
PAYLOAD GPUSNAP GPUCC AHB=1.ON CGMU=1.ON CXO=1.ON
PAYLOAD GPUSNAP GPUCC HUB=1.ON DMT=1.ON HLOS=1.ON
PAYLOAD GPUSNAP R4 CX=ON PWR=1 SC=0 HW=0 CLK=0X7F SM=0XF
PAYLOAD GPUSNAP GPUCC GXGD=0X222001 GXCF=0X8000 UP=0 DN=1
PAYLOAD GPUSNAP GPUCC CXOA=1.ON HUBA=1.ON GXGM=0X80000000.OFF
PAYLOAD GPUSNAP GPUCC GRC=2.ON GRF=0 S=0 HRC=0X80000000.OFF HRF=0X100 S=1
PAYLOAD GPUSNAP GPUCC XRC=0X80000000.OFF XRF=0 S=0
PAYLOAD GPUSNAP NEXT CXMISC
PAYLOAD GPUSNAP CXMISC TCMR=0
PAYLOAD GPUSNAP NEXT GMU
PAYLOAD GPUSNAP GMU GXST=3 GX=OFF INIT=0 FENS=0
PAYLOAD GPUSNAP NEXT RSCC
PAYLOAD GPUSNAP RSCC BSY=0 ST0=0 TCS=0X3FF
PAYLOAD GPUSNAP NEXT SMMU
PAYLOAD GPUSNAP SMMU ID0=0X7C017E9A ID1=0X6000005F ID2=0X5222
PAYLOAD GPUSNAP SMMU SMRG=0X9A CB=0X5F PG=4K NPG=6 PT=5 IAS=2 OAS=2 UBS=2
PAYLOAD GPUSNAP SMMU SCR0=0X230406 GFSR=0 ID7=0X21
PAYLOAD GPUSNAP NEXT WAIT 8 S
PAYLOAD GPUSNAP NEXT S2 GCC
PAYLOAD GPUSNAP NEXT S2 GPUCC GCC=SAME
PAYLOAD GPUSNAP DRIFT NONE CMP=26
PAYLOAD GPUSNAP NEXT LATE GMU
PAYLOAD GPUSNAP LATE GMU RST=1 CFG=0 BUSY=0
PAYLOAD GPUSNAP NEXT LATE RSCC
PAYLOAD GPUSNAP LATE RSCC PDCS=0
PAYLOAD GPUSNAP END LOADS=78 FAULTS=0 SKIPS=0 BLK=0 CUTS=0 GAP_MS=8020 LINES=33
```
<!-- /page-open -->

Excerpts of the same model, one change each, show what the page does when something else is the case (the document test holds each excerpt to the model's output, line by line and in order). First the cold
state plan 7.1 expects before S1: the CX domain is collapsed, GPUCC is read, nothing behind it is, and there are no late lines because no block behind the gate was read. Second `CFGA` reads `.OFF`: GPUCC is not read.
Third, `CFGA` turns off during the wait: snapshot 2 does not visit GPUCC, and the late words are not read.

<!-- cold-lines -->
```
PAYLOAD GPUSNAP GPUCC CXGD=0X222001 SC=1 HW=0 CXHW=0.OFF
PAYLOAD GPUSNAP GPUCC AHB=0X80000000.OFF CGMU=0X80000000.OFF CXO=0X80000000.OFF
PAYLOAD GPUSNAP R4 CX=OFF PWR=0 SC=1 HW=0 CLK=0X18 SM=0X6
PAYLOAD GPUSNAP CXMISC GATED BY CX=OFF
PAYLOAD GPUSNAP GMU GATED BY CX=OFF
PAYLOAD GPUSNAP RSCC GATED BY CX=OFF
PAYLOAD GPUSNAP SMMU GATED BY CX=OFF
PAYLOAD GPUSNAP END LOADS=52 FAULTS=0 SKIPS=0 BLK=0X3C CUTS=0 GAP_MS=8020 LINES=23
```
<!-- /cold-lines -->

<!-- ahboff-lines -->
```
PAYLOAD GPUSNAP GCC CFGA=0X80000000.OFF MNOC=3.ON AXI_NW=3 SNOC=1.ON
PAYLOAD GPUSNAP GPUCC GATED BY AHB
PAYLOAD GPUSNAP CXMISC GATED BY AHB
PAYLOAD GPUSNAP SMMU GATED BY AHB
PAYLOAD GPUSNAP DRIFT NONE CMP=7
PAYLOAD GPUSNAP END LOADS=14 FAULTS=0 SKIPS=0 BLK=0X3E CUTS=0 GAP_MS=8020 LINES=14
```
<!-- /ahboff-lines -->

<!-- s2gated-lines -->
```
PAYLOAD GPUSNAP NEXT S2 GCC
PAYLOAD GPUSNAP S2 GPUCC SKIP GATED GCC=CHG:1
PAYLOAD GPUSNAP DG CFGA=1-0X80000000
PAYLOAD GPUSNAP DRIFT CHANGED=1 LOST=0 CMP=7
PAYLOAD GPUSNAP LATE GMU GATED BY AHB
PAYLOAD GPUSNAP LATE RSCC GATED BY AHB
PAYLOAD GPUSNAP END LOADS=55 FAULTS=0 SKIPS=0 BLK=0X1A CUTS=0 GAP_MS=8020 LINES=32
```
<!-- /s2gated-lines -->

Fourth, the CX GDSC is under hardware control; fifth, one of the seven clocks of the GMU node is stopped; sixth, the clock `HLOS` of the SMMU's list is stopped while the CX verdict is on: the SMMU is not read and the
late words still are; seventh, the first word of GPUCC aborts. Eighth, `QMIP` aborts in GCC in snapshot 1: GCC is not read again, so snapshot 2 cannot judge `CFGA`, and the late words say `AHBERR` and are not read.
Ninth, the counter does not run: no wait, no snapshot 2, and the late words say `NOS2`.

<!-- hwctl-lines -->
```
PAYLOAD GPUSNAP GPUCC CXGD=0X8022F002 SC=0 HW=1 CXHW=0X80000000.ON
PAYLOAD GPUSNAP R4 CX=HWCTL PWR=1 SC=0 HW=1 CLK=0X7F SM=0XF
PAYLOAD GPUSNAP CXMISC GATED BY CX=HWCTL
PAYLOAD GPUSNAP SMMU GATED BY CX=HWCTL
PAYLOAD GPUSNAP END LOADS=52 FAULTS=0 SKIPS=0 BLK=0X3C CUTS=0 GAP_MS=8020 LINES=23
```
<!-- /hwctl-lines -->

<!-- part-lines -->
```
PAYLOAD GPUSNAP GPUCC AHB=1.ON CGMU=0X80000000.OFF CXO=1.ON
PAYLOAD GPUSNAP R4 CX=PART PWR=1 SC=0 HW=0 CLK=0X7D SM=0XF
PAYLOAD GPUSNAP CXMISC GATED BY CX=PART
PAYLOAD GPUSNAP SMMU GATED BY CX=PART
```
<!-- /part-lines -->

<!-- smmuclk-lines -->
```
PAYLOAD GPUSNAP GPUCC HUB=1.ON DMT=1.ON HLOS=0X80000000.OFF
PAYLOAD GPUSNAP R4 CX=ON PWR=1 SC=0 HW=0 CLK=0X7F SM=0XE
PAYLOAD GPUSNAP RSCC BSY=0 ST0=0 TCS=0X3FF
PAYLOAD GPUSNAP SMMU GATED BY SMCLK
PAYLOAD GPUSNAP LATE RSCC PDCS=0
PAYLOAD GPUSNAP END LOADS=72 FAULTS=0 SKIPS=0 BLK=0X20 CUTS=0 GAP_MS=8020 LINES=30
```
<!-- /smmuclk-lines -->

<!-- gpuccabort-lines -->
```
PAYLOAD GPUSNAP GPUCC CXGD=FAULT:6 SC=FAULT:6 HW=FAULT:6 CXHW=SKIP
PAYLOAD GPUSNAP R4 CX=UNK
PAYLOAD GPUSNAP GMU GATED BY CX=UNK
PAYLOAD GPUSNAP DRIFT NONE CMP=7
PAYLOAD GPUSNAP END LOADS=15 FAULTS=1 SKIPS=18 BLK=0X3E CUTS=0 GAP_MS=8020 LINES=22
```
<!-- /gpuccabort-lines -->

<!-- gccabort-lines -->
```
PAYLOAD GPUSNAP GCC QMIP=FAULT:6 VOTE=SKIP CPH=SKIP DIV=SKIP GP0V=SKIP
PAYLOAD GPUSNAP S2 GPUCC SKIP GATED
PAYLOAD GPUSNAP DRIFT NONE CMP=0
PAYLOAD GPUSNAP LATE GMU GATED BY AHBERR
PAYLOAD GPUSNAP LATE RSCC GATED BY AHBERR
PAYLOAD GPUSNAP END LOADS=46 FAULTS=1 SKIPS=2 BLK=0X1B CUTS=0 GAP_MS=8020 LINES=30
```
<!-- /gccabort-lines -->

<!-- nocounter-lines -->
```
PAYLOAD GPUSNAP S2 SKIPPED NO_COUNTER
PAYLOAD GPUSNAP LATE GMU GATED BY NOS2
PAYLOAD GPUSNAP LATE RSCC GATED BY NOS2
PAYLOAD GPUSNAP END LOADS=48 FAULTS=0 SKIPS=0 BLK=0X18 CUTS=0 GAP_MS=0 LINES=28
```
<!-- /nocounter-lines -->

### How to read it

| Line | Fields | Meaning |
| --- | --- | --- |
| 1, 2 | `HZ`, `GAP`; the legend | the counter frequency (`DEFAULT` after it when `CNTFRQ_EL0` was outside 1 to 1000 MHz and 19.2 MHz was used) and the wait; the legend of the notation |
| a field | `KEY=VALUE` | the raw word: below 10 one digit, a larger one `0X` and the fewest upper-case hex digits (the runner's `hex`). A clock or GDSC status word is followed by its decode (below) |
| `GCC` | `CFGA`, `MNOC`, `AXI_NW`, `SNOC`, `QMIP`, `VOTE` (`CPH`, `DIV`), `GP0V` | the clock and vote words of the register table; `CPH` is bit 15 of `VOTE`, `DIV` bit 16 |
| `GPUCC` | `CXGD` (`SC`, `HW`), `CXHW`, `AHB` `CGMU` `CXO` `HUB` `DMT` `HLOS`; `GXGD`, `GXCF` (`UP`, `DN`); `CXOA` `HUBA` `GXGM`; `GRC` `GRF` `HRC` `HRF` `XRC` `XRF` (`S`) | the CX GDSC and the clocks that feed the gate first, then the rest; `SC`, `HW` are bits 0 and 1 of the GDSCR, `S` the source select of a root clock generator |
| `R4` | `CX=`, `PWR`, `SC`, `HW`, `CLK`, `SM` | the verdict, printed as soon as its inputs have gone out: `CX=ON`, `CX=OFF`, `CX=HWCTL`, `CX=PART`, `CX=UNK` (below), and, unless it is `CX=UNK`, PWR_ON, the two GDSCR bits, and a bit per clock that runs (`CLK`: ahb, gmu, cxo, axi, memnoc, hub, demet from bit 0; `SM`: hlos, memnoc, snoc dvm, ahb) |
| `CXMISC`, `GMU`, `RSCC` | `TCMR`; `GXST` (`GX`), `INIT`, `FENS`; `BSY`, `ST0`, `TCS` | the words Linux reads, in the order of the register table; `GX=ON` when both of the two low bits of `GXST` are clear; `TCS` is bit 0 of each of the ten TCS status words, `T0` lowest, so that all idle is `0X3FF` |
| `SMMU` | `ID0`, `ID1`, `ID2`; `SMRG`, `CB`, `PG`, `NPG`, `PT`, `IAS`, `OAS`, `UBS`; `SCR0`, `GFSR`, `ID7` | the identity words, then the identity decoded (smmu:45, smmu:59-63, smmu:65-72): stream matching groups, context banks, page size 4K or 64K, `NPG` = NUMPAGENDXB, `PT` the page table format bits 14:12 of `ID2` (bit 0 of it is 4 KiB, bit 1 16 KiB, bit 2 64 KiB), the size codes, printed only when the three ID words read and none is all ones; then the global words |
| `NEXT <block>` | | printed **before** the first load of a block that is read; nothing of it is read if the line cannot be printed: the last line on the film names what hung |
| `<block> GATED BY <why>` | `AHB`, `AHBERR`, `CX=OFF`, `CX=HWCTL`, `CX=PART`, `CX=UNK`, `SMCLK`, `SMERR` | the block was not read, and why: `AHB` (`CFGA` was read and does not run), `AHBERR` (`CFGA` could not be read), `SMCLK` (the CX verdict is on but a clock of the SMMU's list does not run), `SMERR` (one of those could not be read) |
| `NEXT WAIT 8 S` | | the one wait, 8 s on the counter; if the panel dies here or after it, the film says so |
| `NEXT S2 <block>` | `GCC`, `GPUCC` | snapshot 2 re-reads only the GCC and GPUCC words snapshot 1 read, in windows that had not aborted. The line after `NEXT S2 GCC` ends in `GCC=SAME` or `GCC=CHG:<n>` (n of GCC's words differ), so that what GCC said after the wait is on the film before the likeliest hang |
| `S2 GPUCC SKIP GATED` | | snapshot 2 did not visit GPUCC: its own CFG AHB word, read just before, does not read as running (it is off, or it could not be read: the `DG CFGA=` item and the late reason say which); none of its words is compared |
| `DG`, `DC` | `KEY=OLD-NEW` | what moved in GCC and in GPUCC: raw words; NEW may be `FAULT:6`, `SKIP`, `NA` or `BUDGET` where the re-read failed or did not happen |
| `DRIFT` | `NONE CMP=`, `CHANGED= LOST= CMP= MORE=` | nothing moved of the words compared; or how many differ, how many snapshot 2 could not read, how many were compared, and how many drift items did not fit |
| `NEXT LATE <block>` | `GMU`, `RSCC` | printed **before** the first load of a late block, after the drift report and never before it |
| `LATE <block>` | `RST`, `CFG`, `BUSY`; `PDCS` | the late words, raw; or `LATE <block> GATED BY <why>` (`NOS2`: snapshot 2 never ran) when the state that opened the block no longer holds or cannot be judged |
| `END` | `LOADS FAULTS SKIPS BLK CUTS GAP_MS LINES` | the loads made; the aborted ones; the ones skipped after an abort; a bit per block (`GCC` 1, `GPUCC` 2, `CXMISC` 4, `GMU` 8, `RSCC` 0x10, `SMMU` 0x20) that had a fault, a skip, a `GATED BY` line or was not read; the fields the cap kept off; the milliseconds from the start of snapshot 1 to the start of snapshot 2; the lines printed |
| `S2 SKIPPED NO_COUNTER`, `S2 SKIPPED SPIN` | | no snapshot 2: `NO_COUNTER`, no counter or one that does not run (it stood still for 2 million reads or ran backwards); `SPIN`, a counter that moves and did not reach the 8 s in 2^32-1 reads (INFERRED: minutes of the real loop), a different statement from a dead counter. The wait did not happen, the drift report is skipped, `END` follows with `GAP_MS=0` |
| `SKIPPED_NOT_AT_EL2`, `REFUSED_NO_LOAD32` | | the whole page, alone: CurrentEL is not 2 (it returns 0) or the runner gave no `load32` (it returns the bad-arguments code); nothing was read and there is **no** `END` line. An invalid argument block prints nothing at all |

The page is at most 34 lines whatever the hardware says (the ABI allows 40) and the drift summary and `END` are never crowded out by the lines before them **when the payload gets that far**: the early exits above print their one
line and no `END`. The ordinary lines keep six rows back (two for the drift summary and `END`, four for the late lines), so that the late phase always has its room; a page where everything moves in the wait prints the first
drift items and `MORE=` counts the rest. Snapshot 2 is a **drift list**, not a second page.

### Decoding the tokens

| Token | Where | Decode |
| --- | --- | --- |
| `.ON`, `.OFF` | after a branch clock word | bit 31, CLK_OFF (cb:63-65): set is `.OFF`, clear with CLK_ENABLE set is `.ON` |
| `.ON`, `.OFF` | after a root clock generator's command word | bit 31, ROOT_OFF (rcg:33-39): set is `.OFF` |
| `.ON`, `.OFF` | after `CXHW` | bit 31, PWR_ON (gdsc:21): set is `.ON`. The other polarity: the GDSCR's `SC` and `HW` are the bits themselves |
| `.ODD` | after a word | the bit 31 token cannot be taken at its word: all ones; or, on a branch clock, CLK_OFF clear with CLK_ENABLE clear (a window of zeros), CLK_OFF with HW_CTL set on a clock that has the bit, or with an NoC FSM status of ON. Read the raw word |
| `ODD`, `GX=ODD`, `TCS=ODD` | in place of a field | the field is cut from a word of all ones, or the GMU's GX status word has a bit above bit 1 set (or is all ones), or a TCS word is all ones: nothing is decided from it |
| `AXI_NW` | the DDR subsystem's GPU AXI clock | no token: the halt check is skipped, so bit 31 is no witness (NW) |
| `FAULT:6` | in place of a value | the guarded load aborted (6 is `Q1N1_PAYLOAD_LOAD_E_FAULT`); that window is read no more |
| `SKIP` | in place of a value | not read, because an earlier load of that window aborted |
| `NA` | in place of a value | no load was made for it (a row outside its window: not possible with this table) |
| `BUDGET` | in place of a value | the load cap was reached |
| `R4`, `CX=ON`, `CX=OFF`, `CX=HWCTL`, `CX=PART`, `CX=UNK` | the verdict | `CX=ON`: PWR_ON set, SW_COLLAPSE and HW_CONTROL clear, the seven clocks run; `CX=HWCTL`: HW_CONTROL set; `CX=OFF`: SW_COLLAPSE set or PWR_ON clear; `CX=PART`: on, but not all seven run; `CX=UNK`: one of the nine inputs (`CXGD`, `CXHW`, the seven clock words) was not read or reads all ones. HW_CONTROL wins over OFF and PART; UNK wins over all |

## What each page would mean for the plan

Every row is INFERRED from the plan and the pinned files, none was seen, and none is a finding. There is a row for every token the payload can print that is not a plain value, and for what the film shows when it
prints nothing more.

| On the film | Reading | For the plan |
| --- | --- | --- |
| `GPUCC GATED BY AHB`, `CFGA` `.OFF` or its bit 0 clear | the clock Linux keeps on is not running on this unit, so GPUCC is not reachable by the plan's own rule | R2's stop: S1 cannot start from this state, and the premise of UV2 is false for the unit |
| `GPUCC GATED BY AHBERR`, `CFGA=FAULT:6` or `.ODD` | the CFG AHB word itself could not be read: that is **not** "the clock is off"; nothing behind it was read | the first abort is the result (UV1, UV6): who owns GCC at EL2 comes before anything else |
| `R4 CX=OFF` with `PWR=0 SC=1` | the CX domain is collapsed by software, the cold state the plan expects; nothing behind it was read, so no late lines | S1 (CX power-on) is the next stage; the RSC question (is S2 needed) stays open until CX is up |
| `R4 CX=ON`, then `GMU`, `RSCC` and `SMMU` lines | CX is already on (by whom is UNKNOWN: firmware, hypervisor, secure world); `INIT` says whether a GMU firmware initialised, `GX` what the GMU thinks of GX | S1's power-on would change nothing; the RSC words (`BSY`, `ST0`, `TCS`) decide whether S2 is needed |
| `LATE GMU RST=.. CFG=.. BUSY=..`, `LATE RSCC PDCS=..` | what the four words no Linux code reads hold, read last and only on a state that still held (`RST=1` is the GMU held in reset: INFERRED from gmu:320-333) | the state before any GMU boot; nothing was written to get it |
| `LATE <block> GATED BY AHB`, `AHBERR`, `CX=..` | after the wait the state that opened the block no longer holds, or snapshot 2 could not read its gate words: the late words stay unread | the `DG`/`DC` items (when they fit) and the reason say what moved |
| `R4 CX=HWCTL` | the CX GDSC is under hardware control: the GMU or the RSC may collapse it between two reads | R4 is not proven; S1 needs a write that takes it out of hardware control, which is not here |
| `R4 CX=PART` | CX is on but a clock of the GMU node is not running: the `CLK` mask names it | S1 must enable that clock first |
| `FAULT:6` in GPUCC, then `CX=UNK` | GPUCC refuses a read at EL2, or its AHB clock is not enough (UV2, UV6): the first word aborted | nothing behind it is read; S1 as planned needs another route |
| `FAULT:6` on a later word, `SKIP` for the rest of that window | that register refuses while the words before it in its window answered: the register, not the window, is the finding (a late word: its own `LATE` line) | S1 must not rely on it; the words after it were not tried |
| the `SMMU` decode, `SMMU GATED BY SMCLK` or `SMERR` | the page table formats and address sizes the GPU SMMU implements (`PT`, `IAS`, `OAS`, `UBS`); or that one of its four clocks does not run (`SMCLK`) or could not be read (`SMERR`) | W2 (the GPU window and pool budgets) is decided from the first; the others defer it |
| `.ODD`, `ODD`, `GX=ODD`, `TCS=ODD` | a word of all ones (what a failed read returns) or a mode that makes bit 31 untrustworthy. A gate never opens on an unread, faulted or all-ones word; the two data-path clocks `MNOC` and `AXI_NW` count as running under Linux's own exemption (`MNOC` prints `.ODD`), and the register-path gates (`CFGA`, `AHB`, `CGMU`, `CXO`, the CX GDSC) need proof (INFERRED) | read the raw word; all ones in a window that answered elsewhere means the word was not really read |
| `DRIFT CHANGED`, `DG`, `DC`, `S2 GPUCC SKIP GATED` | something in GCC or GPUCC moved in the 8 s with nobody touching it, or GPUCC was not read again because `CFGA` no longer runs (or could not be read) | S1 must not assume the cold values; `DRIFT NONE` says they held |
| `S2 SKIPPED NO_COUNTER` or `S2 SKIPPED SPIN`, then `LATE <block> GATED BY NOS2` | the wait did not happen (no counter, a dead one, or one that never got there): no snapshot 2, no drift, no late words | the page is snapshot 1 only; `HZ` says what was read; boot again, nothing was written |
| a long silence after `NEXT WAIT 8 S` | the wait reads only the counter, and gives up after 2^32-1 reads: a counter that moves and never gets there can hold the page for minutes (that bound times the time of one read: INFERRED) before `S2 SKIPPED SPIN`; past the film rule below it is a hang or a dead panel | wait out the film rule; the silence says nothing about a GPU word (none is read in the wait) |
| `BUDGET`, `NA`, `CUTS=` or `MORE=` above 0 | a cap cut the page: fields and drift items were dropped and counted, never printed half | the page is incomplete but honest; the counts say how much |
| `SKIPPED_NOT_AT_EL2`, `REFUSED_NO_LOAD32` | the runner called it outside EL2 or without a `load32` | nothing was read; the run is wrong, not the payload |
| the page ends at a `NEXT <block>` or `NEXT LATE <block>` line, or the panel goes dark | a load of that block (a late block: of one of its late words) did not return (a hung bus is not recovered; the ABI says so), and the page does not say which register. The drawing lags the loads (Hazards above), so the hung block can be a LATER one than the last `NEXT` on the film | the premise of that block's step (status reads need nothing powered) is false; the GPU bring-up cannot continue without a review |
| `END` is there, then q1n1's fault page or a reset | not this payload's page: it printed all it had; the next payload of the chain, or q1n1, faulted or the board reset | read the later `PAYLOAD` lines; the words of `gpusnap` are on the film |
| any of the above | recovery: nothing was written, so there is nothing to undo | reset and **boot the stick again**; a hang that repeats at the same line is the result |

Two checks for the operator. **Film for 2 minutes after `END`, and for 10 minutes after `PAYLOAD CALL` if there is no `END`** (the wait above can hold the page that long): boot 16's panel went dark about 62 s on its payload's own clock (stick log section 16), so a blackout that comes only later is a result too (the cause would still be UNKNOWN).
**Read `HZ=0X124F800` (19.2 MHz) on the film**: another value, or `DEFAULT` after it, means the wait is not 8 s of real time (a counter slower than `CNTFRQ_EL0` says stretches it), and `GAP_MS` cannot show that, being measured on the same counter.

## Chaining it in front of the xHCI payloads

The runner calls the payloads of a manifest in **manifest order**, each once, and what a payload returns never stops the chain ([SP11-PAYLOAD.md](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot)). `gpusnap` is
read-only, so it goes **first** and the payload that writes goes last: a payload that may stall the board goes last, and once the board resets every earlier line is gone unless the screen is filmed within seconds.
Build, then make the stick tree (the tool keeps the order it is given; names are 8.3, at most five files):

```sh
make -f platform/uefi/Makefile payloads
python3 tools/sp11_payload_manifest.py --out-dir build/stick-gpusnap build/uefi/payloads/gpusnap.bin build/uefi/payloads/xhci0.bin
```

writes `build/stick-gpusnap/SP11/PAYLOAD.MAN` and the capitalised copies `GPUSNAP.BIN` (manifest index 0, called first) and `XHCI0.BIN` (index 1, last); `xhci1.bin` is taken the same way. The runner itself, the Shell
script and the Snapintosh autorun staging are not touched by this document. The page budget of the chain, from the runner's planning table ([SP11-PAYLOAD.md](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot)) and
the two payloads' own figures (the open sample above; [SP11-PAYLOAD-XHCI.md](SP11-PAYLOAD-XHCI.md#the-page)):

<!-- gpusnap-chain-budget -->
| Item | Nominal | At most |
| --- | --- | --- |
| `LOADED` for each of the two files and `READY` (files + 1) | 3 | 3 |
| `VERIFY`, `CALL`, `DONE` for each of the two payloads | 6 | 6 |
| `gpusnap` | 33 | 34 |
| `xhci0` or `xhci1` | 19 | 40 |
| total | 61 | 83 |
| panel region of the unit's 2880 x 1920 panel | 89 | 89 |
<!-- /gpusnap-chain-budget -->

At the worst both payloads print all their lines and the chain is 83 of the panel's 89 rows (INFERRED: "about 89", from the layout function), six to spare; nominally it is 61. The six rows are what the line cap of 34
buys. A line past the last row is mirrored to the UART but not drawn, so if the end of `xhci0`'s page must be certain to show, run `gpusnap` **alone** in a boot of its own first (one file: `LOADED`, `READY` and its own three runner
lines, then the page: 38 lines, at most 39). Either way this document authorises no run: a stick with `GPUSNAP.BIN` in front of `XHCI0.BIN` is another file set and manifest than any approved record's, and needs its own record and
the operator's approval of the SHA-256 of each file (one hardware client, AC power or at least 50 % battery, AGENTS.md of the Snapintosh tree).

## Limits, and what remains before a run

* **Not run on hardware.** Whether any load of it hangs the bus on the unit is UNKNOWN; no GPU word has ever been read there. A hang is not recovered (the last `NEXT` line on the film names its block, or, the drawing
  lagging, an earlier one), an SError is neither caught nor printed. q1n1's fault page is reached by a fault outside the guarded load (this payload has none) **or by an abort the guard does not recover**:
  that recovery has **never fired on the unit** (every `FAULTS=` figure in [SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md) is 0, 12 of 12, and this payload's QEMU run has no fault), so the first abort here is its
  first real test, and the page then shows `FAULT:6` (recovered) or q1n1's fault page (not).
* The runner draws a line with no barrier before the next load, so the last line before a hang may not have reached the panel (UNKNOWN); the `NEXT` line before a block is the best this payload can do.
* A drift list that prints less than all of it (`MORE=`, `CUTS=`) says so; a value shown as `NA` was refused, not read; a window that aborted in snapshot 1 is neither re-read nor compared; the CX blocks and the SMMU are read once and never compared.
* The decodes (`.ON`, `GX`, `TCS`, `PT`) and the gates are the pinned files', not a statement about this unit; the raw words are what was read. Where a rule misjudges a word, a block that could have been read is not (lost
  evidence) or one that is stopped is read (the hang risk the last line then names). That the SMMU's and the late words answer at all is UNKNOWN, and which of them Linux reads is VERIFIED only for the GMU and RSC blocks.
* UNIMPLEMENTED: a GPLL0 lock status, the PDC, RPMh, the thermal sensors, a second look at the CX blocks, and anything that writes.
* **Common mode.** The harness model and the payload have one author, so a misreading of a rule can be in both and a test that agrees with the payload shows only that; the register list was checked against the pinned sources by an independent reviewer for v1.1 only (nothing later, and nothing about the unit).
* Before any run: its own record, the operator's approval by SHA-256 of the exact binary, one hardware client, AC power or at least 50 % battery, the placement in the chain above, and film of 2 minutes after `END` (10 minutes after `PAYLOAD CALL` if there is no `END`).
