<!-- SPDX-License-Identifier: MIT -->
# SP11 payload `dispsnap`: a read-only look at the display pipeline the firmware left running, taken before anything is written (the X2 display dump list)

**EXPERIMENTAL, hardware NOT RUN, host model and compiled code only.** Nothing in this document authorises a run on the Surface Pro 11: a run needs its own record, the operator's approval of the SHA-256 of the exact binary, one hardware client, AC power or at least 50 % battery, and the film rule below. Labels, as in the rest of the series: VERIFIED (a pinned public Linux file says so; never a statement about the unit), OBSERVED (a real run on the unit), INFERRED, UNKNOWN, UNIMPLEMENTED, EXPERIMENTAL (host model only).

`dispsnap` is a payload for the q1n1 payload runner ([SP11-PAYLOAD.md](SP11-PAYLOAD.md)), one source file (`payloads/dispsnap.c`) and a registers header (`payloads/dispsnap-regs.h`). It reads the 25 registers of the display study's X2 dump list (`docs/SP11-DISPLAY-STUDY.md` of the Snapintosh tree, section 8: the registers whose snapshot decides whether the firmware's display pipeline is ACTIVE, INACTIVE, UNKNOWN or INCONSISTENT) with plain 32-bit loads through the runner's guarded `load32`, writes nothing anywhere, and prints them as at most 34 lines that the host tool `tools/sp11_dispsnap_parse.py` of the Snapintosh tree turns back into the snapshot of `compat/display-pipeline-check` and judges. It is modelled on the sibling payload `gpusnap` (the GPU's clock and power state) and carries every lesson of its two reviews from the start: each line goes out as soon as its loads are done, a `NEXT <block>` line before each block of reads, a line budget and a load budget, guarded loads with `FAULT`, `SKIP` and `GATED BY` tokens, gates that look at clock and power state before a block that may be clock-gated is read, an 8 s wait on the counter with its own tokens, an `END` line, and a proof from the compiled code that no store reaches a device or the framebuffer.

**The panel is the firmware's own scanout.** The page the operator reads is drawn by the runner into the GOP framebuffer, and the pipeline this payload looks at (the DPU's INTF_5, the eDP controller behind it) is what scans that framebuffer out to the panel. So a read must never disturb it. The payload never reads or touches the framebuffer or its address (it takes the GOP's width, height, stride and format from the runner's arguments to print them, and nothing else from there: `fb_base` is not printed, and the host model maps nothing at the address it passes, so a dereference ends the run), issues loads only, and loads only registers of which no pinned source says that a read has a side effect. Which registers were left out for that reason is below.

## What it answers, and what it does not

* It answers, for one moment after ExitBootServices: are the display register clock, the MDSS power domain and the two clocks the DPU needs on; does the MDSS answer with the hardware version the device tree says (9.2); is the eDP interface's timing engine enabled and running with a coherent frame whose active window is the GOP's; does a CTL path list INTF_5; does the frame counter advance over 8 s, and at what rate. It prints the raw words; the host side decides.
* It does **not** answer: whether the panel is lit (the operator sees that), whether the GOP framebuffer is the scanout address of the DPU (UNKNOWN: the display goes through `apps_smmu` stream 0x1c00, dt:5578, and no SSPP register is read), the state of the eDP controller's link or PHY, the panel's EDID or capabilities (no AUX transaction is made), the backlight (no register of it is on the list), or anything about how the firmware set the pipeline up.
* The study's verdicts are INFERRED for the unit until a page has been read. This payload is the reader the study asks for; its page is the first instrument that can turn them into OBSERVED.

## How it follows the study

| Study (section 8 and 5.2) | This payload |
| --- | --- |
| S0: the GOP mode, before any MMIO | the `GOP W H STRIDE FMT` line, from the runner's arguments (no load): the runner's GOP is the one it draws in. The EDID is not read (it is another instrument's, the probe's) |
| S1 to S4: the four gates in order, stop at the first that is off or unreadable | GCC `DAHB` (no gate), then DISPCC (`GDSC`, `AHBC`, `MDPC`) only if `DAHB` runs, then the `DG` verdict; the MDSS and the DPU only if the verdict is `ON` |
| S5: the version | `VER` (MDSS), and the DPU only behind a version word that is neither all ones nor zero |
| S6, S7: the INTF registers, the six CTL words | the interface's 14 words and the six `CTL_INTF_ACTIVE` words, in the study's register order except that Linux's own words (`ST`, `CFG`, `CFG2`) come first in their block |
| S8: `FLC`, then the counter, a wait of at least 100 ms, the counter again, the elapsed time | `FRA` only if `FLC` was read, is not all ones and is not zero; one wait of 8 s on the runner's counter (the same wait that shows whether the gates still hold); `FRB` and `DT`, the ticks between the two readings |
| "What not to add" | nothing of it is read (below) |

## What it reads, block by block

The table is the register table of `payloads/dispsnap-regs.h`; `Offset` is the offset inside the window the payload reads (`Reg` inside the INTF or CTL page for the DPU rows). "Linux reads it" says whether a pinned Linux file reads the word, which is the order argument: the first load of every block is a word Linux itself reads, and the words after it are in the same page.

| Block | Key | Offset | Window | Reg | Linux reads it | Source | Label |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GCC | `DAHB` | `0x27004` | GCC `0x00100000` | | yes: read-modify-write at probe (cmn:317-318) | the critical-clock list, no clock struct (gcc:7447): `GCC_DISP_AHB_CLK`, the clock that makes the display clock controller's registers reachable | VERIFIED; INFERRED for the unit |
| DISPCC | `GDSC` | `0x9000` | dispcc `0x0af00000` | | yes (gdsc:127-141) | `mdss_gdsc`, `gdscr`, status = PWR_ON bit 31 of the same word (dc:1512-1522, gdsc:61-91) | VERIFIED |
| DISPCC | `AHBC` | `0x80a8` | dispcc | | yes (the clock core) | `disp_cc_mdss_ahb_clk`, halt and enable register, BRANCH_HALT (dc:792-808) | VERIFIED |
| DISPCC | `MDPC` | `0x800c` | dispcc | | yes (the clock core) | `disp_cc_mdss_mdp_clk`, BRANCH_HALT (dc:1332-1348) | VERIFIED |
| MDSS | `VER` | `0x0` | MDSS `0x0ae00000` | | yes (mm:276-283) | `HW_VERSION` at the MDSS base, major 31:28, minor 27:16 (mm:241-244); the offset is in a generated header that is not pinned | VERIFIED for the read; offset INFERRED (UV2) |
| DPU | `ST` | `0x3926c` | DPU `0x0ae01000` | `0x26c` | yes (hi:333-335) | `INTF_STATUS`, bit 0 = running on DPU 5 and up | VERIFIED |
| DPU | `EN` | `0x39000` | DPU | `0x000` | no (hi:333-335: only below DPU 5) | `INTF_TIMING_ENGINE_EN` | VERIFIED name and offset; the read INFERRED harmless |
| DPU | `CFG` | `0x39004` | DPU | `0x004` | yes (hi:123, hi:296) | `INTF_CONFIG`: bit 29 ACTIVE_H_EN, bit 30 ACTIVE_V_EN | VERIFIED |
| DPU | `CFG2` | `0x39060` | DPU | `0x060` | yes (hi:593) | `INTF_CONFIG2`: bit 0 DATABUS_WIDEN | VERIFIED |
| DPU | `HS` | `0x39008` | DPU | `0x008` | no (written, hi:17-75) | `INTF_HSYNC_CTL`: line length 31:16 | VERIFIED name and offset |
| DPU | `VP` | `0x3900c` | DPU | `0x00c` | no | `INTF_VSYNC_PERIOD_F0` | VERIFIED name and offset |
| DPU | `DVS` | `0x3901c` | DPU | `0x01c` | no | `INTF_DISPLAY_V_START_F0` | VERIFIED name and offset |
| DPU | `DVE` | `0x39024` | DPU | `0x024` | no | `INTF_DISPLAY_V_END_F0` | VERIFIED name and offset |
| DPU | `AVS` | `0x3902c` | DPU | `0x02c` | no | `INTF_ACTIVE_V_START_F0` | VERIFIED name and offset |
| DPU | `AVE` | `0x39034` | DPU | `0x034` | no | `INTF_ACTIVE_V_END_F0` | VERIFIED name and offset |
| DPU | `DHC` | `0x3903c` | DPU | `0x03c` | no | `INTF_DISPLAY_HCTL`: end 31:16, start 15:0 | VERIFIED name and offset |
| DPU | `AHC` | `0x39040` | DPU | `0x040` | no | `INTF_ACTIVE_HCTL` | VERIFIED name and offset |
| DPU | `FLC` | `0x390a8` | DPU | `0x0a8` | no (written, hi:257) | `INTF_FRAME_LINE_COUNT_EN`: nonzero = counters claimed | VERIFIED name and offset |
| DPU | `FRA` | `0x390ac` | DPU | `0x0ac` | yes (hi:339, hi:491) | `INTF_FRAME_COUNT`, read only if `FLC` says it counts; read again in snapshot 2 as `FRB` | VERIFIED |
| DPU | `C0` | `0x150f4` | DPU | `0xf4` | yes (hc:592, hc:700) | `CTL_INTF_ACTIVE` of `ctl_0` (cat:28-54, hc:35): bit n = INTF_n | VERIFIED |
| DPU | `C1` | `0x160f4` | DPU | `0xf4` | yes | `ctl_1` | VERIFIED |
| DPU | `C2` | `0x170f4` | DPU | `0xf4` | yes | `ctl_2` | VERIFIED |
| DPU | `C3` | `0x180f4` | DPU | `0xf4` | yes | `ctl_3` | VERIFIED |
| DPU | `C4` | `0x190f4` | DPU | `0xf4` | yes | `ctl_4` | VERIFIED |
| DPU | `C5` | `0x1a0f4` | DPU | `0xf4` | yes | `ctl_5` | VERIFIED |

The `GDSC` word is `mdss_gdsc`'s `GDSCR` (dc:1512-1522, gdsc:61-91): PWR_ON (bit 31) is the power status the Linux driver polls, SW_COLLAPSE (bit 0) is the software's vote, and the domain carries the flag HW_CTRL: the Linux driver turns the hardware-trigger mode (bit 1 of the same word) on for it when it powers the domain up, so the hardware may take the collapse over from the software. A set bit 1 is shown as `HW=1` and gates the MDSS off (`DISP=HWCTL`), and the word is read raw before any decode. The Linux files are those of the revision `7475ea8b58616b33c04afb976cf0fbaad9dd63fb`; their digests are in the evidence document.

The interface words are read by Linux as plain loads: the status word on a DPU of major version 5 and later (hi:333-335), the frame counter only while the interface is enabled (hi:339) and again in the tearing information (hi:491), none with an acknowledgement. Linux reads the line counter next to the frame counter; this payload does not (the line counter is not on the study's list, and a word that is not on it is not read).

The windows are the device tree's: GCC 0x00100000 + 0x200000 (dt:758-760), the display clock controller 0x0af00000 + 0x20000 (dt:6022-6026), the MDSS 0x0ae00000 + 0x1000 (dt:5553-5557; power domain `MDSS_GDSC`, clocks the MDSS AHB branch, `GCC_DISP_HF_AXI` and the MDP branch: dt:5560-5562), and the DPU's `mdp` region 0x0ae01000 + 0x8f000 (dt:5589-5593). INTF_5 is `.base = 0x39000`, 0x280 long, type DP, controller 3 (cat:350-356, dt:5633-5639), so its page is 0x0ae3a000; the six CTL paths are 0x1000 apart from 0x15000, 0x290 long (cat:28-54); the DPU is 9.2 (cat:414-417). The INTF and CTL pages lie inside the DPU window, which is therefore one window: the first abort in it ends every later read of it. The register offsets of the INTF block are the `#define`s of the pinned `dpu_hw_intf.c` (hi:17-75).

**Left out, and why.** No clear-on-read, read-to-pop or read-side-effect register is on the list, and these were deliberately **not read**: the DP controller's `AUX_DATA` FIFO (a read pops it), every other word of the DP controller, its PHY and the DPCD (the study's "what not to add"; no AUX transaction is made), the DP, MDSS and DPU interrupt status and clear registers (`INTR_STATUS` words can clear on read, study 5.1), `INTF_MISR_SIGNATURE` (hi:17-75: part of the signature collector), `INTF_LINE_COUNT` (hi:17-75: a counter nothing needs), `INTF_MUX`, the SSPP, mixer and VBIF blocks, the apps SMMU and the extra display branch clocks of dispcc (DPTX3 at 0x8094 to 0x80a0: plain reads of an open window, but not on the study's list). That no word of the list has a side effect is INFERRED (UV4): Linux reads `STATUS`, `CONFIG`, `CONFIG2`, the frame counter and `CTL_INTF_ACTIVE` without any acknowledgement; no Linux code reads the enable, the counter's enable or the eight timing words, which are the study's list and lie in the same page as `STATUS`.

A branch clock word is decoded from raw: CLK_OFF is bit 31, NOC_FSM_STATUS bits 30:28 and CLK_ENABLE bit 0 (cb:63-71); Linux counts an NoC FSM status of ON as on even when CLK_OFF is set (cbc:54-58), so `.OFF` is not proof and the gates ask for more than Linux does: ENABLE set and CLK_OFF clear. None of the three clocks on the list has a hardware gating bit or skips its halt check (dc:792-808, dc:1332-1348), so the exemptions `gpusnap` needs for some of its clocks do not exist here. The GDSC's status is bit 31 of its own GDSCR (gdsc:61-91, dc:1512-1522); the domain is declared with HW_CTRL, so the hardware may be in charge of it: `SW_COLLAPSE` is bit 0 and `HW_CONTROL` bit 1 (gdsc:21, gdsc:26-27), and a GDSC under hardware control is not trusted, because the hardware may collapse it between two reads (`DISP=HWCTL`).

### The gates

Every gate opens on proof only; a word that was not read, faulted, was skipped or reads all ones never opens one, and a failed gate read is never reported as the thing it gates on (`DAHBERR` is not `DAHB`).

| Block | Opens iff | Closed because | Printed as |
| --- | --- | --- | --- |
| GCC | always (Linux keeps `DAHB` on; the first load of the page) | | |
| DISPCC | `DAHB` is read, not all ones, ENABLE set, CLK_OFF clear | read and does not run; could not be read | `DISPCC GATED BY DAHB`; `GATED BY DAHBERR` |
| MDSS | the verdict `DISP=ON`: `GDSC` PWR_ON set, SW_COLLAPSE and HW_CONTROL clear, `AHBC` and `MDPC` both running | HW_CONTROL set; SW_COLLAPSE set or PWR_ON clear; one clock does not run; an input was not read or is all ones | `GATED BY DISP=HWCTL`, `DISP=OFF`, `DISP=PART`, `DISP=UNK` |
| DPU | `DISP=ON` and `VER` was read, is not all ones and is not zero (a block that answers) | the same, or `VER` is zero; `VER` could not be read | `GATED BY VER`; `GATED BY VERERR` |
| snapshot 2: GCC | always, if snapshot 1 read the word in a window that had not aborted | | |
| snapshot 2: DISPCC | snapshot 2's own `DAHB` word runs | | `S2 DISPCC GATED BY DAHB` or `DAHBERR` |
| snapshot 2: DPU | snapshot 2's own `DAHB` and gate words say `DISP=ON` | | `S2 DPU GATED BY DISP=..` |

Why these gates: the A16 tool of the Snapintosh tree states, citing a failure-modes note that is not in that tree, that an unclocked MDSS read is an SError and a cold reboot (INFERRED here, second-hand): the guard does not catch an SError, so the gates and the order are the safety argument, not the guard. The display-configuration NoC vote that makes the registers reachable (dt:5574, "cpu-cfg") has no readable state (UV5): the lit panel the operator reads is the only evidence that it is up.

## The page

The numbers below are measured on runs of the host model (the host test binary built from `tools/test-q1n1-sp11-payload-dispsnap.c`, run with `--numbers`), and the document test compares them with this table.

<!-- numbers -->
| Name | Value | Meaning |
| --- | --- | --- |
| `registers` | 25 | the rows of the register table (the windows' words; the six CTL words included) |
| `line_cap` | 34 | the payload's own cap on the lines of a page; the runner takes 40 per call (`abi_lines`) |
| `load_cap` | 48 | the payload's own cap on the loads of a run; the ABI allows 4096 (`abi_loads`) |
| `abi_lines` | 40 | the runner's cap on the lines of one call |
| `abi_loads` | 4096 | the runner's cap on the loads of one call |
| `open_lines` | 27 | the lines of the open sample above (every gate open, the wait done) |
| `open_snapshot1_lines` | 20 | the lines up to and with `CTL C3`: the page of snapshot 1, the legend and the header included |
| `open_loads` | 32 | the loads of the open sample: 25 in snapshot 1 and 7 in snapshot 2 |
| `open_snapshot1_loads` | 25 | the loads of snapshot 1 |
| `open_snapshot2_loads` | 7 | the loads of snapshot 2: `DAHB`, `GDSC`, `AHBC`, `MDPC`, `ST`, `EN`, `FRB` |
| `cold_lines` | 18 | the lines when the MDSS power domain is off |
| `cold_loads` | 8 | the loads then: the gate words of snapshot 1 (4) and of snapshot 2 (`DAHB`, `GDSC`, `AHBC`, `MDPC`) |
| `dahboff_lines` | 14 | the lines when `DAHB` is off: the shortest page that is not a refusal |
| `dahboff_loads` | 2 | the loads then: `DAHB` twice |
| `wide_lines` | 27 | the lines with the widest values (every word 0XFFFFFFFE, the gate words as wide as they go) |
| `wide_cuts` | 0 | the fields cut to fit the 100-character line then (`CUTS` of `END`) |
| `wideflip_lines` | 27 | the lines with the same widest values when the GCC word changes during the wait (snapshot 2 is gated by it, and the `DRIFT` lines name the change) |
| `wideflip_cuts` | 0 | the fields cut then |
| `wideflip_more` | 0 | the `MORE=` of its `DRIFT` summary (0: the summary fits, nothing is cut from it) |
<!-- /numbers -->

The open sample, every gate open, with **made-up values** (a 2880 x 1920 mode on INTF_5 at 60 Hz, laid out as Linux programs a DP interface; the counter moves by 480 in the wait; NOT the unit's page; the GOP mode is the product's size, which the unit's GOP may not show). Its lines are what the host model prints.

<!-- page-open -->
```
PAYLOAD DISPSNAP READ ONLY EL=2 HZ=0X124F800 GAP=8 S
PAYLOAD DISPSNAP KEY=RAW WORD .ON/.OFF=BIT 31 .ODD=BIT 31 NOT TRUSTED NO STORE NO AUX NO IRQ STATUS
PAYLOAD DISPSNAP GOP W=2880 H=1920 STRIDE=2880 FMT=1
PAYLOAD DISPSNAP MAP GCC=0X100000 DISPCC=0XAF00000 MDSS=0XAE00000 DPU=0XAE01000
PAYLOAD DISPSNAP MAP INTF=5 AT=0X39000 CTL=0X15000 STEP=0X1000 REG=0XF4
PAYLOAD DISPSNAP NEXT GCC
PAYLOAD DISPSNAP GCC DAHB=1.ON
PAYLOAD DISPSNAP NEXT DISPCC
PAYLOAD DISPSNAP DISPCC GDSC=0X8022F000.ON SC=0 HW=0
PAYLOAD DISPSNAP DISPCC AHBC=1.ON MDPC=1.ON
PAYLOAD DISPSNAP DG DISP=ON PWR=1 SC=0 HW=0 CLK=0X3
PAYLOAD DISPSNAP NEXT MDSS
PAYLOAD DISPSNAP MDSS VER=0X90020000 MAJ=9 MIN=2
PAYLOAD DISPSNAP NEXT DPU
PAYLOAD DISPSNAP INTF ST=1 EN=1 CFG=0X60000000 CFG2=0X10
PAYLOAD DISPSNAP INTF HS=0XBE00020 VP=0X5C4F40 DVS=0X19FF0 DVE=0X5AAF4F
PAYLOAD DISPSNAP INTF AVS=0X19FF0 AVE=0X5AAFEF DHC=0XB8F0050 AHC=0XB8F0050
PAYLOAD DISPSNAP INTF FLC=3 FRA=0X3E8
PAYLOAD DISPSNAP CTL C0=0X20 C1=0 C2=0
PAYLOAD DISPSNAP CTL C3=0 C4=0 C5=0
PAYLOAD DISPSNAP NEXT WAIT 8 S
PAYLOAD DISPSNAP NEXT S2 GCC
PAYLOAD DISPSNAP NEXT S2 DISPCC GCC=SAME
PAYLOAD DISPSNAP NEXT S2 DPU DISPCC=SAME
PAYLOAD DISPSNAP S2 INTF ST=1 EN=1 FRB=0X5C8 DT=0X9308A00
PAYLOAD DISPSNAP DRIFT NONE CMP=6
PAYLOAD DISPSNAP END LOADS=32 FAULTS=0 SKIPS=0 BLK=0 CUTS=0 GAP_MS=8030 LINES=27
```
<!-- /page-open -->

Excerpts of the pages of other situations, from the host model; each is a run of lines of that page, in order.

The MDSS power domain is off (`GDSC` bit 31 clear, `SC=1`): the display subsystem is collapsed; the gate words are read, nothing behind them is, and snapshot 2 reads the gate words again.

<!-- cold-lines -->
```
PAYLOAD DISPSNAP DISPCC GDSC=0X222001.OFF SC=1 HW=0
PAYLOAD DISPSNAP DISPCC AHBC=0X80000000.OFF MDPC=0X80000000.OFF
PAYLOAD DISPSNAP DG DISP=OFF PWR=0 SC=1 HW=0 CLK=0X0
PAYLOAD DISPSNAP MDSS GATED BY DISP=OFF
PAYLOAD DISPSNAP DPU GATED BY DISP=OFF
PAYLOAD DISPSNAP END LOADS=8 FAULTS=0 SKIPS=0 BLK=0XC CUTS=0 GAP_MS=8020 LINES=18
```
<!-- /cold-lines -->

`DAHB`, the AHB clock that makes the display clock controller reachable, is off: DISPCC is not read, and neither is anything behind it; the page is 14 lines.

<!-- dahboff-lines -->
```
PAYLOAD DISPSNAP NEXT GCC
PAYLOAD DISPSNAP GCC DAHB=0X80000000.OFF
PAYLOAD DISPSNAP DISPCC GATED BY DAHB
PAYLOAD DISPSNAP MDSS GATED BY DAHB
PAYLOAD DISPSNAP DPU GATED BY DAHB
PAYLOAD DISPSNAP NEXT WAIT 8 S
PAYLOAD DISPSNAP END LOADS=2 FAULTS=0 SKIPS=0 BLK=0XE CUTS=0 GAP_MS=8020 LINES=14
```
<!-- /dahboff-lines -->

The GDSC is on at the first reading and off at the second (the display was powered down during the wait): snapshot 2 judges the DPU by its own words, does not read it, says so and names what changed.

<!-- s2gated-lines -->
```
PAYLOAD DISPSNAP NEXT S2 DISPCC GCC=SAME
PAYLOAD DISPSNAP S2 DPU GATED BY DISP=OFF DISPCC=CHG:1
PAYLOAD DISPSNAP DG GDSC=0X8022F000-0X222001
PAYLOAD DISPSNAP DRIFT CHANGED=1 LOST=0 CMP=4
PAYLOAD DISPSNAP END LOADS=29 FAULTS=0 SKIPS=0 BLK=8 CUTS=0 GAP_MS=8030 LINES=27
```
<!-- /s2gated-lines -->

The GDSC is under hardware control (`HW=1`): the verdict is `DISP=HWCTL`, the power state of the domain is not the software's to say, and the MDSS is not read.

<!-- hwctl-lines -->
```
PAYLOAD DISPSNAP DISPCC GDSC=0X8022F002.ON SC=0 HW=1
PAYLOAD DISPSNAP DG DISP=HWCTL PWR=1 SC=0 HW=1 CLK=0X3
PAYLOAD DISPSNAP MDSS GATED BY DISP=HWCTL
PAYLOAD DISPSNAP DPU GATED BY DISP=HWCTL
```
<!-- /hwctl-lines -->

The domain is on, the display AHB clock runs and the MDP clock is off: `DISP=PART`, the registers are not read.

<!-- part-lines -->
```
PAYLOAD DISPSNAP DISPCC AHBC=1.ON MDPC=0X80000000.OFF
PAYLOAD DISPSNAP DG DISP=PART PWR=1 SC=0 HW=0 CLK=0X1
PAYLOAD DISPSNAP MDSS GATED BY DISP=PART
PAYLOAD DISPSNAP DPU GATED BY DISP=PART
```
<!-- /part-lines -->

The DISPCC window aborts at its first word: that window is dead, the other words of it are `SKIP`, the verdict is `DISP=UNK` and nothing behind it is read.

<!-- dispccabort-lines -->
```
PAYLOAD DISPSNAP DISPCC GDSC=FAULT:6 SC=FAULT:6 HW=FAULT:6
PAYLOAD DISPSNAP DISPCC AHBC=SKIP MDPC=SKIP
PAYLOAD DISPSNAP DG DISP=UNK
PAYLOAD DISPSNAP MDSS GATED BY DISP=UNK
PAYLOAD DISPSNAP DPU GATED BY DISP=UNK
PAYLOAD DISPSNAP END LOADS=3 FAULTS=1 SKIPS=2 BLK=0XE CUTS=0 GAP_MS=8020 LINES=17
```
<!-- /dispccabort-lines -->

The MDSS version read aborts: the version is the gate of the DPU, so the DPU is gated by an error and not read.

<!-- mdssabort-lines -->
```
PAYLOAD DISPSNAP NEXT MDSS
PAYLOAD DISPSNAP MDSS VER=FAULT:6 MAJ=FAULT:6 MIN=FAULT:6
PAYLOAD DISPSNAP DPU GATED BY VERERR
PAYLOAD DISPSNAP END LOADS=9 FAULTS=1 SKIPS=0 BLK=0XC CUTS=0 GAP_MS=8020 LINES=19
```
<!-- /mdssabort-lines -->

The first DPU word aborts: the DPU window is dead, every later word of it is `SKIP`, and nothing is read again.

<!-- dpuabort-lines -->
```
PAYLOAD DISPSNAP NEXT DPU
PAYLOAD DISPSNAP INTF ST=FAULT:6 EN=SKIP CFG=SKIP CFG2=SKIP
PAYLOAD DISPSNAP INTF FLC=SKIP FRA=SKIP
PAYLOAD DISPSNAP CTL C0=SKIP C1=SKIP C2=SKIP
PAYLOAD DISPSNAP END LOADS=10 FAULTS=1 SKIPS=19 BLK=8 CUTS=0 GAP_MS=8020 LINES=25
```
<!-- /dpuabort-lines -->

The frame counter's enable (`FLC`) is zero: the counter is not read (`FRA=NOFLC`), and snapshot 2 has no second reading to make.

<!-- noflc-lines -->
```
PAYLOAD DISPSNAP INTF FLC=0 FRA=NOFLC
PAYLOAD DISPSNAP S2 INTF ST=1 EN=1 FRB=NOFLC
PAYLOAD DISPSNAP END LOADS=30 FAULTS=0 SKIPS=0 BLK=0 CUTS=0 GAP_MS=8020 LINES=27
```
<!-- /noflc-lines -->

The runner's counter does not move at all (the `nocounter` fake: no wait is possible): there is no wait, snapshot 2 is skipped and the gap is zero.

<!-- nocounter-lines -->
```
PAYLOAD DISPSNAP CTL C3=0 C4=0 C5=0
PAYLOAD DISPSNAP S2 SKIPPED NO_COUNTER
PAYLOAD DISPSNAP END LOADS=25 FAULTS=0 SKIPS=0 BLK=0 CUTS=0 GAP_MS=0 LINES=22
```
<!-- /nocounter-lines -->

The display counts frames but the frame counter does not move in the 8 s of the wait (`FRB` equals `FRA`) while the counter of the runner did move (`DT` is large): the frame counter of the interface has stopped although `ST` says it runs.

<!-- stalled-lines -->
```
PAYLOAD DISPSNAP INTF FLC=3 FRA=0X3E8
PAYLOAD DISPSNAP S2 INTF ST=1 EN=1 FRB=0X3E8 DT=0X9308A00
PAYLOAD DISPSNAP DRIFT NONE CMP=6
```
<!-- /stalled-lines -->

The interface is off and idle (`ST=0`, `EN=0`, every `CTL_INTF_ACTIVE` word zero) while the frame counter's enable still reads on: nothing drives the panel from this DPU interface.

<!-- idle-lines -->
```
PAYLOAD DISPSNAP INTF ST=0 EN=0 CFG=0X60000000 CFG2=0X10
PAYLOAD DISPSNAP CTL C0=0 C1=0 C2=0
PAYLOAD DISPSNAP S2 INTF ST=0 EN=0 FRB=0X5C8 DT=0X9308A00
```
<!-- /idle-lines -->

### How to read it

| Line | Fields | Meaning |
| --- | --- | --- |
| 1, 2 | `HZ`, `GAP`; the legend | the counter frequency (`DEFAULT` after it when `CNTFRQ_EL0` was outside 1 to 1000 MHz and 19.2 MHz was used) and the wait; the legend of the notation |
| `GOP` | `W`, `H`, `STRIDE`, `FMT` | the mode of the framebuffer the runner draws in, from the arguments, in pixels (`FMT` 0 is RGBX, 1 BGRX); no load. All zero when the runner had no framebuffer |
| `MAP` | `GCC DISPCC MDSS DPU`; `INTF AT CTL STEP REG` | the window bases the loads use (from the table the loads use) and the geometry inside the DPU window: the interface's index and its offset, the first CTL page, the step between pages, the offset of `CTL_INTF_ACTIVE`. No load. The host side computes every address from them |
| a field | `KEY=VALUE` | the raw word: below 10 one digit, a larger one `0X` and the fewest upper-case hex digits (the runner's `hex`). A clock or GDSC word is followed by its decode (below) |
| `GCC`, `DISPCC` | `DAHB`; `GDSC` (`SC`, `HW`), `AHBC`, `MDPC` | the gate words; `SC`, `HW` are bits 0 and 1 of the GDSCR |
| `DG` | `DISP=`, `PWR`, `SC`, `HW`, `CLK` | the display verdict, printed as soon as its inputs have gone out and before any MDSS word is read: `DISP=ON`, `DISP=OFF`, `DISP=HWCTL`, `DISP=PART`, `DISP=UNK`, and, unless it is `DISP=UNK`, PWR_ON, the two GDSCR bits, and a bit per clock that runs (`CLK`: `AHBC` bit 0, `MDPC` bit 1) |
| `MDSS` | `VER` (`MAJ`, `MIN`) | the hardware version raw and decoded (9.2 is `0X90020000`) |
| `INTF` | `ST EN CFG CFG2`; `HS VP DVS DVE`; `AVS AVE DHC AHC`; `FLC FRA` | the interface's words in the order of the register table; `FRA` is `NOFLC` when `FLC` is zero, all ones or was not read |
| `CTL` | `C0 .. C5` | `CTL_INTF_ACTIVE` of the six paths: bit 5 is INTF_5 |
| `NEXT <block>` | | printed **before** the first load of a block that is read; nothing of it is read if the line cannot be printed: the last line on the film names what hung |
| `<block> GATED BY <why>` | `DAHB`, `DAHBERR`, `DISP=OFF`, `DISP=HWCTL`, `DISP=PART`, `DISP=UNK`, `VER`, `VERERR` | the block was not read, and why |
| `NEXT WAIT 8 S` | | the one wait, 8 s on the counter; if the panel dies here or after it, the film says so |
| `NEXT S2 <block>` | `GCC`, `DISPCC`, `DPU` | snapshot 2 re-reads only the words snapshot 1 read, in windows that had not aborted: the GCC word, the three gate words, and `ST`, `EN` and the frame counter. What the block before said rides the line (`GCC=SAME`, `DISPCC=CHG:<n>`), so that it is on the film before the load most likely to hang |
| `S2 INTF` | `ST`, `EN`, `FRB`, `DT` | the second look at the interface: the words as read; `FRB` the frame counter's second reading (`NOFLC` when snapshot 1 did not read it, so no second reading); `DT` the counter ticks between the two readings, as the counter counts them (divide by `HZ` for seconds) |
| `S2 <block> GATED BY <why>` | | snapshot 2 did not visit the block: its own gate words no longer say what opened it (or could not be read); none of its words is compared |
| `DG`, `DD` | `KEY=OLD-NEW` | what moved in the GCC and DISPCC words and in `ST` and `EN`: raw words; NEW may be `FAULT:6`, `SKIP`, `NA` or `BUDGET` where the re-read failed or did not happen. The frame counter is meant to move and is never drift |
| `DRIFT` | `NONE CMP=`, `CHANGED= LOST= CMP= MORE=` | nothing moved of the words compared; or how many differ, how many snapshot 2 could not read, how many were compared, and how many drift items did not fit |
| `END` | `LOADS FAULTS SKIPS BLK CUTS GAP_MS LINES` | the loads made; the aborted ones; the ones skipped after an abort; a bit per block (`GCC` 1, `DISPCC` 2, `MDSS` 4, `DPU` 8) that had a fault, a skip, a `GATED BY` line or was not read; the fields the cap kept off; the milliseconds from the start of snapshot 1 to the start of snapshot 2; the lines printed |
| `S2 SKIPPED NO_COUNTER`, `S2 SKIPPED SPIN` | | no snapshot 2: `NO_COUNTER`, no counter or one that does not run (it stood still for 2 million reads or ran backwards); `SPIN`, a counter that moves and did not reach the 8 s in 2^32-1 reads (INFERRED: minutes of the real loop), a different statement from a dead counter. The wait did not happen, there is no drift report, `END` follows with `GAP_MS=0` |
| `SKIPPED_NOT_AT_EL2`, `REFUSED_NO_LOAD32` | | the whole page, alone: CurrentEL is not 2 (it returns 0) or the runner gave no `load32` (it returns the bad-arguments code); nothing was read and there is **no** `END` line. An invalid argument block prints nothing at all |

The page is at most 34 lines whatever the hardware says (the ABI allows 40) and the drift summary and `END` are never crowded out by the lines before them **when the payload gets that far**: the early exits above print their one line and no `END`. A page where everything moves in the wait prints the first drift items and `MORE=` counts the rest. Snapshot 2 is a **drift list**, not a second page.

### Decoding the tokens

| Token | Where | Decode |
| --- | --- | --- |
| `.ON`, `.OFF` | after a branch clock word | bit 31, CLK_OFF (cb:63-71): set is `.OFF`, clear with CLK_ENABLE set is `.ON` |
| `.ON`, `.OFF` | after `GDSC` | bit 31, PWR_ON (gdsc:21): set is `.ON`. The other polarity: `SC` and `HW` are the bits themselves |
| `.ODD` | after a word | the bit 31 token cannot be taken at its word: all ones; or, on a branch clock, CLK_OFF clear with CLK_ENABLE clear (a window of zeros), or CLK_OFF with an NoC FSM status of ON. Read the raw word |
| `MAJ=ODD`, `ODD` | in place of a field | the field is cut from a word of all ones: nothing is decided from it |
| `FAULT:6` | in place of a value | the guarded load aborted (6 is `Q1N1_PAYLOAD_LOAD_E_FAULT`); that window is read no more |
| `SKIP` | in place of a value | not read, because an earlier load of that window aborted |
| `NA` | in place of a value | no load was made for it (a row outside its window: not possible with this table) |
| `BUDGET` | in place of a value | the load cap was reached |
| `NOFLC` | in place of `FRA` or `FRB` | the frame counter was not read: its enable `FLC` is zero, all ones or was not read, so the counter is not claimed to count |
| `GATED BY DAHB` | after `DISPCC`, `MDSS` or `DPU` | the GCC word `DAHB` was read and the register clock does not run (ENABLE clear or CLK_OFF set): the block was not read; `GATED BY DAHBERR` is the same line when `DAHB` could not be read (`FAULT:6`, all ones), which is not "the clock is off" |
| `DG`, `DISP=ON`, `DISP=OFF`, `DISP=HWCTL`, `DISP=PART`, `DISP=UNK` | the verdict | `DISP=ON`: PWR_ON set, SW_COLLAPSE and HW_CONTROL clear, both clocks run; `DISP=HWCTL`: HW_CONTROL set; `DISP=OFF`: SW_COLLAPSE set or PWR_ON clear; `DISP=PART`: on, but not both clocks run; `DISP=UNK`: one of the three inputs was not read or reads all ones. HW_CONTROL wins over OFF and PART; UNK wins over all |

### The host side: from page lines to the study's snapshot

`tools/sp11_dispsnap_parse.py` of the Snapintosh tree reads a transcript of the page (every line that has the prefix `PAYLOAD DISPSNAP `; the rest is ignored), rebuilds the snapshot of `compat/display-pipeline-check.h` and runs that C function on it: `python3 tools/sp11_dispsnap_parse.py PAGE.txt [--gop WxH]`, exit 0 ACTIVE, 1 INACTIVE, 2 UNKNOWN, 3 INCONSISTENT, 4 an unusable page. The lines carry exactly what the function needs: each register's raw word is the snapshot's value; `FAULT:<n>` is status FAULT, and `SKIP`, `NA`, `BUDGET`, `NOFLC`, a `GATED BY` block and a word the film did not show are not attempted; the address of a register is the base of its window from the `MAP` lines plus the study's offset (so a payload that read somewhere else than the study's parameters say makes the function answer address or interface mismatch); the interface index is `MAP INTF`; the gap between the two frame-counter readings is `DT` x 10^6 / `HZ` microseconds; the mode is the `GOP` line (or `--gop`). The parameters are the study's tables, not constants of the tool. A film that ends early gives a page with missing words: the verdict is UNKNOWN, never ACTIVE.

## What each page would mean

Every row is INFERRED from the study and the pinned files, none was seen, and none is a finding. There is a row for every token the payload can print that is not a plain value, and for what the film shows when it prints nothing more. The verdicts are the host function's (`tools/sp11_dispsnap_parse.py`).

| On the film | Reading | For the plan |
| --- | --- | --- |
| the open page: `DISP=ON`, `VER` 9.2, `ST=1 EN=1`, a timing whose active window is the GOP's, a `CTL` word with bit 5, `FRB` more than `FRA` | the firmware's pipeline runs the GOP mode on INTF_5: the host verdict is ACTIVE | the console may draw into the GOP framebuffer (study sec. 8); the DISP gates held, so the reads were safe |
| `DISPCC GATED BY DAHB`, `DAHB` `.OFF` or its bit 0 clear | the register clock of the display clock controller is not running on this unit (INFERRED: Linux keeps it on), so DISPCC is not reachable by the study's own rule | the host verdict is UNKNOWN (the clock is off, the gates unreachable); the firmware's pipeline cannot be judged this way |
| `DISPCC GATED BY DAHBERR`, `DAHB=FAULT:6` or `.ODD` | the display register clock word itself could not be read: that is **not** "the clock is off"; nothing behind it was read | the first abort is the result (UV1): whether GCC is mapped at EL2 for this word comes before anything else |
| `DG DISP=OFF` with `PWR=0` | the MDSS power domain is off (or SW_COLLAPSE is set); the display is off, or the pipeline is not the firmware's | the host verdict is INACTIVE; stop and report which gate; nothing behind the gate was read |
| `DG DISP=HWCTL` | the MDSS GDSC is under hardware control: the hardware may collapse it between two reads | the gate is closed on purpose (H5); the host verdict is UNKNOWN; a later payload may read behind it only after the operator rules on it |
| `DG DISP=PART` | the GDSC is on but one of the two clocks does not run: the `CLK` mask names which | the host verdict is INACTIVE (a clock reads off) or UNKNOWN; nothing behind it was read |
| `DG DISP=UNK`, `GDSC`, `AHBC` or `MDPC` `FAULT:6` or `.ODD` | a gate word could not be read: DISPCC refuses a read at EL2 (UV1), or the word reads as a failed read does | the host verdict is UNKNOWN (read-fault or all-ones); the window is read no more |
| `DPU GATED BY VER`, `VERERR`, `VER=FAULT:6` | the MDSS did not answer with a version (zero, a failed read, an abort): the MDSS page may be unmapped or the block not clocked as the CBCRs say | the DPU was not read; the host verdict is UNKNOWN (not read); the DISP gates held but the block did not answer |
| `FAULT:6` on a later word of the DPU, `SKIP` for the rest of it | that register (or page) refuses while the words before it in the window answered: the first abort is the finding | the words after it were not tried; the host verdict is UNKNOWN (read-fault) |
| `INTF ST=0 EN=0` | the interface's timing engine is stopped though the gates are on: the pipeline is off, or the firmware's driver is not what Linux's is | the host verdict is INACTIVE (timing off): the display is not running through INTF_5, or this unit's firmware scans out another way |
| `ST` and `EN` disagree, a timing of zeros, an active window that is not the GOP's, no `CTL` word with bit 5 | the pinned sources' reading of these words does not fit the unit: an inconsistent pipeline, which is a result, not a failure of the test | the host verdict is INCONSISTENT with the rule that tripped; the raw words are the finding |
| `FLC=0`, `NOFLC` (as `FRA=NOFLC` or `FRB=NOFLC`) | the firmware does not enable the frame counters (Linux writes 3 there, hi:257) | the counter evidence is absent, not contradictory: ACTIVE needs only the study's required classes; the refresh rate is not measured |
| `FRB` equal to `FRA`, or moving faster than the plausible rate | the counter claims to run and did not move, or moved too fast over the 8 s | the host verdict is INCONSISTENT (counter stalled or fast) |
| `S2 DISPCC GATED BY DAHB..`, `S2 DPU GATED BY DISP=..`, `DRIFT CHANGED=`, `DG`/`DD` items | something moved in the 8 s with nobody touching it: a gate word, or the interface; or the interface was not read again because its gate no longer holds (or could not be read) | the first look stands; a pipeline that went off during the wait is reported by the second look, not hidden; with no `S2 INTF` line and `FLC` nonzero the host verdict is UNKNOWN (no `FRB`), not ACTIVE |
| `S2 SKIPPED NO_COUNTER` or `S2 SKIPPED SPIN` | the wait did not happen (no counter, a dead one, or one that never got there): no snapshot 2, no drift, no `FRB`, no `DT` | the page is snapshot 1 only; `HZ` says what was read; with `FLC` nonzero the host verdict is UNKNOWN (the counter's second reading, `FRB`, was not read: the study's check wants both before it counts the counter), never ACTIVE; boot again, nothing was written |
| a long silence after `NEXT WAIT 8 S` | the wait reads only the counter, and gives up after 2^32-1 reads: a counter that moves and never gets there can hold the page for minutes (that bound times the time of one read: INFERRED) before `S2 SKIPPED SPIN`; past the film rule below it is a hang or a dead panel | wait out the film rule; the silence says nothing about a display word (none is read in the wait) |
| `.ODD`, `MAJ=ODD`, `ODD` | a word of all ones (what a failed read returns) or a mode that makes bit 31 untrustworthy. A gate never opens on an unread, faulted or all-ones word | read the raw word; all ones in a window that answered elsewhere means the word was not really read |
| `BUDGET`, `NA`, `CUTS=` or `MORE=` above 0 | a cap cut the page: fields and drift items were dropped and counted, never printed half | the page is incomplete but honest; the counts say how much |
| `SKIPPED_NOT_AT_EL2`, `REFUSED_NO_LOAD32` | the runner called it outside EL2 or without a `load32` | nothing was read; the run is wrong, not the payload |
| the page ends at a `NEXT <block>` line, or the panel goes dark or freezes | a load of that block did not return (a hung bus is not recovered; the ABI says so; an SError is not caught), and the page does not say which register. The drawing lags the loads (H3), so the hung block can be a LATER one than the last `NEXT` on the film | the premise of that block's gate (the clock and power words say it is readable) is false for the unit; the display work cannot continue without a review |
| `END` is there, then q1n1's fault page or a reset | not this payload's page: it printed all it had; the next payload of the chain, or q1n1, faulted or the board reset | read the later `PAYLOAD` lines; the words of `dispsnap` are on the film |
| any of the above | recovery: nothing was written, so there is nothing to undo | reset and **boot the stick again**; a hang that repeats at the same line is the result |

Two checks for the operator. **Film for 2 minutes after `END`, and for 10 minutes after `PAYLOAD CALL` if there is no `END`** (the wait above can hold the page that long): a blackout that comes only later is a result too (the cause would still be UNKNOWN; q1n1's pages have gone dark after a minute or more before). **Read `HZ=0X124F800` (19.2 MHz) on the film**: another value, or `DEFAULT` after it, means the wait is not 8 s of real time (a counter slower than `CNTFRQ_EL0` says stretches it), and `GAP_MS` cannot show that, being measured on the same counter; `DT` is on the same counter as well.

## Chaining it in front of the xHCI payloads

The runner calls the payloads of a manifest in **manifest order**, each once, and what a payload returns never stops the chain ([SP11-PAYLOAD.md](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot)). `dispsnap` is read-only, so it goes **first** and the payload that writes goes last: a payload that may stall the board goes last, and once the board resets every earlier line is gone unless the screen is filmed within seconds. Build, then make the stick tree (the tool keeps the order it is given; names are 8.3, at most five files):

```sh
make -f platform/uefi/Makefile payloads
python3 tools/sp11_payload_manifest.py --out-dir build/stick-dispsnap build/uefi/payloads/dispsnap.bin build/uefi/payloads/xhci0.bin
```

writes `build/stick-dispsnap/SP11/PAYLOAD.MAN` and the capitalised copies `DISPSNAP.BIN` (manifest index 0, called first) and `XHCI0.BIN` (index 1, last); `xhci1.bin` is taken the same way. The runner itself, the Shell script and the Snapintosh autorun staging are not touched by this document. The page budget of the chain, from the runner's planning table ([SP11-PAYLOAD.md](SP11-PAYLOAD.md#the-chain-several-payloads-in-one-boot)) and the two payloads' own figures (the open sample above; [SP11-PAYLOAD-XHCI.md](SP11-PAYLOAD-XHCI.md#the-page)):

<!-- dispsnap-chain-budget -->
| Item | Nominal | At most |
| --- | --- | --- |
| `LOADED` for each of two files and `READY` (the runner, once per boot: files + 1) | 3 | 3 |
| `VERIFY`, `CALL`, `DONE` for each of the two payloads (the runner, 3 each) | 6 | 6 |
| `dispsnap` (the open sample; the line cap of the payload) | 27 | 34 |
| `xhci0` (a nominal page; the most it prints per call) | 19 | 40 |
| total | 55 | 83 |
| panel region (the unit's 2880 x 1920 panel, the runner's rows) | 89 | 89 |
<!-- /dispsnap-chain-budget -->

Either way this document authorises no run: a stick with `DISPSNAP.BIN` in front of `XHCI0.BIN` is another file set and manifest than any approved record's, and needs its own record and the operator's approval of the SHA-256 of each file (one hardware client, AC power or at least 50 % battery, AGENTS.md of the Snapintosh tree). Alone in a boot of its own the page is the nominal one plus the runner's own lines.

## Hazards

* **H0, a load that hangs the bus, or an SError.** `load32` is guarded against a synchronous abort only: it comes back as `FAULT:6`. A hung bus, or an SError, is neither caught nor printed, and nothing recovers it. Nothing is written, so there is nothing to undo: power-cycle and boot the stick again. The display is the console: if the CPU hangs, the panel keeps its last frame (the scanout does not depend on it; INFERRED).
* **H1, an unclocked or collapsed MDSS or DPU read.** The A16 notes say it is an SError (second-hand, above). The DISP gate and the version gate are the defence, and a gate that cannot prove a clock or the power opens nothing.
* **H2, the display-configuration NoC vote.** It has no readable state (UV5): the lit panel is the only evidence (INFERRED).
* **H3, the draw lag.** The runner draws a line with `payload_emit` (UART bytes, then the screen, and no barrier before the next load), so the last line before a hang may not have reached the panel (UNKNOWN); the `NEXT` line before a block is the best this payload can do.
* **H4, the wait.** 2^32-1 counter reads bound it, with `NO_COUNTER` and `SPIN` tokens, and nothing but the counter is read during it.
* **H5, a closed gate is a result.** `DISP=HWCTL`, `DISP=PART`, `DISP=OFF`, `DAHB` stop the run before any MDSS word: an informative page, not a failure.

**The stage-1 map.** The runner calls the payload at EL2 under the firmware's tables, and `load32` is identity mapped by them. Whether the unit's EL2 stage-1 map reaches the MDSS, the DPU and dispcc pages is UNKNOWN (study section 9): GCC, DWC3 and apps-SMMU words were read there (OBSERVED, boot 18A, `usbsnap`: no fault), and the PCIe SMMU's page 0x15400000 had no mapping (OBSERVED, boot 22: a level-3 translation fault, see [SP11-PAYLOAD-NVMESNAP.md](SP11-PAYLOAD-NVMESNAP.md)). An unmapped display page gives a translation fault, which the guarded load turns into `FAULT:6` (INFERRED), and the page then reads: the first load of that window `FAULT:6`, the rest `SKIP`, the block's gate lines as above; a `NEXT` line before each block says which window was being tried. The memory map the runner passes is not consulted: it lists what the firmware calls memory-mapped I/O, not what EL2's stage 1 maps.

## Evidence

The safety rules with the seeded bug that must be refused for each, the tests and what they hold, what QEMU shows, and the pinned Linux files with their digests are in [SP11-PAYLOAD-DISPSNAP-EVIDENCE.md](SP11-PAYLOAD-DISPSNAP-EVIDENCE.md).

## Limits, and what remains before a run

* **Not run on hardware.** Whether any load of it hangs the bus on the unit is UNKNOWN; no display word has ever been read there by this payload. A hang is not recovered (the last `NEXT` line on the film names its block, or, the drawing lagging, an earlier one), an SError is neither caught nor printed. q1n1's fault page is reached by a fault outside the guarded load (this payload has none) **or by an abort the guard does not recover**: that recovery has **never fired on the unit** (every `FAULTS=` figure in [SP11-PAYLOAD-RESULTS.md](SP11-PAYLOAD-RESULTS.md) is 0, 12 of 12, and this payload's QEMU run has no fault), so the first abort here is its first real test, and the page then shows `FAULT:6` (recovered) or q1n1's fault page (not).
* The runner draws a line with no barrier before the next load, so the last line before a hang may not have reached the panel (UNKNOWN), as `payload_emit` has no barrier.
* A drift list that prints less than all of it (`MORE=`, `CUTS=`) says so; a value shown as `NA` was refused, not read; a window that aborted in snapshot 1 is neither re-read nor compared; the MDSS and the CTL words are read once and never compared.
* The decodes and the gates are the pinned files', not a statement about this unit; the raw words are what was read. Where a rule misjudges a word, a block that could have been read is not (lost evidence) or one that is stopped is read (the hang risk the last line then names).
* **EL2 stage-1 reach.** Whether the MDSS, DPU and dispcc pages are mapped at EL2 is UNKNOWN (above).
* UNIMPLEMENTED: the DP controller, its PHY, the EDID, the SSPP source address, the interrupt blocks, the backlight, and anything that writes.
* **Common mode.** The harness model and the payload have one author, so a misreading of a rule can be in both and a test that agrees with the payload shows only that; the register list was written from the study's dump list and the pinned files, and no independent reviewer has read this payload yet (the sibling's two reviews apply to its design, not to this binary). The model's own address list was written from the study's table apart from the payload's.
* Before any run: its own record, the operator's approval by SHA-256 of the exact binary, one hardware client, AC power or at least 50 % battery, the placement in the chain above, and film of 2 minutes after `END` (10 minutes after `PAYLOAD CALL` if there is no `END`).

**What could not be verified.** UV1: what any display word holds on the unit, and whether the unit's EL2 stage-1 map reaches the MDSS, the DPU and the display clock controller: none has ever been read there, so whether a read faults, hangs the bus or raises an SError is UNKNOWN. UV2: the offset of the MDSS hardware version: `REG_MDSS_HW_VERSION` is defined in a generated header that is not pinned (mm:276-283 reads it at the MDSS base); 0 is the study's INFERRED value. UV3: that the firmware's display driver sets the same bits as Linux: `CTL_INTF_ACTIVE`, the frame counter's enable and the timing words are read as Linux defines them; what the firmware wrote is the question the run asks. UV4: that reading any word of the list has no side effect on the unit: no Linux code reads the eight timing words, the enable or the counter's enable, and the frame counter is read by Linux (hi:339, hi:491) without any acknowledgement; "no clear-on-read register is on the list" is INFERRED from that and from the A16 tool. UV5: the state of the display-configuration NoC vote that makes the registers reachable (dt:5574, "cpu-cfg"): it has no readable state, and the lit panel is the only evidence that it is up. UV6: whether the GOP framebuffer is the scanout address of the DPU (the display goes through `apps_smmu` stream 0x1c00, dt:5578): no SSPP register is read.

## Staging (not authorised)

`make -f platform/uefi/Makefile payloads` builds `dispsnap.elf` and `dispsnap.bin` with every other payload (it is found by the wildcard), and the manifest tool lists `DISPSNAP.BIN` like any other: `DISPSNAP` has eight letters. The binary's size and SHA-256 are in the report that comes with it, not here: they change with every edit, and the approval is of the exact bytes.
